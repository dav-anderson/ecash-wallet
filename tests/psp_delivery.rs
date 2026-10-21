//! A PSP purchase from payment to notes with no paste, against a real
//! `air_server` started in this process: the wallet builds a purchase with its
//! own one-off reply key, psp-mint settles it with its real settlement code, its
//! deliverer writes the record to the AIR server, and the wallet reads the record
//! from the address it computes, checks the PSP's signature, claims the notes and
//! clears the purchase (`mint_info::psp_pickup`). A payment the PSP holds or
//! rejects is delivered too: the wallet keeps the purchase and its key open until
//! the PSP's reconciliation window closes, and then deletes them
//! (`Wallet::close_expired`), when the PSP forfeits the payment.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of this binary, and the tests take turns on it (see
//! `common/mod.rs`). They are built only with the `air-listener-tests` feature,
//! because the psp-mint they run is a local one that has `delivery`.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use ecash_wallet::config::AirSettings;
use ecash_wallet::mint_info::{PickedUp, Pickup, psp_pickup};
use ecash_wallet::psp::PurchaseBuild;
use ecash_wallet::store::{OpenKind, PendingPurchase};
use ecash_wallet::{Wallet, WalletError};
use mint_core::MintLogic;
use mint_types::{Amount, MintInput};
use psp_mint::delivery::{Deliverer, Report};
use psp_mint::records::Records;
use psp_mint::scan::Received;
use psp_mint::settle::{self, Settlement};
use sp_wire::ServiceDid;
use sp_wire::air_request::addr;
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::delivery::{self as wire, Outcome, Refused, Written};
use sp_wire::seal::SecretKey as DidKey;

/// $10,000 per BTC in cents: a PSP is $0.10, so 5,000 sats is exactly 5 PSP.
const BTC_10K: u64 = 1_000_000;

/// An AIR server that nothing answers: the right name, a host nobody is at (an
/// address reserved for documentation), so a connection fails or times out.
fn down(server: &ServerRef) -> ServerRef {
    ServerRef {
        name: server.name.clone(),
        host: "192.0.2.1".to_string(),
    }
}

/// A PSP mint with its DID key and records, and one wallet, in a folder of their
/// own.
struct Env {
    dir: PathBuf,
    logic: MintLogic,
    records: Records,
    mint_key: DidKey,
    wallet_path: PathBuf,
    wallet: Wallet,
}

fn env(name: &str) -> Env {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ecash-wallet-psp-delivery-{}-{name}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let logic = psp_mint::mint::open(&dir.join("psp"), Amount::from_units(1024)).unwrap();
    let records = Records::open(&dir.join("psp").join("settlements.json")).unwrap();
    let wallet_path = dir.join("wallet.json");
    let wallet = Wallet::open(&wallet_path).unwrap();
    Env {
        dir,
        logic,
        records,
        mint_key: DidKey::new(),
        wallet_path,
        wallet,
    }
}

impl Env {
    fn air(&self, server: &ServerRef) -> AirSettings {
        AirSettings {
            server: server.name.clone(),
            host: server.host.clone(),
            timeout_secs: 5,
            ..AirSettings::default()
        }
    }

    /// The wallet buys PSP outputs of these sizes from this mint.
    fn buy(&mut self, outputs: &[u64]) -> PurchaseBuild {
        self.wallet
            .build_psp_payload(outputs, &self.mint_key.public_key())
            .unwrap()
    }

    /// The mint opens a payment of `sats` carrying `payload` and settles it at 6
    /// confirmations.
    fn settle(&mut self, txid: &str, sats: u64, payload: Vec<u8>) -> Settlement {
        let (opened, ignored) = psp_mint::seal::open_payloads(
            &self.mint_key,
            vec![Received {
                txid: txid.to_string(),
                confirmations: 6,
                value_sats: sats,
                payload: Some(payload),
            }],
        );
        assert_eq!(ignored, 0);
        settle::settle(&self.logic, &mut self.records, &opened[0], &mut || {
            Ok(BTC_10K)
        })
        .unwrap()
    }

    fn deliverer(&self, server: &ServerRef) -> Deliverer {
        Deliverer::new(server.clone(), 3, self.mint_key.clone())
    }

    /// The wallet looks for its records once.
    fn pickup(&mut self, server: &ServerRef) -> Vec<PickedUp> {
        let air = self.air(server);
        psp_pickup(&mut self.wallet, &air, 0).unwrap()
    }

    fn psp_did(&self) -> ServiceDid {
        addr::key_to_did(&self.mint_key.public_key())
    }

    fn note_ids(wallet: &Wallet) -> BTreeSet<String> {
        wallet.notes().iter().map(|n| n.id()).collect()
    }
}

/// The reply DID and the purchase id the wallet holds for a pending purchase.
fn identity(p: &PendingPurchase) -> (ServiceDid, [u8; 32]) {
    let key = addr::secret_from_hex(p.reply_secret.as_ref().expect("a reply key")).unwrap();
    let purchase = hex::decode(p.delivery_id.as_ref().expect("a delivery id"))
        .unwrap()
        .try_into()
        .unwrap();
    (addr::key_to_did(&key.public_key()), purchase)
}

/// Write a record to a cell, as anyone who knew the cell could.
fn plant(server: &ServerRef, cell: &DidKey, sealed: &[u8]) {
    let server = server.clone();
    let cell = cell.clone();
    let sealed = sealed.to_vec();
    let written = block_on_new_runtime(move || async move {
        let client = client::connect(&server).await.unwrap();
        wire::write_record(&client, &cell, &sealed, 10)
            .await
            .unwrap()
    })
    .unwrap();
    assert_eq!(written, Written::Created);
}

fn only(found: &[PickedUp]) -> &Pickup {
    assert_eq!(found.len(), 1, "{found:?}");
    &found[0].what
}

#[test]
fn a_settled_purchase_is_delivered_and_claimed_with_no_paste() {
    let server = common::server();
    let mut e = env("claim");
    let build = e.buy(&[4, 1]);
    assert_eq!(e.wallet.balance().pending_purchases, 1);
    let settled = e.settle("aa", 5_000, build.payload.clone());
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");

    // the PSP has not written anything yet: the wallet finds nothing and keeps
    // the purchase
    assert_eq!(only(&e.pickup(&server)), &Pickup::NotThere);
    assert_eq!(e.wallet.balance().pending_purchases, 1);

    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass(&mut e.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    assert!(e.records.undelivered().is_empty());

    let found = e.pickup(&server);
    let Pickup::Claimed(claimed) = only(&found) else {
        panic!("expected the notes to be claimed: {found:?}");
    };
    assert_eq!(claimed.claim.claimed_units, 5);
    assert_eq!(claimed.claim.still_pending, 0);
    assert!(!claimed.key_kept, "nothing is owed, so the key is dropped");
    let balance = e.wallet.balance();
    assert_eq!((balance.psp, balance.pending_purchases), (5, 0));
    assert!(e.wallet.open_replies().is_empty());

    // every note passes the mint's own check
    let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
    for stored in e.wallet.notes() {
        e.logic
            .verify_note(&MintInput {
                amount: Amount::from_units(stored.amount),
                note: stored.note,
                spend_signature: dummy,
            })
            .unwrap();
    }

    // it was saved: a reopened wallet is the same
    let reopened = Wallet::open(&e.wallet_path).unwrap();
    assert_eq!(reopened.balance(), e.wallet.balance());
    assert_eq!(Env::note_ids(&reopened), Env::note_ids(&e.wallet));
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn reading_the_same_record_twice_changes_nothing() {
    let server = common::server();
    let mut e = env("twice");
    let build = e.buy(&[2, 1]);
    // a copy of the wallet as it was before the pickup (another device, or a
    // restored backup)
    let copy_path = e.dir.join("copy.json");
    fs::copy(&e.wallet_path, &copy_path).unwrap();

    e.settle("aa", 3_000, build.payload);
    let mut deliverer = e.deliverer(&server);
    assert_eq!(deliverer.pass(&mut e.records, Instant::now()).delivered, 1);

    let found = e.pickup(&server);
    assert!(matches!(only(&found), Pickup::Claimed(_)), "{found:?}");
    let balance = e.wallet.balance();
    let notes = Env::note_ids(&e.wallet);
    assert_eq!(balance.psp, 3);

    // the record is still there (the cell is write-once), and the copy claims the
    // very same notes from it
    let air = e.air(&server);
    let mut copy = Wallet::open(&copy_path).unwrap();
    let found = psp_pickup(&mut copy, &air, 0).unwrap();
    assert!(matches!(only(&found), Pickup::Claimed(_)), "{found:?}");
    assert_eq!(copy.balance(), balance);
    assert_eq!(Env::note_ids(&copy), notes);

    // and the wallet that already claimed has nothing pending: no read, no change
    assert!(e.pickup(&server).is_empty());
    assert_eq!(e.wallet.balance(), balance);
    assert_eq!(Env::note_ids(&e.wallet), notes);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_rejection_is_delivered_and_the_purchase_is_kept_open_until_its_window_closes() {
    let server = common::server();
    let mut e = env("reject");
    // 2048 is a power of two the wallet may ask for (it does not know the PSP's
    // largest note), and a size this mint has no key for: it rejects the whole
    // purchase
    let build = e.buy(&[2048]);
    let settled = e.settle("aa", 5_000, build.payload);
    assert!(matches!(settled, Settlement::Rejected(_)), "{settled:?}");

    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass(&mut e.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");

    let found = e.pickup(&server);
    let Pickup::Open(open) = only(&found).clone() else {
        panic!("expected an open purchase: {found:?}");
    };
    assert_eq!(open.kind, OpenKind::Rejected);
    assert!(!open.reason.is_empty());
    // what the PSP received, at its price: 5,000 sats is 50 cents
    assert_eq!((open.paid_sats, open.paid_cents), (5_000, 50));
    assert!(open.open_until > addr::now_secs());

    // nothing was signed, but the purchase and its key are kept
    let balance = e.wallet.balance();
    assert_eq!(
        (balance.psp, balance.notes, balance.pending_purchases),
        (0, 0, 1)
    );
    let kept = &e.wallet.pending_purchases()[0];
    assert!(kept.reply_secret.is_some());
    assert_eq!(kept.open.as_ref(), Some(&open));

    // reading again does not ask the server: it may be down, and the purchase is
    // reported as still open
    let air = e.air(&down(&server));
    let again = psp_pickup(&mut e.wallet, &air, 0).unwrap();
    assert_eq!(only(&again), &Pickup::StillOpen(open.clone()));

    // the open purchase is saved
    let reopened = Wallet::open(&e.wallet_path).unwrap();
    assert_eq!(reopened.pending_purchases()[0].open.as_ref(), Some(&open));

    // inside the window nothing is deleted, and nothing is written
    let version = e.wallet.version();
    assert!(
        e.wallet
            .close_expired(open.open_until - 1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(e.wallet.version(), version);
    // when the window closes the PSP forfeits the payment, and the wallet deletes
    // the purchase and its key
    assert_eq!(
        e.records.forfeit_expired(open.open_until).unwrap(),
        vec!["aa"]
    );
    assert_eq!(
        e.wallet.close_expired(open.open_until).unwrap(),
        vec![build.id.clone()]
    );
    assert_eq!(e.wallet.balance().pending_purchases, 0);
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.pickup(&server).is_empty());
    let reopened = Wallet::open(&e.wallet_path).unwrap();
    assert!(reopened.pending_purchases().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_held_payment_is_delivered_with_what_was_paid_and_closed_with_the_psps_forfeit() {
    let server = common::server();
    let mut e = env("held");
    let build = e.buy(&[4, 1]);
    // 1,000 sats is 1 unit of the 5 asked: short beyond the target, so nothing is
    // signed and the PSP holds the payment
    let settled = e.settle("aa", 1_000, build.payload);
    assert!(
        matches!(settled, Settlement::PaidUnsettled(_)),
        "{settled:?}"
    );
    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass(&mut e.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");

    let found = e.pickup(&server);
    let Pickup::Open(held) = only(&found).clone() else {
        panic!("expected an open purchase: {found:?}");
    };
    assert_eq!(held.kind, OpenKind::Held);
    assert_eq!((held.paid_sats, held.paid_cents), (1_000, 10));
    assert_eq!(held.requested_units, 5);
    assert!(held.over_under_bps < 0, "short: {}", held.over_under_bps);
    assert_eq!(e.wallet.balance().pending_purchases, 1);
    assert_eq!(e.wallet.balance().psp, 0);

    // one tick before the window closes the PSP has not forfeited it and the
    // wallet keeps the purchase; at the end both let go
    assert!(
        e.records
            .forfeit_expired(held.open_until - 1)
            .unwrap()
            .is_empty()
    );
    assert!(
        e.wallet
            .close_expired(held.open_until - 1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(e.wallet.balance().pending_purchases, 1);
    assert_eq!(
        e.records.forfeit_expired(held.open_until).unwrap(),
        vec!["aa"]
    );
    assert_eq!(e.wallet.close_expired(held.open_until).unwrap().len(), 1);
    assert_eq!(e.wallet.balance().pending_purchases, 0);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_credit_keeps_the_key_until_the_psps_window_for_it_closes() {
    let server = common::server();
    let mut e = env("credit");
    let build = e.buy(&[4, 1]);
    // 6,000 sats is 60 cents for 50: 20% over, so 10 cents are credited
    let settled = e.settle("aa", 6_000, build.payload);
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");
    let mut deliverer = e.deliverer(&server);
    assert_eq!(deliverer.pass(&mut e.records, Instant::now()).delivered, 1);

    let found = e.pickup(&server);
    let Pickup::Claimed(claimed) = only(&found) else {
        panic!("expected the notes to be claimed: {found:?}");
    };
    assert_eq!(claimed.credit_cents, 10);
    assert!(claimed.key_kept);
    assert_eq!(e.wallet.balance().psp, 5);

    // the kept key lasts as long as the PSP's window, which is in the record
    let [kept] = e.wallet.open_replies() else {
        panic!("one key is kept");
    };
    let until = kept.open_until;
    assert!(until > addr::now_secs());
    let record = e.records.get("aa").unwrap().open_until;
    assert_eq!(record, Some(until), "the same time the PSP forfeits at");
    assert!(e.wallet.close_expired(until - 1).unwrap().is_empty());
    assert_eq!(e.wallet.open_replies().len(), 1);
    assert_eq!(e.wallet.close_expired(until).unwrap(), vec![build.id]);
    assert!(e.wallet.open_replies().is_empty());
    // the notes were claimed, and stay
    assert_eq!(e.wallet.balance().psp, 5);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn with_the_server_down_at_settlement_a_later_retry_delivers_exactly_one_record() {
    let server = common::server();
    let mut e = env("retry");
    let build = e.buy(&[4]);
    e.settle("aa", 4_000, build.payload);

    // the AIR server cannot be reached when the payment settles: issuance stands,
    // nothing is delivered
    let mut dead = Deliverer::new(down(&server), 2, e.mint_key.clone());
    let report = dead.pass(&mut e.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (0, 1), "{report:?}");
    // the next scan is inside the wait: it is left alone
    let report = dead.pass(&mut e.records, Instant::now());
    assert_eq!((report.failed, report.waiting), (0, 1), "{report:?}");
    assert_eq!(e.records.undelivered().len(), 1);
    assert_eq!(only(&e.pickup(&server)), &Pickup::NotThere);
    let sealed = e
        .records
        .get("aa")
        .unwrap()
        .delivery
        .as_ref()
        .unwrap()
        .sealed
        .clone()
        .expect("the record is saved before it is written");

    // the mint is restarted: the waits are gone, the records are read from disk,
    // and the AIR server is back
    let path = e.dir.join("psp").join("settlements.json");
    e.records = Records::open(&path).unwrap();
    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass(&mut e.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    // the same bytes were written that were saved the first time
    let delivery = e.records.get("aa").unwrap().delivery.clone().unwrap();
    assert!(delivery.delivered);
    assert_eq!(delivery.sealed, Some(sealed));
    // nothing is left to do, now or after another restart
    assert_eq!(
        deliverer.pass(&mut e.records, Instant::now()),
        Report::default()
    );
    e.records = Records::open(&path).unwrap();
    assert_eq!(
        e.deliverer(&server).pass(&mut e.records, Instant::now()),
        Report::default()
    );

    let found = e.pickup(&server);
    let Pickup::Claimed(claimed) = only(&found) else {
        panic!("expected the notes to be claimed: {found:?}");
    };
    assert_eq!(claimed.claim.claimed_units, 4);
    assert_eq!(e.wallet.balance().psp, 4);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_record_that_is_not_the_psps_or_not_for_this_purchase_is_refused() {
    let server = common::server();
    let mut e = env("refused");
    e.buy(&[1]);
    e.buy(&[2]);
    let purchases = e.wallet.pending_purchases().to_vec();
    assert_eq!(purchases.len(), 2);
    let psp = e.psp_did();
    // a forged rejection, to cost the payer their purchase
    let forged = Outcome::Refused(Refused {
        reason: "forged".to_string(),
        ..Refused::default()
    });

    // 1. signed by someone other than the PSP, in the cell the PSP would use
    let (reply, purchase) = identity(&purchases[0]);
    let cell = wire::delivery_secret(&psp, &reply, &purchase);
    let impostor = DidKey::new();
    let built =
        wire::build_record(&impostor, &reply, &purchase, &forged, addr::now_secs()).unwrap();
    plant(&server, &cell, &built.sealed);

    // 2. signed by the PSP, but sealed to another DID than this purchase's
    let (reply, purchase) = identity(&purchases[1]);
    let cell = wire::delivery_secret(&psp, &reply, &purchase);
    let other = addr::key_to_did(&DidKey::new().public_key());
    let built =
        wire::build_record(&e.mint_key, &other, &purchase, &forged, addr::now_secs()).unwrap();
    plant(&server, &cell, &built.sealed);

    let before = e.wallet.balance();
    let found = e.pickup(&server);
    assert_eq!(found.len(), 2, "{found:?}");
    for picked in &found {
        assert!(matches!(picked.what, Pickup::Bad(_)), "{picked:?}");
    }
    // nothing changed: both purchases are still pending, with their keys
    assert_eq!(e.wallet.balance(), before);
    assert_eq!(e.wallet.balance().pending_purchases, 2);
    assert_eq!(e.wallet.balance().notes, 0);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_purchase_made_before_purchases_had_keys_reads_and_is_not_looked_for() {
    // no AIR server is needed: with no key there is nothing to ask for
    let mut e = env("old-wallet");
    e.buy(&[2]);
    let mut json: serde_json::Value =
        serde_json::from_slice(&fs::read(&e.wallet_path).unwrap()).unwrap();
    for p in json["pending_purchases"].as_array_mut().unwrap() {
        let p = p.as_object_mut().unwrap();
        p.remove("reply_secret");
        p.remove("delivery_id");
    }
    // the old wallet's one shared reply DID, which is now ignored
    json["reply_did"] = serde_json::Value::String(format!("02{}", "79be".repeat(16)));
    fs::write(&e.wallet_path, serde_json::to_vec(&json).unwrap()).unwrap();

    let mut old = Wallet::open(&e.wallet_path).unwrap();
    assert_eq!(old.balance().pending_purchases, 1);
    let found = psp_pickup(&mut old, &AirSettings::default(), 0).unwrap();
    assert_eq!(only(&found), &Pickup::NoKey);
    assert_eq!(old.balance().pending_purchases, 1);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn without_air_settings_the_pickup_says_what_is_missing_and_changes_nothing() {
    let mut e = env("no-air");
    e.buy(&[1]);
    let before = e.wallet.balance();
    let err = psp_pickup(&mut e.wallet, &AirSettings::default(), 0).unwrap_err();
    assert!(matches!(err, WalletError::Invalid(_)), "{err:?}");
    assert!(err.to_string().contains("air"), "{err}");
    assert_eq!(e.wallet.balance(), before);
    fs::remove_dir_all(&e.dir).unwrap();
}
