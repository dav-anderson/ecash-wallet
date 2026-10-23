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
use std::time::Instant;

use ecash_wallet::config::AirSettings;
use ecash_wallet::mint_info::{PickedUp, Pickup, psp_pickup};
use ecash_wallet::psp::{Loss, LossKind, PurchaseBuild};
use ecash_wallet::store::{OpenKind, PendingPurchase};
use ecash_wallet::{Wallet, WalletError};
use mint_types::{Amount, MintInput};
use psp_mint::delivery::{Deliverer, Report};
use psp_mint::settle::Settlement;
use sp_wire::ServiceDid;
use sp_wire::air_request::addr;
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::delivery::{self as wire, Outcome, Refused, Written};
use sp_wire::seal::SecretKey as DidKey;

use common::{PspMint, open_wallet, scratch};

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
    psp: PspMint,
    mint_key: DidKey,
    wallet_path: PathBuf,
    wallet: Wallet,
}

fn env(name: &str) -> Env {
    let dir = scratch(&format!("psp-delivery-{name}"));
    let psp = PspMint::open(&dir.join("psp"));
    let wallet_path = dir.join("wallet.json");
    let wallet = open_wallet(&wallet_path).unwrap();
    Env {
        dir,
        psp,
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
        self.psp.pay(&self.mint_key, txid, sats, payload)
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
    let key = addr::secret_from_hex(&p.reply_secret).unwrap();
    let purchase = hex::decode(&p.delivery_id).unwrap().try_into().unwrap();
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

/// The purchase ids of the payments a `close_expired` gave up.
fn ids(lost: &[Loss]) -> Vec<String> {
    lost.iter().map(|l| l.id.clone()).collect()
}

fn only(found: &[PickedUp]) -> &Pickup {
    assert_eq!(found.len(), 1, "{found:?}");
    &found[0].what
}

#[test]
fn a_settled_purchase_is_delivered_and_claimed_with_no_paste() {
    let server = common::air::server();
    let mut e = env("claim");
    let build = e.buy(&[32, 16, 2]);
    assert_eq!(e.wallet.balance().pending_purchases, 1);
    let settled = e.settle("aa", 50_000, build.payload.clone());
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");

    // the PSP has not written anything yet: the wallet finds nothing and keeps
    // the purchase
    assert_eq!(only(&e.pickup(&server)), &Pickup::NotThere);
    assert_eq!(e.wallet.balance().pending_purchases, 1);

    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass_shared(&e.psp.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    assert!(e.psp.records.lock().unwrap().undelivered().is_empty());

    let found = e.pickup(&server);
    let Pickup::Claimed(claimed) = only(&found) else {
        panic!("expected the notes to be claimed: {found:?}");
    };
    assert_eq!(claimed.claim.claimed_units, 50);
    assert_eq!(claimed.claim.still_pending, 0);
    assert!(!claimed.key_kept, "nothing is owed, so the key is dropped");
    let balance = e.wallet.balance();
    assert_eq!((balance.psp, balance.pending_purchases), (50, 0));
    assert!(e.wallet.open_replies().is_empty());

    // every note passes the mint's own check
    let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
    for stored in e.wallet.notes() {
        e.psp
            .state
            .logic
            .lock()
            .unwrap()
            .verify_note(&MintInput {
                amount: Amount::from_units(stored.amount),
                note: stored.note,
                spend_signature: dummy,
            })
            .unwrap();
    }

    // it was saved: a reopened wallet is the same
    let reopened = open_wallet(&e.wallet_path).unwrap();
    assert_eq!(reopened.balance(), e.wallet.balance());
    assert_eq!(Env::note_ids(&reopened), Env::note_ids(&e.wallet));
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn reading_the_same_record_twice_changes_nothing() {
    let server = common::air::server();
    let mut e = env("twice");
    let build = e.buy(&[32, 16, 2]);
    // a copy of the wallet as it was before the pickup (another device, or a
    // restored backup)
    let copy_path = e.dir.join("copy.json");
    fs::copy(&e.wallet_path, &copy_path).unwrap();

    e.settle("aa", 50_000, build.payload);
    let mut deliverer = e.deliverer(&server);
    assert_eq!(
        deliverer
            .pass_shared(&e.psp.records, Instant::now())
            .delivered,
        1
    );

    let found = e.pickup(&server);
    assert!(matches!(only(&found), Pickup::Claimed(_)), "{found:?}");
    let balance = e.wallet.balance();
    let notes = Env::note_ids(&e.wallet);
    assert_eq!(balance.psp, 50);

    // the record is still there (the cell is write-once), and the copy claims the
    // very same notes from it
    let air = e.air(&server);
    let mut copy = open_wallet(&copy_path).unwrap();
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
    let server = common::air::server();
    let mut e = env("reject");
    // 2048 is a power of two the wallet may ask for (it does not know the PSP's
    // largest note), and a size this mint has no key for: it rejects the whole
    // purchase
    let build = e.buy(&[2048]);
    let settled = e.settle("aa", 5_000, build.payload);
    assert!(matches!(settled, Settlement::Rejected(_)), "{settled:?}");

    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass_shared(&e.psp.records, Instant::now());
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
    assert!(!kept.reply_secret.is_empty());
    assert_eq!(kept.open.as_ref(), Some(&open));

    // reading again does not ask the server: it may be down, and the purchase is
    // reported as still open
    let air = e.air(&down(&server));
    let again = psp_pickup(&mut e.wallet, &air, 0).unwrap();
    assert_eq!(only(&again), &Pickup::StillOpen(open.clone()));

    // the open purchase is saved
    let reopened = open_wallet(&e.wallet_path).unwrap();
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
        e.psp
            .records
            .lock()
            .unwrap()
            .forfeit_expired(open.open_until)
            .unwrap(),
        vec!["aa"]
    );
    let lost = e.wallet.close_expired(open.open_until).unwrap();
    assert_eq!(ids(&lost), vec![build.id.clone()]);
    assert_eq!(lost[0].kind, LossKind::Rejected);
    // the user is told it plainly: the payment was forfeited, the funds are lost,
    // and how much
    let said = lost[0].forfeited();
    assert!(
        said.contains("forfeited") && said.contains("lost"),
        "{said}"
    );
    assert!(said.contains("5000 sat, 0.50 USD"), "{said}");
    assert_eq!(e.wallet.balance().pending_purchases, 0);
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.pickup(&server).is_empty());
    let reopened = open_wallet(&e.wallet_path).unwrap();
    assert!(reopened.pending_purchases().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_held_payment_is_delivered_with_what_was_paid_and_closed_with_the_psps_forfeit() {
    let server = common::air::server();
    let mut e = env("held");
    let build = e.buy(&[32, 16, 2]);
    // 10,000 sats is 10 units of the 50 asked: short beyond the target, so nothing
    // is signed and the PSP holds the payment
    let settled = e.settle("aa", 10_000, build.payload);
    assert!(
        matches!(settled, Settlement::PaidUnsettled(_)),
        "{settled:?}"
    );
    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass_shared(&e.psp.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");

    let found = e.pickup(&server);
    let Pickup::Open(held) = only(&found).clone() else {
        panic!("expected an open purchase: {found:?}");
    };
    assert_eq!(held.kind, OpenKind::Held);
    assert_eq!((held.paid_sats, held.paid_cents), (10_000, 100));
    assert_eq!(held.requested_units, 50);
    // what the PSP will issue for the payment, in the rules it stored
    assert_eq!(held.rules.due_units, 10);
    assert!(held.over_under_bps < 0, "short: {}", held.over_under_bps);
    assert_eq!(e.wallet.balance().pending_purchases, 1);
    assert_eq!(e.wallet.balance().psp, 0);

    // one tick before the window closes the PSP has not forfeited it and the
    // wallet keeps the purchase; at the end both let go
    assert!(
        e.psp
            .records
            .lock()
            .unwrap()
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
        e.psp
            .records
            .lock()
            .unwrap()
            .forfeit_expired(held.open_until)
            .unwrap(),
        vec!["aa"]
    );
    let lost = e.wallet.close_expired(held.open_until).unwrap();
    assert_eq!(ids(&lost), vec![build.id.clone()]);
    assert_eq!(lost[0].kind, LossKind::Held);
    assert_eq!(e.wallet.balance().pending_purchases, 0);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_credit_keeps_the_key_until_the_psps_window_for_it_closes() {
    let server = common::air::server();
    let mut e = env("credit");
    let build = e.buy(&[32, 16, 2]);
    // 60,000 sats is 600 cents for 500: 20% over, so 100 cents are credited
    let settled = e.settle("aa", 60_000, build.payload);
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");
    let mut deliverer = e.deliverer(&server);
    assert_eq!(
        deliverer
            .pass_shared(&e.psp.records, Instant::now())
            .delivered,
        1
    );

    let found = e.pickup(&server);
    let Pickup::Claimed(claimed) = only(&found) else {
        panic!("expected the notes to be claimed: {found:?}");
    };
    assert_eq!(claimed.credit_cents, 100);
    assert!(claimed.key_kept);
    assert_eq!(e.wallet.balance().psp, 50);

    // the kept key lasts as long as the PSP's window, which is in the record
    let [kept] = e.wallet.open_replies() else {
        panic!("one key is kept");
    };
    let until = kept.open_until;
    assert!(until > addr::now_secs());
    let record = e.psp.records.lock().unwrap().get("aa").unwrap().open_until;
    assert_eq!(record, Some(until), "the same time the PSP forfeits at");
    assert!(e.wallet.close_expired(until - 1).unwrap().is_empty());
    assert_eq!(e.wallet.open_replies().len(), 1);
    let lost = e.wallet.close_expired(until).unwrap();
    assert_eq!(ids(&lost), vec![build.id]);
    assert_eq!(lost[0].kind, LossKind::Credit);
    assert!(e.wallet.open_replies().is_empty());
    // the notes were claimed, and stay
    assert_eq!(e.wallet.balance().psp, 50);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn with_the_server_down_at_settlement_a_later_retry_delivers_exactly_one_record() {
    let server = common::air::server();
    let mut e = env("retry");
    let build = e.buy(&[32, 16, 2]);
    e.settle("aa", 50_000, build.payload);

    // the AIR server cannot be reached when the payment settles: issuance stands,
    // nothing is delivered
    let mut dead = Deliverer::new(down(&server), 2, e.mint_key.clone());
    let report = dead.pass_shared(&e.psp.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (0, 1), "{report:?}");
    // the next scan is inside the wait: it is left alone
    let report = dead.pass_shared(&e.psp.records, Instant::now());
    assert_eq!((report.failed, report.waiting), (0, 1), "{report:?}");
    assert_eq!(e.psp.records.lock().unwrap().undelivered().len(), 1);
    assert_eq!(only(&e.pickup(&server)), &Pickup::NotThere);
    let sealed = e
        .psp
        .records
        .lock()
        .unwrap()
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
    e.psp.reopen_records();
    let mut deliverer = e.deliverer(&server);
    let report = deliverer.pass_shared(&e.psp.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    // the same bytes were written that were saved the first time
    let delivery = e
        .psp
        .records
        .lock()
        .unwrap()
        .get("aa")
        .unwrap()
        .delivery
        .clone()
        .unwrap();
    assert!(delivery.delivered);
    assert_eq!(delivery.sealed, Some(sealed));
    // nothing is left to do, now or after another restart
    assert_eq!(
        deliverer.pass_shared(&e.psp.records, Instant::now()),
        Report::default()
    );
    e.psp.reopen_records();
    assert_eq!(
        e.deliverer(&server)
            .pass_shared(&e.psp.records, Instant::now()),
        Report::default()
    );

    let found = e.pickup(&server);
    let Pickup::Claimed(claimed) = only(&found) else {
        panic!("expected the notes to be claimed: {found:?}");
    };
    assert_eq!(claimed.claim.claimed_units, 50);
    assert_eq!(e.wallet.balance().psp, 50);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_record_that_is_not_the_psps_or_not_for_this_purchase_is_refused() {
    let server = common::air::server();
    let mut e = env("refused");
    e.buy(&[32, 16, 2]);
    e.buy(&[64]);
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
fn without_air_settings_the_pickup_says_what_is_missing_and_changes_nothing() {
    let mut e = env("no-air");
    e.buy(&[64]);
    let before = e.wallet.balance();
    let err = psp_pickup(&mut e.wallet, &AirSettings::default(), 0).unwrap_err();
    assert!(matches!(err, WalletError::Invalid(_)), "{err:?}");
    assert!(err.to_string().contains("air"), "{err}");
    assert_eq!(e.wallet.balance(), before);
    fs::remove_dir_all(&e.dir).unwrap();
}
