//! A PSP purchase from payment to owed record, against a real `air_server`
//! started in this process: the wallet builds a purchase with a claim key of its
//! own, psp-mint settles it with its real settlement code, its deliverer writes the
//! owed record to the AIR server, and the wallet reads the record from the cell it
//! computes, checks the PSP mint's signature and keeps it (`mint_info::psp_pickup`).
//! The claim itself (AIR kind 15) is in `psp_claim.rs`.
//!
//! The records of one claim key are the cells 0, 1, 2 and so on. The wallet reads
//! them in order, skips a cell that does not open, and stops at the first one that
//! is empty.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of this binary, and the tests take turns on it (see
//! `common/mod.rs`). They are built only with the `air-listener-tests` feature,
//! because the psp-mint they run is a local one that has `delivery`.

mod common;

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ecash_wallet::config::AirSettings;
use ecash_wallet::mint_info::{PickedUp, psp_pickup};
use ecash_wallet::psp::{ClaimStatus, PurchaseBuild};
use ecash_wallet::{Wallet, WalletError};
use psp_mint::delivery::{Deliverer, Report};
use psp_mint::settle::Settlement;
use sp_wire::ServiceDid;
use sp_wire::air_request::KIND_PSP_CLAIM;
use sp_wire::air_request::addr;
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::delivery::{
    self as wire, ClaimTerms, EXPIRY_NOTICE, Outcome, Owed, SEND_PURCHASE_CLAIM, Written,
};
use sp_wire::psp::CLAIM_WINDOW_SECS;
use sp_wire::seal::SecretKey as DidKey;

use common::{FEES, PspMint, open_wallet, scratch};

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

    /// The wallet buys PSP from this mint.
    fn buy(&mut self) -> PurchaseBuild {
        self.wallet
            .build_psp_payload(&self.mint_key.public_key())
            .unwrap()
    }

    /// The mint opens a payment of `sats` carrying `payload` and settles it at 6
    /// confirmations, at $10,000 a BTC: 1,000 sats are 1 unit.
    fn settle(&mut self, txid: &str, sats: u64, payload: Vec<u8>) -> Settlement {
        self.psp.pay(&self.mint_key, txid, sats, payload)
    }

    fn deliverer(&self, server: &ServerRef) -> Deliverer {
        Deliverer::new(server.clone(), 3, self.mint_key)
    }

    /// One pass of the deliverer: the owed record that is next for each claim key
    /// is written, and its window opens now.
    fn deliver(&self, server: &ServerRef) -> Report {
        self.deliverer(server)
            .pass_shared(&self.psp.records, Instant::now(), addr::now_secs())
    }

    /// The wallet looks for its records once.
    fn pickup(&mut self, server: &ServerRef) -> Vec<PickedUp> {
        let air = self.air(server);
        psp_pickup(&mut self.wallet, &air, 0).unwrap()
    }

    /// The claim DID of the wallet's first purchase.
    fn claim(&self) -> ServiceDid {
        ServiceDid::parse(&self.wallet.claim_keys()[0].claim_did).unwrap()
    }
}

/// Write a record to a cell, as anyone who knew the cell could.
fn plant(server: &ServerRef, cell: &DidKey, sealed: &[u8]) {
    let server = server.clone();
    let cell = *cell;
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

/// What a PSP mint writes for a payment owed `due_units`.
fn owed(txid: &str, due_units: u64) -> Outcome {
    Outcome::Owed(Owed {
        txid: txid.to_string(),
        paid_sats: due_units * 1_000,
        value_units: due_units,
        terms: ClaimTerms {
            send: SEND_PURCHASE_CLAIM.to_string(),
            kind: KIND_PSP_CLAIM,
            due_units,
            read_prepaid_units: 0,
            write_prepaid_units: 0,
            window_secs: CLAIM_WINDOW_SECS,
            max_attempts: 2,
            on_expiry: EXPIRY_NOTICE.to_string(),
        },
    })
}

/// A snapshot of the whole wallet file, for comparing before and after.
fn snapshot_text(w: &Wallet) -> String {
    serde_json::to_string(&w.snapshot()).unwrap()
}

#[test]
fn a_paid_purchase_is_delivered_and_picked_up_with_no_paste() {
    let server = common::air::server();
    let mut e = env("pickup");
    let build = e.buy();
    assert_eq!(e.wallet.balance().claim_keys, 1);

    // not paid yet: the wallet waits, and says there is no record
    let found = e.pickup(&server);
    assert_eq!(found.len(), 1);
    assert!(found[0].no_record && found[0].new.is_empty() && found[0].skipped.is_empty());

    // 100,000 sats are 100 units; the fees (two reads of 1 and a write of 2) come
    // off: 100 - 4 = 96 are owed
    let settled = e.settle("aa", 100_000, build.payload.clone());
    assert!(matches!(settled, Settlement::Owed(_)), "{settled:?}");
    assert_eq!(100 - FEES, 96);
    let report = e.deliver(&server);
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");

    let found = e.pickup(&server);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, build.id);
    assert!(!found[0].no_record && found[0].skipped.is_empty());
    let [record] = &found[0].new[..] else {
        panic!("one new record: {found:?}");
    };
    assert_eq!(
        (record.index, record.txid.as_str(), record.due_units),
        (0, "aa", 96)
    );
    assert_eq!((record.window_secs, record.max_attempts), (2_592_000, 2));
    assert_eq!(
        record.record_id,
        hex::encode(wire::record_id(&e.claim(), 0))
    );
    assert!(record.request.is_none() && !record.done);
    let open = e.wallet.open_claims(record.first_read_at);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].status, ClaimStatus::Due);
    assert_eq!(open[0].window_ends, record.first_read_at + 2_592_000);

    // Nothing was built at buy time and nothing is built by reading: no claim, no
    // notes, no AIR request.
    assert!(e.wallet.air_requests().is_empty());
    assert!(e.wallet.notes().is_empty());

    // Reading the same cell again changes nothing, and neither does a reopen.
    let before = snapshot_text(&e.wallet);
    let found = e.pickup(&server);
    assert!(found[0].new.is_empty() && found[0].skipped.is_empty() && !found[0].no_record);
    assert_eq!(snapshot_text(&e.wallet), before);
    let reopened = open_wallet(&e.wallet_path).unwrap();
    assert_eq!(snapshot_text(&reopened), before);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn two_payments_to_one_claim_key_are_two_records_read_in_order() {
    let server = common::air::server();
    let mut e = env("two");
    let build = e.buy();
    // 100 - 4 = 96 and 50 - 4 = 46 units
    e.settle("aa", 100_000, build.payload.clone());
    e.settle("bb", 50_000, build.payload.clone());

    // the deliverer writes the next record of a claim key in each pass
    let report = e.deliver(&server);
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    let found = e.pickup(&server);
    let [first] = &found[0].new[..] else {
        panic!("the first record only: {found:?}");
    };
    assert_eq!(
        (first.index, first.txid.as_str(), first.due_units),
        (0, "aa", 96)
    );
    assert_eq!(e.wallet.claim_keys()[0].next_index, 1);

    let report = e.deliver(&server);
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    assert_eq!(e.deliver(&server), Report::default());
    let found = e.pickup(&server);
    let [second] = &found[0].new[..] else {
        panic!("the second record only: {found:?}");
    };
    assert_eq!(
        (second.index, second.txid.as_str(), second.due_units),
        (1, "bb", 46)
    );
    let key = &e.wallet.claim_keys()[0];
    assert_eq!((key.next_index, key.records.len()), (2, 2));

    // 96 + 46 = 142 units are open, in the order they were written
    let open = e.wallet.open_claims(first.first_read_at);
    let owed_units: Vec<(u32, u64)> = open.iter().map(|o| (o.index, o.due_units)).collect();
    assert_eq!(owed_units, vec![(0, 96), (1, 46)]);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_cell_that_does_not_open_is_skipped_and_the_next_one_is_still_read() {
    let server = common::air::server();
    let mut e = env("bad-cell");
    let build = e.buy();
    e.settle("aa", 100_000, build.payload);
    assert_eq!(e.deliver(&server).delivered, 1);
    let claim = e.claim();

    // cell 1: a record signed by someone other than the PSP mint
    let impostor = DidKey::new();
    let forged =
        wire::build_record(&impostor, &claim, 1, &owed("zz", 5), addr::now_secs()).unwrap();
    // planted in the PSP mint's cell 1 (build_record put it under the impostor's)
    let cell_1 = wire::owed_secret(&addr::key_to_did(&e.mint_key.public_key()), &claim, 1);
    plant(&server, &cell_1, &forged.sealed);
    // cell 2: a good record, signed by the PSP mint
    let good =
        wire::build_record(&e.mint_key, &claim, 2, &owed("cc", 7), addr::now_secs()).unwrap();
    plant(&server, &good.cell, &good.sealed);

    let found = e.pickup(&server);
    let indexes: Vec<u32> = found[0].new.iter().map(|r| r.index).collect();
    assert_eq!(indexes, vec![0, 2]);
    assert_eq!(found[0].skipped.len(), 1);
    assert_eq!(found[0].skipped[0].0, 1);
    assert!(
        found[0].skipped[0].1.contains("was not accepted"),
        "{:?}",
        found[0].skipped
    );
    let key = &e.wallet.claim_keys()[0];
    assert_eq!(key.next_index, 3);
    assert_eq!(key.records.len(), 2);

    // the skipped cell is not read again
    let found = e.pickup(&server);
    assert!(found[0].new.is_empty() && found[0].skipped.is_empty());
    assert_eq!(e.wallet.claim_keys()[0].next_index, 3);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn with_the_server_down_at_settlement_a_later_retry_delivers_exactly_one_record() {
    let server = common::air::server();
    let mut e = env("retry");
    let build = e.buy();
    e.settle("aa", 100_000, build.payload);

    // the AIR server cannot be reached when the payment settles: the payment
    // stands, nothing is delivered
    let mut dead = Deliverer::new(down(&server), 2, e.mint_key);
    let report = dead.pass_shared(&e.psp.records, Instant::now(), addr::now_secs());
    assert_eq!((report.delivered, report.failed), (0, 1), "{report:?}");
    // the next scan is inside the wait: it is left alone
    let report = dead.pass_shared(&e.psp.records, Instant::now(), addr::now_secs());
    assert_eq!((report.failed, report.waiting), (0, 1), "{report:?}");
    assert_eq!(e.psp.records.lock().unwrap().undelivered().len(), 1);
    let found = e.pickup(&server);
    assert!(found[0].no_record && found[0].new.is_empty());
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
    let report = deliverer.pass_shared(&e.psp.records, Instant::now(), addr::now_secs());
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
        deliverer.pass_shared(&e.psp.records, Instant::now(), addr::now_secs()),
        Report::default()
    );
    e.psp.reopen_records();
    assert_eq!(e.deliver(&server), Report::default());

    let found = e.pickup(&server);
    assert_eq!(found[0].new.len(), 1);
    assert_eq!(found[0].new[0].due_units, 96);
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn without_air_settings_the_pickup_says_what_is_missing_and_changes_nothing() {
    let mut e = env("no-air");
    e.buy();
    let before = snapshot_text(&e.wallet);
    let err = psp_pickup(&mut e.wallet, &AirSettings::default(), 0).unwrap_err();
    assert!(matches!(err, WalletError::Invalid(_)), "{err:?}");
    assert!(err.to_string().contains("air"), "{err}");
    assert_eq!(snapshot_text(&e.wallet), before);
    fs::remove_dir_all(&e.dir).unwrap();
}
