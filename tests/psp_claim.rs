//! The wallet's side of the PSP purchase claim (AIR kind 15), against a real
//! psp-mint with its fees on (`claim.write_fee` 2, `delivery.read_fee` 1, as in the
//! live system): the payment is settled by psp-mint's real settlement, its
//! deliverer writes the owed record to a real `air_server`, and the wallet's claim
//! is answered by the PSP mint's own listener (`server::air_served_with`, which runs
//! `claim::claim`). The wallet's claims and the PSP mint's answers are the real
//! types, written with `serde_json::to_vec` by the code under test.
//!
//! Nothing is built when the purchase is made. What the wallet reads at its start
//! (`mint_info::psp_pickup`) it claims (`mint_info::psp_claim`): a claim for exactly
//! the units the record says, split into powers of two, saved before it is sent and
//! sent again as the identical bytes when no answer came. The PSP mint answers an
//! accepted claim only, so the cases here are an answer applied once, a lost reply, a
//! keyset that rotated in between, a window that closes with a claim saved, and what
//! a handoff and a backup carry.
//!
//! The AIR client always dials port 5702, so these tests need that port free (see
//! `common/mod.rs`); one server serves every test of this binary and the tests take
//! turns on it. They are built only with the `air-listener-tests` feature.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use ecash_wallet::air::{Sent, call_with_key};
use ecash_wallet::config::{AirSettings, Party};
use ecash_wallet::mint_info::{
    ClaimOutcome, ClaimReport, PickedUp, psp_claim, psp_close_expired, psp_keys, psp_pickup,
    psp_window,
};
use ecash_wallet::psp::{ClaimBuild, LossKind, PurchaseBuild};
use ecash_wallet::{Kind, Wallet};
use mint_types::{Amount, MintInput};
use psp_mint::settle::Settlement;
use sp_wire::air_request::{KIND_PSP_CLAIM, addr};
use sp_wire::psp::{CLAIM_WINDOW_SECS, ClaimResponse};
use sp_wire::seal::SecretKey as DidKey;

use common::air::PspUp;
use common::{FEES, T0, open_wallet, scratch};

const H: u64 = 3600;

/// One PSP mint with its listener, and one wallet, in a folder of their own.
struct Env {
    dir: PathBuf,
    psp: PspUp,
    wallet_path: PathBuf,
    wallet: Wallet,
}

fn env(name: &str) -> Env {
    let dir = scratch(&format!("psp-claim-{name}"));
    let psp = PspUp::start(&dir.join("psp"), T0);
    env_on(dir, psp)
}

fn env_on(dir: PathBuf, psp: PspUp) -> Env {
    let wallet_path = dir.join("wallet.json");
    let wallet = open_wallet(&wallet_path).unwrap();
    Env {
        dir,
        psp,
        wallet_path,
        wallet,
    }
}

impl Env {
    /// Ten seconds a try, three tries.
    fn air(&self) -> AirSettings {
        self.psp.air()
    }

    /// One try of three seconds: for the calls the PSP mint is not going to
    /// answer.
    fn quick(&self) -> AirSettings {
        self.psp.at.air(3, 1)
    }

    fn buy(&mut self) -> PurchaseBuild {
        self.wallet
            .build_psp_payload(&self.psp.at.key().public_key())
            .unwrap()
    }

    /// The PSP mint opens a payment of `sats` carrying `payload`, settles it (6
    /// confirmations, $10,000 a BTC: 1,000 sats are 1 unit) and its deliverer
    /// writes the owed record of every key that has one waiting.
    fn owe(&self, txid: &str, sats: u64, payload: Vec<u8>) {
        let settled = self.psp.pay(&self.psp.at.key(), txid, sats, payload);
        assert!(matches!(settled, Settlement::Owed(_)), "{settled:?}");
        let report = self.psp.deliver();
        assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    }

    fn pickup(&mut self) -> Vec<PickedUp> {
        let air = self.air();
        psp_pickup(&mut self.wallet, &air, 0).unwrap()
    }

    fn claim(&mut self) -> Vec<ClaimReport> {
        let air = self.air();
        psp_claim(&mut self.wallet, &air).unwrap()
    }

    /// Build the claim of record `index` of purchase `id` from the PSP mint's
    /// current keyset and keys, and save it, without sending it.
    fn save_claim(&mut self, id: &str, index: u32) -> ClaimBuild {
        let air = self.air();
        let window = psp_window(&mut self.wallet, &air).unwrap();
        let keys = psp_keys(&mut self.wallet, &air).unwrap();
        self.wallet
            .build_claim(id, index, &window, &keys, addr::now_secs())
            .unwrap()
    }

    /// The PSP mint's record of a payment.
    fn record(&self, txid: &str) -> psp_mint::records::Record {
        self.psp
            .records
            .lock()
            .unwrap()
            .get(txid)
            .expect("the PSP mint has the payment")
            .clone()
    }

    /// Whether every note of the wallet passes the PSP mint's own check.
    fn notes_pass_the_mint(&self) {
        let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
        let logic = self.psp.state.logic.lock().unwrap();
        for stored in self.wallet.notes() {
            logic
                .verify_note(&MintInput {
                    amount: Amount::from_units(stored.amount),
                    note: stored.note,
                    spend_signature: dummy,
                })
                .unwrap();
        }
    }

    /// Send `body` as a claim from a throwaway wallet with a reply key of its own,
    /// so the PSP mint's answer goes to someone who is not the wallet under test
    /// (a reply that never reaches it).
    fn send_elsewhere(&self, body: &[u8]) -> ClaimResponse {
        let mut other = open_wallet(&self.dir.join("elsewhere.json")).unwrap();
        let air = self.air();
        let sent = call_with_key(
            &mut other,
            &air,
            Party::Psp,
            KIND_PSP_CLAIM,
            body,
            &DidKey::new(),
        )
        .unwrap();
        let Sent::Answered(verified) = sent else {
            panic!("the PSP mint did not answer an accepted claim");
        };
        assert!(!verified.refused());
        serde_json::from_slice(verified.body()).unwrap()
    }
}

fn claimed_of(reports: &[ClaimReport]) -> ecash_wallet::psp::Settled {
    assert_eq!(reports.len(), 1, "{reports:?}");
    match &reports[0].what {
        ClaimOutcome::Claimed(settled) => settled.clone(),
        other => panic!("expected the notes to be claimed: {other:?}"),
    }
}

fn sizes(w: &Wallet) -> Vec<u64> {
    let mut sizes: Vec<u64> = w.notes().iter().map(|n| n.amount).collect();
    sizes.sort_unstable();
    sizes
}

fn note_ids(w: &Wallet) -> BTreeSet<String> {
    w.notes().iter().map(|n| n.id()).collect()
}

/// The wallet file as the real type serialises, for comparing before and after.
fn snapshot_text(w: &Wallet) -> String {
    serde_json::to_string(&w.snapshot()).unwrap()
}

// ---------------------------------------------------------------- W1

/// A paid purchase is claimed for exactly what is due. Fails if the fees are not
/// taken off the units owed, the split is not the binary digits of `due_units`, or
/// the PSP mint signs anything other than that total.
#[test]
fn a_paid_purchase_is_claimed_for_exactly_what_is_due_with_the_fees_on() {
    let mut e = env("claim");
    let build = e.buy();
    // 801,000 sats at $10,000 a BTC are 801 units, and the fees (two reads of 1 and
    // a write of 2) come off: 801 - 4 = 797 = 512 + 256 + 16 + 8 + 4 + 1
    e.owe("aa", 801_000, build.payload.clone());
    assert_eq!(801 - FEES, 797);
    let picked = e.pickup();
    assert_eq!(picked[0].new[0].due_units, 797);
    assert_eq!(
        e.psp.records.lock().unwrap().claims().claimed.units,
        0,
        "nothing is signed before the claim"
    );

    let settled = claimed_of(&e.claim());
    assert_eq!((settled.units, settled.claimed.len()), (797, 6));
    assert_eq!(sizes(&e.wallet), vec![1, 4, 8, 16, 256, 512]);
    assert_eq!(e.wallet.balance().psp, 797);
    e.notes_pass_the_mint();
    // The mint has no epoch rotation here, so every note is on epoch 0, the set
    // that signed it.
    for n in e.wallet.notes() {
        assert_eq!(e.wallet.epoch_of(n), Some(0));
        assert_eq!(e.wallet.psp_keyset_of(n).unwrap(), e.psp.keyset());
    }

    // What the PSP mint's /audit says: one payment claimed, for exactly 797 units
    // (the prepaid costs are its revenue: two reads of 1 and a write of 2).
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (1, 797));
    assert_eq!(
        (claims.read_prepaid_units, claims.write_prepaid_units),
        (2, 2)
    );
    assert_eq!(claims.refused_attempts, 0);
    assert_eq!(e.record("aa").attempts, 0);

    // The record is done, its saved claim and the AIR request that carried it are
    // gone, and the key stays until the record's window has closed.
    let key = &e.wallet.claim_keys()[0];
    assert!(key.records[0].done && key.records[0].request.is_none());
    assert_eq!(key.records[0].attempts, 1);
    assert!(e.wallet.air_requests().is_empty());

    // The next start has nothing to claim and changes nothing; so does a reopen.
    let before = snapshot_text(&e.wallet);
    assert!(e.pickup()[0].new.is_empty());
    assert!(e.claim().is_empty());
    assert_eq!(snapshot_text(&e.wallet), before);
    let reopened = open_wallet(&e.wallet_path).unwrap();
    assert_eq!(snapshot_text(&reopened), before);
    fs::remove_dir_all(&e.dir).unwrap();
}

/// A claim sent again, as the identical bytes, gets the same signatures and counts
/// nothing twice, even when the first answer was never seen. Fails if a resend is
/// rebuilt with new blinded outputs, or the PSP mint signs twice.
#[test]
fn a_resend_of_an_accepted_claim_gets_the_same_signatures_and_counts_nothing_twice() {
    let mut e = env("resend");
    let build = e.buy();
    // 100,000 sats are 100 units; 100 - 4 = 96 = 64 + 32
    e.owe("aa", 100_000, build.payload.clone());
    e.pickup();
    let claim = e.save_claim(&build.id, 0);
    assert_eq!(claim.attempt, 1);
    let amounts: Vec<u64> = claim
        .request
        .outputs
        .iter()
        .map(|o| o.amount.units)
        .collect();
    assert_eq!(amounts, vec![64, 32]);

    // The PSP mint takes the claim and its answer goes astray; the same bytes sent
    // again get the stored answer, signature for signature.
    let first = e.send_elsewhere(&claim.body);
    let again = e.send_elsewhere(&claim.body);
    assert_eq!(first, again);
    assert_eq!(first.issued_units, 96);
    assert_eq!(e.record("aa").claimed.unwrap().hash, claim.hash);
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (1, 96));

    // The wallet's own start sends the saved bytes: the stored answer is applied
    // once, and no second claim was built.
    let settled = claimed_of(&e.claim());
    assert_eq!(settled.units, 96);
    assert_eq!(sizes(&e.wallet), vec![32, 64]);
    e.notes_pass_the_mint();
    assert_eq!(e.wallet.claim_keys()[0].records[0].attempts, 1);
    assert_eq!(e.record("aa").attempts, 0);
    assert!(e.wallet.air_requests().is_empty());
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (1, 96));
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- W2

/// Two payments to one claim key are two records, each claimed for its own units
/// with a claim of its own. Fails if the second record is not read, or is claimed
/// with the first one's id.
#[test]
fn two_records_on_one_key_are_each_claimed_for_their_own_units() {
    let mut e = env("two");
    let build = e.buy();
    // 100 - 4 = 96 = 64 + 32, and 50 - 4 = 46 = 32 + 8 + 4 + 2
    e.owe("aa", 100_000, build.payload.clone());
    e.owe("bb", 50_000, build.payload.clone());
    // the deliverer writes the next record of a key in each pass: both are there
    let picked = e.pickup();
    assert_eq!(
        picked[0].new.iter().map(|r| r.index).collect::<Vec<_>>(),
        vec![0, 1]
    );
    let reports = e.claim();
    assert_eq!(reports.len(), 2, "{reports:?}");
    let units: Vec<(u32, u64)> = reports
        .iter()
        .map(|r| match &r.what {
            ClaimOutcome::Claimed(s) => (r.index, s.units),
            other => panic!("expected the notes to be claimed: {other:?}"),
        })
        .collect();
    assert_eq!(units, vec![(0, 96), (1, 46)]);
    // 96 + 46 = 142
    assert_eq!(e.wallet.balance().psp, 142);
    assert_eq!(sizes(&e.wallet), vec![2, 4, 8, 32, 32, 64]);
    e.notes_pass_the_mint();
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (2, 142));
    assert_eq!(e.record("aa").claimed.unwrap().response.issued_units, 96);
    assert_eq!(e.record("bb").claimed.unwrap().response.issued_units, 46);
    let key = &e.wallet.claim_keys()[0];
    assert!(key.records.iter().all(|r| r.done));
    fs::remove_dir_all(&e.dir).unwrap();
}

/// T2. Two purchases, each owed a record, are both picked up (each on a session of
/// its own) and each claimed once for its own units, whatever order the wallet
/// takes them in, and the next start has nothing left to claim. Fails if the
/// per-purchase loop or the shuffle drops a purchase, or claims one twice.
#[test]
fn two_purchases_are_each_picked_up_and_claimed_once_for_their_own_units() {
    let mut e = env("two-purchases");
    let one = e.buy();
    let two = e.buy();
    // 100 - 4 = 96 = 64 + 32, and 50 - 4 = 46 = 32 + 8 + 4 + 2
    e.owe("aa", 100_000, one.payload.clone());
    e.owe("bb", 50_000, two.payload.clone());
    let picked = e.pickup();
    let got: Vec<(&str, Vec<(u32, u64)>)> = picked
        .iter()
        .map(|p| {
            let new = p.new.iter().map(|r| (r.index, r.due_units)).collect();
            (p.id.as_str(), new)
        })
        .collect();
    assert_eq!(
        got,
        vec![
            (one.id.as_str(), vec![(0, 96)]),
            (two.id.as_str(), vec![(0, 46)])
        ]
    );

    let reports = e.claim();
    let mut claimed: Vec<(String, u32, u64)> = reports
        .iter()
        .map(|r| match &r.what {
            ClaimOutcome::Claimed(s) => (r.id.clone(), r.index, s.units),
            other => panic!("expected the notes to be claimed: {other:?}"),
        })
        .collect();
    claimed.sort();
    let mut expected = vec![(one.id.clone(), 0, 96), (two.id.clone(), 0, 46)];
    expected.sort();
    assert_eq!(claimed, expected);
    // 96 + 46 = 142
    assert_eq!(e.wallet.balance().psp, 142);
    assert_eq!(sizes(&e.wallet), vec![2, 4, 8, 32, 32, 64]);
    e.notes_pass_the_mint();
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (2, 142));
    assert_eq!(e.record("aa").claimed.unwrap().response.issued_units, 96);
    assert_eq!(e.record("bb").claimed.unwrap().response.issued_units, 46);
    assert!(e.claim().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- W3

/// A window that closes while a claim is saved and unanswered: the saved bytes are
/// sent one last time, and if the PSP mint answers it the record is settled and
/// not lost. Fails if the key is deleted under the claim.
#[test]
fn the_last_resend_before_a_window_closes_settles_a_claim_whose_answer_was_lost() {
    let mut e = env("last-resend");
    let build = e.buy();
    e.owe("aa", 100_000, build.payload.clone());
    e.pickup();
    e.save_claim(&build.id, 0);

    // The PSP mint is not listening when the claim is sent: no answer.
    e.psp.at.silence();
    let quick = e.quick();
    let reports = psp_claim(&mut e.wallet, &quick).unwrap();
    assert!(
        matches!(reports[0].what, ClaimOutcome::Waiting { attempts: 1, .. }),
        "{reports:?}"
    );
    assert_eq!(e.wallet.balance().psp, 0);
    let claim_requests = |w: &Wallet| {
        w.air_requests()
            .iter()
            .filter(|r| r.kind == KIND_PSP_CLAIM)
            .count()
    };
    assert_eq!(claim_requests(&e.wallet), 1);
    e.psp.at.listen();

    // This wallet's clock reaches the end of the window; the PSP mint's has not:
    // the last resend is answered, and the record is settled, not lost.
    let air = e.air();
    let first_read = e.wallet.claim_keys()[0].records[0].first_read_at;
    let closed = psp_close_expired(&mut e.wallet, &air, first_read + CLAIM_WINDOW_SECS).unwrap();
    assert!(
        closed.lost.is_empty() && closed.kept.is_empty(),
        "{closed:?}"
    );
    let settled = claimed_of(&closed.reports);
    assert_eq!(settled.units, 96);
    assert_eq!(e.wallet.balance().psp, 96);
    assert!(
        e.wallet.claim_keys().is_empty(),
        "the key goes with its last record"
    );
    assert_eq!(claim_requests(&e.wallet), 0);
    e.notes_pass_the_mint();
    fs::remove_dir_all(&e.dir).unwrap();
}

/// ASK 4 (P2-05). Two purchases whose windows close with a saved claim each: the
/// last resends are sent purchase by purchase (in a random order, a pause between
/// them, each on a session of its own), and each settles its own purchase once,
/// with nothing lost and nothing kept. Fails if the per-purchase grouping or the
/// shuffle in `psp_close_expired` drops a purchase (it is then reported lost and
/// its 96 or 46 units are missing) or sends one twice.
#[test]
fn the_last_resends_of_two_purchases_each_settle_their_own_purchase_once() {
    let mut e = env("close-two");
    let one = e.buy();
    let two = e.buy();
    // 100 - 4 = 96 and 50 - 4 = 46 units
    e.owe("aa", 100_000, one.payload.clone());
    e.owe("bb", 50_000, two.payload.clone());
    e.pickup();
    // Both claims are taken by the PSP mint and their answers go astray: the last
    // resend of each is answered from the PSP mint's stored answer.
    let first = e.save_claim(&one.id, 0);
    let second = e.save_claim(&two.id, 0);
    e.send_elsewhere(&first.body);
    e.send_elsewhere(&second.body);
    let first_read: Vec<u64> = e
        .wallet
        .claim_keys()
        .iter()
        .map(|k| k.records[0].first_read_at)
        .collect();
    // one pickup read both, at one time
    assert_eq!(first_read[0], first_read[1]);

    let air = e.air();
    let closed = psp_close_expired(&mut e.wallet, &air, first_read[0] + CLAIM_WINDOW_SECS).unwrap();
    assert!(
        closed.lost.is_empty() && closed.kept.is_empty(),
        "{closed:?}"
    );
    let mut settled: Vec<(String, u32, u64)> = closed
        .reports
        .iter()
        .map(|r| match &r.what {
            ClaimOutcome::Claimed(s) => (r.id.clone(), r.index, s.units),
            other => panic!("expected the last resend to settle: {other:?}"),
        })
        .collect();
    settled.sort();
    let mut expected = vec![(one.id.clone(), 0, 96), (two.id.clone(), 0, 46)];
    expected.sort();
    assert_eq!(settled, expected);
    // 96 + 46 = 142, and both keys go with their last records
    assert_eq!(e.wallet.balance().psp, 142);
    assert!(e.wallet.claim_keys().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    e.notes_pass_the_mint();
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (2, 142));
    fs::remove_dir_all(&e.dir).unwrap();
}

/// ASK 2/7 (P2-05). A start of the real command line with two purchases owed takes
/// ONE of them (`psp_one_purchase`): its record is read and claimed, the other
/// purchase's cell is not read, and stderr says one other purchase is pending and
/// names `claim-psp`. Fails if `startup_psp` goes back to `psp_pickup` and
/// `psp_claim` over every purchase (both are read and claimed: 142 PSP, both
/// `next_index` 1, no line).
#[test]
fn a_start_takes_one_purchase_of_two_and_names_claim_psp() {
    let mut e = env("start-one");
    let one = e.buy();
    let two = e.buy();
    // 100 - 4 = 96 and 50 - 4 = 46 units, both written to the AIR server
    e.owe("aa", 100_000, one.payload.clone());
    e.owe("bb", 50_000, two.payload.clone());
    let air = e.air();
    let psp_did = air.psp_did.expect("the test PSP's DID").to_hex();
    let ran = std::process::Command::new(env!("CARGO_BIN_EXE_ecash-wallet"))
        .env_clear()
        .env("ECASH_WALLET_FILE", &e.wallet_path)
        .env("ECASH_AIR_SERVER", &air.server)
        .env("ECASH_AIR_HOST", &air.host)
        .env("ECASH_AIR_PSP_DID", &psp_did)
        .arg("--regtest")
        .arg("balance")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(ran.status.success(), "{stderr}");

    // The file as the command left it: one key read and claimed, the other not read.
    let after = open_wallet(&e.wallet_path).unwrap();
    let keys = after.claim_keys();
    assert_eq!(keys.len(), 2);
    let read: Vec<&str> = keys
        .iter()
        .filter(|k| k.next_index == 1)
        .map(|k| k.id.as_str())
        .collect();
    let [read] = read[..] else {
        panic!("one purchase is read at a start, not {read:?}: {stderr}");
    };
    let other = keys.iter().find(|k| k.id != read).unwrap();
    assert_eq!((other.next_index, other.records.len()), (0, 0));
    let taken = keys.iter().find(|k| k.id == read).unwrap();
    assert!(taken.records.iter().all(|r| r.done), "{stderr}");
    let (txid, units): (&str, u64) = if read == one.id {
        ("aa", 96)
    } else {
        ("bb", 46)
    };
    assert_eq!(taken.records[0].txid, txid);
    assert_eq!(after.balance().psp, u128::from(units));
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (1, units));
    assert!(
        stderr.contains("1 other purchase(s) are pending") && stderr.contains("claim-psp"),
        "{stderr}"
    );
    fs::remove_dir_all(&e.dir).unwrap();
}

/// A window that closes while a claim is saved and the PSP mint never answers:
/// the payment is reported lost once, with its units, and the key is deleted.
/// Fails if the loss is not said, or the key stays.
#[test]
fn a_window_that_closes_with_no_answer_reports_the_payment_lost_and_deletes_the_key() {
    let mut e = env("lost");
    let build = e.buy();
    e.owe("aa", 100_000, build.payload.clone());
    e.pickup();
    e.save_claim(&build.id, 0);
    e.psp.at.silence();
    let quick = e.quick();
    let first_read = e.wallet.claim_keys()[0].records[0].first_read_at;

    // one second before the window closes nothing is lost and nothing is deleted
    let closed =
        psp_close_expired(&mut e.wallet, &quick, first_read + CLAIM_WINDOW_SECS - 1).unwrap();
    assert!(closed.lost.is_empty() && closed.reports.is_empty() && closed.kept.is_empty());
    assert_eq!(e.wallet.claim_keys().len(), 1);

    let closed = psp_close_expired(&mut e.wallet, &quick, first_read + CLAIM_WINDOW_SECS).unwrap();
    assert_eq!(closed.lost.len(), 1, "{closed:?}");
    let loss = &closed.lost[0];
    assert_eq!(
        (loss.index, loss.due_units, loss.kind, loss.txid.as_str()),
        (0, 96, LossKind::Expired, "aa")
    );
    assert_eq!(loss.window_ends, first_read + CLAIM_WINDOW_SECS);
    assert!(
        loss.forfeited()
            .contains("The PSP mint keeps the payment: the funds are lost (96 PSP)")
    );
    assert!(e.wallet.claim_keys().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert_eq!(e.wallet.balance().psp, 0);
    // said once: the next close finds nothing
    let closed =
        psp_close_expired(&mut e.wallet, &quick, first_read + CLAIM_WINDOW_SECS + 1).unwrap();
    assert!(closed.lost.is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- W4

/// The keyset race: the PSP mint rotated between the claim being built and sent. It
/// answers nothing (the keyset is not current, which is not counted), the wallet
/// asks for the current keyset, builds a new claim on it and sends that. A lost
/// reply with no rotation is resent as the identical bytes. Fails if a claim on a
/// stale keyset is rebuilt without a rotation, or the race uses up an attempt.
#[test]
fn a_keyset_race_builds_a_new_claim_and_costs_no_attempt_and_a_lost_reply_is_resent_identically() {
    let mut e = env("race");
    // A note of the first set starts the mint's rotation clock (at `T0`): its first
    // set rotates an hour after it.
    e.psp.note(1);
    let first = e.buy();
    let air = e.air();
    let old = psp_window(&mut e.wallet, &air).unwrap().current_id;
    // 64 - 4 = 60 = 32 + 16 + 8 + 4
    e.owe("aa", 64_000, first.payload.clone());
    e.pickup();

    // The claim is built on the first set; then the mint rotates.
    let built = e.save_claim(&first.id, 0);
    assert_eq!(built.request.keyset, old);
    e.psp.set_clock(T0 + H);
    let quick = e.quick();
    let reports = psp_claim(&mut e.wallet, &quick).unwrap();
    let settled = claimed_of(&reports);
    assert_eq!(settled.units, 60);
    let new = psp_window(&mut e.wallet, &air).unwrap();
    assert_ne!(new.current_id, old);
    // two claims were built for the record; the PSP mint counted none
    assert_eq!(e.wallet.claim_keys()[0].records[0].attempts, 2);
    assert_eq!(e.record("aa").attempts, 0);
    assert_eq!(e.psp.records.lock().unwrap().claims().refused_attempts, 0);
    // the notes are on the set that signed them, stamped with its epoch
    assert_eq!(sizes(&e.wallet), vec![4, 8, 16, 32]);
    for n in e.wallet.notes() {
        assert_eq!(e.wallet.psp_keyset_of(n).unwrap(), new.current_id);
        assert_eq!(e.wallet.epoch_of(n), Some(1));
    }
    e.notes_pass_the_mint();

    // Lost reply, no rotation: the PSP mint takes the claim for "bb" and the answer
    // never reaches the wallet, which sends those very bytes again.
    let second = e.buy();
    // 50 - 4 = 46
    e.owe("bb", 50_000, second.payload.clone());
    e.pickup();
    let second_claim = e.save_claim(&second.id, 0);
    let _lost = e.send_elsewhere(&second_claim.body);
    let saved = e.wallet.claim_keys()[1].records[0].request.clone().unwrap();
    assert_eq!(saved.body, hex::encode(&second_claim.body));
    let reports = psp_claim(&mut e.wallet, &air).unwrap();
    assert_eq!(claimed_of(&reports).units, 46);
    assert_eq!(e.wallet.claim_keys()[1].records[0].attempts, 1);
    assert_eq!(e.record("bb").claimed.unwrap().hash, second_claim.hash);
    assert_eq!(e.record("bb").attempts, 0);
    assert_eq!(e.wallet.balance().psp, 60 + 46);
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- W13

/// A handoff carries settled notes only; a backup carries both claim keys with
/// their secrets, records and saved claims, and merging it restores them. Fails if
/// a handoff leaks a claim key, a backup drops one, or a merge adds a key twice.
#[test]
fn a_handoff_carries_settled_notes_only_and_a_backup_carries_the_claim_keys() {
    let mut e = env("handoff-backup");
    // purchase one is claimed: 100 - 4 = 96 = 64 + 32
    let one = e.buy();
    e.owe("aa", 100_000, one.payload.clone());
    e.pickup();
    assert_eq!(claimed_of(&e.claim()).units, 96);
    // purchase two is paid and read, and its claim is saved and sent with no answer
    let two = e.buy();
    e.owe("bb", 50_000, two.payload.clone());
    e.pickup();
    let saved = e.save_claim(&two.id, 0);
    e.psp.at.silence();
    let quick = e.quick();
    let reports = psp_claim(&mut e.wallet, &quick).unwrap();
    assert!(
        matches!(reports[0].what, ClaimOutcome::Waiting { .. }),
        "{reports:?}"
    );
    let secrets: Vec<String> = e
        .wallet
        .claim_keys()
        .iter()
        .map(|k| k.claim_secret.clone())
        .collect();
    let dids: Vec<String> = e
        .wallet
        .claim_keys()
        .iter()
        .map(|k| k.claim_did.clone())
        .collect();
    assert_eq!(secrets.len(), 2);
    assert_ne!(secrets[0], secrets[1]);

    // The handoff: 32 PSP of the settled notes, and nothing of either claim key.
    let to = DidKey::new();
    let ids = e.wallet.select_psp_handoff(32).unwrap();
    let out = e
        .wallet
        .export_psp_handoff(&ids, e.psp.at.did, &to.public_key())
        .unwrap();
    let mut user = open_wallet(&e.dir.join("user.json")).unwrap();
    user.import_psp_handoff(&out.text, &to, e.psp.at.did, "dev")
        .unwrap();
    assert_eq!(user.balance().psp, 32);
    assert!(user.claim_keys().is_empty());
    assert!(user.air_requests().is_empty());
    let user_file = snapshot_text(&user);
    for text in secrets.iter().chain(&dids) {
        assert!(!out.text.contains(text.as_str()));
        assert!(
            !user_file.contains(text.as_str()),
            "a claim key reached the receiver"
        );
    }

    // The backup: both keys with their secrets, the records, and the saved claim.
    let backup = e.wallet.snapshot();
    let text = serde_json::to_string(&backup).unwrap();
    for secret in &secrets {
        assert!(text.contains(secret.as_str()));
    }
    assert!(text.contains(&hex::encode(&saved.body)));
    assert_eq!(backup.claim_keys.len(), 2);

    // Merged into a wallet that lacks them, both come back, with their records and
    // their saved claim; merged again, nothing changes.
    let mut fresh = open_wallet(&e.dir.join("fresh.json")).unwrap();
    let report = fresh.merge_from(&backup).unwrap();
    assert_eq!(report.claim_keys_added, 2);
    assert_eq!(fresh.claim_keys(), e.wallet.claim_keys());
    assert!(fresh.claim_keys()[1].records[0].request.is_some());
    assert_eq!(note_ids(&fresh), note_ids(&e.wallet));
    let before = snapshot_text(&fresh);
    let again = fresh.merge_from(&backup).unwrap();
    assert!(!again.changed(), "{again:?}");
    assert_eq!(again.claim_keys_added, 0);
    assert_eq!(snapshot_text(&fresh), before);
    assert!(fresh.balance().psp > 0 && fresh.notes().iter().all(|n| n.kind == Kind::Psp));
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- review fixes

/// A copy saved before a claim was answered is merged in after the claim settled,
/// some of its notes were handed on and the key was closed and deleted: the key
/// and its saved claim come back, the next start resends it, the PSP mint answers
/// from its stored answer with the same signatures, and no note is added: the
/// handed-on one is not brought back and the held one is not doubled. Fails if a
/// spent note comes back or the balance changes.
#[test]
fn a_stale_copy_merged_after_the_close_resends_and_adds_no_spent_note() {
    let mut e = env("stale-copy");
    let build = e.buy();
    // 100 - 4 = 96 = 64 + 32
    e.owe("aa", 100_000, build.payload.clone());
    e.pickup();
    e.save_claim(&build.id, 0);
    let stale = e.wallet.snapshot();
    assert_eq!(claimed_of(&e.claim()).units, 96);
    let first_read = e.wallet.claim_keys()[0].records[0].first_read_at;

    // the 32 leaves in a handoff
    let to = DidKey::new();
    let ids = e.wallet.select_psp_handoff(32).unwrap();
    e.wallet
        .export_psp_handoff(&ids, e.psp.at.did, &to.public_key())
        .unwrap();
    assert_eq!(e.wallet.balance().psp, 64);
    let air = e.air();
    let closed = psp_close_expired(&mut e.wallet, &air, first_read + CLAIM_WINDOW_SECS).unwrap();
    assert!(
        closed.lost.is_empty() && closed.reports.is_empty(),
        "{closed:?}"
    );
    assert!(e.wallet.claim_keys().is_empty());

    e.wallet.merge_from(&stale).unwrap();
    assert_eq!(
        e.wallet.claim_keys().len(),
        1,
        "no tombstone: the key is back"
    );
    assert!(e.wallet.claim_keys()[0].records[0].request.is_some());
    let held = note_ids(&e.wallet);

    // the next start resends the saved claim; the stored answer adds nothing
    assert!(e.claim().is_empty(), "nothing new is claimed");
    assert_eq!(e.wallet.balance().psp, 64);
    assert_eq!(note_ids(&e.wallet), held);
    let r = &e.wallet.claim_keys()[0].records[0];
    assert!(r.done && r.request.is_none() && r.others.is_empty());
    assert!(e.wallet.air_requests().is_empty());
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (1, 96));
    // and the key is closed again
    let closed = psp_close_expired(&mut e.wallet, &air, first_read + CLAIM_WINDOW_SECS).unwrap();
    assert!(closed.lost.is_empty());
    assert!(e.wallet.claim_keys().is_empty());
    e.notes_pass_the_mint();
    fs::remove_dir_all(&e.dir).unwrap();
}

/// Two copies each built a claim for one record, the PSP mint accepted one (its
/// answer lost), and the copies were merged: both saved claims are kept and sent.
/// The PSP mint answers the accepted one from its stored answer and not the other:
/// the record is settled once, with the notes the PSP mint signed, every saved
/// claim of it is dropped, and nothing is said lost. Fails if the merge drops the
/// signed claim, the record is done before one is applied, or a loss is said.
#[test]
fn two_merged_claims_for_one_record_settle_once_with_the_one_the_psp_mint_signed() {
    let mut e = env("two-claims");
    let build = e.buy();
    e.owe("aa", 100_000, build.payload.clone());
    e.pickup();
    let copy_path = e.dir.join("copy.json");
    fs::copy(&e.wallet_path, &copy_path).unwrap();
    // this copy's claim is accepted by the PSP mint; its answer goes astray
    let signed = e.save_claim(&build.id, 0);
    e.send_elsewhere(&signed.body);
    let signed_copy = e.wallet.snapshot();
    // the other copy builds its own claim, which the PSP mint never signs
    let mut copy = open_wallet(&copy_path).unwrap();
    let air = e.air();
    let window = psp_window(&mut copy, &air).unwrap();
    let keys = psp_keys(&mut copy, &air).unwrap();
    let unsigned = copy
        .build_claim(&build.id, 0, &window, &keys, addr::now_secs())
        .unwrap();
    assert_ne!(signed.hash, unsigned.hash);
    let unsigned_copy = copy.snapshot();

    // merged into the copy: its own claim is the main one, the signed one is kept
    // beside it
    copy.merge_from(&e.wallet.snapshot()).unwrap();
    let r = &copy.claim_keys()[0].records[0];
    assert!(!r.done);
    assert_eq!(r.request.as_ref().unwrap().hash, unsigned.hash);
    assert_eq!(r.others.len(), 1);
    assert_eq!(r.others[0].hash, signed.hash);
    let reports = psp_claim(&mut copy, &air).unwrap();
    assert_eq!(claimed_of(&reports).units, 96);
    assert_eq!(copy.balance().psp, 96);
    let r = &copy.claim_keys()[0].records[0];
    assert!(r.done && r.request.is_none() && r.others.is_empty());
    assert!(copy.air_requests().is_empty());
    let claims = e.psp.records.lock().unwrap().claims();
    assert_eq!((claims.claimed.payments, claims.claimed.units), (1, 96));
    let first_read = r.first_read_at;
    let closed = psp_close_expired(&mut copy, &air, first_read + CLAIM_WINDOW_SECS).unwrap();
    assert!(closed.lost.is_empty(), "{closed:?}");

    // merged the other way: the signed claim is the main one; the other is sent
    // first, is not answered, and the main one settles the record
    let mut fresh = open_wallet(&e.dir.join("fresh.json")).unwrap();
    fresh.merge_from(&signed_copy).unwrap();
    fresh.merge_from(&unsigned_copy).unwrap();
    let r = &fresh.claim_keys()[0].records[0];
    assert_eq!(r.request.as_ref().unwrap().hash, signed.hash);
    assert_eq!(r.others[0].hash, unsigned.hash);
    let quick = e.quick();
    let reports = psp_claim(&mut fresh, &quick).unwrap();
    assert_eq!(claimed_of(&reports).units, 96);
    let r = &fresh.claim_keys()[0].records[0];
    assert!(r.done && r.others.is_empty() && r.request.is_none());
    assert!(fresh.air_requests().is_empty());
    let closed = psp_close_expired(&mut fresh, &quick, first_read + CLAIM_WINDOW_SECS).unwrap();
    assert!(closed.lost.is_empty(), "{closed:?}");
    fs::remove_dir_all(&e.dir).unwrap();
}
