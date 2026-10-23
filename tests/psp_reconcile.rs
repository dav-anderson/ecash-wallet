//! The wallet's side of PSP reconciliation (AIR kind 15), against a real
//! psp-mint: the payment is settled by psp-mint's real settlement
//! (`settle::settle_ruled` under the policy `Config::policy` gives), its
//! deliverer writes the record to a real `air_server`, and the wallet's request is
//! answered by the PSP's own listener (`server::air_served_with`, which runs
//! `reconcile::reconcile`). The wallet's requests and the PSP's answers are the
//! real types, written with `serde_json::to_vec` by the code under test.
//!
//! What a payment the PSP holds, rejects or owes a credit for comes to when the
//! wallet starts (`mint_info::psp_reconcile`): a corrected request or a credit
//! claim is built by the wallet from the rules in the PSP's first record, saved
//! before it is sent, sent, and its answer applied once; a request the PSP does
//! not answer is sent again as it is; and a payment nothing can settle is
//! reported as lost.
//!
//! The AIR client always dials port 5702, so these tests need that port free (see
//! `common/mod.rs`); one server serves every test of this binary and the tests
//! take turns on it. They are built only with the `air-listener-tests` feature.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use ecash_wallet::air::{Sent, call_with_key};
use ecash_wallet::config::{AirSettings, Party};
use ecash_wallet::mint_info::{
    PickedUp, Pickup, ReconcileReport, Reconciled, psp_close_expired, psp_keysets, psp_nothing_due,
    psp_pickup, psp_reconcile,
};
use ecash_wallet::psp::{Applied, LossKind, PurchaseBuild, ReconcileStatus};
use ecash_wallet::store::{OpenKind, OpenPurchase};
use ecash_wallet::{Wallet, WalletError};
use mint_types::{Amount, MintInput};
use psp_mint::delivery::Deliverer;
use psp_mint::records::PendingReconcile;
use psp_mint::settle::Settlement;
use sp_wire::air_request::delivery::{SEND_CORRECTED_REQUEST, SEND_CREDIT_CLAIM};
use sp_wire::air_request::{KIND_PSP_RECONCILE, addr};
use sp_wire::psp::ReconcileResponse;
use sp_wire::seal::SecretKey as DidKey;

use common::air::{PspUp, slot_is_empty};
use common::{PspMint, T0 as T, open_wallet, scratch};

const H: u64 = 3600;
const LATER: u64 = 100;

/// One PSP mint with its listener, and one wallet, in a folder of their own.
struct Env {
    dir: PathBuf,
    psp: PspUp,
    wallet_path: PathBuf,
    wallet: Wallet,
}

fn env(name: &str) -> Env {
    let dir = scratch(&format!("psp-reconcile-{name}"));
    let psp = PspUp::start(&dir.join("psp"), T);
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

fn now() -> u64 {
    addr::now_secs()
}

impl Env {
    /// The wallet buys PSP outputs of these sizes from this PSP.
    fn buy(&mut self, outputs: &[u64]) -> PurchaseBuild {
        self.wallet
            .build_psp_payload(outputs, &self.psp.at.key().public_key())
            .unwrap()
    }

    /// The PSP opens a payment of `sats` carrying `payload` and settles it.
    fn pay(&self, txid: &str, sats: u64, payload: Vec<u8>) -> Settlement {
        self.psp.pay(&self.psp.at.key(), txid, sats, payload)
    }

    /// The PSP's deliverer writes the record of every settled payment.
    fn deliver(&self) {
        let mut deliverer = Deliverer::new((*self.psp.at.server).clone(), 3, self.psp.at.key());
        let report = deliverer.pass_shared(&self.psp.records, Instant::now());
        assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    }

    /// Ten seconds a try, three tries.
    fn air(&self) -> AirSettings {
        self.psp.air()
    }

    /// One try of `secs` seconds: for the calls the PSP is not going to answer.
    fn air_once(&self, secs: u64) -> AirSettings {
        self.psp.at.air(secs, 1)
    }

    fn pickup(&mut self) -> Vec<PickedUp> {
        let air = self.air();
        psp_pickup(&mut self.wallet, &air, 0).unwrap()
    }

    /// A payment of `sats` for a purchase of `outputs` that the PSP holds (it is
    /// short beyond the target), delivered and picked up: the open purchase.
    fn held(&mut self, txid: &str, outputs: &[u64], sats: u64) -> (PurchaseBuild, OpenPurchase) {
        let build = self.buy(outputs);
        let settled = self.pay(txid, sats, build.payload.clone());
        assert!(
            matches!(settled, Settlement::PaidUnsettled(_)),
            "{settled:?}"
        );
        self.deliver();
        let open = open_of(&self.pickup());
        assert_eq!(open.kind, OpenKind::Held);
        (build, open)
    }

    /// Whether every note of the wallet passes the PSP's own check.
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

    /// The PSP's record of a payment.
    fn record(&self, txid: &str) -> psp_mint::records::Record {
        self.psp
            .records
            .lock()
            .unwrap()
            .get(txid)
            .expect("the PSP has the payment")
            .clone()
    }

    /// The request the wallet saved for the purchase `id`, whichever kind of
    /// payment it is.
    fn saved_hash(&self, id: &str) -> Option<String> {
        let purchase = self
            .wallet
            .pending_purchases()
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.open.as_ref())
            .map(|o| o.reconcile.request.clone());
        let credit = self
            .wallet
            .open_replies()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.reconcile.request.clone());
        purchase.or(credit).flatten().map(|r| r.hash)
    }

    fn file_text(&self) -> String {
        fs::read_to_string(&self.wallet_path).unwrap()
    }
}

fn open_of(found: &[PickedUp]) -> OpenPurchase {
    assert_eq!(found.len(), 1, "{found:?}");
    match &found[0].what {
        Pickup::Open(open) => open.clone(),
        other => panic!("expected an open purchase: {other:?}"),
    }
}

fn claimed_of(found: &[PickedUp]) -> ecash_wallet::psp::Claimed {
    assert_eq!(found.len(), 1, "{found:?}");
    match &found[0].what {
        Pickup::Claimed(claimed) => claimed.clone(),
        other => panic!("expected the notes to be claimed: {other:?}"),
    }
}

fn settled_of(reports: &[ReconcileReport]) -> ecash_wallet::psp::Settled {
    assert_eq!(reports.len(), 1, "{reports:?}");
    match &reports[0].what {
        Reconciled::Settled(settled) => settled.clone(),
        other => panic!("expected the payment to be settled: {other:?}"),
    }
}

/// The wallet file as the real type serialises, for comparing before and after.
fn snapshot_text(w: &Wallet) -> String {
    serde_json::to_string(&w.snapshot()).unwrap()
}

fn note_ids(w: &Wallet) -> BTreeSet<String> {
    w.notes().iter().map(|n| n.id()).collect()
}

/// The PSP's answer to the request the wallet saved for `id`, read by someone
/// else: a throwaway wallet sends the very bytes with a reply key of its own, so
/// the PSP accepts the request and the answer goes to a reader that is not the
/// wallet under test. Returns the answer as the PSP made it.
fn answer_read_elsewhere(e: &Env, body: &[u8]) -> ReconcileResponse {
    let mut other = open_wallet(&e.dir.join("elsewhere.json")).unwrap();
    let air = e.air();
    let sent = call_with_key(
        &mut other,
        &air,
        Party::Psp,
        KIND_PSP_RECONCILE,
        body,
        &DidKey::new(),
    )
    .unwrap();
    let Sent::Answered(verified) = sent else {
        panic!("the PSP did not answer an accepted request");
    };
    assert!(!verified.refused());
    serde_json::from_slice(verified.body()).unwrap()
}

// ---------------------------------------------------------------- T1

#[test]
fn a_held_payment_is_settled_by_the_corrected_request_the_wallet_sends_by_itself() {
    let mut e = env("held");
    // 20,000 sats is 20 units of the 50 asked: short beyond the target, so the PSP
    // holds the payment and says what a corrected request must carry
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    assert_eq!(open.rules.send, SEND_CORRECTED_REQUEST);
    assert_eq!(open.rules.due_units, 20);
    let secret = e.wallet.pending_purchases()[0].reply_secret.clone();
    let [due] = &e.wallet.open_reconciliations(now())[..] else {
        panic!("one open payment");
    };
    assert_eq!((due.state, due.due_units), (ReconcileStatus::Due, 20));
    assert!(
        e.file_text().contains(&secret),
        "the key is kept until then"
    );

    // the wallet starts: no command, no paste
    let air = e.air();
    let reports = psp_reconcile(&mut e.wallet, &air).unwrap();
    let settled = settled_of(&reports);
    assert_eq!(reports[0].id, build.id);
    assert_eq!((settled.units, settled.credit), (20, false));

    // notes worth what the rules said, that the PSP's own check accepts
    assert_eq!(e.wallet.balance().psp, 20);
    assert_eq!(settled.claimed.len(), e.wallet.notes().len());
    e.notes_pass_the_mint();
    // the purchase, its key, its request and the AIR request that carried it are gone
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert!(e.wallet.open_reconciliations(now()).is_empty());
    assert!(!e.file_text().contains(&secret), "the key is deleted");
    // the PSP settled the payment once, with the request the wallet sent
    let record = e.record("aa");
    assert!(record.settled_at.is_some() && record.reconciled.is_some());
    assert_eq!((record.attempts, record.refusals.len()), (0, 0));

    // it was saved: a reopened wallet is the same, and the next start sends nothing
    let reopened = open_wallet(&e.wallet_path).unwrap();
    assert_eq!(reopened.balance(), e.wallet.balance());
    assert_eq!(note_ids(&reopened), note_ids(&e.wallet));
    let version = e.wallet.version();
    assert!(psp_reconcile(&mut e.wallet, &air).unwrap().is_empty());
    assert_eq!(e.wallet.version(), version);
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T2

#[test]
fn a_rejected_payment_with_a_readable_payload_is_settled_the_same_way() {
    let mut e = env("rejected");
    // 2048 is a size this PSP has no key for: it rejects the whole purchase, and
    // since the payload is readable it names the reply key and says what a
    // corrected request carries: what 100,000 sats buy, 100 units
    let build = e.buy(&[2048]);
    let settled = e.pay("aa", 100_000, build.payload.clone());
    assert!(matches!(settled, Settlement::Rejected(_)), "{settled:?}");
    e.deliver();
    let open = open_of(&e.pickup());
    assert_eq!(open.kind, OpenKind::Rejected);
    assert_eq!(open.rules.send, SEND_CORRECTED_REQUEST);
    assert_eq!(open.rules.due_units, 100);

    let air = e.air();
    let reports = psp_reconcile(&mut e.wallet, &air).unwrap();
    let settled = settled_of(&reports);
    assert_eq!((settled.units, settled.credit), (100, false));
    // the outputs are powers of two, none above the PSP's largest note (1024)
    assert_eq!(e.wallet.balance().psp, 100);
    assert!(e.wallet.notes().iter().all(|n| n.amount <= 1024));
    e.notes_pass_the_mint();
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert!(e.record("aa").reconciled.is_some());
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T3

#[test]
fn a_credit_is_claimed_for_exactly_what_the_rules_say_and_its_pending_line_goes() {
    let mut e = env("credit");
    let build = e.buy(&[32, 16, 2]);
    // 60,000 sats is 600 cents for 500: 20% over, so 100 cents are credited
    let settled = e.pay("aa", 60_000, build.payload.clone());
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");
    e.deliver();
    let claimed = claimed_of(&e.pickup());
    assert_eq!((claimed.credit_cents, claimed.key_kept), (100, true));
    assert_eq!(e.wallet.balance().psp, 50);

    // the line the balance shows before: the units the claim will issue, and the
    // exact cents
    let line = e.wallet.pending_psp_credit(now()).balance_line();
    let line = line.expect("a credit is owed");
    assert!(line.starts_with("10 PSP (1.00 USD) (pending)"), "{line}");
    let [reply] = e.wallet.open_replies() else {
        panic!("the key is kept");
    };
    assert_eq!(reply.rules.as_ref().unwrap().send, SEND_CREDIT_CLAIM);
    assert_eq!(reply.rules.as_ref().unwrap().due_units, 10);
    let secret = reply.reply_secret.clone();

    let air = e.air();
    let reports = psp_reconcile(&mut e.wallet, &air).unwrap();
    let settled = settled_of(&reports);
    assert_eq!((settled.units, settled.credit), (10, true));
    assert_eq!(e.wallet.balance().psp, 60);
    e.notes_pass_the_mint();
    // the line, the key and the request are gone
    assert_eq!(e.wallet.pending_psp_credit(now()).balance_line(), None);
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert!(!e.file_text().contains(&secret));
    let record = e.record("aa");
    assert_eq!(record.credit_claimed_cents, 100);
    assert!(record.settled_at.is_some());
    // and it does not come back after a restart
    let reopened = open_wallet(&e.wallet_path).unwrap();
    assert_eq!(reopened.pending_psp_credit(now()).balance_line(), None);
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T4

#[test]
fn when_the_fees_take_everything_nothing_is_sent_and_the_user_is_told_the_funds_are_lost() {
    let dir = scratch("psp-reconcile-nothing-due");
    // a fee of 20 units on a payment worth 20: nothing is due
    let mut config = psp_mint::config::Config::defaults("");
    config.reconciliation_fee = 20;
    let psp = PspUp::start_configured(&dir.join("psp"), T, config);
    let mut e = env_on(dir, psp);
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    assert_eq!(open.rules.due_units, 0);
    assert_eq!(open.rules.reconciliation_fee_units, 20);
    let [listed] = &e.wallet.open_reconciliations(now())[..] else {
        panic!("one open payment");
    };
    assert_eq!(listed.state, ReconcileStatus::NothingDue);

    let air = e.air();
    let reports = psp_reconcile(&mut e.wallet, &air).unwrap();
    let [report] = &reports[..] else {
        panic!("one report: {reports:?}");
    };
    assert_eq!(report.id, build.id);
    let Reconciled::NothingDue(loss) = &report.what else {
        panic!("expected nothing due: {report:?}");
    };
    // the user is told that the fees take the whole amount, that the payment is
    // forfeited at open_until and the funds are lost, with the date and the amount
    let said = loss.nothing_due();
    assert!(said.contains("fees take the whole amount"), "{said}");
    assert!(said.contains("20000 sat, 2.00 USD"), "{said}");
    assert!(said.contains("forfeits the payment"), "{said}");
    assert!(said.contains("the funds are lost"), "{said}");
    assert!(
        said.contains(&ecash_wallet::date::format_utc(open.open_until)),
        "{said}"
    );
    assert_eq!(loss.kind, LossKind::Held);

    // nothing was built, saved or written to the PSP's request mailbox (read
    // once: a request would be in its first slot)
    assert!(e.wallet.air_requests().is_empty());
    assert_eq!(e.saved_hash(&build.id), None);
    assert!(
        slot_is_empty(&e.psp.at.server, &e.psp.at.did, 0),
        "nothing went to the PSP"
    );
    assert_eq!(e.wallet.balance().psp, 0);

    // said once: the next start says nothing and still sends nothing
    assert!(psp_reconcile(&mut e.wallet, &air).unwrap().is_empty());
    assert!(psp_nothing_due(&mut e.wallet).unwrap().is_empty());
    let reopened = open_wallet(&e.wallet_path).unwrap();
    assert!(reopened.open_reconciliations(now())[0].told_lost);
    assert!(slot_is_empty(&e.psp.at.server, &e.psp.at.did, 0));

    // the window closes: the key is deleted, and the loss is said again, plainly
    let lost = e.wallet.close_expired(open.open_until).unwrap();
    assert_eq!(lost.len(), 1);
    assert!(lost[0].forfeited().contains("the funds are lost"));
    assert!(e.wallet.pending_purchases().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T5

#[test]
fn a_lost_reply_is_met_with_the_identical_request_and_the_notes_are_stored_once() {
    let mut e = env("lost-reply");
    let (build, _) = e.held("aa", &[32, 16, 2], 20_000);
    let air = e.air();
    let keysets = psp_keysets(&mut e.wallet, &air).unwrap();
    let built = e
        .wallet
        .build_reconcile(&build.id, &keysets, now())
        .unwrap();
    assert_eq!(built.attempt, 1);
    assert_eq!(e.saved_hash(&build.id), Some(built.hash.clone()));

    // the PSP accepts the request and answers it, but the answer goes to a reader
    // that is not this wallet: this wallet never reads it
    let elsewhere = answer_read_elsewhere(&e, &built.body);
    assert_eq!(elsewhere.issued_units, 20);
    let record = e.record("aa");
    assert_eq!(record.reconciled.as_ref().unwrap().hash, built.hash);
    assert_eq!(e.wallet.balance().psp, 0, "the wallet has not heard");
    assert_eq!(e.wallet.pending_purchases().len(), 1);

    // the next run sends the request it saved, not another one, and gets the
    // PSP's stored answer
    let reports = psp_reconcile(&mut e.wallet, &air).unwrap();
    let settled = settled_of(&reports);
    assert_eq!(settled.units, 20);
    let after = e.record("aa");
    assert_eq!(
        after.reconciled.as_ref().unwrap().hash,
        built.hash,
        "the PSP holds the answer of the request the wallet built"
    );
    assert_eq!((after.attempts, after.refusals.len()), (0, 0));
    // the notes are stored once: 20 units, as many notes as the request had
    // outputs, and every one is a note the PSP signed
    assert_eq!(e.wallet.balance().psp, 20);
    assert_eq!(e.wallet.notes().len(), 2, "20 units are a 16 and a 4");
    e.notes_pass_the_mint();
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.air_requests().is_empty());

    // another start: nothing is pending, nothing is sent, nothing changes
    let version = e.wallet.version();
    assert!(psp_reconcile(&mut e.wallet, &air).unwrap().is_empty());
    assert_eq!(e.wallet.version(), version);
    assert_eq!(e.wallet.balance().psp, 20);
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T6

#[test]
fn a_request_whose_keyset_left_the_live_set_gets_one_second_attempt_on_the_current_one() {
    let mut e = env("rotation-race");
    // The first issuance starts the mint's rotation clock (at `T`): its first set
    // rotates an hour after it.
    e.psp.note(1);
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    assert_eq!(open.rules.max_attempts, 2);
    let air = e.air();
    let first = psp_keysets(&mut e.wallet, &air).unwrap();
    let built = e.wallet.build_reconcile(&build.id, &first, now()).unwrap();
    assert_eq!(
        (built.attempt, built.request.keyset.as_str()),
        (1, &*first.current)
    );

    // the PSP rotates twice before the request is sent: the keyset it names is
    // neither the current one nor the previous one any more
    e.psp.set_clock(T + H + LATER);
    let middle = psp_keysets(&mut e.wallet, &air).unwrap();
    assert_eq!(middle.previous.as_deref(), Some(first.current.as_str()));
    e.psp.set_clock(T + 2 * H + LATER);
    let last = psp_keysets(&mut e.wallet, &air).unwrap();
    assert!(!ecash_wallet::psp::keyset_is_live(&last, &first.current));

    // The PSP refuses the request in the saved bytes (a counted attempt, no
    // reply), so the wallet reads the keysets, sees the keyset has left, and
    // sends the one second request on the current one.
    let once = e.air_once(3);
    let reports = psp_reconcile(&mut e.wallet, &once).unwrap();
    let settled = settled_of(&reports);
    assert_eq!(settled.units, 20);
    assert_eq!(e.wallet.balance().psp, 20);
    e.notes_pass_the_mint();
    let record = e.record("aa");
    // the PSP counted the refused request and accepted the second: two requests,
    // the most the rules allow, and no more
    assert_eq!(record.refusals.len(), 1);
    assert_eq!(record.attempts, 1);
    let accepted = record.reconciled.as_ref().unwrap();
    assert_ne!(accepted.hash, built.hash);
    assert_eq!(accepted.response.keyset, last.current);
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn after_the_second_request_no_other_is_built_and_an_unanswered_one_is_reported_lost() {
    let mut e = env("no-third");
    e.psp.note(1);
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    let air = e.air();
    let first = psp_keysets(&mut e.wallet, &air).unwrap();
    let one = e.wallet.build_reconcile(&build.id, &first, now()).unwrap();
    e.psp.set_clock(T + H + LATER);
    psp_keysets(&mut e.wallet, &air).unwrap();
    e.psp.set_clock(T + 2 * H + LATER);
    let last = psp_keysets(&mut e.wallet, &air).unwrap();
    let two = e.wallet.build_reconcile(&build.id, &last, now()).unwrap();
    assert_eq!(two.attempt, 2);
    assert_ne!(two.hash, one.hash);
    assert_eq!(two.request.keyset, last.current);

    // a third is refused, however the PSP's keysets look, and nothing changes
    let before = snapshot_text(&e.wallet);
    let err = e
        .wallet
        .build_reconcile(&build.id, &last, now())
        .unwrap_err();
    assert!(matches!(err, WalletError::Invalid(_)), "{err:?}");
    assert_eq!(snapshot_text(&e.wallet), before);

    // The PSP stops answering. The saved request is sent as it is, nothing more
    // is built, and the user is told once that the request was not accepted and
    // the payment is lost at open_until.
    e.psp.at.silence();
    let once = e.air_once(1);
    let reports = psp_reconcile(&mut e.wallet, &once).unwrap();
    let [report] = &reports[..] else {
        panic!("one report: {reports:?}");
    };
    let Reconciled::NotAccepted { loss, attempts } = &report.what else {
        panic!("expected the request not to be accepted: {report:?}");
    };
    assert_eq!(*attempts, 2);
    let said = loss.not_accepted(*attempts);
    assert!(said.contains("not accepted"), "{said}");
    assert!(said.contains("the funds are lost"), "{said}");
    assert!(said.contains("20000 sat, 2.00 USD"), "{said}");
    assert!(
        said.contains(&ecash_wallet::date::format_utc(open.open_until)),
        "{said}"
    );
    assert_eq!(e.saved_hash(&build.id), Some(two.hash.clone()));

    // said once; the identical request is still sent, and still nothing is built
    let reports = psp_reconcile(&mut e.wallet, &once).unwrap();
    assert!(
        matches!(&reports[..], [r] if matches!(r.what, Reconciled::Waiting { attempts: 2, .. })),
        "{reports:?}"
    );
    assert_eq!(e.saved_hash(&build.id), Some(two.hash));
    assert_eq!(e.wallet.pending_purchases().len(), 1);
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T8

#[test]
fn an_answer_that_does_not_match_the_request_is_a_mint_error_and_stores_nothing() {
    let mut e = env("bad-answer");
    let (build, _) = e.held("aa", &[32, 16, 2], 20_000);
    let air = e.air();
    let keysets = psp_keysets(&mut e.wallet, &air).unwrap();
    let built = e
        .wallet
        .build_reconcile(&build.id, &keysets, now())
        .unwrap();
    assert_eq!(built.request.outputs.len(), 2, "20 is 16 and 4");
    let real = answer_read_elsewhere(&e, &built.body);
    let secret = e.wallet.pending_purchases()[0].reply_secret.clone();

    let mut wrong_id = real.clone();
    wrong_id.keyset = format!("{}00", real.keyset);
    let mut wrong_keys = real.clone();
    let key_set = wrong_keys.keysets.keysets.get_mut(&real.keyset).unwrap();
    let (a, b) = {
        let mut keys = key_set.values().copied();
        (keys.next().unwrap(), keys.next().unwrap())
    };
    let first = *key_set.keys().next().unwrap();
    assert_ne!(a, b);
    key_set.insert(first, b);
    let mut too_few = real.clone();
    too_few.signatures.pop();
    let mut too_many = real.clone();
    too_many.signatures.push(real.signatures[0].clone());
    let mut out_of_order = real.clone();
    out_of_order.signatures.swap(0, 1);
    let mut wrong_total = real.clone();
    wrong_total.issued_units += 1;
    let mut short_total = real.clone();
    short_total.issued_units -= 1;

    let before = snapshot_text(&e.wallet);
    let version = e.wallet.version();
    for (what, bad) in [
        ("a keyset id the PSP does not list", wrong_id),
        ("keys that do not hash to the keyset id", wrong_keys),
        ("one signature too few", too_few),
        ("one signature too many", too_many),
        ("signatures out of the request's order", out_of_order),
        ("an issued total above what is due", wrong_total),
        ("an issued total below what is due", short_total),
    ] {
        let err = e.wallet.apply_reconcile(&build.id, &bad).unwrap_err();
        assert!(matches!(err, WalletError::Mint(_)), "{what}: {err:?}");
        // nothing was stored, the key and the request are kept
        assert_eq!(snapshot_text(&e.wallet), before, "{what}");
        assert_eq!(e.wallet.version(), version, "{what}");
        assert_eq!(e.wallet.balance().psp, 0, "{what}");
        assert!(e.file_text().contains(&secret), "{what}");
        assert_eq!(e.saved_hash(&build.id), Some(built.hash.clone()), "{what}");
    }

    // the genuine answer settles it, and applying it again changes nothing
    let applied = e.wallet.apply_reconcile(&build.id, &real).unwrap();
    let Applied::Settled(settled) = applied else {
        panic!("the real answer settles the payment");
    };
    assert_eq!(settled.units, 20);
    e.notes_pass_the_mint();
    let ids = note_ids(&e.wallet);
    let after = snapshot_text(&e.wallet);
    assert_eq!(
        e.wallet.apply_reconcile(&build.id, &real).unwrap(),
        Applied::AlreadyDone
    );
    assert_eq!(snapshot_text(&e.wallet), after);
    assert_eq!(note_ids(&e.wallet), ids);
    assert_eq!(e.wallet.balance().psp, 20);
    assert!(!e.file_text().contains(&secret));
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T9

#[test]
fn when_the_window_closes_the_user_is_told_the_funds_are_lost_and_the_key_is_deleted() {
    let mut e = env("window");
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    // a request was built (and the PSP never accepted it), so there is a saved
    // request and an AIR request to delete with the key
    let air = e.air();
    let keysets = psp_keysets(&mut e.wallet, &air).unwrap();
    e.wallet
        .build_reconcile(&build.id, &keysets, now())
        .unwrap();
    assert_eq!(e.wallet.air_requests().len(), 1);
    let secret = e.wallet.pending_purchases()[0].reply_secret.clone();

    // inside the window nothing is deleted, nothing is written, nothing is said
    let version = e.wallet.version();
    assert!(
        e.wallet
            .close_expired(open.open_until - 1)
            .unwrap()
            .is_empty()
    );
    assert_eq!(e.wallet.version(), version);
    assert!(e.file_text().contains(&secret));

    // the PSP forfeits the payment at the end of the window, and so does the wallet
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
    let [loss] = &lost[..] else {
        panic!("one payment closed");
    };
    assert_eq!(
        (loss.id.as_str(), loss.kind),
        (build.id.as_str(), LossKind::Held)
    );
    let said = loss.forfeited();
    assert!(said.contains("forfeited"), "{said}");
    assert!(said.contains("the funds are lost"), "{said}");
    assert!(said.contains("20000 sat, 2.00 USD"), "{said}");
    assert!(said.contains(&ecash_wallet::date::format_utc(open.open_until)));
    // the key, the purchase, the saved request and the AIR request are deleted
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert!(!e.file_text().contains(&secret));
    assert!(e.wallet.open_reconciliations(now()).is_empty());
    // and nothing is left to send
    assert!(psp_reconcile(&mut e.wallet, &air).unwrap().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_credit_nobody_claimed_is_reported_lost_with_its_amount_when_the_window_closes() {
    let mut e = env("credit-window");
    let build = e.buy(&[32, 16, 2]);
    // 8 cents of credit would round down to nothing; this one is 100 cents
    let settled = e.pay("aa", 60_000, build.payload.clone());
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");
    e.deliver();
    claimed_of(&e.pickup());
    let secret = e.wallet.open_replies()[0].reply_secret.clone();
    let until = e.wallet.open_replies()[0].open_until;
    assert!(e.wallet.close_expired(until - 1).unwrap().is_empty());
    let lost = e.wallet.close_expired(until).unwrap();
    let [loss] = &lost[..] else {
        panic!("one credit closed");
    };
    assert_eq!(loss.kind, LossKind::Credit);
    let said = loss.forfeited();
    assert!(said.contains("the funds are lost"), "{said}");
    assert!(said.contains("a credit of 1.00 USD"), "{said}");
    assert!(e.wallet.open_replies().is_empty());
    assert!(!e.file_text().contains(&secret));
    // the notes that were claimed stay
    assert_eq!(e.wallet.balance().psp, 50);
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- a resumed request

#[test]
fn a_resumed_request_signed_by_the_current_keyset_is_accepted() {
    let mut e = env("resumed");
    e.psp.note(1);
    let (build, _) = e.held("aa", &[32, 16, 2], 20_000);
    let air = e.air();
    let first = psp_keysets(&mut e.wallet, &air).unwrap();
    let built = e.wallet.build_reconcile(&build.id, &first, now()).unwrap();
    assert_eq!(built.request.keyset, first.current);
    let secret = e.wallet.pending_purchases()[0].reply_secret.clone();

    // The PSP took the request and saved its pending record, and did not answer
    // (it went down before it signed): the record is the one `reconcile` writes
    // for an accepted request, put in the PSP's records.
    let mut pending = e.record("aa");
    assert!(pending.reconcile_pending.is_none());
    pending.reconcile_pending = Some(PendingReconcile {
        hash: built.hash.clone(),
        epoch: 0,
        keyset: built.request.keyset.clone(),
        nonces: built
            .request
            .outputs
            .iter()
            .map(|o| hex::encode(o.blind_nonce.0.serialize()))
            .collect(),
    });
    e.psp.records.lock().unwrap().put("aa", pending).unwrap();

    // The PSP rotates twice: the request's keyset is deleted.
    e.psp.set_clock(T + H + LATER);
    psp_keysets(&mut e.wallet, &air).unwrap();
    e.psp.set_clock(T + 2 * H + LATER);
    let last = psp_keysets(&mut e.wallet, &air).unwrap();
    assert!(!ecash_wallet::psp::keyset_is_live(&last, &first.current));

    // The wallet sends the saved request again. It is the PSP's resumed request,
    // so the PSP signs it with its current keyset and names that keyset in the
    // reply, and the wallet takes the answer.
    let reports = psp_reconcile(&mut e.wallet, &air).unwrap();
    let settled = settled_of(&reports);
    assert_eq!((settled.units, settled.credit), (20, false));
    let record = e.record("aa");
    let accepted = record.reconciled.as_ref().unwrap();
    assert_eq!(accepted.hash, built.hash);
    assert_eq!(accepted.response.keyset, last.current);
    assert_ne!(accepted.response.keyset, first.current);
    assert!(record.reconcile_pending.is_none());
    assert_eq!((record.attempts, record.refusals.len()), (0, 0));
    assert_eq!(e.wallet.balance().psp, 20);
    for stored in e.wallet.notes() {
        assert_eq!(e.wallet.psp_keyset_of(stored).unwrap(), last.current);
    }
    e.notes_pass_the_mint();
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert_eq!(e.saved_hash(&build.id), None);
    assert!(!e.file_text().contains(&secret));
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- the close

#[test]
fn a_saved_request_whose_answer_was_lost_is_sent_one_last_time_when_the_window_closes() {
    let mut e = env("close-answered");
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    let air = e.air();
    let keysets = psp_keysets(&mut e.wallet, &air).unwrap();
    let built = e
        .wallet
        .build_reconcile(&build.id, &keysets, now())
        .unwrap();
    let secret = e.wallet.pending_purchases()[0].reply_secret.clone();

    // the PSP accepts the request and answers, but not to this wallet
    let elsewhere = answer_read_elsewhere(&e, &built.body);
    assert_eq!(elsewhere.issued_units, 20);
    assert_eq!(e.wallet.balance().psp, 0, "the wallet has not heard");

    // the clock passes open_until: before it deletes the payment, the wallet sends
    // the saved request, identical, and the PSP answers it from what it stored
    let closed = psp_close_expired(&mut e.wallet, &air, open.open_until).unwrap();
    let settled = settled_of(&closed.reports);
    assert_eq!(closed.reports[0].id, build.id);
    assert_eq!((settled.units, settled.credit), (20, false));
    assert!(closed.lost.is_empty(), "no loss is reported");
    assert_eq!(e.wallet.balance().psp, 20);
    assert_eq!(e.wallet.notes().len(), 2, "20 units are a 16 and a 4");
    e.notes_pass_the_mint();
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.open_replies().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert_eq!(e.saved_hash(&build.id), None);
    assert!(!e.file_text().contains(&secret));
    let record = e.record("aa");
    assert_eq!(record.reconciled.as_ref().unwrap().hash, built.hash);
    assert_eq!((record.attempts, record.refusals.len()), (0, 0));
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_saved_request_nobody_answers_is_sent_once_at_the_close_and_the_payment_is_reported_lost() {
    let mut e = env("close-silent");
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    let air = e.air();
    let keysets = psp_keysets(&mut e.wallet, &air).unwrap();
    e.wallet
        .build_reconcile(&build.id, &keysets, now())
        .unwrap();
    let secret = e.wallet.pending_purchases()[0].reply_secret.clone();
    assert!(e.saved_hash(&build.id).is_some());

    // The PSP stops answering. So far one request has gone to it: the keysets
    // read, in slot 0.
    e.psp.at.silence();
    assert!(!slot_is_empty(&e.psp.at.server, &e.psp.at.did, 0));
    assert!(slot_is_empty(&e.psp.at.server, &e.psp.at.did, 1));

    // the clock passes open_until: the saved request is sent once, with one try,
    // nobody answers, and the payment is deleted and reported lost
    let once = e.air_once(1);
    let closed = psp_close_expired(&mut e.wallet, &once, open.open_until).unwrap();
    assert!(closed.reports.is_empty(), "{:?}", closed.reports);
    let [loss] = &closed.lost[..] else {
        panic!("one payment lost: {:?}", closed.lost);
    };
    assert_eq!(
        (loss.id.as_str(), loss.kind),
        (build.id.as_str(), LossKind::Held)
    );
    let said = loss.forfeited();
    assert!(said.contains("forfeited"), "{said}");
    assert!(said.contains("the funds are lost"), "{said}");
    assert!(said.contains("20000 sat, 2.00 USD"), "{said}");
    assert!(said.contains(&ecash_wallet::date::format_utc(open.open_until)));
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert!(!e.file_text().contains(&secret));

    // Exactly one request was sent at the close, in slot 1: no keysets were read
    // to build another request, and none was sent again.
    assert!(!slot_is_empty(&e.psp.at.server, &e.psp.at.did, 1));
    assert!(slot_is_empty(&e.psp.at.server, &e.psp.at.did, 2));
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_payment_whose_last_resend_cannot_be_sent_is_kept_and_one_for_another_psp_is_deleted() {
    let mut e = env("close-not-sent");
    let (build, open) = e.held("aa", &[32, 16, 2], 20_000);
    let air = e.air();
    let keysets = psp_keysets(&mut e.wallet, &air).unwrap();
    let built = e
        .wallet
        .build_reconcile(&build.id, &keysets, now())
        .unwrap();
    let secret = e.wallet.pending_purchases()[0].reply_secret.clone();
    // one request has gone to the PSP so far: the keysets read, in slot 0
    assert!(!slot_is_empty(&e.psp.at.server, &e.psp.at.did, 0));
    assert!(slot_is_empty(&e.psp.at.server, &e.psp.at.did, 1));

    // The window has closed, and the AIR settings lack the PSP's address, so the
    // saved request cannot be sent. The payment is not deleted: it is named as
    // not sent, and the wallet, its key and its saved request are as they were.
    let mut no_address = e.air();
    no_address.server = String::new();
    no_address.host = String::new();
    let before = snapshot_text(&e.wallet);
    let closed = psp_close_expired(&mut e.wallet, &no_address, open.open_until).unwrap();
    assert!(closed.reports.is_empty(), "{:?}", closed.reports);
    assert!(closed.lost.is_empty(), "{:?}", closed.lost);
    let [kept] = &closed.kept[..] else {
        panic!("one payment kept: {:?}", closed.kept);
    };
    assert_eq!(kept.id, build.id);
    let Reconciled::NotSent(why) = &kept.what else {
        panic!("expected the payment to be named as not sent: {kept:?}");
    };
    assert!(why.contains("air.server"), "{why}");
    assert_eq!(snapshot_text(&e.wallet), before);
    assert_eq!(e.wallet.pending_purchases().len(), 1);
    assert!(e.file_text().contains(&secret));
    assert_eq!(e.saved_hash(&build.id), Some(built.hash.clone()));
    assert!(
        slot_is_empty(&e.psp.at.server, &e.psp.at.did, 1),
        "nothing was sent"
    );

    // With the real settings the same close sends the saved request and settles it.
    let closed = psp_close_expired(&mut e.wallet, &air, open.open_until).unwrap();
    let settled = settled_of(&closed.reports);
    assert_eq!((settled.units, settled.credit), (20, false));
    assert!(closed.kept.is_empty() && closed.lost.is_empty());
    assert_eq!(e.wallet.balance().psp, 20);
    e.notes_pass_the_mint();
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.air_requests().is_empty());
    assert!(!e.file_text().contains(&secret));
    assert_eq!(e.record("aa").reconciled.as_ref().unwrap().hash, built.hash);
    assert!(!slot_is_empty(&e.psp.at.server, &e.psp.at.did, 1));
    assert!(slot_is_empty(&e.psp.at.server, &e.psp.at.did, 2));

    // A second payment, sealed to another PSP than air.psp_did, with a saved
    // request (built on the keysets read above; it is never sent to that PSP).
    let other = PspMint::open_at(&e.dir.join("psp2"), T);
    let other_key = DidKey::new();
    let other_did = addr::key_to_did(&other_key.public_key());
    let second = e
        .wallet
        .build_psp_payload(&[32, 16, 2], &other_key.public_key())
        .unwrap();
    let settled = other.pay(&other_key, "bb", 20_000, second.payload.clone());
    assert!(
        matches!(settled, Settlement::PaidUnsettled(_)),
        "{settled:?}"
    );
    let mut deliverer = Deliverer::new((*e.psp.at.server).clone(), 3, other_key.clone());
    let report = deliverer.pass_shared(&other.records, Instant::now());
    assert_eq!((report.delivered, report.failed), (1, 0), "{report:?}");
    let found = e.pickup();
    let Some(Pickup::Open(second_open)) = found
        .iter()
        .find(|p| p.id == second.id)
        .map(|p| p.what.clone())
    else {
        panic!("the second purchase is open: {found:?}");
    };
    e.wallet
        .build_reconcile(&second.id, &keysets, now())
        .unwrap();
    assert!(e.saved_hash(&second.id).is_some());

    // The close deletes it and reports it lost, and sends nothing to either PSP.
    let closed = psp_close_expired(&mut e.wallet, &air, second_open.open_until).unwrap();
    assert!(closed.reports.is_empty(), "{:?}", closed.reports);
    assert!(closed.kept.is_empty(), "{:?}", closed.kept);
    let [loss] = &closed.lost[..] else {
        panic!("one payment lost: {:?}", closed.lost);
    };
    assert_eq!(
        (loss.id.as_str(), loss.kind),
        (second.id.as_str(), LossKind::Held)
    );
    assert!(loss.forfeited().contains("the funds are lost"));
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(slot_is_empty(&e.psp.at.server, &e.psp.at.did, 2));
    assert!(slot_is_empty(&e.psp.at.server, &other_did, 0));
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_payment_with_no_saved_request_is_deleted_at_the_close_with_nothing_sent() {
    let mut e = env("close-no-request");
    let build = e.buy(&[32, 16, 2]);
    // 60,000 sats is 100 cents over: a credit nobody claimed, with no request built
    let settled = e.pay("aa", 60_000, build.payload.clone());
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");
    e.deliver();
    claimed_of(&e.pickup());
    let [reply] = e.wallet.open_replies() else {
        panic!("the key is kept");
    };
    let (until, secret) = (reply.open_until, reply.reply_secret.clone());
    assert!(reply.reconcile.request.is_none(), "no request was built");

    let air = e.air();
    let closed = psp_close_expired(&mut e.wallet, &air, until).unwrap();
    assert!(closed.reports.is_empty(), "{:?}", closed.reports);
    let [loss] = &closed.lost[..] else {
        panic!("one credit lost: {:?}", closed.lost);
    };
    assert_eq!(loss.kind, LossKind::Credit);
    let said = loss.forfeited();
    assert!(said.contains("the funds are lost"), "{said}");
    assert!(said.contains("a credit of 1.00 USD"), "{said}");
    assert!(e.wallet.open_replies().is_empty());
    assert!(!e.file_text().contains(&secret));
    assert_eq!(e.wallet.balance().psp, 50);
    // nothing was written to the PSP's request mailbox (read once)
    assert!(
        slot_is_empty(&e.psp.at.server, &e.psp.at.did, 0),
        "nothing went to the PSP"
    );
    fs::remove_dir_all(&e.dir).unwrap();
}

// ---------------------------------------------------------------- T12

#[test]
fn a_request_one_copy_built_is_the_one_the_other_copy_sends_and_the_notes_are_the_same() {
    let mut e = env("merge-request");
    let (build, _) = e.held("aa", &[32, 16, 2], 20_000);
    // a second copy of the wallet (another device, or a restored backup), taken
    // before any request was built
    let copy_path = e.dir.join("copy.json");
    fs::copy(&e.wallet_path, &copy_path).unwrap();
    let mut copy = open_wallet(&copy_path).unwrap();

    let air = e.air();
    let keysets = psp_keysets(&mut e.wallet, &air).unwrap();
    let built = e
        .wallet
        .build_reconcile(&build.id, &keysets, now())
        .unwrap();

    // the merge brings the request to the copy that had none, so the two copies do
    // not each build one
    assert_eq!(
        copy.pending_purchases()[0]
            .open
            .as_ref()
            .unwrap()
            .reconcile
            .attempts,
        0
    );
    copy.merge_from(&e.wallet.snapshot()).unwrap();
    let merged = copy.pending_purchases()[0].open.as_ref().unwrap();
    assert_eq!(merged.reconcile.attempts, 1);
    assert_eq!(merged.reconcile.request.as_ref().unwrap().hash, built.hash);
    // a copy that builds its own request after the merge is refused
    let err = copy
        .build_reconcile(&build.id, &keysets, now())
        .unwrap_err();
    assert!(matches!(err, WalletError::Invalid(_)), "{err:?}");

    // the first copy settles the payment
    let settled = settled_of(&psp_reconcile(&mut e.wallet, &air).unwrap());
    assert_eq!(settled.units, 20);
    // the other copy has not heard: it sends the same request, the PSP answers from
    // what it stored, and it gets the same notes, not others
    let settled_copy = settled_of(&psp_reconcile(&mut copy, &air).unwrap());
    assert_eq!(settled_copy.claimed, settled.claimed);
    assert_eq!(note_ids(&copy), note_ids(&e.wallet));
    assert_eq!(e.record("aa").refusals.len(), 0);

    // merging them adds no note twice and brings nothing back
    let report = e.wallet.merge_from(&copy.snapshot()).unwrap();
    assert_eq!(report.notes_added, 0);
    assert_eq!(e.wallet.balance().psp, 20);
    assert_eq!(e.wallet.notes().len(), 2, "20 units are a 16 and a 4");
    assert!(e.wallet.pending_purchases().is_empty());
    assert!(e.wallet.open_replies().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}

#[test]
fn a_payment_reconciled_in_one_copy_is_never_brought_back_by_a_copy_that_has_not_heard() {
    let mut e = env("merge-reconciled");
    let build = e.buy(&[32, 16, 2]);
    e.pay("aa", 60_000, build.payload.clone());
    e.deliver();
    claimed_of(&e.pickup());
    // two copies that have the credit open and have not claimed it
    let copy_path = e.dir.join("copy.json");
    let other_path = e.dir.join("other.json");
    fs::copy(&e.wallet_path, &copy_path).unwrap();
    fs::copy(&e.wallet_path, &other_path).unwrap();
    let mut stale = open_wallet(&copy_path).unwrap();
    let behind = open_wallet(&other_path).unwrap();
    assert!(stale.pending_psp_credit(now()).balance_line().is_some());

    let air = e.air();
    let settled = settled_of(&psp_reconcile(&mut e.wallet, &air).unwrap());
    assert_eq!((settled.units, settled.credit), (10, true));
    assert_eq!(e.wallet.balance().psp, 60);

    // the stale copy merges what the claiming copy saved: the credit is gone, and
    // so is its pending line, and the notes it brought are there once
    let report = stale.merge_from(&e.wallet.snapshot()).unwrap();
    assert_eq!(report.notes_added, settled.claimed.len());
    assert!(stale.open_replies().is_empty());
    assert_eq!(stale.pending_psp_credit(now()).balance_line(), None);
    assert_eq!(stale.balance().psp, 60);
    // the other way round: the claiming copy takes the stale copy and the credit
    // does not return
    let report = e.wallet.merge_from(&behind.snapshot()).unwrap();
    assert_eq!(report.notes_added, 0);
    assert!(e.wallet.open_replies().is_empty());
    assert_eq!(e.wallet.pending_psp_credit(now()).balance_line(), None);
    assert_eq!(e.wallet.balance().psp, 60);
    // and nothing is left to send at any start
    assert!(psp_reconcile(&mut stale, &air).unwrap().is_empty());
    fs::remove_dir_all(&e.dir).unwrap();
}
