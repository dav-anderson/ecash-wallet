//! FSP from the wallet's side, against a real ESP mint and a real fsp-mint in
//! this process: issue, pay, and the automatic rollover across key rotation,
//! with crashes, an offline wallet and a failed swap.
//!
//! The wallet reaches the FSP mint over AIR, as fsp-mint reaches the ESP mint: the
//! ESP mint and fsp-mint each answer on their real AIR listener against a real
//! `air_server` started in this process (see `common/mod.rs`), and the wallet's
//! `[air]` settings carry the `air.fsp` entry of the service. The AIR client
//! always dials port 5702, so these tests need that port free, and they take turns
//! on the one shared server; they are built only with the `air-listener-tests`
//! feature.

mod common;

use std::path::Path;
use std::sync::atomic::Ordering;

use ecash_wallet::air::Party;
use ecash_wallet::config::{AirSettings, FspAir};
use ecash_wallet::keystream::{Failed, KeyMismatch, KeyPolicy, Site};
use ecash_wallet::mint_info::{
    fsp_keys, fsp_rotation, fsp_sync, send_fsp_issue, send_fsp_spend, settle_fsp,
};
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::terms::Terms;
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
use sp_wire::ServiceDid;

use common::air::{Mints, NOW, StreamMode, service};
use common::{open_wallet, scratch};

const DAY: u64 = 86_400;

/// Both mints. The FSP mint first issued at `NOW`; rotation activates 120
/// hours later, every 240 hours.
fn start(dir: &Path) -> Mints {
    Mints::start(dir, "20", "2", None)
}

/// A wallet holding `units` ESP notes for the service (one note each).
fn wallet_with_esp(dir: &Path, mints: &Mints, units: &[u64]) -> Wallet {
    mints.wallet(dir, "wallet", units)
}

fn fsp_units(w: &Wallet) -> u128 {
    w.balance().fsp
}

fn keysets_of(w: &Wallet) -> Vec<String> {
    let mut v: Vec<String> = w
        .notes()
        .iter()
        .filter(|n| n.kind == Kind::Fsp)
        .filter_map(|n| w.fsp_keyset(n).cloned())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn issue_all(w: &mut Wallet, m: &Mints) {
    let req = w.build_fsp_issue(service(), None, 0).unwrap();
    settle_fsp(w, &m.air, &req.hash()).unwrap();
}

#[test]
fn issue_pay_and_the_rollover_when_a_rotation_is_detected() {
    let dir = scratch("rollover");
    let m = start(&dir);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4, 1]);
    fsp_sync(&mut w, &m.air, service()).unwrap();
    issue_all(&mut w, &m);
    assert_eq!(fsp_units(&w), 13);
    assert_eq!(w.balance().esp, 0);
    let req = w.build_fsp_spend(service(), 5, "coffee").unwrap();
    assert_eq!(
        settle_fsp(&mut w, &m.air, &req.hash()).unwrap(),
        "paid 5 FSP"
    );
    assert_eq!(fsp_units(&w), 8);
    let genesis = keysets_of(&w);
    assert_eq!(genesis.len(), 1);
    // Nothing to roll over before the rotation.
    assert!(fsp_sync(&mut w, &m.air, service()).unwrap().log.is_empty());

    // Right at the rotation this wallet waits its staggered delay.
    m.clock.store(NOW + 5 * DAY, Ordering::SeqCst);
    m.fsp.publish();
    let sync = fsp_sync(&mut w, &m.air, service()).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("staggered"))
            || sync.log.iter().any(|l| l.contains("rolled over")),
        "{:?}",
        sync.log
    );
    // The rotation, past the stagger (240 h period: at most 1.2 h): swapped
    // without asking.
    m.clock.store(NOW + 5 * DAY + 2 * 3600, Ordering::SeqCst);
    m.fsp.publish();
    let sync = fsp_sync(&mut w, &m.air, service()).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("rolled over")),
        "{:?}",
        sync.log
    );
    let mint = w.fsp_mints()[&hex::encode(service().serialize())].clone();
    assert_eq!(mint.previous.as_ref(), Some(&genesis[0]));
    assert_eq!(keysets_of(&w), vec![mint.current.clone()]);
    assert_eq!(fsp_units(&w), 8, "a rollover pays nothing");
    let by = w.fsp_by_keyset();
    assert_eq!(by.values().sum::<u128>(), 8);

    // The window, as the wallet reads it.
    let win = fsp_rotation(&mut w, &m.air, service()).unwrap();
    assert!(win.active);
    assert_eq!(win.current.id, mint.current);
    assert_eq!(win.previous.unwrap().retires, Some(NOW + 15 * DAY));
    assert_eq!(win.next_rotation, mint.next_rotation);
}

#[test]
fn a_crash_after_the_mint_answered_is_finished_from_the_stored_answer() {
    let dir = scratch("crash");
    let m = start(&dir);
    let mut w = wallet_with_esp(&dir, &m, &[16]);
    issue_all(&mut w, &m);
    m.clock.store(NOW + 6 * DAY, Ordering::SeqCst);
    m.fsp.publish();
    // Past the rotation and its stagger, so this sync rolls the notes over at once.
    let sync = fsp_sync(&mut w, &m.air, service()).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("rolled over")),
        "{:?}",
        sync.log
    );
    assert_eq!(sync.lost, 0);
    // Now a rotation-free crash: a payment sent, answered by the mint, and the
    // wallet dies before saving.
    let req = w.build_fsp_spend(service(), 4, "").unwrap();
    send_fsp_spend(&mut w, &m.air, service(), &req).unwrap();
    drop(w);
    let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
    assert_eq!(w.pending_fsp().len(), 1);
    let sync = fsp_sync(&mut w, &m.air, service()).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("paid 4 FSP")),
        "{:?}",
        sync.log
    );
    assert!(w.pending_fsp().is_empty());
    assert_eq!(fsp_units(&w), 12, "paid once");

    // A rollover built and never sent (crash before sending): finished later.
    m.clock.store(NOW + 15 * DAY, Ordering::SeqCst);
    m.fsp.publish();
    let keys = fsp_keys(&mut w, &m.air, service()).unwrap();
    w.note_fsp_keys(service(), &keys).unwrap();
    assert!(w.build_fsp_rollover(service()).unwrap().is_some());
    drop(w);
    let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
    fsp_sync(&mut w, &m.air, service()).unwrap();
    assert!(w.pending_fsp().is_empty());
    assert_eq!(keysets_of(&w), vec![keys.current.clone()]);
    assert_eq!(fsp_units(&w), 12);
}

#[test]
fn offline_within_the_window_rolls_over_and_beyond_it_is_lost() {
    let dir = scratch("offline");
    let m = start(&dir);
    let mut w = wallet_with_esp(&dir, &m, &[2, 1]);
    issue_all(&mut w, &m);
    // Back 9 days after activation: the genesis set is previous for 1 more day.
    m.clock.store(NOW + 14 * DAY, Ordering::SeqCst);
    m.fsp.publish();
    let sync = fsp_sync(&mut w, &m.air, service()).unwrap();
    assert_eq!(sync.lost, 0);
    assert_eq!(fsp_units(&w), 3);

    // Another wallet, offline through a whole period after its set retired. (The
    // first pair of mints gives up its turn on the AIR server first.)
    drop(m);
    let dir2 = scratch("offline-lost");
    let m2 = start(&dir2);
    let mut w2 = wallet_with_esp(&dir2, &m2, &[2, 1]);
    issue_all(&mut w2, &m2);
    m2.clock.store(NOW + 15 * DAY, Ordering::SeqCst);
    m2.fsp.publish();
    let sync = fsp_sync(&mut w2, &m2.air, service()).unwrap();
    assert_eq!(sync.lost, 3, "{:?}", sync.log);
    assert_eq!(fsp_units(&w2), 0);
    assert_eq!(w2.lost_fsp().len(), 2);
}

/// An FSP mint that cannot answer a spend now says so in a signed reply (the
/// `5xx` of the HTTP route): the rollover stays pending, and the next
/// connection finishes it.
#[test]
fn a_failed_rollover_is_logged_and_retried_on_the_next_connection() {
    let dir = scratch("retry");
    let m = start(&dir);
    let mut w = wallet_with_esp(&dir, &m, &[4]);
    issue_all(&mut w, &m);
    m.fsp.fail_spend(true);
    m.clock.store(NOW + 6 * DAY, Ordering::SeqCst);
    m.fsp.publish();
    let sync = fsp_sync(&mut w, &m.air, service()).unwrap();
    assert!(
        sync.log
            .iter()
            .any(|l| l.contains("retried on the next connection")),
        "{:?}",
        sync.log
    );
    assert_eq!(w.pending_fsp().len(), 1, "kept for the retry");
    let old = keysets_of(&w);
    m.fsp.fail_spend(false);
    let sync = fsp_sync(&mut w, &m.air, service()).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("rolled over")),
        "{:?}",
        sync.log
    );
    assert!(w.pending_fsp().is_empty());
    assert_ne!(keysets_of(&w), old);
    assert_eq!(fsp_units(&w), 4);
}

/// A spend the mint refuses (a `400`, a signed refusal over AIR) cancels the
/// pending request and frees the notes: nothing happened at the mint.
#[test]
fn a_refused_spend_cancels_the_request_and_frees_the_notes() {
    let dir = scratch("refused");
    // This FSP mint takes memos of at most 8 bytes.
    let m = Mints::start(&dir, "20", "2", Some(8));
    let mut w = wallet_with_esp(&dir, &m, &[8, 4]);
    issue_all(&mut w, &m);
    assert_eq!(fsp_units(&w), 12);
    let req = w
        .build_fsp_spend(service(), 5, "far too long a memo")
        .unwrap();
    assert_eq!(w.pending_fsp().len(), 1);
    let e = settle_fsp(&mut w, &m.air, &req.hash()).unwrap_err();
    assert!(
        matches!(&e, WalletError::Refused(why) if why.contains("memo_too_long")),
        "{e}"
    );
    assert!(w.pending_fsp().is_empty(), "the refusal cancels it");
    assert_eq!(fsp_units(&w), 12, "the notes are free again");
    // And they pay with a memo the mint takes.
    let req = w.build_fsp_spend(service(), 5, "coffee").unwrap();
    assert_eq!(
        settle_fsp(&mut w, &m.air, &req.hash()).unwrap(),
        "paid 5 FSP"
    );
    assert_eq!(fsp_units(&w), 7);
}

/// A payment with notes the mint has already spent (the wallet lost track of
/// that: here it sent a spend, dropped the reply and freed the notes): the mint
/// names every spent note, and the wallet marks them spent and frees the rest
/// instead of choosing the same notes again.
#[test]
fn a_payment_with_spent_notes_marks_them_spent_and_frees_the_rest() {
    let dir = scratch("spent-elsewhere");
    let m = start(&dir);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4, 1]);
    issue_all(&mut w, &m);
    assert_eq!(fsp_units(&w), 13);
    // The mint spends the 8 and the 4; the wallet never hears and frees them.
    let first = w.build_fsp_spend(service(), 12, "first").unwrap();
    ecash_wallet::mint_info::send_fsp_spend(&mut w, &m.air, service(), &first).unwrap();
    w.cancel_fsp(&first.hash()).unwrap();
    assert_eq!(fsp_units(&w), 13, "the wallet still counts them");

    // It tries all three: the 8 and the 4 (positions 0 and 1) are named.
    let second = w.build_fsp_spend(service(), 13, "second").unwrap();
    let e = settle_fsp(&mut w, &m.air, &second.hash()).unwrap_err();
    match &e {
        WalletError::SpentElsewhere { why, inputs } => {
            assert_eq!(inputs, &vec![0, 1]);
            assert!(why.contains("notes 0, 1 are already spent"), "{why}");
            assert!(
                why.contains(
                    "2 note(s) are marked spent in the wallet, 1 other note(s) are free again"
                ),
                "{why}"
            );
        }
        other => panic!("expected SpentElsewhere, got {other:?}"),
    }
    assert!(w.pending_fsp().is_empty());
    let mut spent: Vec<u64> = w.spent_notes().iter().map(|n| n.amount).collect();
    spent.sort_unstable();
    assert_eq!(spent, vec![4, 8]);
    assert_eq!(fsp_units(&w), 1, "only the 1 is left, and it is free");
    assert_eq!(w.balance().spent_elsewhere, 2);
    // The free note pays.
    let last = w.build_fsp_spend(service(), 1, "last").unwrap();
    assert_eq!(
        settle_fsp(&mut w, &m.air, &last.hash()).unwrap(),
        "paid 1 FSP"
    );
    assert_eq!(fsp_units(&w), 0);
}

/// An ESP mint that does not answer fsp-mint leaves the wallet's issue pending
/// (the FSP mint says so in a signed reply, the `502` of the HTTP route); when the
/// ESP mint is back, the retry finishes it, and the ESP is transferred once.
#[test]
fn an_esp_mint_that_does_not_answer_leaves_the_issue_pending_and_the_retry_finishes_it() {
    let dir = scratch("esp-silent");
    // One short try: an ESP mint that is down is found out quickly.
    let m = Mints::start(&dir, "5", "1", None);
    let mut w = wallet_with_esp(&dir, &m, &[2, 4]);
    // A first issue reads and caches the ESP mint's keyset and transfers the 2.
    let first = w.build_fsp_issue(service(), Some(2), 0).unwrap();
    settle_fsp(&mut w, &m.air, &first.hash()).unwrap();
    assert_eq!(fsp_units(&w), 2);
    assert_eq!(m.fsp.state.issues.lock().unwrap().data.kept.len(), 1);

    // The ESP mint goes quiet: the issue of the 4 is not answered.
    m.esp_at.silence();
    let second = w.build_fsp_issue(service(), Some(4), 0).unwrap();
    let id = second.hash();
    let e = settle_fsp(&mut w, &m.air, &id).unwrap_err();
    assert!(
        matches!(&e, WalletError::Mint(why) if why.contains("could not answer FSP issue")),
        "{e}"
    );
    assert_eq!(w.pending_fsp().len(), 1, "the issue is still pending");
    assert_eq!(fsp_units(&w), 2);
    assert_eq!(m.fsp.state.issues.lock().unwrap().data.kept.len(), 1);

    // The ESP mint comes back. The retry is the same request: it finishes, and
    // the FSP mint keeps the 4 once.
    m.esp_at.listen();
    let text = settle_fsp(&mut w, &m.air, &id).unwrap();
    assert!(text.starts_with("issued 4 FSP"), "{text}");
    assert!(w.pending_fsp().is_empty());
    assert_eq!(fsp_units(&w), 6);
    assert_eq!(m.fsp.state.issues.lock().unwrap().data.kept.len(), 2);
    // A third send of the same request (a wallet that lost its answer) gets the
    // stored answer and issues nothing more.
    let again = send_fsp_issue(&mut w, &m.air, service(), &second).unwrap();
    assert_eq!(again.groups.len(), 1);
    assert_eq!(m.fsp.state.issues.lock().unwrap().data.kept.len(), 2);
}

/// Each service has its own mint: a service with no `air.fsp` entry is refused
/// before anything is sent, and the error names the setting.
#[test]
fn a_service_with_no_air_fsp_entry_is_refused_naming_the_setting() {
    let dir = scratch("no-entry");
    let m = start(&dir);
    let mut w = wallet_with_esp(&dir, &m, &[4]);
    // No entry at all, and the PSP's and the ESP's server set: that is not the FSP's.
    let none = AirSettings {
        server: m.esp_at.server.name.clone(),
        host: m.esp_at.server.host.clone(),
        ..Default::default()
    };
    for (what, e) in [
        ("keys", fsp_keys(&mut w, &none, service()).map(|_| ())),
        (
            "rotation",
            fsp_rotation(&mut w, &none, service()).map(|_| ()),
        ),
        ("sync", fsp_sync(&mut w, &none, service()).map(|_| ())),
    ] {
        let e = e.unwrap_err();
        assert!(
            matches!(&e, WalletError::Invalid(_))
                && e.to_string().contains("air.fsp")
                && e.to_string().contains(&service().to_hex()),
            "{what}: {e}"
        );
    }
    let req = w.build_fsp_issue(service(), None, 0).unwrap();
    let e = settle_fsp(&mut w, &none, &req.hash()).unwrap_err();
    assert!(e.to_string().contains("air.fsp"), "{e}");
    assert_eq!(w.pending_fsp().len(), 1, "nothing was sent: still pending");
    // An entry for another service is not this service's.
    let other = ecash_wallet::config::FspAir {
        service: ServiceDid::from(Keypair::new(SECP256K1, &mut OsRng).public_key()),
        ..m.air.fsp[0].clone()
    };
    let mut elsewhere = m.air.clone();
    elsewhere.fsp = vec![other];
    let e = fsp_keys(&mut w, &elsewhere, service()).unwrap_err();
    assert!(e.to_string().contains("air.fsp"), "{e}");
    // With the entry it goes through.
    settle_fsp(&mut w, &m.air, &req.hash()).unwrap();
    assert_eq!(fsp_units(&w), 4);

    // The settings themselves say the same. Even with the PSP's and the ESP's
    // server set, there is no FSP address without the entry.
    let e = none.fsp_for(service()).unwrap_err();
    assert!(
        e.contains("air.fsp") && e.contains("ECASH_AIR_FSP") && e.contains(&service().to_hex()),
        "{e}"
    );
    let e = Party::Fsp(service()).address(&none).unwrap_err();
    assert!(e.contains("air.fsp"), "{e}");
    // The PSP and the ESP still go through air.server and air.host.
    assert_eq!(
        Party::Psp.address(&none).unwrap(),
        (none.server.clone(), none.host.clone())
    );
    // With the entry, the FSP mint's address is the entry's, and its DID the
    // service's.
    let at = service().to_hex();
    let mut entered = none.clone();
    entered
        .fsp
        .push(FspAir::parse(&format!("{at}@{at}@10.0.0.9")).unwrap());
    assert_eq!(
        Party::Fsp(service()).address(&entered).unwrap(),
        (at.clone(), "10.0.0.9".to_string())
    );
    assert_eq!(Party::Fsp(service()).did(&entered), service());
    assert_eq!(Party::Fsp(service()).setting(), "air.fsp");
}

/// The command line says the same: no entry, a refusal that names `air.fsp`, and
/// no `--fsp-url` any more.
#[test]
fn the_command_refuses_a_service_with_no_entry_and_has_no_fsp_url() {
    let dir = scratch("command");
    let run = |args: &[&str], env: &[(&str, &str)]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_ecash-wallet"))
            .env_clear()
            .env("ECASH_WALLET_FILE", dir.join("wallet.json"))
            .envs(env.iter().copied())
            .args(["--regtest"])
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    let did = service().to_hex();
    for command in ["sync", "issue", "pay --units 1"] {
        let mut args = vec!["fsp"];
        args.extend(command.split(' '));
        args.extend(["--service", did.as_str()]);
        let out = run(&args, &[]);
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(!out.status.success(), "fsp {command} went through: {err}");
        assert!(
            err.contains("air.fsp") && err.contains(&did),
            "{command}: {err}"
        );
    }
    let out = run(&["fsp-window", "--service", did.as_str()], &[]);
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success() && err.contains("air.fsp"), "{err}");
    // The old flag and variable are gone: the flag is refused, the variable does nothing.
    let out = run(
        &[
            "fsp",
            "sync",
            "--service",
            did.as_str(),
            "--fsp-url",
            "http://127.0.0.1:3200",
        ],
        &[],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("--fsp-url") || err.contains("air.fsp"),
        "{err}"
    );
    let help = String::from_utf8_lossy(&run(&["--help"], &[]).stdout).to_string();
    assert!(
        !help.contains("--fsp-url") && !help.contains("ECASH_FSP_URL"),
        "{help}"
    );
    assert!(help.contains("air.fsp"), "{help}");
}

#[test]
fn the_esp_schedule_reads_the_wallets_notes() {
    let dir = scratch("schedule");
    let m = start(&dir);
    let w = wallet_with_esp(&dir, &m, &[8, 2]);
    let day = Terms::new_at(service(), NOW).redeemable_after_day;
    let s = w.esp_schedule(day - 1, Some(day));
    assert_eq!((s.mature_now, s.by, s.total), (0, Some((day, 10)), 10));
    assert_eq!(s.months.values().sum::<u128>(), 10);
    assert_eq!(w.esp_schedule(day, None).mature_now, 10);
}

// ---------------------------------------------------------------- the key check

/// The policy the tests set: the blacklist on or off, the cap as it is by default.
fn policy(blacklist: bool) -> KeyPolicy {
    KeyPolicy {
        blacklist_on_key_mismatch: blacklist,
        blacklist_max: 1000,
    }
}

/// The error of a call whose reply failed the key check.
fn mismatch_of(e: WalletError) -> Box<KeyMismatch> {
    match e {
        WalletError::KeyMismatch(m) => m,
        other => panic!("expected a key mismatch, got {other:?}"),
    }
}

/// An error to retry: what a check gives when the record it needs is not
/// published (yet). Panics on a mismatch or any other error.
fn retryable(e: WalletError) -> String {
    match e {
        WalletError::Mint(why)
            if why.contains("nothing was stored") && why.contains("try again") =>
        {
            why
        }
        other => panic!("expected an error to retry, got {other:?}"),
    }
}

/// Rewrite the keys of every key set of the FSP mint the wallet has read (in the
/// wallet file, the wallet closed): each amount gets the key of the next one.
/// That is the one way to have the wallet hold a published key set that
/// disagrees with the keys its mint signs with under the same ID (an ID is the
/// hash of the keys, so a mint cannot publish other keys under it).
fn hold_other_keys_for(path: &std::path::Path, service: ServiceDid) {
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let name = format!("fsp:{}", service.to_hex());
    let keysets = file["key_streams"][&name]["keysets"]
        .as_array_mut()
        .expect("the wallet read the mint's key sets");
    assert!(!keysets.is_empty());
    for ks in keysets {
        let keys = ks["keys"].as_object_mut().unwrap();
        let values: Vec<serde_json::Value> = keys.values().cloned().collect();
        for (i, v) in keys.values_mut().enumerate() {
            *v = values[(i + 1) % values.len()].clone();
        }
    }
    std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
}

/// An issue whose key sets the FSP mint did not publish (its stream carries one
/// key changed in each, so the key set it signs under is not on AIR) is not
/// stored. It is an error to retry, not a mismatch (a key set not on AIR may
/// not be published yet): no warning, no blacklist, the request and everything
/// the wallet holds are kept, and a retry is the same.
#[test]
fn an_issue_signed_with_keys_the_mint_did_not_publish_is_retried_and_stores_nothing() {
    let dir = scratch("key-issue");
    let m = Mints::start_with(&dir, "8", "1", None, StreamMode::Tampered);
    let air = m.fsp.air(8, 1);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4]);
    assert_eq!(w.key_policy(), KeyPolicy::default());
    assert!(!w.key_policy().blacklist_on_key_mismatch);
    w.set_key_policy(policy(true));
    let esp_before = w.notes().len();
    let req = w.build_fsp_issue(service(), None, 0).unwrap();
    let why = retryable(settle_fsp(&mut w, &air, &req.hash()).unwrap_err());
    assert!(
        why.contains("the FSP mint has not published key set"),
        "{why}"
    );
    assert!(!why.contains("KEY CHECK FAILED"), "{why}");
    // Nothing from the reply was stored, and the request is still there to retry.
    assert_eq!(fsp_units(&w), 0);
    assert_eq!(w.pending_fsp().len(), 1);
    assert_eq!(
        w.notes().len(),
        esp_before,
        "the ESP notes are kept, reserved"
    );
    assert!(
        w.notes()
            .iter()
            .any(|n| n.reserved_by.as_deref() == Some(req.hash().as_str()))
    );
    assert!(w.blacklist().is_empty());
    assert!(!w.is_blacklisted(&service()));
    // A retry is the same.
    retryable(settle_fsp(&mut w, &air, &req.hash()).unwrap_err());
    assert_eq!(w.pending_fsp().len(), 1);
    assert!(w.blacklist().is_empty());
}

/// A spend whose change is signed under a key set the mint did not publish (yet),
/// with the blacklist on: an error to retry, the notes are kept, the request is
/// kept, the mint is not blacklisted, and the next command still talks to it.
/// (The key set that signed is the one the mint rotated to; the genesis set it
/// published honestly.)
#[test]
fn a_spend_signed_under_an_unpublished_key_set_is_retried_and_keeps_the_notes() {
    let dir = scratch("key-spend-off");
    let m = start(&dir);
    let air = m.fsp.air(8, 1);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4, 1]);
    w.set_key_policy(policy(true));
    issue_all(&mut w, &m);
    assert_eq!(fsp_units(&w), 13);

    // The mint rotates, and what it publishes of the new key set is not what it
    // signs with.
    m.fsp.stream().tamper(true);
    m.clock.store(NOW + 5 * DAY + 2 * 3600, Ordering::SeqCst);
    m.fsp.publish();
    let req = w.build_fsp_spend(service(), 5, "coffee").unwrap();
    let why = retryable(settle_fsp(&mut w, &air, &req.hash()).unwrap_err());
    assert!(
        why.contains("the FSP mint has not published key set"),
        "{why}"
    );
    assert_eq!(fsp_units(&w), 13, "the notes are kept");
    assert_eq!(w.pending_fsp().len(), 1, "the request is kept");
    assert!(w.blacklist().is_empty());
    // Not blacklisted: the next call goes to the mint (and is the same).
    retryable(settle_fsp(&mut w, &air, &req.hash()).unwrap_err());
    assert!(w.blacklist().is_empty());
}

/// The same with `fsp.blacklist_on_key_mismatch` on: the mint is blacklisted, its
/// notes and requests are dropped from the wallet (removed, not backed up), the
/// next command sends it nothing and says why, the entry is in the wallet file
/// after a restart, and it goes only when it is removed by hand.
#[test]
fn with_the_blacklist_on_a_failing_fsp_mint_is_blacklisted_dropped_and_not_asked_again() {
    let dir = scratch("key-spend-on");
    let m = start(&dir);
    let air = m.fsp.air(8, 1);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4, 1]);
    issue_all(&mut w, &m);
    assert_eq!(fsp_units(&w), 13);

    // The wallet holds published keys under the key set's ID that are not the
    // keys the mint signs with: a mismatch on published records.
    drop(w);
    hold_other_keys_for(&dir.join("wallet.json"), service());
    let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
    w.set_key_policy(policy(true));
    let req = w.build_fsp_spend(service(), 5, "coffee").unwrap();
    let e = mismatch_of(settle_fsp(&mut w, &air, &req.hash()).unwrap_err());
    assert!(matches!(e.failed, Failed::Key { .. }), "{:?}", e.failed);

    assert_eq!((e.mint, e.site), ("FSP mint", Site::FinishFspSpend));
    assert!(e.blacklisted);
    assert!(
        e.warning.contains("This FSP mint is now BLACKLISTED (fsp.blacklist_on_key_mismatch is on): its notes were DROPPED from this wallet"),
        "{}",
        e.warning
    );
    assert!(w.is_blacklisted(&service()));
    assert_eq!(w.blacklist().len(), 1);
    assert_eq!(w.blacklist()[0].site, "finish_fsp_spend");
    assert_eq!(fsp_units(&w), 0, "its notes are dropped");
    assert!(w.pending_fsp().is_empty(), "and its request");
    assert!(w.notes().iter().all(|n| n.kind != Kind::Fsp));

    // The next command sends the mint nothing, and says so.
    let e = fsp_sync(&mut w, &air, service()).unwrap_err();
    assert!(
        matches!(&e, WalletError::Blacklisted(why) if why.contains("BLACKLISTED") && why.contains("blacklist remove")),
        "{e:?}"
    );
    assert!(
        w.air_requests().is_empty(),
        "nothing was written to the mint"
    );
    let e = fsp_keys(&mut w, &air, service()).unwrap_err();
    assert!(matches!(e, WalletError::Blacklisted(_)), "{e:?}");
    assert!(
        w.air_requests().is_empty(),
        "nothing was written to the mint"
    );

    // The blacklist is in the wallet file, and stays until it is removed by hand.
    drop(w);
    let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
    assert!(w.is_blacklisted(&service()));
    assert!(w.unblacklist(&service()).unwrap());
    assert!(w.blacklist().is_empty());
    assert!(
        !w.unblacklist(&service()).unwrap(),
        "nothing left to remove"
    );
}

/// A mint whose key sets reach AIR after its reply does (its writer is a few
/// seconds behind): the wallet waits for the stream, up to its reply wait, and
/// finishes the issue when the key set arrives. Nothing is decided before.
#[test]
fn a_key_set_published_after_the_reply_is_waited_for_and_the_issue_then_finishes() {
    let dir = scratch("key-late");
    let m = Mints::start_with(&dir, "20", "2", None, StreamMode::Held);
    let air = m.fsp.air(20, 2);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4, 1]);
    let req = w.build_fsp_issue(service(), None, 0).unwrap();
    let text = std::thread::scope(|scope| {
        let publisher = scope.spawn(|| {
            // Long enough for the wallet to have the reply and be waiting.
            std::thread::sleep(std::time::Duration::from_secs(3));
            m.fsp.publish()
        });
        let text = settle_fsp(&mut w, &air, &req.hash()).unwrap();
        assert!(publisher.join().unwrap(), "the key sets were written then");
        text
    });
    assert!(text.starts_with("issued 13 FSP"), "{text}");
    assert_eq!(fsp_units(&w), 13);
    assert!(w.pending_fsp().is_empty());
    assert!(w.blacklist().is_empty());
}

/// A stream the wallet cannot read a key set from yet (nothing was published,
/// the mint's writer is behind or the AIR server is slow) decides nothing: the
/// call is an error to retry, the request and the notes are kept, no warning
/// says the mint cheated, and the retry finishes once the key set is on AIR.
#[test]
fn a_mint_with_nothing_published_yet_is_a_retryable_error_and_not_a_mismatch() {
    let dir = scratch("key-unready");
    let m = Mints::start_with(&dir, "20", "2", None, StreamMode::Held);
    let air = m.fsp.air(6, 1);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4, 1]);
    w.set_key_policy(policy(true));
    let req = w.build_fsp_issue(service(), None, 0).unwrap();
    let e = settle_fsp(&mut w, &air, &req.hash()).unwrap_err();
    assert!(
        matches!(&e, WalletError::Mint(why) if why.contains("the FSP mint has not published key set") && why.contains("try again")),
        "{e:?}"
    );
    assert_eq!(w.pending_fsp().len(), 1, "the request is kept");
    assert!(
        w.blacklist().is_empty(),
        "nobody was blacklisted for being late"
    );

    m.fsp.publish();
    let text = settle_fsp(&mut w, &air, &req.hash()).unwrap();
    assert!(text.starts_with("issued 13 FSP"), "{text}");
    assert!(w.pending_fsp().is_empty());
}

/// Move back by a day, in the wallet file (the wallet closed), the time the
/// wallet first read a stream without each record it is missing: what a day
/// of waiting does, without a setting (the backstop is fixed) and without
/// waiting a day.
fn a_day_passes_for_the_missing_records(path: &std::path::Path) {
    let mut file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let missing = file["unpublished"]
        .as_object_mut()
        .expect("the wallet noted a missing record");
    assert!(!missing.is_empty());
    for seen in missing.values_mut() {
        let since = seen["since"].as_u64().unwrap();
        seen["since"] = serde_json::json!(since - 86_400);
    }
    std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
}

/// A mint that signs an issue under a key set it never publishes is not
/// retried for ever: the reply is an error to retry while the key set could
/// still be late, and once the fixed backstop (a day) has passed since the
/// wallet first read the stream without it (no newer record orders it here),
/// the retry is a key check failure. With the blacklist on, the mint is
/// blacklisted and the ESP notes the issue reserved (their spend secrets went
/// to the mint) are dropped with the request.
#[test]
fn an_issue_under_a_key_set_never_published_is_flagged_after_the_backstop() {
    let dir = scratch("key-backstop");
    let m = Mints::start_with(&dir, "8", "1", None, StreamMode::Tampered);
    let air = m.fsp.air(8, 1);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4]);
    w.set_key_policy(policy(true));
    let esp_before = w.notes().len();
    let req = w.build_fsp_issue(service(), None, 0).unwrap();
    let reserved = w
        .notes()
        .iter()
        .filter(|n| n.reserved_by.as_deref() == Some(req.hash().as_str()))
        .count();
    assert!(reserved > 0);
    let why = retryable(settle_fsp(&mut w, &air, &req.hash()).unwrap_err());
    assert!(
        why.contains("if it is still not published (a day after"),
        "{why}"
    );
    assert!(w.blacklist().is_empty());

    let path = w.path().to_path_buf();
    drop(w);
    a_day_passes_for_the_missing_records(&path);
    let mut w = open_wallet(&path).unwrap();
    w.set_key_policy(policy(true));
    let e = mismatch_of(settle_fsp(&mut w, &air, &req.hash()).unwrap_err());
    assert!(
        matches!(e.failed, Failed::Unpublished { .. }),
        "{:?}",
        e.failed
    );
    assert!(
        e.warning.contains("KEY CHECK FAILED") && e.warning.contains("NOT PUBLISHED"),
        "{}",
        e.warning
    );
    assert_eq!((e.mint, e.site), ("FSP mint", Site::FinishFspIssue));
    assert!(e.blacklisted);
    assert!(w.is_blacklisted(&service()));
    assert!(w.pending_fsp().is_empty(), "the request is dropped");
    assert_eq!(
        w.notes().len(),
        esp_before - reserved,
        "the ESP notes the issue reserved are dropped"
    );
    assert!(w.notes().iter().all(|n| n.reserved_by.is_none()));
}
