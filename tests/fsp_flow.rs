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
use ecash_wallet::mint_info::{
    fsp_keys, fsp_rotation, fsp_sync, send_fsp_issue, send_fsp_spend, settle_fsp,
};
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::terms::Terms;
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
use sp_wire::ServiceDid;

use common::air::{Mints, NOW, service};
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
