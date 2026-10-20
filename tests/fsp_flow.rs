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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ecash_wallet::config::AirSettings;
use ecash_wallet::mint_info::{
    fsp_keys, fsp_rotation, fsp_sync, send_fsp_issue, send_fsp_spend, settle_fsp,
};
use ecash_wallet::store::{HandedNote, Handover};
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::responses::Responses;
use esp_mint::server::EspState;
use esp_mint::terms::Terms;
use fsp_mint::issue::Issues;
use fsp_mint::server::FspState;
use fsp_mint::spend::Spender;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
use sp_wire::ServiceDid;

use common::{EspAt, FspAt, service, service_keypair};

const NOW: u64 = 1_791_571_184;
const DAY: u64 = 86_400;

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "wallet-fsp-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct NoPsp;
impl Psp for NoPsp {
    fn melt(&self, _: &[MintInput], _: &str) -> Result<Amount, String> {
        Err("no psp".into())
    }
    fn burns(&self, _: &[Nonce]) -> Result<Vec<Burn>, String> {
        Err("no psp".into())
    }
}

struct Mints {
    esp: Arc<EspState>,
    /// The wallet's `[air]` settings: the `air.fsp` entry of the service.
    air: AirSettings,
    clock: Arc<AtomicU64>,
    /// fsp-mint's AIR listener (and its state). It drops before the ESP mint's
    /// listener and the turn on the shared AIR server, which are last.
    fsp: FspAt,
    esp_at: EspAt,
}

/// Both mints. The FSP mint first issued at `NOW`; rotation activates 120
/// hours later, every 240 hours.
fn start(dir: &Path) -> Mints {
    start_with(dir, "20", "2", None)
}

/// [`start`], with the time one try of the FSP mint's calls to the ESP mint
/// waits and the number of tries (a test with an ESP mint that is down does not
/// wait long), and the longest memo the FSP mint takes.
fn start_with(dir: &Path, wait_secs: &str, attempts: &str, memo_limit: Option<usize>) -> Mints {
    let (logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    let responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let esp = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(NoPsp),
        responses: Mutex::new(responses),
        queue_path: dir.join("esp").join("queue.json"),
        queue_lock: Mutex::new(()),
        in_flight: Default::default(),
        config: esp_mint::config::Handle::default(),
        rotor: None,
        rollovers: None,
    });
    // The listeners keep their state in folders of their own, outside `dir`.
    let esp_at = EspAt::new(Arc::clone(&esp), &scratch("airstate"));
    let mut cfg = fsp_mint::config::Config::default();
    for (key, value) in esp_at.fsp_settings(wait_secs, attempts) {
        cfg.set(key, &value).unwrap();
    }
    cfg.set("service.did", &service().to_string()).unwrap();
    cfg.set("rotation.activation_hours", "120").unwrap();
    cfg.set("rotation.period_hours", "240").unwrap();
    cfg.validate().unwrap();
    cfg.require_air().unwrap();
    std::fs::create_dir_all(dir.join("fsp")).unwrap();
    fsp_mint::keysets::record_first_issue(&dir.join("fsp"), NOW).unwrap();
    let clock = Arc::new(AtomicU64::new(NOW));
    let c = Arc::clone(&clock);
    let mut spender = Spender::open(&dir.join("fsp"), cfg.rotation(), 1024, NOW).unwrap();
    if let Some(limit) = memo_limit {
        spender = spender.with_max_memo_bytes(limit);
    }
    let state = Arc::new(FspState {
        spender,
        issues: Mutex::new(Issues::open(&dir.join("fsp")).unwrap()),
        issuer: Box::new(fsp_mint::esp_air::AirIssuer::new(&cfg).unwrap()),
        service_keypair: Some(service_keypair()),
        clock: Box::new(move || c.load(Ordering::SeqCst)),
        config: cfg,
    });
    let fsp = FspAt::new(&esp_at.server, state, &scratch("airstate-fsp"));
    // The wallet waits long enough for the FSP mint to be told by its ESP mint
    // that it is not answering.
    let air = fsp.air(60, 2);
    Mints {
        esp,
        air,
        clock,
        fsp,
        esp_at,
    }
}

/// A wallet holding `units` ESP notes for the service (one note each).
fn wallet_with_esp(dir: &Path, mints: &Mints, units: &[u64]) -> Wallet {
    let day = Terms::new_at(service(), NOW).redeemable_after_day;
    let terms = Terms {
        service: service(),
        redeemable_after_day: day,
    };
    let mut notes = Vec::new();
    for &u in units {
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(kp.public_key());
        let (p, r) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(u);
        let sk = mints.esp.master.key_for(amount, &terms);
        let sig = mints
            .esp
            .logic
            .lock()
            .unwrap()
            .issue_with_key(
                &sk,
                &MintOutput {
                    amount,
                    blind_nonce: BlindNonce(p),
                },
            )
            .unwrap();
        notes.push(HandedNote {
            amount: u,
            note: Note {
                nonce,
                signature: bdhke::unblind_message(&sig.0, &r, &sk.public_key(SECP256K1)),
            },
            spend_secret: kp.secret_key(),
            keyset: esp_mint::rotation::keyset_id(&mints.esp.master),
        });
    }
    let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
    w.receive_handover(&Handover {
        service: service(),
        redeemable_after_day: day,
        notes,
    })
    .unwrap();
    w
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
    fsp_sync(&mut w, &m.air, service()).ok();
    // ...the sync above already rolled over. Make another rotation-free crash:
    // a payment sent, answered by the mint, and the wallet dies before saving.
    let req = w.build_fsp_spend(service(), 4, "").unwrap();
    send_fsp_spend(&mut w, &m.air, service(), &req).unwrap();
    drop(w);
    let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
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
    let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
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
    let m = start_with(&dir, "20", "2", Some(8));
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

/// An ESP mint that does not answer fsp-mint leaves the wallet's issue pending
/// (the FSP mint says so in a signed reply, the `502` of the HTTP route); when the
/// ESP mint is back, the retry finishes it, and the ESP is transferred once.
#[test]
fn an_esp_mint_that_does_not_answer_leaves_the_issue_pending_and_the_retry_finishes_it() {
    let dir = scratch("esp-silent");
    // One short try: an ESP mint that is down is found out quickly.
    let m = start_with(&dir, "5", "1", None);
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
    let mut none = AirSettings::default();
    none.server = m.esp_at.server.name.clone();
    none.host = m.esp_at.server.host.clone();
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
