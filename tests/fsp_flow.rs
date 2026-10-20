//! FSP from the wallet's side, against a real ESP mint and a real fsp-mint in
//! this process: issue, pay, and the automatic rollover across key rotation,
//! with crashes, an offline wallet and a failed swap.
//!
//! fsp-mint reaches the ESP mint over AIR only (its Issuer is the real
//! `AirIssuer`), so the ESP mint answers on its real AIR listener against a real
//! `air_server` started in this process (see `common/mod.rs`), as fsp-mint's own
//! `tests/fsp_flow.rs` does. The AIR client always dials port 5702, so these
//! tests need that port free, and they take turns on the one shared server; they
//! are built only with the `air-listener-tests` feature. The wallet's own calls
//! to the FSP mint are HTTP.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use ecash_wallet::store::{HandedNote, Handover};
use ecash_wallet::{Kind, Wallet, http};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::responses::Responses;
use esp_mint::server::EspState;
use esp_mint::terms::Terms;
use fsp_mint::issue::Issues;
use fsp_mint::server::FspState;
use fsp_mint::spend::Spender;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use sp_wire::ServiceDid;
use tokio::runtime::Runtime;

use common::EspAt;

const NOW: u64 = 1_791_571_184;
const DAY: u64 = 86_400;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wallet-fsp-{}-{name}", {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn service_keypair() -> Keypair {
    let mut b = [0u8; 32];
    b[31] = 1;
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&b).unwrap())
}

fn service() -> ServiceDid {
    ServiceDid::from(service_keypair().public_key())
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

fn serve(rt: &Runtime, app: Router) -> String {
    let l = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let a = l.local_addr().unwrap();
    rt.spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{a}")
}

struct Mints {
    esp: Arc<EspState>,
    fsp_url: String,
    clock: Arc<AtomicU64>,
    /// The ESP mint's AIR listener and the turn on the shared AIR server, which
    /// a test holds until it drops the mints. Last.
    _esp_at: EspAt,
}

/// Both mints. The FSP mint first issued at `NOW`; rotation activates 120
/// hours later, every 240 hours.
fn start(rt: &Runtime, dir: &Path) -> Mints {
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
    // The listener keeps its state in a folder of its own, outside `dir`.
    let esp_at = EspAt::new(Arc::clone(&esp), &scratch("airstate"));
    let mut cfg = fsp_mint::config::Config::default();
    for (key, value) in esp_at.fsp_settings("20", "2") {
        cfg.set(key, &value).unwrap();
    }
    cfg.set("service.did", &service().to_string()).unwrap();
    cfg.set("rotation.activation_hours", "120").unwrap();
    cfg.set("rotation.period_hours", "240").unwrap();
    cfg.validate().unwrap();
    std::fs::create_dir_all(dir.join("fsp")).unwrap();
    fsp_mint::keysets::record_first_issue(&dir.join("fsp"), NOW).unwrap();
    let clock = Arc::new(AtomicU64::new(NOW));
    let c = Arc::clone(&clock);
    let state = Arc::new(FspState {
        spender: Spender::open(&dir.join("fsp"), cfg.rotation(), 1024, NOW).unwrap(),
        issues: Mutex::new(Issues::open(&dir.join("fsp")).unwrap()),
        issuer: Box::new(fsp_mint::esp_air::AirIssuer::new(&cfg).unwrap()),
        service_keypair: Some(service_keypair()),
        clock: Box::new(move || c.load(Ordering::SeqCst)),
        config: cfg,
    });
    let fsp_url = serve(rt, fsp_mint::server::router(state));
    Mints {
        esp,
        fsp_url,
        clock,
        _esp_at: esp_at,
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

fn issue_all(w: &mut Wallet, url: &str) {
    let req = w.build_fsp_issue(service(), None, 0).unwrap();
    http::settle_fsp(w, url, &req.hash()).unwrap();
}

#[test]
fn issue_pay_and_the_rollover_when_a_rotation_is_detected() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("rollover");
    let m = start(&rt, &dir);
    let mut w = wallet_with_esp(&dir, &m, &[8, 4, 1]);
    http::fsp_sync(&mut w, service(), &m.fsp_url).unwrap();
    issue_all(&mut w, &m.fsp_url);
    assert_eq!(fsp_units(&w), 13);
    assert_eq!(w.balance().esp, 0);
    let req = w.build_fsp_spend(service(), 5, "coffee").unwrap();
    assert_eq!(
        http::settle_fsp(&mut w, &m.fsp_url, &req.hash()).unwrap(),
        "paid 5 FSP"
    );
    assert_eq!(fsp_units(&w), 8);
    let genesis = keysets_of(&w);
    assert_eq!(genesis.len(), 1);
    // Nothing to roll over before the rotation.
    assert!(
        http::fsp_sync(&mut w, service(), &m.fsp_url)
            .unwrap()
            .log
            .is_empty()
    );

    // Right at the rotation this wallet waits its staggered delay.
    m.clock.store(NOW + 5 * DAY, Ordering::SeqCst);
    let sync = http::fsp_sync(&mut w, service(), &m.fsp_url).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("staggered"))
            || sync.log.iter().any(|l| l.contains("rolled over")),
        "{:?}",
        sync.log
    );
    // The rotation, past the stagger (240 h period: at most 1.2 h): swapped
    // without asking.
    m.clock.store(NOW + 5 * DAY + 2 * 3600, Ordering::SeqCst);
    let sync = http::fsp_sync(&mut w, service(), &m.fsp_url).unwrap();
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
    let win = http::fetch_fsp_rotation(&m.fsp_url).unwrap();
    assert!(win.active);
    assert_eq!(win.current.id, mint.current);
    assert_eq!(win.previous.unwrap().retires, Some(NOW + 15 * DAY));
    assert_eq!(win.next_rotation, mint.next_rotation);
}

#[test]
fn a_crash_after_the_mint_answered_is_finished_from_the_stored_answer() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("crash");
    let m = start(&rt, &dir);
    let mut w = wallet_with_esp(&dir, &m, &[16]);
    issue_all(&mut w, &m.fsp_url);
    m.clock.store(NOW + 6 * DAY, Ordering::SeqCst);
    http::fsp_sync(&mut w, service(), &m.fsp_url).ok();
    // ...the sync above already rolled over. Make another rotation-free crash:
    // a payment sent, answered by the mint, and the wallet dies before saving.
    let req = w.build_fsp_spend(service(), 4, "").unwrap();
    http::send_fsp_spend(&m.fsp_url, &req).unwrap();
    drop(w);
    let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
    assert_eq!(w.pending_fsp().len(), 1);
    let sync = http::fsp_sync(&mut w, service(), &m.fsp_url).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("paid 4 FSP")),
        "{:?}",
        sync.log
    );
    assert!(w.pending_fsp().is_empty());
    assert_eq!(fsp_units(&w), 12, "paid once");

    // A rollover built and never sent (crash before sending): finished later.
    m.clock.store(NOW + 15 * DAY, Ordering::SeqCst);
    let keys = http::fetch_fsp_keys(&m.fsp_url).unwrap();
    w.note_fsp_keys(service(), &m.fsp_url, &keys).unwrap();
    assert!(w.build_fsp_rollover(service()).unwrap().is_some());
    drop(w);
    let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
    http::fsp_sync(&mut w, service(), &m.fsp_url).unwrap();
    assert!(w.pending_fsp().is_empty());
    assert_eq!(keysets_of(&w), vec![keys.current.clone()]);
    assert_eq!(fsp_units(&w), 12);
}

#[test]
fn offline_within_the_window_rolls_over_and_beyond_it_is_lost() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("offline");
    let m = start(&rt, &dir);
    let mut w = wallet_with_esp(&dir, &m, &[2, 1]);
    issue_all(&mut w, &m.fsp_url);
    // Back 9 days after activation: the genesis set is previous for 1 more day.
    m.clock.store(NOW + 14 * DAY, Ordering::SeqCst);
    let sync = http::fsp_sync(&mut w, service(), &m.fsp_url).unwrap();
    assert_eq!(sync.lost, 0);
    assert_eq!(fsp_units(&w), 3);

    // Another wallet, offline through a whole period after its set retired. (The
    // first pair of mints gives up its turn on the AIR server first.)
    drop(m);
    let dir2 = scratch("offline-lost");
    let m2 = start(&rt, &dir2);
    let mut w2 = wallet_with_esp(&dir2, &m2, &[2, 1]);
    issue_all(&mut w2, &m2.fsp_url);
    m2.clock.store(NOW + 15 * DAY, Ordering::SeqCst);
    let sync = http::fsp_sync(&mut w2, service(), &m2.fsp_url).unwrap();
    assert_eq!(sync.lost, 3, "{:?}", sync.log);
    assert_eq!(fsp_units(&w2), 0);
    assert_eq!(w2.lost_fsp().len(), 2);
}

/// A proxy in front of the FSP mint that fails `POST /spend` while `fail` is set.
struct Proxy {
    to: String,
    fail: AtomicBool,
}

async fn forward_get(State(p): State<Arc<Proxy>>, uri: axum::http::Uri) -> (StatusCode, String) {
    let url = format!("{}{}", p.to, uri.path());
    tokio::task::spawn_blocking(move || {
        let r = reqwest::blocking::get(url).unwrap();
        (
            StatusCode::from_u16(r.status().as_u16()).unwrap(),
            r.text().unwrap(),
        )
    })
    .await
    .unwrap()
}

async fn forward_spend(State(p): State<Arc<Proxy>>, body: Bytes) -> (StatusCode, String) {
    if p.fail.load(Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"error":"down","code":"unavailable"}"#.into(),
        );
    }
    let url = format!("{}/spend", p.to);
    tokio::task::spawn_blocking(move || {
        let r = reqwest::blocking::Client::new()
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .unwrap();
        (
            StatusCode::from_u16(r.status().as_u16()).unwrap(),
            r.text().unwrap(),
        )
    })
    .await
    .unwrap()
}

#[test]
fn a_failed_rollover_is_logged_and_retried_on_the_next_connection() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("retry");
    let m = start(&rt, &dir);
    let mut w = wallet_with_esp(&dir, &m, &[4]);
    issue_all(&mut w, &m.fsp_url);
    let proxy = Arc::new(Proxy {
        to: m.fsp_url.clone(),
        fail: AtomicBool::new(true),
    });
    let app = Router::new()
        .route("/keys", get(forward_get))
        .route("/health", get(forward_get))
        .route("/rotation", get(forward_get))
        .route("/spend", post(forward_spend))
        .with_state(Arc::clone(&proxy));
    let url = serve(&rt, app);
    m.clock.store(NOW + 6 * DAY, Ordering::SeqCst);
    let sync = http::fsp_sync(&mut w, service(), &url).unwrap();
    assert!(
        sync.log
            .iter()
            .any(|l| l.contains("retried on the next connection")),
        "{:?}",
        sync.log
    );
    assert_eq!(w.pending_fsp().len(), 1, "kept for the retry");
    let old = keysets_of(&w);
    proxy.fail.store(false, Ordering::SeqCst);
    let sync = http::fsp_sync(&mut w, service(), &url).unwrap();
    assert!(
        sync.log.iter().any(|l| l.contains("rolled over")),
        "{:?}",
        sync.log
    );
    assert!(w.pending_fsp().is_empty());
    assert_ne!(keysets_of(&w), old);
    assert_eq!(fsp_units(&w), 4);
}

#[test]
fn the_esp_schedule_reads_the_wallets_notes() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("schedule");
    let m = start(&rt, &dir);
    let w = wallet_with_esp(&dir, &m, &[8, 2]);
    let day = Terms::new_at(service(), NOW).redeemable_after_day;
    let s = w.esp_schedule(day - 1, Some(day));
    assert_eq!((s.mature_now, s.by, s.total), (0, Some((day, 10)), 10));
    assert_eq!(s.months.values().sum::<u128>(), 10);
    assert_eq!(w.esp_schedule(day, None).mature_now, 10);
}
