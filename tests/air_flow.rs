//! The PSP's read-only calls over AIR, end to end: an `air_server` in this
//! process, psp-mint's real AIR listener answering, and the wallet asking,
//! blocking, the way the command line does. Mint info (`mint_info::verify_psp`)
//! is answered from a health report; keys, keysets and rotation (`psp_keys`,
//! `psp_keysets`, `psp_window` and what is built on them) from a real rotating
//! mint, whose HTTP routes are served in the process too, so that the two ways
//! can be compared.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests
//! need that port free; `local_server::start` says so when it is not. One server
//! serves every test of this binary, and each test has its own mint key.
//!
//! These tests use psp-mint's `air_listener`, which no tag has yet, so they are
//! built only with the `air-listener-tests` feature (the local-mints script
//! turns on every feature).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ecash_wallet::config::AirSettings;
use ecash_wallet::mint_info::{
    psp_claim_keys, psp_keys, psp_keysets, psp_window, rotation_sync, sync_psp_limits, verify_psp,
};
use ecash_wallet::store::{PendingAirRequest, WalletData};
use ecash_wallet::{Kind, Wallet, WalletError, http};
use mint_server::state::AppState;
use mint_types::Amount;
use psp_mint::air_listener::{self, Serve, Settings};
use psp_mint::melts::MeltLog;
use psp_mint::rotation::{Rollovers, Rotor};
use psp_mint::server::{Health, Rotating, SharedRotating};
use sp_wire::air_request::addr::{self, reply_secret, seal_to, shared_wallet};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::envelope::{STATUS_ANSWERED, WireRequest, build_reply};
use sp_wire::air_request::{KIND_KEYS, KIND_MINT_INFO, MintInfo, local_server};
use sp_wire::seal::SecretKey;
use sp_wire::{ServiceDid, WIRE_VERSION};

const NETWORK: &str = "regtest";

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ecash-wallet-airflow-{}-{name}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn server() -> ServerRef {
    local_server::start().expect("a local AIR server (is port 5702 free?)")
}

fn mint_key() -> (SecretKey, ServiceDid) {
    let key = SecretKey::new();
    let did = addr::key_to_did(&key.public_key());
    (key, did)
}

fn air_settings(server: &ServerRef, did: &ServiceDid, wait: u64, attempts: u32) -> AirSettings {
    AirSettings {
        psp_did: Some(*did),
        server: server.name.clone(),
        host: server.host.clone(),
        reply_wait_secs: wait,
        attempts,
        ..AirSettings::default()
    }
}

type Info = Arc<dyn Fn() -> MintInfo + Send + Sync>;

/// A PSP's state as `serve` builds it: the mint, the health report, and the
/// closure the listener answers from.
struct Psp {
    health: Arc<Health>,
    info: Info,
}

fn psp(dir: &PathBuf) -> Psp {
    let logic = psp_mint::mint::open(dir, Amount::from_units(1024)).unwrap();
    let state = psp_mint::server::app_state(logic);
    let health = Health::for_network(100, NETWORK);
    health.record_scan_at(psp_mint::server::now_secs());
    let for_info = Arc::clone(&health);
    Psp {
        health,
        info: Arc::new(move || {
            for_info.mint_info(state.logic.is_poisoned(), psp_mint::server::now_secs())
        }),
    }
}

/// The listener on a thread of its own, as `serve` runs it. Dropping it stops it.
struct Listener {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

fn start_listener(server: &ServerRef, key: &SecretKey, dir: &PathBuf, info: Info) -> Listener {
    start_serving(
        server,
        key,
        dir,
        Arc::new(air_listener::mint_info_only(move || info())),
    )
}

fn start_serving(
    server: &ServerRef,
    key: &SecretKey,
    dir: &PathBuf,
    serve: Arc<Serve>,
) -> Listener {
    let settings = Settings {
        server: server.clone(),
        held_reads: 16,
        timeout_secs: 10,
        state_dir: dir.clone(),
    };
    let key = key.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let thread = thread::Builder::new()
        .name("test-air-listener".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(air_listener::run(&settings, &key, &*serve, async move {
                let _ = stopped.await;
            }))
        })
        .unwrap();
    Listener {
        stop: Some(stop),
        thread: Some(thread),
    }
}

impl Listener {
    fn stop(mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.thread.take().unwrap().join() {
            Ok(result) => result,
            Err(_) => Err("the listener thread panicked".into()),
        }
    }

    fn ended(mut self) -> Result<(), String> {
        match self.thread.take().unwrap().join() {
            Ok(result) => result,
            Err(_) => Err("the listener thread panicked".into()),
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn wait_for_next(dir: &PathBuf, want: u32) {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let now = air_listener::read_next(dir).unwrap();
        if now == want {
            return;
        }
        assert!(
            Instant::now() < until,
            "the counter is {now}, expected {want}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn put(server: &ServerRef, key: &SecretKey, bytes: Vec<u8>) {
    let put = block_on_new_runtime(move || async move {
        let client = client::connect(server).await.unwrap();
        client::create(&client, key, bytes, 10).await.unwrap()
    })
    .unwrap();
    assert!(matches!(put, client::Put::Created(_)));
}

fn open_wallet(dir: &PathBuf) -> Wallet {
    Wallet::open(&dir.join("wallet.json")).unwrap()
}

/// A wallet file that already holds a request in flight for `did`, as if an
/// earlier run had written it and then been stopped.
fn wallet_with_request(
    dir: &PathBuf,
    did: &ServiceDid,
    slots: Vec<u32>,
) -> (Wallet, PendingAirRequest) {
    wallet_with_kind(dir, did, slots, KIND_MINT_INFO)
}

/// The same, for a request of another kind.
fn wallet_with_kind(
    dir: &PathBuf,
    did: &ServiceDid,
    slots: Vec<u32>,
    kind: u8,
) -> (Wallet, PendingAirRequest) {
    let (r, request_id) = (SecretKey::new(), addr::random_id());
    let pending = PendingAirRequest {
        kind,
        request_id: hex::encode(request_id),
        mint: did.to_hex(),
        r: addr::secret_to_hex(&r),
        slots,
        created_at: addr::now_secs(),
    };
    let data = WalletData {
        air_requests: vec![pending.clone()],
        ..Default::default()
    };
    std::fs::write(dir.join("wallet.json"), serde_json::to_vec(&data).unwrap()).unwrap();
    (open_wallet(dir), pending)
}

/// Write `plain` (sealed to the request key) into the reply cell of `pending`.
fn plant_reply(server: &ServerRef, did: &ServiceDid, pending: &PendingAirRequest, plain: &[u8]) {
    let r = addr::secret_from_hex(&pending.r).unwrap();
    let request_id: [u8; 32] = hex::decode(&pending.request_id)
        .unwrap()
        .try_into()
        .unwrap();
    let shared = shared_wallet(&r, &addr::did_to_key(did).unwrap());
    let cell = reply_secret(&shared, &request_id, 0);
    put(server, &cell, seal_to(&r.public_key(), plain).unwrap());
}

fn request_of(pending: &PendingAirRequest) -> WireRequest {
    let r = addr::secret_from_hex(&pending.r).unwrap();
    WireRequest::new(
        pending.kind,
        hex::decode(&pending.request_id)
            .unwrap()
            .try_into()
            .unwrap(),
        addr::key_to_bytes(&r.public_key()),
    )
}

fn info_body(network: &str) -> Vec<u8> {
    serde_json::to_vec(&MintInfo {
        status: "ok".into(),
        wire_version: WIRE_VERSION,
        network: network.into(),
    })
    .unwrap()
}

#[test]
fn verify_mint_goes_over_air_to_psp_mints_listener_and_leaves_nothing_pending() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("happy");
    let psp = psp(&dir.join("psp"));
    let state_dir = scratch("happy-state");
    let listener = start_listener(&server, &key, &state_dir, Arc::clone(&psp.info));

    let mut wallet = open_wallet(&dir);
    let air = air_settings(&server, &did, 10, 3);
    // The URL is not used: with AIR configured nothing goes to it.
    verify_psp(&mut wallet, &air, "http://127.0.0.1:9", NETWORK).unwrap();
    assert!(wallet.air_requests().is_empty());
    wait_for_next(&state_dir, 1);
    // It asked again from a fresh request and was answered again.
    verify_psp(&mut wallet, &air, "http://127.0.0.1:9", NETWORK).unwrap();
    wait_for_next(&state_dir, 2);
    listener.stop().unwrap();
}

#[test]
fn a_psp_on_another_network_is_refused_over_air_like_over_http() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("network");
    let psp = psp(&dir.join("psp"));
    let state_dir = scratch("network-state");
    let listener = start_listener(&server, &key, &state_dir, psp.info);

    let mut wallet = open_wallet(&dir);
    let air = air_settings(&server, &did, 10, 3);
    match verify_psp(&mut wallet, &air, "http://127.0.0.1:9", "main") {
        Err(WalletError::Invalid(why)) => {
            assert!(why.contains("regtest") && why.contains("main"), "{why}");
            assert!(why.contains("Nothing was sent"), "{why}");
        }
        other => panic!("expected the network to be refused, got {other:?}"),
    }
    assert!(
        wallet.air_requests().is_empty(),
        "an answered request is over, even when the answer is a refusal"
    );
    listener.stop().unwrap();
}

#[test]
fn an_unanswered_request_is_kept_and_a_late_reply_is_picked_up_by_the_next_call() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("late");
    let psp = psp(&dir.join("psp"));
    let state_dir = scratch("late-state");

    // The PSP is not listening: one try of two seconds, then "unreachable".
    let mut wallet = open_wallet(&dir);
    let air = air_settings(&server, &did, 2, 1);
    match verify_psp(&mut wallet, &air, "http://127.0.0.1:9", NETWORK) {
        Err(WalletError::Mint(why)) => assert!(why.contains("did not answer"), "{why}"),
        other => panic!("expected the PSP to be unreachable, got {other:?}"),
    }
    let kept = wallet.air_requests().to_vec();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].slots, vec![0]);
    // It is in the file, not only in memory.
    assert_eq!(open_wallet(&dir).air_requests(), &kept[..]);

    // The PSP starts, reads its slot 0 and answers. The wallet's next call
    // carries on with the same request: it finds the reply, and writes nothing.
    let listener = start_listener(&server, &key, &state_dir, psp.info);
    wait_for_next(&state_dir, 1);
    verify_psp(&mut wallet, &air, "http://127.0.0.1:9", NETWORK).unwrap();
    assert!(wallet.air_requests().is_empty());
    assert!(open_wallet(&dir).air_requests().is_empty());
    thread::sleep(Duration::from_millis(500));
    assert_eq!(
        air_listener::read_next(&state_dir).unwrap(),
        1,
        "no second request was written"
    );
    listener.stop().unwrap();
}

#[test]
fn a_reply_found_long_after_it_was_issued_is_dropped_and_a_new_request_is_made() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("stale");
    let psp = psp(&dir.join("psp"));
    let state_dir = scratch("stale-state");

    // The request from an earlier run was answered, but an hour ago.
    let (mut wallet, pending) = wallet_with_request(&dir, &did, vec![0]);
    let old = build_reply(
        &key,
        &request_of(&pending),
        STATUS_ANSWERED,
        addr::now_secs() - 3_600,
        &info_body(NETWORK),
    );
    plant_reply(&server, &did, &pending, &old);

    let listener = start_listener(&server, &key, &state_dir, psp.info);
    let air = air_settings(&server, &did, 10, 3);
    verify_psp(&mut wallet, &air, "http://127.0.0.1:9", NETWORK).unwrap();
    assert!(wallet.air_requests().is_empty());
    // The old request's slot 0 was never written by this test, so the new
    // request took slot 0 here.
    wait_for_next(&state_dir, 1);
    listener.stop().unwrap();
}

#[test]
fn a_tampered_reply_is_refused_and_the_request_is_dropped() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("tamper");

    let (mut wallet, pending) = wallet_with_request(&dir, &did, vec![0]);
    let mut forged = build_reply(
        &key,
        &request_of(&pending),
        STATUS_ANSWERED,
        addr::now_secs(),
        &info_body(NETWORK),
    );
    forged[100] ^= 1;
    plant_reply(&server, &did, &pending, &forged);

    let air = air_settings(&server, &did, 5, 1);
    match verify_psp(&mut wallet, &air, "http://127.0.0.1:9", NETWORK) {
        Err(WalletError::Mint(why)) => {
            assert!(
                why.contains("refused") && why.contains("signature"),
                "{why}"
            )
        }
        other => panic!("expected the reply to be refused, got {other:?}"),
    }
    assert!(
        wallet.air_requests().is_empty(),
        "a write-once cell cannot be answered differently, so the request is over"
    );
}

#[test]
fn the_psp_dying_before_it_replies_costs_a_retry_and_ends_with_one_reply() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("dies");
    let psp = psp(&dir.join("psp"));
    let state_dir = scratch("dies-state");

    let armed = Arc::new(AtomicBool::new(true));
    let live = Arc::clone(&psp.info);
    let dying: Info = {
        let armed = Arc::clone(&armed);
        Arc::new(move || {
            if armed.swap(false, Ordering::SeqCst) {
                panic!("simulated crash of the PSP");
            }
            live()
        })
    };
    let first = start_listener(&server, &key, &state_dir, dying);

    let wallet_thread = {
        let air = air_settings(&server, &did, 3, 3);
        let dir = dir.clone();
        thread::spawn(move || {
            let mut wallet = open_wallet(&dir);
            let result = verify_psp(&mut wallet, &air, "http://127.0.0.1:9", NETWORK);
            (result, wallet.air_requests().to_vec())
        })
    };
    assert!(
        first.ended().is_err(),
        "the first listener should have died"
    );

    thread::sleep(Duration::from_secs(4));
    let second = start_listener(&server, &key, &state_dir, psp.info);
    let (result, pending) = wallet_thread.join().unwrap();
    result.unwrap();
    assert!(pending.is_empty());
    // Slot 0 (tried first) and slot 1 (the retry): both finished, one reply.
    wait_for_next(&state_dir, 2);
    second.stop().unwrap();
}

#[test]
fn with_air_off_the_psp_is_checked_over_http() {
    let dir = scratch("http");
    let psp = psp(&dir.join("psp"));
    let state = psp_mint::server::app_state(
        psp_mint::mint::open(&dir.join("psp-http"), Amount::from_units(1024)).unwrap(),
    );
    let melts = Arc::new(Mutex::new(
        MeltLog::open(&dir.join("melt_memos.json")).unwrap(),
    ));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = psp_mint::server::router(state, Arc::clone(&psp.health), melts);
    runtime.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mut wallet = open_wallet(&dir);
    let off = AirSettings::default();
    assert!(!off.is_configured());
    verify_psp(&mut wallet, &off, &base, NETWORK).unwrap();
    // The HTTP check is the old one: a mint on another network is refused.
    assert!(matches!(
        verify_psp(&mut wallet, &off, &base, "main"),
        Err(WalletError::Invalid(_))
    ));
    // Nothing went over AIR.
    assert!(wallet.air_requests().is_empty());
}

// ---------------------------------------------------------------- keys, keysets, rotation

/// A real rotating PSP (a manual clock, so `/rotation` does not move between two
/// calls) with its HTTP routes served in this process.
struct RealPsp {
    _rt: tokio::runtime::Runtime,
    base: String,
    state: Arc<AppState>,
    rot: SharedRotating,
    health: Arc<Health>,
}

fn real_psp(dir: &PathBuf) -> RealPsp {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (rotor, logic) = Rotor::open_at(
        &dir.join("psp"),
        Amount::from_units(1024),
        1,
        1,
        1_800_000_000,
    )
    .unwrap();
    let rot = Rotating::new(rotor, Rollovers::open(&dir.join("psp")).unwrap());
    let state = psp_mint::server::app_state(logic);
    let melts = Arc::new(Mutex::new(
        MeltLog::open(&dir.join("melt_memos.json")).unwrap(),
    ));
    let health = Health::for_network(100, NETWORK);
    health.record_scan_at(psp_mint::server::now_secs());
    let app = psp_mint::server::router_full(
        Arc::clone(&state),
        Arc::clone(&health),
        melts,
        Default::default(),
        Some(Arc::clone(&rot)),
    );
    let base = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    });
    RealPsp {
        _rt: rt,
        base,
        state,
        rot,
        health,
    }
}

impl RealPsp {
    /// What the PSP's listener answers: the same `serve` psp-mint runs.
    fn serve(&self) -> Arc<Serve> {
        let (state, rot, health) = (
            Arc::clone(&self.state),
            Arc::clone(&self.rot),
            Arc::clone(&self.health),
        );
        Arc::new(move |kind| psp_mint::server::air_served(&state, &rot, &health, kind))
    }
}

/// A URL nothing listens on: with AIR configured it must never be touched.
const DEAD: &str = "http://127.0.0.1:9";

#[test]
fn keys_keysets_rotation_limits_and_claim_keys_over_air_are_what_http_gives() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("keys");
    let psp = real_psp(&dir);
    let state_dir = scratch("keys-state");
    let listener = start_serving(&server, &key, &state_dir, psp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let mut wallet = open_wallet(&dir);
    let mut http_wallet = open_wallet(&scratch("keys-http-wallet"));

    let keys = psp_keys(&mut wallet, &air, DEAD).unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys, http::fetch_psp_keys(&psp.base).unwrap());

    let keysets = psp_keysets(&mut wallet, &air, DEAD).unwrap();
    assert_eq!(
        serde_json::to_value(&keysets).unwrap(),
        serde_json::to_value(http::fetch_psp_keysets(&psp.base).unwrap()).unwrap()
    );

    let window = psp_window(&mut wallet, &air, DEAD).unwrap();
    assert_eq!(
        format!("{window:?}"),
        format!("{:?}", http::fetch_window(&psp.base).unwrap())
    );
    assert_eq!(window.current_id, keysets.current);

    // The note-size cap the wallet learns from the keys.
    sync_psp_limits(&mut wallet, &air, DEAD).unwrap();
    http::sync_psp_limits(&mut http_wallet, &psp.base).unwrap();
    assert!(wallet.psp_max_denomination().is_some());
    assert_eq!(
        wallet.psp_max_denomination(),
        http_wallet.psp_max_denomination()
    );

    // The keys to claim with: older output names no keyset (the keys of `/keys`),
    // a named live keyset gives that keyset's keys, a retired one is refused.
    let none = psp_claim_keys(&mut wallet, &air, DEAD, "signature aa bb").unwrap();
    assert_eq!(none, keys);
    let named = psp_claim_keys(
        &mut wallet,
        &air,
        DEAD,
        &format!("keyset {}\nsignature aa bb", keysets.current),
    )
    .unwrap();
    assert_eq!(named, keys);
    match psp_claim_keys(&mut wallet, &air, DEAD, "keyset 0123456789abcdef") {
        Err(WalletError::Mint(why)) => assert!(why.contains("no longer live"), "{why}"),
        other => panic!("expected a retired keyset to be refused, got {other:?}"),
    }

    // The rotation sync reads the window over AIR; a wallet with no PSP notes has
    // nothing to roll over.
    let log = rotation_sync(&mut wallet, &air, Kind::Psp, DEAD).unwrap();
    assert!(log.is_empty(), "{log:?}");

    assert!(
        wallet.air_requests().is_empty(),
        "every request ended with its answer"
    );
    assert!(open_wallet(&dir).air_requests().is_empty());
    // Nothing is cached: each of the eight calls above was its own request.
    wait_for_next(&state_dir, 8);
    listener.stop().unwrap();
}

#[test]
fn a_kept_request_is_resumed_by_a_call_of_its_own_kind_only() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("kinds");
    let psp = real_psp(&dir);
    let state_dir = scratch("kinds-state");
    let air = air_settings(&server, &did, 2, 1);

    // A mint-info request is waiting, unanswered, from an earlier run.
    let (mut wallet, info_request) = wallet_with_request(&dir, &did, vec![0]);

    // A keys call makes a request of its own: the PSP is not listening yet.
    match psp_keys(&mut wallet, &air, DEAD) {
        Err(WalletError::Mint(why)) => assert!(why.contains("did not answer"), "{why}"),
        other => panic!("expected the PSP to be unreachable, got {other:?}"),
    }
    let kept = wallet.air_requests().to_vec();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0], info_request, "the mint-info request is untouched");
    assert_eq!(kept[1].kind, KIND_KEYS);
    assert_eq!(open_wallet(&dir).air_requests(), &kept[..]);

    // The PSP starts and reads slot 0, where the keys request of the try was
    // written (the old mint-info request never was). The next keys call carries
    // on with the same keys request: it finds the reply and writes nothing.
    let listener = start_serving(&server, &key, &state_dir, psp.serve());
    wait_for_next(&state_dir, 1);
    let air = air_settings(&server, &did, 10, 3);
    assert!(!psp_keys(&mut wallet, &air, DEAD).unwrap().is_empty());
    let left = wallet.air_requests().to_vec();
    assert_eq!(left, vec![info_request], "only the keys request ended");
    thread::sleep(Duration::from_millis(500));
    assert_eq!(air_listener::read_next(&state_dir).unwrap(), 1);
    listener.stop().unwrap();
}

#[test]
fn a_tampered_keys_reply_is_refused_and_a_signed_body_that_is_not_keys_is_too() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("keys-tamper");
    let air = air_settings(&server, &did, 5, 1);
    let honest = b"{\"keys\":{}}";

    // The control: the honest reply, planted for a kept keys request, is accepted.
    let (mut wallet, pending) = wallet_with_kind(&dir, &did, vec![0], KIND_KEYS);
    let reply = build_reply(
        &key,
        &request_of(&pending),
        STATUS_ANSWERED,
        addr::now_secs(),
        honest,
    );
    plant_reply(&server, &did, &pending, &reply);
    assert!(psp_keys(&mut wallet, &air, DEAD).unwrap().is_empty());
    assert!(wallet.air_requests().is_empty());

    // A man in the middle changes the keys: the signature no longer holds.
    let (mut wallet, pending) =
        wallet_with_kind(&scratch("keys-tamper-2"), &did, vec![0], KIND_KEYS);
    let mut forged = build_reply(
        &key,
        &request_of(&pending),
        STATUS_ANSWERED,
        addr::now_secs(),
        honest,
    );
    forged[111 + 3] ^= 1;
    plant_reply(&server, &did, &pending, &forged);
    match psp_keys(&mut wallet, &air, DEAD) {
        Err(WalletError::Mint(why)) => assert!(
            why.contains("refused") && why.contains("signature"),
            "{why}"
        ),
        other => panic!("expected the reply to be refused, got {other:?}"),
    }
    assert!(wallet.air_requests().is_empty());

    // A reply signed by someone else, naming the right PSP.
    let (other, _) = mint_key();
    let (mut wallet, pending) =
        wallet_with_kind(&scratch("keys-tamper-3"), &did, vec![0], KIND_KEYS);
    let forged = sp_wire::air_request::build_reply_naming(
        &other,
        did.as_bytes(),
        &request_of(&pending),
        STATUS_ANSWERED,
        addr::now_secs(),
        honest,
    );
    plant_reply(&server, &did, &pending, &forged);
    assert!(matches!(
        psp_keys(&mut wallet, &air, DEAD),
        Err(WalletError::Mint(_))
    ));
    assert!(wallet.air_requests().is_empty());

    // The PSP signs a body that is not keys: the reply checks out, and reading it
    // as keys is refused as the PSP's own fault.
    let (mut wallet, pending) =
        wallet_with_kind(&scratch("keys-tamper-4"), &did, vec![0], KIND_KEYS);
    let junk = build_reply(
        &key,
        &request_of(&pending),
        STATUS_ANSWERED,
        addr::now_secs(),
        b"not json",
    );
    plant_reply(&server, &did, &pending, &junk);
    match psp_keys(&mut wallet, &air, DEAD) {
        Err(WalletError::Mint(why)) => assert!(why.contains("not what was asked for"), "{why}"),
        other => panic!("expected the body to be refused, got {other:?}"),
    }
    assert!(wallet.air_requests().is_empty());
}

#[test]
fn a_psp_that_cannot_answer_says_so_at_once() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("unavailable");
    let psp = real_psp(&dir);
    let state_dir = scratch("unavailable-state");
    let listener = start_serving(&server, &key, &state_dir, psp.serve());

    // The mint lock is poisoned: the HTTP routes would be a 500.
    let state = Arc::clone(&psp.state);
    let _ = thread::spawn(move || {
        let _held = state.logic.lock().unwrap();
        panic!("poisoning the mint lock on purpose");
    })
    .join();

    let mut wallet = open_wallet(&dir);
    // Three tries of ten seconds: it must not take them.
    let air = air_settings(&server, &did, 10, 3);
    let started = Instant::now();
    match psp_keys(&mut wallet, &air, DEAD) {
        Err(WalletError::Mint(why)) => {
            assert!(why.contains("could not answer keys now"), "{why}")
        }
        other => panic!("expected an unavailable PSP, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(9));
    assert!(wallet.air_requests().is_empty());
    listener.stop().unwrap();
}

#[test]
fn with_air_off_keys_keysets_and_rotation_go_over_http_and_nothing_goes_over_air() {
    let dir = scratch("keys-http");
    let psp = real_psp(&dir);
    let mut wallet = open_wallet(&dir);
    let off = AirSettings::default();
    assert!(!off.is_configured());

    let keys = psp_keys(&mut wallet, &off, &psp.base).unwrap();
    assert_eq!(keys, http::fetch_psp_keys(&psp.base).unwrap());
    assert!(
        psp_keysets(&mut wallet, &off, &psp.base)
            .unwrap()
            .keysets
            .contains_key(&psp_window(&mut wallet, &off, &psp.base).unwrap().current_id)
    );
    assert!(
        rotation_sync(&mut wallet, &off, Kind::Psp, &psp.base)
            .unwrap()
            .is_empty()
    );
    assert!(wallet.air_requests().is_empty());

    // A PSP that is not there is an HTTP error, at once: there is no AIR to try.
    match psp_keys(&mut wallet, &off, DEAD) {
        Err(WalletError::Mint(why)) => assert!(why.contains("127.0.0.1:9"), "{why}"),
        other => panic!("expected an HTTP failure, got {other:?}"),
    }
    assert!(wallet.air_requests().is_empty());
}
