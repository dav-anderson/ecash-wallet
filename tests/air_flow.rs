//! The PSP's mint info over AIR, end to end: an `air_server` in this process,
//! psp-mint's real AIR listener answering from its health report, and the
//! wallet's `verify_mint` (`mint_info::verify_psp`) asking, blocking, the way the
//! command line does.
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
use ecash_wallet::mint_info::verify_psp;
use ecash_wallet::store::{PendingAirRequest, WalletData};
use ecash_wallet::{Wallet, WalletError};
use mint_types::Amount;
use psp_mint::air_listener::{self, Settings};
use psp_mint::melts::MeltLog;
use psp_mint::server::Health;
use sp_wire::air_request::addr::{self, reply_secret, seal_to, shared_wallet};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::envelope::{STATUS_ANSWERED, WireRequest, build_reply};
use sp_wire::air_request::{MintInfo, local_server};
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
            runtime.block_on(air_listener::run(&settings, &key, &*info, async move {
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
    let (r, request_id) = (SecretKey::new(), addr::random_id());
    let pending = PendingAirRequest {
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
    WireRequest::mint_info(
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
