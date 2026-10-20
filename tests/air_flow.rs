//! The PSP's calls over AIR, end to end: an `air_server` in this process,
//! psp-mint's real AIR listener answering, and the wallet asking, blocking, the
//! way the command line does. Mint info (`mint_info::verify_psp`) is answered
//! from a health report; keys, keysets and rotation (`psp_keys`, `psp_keysets`,
//! `psp_window` and what is built on them) and rollover and check-state
//! (`psp_post`, `rotation_sync`, `check_handoff`, `complete_import`,
//! `reclaim_handoff`) from a real rotating mint, whose HTTP routes are served in
//! the process too, so that the two ways can be compared. The built-in
//! placeholder SPI DID is tested here too: it never passes silently.
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

use ecash_wallet::config::{AirSettings, BUILTIN_SPI_DID};
use ecash_wallet::handoff::Standing;
use ecash_wallet::mint_info::{
    check_handoff, complete_import, psp_claim_keys, psp_keys, psp_keysets, psp_post, psp_window,
    reclaim_handoff, rotation_sync, sync_psp_limits, verify_psp,
};
use ecash_wallet::store::{PendingAirRequest, StoredNote, WalletData};
use ecash_wallet::{Kind, Wallet, WalletError, http};
use mint_server::state::AppState;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note, transaction_sighash};
use psp_mint::air_listener::{self, Serve, Settings};
use psp_mint::melts::MeltLog;
use psp_mint::rotation::{Rollovers, Rotor};
use psp_mint::server::{Health, Limits, Rotating, SharedRotating};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
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

/// One test at a time on the shared AIR server. It has a single storage worker,
/// so tests running in parallel starve each other past their timeouts.
static AIR_TURN: Mutex<()> = Mutex::new(());

/// The shared server plus this test's turn on it; the turn ends when this drops,
/// whether the test passed, failed or panicked.
struct Server {
    server: ServerRef,
    _turn: std::sync::MutexGuard<'static, ()>,
}

impl std::ops::Deref for Server {
    type Target = ServerRef;

    fn deref(&self) -> &ServerRef {
        &self.server
    }
}

fn server() -> Server {
    let turn = AIR_TURN.lock().unwrap_or_else(|e| e.into_inner());
    let server = local_server::start().expect("a local AIR server (is port 5702 free?)");
    Server {
        server,
        _turn: turn,
    }
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
        body_hash: String::new(),
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
    limits: Limits,
}

fn real_psp(dir: &PathBuf) -> RealPsp {
    real_psp_with(dir, Limits::default())
}

fn real_psp_with(dir: &PathBuf, limits: Limits) -> RealPsp {
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
        limits,
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
        limits,
    }
}

impl RealPsp {
    /// What the PSP's listener answers: the same `serve` psp-mint runs.
    fn serve(&self) -> Arc<Serve> {
        let (state, rot, health, limits) = (
            Arc::clone(&self.state),
            Arc::clone(&self.rot),
            Arc::clone(&self.health),
            self.limits,
        );
        Arc::new(move |kind, body: &[u8]| {
            psp_mint::server::air_served(&state, &rot, &health, &limits, kind, body)
        })
    }

    fn set_clock(&self, t: u64) {
        self.rot
            .rotor
            .lock()
            .unwrap()
            .clock
            .store(t, Ordering::SeqCst);
    }

    /// A note of `units` the PSP issued, as the wallet stores it.
    fn note(&self, units: u64) -> StoredNote {
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(kp.public_key());
        let (b, r) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let logic = self.state.logic.lock().unwrap();
        let out = logic
            .issue(&MintOutput {
                amount,
                blind_nonce: BlindNonce(b),
            })
            .unwrap();
        StoredNote {
            kind: Kind::Psp,
            amount: units,
            note: Note {
                nonce,
                signature: bdhke::unblind_message(&out.0, &r, &logic.public_keys()[&amount]),
            },
            spend_secret: kp.secret_key(),
            terms: None,
            reserved_by: None,
        }
    }

    fn spent(&self, n: &StoredNote) -> bool {
        let logic = self.state.logic.lock().unwrap();
        let rotor = self.rot.rotor.lock().unwrap();
        logic.is_spent(n.note.nonce).unwrap()
            || rotor
                .previous
                .as_ref()
                .is_some_and(|(_, l)| l.is_spent(n.note.nonce).unwrap())
    }
}

/// A wallet file that holds `notes`, signed by the PSP's keyset now.
fn wallet_with_notes(psp: &RealPsp, dir: &PathBuf, name: &str, notes: Vec<StoredNote>) -> Wallet {
    let path = dir.join(format!("{name}.json"));
    let ks = psp_mint::rotation::keyset_id(psp.state.logic.lock().unwrap().public_keys());
    let data = WalletData {
        keysets: notes.iter().map(|n| (n.id(), ks.clone())).collect(),
        notes,
        ..Default::default()
    };
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    Wallet::open(&path).unwrap()
}

fn psp_total(w: &Wallet) -> u64 {
    w.notes()
        .iter()
        .filter(|n| n.kind == Kind::Psp)
        .map(|n| n.amount)
        .sum()
}

fn zero_sig() -> secp256k1::schnorr::Signature {
    secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap()
}

/// The JSON of a rollover of all of `notes` into fresh outputs of the same
/// amounts, both on the PSP's current keyset, as `POST /rollover` takes it.
fn rollover_body(notes: &[StoredNote], keyset: &str) -> Vec<u8> {
    let outputs: Vec<MintOutput> = notes
        .iter()
        .map(|n| {
            let kp = Keypair::new(SECP256K1, &mut OsRng);
            let (b, _) = bdhke::blind_message(&Nonce(kp.public_key()).as_hash_preimage(), None);
            MintOutput {
                amount: Amount::from_units(n.amount),
                blind_nonce: BlindNonce(b),
            }
        })
        .collect();
    let unsigned: Vec<MintInput> = notes
        .iter()
        .map(|n| MintInput {
            amount: Amount::from_units(n.amount),
            note: n.note,
            spend_signature: zero_sig(),
        })
        .collect();
    let h = transaction_sighash(&unsigned, &outputs);
    let inputs = unsigned
        .into_iter()
        .zip(notes)
        .map(|(i, n)| MintInput {
            spend_signature: SECP256K1
                .sign_schnorr(&h, &Keypair::from_secret_key(SECP256K1, &n.spend_secret)),
            ..i
        })
        .collect();
    serde_json::to_vec(&sp_wire::psp::RolloverRequest {
        input_keysets: vec![keyset.to_string(); notes.len()],
        inputs,
        keyset: keyset.to_string(),
        outputs,
    })
    .unwrap()
}

fn check_body(notes: &[StoredNote]) -> Vec<u8> {
    serde_json::to_vec(&sp_wire::keys::CheckStateRequest {
        nonces: notes.iter().map(|n| n.note.nonce).collect(),
    })
    .unwrap()
}

const T: u64 = 1_800_000_000;
const H: u64 = 3600;
/// Past the stagger window of a 1-hour period.
const LATER: u64 = 100;

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

// ---------------------------------------------------------------- rollover and check-state

#[test]
fn a_rotation_rollover_goes_over_air_and_ends_as_it_does_over_http() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("roll");
    let psp = real_psp(&dir);
    let state_dir = scratch("roll-state");
    let listener = start_serving(&server, &key, &state_dir, psp.serve());
    let air = air_settings(&server, &did, 10, 3);

    // Over AIR. The URL is dead: with AIR configured nothing goes to it.
    let (a, b) = (psp.note(4), psp.note(1));
    let mut w = wallet_with_notes(&psp, &dir, "air", vec![a.clone(), b.clone()]);
    assert!(
        rotation_sync(&mut w, &air, Kind::Psp, DEAD)
            .unwrap()
            .is_empty()
    );
    psp.set_clock(T + H);
    rotation_sync(&mut w, &air, Kind::Psp, DEAD).unwrap(); // draws the swap time
    psp.set_clock(T + H + LATER);
    let air_log = rotation_sync(&mut w, &air, Kind::Psp, DEAD).unwrap();
    assert!(
        air_log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{air_log:?}"
    );
    assert_eq!(psp_total(&w), 5);
    assert!(psp.spent(&a) && psp.spent(&b), "the old notes are burned");
    assert!(w.pending_rollovers().is_empty());
    assert!(w.air_requests().is_empty(), "every request ended");

    // The same story over HTTP, on a mint of its own: the same log.
    let dir2 = scratch("roll-http");
    let psp2 = real_psp(&dir2);
    let (a2, b2) = (psp2.note(4), psp2.note(1));
    let mut w2 = wallet_with_notes(&psp2, &dir2, "http", vec![a2, b2]);
    assert!(
        http::rotation_sync(&mut w2, Kind::Psp, &psp2.base)
            .unwrap()
            .is_empty()
    );
    psp2.set_clock(T + H);
    http::rotation_sync(&mut w2, Kind::Psp, &psp2.base).unwrap();
    psp2.set_clock(T + H + LATER);
    let http_log = http::rotation_sync(&mut w2, Kind::Psp, &psp2.base).unwrap();
    assert_eq!(air_log, http_log);
    assert_eq!(psp_total(&w2), psp_total(&w));
    assert_eq!(w2.notes().len(), w.notes().len());
    listener.stop().unwrap();
}

#[test]
fn a_rollover_resent_over_air_is_the_same_answer_and_a_kept_request_is_found_by_its_body() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("resend");
    let psp = real_psp(&dir);
    let state_dir = scratch("resend-state");
    let a = psp.note(4);
    let b = psp.note(2);
    let mut w = wallet_with_notes(&psp, &dir, "w", vec![a.clone(), b.clone()]);
    let current = http::fetch_psp_keysets(&psp.base).unwrap().current;
    let roll = rollover_body(&[a.clone()], &current);
    let check = check_body(&[b.clone()]);

    // The PSP is not listening: both calls write their request and wait in vain.
    // They are kept apart, each with the hash of its own body.
    let air = air_settings(&server, &did, 1, 1);
    for (route, body) in [("rollover", &roll), ("check-state", &check)] {
        match psp_post(&mut w, &air, DEAD, route, body) {
            Err(WalletError::Mint(why)) => assert!(why.contains("did not answer"), "{why}"),
            other => panic!("{route}: expected the PSP to be unreachable, got {other:?}"),
        }
    }
    let kept = w.air_requests().to_vec();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0].kind, sp_wire::air_request::KIND_ROLLOVER);
    assert_eq!(kept[1].kind, sp_wire::air_request::KIND_CHECK_STATE);
    assert_ne!(kept[0].body_hash, kept[1].body_hash);
    assert!(!kept[0].body_hash.is_empty());
    assert_eq!(open_wallet_at(&dir, "w").air_requests(), &kept[..]);

    // The PSP starts. Its listener reads the two old slots and applies the
    // rollover once. The same call, made again, finds the reply of its kept
    // request and writes nothing; the other call is still kept, untouched.
    let air = air_settings(&server, &did, 10, 3);
    let listener = start_serving(&server, &key, &state_dir, psp.serve());
    wait_for_next(&state_dir, 2);
    let first = psp_post(&mut w, &air, DEAD, "rollover", &roll).unwrap();
    assert!(psp.spent(&a) && !psp.spent(&b));
    assert_eq!(
        w.air_requests(),
        &kept[1..],
        "only the rollover's request ended"
    );
    thread::sleep(Duration::from_millis(500));
    assert_eq!(
        air_listener::read_next(&state_dir).unwrap(),
        2,
        "the resumed call wrote nothing"
    );

    // A new call with the same body is a new request (the old one ended), and
    // the mint answers it from the answer it stored: the same bytes, and nothing
    // is rolled over twice.
    let again = psp_post(&mut w, &air, DEAD, "rollover", &roll).unwrap();
    assert_eq!(again, first);
    let state = psp_post(
        &mut w,
        &air,
        DEAD,
        "check-state",
        &check_body(&[a.clone(), b.clone()]),
    )
    .unwrap();
    assert_eq!(state["spent"], serde_json::json!([true, false]));
    listener.stop().unwrap();
}

fn open_wallet_at(dir: &PathBuf, name: &str) -> Wallet {
    Wallet::open(&dir.join(format!("{name}.json"))).unwrap()
}

#[test]
fn refusals_over_air_are_the_same_wallet_errors_as_over_http() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("refused");
    let limits = Limits {
        rollover_bytes: 4096,
        rollover_notes: 1,
        check_state_bytes: 4096,
        ..Limits::default()
    };
    let psp = real_psp_with(&dir, limits);
    let state_dir = scratch("refused-state");
    let listener = start_serving(&server, &key, &state_dir, psp.serve());
    let air = air_settings(&server, &did, 10, 3);
    let off = AirSettings::default();
    let (a, b) = (psp.note(1), psp.note(1));
    let mut w = wallet_with_notes(&psp, &dir, "w", vec![a.clone(), b.clone()]);
    let current = psp_keysets(&mut w, &air, DEAD).unwrap().current;

    // The same call both ways; the error is the same.
    let mut both = |body: &[u8]| {
        let over_air = psp_post(&mut w, &air, DEAD, "rollover", body);
        let over_http = psp_post(&mut w, &off, &psp.base, "rollover", body);
        (over_air, over_http)
    };

    // More notes than the cap: refused, with the mint's text.
    let two = rollover_body(&[a.clone(), b.clone()], &current);
    let (x, y) = both(&two);
    match (&x, &y) {
        (Err(WalletError::Refused(p)), Err(WalletError::Refused(q))) => {
            assert_eq!(p, q);
            assert!(p.contains("1 to 1 notes"), "{p}");
        }
        other => panic!("expected the same refusal, got {other:?}"),
    }

    // A note that is spent already: `SpentElsewhere`, with the position.
    let first = rollover_body(&[a.clone()], &current);
    assert!(both(&first).0.is_ok());
    let (x, y) = both(&rollover_body(&[a.clone()], &current));
    match (&x, &y) {
        (
            Err(WalletError::SpentElsewhere { why: p, inputs: i }),
            Err(WalletError::SpentElsewhere { why: q, inputs: j }),
        ) => {
            assert_eq!((p, i), (q, j));
            assert_eq!(i, &vec![0]);
        }
        other => panic!("expected the same SpentElsewhere, got {other:?}"),
    }

    // Over the ceiling: a plain mint error both ways (the HTTP 413), with the limit.
    let big = vec![b' '; 4097];
    let (x, y) = both(&big);
    for r in [&x, &y] {
        match r {
            Err(WalletError::Mint(why)) => assert!(why.contains("4096"), "{why}"),
            other => panic!("expected a 413-like mint error, got {other:?}"),
        }
    }
    drop(both);

    // Check-state: the same answer both ways.
    let check = check_body(&[a.clone(), b.clone()]);
    let x = psp_post(&mut w, &air, DEAD, "check-state", &check).unwrap();
    let y = psp_post(&mut w, &off, &psp.base, "check-state", &check).unwrap();
    assert_eq!(x, y);
    assert_eq!(x["spent"], serde_json::json!([true, false]));
    assert!(w.air_requests().is_empty(), "refusals end their requests");
    listener.stop().unwrap();
}

#[test]
fn a_handoff_is_checked_swapped_and_reclaimed_over_air() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("handoff");
    let psp = real_psp(&dir);
    let state_dir = scratch("handoff-state");
    let listener = start_serving(&server, &key, &state_dir, psp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let (a, b, c) = (psp.note(4), psp.note(1), psp.note(2));
    let mut dev = wallet_with_notes(&psp, &dir, "dev", vec![a.clone(), b.clone(), c.clone()]);
    let mut user = wallet_with_notes(&psp, &dir, "user", vec![]);
    let user_key = sp_wire::seal::SecretKey::from_array([7; 32]).unwrap();

    // 5 PSP to the user. Nothing is spent yet: it is still the sender's.
    let ids = dev.select_psp_handoff(5).unwrap();
    let out = dev
        .export_psp_handoff(&ids, DEAD, &user_key.public_key())
        .unwrap();
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Pending
    );

    // The user swaps over AIR, and the sender learns it was claimed.
    let imported = user
        .import_psp_handoff(&out.text, &user_key, "dev")
        .unwrap();
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(psp_total(&user), 5);
    assert!(psp.spent(&a) && psp.spent(&b));
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Received
    );

    // Another handoff, which the sender takes back before anyone swaps it.
    let ids = dev.select_psp_handoff(2).unwrap();
    let out = dev
        .export_psp_handoff(&ids, DEAD, &user_key.public_key())
        .unwrap();
    let done = reclaim_handoff(&mut dev, &air, &out.id).unwrap();
    assert_eq!(done.standing, Standing::Reclaimed);
    assert!(
        done.log.iter().any(|l| l.contains("reclaimed 2 PSP")),
        "{:?}",
        done.log
    );
    assert_eq!(psp_total(&dev), 2, "the notes are back, as fresh ones");
    assert!(psp.spent(&c));
    assert!(dev.air_requests().is_empty() && user.air_requests().is_empty());
    listener.stop().unwrap();
}

#[test]
fn a_mint_that_cannot_answer_a_rollover_says_so_at_once() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("roll-unavailable");
    let psp = real_psp(&dir);
    let state_dir = scratch("roll-unavailable-state");
    let listener = start_serving(&server, &key, &state_dir, psp.serve());
    let a = psp.note(1);
    let mut w = wallet_with_notes(&psp, &dir, "w", vec![a.clone()]);
    let current = http::fetch_psp_keysets(&psp.base).unwrap().current;
    let body = rollover_body(&[a], &current);

    let state = Arc::clone(&psp.state);
    let _ = thread::spawn(move || {
        let _held = state.logic.lock().unwrap();
        panic!("poisoning the mint lock on purpose");
    })
    .join();

    let air = air_settings(&server, &did, 10, 3);
    let started = Instant::now();
    match psp_post(&mut w, &air, DEAD, "rollover", &body) {
        Err(WalletError::Mint(why)) => {
            assert!(why.contains("could not answer rollover now"), "{why}")
        }
        other => panic!("expected an unavailable PSP, got {other:?}"),
    }
    // Not a refusal: the rollover is not cancelled, and the next call may retry.
    assert!(started.elapsed() < Duration::from_secs(9));
    assert!(w.air_requests().is_empty());
    listener.stop().unwrap();
}

#[test]
fn with_air_off_rollover_and_check_state_go_over_http_and_nothing_goes_over_air() {
    let dir = scratch("roll-http-off");
    let psp = real_psp(&dir);
    let a = psp.note(1);
    let mut w = wallet_with_notes(&psp, &dir, "w", vec![a.clone()]);
    let off = AirSettings::default();
    assert!(!off.is_configured());

    let state = psp_post(
        &mut w,
        &off,
        &psp.base,
        "check-state",
        &check_body(&[a.clone()]),
    )
    .unwrap();
    assert_eq!(state["spent"], serde_json::json!([false]));
    let current = psp_keysets(&mut w, &off, &psp.base).unwrap().current;
    let done = psp_post(
        &mut w,
        &off,
        &psp.base,
        "rollover",
        &rollover_body(&[a.clone()], &current),
    )
    .unwrap();
    assert_eq!(done["keyset"], current);
    assert!(psp.spent(&a));
    assert!(w.air_requests().is_empty());

    // A PSP that is not there is an HTTP error at once; any other route is not
    // a call the PSP takes over AIR.
    match psp_post(&mut w, &off, DEAD, "rollover", b"{}") {
        Err(WalletError::Mint(why)) => assert!(why.contains("127.0.0.1:9"), "{why}"),
        other => panic!("expected an HTTP failure, got {other:?}"),
    }
}

#[test]
fn the_builtin_placeholder_did_never_passes_silently() {
    let server = server();
    let dir = scratch("placeholder");
    // AIR is on (server and host) and air.psp_did is not set: the DID in use is
    // the wallet's built-in one, which is a placeholder.
    let air = AirSettings {
        server: server.name.clone(),
        host: server.host.clone(),
        reply_wait_secs: 1,
        attempts: 1,
        ..AirSettings::default()
    };
    assert!(air.is_configured());
    assert_eq!(air.psp_did, None);
    assert_eq!(air.psp_did().to_hex(), BUILTIN_SPI_DID);
    assert!(air.uses_builtin_did());
    assert!(air.placeholder_warning().unwrap().contains("PLACEHOLDER"));

    // A call is sealed to it and nobody can answer: unreachable, and the error
    // says that the DID is the placeholder, for a read and for a post.
    let mut wallet = open_wallet(&dir);
    match verify_psp(&mut wallet, &air, DEAD, NETWORK) {
        Err(WalletError::Mint(why)) => {
            assert!(why.contains("PLACEHOLDER"), "{why}");
            assert!(why.contains("air.psp_did"), "{why}");
        }
        other => panic!("expected the placeholder to be unreachable, got {other:?}"),
    }
    assert_eq!(wallet.air_requests()[0].mint, BUILTIN_SPI_DID);
    match psp_post(&mut wallet, &air, DEAD, "check-state", br#"{"nonces":[]}"#) {
        Err(WalletError::Mint(why)) => assert!(why.contains("PLACEHOLDER"), "{why}"),
        other => panic!("expected the placeholder to be unreachable, got {other:?}"),
    }

    // A real DID in `air.psp_did` replaces it: no warning, and no mention.
    let (_, did) = mint_key();
    let real = AirSettings {
        psp_did: Some(did),
        ..air.clone()
    };
    assert!(!real.uses_builtin_did());
    assert_eq!(real.placeholder_warning(), None);
    match verify_psp(&mut wallet, &real, DEAD, NETWORK) {
        Err(WalletError::Mint(why)) => assert!(!why.contains("PLACEHOLDER"), "{why}"),
        other => panic!("expected the unlistened DID to be unreachable, got {other:?}"),
    }

    // With AIR off the placeholder is never used, so there is nothing to warn about.
    assert_eq!(AirSettings::default().placeholder_warning(), None);
}
