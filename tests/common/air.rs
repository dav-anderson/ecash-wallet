//! The AIR plumbing the wallet's integration tests share: a real `air_server` in
//! this process (`sp_wire::air_request::local_server`), psp-mint's, esp-mint's
//! and fsp-mint's own AIR listeners on it, and the `AirSettings` (or fsp-mint
//! `air.*` settings) that point a wallet (or fsp-mint) at them.
//!
//! The PSP, the ESP and the FSP mints are reached over AIR only, so a test that
//! used to serve a mint's HTTP routes runs its AIR listener instead (`air_flow.rs`
//! and `esp_air_flow.rs` start listeners of their own on the `serve` closures
//! built here, with the finer controls those tests need). fsp-mint's listener
//! answers on the same shared server as the ESP mint's, as a service's own mint
//! does: the DIDs differ, so the mailboxes do.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of a binary, and the tests take turns on it (it has a single
//! storage worker, so tests running in parallel starve each other past their
//! timeouts). A test holds its turn for as long as it holds an [`EspAt`] or a
//! [`PspAt`], so it must drop one before it starts another. Each has its own
//! mint key, so no two tests touch the same cell.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ecash_wallet::Wallet;
use ecash_wallet::config::{AirSettings, FspAir};
use ecash_wallet::store::Handover;
use esp_mint::server::EspState;
use fsp_mint::config::ConfigCell;
use fsp_mint::issue::Issues;
use fsp_mint::server::FspState;
use fsp_mint::spend::Spender;
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use sp_wire::ServiceDid;
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::stream::KeysetPublisher;
use sp_wire::air_request::{KIND_FSP_SPEND, Served, addr, local_server};
use sp_wire::seal::SecretKey as DidKey;

use super::{EspMint, PspMint, scratch};

/// One test at a time on the shared AIR server.
static AIR_TURN: Mutex<()> = Mutex::new(());

/// The shared server plus this test's turn on it; the turn ends when this drops,
/// whether the test passed, failed or panicked.
pub struct Server {
    server: ServerRef,
    _turn: std::sync::MutexGuard<'static, ()>,
}

impl std::ops::Deref for Server {
    type Target = ServerRef;

    fn deref(&self) -> &ServerRef {
        &self.server
    }
}

pub fn server() -> Server {
    let turn = AIR_TURN.lock().unwrap_or_else(|e| e.into_inner());
    let server = local_server::start().expect("a local AIR server (is port 5702 free?)");
    Server {
        server,
        _turn: turn,
    }
}

/// Whether the mailbox slot `slot` of `mint` on `server` holds nothing, read once
/// at once. A call of the wallet has ended when it returns, so a request it had
/// written would be in the first slot the mint's listener has not taken yet: this
/// is how a test shows that a call wrote nothing, with no waiting.
pub fn slot_is_empty(server: &ServerRef, mint: &ServiceDid, slot: u32) -> bool {
    let key = addr::mailbox_secret(mint, slot).public_key();
    block_on_new_runtime(move || async move {
        let client = client::connect(server).await.unwrap();
        client::read_once(&client, key, 10).await.unwrap()
    })
    .unwrap()
    .is_none()
}

/// Wait, for at most 20 seconds, until mailbox slot `slot` of `mint` holds a
/// request (the event itself, polled), and fail with a message if it never does.
pub fn wait_for_slot(server: &ServerRef, mint: &ServiceDid, slot: u32) {
    let until = Instant::now() + Duration::from_secs(20);
    while slot_is_empty(server, mint, slot) {
        assert!(
            Instant::now() < until,
            "slot {slot} of the mint was never written"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// A listener on a thread of its own, as `serve` runs it. Dropping it stops it.
pub struct Listener {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

fn spawn(
    run: impl FnOnce(tokio::sync::oneshot::Receiver<()>) -> Result<(), String> + Send + 'static,
) -> Listener {
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let thread = thread::Builder::new()
        .name("test-air-listener".into())
        .spawn(move || run(stopped))
        .unwrap();
    Listener {
        stop: Some(stop),
        thread: Some(thread),
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

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------- the key streams

/// A shared handle on the publisher of a PSP mint's or an FSP mint's key sets,
/// with the two switches a test of the key check needs.
///
/// - *tampered*: the mint's key sets are published with one key changed, so the
///   key sets the mint signs with are not the ones on AIR (a mint that signs with
///   keys of its own, which is what the wallet's check is for). The key set's ID
///   covers every key, so the one on AIR has another ID than the one the mint
///   signs under. It applies to what is published from then on; a cell on AIR
///   cannot be changed, so a test sets it before the key set it means to spoil
///   is first published.
/// - *held*: the mint publishes nothing by itself (not when it starts and not
///   after a request), only when the test calls `publish`. It is how a test
///   makes a key set late.
#[derive(Clone)]
pub struct Publisher {
    inner: Arc<Mutex<KeysetPublisher>>,
    tampered: Arc<AtomicBool>,
    held: Arc<AtomicBool>,
}

impl Publisher {
    /// Publish the key sets that are live from now on with one key changed
    /// (`true`), or as they are (`false`).
    pub fn tamper(&self, on: bool) {
        self.tampered.store(on, Ordering::SeqCst);
    }

    /// Publish nothing by itself (`true`), or again after each request (`false`).
    pub fn hold(&self, on: bool) {
        self.held.store(on, Ordering::SeqCst);
    }

    fn is_held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }
}

/// A publisher for the mint whose DID key is `key`, on `server`.
pub fn publisher(server: &ServerRef, key: &DidKey) -> Publisher {
    Publisher {
        inner: Arc::new(Mutex::new(KeysetPublisher::new(server.clone(), 10, key))),
        tampered: Arc::new(AtomicBool::new(false)),
        held: Arc::new(AtomicBool::new(false)),
    }
}

/// As [`publisher`], tampered from the start.
pub fn tampered_publisher(server: &ServerRef, key: &DidKey) -> Publisher {
    let p = publisher(server, key);
    p.tamper(true);
    p
}

/// As [`publisher`], held from the start.
pub fn held_publisher(server: &ServerRef, key: &DidKey) -> Publisher {
    let p = publisher(server, key);
    p.hold(true);
    p
}

/// How a mint's key set stream behaves in a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMode {
    /// The mint publishes the key sets it has now and after every request it
    /// answers: what `serve` does, without waiting for its writer's tick.
    Live,
    /// As `Live`, with one key of each key set changed (see [`Publisher`]).
    Tampered,
    /// The mint publishes nothing until a test calls `publish` (see [`Publisher`]).
    Held,
}

impl StreamMode {
    fn publisher(self, server: &ServerRef, key: &DidKey) -> Publisher {
        match self {
            StreamMode::Live => publisher(server, key),
            StreamMode::Tampered => tampered_publisher(server, key),
            StreamMode::Held => held_publisher(server, key),
        }
    }
}

/// A key that is not any mint's: the generator times 7.
fn spoiled_key() -> secp256k1::PublicKey {
    let mut bytes = [0u8; 32];
    bytes[31] = 7;
    secp256k1::SecretKey::from_slice(&bytes)
        .unwrap()
        .public_key(SECP256K1)
}

/// Open the key stream of the ESP mint whose DID key is `key`, on `server`, give
/// it to `state`, and publish once at once: the control record and the days
/// ahead are on AIR when this returns. `dir` is a folder of the test's own (the
/// stream's state goes in it). From then on [`esp_serve`] publishes after every
/// request the mint answers, so what a reply was signed with is on AIR before the
/// wallet reads the reply (the mint's own writer does the same a few seconds
/// later; the wallet waits for it, and a test of that wait leaves the stream
/// unopened).
pub fn esp_stream(state: &Arc<EspState>, server: &ServerRef, key: &DidKey, dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    let stream = esp_mint::stream::Stream::open(dir, server.clone(), 10, key)
        .expect("the ESP mint's key stream opens");
    assert!(
        state.stream.set(stream).is_ok(),
        "the ESP mint already has a key stream"
    );
    esp_mint::server::stream_pass(state).expect("the key stream publishes");
}

/// The 64 public keys (2^0 to 2^63) an ESP mint signs with for `service` on the
/// redeemable-after day `day`, in its current key set: what its key stream would
/// publish for them.
pub fn esp_day_keys(
    state: &EspState,
    service: &ServiceDid,
    day: u64,
) -> [secp256k1::PublicKey; 64] {
    let terms = esp_mint::terms::Terms {
        service: *service,
        redeemable_after_day: day,
    };
    std::array::from_fn(|i| {
        state
            .master
            .key_for(mint_types::Amount::from_units(1u64 << i), &terms)
            .public_key(SECP256K1)
    })
}

/// 64 keys that are no mint's.
pub fn spoiled_keys() -> [secp256k1::PublicKey; 64] {
    std::array::from_fn(|i| {
        let mut bytes = [0u8; 32];
        bytes[30] = 1;
        bytes[31] = i as u8 + 1;
        secp256k1::SecretKey::from_slice(&bytes)
            .unwrap()
            .public_key(SECP256K1)
    })
}

/// Write by hand, as the ESP mint whose DID key is `key`, a key stream that says
/// what the test wants it to say: one control record for each maturity rule in
/// `rules` (record `n` has `rules[n]`; the generation, `generation`, is the same
/// in all), and one day record for each `(day, service, keys)` of `days`. A test
/// that does this does not open the mint's own stream (a cell cannot be written
/// twice), so it is how a mint that publishes one thing and signs with another
/// is made.
pub fn esp_published_by_hand(
    server: &ServerRef,
    key: &DidKey,
    generation: &str,
    rules: &[u64],
    days: &[(u64, ServiceDid, [secp256k1::PublicKey; 64])],
) {
    use sp_wire::air_request::stream::{
        Cell, ControlRecord, DayRecord, GenerationRef, ServiceKeys, write_cell,
    };
    let mut id = [0u8; 8];
    id.copy_from_slice(&hex::decode(generation).expect("the key set ID is hex"));
    let mut writes: Vec<(Cell, Vec<u8>)> = Vec::new();
    for (index, &maturity_days) in rules.iter().enumerate() {
        let record = ControlRecord {
            index: index as u32,
            maturity_days,
            current: GenerationRef { epoch: 0, id },
            previous: None,
        };
        writes.push((
            Cell::Control {
                index: index as u32,
            },
            record.encode(),
        ));
    }
    for (day, service, keys) in days {
        let record = DayRecord {
            generation: id,
            day: *day,
            bucket: 0,
            buckets: 1,
            part: 0,
            services: vec![ServiceKeys {
                service: *service,
                keys: *keys,
            }],
        };
        writes.push((record.cell(), record.encode()));
    }
    let (server, key) = (server.clone(), *key);
    block_on_new_runtime(move || async move {
        let client = client::connect(&server).await.unwrap();
        for (cell, bytes) in &writes {
            write_cell(&client, &key, cell, bytes, 10).await.unwrap();
        }
    })
    .unwrap();
}

/// One pass of a PSP mint's or an FSP mint's key set publisher; `true` when
/// something was written. A tampered publisher changes the key of the smallest
/// amount of each key set it publishes first.
fn publish_live(
    publisher: &Publisher,
    live: &[sp_wire::air_request::stream::KeysetRecord],
) -> bool {
    let spoiled: Vec<sp_wire::air_request::stream::KeysetRecord>;
    let live = if publisher.tampered.load(Ordering::SeqCst) {
        spoiled = live
            .iter()
            .map(|record| {
                let mut record = record.clone();
                if let Some((_, key)) = record.keys.iter_mut().next() {
                    *key = spoiled_key();
                }
                record
            })
            .collect();
        &spoiled[..]
    } else {
        live
    };
    publisher
        .inner
        .lock()
        .unwrap()
        .pass(live)
        .expect("the key sets publish")
        .is_some()
}

// ---------------------------------------------------------------- the ESP

/// What esp-mint's listener answers: the `serve` `esp-mint serve` runs.
///
/// If the mint has a key stream (see [`esp_stream`]) it is published after each
/// request, before the reply goes out: the keys the reply was signed with, and the
/// control record of a rotation the request made, are on AIR when the wallet reads
/// the reply.
pub fn esp_serve(state: &Arc<EspState>) -> Arc<esp_mint::air_listener::Serve> {
    let state = Arc::clone(state);
    Arc::new(move |kind: u8, body: &[u8]| {
        let answer = esp_mint::server::air_served(&state, kind, body);
        if state.stream.get().is_some() {
            esp_mint::server::stream_pass(&state).expect("the key stream publishes");
        }
        answer
    })
}

/// The ESP mint as its callers reach it: its DID and the AIR server, its
/// listener (which a test may stop and start again, as a mint that is down and
/// comes back), and the state it answers from.
pub struct EspAt {
    pub did: ServiceDid,
    key: DidKey,
    pub state: Arc<EspState>,
    /// The ESP mint's data folder: where the listener keeps `air_mailbox_next`.
    data: PathBuf,
    listener: Mutex<Option<Listener>>,
    /// Last, so the turn on the AIR server ends after the listener has stopped.
    pub server: Server,
}

impl EspAt {
    /// Take the turn on the AIR server and start the ESP mint's listener for
    /// `state`. `data` is a folder of the test's own (the listener's state goes
    /// in it).
    pub fn new(state: Arc<EspState>, data: &Path) -> EspAt {
        let server = server();
        std::fs::create_dir_all(data).unwrap();
        let key = DidKey::new();
        esp_stream(&state, &server, &key, &data.join("stream"));
        let at = EspAt {
            did: addr::key_to_did(&key.public_key()),
            key,
            state,
            data: data.to_path_buf(),
            listener: Mutex::new(None),
            server,
        };
        at.listen();
        at
    }

    /// As [`EspAt::new`], and the mint has no key stream of its own: what it
    /// says on AIR is written by hand, a control record for each of `rules` and
    /// the 64 keys of `service` for each of `days` (a `(day, service)`), the mint's
    /// own keys or, with `spoiled`, keys that are no mint's. A mint that signs
    /// with keys other than the ones it published.
    pub fn new_by_hand(
        state: Arc<EspState>,
        data: &Path,
        rules: &[u64],
        days: &[(u64, ServiceDid)],
        spoiled: bool,
    ) -> EspAt {
        let server = server();
        std::fs::create_dir_all(data).unwrap();
        let key = DidKey::new();
        let generation = state.rotor.lock().unwrap().current.id.clone();
        let published: Vec<_> = days
            .iter()
            .map(|(day, service)| {
                let keys = if spoiled {
                    spoiled_keys()
                } else {
                    esp_day_keys(&state, service, *day)
                };
                (*day, *service, keys)
            })
            .collect();
        esp_published_by_hand(&server, &key, &generation, rules, &published);
        let at = EspAt {
            did: addr::key_to_did(&key.public_key()),
            key,
            state,
            data: data.to_path_buf(),
            listener: Mutex::new(None),
            server,
        };
        at.listen();
        at
    }

    /// One pass of the ESP mint's stream writer now (one also runs after every
    /// request the mint answers): the keys of the days in use, the days ahead and
    /// the control record are on AIR when this returns. A test calls it after it
    /// moves the mint's clock and before the wallet's next call, when the wallet's
    /// next call is not a request the mint answers first.
    pub fn publish(&self) -> Option<String> {
        esp_mint::server::stream_pass(&self.state).expect("the key stream publishes")
    }

    /// Start the listener (the ESP mint is answering).
    pub fn listen(&self) {
        let settings = esp_mint::air_listener::Settings {
            server: (*self.server).clone(),
            held_reads: 16,
            timeout_secs: 10,
            state_dir: self.data.clone(),
        };
        let key = self.key;
        let serve = esp_serve(&self.state);
        let listener = spawn(move |stopped| {
            runtime().block_on(esp_mint::air_listener::run(
                &settings,
                &key,
                &serve,
                async move {
                    let _ = stopped.await;
                },
            ))
        });
        *self.listener.lock().unwrap() = Some(listener);
    }

    /// Stop the listener (the ESP mint is not answering).
    pub fn silence(&self) {
        drop(self.listener.lock().unwrap().take());
    }

    /// The wallet's `[air]` settings pointing at this ESP mint.
    pub fn air(&self, wait_secs: u64, attempts: u32) -> AirSettings {
        AirSettings {
            esp_did: Some(self.did),
            server: self.server.name.clone(),
            host: self.server.host.clone(),
            reply_wait_secs: wait_secs,
            attempts,
            ..AirSettings::default()
        }
    }

    /// The `air.*` settings that point fsp-mint at this ESP mint (`air.esp_*`),
    /// and its own listener at the same AIR server (`air.server`, `air.host`).
    pub fn fsp_settings(&self, wait_secs: &str, attempts: &str) -> Vec<(&'static str, String)> {
        vec![
            ("air.esp_did", self.did.to_hex()),
            ("air.esp_server", self.server.name.clone()),
            ("air.esp_host", self.server.host.clone()),
            ("air.server", self.server.name.clone()),
            ("air.host", self.server.host.clone()),
            ("air.reply_wait_secs", wait_secs.to_string()),
            ("air.attempts", attempts.to_string()),
        ]
    }
}

// ---------------------------------------------------------------- the PSP

impl PspMint {
    /// What psp-mint's listener answers: the `serve` `psp-mint serve` runs, with
    /// the records shared with the scan side.
    pub fn serve(&self, psp: ServiceDid) -> Arc<psp_mint::air_listener::Serve> {
        self.serve_inner(psp)
    }

    /// As [`PspMint::serve`], and after every request the mint answers, before the
    /// reply goes out, the key sets that are live then are published with
    /// `publisher` (a rotation the request made is on AIR when the wallet reads
    /// the reply). The key sets the mint has when this is called are published at
    /// once.
    pub fn serve_publishing(
        &self,
        psp: ServiceDid,
        publisher: &Publisher,
    ) -> Arc<psp_mint::air_listener::Serve> {
        let inner = self.serve_inner(psp);
        let (rot, publisher) = (Arc::clone(&self.rot), publisher.clone());
        // The key sets the mint has now are on AIR before the first request.
        publish_psp_unless_held(&rot, &publisher);
        Arc::new(move |kind: u8, body: &[u8]| {
            let answer = inner(kind, body);
            publish_psp_unless_held(&rot, &publisher);
            answer
        })
    }

    fn serve_inner(&self, psp: ServiceDid) -> Arc<psp_mint::air_listener::Serve> {
        let (state, rot, health, limits) = (
            Arc::clone(&self.state),
            Arc::clone(&self.rot),
            Arc::clone(&self.health),
            self.limits,
        );
        // The claims are checked against the records the scan side shares, and
        // every claim's signature covers the DID of the mint it is sent to.
        let desk = psp_mint::server::ClaimDesk {
            records: Arc::clone(&self.records),
            psp,
        };
        Arc::new(move |kind: u8, body: &[u8]| {
            psp_mint::server::air_served_with(&state, &rot, &desk, &health, &limits, kind, body)
        })
    }
}

/// [`publish_psp`], unless the publisher is held.
fn publish_psp_unless_held(rot: &psp_mint::server::SharedRotating, publisher: &Publisher) -> bool {
    !publisher.is_held() && publish_psp(rot, publisher)
}

/// Publish the key sets a PSP mint has now, if the stream does not hold them.
fn publish_psp(rot: &psp_mint::server::SharedRotating, publisher: &Publisher) -> bool {
    let live = {
        let rotor = rot.rotor.lock().unwrap();
        psp_mint::stream::live_records(&rotor).expect("the live key sets")
    };
    publish_live(publisher, &live)
}

/// The PSP mint as its callers reach it, like [`EspAt`]: its DID and the AIR
/// server, and its listener.
pub struct PspAt {
    pub did: ServiceDid,
    key: DidKey,
    serve: Arc<psp_mint::air_listener::Serve>,
    data: PathBuf,
    listener: Mutex<Option<Listener>>,
    rot: psp_mint::server::SharedRotating,
    stream: Publisher,
    /// Last, so the turn on the AIR server ends after the listener has stopped.
    pub server: Server,
}

impl PspAt {
    /// Take the turn on the AIR server and start the listener for `mint`. `data`
    /// is a folder of the test's own (the listener's state goes in it).
    pub fn new(mint: &PspMint, data: &Path) -> PspAt {
        PspAt::new_with(mint, data, StreamMode::Live)
    }

    /// As [`PspAt::new`], with the key set stream behaving as `mode` says.
    pub fn new_with(mint: &PspMint, data: &Path, mode: StreamMode) -> PspAt {
        let server = server();
        std::fs::create_dir_all(data).unwrap();
        let key = DidKey::new();
        let did = addr::key_to_did(&key.public_key());
        let stream = mode.publisher(&server, &key);
        let at = PspAt {
            did,
            key,
            serve: mint.serve_publishing(did, &stream),
            data: data.to_path_buf(),
            listener: Mutex::new(None),
            rot: Arc::clone(&mint.rot),
            stream,
            server,
        };
        at.listen();
        // The key sets the mint has now are on AIR when this returns (not when the
        // stream is held).
        publish_psp_unless_held(&at.rot, &at.stream);
        at
    }

    /// One pass of the PSP mint's key set stream: the key sets that are live now
    /// are published if the stream does not hold them yet. `true` when something
    /// was written. (One also runs after every request the mint answers, unless
    /// the stream is held.)
    pub fn publish(&self) -> bool {
        publish_psp(&self.rot, &self.stream)
    }

    /// The switches of the mint's key set publisher.
    pub fn stream(&self) -> &Publisher {
        &self.stream
    }

    /// The key the PSP mint signs its records and replies with and opens payloads
    /// with: the key of [`PspAt::did`].
    pub fn key(&self) -> DidKey {
        self.key
    }

    /// Start the listener (the PSP mint is answering).
    pub fn listen(&self) {
        let settings = psp_mint::air_listener::Settings {
            server: (*self.server).clone(),
            held_reads: 16,
            timeout_secs: 10,
            state_dir: self.data.clone(),
        };
        let key = self.key;
        let serve = Arc::clone(&self.serve);
        let listener = spawn(move |stopped| {
            runtime().block_on(psp_mint::air_listener::run(
                &settings,
                &key,
                &*serve,
                async move {
                    let _ = stopped.await;
                },
            ))
        });
        *self.listener.lock().unwrap() = Some(listener);
    }

    /// Stop the listener (the PSP mint is not answering).
    pub fn silence(&self) {
        drop(self.listener.lock().unwrap().take());
    }

    /// The wallet's `[air]` settings pointing at this PSP mint.
    pub fn air(&self, wait_secs: u64, attempts: u32) -> AirSettings {
        AirSettings {
            psp_did: Some(self.did),
            server: self.server.name.clone(),
            host: self.server.host.clone(),
            reply_wait_secs: wait_secs,
            attempts,
            ..AirSettings::default()
        }
    }
}

/// A PSP mint on a fixed clock together with its AIR listener (and the turn on
/// the shared server). Dereferences to the [`PspMint`].
pub struct PspUp {
    pub mint: PspMint,
    /// Last: the turn on the shared server ends after the rest is dropped.
    pub at: PspAt,
}

impl PspUp {
    /// The mint in `dir`, on the clock `clock`, with its listener.
    pub fn start(dir: &Path, clock: u64) -> PspUp {
        PspUp::start_with(dir, clock, StreamMode::Live)
    }

    /// As [`PspUp::start`], with the key set stream behaving as `mode` says.
    pub fn start_with(dir: &Path, clock: u64, mode: StreamMode) -> PspUp {
        let mint = PspMint::open_at(dir, clock);
        // The listener keeps its state in a folder of its own, outside `dir`,
        // which a test may remove while the listener is still running.
        let at = PspAt::new_with(&mint, &scratch("airstate-psp"), mode);
        PspUp { mint, at }
    }

    /// As [`PspUp::start`], with this psp-mint `Config` (for the tests that set
    /// fees).
    pub fn start_configured(dir: &Path, clock: u64, config: psp_mint::config::Config) -> PspUp {
        let mint = PspMint::open_configured(dir, clock, config);
        let at = PspAt::new(&mint, &scratch("airstate-psp"));
        PspUp { mint, at }
    }

    /// The wallet's `[air]` settings for this PSP: ten seconds a try, three tries.
    pub fn air(&self) -> AirSettings {
        self.at.air(10, 3)
    }
}

impl PspUp {
    /// One pass of the PSP mint's deliverer: the owed record that is next for each
    /// claim key is written to the AIR server, and its claim window opens now (the
    /// wall clock, as the claims are checked against it). A claim key with
    /// several records needs a pass for each.
    pub fn deliver(&self) -> psp_mint::delivery::Report {
        let mut deliverer =
            psp_mint::delivery::Deliverer::new((*self.at.server).clone(), 3, self.at.key());
        deliverer.pass_shared(&self.records, Instant::now(), addr::now_secs())
    }
}

impl std::ops::Deref for PspUp {
    type Target = PspMint;

    fn deref(&self) -> &PspMint {
        &self.mint
    }
}

// ---------------------------------------------------------------- the FSP

thread_local! {
    /// This test's service key. A test runs on a thread of its own, and a
    /// service's mailboxes on the shared AIR server are its DID's, so a key shared
    /// by tests would have each one's fsp-mint listener read the earlier tests'
    /// requests.
    static SERVICE_SECRET: [u8; 32] = SecretKey::new(&mut OsRng).secret_bytes();
}

/// The key pair of this test's service: the DID of its FSP mint, and what the
/// FSP mint's notes are issued under.
pub fn service_keypair() -> Keypair {
    let b = SERVICE_SECRET.with(|b| *b);
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&b).unwrap())
}

/// This test's service.
pub fn service() -> ServiceDid {
    ServiceDid::from(service_keypair().public_key())
}

/// The same key as the AIR key fsp-mint's listener answers under, made from the
/// hex of `service_key.hex` as `fsp-mint serve` makes it.
pub fn service_air_key() -> DidKey {
    let b = SERVICE_SECRET.with(|b| *b);
    addr::secret_from_hex(&hex::encode(b)).unwrap()
}

/// Publish the key sets an FSP mint has now (at its own clock), if the stream does
/// not hold them.
fn publish_fsp(state: &FspState, publisher: &Publisher) -> bool {
    let live =
        fsp_mint::stream::live_records(&state.spender, (state.clock)()).expect("the live key sets");
    publish_live(publisher, &live)
}

/// A service's fsp-mint as its callers reach it: its DID (the service's) and its
/// own AIR listener on the shared server, answering through `air_served`, the
/// `serve` fsp-mint runs. Dropping it stops the listener, so it must drop before
/// the [`EspAt`] that holds the turn on the server.
pub struct FspAt {
    _listener: Listener,
    pub did: ServiceDid,
    pub state: Arc<FspState>,
    server: ServerRef,
    fail_spend: Arc<AtomicBool>,
    stream: Publisher,
}

impl FspAt {
    /// Start the listener for `state` on `server` (the turn on it is held by the
    /// caller). `data` is a folder of the test's own (the listener's state goes in
    /// it).
    pub fn new(server: &ServerRef, state: Arc<FspState>, data: &Path) -> FspAt {
        FspAt::new_with(server, state, data, StreamMode::Live)
    }

    /// As [`FspAt::new`], with the key set stream behaving as `mode` says.
    pub fn new_with(
        server: &ServerRef,
        state: Arc<FspState>,
        data: &Path,
        mode: StreamMode,
    ) -> FspAt {
        std::fs::create_dir_all(data).unwrap();
        let key = service_air_key();
        let did = addr::key_to_did(&key.public_key());
        assert!(did == service(), "the AIR key is the service's DID key");
        let fail_spend = Arc::new(AtomicBool::new(false));
        let settings = fsp_mint::air_listener::Settings {
            server: server.clone(),
            held_reads: 16,
            timeout_secs: 10,
            state_dir: data.to_path_buf(),
        };
        let stream = mode.publisher(server, &key);
        let (answering, failing, publishing) =
            (Arc::clone(&state), Arc::clone(&fail_spend), stream.clone());
        let listener = spawn(move |stopped| {
            let serve: Arc<fsp_mint::air_listener::Serve> =
                Arc::new(move |kind: u8, body: &[u8]| {
                    // A mint that cannot answer a spend now: a signed "cannot
                    // answer now", and nothing is spent.
                    if kind == KIND_FSP_SPEND && failing.load(Ordering::SeqCst) {
                        return Some(Served::Unavailable);
                    }
                    let answer = fsp_mint::server::air_served(&answering, kind, body);
                    // What the reply was signed with is on AIR before it goes out.
                    if !publishing.is_held() {
                        publish_fsp(&answering, &publishing);
                    }
                    answer
                });
            runtime().block_on(fsp_mint::air_listener::run(
                &settings,
                &key,
                &serve,
                async move {
                    let _ = stopped.await;
                },
            ))
        });
        let at = FspAt {
            _listener: listener,
            did,
            state,
            server: server.clone(),
            fail_spend,
            stream,
        };
        // The key sets the mint has now are on AIR when this returns (not when the
        // stream is held).
        if !at.stream.is_held() {
            at.publish();
        }
        at
    }

    /// The switches of the mint's key set publisher.
    pub fn stream(&self) -> &Publisher {
        &self.stream
    }

    /// One pass of the FSP mint's key set stream: the key sets live now (a
    /// rotation that is due is made) are published if the stream does not hold
    /// them yet. `true` when something was written. (One also runs after every
    /// request the mint answers.)
    pub fn publish(&self) -> bool {
        publish_fsp(&self.state, &self.stream)
    }

    /// Make the mint unable to answer spends (`true`) or able again (`false`).
    pub fn fail_spend(&self, on: bool) {
        self.fail_spend.store(on, Ordering::SeqCst);
    }

    /// The wallet's `[air]` settings pointing at this FSP mint: the one `air.fsp`
    /// entry of its service. Neither the PSP's nor the ESP's.
    pub fn air(&self, wait_secs: u64, attempts: u32) -> AirSettings {
        AirSettings {
            fsp: vec![FspAir {
                service: self.did,
                server: self.server.name.clone(),
                host: self.server.host.clone(),
            }],
            reply_wait_secs: wait_secs,
            attempts,
            ..AirSettings::default()
        }
    }
}

/// The time the FSP mint first issued, in the tests that run one: rotation
/// activates 120 hours later, then every 240 hours.
pub const NOW: u64 = 1_791_571_184;

/// A service's FSP mint with the ESP mint behind it, both on their real AIR
/// listeners on the shared server.
pub struct Mints {
    pub esp: EspMint,
    /// The wallet's `[air]` settings: the `air.fsp` entry of the service.
    pub air: AirSettings,
    /// The FSP mint's clock, in seconds; a test moves it.
    pub clock: Arc<AtomicU64>,
    /// fsp-mint's AIR listener (and its state). It drops before the ESP mint's
    /// listener and the turn on the shared AIR server, which are last.
    pub fsp: FspAt,
    pub esp_at: EspAt,
}

impl Mints {
    /// Both mints in `dir`. `wait_secs` and `attempts` are how long one try of the
    /// FSP mint's calls to the ESP mint waits and how many tries (a test with an
    /// ESP mint that is down does not wait long); `memo_limit` is the longest memo
    /// the FSP mint takes.
    pub fn start(dir: &Path, wait_secs: &str, attempts: &str, memo_limit: Option<usize>) -> Mints {
        Mints::start_with(dir, wait_secs, attempts, memo_limit, StreamMode::Live)
    }

    /// As [`Mints::start`], with the FSP mint's key set stream behaving as `mode`
    /// says (the ESP mint's stream is always live).
    pub fn start_with(
        dir: &Path,
        wait_secs: &str,
        attempts: &str,
        memo_limit: Option<usize>,
        mode: StreamMode,
    ) -> Mints {
        let esp = EspMint::open_without_psp(&dir.join("esp"));
        // The listeners keep their state in folders of their own, outside `dir`.
        let esp_at = EspAt::new(Arc::clone(&esp.state), &scratch("airstate"));
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
            config: ConfigCell::new(cfg),
            data_dir: dir.join("fsp"),
        });
        let fsp = FspAt::new_with(&esp_at.server, state, &scratch("airstate-fsp"), mode);
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

    /// A wallet file `name.json` in `dir`, holding one ESP note of each of `units`
    /// for the service (none for an empty list), and the wallet opened on it. The
    /// notes are redeemable after the day the mint's default terms give at
    /// [`NOW`].
    pub fn wallet(&self, dir: &Path, name: &str, units: &[u64]) -> Wallet {
        let day = esp_mint::terms::Terms::new_at(service(), NOW).redeemable_after_day;
        self.wallet_on_days(dir, name, &[(day, units)])
    }

    /// As [`Mints::wallet`], with the notes on days of the caller's choice: one
    /// ESP note of each of `units` for the service for each `(day, units)`.
    pub fn wallet_on_days(&self, dir: &Path, name: &str, days: &[(u64, &[u64])]) -> Wallet {
        let mut w = super::open_wallet(&dir.join(format!("{name}.json"))).unwrap();
        for &(day, units) in days {
            let notes: Vec<_> = units
                .iter()
                .map(|&u| self.esp.handed(&service(), u, day))
                .collect();
            if !notes.is_empty() {
                w.receive_handover(&Handover {
                    service: service(),
                    redeemable_after_day: day,
                    notes,
                })
                .unwrap();
            }
        }
        w
    }
}
