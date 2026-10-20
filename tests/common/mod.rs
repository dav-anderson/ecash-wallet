//! The AIR plumbing the wallet's integration tests share: a real `air_server` in
//! this process (`sp_wire::air_request::local_server`), psp-mint's and esp-mint's
//! own AIR listeners on it, and the `AirSettings` (or fsp-mint `air.*` settings)
//! that point a wallet (or fsp-mint) at them.
//!
//! The PSP and the ESP are reached over AIR only, so a test that used to serve a
//! mint's HTTP routes runs its AIR listener instead (`air_flow.rs` and
//! `esp_air_flow.rs` carry their own copies of this, with the finer controls
//! those tests need).
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of a binary, and the tests take turns on it (it has a single
//! storage worker, so tests running in parallel starve each other past their
//! timeouts). A test holds its turn for as long as it holds an [`EspAt`] or a
//! [`PspAt`], so it must drop one before it starts another. Each has its own
//! mint key, so no two tests touch the same cell.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use ecash_wallet::config::AirSettings;
use esp_mint::server::EspState;
use mint_server::state::AppState;
use sp_wire::ServiceDid;
use sp_wire::air_request::addr;
use sp_wire::air_request::client::ServerRef;
use sp_wire::air_request::local_server;
use sp_wire::seal::SecretKey as DidKey;

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

// ---------------------------------------------------------------- the ESP

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

    /// Start the listener (the ESP mint is answering).
    pub fn listen(&self) {
        let settings = esp_mint::air_listener::Settings {
            server: (*self.server).clone(),
            held_reads: 16,
            timeout_secs: 10,
            state_dir: self.data.clone(),
        };
        let key = self.key.clone();
        let state = Arc::clone(&self.state);
        let listener = spawn(move |stopped| {
            let serve: Arc<esp_mint::air_listener::Serve> =
                Arc::new(move |kind: u8, body: &[u8]| {
                    esp_mint::server::air_served(&state, kind, body)
                });
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

    /// The `air.*` settings that point fsp-mint at this ESP mint.
    pub fn fsp_settings(&self, wait_secs: &str, attempts: &str) -> Vec<(&'static str, String)> {
        vec![
            ("air.esp_did", self.did.to_hex()),
            ("air.server", self.server.name.clone()),
            ("air.host", self.server.host.clone()),
            ("air.reply_wait_secs", wait_secs.to_string()),
            ("air.attempts", attempts.to_string()),
        ]
    }
}

// ---------------------------------------------------------------- the PSP

/// The PSP mint as its callers reach it, like [`EspAt`]: a rotating mint
/// (`rot`), answering through `air_served`, the `serve` psp-mint runs.
pub struct PspAt {
    pub did: ServiceDid,
    key: DidKey,
    state: Arc<AppState>,
    rot: psp_mint::server::SharedRotating,
    health: Arc<psp_mint::server::Health>,
    data: PathBuf,
    listener: Mutex<Option<Listener>>,
    /// Last, so the turn on the AIR server ends after the listener has stopped.
    pub server: Server,
}

impl PspAt {
    /// Take the turn on the AIR server and start the PSP mint's listener. `data`
    /// is a folder of the test's own (the listener's state goes in it).
    pub fn new(state: Arc<AppState>, rot: psp_mint::server::SharedRotating, data: &Path) -> PspAt {
        let server = server();
        std::fs::create_dir_all(data).unwrap();
        let health = psp_mint::server::Health::for_network(100, "regtest");
        health.record_scan_at(psp_mint::server::now_secs());
        let key = DidKey::new();
        let at = PspAt {
            did: addr::key_to_did(&key.public_key()),
            key,
            state,
            rot,
            health,
            data: data.to_path_buf(),
            listener: Mutex::new(None),
            server,
        };
        at.listen();
        at
    }

    /// Start the listener (the PSP mint is answering).
    pub fn listen(&self) {
        let settings = psp_mint::air_listener::Settings {
            server: (*self.server).clone(),
            held_reads: 16,
            timeout_secs: 10,
            state_dir: self.data.clone(),
        };
        let key = self.key.clone();
        let (state, rot, health) = (
            Arc::clone(&self.state),
            Arc::clone(&self.rot),
            Arc::clone(&self.health),
        );
        let listener = spawn(move |stopped| {
            let limits = psp_mint::server::Limits::default();
            let serve: Arc<psp_mint::air_listener::Serve> =
                Arc::new(move |kind: u8, body: &[u8]| {
                    psp_mint::server::air_served(&state, &rot, &health, &limits, kind, body)
                });
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
