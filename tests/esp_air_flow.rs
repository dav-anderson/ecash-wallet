//! The ESP's calls over AIR, end to end: an `air_server` in this process,
//! esp-mint's real AIR listener answering (with the same `serve` `esp-mint
//! serve` runs), and the wallet asking, blocking, the way the command line does.
//! Every call the wallet moved to AIR runs against a real ESP mint (rotating or
//! not, with a stand-in PSP for the exchange) whose HTTP routes are served in the
//! process too, so the two ways can be compared: mint info (`verify_esp`),
//! keysets, fees and rotation (`sync_esp_keysets`, `sync_esp_limits`,
//! `fetch_redeem_fees`, `esp_window`), rollover (`rotation_sync` for the ESP) and
//! the three that spend, `send_exchange`, `send_transfer` and `send_redeem`.
//! Refusals (a `400`, and a `409`, `413` and `404` that must not be taken for
//! one), a mint that cannot answer, a request resent, a late reply, tampered and
//! forged replies, HTTP with AIR off, and the built-in placeholder ESP DID.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of this binary, and each test has its own mint key.
//!
//! These tests use esp-mint's `air_listener`, which no tag has yet, so they are
//! built only with the `air-listener-tests` feature (the local-mints script
//! turns on every feature).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use ecash_wallet::air::{self, Party};
use ecash_wallet::config::{AirSettings, BUILTIN_ESP_DID, BUILTIN_SPI_DID};
use ecash_wallet::mint_info::{
    esp_window, fetch_redeem_fees, rotation_sync, send_exchange, send_redeem, send_transfer,
    sync_esp_keysets, sync_esp_limits, verify_esp, verify_psp,
};
use ecash_wallet::store::{HandedNote, Handover, PendingAirRequest, StoredNote, WalletData};
use ecash_wallet::{Kind, Wallet, WalletError, http};
use esp_mint::air_listener::{self, Serve, Settings};
use esp_mint::config::{Config, Handle};
use esp_mint::exchange;
use esp_mint::psp_client::HttpPsp;
use esp_mint::queue::Queue;
use esp_mint::responses::Responses;
use esp_mint::rotation::{Rollovers, Rotor};
use esp_mint::server::{self, EspState};
use esp_mint::terms::Terms;
use mint_core::MintLogic;
use mint_core::keygen;
use mint_core::store::Store;
use mint_server::api::{MeltRequest, MeltResponse};
use mint_server::state::AppState;
use mint_types::{Amount, BlindNonce, MintOutput, Nonce, Note, gen_denominations};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use sp_wire::air_request::addr::{self, reply_secret, seal_to, shared_wallet};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::envelope::{STATUS_ANSWERED, WireRequest, build_reply};
use sp_wire::air_request::{
    KIND_EXCHANGE, KIND_FEES, KIND_MINT_INFO, KIND_TRANSFER, MintInfo, Served, local_server,
};
use sp_wire::seal::SecretKey as DidKey;
use sp_wire::{ServiceDid, WIRE_VERSION};

const NETWORK: &str = "main";
/// A URL nothing listens on: with AIR configured nothing may go to it.
const DEAD: &str = "http://127.0.0.1:9";
/// A test amount of PSP, as in the exchange tests.
const ONE_PSP: u64 = 100_000_000_000;
/// A test ESP note size, a power of two.
const ONE: u64 = 1 << 36;
/// A redeemable-after day long past (mature), and one ahead.
const PAST: u64 = 100;
const DAY: u64 = 21_000;
const MEMO: &str = "btc:bc1qpayhere";
/// The rotating mint's clock at the start, and one rotation period.
const T0: u64 = 1_800_000_000;
const H: u64 = 3600;
/// Past the stagger window of a 1-hour period.
const LATER: u64 = 100;

fn secret(n: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    SecretKey::from_slice(&bytes).unwrap()
}

fn service() -> ServiceDid {
    ServiceDid::from(Keypair::from_secret_key(SECP256K1, &secret(1)).public_key())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ecash-wallet-espair-{}-{name}-{}",
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

fn mint_key() -> (DidKey, ServiceDid) {
    let key = DidKey::new();
    let did = addr::key_to_did(&key.public_key());
    (key, did)
}

/// AIR on, with the ESP's own DID.
fn air_settings(server: &ServerRef, did: &ServiceDid, wait: u64, attempts: u32) -> AirSettings {
    AirSettings {
        esp_did: Some(*did),
        server: server.name.clone(),
        host: server.host.clone(),
        reply_wait_secs: wait,
        attempts,
        ..AirSettings::default()
    }
}

fn open_wallet(dir: &Path, name: &str) -> Wallet {
    Wallet::open(&dir.join(format!("{name}.json"))).unwrap()
}

// ---------------------------------------------------------------- the listener

/// The listener on a thread of its own, as `serve` runs it. Dropping it stops it.
struct Listener {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

fn start_serving(server: &ServerRef, key: &DidKey, dir: &Path, serve: Arc<Serve>) -> Listener {
    let settings = Settings {
        server: server.clone(),
        held_reads: 16,
        timeout_secs: 10,
        state_dir: dir.to_path_buf(),
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
            runtime.block_on(air_listener::run(&settings, &key, &serve, async move {
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

fn wait_for_next(dir: &Path, want: u32) {
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

fn put(server: &ServerRef, key: &DidKey, bytes: Vec<u8>) {
    let put = block_on_new_runtime(move || async move {
        let client = client::connect(server).await.unwrap();
        client::create(&client, key, bytes, 10).await.unwrap()
    })
    .unwrap();
    assert!(matches!(put, client::Put::Created(_)));
}

// ---------------------------------------------------------------- the mint

type Memos = Arc<Mutex<BTreeMap<String, String>>>;

fn nonce_key(nonce: &Nonce) -> String {
    hex::encode(nonce.0.serialize())
}

/// `/melt`, which keeps the memo of the burn before it burns, as the real PSP's does.
async fn melt_recording(
    State((state, memos)): State<(Arc<AppState>, Memos)>,
    Json(req): Json<MeltRequest>,
) -> Result<Json<MeltResponse>, (StatusCode, Json<serde_json::Value>)> {
    let logic = state.logic.lock().unwrap();
    for input in &req.inputs {
        if !logic.is_spent(input.note.nonce).unwrap() {
            memos
                .lock()
                .unwrap()
                .insert(nonce_key(&input.note.nonce), req.memo.clone());
        }
    }
    logic
        .melt(&req.inputs, req.memo.as_bytes())
        .map(|burned| Json(MeltResponse { burned }))
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })
}

/// `/burns`: whether each note is spent, and the memo it was burned under.
async fn burns(
    State((state, memos)): State<(Arc<AppState>, Memos)>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let nonces: Vec<Nonce> = serde_json::from_value(req["nonces"].clone()).unwrap();
    let logic = state.logic.lock().unwrap();
    let burns: Vec<serde_json::Value> = nonces
        .iter()
        .map(|n| {
            let spent = logic.is_spent(*n).unwrap();
            let memo = if spent {
                memos.lock().unwrap().get(&nonce_key(n)).cloned()
            } else {
                None
            };
            serde_json::json!({"spent": spent, "memo": memo})
        })
        .collect();
    Json(serde_json::json!({ "burns": burns }))
}

fn serve_http(rt: &tokio::runtime::Runtime, app: Router) -> String {
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A real ESP mint with its HTTP routes served in this process, a stand-in PSP
/// beside it (for the exchange), and the listener's `serve` for it.
struct Esp {
    _rt: tokio::runtime::Runtime,
    /// The ESP's HTTP base URL.
    base: String,
    state: Arc<EspState>,
    psp: Arc<AppState>,
    /// The keyset the mint started on.
    ks: String,
}

/// A mint that rotates (a manual clock at [`T0`], an hour per generation) or one
/// that does not; the PSP the ESP calls is the stand-in unless `psp_url` is given
/// (a dead one, for the tests of a mint that cannot answer).
fn start_esp(dir: &Path, rotating: bool, config: Config, psp_url: Option<&str>) -> Esp {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
    let psp_logic = MintLogic::new(cfg, Store::open(&dir.join("psp-db")).unwrap());
    let psp = Arc::new(AppState {
        logic: Mutex::new(psp_logic),
        admin_token: String::new(),
    });
    let memos: Memos = Arc::new(Mutex::new(BTreeMap::new()));
    let psp_app = Router::new()
        .route("/melt", post(melt_recording))
        .route("/burns", post(burns))
        .with_state((Arc::clone(&psp), Arc::clone(&memos)));
    let psp_base = serve_http(&rt, psp_app);

    let data = dir.join("esp");
    std::fs::create_dir_all(&data).unwrap();
    let (logic, master, rotor, rollovers, ks) = if rotating {
        let (rotor, logic) = Rotor::open_at(&data, 1, 1, T0).unwrap();
        let master = rotor.current.master.clone();
        let ks = rotor.current.id.clone();
        (
            logic,
            master,
            Some(Mutex::new(rotor)),
            Some(Mutex::new(Rollovers::open(&data).unwrap())),
            ks,
        )
    } else {
        let (logic, master) = esp_mint::mint::open(&data).unwrap();
        let ks = esp_mint::rotation::keyset_id(&master);
        (logic, master, None, None, ks)
    };
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master,
        psp: Box::new(HttpPsp::new(psp_url.unwrap_or(&psp_base)).unwrap()),
        responses: Mutex::new(Responses::open(&data.join("responses.json")).unwrap()),
        queue_path: data.join("queue.json"),
        queue_lock: Mutex::new(()),
        config: Handle::new(config),
        rotor,
        rollovers,
        in_flight: Default::default(),
    });
    let base = serve_http(&rt, server::router(Arc::clone(&state)));
    Esp {
        _rt: rt,
        base,
        state,
        psp,
        ks,
    }
}

impl Esp {
    /// The listener's `serve` for this mint: what `esp-mint serve` runs.
    fn serve(&self) -> Arc<Serve> {
        let state = Arc::clone(&self.state);
        Arc::new(move |kind: u8, body: &[u8]| server::air_served(&state, kind, body))
    }

    fn set_clock(&self, t: u64) {
        self.state
            .rotor
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .clock
            .store(t, Ordering::SeqCst);
    }

    /// A PSP note of `units`, issued by the stand-in PSP, as the wallet stores it.
    fn psp_note(&self, units: u64) -> StoredNote {
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(kp.public_key());
        let (b, r) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let logic = self.psp.logic.lock().unwrap();
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

    fn psp_spent(&self, n: &StoredNote) -> bool {
        self.psp
            .logic
            .lock()
            .unwrap()
            .is_spent(n.note.nonce)
            .unwrap()
    }

    /// An ESP note the mint has issued for the service `G` and `day`, handed over
    /// as a customer would.
    fn handed(&self, units: u64, day: u64) -> HandedNote {
        self.handed_on(units, day, &self.ks, &self.state.master)
    }

    fn handed_on(
        &self,
        units: u64,
        day: u64,
        keyset: &str,
        master: &esp_mint::keys::MasterSecret,
    ) -> HandedNote {
        let terms = Terms {
            service: service(),
            redeemable_after_day: day,
        };
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(keypair.public_key());
        let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let sk = master.key_for(amount, &terms);
        let outcome = self
            .state
            .logic
            .lock()
            .unwrap()
            .issue_with_key(
                &sk,
                &MintOutput {
                    amount,
                    blind_nonce: BlindNonce(blind_point),
                },
            )
            .unwrap();
        let signature =
            bdhke::unblind_message(&outcome.0, &blinding_key, &sk.public_key(SECP256K1));
        HandedNote {
            amount: units,
            note: Note { nonce, signature },
            spend_secret: keypair.secret_key(),
            keyset: keyset.to_string(),
        }
    }

    fn is_spent(&self, note: &Note) -> bool {
        // A rotating mint keeps its spent lists by generation: the note is spent
        // if either live generation says so (`Gens::is_spent`).
        let logic = self.state.logic.lock().unwrap();
        let spent = match &self.state.rotor {
            Some(rotor) => rotor
                .lock()
                .unwrap()
                .gens(&logic)
                .is_spent(note.nonce)
                .unwrap(),
            None => logic.is_spent(note.nonce).unwrap(),
        };
        spent
    }

    /// (issued, redeemed) ESP units.
    fn totals(&self) -> (u64, u64) {
        let (issued, redeemed) = self.state.logic.lock().unwrap().audit_totals().unwrap();
        (issued.units, redeemed.units)
    }

    fn queue_len(&self) -> usize {
        Queue::open(&self.state.queue_path).unwrap().len()
    }
}

/// A wallet file that holds PSP `notes`, as if bought and claimed.
fn wallet_with_psp(dir: &Path, name: &str, notes: Vec<StoredNote>) -> Wallet {
    let path = dir.join(format!("{name}.json"));
    let data = WalletData {
        keysets: notes
            .iter()
            .map(|n| (n.id(), "00".repeat(8)))
            .collect::<BTreeMap<_, _>>(),
        notes,
        ..Default::default()
    };
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    Wallet::open(&path).unwrap()
}

fn give(wallet: &mut Wallet, day: u64, notes: Vec<HandedNote>) {
    wallet
        .receive_handover(&Handover {
            service: service(),
            redeemable_after_day: day,
            notes,
        })
        .unwrap();
}

fn json<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap()
}

// ---------------------------------------------------------------- the reads

#[test]
fn the_esp_reads_over_air_are_what_the_http_routes_give() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("reads");
    let esp = start_esp(&dir, true, Config::default(), None);
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    // Over AIR. The URL is dead: with AIR configured nothing goes to it.
    let mut w = open_wallet(&dir, "air");
    verify_esp(&mut w, &air, DEAD, NETWORK).unwrap();
    sync_esp_keysets(&mut w, &air, DEAD).unwrap();
    sync_esp_limits(&mut w, &air, DEAD).unwrap();
    let fees = fetch_redeem_fees(&mut w, &air, DEAD).unwrap();
    let window = esp_window(&mut w, &air, DEAD).unwrap();
    assert!(w.air_requests().is_empty(), "every request ended");

    // The same over HTTP, in a wallet of its own.
    let mut h = open_wallet(&dir, "http");
    http::verify_mint(&esp.base, NETWORK).unwrap();
    http::sync_esp_keysets(&mut h, &esp.base).unwrap();
    http::sync_esp_limits(&mut h, &esp.base).unwrap();
    let http_fees = http::fetch_redeem_fees(&esp.base).unwrap();
    let http_window = ecash_wallet::http::fetch_window(&esp.base).unwrap();

    assert_eq!(w.esp_output_keyset(), esp.ks);
    assert_eq!(w.esp_output_keyset(), h.esp_output_keyset());
    assert_eq!(w.esp_limits(), h.esp_limits());
    assert_eq!(w.esp_limits().exchange_max_items, Some(1000));
    assert_eq!(fees.fee_per_byte, http_fees.fee_per_byte);
    assert_eq!(fees.max_request_bytes, http_fees.max_request_bytes);
    assert_eq!(fees.max_memo_bytes, http_fees.max_memo_bytes);
    assert_eq!(window.current_id, http_window.current_id);
    assert_eq!(window.current_id, esp.ks);
    assert_eq!(window.previous_id, http_window.previous_id);
    assert_eq!(window.current_epoch, http_window.current_epoch);
    assert_eq!(window.period_hours, http_window.period_hours);

    // A mint on another network is refused over AIR as over HTTP, nothing sent.
    match verify_esp(&mut w, &air, DEAD, "regtest") {
        Err(WalletError::Invalid(why)) => {
            assert!(
                why.contains("is on main") && why.contains("Nothing was sent"),
                "{why}"
            )
        }
        other => panic!("expected the network to be refused, got {other:?}"),
    }
    listener.stop().unwrap();
}

#[test]
fn rotation_of_a_mint_that_does_not_rotate_is_an_error_over_air_as_over_http() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("no-rotation");
    let esp = start_esp(&dir, false, Config::default(), None);
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);
    let mut w = open_wallet(&dir, "w");

    // HTTP says 404. Over AIR a signed refusal that says it was a 404: a plain
    // mint error with the status, never a refusal of anything.
    match esp_window(&mut w, &air, DEAD) {
        Err(WalletError::Mint(why)) => assert!(why.contains("404"), "{why}"),
        other => panic!("expected a mint error saying 404, got {other:?}"),
    }
    match ecash_wallet::http::fetch_window(&esp.base) {
        Err(WalletError::Mint(why)) => assert!(why.contains("404"), "{why}"),
        other => panic!("expected a mint error saying 404, got {other:?}"),
    }
    assert!(
        w.air_requests().is_empty(),
        "a signed refusal ends the request"
    );
    // The keysets still answer on a mint that does not rotate.
    sync_esp_keysets(&mut w, &air, DEAD).unwrap();
    assert_eq!(w.esp_output_keyset(), esp.ks);
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- rollover

#[test]
fn an_esp_rotation_rollover_goes_over_air_and_ends_as_it_does_over_http() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("roll");
    let esp = start_esp(&dir, true, Config::default(), None);
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    // Two notes on the first keyset, in a wallet that sends over AIR.
    let (a, b) = (esp.handed(ONE, PAST), esp.handed(ONE, PAST));
    let (na, nb) = (a.note, b.note);
    let mut w = open_wallet(&dir, "air");
    give(&mut w, PAST, vec![a.clone(), b.clone()]);
    assert!(
        rotation_sync(&mut w, &air, Kind::Esp, DEAD)
            .unwrap()
            .is_empty()
    );
    esp.set_clock(T0 + H);
    rotation_sync(&mut w, &air, Kind::Esp, DEAD).unwrap(); // draws the swap time
    esp.set_clock(T0 + H + LATER);
    let air_log = rotation_sync(&mut w, &air, Kind::Esp, DEAD).unwrap();
    assert!(
        air_log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{air_log:?}"
    );
    assert!(
        esp.is_spent(&na) && esp.is_spent(&nb),
        "the old notes are burned"
    );
    assert_eq!(w.balance().esp, u128::from(2 * ONE));
    assert!(w.pending_rollovers().is_empty());
    assert!(w.air_requests().is_empty(), "every request ended");
    listener.stop().unwrap();

    // The same story over HTTP, on a mint of its own: the same log.
    let dir2 = scratch("roll-http");
    let esp2 = start_esp(&dir2, true, Config::default(), None);
    let (a2, b2) = (esp2.handed(ONE, PAST), esp2.handed(ONE, PAST));
    let mut w2 = open_wallet(&dir2, "http");
    give(&mut w2, PAST, vec![a2, b2]);
    assert!(
        http::rotation_sync(&mut w2, Kind::Esp, &esp2.base)
            .unwrap()
            .is_empty()
    );
    esp2.set_clock(T0 + H);
    http::rotation_sync(&mut w2, Kind::Esp, &esp2.base).unwrap();
    esp2.set_clock(T0 + H + LATER);
    let http_log = http::rotation_sync(&mut w2, Kind::Esp, &esp2.base).unwrap();
    assert_eq!(air_log, http_log);
    assert_eq!(w2.balance().esp, w.balance().esp);
    assert_eq!(w2.notes().len(), w.notes().len());
}

// ---------------------------------------------------------------- exchange, transfer, redeem

#[test]
fn an_exchange_over_air_is_what_http_returns_and_a_resent_one_is_not_applied_twice() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("exchange");
    let esp = start_esp(&dir, false, Config::default(), None);
    let state_dir = scratch("exchange-state");
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    sync_esp_keysets(&mut w, &air, DEAD).unwrap();
    sync_esp_limits(&mut w, &air, DEAD).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();

    let response = send_exchange(&mut w, &air, DEAD, &built.request).unwrap();
    let done = w.finish_exchange(&built.id, &response).unwrap();
    assert_eq!(done.esp_units, 4 * u128::from(ONE_PSP));
    assert_eq!(w.balance().esp, 4 * u128::from(ONE_PSP));
    assert!(esp.psp_spent(&note), "the PSP note was burned");
    assert_eq!(esp.totals(), (4 * ONE_PSP, 0));

    // The same request over HTTP is the stored answer, and over AIR again too:
    // nothing is applied twice.
    let over_http = http::send_exchange(&esp.base, &built.request).unwrap();
    assert_eq!(json(&over_http), json(&response));
    let again = send_exchange(&mut w, &air, DEAD, &built.request).unwrap();
    assert_eq!(json(&again), json(&response));
    assert_eq!(esp.totals(), (4 * ONE_PSP, 0));
    assert!(w.air_requests().is_empty(), "every request ended");
    listener.stop().unwrap();
}

#[test]
fn a_transfer_over_air_is_what_http_returns_and_a_double_presentation_is_spent_elsewhere() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("transfer");
    let esp = start_esp(&dir, false, Config::default(), None);
    let state_dir = scratch("transfer-state");
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let (a, b) = (esp.handed(2 * ONE, DAY), esp.handed(ONE, DAY));
    let (na, nb) = (a.note, b.note);
    let mut svc = open_wallet(&dir, "svc");
    sync_esp_keysets(&mut svc, &air, DEAD).unwrap();
    give(&mut svc, DAY, vec![a.clone(), b.clone()]);
    // a second copy of the same notes, held by another wallet
    let mut svc2 = open_wallet(&dir, "svc2");
    sync_esp_keysets(&mut svc2, &air, DEAD).unwrap();
    give(&mut svc2, DAY, vec![a, b]);
    let issued = esp.totals().0;
    // A transfer burns the notes (redeemed) and issues the new ones in their place
    // (issued): both move once, by the same amount.
    let after = (issued + 3 * ONE, 3 * ONE);

    let built = svc.build_transfer(&secret(1), None, None).unwrap();
    assert_eq!(built.esp_units, u128::from(3 * ONE));
    let response = send_transfer(&mut svc, &air, DEAD, &built.request).unwrap();
    let done = svc.finish_transfer(&built.id, &response).unwrap();
    assert_eq!(done.esp_units, u128::from(3 * ONE));
    assert!(esp.is_spent(&na) && esp.is_spent(&nb));
    assert_eq!(
        esp.totals(),
        after,
        "the same amount is redeemed and issued again"
    );

    // The same request over HTTP, and over AIR again: the stored answer.
    let over_http = http::send_transfer(&esp.base, &built.request).unwrap();
    assert_eq!(json(&over_http), json(&response));
    let again = send_transfer(&mut svc, &air, DEAD, &built.request).unwrap();
    assert_eq!(json(&again), json(&response));
    assert_eq!(esp.totals(), after);

    // The other copy is a double presentation: over AIR the same
    // `SpentElsewhere`, naming the same notes, as over HTTP.
    let dup = svc2.build_transfer(&secret(1), None, None).unwrap();
    let over_air = send_transfer(&mut svc2, &air, DEAD, &dup.request).unwrap_err();
    let over_http = http::send_transfer(&esp.base, &dup.request).unwrap_err();
    match (&over_air, &over_http) {
        (
            WalletError::SpentElsewhere { inputs: a, why: wa },
            WalletError::SpentElsewhere { inputs: h, why: wh },
        ) => {
            assert_eq!(a, h);
            assert_eq!(wa, wh);
            // the mint refuses on the first spent input and names only it
            assert_eq!(a.len(), 1);
        }
        other => panic!("expected SpentElsewhere both ways, got {other:?}"),
    }
    assert_eq!(over_air.to_string(), over_http.to_string());
    assert_eq!(esp.totals(), after, "nothing was applied");
    listener.stop().unwrap();
}

#[test]
fn a_redemption_goes_over_air_in_its_binary_encoding_and_a_resent_one_is_not_applied_twice() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("redeem");
    let esp = start_esp(
        &dir,
        false,
        Config {
            redeem_fee_per_byte: 1_000_000,
            ..Config::default()
        },
        None,
    );
    let state_dir = scratch("redeem-state");
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let a = esp.handed(4 * ONE, PAST);
    let na = a.note;
    let mut w = open_wallet(&dir, "w");
    sync_esp_keysets(&mut w, &air, DEAD).unwrap();
    give(&mut w, PAST, vec![a]);

    // The fees come over AIR too.
    let fees = fetch_redeem_fees(&mut w, &air, DEAD).unwrap();
    assert_eq!(fees.fee_per_byte, 1_000_000);
    let built = w.build_redemption(&secret(1), MEMO, &fees, now()).unwrap();
    assert_eq!(built.len(), 1);
    let body = built[0].body.clone();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&body).is_err(),
        "the body is the canonical binary encoding, not JSON"
    );

    let response = send_redeem(&mut w, &air, DEAD, &body).unwrap();
    let outcome = w.finish_redemption(&built[0].id, &response).unwrap();
    assert_eq!(outcome.message, "payout queued");
    assert!(esp.is_spent(&na));
    assert_eq!(esp.totals().1, 4 * ONE);
    assert_eq!(esp.queue_len(), 1);

    // The same bytes over HTTP, and over AIR again: the stored answer, and one
    // queue entry, not three.
    let over_http = http::send_redeem(&esp.base, &body).unwrap();
    assert_eq!(json(&over_http), json(&response));
    let again = send_redeem(&mut w, &air, DEAD, &body).unwrap();
    assert_eq!(json(&again), json(&response));
    assert_eq!(esp.totals().1, 4 * ONE);
    assert_eq!(esp.queue_len(), 1);
    assert!(w.air_requests().is_empty());
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- refusals

#[test]
fn a_400_is_a_refusal_over_air_as_over_http_but_a_409_a_413_and_a_404_are_not() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("refusals");
    let esp = start_esp(
        &dir,
        false,
        Config {
            transfer_max_request_bytes: 1000,
            redeem_max_request_bytes: 100,
            ..Config::default()
        },
        None,
    );
    let state_dir = scratch("refusals-state");
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    sync_esp_keysets(&mut w, &air, DEAD).unwrap();
    sync_esp_limits(&mut w, &air, DEAD).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();

    // A 400 (a keyset the mint does not have): `Refused`, with the HTTP text,
    // and nothing is burned.
    let mut bad = built.request.clone();
    bad.keyset = "ff".repeat(8);
    let over_air = send_exchange(&mut w, &air, DEAD, &bad).unwrap_err();
    let over_http = http::send_exchange(&esp.base, &bad).unwrap_err();
    assert!(matches!(over_air, WalletError::Refused(_)), "{over_air:?}");
    assert!(
        matches!(over_http, WalletError::Refused(_)),
        "{over_http:?}"
    );
    assert_eq!(over_air.to_string(), over_http.to_string());
    assert!(!esp.psp_spent(&note));

    // A 409, the same exchange arriving while it is being processed: a plain
    // mint error that says 409, over AIR as over HTTP. It is not a refusal: the
    // pending exchange stays, with its note reserved, and the same request goes
    // through once the first is over.
    let hash = exchange::request_hash(&built.request).unwrap();
    let claim = esp.state.in_flight.claim(&hash).expect("a free place");
    for result in [
        send_exchange(&mut w, &air, DEAD, &built.request).unwrap_err(),
        http::send_exchange(&esp.base, &built.request).unwrap_err(),
    ] {
        match result {
            WalletError::Mint(why) => assert!(why.contains("409"), "{why}"),
            other => panic!("expected a mint error saying 409, got {other:?}"),
        }
    }
    assert_eq!(w.pending_exchanges().len(), 1);
    assert!(!esp.psp_spent(&note));
    drop(claim);
    let response = send_exchange(&mut w, &air, DEAD, &built.request).unwrap();
    w.finish_exchange(&built.id, &response).unwrap();
    assert!(esp.psp_spent(&note));

    // A 413 on a transfer: a plain mint error that says so, both ways.
    let mut svc = open_wallet(&dir, "svc");
    sync_esp_keysets(&mut svc, &air, DEAD).unwrap();
    let notes: Vec<_> = (0..8).map(|_| esp.handed(ONE, DAY)).collect();
    give(&mut svc, DAY, notes);
    let big = svc.build_transfer(&secret(1), None, None).unwrap();
    for result in [
        send_transfer(&mut svc, &air, DEAD, &big.request).unwrap_err(),
        http::send_transfer(&esp.base, &big.request).unwrap_err(),
    ] {
        match result {
            WalletError::Mint(why) => assert!(why.contains("413"), "{why}"),
            other => panic!("expected a mint error saying 413, got {other:?}"),
        }
    }
    assert_eq!(svc.pending_transfers().len(), 1, "not cancelled");

    // A 413 on a redemption is `RedeemRefused` with its code, both ways.
    let mut r = open_wallet(&dir, "r");
    sync_esp_keysets(&mut r, &air, DEAD).unwrap();
    give(&mut r, PAST, vec![esp.handed(ONE, PAST)]);
    let mut fees = fetch_redeem_fees(&mut r, &air, DEAD).unwrap();
    assert_eq!(
        fees.max_request_bytes, 100,
        "the fees say the mint's ceiling"
    );
    // The wallet refuses to build under a ceiling that small (it will not split
    // below one note), so the request is built as for a roomy mint and sent to
    // this one.
    fees.max_request_bytes = 1 << 20;
    let redeem = r.build_redemption(&secret(1), MEMO, &fees, now()).unwrap();
    let body = redeem[0].body.clone();
    assert!(body.len() > 100);
    let over_air = send_redeem(&mut r, &air, DEAD, &body).unwrap_err();
    let over_http = http::send_redeem(&esp.base, &body).unwrap_err();
    for e in [&over_air, &over_http] {
        match e {
            WalletError::RedeemRefused { code, .. } => assert_eq!(code, "request_too_large"),
            other => panic!("expected RedeemRefused, got {other:?}"),
        }
    }
    listener.stop().unwrap();
}

#[test]
fn a_psp_the_esp_cannot_reach_is_a_mint_error_that_keeps_the_exchange_pending() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("dead-psp");
    // Nothing listens on port 9: the HTTP route would answer 502.
    let esp = start_esp(&dir, false, Config::default(), Some("http://127.0.0.1:9"));
    let state_dir = scratch("dead-psp-state");
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    sync_esp_keysets(&mut w, &air, DEAD).unwrap();
    sync_esp_limits(&mut w, &air, DEAD).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();

    // Over AIR a signed "unavailable"; over HTTP a 502. Neither is a refusal,
    // and the wallet says the request may be sent again.
    match send_exchange(&mut w, &air, DEAD, &built.request) {
        Err(WalletError::Mint(why)) => {
            assert!(why.contains("could not answer exchange now"), "{why}");
            assert!(why.contains("Send the same request again"), "{why}");
        }
        other => panic!("expected a mint error, got {other:?}"),
    }
    match http::send_exchange(&esp.base, &built.request) {
        Err(WalletError::Mint(why)) => assert!(why.contains("502"), "{why}"),
        other => panic!("expected a mint error saying 502, got {other:?}"),
    }
    assert_eq!(w.pending_exchanges().len(), 1);
    assert_eq!(w.balance().reserved, 1, "the note is reserved, not freed");
    assert!(!esp.psp_spent(&note));
    assert_eq!(esp.totals(), (0, 0));
    assert!(
        w.air_requests().is_empty(),
        "a signed reply ends the request"
    );
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- not answered, late, tampered

#[test]
fn an_unanswered_exchange_is_kept_and_the_next_call_carries_on_with_it() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("kept");
    let esp = start_esp(&dir, false, Config::default(), None);
    let state_dir = scratch("kept-state");

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    // The mint is not listening: the call writes its request and waits in vain.
    let quick = air_settings(&server, &did, 1, 1);
    // (The keysets and limits cannot be read either, so name the mint's keyset
    // by hand as a wallet that had read them earlier would.)
    w.note_esp_keysets(DEAD, &esp.ks, None).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();
    match send_exchange(&mut w, &quick, DEAD, &built.request) {
        Err(WalletError::Mint(why)) => {
            assert!(
                why.contains("did not answer") && why.contains("the ESP"),
                "{why}"
            )
        }
        other => panic!("expected the ESP to be unreachable, got {other:?}"),
    }
    let kept = w.air_requests().to_vec();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].kind, KIND_EXCHANGE);
    assert_eq!(kept[0].mint, did.to_hex());
    assert!(!kept[0].body_hash.is_empty());
    assert_eq!(open_wallet(&dir, "w").air_requests(), &kept[..]);
    assert!(!esp.psp_spent(&note));

    // The mint starts. Its listener reads the old slot and applies the exchange
    // once. The same call, made again, finds the reply of its kept request and
    // writes nothing.
    let air = air_settings(&server, &did, 10, 3);
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    wait_for_next(&state_dir, 1);
    assert!(esp.psp_spent(&note));
    let response = send_exchange(&mut w, &air, DEAD, &built.request).unwrap();
    assert!(w.air_requests().is_empty());
    thread::sleep(Duration::from_millis(500));
    assert_eq!(
        air_listener::read_next(&state_dir).unwrap(),
        1,
        "nothing was written"
    );
    w.finish_exchange(&built.id, &response).unwrap();
    assert_eq!(esp.totals(), (4 * ONE_PSP, 0));
    listener.stop().unwrap();
}

/// A wallet file that already holds a request in flight for `did` (of `kind`
/// and `body`), as if an earlier run had written it and then been stopped.
fn wallet_with_request(
    dir: &Path,
    did: &ServiceDid,
    kind: u8,
    body: &[u8],
) -> (Wallet, PendingAirRequest) {
    use sha2::{Digest, Sha256};
    let (r, request_id) = (DidKey::new(), addr::random_id());
    let pending = PendingAirRequest {
        kind,
        request_id: hex::encode(request_id),
        mint: did.to_hex(),
        r: addr::secret_to_hex(&r),
        slots: vec![0],
        created_at: addr::now_secs(),
        body_hash: if body.is_empty() {
            String::new()
        } else {
            hex::encode(Sha256::digest(body))
        },
    };
    let data = WalletData {
        air_requests: vec![pending.clone()],
        ..Default::default()
    };
    std::fs::write(dir.join("w.json"), serde_json::to_vec(&data).unwrap()).unwrap();
    (open_wallet(dir, "w"), pending)
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

fn request_of(pending: &PendingAirRequest, kind: u8) -> WireRequest {
    let r = addr::secret_from_hex(&pending.r).unwrap();
    WireRequest::new(
        kind,
        hex::decode(&pending.request_id)
            .unwrap()
            .try_into()
            .unwrap(),
        addr::key_to_bytes(&r.public_key()),
    )
}

#[test]
fn a_tampered_forged_or_wrong_kind_reply_to_an_esp_call_is_refused_and_applies_nothing() {
    let server = server();
    let (key, did) = mint_key();
    let (psp_key, _) = mint_key();
    let air = air_settings(&server, &did, 5, 1);
    let answer: &[u8] = br#"{"keyset":"k","signatures":[],"keys":[]}"#;
    let now = addr::now_secs();

    // (a read and a call with a body; the body of an exchange here is never
    // parsed by anyone, since no mint answers)
    for (kind, body) in [
        (KIND_FEES, Vec::new()),
        (KIND_EXCHANGE, br#"{"x":1}"#.to_vec()),
    ] {
        let call = |w: &mut Wallet| match kind {
            KIND_FEES => sync_esp_limits(w, &air, DEAD).map(|_| ()),
            _ => air::answer(w, &air, Party::Esp, kind, &body).map(|_| ()),
        };

        // A byte of the answer changed after it was signed.
        let dir = scratch("tamper");
        let (mut w, pending) = wallet_with_request(&dir, &did, kind, &body);
        let mut forged = build_reply(
            &key,
            &request_of(&pending, kind),
            STATUS_ANSWERED,
            now,
            answer,
        );
        forged[100] ^= 1;
        plant_reply(&server, &did, &pending, &forged);
        match call(&mut w) {
            Err(WalletError::Mint(why)) => {
                assert!(
                    why.contains("refused") && why.contains("signature"),
                    "kind {kind}: {why}"
                )
            }
            other => panic!("kind {kind}: expected the reply to be refused, got {other:?}"),
        }
        assert!(
            w.air_requests().is_empty(),
            "a write-once cell cannot be answered differently"
        );

        // The PSP's key (another mint's) signing an answer to the ESP's request.
        let dir = scratch("wrong-mint");
        let (mut w, pending) = wallet_with_request(&dir, &did, kind, &body);
        let other = build_reply(
            &psp_key,
            &request_of(&pending, kind),
            STATUS_ANSWERED,
            now,
            answer,
        );
        plant_reply(&server, &did, &pending, &other);
        match call(&mut w) {
            Err(WalletError::Mint(why)) => {
                assert!(why.contains("different mint DID"), "kind {kind}: {why}")
            }
            other => panic!("kind {kind}: expected the reply to be refused, got {other:?}"),
        }

        // The mint's genuine answer to another call with the same id and key.
        let dir = scratch("wrong-kind");
        let (mut w, pending) = wallet_with_request(&dir, &did, kind, &body);
        let other_kind = if kind == KIND_EXCHANGE {
            KIND_TRANSFER
        } else {
            KIND_EXCHANGE
        };
        let wrong = build_reply(
            &key,
            &request_of(&pending, other_kind),
            STATUS_ANSWERED,
            now,
            answer,
        );
        plant_reply(&server, &did, &pending, &wrong);
        match call(&mut w) {
            Err(WalletError::Mint(why)) => {
                assert!(why.contains("different question"), "kind {kind}: {why}")
            }
            other => panic!("kind {kind}: expected the reply to be refused, got {other:?}"),
        }
        assert!(w.air_requests().is_empty());
    }
}

// ---------------------------------------------------------------- HTTP, DIDs

#[test]
fn with_air_off_every_esp_call_goes_over_http_and_nothing_goes_over_air() {
    let server = server();
    let dir = scratch("off");
    let esp = start_esp(&dir, true, Config::default(), None);
    // AIR is off: no server, no host. A listener would be asked for nothing.
    let (key, _) = mint_key();
    let state_dir = scratch("off-state");
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = AirSettings::default();
    assert!(!air.is_configured());
    assert!(air.placeholder_warnings().is_empty());

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    verify_esp(&mut w, &air, &esp.base, NETWORK).unwrap();
    sync_esp_keysets(&mut w, &air, &esp.base).unwrap();
    sync_esp_limits(&mut w, &air, &esp.base).unwrap();
    assert_eq!(
        fetch_redeem_fees(&mut w, &air, &esp.base)
            .unwrap()
            .max_memo_bytes,
        256
    );
    assert_eq!(
        esp_window(&mut w, &air, &esp.base).unwrap().current_id,
        esp.ks
    );
    let built = w.build_exchange(4, service(), None).unwrap();
    let response = send_exchange(&mut w, &air, &esp.base, &built.request).unwrap();
    w.finish_exchange(&built.id, &response).unwrap();
    assert!(esp.psp_spent(&note));
    assert!(
        rotation_sync(&mut w, &air, Kind::Esp, &esp.base)
            .unwrap()
            .is_empty()
    );
    assert!(w.air_requests().is_empty());
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        air_listener::read_next(&state_dir).unwrap(),
        0,
        "nothing went over AIR"
    );
    listener.stop().unwrap();
}

#[test]
fn the_psp_and_the_esp_share_an_air_server_and_each_is_asked_at_its_own_did() {
    let server = server();
    let (esp_key, esp_did) = mint_key();
    let (psp_key, psp_did) = mint_key();
    let dir = scratch("shared");
    let esp = start_esp(&dir, false, Config::default(), None);
    let esp_state = scratch("shared-esp");
    let psp_state = scratch("shared-psp");
    let listener = start_serving(&server, &esp_key, &esp_state, esp.serve());
    // A stand-in for the PSP: answers only mint info, as its own DID.
    let psp_serve: Arc<Serve> = Arc::new(|kind: u8, _: &[u8]| {
        (kind == KIND_MINT_INFO).then(|| {
            Served::Body(
                serde_json::to_vec(&MintInfo {
                    status: "ok".into(),
                    wire_version: WIRE_VERSION,
                    network: NETWORK.into(),
                })
                .unwrap(),
            )
        })
    });
    let psp_listener = start_serving(&server, &psp_key, &psp_state, psp_serve);
    let air = AirSettings {
        psp_did: Some(psp_did),
        esp_did: Some(esp_did),
        server: server.name.clone(),
        host: server.host.clone(),
        reply_wait_secs: 10,
        attempts: 3,
        ..AirSettings::default()
    };
    assert!(air.placeholder_warnings().is_empty());
    let mut w = open_wallet(&dir, "w");

    // One server, two DIDs, two answers.
    verify_psp(&mut w, &air, DEAD, NETWORK).unwrap();
    verify_esp(&mut w, &air, DEAD, NETWORK).unwrap();
    assert_eq!(Party::Psp.did(&air), psp_did);
    assert_eq!(Party::Esp.did(&air), esp_did);

    // A kind only the ESP serves, asked of the PSP's DID, is not answered
    // (and the ESP's listener never sees it): the wallet gets no reply.
    let quick = AirSettings {
        reply_wait_secs: 1,
        attempts: 1,
        ..air.clone()
    };
    match air::call(&mut w, &quick, Party::Psp, KIND_FEES) {
        Err(WalletError::Mint(why)) => assert!(why.contains("did not answer"), "{why}"),
        other => panic!("expected no reply from the PSP's DID, got {other:?}"),
    }
    // The kept request is the PSP's (its DID), apart from any request to the ESP.
    let kept = w.air_requests().to_vec();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].mint, psp_did.to_hex());
    assert_eq!(kept[0].kind, KIND_FEES);
    // The ESP's fees, same kind, go to its own DID and are answered.
    let fees = air::fetch_text(&mut w, &air, Party::Esp, KIND_FEES).unwrap();
    assert!(fees.contains("exchange"));
    assert_eq!(
        w.air_requests(),
        &kept[..],
        "the PSP's request was not taken for it"
    );
    psp_listener.stop().unwrap();
    listener.stop().unwrap();
}

#[test]
fn the_builtin_placeholder_esp_did_never_passes_silently() {
    let server = server();
    let dir = scratch("placeholder");
    // AIR is on (server and host), air.esp_did is not set: the ESP's DID is the
    // wallet's built-in one, a placeholder, and so is the PSP's.
    let air = AirSettings {
        server: server.name.clone(),
        host: server.host.clone(),
        reply_wait_secs: 1,
        attempts: 1,
        ..AirSettings::default()
    };
    assert!(air.is_configured());
    assert_eq!(air.esp_did, None);
    assert_eq!(air.esp_did().to_hex(), BUILTIN_ESP_DID);
    assert_ne!(BUILTIN_ESP_DID, BUILTIN_SPI_DID);
    assert!(air.uses_builtin_esp_did());
    assert!(
        air.esp_placeholder_warning()
            .unwrap()
            .contains("air.esp_did")
    );
    assert_eq!(air.placeholder_warnings().len(), 2);

    // A call is sealed to it and nobody can answer: unreachable, and the error
    // says that the DID is the ESP's placeholder, for a read and a call with a body.
    let mut w = open_wallet(&dir, "w");
    match verify_esp(&mut w, &air, DEAD, NETWORK) {
        Err(WalletError::Mint(why)) => {
            assert!(why.contains("PLACEHOLDER ESP DID"), "{why}");
            assert!(why.contains("air.esp_did"), "{why}");
        }
        other => panic!("expected the placeholder to be unreachable, got {other:?}"),
    }
    assert_eq!(w.air_requests()[0].mint, BUILTIN_ESP_DID);
    match air::answer(&mut w, &air, Party::Esp, KIND_EXCHANGE, br#"{"x":1}"#) {
        Err(WalletError::Mint(why)) => assert!(why.contains("PLACEHOLDER ESP DID"), "{why}"),
        other => panic!("expected the placeholder to be unreachable, got {other:?}"),
    }

    // A real DID in `air.esp_did` replaces it: no mention of a placeholder.
    let (_, did) = mint_key();
    let real = AirSettings {
        esp_did: Some(did),
        ..air.clone()
    };
    assert!(!real.uses_builtin_esp_did());
    assert_eq!(real.esp_placeholder_warning(), None);
    match verify_esp(&mut w, &real, DEAD, NETWORK) {
        Err(WalletError::Mint(why)) => assert!(!why.contains("PLACEHOLDER"), "{why}"),
        other => panic!("expected the unlistened DID to be unreachable, got {other:?}"),
    }
}
