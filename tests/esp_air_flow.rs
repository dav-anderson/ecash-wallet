//! The ESP's calls over AIR, end to end: an `air_server` in this process,
//! esp-mint's real AIR listener answering (with the same `serve` `esp-mint
//! serve` runs), and the wallet asking, blocking, the way the command line does.
//! Every call the wallet makes of the ESP runs against a real, rotating ESP mint
//! (with a stand-in PSP for the exchange): mint info (`verify_esp`),
//! keysets, fees and rotation (`sync_esp_keysets`, `sync_esp_limits`,
//! `fetch_redeem_fees`, `esp_window`), rollover (`rotation_sync` for the ESP) and
//! the two that spend, `send_exchange` and `send_redeem`.
//! Refusals (a `400`, and a `409`, `413` and `404` that must not be taken for
//! one), a mint that cannot answer, a request resent, a late reply, tampered and
//! forged replies, the missing `air.server` and `air.host` (there is no HTTP
//! form of any call), and the built-in placeholder ESP DID.
//!
//! The AIR client always dials port 5702 (upstream item 12), so these tests need
//! that port free; `local_server::start` says so when it is not. One server
//! serves every test of this binary, and each test has its own mint key.
//!
//! These tests use esp-mint's `air_listener`, which no tag has yet, so they are
//! built only with the `air-listener-tests` feature (the local-mints script
//! turns on every feature).

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use ecash_wallet::air::{self, Party};
use ecash_wallet::config::{AirSettings, BUILTIN_ESP_DID, BUILTIN_SPI_DID};
use ecash_wallet::keystream::{Failed, KeyPolicy, Site};
use ecash_wallet::mint_info::{
    esp_window, fetch_redeem_fees, rotation_sync, send_exchange, send_redeem, sync_esp_keysets,
    sync_esp_limits, verify_esp, verify_psp,
};
use ecash_wallet::store::{HandedNote, Handover, PendingAirRequest, StoredNote, WalletData};
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::air_listener::{self, Serve, Settings};
use esp_mint::config::Config;
use esp_mint::exchange;
use esp_mint::psp_client::HttpPsp;
use esp_mint::queue::Queue;
use mint_core::MintLogic;
use mint_core::keygen;
use mint_core::state::AppState;
use mint_core::store::Store;
use mint_types::{Amount, BlindNonce, MintOutput, Nonce, Note, gen_denominations};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use sp_wire::air_request::addr::{self, reply_secret, seal_to, shared_wallet};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::envelope::{STATUS_ANSWERED, WireRequest, build_reply};
use sp_wire::air_request::{KIND_EXCHANGE, KIND_FEES, KIND_MINT_INFO, MintInfo, Served};
use sp_wire::melt::{MeltRequest, MeltResponse};
use sp_wire::seal::SecretKey as DidKey;
use sp_wire::{ServiceDid, WIRE_VERSION};

use common::air::{server, slot_is_empty};
use common::{EspMint, T0, esp_record, scratch};

const NETWORK: &str = "main";
/// A test amount of PSP, as in the exchange tests.
const ONE_PSP: u64 = 100_000_000_000;
/// A test ESP note size, a power of two.
const ONE: u64 = 1 << 36;
/// A redeemable-after day long past (mature), and one ahead.
const PAST: u64 = 100;
const DAY: u64 = 21_000;
const MEMO: &str = "btc:bc1qpayhere";
/// One rotation period (the rotating mint's clock starts at `T0`).
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
    Wallet::open(&dir.join(format!("{name}.json")), NETWORK).unwrap()
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
    let key = *key;
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

/// A real ESP mint (the shared, rotating fixture), a stand-in PSP beside it (for
/// the exchange, served over HTTP: the ESP's own calls to the PSP are SPI-local),
/// and the listener's `serve` for the ESP. Dereferences to the [`EspMint`].
struct Esp {
    _rt: tokio::runtime::Runtime,
    mint: EspMint,
    psp: Arc<AppState>,
}

impl std::ops::Deref for Esp {
    type Target = EspMint;

    fn deref(&self) -> &EspMint {
        &self.mint
    }
}

/// A mint that rotates (a manual clock at [`T0`], an hour per generation); the
/// PSP the ESP calls is the stand-in unless `psp_url` is given (a dead one, for
/// the tests of a mint that cannot answer).
fn start_esp(dir: &Path, config: Config, psp_url: Option<&str>) -> Esp {
    start_esp_at(dir, config, psp_url, T0)
}

/// As [`start_esp`], on the system clock: for the tests that finish an exchange,
/// whose day the wallet checks against its own clock (a send-day to reply-day
/// window; a mint on a fixed clock months away from the wallet's would fail it,
/// as a mint that signs for another day should).
fn start_esp_now(dir: &Path, config: Config, psp_url: Option<&str>) -> Esp {
    start_esp_at(dir, config, psp_url, 0)
}

fn start_esp_at(dir: &Path, config: Config, psp_url: Option<&str>, clock: u64) -> Esp {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let cfg = keygen::generate(&gen_denominations(2, Amount::from_units(1024)));
    let psp_logic = MintLogic::new(cfg, Store::open(&dir.join("psp-db")).unwrap());
    let psp = Arc::new(AppState {
        logic: Mutex::new(psp_logic),
    });
    let memos: Memos = Arc::new(Mutex::new(BTreeMap::new()));
    let psp_app = Router::new()
        .route("/melt", post(melt_recording))
        .route("/burns", post(burns))
        .with_state((Arc::clone(&psp), Arc::clone(&memos)));
    let psp_base = serve_http(&rt, psp_app);

    let mint = EspMint::open(
        &dir.join("esp"),
        Box::new(HttpPsp::new(psp_url.unwrap_or(&psp_base)).unwrap()),
        config,
        clock,
    );
    Esp { _rt: rt, mint, psp }
}

impl Esp {
    /// The listener's `serve` for this mint: what `esp-mint serve` runs.
    fn serve(&self) -> Arc<Serve> {
        common::air::esp_serve(&self.mint.state)
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
        self.mint.handed(&service(), units, day)
    }

    /// (issued, redeemed) ESP units.
    fn totals(&self) -> (u64, u64) {
        let (issued, redeemed) = self.state.logic.lock().unwrap().audit_totals().unwrap();
        (
            u64::try_from(issued).unwrap(),
            u64::try_from(redeemed).unwrap(),
        )
    }

    fn queue_len(&self) -> usize {
        Queue::open(&self.state.queue_path).unwrap().len()
    }
}

/// A wallet file that holds PSP `notes`, as if bought and claimed.
fn wallet_with_psp(dir: &Path, name: &str, notes: Vec<StoredNote>) -> Wallet {
    let path = dir.join(format!("{name}.json"));
    let data = WalletData {
        network: NETWORK.into(),
        keysets: notes
            .iter()
            .map(|n| (n.id(), "00".repeat(8)))
            .collect::<BTreeMap<_, _>>(),
        notes,
        ..Default::default()
    };
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    Wallet::open(&path, NETWORK).unwrap()
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
fn the_esp_reads_over_air_are_the_mints_own() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("reads");
    let esp = start_esp(&dir, Config::default(), None);
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let mut w = open_wallet(&dir, "air");
    verify_esp(&mut w, &air, NETWORK).unwrap();
    sync_esp_keysets(&mut w, &air, &esp_record(&air)).unwrap();
    sync_esp_limits(&mut w, &air).unwrap();
    let fees = fetch_redeem_fees(&mut w, &air).unwrap();
    let window = esp_window(&mut w, &air).unwrap();
    assert!(w.air_requests().is_empty(), "every request ended");

    assert_eq!(w.esp_output_keyset(), esp.keyset);
    assert_eq!(w.esp_limits().exchange_max_items, Some(1000));
    assert_eq!(fees.max_memo_bytes, 256);
    assert!(fees.max_request_bytes > 0);
    assert_eq!(window.current_id, esp.keyset);
    assert_eq!(window.period_hours, 1);

    // A mint on another network is refused, nothing sent.
    match verify_esp(&mut w, &air, "regtest") {
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

// ---------------------------------------------------------------- rollover

#[test]
fn an_esp_rotation_rollover_goes_over_air_and_ends_with_the_notes_on_the_new_keyset() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("roll");
    let esp = start_esp(&dir, Config::default(), None);
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    // Two notes on the first keyset.
    let (a, b) = (esp.handed(ONE, PAST), esp.handed(ONE, PAST));
    let (na, nb) = (a.note, b.note);
    let mut w = open_wallet(&dir, "air");
    give(&mut w, PAST, vec![a.clone(), b.clone()]);
    assert!(
        rotation_sync(&mut w, &air, Kind::Esp, &esp_record(&air))
            .unwrap()
            .is_empty()
    );
    esp.set_clock(T0 + H);
    rotation_sync(&mut w, &air, Kind::Esp, &esp_record(&air)).unwrap(); // draws the swap time
    esp.set_clock(T0 + H + LATER);
    let air_log = rotation_sync(&mut w, &air, Kind::Esp, &esp_record(&air)).unwrap();
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
    assert_eq!(w.notes().len(), 2, "the two notes were swapped for two");
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- exchange, redeem

#[test]
fn an_exchange_over_air_is_applied_once_and_a_resent_one_gets_the_stored_answer() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("exchange");
    let esp = start_esp_now(&dir, Config::default(), None);
    let state_dir = scratch("exchange-state");
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    sync_esp_keysets(&mut w, &air, &esp_record(&air)).unwrap();
    sync_esp_limits(&mut w, &air).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();

    let response = send_exchange(&mut w, &air, &built.request).unwrap();
    let done = w.finish_exchange(&built.id, &response).unwrap();
    assert_eq!(done.esp_units, 4 * u128::from(ONE_PSP));
    assert_eq!(w.balance().esp, 4 * u128::from(ONE_PSP));
    assert!(esp.psp_spent(&note), "the PSP note was burned");
    assert_eq!(esp.totals(), (4 * ONE_PSP, 0));

    // The same request again is the stored answer: nothing is applied twice.
    let again = send_exchange(&mut w, &air, &built.request).unwrap();
    assert_eq!(json(&again), json(&response));
    assert_eq!(esp.totals(), (4 * ONE_PSP, 0));
    assert!(w.air_requests().is_empty(), "every request ended");
    listener.stop().unwrap();
}

#[test]
fn a_redemption_goes_over_air_in_its_binary_encoding_and_a_resent_one_is_not_applied_twice() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("redeem");
    let esp = start_esp(
        &dir,
        Config {
            redeem_fee_per_byte: 1_000_000,
            ..Config::default()
        },
        None,
    );
    let state_dir = scratch("redeem-state");
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let a = esp.handed(4 * ONE, PAST);
    let na = a.note;
    let mut w = open_wallet(&dir, "w");
    sync_esp_keysets(&mut w, &air, &esp_record(&air)).unwrap();
    give(&mut w, PAST, vec![a]);

    // The fees come over AIR too.
    let fees = fetch_redeem_fees(&mut w, &air).unwrap();
    assert_eq!(fees.fee_per_byte, 1_000_000);
    let built = w.build_redemption(&secret(1), MEMO, &fees, now()).unwrap();
    assert_eq!(built.len(), 1);
    let body = built[0].body.clone();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&body).is_err(),
        "the body is the canonical binary encoding, not JSON"
    );

    let response = send_redeem(&mut w, &air, &body).unwrap();
    let outcome = w.finish_redemption(&built[0].id, &response).unwrap();
    assert_eq!(outcome.message, "payout queued");
    assert!(esp.is_spent(&na));
    assert_eq!(esp.totals().1, 4 * ONE);
    assert_eq!(esp.queue_len(), 1);

    // The same bytes again: the stored answer, and one queue entry, not two.
    let again = send_redeem(&mut w, &air, &body).unwrap();
    assert_eq!(json(&again), json(&response));
    assert_eq!(esp.totals().1, 4 * ONE);
    assert_eq!(esp.queue_len(), 1);
    assert!(w.air_requests().is_empty());
    listener.stop().unwrap();
}

// ---------------------------------------------------------------- refusals

#[test]
fn a_400_is_a_refusal_over_air_but_a_409_a_413_and_a_404_are_not() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("refusals");
    let esp = start_esp_now(
        &dir,
        Config {
            redeem_max_request_bytes: 100,
            ..Config::default()
        },
        None,
    );
    let state_dir = scratch("refusals-state");
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    sync_esp_keysets(&mut w, &air, &esp_record(&air)).unwrap();
    sync_esp_limits(&mut w, &air).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();

    // A 400 (a keyset the mint does not have): `Refused`, and nothing is burned.
    let mut bad = built.request.clone();
    bad.keyset = "ff".repeat(8);
    let refused = send_exchange(&mut w, &air, &bad).unwrap_err();
    assert!(matches!(refused, WalletError::Refused(_)), "{refused:?}");
    assert!(!esp.psp_spent(&note));

    // A 409, the same exchange arriving while it is being processed: a plain
    // mint error that says 409. It is not a refusal: the
    // pending exchange stays, with its note reserved, and the same request goes
    // through once the first is over.
    let hash = exchange::request_hash(&built.request).unwrap();
    let claim = esp.state.in_flight.claim(&hash).expect("a free place");
    match send_exchange(&mut w, &air, &built.request).unwrap_err() {
        WalletError::Mint(why) => assert!(why.contains("409"), "{why}"),
        other => panic!("expected a mint error saying 409, got {other:?}"),
    }
    assert_eq!(w.pending_exchanges().len(), 1);
    assert!(!esp.psp_spent(&note));
    drop(claim);
    let response = send_exchange(&mut w, &air, &built.request).unwrap();
    w.finish_exchange(&built.id, &response).unwrap();
    assert!(esp.psp_spent(&note));

    // A 413 on a redemption is `RedeemRefused` with its code.
    let mut r = open_wallet(&dir, "r");
    sync_esp_keysets(&mut r, &air, &esp_record(&air)).unwrap();
    give(&mut r, PAST, vec![esp.handed(ONE, PAST)]);
    let mut fees = fetch_redeem_fees(&mut r, &air).unwrap();
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
    match send_redeem(&mut r, &air, &body).unwrap_err() {
        WalletError::RedeemRefused { code, .. } => assert_eq!(code, "request_too_large"),
        other => panic!("expected RedeemRefused, got {other:?}"),
    }
    listener.stop().unwrap();
}

#[test]
fn a_psp_the_esp_cannot_reach_is_a_mint_error_that_keeps_the_exchange_pending() {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch("dead-psp");
    // Nothing listens on port 9, where the ESP looks for its PSP.
    let esp = start_esp(&dir, Config::default(), Some("http://127.0.0.1:9"));
    let state_dir = scratch("dead-psp-state");
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = air_settings(&server, &did, 10, 3);

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    sync_esp_keysets(&mut w, &air, &esp_record(&air)).unwrap();
    sync_esp_limits(&mut w, &air).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();

    // A signed "unavailable" (the mint's 502). It is not a refusal, and the
    // wallet says the request may be sent again.
    match send_exchange(&mut w, &air, &built.request) {
        Err(WalletError::Mint(why)) => {
            assert!(why.contains("could not answer exchange now"), "{why}");
            assert!(why.contains("Send the same request again"), "{why}");
        }
        other => panic!("expected a mint error, got {other:?}"),
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
    let esp = start_esp_now(&dir, Config::default(), None);
    let state_dir = scratch("kept-state");

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    // The mint is not listening: the call writes its request and waits in vain.
    let quick = air_settings(&server, &did, 1, 1);
    // (The keysets and limits cannot be read either, so name the mint's keyset
    // by hand as a wallet that had read them earlier would.)
    w.note_esp_keysets(&esp_record(&quick), &esp.keyset, None)
        .unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();
    match send_exchange(&mut w, &quick, &built.request) {
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
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    wait_for_next(&state_dir, 1);
    assert!(esp.psp_spent(&note));
    let response = send_exchange(&mut w, &air, &built.request).unwrap();
    assert!(w.air_requests().is_empty());
    assert!(slot_is_empty(&server, &did, 1), "nothing was written");
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
        network: NETWORK.into(),
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
    let now = addr::now_secs();
    // What the mint answers honestly to each call, as its real reply types.
    let fees_answer = serde_json::to_vec(&esp_mint::server::fees_body(&Config::default())).unwrap();
    let exchange_answer = serde_json::to_vec(&sp_wire::esp::exchange::ExchangeResponse {
        keyset: "ab".repeat(8),
        service: service(),
        redeemable_after_day: DAY,
        signatures: vec![],
        keys: vec![],
        fee_per_byte: 0,
        fee_esp: 0,
        size_bytes: 0,
    })
    .unwrap();

    // (a read and a call with a body; the body of an exchange here is a literal
    // that is deliberately not an exchange request, and is never parsed by
    // anyone, since no mint answers)
    for (kind, body, answer) in [
        (KIND_FEES, Vec::new(), fees_answer),
        (KIND_EXCHANGE, br#"{"x":1}"#.to_vec(), exchange_answer),
    ] {
        let answer = answer.as_slice();
        let call = |w: &mut Wallet| match kind {
            KIND_FEES => sync_esp_limits(w, &air).map(|_| ()),
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
            KIND_FEES
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
fn without_air_server_and_host_no_call_to_the_esp_is_made_and_the_error_names_the_setting() {
    let server = server();
    let dir = scratch("required");
    let esp = start_esp(&dir, Config::default(), None);
    // A listener is up, and must be asked for nothing.
    let (key, did) = mint_key();
    let state_dir = scratch("required-state");
    common::air::esp_stream(&esp.mint.state, &server, &key, &scratch("esp-stream"));
    let listener = start_serving(&server, &key, &state_dir, esp.serve());
    let air = AirSettings::default();
    assert!(!air.is_configured());
    assert!(air.placeholder_warnings().is_empty());

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note.clone()]);
    w.note_esp_keysets(&esp_record(&air), &esp.keyset, None)
        .unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();
    let named_both = |why: &str| {
        assert!(
            why.contains("air.server") && why.contains("air.host"),
            "{why}"
        );
        assert!(
            why.contains("ECASH_AIR_SERVER") && why.contains("ECASH_AIR_HOST"),
            "{why}"
        );
    };
    let invalid = |r: Result<(), WalletError>| match r {
        Err(WalletError::Invalid(why)) => named_both(&why),
        other => panic!("expected the missing settings to be named, got {other:?}"),
    };
    invalid(verify_esp(&mut w, &air, NETWORK));
    invalid(sync_esp_keysets(&mut w, &air, &esp_record(&air)));
    invalid(sync_esp_limits(&mut w, &air));
    invalid(fetch_redeem_fees(&mut w, &air).map(|_| ()));
    invalid(esp_window(&mut w, &air).map(|_| ()));
    invalid(send_exchange(&mut w, &air, &built.request).map(|_| ()));
    invalid(send_redeem(&mut w, &air, b"x").map(|_| ()));
    invalid(rotation_sync(&mut w, &air, Kind::Esp, &esp_record(&air)).map(|_| ()));

    // The exchange is still pending, its note reserved, and nothing went out.
    assert_eq!(w.pending_exchanges().len(), 1);
    assert!(!esp.psp_spent(&note));
    assert!(w.air_requests().is_empty());
    assert!(slot_is_empty(&server, &did, 0), "nothing went over AIR");
    listener.stop().unwrap();
}

#[test]
fn the_psp_and_the_esp_share_an_air_server_and_each_is_asked_at_its_own_did() {
    let server = server();
    let (esp_key, esp_did) = mint_key();
    let (psp_key, psp_did) = mint_key();
    let dir = scratch("shared");
    let esp = start_esp(&dir, Config::default(), None);
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
    verify_psp(&mut w, &air, NETWORK).unwrap();
    verify_esp(&mut w, &air, NETWORK).unwrap();
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
    match verify_esp(&mut w, &air, NETWORK) {
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
    match verify_esp(&mut w, &real, NETWORK) {
        Err(WalletError::Mint(why)) => assert!(!why.contains("PLACEHOLDER"), "{why}"),
        other => panic!("expected the unlistened DID to be unreachable, got {other:?}"),
    }
}

// ---------------------------------------------------------------- the key check

/// What the day records of a hand-made stream carry.
#[derive(Clone, Copy)]
enum HandKeys {
    /// The keys the mint signs with.
    True,
    /// Keys that are no mint's.
    Spoiled,
}

/// One exchange, from the build to `finish_exchange`, against an ESP mint (on
/// the system clock, so the day it gives is the wallet's own today plus its
/// maturity rule) whose key stream was written by hand: one control record for
/// each of `rules`, and day records for the days around today plus 365, with the
/// keys `keys` says. The blacklist setting is on, which does nothing for an ESP.
/// The control records of `late` follow those of `rules`, but are written only
/// after the request was sent and before `finish_exchange`: a rule the wallet has
/// not read when the reply comes.
///
/// Returns what `finish_exchange` made (the ESP units), the wallet, the time the
/// wallet recorded as the first send, and what keeps the mint and the AIR server
/// alive until the caller is done.
fn exchange_against_a_hand_made_stream(
    name: &str,
    rules: &[u64],
    late: &[u64],
    keys: HandKeys,
) -> (
    Result<u128, WalletError>,
    Wallet,
    Option<u64>,
    Box<dyn std::any::Any>,
) {
    exchange_against_a_hand_made_stream_with(name, rules, late, keys, Late::BeforeFinish, false)
}

/// When the rules published after the send are written.
#[derive(Clone, Copy)]
enum Late {
    /// Before `finish_exchange` is called.
    BeforeFinish,
    /// This long after `finish_exchange` is called (while the wallet checks).
    During(Duration),
}

/// [`exchange_against_a_hand_made_stream`], with the late rules written `when`,
/// and with `extreme` the key feed restarted before `finish_exchange` on AIR
/// settings at their least (`air.max_skew_secs`, `air.reply_wait_secs` and
/// `air.timeout_secs` 1), as an app could with `Wallet::start_key_feed`.
fn exchange_against_a_hand_made_stream_with(
    name: &str,
    rules: &[u64],
    late: &[u64],
    keys: HandKeys,
    when: Late,
    extreme: bool,
) -> (
    Result<u128, WalletError>,
    Wallet,
    Option<u64>,
    Box<dyn std::any::Any>,
) {
    let server = server();
    let (key, did) = mint_key();
    let dir = scratch(name);
    let esp = start_esp_now(&dir, Config::default(), None);
    let today = now() / 86_400;
    let days: Vec<_> = (today + 360..=today + 370)
        .map(|day| {
            let published = match keys {
                HandKeys::True => common::air::esp_day_keys(&esp.mint.state, &service(), day),
                HandKeys::Spoiled => common::air::spoiled_keys(),
            };
            (day, service(), published)
        })
        .collect();
    common::air::esp_published_by_hand(&server, &key, &esp.keyset, rules, &days);
    let listener = start_serving(
        &server,
        &key,
        &scratch(&format!("{name}-state")),
        esp.serve(),
    );
    let air = air_settings(&server, &did, 6, 1);

    let note = esp.psp_note(4);
    let mut w = wallet_with_psp(&dir, "w", vec![note]);
    w.set_key_policy(KeyPolicy {
        blacklist_on_key_mismatch: true,
        blacklist_max: 1000,
    });
    sync_esp_keysets(&mut w, &air, &esp_record(&air)).unwrap();
    sync_esp_limits(&mut w, &air).unwrap();
    let built = w.build_exchange(4, service(), None).unwrap();
    assert!(
        w.pending_exchanges()[0].first_sent_at.is_some(),
        "set when the request is built"
    );
    let response = send_exchange(&mut w, &air, &built.request).unwrap();
    let first_sent = w.pending_exchanges()[0].first_sent_at;
    if extreme {
        w.start_key_feed(&AirSettings {
            max_skew_secs: 1,
            reply_wait_secs: 1,
            timeout_secs: 1,
            ..air.clone()
        })
        .unwrap();
    }
    // The records already written are written again (same bytes: stored
    // already); the new ones are the rules published after the send.
    let all: Vec<u64> = rules.iter().chain(late).copied().collect();
    let write_late = || {
        if !late.is_empty() {
            common::air::esp_published_by_hand(&server, &key, &esp.keyset, &all, &[]);
        }
    };
    let done = match when {
        Late::BeforeFinish => {
            write_late();
            w.finish_exchange(&built.id, &response)
        }
        Late::During(after) => thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(after);
                write_late();
            });
            w.finish_exchange(&built.id, &response)
        }),
    }
    .map(|done| done.esp_units);
    (done, w, first_sent, Box::new((listener, esp, server)))
}

/// An ESP mint that signs a new exchange with keys other than the ones it
/// published for that service and day: nothing from the reply is stored (the PSP
/// note is burned at the mint, so the request is kept to be tried again), the
/// warning names the ESP, the site and the output, and the ESP is not
/// blacklisted: the SPI's PSP and ESP mints only warn, whatever the setting says.
#[test]
fn an_exchange_signed_with_keys_the_esp_did_not_publish_warns_and_stores_nothing() {
    let (done, w, first_sent, keep) =
        exchange_against_a_hand_made_stream("key-exchange-keys", &[365], &[], HandKeys::Spoiled);
    let WalletError::KeyMismatch(m) = done.unwrap_err() else {
        panic!("expected a key mismatch");
    };
    assert_eq!((m.mint, m.site), ("ESP mint", Site::FinishExchange));
    assert!(matches!(m.failed, Failed::Key { .. }), "{:?}", m.failed);
    assert!(!m.blacklisted);
    assert!(
        m.warning
            .starts_with("WARNING: KEY CHECK FAILED at finish_exchange. The ESP mint (DID "),
        "{}",
        m.warning
    );
    assert!(
        m.warning.contains("signed the output of ")
            && m.warning
                .contains("with a KEY that is not the key it published"),
        "{}",
        m.warning
    );
    assert!(
        m.warning
            .ends_with("The SPI's PSP and ESP mints are never blacklisted: this only warns."),
        "{}",
        m.warning
    );
    assert_eq!(w.balance().esp, 0, "nothing from the reply was stored");
    assert_eq!(w.pending_exchanges().len(), 1, "the request is kept");
    assert_eq!(
        w.pending_exchanges()[0].first_sent_at,
        first_sent,
        "and its first send time"
    );
    assert!(w.blacklist().is_empty());
    assert_eq!(
        w.key_rereads(),
        1,
        "the day's keys were read again from AIR once before the mismatch"
    );
    // The wallet stops following the mint's stream before the mint goes.
    drop(w);
    drop(keep);
}

/// An ESP mint that gives a new exchange a day its published maturity rule does
/// not allow (it published `m = 300` and gave today plus 365): refused, with the
/// day, the days that were allowed and the rule in the warning.
#[test]
fn an_exchange_given_a_day_the_published_rule_does_not_allow_warns_and_stores_nothing() {
    let (done, w, _, keep) =
        exchange_against_a_hand_made_stream("key-exchange-day", &[300], &[], HandKeys::True);
    let WalletError::KeyMismatch(m) = done.unwrap_err() else {
        panic!("expected a key mismatch");
    };
    assert_eq!((m.mint, m.site), ("ESP mint", Site::FinishExchange));
    let today = now() / 86_400;
    match &m.failed {
        Failed::Day {
            day,
            from,
            to,
            rules,
        } => {
            assert!((today + 365..=today + 366).contains(day), "{day}");
            assert!((today + 300..=today + 301).contains(from), "{from}");
            assert!((today + 300..=today + 301).contains(to), "{to}");
            assert_eq!(rules, &vec![300]);
        }
        other => panic!("expected a day failure, got {other:?}"),
    }
    assert!(
        m.warning
            .contains("outside the days it allows a new exchange")
    );
    assert!(m.warning.contains("its published maturity rule(s) m = 300"));
    assert_eq!(w.balance().esp, 0);
    assert_eq!(w.pending_exchanges().len(), 1);
    assert_eq!(w.key_rereads(), 1, "one fresh read before the mismatch");
    drop(w);
    drop(keep);
}

/// The mint changed its maturity rule (300, then 365) and the exchange got a day
/// under the new one: accepted. The stream's last two rules are both allowed (an
/// exchange sent just before a change is answered just after it), the keys are
/// the mint's own, and the wallet recorded the time of the first send.
#[test]
fn an_exchange_given_a_day_under_either_of_the_last_two_published_rules_is_accepted() {
    let before = now();
    let (done, w, first_sent, keep) =
        exchange_against_a_hand_made_stream("key-exchange-rules", &[300, 365], &[], HandKeys::True);
    assert_eq!(done.unwrap(), 4 * u128::from(ONE_PSP));
    assert_eq!(w.balance().esp, 4 * u128::from(ONE_PSP));
    assert!(w.pending_exchanges().is_empty());
    let first_sent = first_sent.expect("the first send time was recorded");
    assert!(first_sent >= before && first_sent <= now(), "{first_sent}");
    assert_eq!(
        w.key_rereads(),
        0,
        "a day the held rules allow needs no reread"
    );
    drop(w);
    drop(keep);
}

/// The mint changed its maturity rule after the exchange was sent (T5): the
/// wallet had read only `m = 300` when the reply came with the day today plus 365,
/// and the control record for 365 was written meanwhile. The wallet reads the
/// stream again before it calls the day a mismatch, and accepts the day. Fails if
/// the day were judged by the rules the wallet had read before the reply, and
/// if the stream were read again more than once.
#[test]
fn an_exchange_given_a_day_under_a_rule_published_after_the_send_is_accepted() {
    let (done, w, _, keep) = exchange_against_a_hand_made_stream(
        "key-exchange-late-rule",
        &[300],
        &[365],
        HandKeys::True,
    );
    assert_eq!(done.unwrap(), 4 * u128::from(ONE_PSP));
    assert_eq!(w.balance().esp, 4 * u128::from(ONE_PSP));
    assert!(w.pending_exchanges().is_empty());
    // At most one reread: the wallet's stream thread may have taken the new
    // rule in before the reply was checked (then none is needed). The count of
    // exactly one, with the new rule unread, is the unit test
    // a_maturity_rule_changed_after_the_send_is_taken_in_with_exactly_one_reread.
    assert!(w.key_rereads() <= 1, "{}", w.key_rereads());
    drop(w);
    drop(keep);
}

/// The same, but the rule published after the send (400) does not allow the day
/// either (today plus 365 is under neither 300 nor 400): a mismatch that lists
/// both rules, so the new one was read before the day was refused. Fails if the
/// wallet never reads the stream again, or accepts a day neither rule allows.
#[test]
fn an_exchange_given_a_day_under_neither_the_old_nor_the_late_rule_warns() {
    let (done, w, _, keep) = exchange_against_a_hand_made_stream(
        "key-exchange-late-neither",
        &[300],
        &[400],
        HandKeys::True,
    );
    let WalletError::KeyMismatch(m) = done.unwrap_err() else {
        panic!("expected a key mismatch");
    };
    assert_eq!((m.mint, m.site), ("ESP mint", Site::FinishExchange));
    match &m.failed {
        Failed::Day { rules, .. } => {
            assert_eq!(rules, &vec![400, 300], "latest first, both read");
        }
        other => panic!("expected a day failure, got {other:?}"),
    }
    assert_eq!(w.key_rereads(), 1, "exactly one reread before the mismatch");
    assert_eq!(w.balance().esp, 0);
    assert_eq!(w.pending_exchanges().len(), 1);
    drop(w);
    drop(keep);
}

/// An honest ESP changed its rule to 365 and its control record reaches AIR 3 s
/// after the wallet starts checking the reply (a writer that missed a tick):
/// with the AIR settings at their least (skew, reply wait and timeout all 1 s)
/// the exchange is still accepted, because the key check waits its own fixed
/// time (45 s) for the record and reads with its own least timeout (10 s), not
/// the settings. Fails if a 1 s `air.reply_wait_secs` or `air.timeout_secs` made
/// the wallet call an honest mint's day a mismatch.
#[test]
fn extreme_air_settings_do_not_flag_an_honest_esp_whose_new_rule_is_written_late() {
    let (done, w, _, keep) = exchange_against_a_hand_made_stream_with(
        "key-extreme-honest",
        &[300],
        &[365],
        HandKeys::True,
        Late::During(Duration::from_secs(3)),
        true,
    );
    assert_eq!(done.unwrap(), 4 * u128::from(ONE_PSP));
    assert_eq!(w.balance().esp, 4 * u128::from(ONE_PSP));
    assert!(w.pending_exchanges().is_empty());
    assert!(w.blacklist().is_empty());
    drop(w);
    drop(keep);
}

/// A cheating ESP, with the AIR settings at their least (skew, reply wait and
/// timeout all 1 s): keys it never published are a key mismatch, and a day its
/// published rule does not allow is a day mismatch after the fixed wait, with
/// the window of the fixed 300 s slack (not 1 s). Fails if the extreme settings
/// turned either into an error to retry, or a mismatch came before the wait.
#[test]
fn extreme_air_settings_do_not_stop_a_cheating_esp_being_flagged() {
    let (done, w, _, keep) = exchange_against_a_hand_made_stream_with(
        "key-extreme-keys",
        &[365],
        &[],
        HandKeys::Spoiled,
        Late::BeforeFinish,
        true,
    );
    let WalletError::KeyMismatch(m) = done.unwrap_err() else {
        panic!("expected a key mismatch");
    };
    assert_eq!((m.mint, m.site), ("ESP mint", Site::FinishExchange));
    assert!(matches!(m.failed, Failed::Key { .. }), "{:?}", m.failed);
    assert_eq!(w.balance().esp, 0);
    assert_eq!(w.pending_exchanges().len(), 1);
    drop(w);
    drop(keep);

    let started = Instant::now();
    let (done, w, first_sent, keep) = exchange_against_a_hand_made_stream_with(
        "key-extreme-day",
        &[300],
        &[],
        HandKeys::True,
        Late::BeforeFinish,
        true,
    );
    let WalletError::KeyMismatch(m) = done.unwrap_err() else {
        panic!("expected a key mismatch");
    };
    assert!(
        started.elapsed() >= Duration::from_secs(45),
        "the day is called wrong only after the fixed wait"
    );
    let first_sent = first_sent.expect("the first send time was recorded");
    match &m.failed {
        Failed::Day {
            day, from, rules, ..
        } => {
            let today = now() / 86_400;
            assert!((today + 365..=today + 366).contains(day), "{day}");
            assert_eq!(*from, (first_sent - 300) / 86_400 + 300, "the 300 s slack");
            assert_eq!(rules, &vec![300]);
        }
        other => panic!("expected a day failure, got {other:?}"),
    }
    assert_eq!(w.balance().esp, 0);
    assert_eq!(w.pending_exchanges().len(), 1);
    drop(w);
    drop(keep);
}
