//! The wallet's automatic, staggered rollover of PSP and ESP against real
//! psp-mint and esp-mint servers that rotate their keys (fixed clocks).

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use axum::Router;
use ecash_wallet::store::{HandedNote, Handover, StoredNote, WalletData};
use ecash_wallet::{Kind, Wallet, http};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::server::EspState;
use esp_mint::terms::Terms;
use mint_server::state::AppState;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, XOnlyPublicKey};
use tokio::runtime::Runtime;

const T: u64 = 1_800_000_000;
const H: u64 = 3600;
/// Past the stagger window of a 1-hour period (0.5% = 18 s, and a swap time is
/// 1 to 18 s after the set starts).
const LATER: u64 = 100;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wallet-rot-{}-{name}", {
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

fn serve(rt: &Runtime, app: Router) -> String {
    let l = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let a = l.local_addr().unwrap();
    rt.spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{a}")
}

struct PspMint {
    url: String,
    state: Arc<AppState>,
    rot: psp_mint::server::SharedRotating,
}

fn start_psp(rt: &Runtime, dir: &PathBuf) -> PspMint {
    let d = dir.join("psp");
    let (rotor, logic) =
        psp_mint::rotation::Rotor::open_at(&d, Amount::from_units(1024), 1, 1, T).unwrap();
    let rot =
        psp_mint::server::Rotating::new(rotor, psp_mint::rotation::Rollovers::open(&d).unwrap());
    let state = psp_mint::server::app_state(logic);
    let melts = Arc::new(Mutex::new(
        psp_mint::melts::MeltLog::open(&d.join("melt_memos.json")).unwrap(),
    ));
    let app = psp_mint::server::router_full(
        Arc::clone(&state),
        psp_mint::server::Health::new(100),
        melts,
        Default::default(),
        Some(Arc::clone(&rot)),
    );
    PspMint {
        url: serve(rt, app),
        state,
        rot,
    }
}

impl PspMint {
    fn set_clock(&self, t: u64) {
        self.rot
            .rotor
            .lock()
            .unwrap()
            .clock
            .store(t, Ordering::SeqCst);
    }
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
        let n = StoredNote {
            kind: Kind::Psp,
            amount: units,
            note: Note {
                nonce,
                signature: bdhke::unblind_message(&out.0, &r, &logic.public_keys()[&amount]),
            },
            spend_secret: kp.secret_key(),
            terms: None,
            reserved_by: None,
        };
        // The keyset that signed it, as the wallet records on every note.
        let ks = psp_mint::rotation::keyset_id(logic.public_keys());
        SIGNED_BY.with(|m| m.borrow_mut().insert(n.id(), ks));
        n
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

thread_local! {
    /// Each test note's signing keyset, by note id.
    static SIGNED_BY: std::cell::RefCell<std::collections::BTreeMap<String, String>> =
        Default::default();
}

fn wallet_with(dir: &PathBuf, name: &str, notes: Vec<StoredNote>) -> Wallet {
    let path = dir.join(format!("{name}.json"));
    let keysets = SIGNED_BY.with(|m| {
        let m = m.borrow();
        notes
            .iter()
            .filter_map(|n| m.get(&n.id()).map(|k| (n.id(), k.clone())))
            .collect()
    });
    let data = WalletData {
        keysets,
        notes,
        ..Default::default()
    };
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    Wallet::open(&path).unwrap()
}

fn file_text(w: &Wallet) -> String {
    std::fs::read_to_string(w.path()).unwrap()
}

#[test]
fn psp_rolls_over_after_its_staggered_time_and_the_time_is_then_forgotten() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("psp");
    let m = start_psp(&rt, &dir);
    let a = m.note(4);
    let b = m.note(1);
    let mut w = wallet_with(&dir, "w", vec![a.clone(), b.clone()]);
    // Before any rotation: one set, nothing to do, nothing scheduled.
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    assert!(log.is_empty(), "{log:?}");
    assert_eq!(w.swap_schedule_len(), 0);
    assert_eq!(w.epoch_of(&w.notes()[0]), Some(0));

    // The rotation: one random swap time, stored, inside the window.
    m.set_clock(T + H);
    let win = http::fetch_window(&m.url).unwrap();
    assert_eq!((win.current_epoch, win.previous_epoch), (1, Some(0)));
    let start = win.current_starts.unwrap();
    let at = w.swap_time(Kind::Psp, &m.url, &win).unwrap();
    // Strictly after the start: a delay of 0 would make a wallet that syncs the
    // second the set starts swap at once, and this test would then see no
    // "will be rolled over" step to wait through.
    assert!(at > start && at <= start + 18, "0.5% of a 1-hour period");
    assert_eq!(
        w.swap_time(Kind::Psp, &m.url, &win).unwrap(),
        at,
        "drawn once"
    );
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    for l in &log {
        assert!(
            !l.contains(&at.to_string()),
            "a swap time is never logged: {l}"
        );
    }

    // Past the swap time: rolled over without a prompt, and the swap time is
    // gone in the same write that recorded the new notes.
    m.set_clock(T + H + LATER);
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{log:?}"
    );
    assert!(m.spent(&a) && m.spent(&b));
    assert_eq!(w.notes().len(), 2);
    assert!(w.notes().iter().all(|n| w.epoch_of(n) == Some(1)));
    assert_eq!(w.swap_schedule_len(), 0);
    assert!(
        !file_text(&w).contains(&at.to_string()),
        "no history of the swap time in the file"
    );
    let again = Wallet::open(w.path()).unwrap();
    assert_eq!(again.swap_schedule_len(), 0);

    // The next rotation retires generation 0; this wallet's notes are on 1.
    m.set_clock(T + 2 * H + LATER);
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{log:?}"
    );
    assert!(w.lost().is_empty());
}

#[test]
fn psp_left_offline_through_a_full_cycle_is_lost_and_its_schedule_dropped() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("psp-lost");
    let m = start_psp(&rt, &dir);
    let n = m.note(2);
    let mut w = wallet_with(&dir, "w", vec![n]);
    http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap(); // stamped epoch 0
    m.set_clock(T + H);
    let win = http::fetch_window(&m.url).unwrap();
    w.swap_time(Kind::Psp, &m.url, &win).unwrap();
    assert_eq!(w.swap_schedule_len(), 1);
    // Offline past the next rotation: generation 0 is deleted.
    m.set_clock(T + 2 * H);
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    assert!(log.iter().any(|l| l.contains("lost")), "{log:?}");
    assert_eq!(w.lost().len(), 1);
    assert!(w.notes().is_empty());
    assert_eq!(
        w.swap_schedule_len(),
        0,
        "the old set retired: its schedule goes"
    );
}

#[test]
fn a_crash_before_the_send_or_after_the_mint_answered_is_finished_on_the_next_connection() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("psp-crash");
    let m = start_psp(&rt, &dir);
    let (a, b) = (m.note(1), m.note(2));
    let mut w = wallet_with(&dir, "w", vec![a.clone(), b.clone()]);
    http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    m.set_clock(T + H + LATER);
    let win = http::fetch_window(&m.url).unwrap();
    let old = w.prepare_rollover(Kind::Psp, &m.url, &win).unwrap();
    w.swap_time(Kind::Psp, &m.url, &win).unwrap();
    let ids = w.build_rollovers(Kind::Psp, &m.url, &win, old).unwrap();
    // The mint answers, but the reply is lost.
    let body = w.pending_rollovers()[0].body.clone();
    let r = reqwest::blocking::Client::new()
        .post(format!("{}/rollover", m.url))
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    drop(w);
    // Restart: the stored request is sent again and finished from the mint's
    // stored answer.
    let mut w = Wallet::open(&dir.join("w.json")).unwrap();
    assert_eq!(w.pending_rollovers()[0].id, ids[0]);
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{log:?}"
    );
    assert!(w.pending_rollovers().is_empty());
    assert_eq!(w.swap_schedule_len(), 0);
    assert_eq!(w.notes().len(), 2);
}

#[test]
fn a_failed_rollover_is_logged_and_retried_on_the_next_connection() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("psp-fail");
    let m = start_psp(&rt, &dir);
    let mut w = wallet_with(&dir, "w", vec![m.note(8)]);
    http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    m.set_clock(T + H + LATER);
    let win = http::fetch_window(&m.url).unwrap();
    let old = w.prepare_rollover(Kind::Psp, &m.url, &win).unwrap();
    w.swap_time(Kind::Psp, &m.url, &win).unwrap();
    w.build_rollovers(Kind::Psp, &m.url, &win, old).unwrap();
    // The mint is unreachable: point the stored rollover at a dead port.
    let dead = "http://127.0.0.1:1".to_string();
    let mut data: WalletData = serde_json::from_str(&file_text(&w)).unwrap();
    data.pending_rollovers[0].url = dead.clone();
    std::fs::write(w.path(), serde_json::to_vec(&data).unwrap()).unwrap();
    let mut w = Wallet::open(w.path()).unwrap();
    let _ = http::rotation_sync(&mut w, Kind::Psp, &dead);
    assert_eq!(w.pending_rollovers().len(), 1, "kept for the retry");
    assert_eq!(w.swap_schedule_len(), 1, "kept until the swap is done");
    // Back online.
    let mut data: WalletData = serde_json::from_str(&file_text(&w)).unwrap();
    data.pending_rollovers[0].url = m.url.clone();
    std::fs::write(w.path(), serde_json::to_vec(&data).unwrap()).unwrap();
    let mut w = Wallet::open(w.path()).unwrap();
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 1 note(s)")),
        "{log:?}"
    );
    assert_eq!(w.swap_schedule_len(), 0);
}

// ---- ESP ---------------------------------------------------------------------

struct NoPsp;
impl Psp for NoPsp {
    fn melt(&self, _: &[MintInput], _: &str) -> Result<Amount, String> {
        Err("no psp".into())
    }
    fn burns(&self, _: &[Nonce]) -> Result<Vec<Burn>, String> {
        Err("no psp".into())
    }
}

fn service_kp() -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[7u8; 32]).unwrap()
}
fn service() -> XOnlyPublicKey {
    service_kp().x_only_public_key().0
}

/// A rotating ESP mint (1-hour periods from `T`) and three notes of its
/// first set for `service()`: 4 and 4 on day 100, 2 on day 200 (ESP notes are
/// powers of two).
fn start_esp(rt: &Runtime, dir: &PathBuf) -> (Arc<EspState>, String, Vec<(u64, HandedNote)>) {
    let d = dir.join("esp");
    let (rotor, logic) = esp_mint::rotation::Rotor::open_at(&d, 1, 1, T).unwrap();
    let master = rotor.current.master.clone();
    let state = Arc::new(EspState {
        logic: Mutex::new(logic),
        master: master.clone(),
        psp: Box::new(NoPsp),
        responses: Mutex::new(
            esp_mint::responses::Responses::open(&d.join("responses.json")).unwrap(),
        ),
        queue_path: d.join("queue.json"),
        queue_lock: Mutex::new(()),
        in_flight: Default::default(),
        config: esp_mint::config::Handle::new(esp_mint::config::Config::default()),
        rollovers: Some(Mutex::new(esp_mint::rotation::Rollovers::open(&d).unwrap())),
        rotor: Some(Mutex::new(rotor)),
    });
    let url = serve(rt, esp_mint::server::router(Arc::clone(&state)));
    let mut notes = Vec::new();
    for (units, day) in [(4u64, 100u64), (4, 100), (2, 200)] {
        let terms = Terms {
            service: service(),
            redeemable_after_day: day,
        };
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(kp.public_key());
        let (b, r) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let sk = master.key_for(amount, &terms);
        let out = state
            .logic
            .lock()
            .unwrap()
            .issue_with_key(
                &sk,
                &MintOutput {
                    amount,
                    blind_nonce: BlindNonce(b),
                },
            )
            .unwrap();
        notes.push((
            day,
            HandedNote {
                amount: units,
                note: Note {
                    nonce,
                    signature: bdhke::unblind_message(&out.0, &r, &sk.public_key(SECP256K1)),
                },
                spend_secret: kp.secret_key(),
                keyset: esp_mint::rotation::keyset_id(&master),
            },
        ));
    }
    (state, url, notes)
}

#[test]
fn esp_rolls_over_keeping_its_service_and_day() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("esp");
    let (state, url, notes) = start_esp(&rt, &dir);
    let mut w = Wallet::open(&dir.join("w.json")).unwrap();
    for day in [100, 200] {
        w.receive_handover(&Handover {
            service: service(),
            redeemable_after_day: day,
            notes: notes
                .iter()
                .filter(|(d, _)| *d == day)
                .map(|(_, n)| n.clone())
                .collect(),
        })
        .unwrap();
    }
    http::rotation_sync(&mut w, Kind::Esp, &url).unwrap();
    let clock = Arc::clone(&state.rotor.as_ref().unwrap().lock().unwrap().clock);
    clock.store(T + H + LATER, Ordering::SeqCst);
    let log = http::rotation_sync(&mut w, Kind::Esp, &url).unwrap();
    assert!(
        log.iter().filter(|l| l.contains("rolled over")).count() == 2,
        "one per day: {log:?}"
    );
    let mut terms: Vec<(u64, u64)> = w
        .notes()
        .iter()
        .map(|n| (n.amount, n.terms.unwrap().redeemable_after_day))
        .collect();
    terms.sort();
    assert_eq!(
        terms,
        vec![(2, 200), (4, 100), (4, 100)],
        "same amounts, same days"
    );
    assert!(
        w.notes()
            .iter()
            .all(|n| n.terms.unwrap().service == service() && w.epoch_of(n) == Some(1))
    );
    assert_eq!(w.swap_schedule_len(), 0);
}

/// Settle one purchase at the PSP's current set, as psp-mint's service does,
/// and return the text it prints.
fn settle_now(
    m: &PspMint,
    dir: &PathBuf,
    key: &sp_wire::seal::SecretKey,
    txid: &str,
    payload: Vec<u8>,
) -> String {
    let (opened, ignored) = psp_mint::seal::open_payloads(
        key,
        vec![psp_mint::scan::Received {
            txid: txid.to_string(),
            confirmations: 6,
            value_sats: 5_000,
            payload: Some(payload),
        }],
    );
    assert_eq!(ignored, 0);
    let mut records =
        psp_mint::records::Records::open(&dir.join("psp").join("settlements.json")).unwrap();
    let logic = m.state.logic.lock().unwrap();
    // $10,000 per BTC, in cents: a PSP is $0.10, so 5,000 sats is exactly 5 PSP
    let s =
        psp_mint::settle::settle(&logic, &mut records, &opened[0], &mut || Ok(1_000_000)).unwrap();
    assert!(
        matches!(s, psp_mint::settle::Settlement::Issued(_)),
        "{s:?}"
    );
    psp_mint::service::describe(&opened[0], &s).join("\n")
}

#[test]
fn purchases_around_a_psp_rotation_are_claimed_with_the_keys_of_the_set_that_signed() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("psp-claim");
    let m = start_psp(&rt, &dir);
    let _ = m.note(1);
    let mint_key = sp_wire::seal::SecretKey::new();
    let mut w = Wallet::open(&dir.join("w.json")).unwrap();
    let reply = w.reply_did().unwrap();
    // Both purchases are prepared before the rotation; `a` is settled before
    // it, `b` after it.
    let a = w
        .build_psp_payload(&[4], &reply, &mint_key.public_key())
        .unwrap();
    let b = w
        .build_psp_payload(&[1], &reply, &mint_key.public_key())
        .unwrap();
    let old = http::fetch_window(&m.url).unwrap().current_id;
    let text_a = settle_now(&m, &dir, &mint_key, "aa", a.payload);

    m.set_clock(T + H);
    let win = http::fetch_window(&m.url).unwrap();
    assert_ne!(win.current_id, old);
    let text_b = settle_now(&m, &dir, &mint_key, "bb", b.payload);

    // Each settlement names the set that signed it ...
    assert_eq!(ecash_wallet::psp::parse_keyset(&text_a), Some(old.clone()));
    assert_eq!(
        ecash_wallet::psp::parse_keyset(&text_b),
        Some(win.current_id.clone())
    );
    // ... and each is claimed with that set's keys: `a` with the previous
    // set's, though the current set is another.
    for text in [&text_a, &text_b] {
        let keys = http::psp_claim_keys(&m.url, text).unwrap();
        let sigs = ecash_wallet::psp::parse_signatures(text).unwrap();
        w.claim_psp(&w.ours(&sigs), &keys).unwrap();
    }
    assert_eq!(w.balance().psp, 5);
    let by_amount = |units: u64| {
        w.notes()
            .iter()
            .find(|n| n.amount == units)
            .unwrap()
            .clone()
    };
    assert_eq!(w.psp_keyset_of(&by_amount(4)).unwrap(), old);
    assert_eq!(w.psp_keyset_of(&by_amount(1)).unwrap(), win.current_id);
    // The notes are good: the previous-set note rolls over to the current set.
    http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    m.set_clock(T + H + LATER);
    let log = http::rotation_sync(&mut w, Kind::Psp, &m.url).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 1 note")),
        "{log:?}"
    );
    assert_eq!(w.balance().psp, 5);

    // After the next rotation the first set is retired: a settlement it
    // signed can no longer be claimed, and the wallet says why.
    m.set_clock(T + 2 * H);
    let _ = http::fetch_window(&m.url).unwrap();
    let err = http::psp_claim_keys(&m.url, &text_a).unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
}

#[test]
fn a_transfer_built_before_the_esp_mint_rotated_is_signed_by_the_set_it_names() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("esp-stale");
    let (state, url, notes) = start_esp(&rt, &dir);
    let mut w = Wallet::open(&dir.join("w.json")).unwrap();
    w.receive_handover(&Handover {
        service: service(),
        redeemable_after_day: 100,
        notes: notes
            .iter()
            .filter(|(d, _)| *d == 100)
            .map(|(_, n)| n.clone())
            .collect(),
    })
    .unwrap();
    http::sync_esp_keysets(&mut w, &url).unwrap();
    let old = w.esp_output_keyset();
    // The mint rotates; the wallet's cached keyset is now the previous one,
    // which the mint still signs with.
    let clock = Arc::clone(&state.rotor.as_ref().unwrap().lock().unwrap().clock);
    clock.store(T + H + LATER, Ordering::SeqCst);
    let built = w
        .build_transfer(&service_kp().secret_key(), Some(100), None)
        .unwrap();
    assert_eq!(built.request.keyset, old, "built from the stale cache");
    // The wallet kept the keyset with the pending transfer, and sends it as it is.
    let reply = http::send_transfer(&url, &built.request).unwrap();
    assert_eq!(reply.keyset, old, "signed by the set the request named");
    let done = w.finish_transfer(&built.id, &reply).unwrap();
    assert_eq!(done.esp_units, 8);
    for id in &done.notes {
        let n = w.notes().iter().find(|n| &n.id() == id).unwrap();
        assert_eq!(w.esp_keyset_of(n).unwrap(), old);
    }
}

#[test]
fn a_note_without_a_recorded_keyset_is_refused_not_guessed() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("psp-noks");
    let m = start_psp(&rt, &dir);
    let n = m.note(4);
    // Written straight to the file with no keyset, as an old wallet would have.
    let path = dir.join("old.json");
    let data = WalletData {
        notes: vec![n.clone()],
        ..Default::default()
    };
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    let w = Wallet::open(&path).unwrap();
    let e = w.psp_keyset_of(&n).unwrap_err().to_string();
    assert!(e.contains("no recorded keyset"), "{e}");
    let e = w.esp_keyset_of(&n).unwrap_err().to_string();
    assert!(e.contains("cannot be spent"), "{e}");
}
