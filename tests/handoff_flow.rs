//! Value handed from wallet to wallet as a string, with no AIR in between:
//! PSP settled by a swap at a real psp-mint, FSP at a real fsp-mint, and the
//! sender's side (notes taken out, cancel, done).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use ecash_wallet::handoff::{BEARER_WARNING, HandoffState, PREFIX};
use ecash_wallet::store::{HandedNote, Handover, StoredNote, WalletData};
use ecash_wallet::{Kind, Wallet, http};
use esp_mint::exchange::{Burn, Psp};
use esp_mint::responses::Responses;
use esp_mint::server::EspState;
use esp_mint::terms::Terms;
use fsp_mint::issue::Issues;
use fsp_mint::server::FspState;
use fsp_mint::spend::Spender;
use mint_server::state::AppState;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use tokio::runtime::Runtime;

const T: u64 = 1_800_000_000;
const NOW: u64 = 1_791_571_184;

fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "wallet-handoff-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
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

// ---- PSP ---------------------------------------------------------------------------

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

fn psp_wallet(m: &PspMint, dir: &PathBuf, name: &str, notes: Vec<StoredNote>) -> Wallet {
    let path = dir.join(format!("{name}.json"));
    let ks = psp_mint::rotation::keyset_id(m.state.logic.lock().unwrap().public_keys());
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

#[test]
fn a_psp_handoff_with_swap_is_final_and_cannot_be_imported_twice() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("psp");
    let m = start_psp(&rt, &dir);
    let (a, b, c) = (m.note(4), m.note(1), m.note(2));
    let mut dev = psp_wallet(&m, &dir, "dev", vec![a.clone(), b.clone(), c]);
    let mut user = psp_wallet(&m, &dir, "user", vec![]);

    let sel = dev.select_handoff(5, &[]).unwrap();
    let out = dev.export_handoff(&sel, &m.url, None).unwrap();
    assert!(out.text.starts_with(PREFIX));
    assert_eq!((out.notes, out.psp_units, out.fsp_units), (2, 5, 0));
    assert!(out.warning.contains("Anyone who sees it can spend"));
    assert_eq!(out.warning, BEARER_WARNING);
    assert_eq!(psp_total(&dev), 2, "the handed-off notes leave the balance");
    assert_eq!(dev.handoffs_out()[0].state, HandoffState::Pending);

    // The string survives being written down and typed back in.
    let typed = format!("  {}\n", out.text.to_lowercase());
    let imported = user.import_handoff(&typed, "dev", true).unwrap();
    assert_eq!(imported.psp_units, 5);
    assert_eq!(imported.psp_swaps.len(), 1, "the swap is stored first");
    assert_eq!(psp_total(&user), 0, "not final until the mint has swapped");
    let log = http::complete_import(&mut user, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(psp_total(&user), 5);
    assert!(user.pending_rollovers().is_empty());
    assert!(m.spent(&a) && m.spent(&b), "the old notes are burned");
    let nonces: Vec<_> = user.notes().iter().map(|n| n.note.nonce).collect();
    assert!(!nonces.contains(&a.note.nonce) && !nonces.contains(&b.note.nonce));
    assert_eq!(user.handoffs_in()[0].from, "dev");
    assert!(user.handoffs_in()[0].swapped);

    // The same string again: refused, and nothing is added.
    let err = user.import_handoff(&out.text, "dev", true).unwrap_err();
    assert!(err.to_string().contains("imported already"), "{err}");
    assert_eq!(psp_total(&user), 5);
    // A second wallet that tries the same string finds the notes spent.
    let mut thief = psp_wallet(&m, &dir, "thief", vec![]);
    let imported = thief.import_handoff(&out.text, "", true).unwrap();
    let log = http::complete_import(&mut thief, &imported);
    assert!(
        log.iter().any(|l| l.contains("refused")),
        "the mint refuses a second swap: {log:?}"
    );
    assert_eq!(psp_total(&thief), 0, "none of it is kept");

    // The sender learns it was claimed and lets go of the notes.
    dev.finish_handoff(&out.id).unwrap();
    assert_eq!(dev.handoffs_out()[0].state, HandoffState::Done);
    assert!(dev.handoffs_out()[0].notes.is_empty());
    assert!(dev.cancel_handoff(&out.id).is_err());
}

#[test]
fn a_cancelled_handoff_returns_the_notes_and_an_unswapped_import_keeps_them() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("cancel");
    let m = start_psp(&rt, &dir);
    let mut dev = psp_wallet(&m, &dir, "dev", vec![m.note(8), m.note(2)]);
    let sel = dev.select_handoff(10, &[]).unwrap();
    let out = dev.export_handoff(&sel, &m.url, None).unwrap();
    assert_eq!(psp_total(&dev), 0);
    assert_eq!(dev.cancel_handoff(&out.id).unwrap(), 2);
    assert_eq!(psp_total(&dev), 10);
    assert!(dev.handoffs_out().is_empty());
    // The reopened wallet file holds the same.
    let again = Wallet::open(&dir.join("dev.json")).unwrap();
    assert_eq!(psp_total(&again), 10);

    // Export again and import without a swap: the notes are kept as they are
    // (good until someone else spends them), and the source is recorded.
    let sel = dev.select_handoff(10, &[]).unwrap();
    let out = dev.export_handoff(&sel, &m.url, None).unwrap();
    let mut user = psp_wallet(&m, &dir, "user", vec![]);
    let imported = user.import_handoff(&out.text, "", false).unwrap();
    assert!(imported.psp_swaps.is_empty());
    assert_eq!(psp_total(&user), 10);
    assert_eq!(user.handoffs_in()[0].id, out.id);
    assert_eq!(user.handoffs_in()[0].notes.len(), 2);
}

// ---- FSP ---------------------------------------------------------------------------

fn service() -> XOnlyPublicKey {
    let mut b = [0u8; 32];
    b[31] = 1;
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&b).unwrap())
        .x_only_public_key()
        .0
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

struct FspMints {
    esp: Arc<EspState>,
    fsp_url: String,
}

fn start_fsp(rt: &Runtime, dir: &PathBuf) -> FspMints {
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
    let esp_url = serve(rt, esp_mint::server::router(Arc::clone(&esp)));
    let mut cfg = fsp_mint::config::Config::default();
    cfg.set("service.did", &service().to_string()).unwrap();
    cfg.set("rotation.activation_hours", "120").unwrap();
    cfg.set("rotation.period_hours", "240").unwrap();
    cfg.validate().unwrap();
    std::fs::create_dir_all(dir.join("fsp")).unwrap();
    fsp_mint::keysets::record_first_issue(&dir.join("fsp"), NOW).unwrap();
    let service_keypair = {
        let mut b = [0u8; 32];
        b[31] = 1;
        Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&b).unwrap())
    };
    let state = Arc::new(FspState {
        spender: Spender::open(&dir.join("fsp"), cfg.rotation(), 1024, NOW).unwrap(),
        issues: Mutex::new(Issues::open(&dir.join("fsp")).unwrap()),
        issuer: Box::new(fsp_mint::esp_client::HttpIssuer::new(&esp_url, 10).unwrap()),
        service_keypair: Some(service_keypair),
        clock: Box::new(|| NOW),
        config: cfg,
    });
    FspMints {
        esp,
        fsp_url: serve(rt, fsp_mint::server::router(state)),
    }
}

fn fsp_wallet(dir: &PathBuf, m: &FspMints, name: &str, units: &[u64]) -> Wallet {
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
        let sk = m.esp.master.key_for(amount, &terms);
        let sig = m
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
            keyset: esp_mint::rotation::keyset_id(&m.esp.master),
        });
    }
    let mut w = Wallet::open(&dir.join(format!("{name}.json"))).unwrap();
    if !notes.is_empty() {
        w.receive_handover(&Handover {
            service: service(),
            redeemable_after_day: day,
            notes,
        })
        .unwrap();
    }
    w
}

fn fsp_total(w: &Wallet) -> u128 {
    w.balance().fsp
}

#[test]
fn fsp_notes_move_with_their_service_and_are_swapped_at_the_fsp_mint() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("fsp");
    let m = start_fsp(&rt, &dir);
    let mut a = fsp_wallet(&dir, &m, "a", &[8, 4, 1]);
    http::fsp_sync(&mut a, service(), &m.fsp_url).unwrap();
    let req = a.build_fsp_issue(service(), None, 0).unwrap();
    http::settle_fsp(&mut a, &m.fsp_url, &req.hash()).unwrap();
    assert_eq!(fsp_total(&a), 13);
    let hex = hex::encode(service().serialize());
    assert_eq!(a.balance().fsp_by_service[&hex], 13, "grouped by service");
    assert_eq!(a.fsp_unknown_service(), (0, 0));

    // Hand over all of it, and a DID key.
    let key = sp_wire::seal::SecretKey::from_array([7u8; 32]).unwrap();
    let sel = a.select_handoff(0, &[(service(), 13)]).unwrap();
    let out = a.export_handoff(&sel, "", Some(&key)).unwrap();
    assert!(out.with_did_key);
    assert_eq!(out.fsp_units, 13);
    assert_eq!(fsp_total(&a), 0);
    assert!(a.balance().fsp_by_service.get(&hex).copied().unwrap_or(0) == 0);

    // A wallet that has never seen this mint takes it in and swaps it.
    let mut b = fsp_wallet(&dir, &m, "b", &[]);
    let imported = b.import_handoff(&out.text, "a", true).unwrap();
    assert_eq!(imported.fsp_units, 13);
    assert_eq!(imported.did_key.map(|k| k.to_array()), Some([7u8; 32]));
    assert_eq!(fsp_total(&b), 13, "FSP is added first, then swapped");
    let log = http::complete_import(&mut b, &imported);
    assert!(log.iter().any(|l| l.contains("FSP swap")), "{log:?}");
    assert_eq!(fsp_total(&b), 13, "a swap pays nothing");
    assert_eq!(b.balance().fsp_by_service[&hex], 13);
    assert_eq!(b.fsp_unknown_service(), (0, 0));
    assert!(b.pending_fsp().is_empty());
    // The fresh notes are b's alone: none is a note a sent.
    assert!(
        b.notes()
            .iter()
            .filter(|n| n.kind == Kind::Fsp)
            .all(|n| !imported.notes.contains(&n.id()))
    );
    assert_eq!(b.handoffs_in()[0].id, out.id);
}
