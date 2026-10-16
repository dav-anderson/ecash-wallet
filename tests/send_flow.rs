//! PSP handed from wallet to wallet, settled by a swap at a real psp-mint.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use ecash_wallet::send::{Received, SentState, Token};
use ecash_wallet::store::{StoredNote, WalletData};
use ecash_wallet::{Kind, Wallet, http};
use mint_server::state::AppState;
use mint_types::{Amount, BlindNonce, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
use tokio::runtime::Runtime;

const T: u64 = 1_800_000_000;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wallet-send-{}-{name}", {
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

/// A wallet holding `notes`, each recorded with the keyset that signed it (as
/// a claim records it).
fn wallet_with(m: &PspMint, dir: &PathBuf, name: &str, notes: Vec<StoredNote>) -> Wallet {
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
fn a_good_send_is_final_once_the_receiver_swaps_it() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("good");
    let m = start_psp(&rt, &dir);
    let (a, b, c) = (m.note(4), m.note(1), m.note(2));
    let mut dev = wallet_with(&m, &dir, "dev", vec![a.clone(), b.clone(), c]);
    let mut user = wallet_with(&m, &dir, "user", vec![]);
    let token = dev.export_psp_amount(&m.url, 5).unwrap();
    assert_eq!(psp_total(&dev), 2, "the sent notes leave the balance");
    let id = Token::decode(&token).unwrap().id();
    assert_eq!(dev.sent_tokens()[0].state, SentState::Pending);
    assert_eq!(http::check_sent(&mut dev, &id).unwrap(), SentState::Pending);

    assert_eq!(
        http::receive_psp(&mut user, &token).unwrap(),
        Received::Final { amount: 5 }
    );
    assert_eq!(psp_total(&user), 5);
    assert!(user.pending_rollovers().is_empty());
    assert!(
        m.spent(&a) && m.spent(&b),
        "the token's notes are burned by the swap"
    );
    // The user's notes are fresh: the developer's secrets do not touch them.
    let nonces: Vec<_> = user.notes().iter().map(|n| n.note.nonce).collect();
    assert!(!nonces.contains(&a.note.nonce) && !nonces.contains(&b.note.nonce));

    assert_eq!(
        http::check_sent(&mut dev, &id).unwrap(),
        SentState::Received
    );
    assert!(
        dev.sent_tokens()[0].notes.is_empty(),
        "no secrets kept once final"
    );
}

#[test]
fn a_double_spent_token_is_rejected_and_nothing_is_kept() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("double");
    let m = start_psp(&rt, &dir);
    let (a, b) = (m.note(4), m.note(1));
    let mut dev = wallet_with(&m, &dir, "dev", vec![a.clone(), b.clone()]);
    let token = dev.export_psp_amount(&m.url, 5).unwrap();
    let id = Token::decode(&token).unwrap().id();
    // The same token reaches two users (say, a restored app or a bug).
    let mut first = wallet_with(&m, &dir, "first", vec![]);
    let mut second = wallet_with(&m, &dir, "second", vec![]);
    assert!(matches!(
        http::receive_psp(&mut first, &token).unwrap(),
        Received::Final { .. }
    ));
    let r = http::receive_psp(&mut second, &token).unwrap();
    assert!(
        matches!(&r, Received::Rejected { why } if why.contains("spent")),
        "{r:?}"
    );
    assert!(second.notes().is_empty() && second.pending_rollovers().is_empty());

    // A note of a token spent elsewhere first: the whole swap is refused,
    // the other note is not burned, and the sender learns it and reclaims.
    let (c, d) = (m.note(2), m.note(8));
    let mut dev2 = wallet_with(&m, &dir, "dev2", vec![c.clone(), d.clone()]);
    let token2 = dev2.export_psp_amount(&m.url, 10).unwrap();
    let id2 = Token::decode(&token2).unwrap().id();
    let mut thief = wallet_with(&m, &dir, "thief", vec![]);
    let only_c = Token {
        mint: m.url.clone(),
        notes: Token::decode(&token2)
            .unwrap()
            .notes
            .into_iter()
            .filter(|n| n.note.nonce == c.note.nonce)
            .collect(),
    };
    assert!(matches!(
        http::receive_psp(&mut thief, &only_c.encode()).unwrap(),
        Received::Final { .. }
    ));
    let mut user = wallet_with(&m, &dir, "user", vec![]);
    assert!(matches!(
        http::receive_psp(&mut user, &token2).unwrap(),
        Received::Rejected { .. }
    ));
    assert!(user.notes().is_empty());
    assert!(!m.spent(&d), "nothing is burned when a swap is refused");
    assert_eq!(
        http::check_sent(&mut dev2, &id2).unwrap(),
        SentState::Conflict { spent_elsewhere: 1 }
    );
    assert_eq!(
        http::reclaim_sent(&mut dev2, &id2).unwrap(),
        SentState::Reclaimed
    );
    assert_eq!(psp_total(&dev2), 8);
    // The first token: all spent, so received.
    assert_eq!(
        http::check_sent(&mut dev, &id).unwrap(),
        SentState::Received
    );
}

#[test]
fn a_crash_between_import_and_swap_is_finished_and_an_unswapped_token_reclaimed() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("crash");
    let m = start_psp(&rt, &dir);
    let mut dev = wallet_with(&m, &dir, "dev", vec![m.note(4), m.note(2)]);
    let token = dev.export_psp_amount(&m.url, 6).unwrap();
    let mut user = wallet_with(&m, &dir, "user", vec![]);
    user.begin_receive(&Token::decode(&token).unwrap()).unwrap();
    drop(user); // the app dies before the swap is sent
    let mut user = Wallet::open(&dir.join("user.json")).unwrap();
    assert_eq!(
        user.pending_rollovers().len(),
        1,
        "the swap was stored first"
    );
    assert!(user.notes().is_empty(), "not final until the swap");
    // The next start finishes it (the startup sync sends stored swaps).
    let log = http::rotation_sync(&mut user, Kind::Psp, &m.url).unwrap();
    assert!(log.iter().any(|l| l.contains("rolled over 2")), "{log:?}");
    assert_eq!(psp_total(&user), 6);
    assert!(user.pending_rollovers().is_empty());

    // A token that is never swapped: the sender takes it back, and a late
    // import is then rejected.
    let token2 = dev.export_psp_amount(&m.url, 0).err();
    assert!(token2.is_some(), "nothing left to send");
    let mut dev = wallet_with(&m, &dir, "dev3", vec![m.note(1)]);
    let token3 = dev.export_psp_amount(&m.url, 1).unwrap();
    let id3 = Token::decode(&token3).unwrap().id();
    assert_eq!(
        http::reclaim_sent(&mut dev, &id3).unwrap(),
        SentState::Reclaimed
    );
    assert_eq!(psp_total(&dev), 1);
    let mut late = wallet_with(&m, &dir, "late", vec![]);
    assert!(matches!(
        http::receive_psp(&mut late, &token3).unwrap(),
        Received::Rejected { .. }
    ));
    assert!(late.notes().is_empty());
}

#[test]
fn a_swap_retried_by_request_hash_gets_the_stored_answer() {
    let rt = Runtime::new().unwrap();
    let dir = scratch("retry");
    let m = start_psp(&rt, &dir);
    let mut dev = wallet_with(&m, &dir, "dev", vec![m.note(16), m.note(4)]);
    let token = dev.export_psp_amount(&m.url, 20).unwrap();
    let mut user = wallet_with(&m, &dir, "user", vec![]);
    let id = user.begin_receive(&Token::decode(&token).unwrap()).unwrap();
    assert_eq!(
        user.begin_receive(&Token::decode(&token).unwrap()).unwrap(),
        id,
        "one stored swap per token"
    );
    // The mint swaps, but the reply is lost.
    let body = user.pending_rollovers()[0].body.clone();
    let post = || {
        reqwest::blocking::Client::new()
            .post(format!("{}/rollover", m.url))
            .json(&body)
            .send()
            .unwrap()
    };
    let r1 = post();
    assert_eq!(r1.status().as_u16(), 200);
    let first: serde_json::Value = r1.json().unwrap();
    let second: serde_json::Value = post().json().unwrap();
    assert_eq!(first, second, "a repeat gets the stored answer");
    // Importing the same token again sends the same request and finishes.
    assert_eq!(
        http::receive_psp(&mut user, &token).unwrap(),
        Received::Final { amount: 20 }
    );
    assert_eq!(psp_total(&user), 20);
}
