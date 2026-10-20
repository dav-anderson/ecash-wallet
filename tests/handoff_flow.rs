//! Value handed from wallet to wallet as a string, with no AIR in between, in
//! the two valid kinds: a PSP handoff (sealed to the recipient's DID key,
//! in the balance at once and swapped at a real psp-mint) and an FSP handoff (the
//! DID key and a little FSP, never swapped, usable at a real fsp-mint), and the
//! sender's side (notes taken out, check, reclaim before and after the receiver's
//! swap, cancel, done, and records `send-psp` left in old wallet files).
//!
//! The PSP mint is reached over AIR, on its real listener against a real
//! `air_server` started in this process (see `common/mod.rs`); so is the ESP mint
//! behind the fsp-mint of the FSP test, whose Issuer is the real `AirIssuer`. The
//! AIR client always dials port 5702, so these tests need that port free, and they
//! take turns on the one shared server; they are built only with the
//! `air-listener-tests` feature. The wallet's own calls to the FSP mint are HTTP.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use ecash_wallet::config::AirSettings;
use ecash_wallet::handoff::{
    FSP_PREFIX, FSP_WARNING, HandoffKind, HandoffState, PSP_PREFIX, PSP_WARNING, Standing,
};
use ecash_wallet::legacy::{SentState, SentToken};
use ecash_wallet::mint_info::{check_handoff, complete_import, reclaim_handoff, rotation_sync};
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
use secp256k1::{Keypair, SECP256K1, SecretKey};
use sp_wire::ServiceDid;
use sp_wire::seal::SecretKey as DidSecretKey;
use tokio::runtime::Runtime;

use common::{EspAt, PspAt};

/// What the wallet's records call the PSP (the mint a handoff names). Nothing
/// dials it: the PSP is reached by DID.
const RECORD: &str = "http://127.0.0.1:3000";

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
    state: Arc<AppState>,
    rot: psp_mint::server::SharedRotating,
    /// Its AIR listener, and the turn on the shared server. Last.
    at: PspAt,
}

fn start_psp(dir: &Path) -> PspMint {
    let d = dir.join("psp");
    let (rotor, logic) =
        psp_mint::rotation::Rotor::open_at(&d, Amount::from_units(1024), 1, 1, T).unwrap();
    let rot =
        psp_mint::server::Rotating::new(rotor, psp_mint::rotation::Rollovers::open(&d).unwrap());
    let state = psp_mint::server::app_state(logic);
    // The listener keeps its state in a folder of its own, outside `dir`.
    let at = PspAt::new(
        Arc::clone(&state),
        Arc::clone(&rot),
        &scratch("airstate-psp"),
    );
    PspMint { state, rot, at }
}

impl PspMint {
    /// The wallet's `[air]` settings for this PSP.
    fn air(&self) -> AirSettings {
        self.at.air(10, 3)
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

fn psp_wallet(m: &PspMint, dir: &Path, name: &str, notes: Vec<StoredNote>) -> Wallet {
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

fn did(n: u8) -> DidSecretKey {
    DidSecretKey::from_array([n; 32]).unwrap()
}

/// Export `units` PSP from `dev` to `to`; returns the handoff (id and string).
fn make(
    dev: &mut Wallet,
    m: &PspMint,
    units: u128,
    to: &DidSecretKey,
) -> ecash_wallet::handoff::HandoffExport {
    let ids = dev.select_psp_handoff(units).unwrap();
    dev.export_psp_handoff(&ids, RECORD, &to.public_key())
        .unwrap()
}

#[test]
fn a_psp_handoff_sealed_to_the_user_counts_at_once_and_is_swapped_at_the_mint() {
    let dir = scratch("psp");
    let m = start_psp(&dir);
    let air = m.air();
    let (a, b, c) = (m.note(4), m.note(1), m.note(2));
    let mut dev = psp_wallet(&m, &dir, "dev", vec![a.clone(), b.clone(), c]);
    let mut user = psp_wallet(&m, &dir, "user", vec![]);
    let (user_key, other_key) = (did(7), did(9));

    let ids = dev.select_psp_handoff(5).unwrap();
    let out = dev
        .export_psp_handoff(&ids, RECORD, &user_key.public_key())
        .unwrap();
    assert!(out.text.starts_with(PSP_PREFIX));
    assert_eq!(out.kind, HandoffKind::Psp);
    assert_eq!((out.notes, out.psp_units, out.fsp_units), (2, 5, 0));
    assert!(!out.with_did_key, "a PSP handoff never carries a DID key");
    assert_eq!(out.warning, PSP_WARNING);
    assert_eq!(psp_total(&dev), 2, "the handed-off notes leave the balance");
    assert_eq!(dev.handoffs_out()[0].state, HandoffState::Pending);
    assert_eq!(
        dev.handoffs_out()[0].mint,
        RECORD,
        "the mint is kept for check and reclaim"
    );

    // Only the user's DID key opens it, and a failed attempt changes nothing.
    let err = user
        .import_psp_handoff(&out.text, &other_key, "dev")
        .unwrap_err();
    assert!(err.to_string().contains("cannot be opened"), "{err}");
    assert!(user.handoffs_in().is_empty() && user.pending_rollovers().is_empty());

    // The string survives being written down and typed back in.
    let typed = format!("  {}\n", out.text.to_lowercase());
    let imported = user.import_psp_handoff(&typed, &user_key, "dev").unwrap();
    assert_eq!(imported.psp_units, 5);
    assert_eq!(imported.psp_swaps.len(), 1, "the swap is stored first");
    // In the balance at once: no lock on notes that are not swapped yet.
    assert_eq!(psp_total(&user), 5);
    assert_eq!(user.balance().psp, 5);
    assert_eq!(user.unswapped_psp(), 5);
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(psp_total(&user), 5);
    assert_eq!(user.unswapped_psp(), 0);
    assert!(user.pending_rollovers().is_empty());
    assert!(m.spent(&a) && m.spent(&b), "the old notes are burned");
    let nonces: Vec<_> = user.notes().iter().map(|n| n.note.nonce).collect();
    assert!(!nonces.contains(&a.note.nonce) && !nonces.contains(&b.note.nonce));
    assert_eq!(user.handoffs_in()[0].from, "dev");
    assert!(user.handoffs_in()[0].swapped);
    assert_eq!(user.handoffs_in()[0].kind, HandoffKind::Psp);

    // The same string again: refused, and nothing is added.
    let err = user
        .import_psp_handoff(&out.text, &user_key, "dev")
        .unwrap_err();
    assert!(err.to_string().contains("imported already"), "{err}");
    assert_eq!(psp_total(&user), 5);
    // Someone who got hold of the string and the key too late has the notes in
    // the balance for a moment, then the mint says they are spent and they
    // leave it again: none of it is kept.
    let mut thief = psp_wallet(&m, &dir, "thief", vec![]);
    let imported = thief.import_psp_handoff(&out.text, &user_key, "").unwrap();
    assert_eq!(psp_total(&thief), 5);
    let log = complete_import(&mut thief, &air, &imported);
    assert!(
        log.iter().any(|l| l.contains("spent already")),
        "the mint refuses a second swap: {log:?}"
    );
    assert_eq!(psp_total(&thief), 0, "none of it is kept");
    assert_eq!(thief.unswapped_psp(), 0);
    assert!(thief.pending_rollovers().is_empty());
    assert_eq!(thief.spent_notes().len(), 2);

    // The sender asks the mint and learns it was claimed.
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Received
    );
    assert_eq!(dev.handoffs_out()[0].state, HandoffState::Done);
    assert!(dev.handoffs_out()[0].notes.is_empty());
    assert!(dev.cancel_handoff(&out.id).is_err());
}

#[test]
fn unswapped_psp_is_in_the_balance_and_spendable_and_is_swapped_when_the_mint_answers() {
    let dir = scratch("unswapped");
    let m = start_psp(&dir);
    let air = m.air();
    let key = did(7);

    // The mint is not answering: the swap cannot go through (one short try).
    m.at.silence();
    let quick = m.at.air(1, 1);
    let mut dev = psp_wallet(&m, &dir, "dev", vec![m.note(8), m.note(2)]);
    let ids = dev.select_psp_handoff(10).unwrap();
    let out = dev
        .export_psp_handoff(&ids, RECORD, &key.public_key())
        .unwrap();
    let mut user = psp_wallet(&m, &dir, "user", vec![]);
    let imported = user.import_psp_handoff(&out.text, &key, "").unwrap();
    let log = complete_import(&mut user, &quick, &imported);
    assert!(log.iter().any(|l| l.contains("stays unswapped")), "{log:?}");
    assert_eq!(psp_total(&user), 10);
    assert_eq!(user.balance().psp, 10, "counted, not locked");
    assert_eq!(user.balance().unswapped_psp, 10);
    assert_eq!(user.pending_rollovers().len(), 1, "the swap is kept");
    assert_eq!(
        user.select_psp_handoff(2).unwrap().len(),
        1,
        "unswapped notes can be spent or handed on"
    );
    // The state survives a restart.
    let again = Wallet::open(&dir.join("user.json")).unwrap();
    assert_eq!(again.unswapped_psp(), 10);
    assert_eq!(again.balance().psp, 10);

    // The same notes with the mint answering: the swap is sent again by the
    // next sync (what the command line does at every start), and then it is final.
    m.at.listen();
    let mut dev2 = psp_wallet(&m, &dir, "dev2", vec![m.note(8), m.note(2)]);
    let out = make(&mut dev2, &m, 10, &key);
    let mut user2 = psp_wallet(&m, &dir, "user2", vec![]);
    let imported = user2.import_psp_handoff(&out.text, &key, "").unwrap();
    assert_eq!(user2.unswapped_psp(), 10, "stored and not sent yet");
    assert_eq!(psp_total(&user2), 10, "and already counted");
    let log = rotation_sync(&mut user2, &air, Kind::Psp, RECORD).unwrap();
    assert!(log.iter().any(|l| l.contains("swapped 10 PSP")), "{log:?}");
    assert_eq!(imported.psp_swaps.len(), 1);
    assert_eq!(psp_total(&user2), 10);
    assert_eq!(user2.unswapped_psp(), 0);
    assert!(user2.pending_rollovers().is_empty());

    // Spending first: a note handed on before the swap is sent is left out of
    // it, and the one who got it can still swap it, because the mint has not
    // seen it yet.
    let mut dev3 = psp_wallet(&m, &dir, "dev3", vec![m.note(8), m.note(2)]);
    let out = make(&mut dev3, &m, 10, &key);
    let mut user3 = psp_wallet(&m, &dir, "user3", vec![]);
    user3.import_psp_handoff(&out.text, &key, "").unwrap();
    let onward = make(&mut user3, &m, 2, &did(8));
    assert_eq!(psp_total(&user3), 8);
    let log = rotation_sync(&mut user3, &air, Kind::Psp, RECORD).unwrap();
    assert!(log.iter().any(|l| l.contains("swapped 8 PSP")), "{log:?}");
    assert_eq!(psp_total(&user3), 8);
    assert!(user3.pending_rollovers().is_empty());
    let mut friend = psp_wallet(&m, &dir, "friend", vec![]);
    let imported = friend
        .import_psp_handoff(&onward.text, &did(8), "")
        .unwrap();
    let log = complete_import(&mut friend, &air, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(psp_total(&friend), 2);
}

#[test]
fn the_sender_reclaims_a_handoff_the_receiver_has_not_swapped() {
    let dir = scratch("reclaim-before");
    let m = start_psp(&dir);
    let air = m.air();
    let (a, b, c) = (m.note(4), m.note(1), m.note(2));
    let mut dev = psp_wallet(&m, &dir, "dev", vec![a.clone(), b.clone(), c]);
    let key = did(7);
    let out = make(&mut dev, &m, 5, &key);
    assert_eq!(psp_total(&dev), 2);

    // Nothing is spent at the mint yet: it is still the sender's.
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Pending
    );
    let done = reclaim_handoff(&mut dev, &air, &out.id).unwrap();
    assert_eq!(done.standing, Standing::Reclaimed);
    assert!(
        done.log.iter().any(|l| l.contains("reclaimed 5 PSP")),
        "{:?}",
        done.log
    );
    assert_eq!(psp_total(&dev), 7, "the notes are back, as fresh ones");
    assert!(
        m.spent(&a) && m.spent(&b),
        "the handed-off notes are burned"
    );
    assert!(dev.pending_rollovers().is_empty());
    let h = &dev.handoffs_out()[0];
    assert_eq!(
        (h.state, h.reclaim.clone(), h.notes.len()),
        (HandoffState::Reclaimed, None, 0)
    );
    assert!(dev.cancel_handoff(&out.id).is_err());
    // asking again changes nothing
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Reclaimed
    );
    assert_eq!(
        reclaim_handoff(&mut dev, &air, &out.id).unwrap().standing,
        Standing::Reclaimed
    );
    assert_eq!(psp_total(&dev), 7);
    // and it is in the file
    let again = Wallet::open(&dir.join("dev.json")).unwrap();
    assert_eq!(again.handoffs_out()[0].state, HandoffState::Reclaimed);

    // The receiver comes late: its notes are in the balance for a moment, then
    // the mint says they are spent, and they leave it.
    let mut user = psp_wallet(&m, &dir, "user", vec![]);
    let imported = user.import_psp_handoff(&out.text, &key, "dev").unwrap();
    assert_eq!(psp_total(&user), 5);
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("spent already")), "{log:?}");
    assert_eq!(psp_total(&user), 0);
    assert!(user.pending_rollovers().is_empty());
    assert_eq!(user.spent_notes().len(), 2);
}

#[test]
fn a_reclaim_after_the_receiver_swapped_finds_the_notes_gone_and_takes_nothing() {
    let dir = scratch("reclaim-after");
    let m = start_psp(&dir);
    let air = m.air();
    let mut dev = psp_wallet(&m, &dir, "dev", vec![m.note(4), m.note(1), m.note(2)]);
    let key = did(7);
    let out = make(&mut dev, &m, 5, &key);
    let mut user = psp_wallet(&m, &dir, "user", vec![]);
    let imported = user.import_psp_handoff(&out.text, &key, "").unwrap();
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");

    let done = reclaim_handoff(&mut dev, &air, &out.id).unwrap();
    assert_eq!(done.standing, Standing::Received);
    assert!(done.log.is_empty(), "no swap was sent: {:?}", done.log);
    assert_eq!(psp_total(&dev), 2, "nothing came back");
    assert!(dev.pending_rollovers().is_empty());
    let h = &dev.handoffs_out()[0];
    assert_eq!(
        (h.state, h.notes.len(), h.spent_elsewhere),
        (HandoffState::Done, 0, 2)
    );
    assert_eq!(psp_total(&user), 5, "the receiver kept what it swapped");
    // asking again, and cancelling, change nothing
    assert_eq!(
        reclaim_handoff(&mut dev, &air, &out.id).unwrap().standing,
        Standing::Received
    );
    assert!(dev.cancel_handoff(&out.id).is_err());
}

#[test]
fn a_note_spent_elsewhere_drops_out_and_the_rest_is_still_reclaimed_or_swapped() {
    let dir = scratch("partly");
    let m = start_psp(&dir);
    let air = m.air();
    let (c, d) = (m.note(2), m.note(8));
    let key = did(7);

    // Handoff H of c and d; then c is spent at the mint by someone who held a copy.
    let mut dev = psp_wallet(&m, &dir, "dev", vec![c.clone(), d.clone()]);
    let out = make(&mut dev, &m, 10, &key);
    let mut copy = psp_wallet(&m, &dir, "copy", vec![c.clone()]);
    let c_out = make(&mut copy, &m, 2, &did(5));
    let mut holder = psp_wallet(&m, &dir, "holder", vec![]);
    let imported = holder.import_psp_handoff(&c_out.text, &did(5), "").unwrap();
    assert!(
        complete_import(&mut holder, &air, &imported)
            .iter()
            .any(|l| l.contains("final"))
    );
    assert!(m.spent(&c) && !m.spent(&d));

    // The sender sees one of two spent and takes the other back.
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Partly { spent: 1, left: 1 }
    );
    assert_eq!(dev.handoffs_out()[0].notes.len(), 1);
    let done = reclaim_handoff(&mut dev, &air, &out.id).unwrap();
    assert_eq!(done.standing, Standing::Reclaimed);
    assert_eq!(psp_total(&dev), 8, "the unspent note is back");
    assert!(m.spent(&d));

    // The same on the receiving side, with a fresh pair: the note spent
    // elsewhere leaves the balance and the other is swapped in the same run.
    let (e, f) = (m.note(2), m.note(8));
    let mut dev2 = psp_wallet(&m, &dir, "dev2", vec![e.clone(), f.clone()]);
    let out2 = make(&mut dev2, &m, 10, &key);
    let mut copy2 = psp_wallet(&m, &dir, "copy2", vec![e.clone()]);
    let e_out = make(&mut copy2, &m, 2, &did(5));
    let mut holder2 = psp_wallet(&m, &dir, "holder2", vec![]);
    let imported = holder2
        .import_psp_handoff(&e_out.text, &did(5), "")
        .unwrap();
    complete_import(&mut holder2, &air, &imported);
    let mut user = psp_wallet(&m, &dir, "user", vec![]);
    let imported = user.import_psp_handoff(&out2.text, &key, "").unwrap();
    assert_eq!(psp_total(&user), 10);
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("spent already")), "{log:?}");
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(
        psp_total(&user),
        8,
        "only the note nobody else spent is kept"
    );
    assert_eq!(user.spent_notes().len(), 1);
    assert_eq!(user.unswapped_psp(), 0);
    assert!(user.pending_rollovers().is_empty());
    assert_eq!(
        check_handoff(&mut dev2, &air, &out2.id).unwrap(),
        Standing::Received
    );
}

/// A wallet file as wallet 0.4.0 left it after `send-psp`.
fn old_wallet(m: &PspMint, dir: &Path, name: &str, sent: Vec<SentToken>) -> Wallet {
    let ks = psp_mint::rotation::keyset_id(m.state.logic.lock().unwrap().public_keys());
    let data = WalletData {
        keysets: sent
            .iter()
            .flat_map(|t| t.notes.iter())
            .map(|n| (n.id(), ks.clone()))
            .collect(),
        sent,
        ..Default::default()
    };
    let path = dir.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    Wallet::open(&path).unwrap()
}

#[test]
fn old_send_psp_records_are_handoffs_that_can_be_checked_and_reclaimed() {
    let dir = scratch("legacy");
    let m = start_psp(&dir);
    let air = m.air();
    let token = |id: &str, notes: Vec<StoredNote>, state| SentToken {
        id: id.into(),
        mint: RECORD.to_string(),
        amount: notes.iter().map(|n| u128::from(n.amount)).sum(),
        notes,
        state,
    };

    let (a, b) = (m.note(4), m.note(2));
    let mut dev = old_wallet(
        &m,
        &dir,
        "old-pending",
        vec![
            token(
                "pending-token",
                vec![a.clone(), b.clone()],
                SentState::Pending,
            ),
            token("received-token", vec![], SentState::Received),
            token("reclaimed-token", vec![], SentState::Reclaimed),
        ],
    );
    assert!(dev.snapshot().sent.is_empty(), "migrated on load");
    let ids: Vec<&str> = dev.handoffs_out().iter().map(|h| h.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["pending-token", "received-token", "reclaimed-token"]
    );
    assert_eq!(dev.handoffs_out()[0].state, HandoffState::Pending);
    assert_eq!(dev.handoffs_out()[0].kind, HandoffKind::Psp);
    assert_eq!(dev.handoffs_out()[0].psp_units, 6);
    assert_eq!(
        check_handoff(&mut dev, &air, "received-token").unwrap(),
        Standing::Received
    );
    assert_eq!(
        check_handoff(&mut dev, &air, "reclaimed-token").unwrap(),
        Standing::Reclaimed
    );
    assert_eq!(
        check_handoff(&mut dev, &air, "pending-token").unwrap(),
        Standing::Pending
    );
    let done = reclaim_handoff(&mut dev, &air, "pending-token").unwrap();
    assert_eq!(done.standing, Standing::Reclaimed);
    assert_eq!(psp_total(&dev), 6);
    assert!(m.spent(&a) && m.spent(&b));
    // saved without the old field, and the same on the next open
    let text = std::fs::read_to_string(dev.path()).unwrap();
    assert!(!text.contains("\"sent\""), "{text}");
    let again = Wallet::open(dev.path()).unwrap();
    assert_eq!(again.handoffs_out().len(), 3);
    assert_eq!(again.handoffs_out()[0].state, HandoffState::Reclaimed);

    // A token whose swap back was stored and not sent when the old wallet died.
    let (c, d) = (m.note(8), m.note(1));
    let mut maker = psp_wallet(&m, &dir, "maker", vec![c.clone(), d.clone()]);
    let out = make(&mut maker, &m, 9, &did(7));
    let rollover = maker.begin_reclaim(&out.id).unwrap();
    let mut data = maker.snapshot();
    let mut record = data.handoffs_out.remove(0);
    record.reclaim = None;
    data.sent = vec![SentToken {
        id: record.id.clone(),
        mint: RECORD.to_string(),
        amount: 9,
        notes: record.notes.clone(),
        state: SentState::Reclaiming { rollover },
    }];
    let path = dir.join("old-reclaiming.json");
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    let mut old = Wallet::open(&path).unwrap();
    assert!(old.handoffs_out()[0].reclaim.is_some());
    assert_eq!(old.pending_rollovers().len(), 1);
    // `handoff check` sends the stored swap again and finishes it
    assert_eq!(
        check_handoff(&mut old, &air, &record.id).unwrap(),
        Standing::Reclaimed
    );
    assert_eq!(psp_total(&old), 9);
    assert!(old.pending_rollovers().is_empty());
}

#[test]
fn a_cancelled_psp_handoff_returns_the_notes() {
    let dir = scratch("cancel");
    let m = start_psp(&dir);
    let mut dev = psp_wallet(&m, &dir, "dev", vec![m.note(8), m.note(2)]);
    let ids = dev.select_psp_handoff(10).unwrap();
    let out = dev
        .export_psp_handoff(&ids, RECORD, &did(7).public_key())
        .unwrap();
    assert_eq!(psp_total(&dev), 0);
    assert_eq!(dev.cancel_handoff(&out.id).unwrap(), 2);
    assert_eq!(psp_total(&dev), 10);
    assert!(dev.handoffs_out().is_empty());
    // The reopened wallet file holds the same.
    let again = Wallet::open(&dir.join("dev.json")).unwrap();
    assert_eq!(psp_total(&again), 10);
}

// ---- FSP ---------------------------------------------------------------------------

fn service() -> ServiceDid {
    let mut b = [0u8; 32];
    b[31] = 1;
    ServiceDid::from(
        Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&b).unwrap()).public_key(),
    )
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
    /// The ESP mint's AIR listener and the turn on the shared AIR server. Last.
    _esp_at: EspAt,
}

fn start_fsp(rt: &Runtime, dir: &Path) -> FspMints {
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
    // The listener keeps its state in a folder of its own, outside `dir`.
    let esp_at = EspAt::new(Arc::clone(&esp), &scratch("airstate-esp"));
    let mut cfg = fsp_mint::config::Config::default();
    for (key, value) in esp_at.fsp_settings("20", "2") {
        cfg.set(key, &value).unwrap();
    }
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
        issuer: Box::new(fsp_mint::esp_air::AirIssuer::new(&cfg).unwrap()),
        service_keypair: Some(service_keypair),
        clock: Box::new(|| NOW),
        config: cfg,
    });
    FspMints {
        esp,
        fsp_url: serve(rt, fsp_mint::server::router(state)),
        _esp_at: esp_at,
    }
}

fn fsp_wallet(dir: &Path, m: &FspMints, name: &str, units: &[u64]) -> Wallet {
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
fn an_fsp_handoff_carries_the_did_key_and_the_notes_work_at_the_fsp_mint() {
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

    // Hand over all of it, with the DID key.
    let key = did(7);
    let ids = a.select_fsp_handoff(&[(service(), 13)]).unwrap();
    let out = a.export_fsp_handoff(&ids, &key).unwrap();
    assert!(out.text.starts_with(FSP_PREFIX));
    assert_eq!(out.kind, HandoffKind::Fsp);
    assert!(out.with_did_key);
    assert_eq!((out.psp_units, out.fsp_units), (0, 13));
    assert_eq!(out.warning, FSP_WARNING);
    assert_eq!(fsp_total(&a), 0);
    assert!(a.balance().fsp_by_service.get(&hex).copied().unwrap_or(0) == 0);

    // A wallet that has never seen this mint takes it in. Nothing is swapped.
    let mut b = fsp_wallet(&dir, &m, "b", &[]);
    let imported = b.import_fsp_handoff(&out.text, "a").unwrap();
    assert_eq!(imported.fsp_units, 13);
    assert_eq!(
        imported.did_key.as_ref().map(|k| k.to_array()),
        Some([7u8; 32])
    );
    assert!(imported.psp_swaps.is_empty());
    assert!(complete_import(&mut b, &AirSettings::default(), &imported).is_empty());
    assert!(b.pending_rollovers().is_empty() && b.pending_fsp().is_empty());
    assert_eq!(fsp_total(&b), 13);
    assert_eq!(b.balance().fsp_by_service[&hex], 13);
    assert_eq!(b.fsp_unknown_service(), (0, 0));
    assert!(!b.handoffs_in()[0].swapped);
    // They are the very notes a sent.
    let sent: Vec<String> = a.handoffs_out()[0].notes.iter().map(|n| n.id()).collect();
    for id in &sent {
        assert!(b.notes().iter().any(|n| &n.id() == id));
    }
    assert_eq!(b.handoffs_in()[0].id, out.id);

    // And they pay at the service's mint, once the new wallet has read its keys.
    http::fsp_sync(&mut b, service(), &m.fsp_url).unwrap();
    let req = b.build_fsp_spend(service(), 5, "coffee").unwrap();
    http::settle_fsp(&mut b, &m.fsp_url, &req.hash()).unwrap();
    assert_eq!(fsp_total(&b), 8);

    // The old device lets go of what it handed over: after this it cannot be
    // cancelled, so the old copy cannot be put back by mistake.
    a.finish_handoff(&out.id).unwrap();
    assert!(a.cancel_handoff(&out.id).is_err());
}

#[test]
fn the_old_combined_handoff_and_wrong_kinds_are_refused_at_the_wallet() {
    let dir = scratch("wrong");
    let m = start_psp(&dir);
    let mut dev = psp_wallet(&m, &dir, "dev", vec![m.note(4), m.note(2)]);
    let mut user = psp_wallet(&m, &dir, "user", vec![]);
    let ids = dev.select_psp_handoff(6).unwrap();
    let out = dev
        .export_psp_handoff(&ids, RECORD, &did(7).public_key())
        .unwrap();
    // A PSP string is not an FSP handoff and the reverse, and the old prefix is gone.
    assert!(user.import_fsp_handoff(&out.text, "").is_err());
    let e = user
        .import_handoff("SPH1:ABCDEF", None, "")
        .unwrap_err()
        .to_string();
    assert!(e.contains("old combined handoff"), "{e}");
    let e = user
        .import_handoff(&out.text, None, "")
        .unwrap_err()
        .to_string();
    assert!(e.contains("give the DID secret key"), "{e}");
    assert!(user.handoffs_in().is_empty() && user.pending_rollovers().is_empty());
}
