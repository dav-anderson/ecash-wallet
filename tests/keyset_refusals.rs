//! A hand-over holding a note that names no keyset is refused cleanly, and the
//! wallet stores nothing from it (no guessing). The refusal of a file is
//! sp-wire's: `Handover::read` refuses a note with no `keyset` (the file does not
//! parse) and a note with an empty one (naming the note). The wallet's own
//! `receive_handover` takes a typed `Handover`, which can be built without that
//! parse, and refuses an empty keyset too. (A handoff cannot hold one either: its
//! format requires a key set for every note.)

use ecash_wallet::store::{HandedNote, Handover};
use ecash_wallet::{Wallet, WalletError};
use mint_types::{Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};

/// The network these wallets are made for.
const NETWORK: &str = "regtest";

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wallet-noks-{name}-{}", {
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

/// A note whose spend secret matches its nonce (the signature is not checked
/// on receipt).
fn note() -> (Note, secp256k1::SecretKey) {
    let kp = Keypair::new(SECP256K1, &mut OsRng);
    let sig = Keypair::new(SECP256K1, &mut OsRng).public_key();
    (
        Note {
            nonce: Nonce(kp.public_key()),
            signature: sig,
        },
        kp.secret_key(),
    )
}

fn file(w: &Wallet) -> Option<Vec<u8>> {
    std::fs::read(w.path()).ok()
}

fn handed(keyset: &str) -> HandedNote {
    let (n, sk) = note();
    HandedNote {
        amount: 4,
        note: n,
        spend_secret: sk,
        keyset: keyset.into(),
    }
}

fn handover(notes: Vec<HandedNote>) -> Handover {
    Handover {
        service: sp_wire::ServiceDid::from(Keypair::new(SECP256K1, &mut OsRng).public_key()),
        redeemable_after_day: 100,
        notes,
    }
}

#[test]
fn a_handover_with_a_note_without_a_keyset_is_refused_and_nothing_is_stored() {
    let dir = scratch("handover");
    let mut w = Wallet::open(&dir.join("w.json"), NETWORK).unwrap();
    let before = file(&w);

    // The file as fsp-mint writes it reads back as the same hand-over.
    let good = handover(vec![handed(&"ab".repeat(8)), handed(&"cd".repeat(8))]);
    assert_eq!(
        Handover::read(&serde_json::to_vec(&good).unwrap()).unwrap(),
        good
    );

    // With the second note's `keyset` taken out: the first note is fine, the
    // second names no keyset. sp-wire does not read it, so there is nothing to
    // hand to the wallet.
    let mut value = serde_json::to_value(&good).unwrap();
    value["notes"][1]
        .as_object_mut()
        .unwrap()
        .remove("keyset")
        .expect("the file names a keyset for every note");
    let e = Handover::read(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert!(e.starts_with("not a hand-over file: "), "{e}");
    assert!(e.contains("missing field `keyset`"), "{e}");
    assert_eq!(file(&w), before, "the wallet file is unchanged");

    // A note that names an empty keyset: sp-wire's reader refuses the file and
    // names the note.
    let blank = handover(vec![handed(&"ab".repeat(8)), handed("")]);
    let e = Handover::read(&serde_json::to_vec(&blank).unwrap()).unwrap_err();
    assert_eq!(
        e,
        "note 2 of the hand-over file names no keyset (its keyset is empty)"
    );

    // A typed hand-over does not go through the reader, so the wallet refuses
    // the empty keyset itself, and keeps not even the good note.
    match w.receive_handover(&blank) {
        Err(WalletError::Invalid(why)) => assert!(why.contains("names no keyset"), "{why}"),
        other => panic!("expected the empty keyset to be refused, got {other:?}"),
    }
    assert!(w.notes().is_empty(), "not even the good note is kept");
    assert_eq!(file(&w), before, "the wallet file is unchanged");
    let reopened = Wallet::open(&dir.join("w.json"), NETWORK).unwrap();
    assert!(reopened.notes().is_empty());
}
