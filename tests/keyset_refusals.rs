//! A hand-over or a token holding a note that names no keyset is refused
//! cleanly, and the wallet stores nothing from it (no guessing).

use ecash_wallet::Wallet;
use ecash_wallet::send::{Token, TokenNote};
use ecash_wallet::store::{HandedNote, Handover};
use mint_types::{Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};

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

#[test]
fn a_handover_with_a_note_without_a_keyset_is_refused_and_nothing_is_stored() {
    let dir = scratch("handover");
    let mut w = Wallet::open(&dir.join("w.json")).unwrap();
    let before = file(&w);
    let handed = |keyset: &str| {
        let (n, sk) = note();
        HandedNote {
            amount: 4,
            note: n,
            spend_secret: sk,
            keyset: keyset.into(),
        }
    };
    let service = Keypair::new(SECP256K1, &mut OsRng).x_only_public_key().0;
    // The first note is fine; the second names no keyset.
    let h = Handover {
        service,
        redeemable_after_day: 100,
        notes: vec![handed(&"ab".repeat(8)), handed("")],
    };
    let e = w.receive_handover(&h).unwrap_err().to_string();
    assert!(e.contains("names no keyset"), "{e}");
    assert!(w.notes().is_empty(), "not even the good note is kept");
    assert_eq!(file(&w), before, "the wallet file is unchanged");
    let reopened = Wallet::open(&dir.join("w.json")).unwrap();
    assert!(reopened.notes().is_empty());
}

#[test]
fn a_token_with_a_note_without_a_keyset_is_refused_and_nothing_is_stored() {
    let dir = scratch("token");
    let mut w = Wallet::open(&dir.join("w.json")).unwrap();
    let before = file(&w);
    let token_note = |keyset: &str| {
        let (n, sk) = note();
        TokenNote {
            amount: 2,
            note: n,
            spend_secret: sk,
            keyset: keyset.into(),
        }
    };
    let t = Token {
        mint: "http://127.0.0.1:9".into(),
        notes: vec![token_note(&"cd".repeat(8)), token_note("")],
    };
    // Through the encoded form too: an empty keyset is left out of the token.
    let t = Token::decode(&t.encode()).unwrap();
    assert!(t.notes[1].keyset.is_empty());
    let e = w.begin_receive(&t).unwrap_err().to_string();
    assert!(e.contains("names no keyset"), "{e}");
    assert!(w.pending_rollovers().is_empty(), "no swap is stored");
    assert!(w.notes().is_empty());
    assert_eq!(file(&w), before, "the wallet file is unchanged");
}
