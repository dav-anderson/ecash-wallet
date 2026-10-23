//! Taking in the ESP an FSP mint kept for a service.
//!
//! An ESP note names one service, and only that service can redeem it or move
//! it. [`Wallet::receive_handover`], behind the `receive` command, is how the
//! service takes in the ESP that fsp-mint's `export-esp` wrote (a [`Handover`]
//! file). `pick_exact` chooses the ESP notes of a hand-over for `fsp.rs`.
//!
//! The service redeems the notes it receives with the ESP mint (`redeem.rs`); the
//! wallet makes no transfer of its own: FSP issue carries the ESP hand-over to
//! fsp-mint over AIR (`fsp.rs`).

use std::collections::HashSet;

use secp256k1::{Keypair, SECP256K1};

use crate::error::WalletError;
use crate::store::{Handover, Kind, StoredNote, StoredTerms, Wallet};

/// How many search steps to spend looking for an exact set of notes.
const SEARCH_BUDGET: u32 = 100_000;

/// The indexes of notes that add up to exactly `target`, or `None`. `amounts` is
/// sorted largest first. The search gives up after a fixed budget, so a very
/// large wallet with an awkward amount may be refused even when a set exists.
pub(crate) fn pick_exact(amounts: &[u64], target: u128) -> Option<Vec<usize>> {
    if target == 0 {
        return None;
    }
    let mut suffix = vec![0u128; amounts.len() + 1];
    for i in (0..amounts.len()).rev() {
        suffix[i] = suffix[i + 1] + u128::from(amounts[i]);
    }
    if suffix[0] < target {
        return None;
    }
    fn walk(
        amounts: &[u64],
        suffix: &[u128],
        target: u128,
        i: usize,
        sum: u128,
        current: &mut Vec<usize>,
        budget: &mut u32,
    ) -> bool {
        if sum == target {
            return true;
        }
        if *budget == 0 || i == amounts.len() || sum > target || sum + suffix[i] < target {
            return false;
        }
        *budget -= 1;
        current.push(i);
        if walk(
            amounts,
            suffix,
            target,
            i + 1,
            sum + u128::from(amounts[i]),
            current,
            budget,
        ) {
            return true;
        }
        current.pop();
        walk(amounts, suffix, target, i + 1, sum, current, budget)
    }
    let mut budget = SEARCH_BUDGET;
    let mut current = Vec::new();
    if walk(amounts, &suffix, target, 0, 0, &mut current, &mut budget) {
        Some(current)
    } else {
        None
    }
}

impl Wallet {
    /// Take a [`Handover`] into this wallet, as the service. Returns how many
    /// notes were taken and what they are worth. A note whose secret does not
    /// match its nonce, or that the wallet already holds, is refused and nothing
    /// is taken.
    ///
    /// The mint's signature on a note cannot be checked here. Whether the notes
    /// are good is found out when they are redeemed at the mint.
    pub fn receive_handover(&mut self, handover: &Handover) -> Result<(usize, u128), WalletError> {
        if handover.notes.is_empty() {
            return Err(WalletError::Invalid("the handover holds no notes".into()));
        }
        let terms = StoredTerms {
            service: handover.service,
            redeemable_after_day: handover.redeemable_after_day,
        };
        let mut seen: HashSet<String> = self.notes().iter().map(StoredNote::id).collect();
        let mut incoming = Vec::new();
        let mut keysets = Vec::new();
        let mut units = 0u128;
        for handed in &handover.notes {
            if handed.amount == 0 {
                return Err(WalletError::Invalid("a handed note has amount zero".into()));
            }
            let keypair = Keypair::from_secret_key(SECP256K1, &handed.spend_secret);
            if keypair.public_key() != handed.note.nonce.0 {
                return Err(WalletError::Invalid(
                    "a handed note's spend secret does not match its nonce".into(),
                ));
            }
            let stored = StoredNote {
                kind: Kind::Esp,
                amount: handed.amount,
                note: handed.note,
                spend_secret: handed.spend_secret,
                terms: Some(terms),
                reserved_by: None,
            };
            if !seen.insert(stored.id()) {
                return Err(WalletError::Invalid(format!(
                    "note {} is already in this wallet",
                    stored.id()
                )));
            }
            units += u128::from(stored.amount);
            if handed.keyset.is_empty() {
                return Err(WalletError::Invalid(format!(
                    "note {} in the handover names no keyset; it is refused (ask the sender for a handover that names each note's keyset)",
                    stored.id()
                )));
            }
            keysets.push((stored.id(), handed.keyset.clone()));
            incoming.push(stored);
        }
        let count = incoming.len();
        self.update(|d| {
            d.notes.extend(incoming);
            d.keysets.extend(keysets);
            Ok(())
        })?;
        Ok((count, units))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::PendingOutput;
    use crate::store::HandedNote;
    use std::fs;
    use std::path::PathBuf;

    use secp256k1::SecretKey;
    use sp_wire::ServiceDid;

    /// Open a wallet file of the test network.
    fn open_wallet(path: &std::path::Path) -> Result<crate::Wallet, crate::WalletError> {
        crate::Wallet::open(path, "regtest")
    }

    /// A test amount, a power of two (about $1.10). Every ESP note is one.
    const ONE: u64 = 1 << 40;
    const DAY: u64 = 21_106;

    fn key(n: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        SecretKey::from_slice(&bytes).unwrap()
    }

    /// The service with secret key 1 (the generator: the DID `0279be...`).
    fn service() -> ServiceDid {
        ServiceDid::from(Keypair::from_secret_key(SECP256K1, &key(1)).public_key())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-tr-{}-{name}", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A stored ESP note. The mint's signature is made up, so only selection
    /// and bookkeeping are checked here.
    fn esp_note(amount: u64, service: ServiceDid, day: u64) -> StoredNote {
        let sk = SecretKey::new(&mut rand::rngs::OsRng);
        let out = PendingOutput::new(amount);
        let sig = bdhke::sign_message(&sk, &out.blind_nonce.0);
        StoredNote {
            kind: Kind::Esp,
            amount,
            note: out.unblind(&sig, &sk.public_key(SECP256K1)),
            spend_secret: out.nonce_secret,
            terms: Some(StoredTerms {
                service,
                redeemable_after_day: day,
            }),
            reserved_by: None,
        }
    }

    #[test]
    fn pick_exact_finds_a_set_that_adds_up_and_only_then() {
        let amounts = [5u64, 3, 3, 1];
        let picked = pick_exact(&amounts, 6).unwrap();
        let sum: u64 = picked.iter().map(|&i| amounts[i]).sum();
        assert_eq!(sum, 6);
        assert_eq!(pick_exact(&amounts, 12), Some(vec![0, 1, 2, 3]));
        assert_eq!(pick_exact(&amounts, 13), None);
        assert_eq!(pick_exact(&amounts, 2), None);
        assert_eq!(pick_exact(&amounts, 0), None);
        assert_eq!(pick_exact(&[], 1), None);
        // amounts past one note's size still add up in u128
        let big = [u64::MAX, u64::MAX];
        assert_eq!(pick_exact(&big, 2 * u128::from(u64::MAX)), Some(vec![0, 1]));
        assert_eq!(pick_exact(&big, u128::from(u64::MAX) + 1), None);
    }

    /// What an app would hand to the service: `notes` as a [`Handover`].
    fn handover_of(notes: &[StoredNote], day: u64) -> Handover {
        Handover {
            service: service(),
            redeemable_after_day: day,
            notes: notes
                .iter()
                .map(|n| HandedNote {
                    amount: n.amount,
                    note: n.note,
                    spend_secret: n.spend_secret,
                    keyset: "ab".repeat(8),
                })
                .collect(),
        }
    }

    #[test]
    fn a_service_takes_a_handover_in() {
        let handover = handover_of(
            &[
                esp_note(2 * ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
            ],
            DAY,
        );
        let svc_dir = scratch("svc");
        let mut svc = open_wallet(&svc_dir.join("wallet.json")).unwrap();
        let (count, units) = svc.receive_handover(&handover).unwrap();
        assert_eq!((count, units), (2, 3 * u128::from(ONE)));
        let b = svc.balance();
        assert_eq!((b.esp, b.notes), (3 * u128::from(ONE), 2));
        assert_eq!(
            b.esp_by_terms
                .get(&(hex::encode(service().serialize()), DAY)),
            Some(&(3 * u128::from(ONE)))
        );
        // the same handover again is refused, and changes nothing
        assert!(svc.receive_handover(&handover).is_err());
        assert_eq!(svc.balance(), b);
        fs::remove_dir_all(&svc_dir).unwrap();
    }

    #[test]
    fn a_handover_with_a_secret_that_does_not_match_is_refused() {
        let mut handover = handover_of(&[esp_note(ONE, service(), DAY)], DAY);
        handover.notes[0].spend_secret = key(9);
        let svc_dir = scratch("mismatch-svc");
        let mut svc = open_wallet(&svc_dir.join("wallet.json")).unwrap();
        assert!(matches!(
            svc.receive_handover(&handover),
            Err(WalletError::Invalid(_))
        ));
        assert_eq!(svc.balance().notes, 0);
        handover.notes.clear();
        assert!(svc.receive_handover(&handover).is_err());
        fs::remove_dir_all(&svc_dir).unwrap();
    }
}
