//! Buying PSP with BTC.
//!
//! The wallet has no BTC wallet. The app's own Bitcoin wallet puts the bytes from
//! [`Wallet::build_psp_payload`] in an OP_RETURN and pays the PSP's address. When
//! the PSP settles it hands back one blind signature per output it signed, each
//! with the blind nonce it belongs to. [`Wallet::claim_psp`] turns those into
//! notes.

use std::collections::BTreeMap;

use mint_types::{Amount, BlindNonce};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use sp_wire::payload::{self, Payload};
use sp_wire::seal::PublicKey as DidPublicKey;

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{Kind, PendingPurchase, StoredNote, Wallet};

/// The most outputs in one purchase (the payload's count is one byte).
pub const MAX_OUTPUTS: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurchaseBuild {
    /// Identifies this purchase in the wallet: SHA-256 of `payload`, as hex.
    pub id: String,
    /// The encrypted payload, for the OP_RETURN.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimResult {
    /// The ids of the new notes.
    pub claimed: Vec<String>,
    pub claimed_units: u64,
    /// Outputs still waiting for a signature. The PSP signs fewer outputs than
    /// were asked for when a payment is short by more than 1%.
    pub still_pending: usize,
}

/// Check that `amount` is a PSP denomination: a power of two, and not above the
/// PSP's largest note (`top`, read from its `GET /keys`) when that is known.
/// With `top` unknown the PSP decides how large a note may be.
pub fn check_denomination(amount: u64, top: Option<u64>) -> Result<(), WalletError> {
    if amount == 0 || !amount.is_power_of_two() {
        return Err(WalletError::Invalid(format!(
            "{amount} is not a PSP note size: use a power of two"
        )));
    }
    if let Some(top) = top.filter(|&top| amount > top) {
        return Err(WalletError::Invalid(format!(
            "{amount} is above the PSP's largest note, {top} (its mint.max_denomination_units)"
        )));
    }
    Ok(())
}

impl Wallet {
    /// Blind `outputs` (amounts in PSP, ten to the US dollar), encode the payload
    /// with `reply_did`, and encrypt it to the mint's DID public key with AIR's
    /// secp256k1 encryption. Returns the bytes for an OP_RETURN.
    ///
    /// The blinding factors and spend keys are saved in the wallet before this
    /// returns, so the notes can be claimed whenever the signatures arrive.
    pub fn build_psp_payload(
        &mut self,
        outputs: &[u64],
        reply_did: &[u8; 33],
        mint_did_pubkey: &DidPublicKey,
    ) -> Result<PurchaseBuild, WalletError> {
        if outputs.is_empty() {
            return Err(WalletError::Invalid(
                "a purchase needs at least one output".into(),
            ));
        }
        if outputs.len() > MAX_OUTPUTS {
            return Err(WalletError::Invalid(format!(
                "a purchase holds at most {MAX_OUTPUTS} outputs"
            )));
        }
        let top = self.psp_max_denomination();
        for &amount in outputs {
            check_denomination(amount, top)?;
        }
        let pending: Vec<PendingOutput> = outputs.iter().map(|&a| PendingOutput::new(a)).collect();
        // The payload names the PSP's current keyset as last seen, like every
        // other request, and the PSP signs with it while it is live (else with
        // its current one). The settlement prints the keyset that signed, and
        // the claim is unblinded with that set's keys.
        let plaintext = payload::encode(&Payload {
            keyset: self.psp_output_keyset(),
            did: *reply_did,
            outputs: pending.iter().map(PendingOutput::mint_output).collect(),
        })
        .map_err(|e| WalletError::Invalid(e.to_string()))?;
        let sealed = sp_wire::seal::encrypt(mint_did_pubkey, &plaintext)?;
        let id = hex::encode(Sha256::digest(&sealed));
        let record = PendingPurchase {
            id: id.clone(),
            reply_did: hex::encode(reply_did),
            mint_did_pubkey: mint_did_pubkey.to_string(),
            outputs: pending,
        };
        self.update(|d| {
            d.pending_purchases.push(record);
            Ok(())
        })?;
        Ok(PurchaseBuild {
            id,
            payload: sealed,
        })
    }

    /// The signatures that belong to this wallet's pending outputs, in order. The
    /// PSP's printed output has every payer's signatures in it, and
    /// [`Wallet::claim_psp`] refuses a pair it does not know, so a caller reading
    /// that output filters it with this first. Over the AIR only the payer's own
    /// pairs arrive and this is not needed.
    pub fn ours(&self, signatures: &[(BlindNonce, PublicKey)]) -> Vec<(BlindNonce, PublicKey)> {
        signatures
            .iter()
            .filter(|(blind_nonce, _)| {
                self.pending_purchases()
                    .iter()
                    .any(|p| p.outputs.iter().any(|o| o.blind_nonce == *blind_nonce))
            })
            .copied()
            .collect()
    }

    /// Turn the PSP's signatures into notes. Each is a blind nonce and the blind
    /// signature for it, as the PSP prints them. `keys` is the PSP's public key
    /// for each note size (`GET /keys`).
    ///
    /// All or nothing: if any pair does not match a pending output, or the PSP
    /// has no key for its amount, nothing changes. A signature can be claimed
    /// once, because claiming removes its pending output.
    pub fn claim_psp(
        &mut self,
        signatures: &[(BlindNonce, PublicKey)],
        keys: &BTreeMap<Amount, PublicKey>,
    ) -> Result<ClaimResult, WalletError> {
        if signatures.is_empty() {
            return Err(WalletError::Invalid("no signatures to claim".into()));
        }
        self.update(|d| {
            let mut claimed = Vec::new();
            let mut claimed_units = 0u64;
            for (blind_nonce, signature) in signatures {
                let found = d.pending_purchases.iter().enumerate().find_map(|(p, purchase)| {
                    purchase
                        .outputs
                        .iter()
                        .position(|o| o.blind_nonce == *blind_nonce)
                        .map(|o| (p, o))
                });
                let Some((p, o)) = found else {
                    return Err(WalletError::Unknown(format!(
                        "no pending output has blind nonce {} (already claimed, or not from this wallet)",
                        blind_nonce.0
                    )));
                };
                let output = d.pending_purchases[p].outputs.remove(o);
                let key = keys.get(&Amount::from_units(output.amount)).ok_or_else(|| {
                    WalletError::Mint(format!("the PSP has no key for {} units", output.amount))
                })?;
                let note = StoredNote {
                    kind: Kind::Psp,
                    amount: output.amount,
                    note: output.unblind(signature, key),
                    spend_secret: output.nonce_secret,
                    terms: None,
                    reserved_by: None,
                };
                // The keyset is the one whose keys unblinded the note.
                d.keysets.insert(note.id(), sp_wire::keyset::keyset_id(keys));
                claimed.push(note.id());
                claimed_units = claimed_units
                    .checked_add(output.amount)
                    .ok_or_else(|| WalletError::Invalid("amounts are too large".into()))?;
                d.notes.push(note);
            }
            d.pending_purchases.retain(|p| !p.outputs.is_empty());
            let still_pending = d.pending_purchases.iter().map(|p| p.outputs.len()).sum();
            Ok(ClaimResult {
                claimed,
                claimed_units,
                still_pending,
            })
        })
    }

    /// Forget a purchase that was never paid. Its blinding factors are dropped.
    /// Do not do this once the payment has been sent.
    pub fn discard_purchase(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            let before = d.pending_purchases.len();
            d.pending_purchases.retain(|p| p.id != id);
            if d.pending_purchases.len() == before {
                return Err(WalletError::Unknown(format!("no pending purchase {id}")));
            }
            Ok(())
        })
    }
}

/// The keys to unblind a PSP settlement's signatures with: those of the keyset
/// the PSP printed (`keyset <id>`), read from the PSP's keysets, never assumed to
/// be the current set. Older output names none and was signed with the keys of
/// `GET /keys`. A printed keyset that is no longer live means the outputs
/// expired before they were claimed.
///
/// How the keys and the keysets are read (over AIR) is the
/// caller's: `keys` and `keysets` are called only when needed.
pub fn claim_keys_with(
    settlement_text: &str,
    keys: impl FnOnce() -> Result<BTreeMap<Amount, PublicKey>, WalletError>,
    keysets: impl FnOnce() -> Result<sp_wire::psp::KeysetsResponse, WalletError>,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    match parse_keyset(settlement_text) {
        None => keys(),
        Some(id) => {
            let live = keysets()?;
            let Some(keys) = live.keysets.get(&id) else {
                return Err(WalletError::Mint(format!(
                    "keyset {id}, which signed these, is no longer live at the PSP (it was retired at a rotation): the outputs expired before they were claimed and cannot be claimed now"
                )));
            };
            Ok(keys
                .iter()
                .map(|(u, k)| (Amount::from_units(*u), *k))
                .collect())
        }
    }
}

/// The keyset the PSP printed with its signatures (`keyset <16 hex>`), if
/// any. Output from before keysets were printed has none.
pub fn parse_keyset(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let id = l.trim().strip_prefix("keyset ")?.trim();
        (id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())).then(|| id.to_lowercase())
    })
}

/// Read the signatures the PSP prints. A line is
/// `signature <blind nonce hex> <signature hex>`, and a bare pair
/// `<blind nonce hex> <signature hex>` or `<blind nonce hex>:<signature hex>` is
/// accepted too. Any other line is skipped, so the PSP's whole output can be
/// pasted in. A line that starts with `signature` and is not a pair is an error.
pub fn parse_signatures(text: &str) -> Result<Vec<(BlindNonce, PublicKey)>, WalletError> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let (labelled, rest) = match line.strip_prefix("signature") {
            Some(rest) if rest.is_empty() || rest.starts_with(char::is_whitespace) => (true, rest),
            _ => (false, line),
        };
        let parts: Vec<&str> = rest
            .split(|c: char| c.is_whitespace() || c == ':')
            .filter(|p| !p.is_empty())
            .collect();
        let is_pair = parts.len() == 2 && parts.iter().all(|p| p.len() == 66);
        if !is_pair {
            if labelled {
                return Err(WalletError::Invalid(format!(
                    "expected `signature <blind nonce> <signature>`, got `{line}`"
                )));
            }
            continue;
        }
        let point = |text: &str| -> Result<PublicKey, WalletError> {
            let bytes =
                hex::decode(text).map_err(|_| WalletError::Invalid(format!("not hex: {text}")))?;
            PublicKey::from_slice(&bytes)
                .map_err(|_| WalletError::Invalid(format!("not a curve point: {text}")))
        };
        out.push((BlindNonce(point(parts[0])?), point(parts[1])?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psp_mint::scan::Received;
    use secp256k1::{SECP256K1, SecretKey};
    use sp_wire::seal::SecretKey as DidSecretKey;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn the_printed_keyset_is_read_and_junk_is_not() {
        let text = "payment x\n  keyset 0123456789ABCDEF\n  signature a b\n";
        assert_eq!(parse_keyset(text).as_deref(), Some("0123456789abcdef"));
        assert_eq!(parse_keyset("  keyset zz"), None);
        assert_eq!(parse_keyset("signature only"), None);
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-psp-{}-{name}", {
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

    fn wallet(name: &str) -> (Wallet, PathBuf) {
        let dir = scratch(name);
        (Wallet::open(&dir.join("wallet.json")).unwrap(), dir)
    }

    fn payment(payload: Vec<u8>) -> Received {
        Received {
            txid: "aa".into(),
            confirmations: 6,
            value_sats: 5_000,
            payload: Some(payload),
        }
    }

    const DID: [u8; 33] = [0x02; 33];

    #[test]
    fn build_then_encrypt_then_the_mint_decrypts_and_decodes() {
        let (mut w, dir) = wallet("roundtrip");
        let mint = DidSecretKey::new();
        let built = w
            .build_psp_payload(&[4, 1], &DID, &mint.public_key())
            .unwrap();

        // the mint's side: the scanner opens the data output, then decodes it
        let (kept, dropped) =
            psp_mint::seal::open_payloads(&mint, vec![payment(built.payload.clone())]);
        assert_eq!(dropped, 0);
        let decoded = payload::decode(kept[0].payload.as_deref().unwrap()).unwrap();
        assert_eq!(decoded.did, DID);
        let pending = &w.pending_purchases()[0];
        assert_eq!(decoded.outputs.len(), 2);
        assert_eq!(decoded.outputs[0].amount, Amount::from_units(4));
        assert_eq!(decoded.outputs[1].amount, Amount::from_units(1));
        for (sent, held) in decoded.outputs.iter().zip(&pending.outputs) {
            assert_eq!(sent.blind_nonce, held.blind_nonce);
        }
        assert_eq!(built.id, hex::encode(Sha256::digest(&built.payload)));
        assert_eq!(pending.id, built.id);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_purchase_names_the_psp_keyset_the_wallet_last_saw() {
        let (mut w, dir) = wallet("names-keyset");
        let mint = DidSecretKey::new();
        let keyset_of = |w: &mut Wallet| {
            let built = w.build_psp_payload(&[1], &DID, &mint.public_key()).unwrap();
            let (kept, _) = psp_mint::seal::open_payloads(&mint, vec![payment(built.payload)]);
            payload::decode(kept[0].payload.as_deref().unwrap())
                .unwrap()
                .keyset
        };
        assert_eq!(keyset_of(&mut w), None, "none seen yet");
        let named = "ab".repeat(8);
        w.update(|d| {
            d.live_keysets
                .insert("http://psp".to_string(), (named.clone(), None));
            Ok(())
        })
        .unwrap();
        assert_eq!(keyset_of(&mut w), Some(named));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_payload_is_80_bytes_longer_than_plaintext_and_hides_the_did() {
        let (mut w, dir) = wallet("size");
        let mint = DidSecretKey::new();
        let built = w
            .build_psp_payload(&[4, 1], &DID, &mint.public_key())
            .unwrap();
        assert_eq!(built.payload.len(), 35 + 41 * 2 + sp_wire::seal::OVERHEAD);
        assert!(!built.payload.windows(33).any(|win| win == DID));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_payload_encrypted_to_another_key_is_ignored_by_the_mint() {
        let (mut w, dir) = wallet("other-key");
        let mint = DidSecretKey::new();
        let other = DidSecretKey::new();
        let built = w
            .build_psp_payload(&[2], &DID, &other.public_key())
            .unwrap();
        let (kept, dropped) = psp_mint::seal::open_payloads(&mint, vec![payment(built.payload)]);
        assert!(kept.is_empty());
        assert_eq!(dropped, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tampered_payload_is_rejected_by_the_mint() {
        let (mut w, dir) = wallet("tamper");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[2], &DID, &mint.public_key()).unwrap();
        for i in [1usize, 40, built.payload.len() - 1] {
            let mut bad = built.payload.clone();
            bad[i] ^= 0x01;
            assert!(psp_mint::seal::decrypt(&mint, &bad).is_err(), "byte {i}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_purchase_is_saved_before_the_bytes_are_returned() {
        let (mut w, dir) = wallet("saved");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[8], &DID, &mint.public_key()).unwrap();
        let reopened = Wallet::open(w.path()).unwrap();
        assert_eq!(reopened.pending_purchases().len(), 1);
        assert_eq!(reopened.pending_purchases()[0].id, built.id);
        assert_eq!(reopened.pending_purchases()[0].outputs[0].amount, 8);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_psp_note_sizes_are_accepted() {
        let (mut w, dir) = wallet("sizes");
        let mint = DidSecretKey::new();
        let key = mint.public_key();
        for bad in [0u64, 3, 5, 6, 16_777_217, u64::MAX] {
            assert!(w.build_psp_payload(&[bad], &DID, &key).is_err(), "{bad}");
        }
        assert!(w.build_psp_payload(&[], &DID, &key).is_err());
        assert!(w.build_psp_payload(&vec![1; 256], &DID, &key).is_err());
        assert!(w.pending_purchases().is_empty());
        for good in [1u64, 2, 4, 1024, 1_048_576, 16_777_216, 33_554_432] {
            assert!(w.build_psp_payload(&[good], &DID, &key).is_ok(), "{good}");
        }
        assert!(w.build_psp_payload(&vec![1; 255], &DID, &key).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_largest_note_is_the_one_the_psp_says() {
        let (mut w, dir) = wallet("top");
        let mint = DidSecretKey::new();
        let key = mint.public_key();
        // unknown: only the power of two is checked here, the PSP decides the top
        assert_eq!(w.psp_max_denomination(), None);
        assert!(w.build_psp_payload(&[1 << 26], &DID, &key).is_ok());
        // a PSP whose largest note is 1024
        w.set_psp_max_denomination(Some(1024));
        assert!(w.build_psp_payload(&[1024], &DID, &key).is_ok());
        let e = w.build_psp_payload(&[2048], &DID, &key).unwrap_err();
        assert!(e.to_string().contains("largest note, 1024"), "{e}");
        // a PSP that was configured for bigger notes
        w.set_psp_max_denomination(Some(1 << 27));
        assert!(w.build_psp_payload(&[1 << 27], &DID, &key).is_ok());
        assert!(w.build_psp_payload(&[1 << 28], &DID, &key).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A PSP's keys, and what it does when it settles: sign each output.
    fn sign_all(w: &Wallet, sks: &BTreeMap<Amount, SecretKey>) -> Vec<(BlindNonce, PublicKey)> {
        w.pending_purchases()
            .iter()
            .flat_map(|p| &p.outputs)
            .map(|o| {
                let sk = &sks[&Amount::from_units(o.amount)];
                (o.blind_nonce, bdhke::sign_message(sk, &o.blind_nonce.0))
            })
            .collect()
    }

    fn psp_keys() -> (BTreeMap<Amount, SecretKey>, BTreeMap<Amount, PublicKey>) {
        let sks: BTreeMap<Amount, SecretKey> = [1u64, 2, 4, 8]
            .iter()
            .map(|&a| {
                (
                    Amount::from_units(a),
                    SecretKey::new(&mut rand::rngs::OsRng),
                )
            })
            .collect();
        let pks = sks
            .iter()
            .map(|(a, sk)| (*a, sk.public_key(SECP256K1)))
            .collect();
        (sks, pks)
    }

    #[test]
    fn claimed_signatures_become_notes_the_psp_accepts_and_the_purchase_is_cleared() {
        let (mut w, dir) = wallet("claim");
        let mint = DidSecretKey::new();
        w.build_psp_payload(&[4, 1], &DID, &mint.public_key())
            .unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);

        let result = w.claim_psp(&sigs, &pks).unwrap();
        assert_eq!(result.claimed.len(), 2);
        assert_eq!(result.claimed_units, 5);
        assert_eq!(result.still_pending, 0);
        assert!(w.pending_purchases().is_empty());
        assert_eq!(w.balance().psp, 5);
        for n in w.notes() {
            assert_eq!(n.kind, Kind::Psp);
            let sk = &sks[&Amount::from_units(n.amount)];
            assert!(bdhke::verify_message(
                sk,
                n.note.signature,
                &n.note.nonce.as_hash_preimage()
            ));
        }
        // and the held spend key is the note's nonce key
        let again = Wallet::open(w.path()).unwrap();
        assert_eq!(again.notes().len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ours_keeps_only_signatures_for_pending_outputs() {
        let (mut w, dir) = wallet("ours");
        let mint = DidSecretKey::new();
        w.build_psp_payload(&[4, 1], &DID, &mint.public_key())
            .unwrap();
        let (sks, _) = psp_keys();
        let all = sign_all(&w, &sks);
        let stranger = (BlindNonce(all[0].1), all[0].1);
        let mixed = vec![stranger, all[0], all[1]];
        assert_eq!(w.ours(&mixed), vec![all[0], all[1]]);
        assert!(w.ours(&[stranger]).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_partial_claim_leaves_the_rest_pending() {
        let (mut w, dir) = wallet("partial");
        let mint = DidSecretKey::new();
        w.build_psp_payload(&[4, 1], &DID, &mint.public_key())
            .unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        // the PSP signed only the 4
        let result = w.claim_psp(&all[..1], &pks).unwrap();
        assert_eq!(result.claimed_units, 4);
        assert_eq!(result.still_pending, 1);
        assert_eq!(w.pending_purchases().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_signature_cannot_be_claimed_twice_and_a_bad_claim_changes_nothing() {
        let (mut w, dir) = wallet("twice");
        let mint = DidSecretKey::new();
        w.build_psp_payload(&[4, 1], &DID, &mint.public_key())
            .unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        w.claim_psp(&all[..1], &pks).unwrap();
        // the same pair again, and a stranger's
        assert!(matches!(
            w.claim_psp(&all[..1], &pks),
            Err(WalletError::Unknown(_))
        ));
        let stranger = (
            BlindNonce(SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1)),
            all[1].1,
        );
        assert!(matches!(
            w.claim_psp(&[stranger], &pks),
            Err(WalletError::Unknown(_))
        ));
        // a valid pair after an invalid one: nothing is claimed
        assert!(w.claim_psp(&[stranger, all[1]], &pks).is_err());
        assert_eq!(w.balance().psp, 4);
        assert_eq!(w.pending_purchases()[0].outputs.len(), 1);
        // a missing key for an amount is an error and changes nothing
        let mut no_keys = pks.clone();
        no_keys.remove(&Amount::from_units(1));
        assert!(matches!(
            w.claim_psp(&all[1..], &no_keys),
            Err(WalletError::Mint(_))
        ));
        assert_eq!(w.pending_purchases()[0].outputs.len(), 1);
        assert!(w.claim_psp(&[], &pks).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_purchase_can_be_discarded_before_it_is_paid() {
        let (mut w, dir) = wallet("discard");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[1], &DID, &mint.public_key()).unwrap();
        assert!(w.discard_purchase("nope").is_err());
        w.discard_purchase(&built.id).unwrap();
        assert!(w.pending_purchases().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signature_lines_parse_from_the_psp_output() {
        let a = SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1);
        let b = SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1);
        let c = SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1);
        let d = SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1);
        let text = format!(
            "abc confirmations=6 value_sats=5000\n  over/under: 0 bps\n  signature {a} {b}\n  signature {c} {d}\n"
        );
        let pairs = parse_signatures(&text).unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], (BlindNonce(a), b));
        assert_eq!(pairs[1], (BlindNonce(c), d));
        // bare pairs, with a space or a colon
        let bare = parse_signatures(&format!("{a} {b}\n{c}:{d}")).unwrap();
        assert_eq!(bare, pairs);
        // nothing to find is not an error here
        assert!(parse_signatures("no signatures\n").unwrap().is_empty());
        // a labelled line that is not a pair is an error
        assert!(parse_signatures(&format!("signature {a}")).is_err());
        assert!(parse_signatures("signature zz zz").is_err());
    }
}
