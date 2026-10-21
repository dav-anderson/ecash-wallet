//! Buying PSP with BTC.
//!
//! The wallet has no BTC wallet. The app's own Bitcoin wallet puts the bytes from
//! [`Wallet::build_psp_payload`] in an OP_RETURN and pays the PSP's address. The
//! PSP then delivers the purchase on its own: when it handles the payment, it
//! writes one record on the SPI's AIR server, at an address the wallet computes
//! (`sp_wire::air_request::delivery`). The record is the blind signature of each
//! output it signed and the keysets to unblind them with, or it says the payment
//! is held, or the purchase was rejected, with the reason and what was paid.
//! [`crate::mint_info::psp_pickup`] reads those records and
//! [`Wallet::apply_delivery`] turns one into notes. There is nothing to paste.
//!
//! **A key for each purchase.** The payload names a reply DID, and the PSP seals
//! the record to it. [`Wallet::build_psp_payload`] makes a fresh one-off key for
//! each purchase and saves its secret with the pending purchase, so the PSP
//! cannot link two purchases of one wallet. The secret is deleted when the
//! purchase is reconciled: when its signatures are claimed and the PSP owes
//! nothing and every output is accounted for, or when the PSP's reconciliation
//! window closes ([`Wallet::close_expired`]).
//!
//! **A held or rejected payment stays open.** The PSP has the bitcoin and signed
//! nothing, so the purchase and its key are kept ([`Delivered::Open`]) for the
//! window the record names (`open_until`; 7 days by default at the PSP). The
//! corrected request or credit that would settle it is not designed yet. If it is
//! not settled by `open_until` the PSP forfeits the payment, and the wallet
//! deletes the purchase and the key. A purchase the PSP says it owes a credit on
//! also keeps its key, in [`OpenReply`], until the same time. The key is never
//! part of a handoff: a purchase has no notes until it settles.

use std::collections::BTreeMap;

use mint_types::{Amount, BlindNonce};
use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use sp_wire::air_request::addr;
use sp_wire::air_request::delivery::{self, Outcome, Signed};
use sp_wire::payload::{self, Payload};
use sp_wire::seal::{PublicKey as DidPublicKey, SecretKey as DidSecretKey};

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{
    Kind, OPEN_KEY_FALLBACK_SECS, OpenKind, OpenPurchase, OpenReply, PendingPurchase, StoredNote,
    Wallet,
};

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
    /// Outputs of other purchases still waiting for a signature.
    pub still_pending: usize,
}

/// What a purchase's record said, once it was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub claim: ClaimResult,
    /// Requested units the PSP did not sign because the payment was short. It
    /// keeps their value.
    pub skipped_units: u64,
    /// What the PSP owes the payer for an overpayment, in USD cents.
    pub credit_cents: u64,
    /// Requested units that were neither signed nor reported as dropped.
    pub unaccounted_units: u64,
    /// True when the purchase's key was kept because the purchase may still be
    /// open (a credit is owed, or outputs are unaccounted for).
    pub key_kept: bool,
}

/// What applying one purchase's record did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivered {
    /// The signatures were claimed and the purchase cleared.
    Claimed(Claimed),
    /// The PSP holds the payment, or rejected the purchase: nothing was signed.
    /// The purchase and its key are kept open until `open_until` (see
    /// [`Wallet::close_expired`]) or until the PSP settles it. The bitcoin that
    /// was paid stays with the PSP; if the purchase is not settled by then, the
    /// PSP forfeits it.
    Open(OpenPurchase),
    /// Nothing changed: the purchase is not pending (its record was applied
    /// before), or it is open already with this very record.
    AlreadyDone,
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

/// The end of a purchase's window from a record: the PSP's when it names one,
/// else the wallet's own ([`OPEN_KEY_FALLBACK_SECS`] from now), so a record with
/// none never closes a purchase at once.
fn window(open_until: u64) -> u64 {
    if open_until > 0 {
        open_until
    } else {
        addr::now_secs().saturating_add(OPEN_KEY_FALLBACK_SECS)
    }
}

/// A curve point written as 66 hex characters (a blind nonce or a signature).
fn point(text: &str) -> Result<PublicKey, WalletError> {
    let bytes = hex::decode(text).map_err(|_| WalletError::Invalid(format!("not hex: {text}")))?;
    PublicKey::from_slice(&bytes)
        .map_err(|_| WalletError::Invalid(format!("not a curve point: {text}")))
}

/// The keys of the keyset that signed, from the record. They must be the keys the
/// keyset's id names, or the record is not to be trusted with the notes.
fn keys_of(signed: &Signed) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let Some(keys) = signed.keysets.keysets.get(&signed.keyset) else {
        return Err(WalletError::Mint(format!(
            "the PSP's record does not carry the keys of keyset {}, which signed",
            signed.keyset
        )));
    };
    let keys: BTreeMap<Amount, PublicKey> = keys
        .iter()
        .map(|(units, key)| (Amount::from_units(*units), *key))
        .collect();
    if sp_wire::keyset::keyset_id(&keys) != signed.keyset {
        return Err(WalletError::Mint(format!(
            "the keys in the PSP's record are not those of keyset {}",
            signed.keyset
        )));
    }
    Ok(keys)
}

impl Wallet {
    /// Blind `outputs` (amounts in PSP, ten to the US dollar), make this
    /// purchase's own one-off reply key, encode the payload with its public half
    /// as the reply DID, and encrypt it to the mint's DID public key with AIR's
    /// secp256k1 encryption. Returns the bytes for an OP_RETURN.
    ///
    /// The blinding factors, the spend keys and the reply key's secret are saved
    /// in the wallet before this returns, so the notes can be claimed whenever
    /// the PSP delivers them, and the key is on disk before any payment is made.
    pub fn build_psp_payload(
        &mut self,
        outputs: &[u64],
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
        let reply_key = DidSecretKey::new();
        let reply_did = addr::key_to_bytes(&reply_key.public_key());
        // The payload names the PSP's current keyset as last seen, like every
        // other request, and the PSP signs with it while it is live (else with
        // its current one). The record carries the keyset that signed and its
        // keys.
        let plaintext = payload::encode(&Payload {
            keyset: self.psp_output_keyset(),
            did: reply_did,
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
            reply_secret: Some(addr::secret_to_hex(&reply_key)),
            delivery_id: Some(hex::encode(delivery::purchase_id(&plaintext))),
            open: None,
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

    /// Apply the PSP's record for the pending purchase `purchase_id` (its `id`),
    /// which has been opened and checked (`delivery::open_record`).
    ///
    /// - **Signed.** Each pair is unblinded with the keys of the keyset that
    ///   signed, which the record carries (they must be the keys that keyset's id
    ///   names), and becomes a note. All or nothing: a pair that matches no
    ///   pending output, or an amount the keyset has no key for, changes nothing.
    ///   The purchase is cleared. Its key is deleted with it unless the purchase
    ///   may still be open: the PSP owes a credit, or some output was neither
    ///   signed nor reported as dropped. Then the key is kept in `open_replies`
    ///   until the record's `open_until` (or, with none named, a week from now),
    ///   because the PSP will write a follow-up sealed to it.
    /// - **Held or Refused.** The purchase and its key are kept, marked open with
    ///   what the PSP said ([`Delivered::Open`]). Nothing is cleared until the
    ///   PSP settles it or `open_until` passes ([`Wallet::close_expired`]).
    /// - A purchase that is not pending (this record was applied before) is
    ///   [`Delivered::AlreadyDone`], and nothing is written. So is an open
    ///   purchase given the same held or refused record again.
    pub fn apply_delivery(
        &mut self,
        purchase_id: &str,
        outcome: &Outcome,
    ) -> Result<Delivered, WalletError> {
        let Some(current) = self
            .pending_purchases()
            .iter()
            .find(|p| p.id == purchase_id)
        else {
            return Ok(Delivered::AlreadyDone);
        };
        let open = match outcome {
            Outcome::Signed(_) => None,
            Outcome::Refused(r) => Some(OpenPurchase {
                kind: OpenKind::Rejected,
                reason: r.reason.clone(),
                paid_sats: r.paid_sats,
                paid_cents: r.paid_cents,
                requested_units: 0,
                over_under_bps: 0,
                open_until: window(r.open_until),
            }),
            Outcome::Held(h) => Some(OpenPurchase {
                kind: OpenKind::Held,
                reason: h.reason.clone(),
                paid_sats: h.paid_sats,
                paid_cents: h.paid_cents,
                requested_units: h.requested_units,
                over_under_bps: h.over_under_bps,
                open_until: window(h.open_until),
            }),
        };
        if let Some(open) = open {
            if current.open.as_ref() == Some(&open) {
                return Ok(Delivered::AlreadyDone);
            }
            let kept = open.clone();
            self.update(|d| {
                if let Some(p) = d.pending_purchases.iter_mut().find(|p| p.id == purchase_id) {
                    p.open = Some(open);
                }
                Ok(())
            })?;
            return Ok(Delivered::Open(kept));
        }
        let Outcome::Signed(signed) = outcome else {
            unreachable!("the other outcomes returned above");
        };
        let keys = keys_of(signed)?;
        self.update(|d| {
            let at = d
                .pending_purchases
                .iter()
                .position(|p| p.id == purchase_id)
                .ok_or_else(|| {
                    WalletError::Unknown(format!("no pending purchase {purchase_id}"))
                })?;
            let mut claimed = Vec::new();
            let mut claimed_units = 0u64;
            for pair in &signed.signatures {
                let blind_nonce = BlindNonce(point(&pair.blind_nonce)?);
                let signature = point(&pair.signature)?;
                let found = d.pending_purchases[at]
                    .outputs
                    .iter()
                    .position(|o| o.blind_nonce == blind_nonce);
                let Some(o) = found else {
                    return Err(WalletError::Unknown(format!(
                        "no pending output of purchase {purchase_id} has blind nonce {}",
                        blind_nonce.0
                    )));
                };
                let output = d.pending_purchases[at].outputs.remove(o);
                let key = keys
                    .get(&Amount::from_units(output.amount))
                    .ok_or_else(|| {
                        WalletError::Mint(format!("the PSP has no key for {} units", output.amount))
                    })?;
                let note = StoredNote {
                    kind: Kind::Psp,
                    amount: output.amount,
                    note: output.unblind(&signature, key),
                    spend_secret: output.nonce_secret,
                    terms: None,
                    reserved_by: None,
                };
                // The keyset is the one whose keys unblinded the note.
                d.keysets.insert(note.id(), signed.keyset.clone());
                claimed.push(note.id());
                claimed_units = claimed_units
                    .checked_add(output.amount)
                    .ok_or_else(|| WalletError::Invalid("amounts are too large".into()))?;
                d.notes.push(note);
            }
            let purchase = d.pending_purchases.remove(at);
            // What was asked for and not signed must be what the PSP says it
            // dropped. A difference either way means the purchase may not be
            // closed, so its key is kept.
            let left: u64 = purchase.outputs.iter().map(|o| o.amount).sum();
            let unaccounted_units = left.abs_diff(signed.skipped_units);
            let key_kept = signed.credit_cents > 0 || unaccounted_units > 0;
            if key_kept {
                if let (Some(reply_secret), Some(delivery_id)) =
                    (purchase.reply_secret, purchase.delivery_id)
                {
                    // The PSP's window for a credit; else the wallet's own.
                    let open_until = window(signed.open_until);
                    d.open_replies.push(OpenReply {
                        id: purchase.id,
                        delivery_id,
                        mint_did_pubkey: purchase.mint_did_pubkey,
                        reply_secret,
                        credit_cents: signed.credit_cents,
                        unaccounted_units,
                        open_until,
                    });
                }
            }
            let still_pending = d.pending_purchases.iter().map(|p| p.outputs.len()).sum();
            Ok(Delivered::Claimed(Claimed {
                claim: ClaimResult {
                    claimed,
                    claimed_units,
                    still_pending,
                },
                skipped_units: signed.skipped_units,
                credit_cents: signed.credit_cents,
                unaccounted_units,
                key_kept,
            }))
        })
    }

    /// Delete what a closed reconciliation window leaves behind: every open
    /// purchase (held or rejected) whose `open_until` is `now` or earlier, with
    /// its blinding factors and reply key, and every kept reply key whose
    /// `open_until` has passed. The PSP forfeits a payment that is still open at
    /// its `open_until`, so nothing can arrive for these any more. The window is
    /// the PSP's, read from its record, and `now` is this wallet's clock.
    ///
    /// Nothing is written when nothing is closed. A kept key from a file from
    /// before windows (`open_until` 0) is given the wallet's own fallback instead
    /// of being deleted. Returns the ids that were closed.
    pub fn close_expired(&mut self, now: u64) -> Result<Vec<String>, WalletError> {
        let due = |p: &PendingPurchase| p.open.as_ref().is_some_and(|o| o.open_until <= now);
        let unstamped = |r: &OpenReply| r.open_until == 0;
        let expired = |r: &OpenReply| r.open_until != 0 && r.open_until <= now;
        let d = self.data();
        let nothing = !d.pending_purchases.iter().any(due)
            && !d.open_replies.iter().any(|r| unstamped(r) || expired(r));
        if nothing {
            return Ok(Vec::new());
        }
        self.update(|d| {
            let mut closed: Vec<String> = d
                .pending_purchases
                .iter()
                .filter(|p| due(p))
                .map(|p| p.id.clone())
                .collect();
            d.pending_purchases.retain(|p| !due(p));
            closed.extend(
                d.open_replies
                    .iter()
                    .filter(|r| expired(r))
                    .map(|r| r.id.clone()),
            );
            d.open_replies.retain(|r| !expired(r));
            for r in d.open_replies.iter_mut().filter(|r| unstamped(r)) {
                r.open_until = now.saturating_add(OPEN_KEY_FALLBACK_SECS);
            }
            Ok(closed)
        })
    }

    /// Forget a purchase that was never paid. Its blinding factors and its reply
    /// key are dropped. Do not do this once the payment has been sent.
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

#[cfg(test)]
mod tests {
    use super::*;
    use psp_mint::scan::Received;
    use secp256k1::{SECP256K1, SecretKey};
    use sp_wire::air_request::delivery::{Held, Refused, SignedOutput};
    use sp_wire::psp::KeysetsResponse;
    use sp_wire::seal::SecretKey as DidSecretKey;
    use std::fs;
    use std::path::PathBuf;

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

    #[test]
    fn build_then_encrypt_then_the_mint_decrypts_and_decodes() {
        let (mut w, dir) = wallet("roundtrip");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();

        // the mint's side: the scanner opens the data output, then decodes it
        let (kept, dropped) =
            psp_mint::seal::open_payloads(&mint, vec![payment(built.payload.clone())]);
        assert_eq!(dropped, 0);
        let plaintext = kept[0].payload.clone().unwrap();
        let decoded = payload::decode(&plaintext).unwrap();
        let pending = &w.pending_purchases()[0];
        // the payload names the purchase's own reply DID, whose secret the wallet kept
        assert_eq!(hex::encode(decoded.did), pending.reply_did);
        let secret = addr::secret_from_hex(pending.reply_secret.as_deref().unwrap()).unwrap();
        assert_eq!(addr::key_to_bytes(&secret.public_key()), decoded.did);
        assert_eq!(
            pending.delivery_id.as_deref(),
            Some(hex::encode(delivery::purchase_id(&plaintext)).as_str())
        );
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
            let built = w.build_psp_payload(&[1], &mint.public_key()).unwrap();
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
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        assert_eq!(built.payload.len(), 35 + 41 * 2 + sp_wire::seal::OVERHEAD);
        let did = hex::decode(&w.pending_purchases()[0].reply_did).unwrap();
        assert!(!built.payload.windows(33).any(|win| win == did.as_slice()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_payload_encrypted_to_another_key_is_ignored_by_the_mint() {
        let (mut w, dir) = wallet("other-key");
        let mint = DidSecretKey::new();
        let other = DidSecretKey::new();
        let built = w.build_psp_payload(&[2], &other.public_key()).unwrap();
        let (kept, dropped) = psp_mint::seal::open_payloads(&mint, vec![payment(built.payload)]);
        assert!(kept.is_empty());
        assert_eq!(dropped, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tampered_payload_is_rejected_by_the_mint() {
        let (mut w, dir) = wallet("tamper");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[2], &mint.public_key()).unwrap();
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
        let built = w.build_psp_payload(&[8], &mint.public_key()).unwrap();
        let reopened = Wallet::open(w.path()).unwrap();
        assert_eq!(reopened.pending_purchases().len(), 1);
        assert_eq!(reopened.pending_purchases()[0].id, built.id);
        assert_eq!(reopened.pending_purchases()[0].outputs[0].amount, 8);
        // the reply key's secret is on disk too, before any payment is made
        assert!(reopened.pending_purchases()[0].reply_secret.is_some());
        assert!(reopened.pending_purchases()[0].delivery_id.is_some());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_psp_note_sizes_are_accepted() {
        let (mut w, dir) = wallet("sizes");
        let mint = DidSecretKey::new();
        let key = mint.public_key();
        for bad in [0u64, 3, 5, 6, 16_777_217, u64::MAX] {
            assert!(w.build_psp_payload(&[bad], &key).is_err(), "{bad}");
        }
        assert!(w.build_psp_payload(&[], &key).is_err());
        assert!(w.build_psp_payload(&vec![1; 256], &key).is_err());
        assert!(w.pending_purchases().is_empty());
        for good in [1u64, 2, 4, 1024, 1_048_576, 16_777_216, 33_554_432] {
            assert!(w.build_psp_payload(&[good], &key).is_ok(), "{good}");
        }
        assert!(w.build_psp_payload(&vec![1; 255], &key).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_largest_note_is_the_one_the_psp_says() {
        let (mut w, dir) = wallet("top");
        let mint = DidSecretKey::new();
        let key = mint.public_key();
        // unknown: only the power of two is checked here, the PSP decides the top
        assert_eq!(w.psp_max_denomination(), None);
        assert!(w.build_psp_payload(&[1 << 26], &key).is_ok());
        // a PSP whose largest note is 1024
        w.set_psp_max_denomination(Some(1024));
        assert!(w.build_psp_payload(&[1024], &key).is_ok());
        let e = w.build_psp_payload(&[2048], &key).unwrap_err();
        assert!(e.to_string().contains("largest note, 1024"), "{e}");
        // a PSP that was configured for bigger notes
        w.set_psp_max_denomination(Some(1 << 27));
        assert!(w.build_psp_payload(&[1 << 27], &key).is_ok());
        assert!(w.build_psp_payload(&[1 << 28], &key).is_err());
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

    /// The record a PSP writes after signing `pairs` with the keys `pks`.
    fn record(
        pairs: &[(BlindNonce, PublicKey)],
        pks: &BTreeMap<Amount, PublicKey>,
        skipped_units: u64,
        credit_cents: u64,
    ) -> Outcome {
        let id = sp_wire::keyset::keyset_id(pks);
        let mut keysets = BTreeMap::new();
        keysets.insert(id.clone(), pks.iter().map(|(a, k)| (a.units, *k)).collect());
        Outcome::Signed(Signed {
            keyset: id.clone(),
            signatures: pairs
                .iter()
                .map(|(blind_nonce, signature)| SignedOutput {
                    blind_nonce: blind_nonce.0.to_string(),
                    signature: signature.to_string(),
                })
                .collect(),
            keysets: KeysetsResponse {
                current: id,
                previous: None,
                keysets,
            },
            skipped_units,
            credit_cents,
            open_until: 0,
        })
    }

    /// A signed record with the PSP's reconciliation window set.
    fn windowed(outcome: Outcome, open_until: u64) -> Outcome {
        let Outcome::Signed(mut signed) = outcome else {
            unreachable!()
        };
        signed.open_until = open_until;
        Outcome::Signed(signed)
    }

    fn claimed(delivered: Delivered) -> Claimed {
        match delivered {
            Delivered::Claimed(c) => c,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn each_purchase_has_a_key_of_its_own() {
        let (mut w, dir) = wallet("own-key");
        let mint = DidSecretKey::new();
        w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        let [a, b] = w.pending_purchases() else {
            panic!("two purchases");
        };
        assert_ne!(a.reply_did, b.reply_did, "the PSP cannot link them");
        assert_ne!(a.reply_secret, b.reply_secret);
        assert_ne!(a.delivery_id, b.delivery_id);
        for p in [a, b] {
            let secret = addr::secret_from_hex(p.reply_secret.as_deref().unwrap()).unwrap();
            assert_eq!(
                hex::encode(addr::key_to_bytes(&secret.public_key())),
                p.reply_did
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn claimed_signatures_become_notes_the_psp_accepts_and_the_purchase_and_its_key_are_cleared() {
        let (mut w, dir) = wallet("claim");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);

        let c = claimed(
            w.apply_delivery(&built.id, &record(&sigs, &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed.len(), 2);
        assert_eq!(c.claim.claimed_units, 5);
        assert_eq!(c.claim.still_pending, 0);
        assert!(!c.key_kept);
        assert!(w.pending_purchases().is_empty());
        assert!(w.open_replies().is_empty(), "nothing is outstanding");
        assert_eq!(w.balance().psp, 5);
        for n in w.notes() {
            assert_eq!(n.kind, Kind::Psp);
            let sk = &sks[&Amount::from_units(n.amount)];
            assert!(bdhke::verify_message(
                sk,
                n.note.signature,
                &n.note.nonce.as_hash_preimage()
            ));
            // the keyset that unblinded it is recorded
            assert_eq!(
                w.data().keysets.get(&n.id()).map(String::as_str),
                Some(sp_wire::keyset::keyset_id(&pks).as_str())
            );
        }
        let again = Wallet::open(w.path()).unwrap();
        assert_eq!(again.notes().len(), 2);
        assert!(again.pending_purchases().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_short_payment_closes_the_purchase_when_the_psp_reports_what_it_dropped() {
        let (mut w, dir) = wallet("partial");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        // the PSP signed only the 4 and kept the value of the 1
        let c = claimed(
            w.apply_delivery(&built.id, &record(&all[..1], &pks, 1, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 4);
        assert_eq!((c.skipped_units, c.unaccounted_units), (1, 0));
        assert!(!c.key_kept);
        assert!(w.pending_purchases().is_empty());
        assert!(w.open_replies().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_credit_keeps_the_key_for_the_follow_up() {
        let (mut w, dir) = wallet("credit");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let secret = w.pending_purchases()[0].reply_secret.clone().unwrap();
        let delivery_id = w.pending_purchases()[0].delivery_id.clone().unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let c = claimed(
            w.apply_delivery(&built.id, &record(&sigs, &pks, 0, 10))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 5);
        assert_eq!(c.credit_cents, 10);
        assert!(c.key_kept);
        assert!(w.pending_purchases().is_empty(), "the notes are claimed");
        let kept = Wallet::open(w.path()).unwrap().open_replies().to_vec();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, built.id);
        assert_eq!(kept[0].delivery_id, delivery_id);
        assert_eq!(kept[0].reply_secret, secret);
        assert_eq!(kept[0].credit_cents, 10);
        // the record named no window, so the wallet's own is used
        let now = addr::now_secs();
        assert!(kept[0].open_until >= now + OPEN_KEY_FALLBACK_SECS - 60);
        assert!(kept[0].open_until <= now + OPEN_KEY_FALLBACK_SECS + 60);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_credit_keeps_the_key_until_the_window_the_record_names() {
        let (mut w, dir) = wallet("credit-window");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let outcome = windowed(record(&sigs, &pks, 0, 10), 1_800_000_000);
        w.apply_delivery(&built.id, &outcome).unwrap();
        assert_eq!(w.open_replies()[0].open_until, 1_800_000_000);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn outputs_neither_signed_nor_reported_dropped_keep_the_key() {
        let (mut w, dir) = wallet("unaccounted");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        // one output has no signature and the PSP does not say it dropped it
        let c = claimed(
            w.apply_delivery(&built.id, &record(&all[..1], &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.unaccounted_units, 1);
        assert!(c.key_kept);
        assert_eq!(w.open_replies()[0].unaccounted_units, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn applying_the_same_record_twice_changes_nothing() {
        let (mut w, dir) = wallet("twice");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let outcome = record(&sigs, &pks, 0, 10);
        w.apply_delivery(&built.id, &outcome).unwrap();
        let (version, notes, kept) = (w.version(), w.notes().len(), w.open_replies().len());
        assert_eq!(
            w.apply_delivery(&built.id, &outcome).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(
            w.apply_delivery("not a purchase", &outcome).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(w.version(), version, "nothing was written");
        assert_eq!((w.notes().len(), w.open_replies().len()), (notes, kept));
        assert_eq!(w.balance().psp, 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn rejected(open_until: u64) -> Outcome {
        Outcome::Refused(Refused {
            reason: "a blind nonce in the request was already signed".to_string(),
            paid_sats: 5_000,
            paid_cents: 50,
            open_until,
        })
    }

    fn held(open_until: u64) -> Outcome {
        Outcome::Held(Held {
            reason: "the payment is short".to_string(),
            paid_sats: 1_000,
            paid_cents: 10,
            requested_units: 5,
            over_under_bps: -8_000,
            open_until,
        })
    }

    fn open_of(delivered: Delivered) -> OpenPurchase {
        match delivered {
            Delivered::Open(o) => o,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_rejection_keeps_the_purchase_and_its_key_open_with_what_was_paid() {
        let (mut w, dir) = wallet("rejected");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let secret = w.pending_purchases()[0].reply_secret.clone();
        let outcome = rejected(1_800_000_000);
        let open = open_of(w.apply_delivery(&built.id, &outcome).unwrap());
        assert_eq!(open.kind, OpenKind::Rejected);
        assert_eq!(
            open.reason,
            "a blind nonce in the request was already signed"
        );
        assert_eq!((open.paid_sats, open.paid_cents), (5_000, 50));
        assert_eq!(open.open_until, 1_800_000_000);
        // kept, with the same key, marked open; no notes
        let [p] = w.pending_purchases() else {
            panic!("the purchase is kept");
        };
        assert_eq!(p.open.as_ref(), Some(&open));
        assert_eq!(p.reply_secret, secret);
        assert_eq!(p.outputs.len(), 2);
        assert!(w.notes().is_empty() && w.open_replies().is_empty());
        // saved
        assert_eq!(
            Wallet::open(w.path()).unwrap().pending_purchases()[0].open,
            p.open
        );
        // the same record again changes nothing, and writes nothing
        let version = w.version();
        assert_eq!(
            w.apply_delivery(&built.id, &outcome).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(w.version(), version);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_held_payment_keeps_the_purchase_open_and_says_how_short_it_was() {
        let (mut w, dir) = wallet("held");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let open = open_of(w.apply_delivery(&built.id, &held(1_800_000_000)).unwrap());
        assert_eq!(open.kind, OpenKind::Held);
        assert_eq!((open.paid_sats, open.paid_cents), (1_000, 10));
        assert_eq!((open.requested_units, open.over_under_bps), (5, -8_000));
        assert_eq!(w.pending_purchases()[0].open.as_ref(), Some(&open));
        assert!(w.notes().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signatures_can_still_be_claimed_for_a_purchase_that_was_open() {
        let (mut w, dir) = wallet("open-then-signed");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        w.apply_delivery(&built.id, &held(1_800_000_000)).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let c = claimed(
            w.apply_delivery(&built.id, &record(&sigs, &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 5);
        assert!(w.pending_purchases().is_empty());
        assert_eq!(w.balance().psp, 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn closing_deletes_open_purchases_and_their_keys_at_the_end_of_the_window_only() {
        let (mut w, dir) = wallet("close");
        let mint = DidSecretKey::new();
        let a = w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        let b = w.build_psp_payload(&[2], &mint.public_key()).unwrap();
        let c = w.build_psp_payload(&[4], &mint.public_key()).unwrap();
        // a is held until 1,000, b rejected until 2,000, c has no record yet
        w.apply_delivery(&a.id, &held(1_000)).unwrap();
        w.apply_delivery(&b.id, &rejected(2_000)).unwrap();

        let version = w.version();
        assert!(w.close_expired(999).unwrap().is_empty());
        assert_eq!(w.version(), version, "nothing due, nothing written");

        // the end of the window itself closes it (the PSP forfeits at the same time)
        assert_eq!(w.close_expired(1_000).unwrap(), vec![a.id.clone()]);
        let ids: Vec<&str> = w
            .pending_purchases()
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, vec![b.id.as_str(), c.id.as_str()]);

        // a purchase with no record yet is never closed by the clock
        assert_eq!(w.close_expired(u64::MAX - 1).unwrap(), vec![b.id.clone()]);
        let ids: Vec<&str> = w
            .pending_purchases()
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, vec![c.id.as_str()]);
        assert!(w.pending_purchases()[0].reply_secret.is_some());
        assert_eq!(Wallet::open(w.path()).unwrap().pending_purchases().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn closing_deletes_kept_reply_keys_when_their_window_has_passed() {
        let (mut w, dir) = wallet("close-keys");
        let reply = |id: &str, open_until: u64| OpenReply {
            id: id.into(),
            delivery_id: "dd".repeat(32),
            mint_did_pubkey: "03".repeat(33),
            reply_secret: "ee".repeat(32),
            credit_cents: 10,
            unaccounted_units: 0,
            open_until,
        };
        w.update(|d| {
            d.open_replies.push(reply("early", 1_000));
            d.open_replies.push(reply("late", 5_000));
            // from a file from before windows
            d.open_replies.push(reply("old", 0));
            Ok(())
        })
        .unwrap();
        assert_eq!(w.close_expired(2_000).unwrap(), vec!["early".to_string()]);
        let kept: Vec<(&str, u64)> = w
            .open_replies()
            .iter()
            .map(|r| (r.id.as_str(), r.open_until))
            .collect();
        // the unstamped key is not deleted: it is given the wallet's fallback
        assert_eq!(
            kept,
            vec![("late", 5_000), ("old", 2_000 + OPEN_KEY_FALLBACK_SECS)]
        );
        assert!(w.close_expired(4_999).unwrap().is_empty());
        assert_eq!(w.close_expired(5_000).unwrap(), vec!["late".to_string()]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_bad_record_changes_nothing() {
        let (mut w, dir) = wallet("bad-record");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        let version = w.version();
        let unchanged = |w: &Wallet| {
            assert_eq!(w.version(), version);
            assert_eq!(w.pending_purchases()[0].outputs.len(), 2);
            assert!(w.notes().is_empty() && w.open_replies().is_empty());
        };

        // a pair that matches no pending output, before a valid one
        let stranger = (
            BlindNonce(SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1)),
            all[1].1,
        );
        let with_stranger = record(&[all[0], stranger], &pks, 0, 0);
        assert!(matches!(
            w.apply_delivery(&built.id, &with_stranger),
            Err(WalletError::Unknown(_))
        ));
        unchanged(&w);

        // the same pair twice
        let twice = record(&[all[0], all[0]], &pks, 0, 0);
        assert!(w.apply_delivery(&built.id, &twice).is_err());
        unchanged(&w);

        // a keyset with no key for an amount
        let mut no_keys = pks.clone();
        no_keys.remove(&Amount::from_units(1));
        assert!(matches!(
            w.apply_delivery(&built.id, &record(&all, &no_keys, 0, 0)),
            Err(WalletError::Mint(_))
        ));
        unchanged(&w);

        // keys that are not those the keyset id names (the id is taken from the
        // key of the smallest amount)
        let Outcome::Signed(mut forged) = record(&all, &pks, 0, 0) else {
            unreachable!()
        };
        let other = SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1);
        forged
            .keysets
            .keysets
            .get_mut(&forged.keyset)
            .unwrap()
            .insert(1, other);
        assert!(matches!(
            w.apply_delivery(&built.id, &Outcome::Signed(forged)),
            Err(WalletError::Mint(_))
        ));
        unchanged(&w);

        // a record that does not carry the keys of the keyset it names
        let Outcome::Signed(mut missing) = record(&all, &pks, 0, 0) else {
            unreachable!()
        };
        missing.keyset = "0000000000000000".to_string();
        assert!(matches!(
            w.apply_delivery(&built.id, &Outcome::Signed(missing)),
            Err(WalletError::Mint(_))
        ));
        unchanged(&w);

        // a signature that is not a curve point
        let Outcome::Signed(mut junk) = record(&all, &pks, 0, 0) else {
            unreachable!()
        };
        junk.signatures[0].signature = "zz".to_string();
        assert!(w.apply_delivery(&built.id, &Outcome::Signed(junk)).is_err());
        unchanged(&w);

        // and the good record still works afterwards
        let c = claimed(
            w.apply_delivery(&built.id, &record(&all, &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_purchase_made_before_one_off_keys_can_still_be_applied_but_has_no_key_to_keep() {
        let (mut w, dir) = wallet("old-purchase");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        // as an old wallet file has it: no key, no delivery id
        w.update(|d| {
            d.pending_purchases[0].reply_secret = None;
            d.pending_purchases[0].delivery_id = None;
            Ok(())
        })
        .unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let c = claimed(
            w.apply_delivery(&built.id, &record(&sigs, &pks, 0, 10))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 1);
        assert!(c.key_kept, "a credit is owed, but there is no key to keep");
        assert!(w.open_replies().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_purchase_can_be_discarded_before_it_is_paid() {
        let (mut w, dir) = wallet("discard");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        assert!(w.discard_purchase("nope").is_err());
        w.discard_purchase(&built.id).unwrap();
        assert!(w.pending_purchases().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
