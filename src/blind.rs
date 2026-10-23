//! Blinding outputs and unblinding the mint's signatures.
//!
//! An output starts as a fresh nonce key pair. The nonce's public half is the
//! note's identity and its secret half is the spend key. The nonce is blinded
//! with a random factor, so the mint signs it without seeing it. The mint's
//! blind signature, with the blinding factor and the mint's public key for the
//! amount, gives the note. Blind signatures cannot be checked by anyone but the
//! mint, so a wallet cannot tell a bad signature from a good one until the note
//! is spent.

use mint_types::{Amount, BlindNonce, MintOutput, Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
use serde::{Deserialize, Serialize};

/// An output that has been blinded and sent, and is waiting for its signature.
/// This holds the only copy of the spend key and the blinding factor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOutput {
    pub amount: u64,
    pub nonce_secret: SecretKey,
    pub nonce: Nonce,
    pub blinding_key: SecretKey,
    pub blind_nonce: BlindNonce,
}

impl PendingOutput {
    /// A new output of `amount` units, with fresh keys.
    pub fn new(amount: u64) -> Self {
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(keypair.public_key());
        let (point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        PendingOutput {
            amount,
            nonce_secret: keypair.secret_key(),
            nonce,
            blinding_key,
            blind_nonce: BlindNonce(point),
        }
    }

    /// What goes to the mint.
    pub fn mint_output(&self) -> MintOutput {
        MintOutput {
            amount: Amount::from_units(self.amount),
            blind_nonce: self.blind_nonce,
        }
    }

    /// Turn the mint's blind signature into a note. `mint_key` is the mint's
    /// public key for this amount (and, for ESP, these terms).
    pub fn unblind(&self, signature: &PublicKey, mint_key: &PublicKey) -> Note {
        Note {
            nonce: self.nonce,
            signature: bdhke::unblind_message(signature, &self.blinding_key, mint_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mint_key() -> SecretKey {
        SecretKey::new(&mut OsRng)
    }

    #[test]
    fn a_signed_output_unblinds_to_a_note_the_mint_accepts() {
        let sk = mint_key();
        let pk = sk.public_key(SECP256K1);
        let out = PendingOutput::new(4);
        let blind_signature = bdhke::sign_message(&sk, &out.blind_nonce.0);
        let note = out.unblind(&blind_signature, &pk);
        assert_eq!(note.nonce, out.nonce);
        assert!(bdhke::verify_message(
            &sk,
            note.signature,
            &out.nonce.as_hash_preimage()
        ));
    }

    #[test]
    fn the_spend_key_is_the_nonce_key() {
        let out = PendingOutput::new(1);
        let keypair = Keypair::from_secret_key(SECP256K1, &out.nonce_secret);
        assert_eq!(keypair.public_key(), out.nonce.0);

        // every output has fresh keys
        let b = PendingOutput::new(1);
        assert_ne!(out.nonce, b.nonce);
        assert_ne!(out.blind_nonce, b.blind_nonce);
        assert_ne!(out.blinding_key, b.blinding_key);

        // the mint's view of an output carries the amount and the blind nonce
        let big = PendingOutput::new(16);
        let m = big.mint_output();
        assert_eq!(m.amount, Amount::from_units(16));
        assert_eq!(m.blind_nonce, big.blind_nonce);
    }

    #[test]
    fn a_wrong_mint_key_or_blinding_factor_gives_a_note_that_does_not_verify() {
        let sk = mint_key();
        let pk = sk.public_key(SECP256K1);
        let out = PendingOutput::new(2);
        let blind_signature = bdhke::sign_message(&sk, &out.blind_nonce.0);

        // unblinded with another mint's public key
        let other = mint_key().public_key(SECP256K1);
        let bad_key = out.unblind(&blind_signature, &other);
        assert!(!bdhke::verify_message(
            &sk,
            bad_key.signature,
            &out.nonce.as_hash_preimage()
        ));

        // unblinded with another output's blinding factor
        let mut wrong = out.clone();
        wrong.blinding_key = PendingOutput::new(2).blinding_key;
        let bad_factor = wrong.unblind(&blind_signature, &pk);
        assert!(!bdhke::verify_message(
            &sk,
            bad_factor.signature,
            &out.nonce.as_hash_preimage()
        ));
    }
}
