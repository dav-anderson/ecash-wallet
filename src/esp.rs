//! Exchanging PSP for ESP.
//!
//! [`Wallet::build_exchange`] picks PSP notes that add up to exactly the amount
//! asked for, blinds the new ESP outputs, and signs each PSP note's spend over
//! the exchange memo. The request goes to the ESP mint's `/exchange`. The
//! mint burns the PSP notes at the PSP and signs the outputs.
//! [`Wallet::finish_exchange`] unblinds the reply into ESP notes.
//!
//! The wallet only builds exact exchanges. The mint keeps an excess under 10%
//! and records a larger one as credit, and the PSP has no change-making, so an
//! inexact request would lose value.

use mint_types::{Amount, MintInput, melt_sighash};
use secp256k1::{Keypair, SECP256K1, XOnlyPublicKey};

use esp_mint::exchange::{self, ExchangeRequest, ExchangeResponse, MAX_ITEMS};
use esp_mint::units::ESP_PER_PSP;

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{Kind, PendingExchange, StoredNote, StoredTerms, Wallet};

#[derive(Debug, Clone)]
pub struct ExchangeBuild {
    /// The request hash, which names this exchange in the wallet and at the mint.
    pub id: String,
    pub request: ExchangeRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishResult {
    /// The ids of the new ESP notes.
    pub notes: Vec<String>,
    pub esp_units: u128,
    pub redeemable_after_day: u64,
    /// ESP units the mint recorded as credit (the exchange paid 10% or more over).
    pub credit_esp: u128,
}

impl Wallet {
    /// Build an exchange of exactly `psp_units` PSP for ESP bound to `service`.
    ///
    /// `esp_amounts` splits the ESP into notes. It must add up to
    /// `psp_units * 10^12`. Without it the ESP is one note, which fits only up
    /// to 18,446,744 PSP.
    ///
    /// The PSP notes are reserved until the exchange is finished or cancelled.
    pub fn build_exchange(
        &mut self,
        psp_units: u64,
        service: XOnlyPublicKey,
        esp_amounts: Option<&[u64]>,
    ) -> Result<ExchangeBuild, WalletError> {
        if psp_units == 0 {
            return Err(WalletError::Invalid("the amount to exchange is zero".into()));
        }
        let target = u128::from(psp_units) * u128::from(ESP_PER_PSP);
        let amounts: Vec<u64> = match esp_amounts {
            None => vec![u64::try_from(target).map_err(|_| {
                WalletError::Invalid(format!(
                    "{psp_units} PSP is too much for one ESP note (the most is {}). Split it with --amounts",
                    esp_mint::units::MAX_PSP_PER_NOTE
                ))
            })?],
            Some(list) => {
                if list.is_empty() || list.len() > MAX_ITEMS {
                    return Err(WalletError::Invalid(format!(
                        "an exchange holds 1 to {MAX_ITEMS} ESP notes"
                    )));
                }
                if list.contains(&0) {
                    return Err(WalletError::Invalid("an ESP note cannot be zero".into()));
                }
                let sum: u128 = list.iter().map(|&a| u128::from(a)).sum();
                if sum != target {
                    return Err(WalletError::Invalid(format!(
                        "the ESP notes add up to {sum} units but {psp_units} PSP is {target}"
                    )));
                }
                list.to_vec()
            }
        };

        // Greedy, largest first. PSP notes are powers of two, so this finds an
        // exact set whenever one exists.
        let mut candidates: Vec<&StoredNote> = self
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Psp && n.reserved_by.is_none())
            .collect();
        candidates.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.id().cmp(&b.id())));
        let mut remaining = psp_units;
        let mut chosen: Vec<StoredNote> = Vec::new();
        for note in candidates {
            if remaining == 0 {
                break;
            }
            if note.amount <= remaining {
                remaining -= note.amount;
                chosen.push(note.clone());
            }
        }
        if remaining != 0 {
            let held: u128 = self
                .notes()
                .iter()
                .filter(|n| n.kind == Kind::Psp && n.reserved_by.is_none())
                .map(|n| u128::from(n.amount))
                .sum();
            return Err(WalletError::NotEnough(format!(
                "no set of PSP notes adds up to exactly {psp_units} (you hold {held} PSP free to spend, and the wallet cannot make change)"
            )));
        }
        if chosen.len() > MAX_ITEMS {
            return Err(WalletError::Invalid(format!(
                "that would take more than {MAX_ITEMS} PSP notes"
            )));
        }

        let outputs: Vec<PendingOutput> = amounts.iter().map(|&a| PendingOutput::new(a)).collect();
        let mint_outputs: Vec<_> = outputs.iter().map(PendingOutput::mint_output).collect();
        let memo = exchange::memo(&service, &mint_outputs);

        let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64])
            .map_err(|e| WalletError::Invalid(e.to_string()))?;
        let mut inputs: Vec<MintInput> = chosen
            .iter()
            .map(|n| MintInput {
                amount: Amount::from_units(n.amount),
                note: n.note,
                spend_signature: dummy,
            })
            .collect();
        let sighash = melt_sighash(&inputs, memo.as_bytes());
        for (input, held) in inputs.iter_mut().zip(&chosen) {
            let keypair = Keypair::from_secret_key(SECP256K1, &held.spend_secret);
            input.spend_signature = SECP256K1.sign_schnorr(&sighash, &keypair);
        }

        let request = ExchangeRequest {
            service,
            psp_inputs: inputs,
            outputs: mint_outputs,
        };
        let id = exchange::request_hash(&request).map_err(|e| WalletError::Invalid(e.to_string()))?;
        let input_ids: Vec<String> = chosen.iter().map(StoredNote::id).collect();

        let pending = PendingExchange {
            id: id.clone(),
            service,
            input_ids: input_ids.clone(),
            outputs,
            request: request.clone(),
        };
        self.update(|d| {
            for note in d.notes.iter_mut().filter(|n| input_ids.contains(&n.id())) {
                note.reserved_by = Some(id.clone());
            }
            d.pending_exchanges.push(pending);
            Ok(())
        })?;
        Ok(ExchangeBuild { id, request })
    }

    /// Turn the mint's reply into ESP notes and spend the PSP notes that paid
    /// for them. Call it once, with the reply to the request `id` names.
    pub fn finish_exchange(
        &mut self,
        id: &str,
        response: &ExchangeResponse,
    ) -> Result<FinishResult, WalletError> {
        let pending = self
            .pending_exchanges()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending exchange {id}")))?;
        if response.service != pending.service {
            return Err(WalletError::Mint(
                "the reply is for a different service".into(),
            ));
        }
        if response.signatures.len() != pending.outputs.len()
            || response.keys.len() != pending.outputs.len()
        {
            return Err(WalletError::Mint(
                "the reply does not have one signature and key for each output".into(),
            ));
        }
        let terms = StoredTerms {
            service: pending.service,
            redeemable_after_day: response.redeemable_after_day,
        };
        let mut notes = Vec::new();
        let mut esp_units = 0u128;
        for ((output, signature), key) in pending
            .outputs
            .iter()
            .zip(&response.signatures)
            .zip(&response.keys)
        {
            esp_units += u128::from(output.amount);
            notes.push(StoredNote {
                kind: Kind::Esp,
                amount: output.amount,
                note: output.unblind(signature, key),
                spend_secret: output.nonce_secret,
                terms: Some(terms),
                reserved_by: None,
            });
        }
        let ids: Vec<String> = notes.iter().map(StoredNote::id).collect();
        self.update(|d| {
            d.notes.retain(|n| !pending.input_ids.contains(&n.id()));
            d.notes.extend(notes);
            d.pending_exchanges.retain(|p| p.id != id);
            Ok(())
        })?;
        Ok(FinishResult {
            notes: ids,
            esp_units,
            redeemable_after_day: response.redeemable_after_day,
            credit_esp: response.credit_esp,
        })
    }

    /// Drop a pending exchange and free its PSP notes. Only safe when the mint
    /// refused the request, so nothing was burned. After a fault whose outcome is
    /// unknown, resend the same request instead.
    pub fn cancel_exchange(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            let before = d.pending_exchanges.len();
            d.pending_exchanges.retain(|p| p.id != id);
            if d.pending_exchanges.len() == before {
                return Err(WalletError::Unknown(format!("no pending exchange {id}")));
            }
            for note in d.notes.iter_mut() {
                if note.reserved_by.as_deref() == Some(id) {
                    note.reserved_by = None;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Wallet;
    use std::fs;
    use std::path::PathBuf;

    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn service() -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-esp-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A wallet holding PSP notes of the given sizes. Their signatures are not
    /// checked here, only the selection and the request.
    fn wallet_with(name: &str, sizes: &[u64]) -> (Wallet, PathBuf) {
        let dir = scratch(name);
        let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
        let sk = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let notes: Vec<StoredNote> = sizes
            .iter()
            .map(|&a| {
                let out = PendingOutput::new(a);
                let sig = bdhke::sign_message(&sk, &out.blind_nonce.0);
                StoredNote {
                    kind: Kind::Psp,
                    amount: a,
                    note: out.unblind(&sig, &sk.public_key(SECP256K1)),
                    spend_secret: out.nonce_secret,
                    terms: None,
                    reserved_by: None,
                }
            })
            .collect();
        w.update(|d| {
            d.notes.extend(notes);
            Ok(())
        })
        .unwrap();
        (w, dir)
    }

    #[test]
    fn the_exchange_picks_exactly_the_psp_asked_for_largest_first() {
        let (mut w, dir) = wallet_with("pick", &[1, 4, 2, 8]);
        let built = w.build_exchange(7, service(), None).unwrap();
        let mut sizes: Vec<u64> = built.request.psp_inputs.iter().map(|i| i.amount.units).collect();
        sizes.sort();
        assert_eq!(sizes, vec![1, 2, 4]);
        assert_eq!(built.request.outputs.len(), 1);
        assert_eq!(built.request.outputs[0].amount.units, 7_000_000_000_000);
        // the chosen notes are reserved, the rest are free
        let b = w.balance();
        assert_eq!(b.reserved, 3);
        assert_eq!(b.pending_exchanges, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spend_signatures_cover_the_memo_for_exactly_these_outputs() {
        let (mut w, dir) = wallet_with("sigs", &[4, 1]);
        let built = w.build_exchange(5, service(), Some(&[2_000_000_000_000, 3_000_000_000_000])).unwrap();
        let memo = exchange::memo(&built.request.service, &built.request.outputs);
        let sighash = melt_sighash(&built.request.psp_inputs, memo.as_bytes());
        for input in &built.request.psp_inputs {
            SECP256K1
                .verify_schnorr(
                    &input.spend_signature,
                    &sighash,
                    &input.note.spend_key().x_only_public_key().0,
                )
                .unwrap();
        }
        // and the id is the request hash the mint will use
        assert_eq!(built.id, exchange::request_hash(&built.request).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_inexact_or_unaffordable_exchange_is_refused_before_anything_is_reserved() {
        let (mut w, dir) = wallet_with("exact", &[4, 4]);
        // 5 cannot be made from 4 + 4
        assert!(matches!(w.build_exchange(5, service(), None), Err(WalletError::NotEnough(_))));
        // 9 is more than is held
        assert!(matches!(w.build_exchange(9, service(), None), Err(WalletError::NotEnough(_))));
        assert!(w.build_exchange(0, service(), None).is_err());
        assert_eq!(w.balance().reserved, 0);
        assert!(w.pending_exchanges().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_esp_split_must_add_up_exactly() {
        let (mut w, dir) = wallet_with("split", &[2]);
        assert!(w.build_exchange(2, service(), Some(&[1_000_000_000_000])).is_err());
        assert!(w.build_exchange(2, service(), Some(&[1_000_000_000_000, 1_000_000_000_001])).is_err());
        assert!(w.build_exchange(2, service(), Some(&[])).is_err());
        assert!(w.build_exchange(2, service(), Some(&[0, 2_000_000_000_000])).is_err());
        assert!(w.pending_exchanges().is_empty());
        assert!(w.build_exchange(2, service(), Some(&[1, 1_999_999_999_999])).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_esp_note_holds_at_most_18_446_744_psp_and_a_split_gets_past_it() {
        let (mut w, dir) = wallet_with("limit", &[1_048_576]);
        // 18,446,745 PSP is 1.8446745e19 ESP, over u64::MAX, so not one note
        assert!(esp_mint::units::MAX_PSP_PER_NOTE < 18_446_745);
        assert!(w.build_exchange(1_048_576, service(), None).is_ok());
        let (mut big, dir2) = wallet_with("limit2", &[]);
        assert!(matches!(big.build_exchange(18_446_745, service(), None), Err(WalletError::Invalid(_))));
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&dir2).unwrap();
    }

    #[test]
    fn reserved_notes_are_not_used_twice_and_cancel_frees_them() {
        let (mut w, dir) = wallet_with("reserve", &[4]);
        let first = w.build_exchange(4, service(), None).unwrap();
        assert!(matches!(w.build_exchange(4, service(), None), Err(WalletError::NotEnough(_))));
        assert!(w.cancel_exchange("nope").is_err());
        w.cancel_exchange(&first.id).unwrap();
        assert_eq!(w.balance().reserved, 0);
        assert!(w.pending_exchanges().is_empty());
        assert!(w.build_exchange(4, service(), None).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_pending_exchange_survives_a_reopen_with_the_same_request() {
        let (mut w, dir) = wallet_with("reopen", &[4]);
        let built = w.build_exchange(4, service(), None).unwrap();
        let again = Wallet::open(w.path()).unwrap();
        assert_eq!(again.pending_exchanges().len(), 1);
        assert_eq!(again.pending_exchanges()[0].id, built.id);
        assert_eq!(
            exchange::request_hash(&again.pending_exchanges()[0].request).unwrap(),
            built.id
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reply_that_does_not_match_is_refused_and_changes_nothing() {
        let (mut w, dir) = wallet_with("badreply", &[4]);
        let built = w.build_exchange(4, service(), None).unwrap();
        let sk = secp256k1::SecretKey::new(&mut rand::rngs::OsRng);
        let pk = sk.public_key(SECP256K1);
        let good = ExchangeResponse {
            service: service(),
            redeemable_after_day: 21_100,
            signatures: vec![pk],
            keys: vec![pk],
            credit_esp: 0,
        };
        let mut wrong_service = good.clone();
        wrong_service.service = XOnlyPublicKey::from_slice(
            &hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5").unwrap(),
        )
        .unwrap();
        assert!(w.finish_exchange(&built.id, &wrong_service).is_err());
        let mut short = good.clone();
        short.signatures.clear();
        assert!(w.finish_exchange(&built.id, &short).is_err());
        assert!(w.finish_exchange("nope", &good).is_err());
        assert_eq!(w.balance().psp, 4);
        assert_eq!(w.balance().esp, 0);
        assert_eq!(w.pending_exchanges().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }
}
