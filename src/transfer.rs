//! ESP transfer to the service a note is named for.
//!
//! An ESP note names one service, and only that service can redeem it or move
//! it. An app that pays a service hands over whole notes together with their
//! spend secrets ([`Wallet::hand_over_esp`]). The service takes them in
//! ([`Wallet::receive_handover`]) and swaps them at the ESP mint for fresh notes
//! that only it holds ([`Wallet::build_transfer`], then the ESP mint's
//! `/transfer`, then [`Wallet::finish_transfer`]). The new notes have the same
//! service, the same redeemable-after day and the same total. Nothing is burned
//! out of circulation and no value is created.
//!
//! A note can be swapped once, so a second presentation of the same notes fails
//! at the mint. The app cannot move ESP to another service or to a peer: the
//! request must be signed by the service's key, and the mint checks each note
//! against that service's terms.
//!
//! The swap is exact, and ESP notes cannot be split by their holder, so an app
//! can hand over only a set of whole notes whose total is exactly the amount. To
//! make that easy, exchange in the sizes you will pay (`exchange --amounts`).
//! Every ESP note is a power of two (the mint refuses anything else), so the
//! new notes of a transfer are too: by default the same sizes as the old ones,
//! and any other sizes given must be powers of two.
//!
//! Handing the notes to the service is an AIR message, which is deferred. Until
//! then [`Handover`] is a value the command line writes to a file.

use std::collections::{BTreeSet, HashSet};

use mint_types::{Amount, MintInput};
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};

use sp_wire::esp::transfer::{self, TransferRequest, TransferResponse};

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{HandedNote, Handover, Kind, PendingTransfer, StoredNote, StoredTerms, Wallet};

/// How many search steps to spend looking for an exact set of notes.
const SEARCH_BUDGET: u32 = 100_000;

#[derive(Debug, Clone)]
pub struct TransferBuild {
    /// The request hash, which names this transfer in the wallet and at the mint.
    pub id: String,
    pub request: TransferRequest,
    /// The ESP units being swapped.
    pub esp_units: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferDone {
    /// The ids of the new ESP notes.
    pub notes: Vec<String>,
    pub esp_units: u128,
    pub redeemable_after_day: u64,
}

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

/// Whether `note` is ESP for `service` and free to use.
fn is_free_esp_for(note: &StoredNote, service: &XOnlyPublicKey) -> bool {
    note.kind == Kind::Esp
        && note.reserved_by.is_none()
        && note.terms.as_ref().is_some_and(|t| t.service == *service)
}

/// The redeemable-after day to work with: the one asked for, or the only one
/// the notes have. A request covers one set of terms.
fn pick_day(notes: &[&StoredNote], asked: Option<u64>) -> Result<u64, WalletError> {
    let days: BTreeSet<u64> = notes
        .iter()
        .filter_map(|n| n.terms.as_ref().map(|t| t.redeemable_after_day))
        .collect();
    match asked {
        Some(day) if days.contains(&day) => Ok(day),
        Some(day) => Err(WalletError::NotEnough(format!(
            "no free ESP for that service with redeemable-after day {day}"
        ))),
        None => match days.len() {
            0 => Err(WalletError::NotEnough(
                "no free ESP for that service in this wallet".into(),
            )),
            1 => Ok(days.iter().next().copied().unwrap_or_default()),
            n => {
                let list: Vec<String> = days.iter().map(u64::to_string).collect();
                Err(WalletError::Invalid(format!(
                    "this wallet holds ESP for that service with {n} different redeemable-after days ({}). A transfer covers one day: pick one with --day",
                    list.join(", ")
                )))
            }
        },
    }
}

impl Wallet {
    /// Hand ESP to a service: whole notes bound to `service`, with the same
    /// redeemable-after day, that add up to exactly `esp_units`.
    ///
    /// The notes leave the wallet and the [`Handover`] is kept in the wallet's
    /// record of handovers as well as returned, because it holds the only copy of
    /// the notes' spend secrets. Give `day` when the wallet has ESP for the
    /// service with more than one day. If no set of notes adds up exactly the
    /// call fails and the wallet is unchanged.
    pub fn hand_over_esp(
        &mut self,
        service: XOnlyPublicKey,
        esp_units: u128,
        day: Option<u64>,
    ) -> Result<Handover, WalletError> {
        if esp_units == 0 {
            return Err(WalletError::Invalid("there is nothing to hand over".into()));
        }
        let free: Vec<&StoredNote> = self
            .notes()
            .iter()
            .filter(|n| is_free_esp_for(n, &service))
            .collect();
        let day = pick_day(&free, day)?;
        let mut candidates: Vec<&StoredNote> = free
            .into_iter()
            .filter(|n| {
                n.terms
                    .as_ref()
                    .is_some_and(|t| t.redeemable_after_day == day)
            })
            .collect();
        candidates.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.id().cmp(&b.id())));
        let sizes: Vec<u64> = candidates.iter().map(|n| n.amount).collect();
        let Some(picked) = pick_exact(&sizes, esp_units) else {
            let held: u128 = sizes.iter().map(|&a| u128::from(a)).sum();
            return Err(WalletError::NotEnough(format!(
                "no set of this wallet's ESP notes for that service and day adds up to exactly {esp_units} ESP units (it holds {held} in notes of {sizes:?}). A transfer is exact and a note cannot be split, so ask for an amount the notes add up to"
            )));
        };
        if let Some(max) = self.esp_limits().transfer_max_items {
            if picked.len() > max {
                return Err(WalletError::Invalid(format!(
                    "that would take more than the {max} notes the mint takes in one transfer (its transfer.max_items)"
                )));
            }
        }
        let chosen: Vec<StoredNote> = picked.iter().map(|&i| candidates[i].clone()).collect();
        let handover = Handover {
            service,
            redeemable_after_day: day,
            notes: chosen
                .iter()
                .map(|n| -> Result<HandedNote, WalletError> {
                    Ok(HandedNote {
                        amount: n.amount,
                        note: n.note,
                        spend_secret: n.spend_secret,
                        keyset: self.esp_keyset_of(n)?,
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let ids: Vec<String> = chosen.iter().map(StoredNote::id).collect();
        self.update(|d| {
            d.notes.retain(|n| !ids.contains(&n.id()));
            d.handovers.push(handover.clone());
            Ok(())
        })?;
        Ok(handover)
    }

    /// Take a [`Handover`] into this wallet, as the service. Returns how many
    /// notes were taken and what they are worth. A note whose secret does not
    /// match its nonce, or that the wallet already holds, is refused and nothing
    /// is taken.
    ///
    /// The mint's signature on a note cannot be checked here. Whether the notes
    /// are good is found out when they are swapped at the mint.
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

    /// Build a transfer, as the service: swap every free ESP note this wallet
    /// holds for the service whose key is `service_secret` and the day (the only
    /// one the notes have, or `day`) for fresh notes of the same total.
    ///
    /// By default there is one new note for each old one, with the same amount.
    /// `esp_amounts` chooses other sizes, each a power of two, and must add up to
    /// the same total. Each
    /// input is signed over the transfer digest with the note's own key, and the
    /// request is signed with the service's key. The old notes are reserved until
    /// the transfer is finished or cancelled.
    pub fn build_transfer(
        &mut self,
        service_secret: &SecretKey,
        day: Option<u64>,
        esp_amounts: Option<&[u64]>,
    ) -> Result<TransferBuild, WalletError> {
        let service_keypair = Keypair::from_secret_key(SECP256K1, service_secret);
        let service = service_keypair.x_only_public_key().0;

        let free: Vec<&StoredNote> = self
            .notes()
            .iter()
            .filter(|n| is_free_esp_for(n, &service))
            .collect();
        let day = pick_day(&free, day)?;
        let mut chosen: Vec<StoredNote> = free
            .into_iter()
            .filter(|n| {
                n.terms
                    .as_ref()
                    .is_some_and(|t| t.redeemable_after_day == day)
            })
            .cloned()
            .collect();
        chosen.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.id().cmp(&b.id())));
        let total: u128 = chosen.iter().map(|n| u128::from(n.amount)).sum();
        // The mint refuses a note or an output that is not a power of two, before
        // it burns anything, so say so here and send nothing.
        for n in &chosen {
            crate::split::check_denomination(n.amount)?;
        }

        let amounts: Vec<u64> = match esp_amounts {
            None => chosen.iter().map(|n| n.amount).collect(),
            Some(list) => {
                if list.is_empty() {
                    return Err(WalletError::Invalid("give at least one amount".into()));
                }
                if list.contains(&0) {
                    return Err(WalletError::Invalid("an ESP note cannot be zero".into()));
                }
                for &a in list {
                    crate::split::check_denomination(a)?;
                }
                let sum: u128 = list.iter().map(|&a| u128::from(a)).sum();
                if sum != total {
                    return Err(WalletError::Invalid(format!(
                        "the new notes add up to {sum} units but the notes being swapped are worth {total}. A transfer is exact"
                    )));
                }
                list.to_vec()
            }
        };
        if let Some(max) = self.esp_limits().transfer_max_items {
            if chosen.len() > max || amounts.len() > max {
                return Err(WalletError::Invalid(format!(
                    "the mint takes at most {max} notes and {max} outputs in one transfer (its transfer.max_items)"
                )));
            }
        }

        let outputs: Vec<PendingOutput> = amounts.iter().map(|&a| PendingOutput::new(a)).collect();
        let mint_outputs: Vec<_> = outputs.iter().map(PendingOutput::mint_output).collect();

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
        let sighash = transfer::digest(&service, day, &inputs, &mint_outputs);
        for (input, held) in inputs.iter_mut().zip(&chosen) {
            let keypair = Keypair::from_secret_key(SECP256K1, &held.spend_secret);
            input.spend_signature = SECP256K1.sign_schnorr(&sighash, &keypair);
        }
        let service_signature = SECP256K1.sign_schnorr(&sighash, &service_keypair);

        let request = TransferRequest {
            service,
            redeemable_after_day: day,
            input_keysets: chosen
                .iter()
                .map(|n| self.esp_keyset_of(n))
                .collect::<Result<_, _>>()?,
            inputs,
            keyset: self.esp_output_keyset(),
            outputs: mint_outputs,
            service_signature,
        };
        let id = transfer::request_hash(&request);
        let input_ids: Vec<String> = chosen.iter().map(StoredNote::id).collect();

        let pending = PendingTransfer {
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
            d.pending_transfers.push(pending);
            Ok(())
        })?;
        Ok(TransferBuild {
            id,
            request,
            esp_units: total,
        })
    }

    /// Turn the mint's reply into the service's new ESP notes and drop the old
    /// ones. Call it once, with the reply to the request `id` names.
    pub fn finish_transfer(
        &mut self,
        id: &str,
        response: &TransferResponse,
    ) -> Result<TransferDone, WalletError> {
        let pending = self
            .pending_transfers()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending transfer {id}")))?;
        if response.service != pending.service {
            return Err(WalletError::Mint(
                "the reply is for a different service".into(),
            ));
        }
        if response.redeemable_after_day != pending.request.redeemable_after_day {
            return Err(WalletError::Mint(
                "the reply changes the redeemable-after day, which a transfer must keep".into(),
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
            d.pending_transfers.retain(|p| p.id != id);
            Ok(())
        })?;
        // The keyset that actually signed, as the reply names it.
        self.record_keysets(&ids, &response.keyset)?;
        Ok(TransferDone {
            notes: ids,
            esp_units,
            redeemable_after_day: response.redeemable_after_day,
        })
    }

    /// The mint refused transfer `id` because the notes at `inputs` (positions
    /// in the request) are spent. Nothing was burned. Those notes go to the
    /// spent record, the others are free again, and the pending transfer is
    /// dropped. Without this the wallet would offer the spent notes again on
    /// every transfer and be refused each time.
    pub fn mark_spent_in_transfer(
        &mut self,
        id: &str,
        inputs: &[usize],
    ) -> Result<crate::esp::SpentReport, WalletError> {
        self.update(|d| {
            let pending = d
                .pending_transfers
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no pending transfer {id}")))?;
            let count = pending.input_ids.len();
            if inputs.is_empty() || inputs.iter().any(|&i| i >= count) {
                return Err(WalletError::Invalid(format!(
                    "the mint named notes {inputs:?}, but the request has {count} notes"
                )));
            }
            let spent_ids: Vec<String> = inputs
                .iter()
                .map(|&i| pending.input_ids[i].clone())
                .collect();
            d.pending_transfers.retain(|p| p.id != id);
            Ok(Wallet::retire_reserved(d, id, &spent_ids))
        })
    }

    pub fn cancel_transfer(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            let before = d.pending_transfers.len();
            d.pending_transfers.retain(|p| p.id != id);
            if d.pending_transfers.len() == before {
                return Err(WalletError::Unknown(format!("no pending transfer {id}")));
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
    use std::fs;
    use std::path::PathBuf;

    use secp256k1::PublicKey;

    /// A test amount, a power of two (about $1.10). Every ESP note is one.
    const ONE: u64 = 1 << 40;
    const DAY: u64 = 21_106;

    fn key(n: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        SecretKey::from_slice(&bytes).unwrap()
    }

    /// The service with secret key 1 (the generator, x-only `79be...`).
    fn service() -> XOnlyPublicKey {
        Keypair::from_secret_key(SECP256K1, &key(1))
            .x_only_public_key()
            .0
    }

    fn other_service() -> XOnlyPublicKey {
        Keypair::from_secret_key(SECP256K1, &key(2))
            .x_only_public_key()
            .0
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

    /// A stored ESP note. The mint's signature is made up, so only selection,
    /// requests and bookkeeping are checked here.
    fn esp_note(amount: u64, service: XOnlyPublicKey, day: u64) -> StoredNote {
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

    fn wallet_with(name: &str, notes: Vec<StoredNote>) -> (Wallet, PathBuf) {
        let dir = scratch(name);
        let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
        w.update(|d| {
            // Every stored note records its keyset (the wallet never guesses).
            for n in &notes {
                d.keysets.insert(n.id(), "ab".repeat(8));
            }
            d.notes.extend(notes);
            Ok(())
        })
        .unwrap();
        (w, dir)
    }

    fn some_key() -> PublicKey {
        SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1)
    }

    /// A reply with a made-up signature and key for each output.
    fn reply(build: &TransferBuild) -> TransferResponse {
        let n = build.request.outputs.len();
        TransferResponse {
            keyset: "ab".repeat(8),
            service: build.request.service,
            redeemable_after_day: build.request.redeemable_after_day,
            signatures: (0..n).map(|_| some_key()).collect(),
            keys: (0..n).map(|_| some_key()).collect(),
            fee_per_byte: 0,
            fee_esp: 0,
            size_bytes: 0,
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

    #[test]
    fn handing_over_takes_an_exact_set_and_keeps_a_record() {
        let (mut w, dir) = wallet_with(
            "hand",
            vec![
                esp_note(4 * ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
            ],
        );
        let handover = w
            .hand_over_esp(service(), u128::from(4 * ONE), None)
            .unwrap();
        assert_eq!(handover.service, service());
        assert_eq!(handover.redeemable_after_day, DAY);
        let handed: u128 = handover.notes.iter().map(|n| u128::from(n.amount)).sum();
        assert_eq!(handed, u128::from(4 * ONE));
        let b = w.balance();
        assert_eq!(b.esp, u128::from(2 * ONE));
        assert_eq!((b.notes, b.handed_over), (2, 1));
        assert_eq!(w.handovers(), &[handover.clone()]);
        // the record is on disk
        let again = Wallet::open(&dir.join("wallet.json")).unwrap();
        assert_eq!(again.handovers(), &[handover]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_amount_the_notes_cannot_make_is_refused_and_the_wallet_is_unchanged() {
        let (mut w, dir) = wallet_with(
            "inexact",
            vec![
                esp_note(4 * ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
            ],
        );
        let before = w.balance();
        for units in [
            u128::from(ONE + ONE / 2),
            u128::from(2 * ONE),
            u128::from(6 * ONE),
        ] {
            let err = w.hand_over_esp(service(), units, None).unwrap_err();
            assert!(matches!(err, WalletError::NotEnough(_)), "{err}");
        }
        assert!(matches!(
            w.hand_over_esp(service(), 0, None),
            Err(WalletError::Invalid(_))
        ));
        assert_eq!(w.balance(), before);
        assert!(w.handovers().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_notes_for_that_service_are_handed_over() {
        let (mut w, dir) = wallet_with("service", vec![esp_note(ONE, other_service(), DAY)]);
        let err = w
            .hand_over_esp(service(), u128::from(ONE), None)
            .unwrap_err();
        assert!(matches!(err, WalletError::NotEnough(_)), "{err}");
        assert_eq!(w.balance().notes, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn more_than_one_day_needs_a_day_to_be_named() {
        let (mut w, dir) = wallet_with(
            "days",
            vec![
                esp_note(ONE, service(), DAY),
                esp_note(ONE, service(), DAY + 1),
            ],
        );
        let err = w
            .hand_over_esp(service(), u128::from(ONE), None)
            .unwrap_err();
        assert!(matches!(err, WalletError::Invalid(_)), "{err}");
        assert_eq!(w.balance().notes, 2);
        let handover = w
            .hand_over_esp(service(), u128::from(ONE), Some(DAY + 1))
            .unwrap();
        assert_eq!(handover.redeemable_after_day, DAY + 1);
        assert!(
            w.hand_over_esp(service(), u128::from(ONE), Some(DAY + 7))
                .is_err()
        );
        assert_eq!(w.balance().notes, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reserved_notes_are_not_handed_over() {
        let mut held = esp_note(ONE, service(), DAY);
        held.reserved_by = Some("abc".into());
        let (mut w, dir) = wallet_with("reserved", vec![held]);
        assert!(w.hand_over_esp(service(), u128::from(ONE), None).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_service_takes_a_handover_in() {
        let (mut app, app_dir) = wallet_with(
            "app",
            vec![
                esp_note(2 * ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
            ],
        );
        let handover = app
            .hand_over_esp(service(), 3 * u128::from(ONE), None)
            .unwrap();
        let svc_dir = scratch("svc");
        let mut svc = Wallet::open(&svc_dir.join("wallet.json")).unwrap();
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
        fs::remove_dir_all(&app_dir).unwrap();
        fs::remove_dir_all(&svc_dir).unwrap();
    }

    #[test]
    fn a_handover_with_a_secret_that_does_not_match_is_refused() {
        let (mut app, app_dir) = wallet_with("mismatch-app", vec![esp_note(ONE, service(), DAY)]);
        let mut handover = app.hand_over_esp(service(), u128::from(ONE), None).unwrap();
        handover.notes[0].spend_secret = key(9);
        let svc_dir = scratch("mismatch-svc");
        let mut svc = Wallet::open(&svc_dir.join("wallet.json")).unwrap();
        assert!(matches!(
            svc.receive_handover(&handover),
            Err(WalletError::Invalid(_))
        ));
        assert_eq!(svc.balance().notes, 0);
        handover.notes.clear();
        assert!(svc.receive_handover(&handover).is_err());
        fs::remove_dir_all(&app_dir).unwrap();
        fs::remove_dir_all(&svc_dir).unwrap();
    }

    #[test]
    fn a_transfer_refused_for_a_spent_note_retires_it_and_frees_the_others() {
        let notes = vec![
            esp_note(4 * ONE, service(), DAY),
            esp_note(ONE, service(), DAY),
            esp_note(2 * ONE, service(), DAY),
        ];
        let (mut w, dir) = wallet_with("spent-in-transfer", notes);
        let built = w.build_transfer(&key(1), None, None).unwrap();
        assert_eq!(w.pending_transfers().len(), 1);
        let spent_id = w.pending_transfers()[0].input_ids[1].clone();
        // an index past the request is refused and changes nothing
        assert!(w.mark_spent_in_transfer(&built.id, &[3]).is_err());
        assert_eq!(w.pending_transfers().len(), 1);
        let report = w.mark_spent_in_transfer(&built.id, &[1]).unwrap();
        assert_eq!((report.marked_spent, report.freed), (1, 2));
        assert_eq!(w.spent_notes().len(), 1);
        assert_eq!(w.spent_notes()[0].id(), spent_id);
        assert_eq!(w.notes().len(), 2);
        assert!(w.notes().iter().all(|n| n.reserved_by.is_none()));
        assert!(w.pending_transfers().is_empty());
        // the next transfer does not offer the spent note again
        let next = w.build_transfer(&key(1), None, None).unwrap();
        assert_eq!(next.request.inputs.len(), 2);
        assert!(!w.pending_transfers()[0].input_ids.contains(&spent_id));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_transfer_request_is_exact_and_signed_by_every_note_and_the_service() {
        let (mut w, dir) = wallet_with(
            "build",
            vec![
                esp_note(4 * ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
                esp_note(8 * ONE, other_service(), DAY),
            ],
        );
        let built = w.build_transfer(&key(1), None, None).unwrap();
        assert_eq!(built.esp_units, 5 * u128::from(ONE));
        let request = &built.request;
        assert_eq!(request.service, service());
        assert_eq!(request.redeemable_after_day, DAY);
        assert_eq!(request.inputs.len(), 2);
        let ins: u128 = request
            .inputs
            .iter()
            .map(|i| u128::from(i.amount.units))
            .sum();
        let outs: u128 = request
            .outputs
            .iter()
            .map(|o| u128::from(o.amount.units))
            .sum();
        assert_eq!((ins, outs), (5 * u128::from(ONE), 5 * u128::from(ONE)));
        // one new note for each old one, the same size
        let mut sizes: Vec<u64> = request.outputs.iter().map(|o| o.amount.units).collect();
        sizes.sort();
        assert_eq!(sizes, vec![ONE, 4 * ONE]);

        let digest = request.digest();
        SECP256K1
            .verify_schnorr(&request.service_signature, &digest, &service())
            .unwrap();
        for input in &request.inputs {
            SECP256K1
                .verify_schnorr(
                    &input.spend_signature,
                    &digest,
                    &input.note.spend_key().x_only_public_key().0,
                )
                .unwrap();
        }
        assert_eq!(built.id, transfer::request_hash(request));
        // the notes are reserved, the other service's note is not touched
        let b = w.balance();
        assert_eq!((b.reserved, b.pending_transfers), (2, 1));
        assert_eq!(w.pending_transfers()[0].id, built.id);
        // a second build finds nothing free for this service
        assert!(w.build_transfer(&key(1), None, None).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_wallet_with_no_notes_for_the_key_builds_nothing() {
        let (mut w, dir) = wallet_with("nokey", vec![esp_note(ONE, other_service(), DAY)]);
        let err = w.build_transfer(&key(1), None, None).unwrap_err();
        assert!(matches!(err, WalletError::NotEnough(_)), "{err}");
        assert_eq!(w.balance().pending_transfers, 0);
        assert_eq!(w.balance().reserved, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_new_sizes_must_add_up_to_the_same_total() {
        let (mut w, dir) = wallet_with(
            "sizes",
            vec![
                esp_note(4 * ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
            ],
        );
        for bad in [
            vec![5 * ONE + 1],
            vec![5 * ONE - 1],
            vec![0, 5 * ONE],
            vec![],
            // the right total, but 3 ONE is not a power of two
            vec![3 * ONE, 2 * ONE],
        ] {
            assert!(
                w.build_transfer(&key(1), None, Some(&bad)).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(w.balance().reserved, 0);
        let built = w
            .build_transfer(&key(1), None, Some(&[4 * ONE, ONE]))
            .unwrap();
        assert_eq!(built.request.outputs.len(), 2);
        assert_eq!(built.request.inputs.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_note_that_is_not_a_power_of_two_is_not_swapped() {
        let (mut w, dir) = wallet_with("odd", vec![esp_note(ONE + 5, service(), DAY)]);
        let e = w
            .build_transfer(&key(1), None, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not an ESP note size"), "{e}");
        assert_eq!(w.balance().reserved, 0);
        assert!(w.pending_transfers().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_finished_transfer_swaps_the_old_notes_for_the_new_ones() {
        let (mut w, dir) = wallet_with(
            "finish",
            vec![
                esp_note(4 * ONE, service(), DAY),
                esp_note(ONE, service(), DAY),
            ],
        );
        let old_ids: Vec<String> = w.notes().iter().map(StoredNote::id).collect();
        let built = w.build_transfer(&key(1), None, None).unwrap();
        let done = w.finish_transfer(&built.id, &reply(&built)).unwrap();
        assert_eq!(done.esp_units, 5 * u128::from(ONE));
        assert_eq!(done.redeemable_after_day, DAY);
        assert_eq!(done.notes.len(), 2);
        let b = w.balance();
        assert_eq!(
            (b.esp, b.notes, b.reserved, b.pending_transfers),
            (5 * u128::from(ONE), 2, 0, 0)
        );
        for note in w.notes() {
            assert!(!old_ids.contains(&note.id()));
            let terms = note.terms.as_ref().unwrap();
            assert_eq!(
                (terms.service, terms.redeemable_after_day),
                (service(), DAY)
            );
            assert!(done.notes.contains(&note.id()));
        }
        // it survives a reopen
        let again = Wallet::open(&dir.join("wallet.json")).unwrap();
        assert_eq!(again.balance(), w.balance());
        // finishing twice finds nothing pending
        assert!(w.finish_transfer(&built.id, &reply(&built)).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reply_that_does_not_fit_the_request_changes_nothing() {
        let (mut w, dir) = wallet_with("badreply", vec![esp_note(ONE, service(), DAY)]);
        let built = w.build_transfer(&key(1), None, None).unwrap();
        let before = w.balance();

        let mut short = reply(&built);
        short.signatures.clear();
        assert!(matches!(
            w.finish_transfer(&built.id, &short),
            Err(WalletError::Mint(_))
        ));
        let mut wrong_service = reply(&built);
        wrong_service.service = other_service();
        assert!(w.finish_transfer(&built.id, &wrong_service).is_err());
        let mut wrong_day = reply(&built);
        wrong_day.redeemable_after_day = DAY + 1;
        assert!(w.finish_transfer(&built.id, &wrong_day).is_err());
        assert!(w.finish_transfer("nope", &reply(&built)).is_err());

        assert_eq!(w.balance(), before);
        assert_eq!(w.pending_transfers().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cancelled_transfer_frees_its_notes() {
        let (mut w, dir) = wallet_with("cancel", vec![esp_note(ONE, service(), DAY)]);
        let built = w.build_transfer(&key(1), None, None).unwrap();
        assert_eq!(w.balance().reserved, 1);
        w.cancel_transfer(&built.id).unwrap();
        let b = w.balance();
        assert_eq!((b.reserved, b.pending_transfers, b.notes), (0, 0, 1));
        assert!(w.cancel_transfer(&built.id).is_err());
        // and the notes can be used again
        assert!(w.build_transfer(&key(1), None, None).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pending_transfer_is_resent_exactly_after_a_reopen() {
        let (mut w, dir) = wallet_with("resume", vec![esp_note(ONE, service(), DAY)]);
        let built = w.build_transfer(&key(1), None, None).unwrap();
        drop(w);
        let again = Wallet::open(&dir.join("wallet.json")).unwrap();
        assert_eq!(again.pending_transfers().len(), 1);
        let pending = &again.pending_transfers()[0];
        assert_eq!(pending.id, built.id);
        assert_eq!(transfer::request_hash(&pending.request), built.id);
        fs::remove_dir_all(&dir).unwrap();
    }
}
