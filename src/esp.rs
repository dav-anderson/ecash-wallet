//! Exchanging PSP for ESP.
//!
//! [`Wallet::build_exchange`] picks PSP notes worth at least the amount asked
//! for, blinds the new ESP outputs, and signs each PSP note's spend over the
//! exchange memo. The request goes to the ESP mint's `/exchange`. The mint
//! burns the PSP notes at the PSP and signs the outputs.
//! [`Wallet::finish_exchange`] unblinds the reply into ESP notes.
//!
//! The mint's exchange is exact: the PSP notes, times 10^12, must equal the ESP
//! outputs' total, and the smallest exchange is 1 PSP. So the wallet always asks
//! for the full value of the PSP notes it spends. The amount asked for becomes
//! the service's ESP notes, and whatever the chosen PSP notes are worth beyond
//! it comes back as extra ESP notes under the same terms (the same service and
//! redeemable-after day). That change is ESP, not PSP: it can be spent only like
//! any other ESP for that service. The wallet therefore picks the PSP notes with
//! the smallest total that covers the amount, which is the amount itself
//! whenever some set of its notes adds up to it.

use mint_types::{Amount, MintInput, melt_sighash};
use secp256k1::{Keypair, SECP256K1, XOnlyPublicKey};

use esp_mint::exchange::{self, ExchangeRequest, ExchangeResponse, MAX_ITEMS};
use esp_mint::units::ESP_PER_PSP;

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{Kind, PendingExchange, StoredNote, StoredTerms, Wallet};

/// How many search steps to spend looking for a tighter cover than the quick one.
const SEARCH_BUDGET: u32 = 100_000;

#[derive(Debug, Clone)]
pub struct ExchangeBuild {
    /// The request hash, which names this exchange in the wallet and at the mint.
    pub id: String,
    pub request: ExchangeRequest,
    /// PSP spent, which is the full value of the notes chosen.
    pub psp_spent: u64,
    /// ESP units that come back as change: the PSP spent beyond the amount asked
    /// for, times 10^12. Zero when the notes added up exactly.
    pub change_esp: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishResult {
    /// The ids of the new ESP notes, change included.
    pub notes: Vec<String>,
    /// All the ESP received.
    pub esp_units: u128,
    /// The part of `esp_units` that is change.
    pub change_esp: u128,
    pub redeemable_after_day: u64,
}

/// The indexes of the notes with the smallest total that is at least `need`, or
/// `None` if all of them together are not enough. `amounts` is sorted largest
/// first. An exact set is found whenever one exists, because the amounts are
/// powers of two. Otherwise the result is the tightest cover found within a
/// fixed search budget, and always a valid one.
fn pick_cover(amounts: &[u64], need: u64) -> Option<Vec<usize>> {
    let total: u128 = amounts.iter().map(|&a| u128::from(a)).sum();
    let need = u128::from(need);
    if total < need {
        return None;
    }
    // Largest first, taking each note that still fits. With powers of two this
    // reaches the amount exactly if any set can.
    let mut rest = need;
    let mut greedy = Vec::new();
    for (i, &a) in amounts.iter().enumerate() {
        if u128::from(a) <= rest {
            rest -= u128::from(a);
            greedy.push(i);
        }
    }
    if rest == 0 {
        return Some(greedy);
    }
    // Otherwise start from two quick covers: the greedy set plus the smallest note
    // left over (every note left over is bigger than what is still missing), and
    // the single smallest note that covers the whole amount.
    let mut best: Option<(u128, Vec<usize>)> = None;
    let mut consider = |sum: u128, set: Vec<usize>| {
        if best.as_ref().is_none_or(|(b, _)| sum < *b) {
            best = Some((sum, set));
        }
    };
    if let Some(extra) = (0..amounts.len()).rev().find(|i| !greedy.contains(i)) {
        let mut set = greedy.clone();
        set.push(extra);
        let sum = set.iter().map(|&i| u128::from(amounts[i])).sum();
        consider(sum, set);
    }
    if let Some(single) = (0..amounts.len()).rev().find(|&i| u128::from(amounts[i]) >= need) {
        consider(u128::from(amounts[single]), vec![single]);
    }
    let (best_sum, best_set) = best?;

    // Then look for a tighter one, within a budget.
    let mut suffix = vec![0u128; amounts.len() + 1];
    for i in (0..amounts.len()).rev() {
        suffix[i] = suffix[i + 1] + u128::from(amounts[i]);
    }
    let mut budget = SEARCH_BUDGET;
    let mut current = Vec::new();
    fn walk(
        amounts: &[u64],
        suffix: &[u128],
        need: u128,
        i: usize,
        sum: u128,
        current: &mut Vec<usize>,
        best: &mut (u128, Vec<usize>),
        budget: &mut u32,
    ) {
        if *budget == 0 || best.0 == need {
            return;
        }
        *budget -= 1;
        if sum >= need {
            if sum < best.0 {
                *best = (sum, current.clone());
            }
            return;
        }
        if i == amounts.len() || sum + suffix[i] < need || sum >= best.0 {
            return;
        }
        current.push(i);
        walk(amounts, suffix, need, i + 1, sum + u128::from(amounts[i]), current, best, budget);
        current.pop();
        walk(amounts, suffix, need, i + 1, sum, current, best, budget);
    }
    let mut found = (best_sum, best_set);
    walk(amounts, &suffix, need, 0, 0, &mut current, &mut found, &mut budget);
    Some(found.1)
}

impl Wallet {
    /// Build an exchange that gives `service` at least `psp_units` PSP of ESP.
    ///
    /// The smallest exchange is 1 PSP. `esp_amounts` splits the amount asked for
    /// into notes, and must add up to `psp_units * 10^12`. Without it that part
    /// is one note, which fits only up to 18,446,744 PSP.
    ///
    /// The wallet spends the full value of the PSP notes it picks. Anything
    /// beyond `psp_units` comes back as extra ESP notes under the same terms (see
    /// the module docs), so the request always matches the mint's exact rule.
    ///
    /// The PSP notes are reserved until the exchange is finished or cancelled.
    pub fn build_exchange(
        &mut self,
        psp_units: u64,
        service: XOnlyPublicKey,
        esp_amounts: Option<&[u64]>,
    ) -> Result<ExchangeBuild, WalletError> {
        if psp_units == 0 {
            return Err(WalletError::Invalid(
                "the smallest exchange is 1 PSP (10^12 ESP)".into(),
            ));
        }
        let target = u128::from(psp_units) * u128::from(ESP_PER_PSP);
        let mut amounts: Vec<u64> = match esp_amounts {
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

        let mut candidates: Vec<&StoredNote> = self
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Psp && n.reserved_by.is_none())
            .collect();
        candidates.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.id().cmp(&b.id())));
        let sizes: Vec<u64> = candidates.iter().map(|n| n.amount).collect();
        let Some(picked) = pick_cover(&sizes, psp_units) else {
            let held: u128 = sizes.iter().map(|&a| u128::from(a)).sum();
            return Err(WalletError::NotEnough(format!(
                "{psp_units} PSP needed, {held} PSP free to spend"
            )));
        };
        let mut picked = picked;
        picked.sort_unstable();
        let chosen: Vec<StoredNote> = picked.iter().map(|&i| candidates[i].clone()).collect();
        let psp_spent: u64 = chosen
            .iter()
            .try_fold(0u64, |sum, n| sum.checked_add(n.amount))
            .ok_or_else(|| WalletError::Invalid("amounts are too large".into()))?;

        // The rest of the chosen notes' value comes back as ESP under the same
        // terms. Each piece fits one note, so a very large change is split.
        let change_esp = u128::from(psp_spent - psp_units) * u128::from(ESP_PER_PSP);
        let mut left = change_esp;
        while left > 0 {
            let piece = u64::try_from(left).unwrap_or(u64::MAX);
            amounts.push(piece);
            left -= u128::from(piece);
        }
        if chosen.len() > MAX_ITEMS || amounts.len() > MAX_ITEMS {
            return Err(WalletError::Invalid(format!(
                "that would take more than {MAX_ITEMS} PSP notes or ESP notes"
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
            change_esp,
        };
        self.update(|d| {
            for note in d.notes.iter_mut().filter(|n| input_ids.contains(&n.id())) {
                note.reserved_by = Some(id.clone());
            }
            d.pending_exchanges.push(pending);
            Ok(())
        })?;
        Ok(ExchangeBuild {
            id,
            request,
            psp_spent,
            change_esp,
        })
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
            change_esp: pending.change_esp,
            redeemable_after_day: response.redeemable_after_day,
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

    fn output_amounts(built: &ExchangeBuild) -> Vec<u64> {
        built.request.outputs.iter().map(|o| o.amount.units).collect()
    }

    /// The mint's rule, checked here on what the wallet builds.
    fn assert_exact(built: &ExchangeBuild) {
        let psp: u128 = built.request.psp_inputs.iter().map(|i| u128::from(i.amount.units)).sum();
        let esp: u128 = output_amounts(built).iter().map(|&a| u128::from(a)).sum();
        assert_eq!(psp * u128::from(ESP_PER_PSP), esp);
        assert_eq!(u128::from(built.psp_spent), psp);
    }

    #[test]
    fn the_request_always_asks_for_the_full_value_of_the_psp_it_spends() {
        // an exact set exists: no change
        let (mut w, dir) = wallet_with("full-exact", &[1, 4, 2, 8]);
        let built = w.build_exchange(7, service(), None).unwrap();
        assert_exact(&built);
        assert_eq!(built.change_esp, 0);
        assert_eq!(output_amounts(&built), vec![7_000_000_000_000]);
        fs::remove_dir_all(&dir).unwrap();

        // 5 from 8 + 2 + 2: the single 8 is the tightest cover, 3 PSP comes back as ESP
        let (mut w, dir) = wallet_with("full-change", &[8, 2, 2]);
        let built = w.build_exchange(5, service(), None).unwrap();
        assert_exact(&built);
        let spent: Vec<u64> = built.request.psp_inputs.iter().map(|i| i.amount.units).collect();
        assert_eq!(spent, vec![8]);
        assert_eq!(built.psp_spent, 8);
        assert_eq!(built.change_esp, 3_000_000_000_000);
        assert_eq!(output_amounts(&built), vec![5_000_000_000_000, 3_000_000_000_000]);
        assert_eq!(w.pending_exchanges()[0].change_esp, 3_000_000_000_000);
        fs::remove_dir_all(&dir).unwrap();

        // 5 from 4 + 4: both are spent, 3 comes back
        let (mut w, dir) = wallet_with("full-two", &[4, 4]);
        let built = w.build_exchange(5, service(), None).unwrap();
        assert_exact(&built);
        assert_eq!(built.psp_spent, 8);
        assert_eq!(output_amounts(&built), vec![5_000_000_000_000, 3_000_000_000_000]);
        // an asked-for split keeps its notes and the change is added after them
        w.cancel_exchange(&built.id).unwrap();
        let split = w
            .build_exchange(5, service(), Some(&[2_000_000_000_000, 3_000_000_000_000]))
            .unwrap();
        assert_exact(&split);
        assert_eq!(
            output_amounts(&split),
            vec![2_000_000_000_000, 3_000_000_000_000, 3_000_000_000_000]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_cover_is_the_smallest_the_wallet_can_find() {
        let sizes = |list: &[u64]| {
            let mut v = list.to_vec();
            v.sort_by(|a, b| b.cmp(a));
            v
        };
        let total = |amounts: &[u64], picked: &[usize]| -> u64 { picked.iter().map(|&i| amounts[i]).sum() };
        for (held, need, best) in [
            (&[8u64, 2, 2][..], 5u64, 8u64),
            (&[4, 4][..], 5, 8),
            (&[1, 4, 2, 8][..], 7, 7),
            (&[16, 4, 4, 1][..], 9, 9),
            (&[16, 4, 4][..], 9, 16),
            (&[2, 2, 2, 2][..], 5, 6),
            (&[1024][..], 1, 1024),
        ] {
            let held = sizes(held);
            let picked = pick_cover(&held, need).unwrap();
            assert_eq!(total(&held, &picked), best, "{held:?} for {need}");
        }
        assert!(pick_cover(&sizes(&[4, 4]), 9).is_none());
        assert!(pick_cover(&[], 1).is_none());
    }

    #[test]
    fn an_exchange_with_not_enough_psp_or_below_the_minimum_is_refused_before_anything_is_reserved() {
        let (mut w, dir) = wallet_with("exact", &[4, 4]);
        // 9 is more than is held
        assert!(matches!(w.build_exchange(9, service(), None), Err(WalletError::NotEnough(_))));
        // the smallest exchange is 1 PSP
        let err = w.build_exchange(0, service(), None).unwrap_err();
        assert!(err.to_string().contains("smallest exchange is 1 PSP"), "{err}");
        assert_eq!(w.balance().reserved, 0);
        assert!(w.pending_exchanges().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_asked_for_split_must_add_up_exactly() {
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
