//! The automatic rollover of PSP and ESP when their mint rotates its keys, and
//! the swap schedule that FSP shares.
//!
//! A mint keeps two key sets, current and previous. Notes on the previous set
//! are swapped (rolled over) for notes of exactly the same amounts, and for ESP
//! the same service and day, on the current set: `POST /rollover` at psp-mint
//! or esp-mint. The wallet learns the schedule from the mint's public
//! `GET /rotation`.
//!
//! **Staggered.** Each rotation gets one random swap time per mint, drawn once
//! in `(start of the current set, + min(0.5% of the period, 72 h)]` (never at the
//! start itself: a wallet that connects the second a set starts still waits) and kept in
//! the wallet file (`swap_schedule`) until the swap is done, so all wallets do
//! not swap in the same minute. The time is deleted in the same atomic write
//! that records the rolled-over notes, and the whole entry is deleted when the
//! old set retires. No history of swap times is kept, and they are never
//! logged: they would say when this wallet was online.
//!
//! **Which notes.** A note's epoch is recorded when it comes out of a rollover.
//! A note with no recorded epoch is treated as on the previous set when there
//! is one (a rollover of a current-set note is accepted by the mint, so the
//! worst case is one swap too many), and stamped with the current epoch when
//! there is only one set. A note on a set older than the previous one is lost
//! and moved to `lost`.
//!
//! **Crash-safe.** A rollover is stored (notes reserved) before it is sent and
//! is sent again, unchanged, until the mint answers; the mint keeps its answer
//! by request hash.

use rand::Rng;
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};

use crate::blind::PendingOutput;
use crate::config::Party;
use crate::error::WalletError;
use crate::store::{Kind, StoredNote, StoredTerms, Wallet};

/// 0.5% of the period, in parts per million, and the 72-hour cap.
pub const STAGGER_SPREAD_PPM: u64 = 5_000;
pub const STAGGER_CAP_SECS: u64 = 72 * 3600;

/// The stagger window for a rotation period.
pub fn stagger_window(period_secs: u64) -> u64 {
    ((period_secs as u128 * STAGGER_SPREAD_PPM as u128 / 1_000_000) as u64).min(STAGGER_CAP_SECS)
}

/// A fresh random delay in the stagger window: from 1 second to the whole
/// window, or 0 when the window is under a second. It is never 0 for a real
/// window, so "staggered after the rotation" is always true: a swap time equal
/// to the start of the set would let a wallet that connects at that second swap
/// at once, with nothing staggered about it.
pub fn random_delay(period_secs: u64) -> u64 {
    let w = stagger_window(period_secs);
    if w == 0 {
        0
    } else {
        rand::thread_rng().gen_range(1..=w)
    }
}

/// The schedule key of a rotation.
pub fn schedule_key(kind: Kind, record: &str, keyset: &str) -> String {
    format!("{}|{record}|{keyset}", kind_name(kind))
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Psp => "psp",
        Kind::Esp => "esp",
        Kind::Fsp => "fsp",
    }
}

/// The schedule prefix of one mint.
pub fn schedule_prefix(kind: Kind, record: &str) -> String {
    format!("{}|{record}|", kind_name(kind))
}

/// A rollover stored before it is sent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRollover {
    /// The request hash, as the mint keys its answer.
    pub id: String,
    pub kind: Kind,
    pub record: String,
    /// The JSON body sent to `POST /rollover`.
    pub body: serde_json::Value,
    pub inputs: Vec<String>,
    pub outputs: Vec<PendingOutput>,
    pub terms: Option<StoredTerms>,
    /// The schedule entry this rollover belongs to.
    pub schedule: String,
}

/// What the mint's `/rotation` says, as the wallet needs it.
#[derive(Clone, Debug)]
pub struct Window {
    pub current_epoch: u64,
    pub current_id: String,
    pub current_starts: Option<u64>,
    pub previous_epoch: Option<u64>,
    pub previous_id: Option<String>,
    pub period_hours: u64,
    pub now: u64,
}

impl From<sp_wire::fsp::RotationResponse> for Window {
    /// The window a mint's `GET /rotation` body describes, however it came (over
    /// HTTP, or as the signed body of a reply over AIR).
    fn from(w: sp_wire::fsp::RotationResponse) -> Self {
        Window {
            current_epoch: w.current.epoch,
            current_id: w.current.id,
            current_starts: w.current.starts,
            previous_epoch: w.previous.as_ref().map(|p| p.epoch),
            previous_id: w.previous.map(|p| p.id),
            period_hours: w.rotation_period_hours,
            now: w.now,
        }
    }
}

impl Wallet {
    pub fn pending_rollovers(&self) -> &[crate::rotate::PendingRollover] {
        &self.data().pending_rollovers
    }

    pub fn lost(&self) -> &[StoredNote] {
        &self.data().lost
    }

    pub fn swap_schedule_len(&self) -> usize {
        self.data().swap_schedule.len()
    }

    /// The keyset a PSP or ESP note names in a request: the one recorded
    /// when the wallet stored it. A note without one is refused with a clear
    /// error; the wallet never guesses (by epoch or by the mint's live sets).
    pub fn recorded_keyset(&self, note: &StoredNote) -> Result<String, WalletError> {
        match self.data().keysets.get(&note.id()) {
            Some(k) if !k.is_empty() => Ok(k.clone()),
            _ => Err(WalletError::Invalid(format!(
                "note {} has no recorded keyset, so it cannot be spent: the wallet no longer guesses a keyset (receive it again from a handover or token that names its keyset)",
                note.id()
            ))),
        }
    }

    /// The keyset a PSP or ESP note names in a rollover (the recorded one).
    pub fn keyset_for(&self, note: &StoredNote, _w: &Window) -> Result<String, WalletError> {
        self.recorded_keyset(note)
    }

    /// The keyset a PSP note names when it is spent (the recorded one).
    pub fn psp_keyset_of(&self, note: &StoredNote) -> Result<String, WalletError> {
        self.recorded_keyset(note)
    }

    /// The keyset an ESP note names when it is spent (the recorded one, from
    /// the reply that signed it or the handover that brought it).
    pub fn esp_keyset_of(&self, note: &StoredNote) -> Result<String, WalletError> {
        self.recorded_keyset(note)
    }

    /// The keyset new ESP outputs ask to be signed by: the ESP mint's current
    /// keyset as last seen, or empty if unknown (refused as `missing_keyset`,
    /// nothing burned). The reply names the set that actually signed, and
    /// that is what is recorded.
    pub fn esp_output_keyset(&self) -> String {
        let live: Vec<_> = self.data().esp_live_keysets.values().collect();
        match live.as_slice() {
            [(current, _)] => current.clone(),
            _ => String::new(),
        }
    }

    /// Remember the ESP mint's live keysets.
    pub fn note_esp_keysets(
        &mut self,
        record: &str,
        current: &str,
        previous: Option<&str>,
    ) -> Result<(), WalletError> {
        let live = (current.to_string(), previous.map(str::to_string));
        if self.data().esp_live_keysets.get(record) == Some(&live) {
            return Ok(());
        }
        self.update(|d| {
            d.esp_live_keysets.clear();
            d.esp_live_keysets.insert(record.to_string(), live);
            Ok(())
        })
    }

    /// Record the keyset a mint's reply names for these notes. A reply that
    /// names none is refused with a `Mint` error and nothing is stored: a note
    /// is spent under its recorded keyset, so one with none could not be spent.
    /// (esp-mint always names it, `exchange.rs:829`.)
    pub fn record_keysets(&mut self, ids: &[String], keyset: &str) -> Result<(), WalletError> {
        if keyset.is_empty() {
            return Err(WalletError::Mint(
                "the mint's reply names no keyset; its notes cannot be stored".into(),
            ));
        }
        self.update(|d| {
            for id in ids {
                d.keysets.insert(id.clone(), keyset.to_string());
            }
            Ok(())
        })
    }

    /// Remember a mint's live keysets, as just read from `/rotation`.
    pub fn note_live_keysets(&mut self, record: &str, w: &Window) -> Result<(), WalletError> {
        let live = (w.current_id.clone(), w.previous_id.clone());
        if self.data().live_keysets.get(record) == Some(&live) {
            return Ok(());
        }
        self.update(|d| {
            d.live_keysets.insert(record.to_string(), live);
            Ok(())
        })
    }

    /// The recorded epoch of a note, if any.
    pub fn epoch_of(&self, note: &StoredNote) -> Option<u64> {
        self.data().epochs.get(&note.id()).copied()
    }

    /// Bring the wallet in line with a mint's window: mark lost notes, stamp
    /// unrecorded ones when there is only one set, and drop schedule entries
    /// of rotations that are over. Returns the free notes to roll over.
    pub fn prepare_rollover(
        &mut self,
        kind: Kind,
        record: &str,
        w: &Window,
    ) -> Result<Vec<StoredNote>, WalletError> {
        let prefix = schedule_prefix(kind, record);
        let current_key = schedule_key(kind, record, &w.current_id);
        let oldest_live = w.previous_epoch.unwrap_or(w.current_epoch);
        self.update(|d| {
            let (keep, lost): (Vec<StoredNote>, Vec<StoredNote>) =
                d.notes.drain(..).partition(|n| {
                    if n.kind != kind {
                        return true;
                    }
                    // A recorded keyset that is neither current nor previous
                    // was retired: the note expired.
                    if let Some(k) = d.keysets.get(&n.id()) {
                        return *k == w.current_id || Some(k) == w.previous_id.as_ref();
                    }
                    d.epochs.get(&n.id()).is_none_or(|e| *e >= oldest_live)
                });
            d.notes = keep;
            for n in &lost {
                d.epochs.remove(&n.id());
                d.keysets.remove(&n.id());
            }
            d.lost.extend(lost);
            if w.previous_epoch.is_none() {
                for n in d.notes.iter().filter(|n| n.kind == kind) {
                    d.epochs.entry(n.id()).or_insert(w.current_epoch);
                }
            }
            // A rotation that moved on, or an old set that retired: its swap
            // time goes.
            let pending: Vec<String> = d
                .pending_rollovers
                .iter()
                .map(|p| p.schedule.clone())
                .collect();
            d.swap_schedule.retain(|k, _| {
                !k.starts_with(&prefix)
                    || (k == &current_key && w.previous_epoch.is_some())
                    || pending.contains(k)
            });
            Ok(())
        })?;
        let Some(_) = w.previous_epoch else {
            return Ok(vec![]);
        };
        // Notes a stored swap of received notes (a handoff's) will swap are not
        // rolled over as well: one request or the other would be refused.
        let swapping: std::collections::BTreeSet<&String> = self
            .pending_rollovers()
            .iter()
            .filter(|p| p.schedule.starts_with(crate::handoff::SWAP_TAG))
            .flat_map(|p| p.inputs.iter())
            .collect();
        let old: Vec<StoredNote> = self
            .notes()
            .iter()
            .filter(|n| {
                n.kind == kind
                    && n.reserved_by.is_none()
                    && !swapping.contains(&n.id())
                    // A recorded keyset decides (a note signed by the current
                    // set after the rotation needs no rollover); else the epoch.
                    // Only a note with a recorded keyset is rolled over (no
                    // guessing); one signed by the current set needs none.
                    && match self.data().keysets.get(&n.id()) {
                        Some(k) => *k != w.current_id,
                        None => false,
                    }
            })
            .cloned()
            .collect();
        if old.is_empty()
            && !self
                .pending_rollovers()
                .iter()
                .any(|p| p.schedule == current_key)
        {
            self.update(|d| {
                d.swap_schedule.remove(&current_key);
                Ok(())
            })?;
        }
        Ok(old)
    }

    /// FSP: drop swap times of rotations that are over, and this one's when
    /// nothing is left to roll over.
    pub fn drop_fsp_schedule(
        &mut self,
        record: &str,
        current: &str,
        has_old: bool,
    ) -> Result<(), WalletError> {
        let prefix = schedule_prefix(Kind::Fsp, record);
        let key = schedule_key(Kind::Fsp, record, current);
        if !self
            .data()
            .swap_schedule
            .keys()
            .any(|k| k.starts_with(&prefix) && (k != &key || !has_old))
        {
            return Ok(());
        }
        self.update(|d| {
            d.swap_schedule
                .retain(|k, _| !k.starts_with(&prefix) || (k == &key && has_old));
            Ok(())
        })
    }

    /// This rotation's swap time: drawn once and kept until the swap is done.
    pub fn swap_time(&mut self, kind: Kind, record: &str, w: &Window) -> Result<u64, WalletError> {
        let key = schedule_key(kind, record, &w.current_id);
        if let Some(t) = self.data().swap_schedule.get(&key) {
            return Ok(*t);
        }
        let at = w
            .current_starts
            .unwrap_or(w.now)
            .saturating_add(random_delay(w.period_hours.saturating_mul(3600)));
        self.update(|d| {
            d.swap_schedule.insert(key, at);
            Ok(())
        })?;
        Ok(at)
    }

    /// Build and store the rollovers for `old` (one per 1000 notes, and for
    /// ESP one per service and day), reserving the notes.
    pub fn build_rollovers(
        &mut self,
        kind: Kind,
        record: &str,
        w: &Window,
        old: Vec<StoredNote>,
    ) -> Result<Vec<String>, WalletError> {
        let schedule = schedule_key(kind, record, &w.current_id);
        let mut groups: std::collections::BTreeMap<Option<(String, u64)>, Vec<StoredNote>> =
            Default::default();
        for n in old {
            let k = match (kind, n.terms) {
                (Kind::Esp, Some(t)) => {
                    Some((hex::encode(t.service.serialize()), t.redeemable_after_day))
                }
                _ => None,
            };
            groups.entry(k).or_default().push(n);
        }
        let mut built = Vec::new();
        for (_, notes) in groups {
            for chunk in notes.chunks(1000) {
                let outputs: Vec<PendingOutput> =
                    chunk.iter().map(|n| PendingOutput::new(n.amount)).collect();
                let mut inputs: Vec<mint_types::MintInput> = chunk
                    .iter()
                    .map(|n| mint_types::MintInput {
                        amount: mint_types::Amount::from_units(n.amount),
                        note: n.note,
                        spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64])
                            .expect("64 bytes"),
                    })
                    .collect();
                let mint_outputs: Vec<_> = outputs.iter().map(|o| o.mint_output()).collect();
                let terms = chunk[0].terms;
                let (id, body) = match kind {
                    Kind::Psp => {
                        let h = mint_types::transaction_sighash(&inputs, &mint_outputs);
                        for (i, n) in inputs.iter_mut().zip(chunk) {
                            i.spend_signature = SECP256K1.sign_schnorr(
                                &h,
                                &secp256k1::Keypair::from_secret_key(SECP256K1, &n.spend_secret),
                            );
                        }
                        let r = sp_wire::psp::RolloverRequest {
                            input_keysets: chunk
                                .iter()
                                .map(|n| self.keyset_for(n, w))
                                .collect::<Result<_, _>>()?,
                            inputs,
                            keyset: w.current_id.clone(),
                            outputs: mint_outputs,
                        };
                        (
                            r.hash(),
                            serde_json::to_value(&r)
                                .map_err(|e| WalletError::Invalid(e.to_string()))?,
                        )
                    }
                    Kind::Esp => {
                        let t = terms.ok_or_else(|| {
                            WalletError::Invalid("an ESP note without terms".into())
                        })?;
                        let mut r = sp_wire::esp::rollover::RolloverRequest {
                            service: t.service,
                            redeemable_after_day: t.redeemable_after_day,
                            input_keysets: chunk
                                .iter()
                                .map(|n| self.keyset_for(n, w))
                                .collect::<Result<_, _>>()?,
                            keyset: w.current_id.clone(),
                            inputs,
                            outputs: mint_outputs,
                        };
                        let h = r.digest();
                        for (i, n) in r.inputs.iter_mut().zip(chunk) {
                            i.spend_signature = SECP256K1.sign_schnorr(
                                &h,
                                &secp256k1::Keypair::from_secret_key(SECP256K1, &n.spend_secret),
                            );
                        }
                        (
                            r.hash(),
                            serde_json::to_value(&r)
                                .map_err(|e| WalletError::Invalid(e.to_string()))?,
                        )
                    }
                    Kind::Fsp => {
                        return Err(WalletError::Invalid(
                            "FSP rolls over through fsp_sync".into(),
                        ));
                    }
                };
                let ids: Vec<String> = chunk.iter().map(|n| n.id()).collect();
                let p = PendingRollover {
                    id: id.clone(),
                    kind,
                    record: record.to_string(),
                    body,
                    inputs: ids.clone(),
                    outputs,
                    terms: if kind == Kind::Esp { terms } else { None },
                    schedule: schedule.clone(),
                };
                self.update(|d| {
                    for n in d.notes.iter_mut().filter(|n| ids.contains(&n.id())) {
                        n.reserved_by = Some(id.clone());
                    }
                    d.pending_rollovers.push(p);
                    Ok(())
                })?;
                built.push(id);
            }
        }
        Ok(built)
    }

    /// The mint answered: record the new notes with their epoch, drop the
    /// inputs, and in the same write delete the swap time once no rollover of
    /// that rotation is left.
    ///
    /// **Before anything is stored** the keys are checked against what the mint
    /// published on AIR (see [`crate::keystream`]): for a PSP rollover, the PSP
    /// mint's key set; for an ESP rollover, the keys the ESP published for the
    /// note's own service and day in the new key set (a rollover keeps the day;
    /// the day window of a new exchange does not apply). On a mismatch nothing is
    /// stored, the rollover stays pending, a warning is printed, and the error is
    /// [`WalletError::KeyMismatch`].
    pub fn finish_rollover(
        &mut self,
        id: &str,
        epoch: u64,
        keyset: &str,
        signatures: &[secp256k1::PublicKey],
        keys: &[secp256k1::PublicKey],
    ) -> Result<(), WalletError> {
        let p = self
            .pending_rollovers()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending rollover {id}")))?;
        if signatures.len() != p.outputs.len() || keys.len() != p.outputs.len() {
            return Err(WalletError::Mint(
                "the rollover reply does not fit the request".into(),
            ));
        }
        // The shared key check, before anything is stored.
        let signed: Vec<(u64, secp256k1::PublicKey)> = p
            .outputs
            .iter()
            .zip(keys)
            .map(|(o, key)| (o.amount, *key))
            .collect();
        match (p.kind, p.terms) {
            (Kind::Psp, _) => self.check_keyset_keys(
                Party::Psp,
                crate::keystream::Site::FinishRollover,
                keyset,
                &signed,
            )?,
            (Kind::Esp, Some(terms)) => self.check_esp_day_keys(
                crate::keystream::Site::FinishRollover,
                keyset,
                &terms.service,
                terms.redeemable_after_day,
                &signed,
            )?,
            (Kind::Esp, None) => {
                return Err(WalletError::Invalid(format!(
                    "rollover {id} is an ESP rollover with no terms, so its keys cannot be checked"
                )));
            }
            (Kind::Fsp, _) => {
                return Err(WalletError::Invalid(
                    "FSP rolls over through fsp_sync".into(),
                ));
            }
        }
        self.update(|d| {
            d.notes.retain(|n| !p.inputs.contains(&n.id()));
            for i in &p.inputs {
                d.epochs.remove(i);
                d.keysets.remove(i);
            }
            for (k, o) in p.outputs.iter().enumerate() {
                let n = StoredNote {
                    kind: p.kind,
                    amount: o.amount,
                    note: o.unblind(&signatures[k], &keys[k]),
                    spend_secret: o.nonce_secret,
                    terms: p.terms,
                    reserved_by: None,
                };
                d.epochs.insert(n.id(), epoch);
                d.keysets.insert(n.id(), keyset.to_string());
                d.notes.push(n);
            }
            d.pending_rollovers.retain(|q| q.id != id);
            if !d.pending_rollovers.iter().any(|q| q.schedule == p.schedule) {
                d.swap_schedule.remove(&p.schedule);
            }
            // A swap back of a handed-off note ended the handoff, in this write.
            crate::handoff::settle_reclaim(d, &p.schedule, true);
            Ok(())
        })
    }

    /// The mint refused rollover `id` because the notes at `inputs` (positions
    /// in its `inputs`) are spent. Nothing was burned. Those notes go to the
    /// spent record, the others are free again, and the pending rollover is
    /// dropped, so the next rotation check does not offer the spent notes again.
    pub fn mark_spent_in_rollover(
        &mut self,
        id: &str,
        inputs: &[usize],
    ) -> Result<crate::esp::SpentReport, WalletError> {
        self.update(|d| {
            let pending = d
                .pending_rollovers
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no pending rollover {id}")))?;
            let count = pending.inputs.len();
            let schedule = pending.schedule.clone();
            if inputs.is_empty() || inputs.iter().any(|&i| i >= count) {
                return Err(WalletError::Invalid(format!(
                    "the mint named notes {inputs:?}, but the rollover has {count} notes"
                )));
            }
            let spent_ids: Vec<String> =
                inputs.iter().map(|&i| pending.inputs[i].clone()).collect();
            d.pending_rollovers.retain(|q| q.id != id);
            crate::handoff::settle_reclaim(d, &schedule, false);
            Ok(Wallet::retire_reserved(d, id, &spent_ids))
        })
    }

    /// The mint refused the rollover: free its notes. An id that is not a
    /// pending rollover is refused (`Unknown`) and nothing is written.
    pub fn cancel_rollover(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            let schedule = d
                .pending_rollovers
                .iter()
                .find(|q| q.id == id)
                .map(|q| q.schedule.clone())
                .ok_or_else(|| WalletError::Unknown(format!("no pending rollover {id}")))?;
            // A reclaim the mint refused leaves the handoff pending again.
            crate::handoff::settle_reclaim(d, &schedule, false);
            for n in d
                .notes
                .iter_mut()
                .filter(|n| n.reserved_by.as_deref() == Some(id))
            {
                n.reserved_by = None;
            }
            d.pending_rollovers.retain(|q| q.id != id);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::expect;

    /// Open a wallet file of the test network.
    fn open_wallet(path: &std::path::Path) -> Result<crate::Wallet, crate::WalletError> {
        crate::Wallet::open(path, "regtest")
    }

    /// The PSP's name in the wallet's records, as `main` makes it: its DID in
    /// lowercase hex.
    fn psp_record() -> String {
        let sk = secp256k1::SecretKey::from_slice(&[9; 32]).unwrap();
        crate::fsp::record_of(sp_wire::ServiceDid::from(
            sk.public_key(secp256k1::SECP256K1),
        ))
    }

    #[test]
    fn the_stagger_is_half_a_percent_capped_at_72_hours() {
        assert_eq!(stagger_window(8760 * 3600), 8760 * 36 / 2);
        assert_eq!(stagger_window(87600 * 3600), STAGGER_CAP_SECS);
        for _ in 0..100 {
            assert!(random_delay(8760 * 3600) <= 8760 * 18);
        }
        assert_eq!(random_delay(100), 0);
    }

    #[test]
    fn the_delay_is_never_zero_for_a_real_window() {
        // A 1-hour period has an 18-second window. If 0 could be drawn, about
        // one wallet in 19 would swap the second the set starts; 20,000 draws
        // would show a 0 with a chance of 1 - (18/19)^20000, which is certain.
        assert_eq!(stagger_window(3600), 18);
        for _ in 0..20_000 {
            let d = random_delay(3600);
            assert!((1..=18).contains(&d), "{d}");
        }
    }

    #[test]
    fn a_rollover_refused_for_a_spent_note_retires_it_and_frees_the_others() {
        use crate::store::WalletData;
        use secp256k1::Keypair;
        let note = || {
            let kp = Keypair::new(SECP256K1, &mut rand::rngs::OsRng);
            StoredNote {
                kind: Kind::Psp,
                amount: 1,
                note: mint_types::Note {
                    nonce: mint_types::Nonce(kp.public_key()),
                    signature: kp.public_key(),
                },
                spend_secret: kp.secret_key(),
                terms: None,
                reserved_by: Some("roll1".into()),
            }
        };
        let notes = vec![note(), note(), note()];
        let ids: Vec<String> = notes.iter().map(StoredNote::id).collect();
        let pending = PendingRollover {
            id: "roll1".into(),
            kind: Kind::Psp,
            record: psp_record(),
            body: serde_json::json!({}),
            inputs: ids.clone(),
            outputs: Vec::new(),
            terms: None,
            schedule: "s".into(),
        };
        let data = WalletData {
            network: "regtest".into(),
            notes,
            pending_rollovers: vec![pending],
            ..Default::default()
        };
        let path = std::env::temp_dir().join(format!("wallet-spent-roll-{}.json", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let mut w = open_wallet(&path).unwrap();
        // an index past the rollover changes nothing
        let e = expect::invalid(w.mark_spent_in_rollover("roll1", &[3]));
        assert!(
            e.contains("the mint named notes [3], but the rollover has 3 notes"),
            "{e}"
        );
        assert_eq!(w.pending_rollovers().len(), 1);
        let report = w.mark_spent_in_rollover("roll1", &[1]).unwrap();
        assert_eq!((report.marked_spent, report.freed), (1, 2));
        assert_eq!(w.spent_notes().len(), 1);
        assert_eq!(w.spent_notes()[0].id(), ids[1]);
        assert_eq!(w.notes().len(), 2);
        assert!(w.notes().iter().all(|n| n.reserved_by.is_none()));
        assert!(w.pending_rollovers().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_note_whose_recorded_keyset_retired_is_written_off_and_a_live_one_named() {
        use crate::store::WalletData;
        use secp256k1::{Keypair, SECP256K1};
        let note = |k: &str| {
            let kp = Keypair::new(SECP256K1, &mut rand::rngs::OsRng);
            (
                StoredNote {
                    kind: Kind::Psp,
                    amount: 1,
                    note: mint_types::Note {
                        nonce: mint_types::Nonce(kp.public_key()),
                        signature: kp.public_key(),
                    },
                    spend_secret: kp.secret_key(),
                    terms: None,
                    reserved_by: None,
                },
                k.to_string(),
            )
        };
        let (old, live) = (note("aaaaaaaaaaaaaaaa"), note("bbbbbbbbbbbbbbbb"));
        let path = std::env::temp_dir().join(format!("wallet-ks-{}.json", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        let data = WalletData {
            network: "regtest".into(),
            keysets: [(old.0.id(), old.1.clone()), (live.0.id(), live.1.clone())]
                .into_iter()
                .collect(),
            notes: vec![old.0.clone(), live.0.clone()],
            ..Default::default()
        };
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let mut w = open_wallet(&path).unwrap();
        let win = Window {
            current_epoch: 5,
            current_id: "cccccccccccccccc".into(),
            current_starts: Some(0),
            previous_epoch: Some(4),
            previous_id: Some("bbbbbbbbbbbbbbbb".into()),
            period_hours: 1,
            now: 0,
        };
        assert_eq!(w.keyset_for(&live.0, &win).unwrap(), "bbbbbbbbbbbbbbbb");
        w.prepare_rollover(Kind::Psp, "http://psp", &win).unwrap();
        assert_eq!(
            w.lost().len(),
            1,
            "the retired set's note is lost to expiry"
        );
        assert_eq!(w.lost()[0].id(), old.0.id());
        assert!(!w.data().keysets.contains_key(&old.0.id()));
        assert_eq!(w.notes().len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_request_ids_are_refused_and_change_nothing() {
        use crate::store::WalletData;
        use secp256k1::Keypair;
        use sp_wire::esp::redeem::Totals;
        let kp = Keypair::new(SECP256K1, &mut rand::rngs::OsRng);
        let held = StoredNote {
            kind: Kind::Psp,
            amount: 1,
            note: mint_types::Note {
                nonce: mint_types::Nonce(kp.public_key()),
                signature: kp.public_key(),
            },
            spend_secret: kp.secret_key(),
            terms: None,
            reserved_by: Some("roll1".into()),
        };
        let data = WalletData {
            network: "regtest".into(),
            pending_rollovers: vec![PendingRollover {
                id: "roll1".into(),
                kind: Kind::Psp,
                record: psp_record(),
                body: serde_json::json!({}),
                inputs: vec![held.id()],
                outputs: Vec::new(),
                terms: None,
                schedule: "s".into(),
            }],
            notes: vec![held],
            ..Default::default()
        };
        let path = std::env::temp_dir().join(format!(
            "wallet-unknown-ids-{}-{:?}.json",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let mut w = open_wallet(&path).unwrap();
        let state = |w: &Wallet| {
            (
                serde_json::to_value(w.snapshot()).unwrap(),
                std::fs::read(&path).unwrap(),
            )
        };
        let before = state(&w);

        let e = expect::unknown(w.finish_rollover("nope", 1, "k", &[], &[]));
        assert!(e.contains("no pending rollover nope"), "{e}");
        let e = expect::unknown(w.cancel_rollover("nope"));
        assert!(e.contains("no pending rollover nope"), "{e}");
        let e = expect::unknown(w.mark_spent_in_rollover("nope", &[0]));
        assert!(e.contains("no pending rollover nope"), "{e}");
        let totals = Totals {
            notes: vec![],
            accepted_esp: 0,
            rejected_esp: 0,
            fee_esp: 0,
            size_bytes: 0,
            fee_per_byte: 0,
            accepted_by_terms: vec![],
            rejected_by_terms: vec![],
        };
        let e = expect::unknown(w.rebuild_redemption("nope", &kp.secret_key(), &totals));
        assert!(e.contains("no pending redemption nope"), "{e}");
        let e = expect::unknown(w.refuse_redemption("nope", &[]));
        assert!(e.contains("no pending redemption nope"), "{e}");
        assert_eq!(state(&w), before, "no refused call changed the wallet");

        // a reply of the wrong size for the rollover that is there
        match w.finish_rollover("roll1", 1, "k", &[kp.public_key()], &[]) {
            Err(WalletError::Mint(m)) => assert!(m.contains("does not fit the request"), "{m}"),
            other => panic!("expected WalletError::Mint, got {other:?}"),
        }
        assert_eq!(state(&w), before, "the rollover is untouched");
        let _ = std::fs::remove_file(&path);
    }

    // ---- the key check at finish_rollover

    fn pk(n: u8) -> secp256k1::PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        secp256k1::SecretKey::from_slice(&bytes)
            .unwrap()
            .public_key(SECP256K1)
    }

    /// A wallet file with one pending rollover `roll1` of `kind` and `terms`, one
    /// input note and one output for each of `amounts`.
    fn rollover_wallet(kind: Kind, terms: Option<StoredTerms>, amounts: &[u64]) -> crate::Wallet {
        use crate::store::WalletData;
        use secp256k1::Keypair;
        let mut notes = Vec::new();
        let mut outputs = Vec::new();
        for &amount in amounts {
            let kp = Keypair::new(SECP256K1, &mut rand::rngs::OsRng);
            notes.push(StoredNote {
                kind,
                amount,
                note: mint_types::Note {
                    nonce: mint_types::Nonce(kp.public_key()),
                    signature: kp.public_key(),
                },
                spend_secret: kp.secret_key(),
                terms,
                reserved_by: Some("roll1".into()),
            });
            outputs.push(PendingOutput::new(amount));
        }
        let pending = PendingRollover {
            id: "roll1".into(),
            kind,
            record: psp_record(),
            body: serde_json::json!({}),
            inputs: notes.iter().map(StoredNote::id).collect(),
            outputs,
            terms,
            schedule: "s".into(),
        };
        let data = WalletData {
            network: "regtest".into(),
            notes,
            pending_rollovers: vec![pending],
            ..Default::default()
        };
        let path = std::env::temp_dir().join(format!("wallet-roll-keys-{}.json", {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }));
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let w = open_wallet(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        w
    }

    fn mismatch(r: Result<(), WalletError>) -> Box<crate::keystream::KeyMismatch> {
        match r {
            Err(WalletError::KeyMismatch(m)) => m,
            other => panic!("expected WalletError::KeyMismatch, got {other:?}"),
        }
    }

    /// A PSP rollover is stored only if the key set that signed is one the PSP
    /// published and every output's key is the key it published for that amount.
    #[test]
    fn a_psp_rollover_is_checked_against_the_published_key_set_before_it_is_stored() {
        use crate::keystream::{Failed, Site, testing};
        use sp_wire::air_request::stream::KeysetRecord;
        let published: std::collections::BTreeMap<u64, secp256k1::PublicKey> =
            [(1, pk(1)), (2, pk(2))].into_iter().collect();
        let id = KeysetRecord {
            epoch: 0,
            keys: published
                .iter()
                .map(|(a, k)| (sp_wire::Amount::from_units(*a), *k))
                .collect(),
        }
        .id();
        let sigs = [pk(30), pk(31)];

        // A wrong key for the output of 2: nothing is stored.
        let mut w = rollover_wallet(Kind::Psp, None, &[1, 2]);
        testing::publish_keyset(&mut w, "psp", "aa", 0, 0, &published);
        let before = testing::held(&w);
        let m = mismatch(w.finish_rollover("roll1", 1, &id, &sigs, &[pk(1), pk(9)]));
        assert_eq!((m.mint, m.site), ("PSP mint", Site::FinishRollover));
        assert_eq!(m.failed, Failed::Key { amount: 2 });
        assert_eq!(testing::held(&w), before);
        assert_eq!(w.pending_rollovers().len(), 1);

        // A key set the PSP has not published (yet): an error to retry, not a
        // mismatch, and nothing changes.
        let why = testing::retryable(w.finish_rollover(
            "roll1",
            1,
            "ffffffffffffffff",
            &sigs,
            &[pk(1), pk(2)],
        ));
        assert!(
            why.contains(&format!(
                "has not published key set ffffffffffffffff (its key sets: {id})"
            )),
            "{why}"
        );
        assert_eq!(testing::held(&w), before);

        // The published keys: stored, with the rollover gone.
        w.finish_rollover("roll1", 1, &id, &sigs, &[pk(1), pk(2)])
            .unwrap();
        assert!(w.pending_rollovers().is_empty());
        assert_eq!(w.notes().len(), 2);
    }

    /// An ESP rollover keeps the note's own day, which may be long past: it is
    /// checked against the 64 keys the ESP published for the service and that
    /// day, whatever the day is; the new-exchange window does not apply. A key
    /// published for another amount is no better than any other wrong key.
    #[test]
    fn an_esp_rollover_is_checked_against_the_keys_of_the_notes_own_day() {
        use crate::keystream::{Failed, Site, testing};
        let service = sp_wire::ServiceDid::from(pk(77));
        let terms = |day| StoredTerms {
            service,
            redeemable_after_day: day,
        };
        let generation = "1111111111111111";
        let day_keys: Vec<secp256k1::PublicKey> = (0..64u8).map(|i| pk(i + 100)).collect();
        // Day 100 is in 1970: far from any window a new exchange could have.
        let mut w = rollover_wallet(Kind::Esp, Some(terms(100)), &[1, 4]);
        testing::publish_control(&mut w, 0, 365, generation, None);
        testing::publish_day(&mut w, generation, &service, 100, day_keys.clone());
        let sigs = [pk(30), pk(31)];
        let before = testing::held(&w);

        // The key published for the amount 1 offered for the output of 4.
        let m = mismatch(w.finish_rollover("roll1", 1, generation, &sigs, &[pk(100), pk(100)]));
        assert_eq!((m.mint, m.site), ("ESP mint", Site::FinishRollover));
        assert_eq!(m.failed, Failed::Key { amount: 4 });
        assert_eq!(testing::held(&w), before);

        // A key set the ESP's control stream does not name (yet): retry.
        let why = testing::retryable(w.finish_rollover(
            "roll1",
            1,
            "2222222222222222",
            &sigs,
            &[pk(100), pk(102)],
        ));
        assert!(
            why.contains("has not published key set 2222222222222222 as a live key set"),
            "{why}"
        );
        assert_eq!(testing::held(&w), before);

        // The keys of 1 (index 0) and 4 (index 2) on day 100: stored.
        w.finish_rollover("roll1", 1, generation, &sigs, &[pk(100), pk(102)])
            .unwrap();
        assert!(w.pending_rollovers().is_empty());
        assert_eq!(w.notes().len(), 2);
        assert!(
            w.notes()
                .iter()
                .all(|n| n.terms.map(|t| t.redeemable_after_day) == Some(100))
        );

        // A rollover for a day the ESP has published nothing for (yet): an
        // error to retry, the rollover kept.
        let mut w = rollover_wallet(Kind::Esp, Some(terms(101)), &[1]);
        testing::publish_control(&mut w, 0, 365, generation, None);
        testing::publish_day(&mut w, generation, &service, 100, day_keys);
        let before = testing::held(&w);
        let why =
            testing::retryable(w.finish_rollover("roll1", 1, generation, &[pk(30)], &[pk(100)]));
        assert!(
            why.contains(&format!(
                "has not published the keys of this service for day 101 in key set {generation}"
            )),
            "{why}"
        );
        assert_eq!(testing::held(&w), before);
        assert_eq!(w.pending_rollovers().len(), 1);
    }
}
