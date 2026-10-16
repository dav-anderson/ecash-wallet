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
//! in `[start of the current set, + min(0.5% of the period, 72 h)]` and kept in
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
use crate::error::WalletError;
use crate::store::{Kind, StoredNote, StoredTerms, Wallet};

/// 0.5% of the period, in parts per million, and the 72-hour cap.
pub const STAGGER_SPREAD_PPM: u64 = 5_000;
pub const STAGGER_CAP_SECS: u64 = 72 * 3600;

/// The stagger window for a rotation period.
pub fn stagger_window(period_secs: u64) -> u64 {
    ((period_secs as u128 * STAGGER_SPREAD_PPM as u128 / 1_000_000) as u64).min(STAGGER_CAP_SECS)
}

/// A fresh random delay in the stagger window.
pub fn random_delay(period_secs: u64) -> u64 {
    let w = stagger_window(period_secs);
    if w == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=w)
    }
}

/// The schedule key of a rotation.
pub fn schedule_key(kind: Kind, url: &str, keyset: &str) -> String {
    format!("{}|{url}|{keyset}", kind_name(kind))
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Psp => "psp",
        Kind::Esp => "esp",
        Kind::Fsp => "fsp",
    }
}

/// The schedule prefix of one mint.
pub fn schedule_prefix(kind: Kind, url: &str) -> String {
    format!("{}|{url}|", kind_name(kind))
}

/// A rollover stored before it is sent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRollover {
    /// The request hash, as the mint keys its answer.
    pub id: String,
    pub kind: Kind,
    pub url: String,
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

    /// The keyset a PSP purchase names: the PSP mint's current keyset as last
    /// seen, or none if the wallet has not read one (the mint then signs with
    /// its current keyset, and the settlement names it).
    pub fn psp_output_keyset(&self) -> Option<String> {
        let live: Vec<_> = self.data().live_keysets.values().collect();
        match live.as_slice() {
            [(current, _)] => Some(current.clone()),
            _ => None,
        }
    }

    /// Remember the ESP mint's live keysets.
    pub fn note_esp_keysets(
        &mut self,
        url: &str,
        current: &str,
        previous: Option<&str>,
    ) -> Result<(), WalletError> {
        let live = (current.to_string(), previous.map(str::to_string));
        if self.data().esp_live_keysets.get(url) == Some(&live) {
            return Ok(());
        }
        self.update(|d| {
            d.esp_live_keysets.clear();
            d.esp_live_keysets.insert(url.to_string(), live);
            Ok(())
        })
    }

    /// Record the keyset a mint's reply names for these notes. An empty name
    /// (an old mint) records nothing.
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
    pub fn note_live_keysets(&mut self, url: &str, w: &Window) -> Result<(), WalletError> {
        let live = (w.current_id.clone(), w.previous_id.clone());
        if self.data().live_keysets.get(url) == Some(&live) {
            return Ok(());
        }
        self.update(|d| {
            d.live_keysets.insert(url.to_string(), live);
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
        url: &str,
        w: &Window,
    ) -> Result<Vec<StoredNote>, WalletError> {
        let prefix = schedule_prefix(kind, url);
        let current_key = schedule_key(kind, url, &w.current_id);
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
        let old: Vec<StoredNote> = self
            .notes()
            .iter()
            .filter(|n| {
                n.kind == kind
                    && n.reserved_by.is_none()
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
        url: &str,
        current: &str,
        has_old: bool,
    ) -> Result<(), WalletError> {
        let prefix = schedule_prefix(Kind::Fsp, url);
        let key = schedule_key(Kind::Fsp, url, current);
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
    pub fn swap_time(&mut self, kind: Kind, url: &str, w: &Window) -> Result<u64, WalletError> {
        let key = schedule_key(kind, url, &w.current_id);
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
        url: &str,
        w: &Window,
        old: Vec<StoredNote>,
    ) -> Result<Vec<String>, WalletError> {
        let schedule = schedule_key(kind, url, &w.current_id);
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
                    url: url.to_string(),
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
            .ok_or_else(|| WalletError::Invalid(format!("no rollover {id}")))?;
        if signatures.len() != p.outputs.len() || keys.len() != p.outputs.len() {
            return Err(WalletError::Mint(
                "the rollover reply does not fit the request".into(),
            ));
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
            if inputs.is_empty() || inputs.iter().any(|&i| i >= count) {
                return Err(WalletError::Invalid(format!(
                    "the mint named notes {inputs:?}, but the rollover has {count} notes"
                )));
            }
            let spent_ids: Vec<String> =
                inputs.iter().map(|&i| pending.inputs[i].clone()).collect();
            d.pending_rollovers.retain(|q| q.id != id);
            Ok(Wallet::retire_reserved(d, id, &spent_ids))
        })
    }

    /// The mint refused the rollover: free its notes.
    pub fn cancel_rollover(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
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
            url: "http://127.0.0.1:1".into(),
            body: serde_json::json!({}),
            inputs: ids.clone(),
            outputs: Vec::new(),
            terms: None,
            schedule: "s".into(),
        };
        let data = WalletData {
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
        let mut w = Wallet::open(&path).unwrap();
        // an index past the rollover changes nothing
        assert!(w.mark_spent_in_rollover("roll1", &[3]).is_err());
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
            keysets: [(old.0.id(), old.1.clone()), (live.0.id(), live.1.clone())]
                .into_iter()
                .collect(),
            notes: vec![old.0.clone(), live.0.clone()],
            ..Default::default()
        };
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let mut w = Wallet::open(&path).unwrap();
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
}
