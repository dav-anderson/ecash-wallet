//! Reconciling two copies of one wallet.
//!
//! Every wallet is meant to be kept in two places: locally, to pay for reads and
//! writes, and in the AIR, for redundancy and recovery. After a handoff to a new
//! device the two differ: the local copy holds the starter notes, and the stored
//! one holds everything else. [`merge`] makes one wallet of two copies, and
//! [`Wallet::merge_from`] applies it. The merged copy is meant to be saved to
//! both places; its [`WalletData::version`] is above both inputs'.
//!
//! The rules:
//!
//! - **Notes are united by identity** (the nonce). A note is in the result if
//!   either copy holds it, unless it has left the wallet in either copy.
//! - **A note spent in either copy is spent.** A spent note is no longer in
//!   `notes`, so absence alone cannot tell "spent" from "never had": the
//!   wallet keeps ledgers (`departed` and `returned`, see [`WalletData`]) that
//!   `update` maintains, and the merge takes the larger count from each copy.
//!   A note also counts as spent if either copy lists it as spent elsewhere,
//!   lost, handed over, sent in a token or held in a pending handoff. A note
//!   that came back (a cancelled handoff) has `returned` equal to `departed`
//!   and is not spent.
//! - **Requests are united by id**, once each. A request that has ended in
//!   either copy (`finished`) is not brought back as pending by the other.
//!   A note is held by a pending request if either copy says so, and is free
//!   again if the request is not pending any more.
//! - **Everything keyed by a note or a mint** (key sets, epochs, the mints and
//!   key sets last seen, the swap schedule) is united; where both have an entry
//!   the local copy's is kept, because it is the one in use.
//!
//! The merge is a pure function of the two copies, does not change either, and
//! gives the same result when run again on its own output.
//!
//! What it cannot do: tell that a note in the stored copy was spent by a copy
//! that no longer exists (a device lost before it was stored). Such a note is
//! found spent when it is next used, as always. A wallet file from before this
//! version has no ledgers; it is merged as if nothing had ever left it.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::WalletError;
use crate::handoff::{HandoffState, OutgoingHandoff};
use crate::send::{SentState, SentToken};
use crate::store::{StoredNote, Wallet, WalletData, has_departed};

/// What a merge did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// The merged copy's write counter.
    pub version: u64,
    /// Notes the merged copy has that the local copy lacked.
    pub notes_added: usize,
    /// Notes the local copy had that the stored copy shows spent, so they are
    /// gone from the result.
    pub notes_removed: usize,
    /// Pending requests the merged copy has that the local copy lacked.
    pub requests_added: usize,
    /// Pending requests the local copy had that the stored copy had ended, so
    /// they are not pending any more.
    pub requests_dropped: usize,
}

impl MergeReport {
    /// Whether the merge changed the notes or the pending requests of the local
    /// copy. (It may still add map entries, such as mints last seen.)
    pub fn changed(&self) -> bool {
        self.notes_added + self.notes_removed + self.requests_added + self.requests_dropped > 0
    }
}

fn max_counts(a: &BTreeMap<String, u32>, b: &BTreeMap<String, u32>) -> BTreeMap<String, u32> {
    let mut out = a.clone();
    for (k, v) in b {
        let e = out.entry(k.clone()).or_insert(0);
        *e = (*e).max(*v);
    }
    out
}

/// The local entries, then the other copy's that the local lacks.
fn union_map<V: Clone>(a: &BTreeMap<String, V>, b: &BTreeMap<String, V>) -> BTreeMap<String, V> {
    let mut out = a.clone();
    for (k, v) in b {
        out.entry(k.clone()).or_insert_with(|| v.clone());
    }
    out
}

/// The local items, then the other copy's whose key the local lacks, leaving
/// out any whose key is in `skip`.
fn union_list<T: Clone>(
    a: &[T],
    b: &[T],
    key: impl Fn(&T) -> String,
    skip: &BTreeSet<String>,
) -> Vec<T> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in a.iter().chain(b) {
        let k = key(item);
        if skip.contains(&k) || !seen.insert(k) {
            continue;
        }
        out.push(item.clone());
    }
    out
}

fn sent_rank(t: &SentToken) -> u8 {
    match t.state {
        SentState::Pending => 0,
        SentState::Reclaiming { .. } => 1,
        SentState::Conflict { .. } => 2,
        SentState::Received | SentState::Reclaimed => 3,
    }
}

fn pending_request_ids(d: &WalletData, handoffs: &[OutgoingHandoff]) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    ids.extend(d.pending_purchases.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_exchanges.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_transfers.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_redemptions.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_fsp.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_rollovers.iter().map(|p| p.id.clone()));
    ids.extend(
        handoffs
            .iter()
            .filter(|h| h.state == HandoffState::Pending)
            .map(|h| h.id.clone()),
    );
    ids
}

/// Note ids a copy records as no longer in its active notes, other than through
/// the ledgers: spent elsewhere, lost, handed over, sent in a token.
fn listed_gone(d: &WalletData) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    ids.extend(d.spent.iter().map(StoredNote::id));
    ids.extend(d.lost.iter().map(StoredNote::id));
    ids.extend(d.lost_fsp.iter().map(StoredNote::id));
    for h in &d.handovers {
        ids.extend(
            h.notes
                .iter()
                .map(|n| hex::encode(n.note.nonce.0.serialize())),
        );
    }
    for t in &d.sent {
        ids.extend(t.notes.iter().map(StoredNote::id));
    }
    ids
}

/// Make one wallet of `local` and `stored`. Neither is changed.
pub fn merge(local: &WalletData, stored: &WalletData) -> (WalletData, MergeReport) {
    let mut m = local.clone();

    // The ledgers first: everything else is decided by them.
    m.departed = max_counts(&local.departed, &stored.departed);
    m.returned = max_counts(&local.returned, &stored.returned);
    m.finished = local.finished.union(&stored.finished).cloned().collect();

    // Handoffs this wallet made: a done one wins, a cancelled one (in
    // `finished`) is not brought back.
    let mut handoffs: Vec<OutgoingHandoff> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    for h in local.handoffs_out.iter().chain(&stored.handoffs_out) {
        if !ids.contains(&h.id) {
            ids.push(h.id.clone());
        }
    }
    for id in ids {
        let copies: Vec<&OutgoingHandoff> = local
            .handoffs_out
            .iter()
            .chain(&stored.handoffs_out)
            .filter(|h| h.id == id)
            .collect();
        if let Some(done) = copies.iter().find(|h| h.state == HandoffState::Done) {
            handoffs.push((*done).clone());
        } else if !m.finished.contains(&id) {
            handoffs.push(copies[0].clone());
        }
    }
    m.handoffs_out = handoffs;

    // Which notes are gone: the ledgers, and what either copy lists as gone
    // (a pending handoff counts only if it survived above).
    let mut gone = listed_gone(local);
    gone.extend(listed_gone(stored));
    for h in &m.handoffs_out {
        gone.extend(h.notes.iter().map(StoredNote::id));
    }
    let is_gone = |id: &str, d: &WalletData| has_departed(d, id) || gone.contains(id);

    let local_ids: BTreeSet<String> = local.notes.iter().map(StoredNote::id).collect();
    let mut notes: Vec<StoredNote> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut removed = 0usize;
    for n in local.notes.iter().chain(&stored.notes) {
        let id = n.id();
        if !seen.insert(id.clone()) {
            continue;
        }
        if is_gone(&id, &m) {
            if local_ids.contains(&id) {
                removed += 1;
            }
            continue;
        }
        let mut note = n.clone();
        if note.reserved_by.is_none() {
            note.reserved_by = stored
                .notes
                .iter()
                .find(|s| s.id() == id)
                .and_then(|s| s.reserved_by.clone());
        }
        notes.push(note);
    }
    m.notes = notes;

    // Requests, once each, and none that has ended.
    let skip = &m.finished;
    m.pending_purchases = union_list(
        &local.pending_purchases,
        &stored.pending_purchases,
        |p| p.id.clone(),
        skip,
    );
    m.pending_exchanges = union_list(
        &local.pending_exchanges,
        &stored.pending_exchanges,
        |p| p.id.clone(),
        skip,
    );
    m.pending_transfers = union_list(
        &local.pending_transfers,
        &stored.pending_transfers,
        |p| p.id.clone(),
        skip,
    );
    m.pending_redemptions = union_list(
        &local.pending_redemptions,
        &stored.pending_redemptions,
        |p| p.id.clone(),
        skip,
    );
    m.pending_fsp = union_list(
        &local.pending_fsp,
        &stored.pending_fsp,
        |p| p.id.clone(),
        skip,
    );
    m.pending_rollovers = union_list(
        &local.pending_rollovers,
        &stored.pending_rollovers,
        |p| p.id.clone(),
        skip,
    );

    // A note is held only by a request that is still pending.
    let pending = pending_request_ids(&m, &m.handoffs_out);
    for n in &mut m.notes {
        if n.reserved_by.as_ref().is_some_and(|r| !pending.contains(r)) {
            n.reserved_by = None;
        }
    }

    // Records. A done handoff in `handoffs_out` was chosen above.
    m.handoffs_in = union_list(
        &local.handoffs_in,
        &stored.handoffs_in,
        |h| h.id.clone(),
        &BTreeSet::new(),
    );
    let mut handovers = local.handovers.clone();
    for h in &stored.handovers {
        if !handovers.contains(h) {
            handovers.push(h.clone());
        }
    }
    m.handovers = handovers;
    let mut sent = union_list(
        &local.sent,
        &stored.sent,
        |t| t.id.clone(),
        &BTreeSet::new(),
    );
    for t in &mut sent {
        if let Some(other) = stored.sent.iter().find(|o| o.id == t.id) {
            if sent_rank(other) > sent_rank(t) {
                *t = other.clone();
            }
        }
    }
    m.sent = sent;
    m.spent = union_list(
        &local.spent,
        &stored.spent,
        StoredNote::id,
        &BTreeSet::new(),
    );
    m.lost = union_list(&local.lost, &stored.lost, StoredNote::id, &BTreeSet::new());
    m.lost_fsp = union_list(
        &local.lost_fsp,
        &stored.lost_fsp,
        StoredNote::id,
        &BTreeSet::new(),
    );
    let mut bad = local.bad_proof.clone();
    for id in &stored.bad_proof {
        if !bad.contains(id) {
            bad.push(id.clone());
        }
    }
    m.bad_proof = bad;

    // What is kept about a note is kept for the notes the result holds or may
    // get back (lost, or in a pending handoff or token).
    let mut keep: BTreeSet<String> = m.notes.iter().map(StoredNote::id).collect();
    keep.extend(m.lost.iter().map(StoredNote::id));
    keep.extend(m.lost_fsp.iter().map(StoredNote::id));
    for h in &m.handoffs_out {
        keep.extend(h.notes.iter().map(StoredNote::id));
    }
    for t in &m.sent {
        keep.extend(t.notes.iter().map(StoredNote::id));
    }
    let only = |map: BTreeMap<String, String>| -> BTreeMap<String, String> {
        map.into_iter().filter(|(k, _)| keep.contains(k)).collect()
    };
    m.keysets = only(union_map(&local.keysets, &stored.keysets));
    m.fsp_keysets = only(union_map(&local.fsp_keysets, &stored.fsp_keysets));
    m.epochs = union_map(&local.epochs, &stored.epochs)
        .into_iter()
        .filter(|(k, _)| keep.contains(k))
        .collect();
    m.bad_proof.retain(|id| keep.contains(id));

    // Where the mints are and what they last said.
    m.fsp_mints = union_map(&local.fsp_mints, &stored.fsp_mints);
    m.live_keysets = union_map(&local.live_keysets, &stored.live_keysets);
    m.esp_live_keysets = union_map(&local.esp_live_keysets, &stored.esp_live_keysets);
    m.swap_schedule = union_map(&local.swap_schedule, &stored.swap_schedule);
    if m.reply_did.is_none() {
        m.reply_did = stored.reply_did.clone();
    }
    m.version = local.version.max(stored.version);

    let before = pending_request_ids(local, &local.handoffs_out);
    let after = pending_request_ids(&m, &m.handoffs_out);
    let report = MergeReport {
        version: m.version + 1,
        notes_added: m
            .notes
            .iter()
            .filter(|n| !local_ids.contains(&n.id()))
            .count(),
        notes_removed: removed,
        requests_added: after.difference(&before).count(),
        requests_dropped: before.difference(&after).count(),
    };
    (m, report)
}

impl Wallet {
    /// Merge a copy of this wallet retrieved from storage into this one and save
    /// the result (see the module documentation). The caller then stores
    /// [`Wallet::snapshot`] back. If the merge changes nothing, nothing is
    /// written and the counter stays.
    pub fn merge_from(&mut self, stored: &WalletData) -> Result<MergeReport, WalletError> {
        let (merged, report) = merge(self.data(), stored);
        let mut probe = merged.clone();
        probe.version = self.data().version;
        let same = serde_json::to_value(&probe).ok() == serde_json::to_value(self.data()).ok();
        if same {
            return Ok(MergeReport {
                version: self.version(),
                ..report
            });
        }
        self.replace(merged)?;
        Ok(MergeReport {
            version: self.version(),
            ..report
        })
    }

    /// As [`Wallet::merge_from`], with the stored copy read from a wallet file.
    pub fn merge_file(&mut self, path: &std::path::Path) -> Result<MergeReport, WalletError> {
        let bytes = std::fs::read(path)?;
        let stored: WalletData = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::Corrupt(format!("{}: {e}", path.display())))?;
        self.merge_from(&stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::PendingOutput;
    use crate::store::{Kind, PendingPurchase};
    use secp256k1::{SECP256K1, SecretKey};
    use std::fs;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-merge-{}-{name}", {
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

    fn note(amount: u64) -> StoredNote {
        let out = PendingOutput::new(amount);
        let sk = SecretKey::new(&mut rand::rngs::OsRng);
        let sig = bdhke::sign_message(&sk, &out.blind_nonce.0);
        StoredNote {
            kind: Kind::Psp,
            amount,
            note: out.unblind(&sig, &sk.public_key(SECP256K1)),
            spend_secret: out.nonce_secret,
            terms: None,
            reserved_by: None,
        }
    }

    fn purchase(id: &str) -> PendingPurchase {
        PendingPurchase {
            id: id.into(),
            reply_did: "02".repeat(33),
            mint_did_pubkey: "03".repeat(33),
            outputs: vec![PendingOutput::new(1)],
        }
    }

    fn add(w: &mut Wallet, n: &StoredNote) {
        let n = n.clone();
        w.update(|d| {
            d.keysets.insert(n.id(), "0123456789abcdef".into());
            d.notes.push(n);
            Ok(())
        })
        .unwrap();
    }

    fn spend(w: &mut Wallet, n: &StoredNote) {
        let id = n.id();
        w.update(|d| {
            d.notes.retain(|x| x.id() != id);
            d.keysets.remove(&id);
            Ok(())
        })
        .unwrap();
    }

    fn ids(w: &Wallet) -> BTreeSet<String> {
        w.notes().iter().map(StoredNote::id).collect()
    }

    /// Two copies of one wallet that began alike: `local` and `stored`. Both
    /// held `a`, `b`, `c`.
    fn diverged(dir: &PathBuf) -> (Wallet, Wallet, [StoredNote; 3]) {
        let mut base = Wallet::open(&dir.join("base.json")).unwrap();
        let notes = [note(4), note(2), note(1)];
        for n in &notes {
            add(&mut base, n);
        }
        fs::copy(base.path(), dir.join("local.json")).unwrap();
        fs::copy(base.path(), dir.join("stored.json")).unwrap();
        (
            Wallet::open(&dir.join("local.json")).unwrap(),
            Wallet::open(&dir.join("stored.json")).unwrap(),
            notes,
        )
    }

    #[test]
    fn the_version_goes_up_with_every_write() {
        let dir = scratch("version");
        let mut w = Wallet::open(&dir.join("w.json")).unwrap();
        assert_eq!(w.version(), 0);
        add(&mut w, &note(1));
        assert_eq!(w.version(), 1);
        add(&mut w, &note(2));
        assert_eq!(w.version(), 2);
        assert_eq!(Wallet::open(w.path()).unwrap().version(), 2);
        // a failed change does not count
        let _ = w.update(|_| -> Result<(), WalletError> { Err(WalletError::Invalid("no".into())) });
        assert_eq!(w.version(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_diverged_copies_are_united_and_what_either_spent_stays_spent() {
        let dir = scratch("diverged");
        let (mut local, mut stored, [a, b, c]) = diverged(&dir);
        // local spent b and received d; stored spent c and received e
        let (d, e) = (note(8), note(16));
        spend(&mut local, &b);
        add(&mut local, &d);
        spend(&mut stored, &c);
        add(&mut stored, &e);
        let (lv, sv) = (local.version(), stored.version());

        let report = local.merge_from(&stored.snapshot()).unwrap();
        let want: BTreeSet<String> = [&a, &d, &e].iter().map(|n| n.id()).collect();
        assert_eq!(ids(&local), want, "a, d and e; b and c were spent");
        assert_eq!(local.balance().psp, 4 + 8 + 16);
        assert_eq!(report.notes_added, 1, "e");
        assert_eq!(report.notes_removed, 1, "c, which the stored copy spent");
        assert!(local.version() > lv.max(sv), "above both inputs");
        assert_eq!(report.version, local.version());
        // the key sets of the notes that remain are kept, those of spent ones are not
        assert!(local.data().keysets.contains_key(&e.id()));
        assert!(!local.data().keysets.contains_key(&b.id()));
        assert!(!local.data().keysets.contains_key(&c.id()));
        // saved: a reopen gives the same wallet
        assert_eq!(ids(&Wallet::open(local.path()).unwrap()), want);

        // the other direction gives the same notes
        let mut other = Wallet::open(&dir.join("stored.json")).unwrap();
        let before_local = {
            // rebuild the local copy as it was: a, c, d (b spent)
            let mut w = Wallet::open(&dir.join("local2.json")).unwrap();
            for n in [&a, &c, &d] {
                add(&mut w, n);
            }
            w.update(|d2| {
                d2.departed.insert(b.id(), 1);
                Ok(())
            })
            .unwrap();
            w
        };
        other.merge_from(&before_local.snapshot()).unwrap();
        assert_eq!(ids(&other), want);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stale_copy_cannot_bring_back_a_note_the_local_wallet_spent() {
        let dir = scratch("stale");
        let (mut local, stored, [a, b, c]) = diverged(&dir);
        // the stored copy is the old one: it still has all three
        spend(&mut local, &b);
        local.merge_from(&stored.snapshot()).unwrap();
        assert_eq!(ids(&local), [a.id(), c.id()].into_iter().collect());
        // and again, nothing changes
        let report = local.merge_from(&stored.snapshot()).unwrap();
        assert!(!report.changed(), "{report:?}");
        assert_eq!(ids(&local).len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_starter_notes_of_a_new_device_are_united_with_the_stored_wallet() {
        let dir = scratch("newdevice");
        // the stored wallet holds the real value; the new device only the starters
        let mut stored = Wallet::open(&dir.join("stored.json")).unwrap();
        let stored_notes = [note(64), note(32), note(8)];
        for n in &stored_notes {
            add(&mut stored, n);
        }
        let mut local = Wallet::open(&dir.join("local.json")).unwrap();
        let starters = [note(2), note(1)];
        for n in &starters {
            add(&mut local, n);
        }
        local.merge_from(&stored.snapshot()).unwrap();
        assert_eq!(local.balance().psp, 64 + 32 + 8 + 2 + 1);
        assert_eq!(local.notes().len(), 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_requests_are_united_once_and_an_ended_one_is_not_brought_back() {
        let dir = scratch("pending");
        let (mut local, mut stored, _) = diverged(&dir);
        // both have `shared`; only local has `mine`; only stored has `theirs`.
        // `done` is pending in stored and has ended in local. `late` is pending
        // in local and has ended in stored.
        for (w, ids) in [
            (&mut local, vec!["shared", "mine", "done", "late"]),
            (&mut stored, vec!["shared", "theirs", "done", "late"]),
        ] {
            for id in ids {
                w.update(|d| {
                    d.pending_purchases.push(purchase(id));
                    Ok(())
                })
                .unwrap();
            }
        }
        local
            .update(|d| {
                d.pending_purchases.retain(|p| p.id != "done");
                Ok(())
            })
            .unwrap();
        stored
            .update(|d| {
                d.pending_purchases.retain(|p| p.id != "late");
                Ok(())
            })
            .unwrap();
        assert!(local.data().finished.contains("done"));
        assert!(stored.data().finished.contains("late"));
        let report = local.merge_from(&stored.snapshot()).unwrap();
        let mut got: Vec<String> = local
            .pending_purchases()
            .iter()
            .map(|p| p.id.clone())
            .collect();
        got.sort();
        assert_eq!(got, vec!["mine", "shared", "theirs"]);
        assert_eq!(report.requests_added, 1, "theirs");
        assert_eq!(report.requests_dropped, 1, "late");
        // merging again changes nothing
        let again = local.merge_from(&stored.snapshot()).unwrap();
        assert!(!again.changed(), "{again:?}");
        assert_eq!(local.pending_purchases().len(), 3);
        // and the stored copy, merged with the local one, ends the same
        let stored_version = stored.version();
        stored.merge_from(&local.snapshot()).unwrap();
        assert!(stored.version() > stored_version);
        let mut theirs: Vec<String> = stored
            .pending_purchases()
            .iter()
            .map(|p| p.id.clone())
            .collect();
        theirs.sort();
        assert_eq!(theirs, got);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_note_held_by_a_request_is_held_after_the_merge_and_freed_when_it_ended() {
        let dir = scratch("reserve");
        let (mut local, mut stored, [a, b, _c]) = diverged(&dir);
        // stored has a request holding a; local has never heard of it
        let aid = a.id();
        stored
            .update(|d| {
                d.pending_purchases.push(purchase("p1"));
                for n in d.notes.iter_mut().filter(|n| n.id() == aid) {
                    n.reserved_by = Some("p1".into());
                }
                Ok(())
            })
            .unwrap();
        local.merge_from(&stored.snapshot()).unwrap();
        let held = local.notes().iter().find(|n| n.id() == aid).unwrap();
        assert_eq!(held.reserved_by.as_deref(), Some("p1"));
        assert_eq!(local.pending_purchases().len(), 1);

        // a note held by a request nobody has any more is free
        let bid = b.id();
        local
            .update(|d| {
                for n in d.notes.iter_mut().filter(|n| n.id() == bid) {
                    n.reserved_by = Some("gone".into());
                }
                Ok(())
            })
            .unwrap();
        local.merge_from(&stored.snapshot()).unwrap();
        let freed = local.notes().iter().find(|n| n.id() == bid).unwrap();
        assert_eq!(freed.reserved_by, None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_pending_handoff_keeps_its_notes_out_and_a_cancelled_one_brings_them_back() {
        let dir = scratch("handoff");
        let (mut local, stored, [a, _b, _c]) = diverged(&dir);
        // an FSP-free handoff of one PSP note: the stored copy still holds it
        let aid = a.id();
        let sel = crate::handoff::HandoffSelection {
            psp: vec![aid.clone()],
            fsp: vec![],
        };
        let out = local.export_handoff(&sel, "http://m", None).unwrap();
        local.merge_from(&stored.snapshot()).unwrap();
        assert!(
            !ids(&local).contains(&aid),
            "the stored copy must not bring back a note that is in a handoff"
        );
        assert_eq!(local.handoffs_out().len(), 1);

        // cancelled: the note is back, and the stale copy does not take it away
        local.cancel_handoff(&out.id).unwrap();
        assert!(ids(&local).contains(&aid));
        local.merge_from(&stored.snapshot()).unwrap();
        assert!(ids(&local).contains(&aid), "back, and stays");
        assert!(
            local.handoffs_out().is_empty(),
            "the old record is not revived"
        );

        // done: gone for good, in both directions
        let sel = crate::handoff::HandoffSelection {
            psp: vec![aid.clone()],
            fsp: vec![],
        };
        let out = local.export_handoff(&sel, "http://m", None).unwrap();
        local.finish_handoff(&out.id).unwrap();
        local.merge_from(&stored.snapshot()).unwrap();
        assert!(!ids(&local).contains(&aid));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn handoff_records_unite_by_id_and_done_wins() {
        let dir = scratch("records");
        let (mut local, mut stored, _) = diverged(&dir);
        let sel = crate::handoff::HandoffSelection {
            psp: vec![local.notes()[0].id()],
            fsp: vec![],
        };
        let out = local.export_handoff(&sel, "http://m", None).unwrap();
        // the stored copy learns of it as pending, then local finishes it
        stored.merge_from(&local.snapshot()).unwrap();
        assert_eq!(stored.handoffs_out()[0].state, HandoffState::Pending);
        local.finish_handoff(&out.id).unwrap();
        stored.merge_from(&local.snapshot()).unwrap();
        assert_eq!(stored.handoffs_out().len(), 1);
        assert_eq!(stored.handoffs_out()[0].state, HandoffState::Done);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merging_a_wallet_with_itself_changes_nothing_but_the_counter_stays_put() {
        let dir = scratch("self");
        let (mut local, _, _) = diverged(&dir);
        let v = local.version();
        let report = local.merge_from(&local.snapshot()).unwrap();
        assert!(!report.changed());
        assert_eq!(local.version(), v);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merge_file_reads_a_wallet_file_and_refuses_a_damaged_one() {
        let dir = scratch("file");
        let (mut local, mut stored, _) = diverged(&dir);
        add(&mut stored, &note(32));
        let report = local.merge_file(stored.path()).unwrap();
        assert_eq!(report.notes_added, 1);
        assert_eq!(local.notes().len(), 4);
        fs::write(dir.join("bad.json"), "not json").unwrap();
        assert!(matches!(
            local.merge_file(&dir.join("bad.json")),
            Err(WalletError::Corrupt(_))
        ));
        assert!(local.merge_file(&dir.join("missing.json")).is_err());
        assert_eq!(local.notes().len(), 4);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keys_and_mints_are_united_and_the_local_entry_wins() {
        let dir = scratch("maps");
        let (mut local, mut stored, _) = diverged(&dir);
        local
            .update(|d| {
                d.live_keysets
                    .insert("http://m".into(), ("aaaaaaaaaaaaaaaa".into(), None));
                d.reply_did = None;
                Ok(())
            })
            .unwrap();
        stored
            .update(|d| {
                d.live_keysets
                    .insert("http://m".into(), ("bbbbbbbbbbbbbbbb".into(), None));
                d.live_keysets
                    .insert("http://n".into(), ("cccccccccccccccc".into(), None));
                d.reply_did = Some("02".repeat(33));
                Ok(())
            })
            .unwrap();
        local.merge_from(&stored.snapshot()).unwrap();
        let live = &local.data().live_keysets;
        assert_eq!(live["http://m"].0, "aaaaaaaaaaaaaaaa");
        assert_eq!(live["http://n"].0, "cccccccccccccccc");
        assert_eq!(local.data().reply_did, Some("02".repeat(33)));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_tracking_counts_each_departure_and_each_return() {
        let dir = scratch("track");
        let mut w = Wallet::open(&dir.join("w.json")).unwrap();
        let n = note(4);
        let id = n.id();
        add(&mut w, &n);
        assert!(!has_departed(w.data(), &id));
        spend(&mut w, &n);
        assert!(has_departed(w.data(), &id));
        assert_eq!(w.data().departed[&id], 1);
        add(&mut w, &n);
        assert!(!has_departed(w.data(), &id), "it came back");
        spend(&mut w, &n);
        assert!(has_departed(w.data(), &id));
        assert_eq!(w.data().departed[&id], 2);
        assert_eq!(w.data().returned[&id], 1);
        // a request that ends is finished, and one that starts again is not
        w.update(|d| {
            d.pending_purchases.push(purchase("x"));
            Ok(())
        })
        .unwrap();
        assert!(!w.data().finished.contains("x"));
        w.update(|d| {
            d.pending_purchases.clear();
            Ok(())
        })
        .unwrap();
        assert!(w.data().finished.contains("x"));
        w.update(|d| {
            d.pending_purchases.push(purchase("x"));
            Ok(())
        })
        .unwrap();
        assert!(!w.data().finished.contains("x"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
