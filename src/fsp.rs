//! FSP: Fast Service Points, issued by a service's own fsp-mint.
//!
//! - **Issue** ([`Wallet::build_fsp_issue`], [`Wallet::finish_fsp_issue`]): the
//!   app hands its ESP for a service to that service's fsp-mint (an issue
//!   request, over AIR) with blinded FSP outputs, 1:1 less the mint's issue fee. Maturity does not
//!   matter and days may be mixed (one group per day).
//! - **Spend** ([`Wallet::build_fsp_spend`]): a swap with change (a spend
//!   request, over AIR): `pay` goes to the service, the change comes back as new notes.
//! - **Rollover** ([`Wallet::build_fsp_rollover`]): FSP on the mint's previous
//!   keyset is swapped (pay 0) to the current one. The command line does this
//!   automatically every time it talks to an FSP mint and at startup.
//!
//! Every request is stored with its output secrets before it is sent, under its
//! request hash, and its notes are reserved. A retry sends the same request and
//! gets the stored answer, so a crash or a lost reply loses nothing.

use std::collections::BTreeMap;

use mint_types::{Amount, MintInput};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SECP256K1};
use serde::{Deserialize, Serialize};
use sp_wire::ServiceDid;
use sp_wire::fsp::{
    FspInput, GroupResult, HandedEsp, IssueGroup, IssueRequest, IssueResponse, KeysResponse,
    SpendRequest, SpendResponse, issue_group_size,
};

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{HandedNote, Handover, Kind, StoredNote, StoredTerms, Wallet};

/// What the wallet last saw of a service's FSP mint (its keys, over AIR). The mint
/// is found by its service, so no address is kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FspMint {
    pub current: String,
    pub previous: Option<String>,
    /// When the current keyset is replaced, and the previous one deleted.
    pub next_rotation: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FspOp {
    Issue {
        request: IssueRequest,
        /// Per group, the FSP outputs' secrets.
        outputs: Vec<Vec<PendingOutput>>,
        /// Per group, the ESP note ids.
        notes: Vec<Vec<String>>,
    },
    Spend {
        request: SpendRequest,
        change: Vec<PendingOutput>,
        inputs: Vec<String>,
    },
}

impl FspOp {
    /// The ids of the notes the request spends, in the order the mint counts
    /// them when it names some by position: a spend's inputs, or an issue's ESP
    /// notes counted across the groups.
    pub(crate) fn note_ids(&self) -> Vec<String> {
        match self {
            FspOp::Spend { inputs, .. } => inputs.clone(),
            FspOp::Issue { notes, .. } => notes.iter().flatten().cloned().collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingFsp {
    pub id: String,
    pub service: ServiceDid,
    pub op: FspOp,
}

/// A service's mint in the wallet's records (`fsp_mints`, the swap schedule, the
/// live keysets, the mint a handoff names): the service's DID in lowercase hex.
/// The same name is used for the PSP and the ESP. It is never dialled; an FSP
/// mint is reached through the service's `air.fsp` entry, the PSP and the ESP
/// through `air.server` and `air.host`.
pub fn record_of(service: ServiceDid) -> String {
    hex::encode(service.serialize())
}

/// What an issue gave.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IssueOutcome {
    pub fsp: u128,
    pub fee: u128,
    /// Groups the Issuer refused: their ESP notes are free again.
    pub refused: Vec<String>,
}

/// Powers of two adding up to `units`, largest first.
pub fn split(units: u128) -> Vec<u64> {
    (0..64)
        .rev()
        .filter(|b| units >> b & 1 == 1)
        .map(|b| 1u64 << b)
        .collect()
}

/// FSP output sizes for a group of `notes` notes worth `total`, after the fee
/// (which depends on the number of outputs).
pub fn outputs_for(total: u128, notes: usize, fee_per_byte: u64) -> Option<Vec<u64>> {
    if total >> 64 != 0 {
        return None;
    }
    for k in 1..=200usize {
        let fee = u128::from(issue_group_size(notes, k)) * u128::from(fee_per_byte);
        if fee >= total {
            return None;
        }
        let mut parts = split(total - fee);
        while parts.len() < k {
            let Some(i) = parts.iter().position(|&p| p > 1) else {
                break;
            };
            let half = parts[i] / 2;
            parts[i] = half;
            parts.insert(i + 1, half);
        }
        if parts.len() == k {
            return Some(parts);
        }
    }
    None
}

fn sign(request: &mut SpendRequest, secrets: &[secp256k1::SecretKey]) {
    let digest = request.digest();
    for (input, s) in request.inputs.iter_mut().zip(secrets) {
        input.input.spend_signature =
            SECP256K1.sign_schnorr(&digest, &Keypair::from_secret_key(SECP256K1, s));
    }
}

fn dummy() -> Signature {
    Signature::from_slice(&[1u8; 64]).expect("64 bytes")
}

/// `YYYY-MM` of a day count since 1970.
pub fn month_of(day: u64) -> String {
    let z = day as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}")
}

/// When the wallet's ESP becomes redeemable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EspSchedule {
    pub mature_now: u128,
    /// The day asked about and the ESP mature by then (including now).
    pub by: Option<(u64, u128)>,
    /// ESP by the month its redeemable-after day falls in.
    pub months: BTreeMap<String, u128>,
    pub total: u128,
}

impl Wallet {
    pub fn fsp_mints(&self) -> &BTreeMap<String, FspMint> {
        &self.data().fsp_mints
    }

    pub fn pending_fsp(&self) -> &[PendingFsp] {
        &self.data().pending_fsp
    }

    /// FSP notes this wallet lost because their keyset was deleted.
    pub fn lost_fsp(&self) -> &[StoredNote] {
        &self.data().lost_fsp
    }

    /// The keyset an FSP note was signed with.
    pub fn fsp_keyset(&self, note: &StoredNote) -> Option<&String> {
        self.data().fsp_keysets.get(&note.id())
    }

    /// FSP units by service (hex) and keyset. A note whose service is not known
    /// is under [`crate::store::UNKNOWN_SERVICE`].
    pub fn fsp_by_keyset(&self) -> BTreeMap<(String, String), u128> {
        let mut out = BTreeMap::new();
        for n in self.notes().iter().filter(|n| n.kind == Kind::Fsp) {
            let service = n
                .fsp_service()
                .map(|k| hex::encode(k.serialize()))
                .unwrap_or_else(|| crate::store::UNKNOWN_SERVICE.to_string());
            let ks = self.fsp_keyset(n).cloned().unwrap_or_default();
            *out.entry((service, ks)).or_default() += u128::from(n.amount);
        }
        out
    }

    /// The FSP notes whose service is not known, and their units. They are not
    /// spent, handed off or counted under a service until it is known.
    pub fn fsp_unknown_service(&self) -> (usize, u128) {
        self.notes()
            .iter()
            .filter(|n| n.kind == Kind::Fsp && n.terms.is_none())
            .fold((0, 0), |(c, u), n| (c + 1, u + u128::from(n.amount)))
    }

    /// Record what an FSP mint's keys said, and move FSP on keysets it no
    /// longer has to the lost record. Returns the lost units. Refuses a mint
    /// that is not the service's.
    pub fn note_fsp_keys(
        &mut self,
        service: ServiceDid,
        keys: &KeysResponse,
    ) -> Result<u128, WalletError> {
        if keys.service != Some(service) {
            return Err(WalletError::Invalid(format!(
                "the FSP mint reached for service {service} (through its air.fsp entry) says it is not that service's mint"
            )));
        }
        let svc = hex::encode(service.serialize());
        let live: Vec<String> = keys.keysets.keys().cloned().collect();
        self.update(|d| {
            d.fsp_mints.insert(
                svc.clone(),
                FspMint {
                    current: keys.current.clone(),
                    previous: keys.previous.clone(),
                    next_rotation: keys.next_rotation,
                },
            );
            let mut lost = 0u128;
            let mut keep = Vec::new();
            for mut n in std::mem::take(&mut d.notes) {
                // A note of this mint's whose service was not known: its key
                // set is one only this mint has, so the service is this one.
                if n.kind == Kind::Fsp
                    && n.terms.is_none()
                    && d.fsp_keysets.get(&n.id()).is_some_and(|k| live.contains(k))
                {
                    n.terms = Some(StoredTerms {
                        service,
                        redeemable_after_day: 0,
                    });
                }
                let ours = n.kind == Kind::Fsp
                    && n.terms.is_some_and(|t| t.service == service)
                    && n.reserved_by.is_none();
                let ks = d.fsp_keysets.get(&n.id());
                if ours && ks.is_some_and(|k| !live.contains(k)) {
                    lost += u128::from(n.amount);
                    d.lost_fsp.push(n);
                } else {
                    keep.push(n);
                }
            }
            d.notes = keep;
            Ok(lost)
        })
    }

    /// Build an issue: ESP for `service` (all of it, or a set adding up to
    /// exactly `units`), grouped by day, for FSP at `fee_per_byte`.
    pub fn build_fsp_issue(
        &mut self,
        service: ServiceDid,
        units: Option<u128>,
        fee_per_byte: u64,
    ) -> Result<IssueRequest, WalletError> {
        let mut free: Vec<StoredNote> = self
            .notes()
            .iter()
            .filter(|n| {
                n.kind == Kind::Esp
                    && n.reserved_by.is_none()
                    && n.terms.is_some_and(|t| t.service == service)
            })
            .cloned()
            .collect();
        free.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.id().cmp(&b.id())));
        let chosen: Vec<StoredNote> = match units {
            None => free,
            Some(u) => {
                let sizes: Vec<u64> = free.iter().map(|n| n.amount).collect();
                let picked = crate::transfer::pick_exact(&sizes, u).ok_or_else(|| {
                    WalletError::NotEnough(format!("no set of this wallet's ESP notes for that service adds up to exactly {u} units (notes of {sizes:?})"))
                })?;
                picked.into_iter().map(|i| free[i].clone()).collect()
            }
        };
        if chosen.is_empty() {
            return Err(WalletError::NotEnough(
                "this wallet holds no free ESP for that service".into(),
            ));
        }
        let mut by_day: BTreeMap<u64, Vec<StoredNote>> = BTreeMap::new();
        for n in chosen {
            by_day
                .entry(n.terms.map(|t| t.redeemable_after_day).unwrap_or(0))
                .or_default()
                .push(n);
        }
        let (mut groups, mut outputs, mut notes) = (Vec::new(), Vec::new(), Vec::new());
        for (day, ns) in by_day {
            let total: u128 = ns.iter().map(|n| u128::from(n.amount)).sum();
            let sizes = outputs_for(total, ns.len(), fee_per_byte).ok_or_else(|| {
                WalletError::NotEnough(format!(
                    "the {total} ESP units of day {day} do not cover the issue fee"
                ))
            })?;
            let outs: Vec<PendingOutput> = sizes.into_iter().map(PendingOutput::new).collect();
            groups.push(IssueGroup {
                redeemable_after_day: day,
                notes: ns
                    .iter()
                    .map(|n| -> Result<HandedEsp, WalletError> {
                        Ok(HandedEsp {
                            amount: n.amount,
                            note: n.note,
                            spend_secret: n.spend_secret,
                            keyset: self.esp_keyset_of(n)?,
                        })
                    })
                    .collect::<Result<_, _>>()?,
                outputs: outs.iter().map(PendingOutput::mint_output).collect(),
            });
            outputs.push(outs);
            notes.push(ns.iter().map(StoredNote::id).collect::<Vec<_>>());
        }
        let request = IssueRequest { service, groups };
        let id = request.hash();
        let held: Vec<String> = notes.iter().flatten().cloned().collect();
        let pending = PendingFsp {
            id: id.clone(),
            service,
            op: FspOp::Issue {
                request: request.clone(),
                outputs,
                notes,
            },
        };
        self.update(|d| {
            for n in d.notes.iter_mut().filter(|n| held.contains(&n.id())) {
                n.reserved_by = Some(id.clone());
            }
            d.pending_fsp.push(pending);
            Ok(())
        })?;
        Ok(request)
    }

    fn take_pending(&self, id: &str) -> Result<PendingFsp, WalletError> {
        self.pending_fsp()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending FSP request {id}")))
    }

    pub fn finish_fsp_issue(
        &mut self,
        id: &str,
        reply: &IssueResponse,
    ) -> Result<IssueOutcome, WalletError> {
        let p = self.take_pending(id)?;
        let FspOp::Issue {
            request,
            outputs,
            notes,
        } = p.op
        else {
            return Err(WalletError::Invalid(format!("{id} is not an issue")));
        };
        if reply.groups.len() != request.groups.len() {
            return Err(WalletError::Mint(
                "the FSP mint's reply does not fit the request".into(),
            ));
        }
        let mut outcome = IssueOutcome::default();
        let mut add = Vec::new();
        let mut gone: Vec<String> = Vec::new();
        let mut handovers = Vec::new();
        for (g, result) in reply.groups.iter().enumerate() {
            match result {
                GroupResult::Issued {
                    keyset,
                    signatures,
                    keys,
                    fee,
                } => {
                    if signatures.len() != outputs[g].len() || keys.len() != outputs[g].len() {
                        return Err(WalletError::Mint(
                            "the FSP mint's reply does not fit the request".into(),
                        ));
                    }
                    for (i, o) in outputs[g].iter().enumerate() {
                        add.push((
                            StoredNote {
                                kind: Kind::Fsp,
                                amount: o.amount,
                                note: o.unblind(&signatures[i], &keys[i]),
                                spend_secret: o.nonce_secret,
                                terms: Some(StoredTerms {
                                    service: p.service,
                                    redeemable_after_day: 0,
                                }),
                                reserved_by: None,
                            },
                            keyset.clone(),
                        ));
                        outcome.fsp += u128::from(o.amount);
                    }
                    outcome.fee += u128::from(*fee);
                    gone.extend(notes[g].iter().cloned());
                    let grp = &request.groups[g];
                    handovers.push(Handover {
                        service: p.service,
                        redeemable_after_day: grp.redeemable_after_day,
                        notes: grp
                            .notes
                            .iter()
                            .map(|n| HandedNote {
                                amount: n.amount,
                                note: n.note,
                                spend_secret: n.spend_secret,
                                keyset: n.keyset.clone(),
                            })
                            .collect(),
                    });
                }
                GroupResult::Refused { why, .. } => outcome.refused.push(format!(
                    "day {}: {why}",
                    request.groups[g].redeemable_after_day
                )),
            }
        }
        self.update(|d| {
            d.notes.retain(|n| !gone.contains(&n.id()));
            for n in d
                .notes
                .iter_mut()
                .filter(|n| n.reserved_by.as_deref() == Some(id))
            {
                n.reserved_by = None;
            }
            for (n, ks) in add {
                d.fsp_keysets.insert(n.id(), ks);
                d.notes.push(n);
            }
            d.handovers.extend(handovers);
            d.pending_fsp.retain(|q| q.id != id);
            Ok(())
        })?;
        Ok(outcome)
    }

    /// Drop a pending FSP request the mint refused (nothing happened there) and
    /// free its notes.
    pub fn cancel_fsp(&mut self, id: &str) -> Result<(), WalletError> {
        self.take_pending(id)?;
        self.update(|d| {
            for n in d
                .notes
                .iter_mut()
                .filter(|n| n.reserved_by.as_deref() == Some(id))
            {
                n.reserved_by = None;
            }
            d.pending_fsp.retain(|q| q.id != id);
            Ok(())
        })
    }

    /// The mint refused a pending FSP request because some of its inputs are
    /// already spent (`note_spent_elsewhere`), and named them by `positions` in
    /// the request: the notes of a spend in its input order, or the ESP notes of
    /// an issue counted across the groups in order. Nothing happened at the mint.
    /// The named notes go to the spent record and leave the balance, the request's
    /// other notes are free again, and the request is dropped.
    pub fn mark_spent_in_fsp(
        &mut self,
        id: &str,
        positions: &[usize],
    ) -> Result<crate::esp::SpentReport, WalletError> {
        self.update(|d| {
            let pending = d
                .pending_fsp
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no pending FSP request {id}")))?;
            let ids = pending.op.note_ids();
            if positions.is_empty() || positions.iter().any(|&i| i >= ids.len()) {
                return Err(WalletError::Invalid(format!(
                    "the mint named notes {positions:?}, but the request has {} notes",
                    ids.len()
                )));
            }
            let spent_ids: Vec<String> = positions.iter().map(|&i| ids[i].clone()).collect();
            d.pending_fsp.retain(|q| q.id != id);
            for spent in &spent_ids {
                d.fsp_keysets.remove(spent);
            }
            Ok(Wallet::retire_reserved(d, id, &spent_ids))
        })
    }

    pub(crate) fn build_swap(
        &mut self,
        service: ServiceDid,
        chosen: Vec<StoredNote>,
        pay: u64,
        memo: &str,
    ) -> Result<SpendRequest, WalletError> {
        let total: u128 = chosen.iter().map(|n| u128::from(n.amount)).sum();
        let change: Vec<PendingOutput> = split(total - u128::from(pay))
            .into_iter()
            .map(PendingOutput::new)
            .collect();
        let mut request = SpendRequest {
            inputs: chosen
                .iter()
                .map(|n| FspInput {
                    keyset: self.fsp_keyset(n).cloned().unwrap_or_default(),
                    input: MintInput {
                        amount: Amount::from_units(n.amount),
                        note: n.note,
                        spend_signature: dummy(),
                    },
                })
                .collect(),
            outputs: change.iter().map(PendingOutput::mint_output).collect(),
            pay,
            memo: memo.into(),
        };
        sign(
            &mut request,
            &chosen.iter().map(|n| n.spend_secret).collect::<Vec<_>>(),
        );
        let id = request.hash();
        let inputs: Vec<String> = chosen.iter().map(StoredNote::id).collect();
        let pending = PendingFsp {
            id: id.clone(),
            service,
            op: FspOp::Spend {
                request: request.clone(),
                change,
                inputs: inputs.clone(),
            },
        };
        self.update(|d| {
            for n in d.notes.iter_mut().filter(|n| inputs.contains(&n.id())) {
                n.reserved_by = Some(id.clone());
            }
            d.pending_fsp.push(pending);
            Ok(())
        })?;
        Ok(request)
    }

    fn free_fsp(&self, service: &ServiceDid) -> Vec<StoredNote> {
        self.notes()
            .iter()
            .filter(|n| {
                n.kind == Kind::Fsp
                    && n.reserved_by.is_none()
                    && n.terms.is_some_and(|t| t.service == *service)
            })
            .cloned()
            .collect()
    }

    /// Pay `pay` FSP units to the service, with change. Notes are taken largest
    /// first until they cover the payment.
    pub fn build_fsp_spend(
        &mut self,
        service: ServiceDid,
        pay: u64,
        memo: &str,
    ) -> Result<SpendRequest, WalletError> {
        if pay == 0 {
            return Err(WalletError::Invalid("pay at least 1 FSP unit".into()));
        }
        let mut free = self.free_fsp(&service);
        free.sort_by(|a, b| b.amount.cmp(&a.amount));
        let mut chosen = Vec::new();
        let mut sum = 0u128;
        for n in free {
            if sum >= u128::from(pay) {
                break;
            }
            sum += u128::from(n.amount);
            chosen.push(n);
        }
        if sum < u128::from(pay) {
            return Err(WalletError::NotEnough(format!(
                "this wallet holds {sum} free FSP units for that service, less than {pay}"
            )));
        }
        self.build_swap(service, chosen, pay, memo)
    }

    /// Swap every free FSP note of `service` on the mint's previous keyset to
    /// the current one (pay 0). `None` if there is nothing to roll over.
    pub fn build_fsp_rollover(
        &mut self,
        service: ServiceDid,
    ) -> Result<Option<SpendRequest>, WalletError> {
        let Some(previous) = self
            .fsp_mints()
            .get(&hex::encode(service.serialize()))
            .and_then(|m| m.previous.clone())
        else {
            return Ok(None);
        };
        let old: Vec<StoredNote> = self
            .free_fsp(&service)
            .into_iter()
            .filter(|n| self.fsp_keyset(n) == Some(&previous))
            .collect();
        if old.is_empty() {
            return Ok(None);
        }
        self.build_swap(service, old, 0, "rollover").map(Some)
    }

    pub fn finish_fsp_spend(
        &mut self,
        id: &str,
        reply: &SpendResponse,
    ) -> Result<u64, WalletError> {
        let p = self.take_pending(id)?;
        let FspOp::Spend { change, inputs, .. } = p.op else {
            return Err(WalletError::Invalid(format!("{id} is not a spend")));
        };
        if reply.signatures.len() != change.len() || reply.keys.len() != change.len() {
            return Err(WalletError::Mint(
                "the FSP mint's reply does not fit the request".into(),
            ));
        }
        self.update(|d| {
            d.notes.retain(|n| !inputs.contains(&n.id()));
            for i in &inputs {
                d.fsp_keysets.remove(i);
            }
            for (i, o) in change.iter().enumerate() {
                let n = StoredNote {
                    kind: Kind::Fsp,
                    amount: o.amount,
                    note: o.unblind(&reply.signatures[i], &reply.keys[i]),
                    spend_secret: o.nonce_secret,
                    terms: Some(StoredTerms {
                        service: p.service,
                        redeemable_after_day: 0,
                    }),
                    reserved_by: None,
                };
                d.fsp_keysets.insert(n.id(), reply.keyset.clone());
                d.notes.push(n);
            }
            d.pending_fsp.retain(|q| q.id != id);
            // A rollover done: its swap time goes in this same write.
            if reply.paid == 0 {
                let prefix = crate::rotate::schedule_prefix(Kind::Fsp, &record_of(p.service));
                d.swap_schedule.retain(|k, _| !k.starts_with(&prefix));
            }
            Ok(())
        })?;
        Ok(reply.paid)
    }

    /// When this wallet's ESP is redeemable: now (`today`, days since 1970),
    /// by `by` if given, and by month.
    pub fn esp_schedule(&self, today: u64, by: Option<u64>) -> EspSchedule {
        let mut s = EspSchedule {
            by: by.map(|d| (d, 0)),
            ..Default::default()
        };
        for n in self.notes().iter().filter(|n| n.kind == Kind::Esp) {
            let Some(t) = n.terms else { continue };
            let units = u128::from(n.amount);
            s.total += units;
            if t.redeemable_after_day <= today {
                s.mature_now += units;
            }
            if let Some((d, sum)) = s.by.as_mut() {
                if t.redeemable_after_day <= *d {
                    *sum += units;
                }
            }
            *s.months
                .entry(month_of(t.redeemable_after_day))
                .or_default() += units;
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::expect;
    use crate::store::WalletData;

    /// Open a wallet file of the test network.
    fn open_wallet(path: &std::path::Path) -> Result<crate::Wallet, crate::WalletError> {
        crate::Wallet::open(path, "regtest")
    }

    #[test]
    fn splits_and_outputs() {
        assert_eq!(split(13), vec![8, 4, 1]);
        assert_eq!(outputs_for(13, 1, 0), Some(vec![8, 4, 1]));
        // 1 a byte: 1 note and k outputs cost 122 + 41k.
        let o = outputs_for(1000, 1, 1).unwrap();
        let fee = 122 + 41 * o.len() as u128;
        assert_eq!(o.iter().map(|&x| u128::from(x)).sum::<u128>() + fee, 1000);
        assert_eq!(outputs_for(100, 1, 1), None);
        assert_eq!(outputs_for(2, 1, 0), Some(vec![2]));
    }

    fn service_of(seed: u8) -> ServiceDid {
        ServiceDid::from(
            secp256k1::SecretKey::from_slice(&[seed; 32])
                .unwrap()
                .public_key(secp256k1::SECP256K1),
        )
    }

    /// An FSP note of `amount` with no service recorded, on key set `keyset`
    /// unless that is empty.
    fn bare_note(seed: u8, amount: u64) -> StoredNote {
        let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = sk.public_key(secp256k1::SECP256K1);
        StoredNote {
            kind: Kind::Fsp,
            amount,
            note: mint_types::Note {
                nonce: mint_types::Nonce(pk),
                signature: pk,
            },
            spend_secret: sk,
            terms: None,
            reserved_by: None,
        }
    }

    fn scratch_file(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wallet-fsp-svc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("wallet.json")
    }

    #[test]
    fn fsp_calls_with_bad_input_are_refused_and_change_nothing() {
        let (s, other) = (service_of(44), service_of(45));
        let mut data = WalletData {
            network: "regtest".into(),
            ..Default::default()
        };
        for (seed, amount) in [(10, 8), (11, 4)] {
            let mut n = bare_note(seed, amount);
            n.terms = Some(StoredTerms {
                service: s,
                redeemable_after_day: 0,
            });
            data.fsp_keysets.insert(n.id(), "k1".into());
            data.notes.push(n);
        }
        let path = scratch_file("bad-input");
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let mut w = open_wallet(&path).unwrap();
        let state = |w: &Wallet| {
            (
                serde_json::to_value(w.snapshot()).unwrap(),
                std::fs::read(&path).unwrap(),
            )
        };
        let before = state(&w);

        let e = expect::invalid(w.build_fsp_spend(s, 0, ""));
        assert!(e.contains("pay at least 1 FSP unit"), "{e}");
        let e = expect::not_enough(w.build_fsp_spend(s, 13, ""));
        assert!(
            e.contains("holds 12 free FSP units for that service, less than 13"),
            "{e}"
        );
        let e = expect::not_enough(w.build_fsp_spend(other, 1, ""));
        assert!(
            e.contains("holds 0 free FSP units for that service, less than 1"),
            "{e}"
        );
        let issue = IssueResponse {
            groups: vec![],
            fee_per_byte: 0,
        };
        let e = expect::unknown(w.finish_fsp_issue("nope", &issue));
        assert!(e.contains("no pending FSP request nope"), "{e}");
        let spend = SpendResponse {
            keyset: "k1".into(),
            signatures: vec![],
            keys: vec![],
            paid: 0,
        };
        let e = expect::unknown(w.finish_fsp_spend("nope", &spend));
        assert!(e.contains("no pending FSP request nope"), "{e}");
        let e = expect::unknown(w.cancel_fsp("nope"));
        assert!(e.contains("no pending FSP request nope"), "{e}");
        assert_eq!(state(&w), before, "no refused call changed the wallet");

        // a reply that does not fit the request: paying 5 of the 8 leaves
        // change of 3, which is two notes
        w.build_fsp_spend(s, 5, "memo").unwrap();
        let id = w.pending_fsp()[0].id.clone();
        let built = state(&w);
        let key = bare_note(12, 1).note.nonce.0;
        for (signatures, keys) in [
            (vec![], vec![]),
            (vec![key, key], vec![key]),
            (vec![key], vec![key, key]),
        ] {
            let reply = SpendResponse {
                keyset: "k1".into(),
                signatures,
                keys,
                paid: 5,
            };
            match w.finish_fsp_spend(&id, &reply) {
                Err(WalletError::Mint(m)) => {
                    assert!(m.contains("does not fit the request"), "{m}");
                }
                other => panic!("expected WalletError::Mint, got {other:?}"),
            }
            assert_eq!(state(&w), built, "the pending spend is untouched");
        }
        // and a spend id is not an issue
        match w.finish_fsp_issue(&id, &issue) {
            Err(WalletError::Invalid(m)) => assert!(m.contains("is not an issue"), "{m}"),
            other => panic!("expected WalletError::Invalid, got {other:?}"),
        }
        assert_eq!(state(&w), built);
    }

    #[test]
    fn only_a_note_with_a_service_is_picked_for_it() {
        let s = service_of(43);
        let mut known = bare_note(7, 4);
        known.terms = Some(StoredTerms {
            service: s,
            redeemable_after_day: 0,
        });
        let unknown = bare_note(8, 4);
        let data = WalletData {
            network: "regtest".into(),
            notes: vec![known.clone(), unknown],
            ..Default::default()
        };
        let path = scratch_file("pick");
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let w = open_wallet(&path).unwrap();
        assert_eq!(known.fsp_service(), Some(s));
        assert!(
            w.select_fsp_handoff(&[(s, 8)]).is_err(),
            "only 4 is the service's"
        );
        assert_eq!(w.select_fsp_handoff(&[(s, 4)]).unwrap().len(), 1);
    }

    /// A wallet holding FSP notes of `amounts` for a service, all on keyset
    /// `old`, in that order. With `rotating`, the wallet's record of the mint
    /// names `old` as the previous keyset, so a rollover has notes to move.
    fn wallet_with_fsp(name: &str, amounts: &[u64], rotating: bool) -> (Wallet, ServiceDid) {
        let s = service_of(44);
        let mut data = WalletData {
            network: "regtest".into(),
            ..Default::default()
        };
        for (i, &amount) in amounts.iter().enumerate() {
            let mut n = bare_note(10 + i as u8, amount);
            n.terms = Some(StoredTerms {
                service: s,
                redeemable_after_day: 0,
            });
            data.fsp_keysets.insert(n.id(), "old".into());
            data.notes.push(n);
        }
        if rotating {
            data.fsp_mints.insert(
                record_of(s),
                FspMint {
                    current: "new".into(),
                    previous: Some("old".into()),
                    next_rotation: None,
                },
            );
        }
        let path = scratch_file(name);
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        (open_wallet(&path).unwrap(), s)
    }

    /// The mint's refusal of a request whose inputs `at` are already spent.
    fn spent_refusal(at: &[usize]) -> Result<crate::mint_info::FspReply, WalletError> {
        Err(WalletError::SpentElsewhere {
            why: "the mint's text".into(),
            inputs: at.to_vec(),
        })
    }

    fn amounts(notes: &[StoredNote]) -> Vec<u64> {
        let mut v: Vec<u64> = notes.iter().map(|n| n.amount).collect();
        v.sort_unstable();
        v
    }

    #[test]
    fn a_refused_payment_marks_the_spent_notes_spent_and_frees_the_rest() {
        let (mut w, s) = wallet_with_fsp("pay-spent", &[8, 4, 2, 1], false);
        // 15 takes all four notes, largest first: 8, 4, 2, 1
        let id = w.build_fsp_spend(s, 15, "memo").unwrap().hash();
        assert_eq!(w.pending_fsp().len(), 1);
        assert_eq!(w.balance().fsp, 15);

        // the mint says the notes at positions 1 and 2 (the 4 and the 2) are spent
        let e =
            crate::mint_info::settle_fsp_with(&mut w, &id, &mut |_, _, _| spent_refusal(&[1, 2]))
                .unwrap_err();
        match e {
            WalletError::SpentElsewhere { why, inputs } => {
                assert_eq!(inputs, vec![1, 2]);
                assert_eq!(
                    why,
                    "the mint's text. 2 note(s) are marked spent in the wallet, 2 other note(s) are free again"
                );
            }
            other => panic!("expected SpentElsewhere, got {other:?}"),
        }
        // the request is gone, the two spent notes left the balance, the others are free
        assert!(w.pending_fsp().is_empty());
        assert_eq!(amounts(w.spent_notes()), vec![2, 4]);
        let b = w.balance();
        assert_eq!((b.fsp, b.spent_elsewhere), (9, 2));
        assert!(w.notes().iter().all(|n| n.reserved_by.is_none()));
        // so a later payment can use the free ones, and cannot use the spent ones
        assert!(w.build_fsp_spend(s, 9, "memo").is_ok());
        let (mut w2, s2) = wallet_with_fsp("pay-spent-2", &[8, 4, 2, 1], false);
        let id = w2.build_fsp_spend(s2, 15, "memo").unwrap().hash();
        crate::mint_info::settle_fsp_with(&mut w2, &id, &mut |_, _, _| spent_refusal(&[1, 2]))
            .unwrap_err();
        assert!(matches!(
            w2.build_fsp_spend(s2, 10, "memo"),
            Err(WalletError::NotEnough(_))
        ));
        // and it is all on disk
        let again = open_wallet(w2.path()).unwrap();
        assert_eq!(amounts(again.spent_notes()), vec![2, 4]);
        assert_eq!(again.balance().fsp, 9);
        assert!(again.pending_fsp().is_empty());
    }

    #[test]
    fn a_refused_rollover_marks_the_spent_notes_spent_and_the_next_one_leaves_them_out() {
        let (mut w, s) = wallet_with_fsp("roll-spent", &[8, 4, 2, 1], true);
        let request = w.build_fsp_rollover(s).unwrap().unwrap();
        assert_eq!(request.pay, 0);
        assert_eq!(request.inputs.len(), 4);

        // the first and the last (the 8 and the 1) are spent: a rollover is nobody's
        // request, so this is a line for the log and not an error
        let text = crate::mint_info::settle_fsp_with(&mut w, &request.hash(), &mut |_, _, _| {
            spent_refusal(&[0, 3])
        })
        .unwrap();
        assert_eq!(
            text,
            "rollover refused (the mint's text): 2 note(s) marked spent, 2 freed"
        );
        assert!(w.pending_fsp().is_empty());
        assert_eq!(amounts(w.spent_notes()), vec![1, 8]);
        assert_eq!(w.balance().fsp, 6);

        // the next rollover is of the two notes that are left
        let next = w.build_fsp_rollover(s).unwrap().unwrap();
        let mut left: Vec<u64> = next.inputs.iter().map(|i| i.input.amount.units).collect();
        left.sort_unstable();
        assert_eq!(left, vec![2, 4]);
    }

    /// A wallet holding free ESP notes for a service on two days: day 1 a 2 and a
    /// 1, day 2 an 8 and a 4.
    fn wallet_with_esp_on_two_days(name: &str) -> (Wallet, ServiceDid) {
        let s = service_of(44);
        let mut data = WalletData {
            network: "regtest".into(),
            ..Default::default()
        };
        for (i, (amount, day)) in [(2u64, 1u64), (1, 1), (8, 2), (4, 2)]
            .into_iter()
            .enumerate()
        {
            let mut n = bare_note(20 + i as u8, amount);
            n.kind = Kind::Esp;
            n.terms = Some(StoredTerms {
                service: s,
                redeemable_after_day: day,
            });
            data.keysets.insert(n.id(), "esp-keyset".into());
            data.notes.push(n);
        }
        let path = scratch_file(name);
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        (open_wallet(&path).unwrap(), s)
    }

    #[test]
    fn a_refused_issue_marks_the_spent_esp_notes_spent_counted_across_the_groups() {
        let (mut w, s) = wallet_with_esp_on_two_days("issue-spent");
        let request = w.build_fsp_issue(s, None, 0).unwrap();
        // the groups are by day, and each holds its notes largest first: 2, 1 | 8, 4
        assert_eq!(request.groups.len(), 2);

        // positions 1 and 2 counted across the groups are the 1 and the 8
        let e = crate::mint_info::settle_fsp_with(&mut w, &request.hash(), &mut |_, _, _| {
            spent_refusal(&[1, 2])
        })
        .unwrap_err();
        assert!(matches!(e, WalletError::SpentElsewhere { .. }), "{e:?}");
        assert!(w.pending_fsp().is_empty());
        assert_eq!(amounts(w.spent_notes()), vec![1, 8]);
        assert!(w.notes().iter().all(|n| n.reserved_by.is_none()));
        assert_eq!(amounts(w.notes()), vec![2, 4]);
    }

    #[test]
    fn a_bad_answer_from_the_mint_marks_nothing() {
        // A refusal that names no note, or a position the request does not have,
        // is a mint error: the request is cancelled, nothing is marked spent and
        // the notes are free. Through `settle_fsp_with`, for a payment, a rollover
        // and an issue.
        let expect = |positions: &str, notes: usize| {
            format!(
                "the mint named a note the request did not have: it named positions {positions} of a request of {notes} note(s) (the mint's text). The request is cancelled, nothing is marked spent, and its notes are free again"
            )
        };
        let check = |w: &Wallet, free: Vec<u64>| {
            assert!(w.pending_fsp().is_empty(), "the request is still pending");
            assert!(w.spent_notes().is_empty(), "a note was marked spent");
            assert!(
                w.notes().iter().all(|n| n.reserved_by.is_none()),
                "a note is still held"
            );
            assert_eq!(amounts(w.notes()), free);
            // and it is all on disk
            let again = open_wallet(w.path()).unwrap();
            assert!(again.pending_fsp().is_empty());
            assert!(again.spent_notes().is_empty());
            assert!(again.notes().iter().all(|n| n.reserved_by.is_none()));
        };
        let settle =
            |w: &mut Wallet, id: &str, at: &[usize]| match crate::mint_info::settle_fsp_with(
                w,
                id,
                &mut |_, _, _| spent_refusal(at),
            ) {
                Err(WalletError::Mint(why)) => why,
                other => panic!("expected a Mint error, got {other:?}"),
            };

        // a payment of two notes: a position past the end
        let (mut w, s) = wallet_with_fsp("bad-pay", &[8, 4], false);
        let id = w.build_fsp_spend(s, 12, "memo").unwrap().hash();
        assert_eq!(w.pending_fsp().len(), 1);
        assert_eq!(settle(&mut w, &id, &[0, 2]), expect("[0, 2]", 2));
        check(&w, vec![4, 8]);
        assert_eq!(w.balance().fsp, 12);

        // the same payment, the mint naming no note at all
        let id = w.build_fsp_spend(s, 12, "memo").unwrap().hash();
        assert_eq!(settle(&mut w, &id, &[]), expect("[]", 2));
        check(&w, vec![4, 8]);

        // a rollover of four notes: position 4 is the fifth
        let (mut w, s) = wallet_with_fsp("bad-roll", &[8, 4, 2, 1], true);
        let id = w.build_fsp_rollover(s).unwrap().unwrap().hash();
        assert_eq!(settle(&mut w, &id, &[4]), expect("[4]", 4));
        check(&w, vec![1, 2, 4, 8]);
        // so the next rollover is built from all four again, and is not stuck
        assert_eq!(w.build_fsp_rollover(s).unwrap().unwrap().inputs.len(), 4);

        // an issue of four ESP notes in two groups: position 4 is the fifth
        let (mut w, s) = wallet_with_esp_on_two_days("bad-issue");
        let id = w.build_fsp_issue(s, None, 0).unwrap().hash();
        assert_eq!(settle(&mut w, &id, &[1, 4]), expect("[1, 4]", 4));
        check(&w, vec![1, 2, 4, 8]);
    }

    #[test]
    fn mark_spent_in_fsp_refuses_a_bad_position_and_an_unknown_request_and_changes_nothing() {
        // `mark_spent_in_fsp` is public, so the library call refuses what
        // `settle_fsp_with` never hands it: no position at all, a position the
        // request does not have, and a request that is not pending.
        let (mut w, s) = wallet_with_fsp("bad-direct", &[8, 4], false);
        let id = w.build_fsp_spend(s, 12, "memo").unwrap().hash();
        let before = serde_json::to_value(w.snapshot()).unwrap();
        for (positions, text) in [
            (
                &[][..],
                "the mint named notes [], but the request has 2 notes",
            ),
            (
                &[0, 2][..],
                "the mint named notes [0, 2], but the request has 2 notes",
            ),
        ] {
            match w.mark_spent_in_fsp(&id, positions) {
                Err(WalletError::Invalid(why)) => assert_eq!(why, text),
                other => panic!("expected an Invalid refusal, got {other:?}"),
            }
        }
        match w.mark_spent_in_fsp("nope", &[0]) {
            Err(WalletError::Unknown(why)) => assert_eq!(why, "no pending FSP request nope"),
            other => panic!("expected an Unknown refusal, got {other:?}"),
        }
        assert_eq!(serde_json::to_value(w.snapshot()).unwrap(), before);
    }

    #[test]
    fn a_request_the_wallet_cancelled_is_logged_as_cancelled_and_one_still_pending_as_retried() {
        let (mut w, s) = wallet_with_fsp("wording", &[8, 4], false);
        let id = w.build_fsp_spend(s, 12, "memo").unwrap().hash();
        // the mint did not answer: the request is kept and sent again
        let down = WalletError::Mint("cannot answer now".into());
        assert_eq!(
            crate::mint_info::fsp_failure(&w, "pending", "not finished", &id, &down),
            format!("pending {id} not finished, retried on the next connection: cannot answer now")
        );
        // the mint named a position the request does not have: the wallet cancels
        // the request, and the next connection does not send it again
        let why = match crate::mint_info::settle_fsp_with(&mut w, &id, &mut |_, _, _| {
            spent_refusal(&[0, 2])
        }) {
            Err(e) => e,
            other => panic!("expected an error, got {other:?}"),
        };
        assert!(w.pending_fsp().is_empty());
        assert_eq!(
            crate::mint_info::fsp_failure(&w, "pending", "not finished", &id, &why),
            format!(
                "pending {id} cancelled, not retried: the mint named a note the request did not have: it named positions [0, 2] of a request of 2 note(s) (the mint's text). The request is cancelled, nothing is marked spent, and its notes are free again"
            )
        );
    }

    #[test]
    fn months() {
        assert_eq!(month_of(0), "1970-01");
        assert_eq!(month_of(20_741), "2026-10");
        assert_eq!(month_of(19_782), "2024-02");
    }
}
