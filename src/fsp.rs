//! FSP: Fast Service Points, issued by a service's own fsp-mint.
//!
//! - **Issue** ([`Wallet::build_fsp_issue`], [`Wallet::finish_fsp_issue`]): the
//!   app hands its ESP for a service to that service's fsp-mint (`POST /issue`)
//!   with blinded FSP outputs, 1:1 less the mint's issue fee. Maturity does not
//!   matter and days may be mixed (one group per day).
//! - **Spend** ([`Wallet::build_fsp_spend`]): a swap with change (`POST
//!   /spend`): `pay` goes to the service, the change comes back as new notes.
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

/// What the wallet last saw of an FSP mint (`GET /keys`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FspMint {
    pub url: String,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingFsp {
    pub id: String,
    pub service: ServiceDid,
    pub op: FspOp,
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
    /// spent, handed off or counted under a service until it is known (see
    /// [`Wallet::fill_fsp_services`]).
    pub fn fsp_unknown_service(&self) -> (usize, u128) {
        self.notes()
            .iter()
            .filter(|n| n.kind == Kind::Fsp && n.terms.is_none())
            .fold((0, 0), |(c, u), n| (c + 1, u + u128::from(n.amount)))
    }

    /// Fill in the service of FSP notes that have none, from the FSP mints this
    /// wallet has seen: a note whose key set is the current or previous one of
    /// exactly one known mint belongs to that mint's service. Anything else is
    /// left unknown, not guessed. Returns how many notes were filled in. Run at
    /// startup (a wallet file from before the service was kept) and whenever a
    /// mint's keys are read.
    pub fn fill_fsp_services(&mut self) -> Result<usize, WalletError> {
        let mut owner: BTreeMap<String, Option<ServiceDid>> = BTreeMap::new();
        for (svc, m) in &self.data().fsp_mints {
            let Ok(key) = ServiceDid::parse(svc) else {
                continue;
            };
            for ks in std::iter::once(&m.current).chain(m.previous.iter()) {
                // a key set that two mints both claim belongs to neither
                owner
                    .entry(ks.clone())
                    .and_modify(|o| *o = None)
                    .or_insert(Some(key));
            }
        }
        let wanted: Vec<(String, ServiceDid)> = self
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Fsp && n.terms.is_none())
            .filter_map(|n| {
                let ks = self.data().fsp_keysets.get(&n.id())?;
                let service = (*owner.get(ks)?)?;
                Some((n.id(), service))
            })
            .collect();
        if wanted.is_empty() {
            return Ok(0);
        }
        self.update(|d| {
            for n in d.notes.iter_mut().filter(|n| n.kind == Kind::Fsp) {
                if let Some((_, service)) = wanted.iter().find(|(id, _)| *id == n.id()) {
                    n.terms = Some(StoredTerms {
                        service: *service,
                        redeemable_after_day: 0,
                    });
                }
            }
            Ok(wanted.len())
        })
    }

    /// Record what an FSP mint's `/keys` said, and move FSP on keysets it no
    /// longer has to the lost record. Returns the lost units. Refuses a mint
    /// that is not the service's.
    pub fn note_fsp_keys(
        &mut self,
        service: ServiceDid,
        url: &str,
        keys: &KeysResponse,
    ) -> Result<u128, WalletError> {
        if keys.service != Some(service) {
            return Err(WalletError::Invalid(format!(
                "the FSP mint at {url} is not the mint of service {service}"
            )));
        }
        let svc = hex::encode(service.serialize());
        let live: Vec<String> = keys.keysets.keys().cloned().collect();
        self.update(|d| {
            d.fsp_mints.insert(
                svc.clone(),
                FspMint {
                    url: url.into(),
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
                if let Some(m) = d.fsp_mints.get(&hex::encode(p.service.serialize())) {
                    let prefix = crate::rotate::schedule_prefix(Kind::Fsp, &m.url);
                    d.swap_schedule.retain(|k, _| !k.starts_with(&prefix));
                }
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
    use crate::store::WalletData;

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

    /// An FSP note of `amount` with no service recorded (as an older wallet
    /// file has it), on key set `keyset` unless that is empty.
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

    fn fsp_mint(url: &str, current: &str, previous: Option<&str>) -> FspMint {
        FspMint {
            url: url.into(),
            current: current.into(),
            previous: previous.map(String::from),
            next_rotation: None,
        }
    }

    #[test]
    fn the_service_of_an_old_note_is_filled_from_the_one_mint_that_has_its_keyset() {
        let (s1, s2) = (service_of(41), service_of(42));
        // k0 is only service 1's previous set and k2 only service 2's current
        // set; k1 is claimed by both mints, so it belongs to neither.
        let notes = [
            (bare_note(1, 8), "k0"),
            (bare_note(2, 4), "k2"),
            (bare_note(3, 2), "k1"),
            (bare_note(4, 1), "kz"),
        ];
        let mut with_terms = bare_note(5, 16);
        with_terms.terms = Some(StoredTerms {
            service: s2,
            redeemable_after_day: 0,
        });
        let mut data = WalletData::default();
        for (n, ks) in &notes {
            data.fsp_keysets.insert(n.id(), ks.to_string());
        }
        data.fsp_keysets.insert(with_terms.id(), "k0".into());
        data.notes = notes.iter().map(|(n, _)| n.clone()).collect();
        data.notes.push(with_terms.clone());
        data.fsp_mints.insert(
            hex::encode(s1.serialize()),
            fsp_mint("http://one", "k1", Some("k0")),
        );
        data.fsp_mints.insert(
            hex::encode(s2.serialize()),
            fsp_mint("http://two", "k2", Some("k1")),
        );
        let path = scratch_file("fill");
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();

        let mut w = Wallet::open(&path).unwrap();
        assert_eq!(
            w.fsp_unknown_service(),
            (4, 15),
            "four notes have no service"
        );
        assert_eq!(w.fill_fsp_services().unwrap(), 2);
        let svc = |seed: u8| {
            w.notes()
                .iter()
                .find(|n| n.id() == bare_note(seed, 1).id())
                .unwrap()
                .fsp_service()
        };
        assert_eq!(svc(1), Some(s1));
        assert_eq!(svc(2), Some(s2));
        assert_eq!(svc(3), None, "a keyset two mints claim is not guessed");
        assert_eq!(svc(4), None, "a keyset no mint has is not guessed");
        assert_eq!(svc(5), Some(s2), "a recorded service is never changed");
        assert_eq!(w.fsp_unknown_service(), (2, 3));

        // Grouped by service in the balance and by keyset.
        let by = w.balance().fsp_by_service;
        assert_eq!(by[&hex::encode(s1.serialize())], 8);
        assert_eq!(by[&hex::encode(s2.serialize())], 4 + 16);
        assert_eq!(by[crate::store::UNKNOWN_SERVICE], 3);
        assert_eq!(w.balance().fsp, 8 + 4 + 2 + 1 + 16);
        let ks = w.fsp_by_keyset();
        assert_eq!(ks[&(hex::encode(s1.serialize()), "k0".to_string())], 8);
        assert_eq!(
            ks[&(crate::store::UNKNOWN_SERVICE.to_string(), "k1".to_string())],
            2
        );

        // It is saved, and a second run has nothing left to do.
        assert_eq!(w.fill_fsp_services().unwrap(), 0);
        let again = Wallet::open(&path).unwrap();
        assert_eq!(again.fsp_unknown_service(), (2, 3));
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
            notes: vec![known.clone(), unknown],
            ..Default::default()
        };
        let path = scratch_file("pick");
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        let w = Wallet::open(&path).unwrap();
        assert_eq!(known.fsp_service(), Some(s));
        assert!(
            w.select_fsp_handoff(&[(s, 8)]).is_err(),
            "only 4 is the service's"
        );
        assert_eq!(w.select_fsp_handoff(&[(s, 4)]).unwrap().len(), 1);
    }

    #[test]
    fn months() {
        assert_eq!(month_of(0), "1970-01");
        assert_eq!(month_of(20_741), "2026-10");
        assert_eq!(month_of(19_782), "2024-02");
    }
}
