//! ESP redemption, as the service.
//!
//! Only the owner of a service's DID key can redeem ESP for that service. The
//! wallet builds the request the ESP mint takes on `POST /redeem` (see the
//! esp-mint README, "Redemption"): its canonical binary encoding, made with the
//! mint's own `sp_wire::esp::redeem::encode`, signed by the service's key, with every
//! note's spend signature over the same digest.
//!
//! What the wallet does, step by step:
//!
//! 1. **Pick the notes.** Every free ESP note for the service whose
//!    redeemable-after day has come by this machine's clock (the mint's rule,
//!    `Terms::is_redeemable_at`), not flagged for a bad proof. Mixed days go in
//!    one request. A request that would owe nothing is not sent, with the reason.
//! 2. **Size and fee.** The size is exact before anything is signed:
//!    `119 + 186 × notes + memo bytes + 81 × outputs`. The fee is the size times
//!    the rate from `GET /fees`. The mint charges the rate in force when it
//!    accepts the request and says which on the reply.
//! 3. **Outputs.** The wallet expects every note to be accepted, so it asks for
//!    `decline_outputs` worth the accepted total minus the fee, one per service
//!    and day (the fee is taken from the day with the most value first), so that a declined
//!    payout gives the notes back under their own terms. `refund_outputs` are
//!    only needed when the accepted notes do not cover the fee; the wallet adds
//!    them when the mint says so (below).
//! 4. **Split.** A redemption larger than the mint's ceiling on one request
//!    (`redeem.max_request_bytes`, 64 MiB by default, from `GET /fees`) is split
//!    into several requests, each under the ceiling with room for its outputs.
//!    Each pays its own fee and gets its own queue entry.
//! 5. **Crash safety.** Each request is stored by its request hash with its
//!    encoded bytes and the blinding factors of its outputs, and its notes are
//!    reserved, before it is handed out. A retry sends exactly the same bytes, so
//!    the mint answers from its stored record.
//! 6. **The reply.** One result per note. Burned notes leave the wallet; a note
//!    the mint says is already spent is moved to the spent record; a note with a
//!    bad proof is flagged; any other note that was not burned is free again. Refund signatures become notes.
//!    If something is owed, the request stays in the wallet as *queued* until
//!    the operator pays it or declines it. "nothing owed, fee taken" ends it.
//! 7. **Refusals with totals.** When the mint refuses with `refund_required` or
//!    `outputs_over_limit`, nothing was burned and the body carries the totals
//!    the mint worked out. The wallet rebuilds the request from them (dropping
//!    notes that are spent or not genuine), signs it again and sends the new one.
//!    Any other refusal frees the notes.
//! 8. **Collect.** Sending a queued request again returns its queue entry as it
//!    is now: open, completed (with the payment reference), or declined (with the
//!    reason and the signatures on the reissued notes, which the wallet unblinds
//!    with the decline outputs' blinding factors).

use std::collections::BTreeMap;

use mint_types::{Amount, MintInput};
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use sp_wire::esp::queue::Status;
use sp_wire::esp::redeem::{
    self, NoteResult, Reason, RedeemInput, RedeemOutput, RedeemRequest, RedeemResponse, Totals,
};
use sp_wire::esp::terms::Terms;

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{Kind, StoredNote, StoredTerms, Wallet};

/// The fee rate to assume (ESP units per encoded byte) until `/fees` has been
/// read. It is the mint's placeholder default, not part of the wire format: the
/// mint's own rate is read from `GET /fees` and replaces it.
const DEFAULT_FEE_PER_BYTE: u128 = 1_000_000;

/// The request ceiling to assume (64 MiB) until `/fees` has been read. Also the
/// mint's default, not wire format.
const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;

/// The fee for a request of `size` encoded bytes at `fee_per_byte`: the size
/// times the rate, the way the mint charges it.
fn fee_for(size: u64, fee_per_byte: u128) -> u128 {
    u128::from(size).saturating_mul(fee_per_byte)
}

/// What the ESP mint says about redemption (`GET /fees`, `redeem`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedeemFees {
    /// ESP units per byte of the canonical encoding.
    pub fee_per_byte: u128,
    /// The ceiling on one encoded request, in bytes.
    pub max_request_bytes: u64,
    /// The longest payout memo, in bytes.
    pub max_memo_bytes: usize,
}

impl Default for RedeemFees {
    /// The mint's documented defaults.
    fn default() -> Self {
        RedeemFees {
            fee_per_byte: DEFAULT_FEE_PER_BYTE,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES as u64,
            max_memo_bytes: redeem::DEFAULT_MAX_MEMO_BYTES,
        }
    }
}

/// One output of a redemption, with its terms and blinding factors.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TermsOutput {
    pub service: XOnlyPublicKey,
    pub redeemable_after_day: u64,
    pub output: PendingOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionState {
    /// Built and maybe sent; no reply has been taken in yet.
    Sent,
    /// The mint took it and queued a payout. Waiting for the operator.
    Queued,
}

/// A redemption that has been built and is not over.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRedemption {
    /// The request hash, as the mint stores it and names its queue entry.
    pub id: String,
    pub service: XOnlyPublicKey,
    pub memo: String,
    /// The notes in the request, in its order.
    pub input_ids: Vec<String>,
    pub decline_outputs: Vec<TermsOutput>,
    pub refund_outputs: Vec<TermsOutput>,
    /// The canonical encoding, sent as is on every retry.
    pub body_hex: String,
    pub size_bytes: u64,
    /// The rate the request was sized for, and its fee at that rate.
    pub fee_per_byte: u128,
    pub fee_esp: u128,
    /// What the wallet expects to be owed, before the reply; what the mint
    /// says is owed, after it.
    pub owed_esp: u128,
    pub state: RedemptionState,
}

impl PendingRedemption {
    pub fn body(&self) -> Result<Vec<u8>, WalletError> {
        hex::decode(&self.body_hex)
            .map_err(|_| WalletError::Corrupt(format!("redemption {}: body is not hex", self.id)))
    }
}

/// A request ready to send.
#[derive(Debug, Clone)]
pub struct RedeemBuild {
    pub id: String,
    /// The body of `POST /redeem`.
    pub body: Vec<u8>,
    pub notes: usize,
    /// The notes' total, which the wallet expects to be accepted.
    pub esp_units: u128,
    pub size_bytes: u64,
    pub fee_per_byte: u128,
    pub fee_esp: u128,
    /// What the wallet expects to be owed: the accepted total minus the fee.
    pub owed_esp: u128,
    pub decline_outputs: usize,
    pub refund_outputs: usize,
}

/// What [`Wallet::plan_redemption`] built, and why any part was not built.
#[derive(Debug, Clone)]
pub struct RedeemPlan {
    pub built: Vec<RedeemBuild>,
    /// One line for each part that was not built, saying why.
    pub skipped: Vec<String>,
}

/// What a reply, or a later look at the entry, did to the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemOutcome {
    pub id: String,
    /// Per note, in the request's order: accepted, the reason if not, burned.
    pub notes: Vec<(bool, Option<Reason>, bool)>,
    pub accepted_esp: u128,
    pub rejected_esp: u128,
    pub fee_esp: u128,
    pub fee_per_byte: u128,
    pub size_bytes: u64,
    pub owed_esp: u128,
    /// "payout queued" or "nothing owed, fee taken".
    pub message: String,
    /// New notes from `refund_outputs`.
    pub refunded: Vec<String>,
    /// Notes the mint says are already spent, moved to the spent record.
    pub marked_spent: usize,
    /// Notes the mint did not burn and that are free again.
    pub freed: usize,
    /// How many of the freed notes were flagged for a bad proof.
    pub flagged_bad_proof: usize,
    /// Where the payout stands, if one is owed.
    pub entry: Option<EntryOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryOutcome {
    /// Waiting for the operator. Send the same request again later.
    Open,
    /// Paid, with the operator's payment reference.
    Completed { payment_ref: Option<String> },
    /// Declined: the accepted notes came back, minus the fee, as these notes.
    Declined {
        reason: Option<String>,
        reissued: Vec<String>,
        reissued_esp: u128,
    },
}

/// The amounts for one list of outputs: what is left of each service and day
/// after `take` is taken from them, in pieces that fit a `u64`. `take` comes
/// from the service and day with the most value first (on a tie, the one that
/// comes first in the mint's order), then the next largest, and so on. The mint
/// does not fix where the fee comes from: it only checks the total and each
/// day's cap. The outputs stay in the mint's order.
fn pieces(by_terms: &[(StoredTerms, u128)], take: u128) -> Vec<(StoredTerms, u64)> {
    let mut order: Vec<usize> = (0..by_terms.len()).collect();
    order.sort_by(|&x, &y| by_terms[y].1.cmp(&by_terms[x].1).then(x.cmp(&y)));
    let mut taken = vec![0u128; by_terms.len()];
    let mut left_to_take = take;
    for i in order {
        let t = left_to_take.min(by_terms[i].1);
        taken[i] = t;
        left_to_take -= t;
    }
    let mut out = Vec::new();
    for ((terms, total), taken) in by_terms.iter().zip(taken) {
        let mut rest = total - taken;
        while rest > 0 {
            let piece = rest.min(u128::from(u64::MAX));
            out.push((*terms, piece as u64));
            rest -= piece;
        }
    }
    out
}

/// The outputs a request needs, worked out the way the mint checks them
/// (`decide` in esp-mint): `accepted` and `rejected` are the genuine, unspent
/// notes' totals by service and day; `inputs` and `memo_bytes` size the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub decline: Vec<(StoredTerms, u64)>,
    pub refund: Vec<(StoredTerms, u64)>,
    pub size_bytes: u64,
    pub fee_esp: u128,
    pub owed_esp: u128,
}

pub fn allocate(
    accepted: &[(StoredTerms, u128)],
    rejected: &[(StoredTerms, u128)],
    inputs: usize,
    memo_bytes: usize,
    fee_per_byte: u128,
) -> Result<Allocation, WalletError> {
    let a: u128 = accepted.iter().map(|(_, v)| v).sum();
    let r: u128 = rejected.iter().map(|(_, v)| v).sum();
    // The output counts change the size, which changes the fee, which can change
    // the counts. Start from one output per service and day and settle on
    // counts that reproduce themselves.
    let mut counts = (pieces(accepted, 0).len(), 0usize);
    let mut seen = Vec::new();
    loop {
        let size = redeem::encoded_len(inputs, memo_bytes, counts.0, counts.1);
        let fee = fee_for(size, fee_per_byte);
        if a + r < fee {
            return Err(WalletError::NotEnough(format!(
                "the notes are worth {} ESP units, less than the fee of {fee} ({size} bytes at {fee_per_byte} a byte). The mint would refuse: nothing is sent",
                a + r
            )));
        }
        let (decline, refund) = if a >= fee {
            (pieces(accepted, fee), Vec::new())
        } else {
            (Vec::new(), pieces(rejected, fee - a))
        };
        let next = (decline.len(), refund.len());
        if next == counts {
            return Ok(Allocation {
                decline,
                refund,
                size_bytes: size,
                fee_esp: fee,
                owed_esp: a.saturating_sub(fee),
            });
        }
        if seen.contains(&next) && a > 0 {
            let size = redeem::encoded_len(inputs, memo_bytes, next.0, next.1).max(size);
            let fee = fee_for(size, fee_per_byte);
            // The value is about the fee: with its decline output the fee takes
            // everything, and without one the request is smaller and owes a
            // little, which needs the output again. Either way it is not worth
            // sending: with the output it would owe nothing.
            return Err(WalletError::NotEnough(format!(
                "{} note(s) worth {a} ESP units would all go to the fee of {fee} ESP units ({size} bytes at {fee_per_byte} a byte), so the mint would owe nothing. Nothing is sent",
                inputs
            )));
        }
        if seen.contains(&next) || seen.len() > 8 {
            return Err(WalletError::Invalid(
                "could not settle on a number of outputs for this redemption".into(),
            ));
        }
        seen.push(counts);
        counts = next;
    }
}

/// Whether a list of outputs is within what the mint will sign: at most `cap`
/// in all, and for each service and day at most what `per_terms` holds.
fn within(list: &[(StoredTerms, u64)], cap: u128, per_terms: &[(StoredTerms, u128)]) -> bool {
    let mut asked: BTreeMap<([u8; 32], u64), u128> = BTreeMap::new();
    for (t, v) in list {
        *asked
            .entry((t.service.serialize(), t.redeemable_after_day))
            .or_default() += u128::from(*v);
    }
    let total: u128 = asked.values().sum();
    total <= cap
        && asked.iter().all(|((s, d), v)| {
            per_terms
                .iter()
                .find(|(t, _)| t.service.serialize() == *s && t.redeemable_after_day == *d)
                .is_some_and(|(_, have)| v <= have)
        })
}

/// The mint's checks on an allocation (`decide`, after the decision): the
/// decline outputs within the payout, refunds present when they are due and
/// within the rest. Used by the tests and as a last check before signing.
pub fn mint_would_accept(
    alloc: &Allocation,
    accepted: &[(StoredTerms, u128)],
    rejected: &[(StoredTerms, u128)],
) -> bool {
    let a: u128 = accepted.iter().map(|(_, v)| v).sum();
    let r: u128 = rejected.iter().map(|(_, v)| v).sum();
    let fee = alloc.fee_esp;
    if a + r < fee {
        return false;
    }
    let shortfall = fee.saturating_sub(a);
    let owed = a.saturating_sub(fee);
    let refundable = if shortfall > 0 { r - shortfall } else { 0 };
    within(&alloc.decline, owed, accepted)
        && !(shortfall > 0 && refundable > 0 && alloc.refund.is_empty())
        && within(&alloc.refund, refundable, rejected)
}

/// Totals by service and day, in the mint's order (service bytes, then day).
fn by_terms(notes: &[&StoredNote]) -> Vec<(StoredTerms, u128)> {
    let mut map: BTreeMap<([u8; 32], u64), (StoredTerms, u128)> = BTreeMap::new();
    for n in notes {
        if let Some(t) = n.terms {
            let slot = map
                .entry((t.service.serialize(), t.redeemable_after_day))
                .or_insert((t, 0));
            slot.1 += u128::from(n.amount);
        }
    }
    map.into_values().collect()
}

fn from_totals(list: &[redeem::TermsTotal]) -> Vec<(StoredTerms, u128)> {
    let mut v: Vec<(StoredTerms, u128)> = list
        .iter()
        .map(|t| {
            (
                StoredTerms {
                    service: t.service,
                    redeemable_after_day: t.redeemable_after_day,
                },
                t.esp,
            )
        })
        .collect();
    v.sort_by_key(|(t, _)| (t.service.serialize(), t.redeemable_after_day));
    v
}

fn check_memo(memo: &str, max: usize) -> Result<(), WalletError> {
    if memo.trim().is_empty() || memo.len() > max {
        return Err(WalletError::Invalid(format!(
            "the payout memo must not be empty and must be at most {max} bytes"
        )));
    }
    Ok(())
}

/// Sign a request for these notes and outputs and make its pending record.
fn sign_request(
    service_keypair: &Keypair,
    notes: &[StoredNote],
    input_keysets: &[String],
    output_keyset: &str,
    memo: &str,
    alloc: &Allocation,
    fee_per_byte: u128,
) -> Result<(RedeemBuild, PendingRedemption), WalletError> {
    if output_keyset.is_empty() {
        return Err(WalletError::Invalid(
            "the ESP mint's current keyset is not known yet: connect to the mint first".into(),
        ));
    }
    let service = service_keypair.x_only_public_key().0;
    let make = |list: &[(StoredTerms, u64)]| -> Vec<TermsOutput> {
        list.iter()
            .map(|(t, amount)| TermsOutput {
                service: t.service,
                redeemable_after_day: t.redeemable_after_day,
                output: PendingOutput::new(*amount),
            })
            .collect()
    };
    let decline = make(&alloc.decline);
    let refund = make(&alloc.refund);
    let wire = |list: &[TermsOutput]| -> Vec<RedeemOutput> {
        list.iter()
            .map(|o| RedeemOutput {
                service: o.service,
                redeemable_after_day: o.redeemable_after_day,
                output: o.output.mint_output(),
            })
            .collect()
    };
    let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64])
        .map_err(|e| WalletError::Invalid(e.to_string()))?;
    let mut inputs: Vec<RedeemInput> = Vec::with_capacity(notes.len());
    for (n, keyset) in notes.iter().zip(input_keysets) {
        let t = n
            .terms
            .ok_or_else(|| WalletError::Invalid("an ESP note has no terms".into()))?;
        inputs.push(RedeemInput {
            service: t.service,
            redeemable_after_day: t.redeemable_after_day,
            keyset: keyset.clone(),
            input: MintInput {
                amount: Amount::from_units(n.amount),
                note: n.note,
                spend_signature: dummy,
            },
        });
    }
    let mut request = RedeemRequest {
        service,
        output_keyset: output_keyset.to_string(),
        inputs,
        memo: memo.to_string(),
        decline_outputs: wire(&decline),
        refund_outputs: wire(&refund),
        service_signature: dummy,
    };
    let digest = request.digest();
    for (input, held) in request.inputs.iter_mut().zip(notes) {
        let keypair = Keypair::from_secret_key(SECP256K1, &held.spend_secret);
        input.input.spend_signature = SECP256K1.sign_schnorr(&digest, &keypair);
    }
    request.service_signature = SECP256K1.sign_schnorr(&digest, service_keypair);
    let body = request.encode();
    if body.len() as u64 != alloc.size_bytes || request.encoded_len() != alloc.size_bytes {
        return Err(WalletError::Invalid(format!(
            "the request is {} bytes, not the {} it was sized for",
            body.len(),
            alloc.size_bytes
        )));
    }
    let id = redeem::request_hash(&request);
    let esp_units: u128 = notes.iter().map(|n| u128::from(n.amount)).sum();
    let pending = PendingRedemption {
        id: id.clone(),
        service,
        memo: memo.to_string(),
        input_ids: notes.iter().map(StoredNote::id).collect(),
        decline_outputs: decline,
        refund_outputs: refund,
        body_hex: hex::encode(&body),
        size_bytes: alloc.size_bytes,
        fee_per_byte,
        fee_esp: alloc.fee_esp,
        owed_esp: alloc.owed_esp,
        state: RedemptionState::Sent,
    };
    let build = RedeemBuild {
        id,
        body,
        notes: notes.len(),
        esp_units,
        size_bytes: alloc.size_bytes,
        fee_per_byte,
        fee_esp: alloc.fee_esp,
        owed_esp: alloc.owed_esp,
        decline_outputs: pending.decline_outputs.len(),
        refund_outputs: pending.refund_outputs.len(),
    };
    Ok((build, pending))
}

/// Split notes, in order, into groups that fit the ceiling: each group's
/// request, with one decline and one refund output per service and day (the
/// most it can need), is at most `max_bytes`.
fn split(
    notes: Vec<StoredNote>,
    memo_bytes: usize,
    max_bytes: u64,
) -> Result<Vec<Vec<StoredNote>>, WalletError> {
    let worst = |group: &[StoredNote]| -> u64 {
        let refs: Vec<&StoredNote> = group.iter().collect();
        let terms = pieces(&by_terms(&refs), 0).len();
        redeem::encoded_len(group.len(), memo_bytes, terms, terms)
    };
    let mut groups: Vec<Vec<StoredNote>> = Vec::new();
    let mut current: Vec<StoredNote> = Vec::new();
    for note in notes {
        current.push(note);
        if worst(&current) > max_bytes {
            let note = current.pop().unwrap_or_else(|| unreachable!());
            if current.is_empty() {
                return Err(WalletError::Invalid(format!(
                    "the mint's ceiling of {max_bytes} bytes is too small for even one note"
                )));
            }
            groups.push(std::mem::take(&mut current));
            current.push(note);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    Ok(groups)
}

impl Wallet {
    pub fn pending_redemptions(&self) -> &[PendingRedemption] {
        self.redemptions()
    }

    /// Build the redemption of every free, mature ESP note this wallet holds for
    /// the service whose key is `service_secret`, as one request or, past the
    /// mint's ceiling, several. `now_unix` is this machine's clock, which picks
    /// the mature notes the way the mint's does. Nothing is sent: each request
    /// is stored, with its notes reserved, and returned for the caller to send.
    ///
    /// Refused here, before anything is stored: no mature notes; a memo the mint
    /// would refuse; and a request whose notes would not cover its fee, or would
    /// leave nothing to pay out once the fee is taken.
    pub fn build_redemption(
        &mut self,
        service_secret: &SecretKey,
        memo: &str,
        fees: &RedeemFees,
        now_unix: u64,
    ) -> Result<Vec<RedeemBuild>, WalletError> {
        Ok(self
            .plan_redemption(service_secret, memo, fees, now_unix)?
            .built)
    }

    /// As [`Wallet::build_redemption`], and also says why any part was not
    /// built. A part (after splitting under the ceiling) whose notes would all
    /// go to the fee, so that the mint would owe nothing, is not built: its
    /// notes stay free and `skipped` says why. If no part is left, this is
    /// `NotEnough` with the same reason. Notes flagged for a bad proof are
    /// never picked.
    pub fn plan_redemption(
        &mut self,
        service_secret: &SecretKey,
        memo: &str,
        fees: &RedeemFees,
        now_unix: u64,
    ) -> Result<RedeemPlan, WalletError> {
        check_memo(memo, fees.max_memo_bytes)?;
        let keypair = Keypair::from_secret_key(SECP256K1, service_secret);
        let service = keypair.x_only_public_key().0;
        let mut chosen: Vec<StoredNote> = self
            .notes()
            .iter()
            .filter(|n| {
                n.kind == Kind::Esp
                    && n.reserved_by.is_none()
                    && !self.is_flagged_bad_proof(&n.id())
                    && n.terms.is_some_and(|t| {
                        t.service == service
                            && Terms {
                                service: t.service,
                                redeemable_after_day: t.redeemable_after_day,
                            }
                            .is_redeemable_at(now_unix)
                    })
            })
            .cloned()
            .collect();
        if chosen.is_empty() {
            return Err(WalletError::NotEnough(
                "this wallet holds no free ESP for that service whose redeemable-after day has come".into(),
            ));
        }
        chosen.sort_by(|a, b| {
            let (ta, tb) = (
                a.terms.unwrap_or_else(|| unreachable!()),
                b.terms.unwrap_or_else(|| unreachable!()),
            );
            ta.redeemable_after_day
                .cmp(&tb.redeemable_after_day)
                .then_with(|| b.amount.cmp(&a.amount))
                .then_with(|| a.id().cmp(&b.id()))
        });
        let groups = split(chosen, memo.len(), fees.max_request_bytes)?;
        let mut built = Vec::new();
        let mut pendings = Vec::new();
        let mut skipped = Vec::new();
        for group in &groups {
            let refs: Vec<&StoredNote> = group.iter().collect();
            let accepted = by_terms(&refs);
            let alloc = match allocate(&accepted, &[], group.len(), memo.len(), fees.fee_per_byte) {
                Ok(a) => a,
                Err(WalletError::NotEnough(why)) => {
                    skipped.push(format!("not sent: {why}"));
                    continue;
                }
                Err(e) => return Err(e),
            };
            if alloc.owed_esp == 0 {
                skipped.push(format!(
                    "not sent: {} note(s) worth {} ESP units would all go to the fee of {} ESP units ({} bytes at {} a byte), so the mint would owe nothing. The notes stay in the wallet; redeem them with more notes later",
                    group.len(),
                    accepted.iter().map(|(_, v)| v).sum::<u128>(),
                    alloc.fee_esp,
                    alloc.size_bytes,
                    fees.fee_per_byte
                ));
                continue;
            }
            if alloc.size_bytes > fees.max_request_bytes
                || !mint_would_accept(&alloc, &accepted, &[])
            {
                return Err(WalletError::Invalid(
                    "the request does not fit the mint's rules".into(),
                ));
            }
            let keysets: Vec<String> = group
                .iter()
                .map(|n| self.esp_keyset_of(n))
                .collect::<Result<_, _>>()?;
            let (build, pending) = sign_request(
                &keypair,
                group,
                &keysets,
                &self.esp_output_keyset(),
                memo,
                &alloc,
                fees.fee_per_byte,
            )?;
            built.push(build);
            pendings.push(pending);
        }
        self.update(|d| {
            for p in &pendings {
                for note in d.notes.iter_mut().filter(|n| p.input_ids.contains(&n.id())) {
                    note.reserved_by = Some(p.id.clone());
                }
            }
            d.pending_redemptions.extend(pendings);
            Ok(())
        })?;
        if built.is_empty() {
            return Err(WalletError::NotEnough(skipped.join("; ")));
        }
        Ok(RedeemPlan { built, skipped })
    }

    /// Whether a note is flagged because the mint found its proof bad. A flagged
    /// note stays in the wallet but is not picked for a redemption.
    pub fn is_flagged_bad_proof(&self, note_id: &str) -> bool {
        self.bad_proof_notes().iter().any(|id| id == note_id)
    }

    /// Clear the bad-proof flag on a note, so it can be picked again.
    pub fn clear_bad_proof(&mut self, note_id: &str) -> Result<(), WalletError> {
        if !self.is_flagged_bad_proof(note_id) {
            return Err(WalletError::Unknown(format!(
                "note {note_id} is not flagged"
            )));
        }
        self.update(|d| {
            d.bad_proof.retain(|id| id != note_id);
            Ok(())
        })
    }

    /// Rebuild a refused request from the totals in the mint's refusal
    /// (`refund_required` or `outputs_over_limit`), as the mint worked them out.
    /// Nothing was burned. Notes the mint found already spent go to the spent
    /// record and notes that are not genuine are freed; both are left out. The
    /// outputs are made again for what the mint will reissue, the request is
    /// signed again, and it replaces the refused one.
    pub fn rebuild_redemption(
        &mut self,
        id: &str,
        service_secret: &SecretKey,
        totals: &Totals,
    ) -> Result<RedeemBuild, WalletError> {
        let pending = self.find_redemption(id)?;
        if pending.state != RedemptionState::Sent {
            return Err(WalletError::Invalid(format!(
                "redemption {id} was already taken by the mint"
            )));
        }
        let keypair = Keypair::from_secret_key(SECP256K1, service_secret);
        if keypair.x_only_public_key().0 != pending.service {
            return Err(WalletError::Invalid(
                "that is not the key of the service this redemption is for".into(),
            ));
        }
        if totals.notes.len() != pending.input_ids.len() {
            return Err(WalletError::Mint(
                "the mint's totals do not match the request".into(),
            ));
        }
        let mut keep = Vec::new();
        let mut spent = Vec::new();
        let mut drop = Vec::new();
        for (note_id, result) in pending.input_ids.iter().zip(&totals.notes) {
            match result.reason {
                Some(Reason::AlreadySpent) => spent.push(note_id.clone()),
                Some(Reason::BadProof) => drop.push(note_id.clone()),
                _ => keep.push(note_id.clone()),
            }
        }
        let notes: Vec<StoredNote> = keep
            .iter()
            .map(|nid| {
                self.notes()
                    .iter()
                    .find(|n| &n.id() == nid)
                    .cloned()
                    .ok_or_else(|| WalletError::Corrupt(format!("reserved note {nid} is missing")))
            })
            .collect::<Result<_, _>>()?;
        let accepted = from_totals(&totals.accepted_by_terms);
        let rejected = from_totals(&totals.rejected_by_terms);
        let freed = |d: &mut crate::store::WalletData| {
            d.notes
                .retain(|n| if spent.contains(&n.id()) { false } else { true });
        };
        let spent_notes: Vec<StoredNote> = self
            .notes()
            .iter()
            .filter(|n| spent.contains(&n.id()))
            .cloned()
            .map(|mut n| {
                n.reserved_by = None;
                n
            })
            .collect();
        let flag = drop.clone();
        if notes.is_empty() {
            self.update(|d| {
                freed(d);
                for nid in &flag {
                    if !d.bad_proof.contains(nid) {
                        d.bad_proof.push(nid.clone());
                    }
                }
                d.spent.extend(spent_notes);
                d.pending_redemptions.retain(|p| p.id != id);
                for n in d
                    .notes
                    .iter_mut()
                    .filter(|n| n.reserved_by.as_deref() == Some(id))
                {
                    n.reserved_by = None;
                }
                Ok(())
            })?;
            return Err(WalletError::NotEnough(format!(
                "none of the notes can be redeemed: {} already spent, {} with a bad proof (flagged)",
                spent.len(),
                flag.len()
            )));
        }
        let rate = totals.fee_per_byte;
        let alloc = match allocate(&accepted, &rejected, notes.len(), pending.memo.len(), rate) {
            Ok(a) if mint_would_accept(&a, &accepted, &rejected) => a,
            other => {
                self.cancel_redemption(id)?;
                return Err(match other {
                    Err(e) => e,
                    Ok(_) => WalletError::Invalid(
                        "the rebuilt request does not fit the mint's rules".into(),
                    ),
                });
            }
        };
        let keysets: Vec<String> = notes
            .iter()
            .map(|n| self.esp_keyset_of(n))
            .collect::<Result<_, _>>()?;
        let (build, next) = sign_request(
            &keypair,
            &notes,
            &keysets,
            &self.esp_output_keyset(),
            &pending.memo,
            &alloc,
            rate,
        )?;
        let new_id = next.id.clone();
        self.update(|d| {
            freed(d);
            for nid in &flag {
                if !d.bad_proof.contains(nid) {
                    d.bad_proof.push(nid.clone());
                }
            }
            d.spent.extend(spent_notes);
            d.pending_redemptions.retain(|p| p.id != id);
            for n in d.notes.iter_mut() {
                if n.reserved_by.as_deref() == Some(id) {
                    n.reserved_by = if keep.contains(&n.id()) {
                        Some(new_id.clone())
                    } else {
                        None
                    };
                }
            }
            d.pending_redemptions.push(next);
            Ok(())
        })?;
        Ok(build)
    }

    fn find_redemption(&self, id: &str) -> Result<PendingRedemption, WalletError> {
        self.pending_redemptions()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending redemption {id}")))
    }

    /// Take in the mint's reply to a redemption, or to the same request sent
    /// again. The first reply settles the notes and the refunds; every reply
    /// reports the payout's entry, and a completed or declined entry ends the
    /// redemption (a declined one gives the reissued notes back). Safe to call
    /// with a repeated reply.
    pub fn finish_redemption(
        &mut self,
        id: &str,
        response: &RedeemResponse,
    ) -> Result<RedeemOutcome, WalletError> {
        let pending = self.find_redemption(id)?;
        if response.notes.len() != pending.input_ids.len() {
            return Err(WalletError::Mint(
                "the reply does not have one result for each note".into(),
            ));
        }
        let first = pending.state == RedemptionState::Sent;
        if first && response.refund.len() != pending.refund_outputs.len() {
            return Err(WalletError::Mint(
                "the reply does not have one signature for each refund output".into(),
            ));
        }
        if response.owed_esp > 0 && response.entry.is_none() {
            return Err(WalletError::Mint(
                "the reply says something is owed but has no entry".into(),
            ));
        }
        let mut refunded = Vec::new();
        let mut new_notes = Vec::new();
        // The keyset each reissued note was signed by, as the mint names it.
        let mut new_keysets: Vec<(String, String)> = Vec::new();
        if first {
            for (o, signed) in pending.refund_outputs.iter().zip(&response.refund) {
                let note = StoredNote {
                    kind: Kind::Esp,
                    amount: o.output.amount,
                    note: o.output.unblind(&signed.signature, &signed.key),
                    spend_secret: o.output.nonce_secret,
                    terms: Some(StoredTerms {
                        service: o.service,
                        redeemable_after_day: o.redeemable_after_day,
                    }),
                    reserved_by: None,
                };
                new_keysets.push((note.id(), signed.keyset.clone()));
                refunded.push(note.id());
                new_notes.push(note);
            }
        }
        let mut burned = Vec::new();
        let mut spent = Vec::new();
        let mut free = Vec::new();
        let mut flagged: Vec<String> = Vec::new();
        if first {
            for (nid, r) in pending.input_ids.iter().zip(&response.notes) {
                if r.burned {
                    burned.push(nid.clone());
                } else if r.reason == Some(Reason::AlreadySpent) {
                    spent.push(nid.clone());
                } else {
                    if r.reason == Some(Reason::BadProof) {
                        flagged.push(nid.clone());
                    }
                    free.push(nid.clone());
                }
            }
        }
        let entry = match &response.entry {
            None => None,
            Some(view) => Some(match view.status {
                Status::Open => EntryOutcome::Open,
                Status::Completed => EntryOutcome::Completed {
                    payment_ref: view.payment_ref.clone(),
                },
                Status::Declined => {
                    if view.decline_signatures.len() != pending.decline_outputs.len() {
                        return Err(WalletError::Mint(
                            "the declined entry does not have one signature for each decline output".into(),
                        ));
                    }
                    let mut ids = Vec::new();
                    let mut units = 0u128;
                    for (o, signed) in pending.decline_outputs.iter().zip(&view.decline_signatures)
                    {
                        let note = StoredNote {
                            kind: Kind::Esp,
                            amount: o.output.amount,
                            note: o.output.unblind(&signed.signature, &signed.key),
                            spend_secret: o.output.nonce_secret,
                            terms: Some(StoredTerms {
                                service: o.service,
                                redeemable_after_day: o.redeemable_after_day,
                            }),
                            reserved_by: None,
                        };
                        units += u128::from(o.output.amount);
                        new_keysets.push((note.id(), signed.keyset.clone()));
                        ids.push(note.id());
                        new_notes.push(note);
                    }
                    EntryOutcome::Declined {
                        reason: view.decline_reason.clone(),
                        reissued: ids,
                        reissued_esp: units,
                    }
                }
            }),
        };
        let over = !matches!(entry, Some(EntryOutcome::Open));
        let (marked_spent, freed) = (spent.len(), free.len());
        self.update(|d| {
            let moved: Vec<StoredNote> = d
                .notes
                .iter()
                .filter(|n| spent.contains(&n.id()))
                .cloned()
                .map(|mut n| {
                    n.reserved_by = None;
                    n
                })
                .collect();
            d.spent.extend(moved);
            d.notes
                .retain(|n| !burned.contains(&n.id()) && !spent.contains(&n.id()));
            for n in d.notes.iter_mut().filter(|n| free.contains(&n.id())) {
                n.reserved_by = None;
            }
            for nid in &flagged {
                if !d.bad_proof.contains(nid) {
                    d.bad_proof.push(nid.clone());
                }
            }
            for (nid, keyset) in &new_keysets {
                if keyset.is_empty() {
                    return Err(WalletError::Mint(format!(
                        "the mint's reply names no keyset for note {nid}; it cannot be stored"
                    )));
                }
                d.keysets.insert(nid.clone(), keyset.clone());
            }
            // Only notes the wallet does not hold yet: a repeated reply adds nothing.
            for note in new_notes {
                if !d.notes.iter().any(|n| n.id() == note.id()) {
                    d.notes.push(note);
                }
            }
            if over {
                d.pending_redemptions.retain(|p| p.id != id);
            } else if let Some(p) = d.pending_redemptions.iter_mut().find(|p| p.id == id) {
                p.state = RedemptionState::Queued;
                p.owed_esp = response.owed_esp;
                p.fee_esp = response.fee_esp;
                p.fee_per_byte = response.fee_per_byte;
            }
            Ok(())
        })?;
        Ok(RedeemOutcome {
            id: id.to_string(),
            notes: response
                .notes
                .iter()
                .map(|n| (n.accepted, n.reason, n.burned))
                .collect(),
            accepted_esp: response.accepted_esp,
            rejected_esp: response.rejected_esp,
            fee_esp: response.fee_esp,
            fee_per_byte: response.fee_per_byte,
            size_bytes: response.size_bytes,
            owed_esp: response.owed_esp,
            message: response.message.clone(),
            refunded,
            marked_spent,
            freed,
            flagged_bad_proof: flagged.len(),
            entry,
        })
    }

    /// The mint refused redemption `id` and said what it made of each note
    /// (`below_fee` carries `notes`). Nothing was burned. Notes it calls
    /// already spent go to the spent record, notes with a bad proof are flagged
    /// like a rebuild would, the others are free again, and the redemption is
    /// dropped. If `notes` is empty or does not match the request, this is
    /// `cancel_redemption`.
    pub fn refuse_redemption(
        &mut self,
        id: &str,
        notes: &[NoteResult],
    ) -> Result<crate::esp::SpentReport, WalletError> {
        let pending = self.find_redemption(id)?;
        if pending.state == RedemptionState::Queued {
            return Err(WalletError::Invalid(format!(
                "redemption {id} was taken by the mint and its notes are burned. Collect it instead"
            )));
        }
        if notes.len() != pending.input_ids.len() {
            self.cancel_redemption(id)?;
            return Ok(Default::default());
        }
        let mut spent_ids = Vec::new();
        let mut bad = Vec::new();
        for (nid, r) in pending.input_ids.iter().zip(notes) {
            match r.reason {
                Some(Reason::AlreadySpent) => spent_ids.push(nid.clone()),
                Some(Reason::BadProof) => bad.push(nid.clone()),
                _ => {}
            }
        }
        self.update(|d| {
            d.pending_redemptions.retain(|p| p.id != id);
            for nid in &bad {
                if !d.bad_proof.contains(nid) {
                    d.bad_proof.push(nid.clone());
                }
            }
            Ok(Wallet::retire_reserved(d, id, &spent_ids))
        })
    }

    /// Drop a redemption the mint refused and free its notes. Only safe when the
    /// mint refused it, so nothing was burned. After a fault whose outcome is
    /// unknown, send the same request again instead. A queued redemption cannot
    /// be cancelled: the mint has burned its notes.
    pub fn cancel_redemption(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            let Some(p) = d.pending_redemptions.iter().find(|p| p.id == id) else {
                return Err(WalletError::Unknown(format!("no pending redemption {id}")));
            };
            if p.state == RedemptionState::Queued {
                return Err(WalletError::Invalid(format!(
                    "redemption {id} was taken by the mint and its notes are burned. Collect it instead"
                )));
            }
            d.pending_redemptions.retain(|p| p.id != id);
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
    use sp_wire::esp::queue::{EntryView, SignedOutput};
    use sp_wire::esp::redeem::NoteResult;

    /// Day 20_735 at noon.
    const NOW: u64 = 20_735 * 86_400 + 43_200;
    const PAST: u64 = 20_000;
    const PAST2: u64 = 20_500;
    const FUTURE: u64 = 21_000;
    const ONE: u64 = 1_000_000_000_000;
    const RATE: u128 = 1_000_000;
    const MEMO: &str = "btc:bc1qpayhere";

    fn key(n: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        SecretKey::from_slice(&bytes).unwrap()
    }

    fn service() -> XOnlyPublicKey {
        Keypair::from_secret_key(SECP256K1, &key(1))
            .x_only_public_key()
            .0
    }

    fn terms(day: u64) -> StoredTerms {
        StoredTerms {
            service: service(),
            redeemable_after_day: day,
        }
    }

    fn fees() -> RedeemFees {
        RedeemFees {
            fee_per_byte: RATE,
            ..RedeemFees::default()
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-rd-{}-{name}", {
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

    /// A stored ESP note with a made-up mint signature.
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
        w.note_esp_keysets("http://esp", &"ab".repeat(8), None)
            .unwrap();
        (w, dir)
    }

    fn fee_of(inputs: usize, decline: usize, refund: usize) -> u128 {
        fee_for(
            redeem::encoded_len(inputs, MEMO.len(), decline, refund),
            RATE,
        )
    }

    #[test]
    fn one_day_pays_the_fee_and_the_rest_comes_back_in_one_decline_output() {
        let accepted = [(terms(PAST), u128::from(5 * ONE))];
        let a = allocate(&accepted, &[], 2, MEMO.len(), RATE).unwrap();
        assert_eq!(a.size_bytes, 119 + 2 * 186 + MEMO.len() as u64 + 81);
        assert_eq!(a.fee_esp, fee_of(2, 1, 0));
        assert_eq!(
            a.decline,
            vec![(terms(PAST), (u128::from(5 * ONE) - a.fee_esp) as u64)]
        );
        assert!(a.refund.is_empty());
        assert_eq!(a.owed_esp, u128::from(5 * ONE) - a.fee_esp);
        assert!(mint_would_accept(&a, &accepted, &[]));
    }

    #[test]
    fn with_mixed_days_the_fee_is_taken_from_the_largest_day_first_and_each_day_keeps_its_own() {
        let accepted = [(terms(PAST), 1_000), (terms(PAST2), u128::from(ONE))];
        let a = allocate(&accepted, &[], 2, MEMO.len(), RATE).unwrap();
        // The later day holds the most, so the fee comes out of it and the
        // small early day keeps its 1000 units.
        assert_eq!(a.fee_esp, fee_of(2, 2, 0));
        assert_eq!(
            a.decline,
            vec![
                (terms(PAST), 1_000),
                (terms(PAST2), (u128::from(ONE) - a.fee_esp) as u64)
            ]
        );
        assert!(mint_would_accept(&a, &accepted, &[]));
        // When the largest day cannot cover it all, the next largest pays the rest.
        let f2 = fee_of(2, 2, 0);
        let total = f2 + 15;
        let accepted = [(terms(PAST), f2 / 2 + 5), (terms(PAST2), f2 / 2 + 10)];
        let a = allocate(&accepted, &[], 2, MEMO.len(), RATE).unwrap();
        // PAST2 is all taken; PAST pays the rest and keeps what is left.
        assert_eq!(a.fee_esp, fee_of(2, 1, 0));
        assert_eq!(a.decline, vec![(terms(PAST), (total - a.fee_esp) as u64)]);
        assert!(mint_would_accept(&a, &accepted, &[]));
        // Both big enough: one output each.
        let accepted = [
            (terms(PAST), u128::from(ONE)),
            (terms(PAST2), u128::from(ONE)),
        ];
        let a = allocate(&accepted, &[], 2, MEMO.len(), RATE).unwrap();
        assert_eq!(a.decline.len(), 2);
        assert_eq!(a.decline[1], (terms(PAST2), ONE));
        assert_eq!(u128::from(a.decline[0].1), u128::from(ONE) - a.fee_esp);
        assert!(mint_would_accept(&a, &accepted, &[]));
    }

    #[test]
    fn when_the_accepted_notes_do_not_cover_the_fee_the_rejected_ones_are_refunded() {
        let accepted = [(terms(PAST), 1_000)];
        let rejected = [(terms(FUTURE), u128::from(ONE))];
        let a = allocate(&accepted, &rejected, 2, MEMO.len(), RATE).unwrap();
        assert!(a.decline.is_empty());
        assert_eq!(a.fee_esp, fee_of(2, 0, 1));
        assert_eq!(
            a.refund,
            vec![(terms(FUTURE), (u128::from(ONE) + 1_000 - a.fee_esp) as u64)]
        );
        assert_eq!(a.owed_esp, 0);
        assert!(mint_would_accept(&a, &accepted, &rejected));
        // Without the refund the mint would refuse (refund_required).
        let mut missing = a.clone();
        missing.refund.clear();
        assert!(!mint_would_accept(&missing, &accepted, &rejected));
        // Asking for more than is left is over the limit.
        let mut greedy = a.clone();
        greedy.refund[0].1 += 1;
        assert!(!mint_would_accept(&greedy, &accepted, &rejected));
    }

    #[test]
    fn notes_worth_less_than_the_fee_are_refused_before_anything_is_sent() {
        let err = allocate(&[(terms(PAST), 1_000)], &[], 1, MEMO.len(), RATE).unwrap_err();
        assert!(matches!(err, WalletError::NotEnough(_)), "{err}");
    }

    #[test]
    fn a_total_past_u64_comes_back_in_pieces_that_fit() {
        let big = u128::from(u64::MAX) * 2 + 10;
        let p = pieces(&[(terms(PAST), big)], 5);
        assert_eq!(p.len(), 3);
        assert_eq!(p.iter().map(|(_, v)| u128::from(*v)).sum::<u128>(), big - 5);
    }

    #[test]
    fn the_request_is_the_mints_encoding_signed_by_the_service_and_its_notes_are_held() {
        let notes = vec![
            esp_note(3 * ONE, service(), PAST),
            esp_note(2 * ONE, service(), PAST2),
            esp_note(ONE, service(), FUTURE),
            esp_note(
                ONE,
                Keypair::from_secret_key(SECP256K1, &key(2))
                    .x_only_public_key()
                    .0,
                PAST,
            ),
        ];
        let (mut w, dir) = wallet_with("build", notes.clone());
        let built = w.build_redemption(&key(1), MEMO, &fees(), NOW).unwrap();
        assert_eq!(built.len(), 1);
        let b = &built[0];
        // the two mature notes for this service, mixed days; not the future one
        // and not the other service's
        assert_eq!(b.notes, 2);
        assert_eq!(b.esp_units, u128::from(5 * ONE));
        assert_eq!(b.body.len() as u64, b.size_bytes);
        assert_eq!(b.size_bytes, redeem::encoded_len(2, MEMO.len(), 2, 0));
        assert_eq!(b.fee_esp, fee_for(b.size_bytes, RATE));
        assert_eq!(b.owed_esp, b.esp_units - b.fee_esp);
        let request = redeem::decode(&b.body).unwrap();
        assert_eq!(redeem::request_hash(&request), b.id);
        assert_eq!(request.memo, MEMO);
        assert_eq!(request.service, service());
        SECP256K1
            .verify_schnorr(&request.service_signature, &request.digest(), &service())
            .unwrap();
        for input in &request.inputs {
            SECP256K1
                .verify_schnorr(
                    &input.input.spend_signature,
                    &request.digest(),
                    &input.input.note.spend_key().x_only_public_key().0,
                )
                .unwrap();
        }
        let decline: u128 = request
            .decline_outputs
            .iter()
            .map(|o| u128::from(o.output.amount.units))
            .sum();
        assert_eq!(decline, b.owed_esp);
        // held: the two notes are reserved, the stored body is the same bytes
        let reserved: Vec<_> = w
            .notes()
            .iter()
            .filter(|n| n.reserved_by.as_deref() == Some(b.id.as_str()))
            .collect();
        assert_eq!(reserved.len(), 2);
        assert_eq!(w.pending_redemptions()[0].body().unwrap(), b.body);
        assert_eq!(w.balance().pending_redemptions, 1);
        // the reservation survives a reopen, and a second build finds nothing free
        let mut again = Wallet::open(w.path()).unwrap();
        assert_eq!(again.pending_redemptions().len(), 1);
        assert!(matches!(
            again.build_redemption(&key(1), MEMO, &fees(), NOW),
            Err(WalletError::NotEnough(_))
        ));
        // cancelling frees them
        again.cancel_redemption(&b.id).unwrap();
        assert!(again.notes().iter().all(|n| n.reserved_by.is_none()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bad_memos_dust_and_other_keys_are_refused_and_nothing_is_held() {
        let (mut w, dir) = wallet_with("refuse", vec![esp_note(ONE, service(), PAST)]);
        assert!(matches!(
            w.build_redemption(&key(1), " ", &fees(), NOW),
            Err(WalletError::Invalid(_))
        ));
        let long = "x".repeat(257);
        assert!(matches!(
            w.build_redemption(&key(1), &long, &fees(), NOW),
            Err(WalletError::Invalid(_))
        ));
        // the owner of another key holds nothing to redeem here
        assert!(matches!(
            w.build_redemption(&key(2), MEMO, &fees(), NOW),
            Err(WalletError::NotEnough(_))
        ));
        // a rate at which the fee takes everything
        let steep = RedeemFees {
            fee_per_byte: u128::from(ONE),
            ..fees()
        };
        assert!(matches!(
            w.build_redemption(&key(1), MEMO, &steep, NOW),
            Err(WalletError::NotEnough(_))
        ));
        assert!(w.pending_redemptions().is_empty());
        assert!(w.notes().iter().all(|n| n.reserved_by.is_none()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_redemption_over_the_ceiling_is_split_and_every_part_fits() {
        let notes: Vec<StoredNote> = (0..7)
            .map(|i| esp_note(ONE + i, service(), if i % 2 == 0 { PAST } else { PAST2 }))
            .collect();
        let (mut w, dir) = wallet_with("split", notes);
        let ceiling = redeem::encoded_len(3, MEMO.len(), 2, 2);
        let small = RedeemFees {
            max_request_bytes: ceiling,
            ..fees()
        };
        let built = w.build_redemption(&key(1), MEMO, &small, NOW).unwrap();
        assert_eq!(built.len(), 3);
        assert_eq!(built.iter().map(|b| b.notes).sum::<usize>(), 7);
        for b in &built {
            assert!(b.size_bytes <= ceiling);
            assert_eq!(b.body.len() as u64, b.size_bytes);
            assert!(b.owed_esp > 0);
        }
        let ids: std::collections::HashSet<_> = built.iter().map(|b| b.id.clone()).collect();
        assert_eq!(ids.len(), 3);
        assert_eq!(w.pending_redemptions().len(), 3);
        // too small for even one note
        let tiny = RedeemFees {
            max_request_bytes: 200,
            ..fees()
        };
        let (mut w2, dir2) = wallet_with("tiny", vec![esp_note(ONE, service(), PAST)]);
        assert!(w2.build_redemption(&key(1), MEMO, &tiny, NOW).is_err());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&dir2).unwrap();
    }

    fn signed(sk: &SecretKey, o: &TermsOutput) -> SignedOutput {
        SignedOutput {
            signature: bdhke::sign_message(sk, &o.output.blind_nonce.0),
            key: sk.public_key(SECP256K1),
            // not the set the request asked for: the mint signed with another
            keyset: "cd".repeat(8),
        }
    }

    fn view(status: Status, owed: u128, sigs: Vec<SignedOutput>) -> EntryView {
        EntryView {
            status,
            owed_esp: owed,
            fee_per_byte: RATE,
            fee_esp: 0,
            payment_ref: if status == Status::Completed {
                Some("tx123".into())
            } else {
                None
            },
            decline_reason: if status == Status::Declined {
                Some("terms not met".into())
            } else {
                None
            },
            decline_signatures: sigs,
        }
    }

    fn reply(
        p: &PendingRedemption,
        notes: Vec<NoteResult>,
        owed: u128,
        refund: Vec<SignedOutput>,
        entry: Option<EntryView>,
    ) -> RedeemResponse {
        RedeemResponse {
            notes,
            accepted_esp: owed + p.fee_esp,
            rejected_esp: 0,
            fee_esp: p.fee_esp,
            size_bytes: p.size_bytes,
            fee_per_byte: RATE,
            owed_esp: owed,
            message: if owed > 0 {
                "payout queued".into()
            } else {
                "nothing owed, fee taken".into()
            },
            refund,
            entry,
        }
    }

    const OK: NoteResult = NoteResult {
        accepted: true,
        reason: None,
        burned: true,
    };

    #[test]
    fn a_queued_payout_waits_then_a_decline_gives_the_notes_back_once() {
        let (mut w, dir) = wallet_with(
            "decline",
            vec![
                esp_note(2 * ONE, service(), PAST),
                esp_note(ONE, service(), PAST2),
            ],
        );
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        let p = w.pending_redemptions()[0].clone();
        let open = reply(
            &p,
            vec![OK, OK],
            b.owed_esp,
            vec![],
            Some(view(Status::Open, b.owed_esp, vec![])),
        );
        let done = w.finish_redemption(&b.id, &open).unwrap();
        assert_eq!(done.entry, Some(EntryOutcome::Open));
        assert_eq!(done.message, "payout queued");
        // the notes are burned and gone; the redemption waits, queued
        assert!(w.notes().is_empty());
        assert_eq!(w.pending_redemptions()[0].state, RedemptionState::Queued);
        assert!(matches!(
            w.cancel_redemption(&b.id),
            Err(WalletError::Invalid(_))
        ));
        // a repeated open reply changes nothing
        w.finish_redemption(&b.id, &open).unwrap();
        assert!(w.notes().is_empty());
        // declined: the decline outputs are signed, one per day, minus the fee
        let mint = SecretKey::new(&mut rand::rngs::OsRng);
        let sigs: Vec<_> = p.decline_outputs.iter().map(|o| signed(&mint, o)).collect();
        let declined = reply(
            &p,
            vec![OK, OK],
            b.owed_esp,
            vec![],
            Some(view(Status::Declined, b.owed_esp, sigs)),
        );
        let done = w.finish_redemption(&b.id, &declined).unwrap();
        match done.entry {
            Some(EntryOutcome::Declined {
                reason,
                reissued,
                reissued_esp,
            }) => {
                assert_eq!(reason.as_deref(), Some("terms not met"));
                assert_eq!(reissued.len(), 2);
                assert_eq!(reissued_esp, b.owed_esp);
            }
            other => panic!("{other:?}"),
        }
        assert!(w.pending_redemptions().is_empty());
        let b2 = w.balance();
        assert_eq!(b2.esp, b.owed_esp);
        let mut days: Vec<u64> = w
            .notes()
            .iter()
            .map(|n| n.terms.unwrap().redeemable_after_day)
            .collect();
        days.sort();
        assert_eq!(days, vec![PAST, PAST2]);
        // the reissued note unblinds to one the mint's key signed
        let n = &w.notes()[0];
        // and is recorded under the keyset the mint says signed it, not the
        // one the request asked for
        for n in w.notes() {
            assert_eq!(w.esp_keyset_of(n).unwrap(), "cd".repeat(8));
        }
        assert!(bdhke::verify_message(
            &mint,
            n.note.signature,
            &n.note.nonce.as_hash_preimage()
        ));
        // and the redemption is over
        assert!(matches!(
            w.finish_redemption(&b.id, &declined),
            Err(WalletError::Unknown(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_completed_payout_ends_the_redemption() {
        let (mut w, dir) = wallet_with("paid", vec![esp_note(ONE, service(), PAST)]);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        let p = w.pending_redemptions()[0].clone();
        let paid = reply(
            &p,
            vec![OK],
            b.owed_esp,
            vec![],
            Some(view(Status::Completed, b.owed_esp, vec![])),
        );
        let done = w.finish_redemption(&b.id, &paid).unwrap();
        assert_eq!(
            done.entry,
            Some(EntryOutcome::Completed {
                payment_ref: Some("tx123".into())
            })
        );
        assert!(w.pending_redemptions().is_empty());
        assert_eq!(w.balance().esp, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spent_notes_are_recorded_other_rejects_are_freed_and_refunds_become_notes() {
        let notes = vec![
            esp_note(2 * ONE, service(), PAST),
            esp_note(ONE, service(), PAST),
            esp_note(ONE, service(), PAST2),
        ];
        let ids: Vec<String> = notes.iter().map(StoredNote::id).collect();
        let (mut w, dir) = wallet_with("mixed", notes);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        let p = w.pending_redemptions()[0].clone();
        let order = p.input_ids.clone();
        let results: Vec<NoteResult> = order
            .iter()
            .map(|id| {
                if *id == ids[1] {
                    NoteResult {
                        accepted: false,
                        reason: Some(Reason::AlreadySpent),
                        burned: false,
                    }
                } else if *id == ids[2] {
                    NoteResult {
                        accepted: false,
                        reason: Some(Reason::Immature),
                        burned: false,
                    }
                } else {
                    OK
                }
            })
            .collect();
        let r = reply(
            &p,
            results,
            b.owed_esp,
            vec![],
            Some(view(Status::Open, b.owed_esp, vec![])),
        );
        let done = w.finish_redemption(&b.id, &r).unwrap();
        assert_eq!((done.marked_spent, done.freed), (1, 1));
        assert_eq!(w.spent_notes().len(), 1);
        assert_eq!(w.spent_notes()[0].id(), ids[1]);
        assert_eq!(w.notes().len(), 1);
        assert_eq!(w.notes()[0].id(), ids[2]);
        assert!(w.notes()[0].reserved_by.is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_below_fee_refusal_retires_the_spent_notes_and_frees_the_rest() {
        let notes = vec![
            esp_note(2 * ONE, service(), PAST),
            esp_note(ONE, service(), PAST),
            esp_note(ONE, service(), PAST2),
        ];
        let ids: Vec<String> = notes.iter().map(StoredNote::id).collect();
        let (mut w, dir) = wallet_with("below-fee-spent", notes);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        let order = w.pending_redemptions()[0].input_ids.clone();
        // the mint's reasons, in the request's order: one spent, one with a
        // bad proof, one only too small
        let notes: Vec<NoteResult> = order
            .iter()
            .map(|id| NoteResult {
                accepted: *id == ids[2],
                reason: if *id == ids[0] {
                    Some(Reason::AlreadySpent)
                } else if *id == ids[1] {
                    Some(Reason::BadProof)
                } else {
                    None
                },
                burned: false,
            })
            .collect();
        let report = w.refuse_redemption(&b.id, &notes).unwrap();
        assert_eq!((report.marked_spent, report.freed), (1, 2));
        // the spent note is in the spent record and out of the balance
        assert_eq!(w.spent_notes().len(), 1);
        assert_eq!(w.spent_notes()[0].id(), ids[0]);
        assert_eq!(w.notes().len(), 2);
        assert!(w.notes().iter().all(|n| n.reserved_by.is_none()));
        // the bad-proof note stays but is flagged, so redeem leaves it out
        assert_eq!(w.balance().bad_proof, 1);
        assert!(w.pending_redemptions().is_empty());
        // asking again does not offer the spent note: only the flagged note
        // and the other are left, and the flagged one is skipped
        let again = w.build_redemption(&key(1), MEMO, &fees(), NOW);
        if let Ok(built) = again {
            let p = w.pending_redemptions();
            assert!(built.len() <= 1);
            assert!(p.iter().all(|p| !p.input_ids.contains(&ids[0])));
            assert!(p.iter().all(|p| !p.input_ids.contains(&ids[1])));
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_refusal_without_reasons_just_frees_the_notes() {
        let (mut w, dir) = wallet_with("no-reasons", vec![esp_note(2 * ONE, service(), PAST)]);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        // an older mint sends no per-note list
        let report = w.refuse_redemption(&b.id, &[]).unwrap();
        assert_eq!((report.marked_spent, report.freed), (0, 0));
        assert!(w.spent_notes().is_empty());
        assert_eq!(w.notes().len(), 1);
        assert!(w.notes()[0].reserved_by.is_none());
        assert!(w.pending_redemptions().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nothing_owed_fee_taken_ends_it_and_keeps_the_refunds() {
        let (mut w, dir) = wallet_with("refund", vec![esp_note(ONE, service(), PAST)]);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        // as if the mint had found the note immature and asked for a refund: put
        // a refund output on the pending record the way a rebuild would
        let mut totals = Totals {
            notes: vec![NoteResult {
                accepted: false,
                reason: Some(Reason::Immature),
                burned: true,
            }],
            accepted_esp: 0,
            rejected_esp: u128::from(ONE),
            fee_esp: 0,
            size_bytes: 0,
            fee_per_byte: RATE,
            accepted_by_terms: vec![],
            rejected_by_terms: vec![redeem::TermsTotal {
                service: service(),
                redeemable_after_day: PAST,
                esp: u128::from(ONE),
            }],
        };
        let rebuilt = w.rebuild_redemption(&b.id, &key(1), &totals).unwrap();
        assert_ne!(rebuilt.id, b.id);
        assert_eq!((rebuilt.decline_outputs, rebuilt.refund_outputs), (0, 1));
        assert_eq!(rebuilt.owed_esp, 0);
        assert_eq!(w.pending_redemptions().len(), 1);
        assert_eq!(
            w.notes()[0].reserved_by.as_deref(),
            Some(rebuilt.id.as_str())
        );
        let p = w.pending_redemptions()[0].clone();
        let mint = SecretKey::new(&mut rand::rngs::OsRng);
        let refund = vec![signed(&mint, &p.refund_outputs[0])];
        totals.fee_esp = p.fee_esp;
        let r = RedeemResponse {
            notes: totals.notes.clone(),
            accepted_esp: 0,
            rejected_esp: u128::from(ONE),
            fee_esp: p.fee_esp,
            size_bytes: p.size_bytes,
            fee_per_byte: RATE,
            owed_esp: 0,
            message: "nothing owed, fee taken".into(),
            refund,
            entry: None,
        };
        let done = w.finish_redemption(&rebuilt.id, &r).unwrap();
        assert_eq!(done.message, "nothing owed, fee taken");
        assert_eq!(done.refunded.len(), 1);
        assert!(done.entry.is_none());
        assert!(w.pending_redemptions().is_empty());
        assert_eq!(w.balance().esp, u128::from(ONE) - p.fee_esp);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_reply_that_does_not_fit_is_refused_and_changes_nothing() {
        let (mut w, dir) = wallet_with("badreply", vec![esp_note(ONE, service(), PAST)]);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        let p = w.pending_redemptions()[0].clone();
        let short = reply(&p, vec![], b.owed_esp, vec![], None);
        assert!(matches!(
            w.finish_redemption(&b.id, &short),
            Err(WalletError::Mint(_))
        ));
        let no_entry = reply(&p, vec![OK], b.owed_esp, vec![], None);
        assert!(matches!(
            w.finish_redemption(&b.id, &no_entry),
            Err(WalletError::Mint(_))
        ));
        let k = PublicKey::from_secret_key(SECP256K1, &key(3));
        let extra = reply(
            &p,
            vec![OK],
            b.owed_esp,
            vec![SignedOutput {
                signature: k,
                key: k,
                keyset: "ab".repeat(8),
            }],
            Some(view(Status::Open, 1, vec![])),
        );
        assert!(matches!(
            w.finish_redemption(&b.id, &extra),
            Err(WalletError::Mint(_))
        ));
        assert_eq!(w.notes()[0].reserved_by.as_deref(), Some(b.id.as_str()));
        assert_eq!(w.pending_redemptions()[0].state, RedemptionState::Sent);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn notes_with_a_bad_proof_stay_flagged_and_are_not_picked_again() {
        let notes = vec![
            esp_note(2 * ONE, service(), PAST),
            esp_note(ONE, service(), PAST2),
        ];
        let ids: Vec<String> = notes.iter().map(StoredNote::id).collect();
        let (mut w, dir) = wallet_with("badproof", notes);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        let p = w.pending_redemptions()[0].clone();
        let results: Vec<NoteResult> = p
            .input_ids
            .iter()
            .map(|id| {
                if *id == ids[1] {
                    NoteResult {
                        accepted: false,
                        reason: Some(Reason::BadProof),
                        burned: false,
                    }
                } else {
                    OK
                }
            })
            .collect();
        let r = reply(
            &p,
            results,
            b.owed_esp,
            vec![],
            Some(view(Status::Open, b.owed_esp, vec![])),
        );
        let done = w.finish_redemption(&b.id, &r).unwrap();
        assert_eq!((done.freed, done.flagged_bad_proof), (1, 1));
        // still held, counted, flagged, and the flag survives a reopen
        let mut w = Wallet::open(w.path()).unwrap();
        assert_eq!(w.notes().len(), 1);
        assert!(w.is_flagged_bad_proof(&ids[1]));
        let bal = w.balance();
        assert_eq!(
            (bal.bad_proof, bal.bad_proof_esp, bal.esp),
            (1, u128::from(ONE), u128::from(ONE))
        );
        // not picked again
        assert!(matches!(
            w.build_redemption(&key(1), MEMO, &fees(), NOW),
            Err(WalletError::NotEnough(_))
        ));
        // clearing the flag makes it eligible again
        w.clear_bad_proof(&ids[1]).unwrap();
        assert_eq!(w.balance().bad_proof, 0);
        assert_eq!(
            w.build_redemption(&key(1), MEMO, &fees(), NOW)
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            w.clear_bad_proof(&ids[1]),
            Err(WalletError::Unknown(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_rebuild_flags_notes_the_mint_found_bad() {
        let notes = vec![
            esp_note(2 * ONE, service(), PAST),
            esp_note(ONE, service(), PAST),
        ];
        let ids: Vec<String> = notes.iter().map(StoredNote::id).collect();
        let (mut w, dir) = wallet_with("rebuildbad", notes);
        let b = w
            .build_redemption(&key(1), MEMO, &fees(), NOW)
            .unwrap()
            .remove(0);
        let p = w.pending_redemptions()[0].clone();
        let results: Vec<NoteResult> = p
            .input_ids
            .iter()
            .map(|id| {
                if *id == ids[1] {
                    NoteResult {
                        accepted: false,
                        reason: Some(Reason::BadProof),
                        burned: false,
                    }
                } else {
                    NoteResult {
                        accepted: true,
                        reason: None,
                        burned: false,
                    }
                }
            })
            .collect();
        let totals = Totals {
            notes: results,
            accepted_esp: u128::from(2 * ONE),
            rejected_esp: 0,
            fee_esp: 0,
            size_bytes: 0,
            fee_per_byte: RATE,
            accepted_by_terms: vec![redeem::TermsTotal {
                service: service(),
                redeemable_after_day: PAST,
                esp: u128::from(2 * ONE),
            }],
            rejected_by_terms: vec![],
        };
        let rebuilt = w.rebuild_redemption(&b.id, &key(1), &totals).unwrap();
        assert_eq!(rebuilt.notes, 1);
        assert!(w.is_flagged_bad_proof(&ids[1]));
        assert!(
            w.notes()
                .iter()
                .find(|n| n.id() == ids[1])
                .unwrap()
                .reserved_by
                .is_none()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_part_that_would_owe_nothing_is_not_built_and_says_why() {
        // Under a small ceiling the big notes go in one part and a dust note
        // ends up alone in another, where the fee would take all of it.
        let notes = vec![
            esp_note(ONE, service(), PAST),
            esp_note(ONE, service(), PAST),
            esp_note(1_000, service(), PAST2),
        ];
        let (mut w, dir) = wallet_with("skip", notes);
        let ceiling = redeem::encoded_len(2, MEMO.len(), 2, 2);
        let small = RedeemFees {
            max_request_bytes: ceiling,
            ..fees()
        };
        let plan = w.plan_redemption(&key(1), MEMO, &small, NOW).unwrap();
        assert_eq!(plan.built.len(), 1);
        assert_eq!(plan.skipped.len(), 1);
        assert!(
            plan.skipped[0]
                .starts_with("not sent: the notes are worth 1000 ESP units, less than the fee"),
            "{}",
            plan.skipped[0]
        );
        // the dust note is left free
        assert_eq!(
            w.notes().iter().filter(|n| n.reserved_by.is_none()).count(),
            1
        );
        // alone, the reason is the error
        // a note worth exactly the fee: the mint would take it all and owe nothing
        let exact = fee_of(1, 1, 0) as u64;
        let (mut w2, dir2) = wallet_with("skip2", vec![esp_note(exact, service(), PAST)]);
        match w2.build_redemption(&key(1), MEMO, &fees(), NOW) {
            Err(WalletError::NotEnough(why)) => {
                assert!(why.starts_with("not sent: 1 note(s) worth"), "{why}");
                assert!(why.contains("the mint would owe nothing"), "{why}");
            }
            other => panic!("{other:?}"),
        }
        assert!(w2.pending_redemptions().is_empty());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&dir2).unwrap();
    }
}
