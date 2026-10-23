//! Buying PSP with BTC, and settling a payment the PSP did not sign.
//!
//! The wallet has no BTC wallet. The app's own Bitcoin wallet puts the bytes from
//! [`Wallet::build_psp_payload`] in an OP_RETURN and pays the PSP's address. The
//! PSP then delivers the purchase on its own: when it handles the payment, it
//! writes one record on the SPI's AIR server, at an address the wallet computes
//! (`sp_wire::air_request::delivery`). The record is the blind signature of each
//! output it signed and the keysets to unblind them with, or it says the payment
//! is held, or the purchase was rejected, with the reason and what was paid, or
//! that a credit is owed. [`crate::mint_info::psp_pickup`] reads those records and
//! [`Wallet::apply_delivery`] turns one into notes. There is nothing to paste.
//!
//! **A purchase pays exactly once.** The payload is one-time use: a second
//! payment that carries the same payload buys nothing and its funds are lost
//! ([`ONE_TIME_USE`]; `buy-psp` prints it with the payload). It is also not
//! built below `psp.min_purchase` ([`DEFAULT_MIN_PURCHASE`], 50 PSP): the PSP's
//! fees come out of what a payment buys, so a small purchase can be eaten whole
//! and the payment lost.
//!
//! **A key for each purchase.** The payload names a reply DID, and the PSP seals
//! the record to it. [`Wallet::build_psp_payload`] makes a fresh one-off key for
//! each purchase and saves its secret with the pending purchase, so the PSP
//! cannot link two purchases of one wallet. The secret is deleted when the
//! purchase is reconciled: when its signatures are claimed and the PSP owes
//! nothing and every output is accounted for, when the corrected request or the
//! credit claim is answered ([`Wallet::apply_reconcile`]), or when the PSP's
//! reconciliation window closes ([`Wallet::close_expired`]).
//!
//! **A held or rejected payment, or a credit, is settled by a reconciliation
//! request (AIR kind 15).** The PSP has the bitcoin and signed nothing (held,
//! rejected), or owes the payer a credit, so the purchase and its key are kept
//! ([`Delivered::Open`], [`OpenReply`]) for the window the record names
//! (`open_until`; 14 days by default at the PSP). The record carries the rules
//! ([`ReconcileRules`]): what to send, the exact total the request must carry
//! (`due_units`, after every fee), the deadline and how many requests the PSP
//! counts. The wallet follows them without being asked:
//!
//! - [`Wallet::build_reconcile`] makes the request: fresh blinded outputs that
//!   are powers of two, none above the PSP's largest note, adding up to
//!   `due_units` exactly (the PSP signs the request whole or not at all), on the
//!   PSP's current keyset, signed (BIP340) by the purchase's reply key over
//!   [`ReconcileRequest::digest`]. [`check_reconcile`] checks all of it, and the
//!   rules' kind and deadline, before anything is saved or sent: a request that
//!   fails is a wallet bug, and is neither saved nor sent. The request, its bytes,
//!   its hash and the blinding factors are saved with the purchase or credit,
//!   together with the AIR request that will carry it (`R` is the reply key), in
//!   one write before the first AIR write.
//! - [`crate::mint_info::psp_reconcile`] sends it, at every start and in
//!   `claim-psp`, until `open_until`. The PSP answers an accepted request only; a
//!   refused one gets no reply. A saved request with no answer is sent again as
//!   the identical bytes (the PSP answers a repeat of an accepted request from its
//!   stored answer and counts nothing twice). The one exception is the
//!   keyset-rotation race: when the PSP does not answer and the request's keyset is
//!   no longer one of its two live keysets, the wallet builds the one second
//!   request on the current keyset the rules allow, never more than
//!   `rules.max_attempts`.
//! - [`Wallet::apply_reconcile`] checks the answer (the keyset's keys hash to its
//!   id, one signature for each output in order, `issued_units == due_units`),
//!   and in one write stores the notes, records their keyset and removes the
//!   purchase or credit, its key and the saved request. A bad answer stores
//!   nothing and keeps the key. Applying an answer twice adds no notes.
//!
//! **When nothing is due** (`due_units` is 0, because the PSP's fees take the
//! whole amount) nothing is built and nothing is sent: the PSP would refuse it
//! as `nothing_to_issue`. The user is told once that the payment is lost at
//! `open_until` ([`Loss::nothing_due`]). **When a window closes** with the
//! payment still open, [`Wallet::close_expired`] returns what was forfeited
//! ([`Loss::forfeited`]), the amount included.
//!
//! **A credit is in whole PSP units, and the wallet never rounds it.** The PSP
//! owes cents; the rules' `due_units` is what it will issue, after rounding (it
//! rounds up from `reconciliation.round_up_from`, 9 cents by default, so a credit
//! of 8 cents or less is 0 units) and fees. [`PspCredit`] shows `due_units` PSP
//! with the exact cents in USD.

use std::collections::{BTreeMap, BTreeSet};

use mint_types::{Amount, BlindNonce};
use secp256k1::{Keypair, PublicKey, SECP256K1};
use sha2::{Digest, Sha256};
use sp_wire::ServiceDid;
use sp_wire::air_request::delivery::{
    self, Outcome, ReconcileRules, SEND_CORRECTED_REQUEST, SEND_CREDIT_CLAIM,
};
use sp_wire::air_request::{KIND_PSP_RECONCILE, addr};
use sp_wire::payload::{self, Payload};
use sp_wire::psp::{KeysetsResponse, MAX_ROLLOVER_NOTES, ReconcileRequest, ReconcileResponse};
use sp_wire::seal::{PublicKey as DidPublicKey, SecretKey as DidSecretKey};

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::store::{
    Kind, OPEN_KEY_FALLBACK_SECS, OpenKind, OpenPurchase, OpenReply, PendingAirRequest,
    PendingPurchase, ReconcileState, SavedRequest, StoredNote, Wallet, WalletData,
};

/// The most outputs in one purchase (the payload's count is one byte).
pub const MAX_OUTPUTS: usize = 255;

/// The default of `psp.min_purchase`: the smallest purchase the wallet builds,
/// in PSP units. The PSP's fees are taken from what a payment buys, so a small
/// purchase can be eaten whole and the payment lost; 100 PSP ($10) is a
/// realistic purchase. Lowering the setting is not advised.
pub const DEFAULT_MIN_PURCHASE: u64 = 50;

/// What `buy-psp` says next to the payload, and what an app should show next to
/// it: the payload is paid once. The PSP refuses a second payment that carries
/// the same payload and keeps its funds.
pub const ONE_TIME_USE: &str = "ONE-TIME USE: pay this payload exactly once. A second payment carrying the same payload buys nothing and its funds are lost.";

/// The most requests the wallet builds for one open payment: the first, and the
/// one second request the keyset-rotation race allows. Never more than the
/// rules' `max_attempts` either.
pub const MAX_BUILT_REQUESTS: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurchaseBuild {
    /// Identifies this purchase in the wallet: SHA-256 of `payload`, as hex.
    pub id: String,
    /// The encrypted payload, for the OP_RETURN.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimResult {
    /// The ids of the new notes.
    pub claimed: Vec<String>,
    pub claimed_units: u64,
    /// Outputs of other purchases still waiting for a signature.
    pub still_pending: usize,
}

/// Cents in one PSP unit: $0.10.
const CENTS_PER_PSP: u128 = 10;
const _: () = assert!(
    CENTS_PER_PSP * (sp_wire::units::ESP_PER_USD / 100) == sp_wire::units::ESP_PER_PSP as u128
);

/// USD cents as dollars, two decimals: `"0.94"`.
fn usd(cents: u64) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// What the PSP owes the wallet in credit ([`Wallet::pending_psp_credit`]).
///
/// The PSP's credit is in USD cents. A PSP unit is worth $0.10 (10 PSP to the
/// dollar, `sp_wire::units`), so a cent is a tenth of a PSP unit. The two figures
/// are not the same number: `cents` is the exact value the PSP owes, and `units`
/// is what its rules say it will issue for the claim (`due_units`: whole units,
/// after the rounding the PSP applies and its fees). The wallet never rounds by
/// itself, so a credit of 8 cents shows as `0 PSP (0.08 USD)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PspCredit {
    /// The credit, in USD cents.
    pub cents: u128,
    /// What the claims will issue, in PSP units (the rules' `due_units`).
    pub units: u128,
    /// How many purchases owe it.
    pub purchases: usize,
}

impl PspCredit {
    /// The credit as US dollars, two decimals: `"1.00"`.
    pub fn usd(&self) -> String {
        format!("{}.{:02}", self.cents / 100, self.cents % 100)
    }

    /// The line `balance` prints under the PSP total, or `None` when nothing is
    /// owed: the PSP units the claim will issue with the exact cents in USD, as in
    /// `9 PSP (0.94 USD) (pending)`. The credit is not a note yet, so it is marked
    /// pending.
    pub fn balance_line(&self) -> Option<String> {
        (self.cents > 0).then(|| {
            format!(
                "{} PSP ({} USD) (pending): credit the PSP owes for {} purchase(s), not counted above until it is claimed",
                self.psp(),
                self.usd(),
                self.purchases
            )
        })
    }

    /// The PSP units the claim will issue: `"9"`.
    pub fn psp(&self) -> String {
        self.units.to_string()
    }
}

/// What a purchase's record said, once it was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub claim: ClaimResult,
    /// Requested units the PSP did not sign because the payment was short. It
    /// keeps their value.
    pub skipped_units: u64,
    /// What the PSP owes the payer for an overpayment, in USD cents.
    pub credit_cents: u64,
    /// Requested units that were neither signed nor reported as dropped.
    pub unaccounted_units: u64,
    /// True when the purchase's key was kept because the purchase may still be
    /// open (a credit is owed, or outputs are unaccounted for).
    pub key_kept: bool,
}

/// What applying one purchase's record did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivered {
    /// The signatures were claimed and the purchase cleared.
    Claimed(Claimed),
    /// The PSP holds the payment, or rejected the purchase: nothing was signed.
    /// The purchase and its key are kept open until `open_until` (see
    /// [`Wallet::close_expired`]) or until a reconciliation request settles it
    /// ([`crate::mint_info::psp_reconcile`]). The bitcoin that was paid stays
    /// with the PSP; if the purchase is not settled by then, the PSP forfeits it.
    Open(OpenPurchase),
    /// Nothing changed: the purchase is not pending (its record was applied
    /// before), or it is open already with this very record.
    AlreadyDone,
}

/// Where a payment that is open stands (see [`OpenReconciliation`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileStatus {
    /// Nothing has been built yet: the next [`crate::mint_info::psp_reconcile`]
    /// builds the request and sends it.
    Due,
    /// A request is saved and sent; the PSP has not answered it yet. It is sent
    /// again, as the identical bytes, at the next start.
    Sent,
    /// The rules' `due_units` is 0: the fees take the whole amount. Nothing is
    /// built or sent, and the payment is lost at `open_until`.
    NothingDue,
    /// The PSP did not answer the last request and the wallet has built every
    /// request the rules allow, so the PSP did not accept it. The payment is lost
    /// at `open_until` (the saved request is still sent again, as it might have
    /// been accepted and its answer lost).
    Lost,
}

/// One open payment the wallet is settling: a held or rejected purchase, or a
/// credit ([`Wallet::open_reconciliations`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReconciliation {
    /// The purchase's id.
    pub id: String,
    /// The PSP's key the purchase was sealed to (66 hex characters), the mint
    /// the request is for.
    pub mint: String,
    /// What is sent: [`SEND_CORRECTED_REQUEST`] or [`SEND_CREDIT_CLAIM`].
    pub send: String,
    /// The exact total the request must carry, in PSP units.
    pub due_units: u64,
    /// When the window closes (Unix seconds, the PSP's clock).
    pub open_until: u64,
    /// How many requests the wallet has built for it.
    pub attempts: u32,
    /// How many the PSP counts (`rules.max_attempts`).
    pub max_attempts: u32,
    pub state: ReconcileStatus,
    /// True once the user was told the payment is lost (nothing due, or the PSP
    /// did not accept the request), so it is said once.
    pub told_lost: bool,
    /// What was paid, for a purchase (0 for a credit).
    pub paid_sats: u64,
    pub paid_cents: u64,
    /// What is owed, for a credit (0 for a purchase).
    pub credit_cents: u64,
}

/// What a payment that is lost was worth, for the words the user is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossKind {
    /// A payment the PSP holds.
    Held,
    /// A purchase the PSP rejected.
    Rejected,
    /// A credit the PSP owes.
    Credit,
    /// A key kept only for outputs that were neither signed nor reported as
    /// dropped: no rules, no amount.
    Key,
}

/// A payment that is, or will be, lost: its words ([`Loss::forfeited`],
/// [`Loss::nothing_due`], [`Loss::not_accepted`]) say so plainly, with the
/// amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loss {
    /// The purchase's id.
    pub id: String,
    pub kind: LossKind,
    /// What the PSP received, for a purchase.
    pub paid_sats: u64,
    pub paid_cents: u64,
    /// What it owes, for a credit.
    pub credit_cents: u64,
    /// When the window closes or closed (Unix seconds).
    pub open_until: u64,
}

impl Loss {
    /// The amount in the user's words: sats and cents for a purchase, cents for a
    /// credit.
    pub fn amount(&self) -> String {
        match self.kind {
            LossKind::Held | LossKind::Rejected => {
                format!("{} sat, {} USD", self.paid_sats, usd(self.paid_cents))
            }
            LossKind::Credit => format!("a credit of {} USD", usd(self.credit_cents)),
            LossKind::Key => "no amount".to_string(),
        }
    }

    fn date(&self) -> String {
        crate::date::format_utc(self.open_until)
    }

    /// What is said when the window closed with the payment still open: the PSP
    /// forfeited it and the funds are lost.
    pub fn forfeited(&self) -> String {
        let id = &self.id;
        let date = self.date();
        match self.kind {
            LossKind::Held | LossKind::Rejected => format!(
                "purchase {id}: it was not reconciled by {date}, when its window closed. The PSP forfeited the payment: the funds are lost ({}). The purchase and its key are deleted",
                self.amount()
            ),
            LossKind::Credit => format!(
                "purchase {id}: the credit was not claimed by {date}, when its window closed. The PSP forfeited it: the funds are lost ({}). The purchase's key is deleted",
                self.amount()
            ),
            LossKind::Key => {
                format!("purchase {id}: its window closed at {date}. The purchase's key is deleted")
            }
        }
    }

    /// What is said once when the PSP's fees take the whole amount, so nothing is
    /// due and nothing can be sent.
    pub fn nothing_due(&self) -> String {
        format!(
            "purchase {}: the PSP's fees take the whole amount ({}), so nothing can be issued and no request is sent. The PSP forfeits the payment at {}: the funds are lost",
            self.id,
            self.amount(),
            self.date()
        )
    }

    /// What is said once when the PSP did not answer the request after the wallet
    /// had built every request the rules allow.
    pub fn not_accepted(&self, attempts: u32) -> String {
        format!(
            "purchase {}: the request was not accepted by the PSP (it answers an accepted request only) after {attempts} attempt(s). The payment ({}) is forfeited at {}: the funds are lost",
            self.id,
            self.amount(),
            self.date()
        )
    }
}

/// What applying the PSP's answer to a reconciliation request did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// The notes were stored and the purchase or credit, its key and its saved
    /// request were removed.
    Settled(Settled),
    /// Nothing changed: the payment is not open any more (the answer was applied
    /// before, here or in another copy of the wallet).
    AlreadyDone,
}

/// The notes a reconciliation brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    /// The ids of the new notes.
    pub claimed: Vec<String>,
    /// Their total, in PSP units (the rules' `due_units`).
    pub units: u64,
    /// True for a credit claim, false for a corrected request.
    pub credit: bool,
}

/// A reconciliation request the wallet built and saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileBuild {
    /// The purchase's id.
    pub id: String,
    pub request: ReconcileRequest,
    /// The bytes that are sent: the JSON of `request`, exactly as saved.
    pub body: Vec<u8>,
    /// `request.hash()`: what the PSP stores its answer under.
    pub hash: String,
    /// 1 for the first request built for the payment, 2 for the second.
    pub attempt: u32,
}

/// Check that `amount` is a PSP denomination: a power of two, and not above the
/// PSP's largest note (`top`, read from its `GET /keys`) when that is known.
/// With `top` unknown the PSP decides how large a note may be.
pub fn check_denomination(amount: u64, top: Option<u64>) -> Result<(), WalletError> {
    if amount == 0 || !amount.is_power_of_two() {
        return Err(WalletError::Invalid(format!(
            "{amount} is not a PSP note size: use a power of two"
        )));
    }
    if let Some(top) = top.filter(|&top| amount > top) {
        return Err(WalletError::Invalid(format!(
            "{amount} is above the PSP's largest note, {top} (its mint.max_denomination_units)"
        )));
    }
    Ok(())
}

/// A purchase's output sizes, checked without any network: at least one, at most
/// [`MAX_OUTPUTS`], each a PSP note size (see [`check_denomination`]), and adding
/// up to at least `min_purchase` PSP (`psp.min_purchase`): the PSP's fees come out
/// of what a payment buys, so a small purchase can be eaten whole. The command
/// line runs this before it asks the PSP anything, so a bad amount is refused for
/// itself; `build_psp_payload` runs it again.
pub fn check_outputs(
    outputs: &[u64],
    top: Option<u64>,
    min_purchase: u64,
) -> Result<(), WalletError> {
    if outputs.is_empty() {
        return Err(WalletError::Invalid(
            "a purchase needs at least one output".into(),
        ));
    }
    if outputs.len() > MAX_OUTPUTS {
        return Err(WalletError::Invalid(format!(
            "a purchase holds at most {MAX_OUTPUTS} outputs"
        )));
    }
    for &amount in outputs {
        check_denomination(amount, top)?;
    }
    let total: u128 = outputs.iter().map(|&a| u128::from(a)).sum();
    if total < u128::from(min_purchase) {
        return Err(WalletError::Invalid(format!(
            "a purchase of {total} PSP is below the minimum of {min_purchase} PSP (psp.min_purchase, or ECASH_PSP_MIN_PURCHASE). The PSP's fees come out of what a payment buys, so a small purchase can be eaten whole and the payment lost: nothing was built. Buy at least {min_purchase} PSP (100 PSP is a realistic purchase), or lower the setting (not advised)"
        )));
    }
    Ok(())
}

/// The end of a purchase's window from a record: the PSP's when it names one,
/// else the wallet's own ([`OPEN_KEY_FALLBACK_SECS`] from now), so a record with
/// none never closes a purchase at once.
fn window(open_until: u64) -> u64 {
    if open_until > 0 {
        open_until
    } else {
        addr::now_secs().saturating_add(OPEN_KEY_FALLBACK_SECS)
    }
}

/// A curve point written as 66 hex characters (a blind nonce or a signature).
fn point(text: &str) -> Result<PublicKey, WalletError> {
    let bytes = hex::decode(text).map_err(|_| WalletError::Invalid(format!("not hex: {text}")))?;
    PublicKey::from_slice(&bytes)
        .map_err(|_| WalletError::Invalid(format!("not a curve point: {text}")))
}

/// The keys of the keyset that signed, from the record or the answer. They must
/// be the keys the keyset's id names, or it is not to be trusted with the notes.
fn keys_of(
    keyset: &str,
    keysets: &KeysetsResponse,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let Some(keys) = keysets.keysets.get(keyset) else {
        return Err(WalletError::Mint(format!(
            "the PSP's reply does not carry the keys of keyset {keyset}, which signed"
        )));
    };
    let keys: BTreeMap<Amount, PublicKey> = keys
        .iter()
        .map(|(units, key)| (Amount::from_units(*units), *key))
        .collect();
    if sp_wire::keyset::keyset_id(&keys) != keyset {
        return Err(WalletError::Mint(format!(
            "the keys in the PSP's reply are not those of keyset {keyset}"
        )));
    }
    Ok(keys)
}

/// The words for a record that opens a reconciliation but carries no rules.
fn no_rules(what: &str) -> WalletError {
    WalletError::Mint(format!(
        "the PSP's record for this {what} opens a reconciliation window but carries no rules, so nothing can be sent to settle it. The record is not stored and the purchase is left as it was"
    ))
}

/// The rules of a record, or the mint error for a record without them.
fn rules_of(what: &str, rules: &Option<ReconcileRules>) -> Result<ReconcileRules, WalletError> {
    rules.clone().ok_or_else(|| no_rules(what))
}

/// The fewest outputs that add up to `due` exactly, each a power of two and at
/// most `top`: as many of `top` as fit, then the binary digits of the rest. More
/// than [`MAX_ROLLOVER_NOTES`] of them is refused before anything is built.
fn split_due(due: u64, top: u64) -> Result<Vec<u64>, WalletError> {
    let (full, rest) = (due / top, due % top);
    let count = u128::from(full) + u128::from(rest.count_ones());
    if count > MAX_ROLLOVER_NOTES as u128 {
        return Err(WalletError::Invalid(format!(
            "{due} PSP in notes of at most {top} needs {count} notes, and a reconciliation request carries at most {MAX_ROLLOVER_NOTES}. The PSP signs a request whole or not at all, so nothing was built"
        )));
    }
    let mut out = vec![top; full as usize];
    for shift in 0..64 {
        let bit = 1u64 << shift;
        if bit >= top {
            break;
        }
        if rest & bit != 0 {
            out.push(bit);
        }
    }
    Ok(out)
}

/// The keys of a keyset the PSP names as live, from a keysets reply. `id` must be
/// its current or its previous keyset, with keys that hash to the id.
fn live_keys(
    keysets: &KeysetsResponse,
    id: &str,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let live = id == keysets.current || keysets.previous.as_deref() == Some(id);
    if !live {
        return Err(WalletError::Invalid(format!(
            "keyset {id} is neither the PSP's current keyset ({}) nor its previous one",
            keysets.current
        )));
    }
    keys_of(id, keysets)
}

/// True when `keyset` is one of the PSP's two live keysets.
pub fn keyset_is_live(keysets: &KeysetsResponse, keyset: &str) -> bool {
    keyset == keysets.current || keysets.previous.as_deref() == Some(keyset)
}

/// The check every reconciliation request passes before it is saved or sent. A
/// request that fails it is a bug in the wallet, so the error says so and the
/// caller saves nothing and sends nothing. It checks, against `rules` (the
/// PSP's own, from the first record) and `keysets` (a fresh read of the PSP's
/// live keysets):
///
/// - the rules name kind 15 ([`KIND_PSP_RECONCILE`]) and `now` is before
///   `rules.open_until`;
/// - the request names this purchase's reply DID and purchase id, and its
///   signature verifies (BIP340, by the reply key, over the request's digest);
/// - the keyset is the PSP's current or previous one, and its keys hash to its id;
/// - there are at least 1 and at most [`MAX_ROLLOVER_NOTES`] outputs;
/// - each output is a power of two and a denomination the keyset has a key for
///   (so none is above the PSP's largest note);
/// - no two outputs share a blind nonce;
/// - the outputs add up to `rules.due_units` exactly.
pub fn check_reconcile(
    request: &ReconcileRequest,
    rules: &ReconcileRules,
    keysets: &KeysetsResponse,
    reply_did: &ServiceDid,
    purchase: &[u8; 32],
    now: u64,
) -> Result<(), WalletError> {
    let bug = |why: String| {
        WalletError::Invalid(format!(
            "the reconciliation request is not right ({why}). That is a bug in the wallet, so nothing was saved and nothing was sent"
        ))
    };
    if rules.kind != KIND_PSP_RECONCILE {
        return Err(bug(format!(
            "the PSP's rules name request kind {}, not {KIND_PSP_RECONCILE}",
            rules.kind
        )));
    }
    if now >= rules.open_until {
        return Err(bug(format!(
            "the window closed at {}",
            crate::date::format_utc(rules.open_until)
        )));
    }
    if &request.reply_did != reply_did {
        return Err(bug("it names another reply DID than the purchase's".into()));
    }
    if &request.purchase != purchase {
        return Err(bug("it names another purchase id".into()));
    }
    SECP256K1
        .verify_schnorr(
            &request.signature,
            &request.digest(),
            &request.reply_did.x_only(),
        )
        .map_err(|_| bug("the signature does not verify under the reply key".into()))?;
    let keys = live_keys(keysets, &request.keyset).map_err(|e| bug(e.to_string()))?;
    if request.outputs.is_empty() {
        return Err(bug("it has no outputs".into()));
    }
    if request.outputs.len() > MAX_ROLLOVER_NOTES {
        return Err(bug(format!(
            "it has {} outputs, at most {MAX_ROLLOVER_NOTES}",
            request.outputs.len()
        )));
    }
    let mut seen = BTreeSet::new();
    let mut total: u128 = 0;
    for (i, output) in request.outputs.iter().enumerate() {
        let units = output.amount.units;
        if units == 0 || !units.is_power_of_two() {
            return Err(bug(format!("output {i}: {units} is not a power of two")));
        }
        if !keys.contains_key(&output.amount) {
            return Err(bug(format!(
                "output {i}: {units} is above the PSP's largest note, or not a denomination of keyset {}",
                request.keyset
            )));
        }
        if !seen.insert(output.blind_nonce.0.serialize()) {
            return Err(bug(format!("output {i} repeats a blind nonce")));
        }
        total += u128::from(units);
    }
    if total != u128::from(rules.due_units) {
        return Err(bug(format!(
            "the outputs add up to {total}, the rules say {}",
            rules.due_units
        )));
    }
    Ok(())
}

/// One open payment, as the wallet keeps it: a held or rejected purchase, or a
/// credit that is owed.
struct Target {
    id: String,
    credit: bool,
    reply_secret: String,
    /// The purchase's reply DID as saved (a purchase has it; a credit does not).
    reply_did: Option<String>,
    delivery_id: String,
    mint_did_pubkey: String,
    rules: Option<ReconcileRules>,
    state: ReconcileState,
    open_until: u64,
    kind: LossKind,
    paid_sats: u64,
    paid_cents: u64,
    credit_cents: u64,
}

impl Target {
    fn loss(&self) -> Loss {
        Loss {
            id: self.id.clone(),
            kind: self.kind,
            paid_sats: self.paid_sats,
            paid_cents: self.paid_cents,
            credit_cents: self.credit_cents,
            open_until: self.open_until,
        }
    }

    fn status(&self, rules: &ReconcileRules) -> ReconcileStatus {
        let may_build = rules.max_attempts.min(MAX_BUILT_REQUESTS);
        if rules.due_units == 0 {
            ReconcileStatus::NothingDue
        } else if self.state.request.is_none() {
            ReconcileStatus::Due
        } else if self.state.unanswered && self.state.attempts >= may_build {
            ReconcileStatus::Lost
        } else {
            ReconcileStatus::Sent
        }
    }
}

fn target_of(d: &WalletData, id: &str) -> Option<Target> {
    if let Some(p) = d.pending_purchases.iter().find(|p| p.id == id) {
        let o = p.open.as_ref()?;
        return Some(Target {
            id: p.id.clone(),
            credit: false,
            reply_secret: p.reply_secret.clone(),
            reply_did: Some(p.reply_did.clone()),
            delivery_id: p.delivery_id.clone(),
            mint_did_pubkey: p.mint_did_pubkey.clone(),
            rules: Some(o.rules.clone()),
            state: o.reconcile.clone(),
            open_until: o.open_until,
            kind: match o.kind {
                OpenKind::Held => LossKind::Held,
                OpenKind::Rejected => LossKind::Rejected,
            },
            paid_sats: o.paid_sats,
            paid_cents: o.paid_cents,
            credit_cents: 0,
        });
    }
    let r = d.open_replies.iter().find(|r| r.id == id)?;
    Some(Target {
        id: r.id.clone(),
        credit: true,
        reply_secret: r.reply_secret.clone(),
        reply_did: None,
        delivery_id: r.delivery_id.clone(),
        mint_did_pubkey: r.mint_did_pubkey.clone(),
        rules: r.rules.clone(),
        state: r.reconcile.clone(),
        open_until: r.open_until,
        kind: if r.credit_cents > 0 {
            LossKind::Credit
        } else {
            LossKind::Key
        },
        paid_sats: 0,
        paid_cents: 0,
        credit_cents: r.credit_cents,
    })
}

/// The state of an open payment, to change it in a write.
fn state_mut<'a>(d: &'a mut WalletData, id: &str) -> Option<&'a mut ReconcileState> {
    if let Some(p) = d.pending_purchases.iter_mut().find(|p| p.id == id) {
        return p.open.as_mut().map(|o| &mut o.reconcile);
    }
    d.open_replies
        .iter_mut()
        .find(|r| r.id == id)
        .map(|r| &mut r.reconcile)
}

/// Remove the kind 15 AIR request of the payment whose reply key is
/// `reply_secret`. The reply key is the request's `R`, and no other request has
/// it.
fn drop_air_request(d: &mut WalletData, reply_secret: &str) {
    d.air_requests
        .retain(|r| !(r.kind == KIND_PSP_RECONCILE && r.r == reply_secret));
}

/// What `psp_reconcile` needs to send a saved request.
pub(crate) struct ToSend {
    pub body: Vec<u8>,
    pub key: DidSecretKey,
    pub keyset: String,
}

impl Wallet {
    /// Blind `outputs` (amounts in PSP, ten to the US dollar), make this
    /// purchase's own one-off reply key, encode the payload with its public half
    /// as the reply DID, and encrypt it to the mint's DID public key with AIR's
    /// secp256k1 encryption. Returns the bytes for an OP_RETURN.
    ///
    /// The purchase must total at least `psp.min_purchase` PSP
    /// ([`Wallet::psp_min_purchase`], 50 by default): the PSP's fees come out of
    /// what a payment buys, so a small purchase can be eaten whole. A smaller one
    /// is refused here, before anything is saved, with a message that names the
    /// setting. The payload is one-time use ([`ONE_TIME_USE`]).
    ///
    /// The blinding factors, the spend keys and the reply key's secret are saved
    /// in the wallet before this returns, so the notes can be claimed whenever
    /// the PSP delivers them, and the key is on disk before any payment is made.
    pub fn build_psp_payload(
        &mut self,
        outputs: &[u64],
        mint_did_pubkey: &DidPublicKey,
    ) -> Result<PurchaseBuild, WalletError> {
        check_outputs(
            outputs,
            self.psp_max_denomination(),
            self.psp_min_purchase(),
        )?;
        let pending: Vec<PendingOutput> = outputs.iter().map(|&a| PendingOutput::new(a)).collect();
        let reply_key = DidSecretKey::new();
        let reply_did = addr::key_to_bytes(&reply_key.public_key());
        // The payload names the PSP's current keyset as last seen, like every
        // other request, and the PSP signs with it while it is live (else with
        // its current one). The record carries the keyset that signed and its
        // keys.
        let plaintext = payload::encode(&Payload {
            keyset: self.psp_output_keyset(),
            did: reply_did,
            outputs: pending.iter().map(PendingOutput::mint_output).collect(),
        })
        .map_err(|e| WalletError::Invalid(e.to_string()))?;
        let sealed = sp_wire::seal::encrypt(mint_did_pubkey, &plaintext)?;
        let id = hex::encode(Sha256::digest(&sealed));
        let record = PendingPurchase {
            id: id.clone(),
            reply_did: hex::encode(reply_did),
            mint_did_pubkey: mint_did_pubkey.to_string(),
            outputs: pending,
            reply_secret: addr::secret_to_hex(&reply_key),
            delivery_id: hex::encode(delivery::purchase_id(&plaintext)),
            open: None,
        };
        self.update(|d| {
            d.pending_purchases.push(record);
            Ok(())
        })?;
        Ok(PurchaseBuild {
            id,
            payload: sealed,
        })
    }

    /// Apply the PSP's record for the pending purchase `purchase_id` (its `id`),
    /// which has been opened and checked (`delivery::open_record`).
    ///
    /// - **Signed.** Each pair is unblinded with the keys of the keyset that
    ///   signed, which the record carries (they must be the keys that keyset's id
    ///   names), and becomes a note. All or nothing: a pair that matches no
    ///   pending output, or an amount the keyset has no key for, changes nothing.
    ///   The purchase is cleared. Its key is deleted with it unless the purchase
    ///   may still be open: the PSP owes a credit, or some output was neither
    ///   signed nor reported as dropped. Then the key is kept in `open_replies`
    ///   until the record's `open_until` (or, with none named, 14 days from now).
    ///   A credit carries the record's rules, which are what the claim
    ///   ([`Wallet::build_reconcile`]) follows; a record that owes a credit and
    ///   carries no rules is a mint error, and nothing is stored.
    /// - **Held or Refused.** The purchase and its key are kept, marked open with
    ///   what the PSP said and its rules ([`Delivered::Open`]). Nothing is cleared
    ///   until a reconciliation request settles it ([`Wallet::apply_reconcile`])
    ///   or `open_until` passes ([`Wallet::close_expired`]). A record that opens a
    ///   window and carries no rules is a mint error, and nothing is stored: there
    ///   would be nothing to send.
    /// - A purchase that is not pending (this record was applied before) is
    ///   [`Delivered::AlreadyDone`], and nothing is written. So is an open
    ///   purchase given the same held or refused record again (a request already
    ///   built for it is kept). A different record replaces the first, and a
    ///   request built under other rules is dropped with its AIR request.
    pub fn apply_delivery(
        &mut self,
        purchase_id: &str,
        outcome: &Outcome,
    ) -> Result<Delivered, WalletError> {
        let Some(current) = self
            .pending_purchases()
            .iter()
            .find(|p| p.id == purchase_id)
        else {
            return Ok(Delivered::AlreadyDone);
        };
        let open = match outcome {
            Outcome::Signed(_) => None,
            Outcome::Refused(r) => Some(OpenPurchase {
                kind: OpenKind::Rejected,
                reason: r.reason.clone(),
                paid_sats: r.paid_sats,
                paid_cents: r.paid_cents,
                requested_units: 0,
                over_under_bps: 0,
                open_until: window(r.open_until),
                rules: rules_of("rejected purchase", &r.rules)?,
                reconcile: ReconcileState::default(),
            }),
            Outcome::Held(h) => Some(OpenPurchase {
                kind: OpenKind::Held,
                reason: h.reason.clone(),
                paid_sats: h.paid_sats,
                paid_cents: h.paid_cents,
                requested_units: h.requested_units,
                over_under_bps: h.over_under_bps,
                open_until: window(h.open_until),
                rules: rules_of("held payment", &h.rules)?,
                reconcile: ReconcileState::default(),
            }),
        };
        if let Some(mut open) = open {
            if current
                .open
                .as_ref()
                .is_some_and(|kept| kept.same_record(&open))
            {
                return Ok(Delivered::AlreadyDone);
            }
            let key = current.reply_secret.clone();
            self.update(|d| {
                let old = d
                    .pending_purchases
                    .iter_mut()
                    .find(|p| p.id == purchase_id)
                    .and_then(|p| p.open.take());
                if let Some(old) = old {
                    if old.rules == open.rules {
                        open.reconcile = old.reconcile;
                    } else {
                        drop_air_request(d, &key);
                    }
                }
                if let Some(p) = d.pending_purchases.iter_mut().find(|p| p.id == purchase_id) {
                    p.open = Some(open);
                }
                Ok(())
            })?;
            let kept = self
                .pending_purchases()
                .iter()
                .find(|p| p.id == purchase_id)
                .and_then(|p| p.open.clone())
                .expect("the open record was just stored");
            return Ok(Delivered::Open(kept));
        }
        let Outcome::Signed(signed) = outcome else {
            unreachable!("the other outcomes returned above");
        };
        let claim_rules = if signed.credit_cents > 0 {
            Some(rules_of("credit", &signed.rules)?)
        } else {
            signed.rules.clone()
        };
        let keys = keys_of(&signed.keyset, &signed.keysets)?;
        self.update(|d| {
            let at = d
                .pending_purchases
                .iter()
                .position(|p| p.id == purchase_id)
                .ok_or_else(|| {
                    WalletError::Unknown(format!("no pending purchase {purchase_id}"))
                })?;
            let mut claimed = Vec::new();
            let mut claimed_units = 0u64;
            for pair in &signed.signatures {
                let blind_nonce = BlindNonce(point(&pair.blind_nonce)?);
                let signature = point(&pair.signature)?;
                let found = d.pending_purchases[at]
                    .outputs
                    .iter()
                    .position(|o| o.blind_nonce == blind_nonce);
                let Some(o) = found else {
                    return Err(WalletError::Unknown(format!(
                        "no pending output of purchase {purchase_id} has blind nonce {}",
                        blind_nonce.0
                    )));
                };
                let output = d.pending_purchases[at].outputs.remove(o);
                let key = keys
                    .get(&Amount::from_units(output.amount))
                    .ok_or_else(|| {
                        WalletError::Mint(format!("the PSP has no key for {} units", output.amount))
                    })?;
                let note = StoredNote {
                    kind: Kind::Psp,
                    amount: output.amount,
                    note: output.unblind(&signature, key),
                    spend_secret: output.nonce_secret,
                    terms: None,
                    reserved_by: None,
                };
                // The keyset is the one whose keys unblinded the note.
                d.keysets.insert(note.id(), signed.keyset.clone());
                claimed.push(note.id());
                claimed_units = claimed_units
                    .checked_add(output.amount)
                    .ok_or_else(|| WalletError::Invalid("amounts are too large".into()))?;
                d.notes.push(note);
            }
            let purchase = d.pending_purchases.remove(at);
            // What was asked for and not signed must be what the PSP says it
            // dropped. A difference either way means the purchase may not be
            // closed, so its key is kept.
            let left: u64 = purchase.outputs.iter().map(|o| o.amount).sum();
            let unaccounted_units = left.abs_diff(signed.skipped_units);
            let key_kept = signed.credit_cents > 0 || unaccounted_units > 0;
            if key_kept {
                // The PSP's window for a credit; else the wallet's own.
                let open_until = window(signed.open_until);
                d.open_replies.push(OpenReply {
                    id: purchase.id,
                    delivery_id: purchase.delivery_id,
                    mint_did_pubkey: purchase.mint_did_pubkey,
                    reply_secret: purchase.reply_secret,
                    credit_cents: signed.credit_cents,
                    unaccounted_units,
                    open_until,
                    rules: claim_rules,
                    reconcile: ReconcileState::default(),
                });
            }
            let still_pending = d.pending_purchases.iter().map(|p| p.outputs.len()).sum();
            Ok(Delivered::Claimed(Claimed {
                claim: ClaimResult {
                    claimed,
                    claimed_units,
                    still_pending,
                },
                skipped_units: signed.skipped_units,
                credit_cents: signed.credit_cents,
                unaccounted_units,
                key_kept,
            }))
        })
    }

    /// The credit the PSP owes this wallet for overpayments, summed over the
    /// credits whose window is still open at `now` (Unix seconds, this wallet's
    /// clock). It is not in [`Wallet::balance`]'s `psp`: the wallet holds no note
    /// for it until the credit is claimed ([`crate::mint_info::psp_reconcile`]).
    /// `units` is what the claim will issue (the rules' `due_units`), `cents` the
    /// exact credit. A credit whose window has closed is left out, as
    /// [`Wallet::close_expired`] would delete it, and so is one that was claimed.
    pub fn pending_psp_credit(&self, now: u64) -> PspCredit {
        let mut credit = PspCredit {
            cents: 0,
            units: 0,
            purchases: 0,
        };
        for r in self
            .open_replies()
            .iter()
            .filter(|r| r.credit_cents > 0 && r.open_until > now)
        {
            credit.cents += u128::from(r.credit_cents);
            credit.units += r
                .rules
                .as_ref()
                .map_or(0, |rules| u128::from(rules.due_units));
            credit.purchases += 1;
        }
        credit
    }

    /// Delete what a closed reconciliation window leaves behind: every open
    /// purchase (held or rejected) whose `open_until` is `now` or earlier, with
    /// its blinding factors, its reply key and the request it saved, and every
    /// kept reply key (a credit, or outputs not accounted for) whose `open_until`
    /// has passed. The PSP forfeits a payment that is still open at its
    /// `open_until`, so nothing can arrive for these any more. The window is the
    /// PSP's, read from its record, and `now` is this wallet's clock.
    ///
    /// Nothing is written when nothing is closed. Returns what was closed, one
    /// [`Loss`] each: its [`Loss::forfeited`] says plainly that the payment was
    /// forfeited and the funds are lost, with the amount.
    pub fn close_expired(&mut self, now: u64) -> Result<Vec<Loss>, WalletError> {
        self.close_expired_keeping(now, &[])
    }

    /// [`Wallet::close_expired`], leaving the payments in `keep` as they are: the
    /// ones whose last resend could not be sent
    /// ([`crate::mint_info::psp_close_expired`]), which are closed at a later
    /// start. No network use.
    pub(crate) fn close_expired_keeping(
        &mut self,
        now: u64,
        keep: &[String],
    ) -> Result<Vec<Loss>, WalletError> {
        let due = |p: &PendingPurchase| {
            p.open.as_ref().is_some_and(|o| o.open_until <= now) && !keep.contains(&p.id)
        };
        let expired = |r: &OpenReply| r.open_until <= now && !keep.contains(&r.id);
        let d = self.data();
        let ids: Vec<String> = d
            .pending_purchases
            .iter()
            .filter(|p| due(p))
            .map(|p| p.id.clone())
            .chain(
                d.open_replies
                    .iter()
                    .filter(|r| expired(r))
                    .map(|r| r.id.clone()),
            )
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let losses: Vec<Loss> = ids
            .iter()
            .filter_map(|id| target_of(d, id))
            .map(|t| t.loss())
            .collect();
        let keys: Vec<String> = ids
            .iter()
            .filter_map(|id| target_of(d, id))
            .map(|t| t.reply_secret)
            .collect();
        self.update(|d| {
            d.pending_purchases.retain(|p| !due(p));
            d.open_replies.retain(|r| !expired(r));
            for key in &keys {
                drop_air_request(d, key);
            }
            Ok(())
        })?;
        Ok(losses)
    }

    /// Forget a purchase that was never paid. Its blinding factors and its reply
    /// key are dropped. Do not do this once the payment has been sent.
    pub fn discard_purchase(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            let before = d.pending_purchases.len();
            d.pending_purchases.retain(|p| p.id != id);
            if d.pending_purchases.len() == before {
                return Err(WalletError::Unknown(format!("no pending purchase {id}")));
            }
            Ok(())
        })
    }

    /// The payments the wallet is settling that are still open at `now`: every
    /// held or rejected purchase and every credit, with what is due, until when,
    /// and where it stands ([`ReconcileStatus`]). Oldest first (purchases, then
    /// credits). A payment whose window has closed is not listed:
    /// [`Wallet::close_expired`] reports it as lost.
    pub fn open_reconciliations(&self, now: u64) -> Vec<OpenReconciliation> {
        let d = self.data();
        let ids = d
            .pending_purchases
            .iter()
            .filter(|p| p.open.is_some())
            .map(|p| p.id.clone())
            .chain(
                d.open_replies
                    .iter()
                    .filter(|r| r.rules.is_some())
                    .map(|r| r.id.clone()),
            );
        ids.filter_map(|id| {
            let t = target_of(d, &id)?;
            let rules = t.rules.clone()?;
            (t.open_until > now).then(|| OpenReconciliation {
                id: t.id.clone(),
                mint: ServiceDid::parse(&t.mint_did_pubkey)
                    .map_or_else(|_| t.mint_did_pubkey.clone(), |did| did.to_hex()),
                send: rules.send.clone(),
                due_units: rules.due_units,
                open_until: t.open_until,
                attempts: t.state.attempts,
                max_attempts: rules.max_attempts,
                state: t.status(&rules),
                told_lost: t.state.told_lost,
                paid_sats: t.paid_sats,
                paid_cents: t.paid_cents,
                credit_cents: t.credit_cents,
            })
        })
        .collect()
    }

    /// The payments whose window has closed at `now` (`open_until` is `now` or
    /// earlier) and that still hold a saved request: `(id, the PSP it was sealed
    /// to as hex)`. These are the ones [`crate::mint_info::psp_close_expired`]
    /// sends the saved request of one last time before
    /// [`Wallet::close_expired`] deletes them. A payment without a saved request
    /// (nothing due, or none built) is not listed.
    pub(crate) fn expired_requests(&self, now: u64) -> Vec<(String, String)> {
        let d = self.data();
        d.pending_purchases
            .iter()
            .filter(|p| p.open.is_some())
            .map(|p| p.id.clone())
            .chain(
                d.open_replies
                    .iter()
                    .filter(|r| r.rules.is_some())
                    .map(|r| r.id.clone()),
            )
            .filter_map(|id| {
                let t = target_of(d, &id)?;
                (t.open_until <= now && t.rules.is_some() && t.state.request.is_some()).then(|| {
                    let mint = ServiceDid::parse(&t.mint_did_pubkey)
                        .map_or_else(|_| t.mint_did_pubkey.clone(), |did| did.to_hex());
                    (t.id.clone(), mint)
                })
            })
            .collect()
    }

    /// What the user is told if payment `id` is lost: `None` when it is not an
    /// open payment.
    pub(crate) fn reconcile_loss(&self, id: &str) -> Option<Loss> {
        target_of(self.data(), id).map(|t| t.loss())
    }

    /// Build the reconciliation request (AIR kind 15) for the open payment `id`
    /// and save it, so that [`crate::mint_info::psp_reconcile`] can send it.
    /// `keysets` is a fresh read of the PSP's keysets, `now` this wallet's clock
    /// in Unix seconds.
    ///
    /// The request follows the payment's rules: fresh blinded outputs that are
    /// powers of two, none above the PSP's largest note, adding up to the rules'
    /// `due_units` exactly; on the PSP's current keyset; signed by the purchase's
    /// reply key. [`check_reconcile`] checks all of it before anything is saved,
    /// and a request that fails is refused: nothing is saved and nothing is sent.
    /// The request, its bytes and its blinding factors are then saved with the
    /// payment, together with the AIR request that will carry it (its `R` is the
    /// reply key), in one write.
    ///
    /// It refuses, with the wallet unchanged: a payment with nothing due (the
    /// fees take the whole amount); one whose window has closed; one whose rules
    /// name something other than what this payment is sent as; a saved request
    /// whose keyset is still live (that one is sent again as it is); and any
    /// request beyond `min(rules.max_attempts, 2)`: the first, and the one second
    /// request the keyset-rotation race allows.
    pub fn build_reconcile(
        &mut self,
        id: &str,
        keysets: &KeysetsResponse,
        now: u64,
    ) -> Result<ReconcileBuild, WalletError> {
        let t = target_of(self.data(), id)
            .ok_or_else(|| WalletError::Unknown(format!("no open payment {id}")))?;
        let Some(rules) = t.rules.clone() else {
            return Err(WalletError::Unknown(format!(
                "purchase {id} has no reconciliation rules: the PSP named nothing to send for it"
            )));
        };
        let (send, what) = if t.credit {
            (SEND_CREDIT_CLAIM, "a credit")
        } else {
            (SEND_CORRECTED_REQUEST, "a held or rejected payment")
        };
        if rules.send != send {
            return Err(WalletError::Mint(format!(
                "the PSP's rules for {what} say to send {:?}, but this wallet sends {send:?} for it. Nothing was built",
                rules.send
            )));
        }
        if now >= rules.open_until {
            return Err(WalletError::Invalid(format!(
                "purchase {id}: the window closed at {}, so nothing is built or sent",
                crate::date::format_utc(rules.open_until)
            )));
        }
        if rules.due_units == 0 {
            return Err(WalletError::Invalid(format!(
                "purchase {id}: nothing is due (the PSP's fees take the whole amount), so no request is built"
            )));
        }
        let may_build = rules.max_attempts.min(MAX_BUILT_REQUESTS);
        if t.state.attempts >= may_build {
            return Err(WalletError::Invalid(format!(
                "purchase {id}: {} request(s) were built already, and the rules allow {} ({} at most the wallet builds). No other is built",
                t.state.attempts, rules.max_attempts, MAX_BUILT_REQUESTS
            )));
        }
        if let Some(saved) = &t.state.request
            && keyset_is_live(keysets, &saved.keyset)
        {
            return Err(WalletError::Invalid(format!(
                "purchase {id}: the saved request names keyset {}, which is still live. It is sent again as it is, never rebuilt",
                saved.keyset
            )));
        }
        let keyset = keysets.current.clone();
        let keys = keys_of(&keyset, keysets)?;
        let top =
            keys.keys().map(|a| a.units).max().ok_or_else(|| {
                WalletError::Mint(format!("the PSP's keyset {keyset} has no keys"))
            })?;
        let outputs: Vec<PendingOutput> = split_due(rules.due_units, top)?
            .into_iter()
            .map(PendingOutput::new)
            .collect();

        let key = addr::secret_from_hex(&t.reply_secret).map_err(|_| {
            WalletError::Corrupt(format!("the reply key of purchase {id} is not valid"))
        })?;
        let reply_did = addr::key_to_did(&key.public_key());
        if t.reply_did
            .as_deref()
            .is_some_and(|saved| saved != reply_did.to_hex())
        {
            return Err(WalletError::Corrupt(format!(
                "the reply key of purchase {id} is not the one its payload names"
            )));
        }
        let purchase: [u8; 32] = hex::decode(&t.delivery_id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                WalletError::Corrupt(format!("the delivery id of purchase {id} is not valid"))
            })?;
        let secret = secp256k1::SecretKey::from_slice(&key.to_array()).map_err(|_| {
            WalletError::Corrupt(format!("the reply key of purchase {id} is not valid"))
        })?;
        let mut request = ReconcileRequest {
            reply_did,
            purchase,
            keyset: keyset.clone(),
            outputs: outputs.iter().map(PendingOutput::mint_output).collect(),
            signature: secp256k1::schnorr::Signature::from_slice(&[0; 64])
                .expect("any 64 bytes are a signature to sign over"),
        };
        request.signature = SECP256K1.sign_schnorr(
            &request.digest(),
            &Keypair::from_secret_key(SECP256K1, &secret),
        );
        check_reconcile(&request, &rules, keysets, &reply_did, &purchase, now)?;
        let body = serde_json::to_vec(&request)
            .map_err(|e| WalletError::Invalid(format!("the request could not be encoded: {e}")))?;
        let hash = request.hash();
        let attempt = t.state.attempts + 1;

        let saved = SavedRequest {
            body: hex::encode(&body),
            hash: hash.clone(),
            keyset,
            outputs,
        };
        let air_request = PendingAirRequest {
            kind: KIND_PSP_RECONCILE,
            request_id: hex::encode(addr::random_id()),
            mint: ServiceDid::parse(&t.mint_did_pubkey)
                .map_err(|e| {
                    WalletError::Corrupt(format!(
                        "the PSP's key of purchase {id} is not valid: {e}"
                    ))
                })?
                .to_hex(),
            r: addr::secret_to_hex(&key),
            slots: Vec::new(),
            created_at: addr::now_secs(),
            body_hash: crate::air::body_hash(&body),
        };
        self.update(|d| {
            let state = state_mut(d, id)
                .ok_or_else(|| WalletError::Unknown(format!("no open payment {id}")))?;
            state.request = Some(saved);
            state.attempts = attempt;
            state.unanswered = false;
            drop_air_request(d, &t.reply_secret);
            d.air_requests.push(air_request);
            Ok(())
        })?;
        Ok(ReconcileBuild {
            id: id.to_string(),
            request,
            body,
            hash,
            attempt,
        })
    }

    /// Apply the PSP's answer to the reconciliation request saved for the open
    /// payment `id`. The answer is checked first, and any failure is a mint error
    /// that stores nothing and keeps the key and the saved request:
    ///
    /// - the keyset that signed is listed in the answer and its keys hash to its
    ///   id (it need not be the keyset the request named: the PSP signs a request
    ///   it had already taken with its current keyset when the request's keyset was
    ///   deleted meanwhile);
    /// - there is one signature for each output, in the request's order, for that
    ///   output's blind nonce, and the keyset has a key for its amount;
    /// - `issued_units` is the rules' `due_units`.
    ///
    /// Then, in one write, the notes are stored (with their keyset recorded), and
    /// the purchase or credit, its reply key, the saved request and the AIR
    /// request that carried it are removed. A payment that is not open any more
    /// (the same answer applied before, here or in another copy of the wallet) is
    /// [`Applied::AlreadyDone`]: nothing is written and no note is added.
    pub fn apply_reconcile(
        &mut self,
        id: &str,
        response: &ReconcileResponse,
    ) -> Result<Applied, WalletError> {
        let Some(t) = target_of(self.data(), id) else {
            return Ok(Applied::AlreadyDone);
        };
        let Some(rules) = t.rules.clone() else {
            return Err(WalletError::Unknown(format!(
                "purchase {id} has no reconciliation rules: there is no request to apply an answer to"
            )));
        };
        let Some(saved) = t.state.request.clone() else {
            return Err(WalletError::Unknown(format!(
                "no reconciliation request was built for purchase {id}, so there is nothing for this answer to settle"
            )));
        };
        let wrong = |why: String| {
            WalletError::Mint(format!(
                "the PSP's answer to the reconciliation request of purchase {id} is not right ({why}). Nothing was stored and the key is kept"
            ))
        };
        // The keyset that signed need not be the one the request names: the PSP
        // signs a resumed request whose keyset was deleted since with its current
        // one, and the reply names it. It must be listed in the reply, with keys
        // that hash to its id (`keys_of`), and the notes take it.
        let keys =
            keys_of(&response.keyset, &response.keysets).map_err(|e| wrong(e.to_string()))?;
        if response.signatures.len() != saved.outputs.len() {
            return Err(wrong(format!(
                "it has {} signature(s) for {} output(s)",
                response.signatures.len(),
                saved.outputs.len()
            )));
        }
        let mut notes = Vec::with_capacity(saved.outputs.len());
        for (i, (output, pair)) in saved.outputs.iter().zip(&response.signatures).enumerate() {
            let blind_nonce = point(&pair.blind_nonce)
                .map(BlindNonce)
                .map_err(|e| wrong(format!("signature {i}: {e}")))?;
            if blind_nonce != output.blind_nonce {
                return Err(wrong(format!("signature {i} is for another output")));
            }
            let signature =
                point(&pair.signature).map_err(|e| wrong(format!("signature {i}: {e}")))?;
            let key = keys
                .get(&Amount::from_units(output.amount))
                .ok_or_else(|| {
                    wrong(format!("the keyset has no key for {} units", output.amount))
                })?;
            notes.push(StoredNote {
                kind: Kind::Psp,
                amount: output.amount,
                note: output.unblind(&signature, key),
                spend_secret: output.nonce_secret,
                terms: None,
                reserved_by: None,
            });
        }
        if response.issued_units != rules.due_units {
            return Err(wrong(format!(
                "it issued {} units, the rules say {}",
                response.issued_units, rules.due_units
            )));
        }
        let claimed: Vec<String> = notes.iter().map(StoredNote::id).collect();
        let units: u64 = notes.iter().map(|n| n.amount).sum();
        let keyset = response.keyset.clone();
        self.update(|d| {
            for note in notes {
                d.keysets.insert(note.id(), keyset.clone());
                d.notes.push(note);
            }
            if t.credit {
                d.open_replies.retain(|r| r.id != id);
            } else {
                d.pending_purchases.retain(|p| p.id != id);
            }
            drop_air_request(d, &t.reply_secret);
            d.reconciled.insert(id.to_string());
            Ok(())
        })?;
        Ok(Applied::Settled(Settled {
            claimed,
            units,
            credit: t.credit,
        }))
    }

    /// The saved request of payment `id`, with what sending it needs.
    pub(crate) fn reconcile_to_send(&self, id: &str) -> Result<ToSend, WalletError> {
        let t = target_of(self.data(), id)
            .ok_or_else(|| WalletError::Unknown(format!("no open payment {id}")))?;
        let (Some(_), Some(saved)) = (t.rules.as_ref(), t.state.request.as_ref()) else {
            return Err(WalletError::Unknown(format!(
                "no reconciliation request is saved for purchase {id}"
            )));
        };
        let corrupt = |what: &str| {
            WalletError::Corrupt(format!("the saved request of purchase {id} has {what}"))
        };
        let body = hex::decode(&saved.body).map_err(|_| corrupt("a body that is not hex"))?;
        let key = addr::secret_from_hex(&t.reply_secret)
            .map_err(|_| corrupt("a key that is not valid"))?;
        // The PSP key is not sent with the request, but a purchase sealed to a
        // key that does not parse is still refused here, as it always was.
        ServiceDid::parse(&t.mint_did_pubkey)
            .map_err(|_| corrupt("a PSP key that is not valid"))?;
        Ok(ToSend {
            body,
            key,
            keyset: saved.keyset.clone(),
        })
    }

    /// Record that the PSP did not answer the saved request of payment `id`
    /// (`true`), or that it did (`false`). Nothing is written when it is as
    /// recorded already.
    pub(crate) fn note_unanswered(
        &mut self,
        id: &str,
        unanswered: bool,
    ) -> Result<(), WalletError> {
        match target_of(self.data(), id) {
            Some(t) if t.state.unanswered != unanswered => {}
            _ => return Ok(()),
        }
        self.update(|d| {
            if let Some(state) = state_mut(d, id) {
                state.unanswered = unanswered;
            }
            Ok(())
        })
    }

    /// Record that the user was told payment `id` is lost, so it is said once.
    /// Nothing is written when it was recorded already.
    pub(crate) fn note_told_lost(&mut self, id: &str) -> Result<(), WalletError> {
        match target_of(self.data(), id) {
            Some(t) if !t.state.told_lost => {}
            _ => return Ok(()),
        }
        self.update(|d| {
            if let Some(state) = state_mut(d, id) {
                state.told_lost = true;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::expect;
    use psp_mint::scan::Received;
    use secp256k1::{SECP256K1, SecretKey};
    use sp_wire::air_request::delivery::{Held, Refused, Signed, SignedOutput};
    use sp_wire::psp::KeysetsResponse;
    use sp_wire::seal::SecretKey as DidSecretKey;
    use std::fs;
    use std::path::PathBuf;

    /// Open a wallet file of the test network.
    fn open_wallet(path: &std::path::Path) -> Result<crate::Wallet, crate::WalletError> {
        crate::Wallet::open(path, "regtest")
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-psp-{}-{name}", {
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

    /// A wallet that takes small purchases: these tests use outputs of a few
    /// units, below the default `psp.min_purchase` (the minimum has tests of its
    /// own, which use the default).
    fn wallet(name: &str) -> (Wallet, PathBuf) {
        let dir = scratch(name);
        let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
        w.set_psp_min_purchase(1).unwrap();
        (w, dir)
    }

    /// The rules a PSP gives a payment that is open until `open_until`.
    fn rules(send: &str, due_units: u64, open_until: u64) -> ReconcileRules {
        ReconcileRules {
            send: send.to_string(),
            kind: KIND_PSP_RECONCILE,
            due_units,
            reconciliation_fee_units: 0,
            read_prepaid_units: 0,
            write_prepaid_units: 0,
            open_until,
            max_attempts: 3,
            on_failure: delivery::FORFEIT_NOTICE.to_string(),
        }
    }

    /// The ids of the payments a call closed.
    fn lost_ids(losses: &[Loss]) -> Vec<String> {
        losses.iter().map(|l| l.id.clone()).collect()
    }

    fn payment(payload: Vec<u8>) -> Received {
        Received {
            txid: "aa".into(),
            confirmations: 6,
            value_sats: 5_000,
            payload: Some(payload),
        }
    }

    #[test]
    fn build_then_encrypt_then_the_mint_decrypts_and_decodes() {
        let (mut w, dir) = wallet("roundtrip");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();

        // the mint's side: the scanner opens the data output, then decodes it
        let (kept, dropped) =
            psp_mint::seal::open_payloads(&mint, vec![payment(built.payload.clone())]);
        assert_eq!(dropped, 0);
        let plaintext = kept[0].payload.clone().unwrap();
        let decoded = payload::decode(&plaintext).unwrap();
        let pending = &w.pending_purchases()[0];
        // the payload names the purchase's own reply DID, whose secret the wallet kept
        assert_eq!(hex::encode(decoded.did), pending.reply_did);
        let secret = addr::secret_from_hex(&pending.reply_secret).unwrap();
        assert_eq!(addr::key_to_bytes(&secret.public_key()), decoded.did);
        assert_eq!(
            pending.delivery_id,
            hex::encode(delivery::purchase_id(&plaintext))
        );
        assert_eq!(decoded.outputs.len(), 2);
        assert_eq!(decoded.outputs[0].amount, Amount::from_units(4));
        assert_eq!(decoded.outputs[1].amount, Amount::from_units(1));
        for (sent, held) in decoded.outputs.iter().zip(&pending.outputs) {
            assert_eq!(sent.blind_nonce, held.blind_nonce);
        }
        assert_eq!(built.id, hex::encode(Sha256::digest(&built.payload)));
        assert_eq!(pending.id, built.id);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_purchase_names_the_psp_keyset_the_wallet_last_saw() {
        let (mut w, dir) = wallet("names-keyset");
        let mint = DidSecretKey::new();
        let keyset_of = |w: &mut Wallet| {
            let built = w.build_psp_payload(&[1], &mint.public_key()).unwrap();
            let (kept, _) = psp_mint::seal::open_payloads(&mint, vec![payment(built.payload)]);
            payload::decode(kept[0].payload.as_deref().unwrap())
                .unwrap()
                .keyset
        };
        assert_eq!(keyset_of(&mut w), None, "none seen yet");
        let named = "ab".repeat(8);
        w.update(|d| {
            d.live_keysets
                .insert("http://psp".to_string(), (named.clone(), None));
            Ok(())
        })
        .unwrap();
        assert_eq!(keyset_of(&mut w), Some(named));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_purchase_is_saved_before_the_bytes_are_returned() {
        let (mut w, dir) = wallet("saved");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[8], &mint.public_key()).unwrap();
        let reopened = open_wallet(w.path()).unwrap();
        assert_eq!(reopened.pending_purchases().len(), 1);
        assert_eq!(reopened.pending_purchases()[0].id, built.id);
        assert_eq!(reopened.pending_purchases()[0].outputs[0].amount, 8);
        // the reply key's secret is on disk too, before any payment is made
        assert_eq!(
            reopened.pending_purchases()[0].reply_secret,
            w.pending_purchases()[0].reply_secret
        );
        assert_eq!(
            reopened.pending_purchases()[0].delivery_id,
            w.pending_purchases()[0].delivery_id
        );
        assert!(!w.pending_purchases()[0].reply_secret.is_empty());
        assert!(!w.pending_purchases()[0].delivery_id.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_psp_note_sizes_are_accepted() {
        let (mut w, dir) = wallet("sizes");
        let mint = DidSecretKey::new();
        let key = mint.public_key();
        for bad in [0u64, 3, 5, 6, 16_777_217, u64::MAX] {
            let e = expect::invalid(w.build_psp_payload(&[bad], &key));
            assert!(
                e.contains(&format!("{bad} is not a PSP note size: use a power of two")),
                "{bad}: {e}"
            );
        }
        let e = expect::invalid(w.build_psp_payload(&[], &key));
        assert!(e.contains("at least one output"), "{e}");
        let e = expect::invalid(w.build_psp_payload(&vec![1; 256], &key));
        assert!(e.contains("at most 255 outputs"), "{e}");
        assert!(w.pending_purchases().is_empty());
        for good in [1u64, 2, 4, 1024, 1_048_576, 16_777_216, 33_554_432] {
            assert!(w.build_psp_payload(&[good], &key).is_ok(), "{good}");
        }
        assert!(w.build_psp_payload(&vec![1; 255], &key).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_largest_note_is_the_one_the_psp_says() {
        let (mut w, dir) = wallet("top");
        let mint = DidSecretKey::new();
        let key = mint.public_key();
        // unknown: only the power of two is checked here, the PSP decides the top
        assert_eq!(w.psp_max_denomination(), None);
        assert!(w.build_psp_payload(&[1 << 26], &key).is_ok());
        // a PSP whose largest note is 1024
        w.set_psp_max_denomination(Some(1024));
        assert!(w.build_psp_payload(&[1024], &key).is_ok());
        let e = w.build_psp_payload(&[2048], &key).unwrap_err();
        assert!(e.to_string().contains("largest note, 1024"), "{e}");
        // a PSP that was configured for bigger notes
        w.set_psp_max_denomination(Some(1 << 27));
        assert!(w.build_psp_payload(&[1 << 27], &key).is_ok());
        let e = expect::invalid(w.build_psp_payload(&[1 << 28], &key));
        assert!(e.contains("largest note, 134217728"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A PSP's keys, and what it does when it settles: sign each output.
    fn sign_all(w: &Wallet, sks: &BTreeMap<Amount, SecretKey>) -> Vec<(BlindNonce, PublicKey)> {
        w.pending_purchases()
            .iter()
            .flat_map(|p| &p.outputs)
            .map(|o| {
                let sk = &sks[&Amount::from_units(o.amount)];
                (o.blind_nonce, bdhke::sign_message(sk, &o.blind_nonce.0))
            })
            .collect()
    }

    fn psp_keys() -> (BTreeMap<Amount, SecretKey>, BTreeMap<Amount, PublicKey>) {
        let sks: BTreeMap<Amount, SecretKey> = [1u64, 2, 4, 8]
            .iter()
            .map(|&a| {
                (
                    Amount::from_units(a),
                    SecretKey::new(&mut rand::rngs::OsRng),
                )
            })
            .collect();
        let pks = sks
            .iter()
            .map(|(a, sk)| (*a, sk.public_key(SECP256K1)))
            .collect();
        (sks, pks)
    }

    /// The record a PSP writes after signing `pairs` with the keys `pks`.
    fn record(
        pairs: &[(BlindNonce, PublicKey)],
        pks: &BTreeMap<Amount, PublicKey>,
        skipped_units: u64,
        credit_cents: u64,
    ) -> Outcome {
        let id = sp_wire::keyset::keyset_id(pks);
        let mut keysets = BTreeMap::new();
        keysets.insert(id.clone(), pks.iter().map(|(a, k)| (a.units, *k)).collect());
        Outcome::Signed(Signed {
            keyset: id.clone(),
            signatures: pairs
                .iter()
                .map(|(blind_nonce, signature)| SignedOutput {
                    blind_nonce: blind_nonce.0.to_string(),
                    signature: signature.to_string(),
                })
                .collect(),
            keysets: KeysetsResponse {
                current: id,
                previous: None,
                keysets,
            },
            skipped_units,
            credit_cents,
            open_until: 0,
            // a credit of 10 cents is a claim for 1 PSP unit
            rules: (credit_cents > 0).then(|| rules(SEND_CREDIT_CLAIM, credit_cents / 10, 0)),
        })
    }

    /// A signed record with the PSP's reconciliation window set.
    fn windowed(outcome: Outcome, open_until: u64) -> Outcome {
        let Outcome::Signed(mut signed) = outcome else {
            unreachable!()
        };
        signed.open_until = open_until;
        if let Some(r) = signed.rules.as_mut() {
            r.open_until = open_until;
        }
        Outcome::Signed(signed)
    }

    fn claimed(delivered: Delivered) -> Claimed {
        match delivered {
            Delivered::Claimed(c) => c,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn each_purchase_has_a_key_of_its_own() {
        let (mut w, dir) = wallet("own-key");
        let mint = DidSecretKey::new();
        w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        let [a, b] = w.pending_purchases() else {
            panic!("two purchases");
        };
        assert_ne!(a.reply_did, b.reply_did, "the PSP cannot link them");
        assert_ne!(a.reply_secret, b.reply_secret);
        assert_ne!(a.delivery_id, b.delivery_id);
        for p in [a, b] {
            let secret = addr::secret_from_hex(&p.reply_secret).unwrap();
            assert_eq!(
                hex::encode(addr::key_to_bytes(&secret.public_key())),
                p.reply_did
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn claimed_signatures_become_notes_the_psp_accepts_and_the_purchase_and_its_key_are_cleared() {
        let (mut w, dir) = wallet("claim");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);

        let c = claimed(
            w.apply_delivery(&built.id, &record(&sigs, &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed.len(), 2);
        assert_eq!(c.claim.claimed_units, 5);
        assert_eq!(c.claim.still_pending, 0);
        assert!(!c.key_kept);
        assert!(w.pending_purchases().is_empty());
        assert!(w.open_replies().is_empty(), "nothing is outstanding");
        assert_eq!(w.balance().psp, 5);
        for n in w.notes() {
            assert_eq!(n.kind, Kind::Psp);
            let sk = &sks[&Amount::from_units(n.amount)];
            assert!(bdhke::verify_message(
                sk,
                n.note.signature,
                &n.note.nonce.as_hash_preimage()
            ));
            // the keyset that unblinded it is recorded
            assert_eq!(
                w.data().keysets.get(&n.id()).map(String::as_str),
                Some(sp_wire::keyset::keyset_id(&pks).as_str())
            );
        }
        let again = open_wallet(w.path()).unwrap();
        assert_eq!(again.notes().len(), 2);
        assert!(again.pending_purchases().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_short_payment_closes_the_purchase_when_the_psp_reports_what_it_dropped() {
        let (mut w, dir) = wallet("partial");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        // the PSP signed only the 4 and kept the value of the 1
        let c = claimed(
            w.apply_delivery(&built.id, &record(&all[..1], &pks, 1, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 4);
        assert_eq!((c.skipped_units, c.unaccounted_units), (1, 0));
        assert!(!c.key_kept);
        assert!(w.pending_purchases().is_empty());
        assert!(w.open_replies().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_credit_keeps_the_key_for_the_follow_up() {
        let (mut w, dir) = wallet("credit");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let secret = w.pending_purchases()[0].reply_secret.clone();
        let delivery_id = w.pending_purchases()[0].delivery_id.clone();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let c = claimed(
            w.apply_delivery(&built.id, &record(&sigs, &pks, 0, 10))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 5);
        assert_eq!(c.credit_cents, 10);
        assert!(c.key_kept);
        assert!(w.pending_purchases().is_empty(), "the notes are claimed");
        let kept = open_wallet(w.path()).unwrap().open_replies().to_vec();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, built.id);
        assert_eq!(kept[0].delivery_id, delivery_id);
        assert_eq!(kept[0].reply_secret, secret);
        assert_eq!(kept[0].credit_cents, 10);
        // the record named no window, so the wallet's own is used
        let now = addr::now_secs();
        assert!(kept[0].open_until >= now + OPEN_KEY_FALLBACK_SECS - 60);
        assert!(kept[0].open_until <= now + OPEN_KEY_FALLBACK_SECS + 60);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_credit_keeps_the_key_until_the_window_the_record_names() {
        let (mut w, dir) = wallet("credit-window");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let outcome = windowed(record(&sigs, &pks, 0, 10), 1_800_000_000);
        w.apply_delivery(&built.id, &outcome).unwrap();
        assert_eq!(w.open_replies()[0].open_until, 1_800_000_000);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn outputs_neither_signed_nor_reported_dropped_keep_the_key() {
        let (mut w, dir) = wallet("unaccounted");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        // one output has no signature and the PSP does not say it dropped it
        let c = claimed(
            w.apply_delivery(&built.id, &record(&all[..1], &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.unaccounted_units, 1);
        assert!(c.key_kept);
        assert_eq!(w.open_replies()[0].unaccounted_units, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn applying_the_same_record_twice_changes_nothing() {
        let (mut w, dir) = wallet("twice");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let outcome = record(&sigs, &pks, 0, 10);
        w.apply_delivery(&built.id, &outcome).unwrap();
        let (version, notes, kept) = (w.version(), w.notes().len(), w.open_replies().len());
        assert_eq!(
            w.apply_delivery(&built.id, &outcome).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(
            w.apply_delivery("not a purchase", &outcome).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(w.version(), version, "nothing was written");
        assert_eq!((w.notes().len(), w.open_replies().len()), (notes, kept));
        assert_eq!(w.balance().psp, 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn rejected(open_until: u64) -> Outcome {
        Outcome::Refused(Refused {
            reason: "a blind nonce in the request was already signed".to_string(),
            paid_sats: 5_000,
            paid_cents: 50,
            open_until,
            rules: Some(rules(SEND_CORRECTED_REQUEST, 5, open_until)),
        })
    }

    fn held(open_until: u64) -> Outcome {
        Outcome::Held(Held {
            reason: "the payment is short".to_string(),
            paid_sats: 1_000,
            paid_cents: 10,
            requested_units: 5,
            over_under_bps: -8_000,
            open_until,
            rules: Some(rules(SEND_CORRECTED_REQUEST, 5, open_until)),
        })
    }

    fn open_of(delivered: Delivered) -> OpenPurchase {
        match delivered {
            Delivered::Open(o) => o,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_rejection_keeps_the_purchase_and_its_key_open_with_what_was_paid() {
        let (mut w, dir) = wallet("rejected");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let secret = w.pending_purchases()[0].reply_secret.clone();
        let outcome = rejected(1_800_000_000);
        let open = open_of(w.apply_delivery(&built.id, &outcome).unwrap());
        assert_eq!(open.kind, OpenKind::Rejected);
        assert_eq!(
            open.reason,
            "a blind nonce in the request was already signed"
        );
        assert_eq!((open.paid_sats, open.paid_cents), (5_000, 50));
        assert_eq!(open.open_until, 1_800_000_000);
        // kept, with the same key, marked open; no notes
        let [p] = w.pending_purchases() else {
            panic!("the purchase is kept");
        };
        assert_eq!(p.open.as_ref(), Some(&open));
        assert_eq!(p.reply_secret, secret);
        assert_eq!(p.outputs.len(), 2);
        assert!(w.notes().is_empty() && w.open_replies().is_empty());
        // saved
        assert_eq!(
            open_wallet(w.path()).unwrap().pending_purchases()[0].open,
            p.open
        );
        // the same record again changes nothing, and writes nothing
        let version = w.version();
        assert_eq!(
            w.apply_delivery(&built.id, &outcome).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(w.version(), version);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_held_payment_keeps_the_purchase_open_and_says_how_short_it_was() {
        let (mut w, dir) = wallet("held");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let open = open_of(w.apply_delivery(&built.id, &held(1_800_000_000)).unwrap());
        assert_eq!(open.kind, OpenKind::Held);
        assert_eq!((open.paid_sats, open.paid_cents), (1_000, 10));
        assert_eq!((open.requested_units, open.over_under_bps), (5, -8_000));
        assert_eq!(w.pending_purchases()[0].open.as_ref(), Some(&open));
        assert!(w.notes().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn signatures_can_still_be_claimed_for_a_purchase_that_was_open() {
        let (mut w, dir) = wallet("open-then-signed");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        w.apply_delivery(&built.id, &held(1_800_000_000)).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let c = claimed(
            w.apply_delivery(&built.id, &record(&sigs, &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 5);
        assert!(w.pending_purchases().is_empty());
        assert_eq!(w.balance().psp, 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn closing_deletes_open_purchases_and_their_keys_at_the_end_of_the_window_only() {
        let (mut w, dir) = wallet("close");
        let mint = DidSecretKey::new();
        let a = w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        let b = w.build_psp_payload(&[2], &mint.public_key()).unwrap();
        let c = w.build_psp_payload(&[4], &mint.public_key()).unwrap();
        // a is held until 1,000, b rejected until 2,000, c has no record yet
        w.apply_delivery(&a.id, &held(1_000)).unwrap();
        w.apply_delivery(&b.id, &rejected(2_000)).unwrap();

        let version = w.version();
        assert!(w.close_expired(999).unwrap().is_empty());
        assert_eq!(w.version(), version, "nothing due, nothing written");

        // the end of the window itself closes it (the PSP forfeits at the same time)
        assert_eq!(
            lost_ids(&w.close_expired(1_000).unwrap()),
            vec![a.id.clone()]
        );
        let ids: Vec<&str> = w
            .pending_purchases()
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, vec![b.id.as_str(), c.id.as_str()]);

        // a purchase with no record yet is never closed by the clock
        assert_eq!(
            lost_ids(&w.close_expired(u64::MAX - 1).unwrap()),
            vec![b.id.clone()]
        );
        let ids: Vec<&str> = w
            .pending_purchases()
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids, vec![c.id.as_str()]);
        assert!(!w.pending_purchases()[0].reply_secret.is_empty());
        assert_eq!(open_wallet(w.path()).unwrap().pending_purchases().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn closing_deletes_kept_reply_keys_when_their_window_has_passed() {
        let (mut w, dir) = wallet("close-keys");
        let reply = |id: &str, open_until: u64| OpenReply {
            id: id.into(),
            delivery_id: "dd".repeat(32),
            mint_did_pubkey: "03".repeat(33),
            reply_secret: "ee".repeat(32),
            credit_cents: 10,
            unaccounted_units: 0,
            open_until,
            rules: Some(rules(SEND_CREDIT_CLAIM, 1, open_until)),
            reconcile: ReconcileState::default(),
        };
        w.update(|d| {
            d.open_replies.push(reply("early", 1_000));
            d.open_replies.push(reply("late", 5_000));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            lost_ids(&w.close_expired(2_000).unwrap()),
            vec!["early".to_string()]
        );
        let kept: Vec<(&str, u64)> = w
            .open_replies()
            .iter()
            .map(|r| (r.id.as_str(), r.open_until))
            .collect();
        assert_eq!(kept, vec![("late", 5_000)]);
        assert!(w.close_expired(4_999).unwrap().is_empty());
        assert_eq!(
            lost_ids(&w.close_expired(5_000).unwrap()),
            vec!["late".to_string()]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_credit_the_psp_owes_is_summed_over_open_credits_in_psp_units_and_usd_cents() {
        let (mut w, dir) = wallet("owed-credit");
        let nothing = w.pending_psp_credit(0);
        assert_eq!((nothing.cents, nothing.units, nothing.purchases), (0, 0, 0));
        assert_eq!(
            (nothing.psp().as_str(), nothing.usd().as_str()),
            ("0", "0.00")
        );
        assert_eq!(nothing.balance_line(), None);

        // a purchase that was overpaid by 1.00 USD, through the real record path,
        // with the PSP's window open until 5000: the claim is for 10 units
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        w.apply_delivery(&built.id, &windowed(record(&sigs, &pks, 0, 100), 5_000))
            .unwrap();
        let one = w.pending_psp_credit(4_999);
        assert_eq!((one.cents, one.units, one.purchases), (100, 10, 1));
        assert_eq!((one.psp().as_str(), one.usd().as_str()), ("10", "1.00"));
        assert_eq!(
            one.balance_line().as_deref(),
            Some(
                "10 PSP (1.00 USD) (pending): credit the PSP owes for 1 purchase(s), not counted above until it is claimed"
            )
        );

        // a second credit of 12 cents whose claim is for 1 unit (the PSP rounds,
        // the wallet does not), and a key kept for outputs only (no credit)
        let reply = |id: &str, credit_cents: u64, due_units: u64, open_until: u64| OpenReply {
            id: id.into(),
            delivery_id: "dd".repeat(32),
            mint_did_pubkey: "03".repeat(33),
            reply_secret: "ee".repeat(32),
            credit_cents,
            unaccounted_units: 1,
            open_until,
            rules: (credit_cents > 0).then(|| rules(SEND_CREDIT_CLAIM, due_units, open_until)),
            reconcile: ReconcileState::default(),
        };
        w.update(|d| {
            d.open_replies.push(reply("small", 12, 1, 9_000));
            d.open_replies.push(reply("outputs-only", 0, 0, 9_000));
            Ok(())
        })
        .unwrap();
        let both = w.pending_psp_credit(4_999);
        assert_eq!((both.cents, both.units, both.purchases), (112, 11, 2));
        assert_eq!((both.psp().as_str(), both.usd().as_str()), ("11", "1.12"));

        // the first window closes at 5000; only the second is still owed
        let later = w.pending_psp_credit(5_000);
        assert_eq!((later.cents, later.units, later.purchases), (12, 1, 1));
        assert_eq!((later.psp().as_str(), later.usd().as_str()), ("1", "0.12"));
        // after the second window, nothing is owed
        assert_eq!(w.pending_psp_credit(9_000).purchases, 0);

        // a credit of 8 cents is 0 units at the PSP's default rounding: the line
        // says so as it is, and the wallet rounds nothing
        let eight = PspCredit {
            cents: 8,
            units: 0,
            purchases: 1,
        };
        assert_eq!(
            eight.balance_line().as_deref(),
            Some(
                "0 PSP (0.08 USD) (pending): credit the PSP owes for 1 purchase(s), not counted above until it is claimed"
            )
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_bad_record_changes_nothing() {
        let (mut w, dir) = wallet("bad-record");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let all = sign_all(&w, &sks);
        let version = w.version();
        let unchanged = |w: &Wallet| {
            assert_eq!(w.version(), version);
            assert_eq!(w.pending_purchases()[0].outputs.len(), 2);
            assert!(w.notes().is_empty() && w.open_replies().is_empty());
        };

        // a pair that matches no pending output, before a valid one
        let stranger = (
            BlindNonce(SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1)),
            all[1].1,
        );
        let with_stranger = record(&[all[0], stranger], &pks, 0, 0);
        assert!(matches!(
            w.apply_delivery(&built.id, &with_stranger),
            Err(WalletError::Unknown(_))
        ));
        unchanged(&w);

        // the same pair twice
        let twice = record(&[all[0], all[0]], &pks, 0, 0);
        assert!(w.apply_delivery(&built.id, &twice).is_err());
        unchanged(&w);

        // a keyset with no key for an amount
        let mut no_keys = pks.clone();
        no_keys.remove(&Amount::from_units(1));
        assert!(matches!(
            w.apply_delivery(&built.id, &record(&all, &no_keys, 0, 0)),
            Err(WalletError::Mint(_))
        ));
        unchanged(&w);

        // keys that are not those the keyset id names (the id is taken from the
        // key of the smallest amount)
        let Outcome::Signed(mut forged) = record(&all, &pks, 0, 0) else {
            unreachable!()
        };
        let other = SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1);
        forged
            .keysets
            .keysets
            .get_mut(&forged.keyset)
            .unwrap()
            .insert(1, other);
        assert!(matches!(
            w.apply_delivery(&built.id, &Outcome::Signed(forged)),
            Err(WalletError::Mint(_))
        ));
        unchanged(&w);

        // a record that does not carry the keys of the keyset it names
        let Outcome::Signed(mut missing) = record(&all, &pks, 0, 0) else {
            unreachable!()
        };
        missing.keyset = "0000000000000000".to_string();
        assert!(matches!(
            w.apply_delivery(&built.id, &Outcome::Signed(missing)),
            Err(WalletError::Mint(_))
        ));
        unchanged(&w);

        // a signature that is not a curve point
        let Outcome::Signed(mut junk) = record(&all, &pks, 0, 0) else {
            unreachable!()
        };
        junk.signatures[0].signature = "zz".to_string();
        assert!(w.apply_delivery(&built.id, &Outcome::Signed(junk)).is_err());
        unchanged(&w);

        // and the good record still works afterwards
        let c = claimed(
            w.apply_delivery(&built.id, &record(&all, &pks, 0, 0))
                .unwrap(),
        );
        assert_eq!(c.claim.claimed_units, 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_purchase_can_be_discarded_before_it_is_paid() {
        let (mut w, dir) = wallet("discard");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[1], &mint.public_key()).unwrap();
        let other = w.build_psp_payload(&[2], &mint.public_key()).unwrap();
        let version = w.version();
        let e = expect::unknown(w.discard_purchase("nope"));
        assert!(e.contains("no pending purchase nope"), "{e}");
        assert_eq!(w.version(), version, "a refused discard writes nothing");
        assert_eq!(w.pending_purchases().len(), 2);
        w.discard_purchase(&built.id).unwrap();
        let ids = |w: &Wallet| -> Vec<String> {
            w.pending_purchases().iter().map(|p| p.id.clone()).collect()
        };
        assert_eq!(ids(&w), vec![other.id.clone()]);
        // gone from the file, not only from memory
        let reopened = open_wallet(w.path()).unwrap();
        assert_eq!(ids(&reopened), vec![other.id.clone()]);
        // and a second discard of the same purchase is refused
        let e = expect::unknown(w.discard_purchase(&built.id));
        assert!(e.contains(&built.id), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    // ---- the minimum purchase -------------------------------------------------

    #[test]
    fn a_purchase_below_the_minimum_is_refused_naming_the_setting_and_nothing_is_saved() {
        let dir = scratch("minimum");
        let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
        let key = DidSecretKey::new().public_key();
        assert_eq!(DEFAULT_MIN_PURCHASE, 50);
        assert_eq!(w.psp_min_purchase(), 50, "the default");
        // 49 in total, however it is split
        for outputs in [vec![32, 16, 1], vec![1; 49], vec![16, 16, 16, 1]] {
            let e = expect::invalid(w.build_psp_payload(&outputs, &key));
            assert!(e.contains("below the minimum of 50 PSP"), "{e}");
            assert!(e.contains("psp.min_purchase"), "{e}");
            assert!(e.contains("ECASH_PSP_MIN_PURCHASE"), "{e}");
            assert!(e.contains("100 PSP is a realistic purchase"), "{e}");
        }
        assert!(w.pending_purchases().is_empty(), "nothing was saved");
        assert!(!w.path().exists(), "nothing was written");
        // 50 is accepted
        assert!(w.build_psp_payload(&[32, 16, 2], &key).is_ok());
        assert_eq!(w.pending_purchases().len(), 1);
        // a lower setting is honoured, and the line moves with it
        w.set_psp_min_purchase(10).unwrap();
        assert!(w.build_psp_payload(&[8, 2], &key).is_ok());
        let e = expect::invalid(w.build_psp_payload(&[8, 1], &key));
        assert!(e.contains("below the minimum of 10 PSP"), "{e}");
        // 0 is not a minimum
        let e = expect::invalid(w.set_psp_min_purchase(0));
        assert!(e.contains("psp.min_purchase"), "{e}");
        assert_eq!(
            w.psp_min_purchase(),
            10,
            "the refused value changed nothing"
        );
        // the check is the same one the command line runs before any network use
        assert!(check_outputs(&[32, 16, 1], None, 50).is_err());
        assert!(check_outputs(&[32, 16, 2], None, 50).is_ok());
        // a bad size is refused for itself before the total is looked at
        let e = expect::invalid(check_outputs(&[3], None, 50));
        assert!(e.contains("not a PSP note size"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_one_time_use_warning_is_the_text_the_brief_names() {
        assert_eq!(
            ONE_TIME_USE,
            "ONE-TIME USE: pay this payload exactly once. A second payment carrying the same payload buys nothing and its funds are lost."
        );
    }

    // ---- reconciliation ---------------------------------------------------

    fn state(w: &Wallet) -> String {
        serde_json::to_string(&w.snapshot()).unwrap()
    }

    fn keysets_of(pks: &BTreeMap<Amount, PublicKey>) -> KeysetsResponse {
        let id = sp_wire::keyset::keyset_id(pks);
        let mut keysets = BTreeMap::new();
        keysets.insert(id.clone(), pks.iter().map(|(a, k)| (a.units, *k)).collect());
        KeysetsResponse {
            current: id,
            previous: None,
            keysets,
        }
    }

    /// A purchase of [4, 1] that the PSP holds, under `rules`.
    fn open_held(w: &mut Wallet, mint: &DidSecretKey, rules: ReconcileRules) -> String {
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let outcome = Outcome::Held(Held {
            reason: "the payment is short".to_string(),
            paid_sats: 1_000,
            paid_cents: 10,
            requested_units: 5,
            over_under_bps: -8_000,
            open_until: rules.open_until,
            rules: Some(rules),
        });
        w.apply_delivery(&built.id, &outcome).unwrap();
        built.id
    }

    fn signer(w: &Wallet, id: &str) -> Keypair {
        let p = w.pending_purchases().iter().find(|p| p.id == id).unwrap();
        let key = addr::secret_from_hex(&p.reply_secret).unwrap();
        let secret = SecretKey::from_slice(&key.to_array()).unwrap();
        Keypair::from_secret_key(SECP256K1, &secret)
    }

    fn resign(request: &mut ReconcileRequest, keypair: &Keypair) {
        request.signature = SECP256K1.sign_schnorr(&request.digest(), keypair);
    }

    fn saved_of(w: &Wallet, id: &str) -> ReconcileState {
        let p = w.pending_purchases().iter().find(|p| p.id == id).unwrap();
        p.open.as_ref().unwrap().reconcile.clone()
    }

    /// What the PSP answers once it accepts the saved request of `id`.
    fn answer(
        w: &Wallet,
        id: &str,
        sks: &BTreeMap<Amount, SecretKey>,
        pks: &BTreeMap<Amount, PublicKey>,
    ) -> ReconcileResponse {
        let saved = saved_of(w, id).request.unwrap();
        let keysets = keysets_of(pks);
        ReconcileResponse {
            keyset: keysets.current.clone(),
            signatures: saved
                .outputs
                .iter()
                .map(|o| SignedOutput {
                    blind_nonce: o.blind_nonce.0.to_string(),
                    signature: bdhke::sign_message(
                        &sks[&Amount::from_units(o.amount)],
                        &o.blind_nonce.0,
                    )
                    .to_string(),
                })
                .collect(),
            keysets,
            issued_units: saved.outputs.iter().map(|o| o.amount).sum(),
            fee_units: 0,
            read_prepaid_units: 0,
            write_prepaid_units: 0,
            kept_cents: 0,
            given_cents: 0,
        }
    }

    #[test]
    fn a_record_that_opens_a_window_but_carries_no_rules_is_a_mint_error_and_stores_nothing() {
        let (mut w, dir) = wallet("no-rules");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let before = state(&w);

        let Outcome::Held(mut held) = held(5_000) else {
            unreachable!()
        };
        held.rules = None;
        let Outcome::Refused(mut refused) = rejected(5_000) else {
            unreachable!()
        };
        refused.rules = None;
        for outcome in [Outcome::Held(held), Outcome::Refused(refused)] {
            let e = expect::mint(w.apply_delivery(&built.id, &outcome));
            assert!(e.contains("carries no rules"), "{e}");
            assert_eq!(state(&w), before, "nothing was stored");
        }

        // a credit with no rules: the notes are not claimed either
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        let Outcome::Signed(mut signed) = record(&sigs, &pks, 0, 10) else {
            unreachable!()
        };
        signed.rules = None;
        let e = expect::mint(w.apply_delivery(&built.id, &Outcome::Signed(signed)));
        assert!(e.contains("carries no rules"), "{e}");
        assert_eq!(state(&w), before, "no notes, no kept key");
        assert!(w.notes().is_empty() && w.open_replies().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_request_is_signed_checked_and_saved_with_its_air_request_in_one_write() {
        let (mut w, dir) = wallet("build");
        let mint = DidSecretKey::new();
        let id = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 20, 1_000));
        let (_, pks) = psp_keys();
        let keysets = keysets_of(&pks);
        let version = w.version();

        let built = w.build_reconcile(&id, &keysets, 100).unwrap();
        assert_eq!(w.version(), version + 1, "one write");
        assert_eq!(built.attempt, 1);
        // 20 units in notes of at most 8 (the PSP's largest): 8 + 8 + 4
        let amounts: Vec<u64> = built
            .request
            .outputs
            .iter()
            .map(|o| o.amount.units)
            .collect();
        assert_eq!(amounts, vec![8, 8, 4]);
        assert_eq!(built.request.keyset, keysets.current);
        let p = &w.pending_purchases()[0];
        assert_eq!(hex::encode(built.request.reply_did.as_bytes()), p.reply_did);
        assert_eq!(hex::encode(built.request.purchase), p.delivery_id);
        // it passes the check, and the bytes are the JSON of the request
        let did = built.request.reply_did;
        check_reconcile(
            &built.request,
            &p.open.as_ref().unwrap().rules,
            &keysets,
            &did,
            &built.request.purchase,
            100,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<ReconcileRequest>(&built.body).unwrap(),
            built.request
        );
        assert_eq!(built.hash, built.request.hash());

        // saved with the purchase: bytes, hash, keyset and the blinding factors
        let state = saved_of(&w, &id);
        let saved = state.request.unwrap();
        assert_eq!(saved.body, hex::encode(&built.body));
        assert_eq!(saved.hash, built.hash);
        assert_eq!(saved.keyset, keysets.current);
        let nonces: Vec<_> = saved.outputs.iter().map(|o| o.blind_nonce).collect();
        let sent: Vec<_> = built
            .request
            .outputs
            .iter()
            .map(|o| o.blind_nonce)
            .collect();
        assert_eq!(nonces, sent);
        assert_eq!(
            (state.attempts, state.unanswered, state.told_lost),
            (1, false, false)
        );
        // and with the AIR request that carries it: R is the reply key
        let [air] = w.air_requests() else {
            panic!("one AIR request");
        };
        assert_eq!(air.kind, KIND_PSP_RECONCILE);
        assert_eq!(air.r, p.reply_secret);
        assert_eq!(air.body_hash, crate::air::body_hash(&built.body));
        assert_eq!(air.mint, did_hex(&mint));
        assert!(air.slots.is_empty(), "nothing was written to AIR yet");
        // on disk
        let again = open_wallet(w.path()).unwrap();
        assert_eq!(again.air_requests(), w.air_requests());
        assert_eq!(saved_of(&again, &id).request.unwrap().hash, built.hash);

        // the saved request is sent again, never rebuilt, while its keyset is live
        let before = self::state(&w);
        let e = expect::invalid(w.build_reconcile(&id, &keysets, 100));
        assert!(e.contains("still live"), "{e}");
        assert_eq!(self::state(&w), before);
        fs::remove_dir_all(&dir).unwrap();
    }

    fn did_hex(mint: &DidSecretKey) -> String {
        hex::encode(addr::key_to_bytes(&mint.public_key()))
    }

    #[test]
    fn nothing_is_built_that_the_rules_do_not_allow() {
        let (mut w, dir) = wallet("refused-builds");
        let mint = DidSecretKey::new();
        let (_, pks) = psp_keys();
        let keysets = keysets_of(&pks);

        let unchanged =
            |w: &mut Wallet, id: &str, keysets: &KeysetsResponse, now: u64, want: &str| {
                let before = state(w);
                let e = w.build_reconcile(id, keysets, now).unwrap_err().to_string();
                assert!(e.contains(want), "{e}");
                assert_eq!(state(w), before, "nothing was saved");
                assert!(w.air_requests().is_empty(), "nothing will be sent");
            };

        let nothing_due = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 0, 1_000));
        unchanged(&mut w, &nothing_due, &keysets, 100, "nothing is due");
        let ok = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 1_000));
        unchanged(&mut w, &ok, &keysets, 1_000, "window closed");
        unchanged(&mut w, &ok, &keysets, 5_000, "window closed");
        unchanged(&mut w, "no such payment", &keysets, 100, "no open payment");
        // the PSP's rules name something this wallet does not send for a held payment
        let other = open_held(&mut w, &mint, rules(SEND_CREDIT_CLAIM, 5, 1_000));
        unchanged(&mut w, &other, &keysets, 100, "this wallet sends");
        // a request the check refuses: the rules name another kind
        let mut kind = rules(SEND_CORRECTED_REQUEST, 5, 1_000);
        kind.kind = 14;
        let wrong_kind = open_held(&mut w, &mint, kind);
        unchanged(
            &mut w,
            &wrong_kind,
            &keysets,
            100,
            "request kind 14, not 15",
        );
        // more notes than one request may carry: 8 * 1001 units in notes of 8
        let many = open_held(
            &mut w,
            &mint,
            rules(SEND_CORRECTED_REQUEST, 8 * 1_001, 1_000),
        );
        unchanged(&mut w, &many, &keysets, 100, "carries at most 1000");
        // keys that are not those the keyset's id names
        let mut forged = keysets.clone();
        forged.keysets.get_mut(&forged.current).unwrap().insert(
            1,
            SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1),
        );
        unchanged(&mut w, &ok, &forged, 100, "not those of keyset");
        // rules that allow no request at all
        let mut none = rules(SEND_CORRECTED_REQUEST, 5, 1_000);
        none.max_attempts = 0;
        let no_attempts = open_held(&mut w, &mint, none);
        unchanged(&mut w, &no_attempts, &keysets, 100, "No other is built");
        // the good one is still buildable, so none of that changed anything
        w.build_reconcile(&ok, &keysets, 100).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_check_refuses_each_rule_a_request_breaks_and_names_a_wallet_bug() {
        let (mut w, dir) = wallet("check");
        let mint = DidSecretKey::new();
        let id = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 1_000));
        let (_, pks) = psp_keys();
        let keysets = keysets_of(&pks);
        let built = w.build_reconcile(&id, &keysets, 100).unwrap();
        let (good, did, purchase) = (
            built.request.clone(),
            built.request.reply_did,
            built.request.purchase,
        );
        let rules_ = rules(SEND_CORRECTED_REQUEST, 5, 1_000);
        let keypair = signer(&w, &id);
        let run = |req: &ReconcileRequest, r: &ReconcileRules, k: &KeysetsResponse, now: u64| {
            check_reconcile(req, r, k, &did, &purchase, now)
        };
        run(&good, &rules_, &keysets, 100).unwrap();

        let refused = |result: Result<(), WalletError>, why: &str| {
            let e = expect::invalid(result);
            assert!(e.contains("bug in the wallet"), "{e}");
            assert!(e.contains("nothing was saved and nothing was sent"), "{e}");
            assert!(e.contains(why), "{why}: {e}");
        };

        // the rules: kind 15, and before the window's end
        let mut r = rules_.clone();
        r.kind = 14;
        refused(run(&good, &r, &keysets, 100), "not 15");
        refused(run(&good, &rules_, &keysets, 1_000), "the window closed at");
        refused(run(&good, &rules_, &keysets, 2_000), "the window closed at");
        // the total
        let mut r = rules_.clone();
        r.due_units = 6;
        refused(
            run(&good, &r, &keysets, 100),
            "add up to 5, the rules say 6",
        );

        // who it is for
        let mut req = good.clone();
        req.reply_did = addr::key_to_did(&DidSecretKey::new().public_key());
        resign(&mut req, &keypair);
        refused(run(&req, &rules_, &keysets, 100), "another reply DID");
        let mut req = good.clone();
        req.purchase = [7; 32];
        resign(&mut req, &keypair);
        refused(run(&req, &rules_, &keysets, 100), "another purchase id");
        // the signature
        let mut req = good.clone();
        let other = Keypair::from_secret_key(SECP256K1, &SecretKey::new(&mut rand::rngs::OsRng));
        resign(&mut req, &other);
        refused(run(&req, &rules_, &keysets, 100), "does not verify");
        let mut req = good.clone();
        req.outputs.pop();
        refused(run(&req, &rules_, &keysets, 100), "does not verify");

        // the keyset
        let (_, other_pks) = psp_keys();
        let rotated = keysets_of(&other_pks);
        refused(
            run(&good, &rules_, &rotated, 100),
            "neither the PSP's current keyset",
        );
        // a keyset that is the previous one is live
        let mut with_previous = rotated.clone();
        with_previous.previous = Some(keysets.current.clone());
        with_previous.keysets.insert(
            keysets.current.clone(),
            keysets.keysets[&keysets.current].clone(),
        );
        run(&good, &rules_, &with_previous, 100).unwrap();

        // the outputs
        let mut req = good.clone();
        req.outputs.clear();
        resign(&mut req, &keypair);
        refused(run(&req, &rules_, &keysets, 100), "no outputs");
        let mut req = good.clone();
        req.outputs[0].amount = Amount::from_units(3);
        resign(&mut req, &keypair);
        refused(run(&req, &rules_, &keysets, 100), "not a power of two");
        let mut req = good.clone();
        req.outputs[0].amount = Amount::from_units(16);
        resign(&mut req, &keypair);
        refused(
            run(&req, &rules_, &keysets, 100),
            "above the PSP's largest note",
        );
        let mut req = good.clone();
        req.outputs[1] = req.outputs[0].clone();
        resign(&mut req, &keypair);
        refused(run(&req, &rules_, &keysets, 100), "repeats a blind nonce");
        let mut req = good.clone();
        req.outputs = (0..1_001)
            .map(|_| PendingOutput::new(1).mint_output())
            .collect();
        resign(&mut req, &keypair);
        refused(run(&req, &rules_, &keysets, 100), "at most 1000");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_second_request_is_built_once_when_the_keyset_has_left_the_live_set() {
        let (mut w, dir) = wallet("second");
        let mint = DidSecretKey::new();
        let id = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 1_000));
        let (_, pks) = psp_keys();
        let first = keysets_of(&pks);
        let one = w.build_reconcile(&id, &first, 100).unwrap();

        // the PSP rotated twice: the first request's keyset is gone
        let (_, pks2) = psp_keys();
        let second = keysets_of(&pks2);
        let two = w.build_reconcile(&id, &second, 200).unwrap();
        assert_eq!(two.attempt, 2);
        assert_eq!(two.request.keyset, second.current);
        assert_ne!(two.hash, one.hash, "a new request, with new outputs");
        let saved = saved_of(&w, &id);
        assert_eq!(saved.attempts, 2);
        assert_eq!(saved.request.unwrap().hash, two.hash);
        let [air] = w.air_requests() else {
            panic!("the first request's AIR request was replaced");
        };
        assert_eq!(air.body_hash, crate::air::body_hash(&two.body));

        // never a third, whatever the keysets
        let (_, pks3) = psp_keys();
        let before = state(&w);
        let e = expect::invalid(w.build_reconcile(&id, &keysets_of(&pks3), 300));
        assert!(e.contains("2 request(s) were built already"), "{e}");
        assert_eq!(state(&w), before);

        // and the rules' own count caps it: one attempt allowed, one built
        let mut one_only = rules(SEND_CORRECTED_REQUEST, 5, 1_000);
        one_only.max_attempts = 1;
        let id = open_held(&mut w, &mint, one_only);
        w.build_reconcile(&id, &first, 100).unwrap();
        let e = expect::invalid(w.build_reconcile(&id, &second, 100));
        assert!(e.contains("the rules allow 1"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_answer_is_applied_once_and_its_notes_are_the_ones_the_psp_signed() {
        let (mut w, dir) = wallet("apply");
        let mint = DidSecretKey::new();
        let id = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 20, 1_000));
        let (sks, pks) = psp_keys();
        w.build_reconcile(&id, &keysets_of(&pks), 100).unwrap();
        let response = answer(&w, &id, &sks, &pks);

        let settled = match w.apply_reconcile(&id, &response).unwrap() {
            Applied::Settled(s) => s,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            (settled.units, settled.claimed.len(), settled.credit),
            (20, 3, false)
        );
        assert_eq!(w.balance().psp, 20);
        for n in w.notes() {
            let sk = &sks[&Amount::from_units(n.amount)];
            assert!(bdhke::verify_message(
                sk,
                n.note.signature,
                &n.note.nonce.as_hash_preimage()
            ));
            assert_eq!(
                w.data().keysets.get(&n.id()),
                Some(&sp_wire::keyset::keyset_id(&pks))
            );
        }
        // the purchase, its key, the saved request and the AIR request are gone
        assert!(w.pending_purchases().is_empty());
        assert!(w.air_requests().is_empty());
        assert!(w.data().reconciled.contains(&id));
        assert!(w.data().finished.contains(&id));
        assert!(w.open_reconciliations(100).is_empty());

        // the same answer again adds nothing and writes nothing
        let (version, notes) = (w.version(), w.notes().len());
        assert_eq!(
            w.apply_reconcile(&id, &response).unwrap(),
            Applied::AlreadyDone
        );
        assert_eq!((w.version(), w.notes().len()), (version, notes));
        assert_eq!(w.balance().psp, 20);
        // saved
        assert_eq!(open_wallet(w.path()).unwrap().balance().psp, 20);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_credit_claim_is_settled_the_same_way_and_the_pending_line_goes() {
        let (mut w, dir) = wallet("apply-credit");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        let sigs = sign_all(&w, &sks);
        // 94 cents owed; the PSP's rules say the claim is for 9 units
        let mut outcome = windowed(record(&sigs, &pks, 0, 94), 5_000);
        if let Outcome::Signed(s) = &mut outcome {
            s.rules = Some(rules(SEND_CREDIT_CLAIM, 9, 5_000));
        }
        w.apply_delivery(&built.id, &outcome).unwrap();
        assert_eq!(
            w.pending_psp_credit(100).balance_line().as_deref(),
            Some(
                "9 PSP (0.94 USD) (pending): credit the PSP owes for 1 purchase(s), not counted above until it is claimed"
            )
        );
        let listed = w.open_reconciliations(100);
        assert_eq!(listed.len(), 1);
        let open = &listed[0];
        assert_eq!(
            (open.send.as_str(), open.due_units, open.credit_cents),
            (SEND_CREDIT_CLAIM, 9, 94)
        );
        assert_eq!(open.state, ReconcileStatus::Due);

        let (sks2, pks2) = psp_keys();
        let built = w
            .build_reconcile(&built.id, &keysets_of(&pks2), 100)
            .unwrap();
        let amounts: Vec<u64> = built
            .request
            .outputs
            .iter()
            .map(|o| o.amount.units)
            .collect();
        assert_eq!(amounts, vec![8, 1]);
        // the answer
        let saved = w.open_replies()[0].reconcile.request.clone().unwrap();
        let keysets = keysets_of(&pks2);
        let response = ReconcileResponse {
            keyset: keysets.current.clone(),
            signatures: saved
                .outputs
                .iter()
                .map(|o| SignedOutput {
                    blind_nonce: o.blind_nonce.0.to_string(),
                    signature: bdhke::sign_message(
                        &sks2[&Amount::from_units(o.amount)],
                        &o.blind_nonce.0,
                    )
                    .to_string(),
                })
                .collect(),
            keysets,
            issued_units: 9,
            fee_units: 0,
            read_prepaid_units: 0,
            write_prepaid_units: 0,
            kept_cents: 4,
            given_cents: 0,
        };
        match w.apply_reconcile(&built.id, &response).unwrap() {
            Applied::Settled(s) => assert_eq!((s.units, s.credit), (9, true)),
            other => panic!("{other:?}"),
        }
        assert_eq!(w.balance().psp, 5 + 9);
        assert!(w.open_replies().is_empty());
        assert_eq!(w.pending_psp_credit(100).balance_line(), None);
        assert!(w.air_requests().is_empty());
        assert!(w.data().reconciled.contains(&built.id));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_bad_answer_is_a_mint_error_that_stores_nothing_and_keeps_the_key() {
        let (mut w, dir) = wallet("bad-answer");
        let mint = DidSecretKey::new();
        let id = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 20, 1_000));
        let (sks, pks) = psp_keys();
        w.build_reconcile(&id, &keysets_of(&pks), 100).unwrap();
        let good = answer(&w, &id, &sks, &pks);
        let before = state(&w);

        let mut variants: Vec<(&str, ReconcileResponse)> = Vec::new();
        let mut r = good.clone();
        r.keyset = "0000000000000000".into();
        variants.push(("keyset", r));
        let mut r = good.clone();
        r.keysets.keysets.get_mut(&good.keyset).unwrap().insert(
            1,
            SecretKey::new(&mut rand::rngs::OsRng).public_key(SECP256K1),
        );
        variants.push(("keys that do not hash to the id", r));
        let mut r = good.clone();
        r.signatures.pop();
        variants.push(("signature count", r));
        let mut r = good.clone();
        r.signatures.push(r.signatures[0].clone());
        variants.push(("one signature too many", r));
        let mut r = good.clone();
        r.signatures.swap(0, 2);
        variants.push(("signatures out of order", r));
        let mut r = good.clone();
        r.issued_units = 19;
        variants.push(("issued units", r));
        let mut r = good.clone();
        r.signatures[1].signature = "zz".into();
        variants.push(("not a point", r));
        for (what, response) in variants {
            let e = expect::mint(w.apply_reconcile(&id, &response));
            assert!(
                e.contains("Nothing was stored and the key is kept"),
                "{what}: {e}"
            );
            assert_eq!(state(&w), before, "{what}: nothing changed");
        }
        assert_eq!(w.balance().psp, 0);
        // the right answer still settles it afterwards
        assert!(matches!(
            w.apply_reconcile(&id, &good).unwrap(),
            Applied::Settled(_)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_answer_to_a_payment_with_no_saved_request_is_refused() {
        let (mut w, dir) = wallet("no-request");
        let mint = DidSecretKey::new();
        let id = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 1_000));
        let (sks, pks) = psp_keys();
        let other = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 1_000));
        w.build_reconcile(&other, &keysets_of(&pks), 100).unwrap();
        let response = answer(&w, &other, &sks, &pks);
        let before = state(&w);
        let e = expect::unknown(w.apply_reconcile(&id, &response));
        assert!(e.contains("no reconciliation request was built"), "{e}");
        assert_eq!(state(&w), before);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn open_payments_are_listed_with_where_each_stands() {
        let (mut w, dir) = wallet("listing");
        let mint = DidSecretKey::new();
        let (_, pks) = psp_keys();
        let due = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 1_000));
        let none = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 0, 1_000));
        let late = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 50));
        w.update(|d| {
            d.open_replies.push(OpenReply {
                id: "key-only".into(),
                delivery_id: "dd".repeat(32),
                mint_did_pubkey: "03".repeat(33),
                reply_secret: "ee".repeat(32),
                credit_cents: 0,
                unaccounted_units: 1,
                open_until: 1_000,
                rules: None,
                reconcile: ReconcileState::default(),
            });
            Ok(())
        })
        .unwrap();
        let states = |w: &Wallet, now: u64| -> Vec<(String, ReconcileStatus)> {
            w.open_reconciliations(now)
                .into_iter()
                .map(|o| (o.id, o.state))
                .collect()
        };
        // a key kept for outputs only has nothing to send, so it is not listed;
        // `late` is closed at 100
        assert_eq!(
            states(&w, 10),
            vec![
                (due.clone(), ReconcileStatus::Due),
                (none.clone(), ReconcileStatus::NothingDue),
                (late.clone(), ReconcileStatus::Due)
            ]
        );
        assert_eq!(states(&w, 100).len(), 2, "the closed window is not listed");

        w.build_reconcile(&due, &keysets_of(&pks), 10).unwrap();
        assert_eq!(states(&w, 10)[0], (due.clone(), ReconcileStatus::Sent));
        // one unanswered try is not yet "not accepted": a second request is allowed
        w.note_unanswered(&due, true).unwrap();
        assert_eq!(states(&w, 10)[0].1, ReconcileStatus::Sent);
        // the second request, built because the keyset is gone, is the last one
        let (_, pks2) = psp_keys();
        w.build_reconcile(&due, &keysets_of(&pks2), 10).unwrap();
        assert_eq!(states(&w, 10)[0].1, ReconcileStatus::Sent);
        w.note_unanswered(&due, true).unwrap();
        assert_eq!(states(&w, 10)[0].1, ReconcileStatus::Lost);
        let listed = &w.open_reconciliations(10)[0];
        assert_eq!((listed.attempts, listed.max_attempts), (2, 3));
        assert_eq!(
            (listed.paid_sats, listed.paid_cents, listed.open_until),
            (1_000, 10, 1_000)
        );
        assert_eq!(listed.due_units, 5);
        // answered again (a late reply, say): the mark is cleared
        w.note_unanswered(&due, false).unwrap();
        assert_eq!(states(&w, 10)[0].1, ReconcileStatus::Sent);
        // a mark that is as recorded writes nothing
        let version = w.version();
        w.note_unanswered(&due, false).unwrap();
        w.note_told_lost(&none).unwrap();
        let told = w.version();
        assert_eq!(told, version + 1);
        w.note_told_lost(&none).unwrap();
        assert_eq!(w.version(), told);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_same_record_keeps_the_request_built_for_it_and_another_record_drops_it() {
        let (mut w, dir) = wallet("same-record");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let first = held(5_000);
        w.apply_delivery(&built.id, &first).unwrap();
        let (_, pks) = psp_keys();
        let request = w
            .build_reconcile(&built.id, &keysets_of(&pks), 100)
            .unwrap();

        // the PSP's record read again: nothing changes, the request stays
        let version = w.version();
        assert_eq!(
            w.apply_delivery(&built.id, &first).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(w.version(), version);
        assert_eq!(saved_of(&w, &built.id).request.unwrap().hash, request.hash);

        // another record with the same rules replaces the words and keeps it
        let Outcome::Held(mut again) = held(5_000) else {
            unreachable!()
        };
        again.reason = "still short".into();
        w.apply_delivery(&built.id, &Outcome::Held(again)).unwrap();
        assert_eq!(saved_of(&w, &built.id).request.unwrap().hash, request.hash);
        assert_eq!(w.air_requests().len(), 1);

        // a record with other rules: the request was built for rules that are
        // gone, so it and its AIR request are dropped
        let Outcome::Held(mut changed) = held(5_000) else {
            unreachable!()
        };
        changed.rules = Some(rules(SEND_CORRECTED_REQUEST, 6, 5_000));
        w.apply_delivery(&built.id, &Outcome::Held(changed))
            .unwrap();
        assert_eq!(saved_of(&w, &built.id), ReconcileState::default());
        assert!(w.air_requests().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_closed_window_says_plainly_that_the_funds_are_lost_with_the_amount() {
        let (mut w, dir) = wallet("lost-words");
        let mint = DidSecretKey::new();
        let id = open_held(&mut w, &mint, rules(SEND_CORRECTED_REQUEST, 5, 1_000));
        let (_, pks) = psp_keys();
        w.build_reconcile(&id, &keysets_of(&pks), 10).unwrap();
        let key = w.pending_purchases()[0].reply_secret.clone();
        // and a credit that was never claimed
        let built = w.build_psp_payload(&[4, 1], &mint.public_key()).unwrap();
        let (sks, pks) = psp_keys();
        // the PSP signs this purchase's outputs only, not the held purchase's
        let sigs: Vec<_> = sign_all(&w, &sks)
            .into_iter()
            .filter(|(nonce, _)| {
                w.pending_purchases()
                    .iter()
                    .filter(|p| p.id == built.id)
                    .flat_map(|p| &p.outputs)
                    .any(|o| o.blind_nonce == *nonce)
            })
            .collect();
        w.apply_delivery(&built.id, &windowed(record(&sigs, &pks, 0, 94), 2_000))
            .unwrap();

        let losses = w.close_expired(2_000).unwrap();
        assert_eq!(lost_ids(&losses), vec![id.clone(), built.id.clone()]);
        let held_text = losses[0].forfeited();
        for want in [
            "forfeited",
            "the funds are lost",
            "1000 sat, 0.10 USD",
            "1970-01-01 00:16 UTC",
            "key are deleted",
            &id,
        ] {
            assert!(held_text.contains(want), "{want}: {held_text}");
        }
        assert!(!held_text.contains("may"), "no hedging: {held_text}");
        let credit_text = losses[1].forfeited();
        for want in [
            "forfeited",
            "the funds are lost",
            "a credit of 0.94 USD",
            "1970-01-01 00:33 UTC",
            "key is deleted",
        ] {
            assert!(credit_text.contains(want), "{want}: {credit_text}");
        }
        // the keys, the saved request and its AIR request are gone
        assert!(w.pending_purchases().is_empty() && w.open_replies().is_empty());
        assert!(w.air_requests().iter().all(|a| a.r != key));
        assert!(w.air_requests().is_empty());
        assert!(w.open_reconciliations(0).is_empty());
        // and nothing is left to close
        let version = w.version();
        assert!(w.close_expired(u64::MAX - 1).unwrap().is_empty());
        assert_eq!(w.version(), version);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_words_for_a_payment_nothing_can_settle_say_the_funds_are_lost() {
        let loss = Loss {
            id: "ab".repeat(32),
            kind: LossKind::Rejected,
            paid_sats: 123_456,
            paid_cents: 994,
            credit_cents: 0,
            open_until: 951_782_400,
        };
        let nothing = loss.nothing_due();
        for want in [
            "the PSP's fees take the whole amount",
            "123456 sat, 9.94 USD",
            "2000-02-29 00:00 UTC",
            "no request is sent",
            "the funds are lost",
        ] {
            assert!(nothing.contains(want), "{want}: {nothing}");
        }
        let refused = loss.not_accepted(2);
        for want in [
            "the request was not accepted by the PSP",
            "after 2 attempt(s)",
            "123456 sat, 9.94 USD",
            "forfeited at 2000-02-29 00:00 UTC",
            "the funds are lost",
        ] {
            assert!(refused.contains(want), "{want}: {refused}");
        }
        let credit = Loss {
            kind: LossKind::Credit,
            credit_cents: 8,
            ..loss
        };
        assert!(credit.nothing_due().contains("a credit of 0.08 USD"));
    }
}
