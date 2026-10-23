//! The wallet's note file.
//!
//! One JSON file holds every note with its spend key, the requests that have
//! been sent and are waiting for the mint's reply, and the blinding factors they
//! need. It is a placeholder: moving the note store into the AIR is deferred.
//!
//! The file holds spend keys, so it is created with `0600` permissions. Every
//! change is written to a temporary file, fsynced and renamed over the old file,
//! and the directory is fsynced. A change is saved before the call that made it
//! returns, so a payload or request is never handed out before its blinding
//! factors are safely on disk. A missing file is an empty wallet. A file that
//! cannot be read is an error and is never replaced.
//!
//! The file records the network it is for (`network`: `main`, `regtest`, `signet`
//! or `testnet`), and [`Wallet::open`] takes the network it is opened for: a new
//! file is made with it, a file of another network is refused, and so is a file
//! that records none (written by a pre-release version; there is no
//! compatibility for it).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use mint_types::Note;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sp_wire::ServiceDid;
use sp_wire::air_request::delivery::ReconcileRules;
use sp_wire::esp::exchange::ExchangeRequest;

use crate::blind::PendingOutput;
use crate::error::WalletError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Primary Service Points, bought with BTC.
    Psp,
    /// Encumbered Service Points, bound to a service and a date.
    Esp,
    /// Fast Service Points, issued by a service.
    Fsp,
}

/// What an FSP note's service is called when it is not known.
pub const UNKNOWN_SERVICE: &str = "unknown";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTerms {
    pub service: ServiceDid,
    pub redeemable_after_day: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredNote {
    pub kind: Kind,
    pub amount: u64,
    pub note: Note,
    pub spend_secret: SecretKey,
    pub terms: Option<StoredTerms>,
    /// The id of the pending request that will spend this note, if any.
    pub reserved_by: Option<String>,
}

impl StoredNote {
    /// The note's id: its nonce, as hex.
    pub fn id(&self) -> String {
        hex::encode(self.note.nonce.0.serialize())
    }

    /// The service an FSP note belongs to: the service whose fsp-mint issued it.
    /// The wallet keeps it in `terms.service` (with day 0, which FSP does not
    /// use), filled in from the mint the note came from. It is not part of what
    /// the mint signs. `None` for a note of another kind, and for an FSP note
    /// whose service is not known; such a note is not spent until it is.
    pub fn fsp_service(&self) -> Option<ServiceDid> {
        if self.kind == Kind::Fsp {
            self.terms.map(|t| t.service)
        } else {
            None
        }
    }
}

/// A PSP purchase whose payload has been made and whose signatures have not
/// been claimed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingPurchase {
    /// SHA-256 of the sealed payload, as hex.
    pub id: String,
    /// The purchase's reply DID, as hex: the public half of `reply_secret`. It
    /// is in the payload, so the PSP knows it, and no other purchase has it.
    pub reply_did: String,
    pub mint_did_pubkey: String,
    pub outputs: Vec<PendingOutput>,
    /// The one-off secret key of the reply DID, as hex. The PSP seals the
    /// purchase's delivery record to the reply DID, and only this opens it. It is
    /// made for this purchase alone (the PSP cannot link two purchases of one
    /// wallet), saved here before the payload is returned, and deleted when the
    /// purchase is fully reconciled (see `Wallet::apply_delivery`). It is never
    /// part of a handoff: a purchase has no notes until it settles.
    pub reply_secret: String,
    /// What the PSP delivers this purchase under, as hex: the hash of the
    /// unsealed payload (`sp_wire::air_request::delivery::purchase_id`).
    pub delivery_id: String,
    /// Set when the PSP's record said the payment is held or was rejected: the
    /// purchase and its key stay until the PSP settles it or `open.open_until`
    /// passes ([`Wallet::close_expired`]). `None` while nothing has been
    /// delivered.
    #[serde(default)]
    pub open: Option<OpenPurchase>,
}

/// Why a paid purchase is still open, from the PSP's record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenKind {
    /// The payment is held: not settled yet (the amount paid does not match what
    /// was asked for, say).
    Held,
    /// The purchase was rejected and nothing was signed.
    Rejected,
}

/// What the PSP said about a purchase it did not sign (see [`OpenKind`]), and
/// until when it keeps the payment open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPurchase {
    pub kind: OpenKind,
    /// The PSP's reason.
    pub reason: String,
    /// What the PSP received, in satoshis and in USD cents at its price.
    pub paid_sats: u64,
    pub paid_cents: u64,
    /// For a held payment: the units the purchase asked for, and how far the
    /// payment is from covering them, in basis points (negative: short). 0 for a
    /// rejection.
    pub requested_units: u64,
    pub over_under_bps: i64,
    /// Unix seconds. If the payment is not settled by then the PSP forfeits it
    /// and keeps the bitcoin; the wallet deletes the purchase and its key.
    pub open_until: u64,
    /// The rules of the reconciliation, as the first record gave them and as the
    /// PSP will check a request against them (never against its current
    /// settings): what to send, the exact total it must carry, the deadline and
    /// the most requests the PSP counts. A record that is held or rejected and
    /// carries no rules is not stored (a mint error).
    pub rules: ReconcileRules,
    /// What the wallet has built and sent to settle it.
    pub reconcile: ReconcileState,
}

impl OpenPurchase {
    /// Whether `other` is the same record of the PSP: everything but what the
    /// wallet has done since (`reconcile`).
    pub(crate) fn same_record(&self, other: &OpenPurchase) -> bool {
        self.kind == other.kind
            && self.reason == other.reason
            && self.paid_sats == other.paid_sats
            && self.paid_cents == other.paid_cents
            && self.requested_units == other.requested_units
            && self.over_under_bps == other.over_under_bps
            && self.open_until == other.open_until
            && self.rules == other.rules
    }
}

/// What the wallet has done to settle one open payment (a held or rejected
/// purchase, or a credit): the request it built, how many it has built, and what
/// the user has been told. It is part of the payment's record, so a payment
/// that is closed (reconciled, or its window ended) takes it along, and a merge
/// carries it with the payment (see `merge.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileState {
    /// The request that was built, saved before it was first sent. `None` until
    /// one is built (and for a payment with nothing due, which is never sent).
    pub request: Option<SavedRequest>,
    /// How many requests the wallet has built for this payment. The PSP counts a
    /// request it refuses for its content, and accepts `rules.max_attempts` of
    /// them, so the wallet builds a second only for the keyset-rotation race and
    /// never more than the rules allow.
    pub attempts: u32,
    /// True when the last time the saved request was sent the PSP did not answer
    /// (every try of `air.attempts` passed with no reply). Cleared when a new
    /// request is built.
    pub unanswered: bool,
    /// True once the user was told that the payment is lost (nothing is due, or
    /// the PSP did not accept the request), so it is said once.
    pub told_lost: bool,
}

/// A reconciliation request as it was built and saved: the exact bytes that are
/// sent (a resend is these bytes, never a rebuilt request) and the blinding
/// factors of its outputs, which are the only copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedRequest {
    /// The request body as sent: the JSON of `sp_wire::psp::ReconcileRequest`,
    /// as hex.
    pub body: String,
    /// The request's hash (`ReconcileRequest::hash`): the key the PSP stores its
    /// answer and its counted refusals under.
    pub hash: String,
    /// The keyset the request names for its outputs.
    pub keyset: String,
    /// The request's outputs, with what is needed to unblind them.
    pub outputs: Vec<PendingOutput>,
}

/// How long the wallet keeps a purchase's key when the PSP's record names no
/// window for what is outstanding (outputs neither signed nor reported as
/// dropped): 14 days, the PSP's default reconciliation window.
pub const OPEN_KEY_FALLBACK_SECS: u64 = 14 * 24 * 3600;

/// The one-off key of a purchase that was claimed but may not be closed: the PSP
/// owes the payer a credit, or part of the purchase was neither signed nor
/// reported as dropped. A credit is claimed with a reconciliation request (AIR
/// kind 15) signed by this key, and the PSP's answer is sealed to it, so the key
/// is kept until the credit is claimed or `open_until` ([`Wallet::close_expired`]
/// deletes it then).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenReply {
    /// The purchase's id (`PendingPurchase::id`).
    pub id: String,
    pub delivery_id: String,
    pub mint_did_pubkey: String,
    pub reply_secret: String,
    /// What the PSP said it owes, in USD cents.
    pub credit_cents: u64,
    /// Requested units that were neither signed nor reported as dropped.
    pub unaccounted_units: u64,
    /// Unix seconds: when the PSP's window for the credit closes (from its
    /// record), or, for outputs only unaccounted for, when the wallet gives up
    /// ([`OPEN_KEY_FALLBACK_SECS`] after the record was applied).
    pub open_until: u64,
    /// The rules of the credit claim, from the record that said a credit is owed.
    /// `Some` for every credit (a record that owes one and carries no rules is
    /// not stored). `None` for a key kept only because some outputs were neither
    /// signed nor reported as dropped: the PSP gave no rules for it, so there is
    /// nothing to send.
    pub rules: Option<ReconcileRules>,
    /// What the wallet has built and sent to claim it.
    pub reconcile: ReconcileState,
}

/// An ESP exchange that has been built and has not been finished.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingExchange {
    /// The request hash, as the mint stores it.
    pub id: String,
    pub service: ServiceDid,
    pub input_ids: Vec<String>,
    pub outputs: Vec<PendingOutput>,
    /// Kept so that a retry sends exactly the same request.
    pub request: ExchangeRequest,
    /// ESP units among the outputs that are change (see `esp.rs`).
    pub change_esp: u128,
}

/// ESP notes handed to a service, with each note's spend secret, so whoever holds
/// it holds the notes. The type is sp-wire's (`sp_wire::esp::handover`), the one
/// fsp-mint's `export-esp` writes and `Handover::read` parses; the wallet makes
/// one when `fsp issue` hands ESP to an FSP mint (it keeps it in `handovers` as a
/// record) and takes one in with `receive_handover` (see `transfer.rs`). The notes
/// name the service, and only the service can ask the mint to move them or redeem
/// them.
pub use sp_wire::esp::handover::{HandedNote, Handover};

/// A request sent over AIR and not yet answered (see `air.rs`). The
/// wallet keeps the pair that can read the reply, `request_id` and the one-off
/// key `r`, until the request ends, so that a reply that came while the wallet
/// was not looking can still be read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAirRequest {
    /// What was asked: the request kind byte (1 mint info, 2 keys, 3 keysets,
    /// 4 rotation).
    pub kind: u8,
    /// 32 random bytes, hex.
    pub request_id: String,
    /// The mint's DID the request was written for, hex.
    pub mint: String,
    /// The one-off secret key `r`, hex. Used for this request only.
    pub r: String,
    /// The mailbox slots the request was written to, in order.
    pub slots: Vec<u32>,
    /// When the request was made, unix seconds.
    pub created_at: u64,
    /// For a request with a body (5 rollover, 6 check-state): the SHA-256 of the
    /// body, hex, so that the same call resumes it and another call, with another
    /// body, does not. Empty for the plain reads.
    pub body_hash: String,
}

/// How long a request over AIR is kept in the wallet file if it never ends (the
/// mint did not answer, and the call that made it was never repeated: say a
/// rollover that was cancelled meanwhile). After that it is dropped the next
/// time one is saved. A call that is repeated later just makes a new request,
/// which the mint answers the same way.
pub const AIR_REQUEST_KEEP_SECS: u64 = 30 * 24 * 3600;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalletData {
    /// The network this wallet file is for: `main`, `regtest`, `signet` or
    /// `testnet` (the names of the per-network folders). Required: a file
    /// without it is refused when opened (see [`Wallet::open`]), and a snapshot of
    /// another network is refused by a merge.
    pub network: String,
    pub notes: Vec<StoredNote>,
    pub pending_purchases: Vec<PendingPurchase>,
    /// The one-off keys of PSP purchases that were claimed but may still be open.
    pub open_replies: Vec<OpenReply>,
    pub pending_exchanges: Vec<PendingExchange>,
    /// What this wallet has handed to services, kept as a record. The notes in
    /// it are no longer in `notes`.
    pub handovers: Vec<Handover>,
    /// PSP notes the ESP mint reported spent by a different request. They are
    /// no longer in `notes`, are not counted in the balance and cannot be spent.
    /// Kept as a record.
    pub spent: Vec<StoredNote>,
    /// ESP redemptions that have been built and are not over (see `redeem.rs`).
    pub pending_redemptions: Vec<crate::redeem::PendingRedemption>,
    /// Ids of notes the ESP mint rejected for a bad proof. They stay in `notes`
    /// and in the balance, but a redemption does not pick them.
    pub bad_proof: Vec<String>,
    /// The keyset of each FSP note, by note id.
    pub fsp_keysets: BTreeMap<String, String>,
    /// The FSP mints this wallet has used, by service (hex), as last seen.
    pub fsp_mints: BTreeMap<String, crate::fsp::FspMint>,
    /// FSP requests sent or about to be sent and not settled.
    pub pending_fsp: Vec<crate::fsp::PendingFsp>,
    /// FSP notes whose keyset the mint deleted. Not in any total.
    pub lost_fsp: Vec<StoredNote>,
    /// The key-set epoch of each PSP and ESP note, by note id. A note with no
    /// entry is treated as on the oldest live set (see `rotate.rs`).
    pub epochs: BTreeMap<String, u64>,
    /// The keyset ID of each PSP and ESP note, by note id: the keyset that
    /// signed it, from the keys it was unblinded with or the mint's reply.
    /// Every request that spends a note names this keyset.
    pub keysets: BTreeMap<String, String>,
    /// Each PSP and ESP mint's live keysets as last seen, by the service's DID
    /// in lowercase hex: (current, previous). Refreshed on every connection.
    pub live_keysets: BTreeMap<String, (String, Option<String>)>,
    /// The ESP mint's live keysets as last seen, by its DID in lowercase hex:
    /// (current, previous), from the keysets and rotation calls. Kept apart from
    /// `live_keysets` so the PSP fallback there still sees one mint.
    pub esp_live_keysets: BTreeMap<String, (String, Option<String>)>,
    /// The time each pending rollover may be sent, by
    /// `<kind>|<mint record>|<new keyset id>` (the record is the PSP's or the ESP's
    /// name in the wallet's records, or the service's DID in hex for an FSP mint).
    /// Removed in the same write that
    /// records the rolled-over notes, and when the old set retires. No
    /// history is kept.
    pub swap_schedule: BTreeMap<String, u64>,
    /// PSP and ESP rollovers sent or about to be sent and not settled.
    pub pending_rollovers: Vec<crate::rotate::PendingRollover>,
    /// PSP and ESP notes whose key set the mint deleted. Not in any total.
    pub lost: Vec<StoredNote>,
    /// Counts the writes. It goes up by one every time the wallet saves, so of
    /// two copies of one wallet the one with the higher number has been written
    /// to more. [`crate::merge`] uses it for the merged copy's number only;
    /// what is kept comes from the ledgers below, not from this.
    pub version: u64,
    /// For each note that has left `notes`, how many times it has (spent,
    /// swapped away, handed off, lost, ...). Kept so that a copy of the wallet
    /// retrieved from storage cannot bring back a note this copy has spent. A
    /// note that comes back (a cancelled handoff) is counted in `returned`.
    /// Maintained by `update`; nothing else writes it. About 70 bytes a note.
    pub departed: BTreeMap<String, u32>,
    /// For each note that has come back into `notes` after leaving it, the
    /// number of times it had left when it came back. A note is spent, as far as
    /// the wallet knows, when `departed` is above `returned`.
    pub returned: BTreeMap<String, u32>,
    /// Ids of requests that have ended (finished, cancelled or refused), so that
    /// a copy retrieved from storage cannot bring them back as pending.
    pub finished: BTreeSet<String>,
    /// Notes this wallet has handed off to another wallet (see `handoff.rs`).
    pub handoffs_out: Vec<crate::handoff::OutgoingHandoff>,
    /// Handoffs this wallet has imported, so that none is imported twice.
    pub handoffs_in: Vec<crate::handoff::IncomingHandoff>,
    /// Requests over AIR that have not ended (see `air.rs`). Local to
    /// this copy of the wallet: a merge keeps this copy's.
    pub air_requests: Vec<PendingAirRequest>,
    /// Ids of PSP purchases whose reconciliation is done (the corrected request
    /// or the credit claim was answered and its notes stored). A purchase that is
    /// claimed with a credit owed is `finished` already while its key is kept, so
    /// `finished` cannot say that the credit was claimed; this does, and a copy
    /// retrieved from storage cannot bring back an open payment, or a credit,
    /// that either copy has reconciled (see `merge.rs`).
    pub reconciled: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub psp: u128,
    pub esp: u128,
    pub fsp: u128,
    /// FSP units by service (hex), the service each note belongs to. Notes
    /// whose service is not known are under [`UNKNOWN_SERVICE`].
    pub fsp_by_service: BTreeMap<String, u128>,
    /// ESP units by service (hex) and redeemable-after day.
    pub esp_by_terms: BTreeMap<(String, u64), u128>,
    pub notes: usize,
    /// Of `psp` above, the units received in a PSP handoff that the mint has
    /// not swapped yet. They are counted in `psp` and can be spent; the swap is
    /// sent again on every connection to the mint.
    pub unswapped_psp: u128,
    /// Notes held back for a pending request.
    pub reserved: usize,
    pub pending_purchases: usize,
    pub pending_exchanges: usize,
    /// Redemptions built and not over, including ones queued for payout.
    pub pending_redemptions: usize,
    /// Handovers this wallet has made.
    pub handed_over: usize,
    /// Notes marked spent because they were spent elsewhere. Not in any total.
    pub spent_elsewhere: usize,
    /// Notes flagged because the mint found their proof bad, and their value.
    /// Still counted in `esp` above.
    pub bad_proof: usize,
    pub bad_proof_esp: u128,
}

/// What the ESP mint accepts in one exchange (`exchange.max_items`), as its
/// fees reply says. The wallet does not
/// keep a number of its own: until the limits are read (`mint_info::sync_esp_limits`)
/// it checks nothing locally and the mint's own refusal decides. Not saved in
/// the wallet file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EspLimits {
    pub exchange_max_items: Option<usize>,
}

pub struct Wallet {
    path: PathBuf,
    data: WalletData,
    limits: EspLimits,
    /// The PSP's largest note size, once read from its `GET /keys`. Not saved.
    psp_top: Option<u64>,
    /// The smallest purchase the wallet will build, in PSP units
    /// (`psp.min_purchase`). Not saved: it is a setting, given by the caller.
    psp_min: u64,
}

/// Read a wallet file's bytes (`what` names the file in messages). A file that
/// records no network is refused with a message of its own, before anything else
/// is read from it, because serde's missing-field message would say nothing
/// about what to do.
pub(crate) fn parse_wallet(bytes: &[u8], what: &str) -> Result<WalletData, WalletError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| WalletError::Corrupt(format!("{what}: {e}")))?;
    if value
        .as_object()
        .is_some_and(|o| !o.contains_key("network"))
    {
        return Err(WalletError::Corrupt(format!(
            "{what}: it records no network. It was written by a pre-release version of the wallet, which this version cannot read (there is no compatibility for it). Start a new wallet file, or merge from a backup written by this version"
        )));
    }
    serde_json::from_value(value).map_err(|e| WalletError::Corrupt(format!("{what}: {e}")))
}

impl Wallet {
    /// Open the wallet at `path`, for `network` (`main`, `regtest`, `signet` or
    /// `testnet`). A missing file is an empty wallet of that network. The file
    /// records its network and is refused if it is another one, or if it records
    /// none (a file from a pre-release version): nothing is read into the wallet
    /// and the file is not touched.
    pub fn open(path: &Path, network: &str) -> Result<Self, WalletError> {
        let data: WalletData = match fs::read(path) {
            Ok(bytes) => {
                let data = parse_wallet(&bytes, &path.display().to_string())?;
                if data.network != network {
                    return Err(WalletError::Invalid(format!(
                        "{}: this wallet file is for the {} network, but it was opened for the {network} network. Nothing was changed. Use a wallet file made for the {network} network",
                        path.display(),
                        data.network
                    )));
                }
                data
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => WalletData {
                network: network.to_string(),
                ..WalletData::default()
            },
            Err(e) => return Err(e.into()),
        };
        Ok(Wallet {
            path: path.to_path_buf(),
            data,
            limits: EspLimits::default(),
            psp_top: None,
            psp_min: crate::psp::DEFAULT_MIN_PURCHASE,
        })
    }

    /// The ESP mint's note limits, if they have been read.
    pub fn esp_limits(&self) -> EspLimits {
        self.limits
    }

    /// Set the ESP mint's note limits (see [`EspLimits`]).
    pub fn set_esp_limits(&mut self, limits: EspLimits) {
        self.limits = limits;
    }

    /// The PSP's largest note size, if it has been read (see
    /// `mint_info::sync_psp_limits`). The wallet keeps no number of its own: until
    /// it is read, a purchase is checked only for being a power of two and the
    /// PSP decides the top.
    pub fn psp_max_denomination(&self) -> Option<u64> {
        self.psp_top
    }

    /// Set the PSP's largest note size.
    pub fn set_psp_max_denomination(&mut self, top: Option<u64>) {
        self.psp_top = top;
    }

    /// The smallest purchase this wallet will build, in PSP units: the default
    /// ([`crate::psp::DEFAULT_MIN_PURCHASE`]) until [`Wallet::set_psp_min_purchase`].
    pub fn psp_min_purchase(&self) -> u64 {
        self.psp_min
    }

    /// Set the smallest purchase the wallet will build (`psp.min_purchase`), in
    /// PSP units, 1 or more. This is the wallet refusing to build a payload that
    /// the PSP's fees could eat whole; the PSP itself is unchanged. The setting
    /// is not saved in the wallet file: the caller gives it every run.
    pub fn set_psp_min_purchase(&mut self, units: u64) -> Result<(), WalletError> {
        if units == 0 {
            return Err(WalletError::Invalid(
                "psp.min_purchase must be 1 or more PSP units".into(),
            ));
        }
        self.psp_min = units;
        Ok(())
    }

    pub(crate) fn data(&self) -> &WalletData {
        &self.data
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn notes(&self) -> &[StoredNote] {
        &self.data.notes
    }

    pub fn pending_purchases(&self) -> &[PendingPurchase] {
        &self.data.pending_purchases
    }

    /// The keys kept for PSP purchases that may still be open.
    pub fn open_replies(&self) -> &[OpenReply] {
        &self.data.open_replies
    }

    pub fn pending_exchanges(&self) -> &[PendingExchange] {
        &self.data.pending_exchanges
    }

    pub(crate) fn redemptions(&self) -> &[crate::redeem::PendingRedemption] {
        &self.data.pending_redemptions
    }

    /// Notes marked spent because the mint said they were spent by a different
    /// request. Not part of the balance.
    pub fn spent_notes(&self) -> &[StoredNote] {
        &self.data.spent
    }

    /// Ids of the notes flagged because the ESP mint rejected their proof.
    pub fn bad_proof_notes(&self) -> &[String] {
        &self.data.bad_proof
    }

    /// The requests over AIR that have not ended, oldest first.
    pub fn air_requests(&self) -> &[PendingAirRequest] {
        &self.data.air_requests
    }

    /// Keep a request over AIR (new, or with more slots than before) and save.
    pub(crate) fn save_air_request(
        &mut self,
        request: PendingAirRequest,
    ) -> Result<(), WalletError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.update(|d| {
            match d
                .air_requests
                .iter_mut()
                .find(|r| r.request_id == request.request_id)
            {
                Some(kept) => *kept = request,
                None => d.air_requests.push(request),
            }
            d.air_requests
                .retain(|r| r.created_at.saturating_add(AIR_REQUEST_KEEP_SECS) >= now);
            Ok(())
        })
    }

    /// Forget a request over AIR that has ended (answered, or refused for good).
    pub(crate) fn end_air_request(&mut self, request_id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            d.air_requests.retain(|r| r.request_id != request_id);
            Ok(())
        })
    }

    /// The handovers this wallet has made, oldest first.
    pub fn handovers(&self) -> &[Handover] {
        &self.data.handovers
    }

    /// Apply a change and save it. The change is made on a copy and only takes
    /// effect if the save succeeds, so memory never runs ahead of the file.
    pub(crate) fn update<T>(
        &mut self,
        change: impl FnOnce(&mut WalletData) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let mut next = self.data.clone();
        let out = change(&mut next)?;
        track(&self.data, &mut next);
        next.version = self.data.version.max(next.version) + 1;
        write_atomic(&self.path, &next)?;
        self.data = next;
        Ok(out)
    }

    /// Replace the whole wallet with `next` and save it, as the merge does. The
    /// ledgers are not touched: `next` already holds the merged ones.
    pub(crate) fn replace(&mut self, mut next: WalletData) -> Result<(), WalletError> {
        next.version = self.data.version.max(next.version) + 1;
        write_atomic(&self.path, &next)?;
        self.data = next;
        Ok(())
    }

    /// A copy of everything the wallet holds, as it would be saved. For handing
    /// to storage; `merge_from` takes one back.
    pub fn snapshot(&self) -> WalletData {
        self.data.clone()
    }

    /// The write counter (see [`WalletData::version`]).
    pub fn version(&self) -> u64 {
        self.data.version
    }

    pub fn balance(&self) -> Balance {
        let mut b = Balance::default();
        for n in &self.data.notes {
            b.notes += 1;
            if n.reserved_by.is_some() {
                b.reserved += 1;
            }
            let units = u128::from(n.amount);
            match n.kind {
                Kind::Psp => b.psp += units,
                Kind::Fsp => {
                    b.fsp += units;
                    let service = n
                        .fsp_service()
                        .map(|k| hex::encode(k.serialize()))
                        .unwrap_or_else(|| UNKNOWN_SERVICE.to_string());
                    *b.fsp_by_service.entry(service).or_default() += units;
                }
                Kind::Esp => {
                    b.esp += units;
                    if let Some(t) = &n.terms {
                        *b.esp_by_terms
                            .entry((hex::encode(t.service.serialize()), t.redeemable_after_day))
                            .or_default() += units;
                    }
                }
            }
        }
        b.unswapped_psp = self.unswapped_psp();
        b.pending_purchases = self.data.pending_purchases.len();
        b.pending_exchanges = self.data.pending_exchanges.len();
        b.pending_redemptions = self.data.pending_redemptions.len();
        b.handed_over = self.data.handovers.len();
        b.spent_elsewhere = self.data.spent.len();
        for n in self
            .data
            .notes
            .iter()
            .filter(|n| self.data.bad_proof.contains(&n.id()))
        {
            b.bad_proof += 1;
            b.bad_proof_esp += u128::from(n.amount);
        }
        b
    }
}

/// The ids of the requests a wallet is waiting on, of every kind.
fn pending_ids(d: &WalletData) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    ids.extend(d.pending_purchases.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_exchanges.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_redemptions.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_fsp.iter().map(|p| p.id.clone()));
    ids.extend(d.pending_rollovers.iter().map(|p| p.id.clone()));
    ids.extend(
        d.handoffs_out
            .iter()
            .filter(|h| h.state == crate::handoff::HandoffState::Pending)
            .map(|h| h.id.clone()),
    );
    ids
}

/// Keep the ledgers of a change that `update` is about to save: a note that is
/// no longer in `notes` has departed, a note that is back has returned, a
/// request that is no longer pending has finished and one that is again is not.
fn track(before: &WalletData, after: &mut WalletData) {
    let was: BTreeSet<String> = before.notes.iter().map(StoredNote::id).collect();
    let is: BTreeSet<String> = after.notes.iter().map(StoredNote::id).collect();
    for id in was.difference(&is) {
        *after.departed.entry(id.clone()).or_default() += 1;
    }
    for id in is.difference(&was) {
        if let Some(&left) = after.departed.get(id) {
            if after.returned.get(id).copied().unwrap_or(0) < left {
                after.returned.insert(id.clone(), left);
            }
        }
    }
    let was = pending_ids(before);
    let is = pending_ids(after);
    for id in was.difference(&is) {
        after.finished.insert(id.clone());
    }
    for id in is.difference(&was) {
        after.finished.remove(id);
    }
}

/// Whether the ledgers say the note has left the wallet and not come back.
pub(crate) fn has_departed(d: &WalletData, id: &str) -> bool {
    d.departed.get(id).copied().unwrap_or(0) > d.returned.get(id).copied().unwrap_or(0)
}

fn write_atomic(path: &Path, data: &WalletData) -> Result<(), WalletError> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir)?;
        }
    }
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(data)
        .map_err(|e| WalletError::Corrupt(format!("could not write the wallet: {e}")))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    // Make the rename itself durable. Not every platform allows opening a
    // directory, so a failure here is ignored.
    if let Some(dir) = path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::PendingOutput;
    use secp256k1::SECP256K1;

    /// Open a wallet file of the test network.
    fn open_wallet(path: &std::path::Path) -> Result<crate::Wallet, crate::WalletError> {
        crate::Wallet::open(path, "regtest")
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-{}-{name}", {
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

    fn some_note(kind: Kind, amount: u64) -> StoredNote {
        let out = PendingOutput::new(amount);
        let sk = SecretKey::new(&mut rand::rngs::OsRng);
        let sig = bdhke::sign_message(&sk, &out.blind_nonce.0);
        StoredNote {
            kind,
            amount,
            note: out.unblind(&sig, &sk.public_key(SECP256K1)),
            spend_secret: out.nonce_secret,
            terms: None,
            reserved_by: None,
        }
    }

    #[test]
    fn a_missing_file_is_an_empty_wallet_and_changes_survive_a_reopen() {
        let dir = scratch("reopen");
        let path = dir.join("w").join("wallet.json");
        let mut w = open_wallet(&path).unwrap();
        assert!(w.notes().is_empty());
        assert_eq!(w.snapshot().network, "regtest");
        let note = some_note(Kind::Psp, 4);
        let id = note.id();
        w.update(|d| {
            d.notes.push(note);
            Ok(())
        })
        .unwrap();
        let again = open_wallet(&path).unwrap();
        assert_eq!(again.notes().len(), 1);
        assert_eq!(again.notes()[0].id(), id);
        assert_eq!(again.balance().psp, 4);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_with_no_network_is_refused_on_open_and_left_alone() {
        let dir = scratch("no-network");
        let path = dir.join("wallet.json");
        // A real wallet file, as this version writes it, with the network taken
        // out: what a pre-release version left.
        let mut w = open_wallet(&path).unwrap();
        w.update(|d| {
            d.notes.push(some_note(Kind::Psp, 4));
            Ok(())
        })
        .unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("network")
            .expect("the file records its network");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let before = fs::read(&path).unwrap();

        match open_wallet(&path) {
            Err(WalletError::Corrupt(why)) => {
                assert!(why.contains(&path.display().to_string()), "{why}");
                assert!(why.contains("it records no network"), "{why}");
                assert!(why.contains("pre-release version"), "{why}");
                assert!(
                    why.contains(
                        "Start a new wallet file, or merge from a backup written by this version"
                    ),
                    "{why}"
                );
            }
            other => panic!(
                "expected the file to be refused, got {:?}",
                other.map(|_| ())
            ),
        }
        assert_eq!(fs::read(&path).unwrap(), before, "the file is left alone");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_file_of_another_network_is_refused_on_open_and_left_alone() {
        let dir = scratch("other-network");
        let path = dir.join("wallet.json");
        let mut w = Wallet::open(&path, "signet").unwrap();
        assert_eq!(w.snapshot().network, "signet", "a new file has the network");
        w.update(|d| {
            d.notes.push(some_note(Kind::Psp, 4));
            Ok(())
        })
        .unwrap();
        let before = fs::read(&path).unwrap();

        match open_wallet(&path) {
            Err(WalletError::Invalid(why)) => {
                assert!(why.contains(&path.display().to_string()), "{why}");
                assert!(
                    why.contains(
                        "this wallet file is for the signet network, but it was opened for the regtest network"
                    ),
                    "{why}"
                );
                assert!(why.contains("Nothing was changed"), "{why}");
            }
            other => panic!(
                "expected the file to be refused, got {:?}",
                other.map(|_| ())
            ),
        }
        assert_eq!(fs::read(&path).unwrap(), before, "the file is left alone");
        // Its own network opens it, with the note.
        let again = Wallet::open(&path, "signet").unwrap();
        assert_eq!(again.balance().psp, 4);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_is_an_error_and_is_left_alone() {
        let dir = scratch("damaged");
        let path = dir.join("wallet.json");
        fs::write(&path, "not json").unwrap();
        assert!(matches!(open_wallet(&path), Err(WalletError::Corrupt(_))));
        assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_and_leaves_no_temporary_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let path = dir.join("wallet.json");
        let mut w = open_wallet(&path).unwrap();
        w.update(|_| Ok(())).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!dir.join("wallet.json.tmp").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_change_leaves_the_wallet_as_it_was() {
        let dir = scratch("failed");
        let path = dir.join("wallet.json");
        let mut w = open_wallet(&path).unwrap();
        let result: Result<(), WalletError> = w.update(|d| {
            d.notes.push(some_note(Kind::Psp, 1));
            Err(WalletError::Invalid("no".into()))
        });
        assert!(result.is_err());
        assert!(w.notes().is_empty());
        assert!(!path.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_balance_adds_up_by_kind_and_by_esp_terms() {
        let dir = scratch("balance");
        let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
        let service =
            ServiceDid::parse("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let mut esp = some_note(Kind::Esp, 3_000_000_000_000);
        esp.terms = Some(StoredTerms {
            service,
            redeemable_after_day: 21_100,
        });
        let mut reserved = some_note(Kind::Psp, 2);
        reserved.reserved_by = Some("x".into());
        w.update(|d| {
            d.notes.push(some_note(Kind::Psp, 4));
            d.notes.push(reserved);
            d.notes.push(esp);
            d.notes.push(some_note(Kind::Fsp, 9));
            Ok(())
        })
        .unwrap();
        let b = w.balance();
        assert_eq!((b.psp, b.esp, b.fsp), (6, 3_000_000_000_000, 9));
        assert_eq!(b.notes, 4);
        assert_eq!(b.reserved, 1);
        assert_eq!(
            b.esp_by_terms[&(hex::encode(service.serialize()), 21_100)],
            3_000_000_000_000
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sums_do_not_overflow_at_the_u64_limit() {
        let dir = scratch("limit");
        let mut w = open_wallet(&dir.join("wallet.json")).unwrap();
        w.update(|d| {
            d.notes.push(some_note(Kind::Esp, u64::MAX));
            d.notes.push(some_note(Kind::Esp, u64::MAX));
            Ok(())
        })
        .unwrap();
        assert_eq!(w.balance().esp, 2 * u128::from(u64::MAX));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_snapshot_is_what_is_saved_and_a_copy() {
        let dir = scratch("snapshot");
        let path = dir.join("wallet.json");
        let mut w = open_wallet(&path).unwrap();
        w.update(|d| {
            d.notes.push(some_note(Kind::Psp, 4));
            d.notes.push(some_note(Kind::Fsp, 9));
            Ok(())
        })
        .unwrap();
        let json = |d: &WalletData| serde_json::to_value(d).unwrap();
        let taken = w.snapshot();
        // it is what is saved: the file read back as WalletData, and the wallet
        // reopened from it
        let saved: WalletData = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let reopened = open_wallet(&path).unwrap();
        assert_eq!(json(&taken), json(&saved));
        assert_eq!(json(&taken), json(&reopened.snapshot()));
        // it is a copy: changing the wallet afterwards leaves it as it was
        let frozen = json(&taken);
        w.update(|d| {
            d.notes.push(some_note(Kind::Psp, 2));
            Ok(())
        })
        .unwrap();
        assert_eq!(json(&taken), frozen);
        assert_eq!(taken.notes.len(), 2);
        assert_eq!(w.snapshot().notes.len(), 3);
        // merging it into a fresh wallet gives the same balance
        let mut fresh = open_wallet(&dir.join("fresh.json")).unwrap();
        fresh.merge_from(&taken).unwrap();
        assert_eq!(fresh.balance(), reopened.balance());
        assert_eq!((fresh.balance().psp, fresh.balance().fsp), (4, 9));
        fs::remove_dir_all(&dir).unwrap();
    }
}
