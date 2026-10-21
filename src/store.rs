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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use mint_types::Note;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sp_wire::ServiceDid;
use sp_wire::esp::exchange::ExchangeRequest;
use sp_wire::esp::transfer::TransferRequest;

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
    /// part of a handoff: a purchase has no notes until it settles. `None` on a
    /// purchase made before purchases had their own key: nothing can be
    /// picked up for it.
    #[serde(default)]
    pub reply_secret: Option<String>,
    /// What the PSP delivers this purchase under, as hex: the hash of the
    /// unsealed payload (`sp_wire::air_request::delivery::purchase_id`). `None`
    /// exactly when `reply_secret` is.
    #[serde(default)]
    pub delivery_id: Option<String>,
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
    #[serde(default)]
    pub requested_units: u64,
    #[serde(default)]
    pub over_under_bps: i64,
    /// Unix seconds. If the payment is not settled by then the PSP forfeits it
    /// and keeps the bitcoin; the wallet deletes the purchase and its key.
    pub open_until: u64,
}

/// How long the wallet keeps a purchase's key when the PSP's record names no
/// window for what is outstanding (outputs neither signed nor reported as
/// dropped): the PSP's default reconciliation window.
pub const OPEN_KEY_FALLBACK_SECS: u64 = 7 * 24 * 3600;

/// The one-off key of a purchase that was claimed but may not be closed: the PSP
/// owes the payer a credit, or part of the purchase was neither signed nor
/// reported as dropped. The PSP will write a follow-up to the same key (its
/// address and shape are not designed yet), so the key is kept until `open_until`
/// ([`Wallet::close_expired`] deletes it then).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenReply {
    /// The purchase's id (`PendingPurchase::id`).
    pub id: String,
    pub delivery_id: String,
    pub mint_did_pubkey: String,
    pub reply_secret: String,
    /// What the PSP said it owes, in USD cents.
    #[serde(default)]
    pub credit_cents: u64,
    /// Requested units that were neither signed nor reported as dropped.
    #[serde(default)]
    pub unaccounted_units: u64,
    /// Unix seconds: when the PSP's window for the credit closes (from its
    /// record), or, for outputs only unaccounted for, when the wallet gives up
    /// ([`OPEN_KEY_FALLBACK_SECS`] after the record was applied). 0 in a file
    /// from before: [`Wallet::close_expired`] gives it the fallback.
    #[serde(default)]
    pub open_until: u64,
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
    #[serde(default)]
    pub change_esp: u128,
}

/// An ESP transfer that has been built and has not been finished. The wallet
/// that holds it is the service's.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTransfer {
    /// The request hash, as the mint stores it.
    pub id: String,
    pub service: ServiceDid,
    pub input_ids: Vec<String>,
    pub outputs: Vec<PendingOutput>,
    /// Kept so that a retry sends exactly the same request.
    pub request: TransferRequest,
}

/// One ESP note given to a service, with its spend secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandedNote {
    pub amount: u64,
    pub note: Note,
    pub spend_secret: SecretKey,
    /// The ESP keyset that signed it, so the receiver names it when it spends
    /// the note. Empty in a hand-over made before keysets.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyset: String,
}

/// ESP notes handed to a service, with each note's spend secret, so whoever holds
/// it holds the notes. The wallet makes one when `fsp issue` hands ESP to an FSP
/// mint (the wallet keeps it in `handovers` as a record), and fsp-mint's
/// `export-esp` writes the same shape to a file for the service's wallet to
/// `receive` (see `transfer.rs`). The notes name the service, and only the service
/// can ask the mint to move them or redeem them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handover {
    pub service: ServiceDid,
    pub redeemable_after_day: u64,
    pub notes: Vec<HandedNote>,
}

/// A request sent over AIR and not yet answered (see `air.rs`). The
/// wallet keeps the pair that can read the reply, `request_id` and the one-off
/// key `r`, until the request ends, so that a reply that came while the wallet
/// was not looking can still be read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAirRequest {
    /// What was asked: the request kind byte (1 mint info, 2 keys, 3 keysets,
    /// 4 rotation). A file from before the keys calls moved to AIR has none, and
    /// every request in it is mint info.
    #[serde(default = "mint_info_kind")]
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
    /// body, does not. Empty for the plain reads, and in a file from before.
    #[serde(default)]
    pub body_hash: String,
}

/// How long a request over AIR is kept in the wallet file if it never ends (the
/// mint did not answer, and the call that made it was never repeated: say a
/// rollover that was cancelled meanwhile). After that it is dropped the next
/// time one is saved. A call that is repeated later just makes a new request,
/// which the mint answers the same way.
pub const AIR_REQUEST_KEEP_SECS: u64 = 30 * 24 * 3600;

fn mint_info_kind() -> u8 {
    sp_wire::air_request::KIND_MINT_INFO
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalletData {
    #[serde(default)]
    pub notes: Vec<StoredNote>,
    #[serde(default)]
    pub pending_purchases: Vec<PendingPurchase>,
    /// The one-off keys of PSP purchases that were claimed but may still be open.
    #[serde(default)]
    pub open_replies: Vec<OpenReply>,
    #[serde(default)]
    pub pending_exchanges: Vec<PendingExchange>,
    #[serde(default)]
    pub pending_transfers: Vec<PendingTransfer>,
    /// What this wallet has handed to services, kept as a record. The notes in
    /// it are no longer in `notes`.
    #[serde(default)]
    pub handovers: Vec<Handover>,
    /// PSP tokens that `send-psp` exported (wallet 0.4.0 and earlier). Read
    /// only, to be migrated: [`WalletData::migrate_legacy`] turns each into a
    /// PSP handoff record when the file is opened, and nothing writes here any
    /// more (see `legacy.rs`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sent: Vec<crate::legacy::SentToken>,
    /// PSP notes the ESP mint reported spent by a different request. They are
    /// no longer in `notes`, are not counted in the balance and cannot be spent.
    /// Kept as a record.
    #[serde(default)]
    pub spent: Vec<StoredNote>,
    /// ESP redemptions that have been built and are not over (see `redeem.rs`).
    #[serde(default)]
    pub pending_redemptions: Vec<crate::redeem::PendingRedemption>,
    /// Ids of notes the ESP mint rejected for a bad proof. They stay in `notes`
    /// and in the balance, but a redemption does not pick them.
    #[serde(default)]
    pub bad_proof: Vec<String>,
    /// The keyset of each FSP note, by note id.
    #[serde(default)]
    pub fsp_keysets: BTreeMap<String, String>,
    /// The FSP mints this wallet has used, by service (hex), as last seen.
    #[serde(default)]
    pub fsp_mints: BTreeMap<String, crate::fsp::FspMint>,
    /// FSP requests sent or about to be sent and not settled.
    #[serde(default)]
    pub pending_fsp: Vec<crate::fsp::PendingFsp>,
    /// FSP notes whose keyset the mint deleted. Not in any total.
    #[serde(default)]
    pub lost_fsp: Vec<StoredNote>,
    /// The key-set epoch of each PSP and ESP note, by note id. A note with no
    /// entry is treated as on the oldest live set (see `rotate.rs`).
    #[serde(default)]
    pub epochs: BTreeMap<String, u64>,
    /// The keyset ID of each PSP and ESP note, by note id: the keyset that
    /// signed it, from the keys it was unblinded with or the mint's reply.
    /// Every request that spends a note names this keyset.
    #[serde(default)]
    pub keysets: BTreeMap<String, String>,
    /// Each PSP and ESP mint's live keysets as last seen, by URL:
    /// (current, previous). Refreshed on every connection.
    #[serde(default)]
    pub live_keysets: BTreeMap<String, (String, Option<String>)>,
    /// The ESP mint's live keysets as last seen, by URL: (current, previous),
    /// from `GET /keysets` or `/rotation`. Kept apart from `live_keysets` so
    /// the PSP fallback there still sees one mint.
    #[serde(default)]
    pub esp_live_keysets: BTreeMap<String, (String, Option<String>)>,
    /// The time each pending rollover may be sent, by
    /// `<kind>|<mint record>|<new keyset id>` (the record is the PSP's or the ESP's
    /// name in the wallet's records, or the service's DID in hex for an FSP mint).
    /// Removed in the same write that
    /// records the rolled-over notes, and when the old set retires. No
    /// history is kept.
    #[serde(default)]
    pub swap_schedule: BTreeMap<String, u64>,
    /// PSP and ESP rollovers sent or about to be sent and not settled.
    #[serde(default)]
    pub pending_rollovers: Vec<crate::rotate::PendingRollover>,
    /// PSP and ESP notes whose key set the mint deleted. Not in any total.
    #[serde(default)]
    pub lost: Vec<StoredNote>,
    /// Counts the writes. It goes up by one every time the wallet saves, so of
    /// two copies of one wallet the one with the higher number has been written
    /// to more. [`crate::merge`] uses it for the merged copy's number only;
    /// what is kept comes from the ledgers below, not from this.
    #[serde(default)]
    pub version: u64,
    /// For each note that has left `notes`, how many times it has (spent,
    /// swapped away, handed off, lost, ...). Kept so that a copy of the wallet
    /// retrieved from storage cannot bring back a note this copy has spent. A
    /// note that comes back (a cancelled handoff) is counted in `returned`.
    /// Maintained by `update`; nothing else writes it. About 70 bytes a note.
    #[serde(default)]
    pub departed: BTreeMap<String, u32>,
    /// For each note that has come back into `notes` after leaving it, the
    /// number of times it had left when it came back. A note is spent, as far as
    /// the wallet knows, when `departed` is above `returned`.
    #[serde(default)]
    pub returned: BTreeMap<String, u32>,
    /// Ids of requests that have ended (finished, cancelled or refused), so that
    /// a copy retrieved from storage cannot bring them back as pending.
    #[serde(default)]
    pub finished: BTreeSet<String>,
    /// Notes this wallet has handed off to another wallet (see `handoff.rs`).
    #[serde(default)]
    pub handoffs_out: Vec<crate::handoff::OutgoingHandoff>,
    /// Handoffs this wallet has imported, so that none is imported twice.
    #[serde(default)]
    pub handoffs_in: Vec<crate::handoff::IncomingHandoff>,
    /// Requests over AIR that have not ended (see `air.rs`). Local to
    /// this copy of the wallet: a merge keeps this copy's.
    #[serde(default)]
    pub air_requests: Vec<PendingAirRequest>,
}

impl WalletData {
    /// Turn the records `send-psp` left in `sent` into PSP handoff records, so
    /// that `handoff check` and `handoff reclaim` work on them (see
    /// `legacy.rs` for the mapping). A record whose id is already a handoff is
    /// dropped as a duplicate. Does nothing when `sent` is empty.
    pub fn migrate_legacy(&mut self) {
        for t in std::mem::take(&mut self.sent) {
            if self.handoffs_out.iter().any(|h| h.id == t.id) {
                continue;
            }
            self.handoffs_out.push(t.into_handoff());
        }
    }
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
    pub pending_transfers: usize,
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

/// What the ESP mint accepts in one exchange or transfer (`exchange.max_items`
/// and `transfer.max_items`), as its `GET /fees` says. The wallet does not
/// keep a number of its own: until the limits are read (`mint_info::sync_esp_limits`)
/// it checks nothing locally and the mint's own refusal decides. Not saved in
/// the wallet file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EspLimits {
    pub exchange_max_items: Option<usize>,
    pub transfer_max_items: Option<usize>,
}

pub struct Wallet {
    path: PathBuf,
    data: WalletData,
    limits: EspLimits,
    /// The PSP's largest note size, once read from its `GET /keys`. Not saved.
    psp_top: Option<u64>,
}

impl Wallet {
    /// Open the wallet at `path`. A missing file is an empty wallet.
    pub fn open(path: &Path) -> Result<Self, WalletError> {
        let mut data: WalletData = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| WalletError::Corrupt(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => WalletData::default(),
            Err(e) => return Err(e.into()),
        };
        // Records of the removed `send-psp` become PSP handoff records. This is
        // in memory; the file is rewritten without them at the next save.
        data.migrate_legacy();
        Ok(Wallet {
            path: path.to_path_buf(),
            data,
            limits: EspLimits::default(),
            psp_top: None,
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

    pub fn pending_transfers(&self) -> &[PendingTransfer] {
        &self.data.pending_transfers
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
        b.pending_transfers = self.data.pending_transfers.len();
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
    ids.extend(d.pending_transfers.iter().map(|p| p.id.clone()));
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

pub fn parse_did(text: &str) -> Result<[u8; 33], WalletError> {
    let bytes = hex::decode(text.trim())
        .map_err(|_| WalletError::Invalid("a DID must be hex".to_string()))?;
    <[u8; 33]>::try_from(bytes.as_slice())
        .map_err(|_| WalletError::Invalid("a DID must be 33 bytes (66 hex characters)".to_string()))
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
        let mut w = Wallet::open(&path).unwrap();
        assert!(w.notes().is_empty());
        let note = some_note(Kind::Psp, 4);
        let id = note.id();
        w.update(|d| {
            d.notes.push(note);
            Ok(())
        })
        .unwrap();
        let again = Wallet::open(&path).unwrap();
        assert_eq!(again.notes().len(), 1);
        assert_eq!(again.notes()[0].id(), id);
        assert_eq!(again.balance().psp, 4);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_is_an_error_and_is_left_alone() {
        let dir = scratch("damaged");
        let path = dir.join("wallet.json");
        fs::write(&path, "not json").unwrap();
        assert!(matches!(Wallet::open(&path), Err(WalletError::Corrupt(_))));
        assert_eq!(fs::read_to_string(&path).unwrap(), "not json");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private_and_leaves_no_temporary_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let path = dir.join("wallet.json");
        let mut w = Wallet::open(&path).unwrap();
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
        let mut w = Wallet::open(&path).unwrap();
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
    fn a_wallet_file_from_before_one_off_purchase_keys_still_reads() {
        let dir = scratch("old-purchase");
        let path = dir.join("wallet.json");
        // an old file: the shared `reply_did` field (now ignored) and a pending
        // purchase with no key of its own
        fs::write(
            &path,
            format!(
                r#"{{"reply_did": "{did}", "pending_purchases": [{{"id": "aa", "reply_did": "{did}",
                    "mint_did_pubkey": "{did}", "outputs": []}}]}}"#,
                did = "02".repeat(33)
            ),
        )
        .unwrap();
        let mut w = Wallet::open(&path).unwrap();
        let p = &w.pending_purchases()[0];
        assert_eq!(
            (p.id.as_str(), p.reply_secret.clone(), p.delivery_id.clone()),
            ("aa", None, None)
        );
        assert!(w.open_replies().is_empty());
        // and it saves, without the ignored field
        w.update(|d| {
            d.finished.insert("x".into());
            Ok(())
        })
        .unwrap();
        let saved: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(saved.get("reply_did").is_none());
        assert!(saved["pending_purchases"][0].get("reply_did").is_some());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parse_did_wants_exactly_33_bytes_of_hex() {
        assert!(parse_did(&"02".repeat(33)).is_ok());
        assert!(parse_did(&"02".repeat(32)).is_err());
        assert!(parse_did(&"02".repeat(34)).is_err());
        assert!(parse_did("zz").is_err());
    }

    #[test]
    fn the_balance_adds_up_by_kind_and_by_esp_terms() {
        let dir = scratch("balance");
        let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
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
        let mut w = Wallet::open(&dir.join("wallet.json")).unwrap();
        w.update(|d| {
            d.notes.push(some_note(Kind::Esp, u64::MAX));
            d.notes.push(some_note(Kind::Esp, u64::MAX));
            Ok(())
        })
        .unwrap();
        assert_eq!(w.balance().esp, 2 * u128::from(u64::MAX));
        fs::remove_dir_all(&dir).unwrap();
    }
}
