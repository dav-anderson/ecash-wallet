//! Buying PSP with BTC, and claiming what the PSP mint owes for it.
//!
//! The wallet has no BTC wallet. The app's own Bitcoin wallet puts the bytes from
//! [`Wallet::build_psp_payload`] in an OP_RETURN and pays the PSP mint's address.
//! Nothing else is built at buy time: the payload is the purchase's claim DID
//! and nothing more, with no amounts and no notes.
//!
//! **A claim key for each purchase.** [`Wallet::build_psp_payload`] makes a fresh
//! throwaway key at random, never derived from or linked to the wallet's main DID,
//! and saves its secret in the wallet file ([`ClaimKey`]) before the payload is
//! returned, so the PSP mint cannot link two purchases of one wallet. The secret
//! opens the PSP mint's owed records, signs the claims, is kept like a PSP note
//! (a backup carries it and a merge keeps it), and is never logged and never part
//! of a handoff.
//!
//! **What is owed is a record, and there may be many.** When the payment has its
//! confirmations the PSP mint writes an owed record for it to the SPI's AIR
//! server, at a cell the wallet can compute from `(PSP mint, claim DID, index)`
//! and nobody else can (`sp_wire::air_request::delivery`). A claim DID may be paid
//! more than once, so the records are cells 0, 1, 2 and so on, in the order the
//! PSP mint writes them. [`crate::mint_info::psp_pickup`] reads them: it opens
//! each cell with [`Wallet::apply_delivery`], skips a cell that does not open (a
//! mint error or a forged write) and says so, and stops at the first empty cell.
//! Every start and every `claim-psp` reads the next empty cell of each key once,
//! each purchase on an AIR session of its own, in a random order, with a random
//! pause between two purchases.
//! A record says the units the payment is owed (`due_units`, whole PSP units
//! after every fee), how long it stays claimable (`window_secs`,
//! `sp_wire::psp::CLAIM_WINDOW_SECS`, 30 days) and how many claims the PSP mint
//! counts for it.
//!
//! **A clock for each record.** The window is counted from the PSP mint's write,
//! which the wallet cannot see and which is never later than the wallet's first
//! read, so each record's window runs from the wallet's first read of it
//! ([`OwedClaim::first_read_at`]) for its own `window_secs`. A claim key is kept
//! until the window of its last record has closed and nothing it holds is waiting
//! for an answer to a saved claim ([`Wallet::close_expired`]).
//!
//! **A key with no record expires.** A purchase that was never paid would
//! otherwise be kept, and read, for ever. A key that still has no owed record
//! `psp.unpaid_key_days` days (90 by default) after it was made
//! ([`ClaimKey::created_at`]) is dropped with its secret, and the user is told
//! once ([`Loss::unpaid`], [`Wallet::expire_unpaid`]). It is dropped only right
//! after the PSP mint's AIR server was asked and had no record for it, never when
//! the AIR server could not be read. 0 keeps such a key for ever. **A payment
//! made to the payload after its key was dropped is lost**: the PSP mint writes
//! the record, and nothing is left that can open it or claim it.
//!
//! **A claim (AIR kind 15, `KIND_PSP_CLAIM`).** [`Wallet::build_claim`] builds
//! it when the wallet claims, never before: fresh blinded outputs that are powers
//! of two and add up to `due_units` exactly (the PSP mint signs a claim whole or
//! not at all), on the PSP mint's current keyset (rotation, kind 4), signed
//! (BIP340) by the claim key over `ClaimRequest::digest(psp)`. The request, its
//! bytes, its hash and the blinding factors are saved with the record, together
//! with the AIR request that will carry it, in one write before the first AIR
//! write. [`crate::mint_info::psp_claim`] sends it. The PSP mint answers an
//! accepted claim only; a refused one gets no reply. A saved claim with no answer
//! is sent again as the identical bytes (the PSP mint answers a repeat of an
//! accepted claim from its stored answer and counts nothing twice). The one
//! exception is the keyset race: when the PSP mint does not answer and its
//! current keyset is no longer the one the claim names, the wallet builds a new
//! claim on the current keyset, never more than the record's `max_attempts`. A
//! refusal that names the keyset (not current, retired, unknown) does not use up
//! an attempt at the PSP mint.
//!
//! [`Wallet::apply_claim`] checks the answer (the keyset is the one asked for and
//! its keys hash to its id, one signature for each output in order, each a curve
//! point, `issued_units == due_units`) and in one write stores the notes, stamped
//! with the keyset and the epoch that signed them, and marks the record done. A
//! bad answer stores nothing. Applying an answer twice adds no notes, and a note
//! that has left this wallet already (spent, handed over, lost) is never added
//! back: a copy of the wallet from before the claim was settled can bring the key
//! and its saved claim back in a merge, the resend gets the PSP mint's stored
//! answer, and those notes were spent since. A note claimed on the current keyset
//! is not rolled over: only notes of a previous keyset are.
//!
//! **What the wallet cannot check.** Plain BDHKE is not publicly verifiable, and
//! the PSP mint sends no DLEQ proof (mint-core has none). The wallet can check
//! that each signature is a curve point for the right output, under keys that
//! hash to the keyset named, but it cannot prove that a signature is the PSP
//! mint's real one for that output. It relies on the PSP mint signing correctly:
//! an answer of valid points that are not real signatures would be stored as
//! notes that the PSP mint then refuses to spend, and the record would be done.
//!
//! **Two copies, two claims.** When two copies of the wallet each built a claim
//! for the same record, a merge keeps both ([`OwedClaim::others`]). Both are sent
//! at each start, the others first; the one the PSP mint signed is applied and
//! the record is done, and the rest are dropped with no loss told. A signed
//! refusal of one drops that one only.
//!
//! **When a window closes** with the record unclaimed, [`Wallet::close_expired`]
//! returns what was lost ([`Loss::forfeited`]), once, with the units. **When
//! nothing is due** (`due_units` is 0, because the fees take the whole payment)
//! nothing is claimed.
//!
//! **A PSP note is valid if its amount is a power of two.** There is no largest
//! note and no smallest purchase: a PSP mint keyset has 64 keys, one for each
//! power of two a note can have.

use std::collections::{BTreeMap, BTreeSet};

use mint_types::{Amount, BlindNonce};
use secp256k1::{Keypair, PublicKey, SECP256K1};
use sha2::{Digest, Sha256};
use sp_wire::ServiceDid;
use sp_wire::air_request::delivery::{self, Outcome, SEND_PURCHASE_CLAIM};
use sp_wire::air_request::{KIND_PSP_CLAIM, addr};
use sp_wire::payload;
use sp_wire::psp::{ClaimRequest, ClaimResponse, KeysetsResponse};
use sp_wire::seal::{PublicKey as DidPublicKey, SecretKey as DidSecretKey};

use crate::blind::PendingOutput;
use crate::config::Party;
use crate::error::WalletError;
use crate::rotate::Window;
use crate::store::{
    ClaimKey, Kind, OwedClaim, PendingAirRequest, SavedClaim, StoredNote, Wallet, WalletData,
};

/// What `buy-psp` says next to the payload, and what an app should show next to
/// it. A second payment to the same payload is not lost, but it links the two
/// purchases.
pub const PAY_ONCE: &str = "Pay this payload once. Each purchase has a key of its own so the PSP mint cannot link your purchases; a second payment to the same payload is still owed to you and claimed with the first, but it links the two.";

/// What `buy-psp` and the docs say about the size of a purchase. It is a
/// recommendation: nothing in the wallet enforces it.
pub const RECOMMENDED_PURCHASE: &str = "We recommend a PSP purchase of at least $5 (50 PSP): the PSP mint's fees come out of what a payment buys, so a smaller payment can buy little or nothing. This is a recommendation; nothing enforces it.";

/// A purchase the wallet has made the payload of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurchaseBuild {
    /// Identifies this purchase (its claim key) in the wallet: SHA-256 of
    /// `payload`, as hex.
    pub id: String,
    /// The encrypted payload, for the OP_RETURN.
    pub payload: Vec<u8>,
}

/// What applying one owed record did.
// One value is made for each record read, so the size does not matter; boxing
// the record would change the public type for nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivered {
    /// The record opened, passed its checks and was stored.
    Stored(OwedClaim),
    /// Nothing changed: the cell was read before, here or in another copy of the
    /// wallet.
    AlreadyDone,
}

/// Where an owed record that is still open stands ([`OpenClaim`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimStatus {
    /// No claim has been built yet: the next [`crate::mint_info::psp_claim`]
    /// builds it and sends it.
    Due,
    /// A claim is saved and sent. It is sent again, as the identical bytes, at
    /// the next start.
    Sent,
    /// The PSP mint did not answer the last claim and the wallet has built every
    /// claim the record allows, so the PSP mint did not accept it. The saved claim
    /// is still sent again, in case it was accepted and its answer lost.
    Refused,
}

/// One owed record that can still be claimed ([`Wallet::open_claims`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenClaim {
    /// The claim key's id (the purchase).
    pub id: String,
    /// The record's index under the claim key.
    pub index: u32,
    /// The PSP mint's DID the purchase was sealed to (66 hex characters).
    pub psp: String,
    /// The transaction the record is for.
    pub txid: String,
    /// The exact total of the claim, in PSP units.
    pub due_units: u64,
    /// When the record's window closes (Unix seconds): its first read plus its
    /// `window_secs`.
    pub window_ends: u64,
    /// How many claims the wallet has built for it.
    pub attempts: u32,
    /// How many the PSP mint counts (the record's `max_attempts`).
    pub max_attempts: u32,
    pub status: ClaimStatus,
    /// True once the user was told the record is lost, so it is said once.
    pub told_lost: bool,
}

/// Why a record is lost, for the words the user is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossKind {
    /// The window closed and the record was never claimed.
    Expired,
    /// The PSP mint did not accept the claim, and the wallet has built every
    /// claim the record allows.
    Refused,
    /// The claim key had no owed record `psp.unpaid_key_days` after it was made,
    /// and was dropped ([`Wallet::expire_unpaid`]). `index` is 0, `txid` empty,
    /// `due_units` 0 and `window_ends` the time the key expired.
    Unpaid,
}

/// A payment that is, or will be, lost: its words ([`Loss::forfeited`],
/// [`Loss::not_accepted`]) say so plainly, with the units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loss {
    /// The claim key's id (the purchase).
    pub id: String,
    /// The record's index under the claim key.
    pub index: u32,
    /// The transaction the record is for.
    pub txid: String,
    /// What the record owed, in PSP units.
    pub due_units: u64,
    pub kind: LossKind,
    /// When the record's window closes or closed (Unix seconds).
    pub window_ends: u64,
}

impl Loss {
    fn date(&self) -> String {
        crate::date::format_utc(self.window_ends)
    }

    /// What is said once when the window closed with the record unclaimed: the PSP
    /// mint keeps the payment and the funds are lost.
    pub fn forfeited(&self) -> String {
        format!(
            "purchase {}, record {} (payment {}): expired. It was not claimed by {}, when its window closed. The PSP mint keeps the payment: the funds are lost ({} PSP)",
            self.id,
            self.index,
            self.txid,
            self.date(),
            self.due_units
        )
    }

    /// What is said once when a claim key with no owed record was dropped
    /// ([`LossKind::Unpaid`]).
    pub fn unpaid(&self) -> String {
        format!(
            "purchase {}: the PSP mint has written no record for it, and it expired at {}, so its claim key was dropped. If its payload is paid now the PSP mint keeps the payment: the funds are lost. Set psp.unpaid_key_days to keep an unpaid purchase longer (0 keeps it for ever)",
            self.id,
            self.date()
        )
    }

    /// What is said once for this loss: [`Loss::forfeited`] or [`Loss::unpaid`].
    /// (A refusal is said by [`Loss::not_accepted`], which needs the attempts.)
    pub fn said(&self) -> String {
        match self.kind {
            LossKind::Unpaid => self.unpaid(),
            LossKind::Expired | LossKind::Refused => self.forfeited(),
        }
    }

    /// What is said once when the PSP mint did not answer the claim after the
    /// wallet had built every claim the record allows.
    pub fn not_accepted(&self, attempts: u32) -> String {
        format!(
            "purchase {}, record {} (payment {}): refused. The PSP mint did not accept the claim (it answers an accepted claim only) after {attempts} attempt(s). Unless it answers by {}, the payment ({} PSP) is lost",
            self.id,
            self.index,
            self.txid,
            self.date(),
            self.due_units
        )
    }
}

/// What applying the PSP mint's answer to a claim did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// The notes were stored and the record was marked done.
    Settled(Settled),
    /// Nothing changed: the record is done already (the answer was applied
    /// before, here or in another copy of the wallet).
    AlreadyDone,
}

/// The notes a claim brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    /// The ids of the new notes.
    pub claimed: Vec<String>,
    /// Their total, in PSP units (the record's `due_units`).
    pub units: u64,
}

/// A claim the wallet built and saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimBuild {
    /// The claim key's id (the purchase).
    pub id: String,
    /// The record's index under the claim key.
    pub index: u32,
    pub request: ClaimRequest,
    /// The bytes that are sent: the JSON of `request`, exactly as saved.
    pub body: Vec<u8>,
    /// `request.hash(psp)`: what the PSP mint stores its answer under.
    pub hash: String,
    /// 1 for the first claim built for the record, 2 for the second, and so on.
    pub attempt: u32,
}

/// Check that `amount` is a PSP note size: a power of two. There is no largest
/// note size; the PSP mint's keyset has a key for every power of two.
pub fn check_denomination(amount: u64) -> Result<(), WalletError> {
    if !amount.is_power_of_two() {
        return Err(WalletError::Invalid(format!(
            "{amount} is not a PSP note size: use a power of two"
        )));
    }
    Ok(())
}

/// A claim's output sizes, checked without any network: at least one, and each a
/// PSP note size ([`check_denomination`]). There is no largest and no smallest
/// total.
pub fn check_outputs(outputs: &[u64]) -> Result<(), WalletError> {
    if outputs.is_empty() {
        return Err(WalletError::Invalid(
            "a claim needs at least one output".into(),
        ));
    }
    for &amount in outputs {
        check_denomination(amount)?;
    }
    Ok(())
}

/// A curve point written as 66 hex characters (a blind nonce or a signature).
fn point(text: &str) -> Result<PublicKey, WalletError> {
    let bytes = hex::decode(text).map_err(|_| WalletError::Invalid(format!("not hex: {text}")))?;
    PublicKey::from_slice(&bytes)
        .map_err(|_| WalletError::Invalid(format!("not a curve point: {text}")))
}

/// The keys of the keyset that signed, from the answer. They must be the keys the
/// keyset's id names (the id hashes every amount and key), or it is not to be
/// trusted with the notes. [`Wallet::apply_claim`] then checks them against the
/// keys the PSP mint published ([`crate::keystream`]).
fn keys_of(
    keyset: &str,
    keysets: &KeysetsResponse,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let Some(keys) = keysets.keysets.get(keyset) else {
        return Err(WalletError::Mint(format!(
            "the PSP mint's reply does not carry the keys of keyset {keyset}, which signed"
        )));
    };
    let keys: BTreeMap<Amount, PublicKey> = keys
        .iter()
        .map(|(units, key)| (Amount::from_units(*units), *key))
        .collect();
    if sp_wire::keyset::keyset_id(&keys) != keyset {
        return Err(WalletError::Mint(format!(
            "the keys in the PSP mint's reply are not those of keyset {keyset}"
        )));
    }
    Ok(keys)
}

/// The outputs of a claim for `due` units: the binary digits of `due`, largest
/// first, each a power of two, adding up to `due` exactly. At most 64 of them.
fn split_due(due: u64) -> Vec<u64> {
    (0..64)
        .rev()
        .map(|shift| 1u64 << shift)
        .filter(|bit| due & bit != 0)
        .collect()
}

/// Remove the kind 15 AIR request that carries the claim whose body hashes to
/// `body_hash`, made with the claim key `claim_secret` (its `R`). A key's other
/// records have claims of their own, with other bodies.
fn drop_air_request(d: &mut WalletData, claim_secret: &str, body_hash: &str) {
    d.air_requests
        .retain(|r| !(r.kind == KIND_PSP_CLAIM && r.r == claim_secret && r.body_hash == body_hash));
}

/// The record `index` of the claim key `id`, to change it in a write.
fn record_mut<'a>(d: &'a mut WalletData, id: &str, index: u32) -> Option<&'a mut OwedClaim> {
    d.claim_keys
        .iter_mut()
        .find(|k| k.id == id)?
        .records
        .iter_mut()
        .find(|r| r.index == index)
}

/// The saved claim of `record` whose hash is `hash`, or its main one (`request`)
/// for `None`.
fn saved_of<'a>(record: &'a OwedClaim, hash: Option<&str>) -> Option<&'a SavedClaim> {
    match hash {
        None => record.request.as_ref(),
        Some(h) => record
            .request
            .iter()
            .chain(&record.others)
            .find(|s| s.hash == h),
    }
}

/// A day, in seconds.
const DAY_SECS: u64 = 86_400;

/// `psp.unpaid_key_days` by default: a claim key with no owed record is dropped
/// 90 days after it was made.
pub const DEFAULT_UNPAID_KEY_DAYS: u64 = 90;

/// The claim key `id` and its record `index`.
fn record_of<'a>(d: &'a WalletData, id: &str, index: u32) -> Option<(&'a ClaimKey, &'a OwedClaim)> {
    let key = d.claim_keys.iter().find(|k| k.id == id)?;
    let record = key.records.iter().find(|r| r.index == index)?;
    Some((key, record))
}

/// What `psp_claim` needs to send a saved claim.
pub(crate) struct ToSend {
    pub body: Vec<u8>,
    pub key: DidSecretKey,
    pub keyset: String,
}

impl Wallet {
    /// Make this purchase's own throwaway claim key, encode the payload (the claim
    /// DID, 33 bytes, and nothing else), and encrypt it to the PSP mint's DID
    /// public key with AIR's secp256k1 encryption. Returns the bytes for an
    /// OP_RETURN.
    ///
    /// No amount is chosen and nothing is checked about the size of the purchase:
    /// what the payment is worth is decided by the PSP mint when it handles the
    /// payment, and the wallet claims whatever it is owed. A purchase of at least
    /// $5 (50 PSP) is recommended ([`RECOMMENDED_PURCHASE`]), not enforced. The
    /// payload is paid once ([`PAY_ONCE`]).
    ///
    /// The claim key is made at random, never derived from or linked to the
    /// wallet's main DID, and its secret is saved in the wallet before this
    /// returns, so the key is on disk before any payment is made.
    pub fn build_psp_payload(
        &mut self,
        psp_did: &DidPublicKey,
    ) -> Result<PurchaseBuild, WalletError> {
        let key = DidSecretKey::new();
        let claim_did = addr::key_to_bytes(&key.public_key());
        let plaintext =
            payload::encode(&claim_did).map_err(|e| WalletError::Invalid(e.to_string()))?;
        let sealed = sp_wire::seal::encrypt(psp_did, &plaintext)?;
        let id = hex::encode(Sha256::digest(&sealed));
        let record = ClaimKey {
            id: id.clone(),
            claim_did: hex::encode(claim_did),
            claim_secret: addr::secret_to_hex(&key),
            psp_did: psp_did.to_string(),
            created_at: addr::now_secs(),
            next_index: 0,
            records: Vec::new(),
        };
        self.update(|d| {
            d.claim_keys.push(record);
            Ok(())
        })?;
        Ok(PurchaseBuild {
            id,
            payload: sealed,
        })
    }

    /// Apply the PSP mint's owed record at cell `index` of the claim key `id`:
    /// `sealed` is the cell's bytes, `now` this wallet's clock in Unix seconds
    /// (the first read of the record, which starts its window).
    ///
    /// The record is opened with the claim key and checked
    /// (`delivery::open_record`: it opens, names this PSP mint, carries the PSP
    /// mint's signature and answers this record id and claim DID), and its terms
    /// must be a purchase claim sent as kind 15. A record that fails any of this is
    /// a mint error and changes nothing; [`crate::mint_info::psp_pickup`] then skips
    /// the cell ([`Wallet::skip_record`]) and reads on. A good record is stored in
    /// the key's `records` and `next_index` moves past it, in one write. A record
    /// whose `due_units` is 0 (the fees take the whole payment) is stored as done
    /// and told: there is nothing to claim.
    ///
    /// Cells are applied in order. A cell below `next_index` was applied or skipped
    /// before, here or in another copy of the wallet ([`Delivered::AlreadyDone`]);
    /// one above it is a caller's error.
    pub fn apply_delivery(
        &mut self,
        id: &str,
        index: u32,
        sealed: &[u8],
        now: u64,
    ) -> Result<Delivered, WalletError> {
        let Some(key) = self.claim_keys().iter().find(|k| k.id == id) else {
            return Err(WalletError::Unknown(format!("no purchase {id}")));
        };
        if index < key.next_index {
            return Ok(Delivered::AlreadyDone);
        }
        if index > key.next_index {
            return Err(WalletError::Invalid(format!(
                "purchase {id}: record {index} is read before record {}",
                key.next_index
            )));
        }
        let corrupt = |what: &str| WalletError::Corrupt(format!("purchase {id}: {what}"));
        let secret = addr::secret_from_hex(&key.claim_secret)
            .map_err(|_| corrupt("its claim key is not valid"))?;
        let psp = ServiceDid::parse(&key.psp_did)
            .map_err(|_| corrupt("the PSP mint key it was sealed to is not valid"))?;
        let claim = addr::key_to_did(&secret.public_key());
        if claim.to_hex() != key.claim_did {
            return Err(corrupt("its claim key is not the one its payload names"));
        }
        let opened = delivery::open_record(&secret, &psp, index, sealed).map_err(|e| {
            WalletError::Mint(format!(
                "the PSP mint's record {index} for purchase {id} was not accepted: {e}"
            ))
        })?;
        let Outcome::Owed(owed) = opened.outcome;
        let terms = &owed.terms;
        if terms.send != SEND_PURCHASE_CLAIM || terms.kind != KIND_PSP_CLAIM {
            return Err(WalletError::Mint(format!(
                "the PSP mint's record {index} for purchase {id} says to send {:?} as kind {}, but this wallet sends {SEND_PURCHASE_CLAIM:?} as kind {KIND_PSP_CLAIM}. Nothing was stored",
                terms.send, terms.kind
            )));
        }
        let nothing_due = terms.due_units == 0;
        let record = OwedClaim {
            index,
            record_id: hex::encode(delivery::record_id(&claim, index)),
            txid: owed.txid.clone(),
            due_units: terms.due_units,
            window_secs: terms.window_secs,
            first_read_at: now,
            max_attempts: terms.max_attempts,
            request: None,
            others: Vec::new(),
            attempts: 0,
            unanswered: false,
            told_lost: nothing_due,
            done: nothing_due,
        };
        let stored = record.clone();
        self.update(|d| {
            let key = d
                .claim_keys
                .iter_mut()
                .find(|k| k.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no purchase {id}")))?;
            key.records.push(record);
            key.records.sort_by_key(|r| r.index);
            key.next_index = index + 1;
            Ok(())
        })?;
        Ok(Delivered::Stored(stored))
    }

    /// Move the claim key `id` past cell `index` without storing a record: the
    /// cell did not open, so it is skipped for good (a cell is written once). Does
    /// nothing when `index` is not the key's next cell.
    pub(crate) fn skip_record(&mut self, id: &str, index: u32) -> Result<(), WalletError> {
        match self.claim_keys().iter().find(|k| k.id == id) {
            Some(key) if key.next_index == index => {}
            _ => return Ok(()),
        }
        self.update(|d| {
            if let Some(key) = d.claim_keys.iter_mut().find(|k| k.id == id) {
                key.next_index = index + 1;
            }
            Ok(())
        })
    }

    /// The owed records that can still be claimed at `now`: the window is open,
    /// the record is not done and something is due. Oldest key first, each key's
    /// records in order.
    pub fn open_claims(&self, now: u64) -> Vec<OpenClaim> {
        let mut out = Vec::new();
        for key in self.claim_keys() {
            let psp = ServiceDid::parse(&key.psp_did)
                .map_or_else(|_| key.psp_did.clone(), |did| did.to_hex());
            for r in &key.records {
                if r.done || r.due_units == 0 || !r.is_open(now) {
                    continue;
                }
                let status = if r.request.is_none() {
                    ClaimStatus::Due
                } else if r.unanswered && r.attempts >= r.max_attempts {
                    ClaimStatus::Refused
                } else {
                    ClaimStatus::Sent
                };
                out.push(OpenClaim {
                    id: key.id.clone(),
                    index: r.index,
                    psp: psp.clone(),
                    txid: r.txid.clone(),
                    due_units: r.due_units,
                    window_ends: r.window_ends(),
                    attempts: r.attempts,
                    max_attempts: r.max_attempts,
                    status,
                    told_lost: r.told_lost,
                });
            }
        }
        out
    }

    /// Delete what closed windows leave behind. Each record whose window has
    /// closed (its first read plus its `window_secs` is `now` or earlier) without
    /// being claimed goes to the returned list once ([`Loss::forfeited`]), and a
    /// record that was reported lost already, or has a claim saved and waiting for
    /// an answer, is not. A claim key is deleted, with its secret, its records and
    /// their saved claims, only when it holds at least one record, the window of
    /// every record has closed and none of them is waiting for an answer to a
    /// saved claim ([`crate::mint_info::psp_close_expired`] sends that claim one
    /// last time first). A key with no record is not deleted here: its payment
    /// may still be waiting for its confirmations ([`Wallet::expire_unpaid`]
    /// drops it once it is old enough). The windows are the records', and `now`
    /// is this wallet's clock.
    ///
    /// Nothing is written when nothing is closed.
    pub fn close_expired(&mut self, now: u64) -> Result<Vec<Loss>, WalletError> {
        self.close_expired_keeping(now, &[])
    }

    /// [`Wallet::close_expired`], leaving the claim keys in `keep` in place: the
    /// ones whose last resend could not be sent
    /// ([`crate::mint_info::psp_close_expired`]), which are closed at a later
    /// start. No network use.
    pub(crate) fn close_expired_keeping(
        &mut self,
        now: u64,
        keep: &[String],
    ) -> Result<Vec<Loss>, WalletError> {
        let mut losses = Vec::new();
        for key in self.claim_keys() {
            for r in &key.records {
                if !r.is_open(now)
                    && !r.done
                    && !r.told_lost
                    && r.request.is_none()
                    && r.others.is_empty()
                {
                    losses.push(Loss {
                        id: key.id.clone(),
                        index: r.index,
                        txid: r.txid.clone(),
                        due_units: r.due_units,
                        kind: LossKind::Expired,
                        window_ends: r.window_ends(),
                    });
                }
            }
        }
        let deletable = |k: &ClaimKey| {
            !keep.contains(&k.id)
                && !k.records.is_empty()
                && k.records.iter().all(|r| {
                    !r.is_open(now) && (r.done || (r.request.is_none() && r.others.is_empty()))
                })
        };
        if losses.is_empty() && !self.claim_keys().iter().any(deletable) {
            return Ok(Vec::new());
        }
        let told: Vec<(String, u32)> = losses.iter().map(|l| (l.id.clone(), l.index)).collect();
        self.update(|d| {
            for (id, index) in &told {
                if let Some(r) = record_mut(d, id, *index) {
                    r.told_lost = true;
                }
            }
            let gone: Vec<ClaimKey> = d
                .claim_keys
                .iter()
                .filter(|k| deletable(k))
                .cloned()
                .collect();
            d.claim_keys.retain(|k| !deletable(k));
            for key in &gone {
                d.air_requests
                    .retain(|a| !(a.kind == KIND_PSP_CLAIM && a.r == key.claim_secret));
            }
            Ok(())
        })?;
        Ok(losses)
    }

    /// Forget a purchase that was never paid. Its claim key and its secret are
    /// dropped. Do not do this once the payment has been sent: the PSP mint may
    /// already owe it.
    pub fn discard_purchase(&mut self, id: &str) -> Result<(), WalletError> {
        self.update(|d| {
            let before = d.claim_keys.len();
            d.claim_keys.retain(|k| k.id != id);
            if d.claim_keys.len() == before {
                return Err(WalletError::Unknown(format!("no purchase {id}")));
            }
            Ok(())
        })
    }

    /// Drop the claim keys that have no owed record and were made `days` days or
    /// more before `now` (`psp.unpaid_key_days`; 0 keeps them for ever), each
    /// returned once as a [`LossKind::Unpaid`] loss ([`Loss::unpaid`]). Only the
    /// keys in `checked` are looked at: the ones the PSP mint's AIR server was just
    /// asked about and had no record for ([`crate::mint_info::psp_pickup`],
    /// `no_record`), so a key is never dropped because the AIR server could not be
    /// read. A key with a record is never dropped here: its records keep their own
    /// rules ([`Wallet::close_expired`]). A payment made to a dropped key's payload
    /// is lost. Nothing is written when nothing expires.
    pub fn expire_unpaid(
        &mut self,
        now: u64,
        days: u64,
        checked: &[String],
    ) -> Result<Vec<Loss>, WalletError> {
        if days == 0 {
            return Ok(Vec::new());
        }
        let after = days.saturating_mul(DAY_SECS);
        let expired = |k: &ClaimKey| {
            k.records.is_empty()
                && checked.contains(&k.id)
                && now >= k.created_at.saturating_add(after)
        };
        let losses: Vec<Loss> = self
            .claim_keys()
            .iter()
            .filter(|k| expired(k))
            .map(|k| Loss {
                id: k.id.clone(),
                index: 0,
                txid: String::new(),
                due_units: 0,
                kind: LossKind::Unpaid,
                window_ends: k.created_at.saturating_add(after),
            })
            .collect();
        if losses.is_empty() {
            return Ok(losses);
        }
        self.update(|d| {
            let gone: Vec<String> = d
                .claim_keys
                .iter()
                .filter(|k| expired(k))
                .map(|k| k.claim_secret.clone())
                .collect();
            d.claim_keys.retain(|k| !expired(k));
            d.air_requests
                .retain(|a| !(a.kind == KIND_PSP_CLAIM && gone.contains(&a.r)));
            Ok(())
        })?;
        Ok(losses)
    }

    /// The records whose window has closed at `now` and that still hold a saved
    /// claim that was not settled: `(the claim key's id, the record's index, the
    /// PSP mint it was sealed to as hex)`. These are the ones
    /// [`crate::mint_info::psp_close_expired`] sends the saved claim of one last
    /// time before [`Wallet::close_expired`] deletes them.
    pub(crate) fn expired_claims(&self, now: u64) -> Vec<(String, u32, String)> {
        let mut out = Vec::new();
        for key in self.claim_keys() {
            let psp = ServiceDid::parse(&key.psp_did)
                .map_or_else(|_| key.psp_did.clone(), |did| did.to_hex());
            for r in &key.records {
                if !r.is_open(now) && !r.done && (r.request.is_some() || !r.others.is_empty()) {
                    out.push((key.id.clone(), r.index, psp.clone()));
                }
            }
        }
        out
    }

    /// Let go of the saved claim of a record whose window has closed and whose last
    /// resend got no answer (or was never going to be sent: the purchase was sealed
    /// to another PSP mint): the claim is over, the blinding factors are of no use,
    /// and [`Wallet::close_expired`] can report the record lost and delete its key.
    pub(crate) fn give_up_claim(&mut self, id: &str, index: u32) -> Result<(), WalletError> {
        self.update(|d| {
            let secret = d
                .claim_keys
                .iter()
                .find(|k| k.id == id)
                .map(|k| k.claim_secret.clone());
            let hashes: Vec<String> = record_mut(d, id, index)
                .map(|r| {
                    r.unanswered = false;
                    r.request
                        .take()
                        .into_iter()
                        .chain(std::mem::take(&mut r.others))
                        .map(|s| crate::air::body_hash(&hex_body(&s)))
                        .collect()
                })
                .unwrap_or_default();
            if let Some(secret) = secret {
                for hash in &hashes {
                    drop_air_request(d, &secret, hash);
                }
            }
            Ok(())
        })
    }

    /// What the user is told if the open record `index` of purchase `id` is lost
    /// because the PSP mint did not accept the claim: `None` when it is not an
    /// open record.
    pub(crate) fn refused_loss(&self, id: &str, index: u32) -> Option<Loss> {
        let (_, r) = record_of(self.data(), id, index)?;
        Some(Loss {
            id: id.to_string(),
            index,
            txid: r.txid.clone(),
            due_units: r.due_units,
            kind: LossKind::Refused,
            window_ends: r.window_ends(),
        })
    }

    /// Build the claim (AIR kind 15) for the open record `index` of the claim key
    /// `id` and save it, so that [`crate::mint_info::psp_claim`] can send it.
    /// `window` is a fresh read of the PSP mint's rotation (its current keyset and
    /// that keyset's epoch), `keys` a fresh read of the keys of that keyset, `now`
    /// this wallet's clock in Unix seconds.
    ///
    /// The claim follows the record: fresh blinded outputs that are powers of two
    /// (the binary digits of `due_units`, largest first) adding up to `due_units`
    /// exactly, on the PSP mint's current keyset, signed by the claim key over
    /// `ClaimRequest::digest(psp)`. Every output must have a key in `keys`, and
    /// `keys` must be the keys the keyset's id names. The claim, its bytes and its
    /// blinding factors are then saved with the record, together with the AIR
    /// request that will carry it (its `R` is the claim key), in one write; a
    /// claim that fails a check is refused and nothing is saved.
    ///
    /// It refuses, with the wallet unchanged: a record that is done, has nothing
    /// due, or whose window has closed; a saved claim whose keyset is still the
    /// current one (that one is sent again as it is, never rebuilt); and any claim
    /// beyond the record's `max_attempts`.
    pub fn build_claim(
        &mut self,
        id: &str,
        index: u32,
        window: &Window,
        keys: &BTreeMap<Amount, PublicKey>,
        now: u64,
    ) -> Result<ClaimBuild, WalletError> {
        let (key, record) = record_of(self.data(), id, index)
            .map(|(k, r)| (k.clone(), r.clone()))
            .ok_or_else(|| WalletError::Unknown(format!("no record {index} of purchase {id}")))?;
        let corrupt = |what: &str| WalletError::Corrupt(format!("purchase {id}: {what}"));
        if record.done || record.due_units == 0 {
            return Err(WalletError::Invalid(format!(
                "purchase {id}, record {index}: nothing is left to claim"
            )));
        }
        if !record.is_open(now) {
            return Err(WalletError::Invalid(format!(
                "purchase {id}, record {index}: the window closed at {}, so nothing is built or sent",
                crate::date::format_utc(record.window_ends())
            )));
        }
        if record.attempts >= record.max_attempts {
            return Err(WalletError::Invalid(format!(
                "purchase {id}, record {index}: {} claim(s) were built already, and the PSP mint counts {}. No other is built",
                record.attempts, record.max_attempts
            )));
        }
        let keyset = window.current_id.clone();
        if let Some(saved) = &record.request
            && saved.keyset == keyset
        {
            return Err(WalletError::Invalid(format!(
                "purchase {id}, record {index}: the saved claim names keyset {keyset}, which is still current. It is sent again as it is, never rebuilt"
            )));
        }
        if sp_wire::keyset::keyset_id(keys) != keyset {
            return Err(WalletError::Mint(format!(
                "the keys the PSP mint gave are not those of its current keyset {keyset}"
            )));
        }
        let amounts = split_due(record.due_units);
        check_outputs(&amounts)?;
        for amount in &amounts {
            if !keys.contains_key(&Amount::from_units(*amount)) {
                return Err(WalletError::Mint(format!(
                    "the PSP mint's keyset {keyset} has no key for {amount} units, so a claim of {} cannot be built",
                    record.due_units
                )));
            }
        }
        // The shared key check: every key of the keyset the claim is built on is
        // the key the PSP mint published for it, not only the hash of them.
        let every: Vec<(u64, PublicKey)> = keys.iter().map(|(a, k)| (a.units, *k)).collect();
        self.check_keyset_keys(
            Party::Psp,
            crate::keystream::Site::BuildClaim,
            &keyset,
            &every,
        )?;
        let outputs: Vec<PendingOutput> = amounts.into_iter().map(PendingOutput::new).collect();

        let secret = addr::secret_from_hex(&key.claim_secret)
            .map_err(|_| corrupt("its claim key is not valid"))?;
        let claim_did = addr::key_to_did(&secret.public_key());
        if claim_did.to_hex() != key.claim_did {
            return Err(corrupt("its claim key is not the one its payload names"));
        }
        let psp = ServiceDid::parse(&key.psp_did).map_err(|e| {
            corrupt(&format!(
                "the PSP mint key it was sealed to is not valid: {e}"
            ))
        })?;
        let record_id: [u8; 32] = hex::decode(&record.record_id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| corrupt("a record id that is not 32 bytes of hex"))?;
        let signing = secp256k1::SecretKey::from_slice(&secret.to_array())
            .map_err(|_| corrupt("its claim key is not valid"))?;
        let mut request = ClaimRequest {
            claim_did,
            record_id,
            keyset: keyset.clone(),
            outputs: outputs.iter().map(PendingOutput::mint_output).collect(),
            signature: secp256k1::schnorr::Signature::from_slice(&[0; 64])
                .expect("any 64 bytes are a signature to sign over"),
        };
        request.signature = SECP256K1.sign_schnorr(
            &request.digest(&psp),
            &Keypair::from_secret_key(SECP256K1, &signing),
        );
        let bug = |why: &str| {
            WalletError::Invalid(format!(
                "the claim is not right ({why}). That is a bug in the wallet, so nothing was saved and nothing was sent"
            ))
        };
        SECP256K1
            .verify_schnorr(
                &request.signature,
                &request.digest(&psp),
                &request.claim_did.x_only(),
            )
            .map_err(|_| bug("the signature does not verify under the claim key"))?;
        let total: u128 = request
            .outputs
            .iter()
            .map(|o| u128::from(o.amount.units))
            .sum();
        if total != u128::from(record.due_units) {
            return Err(bug(&format!(
                "the outputs add up to {total}, the record says {}",
                record.due_units
            )));
        }
        let mut nonces = BTreeSet::new();
        if !request
            .outputs
            .iter()
            .all(|o| nonces.insert(o.blind_nonce.0.serialize()))
        {
            return Err(bug("two outputs share a blind nonce"));
        }
        let body = serde_json::to_vec(&request)
            .map_err(|e| WalletError::Invalid(format!("the claim could not be encoded: {e}")))?;
        let hash = request.hash(&psp);
        let attempt = record.attempts + 1;

        let saved = SavedClaim {
            body: hex::encode(&body),
            hash: hash.clone(),
            keyset,
            epoch: window.current_epoch,
            outputs,
        };
        let air_request = PendingAirRequest {
            kind: KIND_PSP_CLAIM,
            request_id: hex::encode(addr::random_id()),
            mint: psp.to_hex(),
            r: key.claim_secret.clone(),
            slots: Vec::new(),
            created_at: addr::now_secs(),
            body_hash: crate::air::body_hash(&body),
        };
        let old = record.request.as_ref().map(hex_body);
        self.update(|d| {
            let r = record_mut(d, id, index).ok_or_else(|| {
                WalletError::Unknown(format!("no record {index} of purchase {id}"))
            })?;
            r.request = Some(saved);
            r.attempts = attempt;
            r.unanswered = false;
            if let Some(old) = &old {
                drop_air_request(d, &key.claim_secret, &crate::air::body_hash(old));
            }
            d.air_requests.push(air_request);
            Ok(())
        })?;
        Ok(ClaimBuild {
            id: id.to_string(),
            index,
            request,
            body,
            hash,
            attempt,
        })
    }

    /// Apply the PSP mint's answer to the claim saved for record `index` of the
    /// claim key `id`. The answer is checked first, and any failure is a mint error
    /// that stores nothing and keeps the key and the saved claim:
    ///
    /// - the keyset that signed is the one the claim named, it is listed in the
    ///   answer, and its keys hash to its id;
    /// - there is one signature for each output, in the claim's order, for that
    ///   output's blind nonce, each a curve point (a blind signature cannot be
    ///   checked further without the PSP mint's secret key; the notes are checked
    ///   when they are spent), and the keyset has a key for the output's amount;
    /// - `issued_units` is the record's `due_units`.
    ///
    /// Then, in one write, the notes are stored (with their keyset and the epoch
    /// the claim was built under recorded), the record is marked done, its saved
    /// claim is dropped and so are its other saved claims ([`OwedClaim::others`])
    /// and the AIR requests that carried them. A record that is done already (the
    /// same answer applied before, here or in another copy of the wallet) is
    /// [`Applied::AlreadyDone`]: nothing is written and no note is added.
    ///
    /// A note that has left this wallet already (the ledgers count it departed and
    /// not returned) or is held already is not added again: a stale copy merged in
    /// can bring back a settled record's saved claim, and the PSP mint answers its
    /// resend from its stored answer, with the notes that were spent since. When no
    /// note is left to add, the record is marked done and the answer is
    /// [`Applied::AlreadyDone`].
    pub fn apply_claim(
        &mut self,
        id: &str,
        index: u32,
        response: &ClaimResponse,
    ) -> Result<Applied, WalletError> {
        self.apply_claim_to(id, index, None, response)
    }

    /// [`Wallet::apply_claim`] for the saved claim whose hash is `hash` (one of
    /// [`OwedClaim::others`], or the main one), or the main one for `None`.
    pub(crate) fn apply_claim_to(
        &mut self,
        id: &str,
        index: u32,
        hash: Option<&str>,
        response: &ClaimResponse,
    ) -> Result<Applied, WalletError> {
        let Some((key, record)) = record_of(self.data(), id, index) else {
            return Ok(Applied::AlreadyDone);
        };
        if record.done {
            return Ok(Applied::AlreadyDone);
        }
        let Some(saved) = saved_of(record, hash).cloned() else {
            return Err(WalletError::Unknown(format!(
                "no claim was built for record {index} of purchase {id}, so there is nothing for this answer to settle"
            )));
        };
        let all_saved: Vec<String> = record
            .request
            .iter()
            .chain(&record.others)
            .map(|s| crate::air::body_hash(&hex_body(s)))
            .collect();
        let (due_units, secret) = (record.due_units, key.claim_secret.clone());
        let wrong = |why: String| {
            WalletError::Mint(format!(
                "the PSP mint's answer to the claim of record {index} of purchase {id} is not right ({why}). Nothing was stored and the key is kept"
            ))
        };
        if response.keyset != saved.keyset {
            return Err(wrong(format!(
                "it was signed by keyset {}, the claim named {}",
                response.keyset, saved.keyset
            )));
        }
        let keys =
            keys_of(&response.keyset, &response.keysets).map_err(|e| wrong(e.to_string()))?;
        // The shared key check, before anything is stored: every key of the
        // keyset in the answer is the key the PSP mint published for it.
        let every: Vec<(u64, PublicKey)> = keys.iter().map(|(a, k)| (a.units, *k)).collect();
        self.check_keyset_keys(
            Party::Psp,
            crate::keystream::Site::ApplyClaim,
            &response.keyset,
            &every,
        )?;
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
        if response.issued_units != due_units {
            return Err(wrong(format!(
                "it issued {} units, the record says {due_units}",
                response.issued_units
            )));
        }
        let total: u64 = notes.iter().map(|n| n.amount).sum();
        if total != due_units {
            return Err(wrong(format!(
                "the outputs add up to {total}, the record says {due_units}"
            )));
        }
        // A note that left this wallet (spent, handed over, lost) or is held
        // already is not added again.
        let held: BTreeSet<String> = self.notes().iter().map(StoredNote::id).collect();
        notes.retain(|n| {
            let nid = n.id();
            !held.contains(&nid) && !crate::store::has_departed(self.data(), &nid)
        });
        let claimed: Vec<String> = notes.iter().map(StoredNote::id).collect();
        let units: u64 = notes.iter().map(|n| n.amount).sum();
        let keyset = response.keyset.clone();
        self.update(|d| {
            for note in notes {
                d.keysets.insert(note.id(), keyset.clone());
                d.epochs.insert(note.id(), saved.epoch);
                d.notes.push(note);
            }
            if let Some(r) = record_mut(d, id, index) {
                r.done = true;
                r.unanswered = false;
                r.request = None;
                r.others.clear();
            }
            for hash in &all_saved {
                drop_air_request(d, &secret, hash);
            }
            Ok(())
        })?;
        if claimed.is_empty() {
            return Ok(Applied::AlreadyDone);
        }
        Ok(Applied::Settled(Settled { claimed, units }))
    }

    /// The saved claim of record `index` of purchase `id`, with what sending it
    /// needs.
    pub(crate) fn claim_to_send(&self, id: &str, index: u32) -> Result<ToSend, WalletError> {
        self.claim_to_send_of(id, index, None)
    }

    /// [`Wallet::claim_to_send`] for the saved claim whose hash is `hash`, or the
    /// main one for `None`.
    pub(crate) fn claim_to_send_of(
        &self,
        id: &str,
        index: u32,
        hash: Option<&str>,
    ) -> Result<ToSend, WalletError> {
        let (key, record) = record_of(self.data(), id, index)
            .ok_or_else(|| WalletError::Unknown(format!("no record {index} of purchase {id}")))?;
        let Some(saved) = saved_of(record, hash) else {
            return Err(WalletError::Unknown(format!(
                "no claim is saved for record {index} of purchase {id}"
            )));
        };
        let corrupt = |what: &str| {
            WalletError::Corrupt(format!(
                "the saved claim of record {index} of purchase {id} has {what}"
            ))
        };
        let body = hex::decode(&saved.body).map_err(|_| corrupt("a body that is not hex"))?;
        let claim_key = addr::secret_from_hex(&key.claim_secret)
            .map_err(|_| corrupt("a key that is not valid"))?;
        ServiceDid::parse(&key.psp_did).map_err(|_| corrupt("a PSP mint key that is not valid"))?;
        Ok(ToSend {
            body,
            key: claim_key,
            keyset: saved.keyset.clone(),
        })
    }

    /// The hashes of the other saved claims of record `index` of purchase `id`
    /// ([`OwedClaim::others`]), in order. Empty when the record is done or gone.
    pub(crate) fn other_claims(&self, id: &str, index: u32) -> Vec<String> {
        match record_of(self.data(), id, index) {
            Some((_, r)) if !r.done => r.others.iter().map(|s| s.hash.clone()).collect(),
            _ => Vec::new(),
        }
    }

    /// Drop the other saved claim `hash` of record `index` of purchase `id`: the
    /// PSP mint refused it in a signed reply, or its window closed and its last
    /// resend got no answer. Nothing is written when it is not there.
    pub(crate) fn drop_other_claim(
        &mut self,
        id: &str,
        index: u32,
        hash: &str,
    ) -> Result<(), WalletError> {
        let Some((key, r)) = record_of(self.data(), id, index) else {
            return Ok(());
        };
        let Some(saved) = r.others.iter().find(|s| s.hash == hash) else {
            return Ok(());
        };
        let (secret, body_hash) = (
            key.claim_secret.clone(),
            crate::air::body_hash(&hex_body(saved)),
        );
        self.update(|d| {
            if let Some(r) = record_mut(d, id, index) {
                r.others.retain(|s| s.hash != hash);
            }
            drop_air_request(d, &secret, &body_hash);
            Ok(())
        })
    }

    /// Record that the PSP mint did not answer the saved claim of record `index` of
    /// purchase `id` (`true`), or that it did (`false`). Nothing is written when it
    /// is as recorded already.
    pub(crate) fn note_unanswered(
        &mut self,
        id: &str,
        index: u32,
        unanswered: bool,
    ) -> Result<(), WalletError> {
        match record_of(self.data(), id, index) {
            Some((_, r)) if r.unanswered != unanswered => {}
            _ => return Ok(()),
        }
        self.update(|d| {
            if let Some(r) = record_mut(d, id, index) {
                r.unanswered = unanswered;
            }
            Ok(())
        })
    }

    /// Record that the user was told record `index` of purchase `id` is lost, so it
    /// is said once. Nothing is written when it was recorded already.
    pub(crate) fn note_told_lost(&mut self, id: &str, index: u32) -> Result<(), WalletError> {
        match record_of(self.data(), id, index) {
            Some((_, r)) if !r.told_lost => {}
            _ => return Ok(()),
        }
        self.update(|d| {
            if let Some(r) = record_mut(d, id, index) {
                r.told_lost = true;
            }
            Ok(())
        })
    }
}

/// The bytes of a saved claim.
fn hex_body(saved: &SavedClaim) -> Vec<u8> {
    hex::decode(&saved.body).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::expect;
    use psp_mint::scan::Received;
    use secp256k1::SecretKey;
    use sp_wire::air_request::delivery::{ClaimTerms, EXPIRY_NOTICE, Owed, build_record};
    use sp_wire::psp::{CLAIM_WINDOW_SECS, SignedOutput};
    use std::fs;
    use std::path::PathBuf;

    const FIRST: u64 = 1_800_000_000;
    const SECOND: u64 = 1_802_000_000;

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

    fn open_wallet(path: &std::path::Path) -> Result<Wallet, WalletError> {
        Wallet::open(path, "regtest")
    }

    fn wallet(name: &str) -> (Wallet, PathBuf) {
        let dir = scratch(name);
        let w = open_wallet(&dir.join("wallet.json")).unwrap();
        (w, dir)
    }

    /// What a PSP mint writes for a payment owed `due_units`: the fees are on
    /// (2 units prepaid for the two reads, 2 for the one write), so `due_units`
    /// is four below `value_units`.
    fn owed(txid: &str, due_units: u64) -> Outcome {
        Outcome::Owed(Owed {
            txid: txid.to_string(),
            paid_sats: 100_000,
            value_units: due_units + 4,
            terms: ClaimTerms {
                send: SEND_PURCHASE_CLAIM.to_string(),
                kind: KIND_PSP_CLAIM,
                due_units,
                read_prepaid_units: 2,
                write_prepaid_units: 2,
                window_secs: CLAIM_WINDOW_SECS,
                max_attempts: 3,
                on_expiry: EXPIRY_NOTICE.to_string(),
            },
        })
    }

    /// The sealed bytes of the PSP mint's record `index` for purchase `id`.
    fn sealed(w: &Wallet, psp: &DidSecretKey, id: &str, index: u32, outcome: &Outcome) -> Vec<u8> {
        let key = w.claim_keys().iter().find(|k| k.id == id).unwrap();
        let claim = ServiceDid::parse(&key.claim_did).unwrap();
        build_record(psp, &claim, index, outcome, FIRST)
            .unwrap()
            .sealed
    }

    /// A purchase whose record 0 is owed `due_units`, first read at `FIRST`.
    fn bought(w: &mut Wallet, psp: &DidSecretKey, due_units: u64) -> String {
        let id = w.build_psp_payload(&psp.public_key()).unwrap().id;
        let bytes = sealed(w, psp, &id, 0, &owed("aa", due_units));
        assert!(matches!(
            w.apply_delivery(&id, 0, &bytes, FIRST).unwrap(),
            Delivered::Stored(_)
        ));
        id
    }

    /// A PSP mint keyset with keys for 1 to 1024, and the rotation window that
    /// names it as current in epoch `epoch`.
    struct Keyset {
        sks: BTreeMap<Amount, SecretKey>,
        pks: BTreeMap<Amount, PublicKey>,
        window: Window,
    }

    impl Keyset {
        fn new(epoch: u64) -> Keyset {
            let sks: BTreeMap<Amount, SecretKey> = (0..=10)
                .map(|bit| {
                    (
                        Amount::from_units(1 << bit),
                        SecretKey::new(&mut rand::rngs::OsRng),
                    )
                })
                .collect();
            let pks: BTreeMap<Amount, PublicKey> = sks
                .iter()
                .map(|(a, sk)| (*a, sk.public_key(SECP256K1)))
                .collect();
            let window = Window {
                current_epoch: epoch,
                current_id: sp_wire::keyset::keyset_id(&pks),
                current_starts: None,
                previous_epoch: None,
                previous_id: None,
                period_hours: 24,
                now: FIRST,
            };
            Keyset { sks, pks, window }
        }

        /// The PSP mint "publishes" this keyset on its stream, as a wallet that
        /// follows the stream has read it: every key, by amount. The record's
        /// index is the epoch.
        fn publish(&self, w: &mut Wallet) {
            let keys: BTreeMap<u64, PublicKey> =
                self.pks.iter().map(|(a, k)| (a.units, *k)).collect();
            crate::keystream::testing::publish_keyset(
                w,
                "psp",
                "00",
                self.window.current_epoch as u32,
                self.window.current_epoch,
                &keys,
            );
        }

        fn listing(&self) -> KeysetsResponse {
            let id = self.window.current_id.clone();
            let mut keysets = BTreeMap::new();
            keysets.insert(
                id.clone(),
                self.pks.iter().map(|(a, k)| (a.units, *k)).collect(),
            );
            KeysetsResponse {
                current: id,
                previous: None,
                keysets,
            }
        }
    }

    /// What the PSP mint answers to the claim saved for record `index`: each output
    /// signed by this keyset.
    fn answer(w: &Wallet, id: &str, index: u32, ks: &Keyset) -> ClaimResponse {
        let (_, r) = record_of(w.data(), id, index).unwrap();
        answer_to(r.request.as_ref().unwrap(), r.due_units, ks)
    }

    /// What the PSP mint answers to the saved claim `saved` of a record owed
    /// `due_units`.
    fn answer_to(saved: &SavedClaim, due_units: u64, ks: &Keyset) -> ClaimResponse {
        ClaimResponse {
            keyset: saved.keyset.clone(),
            signatures: saved
                .outputs
                .iter()
                .map(|o| SignedOutput {
                    blind_nonce: o.blind_nonce.0.to_string(),
                    signature: bdhke::sign_message(
                        &ks.sks[&Amount::from_units(o.amount)],
                        &o.blind_nonce.0,
                    )
                    .to_string(),
                })
                .collect(),
            keysets: ks.listing(),
            issued_units: due_units,
            read_prepaid_units: 2,
            write_prepaid_units: 2,
        }
    }

    fn record_state(w: &Wallet, id: &str, index: u32) -> OwedClaim {
        record_of(w.data(), id, index).unwrap().1.clone()
    }

    /// The payload is the 33-byte claim DID and nothing else. Fails if the payload
    /// carries amounts, a keyset or notes again, or is not sealed to the PSP mint.
    #[test]
    fn the_payload_is_the_claim_did_alone() {
        let (mut w, dir) = wallet("payload");
        let mint = DidSecretKey::new();
        let built = w.build_psp_payload(&mint.public_key()).unwrap();
        let (kept, dropped) = psp_mint::seal::open_payloads(
            &mint,
            vec![Received {
                txid: "aa".into(),
                confirmations: 6,
                value_sats: 100_000,
                payload: Some(built.payload.clone()),
                block_time: Some(FIRST),
            }],
        );
        assert_eq!(dropped, 0);
        let plaintext = kept[0].payload.clone().unwrap();
        assert_eq!(plaintext.len(), 33);
        let decoded = payload::decode(&plaintext).unwrap();
        let key = &w.claim_keys()[0];
        assert_eq!(decoded.claim_did.to_hex(), key.claim_did);
        assert_eq!(built.id, hex::encode(Sha256::digest(&built.payload)));
        assert_eq!(key.id, built.id);
        assert_eq!(key.psp_did, mint.public_key().to_string());
        assert_eq!(key.next_index, 0);
        assert!(key.records.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The claim key is on disk before the payload is returned, and every purchase
    /// has a key of its own. Fails if the secret is saved after the return, is
    /// derived from the wallet's main DID, or is shared by two purchases.
    #[test]
    fn the_claim_key_is_saved_before_the_payload_is_returned_and_is_new_each_time() {
        let (mut w, dir) = wallet("saved");
        let mint = DidSecretKey::new();
        let first = w.build_psp_payload(&mint.public_key()).unwrap();
        let reopened = open_wallet(w.path()).unwrap();
        assert_eq!(reopened.claim_keys().len(), 1);
        assert_eq!(reopened.claim_keys()[0].id, first.id);
        assert_eq!(reopened.claim_keys()[0].claim_secret.len(), 64);
        assert_eq!(
            reopened.claim_keys()[0].claim_secret,
            w.claim_keys()[0].claim_secret
        );
        let second = w.build_psp_payload(&mint.public_key()).unwrap();
        assert_ne!(second.id, first.id);
        let keys = w.claim_keys();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0].claim_did, keys[1].claim_did);
        assert_ne!(keys[0].claim_secret, keys[1].claim_secret);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A good record is stored with the terms it states, a record read twice
    /// changes nothing, and a cell is never read out of order. Fails if the clock
    /// starts anywhere but the first read or `next_index` does not move.
    #[test]
    fn a_record_is_stored_once_with_its_own_terms_and_clock() {
        let (mut w, dir) = wallet("store");
        let psp = DidSecretKey::new();
        let id = w.build_psp_payload(&psp.public_key()).unwrap().id;
        let bytes = sealed(&w, &psp, &id, 0, &owed("bb", 797));
        let Delivered::Stored(r) = w.apply_delivery(&id, 0, &bytes, FIRST).unwrap() else {
            panic!("the record was not stored");
        };
        assert_eq!(
            (r.index, r.txid.as_str(), r.due_units, r.window_secs),
            (0, "bb", 797, 2_592_000)
        );
        assert_eq!((r.first_read_at, r.max_attempts), (FIRST, 3));
        assert_eq!(r.record_id.len(), 64);
        assert!(r.request.is_none() && !r.done && !r.told_lost);
        assert_eq!(w.claim_keys()[0].next_index, 1);
        assert_eq!(
            w.apply_delivery(&id, 0, &bytes, FIRST + 5).unwrap(),
            Delivered::AlreadyDone
        );
        assert_eq!(record_state(&w, &id, 0).first_read_at, FIRST);
        let e = expect::invalid(w.apply_delivery(&id, 2, &bytes, FIRST));
        assert!(e.contains("record 2 is read before record 1"), "{e}");
        let e = expect::unknown(w.apply_delivery("nope", 0, &bytes, FIRST));
        assert_eq!(e, "no purchase nope");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A record the PSP mint did not sign, one for another claim key, and one that
    /// asks for something else are refused with the wallet unchanged. Fails if the
    /// wallet stores a forged or foreign record.
    #[test]
    fn a_forged_or_foreign_record_is_a_mint_error_and_changes_nothing() {
        let (mut w, dir) = wallet("forged");
        let psp = DidSecretKey::new();
        let id = w.build_psp_payload(&psp.public_key()).unwrap().id;
        let other = w.build_psp_payload(&psp.public_key()).unwrap().id;
        let forger = DidSecretKey::new();
        let forged = sealed(&w, &forger, &id, 0, &owed("cc", 50));
        let e = expect::mint(w.apply_delivery(&id, 0, &forged, FIRST));
        assert!(e.contains("was not accepted"), "{e}");
        let foreign = sealed(&w, &psp, &other, 0, &owed("cc", 50));
        expect::mint(w.apply_delivery(&id, 0, &foreign, FIRST));
        let mut outcome = owed("cc", 50);
        let Outcome::Owed(o) = &mut outcome;
        o.terms.kind = 14;
        let wrong_kind = sealed(&w, &psp, &id, 0, &outcome);
        let e = expect::mint(w.apply_delivery(&id, 0, &wrong_kind, FIRST));
        assert!(e.contains("as kind 14"), "{e}");
        let Outcome::Owed(o) = &mut outcome;
        o.terms.kind = KIND_PSP_CLAIM;
        o.terms.send = "swap".into();
        let wrong_send = sealed(&w, &psp, &id, 0, &outcome);
        expect::mint(w.apply_delivery(&id, 0, &wrong_send, FIRST));
        assert_eq!(w.claim_keys()[0].next_index, 0);
        assert!(w.claim_keys()[0].records.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A cell that cannot be opened is skipped for good, and the next one is still
    /// read. A record with nothing due is stored done and told. Fails if a bad
    /// cell stops the key or a zero record is offered for a claim.
    #[test]
    fn a_bad_cell_is_skipped_and_a_record_with_nothing_due_is_done() {
        let (mut w, dir) = wallet("skip");
        let psp = DidSecretKey::new();
        let id = w.build_psp_payload(&psp.public_key()).unwrap().id;
        w.skip_record(&id, 1).unwrap();
        assert_eq!(w.claim_keys()[0].next_index, 0, "not the next cell");
        w.skip_record(&id, 0).unwrap();
        assert_eq!(w.claim_keys()[0].next_index, 1);
        let zero = sealed(&w, &psp, &id, 1, &owed("dd", 0));
        w.apply_delivery(&id, 1, &zero, FIRST).unwrap();
        let r = record_state(&w, &id, 1);
        assert!(r.done && r.told_lost);
        assert_eq!(w.claim_keys()[0].next_index, 2);
        assert!(w.open_claims(FIRST).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The lifetime of a key with two records (W3): each record has its own clock
    /// from its first read, a loss is told once, and the key goes with its last
    /// record. Fails if one clock serves both records, a loss is told twice, or
    /// the key goes before its last window closes.
    #[test]
    fn a_key_lives_until_its_last_record_window_closes() {
        let (mut w, dir) = wallet("lifetime");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let second = sealed(&w, &psp, &id, 1, &owed("bb", 100));
        w.apply_delivery(&id, 1, &second, SECOND).unwrap();
        let empty = w.build_psp_payload(&psp.public_key()).unwrap().id;

        // record 0 closes at 1_800_000_000 + 2_592_000
        assert!(w.close_expired(1_802_591_999).unwrap().is_empty());
        assert_eq!(w.open_claims(1_802_591_999).len(), 2);
        let lost = w.close_expired(1_802_592_000).unwrap();
        assert_eq!(
            lost,
            vec![Loss {
                id: id.clone(),
                index: 0,
                txid: "aa".into(),
                due_units: 797,
                kind: LossKind::Expired,
                window_ends: 1_802_592_000,
            }]
        );
        assert_eq!(
            lost[0].forfeited(),
            format!(
                "purchase {id}, record 0 (payment aa): expired. It was not claimed by 2027-02-14 08:00 UTC, when its window closed. The PSP mint keeps the payment: the funds are lost (797 PSP)"
            )
        );
        assert_eq!(w.claim_keys().len(), 2, "the key is kept for record 1");
        assert!(
            w.close_expired(1_802_592_000).unwrap().is_empty(),
            "told once"
        );

        // only record 1 can be claimed now
        let open = w.open_claims(1_803_000_000);
        assert_eq!(open.len(), 1);
        assert_eq!((open[0].index, open[0].due_units), (1, 100));
        assert_eq!(open[0].window_ends, 1_804_592_000);

        assert!(w.close_expired(1_804_591_999).unwrap().is_empty());
        assert_eq!(w.claim_keys().len(), 2);
        let lost = w.close_expired(1_804_592_000).unwrap();
        assert_eq!(lost.len(), 1);
        assert_eq!((lost[0].index, lost[0].due_units), (1, 100));
        assert_eq!(
            lost[0].forfeited(),
            format!(
                "purchase {id}, record 1 (payment bb): expired. It was not claimed by 2027-03-09 11:33 UTC, when its window closed. The PSP mint keeps the payment: the funds are lost (100 PSP)"
            )
        );
        // the key with records is gone; the key with none is not closed by
        // close_expired (only expire_unpaid drops it, after psp.unpaid_key_days)
        assert_eq!(w.claim_keys().len(), 1);
        assert_eq!(w.claim_keys()[0].id, empty);
        assert!(w.close_expired(1_900_000_000).unwrap().is_empty());
        assert_eq!(w.claim_keys().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// With record 0's window closed and record 1's open (W3), a claim is built
    /// for record 1 and none for record 0. Fails if the window is counted for the
    /// key and not for each record, in either direction.
    #[test]
    fn a_claim_is_built_only_for_a_record_whose_own_window_is_open() {
        let (mut w, dir) = wallet("own-window");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let second = sealed(&w, &psp, &id, 1, &owed("bb", 100));
        w.apply_delivery(&id, 1, &second, SECOND).unwrap();
        let ks = Keyset::new(5);
        ks.publish(&mut w);

        // 1_800_000_000 + 2_592_000 = 1_802_592_000 < 1_803_000_000
        let refused = w
            .build_claim(&id, 0, &ks.window, &ks.pks, 1_803_000_000)
            .unwrap_err()
            .to_string();
        assert!(
            refused
                .contains("the window closed at 2027-02-14 08:00 UTC, so nothing is built or sent"),
            "{refused}"
        );
        assert!(record_state(&w, &id, 0).request.is_none());

        // 1_802_000_000 + 2_592_000 = 1_804_592_000 > 1_803_000_000: 64 + 32 + 4 = 100
        let built = w
            .build_claim(&id, 1, &ks.window, &ks.pks, 1_803_000_000)
            .unwrap();
        let amounts: Vec<u64> = built
            .request
            .outputs
            .iter()
            .map(|o| o.amount.units)
            .collect();
        assert_eq!(amounts, vec![64, 32, 4]);
        assert_eq!((built.index, built.attempt), (1, 1));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A key with a saved claim nobody answered is not deleted when the window
    /// closes, is not reported lost, and is offered for one last resend; once the
    /// claim is given up it is reported and deleted. Fails if the key is deleted
    /// under an unanswered claim.
    #[test]
    fn an_unanswered_saved_claim_keeps_the_key_past_the_window() {
        let (mut w, dir) = wallet("unanswered");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let after = FIRST + CLAIM_WINDOW_SECS;
        assert!(w.close_expired(after).unwrap().is_empty());
        assert_eq!(w.claim_keys().len(), 1);
        assert_eq!(w.air_requests().len(), 1);
        assert_eq!(
            w.expired_claims(after),
            vec![(id.clone(), 0, psp.public_key().to_string())]
        );
        assert!(w.expired_claims(after - 1).is_empty());
        // a key whose last resend could not be sent is left for a later start
        w.give_up_claim(&id, 0).unwrap();
        assert!(w.air_requests().is_empty());
        let told = w
            .close_expired_keeping(after, std::slice::from_ref(&id))
            .unwrap();
        assert_eq!(told.len(), 1);
        assert_eq!((told[0].index, told[0].due_units), (0, 797));
        assert_eq!(w.claim_keys().len(), 1, "kept, as asked");
        let lost = w.close_expired(after).unwrap();
        assert!(lost.is_empty(), "already told above");
        assert!(w.claim_keys().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The claim for 797 units is the binary split 512+256+16+8+4+1, signed by the
    /// claim key over the digest, saved with its AIR request before anything is
    /// sent. Fails if the outputs are not the binary digits of `due_units`, the
    /// signature is over something else, or the claim is not saved.
    #[test]
    fn a_claim_is_the_binary_split_signed_by_the_claim_key_and_saved() {
        let (mut w, dir) = wallet("build");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        let built = w
            .build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        // 512 + 256 + 16 + 8 + 4 + 1 = 797
        let amounts: Vec<u64> = built
            .request
            .outputs
            .iter()
            .map(|o| o.amount.units)
            .collect();
        assert_eq!(amounts, vec![512, 256, 16, 8, 4, 1]);
        assert_eq!(amounts.iter().sum::<u64>(), 797);
        assert_eq!(built.attempt, 1);
        assert_eq!(built.request.keyset, ks.window.current_id);
        let psp_did = ServiceDid::parse(&psp.public_key().to_string()).unwrap();
        assert_eq!(built.hash, built.request.hash(&psp_did));
        SECP256K1
            .verify_schnorr(
                &built.request.signature,
                &built.request.digest(&psp_did),
                &built.request.claim_did.x_only(),
            )
            .unwrap();
        assert_eq!(
            built.request.claim_did.to_hex(),
            w.claim_keys()[0].claim_did
        );
        assert_eq!(
            hex::encode(built.request.record_id),
            record_state(&w, &id, 0).record_id
        );
        assert_eq!(serde_json::to_vec(&built.request).unwrap(), built.body);

        // on disk before it is sent, with the request that carries it
        let again = open_wallet(w.path()).unwrap();
        let r = record_state(&again, &id, 0);
        assert_eq!(r.attempts, 1);
        let saved = r.request.unwrap();
        assert_eq!(saved.body, hex::encode(&built.body));
        assert_eq!((saved.epoch, saved.outputs.len()), (5, 6));
        assert_eq!(again.air_requests().len(), 1);
        let a = &again.air_requests()[0];
        assert_eq!(a.kind, KIND_PSP_CLAIM);
        assert_eq!(a.r, again.claim_keys()[0].claim_secret);
        assert_eq!(a.body_hash, crate::air::body_hash(&built.body));
        let send = again.claim_to_send(&id, 0).unwrap();
        assert_eq!(send.body, built.body);
        assert_eq!(send.keyset, ks.window.current_id);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A saved claim on the current keyset is never rebuilt, a claim on a newer
    /// keyset is built (and replaces the old request) until `max_attempts`, and
    /// never beyond. Fails if a resend rebuilds, or a fourth claim is built.
    #[test]
    fn a_claim_is_rebuilt_only_for_a_new_keyset_and_never_beyond_max_attempts() {
        let (mut w, dir) = wallet("attempts");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let first = Keyset::new(5);
        first.publish(&mut w);
        w.build_claim(&id, 0, &first.window, &first.pks, FIRST + 10)
            .unwrap();
        let e = expect::invalid(w.build_claim(&id, 0, &first.window, &first.pks, FIRST + 20));
        assert!(
            e.contains("still current. It is sent again as it is"),
            "{e}"
        );
        assert_eq!(record_state(&w, &id, 0).attempts, 1);

        let second = Keyset::new(6);
        second.publish(&mut w);
        let built = w
            .build_claim(&id, 0, &second.window, &second.pks, FIRST + 30)
            .unwrap();
        assert_eq!(built.attempt, 2);
        assert_eq!(w.air_requests().len(), 1, "the old request is replaced");
        let third = Keyset::new(7);
        third.publish(&mut w);
        assert_eq!(
            w.build_claim(&id, 0, &third.window, &third.pks, FIRST + 40)
                .unwrap()
                .attempt,
            3
        );
        let fourth = Keyset::new(8);
        fourth.publish(&mut w);
        let e = expect::invalid(w.build_claim(&id, 0, &fourth.window, &fourth.pks, FIRST + 50));
        assert!(
            e.contains("3 claim(s) were built already, and the PSP mint counts 3"),
            "{e}"
        );
        assert_eq!(record_state(&w, &id, 0).attempts, 3);
        assert_eq!(w.air_requests().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A claim is refused, and nothing saved, for a closed window, a done record,
    /// keys that do not hash to the keyset, a keyset without a key for an output,
    /// and an unknown record. Fails if any is built.
    #[test]
    fn a_claim_that_fails_a_check_is_not_saved() {
        let (mut w, dir) = wallet("refused");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        let e =
            expect::invalid(w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + CLAIM_WINDOW_SECS));
        assert!(
            e.contains("the window closed at 2027-02-14 08:00 UTC, so nothing is built or sent"),
            "{e}"
        );
        let other = Keyset::new(5);
        let e = expect::mint(w.build_claim(&id, 0, &ks.window, &other.pks, FIRST + 10));
        assert!(e.contains("are not those of its current keyset"), "{e}");
        // a keyset with no key for 512
        let mut short = Keyset::new(5);
        short.pks.remove(&Amount::from_units(512));
        short.window.current_id = sp_wire::keyset::keyset_id(&short.pks);
        let e = expect::mint(w.build_claim(&id, 0, &short.window, &short.pks, FIRST + 10));
        assert!(e.contains("has no key for 512 units"), "{e}");
        expect::unknown(w.build_claim("nope", 0, &ks.window, &ks.pks, FIRST + 10));
        expect::unknown(w.build_claim(&id, 9, &ks.window, &ks.pks, FIRST + 10));
        assert!(w.air_requests().is_empty());
        assert!(record_state(&w, &id, 0).request.is_none());
        assert_eq!(record_state(&w, &id, 0).attempts, 0);

        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let reply = answer(&w, &id, 0, &ks);
        w.apply_claim(&id, 0, &reply).unwrap();
        let next = Keyset::new(6);
        next.publish(&mut w);
        let e = expect::invalid(w.build_claim(&id, 0, &next.window, &next.pks, FIRST + 20));
        assert!(e.contains("nothing is left to claim"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The answer is applied once: six notes of 512, 256, 16, 8, 4 and 1 units
    /// (797), stamped with the keyset and the epoch of the claim, the record done,
    /// the request dropped. Fails if the notes are stamped with another epoch (a
    /// fresh note would be rolled), or an answer applied twice adds notes.
    #[test]
    fn an_answer_stores_notes_stamped_with_the_signing_epoch_and_applies_once() {
        let (mut w, dir) = wallet("apply");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let reply = answer(&w, &id, 0, &ks);
        let Applied::Settled(s) = w.apply_claim(&id, 0, &reply).unwrap() else {
            panic!("not settled");
        };
        // 512 + 256 + 16 + 8 + 4 + 1 = 797
        assert_eq!(s.units, 797);
        assert_eq!(s.claimed.len(), 6);
        let mut amounts: Vec<u64> = w.notes().iter().map(|n| n.amount).collect();
        amounts.sort_unstable();
        assert_eq!(amounts, vec![1, 4, 8, 16, 256, 512]);
        for n in w.notes() {
            assert_eq!(n.kind, Kind::Psp);
            assert_eq!(w.data().epochs[&n.id()], 5);
            assert_eq!(w.data().keysets[&n.id()], ks.window.current_id);
        }
        let r = record_state(&w, &id, 0);
        assert!(r.done && r.request.is_none());
        assert!(w.air_requests().is_empty());
        assert_eq!(w.apply_claim(&id, 0, &reply).unwrap(), Applied::AlreadyDone);
        assert_eq!(w.notes().len(), 6);
        // after a restart too
        let mut again = open_wallet(w.path()).unwrap();
        assert_eq!(
            again.apply_claim(&id, 0, &reply).unwrap(),
            Applied::AlreadyDone
        );
        assert_eq!(again.notes().len(), 6);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A bad answer stores nothing and keeps the saved claim. Fails if a wrong
    /// keyset, a wrong count, a swapped output, a short `issued_units`, keys that
    /// do not hash to the id, or a signature that is not a point is accepted.
    #[test]
    fn a_bad_answer_stores_nothing() {
        let (mut w, dir) = wallet("bad-answer");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let good = answer(&w, &id, 0, &ks);

        let mut wrong_keyset = good.clone();
        wrong_keyset.keyset = "ab".repeat(8);
        let e = expect::mint(w.apply_claim(&id, 0, &wrong_keyset));
        assert!(
            e.contains("it was signed by keyset abababababababab"),
            "{e}"
        );

        let mut short = good.clone();
        short.signatures.pop();
        let e = expect::mint(w.apply_claim(&id, 0, &short));
        assert!(e.contains("it has 5 signature(s) for 6 output(s)"), "{e}");

        let mut swapped = good.clone();
        swapped.signatures.swap(0, 1);
        let e = expect::mint(w.apply_claim(&id, 0, &swapped));
        assert!(e.contains("signature 0 is for another output"), "{e}");

        let mut under = good.clone();
        under.issued_units = 796;
        let e = expect::mint(w.apply_claim(&id, 0, &under));
        assert!(
            e.contains("it issued 796 units, the record says 797"),
            "{e}"
        );

        let mut forged_keys = good.clone();
        let other = Keyset::new(5);
        forged_keys.keysets.keysets.insert(
            good.keyset.clone(),
            other.listing().keysets.into_values().next().unwrap(),
        );
        let e = expect::mint(w.apply_claim(&id, 0, &forged_keys));
        assert!(e.contains("are not those of keyset"), "{e}");

        let mut not_a_point = good.clone();
        not_a_point.signatures[2].signature = "00".repeat(33);
        let e = expect::mint(w.apply_claim(&id, 0, &not_a_point));
        assert!(e.contains("signature 2: not a curve point"), "{e}");

        let mut unlisted = good.clone();
        unlisted.keysets.keysets.clear();
        let e = expect::mint(w.apply_claim(&id, 0, &unlisted));
        assert!(e.contains("does not carry the keys of keyset"), "{e}");

        assert!(w.notes().is_empty());
        let r = record_state(&w, &id, 0);
        assert!(!r.done && r.request.is_some());
        assert_eq!(w.air_requests().len(), 1);
        // the good answer still settles it
        assert!(matches!(
            w.apply_claim(&id, 0, &good).unwrap(),
            Applied::Settled(_)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// An answer for a record with no claim saved settles nothing, and an answer
    /// for a record the wallet does not have is `AlreadyDone`. Fails if notes are
    /// stored without a saved claim.
    #[test]
    fn an_answer_with_no_saved_claim_settles_nothing() {
        let (mut w, dir) = wallet("no-claim");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let reply = answer(&w, &id, 0, &ks);
        w.give_up_claim(&id, 0).unwrap();
        let e = expect::unknown(w.apply_claim(&id, 0, &reply));
        assert!(e.contains("no claim was built for record 0"), "{e}");
        assert_eq!(
            w.apply_claim("nope", 0, &reply).unwrap(),
            Applied::AlreadyDone
        );
        assert!(w.notes().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The note sizes (W6): 1, 2^40 and 2^63 are accepted; 0, 3 and 2^63-1 are
    /// refused; there is no largest size. Fails if a cap on the size comes back.
    #[test]
    fn a_note_size_is_valid_if_it_is_a_power_of_two() {
        for ok in [1u64, 2, 1 << 40, 1 << 63] {
            check_denomination(ok).unwrap();
            check_outputs(&[ok]).unwrap();
        }
        for bad in [0u64, 3, (1 << 63) - 1, u64::MAX] {
            let e = expect::invalid(check_denomination(bad));
            assert_eq!(
                e,
                format!("{bad} is not a PSP note size: use a power of two")
            );
        }
        let e = expect::invalid(check_outputs(&[]));
        assert_eq!(e, "a claim needs at least one output");
        let e = expect::invalid(check_outputs(&[4, 6]));
        assert_eq!(e, "6 is not a PSP note size: use a power of two");
    }

    /// The split of what is due: the binary digits, largest first, at most 64.
    #[test]
    fn the_split_is_the_binary_digits_of_what_is_due() {
        assert_eq!(split_due(0), Vec::<u64>::new());
        assert_eq!(split_due(1), vec![1]);
        // 512 + 256 + 16 + 8 + 4 + 1 = 797
        assert_eq!(split_due(797), vec![512, 256, 16, 8, 4, 1]);
        // 2^40 + 4 + 1
        assert_eq!(split_due((1 << 40) + 5), vec![1 << 40, 4, 1]);
        assert_eq!(split_due((1 << 63) + 1), vec![1 << 63, 1]);
        assert_eq!(split_due(u64::MAX).len(), 64);
    }

    /// Where an open record stands. Fails if a claim the PSP mint did not answer
    /// after every allowed attempt is still called `Sent`.
    #[test]
    fn an_open_claim_says_whether_it_is_due_sent_or_refused() {
        let (mut w, dir) = wallet("status");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let now = FIRST + 10;
        let open = w.open_claims(now);
        assert_eq!(open.len(), 1);
        assert_eq!(
            (open[0].status, open[0].attempts, open[0].max_attempts),
            (ClaimStatus::Due, 0, 3)
        );
        assert_eq!(open[0].psp, psp.public_key().to_string());
        assert_eq!((open[0].txid.as_str(), open[0].due_units), ("aa", 797));
        assert_eq!(open[0].window_ends, 1_802_592_000);
        for epoch in 5..8 {
            let ks = Keyset::new(epoch);
            ks.publish(&mut w);
            w.build_claim(&id, 0, &ks.window, &ks.pks, now).unwrap();
        }
        assert_eq!(w.open_claims(now)[0].status, ClaimStatus::Sent);
        w.note_unanswered(&id, 0, true).unwrap();
        assert_eq!(w.open_claims(now)[0].status, ClaimStatus::Refused);
        assert_eq!(w.open_claims(now)[0].attempts, 3);
        w.note_unanswered(&id, 0, false).unwrap();
        assert_eq!(w.open_claims(now)[0].status, ClaimStatus::Sent);
        assert!(!w.open_claims(now)[0].told_lost);
        w.note_told_lost(&id, 0).unwrap();
        w.note_told_lost(&id, 0).unwrap();
        assert!(w.open_claims(now)[0].told_lost);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The words of a loss, with the date and the units.
    #[test]
    fn a_refused_claim_is_told_with_its_attempts_date_and_units() {
        let (mut w, dir) = wallet("words");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let loss = w.refused_loss(&id, 0).unwrap();
        assert_eq!(loss.kind, LossKind::Refused);
        assert_eq!(
            loss.not_accepted(3),
            format!(
                "purchase {id}, record 0 (payment aa): refused. The PSP mint did not accept the claim (it answers an accepted claim only) after 3 attempt(s). Unless it answers by 2027-02-14 08:00 UTC, the payment (797 PSP) is lost"
            )
        );
        assert!(w.refused_loss(&id, 4).is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A purchase that was never paid can be forgotten; one that does not exist
    /// cannot.
    #[test]
    fn an_unpaid_purchase_can_be_discarded() {
        let (mut w, dir) = wallet("discard");
        let psp = DidSecretKey::new();
        let id = w.build_psp_payload(&psp.public_key()).unwrap().id;
        let e = expect::unknown(w.discard_purchase("nope"));
        assert_eq!(e, "no purchase nope");
        w.discard_purchase(&id).unwrap();
        assert!(w.claim_keys().is_empty());
        assert!(open_wallet(w.path()).unwrap().claim_keys().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A copy saved before a claim was settled is merged in after the key was
    /// closed and deleted: the key and its saved claim come back, the resend is
    /// answered from the PSP mint's stored answer, and none of the notes it names
    /// is added again, the spent ones nor the held ones. Fails if a spent note is
    /// re-added or the balance changes.
    #[test]
    fn a_stale_copy_resent_never_brings_back_spent_notes() {
        let (mut w, dir) = wallet("stale-copy");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let stale = w.snapshot();
        let reply = answer(&w, &id, 0, &ks);
        assert!(matches!(
            w.apply_claim(&id, 0, &reply).unwrap(),
            Applied::Settled(_)
        ));
        assert_eq!(w.notes().len(), 6);
        // spend the 512 and the 256 (they leave the wallet), keep the rest
        w.update(|d| {
            d.notes.retain(|n| n.amount < 256);
            Ok(())
        })
        .unwrap();
        let held = |w: &Wallet| -> u64 { w.notes().iter().map(|n| n.amount).sum() };
        assert_eq!(held(&w), 29);
        // the record is done and its window closes: the key is deleted
        assert!(
            w.close_expired(FIRST + CLAIM_WINDOW_SECS)
                .unwrap()
                .is_empty()
        );
        assert!(w.claim_keys().is_empty());

        w.merge_from(&stale).unwrap();
        let r = record_state(&w, &id, 0);
        assert!(
            !r.done && r.request.is_some(),
            "the stale copy's claim is back"
        );
        assert_eq!(w.notes().len(), 4);
        // the resend gets the stored answer: the same signatures
        assert_eq!(answer(&w, &id, 0, &ks), reply);
        assert_eq!(w.apply_claim(&id, 0, &reply).unwrap(), Applied::AlreadyDone);
        assert_eq!(held(&w), 29, "no spent note is back");
        assert_eq!(w.notes().len(), 4, "no held note is twice");
        assert_eq!(w.balance(), {
            let mut again = open_wallet(w.path()).unwrap();
            assert_eq!(
                again.apply_claim(&id, 0, &reply).unwrap(),
                Applied::AlreadyDone
            );
            again.balance()
        });
        let r = record_state(&w, &id, 0);
        assert!(r.done && r.request.is_none() && r.others.is_empty());
        assert!(w.air_requests().is_empty());
        // and the key is closed again
        assert!(
            w.close_expired(FIRST + CLAIM_WINDOW_SECS)
                .unwrap()
                .is_empty()
        );
        assert!(w.claim_keys().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A claim key with no record is dropped `days` after it was made, only when
    /// the pickup found no record for it (`checked`), and is said once as unpaid.
    /// Fails if it is dropped a second early, kept after, dropped with 0 days, or
    /// a key with a record or one not checked is dropped.
    #[test]
    fn an_unpaid_key_expires_after_its_days_and_never_with_zero() {
        let (mut w, dir) = wallet("unpaid-expiry");
        let psp = DidSecretKey::new();
        let unpaid = w.build_psp_payload(&psp.public_key()).unwrap().id;
        let paid = bought(&mut w, &psp, 797);
        let unread = w.build_psp_payload(&psp.public_key()).unwrap().id;
        let made = w.claim_keys().iter().map(|k| k.created_at).max().unwrap();
        assert!(made > 0);
        let ends = |id: &str| {
            w.claim_keys()
                .iter()
                .find(|k| k.id == id)
                .unwrap()
                .created_at
                + DEFAULT_UNPAID_KEY_DAYS * DAY_SECS
        };
        let at = ends(&unpaid);
        let checked = vec![unpaid.clone(), paid.clone()];
        assert_eq!(DEFAULT_UNPAID_KEY_DAYS, 90);

        assert!(w.expire_unpaid(at - 1, 90, &checked).unwrap().is_empty());
        assert_eq!(w.claim_keys().len(), 3, "kept before 90 days");
        assert!(
            w.expire_unpaid(at + 10 * DAY_SECS, 0, &checked)
                .unwrap()
                .is_empty()
        );
        assert!(w.expire_unpaid(u64::MAX, 0, &checked).unwrap().is_empty());
        assert_eq!(w.claim_keys().len(), 3, "0 keeps it for ever");

        let lost = w.expire_unpaid(at, 90, &checked).unwrap();
        assert_eq!(
            lost,
            vec![Loss {
                id: unpaid.clone(),
                index: 0,
                txid: String::new(),
                due_units: 0,
                kind: LossKind::Unpaid,
                window_ends: at,
            }]
        );
        assert_eq!(lost[0].said(), lost[0].unpaid());
        assert!(lost[0].unpaid().starts_with(&format!(
            "purchase {unpaid}: the PSP mint has written no record for it, and it expired at "
        )));
        assert!(lost[0].unpaid().contains("the funds are lost"));
        let ids: Vec<&str> = w.claim_keys().iter().map(|k| k.id.as_str()).collect();
        assert!(!ids.contains(&unpaid.as_str()));
        assert!(
            ids.contains(&paid.as_str()),
            "a key with a record keeps its rules"
        );
        assert!(ids.contains(&unread.as_str()), "a key not read is kept");
        assert!(
            w.expire_unpaid(at, 90, &checked).unwrap().is_empty(),
            "said once"
        );
        assert_eq!(open_wallet(w.path()).unwrap().claim_keys().len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Two copies built two claims for one record and were merged: both are kept.
    /// The PSP mint signed the other one: applying it settles the record, drops
    /// the main one and every AIR request, and nothing is told lost. A refused
    /// other is dropped alone. Fails if a saved claim is lost in the merge, the
    /// record is done before one is applied, or a loss is said.
    #[test]
    fn two_merged_claims_for_one_record_settle_once_with_the_signed_one() {
        let (mut a, dir) = wallet("two-claims");
        let psp = DidSecretKey::new();
        let id = bought(&mut a, &psp, 797);
        let b_path = dir.join("copy.json");
        fs::copy(a.path(), &b_path).unwrap();
        let mut b = open_wallet(&b_path).unwrap();
        let ks = Keyset::new(5);
        ks.publish(&mut a);
        ks.publish(&mut b);
        a.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        b.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 20)
            .unwrap();
        let a_claim = record_state(&a, &id, 0).request.unwrap();
        let b_claim = record_state(&b, &id, 0).request.unwrap();
        assert_ne!(a_claim.hash, b_claim.hash);

        // the same copy twice is one claim
        let mut same = open_wallet(a.path()).unwrap();
        same.merge_from(&a.snapshot()).unwrap();
        assert!(record_state(&same, &id, 0).others.is_empty());

        a.merge_from(&b.snapshot()).unwrap();
        a.merge_from(&b.snapshot()).unwrap();
        let r = record_state(&a, &id, 0);
        assert_eq!(r.request.as_ref().unwrap().hash, a_claim.hash);
        assert_eq!(r.others, vec![b_claim.clone()], "both kept, once each");
        assert!(!r.done);
        assert_eq!(a.other_claims(&id, 0), vec![b_claim.hash.clone()]);
        assert!(a.claim_to_send_of(&id, 0, Some(&b_claim.hash)).is_ok());

        // the PSP mint signed b's claim: it settles the record
        let reply = answer_to(&b_claim, 797, &ks);
        let Applied::Settled(s) = a
            .apply_claim_to(&id, 0, Some(&b_claim.hash), &reply)
            .unwrap()
        else {
            panic!("not settled");
        };
        assert_eq!(s.units, 797);
        assert_eq!(a.notes().iter().map(|n| n.amount).sum::<u64>(), 797);
        let r = record_state(&a, &id, 0);
        assert!(r.done && r.request.is_none() && r.others.is_empty());
        assert!(a.other_claims(&id, 0).is_empty());
        assert!(a.air_requests().is_empty());
        assert_eq!(
            a.apply_claim(&id, 0, &answer_to(&a_claim, 797, &ks))
                .unwrap(),
            Applied::AlreadyDone
        );
        assert!(
            a.close_expired(FIRST + CLAIM_WINDOW_SECS)
                .unwrap()
                .is_empty(),
            "nothing lost"
        );

        // a refused other is dropped and the main one is kept
        let mut c = open_wallet(&b_path).unwrap();
        c.merge_from(&same.snapshot()).unwrap();
        let other = c.other_claims(&id, 0);
        assert_eq!(other.len(), 1);
        c.drop_other_claim(&id, 0, &other[0]).unwrap();
        let r = record_state(&c, &id, 0);
        assert!(r.others.is_empty() && r.request.is_some() && !r.done);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A claim is built only on a key set the PSP published: on keys it has not
    /// published (yet) no claim is built, the wallet writes and sends nothing,
    /// and the error is one to retry, not a mismatch (it may be published in a
    /// moment).
    #[test]
    fn a_claim_is_not_built_on_a_key_set_the_psp_did_not_publish() {
        let (mut w, dir) = wallet("claim-unpublished");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        // The PSP published a key set, and it is another one.
        Keyset::new(6).publish(&mut w);
        let why = crate::keystream::testing::retryable(w.build_claim(
            &id,
            0,
            &ks.window,
            &ks.pks,
            FIRST + 10,
        ));
        assert!(
            why.contains(&format!(
                "the PSP mint has not published key set {}",
                ks.window.current_id
            )),
            "{why}"
        );
        assert!(w.air_requests().is_empty());
        assert!(record_state(&w, &id, 0).request.is_none());
        assert_eq!(record_state(&w, &id, 0).attempts, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// An answer is stored only if its key set is still one of the last two the
    /// PSP published: the key set of a claim the PSP has rotated away from twice
    /// since the claim was built is not stored from, and the claim is kept. It is
    /// an error to retry, not a mismatch: the wallet cannot tell it from a key set
    /// not published yet.
    #[test]
    fn an_answer_under_a_key_set_two_rotations_old_is_not_stored() {
        let (mut w, dir) = wallet("claim-old");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let reply = answer(&w, &id, 0, &ks);

        // One rotation on: the previous key set is still accepted ...
        Keyset::new(6).publish(&mut w);
        let before = crate::keystream::testing::held(&w);
        // ... two on, it is not.
        Keyset::new(7).publish(&mut w);
        let before_two = crate::keystream::testing::held(&w);
        assert_ne!(before, before_two, "the stream moved");
        let why = crate::keystream::testing::retryable(w.apply_claim(&id, 0, &reply));
        assert!(
            why.contains("the PSP mint has not published key set"),
            "{why}"
        );
        assert!(w.notes().is_empty(), "nothing from the answer was stored");
        let r = record_state(&w, &id, 0);
        assert!(!r.done && r.request.is_some(), "the claim is kept");
        assert_eq!(crate::keystream::testing::held(&w), before_two);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The previous key set is accepted: an answer to a claim built one rotation
    /// ago is stored.
    #[test]
    fn an_answer_under_the_previous_key_set_is_stored() {
        let (mut w, dir) = wallet("claim-previous");
        let psp = DidSecretKey::new();
        let id = bought(&mut w, &psp, 797);
        let ks = Keyset::new(5);
        ks.publish(&mut w);
        w.build_claim(&id, 0, &ks.window, &ks.pks, FIRST + 10)
            .unwrap();
        let reply = answer(&w, &id, 0, &ks);
        Keyset::new(6).publish(&mut w);
        let Applied::Settled(s) = w.apply_claim(&id, 0, &reply).unwrap() else {
            panic!("not settled");
        };
        assert_eq!(s.units, 797);
        fs::remove_dir_all(&dir).unwrap();
    }
}
