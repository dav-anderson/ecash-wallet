//! The keys the mints published, and the check of every key a mint signs with
//! against them (ROADMAP item 31, finding P2-04, the mint fingerprinting attack).
//!
//! **Why.** A mint that signs one user's outputs with a key it uses for that user
//! alone, or gives one user a redeemable day nobody else has, can recognise that
//! user's notes when they come back. A wallet can only see it if every user can
//! see the same keys. So each mint publishes its keys on AIR, under its own DID
//! (`sp_wire::air_request::stream`), and the wallet checks, **before it stores
//! anything from a reply**, that each key the mint used for an output is the key it
//! published. The check is one function for every place a mint's reply is turned
//! into notes ([`Site`]), and it does not ask the mint anything: it reads what the
//! wallet has read of the streams.
//!
//! **What the wallet keeps.** For each mint it follows ([`MintStream`], saved in
//! the wallet file under `key_streams`): the index of the next record to read, the
//! last two key sets of a PSP or FSP mint (the current and the previous one), the
//! last two control records of the ESP (its maturity rule `m` and which key sets
//! are live), and the 64 keys of each (key set, service, day) the wallet has
//! needed for an ESP check. Days no note or request needs any more are dropped.
//!
//! **How it reads** ([`Wallet::start_key_feed`]). For each mint the wallet holds
//! notes from or has a request pending with, a thread reads the stream: at the
//! first start the latest record (and the one before), after a restart forward
//! from the saved index to catch up, then it holds a read on the next, empty cell.
//! AIR pushes the record when the mint writes it, and the thread holds a read on
//! the one after. Each followed mint costs one held read, on an AIR session of its
//! own (the AIR server closes a session at the 257th, so the limit is far off):
//! a wallet needs one for the PSP, one for the ESP and one for each FSP mint it
//! holds notes from, and a read of an ESP day adds one for as long as it waits.
//! The thread stops when the wallet holds no more notes from the mint and has
//! nothing pending with it. An ESP day is read
//! when a check needs it, by `sp_wire::air_request::stream` (one read of the
//! day's first record, then the parts of the service's bucket), not asked of the
//! mint.
//!
//! **Never an honest mint.** A mismatch is reported only when the wallet holds
//! published records, read fresh, that disagree with the reply: keys under the
//! key set the reply names that are not its keys (a key set's ID is the hash of
//! its keys, and a stream cell is written once), an ESP day's keys read again
//! from AIR that are not the ones signed with, or a redeemable day outside what
//! the ESP's control records, read again from AIR (and waited on), allow. A
//! record that is not there after the wait (a key set, a control record, a day
//! not published yet, a stream that could not be read, a fresh read that failed)
//! is a [`WalletError::Mint`] to retry: nothing is stored, the pending request is
//! kept as it was, and no warning is printed.
//!
//! **Not published at all.** A record that is missing stays an error to retry
//! only while it could still be a late write. Before deciding, the whole stream
//! is read from its first record (a reply stored from more than two rotations
//! back names a key set the wallet no longer keeps: it is found there and
//! checked). The first time a stream read to its end lacks the record, the
//! wallet notes the time and the stream's end in the wallet file (`unpublished`,
//! [`Unpublished`]), so a restart does not reset either. The record is then
//! called not published, a key check failure ([`Failed::Unpublished`]), when:
//!
//! 1. the stream already holds records written after the point where the record
//!    should have appeared: 4 new key-set records since that first read for a
//!    PSP or FSP key set (a pass of the writer writes at most the two live key
//!    sets, so the pass in flight when the mint signed accounts for two, and the
//!    next pass writes every live key set it lacks), or 2 new control records
//!    for an ESP key set (a pass writes at most one). A key set that was
//!    retired before any pass could write it is never written after, so this
//!    only ever calls a record missing that is not coming. A day's keys and a
//!    first control record have no such order to go by (the parts of a day are
//!    not ordered against anything the wallet reads, and an empty control
//!    stream has no later record), so for them only (2) applies;
//! 2. or `UNPUBLISHED_BACKSTOP_SECS` (a day, fixed: no setting, no API
//!    field, so neither a user nor an app can make the wallet more or less
//!    willing to call a mint dishonest) have passed since that first read, and
//!    a read made now still lacks it.
//!
//! The record is looked for again on every try, so an honest late write is
//! taken in whenever it comes before that.
//!
//! **A mismatch** ([`KeyMismatch`], [`WalletError::KeyMismatch`]) stores nothing
//! from the reply, keeps the notes and the pending request, and prints a warning
//! that names the mint, what failed and where. For an FSP mint, with
//! `fsp.blacklist_on_key_mismatch` on ([`KeyPolicy`]), the wallet also blacklists
//! the mint and drops its notes. A PSP or ESP mint is never blacklisted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sp_wire::ServiceDid;
use sp_wire::air_request::client::{self, Event, ServerRef, block_on_new_runtime};
use sp_wire::air_request::delivery;
use sp_wire::air_request::stream::{
    self, Cell, ControlRecord, DayCell, DayRecord, ESP_KEYS_PER_SERVICE, KeysetRecord,
};

use crate::Wallet;
use crate::config::{AirSettings, Party};
use crate::error::WalletError;
use crate::store::{BlacklistedMint, StoredNote};

/// Seconds in a day, the unit of the ESP's redeemable-after days.
const SECONDS_PER_DAY: u64 = 86_400;

/// How many key sets of a PSP or FSP mint the wallet keeps: the current and the
/// previous one.
const KEEP_KEYSETS: usize = 2;

/// How many control records of the ESP the wallet keeps: the latest, and the one
/// before it (the maturity rule `m` before the last change).
const KEEP_CONTROLS: usize = 2;

/// The most entries the blacklist has by default (`fsp.blacklist_max`).
pub const DEFAULT_BLACKLIST_MAX: u64 = 1000;

/// The most `fsp.blacklist_max` can be.
pub const MAX_BLACKLIST_MAX: u64 = 1_000_000;

/// How long a record a reply was signed under may be missing from its mint's
/// stream, from the first time this wallet read the stream to its end without
/// it, before it is called not published (a key check failure): a day. Fixed,
/// with no setting and no API field: whether a mint is flagged must not be
/// something a user or an app can tune. A mint's writer ticks every 5 s and
/// retries every 30 s, so an honest one is seconds to minutes late.
pub(crate) const UNPUBLISHED_BACKSTOP_SECS: u64 = 86_400;

/// New key-set records after which a key set still missing is not published:
/// two from the writer's pass in flight when the mint signed, and two from the
/// next pass, which writes every live key set the stream lacks.
const NEWER_KEYSETS: u32 = 2 * KEEP_KEYSETS as u32;

/// New control records after which an ESP key set still missing is not
/// published: one from the pass in flight, one from the next.
const NEWER_CONTROLS: u32 = 2;

/// How many key sets older than the last two the wallet keeps after a check
/// found them on the stream.
const KEEP_FOUND: usize = 8;

/// The clock slack the ESP day check allows at each end of an exchange's window
/// (the day of the first send less it, to the day of the reply plus it): 5
/// minutes, for the wallet's and the ESP's clocks to differ by. Fixed, and not
/// `air.max_skew_secs` (which only decides how old a reply may be before AIR
/// drops it): a smaller slack would flag an honest ESP whose clock is a little
/// off near midnight, a larger one would let a wrong day through.
pub(crate) const DAY_SKEW_SECS: u64 = 300;

/// How long a key check waits for a record its mint has not written yet, and
/// how long the ESP day check waits for a new control record before it calls the
/// day a mismatch: 45 s. A mint's writer ticks every 5 s and retries a failed
/// write 30 s later, so an honest record is at most 35 s late after one failed
/// write; the 10 s more is one read at [`KEY_READ_MIN_TIMEOUT_SECS`]. Fixed, and
/// not `air.reply_wait_secs` (which only paces AIR requests): a shorter wait
/// would call an honest ESP's day wrong before its control record could arrive.
/// A record still missing at the end is an error to retry, not a mismatch.
/// Without a key feed nothing can arrive while the check waits, so it does not.
pub(crate) const KEY_CHECK_WAIT_SECS: u64 = 45;

/// The least time a key-check read of a stream (the threads that follow the
/// streams, the whole-stream read, the reread, an ESP day) is given before it
/// fails: 10 s, the default of `air.timeout_secs`, a connection and a read on a
/// healthy server with room to spare. A read that fails is an error to retry
/// and starts no backstop, so a very short `air.timeout_secs` would otherwise
/// keep a mint that never publishes from ever being flagged. A longer
/// `air.timeout_secs` is used as it is (it only makes the wallet more patient).
pub(crate) const KEY_READ_MIN_TIMEOUT_SECS: u64 = 10;

/// The timeout of a key-check read: `air.timeout_secs`, at least
/// [`KEY_READ_MIN_TIMEOUT_SECS`].
pub(crate) fn key_read_timeout(air: &AirSettings) -> u64 {
    air.timeout_secs.max(KEY_READ_MIN_TIMEOUT_SECS)
}

// ---------------------------------------------------------------- what is kept

/// One key set a PSP or FSP mint published: record `index` of its stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedKeyset {
    /// The record's place in the stream.
    pub index: u32,
    /// The mint's epoch of this key set.
    pub epoch: u64,
    /// The key set's ID (`sp_wire::keyset::keyset_id` over every key).
    pub id: String,
    /// Every key of the key set, by amount in units.
    pub keys: BTreeMap<u64, PublicKey>,
}

/// One control record the ESP published: record `index` of its control stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedControl {
    /// The record's place in the stream.
    pub index: u32,
    /// The ESP's maturity rule `m`: a new exchange's notes are redeemable after
    /// the day of the exchange plus this many days.
    pub maturity_days: u64,
    /// The epoch of the generation that signs new exchanges.
    pub current_epoch: u64,
    /// That generation's key-set ID, as hex.
    pub current_id: String,
    /// The generation before it, while it is live, as hex.
    pub previous_id: Option<String>,
}

/// What the wallet has read of one mint's stream.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintStream {
    /// The DID of the mint the stream is under, as hex. A stream saved under
    /// another DID than the one now configured is dropped.
    pub did: String,
    /// The index of the next record to read: the records below it were read.
    pub next: u32,
    /// The last two key sets of a PSP or FSP mint, oldest first.
    pub keysets: Vec<PublishedKeyset>,
    /// The last two control records of the ESP, oldest first.
    pub controls: Vec<PublishedControl>,
    /// The 64 keys of a (key set, service, day) of the ESP, by
    /// `<key set ID>:<service DID>:<day>`, in the order 2^0 to 2^63.
    pub days: BTreeMap<String, Vec<PublicKey>>,
    /// Key sets older than the last two that a check found when it read the
    /// whole stream (a reply stored from further back), newest find last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub found: Vec<PublishedKeyset>,
    /// Every ESP key set a control record the wallet read named live (current
    /// or previous): published, so its days are checked even after it retired.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub generations: BTreeSet<String>,
}

/// When the wallet first read a mint's stream to its end without a record a
/// reply needs, in the wallet file under `unpublished` (see "Not published at
/// all" above).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unpublished {
    /// Unix seconds, this wallet's clock.
    pub since: u64,
    /// The stream's end then (the index of its first empty cell), for a key set
    /// or a control record; `None` for a day.
    pub end: Option<u32>,
}

/// A record as [`MintStream`] keeps it.
fn published_keyset(index: u32, record: &KeysetRecord) -> PublishedKeyset {
    PublishedKeyset {
        index,
        epoch: record.epoch,
        id: record.id(),
        keys: record
            .keys
            .iter()
            .map(|(amount, key)| (amount.units, *key))
            .collect(),
    }
}

/// A control record as [`MintStream`] keeps it.
fn published_control(record: &ControlRecord) -> PublishedControl {
    PublishedControl {
        index: record.index,
        maturity_days: record.maturity_days,
        current_epoch: record.current.epoch,
        current_id: hex::encode(record.current.id),
        previous_id: record.previous.map(|p| hex::encode(p.id)),
    }
}

/// The name of a (key set, service, day) in [`MintStream::days`].
pub fn day_key(generation: &str, service: &ServiceDid, day: u64) -> String {
    format!("{generation}:{}:{day}", service.to_hex())
}

impl MintStream {
    fn apply_keyset(&mut self, index: u32, record: &KeysetRecord) {
        self.take_keyset(published_keyset(index, record));
    }

    fn take_keyset(&mut self, keyset: PublishedKeyset) {
        let index = keyset.index;
        self.keysets.retain(|k| k.index != index);
        self.keysets.push(keyset);
        self.keysets.sort_by_key(|k| k.index);
        while self.keysets.len() > KEEP_KEYSETS {
            self.keysets.remove(0);
        }
        self.next = self.next.max(index.saturating_add(1));
    }

    fn apply_control(&mut self, record: &ControlRecord) {
        self.take_control(published_control(record));
    }

    fn take_control(&mut self, control: PublishedControl) {
        let index = control.index;
        self.generations.insert(control.current_id.clone());
        if let Some(previous) = &control.previous_id {
            self.generations.insert(previous.clone());
        }
        self.controls.retain(|c| c.index != index);
        self.controls.push(control);
        self.controls.sort_by_key(|c| c.index);
        while self.controls.len() > KEEP_CONTROLS {
            self.controls.remove(0);
        }
        self.next = self.next.max(index.saturating_add(1));
    }

    fn keyset(&self, id: &str) -> Option<&PublishedKeyset> {
        self.keysets
            .iter()
            .chain(self.found.iter())
            .find(|k| k.id == id)
    }
}

// ---------------------------------------------------------------- the check

/// Where a mint's reply is turned into notes: each is a place the shared check
/// runs before anything is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Site {
    /// `Wallet::finish_exchange`: the ESP's keys and the redeemable day of a new
    /// exchange.
    FinishExchange,
    /// `Wallet::finish_fsp_issue`.
    FinishFspIssue,
    /// `Wallet::finish_fsp_spend`.
    FinishFspSpend,
    /// `Wallet::finish_rollover`, of the PSP or of the ESP.
    FinishRollover,
    /// `Wallet::finish_redemption`, a refund output.
    RedeemRefund,
    /// `Wallet::finish_redemption`, a decline output.
    RedeemDecline,
    /// `Wallet::apply_claim`: the keys in the PSP mint's answer to a claim.
    ApplyClaim,
    /// `Wallet::build_claim`: the keys the wallet is about to build a claim on.
    BuildClaim,
}

impl Site {
    /// The name of the place, as the warning gives it.
    pub fn name(self) -> &'static str {
        match self {
            Site::FinishExchange => "finish_exchange",
            Site::FinishFspIssue => "finish_fsp_issue",
            Site::FinishFspSpend => "finish_fsp_spend",
            Site::FinishRollover => "finish_rollover",
            Site::RedeemRefund => "finish_redemption (refund)",
            Site::RedeemDecline => "finish_redemption (decline)",
            Site::ApplyClaim => "apply_claim",
            Site::BuildClaim => "build_claim",
        }
    }
}

/// What failed in a check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failed {
    /// The key for this amount is not the key the mint published.
    Key {
        /// The amount in units.
        amount: u64,
    },
    /// The redeemable day of a new exchange is outside the days the mint's
    /// published rule allows.
    Day {
        /// The day the mint gave.
        day: u64,
        /// The earliest day allowed, with the latest maturity rule `m`.
        from: u64,
        /// The latest day allowed, with the latest maturity rule `m`.
        to: u64,
        /// The maturity rules the mint published last, latest first.
        rules: Vec<u64>,
    },
    /// The reply was signed under a record (a key set, an ESP day's keys, an ESP
    /// control record) that the mint's stream, read to its end, does not hold,
    /// and it is past the point where a late write could explain it.
    Unpublished {
        /// What is not published, as the warning names it.
        record: String,
        /// Why it is not a late write.
        by: UnpublishedBy,
    },
}

/// Why a record missing from a mint's stream is not a late write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnpublishedBy {
    /// The stream holds `end - from` records written since the wallet first read
    /// it to its end without the record (at index `from`), at least `needed`:
    /// more than the mint's writer could have written before it.
    NewerRecords {
        /// The stream's end at that first read.
        from: u32,
        /// Its end now.
        end: u32,
        /// How many newer records make it final.
        needed: u32,
    },
    /// `secs` (the fixed backstop, a day) have passed since the wallet first
    /// read the stream without it, at `since`.
    Backstop {
        /// Unix seconds, this wallet's clock.
        since: u64,
        /// The backstop that was applied, in seconds.
        secs: u64,
    },
}

impl fmt::Display for UnpublishedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnpublishedBy::NewerRecords { from, end, needed } => write!(
                f,
                "its stream already holds {} record(s) written after this wallet first read it to its end without it (records {from} to {}), and a writer that was only late writes it within {needed}",
                end.saturating_sub(*from),
                end.saturating_sub(1)
            ),
            UnpublishedBy::Backstop { since, secs } => write!(
                f,
                "it was still not on its stream {secs} s after this wallet first read the stream without it (at {since}, unix seconds)"
            ),
        }
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failed::Key { amount } => write!(
                f,
                "signed the output of {amount} unit(s) with a KEY that is not the key it published"
            ),
            Failed::Day {
                day,
                from,
                to,
                rules,
            } => write!(
                f,
                "gave a redeemable DAY {day}, outside the days it allows a new exchange ({from} to {to}; its published maturity rule(s) m = {})",
                rules
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Failed::Unpublished { record, by } => write!(
                f,
                "signed under {record}, which it has NOT PUBLISHED on AIR: {by}"
            ),
        }
    }
}

/// A key check that failed: which mint, what and where. Nothing from the reply
/// was stored. The notes and the pending request were kept, unless the mint is
/// an FSP mint that was blacklisted (`blacklisted`): then they were dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMismatch {
    /// Which mint: `PSP mint`, `ESP mint` or `FSP mint`.
    pub mint: &'static str,
    /// The mint's DID, as hex.
    pub did: String,
    /// For an FSP mint, its service's DID, as hex.
    pub service: Option<String>,
    /// Where the check failed.
    pub site: Site,
    /// What failed.
    pub failed: Failed,
    /// Whether the mint is now blacklisted (an FSP mint, with
    /// `fsp.blacklist_on_key_mismatch` on and room in the blacklist).
    pub blacklisted: bool,
    /// The whole warning, as it was printed.
    pub warning: String,
}

impl KeyMismatch {
    fn new(
        mint: &'static str,
        did: String,
        service: Option<String>,
        site: Site,
        failed: Failed,
        outcome: Outcome,
    ) -> KeyMismatch {
        let who = match &service {
            Some(s) => format!("{mint} (DID {did}, service {s})"),
            None => format!("{mint} (DID {did})"),
        };
        let tail = match &outcome {
            Outcome::Blacklisted => "This FSP mint is now BLACKLISTED (fsp.blacklist_on_key_mismatch is on): its notes were DROPPED from this wallet, and no request will be sent to it until an operator removes it from the blacklist by hand.".to_string(),
            Outcome::BlacklistFull(max) => format!("The blacklist is FULL ({max} entries, fsp.blacklist_max), so this FSP mint was NOT blacklisted and its notes were kept. Remove entries by hand, or raise fsp.blacklist_max."),
            Outcome::OptedOut => "This FSP mint is NOT blacklisted (fsp.blacklist_on_key_mismatch is off).".to_string(),
            Outcome::NeverBlacklisted => "The SPI's PSP and ESP mints are never blacklisted: this only warns.".to_string(),
        };
        // A blacklisted mint's notes are dropped, so only the other outcomes keep them.
        let kept = if matches!(outcome, Outcome::Blacklisted) {
            ""
        } else {
            " Your notes and the pending request were kept."
        };
        let warning = format!(
            "WARNING: KEY CHECK FAILED at {}. The {who} {failed}. Nothing from its reply was stored.{kept} A mint that signs with keys other users do not see can recognise your notes when they come back. {tail}",
            site.name()
        );
        KeyMismatch {
            mint,
            did,
            service,
            site,
            failed,
            blacklisted: matches!(outcome, Outcome::Blacklisted),
            warning,
        }
    }
}

impl fmt::Display for KeyMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.warning)
    }
}

/// What the wallet did about a failed check, for the warning.
enum Outcome {
    Blacklisted,
    BlacklistFull(usize),
    OptedOut,
    NeverBlacklisted,
}

/// What the wallet does about a failed check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    /// `fsp.blacklist_on_key_mismatch`: blacklist an FSP mint that fails the
    /// check, and drop its notes. Off by default. The SPI's PSP and ESP mints are
    /// never blacklisted, whatever this is.
    pub blacklist_on_key_mismatch: bool,
    /// `fsp.blacklist_max`: the most entries the blacklist holds; 0 keeps every
    /// entry. At the cap a mint that fails the check is not added (the warning
    /// says so) and nothing is dropped; no entry is ever removed on its own.
    pub blacklist_max: u64,
}

impl Default for KeyPolicy {
    fn default() -> Self {
        KeyPolicy {
            blacklist_on_key_mismatch: false,
            blacklist_max: DEFAULT_BLACKLIST_MAX,
        }
    }
}

/// The verdict of one look at what the wallet has read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Every key is the published one.
    Good,
    /// The keys are not the published ones.
    Bad(Failed),
    /// The record that decides is not here (yet).
    Missing(Missing),
}

/// The record a verdict is waiting for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Missing {
    /// A key set (or an ESP generation) this stream has not shown yet.
    Keyset(String),
    /// The ESP's control record.
    Control,
    /// The keys of a (key set, service, day) of the ESP.
    Day {
        generation: String,
        service: ServiceDid,
        day: u64,
    },
}

/// The keys of an output, by amount in units.
pub(crate) type Keys = [(u64, PublicKey)];

/// Check keys against the key sets a PSP or FSP mint published: the key set must
/// be one of its last two, and each key must be the published key for its amount.
pub(crate) fn check_keyset(stream: Option<&MintStream>, keyset: &str, keys: &Keys) -> Verdict {
    let Some(stream) = stream else {
        return Verdict::Missing(Missing::Keyset(keyset.to_string()));
    };
    let Some(published) = stream.keyset(keyset) else {
        return Verdict::Missing(Missing::Keyset(keyset.to_string()));
    };
    for (amount, key) in keys {
        if published.keys.get(amount) != Some(key) {
            return Verdict::Bad(Failed::Key { amount: *amount });
        }
    }
    Verdict::Good
}

/// Check keys against the keys the ESP published for a service and a day: the
/// key set must be live (the current or previous generation of the latest
/// control record) or named live by a control record the wallet read (a reply
/// from before it retired), the day's keys must be known, and each key must be
/// the published one (the key of amount 2^i is the i-th of the 64).
pub(crate) fn check_esp_keys(
    stream: Option<&MintStream>,
    keyset: &str,
    service: &ServiceDid,
    day: u64,
    keys: &Keys,
) -> Verdict {
    let Some(stream) = stream else {
        return Verdict::Missing(Missing::Keyset(keyset.to_string()));
    };
    let Some(control) = stream.controls.last() else {
        return Verdict::Missing(Missing::Keyset(keyset.to_string()));
    };
    let live = control.current_id == keyset || control.previous_id.as_deref() == Some(keyset);
    if !live && !stream.generations.contains(keyset) {
        return Verdict::Missing(Missing::Keyset(keyset.to_string()));
    }
    let Some(published) = stream.days.get(&day_key(keyset, service, day)) else {
        return Verdict::Missing(Missing::Day {
            generation: keyset.to_string(),
            service: *service,
            day,
        });
    };
    for (amount, key) in keys {
        if !amount.is_power_of_two() {
            return Verdict::Bad(Failed::Key { amount: *amount });
        }
        let index = amount.trailing_zeros() as usize;
        if published.get(index) != Some(key) {
            return Verdict::Bad(Failed::Key { amount: *amount });
        }
    }
    Verdict::Good
}

/// The day of `t` (unix seconds).
fn day_of(t: u64) -> u64 {
    t / SECONDS_PER_DAY
}

/// Check the redeemable day of a new exchange: from the day of (first send time
/// minus `skew`, [`DAY_SKEW_SECS`] in the wallet) plus m to the day of (reply time plus `skew`) plus m, both ends
/// included, for m the ESP published: its latest rule, or the one before it
/// (the rule may have changed between the send and the reply).
pub(crate) fn check_exchange_day(
    stream: Option<&MintStream>,
    first_sent_at: u64,
    replied_at: u64,
    skew: u64,
    day: u64,
) -> Verdict {
    let Some(stream) = stream else {
        return Verdict::Missing(Missing::Control);
    };
    if stream.controls.is_empty() {
        return Verdict::Missing(Missing::Control);
    }
    let send_day = day_of(first_sent_at.saturating_sub(skew));
    let reply_day = day_of(replied_at.saturating_add(skew));
    let rules: Vec<u64> = stream
        .controls
        .iter()
        .rev()
        .map(|c| c.maturity_days)
        .collect();
    let allowed = rules
        .iter()
        .any(|m| send_day.saturating_add(*m) <= day && day <= reply_day.saturating_add(*m));
    if allowed {
        return Verdict::Good;
    }
    let latest = rules[0];
    Verdict::Bad(Failed::Day {
        day,
        from: send_day.saturating_add(latest),
        to: reply_day.saturating_add(latest),
        rules,
    })
}

// ---------------------------------------------------------------- the feed

/// How a mint's stream is named in the wallet file: `psp`, `esp`, or
/// `fsp:<service DID>`.
pub(crate) fn stream_name(party: Party) -> String {
    match party {
        Party::Psp => "psp".to_string(),
        Party::Esp => "esp".to_string(),
        Party::Fsp(service) => format!("fsp:{}", service.to_hex()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamKind {
    Keyset,
    Control,
}

/// A stream to follow.
#[derive(Clone, Debug)]
pub(crate) struct Followed {
    name: String,
    did: ServiceDid,
    server: ServerRef,
    kind: StreamKind,
    /// The saved index of the next record, if the wallet has read this stream.
    next: Option<u32>,
    timeout_secs: u64,
}

/// A whole stream, read from its first record to its first empty cell.
#[derive(Clone, Debug, Default)]
pub(crate) struct Scan {
    /// The DID of the mint, as hex.
    pub(crate) did: String,
    /// The index of the first empty cell.
    pub(crate) end: u32,
    /// The key sets of a PSP or FSP mint, oldest first.
    pub(crate) keysets: Vec<PublishedKeyset>,
    /// The control records of the ESP, oldest first.
    pub(crate) controls: Vec<PublishedControl>,
}

/// What a whole read of a stream decided about a missing record.
enum Lookup {
    /// It is there now: look again.
    Again,
    /// It is not published.
    Flag(Failed),
}

/// A record that a reply needs and a stream lacks, as `unpublished` in the
/// wallet file names it: `<stream>|keyset:<ID>`, `esp|generation:<ID>`,
/// `esp|control` or `esp|day:<day key>`.
fn unpublished_key(name: &str, party: Party, missing: &Missing) -> String {
    match missing {
        Missing::Keyset(id) if party == Party::Esp => format!("{name}|generation:{id}"),
        Missing::Keyset(id) => format!("{name}|keyset:{id}"),
        Missing::Control => format!("{name}|control"),
        Missing::Day {
            generation,
            service,
            day,
        } => format!("{name}|day:{}", day_key(generation, service, *day)),
    }
}

/// Whether the record an `unpublished` entry names is in what the wallet read.
fn is_read(streams: &BTreeMap<String, MintStream>, key: &str) -> bool {
    let Some((name, what)) = key.split_once('|') else {
        return true;
    };
    let Some(s) = streams.get(name) else {
        return false;
    };
    match what.split_once(':') {
        Some(("keyset", id)) => s.keyset(id).is_some(),
        Some(("generation", id)) => s.generations.contains(id),
        Some(("day", day)) => s.days.contains_key(day),
        _ => what == "control" && !s.controls.is_empty(),
    }
}

/// A record the feed read.
struct Arrival {
    name: String,
    did: ServiceDid,
    kind: StreamKind,
    index: u32,
    bytes: Vec<u8>,
}

struct Running {
    stop: Arc<AtomicBool>,
    did: ServiceDid,
}

#[derive(Default)]
struct Inner {
    arrivals: Vec<Arrival>,
    ready: BTreeSet<String>,
    errors: BTreeMap<String, String>,
    running: BTreeMap<String, Running>,
    /// Goes up whenever something arrives, a stream becomes ready or fails.
    version: u64,
}

struct Shared {
    inner: Mutex<Inner>,
    changed: Condvar,
}

fn lock(shared: &Shared) -> MutexGuard<'_, Inner> {
    shared.inner.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    fn bump(&self, inner: &mut Inner) {
        inner.version += 1;
        self.changed.notify_all();
    }
}

/// The threads that follow the streams of the mints the wallet holds notes from
/// or has a request pending with, and what they have read.
pub(crate) struct KeyFeed {
    shared: Arc<Shared>,
    pub(crate) air: AirSettings,
}

impl Drop for KeyFeed {
    fn drop(&mut self) {
        let inner = lock(&self.shared);
        for running in inner.running.values() {
            running.stop.store(true, Ordering::SeqCst);
        }
    }
}

impl KeyFeed {
    pub(crate) fn new(air: AirSettings) -> KeyFeed {
        KeyFeed {
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner::default()),
                changed: Condvar::new(),
            }),
            air,
        }
    }

    /// Follow exactly `wanted`: start a thread for each stream not followed yet,
    /// stop the thread of each that is not wanted any more.
    pub(crate) fn follow(&self, wanted: Vec<Followed>) {
        let mut inner = lock(&self.shared);
        let names: BTreeSet<String> = wanted.iter().map(|w| w.name.clone()).collect();
        let gone: Vec<String> = inner
            .running
            .keys()
            .filter(|n| !names.contains(*n))
            .cloned()
            .collect();
        for name in gone {
            if let Some(running) = inner.running.remove(&name) {
                running.stop.store(true, Ordering::SeqCst);
            }
            inner.ready.remove(&name);
            inner.errors.remove(&name);
        }
        for spec in wanted {
            if let Some(running) = inner.running.get(&spec.name) {
                if running.did == spec.did {
                    continue;
                }
                running.stop.store(true, Ordering::SeqCst);
                inner.ready.remove(&spec.name);
            }
            let stop = Arc::new(AtomicBool::new(false));
            inner.running.insert(
                spec.name.clone(),
                Running {
                    stop: Arc::clone(&stop),
                    did: spec.did,
                },
            );
            let shared = Arc::clone(&self.shared);
            let name = spec.name.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("key-feed-{name}"))
                .spawn(move || {
                    let _ = block_on_new_runtime(|| follower(shared, spec, stop));
                });
            if let Err(e) = spawned {
                inner.running.remove(&name);
                inner
                    .errors
                    .insert(name, format!("could not start a thread: {e}"));
            }
        }
        self.shared.changed.notify_all();
    }

    /// Everything read since the last call, and the version it is at.
    fn take(&self) -> (Vec<Arrival>, u64) {
        let mut inner = lock(&self.shared);
        (std::mem::take(&mut inner.arrivals), inner.version)
    }

    /// Whether the stream was read up to its end at least once and is connected.
    fn is_ready(&self, name: &str) -> bool {
        lock(&self.shared).ready.contains(name)
    }

    /// The last error of a stream that is not ready.
    fn error_of(&self, name: &str) -> Option<String> {
        lock(&self.shared).errors.get(name).cloned()
    }

    /// Wait until something changed since `since`, or `deadline`. True when it
    /// changed.
    fn wait_change(&self, since: u64, deadline: Instant) -> bool {
        let mut inner = lock(&self.shared);
        loop {
            if inner.version != since {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            inner = self
                .shared
                .changed
                .wait_timeout(inner, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn push(&self, arrival: Arrival) {
        push(&self.shared, arrival);
    }
}

fn push(shared: &Shared, arrival: Arrival) {
    let mut inner = lock(shared);
    inner.arrivals.push(arrival);
    shared.bump(&mut inner);
}

fn cell_of(kind: StreamKind) -> impl Fn(u32) -> Cell + Copy {
    move |index| match kind {
        StreamKind::Keyset => Cell::Keyset { index },
        StreamKind::Control => Cell::Control { index },
    }
}

/// The thread of one stream: connect, read, hold; on any failure wait and start
/// again from where it was.
async fn follower(shared: Arc<Shared>, spec: Followed, stop: Arc<AtomicBool>) {
    let mut next = spec.next;
    let mut wait = 1u64;
    while !stop.load(Ordering::SeqCst) {
        match session(&shared, &spec, &stop, &mut next).await {
            Ok(()) => return,
            Err(why) => {
                {
                    let mut inner = lock(&shared);
                    inner.ready.remove(&spec.name);
                    inner.errors.insert(spec.name.clone(), why);
                    shared.bump(&mut inner);
                }
                for _ in 0..wait * 5 {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                wait = (wait * 2).min(30);
            }
        }
    }
}

async fn session(
    shared: &Arc<Shared>,
    spec: &Followed,
    stop: &Arc<AtomicBool>,
    next: &mut Option<u32>,
) -> Result<(), String> {
    let secs = spec.timeout_secs;
    let client = tokio::time::timeout(Duration::from_secs(secs), client::connect(&spec.server))
        .await
        .map_err(|_| format!("no connection to the AIR server within {secs} s"))?
        .map_err(|e| e.0)?;
    let cell = cell_of(spec.kind);
    let deliver = |index: u32, bytes: Vec<u8>| {
        push(
            shared,
            Arrival {
                name: spec.name.clone(),
                did: spec.did,
                kind: spec.kind,
                index,
                bytes,
            },
        );
    };
    let mut at = match *next {
        Some(n) => n,
        None => {
            // The first start: the latest records only.
            let end = stream::find_end(&client, &spec.did, cell, secs)
                .await
                .map_err(|e| e.0)?;
            for index in end.saturating_sub(KEEP_KEYSETS as u32)..end {
                let bytes = stream::read_cell(&client, &spec.did, &cell(index), secs)
                    .await
                    .map_err(|e| e.0)?
                    .ok_or_else(|| format!("record {index} of the stream is empty"))?;
                deliver(index, bytes);
            }
            end
        }
    };
    *next = Some(at);
    // Catch up: forward from where the wallet was, until a cell is empty.
    while let Some(bytes) = stream::read_cell(&client, &spec.did, &cell(at), secs)
        .await
        .map_err(|e| e.0)?
    {
        deliver(at, bytes);
        at = at.saturating_add(1);
        *next = Some(at);
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
    }
    {
        let mut inner = lock(shared);
        inner.ready.insert(spec.name.clone());
        inner.errors.remove(&spec.name);
        shared.bump(&mut inner);
    }
    // Hold a read on the next cell; on each record, on the one after.
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let address = stream::cell_address(&spec.did, &cell(at)).map_err(|e| e.0)?;
        let handle = client::hold(&client, address, at, tx).await;
        let got = loop {
            if stop.load(Ordering::SeqCst) {
                handle.abort();
                return Ok(());
            }
            match tokio::time::timeout(Duration::from_millis(250), rx.recv()).await {
                Ok(Some(Event::Filled(_, bytes))) => break Ok(bytes),
                Ok(Some(Event::Lost(_))) | Ok(None) => {
                    break Err("the AIR session ended".to_string());
                }
                Err(_) => continue,
            }
        };
        handle.abort();
        deliver(at, got?);
        at = at.saturating_add(1);
        *next = Some(at);
    }
}

/// Read the stream forward from `from` once, on the calling thread, until a cell
/// is empty: a reread, or (from 0) the whole stream.
fn read_forward(spec: &Followed, from: u32) -> Result<Vec<(u32, Vec<u8>)>, String> {
    let secs = spec.timeout_secs;
    let cell = cell_of(spec.kind);
    block_on_new_runtime(|| async {
        let client = tokio::time::timeout(Duration::from_secs(secs), client::connect(&spec.server))
            .await
            .map_err(|_| format!("no connection to the AIR server within {secs} s"))?
            .map_err(|e| e.0)?;
        let mut out = Vec::new();
        let mut at = from;
        while let Some(bytes) = stream::read_cell(&client, &spec.did, &cell(at), secs)
            .await
            .map_err(|e| e.0)?
        {
            out.push((at, bytes));
            at = at.saturating_add(1);
        }
        Ok::<_, String>(out)
    })
    .map_err(|e| e.0)?
}

/// The 64 keys of `service` for `day` in `generation`, as the ESP published
/// them: the first record of the day says how many buckets it has, then the
/// parts of the service's bucket are read from 0 until one holds the service.
/// Waits up to `deadline` for a record that is not there yet. `None` when the
/// day (or the service in it) is not published by then.
fn fetch_day(
    server: &ServerRef,
    mint: ServiceDid,
    generation: [u8; 8],
    service: ServiceDid,
    day: u64,
    read_secs: u64,
    deadline: Instant,
) -> Result<Option<Vec<PublicKey>>, String> {
    block_on_new_runtime(|| async move {
        let client =
            tokio::time::timeout(Duration::from_secs(read_secs), client::connect(server))
                .await
                .map_err(|_| format!("no connection to the AIR server within {read_secs} s"))?
                .map_err(|e| e.0)?;
        let part_of = |bucket: u32, part: u32| {
            Cell::Day(DayCell {
                generation,
                day,
                bucket,
                part,
            })
        };
        let wait_for = |bucket: u32, part: u32| {
            let client = &client;
            async move {
                let address = stream::cell_address(&mint, &part_of(bucket, part))
                    .map_err(|e| e.0)?;
                let left = deadline.saturating_duration_since(Instant::now());
                let bytes = delivery::read_record(client, &address, read_secs, left.as_secs())
                    .await
                    .map_err(|e| e.0)?;
                match bytes {
                    None => Ok::<Option<DayRecord>, String>(None),
                    Some(bytes) => DayRecord::decode(&bytes)
                        .map(Some)
                        .map_err(|e| format!("a day record does not decode: {}", e.0)),
                }
            }
        };
        let Some(first) = wait_for(0, 0).await? else {
            return Ok(None);
        };
        let buckets = first.buckets.max(1);
        let bucket = stream::bucket_of(&service, buckets);
        let mut part = 0u32;
        loop {
            let record = if bucket == 0 && part == 0 {
                Some(first.clone())
            } else {
                wait_for(bucket, part).await?
            };
            let Some(record) = record else {
                return Ok(None);
            };
            if record.generation != generation || record.day != day || record.bucket != bucket {
                return Err(format!(
                    "the record at day {day}, bucket {bucket}, part {part} is for another day or bucket"
                ));
            }
            if let Some(found) = record.services.iter().find(|s| s.service == service) {
                return Ok(Some(found.keys.to_vec()));
            }
            part = part.saturating_add(1);
        }
    })
    .map_err(|e| e.0)?
}

// ---------------------------------------------------------------- the wallet

impl Wallet {
    /// Start following the key streams of the mints this wallet holds notes from
    /// or has a request pending with, with these `[air]` settings. The streams
    /// are read by threads of their own; what they read is saved in the wallet
    /// file when a check needs it. A check that needs a record that is not in the
    /// file yet waits for it, up to `air.reply_wait_secs`. The threads follow the
    /// wallet's notes and requests as they change, and stop when the wallet is
    /// dropped.
    ///
    /// An app calls this when it starts, so that the latest records are read
    /// before the first check. A wallet that is not started this way starts it
    /// itself, with the settings of the first call it makes to a mint (so no
    /// reply is ever turned into notes unchecked); a later call with other
    /// settings changes the feed's. A wallet whose file holds notes of a mint it
    /// has not been connected to yet follows that mint from this call.
    pub fn start_key_feed(&mut self, air: &AirSettings) -> Result<(), WalletError> {
        self.ensure_key_feed(air);
        Ok(())
    }

    /// Make sure the feed runs with these settings: start it, or change its
    /// settings, and make the threads follow what the wallet holds.
    pub(crate) fn ensure_key_feed(&mut self, air: &AirSettings) {
        let changed = match &mut self.feed {
            Some(feed) if feed.air == *air => false,
            Some(feed) => {
                feed.air = air.clone();
                true
            }
            None => {
                self.feed = Some(KeyFeed::new(air.clone()));
                true
            }
        };
        if changed {
            self.refresh_key_feed();
        }
    }

    /// Take into the wallet file what the key streams have read since the last
    /// time, and wait until `done` is true of what the wallet then holds of the
    /// streams (by `psp`, `esp` or `fsp:<service DID>`), up to `wait`. Returns
    /// whether it was. `Ok(false)` as well when no feed was started. Used to wait
    /// for the latest records after a start or a rotation.
    pub fn wait_for_keys(
        &mut self,
        wait: Duration,
        done: &dyn Fn(&BTreeMap<String, MintStream>) -> bool,
    ) -> Result<bool, WalletError> {
        if self.feed.is_none() {
            return Ok(false);
        }
        let deadline = Instant::now() + wait;
        loop {
            let seen = self.absorb_feed()?;
            if done(&self.data().key_streams) {
                return Ok(true);
            }
            let changed = match &self.feed {
                Some(feed) => feed.wait_change(seen, deadline),
                None => false,
            };
            if !changed {
                return Ok(false);
            }
        }
    }

    /// Whether the key streams are being followed.
    pub fn key_feed_running(&self) -> bool {
        self.feed.is_some()
    }

    /// What the wallet does about a failed key check (see [`KeyPolicy`]). Set it
    /// from the settings `fsp.blacklist_on_key_mismatch` and `fsp.blacklist_max`.
    pub fn set_key_policy(&mut self, policy: KeyPolicy) {
        self.policy = policy;
    }

    /// The policy now in force.
    pub fn key_policy(&self) -> KeyPolicy {
        self.policy
    }

    /// What the wallet has read of each mint's stream, by `psp`, `esp` or
    /// `fsp:<service DID>`.
    pub fn key_streams(&self) -> &BTreeMap<String, MintStream> {
        &self.data().key_streams
    }

    /// The FSP mints this wallet has blacklisted, in the order it did.
    pub fn blacklist(&self) -> &[BlacklistedMint] {
        &self.data().blacklist
    }

    /// Whether the FSP mint of `service` is blacklisted.
    pub fn is_blacklisted(&self, service: &ServiceDid) -> bool {
        self.data().blacklist.iter().any(|b| b.service == *service)
    }

    /// Take the FSP mint of `service` off the blacklist, by hand. Nothing else
    /// ever removes an entry. `true` when it was there. Its notes stay dropped.
    pub fn unblacklist(&mut self, service: &ServiceDid) -> Result<bool, WalletError> {
        if !self.is_blacklisted(service) {
            return Ok(false);
        }
        self.update(|d| {
            d.blacklist.retain(|b| b.service != *service);
            Ok(())
        })?;
        Ok(true)
    }

    /// An error if `party` is a blacklisted FSP mint: no request is sent to it.
    pub(crate) fn refuse_blacklisted(&self, party: Party) -> Result<(), WalletError> {
        let Party::Fsp(service) = party else {
            return Ok(());
        };
        match self.data().blacklist.iter().find(|b| b.service == service) {
            None => Ok(()),
            Some(entry) => Err(WalletError::Blacklisted(format!(
                "the FSP mint of service {} is BLACKLISTED, so nothing is sent to it: at {} it failed this wallet's key check ({}: {}). Its notes were dropped. If you trust it again, remove it from the blacklist by hand (`ecash-wallet blacklist remove --service {}`)",
                service.to_hex(),
                crate::date::format_utc(entry.at),
                entry.site,
                entry.what,
                service.to_hex()
            ))),
        }
    }

    /// The streams the wallet should follow now: the PSP when it holds PSP notes
    /// or purchases or has a PSP rollover pending, the ESP when it holds ESP
    /// notes or has an exchange, redemption or rollover pending, and an FSP mint
    /// when it holds notes from it or has a request pending with it.
    fn followed(&self, air: &AirSettings) -> Vec<Followed> {
        let d = self.data();
        let mut parties: Vec<Party> = Vec::new();
        let mut want = |party: Party| {
            if !parties.contains(&party) {
                parties.push(party);
            }
        };
        for n in &d.notes {
            match n.kind {
                crate::store::Kind::Psp => want(Party::Psp),
                crate::store::Kind::Esp => want(Party::Esp),
                crate::store::Kind::Fsp => {
                    if let Some(service) = n.fsp_service() {
                        want(Party::Fsp(service));
                    }
                }
            }
        }
        if !d.claim_keys.is_empty() {
            want(Party::Psp);
        }
        if !d.pending_exchanges.is_empty() || !d.pending_redemptions.is_empty() {
            want(Party::Esp);
        }
        for p in &d.pending_rollovers {
            match p.kind {
                crate::store::Kind::Psp => want(Party::Psp),
                crate::store::Kind::Esp => want(Party::Esp),
                crate::store::Kind::Fsp => {}
            }
        }
        for p in &d.pending_fsp {
            want(Party::Fsp(p.service));
        }
        let mut out = Vec::new();
        for party in parties {
            if let Party::Fsp(service) = party
                && d.blacklist.iter().any(|b| b.service == service)
            {
                continue;
            }
            let Ok((name, host)) = party.address(air) else {
                continue;
            };
            let did = party.did(air);
            let stream_name = stream_name(party);
            let next = d
                .key_streams
                .get(&stream_name)
                .filter(|s| s.did == did.to_hex())
                .map(|s| s.next);
            out.push(Followed {
                name: stream_name,
                did,
                server: ServerRef { name, host },
                kind: match party {
                    Party::Esp => StreamKind::Control,
                    Party::Psp | Party::Fsp(_) => StreamKind::Keyset,
                },
                next,
                timeout_secs: key_read_timeout(air),
            });
        }
        out
    }

    /// Make the threads follow what the wallet now holds and has pending.
    pub(crate) fn refresh_key_feed(&mut self) {
        let Some(feed) = &self.feed else {
            return;
        };
        let wanted = self.followed(&feed.air);
        feed.follow(wanted);
    }

    /// Take what the streams have read into the wallet file. Returns the version
    /// of the feed it is current to (0 without a feed).
    fn absorb_feed(&mut self) -> Result<u64, WalletError> {
        let Some(feed) = &self.feed else {
            return Ok(0);
        };
        let (arrivals, version) = feed.take();
        if arrivals.is_empty() {
            return Ok(version);
        }
        let today = day_of(sp_wire::air_request::addr::now_secs());
        self.update(|d| {
            for a in &arrivals {
                let entry = d.key_streams.entry(a.name.clone()).or_default();
                if entry.did != a.did.to_hex() {
                    *entry = MintStream {
                        did: a.did.to_hex(),
                        ..MintStream::default()
                    };
                }
                match a.kind {
                    StreamKind::Keyset => match KeysetRecord::decode(&a.bytes) {
                        Ok(record) => entry.apply_keyset(a.index, &record),
                        Err(_) => entry.next = entry.next.max(a.index.saturating_add(1)),
                    },
                    StreamKind::Control => match ControlRecord::decode(&a.bytes) {
                        Ok(record) => entry.apply_control(&record),
                        Err(_) => entry.next = entry.next.max(a.index.saturating_add(1)),
                    },
                }
            }
            prune(d, today);
            Ok(())
        })?;
        Ok(version)
    }

    /// How long a check may wait for a record: [`KEY_CHECK_WAIT_SECS`] from now
    /// (no setting changes it), or not at all without a key feed, when nothing
    /// can arrive while it waits.
    fn check_deadline(&self) -> Instant {
        let wait = if self.feed.is_some() {
            KEY_CHECK_WAIT_SECS
        } else {
            0
        };
        Instant::now() + Duration::from_secs(wait)
    }

    /// Look at what the wallet has read with `eval`, and while the record that
    /// decides is missing, wait for the stream (up to `deadline`) or, for an ESP
    /// day, read it. `Ok(None)` when the keys are the published ones,
    /// `Ok(Some(failed))` when what the wallet holds disagrees with them (the
    /// caller decides whether that is final), and an error to retry when the
    /// record is still missing after the wait and one read of the stream, and
    /// could still be a late write. When it can no longer be (see "Not published
    /// at all" above), `Ok(Some(Failed::Unpublished))`.
    fn settle(
        &mut self,
        party: Party,
        eval: &dyn Fn(Option<&MintStream>) -> Verdict,
        deadline: Instant,
    ) -> Result<Option<Failed>, WalletError> {
        let name = stream_name(party);
        let mut reread: Option<Result<(), String>> = None;
        let mut scanned = false;
        loop {
            let seen = self.absorb_feed()?;
            let missing = match eval(self.data().key_streams.get(&name)) {
                Verdict::Good => {
                    self.forget_published()?;
                    return Ok(None);
                }
                Verdict::Bad(failed) => {
                    self.forget_published()?;
                    return Ok(Some(failed));
                }
                Verdict::Missing(missing) => missing,
            };
            match &missing {
                Missing::Day {
                    generation,
                    service,
                    day,
                } => {
                    if let Some(keys) = self.read_day(generation, service, *day, deadline)? {
                        self.store_day(&name, day_key(generation, service, *day), keys)?;
                        continue;
                    }
                }
                Missing::Keyset(_) | Missing::Control => {
                    let waited = match &self.feed {
                        Some(feed) => feed.wait_change(seen, deadline),
                        None => false,
                    };
                    if waited {
                        continue;
                    }
                    // Nothing came in time: one read of the stream from where the
                    // wallet is (the push may have been missed), then retry.
                    if reread.is_none() && self.feed.is_some() {
                        let done = self.reread(party);
                        let ok = done.is_ok();
                        reread = Some(done);
                        if ok {
                            continue;
                        }
                    }
                }
            }
            let why = reread.as_ref().and_then(|r| r.clone().err());
            match self.unpublished(party, &missing, why, &mut scanned)? {
                Lookup::Again => continue,
                Lookup::Flag(failed) => return Ok(Some(failed)),
            }
        }
    }

    /// This wallet's clock, for the backstop ([`UNPUBLISHED_BACKSTOP_SECS`]) and
    /// an exchange's first send time.
    pub(crate) fn key_check_now(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.test_now {
            return now;
        }
        sp_wire::air_request::addr::now_secs()
    }

    /// Drop the `unpublished` entries whose record the wallet has read now.
    fn forget_published(&mut self) -> Result<(), WalletError> {
        let d = self.data();
        if d.unpublished.keys().all(|k| !is_read(&d.key_streams, k)) {
            return Ok(());
        }
        self.update(|d| {
            let streams = d.key_streams.clone();
            d.unpublished.retain(|k, _| !is_read(&streams, k));
            Ok(())
        })
    }

    /// Read the whole stream of `party`, from its first record, on this thread.
    fn scan(&self, party: Party) -> Result<Scan, String> {
        let Some(feed) = &self.feed else {
            #[cfg(test)]
            if self.streams_are_fresh {
                // The unit tests' AIR: what the test put there, or else what the
                // wallet holds is all there is.
                let name = stream_name(party);
                if let Some(scan) = self.test_air.get(&name) {
                    return Ok(scan.clone());
                }
                let s = self
                    .data()
                    .key_streams
                    .get(&name)
                    .cloned()
                    .unwrap_or_default();
                return Ok(Scan {
                    did: s.did,
                    end: s.next,
                    keysets: s.keysets,
                    controls: s.controls,
                });
            }
            return Err("the key streams were not started".to_string());
        };
        let name = stream_name(party);
        let Some(spec) = self
            .followed(&feed.air)
            .into_iter()
            .find(|f| f.name == name)
        else {
            return Err(format!(
                "this wallet does not follow the {}'s stream",
                party.name()
            ));
        };
        let read = read_forward(&spec, 0)?;
        let mut scan = Scan {
            did: spec.did.to_hex(),
            end: read.last().map(|(i, _)| i.saturating_add(1)).unwrap_or(0),
            ..Scan::default()
        };
        for (index, bytes) in read {
            match spec.kind {
                StreamKind::Keyset => {
                    if let Ok(record) = KeysetRecord::decode(&bytes) {
                        scan.keysets.push(published_keyset(index, &record));
                    }
                }
                StreamKind::Control => {
                    if let Ok(record) = ControlRecord::decode(&bytes) {
                        scan.controls.push(published_control(&record));
                    }
                }
            }
        }
        Ok(scan)
    }

    /// A record is still missing after the wait and the reread: read the whole
    /// stream once (for a key set or a control record) and take in what it
    /// holds. `Again` when the record is there now; `Flag` when it is not and
    /// cannot be a late write any more (newer records, or the backstop; see "Not
    /// published at all" above); else the error to retry.
    fn unpublished(
        &mut self,
        party: Party,
        missing: &Missing,
        reread: Option<String>,
        scanned: &mut bool,
    ) -> Result<Lookup, WalletError> {
        let name = stream_name(party);
        let now = self.key_check_now();
        #[cfg(test)]
        let fresh = self.streams_are_fresh;
        #[cfg(not(test))]
        let fresh = false;
        let (end, needed) = match missing {
            Missing::Day { .. } => {
                // `read_day` read the day's cells up to the empty one, waiting
                // to the deadline; without a feed it read nothing.
                if self.feed.is_none() && !fresh {
                    return Err(self.not_published(party, missing.clone(), reread));
                }
                (None, None)
            }
            Missing::Keyset(_) | Missing::Control => {
                if *scanned {
                    return Err(self.not_published(party, missing.clone(), reread));
                }
                *scanned = true;
                let scan = match self.scan(party) {
                    Ok(scan) => scan,
                    Err(why) => return Err(self.not_published(party, missing.clone(), Some(why))),
                };
                let there = match missing {
                    Missing::Keyset(id) if party == Party::Esp => scan
                        .controls
                        .iter()
                        .any(|c| c.current_id == *id || c.previous_id.as_deref() == Some(id)),
                    Missing::Keyset(id) => scan.keysets.iter().any(|k| k.id == *id),
                    _ => !scan.controls.is_empty(),
                };
                self.take_scan(&name, missing, &scan)?;
                if there {
                    return Ok(Lookup::Again);
                }
                let needed = match missing {
                    Missing::Keyset(_) if party == Party::Esp => Some(NEWER_CONTROLS),
                    Missing::Keyset(_) => Some(NEWER_KEYSETS),
                    _ => None,
                };
                (Some(scan.end), needed)
            }
        };
        let key = unpublished_key(&name, party, missing);
        let before = self.data().unpublished.get(&key).copied();
        let seen = match before {
            Some(mut seen) => {
                seen.end = seen.end.or(end);
                seen
            }
            None => Unpublished { since: now, end },
        };
        if before != Some(seen) {
            self.update(|d| {
                d.unpublished.insert(key, seen);
                Ok(())
            })?;
        }
        let backstop = UNPUBLISHED_BACKSTOP_SECS;
        let by = match (needed, seen.end, end) {
            (Some(needed), Some(from), Some(end)) if end >= from.saturating_add(needed) => {
                Some(UnpublishedBy::NewerRecords { from, end, needed })
            }
            _ if now >= seen.since.saturating_add(backstop) => Some(UnpublishedBy::Backstop {
                since: seen.since,
                secs: backstop,
            }),
            _ => None,
        };
        if let Some(by) = by {
            return Ok(Lookup::Flag(Failed::Unpublished {
                record: self.record_name(missing),
                by,
            }));
        }
        let mut when = Vec::new();
        if let (Some(needed), Some(from)) = (needed, seen.end) {
            let after = match from {
                0 => "after this wallet first read it empty".to_string(),
                n => format!("after record {}", n - 1),
            };
            when.push(format!(
                "once its stream holds {needed} records written {after} without it"
            ));
        }
        when.push(format!(
            "in {} s if it is still not published (a day after this wallet first read the stream without it)",
            seen.since.saturating_add(backstop).saturating_sub(now)
        ));
        let what = self.missing_text(party, missing);
        let tail = format!("It becomes a key check failure {}", when.join(", or "));
        Err(WalletError::Mint(format!(
            "the {} mint has not published {what} on AIR yet, as far as this wallet can read, so the reply was not checked and nothing was stored. The request is kept: try again. {tail}.",
            party.name().trim_end_matches(" mint")
        )))
    }

    /// Take in a whole read of a stream: its last two records as a feed read
    /// them, every ESP key set a control record names, and an older key set the
    /// check is missing.
    fn take_scan(&mut self, name: &str, missing: &Missing, scan: &Scan) -> Result<(), WalletError> {
        if scan.keysets.is_empty() && scan.controls.is_empty() {
            return Ok(());
        }
        let held = self.data().key_streams.get(name);
        let mut entry = match held {
            Some(s) if scan.did.is_empty() || s.did == scan.did => s.clone(),
            _ => MintStream {
                did: scan.did.clone(),
                ..MintStream::default()
            },
        };
        for k in &scan.keysets {
            entry.take_keyset(k.clone());
        }
        for c in &scan.controls {
            entry.take_control(c.clone());
        }
        if let Missing::Keyset(id) = missing
            && entry.keysets.iter().all(|k| k.id != *id)
            && let Some(older) = scan.keysets.iter().find(|k| k.id == *id)
        {
            entry.found.retain(|k| k.id != *id);
            entry.found.push(older.clone());
            while entry.found.len() > KEEP_FOUND {
                entry.found.remove(0);
            }
        }
        if held == Some(&entry) {
            return Ok(());
        }
        let name = name.to_string();
        self.update(|d| {
            d.key_streams.insert(name, entry);
            Ok(())
        })
    }

    /// The record a reply needs, as the warning names it.
    fn record_name(&self, missing: &Missing) -> String {
        match missing {
            Missing::Keyset(id) => format!("KEY SET {id}"),
            Missing::Control => "a maturity rule and live key sets (a control record)".to_string(),
            Missing::Day {
                generation,
                service,
                day,
            } => format!(
                "the KEYS of service {} for day {day} in key set {generation}",
                service.to_hex()
            ),
        }
    }

    /// What a mint has not published, with what it has, for the error to retry.
    fn missing_text(&self, party: Party, missing: &Missing) -> String {
        let name = stream_name(party);
        let published: Vec<String> = self
            .data()
            .key_streams
            .get(&name)
            .map(|s| {
                if party == Party::Esp {
                    s.controls
                        .last()
                        .map(|c| {
                            let mut v: Vec<String> = c.previous_id.iter().cloned().collect();
                            v.push(c.current_id.clone());
                            v
                        })
                        .unwrap_or_default()
                } else {
                    s.keysets.iter().map(|k| k.id.clone()).collect()
                }
            })
            .unwrap_or_default();
        let shows = if published.is_empty() {
            "none".to_string()
        } else {
            published.join(", ")
        };
        match missing {
            Missing::Keyset(keyset) if party == Party::Esp => {
                format!("key set {keyset} as a live key set (its live key sets: {shows})")
            }
            Missing::Keyset(keyset) => format!("key set {keyset} (its key sets: {shows})"),
            Missing::Control => "its control record".to_string(),
            Missing::Day {
                generation, day, ..
            } => format!("the keys of this service for day {day} in key set {generation}"),
        }
    }

    /// Read the mint's stream forward from where the wallet is, once, on this
    /// thread, and hand what it read to the feed (the next look takes it in).
    /// `Err` with the reason when no fresh read could be made: no feed, a stream
    /// the wallet does not follow (a blacklisted FSP mint, or no AIR address), or
    /// a read that failed.
    fn reread(&mut self, party: Party) -> Result<(), String> {
        let Some(feed) = &self.feed else {
            #[cfg(test)]
            if self.streams_are_fresh {
                // The unit tests' streams are what the mint published, with the
                // control records it published that were not read yet.
                self.rereads += 1;
                for (index, m, current, previous) in std::mem::take(&mut self.unread_controls) {
                    testing::publish_control(self, index, m, &current, previous.as_deref());
                }
                return Ok(());
            }
            return Err("the key streams were not started".to_string());
        };
        let name = stream_name(party);
        let Some(spec) = self
            .followed(&feed.air)
            .into_iter()
            .find(|f| f.name == name)
        else {
            return Err(format!(
                "this wallet does not follow the {}'s stream",
                party.name()
            ));
        };
        let from = self
            .data()
            .key_streams
            .get(&name)
            .filter(|s| s.did == spec.did.to_hex())
            .map(|s| s.next)
            .unwrap_or(0);
        self.rereads += 1;
        // A stream the wallet never read starts at its latest records, which the
        // thread reads; a reread only goes forward.
        let read = read_forward(&spec, from)?;
        if let Some(feed) = &self.feed {
            for (index, bytes) in read {
                feed.push(Arrival {
                    name: spec.name.clone(),
                    did: spec.did,
                    kind: spec.kind,
                    index,
                    bytes,
                });
            }
        }
        Ok(())
    }

    /// How many times this wallet read a mint's stream again on its own thread
    /// before deciding a check (since it was opened; not saved).
    pub fn key_rereads(&self) -> u64 {
        self.rereads
    }

    /// A fresh read before a mismatch is reported: the stream once more, and for
    /// an ESP day its cached keys forgotten so that the next look reads them from
    /// AIR again. An error to retry (nothing stored, the request kept) when the
    /// fresh read could not be made: what the wallet holds may be stale, so it
    /// decides nothing.
    fn fresh_read(&mut self, party: Party, day: Option<String>) -> Result<(), WalletError> {
        if let Err(why) = self.reread(party) {
            return Err(WalletError::Mint(format!(
                "the {}'s published keys could not be read again before deciding ({why}), so the reply was not checked and nothing was stored. The request is kept: try again",
                party.name()
            )));
        }
        #[cfg(test)]
        if self.feed.is_none() && self.streams_are_fresh {
            // No AIR to read the day from: the unit tests' days are published.
            return Ok(());
        }
        if let Some(key) = day {
            let name = stream_name(party);
            if self
                .data()
                .key_streams
                .get(&name)
                .is_some_and(|s| s.days.contains_key(&key))
            {
                self.update(|d| {
                    if let Some(s) = d.key_streams.get_mut(&name) {
                        s.days.remove(&key);
                    }
                    Ok(())
                })?;
            }
        }
        Ok(())
    }

    /// Read an ESP day's keys for a service (see [`fetch_day`]); `None` when it
    /// is not published, or without a feed.
    fn read_day(
        &self,
        generation: &str,
        service: &ServiceDid,
        day: u64,
        deadline: Instant,
    ) -> Result<Option<Vec<PublicKey>>, WalletError> {
        let Some(feed) = &self.feed else {
            return Ok(None);
        };
        let air = &feed.air;
        let (name, host) = Party::Esp.address(air).map_err(WalletError::Invalid)?;
        let generation_bytes: [u8; 8] = hex::decode(generation)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| WalletError::Mint(format!("key set {generation} is not 8 bytes")))?;
        fetch_day(
            &ServerRef { name, host },
            air.esp_did(),
            generation_bytes,
            *service,
            day,
            key_read_timeout(air),
            deadline,
        )
        .map_err(|why| {
            WalletError::Mint(format!(
                "the ESP's published keys for day {day} could not be read ({why}), so the reply was not checked and nothing was stored. The request is kept: try again"
            ))
        })
    }

    fn store_day(
        &mut self,
        name: &str,
        key: String,
        keys: Vec<PublicKey>,
    ) -> Result<(), WalletError> {
        if keys.len() != ESP_KEYS_PER_SERVICE {
            return Err(WalletError::Mint(format!(
                "a day record has {} keys for a service, not {ESP_KEYS_PER_SERVICE}",
                keys.len()
            )));
        }
        let did = self
            .feed
            .as_ref()
            .map(|f| f.air.esp_did().to_hex())
            .unwrap_or_default();
        let name = name.to_string();
        self.update(|d| {
            let entry = d.key_streams.entry(name).or_default();
            if entry.did.is_empty() {
                entry.did = did;
            }
            entry.days.insert(key, keys);
            Ok(())
        })
    }

    /// The error when the record that decides did not come in time and the
    /// stream could not be read to its end: always one to retry, never a
    /// mismatch, and the backstop does not start (the record may be there).
    /// Nothing is stored and the request is kept as it is. `reread` is why the
    /// read of the stream failed, if it did.
    fn not_published(
        &mut self,
        party: Party,
        missing: Missing,
        reread: Option<String>,
    ) -> WalletError {
        let name = stream_name(party);
        let held = self
            .data()
            .key_streams
            .get(&name)
            .is_some_and(|s| !s.keysets.is_empty() || !s.controls.is_empty());
        let (ready, error) = match &self.feed {
            Some(feed) => (feed.is_ready(&name), feed.error_of(&name).or(reread)),
            None => (held, None),
        };
        // A stream read to its end with nothing on it at all is a mint that has
        // not published yet (a late or failed writer).
        if !(ready && held) {
            return WalletError::Mint(match error {
                Some(why) => format!(
                    "the {}'s published keys could not be read ({why}), so the reply was not checked and nothing was stored. The request is kept: try again",
                    party.name()
                ),
                None if self.feed.is_none() => format!(
                    "the {}'s published keys have not been read, so the reply was not checked and nothing was stored. Start the key streams (Wallet::start_key_feed) and try again",
                    party.name()
                ),
                None => format!(
                    "the {}'s published keys have not been read yet, so the reply was not checked and nothing was stored. The request is kept: try again",
                    party.name()
                ),
            });
        }
        let what = self.missing_text(party, &missing);
        WalletError::Mint(format!(
            "the {} mint has not published {what} on AIR yet, as far as this wallet can read, so the reply was not checked and nothing was stored. The request is kept: try again",
            // "PSP mint", "ESP mint", "FSP mint".
            party.name().trim_end_matches(" mint")
        ))
    }

    /// A check failed: print the warning, blacklist and drop the notes of an FSP
    /// mint when the policy says so, and make the error.
    fn key_mismatch(&mut self, party: Party, site: Site, failed: Failed) -> WalletError {
        let name = stream_name(party);
        let did = self
            .data()
            .key_streams
            .get(&name)
            .map(|s| s.did.clone())
            .filter(|d| !d.is_empty())
            .or_else(|| self.feed.as_ref().map(|f| party.did(&f.air).to_hex()))
            .unwrap_or_else(|| "(not known: the key streams were not started)".to_string());
        let (mint, service, outcome) = match party {
            Party::Psp => ("PSP mint", None, Outcome::NeverBlacklisted),
            Party::Esp => ("ESP mint", None, Outcome::NeverBlacklisted),
            Party::Fsp(service) => {
                let outcome = if !self.policy.blacklist_on_key_mismatch {
                    Outcome::OptedOut
                } else {
                    match self.blacklist_fsp(service, site, &failed) {
                        Ok(true) => Outcome::Blacklisted,
                        Ok(false) => Outcome::BlacklistFull(self.data().blacklist.len()),
                        Err(e) => return e,
                    }
                };
                ("FSP mint", Some(service.to_hex()), outcome)
            }
        };
        let did = if did.starts_with('(') {
            service.clone().unwrap_or(did)
        } else {
            did
        };
        let mismatch = KeyMismatch::new(mint, did, service, site, failed, outcome);
        eprintln!("{}", mismatch.warning);
        WalletError::KeyMismatch(Box::new(mismatch))
    }

    /// Blacklist the FSP mint of `service` and drop its notes and requests from
    /// the wallet (removed, not moved to a backup), and the ESP notes its pending
    /// issues reserved (spent: their secrets went to the mint). `false` when the blacklist is
    /// at `fsp.blacklist_max` and the mint was not added: nothing is dropped then,
    /// and no entry is removed to make room.
    fn blacklist_fsp(
        &mut self,
        service: ServiceDid,
        site: Site,
        failed: &Failed,
    ) -> Result<bool, WalletError> {
        let listed = self.is_blacklisted(&service);
        let max = self.policy.blacklist_max;
        if !listed && max != 0 && self.data().blacklist.len() as u64 >= max {
            return Ok(false);
        }
        let now = sp_wire::air_request::addr::now_secs();
        let entry = BlacklistedMint {
            service,
            at: now,
            site: site.name().to_string(),
            what: failed.to_string(),
        };
        self.update(|d| {
            if !listed {
                d.blacklist.push(entry);
            }
            let mine = |n: &StoredNote| n.fsp_service() == Some(service);
            let ids: Vec<String> = d
                .notes
                .iter()
                .filter(|n| mine(n))
                .map(StoredNote::id)
                .collect();
            d.notes.retain(|n| !mine(n));
            for id in &ids {
                d.fsp_keysets.remove(id);
            }
            // The ESP notes a pending issue to this mint reserved are spent: the
            // request handed their spend secrets to the mint. They leave the
            // wallet with the request, so no note is left reserved by a request
            // that is gone.
            let issues: Vec<String> = d
                .pending_fsp
                .iter()
                .filter(|p| p.service == service)
                .map(|p| p.id.clone())
                .collect();
            d.notes
                .retain(|n| n.reserved_by.as_ref().is_none_or(|by| !issues.contains(by)));
            d.pending_fsp.retain(|p| p.service != service);
            d.fsp_mints.remove(&crate::fsp::record_of(service));
            let prefix = format!("fsp:{}|", service.to_hex());
            d.unpublished.retain(|k, _| !k.starts_with(&prefix));
            Ok(())
        })?;
        self.refresh_key_feed();
        Ok(true)
    }

    // ---- the entry points of the sites

    /// Check keys against the key sets a PSP or FSP mint published. `keyset` is
    /// the key set the reply says signed. A key set's ID is the hash of its keys
    /// and its stream cell is written once, so keys under that ID that are not
    /// the ones the wallet read from the stream are not the published ones: no
    /// fresh read can change that.
    pub(crate) fn check_keyset_keys(
        &mut self,
        party: Party,
        site: Site,
        keyset: &str,
        keys: &Keys,
    ) -> Result<(), WalletError> {
        let deadline = self.check_deadline();
        match self.settle(
            party,
            &|stream| check_keyset(stream, keyset, keys),
            deadline,
        )? {
            None => Ok(()),
            Some(failed) => Err(self.key_mismatch(party, site, failed)),
        }
    }

    /// Check keys the ESP signed a service's output with on `day` against the
    /// keys it published: the refund, decline and rollover of a note (the note's
    /// own day) and the keys of a new exchange. Before a mismatch the control
    /// stream is read once more and the day's keys are read again from AIR.
    pub(crate) fn check_esp_day_keys(
        &mut self,
        site: Site,
        keyset: &str,
        service: &ServiceDid,
        day: u64,
        keys: &Keys,
    ) -> Result<(), WalletError> {
        let eval = |stream: Option<&MintStream>| check_esp_keys(stream, keyset, service, day, keys);
        let deadline = self.check_deadline();
        if self.settle(Party::Esp, &eval, deadline)?.is_none() {
            return Ok(());
        }
        self.fresh_read(Party::Esp, Some(day_key(keyset, service, day)))?;
        let deadline = self.check_deadline();
        match self.settle(Party::Esp, &eval, deadline)? {
            None => Ok(()),
            Some(failed) => Err(self.key_mismatch(Party::Esp, site, failed)),
        }
    }

    /// Check the redeemable day of a new exchange (see [`check_exchange_day`]).
    /// When the day is outside the days the rules the wallet holds allow, the
    /// control stream is read once more (the rule `m` may have changed between
    /// the send and the reply), and then waited on up to [`KEY_CHECK_WAIT_SECS`]
    /// (an AIR server or a mint that lags), before the day is called a mismatch.
    /// The slack is [`DAY_SKEW_SECS`], with a key feed or without one.
    pub(crate) fn check_exchange_day_of(
        &mut self,
        first_sent_at: u64,
        replied_at: u64,
        day: u64,
    ) -> Result<(), WalletError> {
        let eval = |stream: Option<&MintStream>| {
            check_exchange_day(stream, first_sent_at, replied_at, DAY_SKEW_SECS, day)
        };
        let deadline = self.check_deadline();
        if self.settle(Party::Esp, &eval, deadline)?.is_none() {
            return Ok(());
        }
        // The one reread.
        self.fresh_read(Party::Esp, None)?;
        let deadline = self.check_deadline();
        loop {
            let Some(failed) = self.settle(Party::Esp, &eval, deadline)? else {
                return Ok(());
            };
            let seen = self.absorb_feed()?;
            let changed = match &self.feed {
                Some(feed) => feed.wait_change(seen, deadline),
                None => false,
            };
            if !changed {
                return Err(self.key_mismatch(Party::Esp, Site::FinishExchange, failed));
            }
        }
    }
}

/// Drop what the check no longer needs: the days no note or request of the wallet
/// is on (and that are past), the streams of FSP mints the wallet holds nothing
/// from (and their `unpublished` entries), the days of key sets the ESP no
/// longer lists as live while nothing is pending with it, and the `unpublished`
/// entries whose record the wallet has read.
fn prune(d: &mut crate::store::WalletData, today: u64) {
    let mut needed: BTreeSet<(String, u64)> = BTreeSet::new();
    for n in &d.notes {
        if let Some(t) = n.terms
            && n.kind == crate::store::Kind::Esp
        {
            needed.insert((t.service.to_hex(), t.redeemable_after_day));
        }
    }
    for p in &d.pending_exchanges {
        needed.insert((p.service.to_hex(), u64::MAX));
    }
    let any_pending = !d.pending_exchanges.is_empty()
        || !d.pending_redemptions.is_empty()
        || d.pending_rollovers
            .iter()
            .any(|p| p.kind == crate::store::Kind::Esp);
    let fsp_held: BTreeSet<String> = d
        .notes
        .iter()
        .filter_map(StoredNote::fsp_service)
        .map(|s| format!("fsp:{}", s.to_hex()))
        .chain(
            d.pending_fsp
                .iter()
                .map(|p| format!("fsp:{}", p.service.to_hex())),
        )
        .collect();
    d.key_streams
        .retain(|name, _| !name.starts_with("fsp:") || fsp_held.contains(name));
    let streams = &d.key_streams;
    d.unpublished.retain(|key, _| {
        let name = key.split_once('|').map(|(n, _)| n).unwrap_or(key);
        (!name.starts_with("fsp:") || fsp_held.contains(name)) && !is_read(streams, key)
    });
    if let Some(esp) = d.key_streams.get_mut("esp") {
        let live: BTreeSet<String> = esp
            .controls
            .last()
            .map(|c| {
                let mut v: BTreeSet<String> = c.previous_id.iter().cloned().collect();
                v.insert(c.current_id.clone());
                v
            })
            .unwrap_or_default();
        esp.days.retain(|key, _| {
            let mut parts = key.splitn(3, ':');
            let (Some(generation), Some(service), Some(day)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return false;
            };
            let Ok(day) = day.parse::<u64>() else {
                return false;
            };
            (live.is_empty() || live.contains(generation) || any_pending)
                && (day >= today || any_pending || needed.contains(&(service.to_string(), day)))
        });
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A stream the way the wallet reads one, for the unit tests that check a
    //! reply without a mint.

    use super::*;

    /// Put a key set the PSP or an FSP mint "published" in the wallet's streams
    /// (`name` is `psp` or `fsp:<service>`).
    pub(crate) fn publish_keyset(
        w: &mut Wallet,
        name: &str,
        did: &str,
        index: u32,
        epoch: u64,
        keys: &BTreeMap<u64, PublicKey>,
    ) {
        let record = KeysetRecord {
            epoch,
            keys: keys
                .iter()
                .map(|(a, k)| (sp_wire::Amount::from_units(*a), *k))
                .collect(),
        };
        let (name, did) = (name.to_string(), did.to_string());
        w.streams_are_fresh = true;
        w.update(|d| {
            let entry = d.key_streams.entry(name).or_default();
            entry.did = did;
            entry.apply_keyset(index, &record);
            Ok(())
        })
        .unwrap();
    }

    /// [`publish_keyset`] with the key set's ID given, for a test whose fixture
    /// names a key set by a fixed text and not by the hash of its keys.
    pub(crate) fn publish_keyset_as(
        w: &mut Wallet,
        name: &str,
        did: &str,
        index: u32,
        epoch: u64,
        id: &str,
        keys: &BTreeMap<u64, PublicKey>,
    ) {
        let (name, did, id, keys) = (
            name.to_string(),
            did.to_string(),
            id.to_string(),
            keys.clone(),
        );
        w.streams_are_fresh = true;
        w.update(|d| {
            let entry = d.key_streams.entry(name).or_default();
            entry.did = did;
            entry.keysets.retain(|k| k.index != index);
            entry.keysets.push(PublishedKeyset {
                index,
                epoch,
                id,
                keys,
            });
            entry.keysets.sort_by_key(|k| k.index);
            while entry.keysets.len() > KEEP_KEYSETS {
                entry.keysets.remove(0);
            }
            entry.next = entry.next.max(index.saturating_add(1));
            Ok(())
        })
        .unwrap();
    }

    /// Put a control record the ESP "published" in the wallet's streams: its
    /// maturity rule `m` and its live key sets.
    pub(crate) fn publish_control(
        w: &mut Wallet,
        index: u32,
        maturity_days: u64,
        current_id: &str,
        previous_id: Option<&str>,
    ) {
        let (current_id, previous_id) = (current_id.to_string(), previous_id.map(str::to_string));
        w.streams_are_fresh = true;
        w.update(|d| {
            let entry = d.key_streams.entry("esp".to_string()).or_default();
            if entry.did.is_empty() {
                entry.did = "00".to_string();
            }
            entry.controls.retain(|c| c.index != index);
            // As `take_control` does: every key set a record names is published.
            entry.generations.insert(current_id.clone());
            entry.generations.extend(previous_id.clone());
            entry.controls.push(PublishedControl {
                index,
                maturity_days,
                current_epoch: u64::from(index),
                current_id,
                previous_id,
            });
            entry.controls.sort_by_key(|c| c.index);
            while entry.controls.len() > KEEP_CONTROLS {
                entry.controls.remove(0);
            }
            entry.next = entry.next.max(index.saturating_add(1));
            Ok(())
        })
        .unwrap();
    }

    /// The unit tests' AIR for stream `name` (`psp`, `esp`, `fsp:<service>`):
    /// what the wallet holds of it, the first time.
    fn air<'a>(w: &'a mut Wallet, name: &str) -> &'a mut Scan {
        if !w.test_air.contains_key(name) {
            let s = w.data().key_streams.get(name).cloned().unwrap_or_default();
            let did = if s.did.is_empty() {
                "00".to_string()
            } else {
                s.did
            };
            w.test_air.insert(
                name.to_string(),
                Scan {
                    did,
                    end: s.next,
                    keysets: s.keysets,
                    controls: s.controls,
                },
            );
        }
        w.streams_are_fresh = true;
        w.test_air.get_mut(name).unwrap()
    }

    /// Write a key set on the unit tests' AIR, after the stream's end, without
    /// the wallet reading it. Returns its index.
    pub(crate) fn air_keyset(
        w: &mut Wallet,
        name: &str,
        id: &str,
        keys: &BTreeMap<u64, PublicKey>,
    ) -> u32 {
        let air = air(w, name);
        let index = air.end;
        air.keysets.push(PublishedKeyset {
            index,
            epoch: u64::from(index),
            id: id.to_string(),
            keys: keys.clone(),
        });
        air.end += 1;
        index
    }

    /// Write a control record of the ESP on the unit tests' AIR, after the
    /// stream's end, without the wallet reading it. Returns its index.
    pub(crate) fn air_control(
        w: &mut Wallet,
        maturity_days: u64,
        current_id: &str,
        previous_id: Option<&str>,
    ) -> u32 {
        let air = air(w, "esp");
        let index = air.end;
        air.controls.push(PublishedControl {
            index,
            maturity_days,
            current_epoch: u64::from(index),
            current_id: current_id.to_string(),
            previous_id: previous_id.map(str::to_string),
        });
        air.end += 1;
        index
    }

    /// Set this wallet's clock for the backstop.
    pub(crate) fn set_now(w: &mut Wallet, now: u64) {
        w.test_now = Some(now);
    }

    /// The `Failed::Unpublished` of a mismatch, and why. Panics on anything else.
    pub(crate) fn unpublished_of<T: fmt::Debug>(
        r: Result<T, WalletError>,
    ) -> (String, UnpublishedBy) {
        match r {
            Err(WalletError::KeyMismatch(m)) => match m.failed {
                Failed::Unpublished { record, by } => (record, by),
                other => panic!("expected Failed::Unpublished, got {other:?}"),
            },
            other => panic!("expected WalletError::KeyMismatch, got {other:?}"),
        }
    }

    /// The wallet file as a test compares it before and after a reply that
    /// changed nothing: without the first-seen times of missing records (the
    /// one thing such a reply writes) and the file's version.
    pub(crate) fn held(w: &Wallet) -> serde_json::Value {
        let mut v = serde_json::to_value(w.snapshot()).unwrap();
        let o = v.as_object_mut().unwrap();
        o.remove("unpublished");
        o.remove("version");
        v
    }

    /// The message of an error to retry (`WalletError::Mint`): what a check
    /// gives when a record is not published yet. Panics on anything else, a
    /// mismatch above all.
    pub(crate) fn retryable<T: fmt::Debug>(r: Result<T, WalletError>) -> String {
        match r {
            Err(WalletError::Mint(why)) => {
                assert!(
                    why.contains("nothing was stored") && why.contains("try again"),
                    "{why}"
                );
                why
            }
            other => panic!("expected an error to retry (WalletError::Mint), got {other:?}"),
        }
    }

    /// Put the 64 keys the ESP "published" for a service on a day in a key set
    /// in the wallet's streams.
    pub(crate) fn publish_day(
        w: &mut Wallet,
        generation: &str,
        service: &ServiceDid,
        day: u64,
        keys: Vec<PublicKey>,
    ) {
        let name = day_key(generation, service, day);
        w.streams_are_fresh = true;
        w.update(|d| {
            let entry = d.key_streams.entry("esp".to_string()).or_default();
            if entry.did.is_empty() {
                entry.did = "00".to_string();
            }
            entry.days.insert(name, keys);
            Ok(())
        })
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        secp256k1::SecretKey::from_slice(&bytes)
            .unwrap()
            .public_key(secp256k1::SECP256K1)
    }

    fn service(n: u8) -> ServiceDid {
        ServiceDid::from_slice(&key(n).serialize()).unwrap()
    }

    fn keyset_stream(ids: &[(&str, &[(u64, u8)])]) -> MintStream {
        let mut s = MintStream {
            did: "aa".into(),
            ..MintStream::default()
        };
        for (i, (id, keys)) in ids.iter().enumerate() {
            s.keysets.push(PublishedKeyset {
                index: i as u32,
                epoch: i as u64,
                id: (*id).to_string(),
                keys: keys.iter().map(|(a, n)| (*a, key(*n))).collect(),
            });
        }
        s
    }

    /// Fails if a check lets a key through that is not the published one, or
    /// looks at the 1-unit key only: the key of 32 units is wrong here and the
    /// 1-unit key is right.
    #[test]
    fn a_key_set_check_compares_every_key_not_only_the_one_unit_key() {
        let stream = keyset_stream(&[("k1", &[(1, 1), (32, 2), (64, 3)])]);
        let right = [(1u64, key(1)), (32, key(2)), (64, key(3))];
        assert_eq!(check_keyset(Some(&stream), "k1", &right), Verdict::Good);
        let wrong_32 = [(1u64, key(1)), (32, key(9)), (64, key(3))];
        assert_eq!(
            check_keyset(Some(&stream), "k1", &wrong_32),
            Verdict::Bad(Failed::Key { amount: 32 })
        );
        // an amount the mint never published a key for
        let extra = [(2u64, key(1))];
        assert_eq!(
            check_keyset(Some(&stream), "k1", &extra),
            Verdict::Bad(Failed::Key { amount: 2 })
        );
        // a key set that is not in the stream is not decided yet
        assert_eq!(
            check_keyset(Some(&stream), "other", &right),
            Verdict::Missing(Missing::Keyset("other".into()))
        );
        assert_eq!(
            check_keyset(None, "k1", &right),
            Verdict::Missing(Missing::Keyset("k1".into()))
        );
    }

    #[test]
    fn only_the_last_two_key_sets_are_kept_and_known() {
        let mut s = MintStream::default();
        for index in 0..3u32 {
            let mut keys = BTreeMap::new();
            keys.insert(sp_wire::Amount::from_units(1), key(10 + index as u8));
            s.apply_keyset(
                index,
                &KeysetRecord {
                    epoch: u64::from(index),
                    keys,
                },
            );
        }
        assert_eq!(s.keysets.len(), 2);
        assert_eq!(s.keysets[0].index, 1);
        assert_eq!(s.keysets[1].index, 2);
        assert_eq!(s.next, 3);
        // the oldest of three is two rotations old: it is not known
        let oldest = KeysetRecord {
            epoch: 0,
            keys: BTreeMap::from([(sp_wire::Amount::from_units(1), key(10))]),
        }
        .id();
        assert!(s.keyset(&oldest).is_none());
    }

    fn esp_stream(rules: &[u64]) -> MintStream {
        let mut s = MintStream {
            did: "bb".into(),
            ..MintStream::default()
        };
        for (i, m) in rules.iter().enumerate() {
            s.controls.push(PublishedControl {
                index: i as u32,
                maturity_days: *m,
                current_epoch: 0,
                current_id: "g0".into(),
                previous_id: None,
            });
        }
        s
    }

    /// The edges of the day window, with literal days (see the brief, T4):
    /// sent at day S = 20,000, replied at day R = 20,001, m = 365: the days
    /// S + m = 20,365 to R + m = 20,366.
    #[test]
    fn the_exchange_day_window_includes_both_edges_and_nothing_outside() {
        let stream = esp_stream(&[365]);
        let s = 20_000 * SECONDS_PER_DAY + 43_200; // noon of day S
        let r = 20_001 * SECONDS_PER_DAY + 43_200; // noon of day R
        let at = |day| check_exchange_day(Some(&stream), s, r, 300, day);
        assert_eq!(at(20_365), Verdict::Good);
        assert_eq!(at(20_366), Verdict::Good);
        assert_eq!(
            at(20_364),
            Verdict::Bad(Failed::Day {
                day: 20_364,
                from: 20_365,
                to: 20_366,
                rules: vec![365]
            })
        );
        assert!(matches!(at(20_367), Verdict::Bad(Failed::Day { .. })));
    }

    /// The skew moves each edge by the 300 s, exactly: sent at S x 86,400 + 100
    /// the send day is S - 1 (100 - 300 < 0), so S - 1 + m is allowed; at + 300
    /// it is S, so S - 1 + m is not. Replied at (R + 1) x 86,400 - 300 the reply
    /// day is R + 1; one second earlier it is R.
    #[test]
    fn the_skew_moves_each_edge_by_exactly_the_setting() {
        let stream = esp_stream(&[365]);
        let (s, r) = (20_000u64, 20_001u64);
        let sent = |t: u64, replied: u64, day: u64| {
            check_exchange_day(Some(&stream), t, replied, 300, day)
        };
        let mid = r * SECONDS_PER_DAY + 43_200;
        // S - 1 + m = 20,364
        assert_eq!(sent(s * SECONDS_PER_DAY + 100, mid, 20_364), Verdict::Good);
        assert!(matches!(
            sent(s * SECONDS_PER_DAY + 300, mid, 20_364),
            Verdict::Bad(Failed::Day { .. })
        ));
        // R + 1 + m = 20,367
        let sent_at = s * SECONDS_PER_DAY + 43_200;
        assert_eq!(
            sent(sent_at, (r + 1) * SECONDS_PER_DAY - 300, 20_367),
            Verdict::Good
        );
        assert!(matches!(
            sent(sent_at, (r + 1) * SECONDS_PER_DAY - 301, 20_367),
            Verdict::Bad(Failed::Day { .. })
        ));
    }

    /// Two rules (the stream published m1 = 365, then m2 = 30): a day valid under
    /// either is allowed; a day valid under neither is not.
    #[test]
    fn a_day_valid_under_the_rule_before_the_last_change_is_allowed_too() {
        let stream = esp_stream(&[365, 30]);
        let t = 20_000 * SECONDS_PER_DAY + 43_200;
        let at = |day| check_exchange_day(Some(&stream), t, t, 300, day);
        assert_eq!(at(20_365), Verdict::Good); // m = 365
        assert_eq!(at(20_030), Verdict::Good); // m = 30
        assert!(matches!(at(20_200), Verdict::Bad(Failed::Day { .. })));
        // no control record read yet: not decided
        assert_eq!(
            check_exchange_day(Some(&MintStream::default()), t, t, 300, 20_365),
            Verdict::Missing(Missing::Control)
        );
    }

    #[test]
    fn an_esp_key_is_checked_against_its_day_and_generation() {
        let mut stream = esp_stream(&[365]);
        let svc = service(7);
        let keys: Vec<PublicKey> = (0..64u8).map(|i| key(i + 1)).collect();
        stream.days.insert(day_key("g0", &svc, 20_365), keys);
        let right = [(1u64, key(1)), (8, key(4)), (1 << 63, key(64))];
        assert_eq!(
            check_esp_keys(Some(&stream), "g0", &svc, 20_365, &right),
            Verdict::Good
        );
        // the key of 8 units is the 4th (2^3): key(4). key(5) is the 16-unit one.
        let wrong = [(1u64, key(1)), (8, key(5))];
        assert_eq!(
            check_esp_keys(Some(&stream), "g0", &svc, 20_365, &wrong),
            Verdict::Bad(Failed::Key { amount: 8 })
        );
        // an amount that is not a power of two has no published key
        let odd = [(3u64, key(1))];
        assert_eq!(
            check_esp_keys(Some(&stream), "g0", &svc, 20_365, &odd),
            Verdict::Bad(Failed::Key { amount: 3 })
        );
        // another day, another service, a key set that is not live
        assert!(matches!(
            check_esp_keys(Some(&stream), "g0", &svc, 20_366, &right),
            Verdict::Missing(Missing::Day { .. })
        ));
        assert!(matches!(
            check_esp_keys(Some(&stream), "g0", &service(8), 20_365, &right),
            Verdict::Missing(Missing::Day { .. })
        ));
        assert_eq!(
            check_esp_keys(Some(&stream), "gone", &svc, 20_365, &right),
            Verdict::Missing(Missing::Keyset("gone".into()))
        );
    }

    // ---- the wallet: a failed check, the blacklist

    fn scratch_wallet(name: &str) -> (Wallet, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "ecash-wallet-keystream-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (
            Wallet::open(&dir.join("wallet.json"), "regtest").unwrap(),
            dir,
        )
    }

    fn fsp_note(seed: u8, amount: u64, service: ServiceDid) -> StoredNote {
        let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let pk = sk.public_key(secp256k1::SECP256K1);
        StoredNote {
            kind: crate::store::Kind::Fsp,
            amount,
            note: mint_types::Note {
                nonce: mint_types::Nonce(pk),
                signature: pk,
            },
            spend_secret: sk,
            terms: Some(crate::store::StoredTerms {
                service,
                redeemable_after_day: 0,
            }),
            reserved_by: None,
        }
    }

    /// A wallet holding FSP notes of 8 and 4 units from the FSP mints of
    /// `services`, whose key set `k1` has the key `key(1)` for 8 units and
    /// `key(2)` for 4.
    fn wallet_with_fsp_mints(name: &str, services: &[ServiceDid]) -> (Wallet, std::path::PathBuf) {
        let (mut w, dir) = scratch_wallet(name);
        let keys = BTreeMap::from([(8u64, key(1)), (4u64, key(2))]);
        for (i, s) in services.iter().enumerate() {
            let notes = [
                fsp_note(10 + 2 * i as u8, 8, *s),
                fsp_note(11 + 2 * i as u8, 4, *s),
            ];
            w.update(|d| {
                d.notes.extend(notes);
                Ok(())
            })
            .unwrap();
            testing::publish_keyset_as(
                &mut w,
                &format!("fsp:{}", s.to_hex()),
                "00",
                0,
                0,
                "k1",
                &keys,
            );
        }
        (w, dir)
    }

    fn the_mismatch<T: fmt::Debug>(r: Result<T, WalletError>) -> Box<KeyMismatch> {
        match r {
            Err(WalletError::KeyMismatch(m)) => m,
            other => panic!("expected WalletError::KeyMismatch, got {other:?}"),
        }
    }

    const WRONG_4: [(u64, u8); 2] = [(8, 1), (4, 9)];

    fn keys_of_pairs(pairs: &[(u64, u8)]) -> Vec<(u64, PublicKey)> {
        pairs.iter().map(|(a, n)| (*a, key(*n))).collect()
    }

    /// With `fsp.blacklist_on_key_mismatch` off (the default), an FSP mint that
    /// signed one amount (the 4-unit one, not the 8-unit one the first key is
    /// for) with an unpublished key warns, keeps the notes, and is not
    /// blacklisted; the right keys pass. Fails if the default blacklists, if the
    /// notes are dropped, or if the warning does not name the mint and the site.
    #[test]
    fn with_the_blacklist_off_a_failing_fsp_mint_warns_and_keeps_its_notes() {
        let (a, b) = (service(1), service(2));
        let (mut w, dir) = wallet_with_fsp_mints("off", &[a, b]);
        assert_eq!(w.key_policy(), KeyPolicy::default());
        let m = the_mismatch(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspSpend,
            "k1",
            &keys_of_pairs(&WRONG_4),
        ));
        assert_eq!(m.mint, "FSP mint");
        assert_eq!(m.service.as_deref(), Some(a.to_hex().as_str()));
        assert_eq!(m.site, Site::FinishFspSpend);
        assert_eq!(m.failed, Failed::Key { amount: 4 });
        assert!(!m.blacklisted);
        assert!(m.warning.contains("finish_fsp_spend"), "{}", m.warning);
        assert!(m.warning.contains(&a.to_hex()), "{}", m.warning);
        assert!(
            m.warning.ends_with(
                "This FSP mint is NOT blacklisted (fsp.blacklist_on_key_mismatch is off)."
            )
        );
        assert_eq!(w.notes().len(), 4, "every note is kept");
        assert!(w.blacklist().is_empty());
        assert!(!w.is_blacklisted(&a));
        // the right keys pass, and a request to the mint is not refused
        w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspSpend,
            "k1",
            &keys_of_pairs(&[(8, 1), (4, 2)]),
        )
        .unwrap();
        w.refuse_blacklisted(Party::Fsp(a)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// With it on, the same failure blacklists that mint alone and drops its
    /// notes (removed, not backed up); the other mint's notes stay; the entry
    /// names the place and what failed, survives a restart, makes the next
    /// request to the mint refuse with the reason, and goes only by hand. Fails
    /// if the notes stay, if another mint's notes go, or if the entry is lost.
    #[test]
    fn with_the_blacklist_on_a_failing_fsp_mint_is_blacklisted_and_its_notes_are_dropped() {
        let (a, b) = (service(1), service(2));
        let (mut w, dir) = wallet_with_fsp_mints("on", &[a, b]);
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1000,
        });
        let m = the_mismatch(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspIssue,
            "k1",
            &keys_of_pairs(&WRONG_4),
        ));
        assert!(m.blacklisted);
        assert!(m.warning.ends_with("This FSP mint is now BLACKLISTED (fsp.blacklist_on_key_mismatch is on): its notes were DROPPED from this wallet, and no request will be sent to it until an operator removes it from the blacklist by hand."), "{}", m.warning);
        assert_eq!(w.notes().len(), 2);
        assert!(w.notes().iter().all(|n| n.fsp_service() == Some(b)));
        assert!(w.balance().spent_elsewhere == 0 && w.spent_notes().is_empty());
        assert_eq!(w.blacklist().len(), 1);
        assert_eq!(w.blacklist()[0].service, a);
        assert_eq!(w.blacklist()[0].site, "finish_fsp_issue");
        assert_eq!(
            w.blacklist()[0].what,
            "signed the output of 4 unit(s) with a KEY that is not the key it published"
        );

        // after a restart: still blacklisted, and a request to it is refused
        let mut again = Wallet::open(w.path(), "regtest").unwrap();
        assert!(again.is_blacklisted(&a) && !again.is_blacklisted(&b));
        match again.refuse_blacklisted(Party::Fsp(a)) {
            Err(WalletError::Blacklisted(why)) => {
                assert!(
                    why.contains(&format!(
                        "the FSP mint of service {} is BLACKLISTED",
                        a.to_hex()
                    )),
                    "{why}"
                );
                assert!(why.contains("finish_fsp_issue"), "{why}");
                assert!(
                    why.contains(&format!(
                        "ecash-wallet blacklist remove --service {}",
                        a.to_hex()
                    )),
                    "{why}"
                );
            }
            other => panic!("expected WalletError::Blacklisted, got {other:?}"),
        }
        again.refuse_blacklisted(Party::Fsp(b)).unwrap();

        // by hand, and only by hand
        assert!(again.unblacklist(&a).unwrap());
        assert!(!again.unblacklist(&a).unwrap());
        again.refuse_blacklisted(Party::Fsp(a)).unwrap();
        assert_eq!(again.notes().len(), 2, "the dropped notes do not come back");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// At `fsp.blacklist_max` a mint that fails is not added, nothing is dropped
    /// and nothing is removed to make room; the warning says the blacklist is
    /// full. 0 is no cap. Fails if the cap is ignored or an entry is evicted.
    #[test]
    fn at_the_blacklist_cap_the_mint_is_not_added_and_nothing_is_dropped() {
        let (a, b, c) = (service(1), service(2), service(3));
        let (mut w, dir) = wallet_with_fsp_mints("cap", &[a, b, c]);
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1,
        });
        assert!(
            the_mismatch(w.check_keyset_keys(
                Party::Fsp(a),
                Site::FinishFspSpend,
                "k1",
                &keys_of_pairs(&WRONG_4)
            ))
            .blacklisted
        );
        let m = the_mismatch(w.check_keyset_keys(
            Party::Fsp(b),
            Site::FinishFspSpend,
            "k1",
            &keys_of_pairs(&WRONG_4),
        ));
        assert!(!m.blacklisted);
        assert!(m.warning.ends_with("The blacklist is FULL (1 entries, fsp.blacklist_max), so this FSP mint was NOT blacklisted and its notes were kept. Remove entries by hand, or raise fsp.blacklist_max."), "{}", m.warning);
        assert_eq!(w.blacklist().len(), 1);
        assert_eq!(w.blacklist()[0].service, a, "no entry was evicted");
        assert_eq!(w.notes().len(), 4, "a's notes dropped; b's and c's kept");
        // 0: no cap
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 0,
        });
        assert!(
            the_mismatch(w.check_keyset_keys(
                Party::Fsp(b),
                Site::FinishFspSpend,
                "k1",
                &keys_of_pairs(&WRONG_4)
            ))
            .blacklisted
        );
        assert!(
            the_mismatch(w.check_keyset_keys(
                Party::Fsp(c),
                Site::FinishFspSpend,
                "k1",
                &keys_of_pairs(&WRONG_4)
            ))
            .blacklisted
        );
        assert_eq!(w.blacklist().len(), 3);
        assert!(w.notes().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The SPI's PSP and ESP mints are never blacklisted, with the setting on:
    /// each failure warns, keeps the notes, and blacklists nothing. Fails if a
    /// PSP or ESP failure reaches the blacklist or drops a note.
    #[test]
    fn the_psp_and_the_esp_are_never_blacklisted_they_only_warn() {
        let (mut w, dir) = scratch_wallet("spi");
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1000,
        });
        let keys = BTreeMap::from([(8u64, key(1)), (4u64, key(2))]);
        testing::publish_keyset_as(&mut w, "psp", "00", 0, 0, "k1", &keys);
        let held = fsp_note(30, 8, service(1));
        w.update(|d| {
            d.notes.push(held);
            Ok(())
        })
        .unwrap();
        let m = the_mismatch(w.check_keyset_keys(
            Party::Psp,
            Site::ApplyClaim,
            "k1",
            &keys_of_pairs(&WRONG_4),
        ));
        assert_eq!((m.mint, m.blacklisted), ("PSP mint", false));
        assert!(
            m.warning
                .ends_with("The SPI's PSP and ESP mints are never blacklisted: this only warns."),
            "{}",
            m.warning
        );

        testing::publish_control(&mut w, 0, 365, "g0", None);
        let day_keys: Vec<PublicKey> = (0..64u8).map(|i| key(i + 1)).collect();
        testing::publish_day(&mut w, "g0", &service(1), 20_000, day_keys);
        // key(4) is the 8-unit key (2^3); key(1) is the 1-unit one.
        let m = the_mismatch(w.check_esp_day_keys(
            Site::RedeemDecline,
            "g0",
            &service(1),
            20_000,
            &keys_of_pairs(&[(8, 1)]),
        ));
        assert_eq!((m.mint, m.blacklisted), ("ESP mint", false));
        assert_eq!(m.failed, Failed::Key { amount: 8 });
        assert!(w.blacklist().is_empty());
        assert_eq!(w.notes().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn esp_note(
        seed: u8,
        amount: u64,
        service: ServiceDid,
        reserved_by: Option<&str>,
    ) -> StoredNote {
        let mut n = fsp_note(seed, amount, service);
        n.kind = crate::store::Kind::Esp;
        n.terms = Some(crate::store::StoredTerms {
            service,
            redeemable_after_day: 20_365,
        });
        n.reserved_by = reserved_by.map(str::to_string);
        n
    }

    fn pending_issue(id: &str, service: ServiceDid) -> crate::fsp::PendingFsp {
        crate::fsp::PendingFsp {
            id: id.to_string(),
            service,
            op: crate::fsp::FspOp::Issue {
                request: sp_wire::fsp::IssueRequest {
                    service,
                    groups: Vec::new(),
                },
                outputs: Vec::new(),
                notes: Vec::new(),
            },
        }
    }

    /// Finding B: blacklisting an FSP mint drops, with its pending issues, the
    /// ESP notes those issues reserved: the requests handed their spend secrets
    /// to the mint, so they are spent. ESP notes that are free, or reserved by an
    /// issue to another FSP mint, stay. Fails if a reserved note is left behind
    /// (a `reserved_by` naming a request that is gone) or another note goes.
    #[test]
    fn a_blacklisted_fsp_mint_takes_the_esp_notes_its_pending_issues_reserved() {
        let (a, b) = (service(1), service(2));
        let (mut w, dir) = wallet_with_fsp_mints("reserved", &[a, b]);
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1000,
        });
        let (to_a, to_b) = (
            esp_note(40, 16, a, Some("issue-a")),
            esp_note(41, 32, b, Some("issue-b")),
        );
        let free = esp_note(42, 64, a, None);
        let (to_a_id, to_b_id, free_id) = (to_a.id(), to_b.id(), free.id());
        w.update(|d| {
            d.notes.extend([to_a, to_b, free]);
            d.pending_fsp.push(pending_issue("issue-a", a));
            d.pending_fsp.push(pending_issue("issue-b", b));
            Ok(())
        })
        .unwrap();
        assert_eq!(w.notes().len(), 7);

        let m = the_mismatch(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspIssue,
            "k1",
            &keys_of_pairs(&WRONG_4),
        ));
        assert!(m.blacklisted);
        let ids: Vec<String> = w.notes().iter().map(StoredNote::id).collect();
        assert!(
            !ids.contains(&to_a_id),
            "the ESP note issue-a reserved is spent"
        );
        assert!(ids.contains(&to_b_id) && ids.contains(&free_id));
        // b's two FSP notes, b's reserved ESP note, the free ESP note
        assert_eq!(w.notes().len(), 4);
        assert_eq!(w.pending_fsp().len(), 1);
        assert_eq!(w.pending_fsp()[0].id, "issue-b");
        let pending: Vec<&str> = w.pending_fsp().iter().map(|p| p.id.as_str()).collect();
        assert!(
            w.notes().iter().all(|n| n
                .reserved_by
                .as_deref()
                .is_none_or(|by| pending.contains(&by))),
            "no note is reserved by a request that is gone"
        );
        // it is saved that way
        let again = Wallet::open(w.path(), "regtest").unwrap();
        assert_eq!(again.notes().len(), 4);
        assert!(again.notes().iter().all(|n| n.id() != to_a_id));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding C / ASK 6: a record that is not published (yet) is an error to
    /// retry and never a mismatch, for every mint: a PSP or FSP key set, the
    /// ESP's control record, a key set the ESP does not list as live, an ESP day.
    /// The wallet is not changed, nothing is blacklisted (with the policy on), no
    /// warning is made. Fails if any of them is a `KeyMismatch`.
    #[test]
    fn a_record_not_published_yet_is_an_error_to_retry_for_every_mint() {
        let (a, svc) = (service(1), service(7));
        let (mut w, dir) = wallet_with_fsp_mints("not-yet", &[a]);
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1000,
        });
        let keys = BTreeMap::from([(8u64, key(1)), (4u64, key(2))]);
        testing::publish_keyset_as(&mut w, "psp", "00", 0, 0, "k1", &keys);
        let right = keys_of_pairs(&[(8, 1), (4, 2)]);
        // Nothing changes but the first-seen entries of the missing records.
        let held = testing::held;
        let before = held(&w);
        let unchanged = |w: &Wallet| {
            assert_eq!(held(w), before);
            assert!(w.blacklist().is_empty());
        };

        let why = testing::retryable(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspIssue,
            "k2",
            &right,
        ));
        assert!(
            why.contains("the FSP mint has not published key set k2 (its key sets: k1)"),
            "{why}"
        );
        unchanged(&w);
        let why =
            testing::retryable(w.check_keyset_keys(Party::Psp, Site::ApplyClaim, "k2", &right));
        assert!(
            why.contains("the PSP mint has not published key set k2"),
            "{why}"
        );
        unchanged(&w);

        // The ESP: no control record read at all (nothing on its stream).
        testing::retryable(w.check_esp_day_keys(Site::RedeemRefund, "g0", &svc, 20_000, &right));
        testing::retryable(w.check_exchange_day_of(0, 0, 20_365));
        unchanged(&w);

        testing::publish_control(&mut w, 0, 365, "g0", None);
        let before = held(&w);
        // A key set the control record does not list (a rotation not read yet).
        let why = testing::retryable(w.check_esp_day_keys(
            Site::RedeemRefund,
            "g1",
            &svc,
            20_000,
            &right,
        ));
        assert!(
            why.contains("has not published key set g1 as a live key set (its live key sets: g0)"),
            "{why}"
        );
        // A day not published yet.
        let why = testing::retryable(w.check_esp_day_keys(
            Site::RedeemRefund,
            "g0",
            &svc,
            20_000,
            &right,
        ));
        assert!(
            why.contains("the keys of this service for day 20000 in key set g0"),
            "{why}"
        );
        assert_eq!(held(&w), before);
        assert!(w.blacklist().is_empty());
        assert!(w.notes().len() == 2 && !w.data().unpublished.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ------------------------------------------- round 3: never published at all

    const T0: u64 = 1_800_000_000;

    /// The PSP or FSP stream `name` of a unit test, with the wallet's clock at
    /// `T0`: what is on AIR is what the wallet holds.
    fn at_t0(w: &mut Wallet) {
        testing::set_now(w, T0);
        w.streams_are_fresh = true;
    }

    /// An honest mint whose writer is behind: the key set it signed under is
    /// missing, the in-flight pass writes the two records it was writing, the
    /// clock runs to one second before the backstop, and the reply is still an
    /// error to retry each time. When the key set is written, the reply is
    /// accepted and the first-seen entry goes. Fails if the late mint is
    /// flagged at any point, or the entry is left behind.
    #[test]
    fn an_honest_late_key_set_stays_retryable_and_is_taken_in_when_written() {
        let a = service(1);
        let name = format!("fsp:{}", a.to_hex());
        let (mut w, dir) = wallet_with_fsp_mints("late", &[a]);
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1000,
        });
        at_t0(&mut w);
        let keys = BTreeMap::from([(8u64, key(1)), (4u64, key(2))]);
        let right = keys_of_pairs(&[(8, 1), (4, 2)]);
        let check =
            |w: &mut Wallet| w.check_keyset_keys(Party::Fsp(a), Site::FinishFspIssue, "k2", &right);
        let why = testing::retryable(check(&mut w));
        assert!(
            why.contains("once its stream holds 4 records written after record 0 without it")
                && why.contains("in 86400 s if it is still not published"),
            "{why}"
        );
        let key = format!("{name}|keyset:k2");
        assert_eq!(
            w.data().unpublished.get(&key).copied(),
            Some(Unpublished {
                since: T0,
                end: Some(1)
            })
        );
        // The pass in flight writes the two records it was writing.
        testing::air_keyset(&mut w, &name, "p1", &keys);
        testing::air_keyset(&mut w, &name, "p2", &keys);
        testing::set_now(&mut w, T0 + UNPUBLISHED_BACKSTOP_SECS - 1);
        let why = testing::retryable(check(&mut w));
        assert!(why.contains("in 1 s if it is still not published"), "{why}");
        // Then the key set: taken in, the reply accepted, the entry gone.
        testing::air_keyset(&mut w, &name, "k2", &keys);
        check(&mut w).unwrap();
        assert!(
            w.data().unpublished.is_empty(),
            "{:?}",
            w.data().unpublished
        );
        assert!(w.blacklist().is_empty());
        assert_eq!(w.notes().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A PSP or FSP key set never published is a mismatch once its stream holds
    /// four records written after the read that missed it (two the pass in
    /// flight may write, two of a later pass that would have written it had it
    /// been live), and not at three. Fails if it is flagged early, or never.
    #[test]
    fn a_key_set_never_published_is_flagged_once_newer_records_exist() {
        let a = service(1);
        let (mut w, dir) = wallet_with_fsp_mints("never", &[a]);
        at_t0(&mut w);
        let keys = BTreeMap::from([(8u64, key(1)), (4u64, key(2))]);
        let right = keys_of_pairs(&[(8, 1), (4, 2)]);
        for name in [format!("fsp:{}", a.to_hex()), "psp".to_string()] {
            let party = if name == "psp" {
                Party::Psp
            } else {
                Party::Fsp(a)
            };
            if name == "psp" {
                testing::publish_keyset_as(&mut w, "psp", "00", 0, 0, "k1", &keys);
            }
            let check = |w: &mut Wallet| w.check_keyset_keys(party, Site::ApplyClaim, "k9", &right);
            testing::retryable(check(&mut w));
            for i in 0..3 {
                testing::air_keyset(&mut w, &name, &format!("n{i}"), &keys);
                testing::retryable(check(&mut w));
            }
            testing::air_keyset(&mut w, &name, "n3", &keys);
            let (record, by) = testing::unpublished_of(check(&mut w));
            assert_eq!(record, "KEY SET k9");
            assert_eq!(
                by,
                UnpublishedBy::NewerRecords {
                    from: 1,
                    end: 5,
                    needed: NEWER_KEYSETS
                }
            );
            let m = the_mismatch(check(&mut w));
            assert!(
                m.warning.contains("KEY CHECK FAILED")
                    && m.warning.contains("which it has NOT PUBLISHED on AIR"),
                "{}",
                m.warning
            );
            assert!(!m.blacklisted, "the blacklist is off by default");
        }
        assert_eq!(
            w.notes().len(),
            2,
            "nothing is dropped with the blacklist off"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// With no newer record at all, the backstop flags the missing record when
    /// it has passed since the wallet first read the stream without it (a
    /// fixed clock), and not a second before. The wallet started again keeps
    /// the first-seen time. The backstop is a fixed day: no policy changes it.
    #[test]
    fn the_backstop_flags_a_missing_record_and_a_restart_keeps_the_first_seen_time() {
        let a = service(1);
        let (mut w, dir) = wallet_with_fsp_mints("backstop", &[a]);
        at_t0(&mut w);
        let right = keys_of_pairs(&[(8, 1), (4, 2)]);
        testing::retryable(w.check_keyset_keys(Party::Fsp(a), Site::FinishFspSpend, "k9", &right));

        // Started again a day less a second later: same first-seen time.
        let path = w.path().to_path_buf();
        drop(w);
        let mut w = Wallet::open(&path, "regtest").unwrap();
        w.streams_are_fresh = true;
        testing::set_now(&mut w, T0 + 86_399);
        let why = testing::retryable(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspSpend,
            "k9",
            &right,
        ));
        assert!(why.contains("in 1 s if it is still not published"), "{why}");
        let key = format!("fsp:{}|keyset:k9", a.to_hex());
        assert_eq!(w.data().unpublished[&key].since, T0);

        // Whatever the policy an app sets (the blacklist only), the backstop
        // is the same day: there is nothing else to set.
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: false,
            blacklist_max: 0,
        });

        // At T0 + one day: flagged.
        testing::set_now(&mut w, T0 + 86_400);
        let (record, by) = testing::unpublished_of(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspSpend,
            "k9",
            &right,
        ));
        assert_eq!(record, "KEY SET k9");
        assert_eq!(
            by,
            UnpublishedBy::Backstop {
                since: T0,
                secs: 86_400
            }
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The ESP: a key set no control record names is flagged after two newer
    /// control records (one record per pass); its control record, with
    /// nothing on its stream, and its day keys, however many records follow,
    /// have no ordering to go by and are flagged by the backstop only. Day
    /// parts are written in sequence and one pass may write any number of
    /// them, so records after a day never count against it. Fails if a day or
    /// an empty control stream is flagged by newer records, or the key set is
    /// not flagged after two.
    #[test]
    fn esp_records_never_published_are_flagged_by_their_own_rule() {
        let svc = service(7);
        let (mut w, dir) = scratch_wallet("esp-never");
        at_t0(&mut w);
        let right = keys_of_pairs(&[(8, 4)]);
        let t = 20_000 * SECONDS_PER_DAY + 43_200;

        // No control record at all: backstop only.
        let why = testing::retryable(w.check_exchange_day_of(t, t, 20_365));
        assert!(!why.contains("records written"), "{why}");
        testing::set_now(&mut w, T0 + 86_400);
        let (record, by) = testing::unpublished_of(w.check_exchange_day_of(t, t, 20_365));
        assert!(record.contains("control"), "{record}");
        assert!(
            matches!(by, UnpublishedBy::Backstop { since: T0, .. }),
            "{by:?}"
        );
        testing::set_now(&mut w, T0);

        testing::air_control(&mut w, 365, "g0", None);
        w.check_exchange_day_of(t, t, 20_365).unwrap();
        assert!(
            !w.data().unpublished.contains_key("esp|control"),
            "found: the entry goes"
        );

        // A key set no control record names: two newer records.
        let check_g9 =
            |w: &mut Wallet| w.check_esp_day_keys(Site::RedeemRefund, "g9", &svc, 20_000, &right);
        let why = testing::retryable(check_g9(&mut w));
        assert!(why.contains("once its stream holds 2 records"), "{why}");
        testing::air_control(&mut w, 365, "g1", Some("g0"));
        testing::retryable(check_g9(&mut w));
        testing::air_control(&mut w, 365, "g2", Some("g1"));
        let (record, by) = testing::unpublished_of(check_g9(&mut w));
        assert_eq!(record, "KEY SET g9");
        assert_eq!(
            by,
            UnpublishedBy::NewerRecords {
                from: 1,
                end: 3,
                needed: NEWER_CONTROLS
            }
        );

        // A day of a live key set, never written: any number of records after
        // it change nothing; the backstop flags it.
        let check_day =
            |w: &mut Wallet| w.check_esp_day_keys(Site::RedeemRefund, "g2", &svc, 20_000, &right);
        let why = testing::retryable(check_day(&mut w));
        assert!(!why.contains("records written"), "{why}");
        for i in 3..9 {
            testing::air_control(&mut w, 365, "g2", Some("g1"));
            let _ = i;
            testing::retryable(check_day(&mut w));
        }
        testing::set_now(&mut w, T0 + 86_399);
        testing::retryable(check_day(&mut w));
        testing::set_now(&mut w, T0 + 86_400);
        let (record, by) = testing::unpublished_of(check_day(&mut w));
        assert!(record.contains("day 20000 in key set g2"), "{record}");
        assert_eq!(
            by,
            UnpublishedBy::Backstop {
                since: T0,
                secs: 86_400
            }
        );

        // Written late but before the backstop: accepted, the entry goes.
        testing::set_now(&mut w, T0);
        w.update(|d| {
            d.unpublished.clear();
            Ok(())
        })
        .unwrap();
        testing::retryable(check_day(&mut w));
        testing::publish_day(
            &mut w,
            "g2",
            &svc,
            20_000,
            (0..64u8).map(|i| key(i + 1)).collect(),
        );
        check_day(&mut w).unwrap();
        assert!(
            w.data().unpublished.is_empty(),
            "{:?}",
            w.data().unpublished
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A reply stored while the wallet was away for more than two rotations is
    /// checked against the key set it was signed under, read from the whole
    /// stream: accepted when the keys agree, a mismatch when they do not, and
    /// never "not published". The ESP the same, for a key set an old control
    /// record named.
    #[test]
    fn a_reply_from_more_than_two_rotations_back_is_checked_against_the_whole_stream() {
        let svc = service(7);
        let (mut w, dir) = scratch_wallet("old-reply");
        at_t0(&mut w);
        let keys = |n: u8| BTreeMap::from([(8u64, key(n)), (4u64, key(n + 1))]);
        for i in 0..4u8 {
            testing::air_keyset(&mut w, "psp", &format!("k{i}"), &keys(10 * i + 1));
        }
        for i in 2..4u8 {
            testing::publish_keyset_as(
                &mut w,
                "psp",
                "00",
                u32::from(i),
                0,
                &format!("k{i}"),
                &keys(10 * i + 1),
            );
        }
        assert!(w.data().key_streams["psp"].keyset("k0").is_none());
        w.check_keyset_keys(
            Party::Psp,
            Site::ApplyClaim,
            "k0",
            &keys_of_pairs(&[(8, 1), (4, 2)]),
        )
        .unwrap();
        assert!(w.data().key_streams["psp"].keyset("k0").is_some());
        let m = the_mismatch(w.check_keyset_keys(
            Party::Psp,
            Site::ApplyClaim,
            "k0",
            &keys_of_pairs(&[(8, 1), (4, 9)]),
        ));
        assert_eq!(m.failed, Failed::Key { amount: 4 });

        // The ESP: g0 is named only by records 0 and 1; the wallet holds 2 and 3.
        testing::air_control(&mut w, 365, "g0", None);
        testing::air_control(&mut w, 365, "g1", Some("g0"));
        testing::air_control(&mut w, 365, "g2", Some("g1"));
        testing::air_control(&mut w, 365, "g3", Some("g2"));
        testing::publish_control(&mut w, 2, 365, "g2", Some("g1"));
        testing::publish_control(&mut w, 3, 365, "g3", Some("g2"));
        testing::publish_day(
            &mut w,
            "g0",
            &svc,
            20_000,
            (0..64u8).map(|i| key(i + 1)).collect(),
        );
        w.check_esp_day_keys(
            Site::RedeemRefund,
            "g0",
            &svc,
            20_000,
            &keys_of_pairs(&[(8, 4)]),
        )
        .unwrap();
        assert!(
            w.data().unpublished.is_empty(),
            "{:?}",
            w.data().unpublished
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// With the blacklist on, an FSP mint flagged for a key set it never
    /// published is blacklisted like any mismatch: its notes, its pending
    /// issue and the ESP notes that issue reserved are dropped, and its
    /// first-seen entries go. Fails if a reserved ESP note is left behind.
    #[test]
    fn a_blacklisted_unpublished_fsp_mint_takes_the_esp_notes_its_issues_reserved() {
        let (a, b) = (service(1), service(2));
        let (mut w, dir) = wallet_with_fsp_mints("unpub-reserved", &[a, b]);
        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1000,
        });
        at_t0(&mut w);
        let (to_a, free) = (
            esp_note(40, 16, a, Some("issue-a")),
            esp_note(42, 64, a, None),
        );
        let (to_a_id, free_id) = (to_a.id(), free.id());
        w.update(|d| {
            d.notes.extend([to_a, free]);
            d.pending_fsp.push(pending_issue("issue-a", a));
            Ok(())
        })
        .unwrap();
        let right = keys_of_pairs(&[(8, 1), (4, 2)]);
        testing::retryable(w.check_keyset_keys(Party::Fsp(a), Site::FinishFspIssue, "k9", &right));
        assert_eq!(w.data().unpublished.len(), 1);
        testing::set_now(&mut w, T0 + 86_400);
        let m =
            the_mismatch(w.check_keyset_keys(Party::Fsp(a), Site::FinishFspIssue, "k9", &right));
        assert!(
            matches!(m.failed, Failed::Unpublished { .. }),
            "{:?}",
            m.failed
        );
        assert!(m.blacklisted);
        let ids: Vec<String> = w.notes().iter().map(StoredNote::id).collect();
        assert!(
            !ids.contains(&to_a_id),
            "the ESP note issue-a reserved is spent"
        );
        assert!(ids.contains(&free_id));
        // b's two FSP notes and the free ESP note
        assert_eq!(w.notes().len(), 3);
        assert!(w.pending_fsp().is_empty());
        assert!(
            w.data().unpublished.is_empty(),
            "{:?}",
            w.data().unpublished
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A merge keeps this wallet's own blacklist only. The other copy (a file,
    /// merged as the `merge` command does) was taken before this wallet
    /// blacklisted mint a, and has an entry for mint b planted in it. After the
    /// merge a is still blacklisted and its dropped notes stay gone, b is not
    /// blacklisted, its notes are kept and its honest reply is accepted. Fails
    /// if a merge takes a blacklist entry from the other copy, or loses one of
    /// this wallet's.
    #[test]
    fn a_merge_keeps_the_local_blacklist_only() {
        let (a, b) = (service(1), service(2));
        let (mut w, dir) = wallet_with_fsp_mints("merge-blacklist", &[a, b]);
        let other_path = dir.join("other.json");
        std::fs::copy(w.path(), &other_path).unwrap();
        let mut other = Wallet::open(&other_path, "regtest").unwrap();
        other
            .update(|d| {
                d.blacklist.push(crate::store::BlacklistedMint {
                    service: b,
                    at: 1,
                    site: "finish_fsp_issue".into(),
                    what: "planted".into(),
                });
                Ok(())
            })
            .unwrap();
        drop(other);

        w.set_key_policy(KeyPolicy {
            blacklist_on_key_mismatch: true,
            blacklist_max: 1000,
        });
        let m = the_mismatch(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspIssue,
            "k1",
            &keys_of_pairs(&WRONG_4),
        ));
        assert!(m.blacklisted);
        let mine = serde_json::to_value(w.blacklist()).unwrap();

        w.merge_file(&other_path).unwrap();
        assert_eq!(serde_json::to_value(w.blacklist()).unwrap(), mine);
        assert!(w.is_blacklisted(&a) && !w.is_blacklisted(&b));
        assert_eq!(w.notes().len(), 2, "a's dropped notes stay gone");
        assert!(w.notes().iter().all(|n| n.fsp_service() == Some(b)));
        w.check_keyset_keys(
            Party::Fsp(b),
            Site::FinishFspIssue,
            "k1",
            &keys_of_pairs(&[(8, 1), (4, 2)]),
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A merged file carries no key-check state, so it changes no verdict. The
    /// other copy (a file, merged as the `merge` command does) says the missing
    /// key set k9 was first seen a day before this wallet saw it, adds a
    /// first-seen time for the ESP's control stream, and plants a key set k1
    /// with another 4-unit key for the same mint. After the merge the wallet's
    /// own first-seen times and stream records are as they were: k9 is still an
    /// error to retry a second later (not flagged by the planted time), and the
    /// mint's honest k1 reply is accepted (not a mismatch against the planted
    /// keys). Fails if a merge takes `unpublished` or `key_streams` from the
    /// other copy.
    #[test]
    fn a_merge_takes_no_key_check_state_from_the_other_copy() {
        let a = service(1);
        let name = format!("fsp:{}", a.to_hex());
        let (mut w, dir) = wallet_with_fsp_mints("merge-state", &[a]);
        at_t0(&mut w);
        let right = keys_of_pairs(&[(8, 1), (4, 2)]);
        testing::retryable(w.check_keyset_keys(Party::Fsp(a), Site::FinishFspSpend, "k9", &right));
        let missing = format!("{name}|keyset:k9");
        assert_eq!(w.data().unpublished[&missing].since, T0);
        let streams = serde_json::to_value(&w.data().key_streams).unwrap();
        let firsts = serde_json::to_value(&w.data().unpublished).unwrap();

        let other_path = dir.join("other.json");
        std::fs::copy(w.path(), &other_path).unwrap();
        let mut other = Wallet::open(&other_path, "regtest").unwrap();
        other
            .update(|d| {
                d.unpublished.get_mut(&missing).unwrap().since = T0 - 86_400;
                d.unpublished.insert(
                    "esp|control".into(),
                    Unpublished {
                        since: 0,
                        end: None,
                    },
                );
                let planted = d.key_streams.get_mut(&name).unwrap();
                planted.keysets[0].keys.insert(4, key(9));
                Ok(())
            })
            .unwrap();
        drop(other);

        w.merge_file(&other_path).unwrap();
        assert_eq!(serde_json::to_value(&w.data().unpublished).unwrap(), firsts);
        assert_eq!(
            serde_json::to_value(&w.data().key_streams).unwrap(),
            streams
        );
        testing::set_now(&mut w, T0 + 1);
        let why = testing::retryable(w.check_keyset_keys(
            Party::Fsp(a),
            Site::FinishFspSpend,
            "k9",
            &right,
        ));
        assert!(why.contains("if it is still not published"), "{why}");
        w.check_keyset_keys(Party::Fsp(a), Site::FinishFspSpend, "k1", &right)
            .unwrap();
        assert!(w.blacklist().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ASK 8: the ESP changed its rule m after the send, and the wallet holds
    /// only the old rule when the reply comes. The day under the new rule is
    /// accepted after exactly one reread of the control stream, and none is made
    /// for a day the held rules allow. Fails if the day is refused, or if more or
    /// fewer than one reread is made.
    #[test]
    fn a_maturity_rule_changed_after_the_send_is_taken_in_with_exactly_one_reread() {
        let (mut w, dir) = scratch_wallet("m-changed");
        testing::publish_control(&mut w, 0, 300, "g0", None);
        let t = 20_000 * SECONDS_PER_DAY + 43_200;
        // A day the rule held allows needs no reread.
        w.check_exchange_day_of(t, t, 20_300).unwrap();
        assert_eq!(w.key_rereads(), 0);

        // The mint changed m to 365 after the send: on AIR, not read yet. The
        // reply's day is under the new rule: accepted after exactly one reread.
        w.unread_controls.push((1, 365, "g0".to_string(), None));
        w.check_exchange_day_of(t, t, 20_365).unwrap();
        assert_eq!(w.key_rereads(), 1, "m changed: exactly one reread");
        assert!(w.unread_controls.is_empty(), "the new rule was read");
        // Held now: no more rereads, and the last two rules both pass.
        w.check_exchange_day_of(t, t, 20_365).unwrap();
        w.check_exchange_day_of(t, t, 20_300).unwrap();
        assert_eq!(w.key_rereads(), 1);
        // A day under neither rule: one more reread, then the mismatch.
        let m = the_mismatch(w.check_exchange_day_of(t, t, 20_400));
        assert!(
            matches!(&m.failed, Failed::Day { rules, .. } if rules == &vec![365, 300]),
            "{:?}",
            m.failed
        );
        assert_eq!(w.key_rereads(), 2, "exactly one reread for the mismatch");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A mismatch needs a fresh read. A wallet that cannot read the streams again
    /// (here: its records come from the file and no feed is started) decides
    /// nothing on a day outside the rules it holds, or on day keys that disagree:
    /// an error to retry. With a fresh read (the unit tests' streams stand for
    /// what was published) each is a mismatch after exactly one reread. Fails if
    /// a mismatch is reported on records that were not read again, or if more or
    /// fewer than one reread is made.
    #[test]
    fn a_mismatch_is_reported_only_after_one_fresh_read() {
        let svc = service(7);
        let (mut w, dir) = scratch_wallet("fresh");
        testing::publish_control(&mut w, 0, 365, "g0", None);
        let day_keys: Vec<PublicKey> = (0..64u8).map(|i| key(i + 1)).collect();
        testing::publish_day(&mut w, "g0", &svc, 20_000, day_keys);
        let t = 20_000 * SECONDS_PER_DAY + 43_200;

        // From the file only: no fresh read can be made, so nothing is decided.
        let mut cold = Wallet::open(w.path(), "regtest").unwrap();
        let why = testing::retryable(cold.check_exchange_day_of(t, t, 20_000 + 30));
        assert!(
            why.contains(
                "could not be read again before deciding (the key streams were not started)"
            ),
            "{why}"
        );
        let why = testing::retryable(cold.check_esp_day_keys(
            Site::RedeemRefund,
            "g0",
            &svc,
            20_000,
            &keys_of_pairs(&[(8, 1)]),
        ));
        assert!(
            why.contains("could not be read again before deciding"),
            "{why}"
        );
        assert_eq!(cold.key_rereads(), 0);
        // and the right ones pass without any reread
        cold.check_exchange_day_of(t, t, 20_365).unwrap();
        cold.check_esp_day_keys(
            Site::RedeemRefund,
            "g0",
            &svc,
            20_000,
            &keys_of_pairs(&[(8, 4)]),
        )
        .unwrap();
        assert_eq!(cold.key_rereads(), 0);

        // With the streams fresh: one reread, then the mismatch.
        let m = the_mismatch(w.check_exchange_day_of(t, t, 20_000 + 30));
        assert!(
            matches!(m.failed, Failed::Day { day: 20_030, .. }),
            "{:?}",
            m.failed
        );
        assert_eq!(w.key_rereads(), 1);
        let m = the_mismatch(w.check_esp_day_keys(
            Site::RedeemRefund,
            "g0",
            &svc,
            20_000,
            &keys_of_pairs(&[(8, 1)]),
        ));
        assert_eq!(m.failed, Failed::Key { amount: 8 });
        assert_eq!(w.key_rereads(), 2);
        // A PSP or FSP key set is never read again: its ID is the hash of its keys.
        testing::publish_keyset_as(
            &mut w,
            "psp",
            "00",
            0,
            0,
            "k1",
            &BTreeMap::from([(8u64, key(1))]),
        );
        the_mismatch(w.check_keyset_keys(
            Party::Psp,
            Site::ApplyClaim,
            "k1",
            &keys_of_pairs(&[(8, 2)]),
        ));
        assert_eq!(w.key_rereads(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_warning_names_the_mint_what_failed_and_where() {
        let m = KeyMismatch::new(
            "FSP mint",
            "02aa".into(),
            Some("02bb".into()),
            Site::FinishFspSpend,
            Failed::Key { amount: 32 },
            Outcome::OptedOut,
        );
        assert_eq!(
            m.warning,
            "WARNING: KEY CHECK FAILED at finish_fsp_spend. The FSP mint (DID 02aa, service 02bb) signed the output of 32 unit(s) with a KEY that is not the key it published. Nothing from its reply was stored. Your notes and the pending request were kept. A mint that signs with keys other users do not see can recognise your notes when they come back. This FSP mint is NOT blacklisted (fsp.blacklist_on_key_mismatch is off)."
        );
        assert!(!m.blacklisted);
    }
    /// The AIR settings at their extremes (`air.max_skew_secs`,
    /// `air.reply_wait_secs` and `air.timeout_secs` all 1, on the key feed as an
    /// app would set them with `start_key_feed`) change nothing the key check
    /// decides with: the day slack is [`DAY_SKEW_SECS`], the wait
    /// [`KEY_CHECK_WAIT_SECS`], a read's timeout at least
    /// [`KEY_READ_MIN_TIMEOUT_SECS`]. An honest ESP whose clock is 100 s ahead of
    /// the wallet's just before midnight gives the next day's day: accepted with
    /// and without the feed (a 1 s slack would flag it). A day two days out is a
    /// mismatch. Fails if the check reads any of the three settings.
    #[test]
    fn extreme_air_settings_change_nothing_the_key_check_decides_with() {
        let extreme = AirSettings {
            max_skew_secs: 1,
            reply_wait_secs: 1,
            timeout_secs: 1,
            ..AirSettings::default()
        };
        assert_eq!(key_read_timeout(&extreme), KEY_READ_MIN_TIMEOUT_SECS);
        let patient = AirSettings {
            timeout_secs: 600,
            ..AirSettings::default()
        };
        assert_eq!(key_read_timeout(&patient), 600, "a longer timeout is kept");

        let (mut w, dir) = scratch_wallet("extreme");
        testing::publish_control(&mut w, 0, 365, "g0", None);
        let d = 20_000;
        let sent = d * SECONDS_PER_DAY + 86_390; // 23:59:50 on day D
        let replied = d * SECONDS_PER_DAY + 86_395; // 23:59:55, the wallet's clock
        let honest = d + 1 + 365; // the ESP's clock is past midnight
        let cheat = d + 2 + 365;
        assert!(
            !matches!(
                check_exchange_day(
                    w.data().key_streams.get(&stream_name(Party::Esp)),
                    sent,
                    replied,
                    1,
                    honest
                ),
                Verdict::Good
            ),
            "a 1 s slack would refuse the honest day"
        );

        // Without a feed: the fixed slack, and no wait.
        w.check_exchange_day_of(sent, replied, honest).unwrap();
        assert!(w.check_deadline() <= Instant::now() + Duration::from_secs(1));
        let m = the_mismatch(w.check_exchange_day_of(sent, replied, cheat));
        assert!(matches!(m.failed, Failed::Day { .. }), "{:?}", m.failed);

        // With a feed on the extreme settings: the same slack, the fixed wait.
        w.feed = Some(KeyFeed::new(extreme));
        let before = Instant::now();
        assert!(w.check_deadline() >= before + Duration::from_secs(KEY_CHECK_WAIT_SECS));
        w.check_exchange_day_of(sent, replied, honest).unwrap();
        w.feed = None;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
