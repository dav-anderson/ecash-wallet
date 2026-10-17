//! Handoff: moving PSP and FSP notes, and optionally a DID secret key, from one
//! wallet to another without the AIR.
//!
//! An unfunded wallet cannot pay to read from the AIR, so a new device or a new
//! user gets its first notes (and, for a new device, its identity) from another
//! device or from an app, as a string or a QR code. This module makes that
//! payload ([`Wallet::export_handoff`]) and takes one in ([`Wallet::import_handoff`]).
//! It does no I/O of its own. The command line is `handoff export`, `handoff
//! import`, `handoff cancel`, `handoff done` and `handoff list`.
//!
//! **The payload holds bearer secrets.** It carries the spend secret of every
//! note in it and, if asked, a DID secret key. Whoever reads it can spend the
//! notes and use the key. [`BEARER_WARNING`] is shown wherever one is made.
//!
//! # Taking notes out, putting them back
//!
//! Export takes the notes out of the sender's `notes` in the same write that
//! records the handoff (state [`HandoffState::Pending`]), so the sender cannot
//! spend them while the handoff is out. [`Wallet::cancel_handoff`] puts them
//! back. That is a local act: it does not tell the mint or the receiver. A
//! receiver that imported the payload without swapping still holds the same
//! secrets, so after a cancel the first of the two to spend the notes wins, and
//! the other is told by the mint that they are spent. Cancel when the payload
//! was lost or never imported. A receiver that imports with `--swap` swaps the
//! notes at the mint for notes only it knows, which makes the handoff final and
//! the sender's copy worthless. [`Wallet::finish_handoff`] drops the sender's
//! record of the notes once the sender knows the handoff has been claimed.
//!
//! # Importing
//!
//! Import refuses a payload that is damaged, of another version, already
//! imported (by its id, or because any of its notes is already here or was and
//! has left), or whose note keys do not match their nonces. Against what the
//! wallet already knows it checks each note's key-set ID (a mint whose live key
//! sets the wallet has seen must still have the note's set live) and, for FSP,
//! the service and its mint. What it has not seen it cannot check, and says so
//! in [`Imported::warnings`]; the command line then reads the mint's keys
//! (`fsp_sync` or `rotation_sync`), which moves notes on a retired set to the
//! lost record. A blind signature can only be checked by the mint, so a note is
//! known good only once it is swapped or spent.
//!
//! Each imported note keeps its source: the handoff id, in
//! [`WalletData::handoffs_in`], with the sender's name if one was given.
//!
//! # Swapping what was received
//!
//! Optional, and cheap: PSP is swapped with psp-mint's `POST /rollover` for notes
//! of the same amounts (the notes are never put in `notes`; the swap is stored
//! in the same write as the import record), and FSP with a normal fsp-mint swap
//! that pays 0. Both are in [`crate::http`]. Not swapping is allowed: the notes
//! are then good for as long as nobody else holds a copy of the payload.
//!
//! # The encoding
//!
//! `SPH1:` and then the bytes below in base 44 (the characters of a QR code's
//! alphanumeric mode, less the space, so the whole string is one QR segment and
//! survives being pasted: `0-9 A-Z $ % * + - . / :`). Three characters carry two
//! bytes. All numbers are big-endian.
//!
//! ```text
//! version      1   1
//! flags        1   bit 0: a DID secret key follows the groups
//! groups       1   how many groups (0 to 255)
//!   per group:
//!   kind       1   0 PSP, 1 FSP
//!   service   32   FSP only: the service's x-only key
//!   mint       2+n the mint's URL, a length and UTF-8
//!   keysets    1+8k how many key sets the notes use, and each (8 bytes)
//!   notes      2   how many notes
//!     per note:
//!     size     1   the amount is 2 to this power
//!     keyset   1   which of the group's key sets
//!     nonce   33   the note's identity (compressed)
//!     sig     33   the mint's signature (compressed)
//!     secret  32   the spend secret
//! did key     32   the DID secret key, if flagged
//! check        4   the first 4 bytes of SHA-256 of everything above
//! ```
//!
//! A note is [`NOTE_BYTES`] (100) bytes, 150 characters. A group adds its
//! header: 12 bytes plus 8 for each key set for PSP (usually one group with one
//! key set, 20 to 28 bytes, in the URL's length included), and 32 more for FSP.
//! A DID key adds 32 bytes, 48 characters. The fixed part is 3 bytes and the
//! 4-byte check, with the 5-character prefix. So a handoff of N notes of one PSP
//! mint with a 22-character URL is about 3 + 33 + 100N + 4 bytes, which is
//! 60 + 150N characters; with a DID key, 108 + 150N. A QR code holds at most
//! 4,296 alphanumeric characters (error correction L, version 40) or 3,391 (M).
//! One code therefore holds about 28 notes at L or 22 at M. A funding handoff
//! of $100 is 3 PSP notes (64, 32 and 4 PSP), about 500 characters. A handoff
//! of more notes than that is a string or a file, not a QR code.

use std::collections::{BTreeMap, BTreeSet};

use mint_types::{Nonce, Note};
use secp256k1::{PublicKey, SECP256K1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_wire::seal::SecretKey as DidSecretKey;

use crate::error::WalletError;
use crate::store::{Kind, StoredNote, StoredTerms, Wallet, has_departed};

/// Shown wherever a handoff is made or read.
pub const BEARER_WARNING: &str = "This handoff holds the secret keys that spend its notes (and a DID secret key, if one was added). Anyone who sees it can spend them. Hand it over in person or on a channel you trust, do not post it, and delete it once it is imported.";

/// Every handoff string starts with this. The digit is the format version.
pub const PREFIX: &str = "SPH1:";
/// The format version this wallet reads and writes.
pub const FORMAT_VERSION: u8 = 1;
/// Bytes of one note in the payload.
pub const NOTE_BYTES: usize = 100;
/// Bytes of a DID secret key in the payload.
pub const DID_KEY_BYTES: usize = 32;
/// The most notes in one handoff, as in a PSP token.
pub const MAX_NOTES: usize = 1000;
const CHECK_BYTES: usize = 4;

// ---- base 44 -----------------------------------------------------------------

const ALPHABET: &[u8; 44] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$%*+-./:";

fn base44_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3 / 2 + 2);
    for chunk in bytes.chunks(2) {
        let mut n = chunk.iter().fold(0usize, |n, b| n * 256 + usize::from(*b));
        let digits = if chunk.len() == 2 { 3 } else { 2 };
        for _ in 0..digits {
            out.push(ALPHABET[n % 44] as char);
            n /= 44;
        }
    }
    out
}

fn base44_decode(text: &str) -> Result<Vec<u8>, WalletError> {
    let mut values = Vec::with_capacity(text.len());
    for c in text.bytes() {
        let v = ALPHABET.iter().position(|a| *a == c).ok_or_else(|| {
            WalletError::Invalid(format!(
                "the handoff has a character that does not belong in one: `{}`",
                c as char
            ))
        })?;
        values.push(v);
    }
    let mut out = Vec::with_capacity(values.len() * 2 / 3 + 1);
    for chunk in values.chunks(3) {
        let n = match *chunk {
            [c, d, e] => c + d * 44 + e * 44 * 44,
            [c, d] => c + d * 44,
            _ => {
                return Err(WalletError::Invalid(
                    "the handoff is cut short or damaged".into(),
                ));
            }
        };
        if chunk.len() == 3 {
            if n > 0xFFFF {
                return Err(WalletError::Invalid("the handoff is damaged".into()));
            }
            out.push((n >> 8) as u8);
            out.push((n & 0xFF) as u8);
        } else {
            if n > 0xFF {
                return Err(WalletError::Invalid("the handoff is damaged".into()));
            }
            out.push(n as u8);
        }
    }
    Ok(out)
}

// ---- the payload ---------------------------------------------------------------

/// One note in a payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadNote {
    pub amount: u64,
    /// The key set that signed it (16 hex characters).
    pub keyset: String,
    pub note: Note,
    pub spend_secret: SecretKey,
}

/// Notes of one mint (and, for FSP, one service).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// `Kind::Psp` or `Kind::Fsp`.
    pub kind: Kind,
    /// The service the notes belong to. FSP only.
    pub service: Option<XOnlyPublicKey>,
    pub mint: String,
    pub notes: Vec<PayloadNote>,
}

/// What a handoff string holds, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub groups: Vec<Group>,
    pub did_key: Option<DidSecretKey>,
}

impl Payload {
    /// The notes in all groups.
    pub fn note_count(&self) -> usize {
        self.groups.iter().map(|g| g.notes.len()).sum()
    }

    /// Units of one kind in the payload.
    pub fn units(&self, kind: Kind) -> u128 {
        self.groups
            .iter()
            .filter(|g| g.kind == kind)
            .flat_map(|g| g.notes.iter())
            .map(|n| u128::from(n.amount))
            .sum()
    }

    fn body(&self) -> Result<Vec<u8>, WalletError> {
        if self.groups.len() > 255 {
            return Err(WalletError::Invalid(
                "a handoff has at most 255 groups".into(),
            ));
        }
        if self.note_count() > MAX_NOTES {
            return Err(WalletError::Invalid(format!(
                "a handoff holds at most {MAX_NOTES} notes"
            )));
        }
        if self.note_count() == 0 && self.did_key.is_none() {
            return Err(WalletError::Invalid("the handoff holds nothing".into()));
        }
        let mut b = vec![FORMAT_VERSION, u8::from(self.did_key.is_some())];
        b.push(self.groups.len() as u8);
        for g in &self.groups {
            match g.kind {
                Kind::Psp => b.push(0),
                Kind::Fsp => {
                    b.push(1);
                    let service = g.service.ok_or_else(|| {
                        WalletError::Invalid("an FSP group needs its service".into())
                    })?;
                    b.extend_from_slice(&service.serialize());
                }
                Kind::Esp => {
                    return Err(WalletError::Invalid("ESP is not handed off".into()));
                }
            }
            if g.kind == Kind::Psp && g.service.is_some() {
                return Err(WalletError::Invalid("a PSP group has no service".into()));
            }
            let url = g.mint.as_bytes();
            if url.is_empty() || url.len() > 0xFFFF {
                return Err(WalletError::Invalid(
                    "a group needs the mint's URL (up to 65,535 bytes)".into(),
                ));
            }
            b.extend_from_slice(&(url.len() as u16).to_be_bytes());
            b.extend_from_slice(url);
            if g.notes.is_empty() || g.notes.len() > 0xFFFF {
                return Err(WalletError::Invalid(
                    "a group needs at least one note".into(),
                ));
            }
            let mut keysets: Vec<&str> = Vec::new();
            for n in &g.notes {
                if !keysets.contains(&n.keyset.as_str()) {
                    keysets.push(&n.keyset);
                }
            }
            if keysets.len() > 255 {
                return Err(WalletError::Invalid(
                    "a group uses at most 255 key sets".into(),
                ));
            }
            b.push(keysets.len() as u8);
            for k in &keysets {
                let raw = keyset_bytes(k)?;
                b.extend_from_slice(&raw);
            }
            b.extend_from_slice(&(g.notes.len() as u16).to_be_bytes());
            for n in &g.notes {
                if !n.amount.is_power_of_two() {
                    return Err(WalletError::Invalid(format!(
                        "{} is not a power of two; PSP and FSP notes are",
                        n.amount
                    )));
                }
                b.push(n.amount.trailing_zeros() as u8);
                let at = keysets
                    .iter()
                    .position(|k| *k == n.keyset)
                    .expect("collected above");
                b.push(at as u8);
                b.extend_from_slice(&n.note.nonce.0.serialize());
                b.extend_from_slice(&n.note.signature.serialize());
                b.extend_from_slice(&n.spend_secret.secret_bytes());
            }
        }
        if let Some(k) = &self.did_key {
            b.extend_from_slice(&k.to_array());
        }
        Ok(b)
    }

    /// The handoff string. Its id is the second thing returned.
    pub fn encode(&self) -> Result<(String, String), WalletError> {
        let mut b = self.body()?;
        let digest = Sha256::digest(&b);
        let id = hex::encode(&digest[..16]);
        b.extend_from_slice(&digest[..CHECK_BYTES]);
        Ok((format!("{PREFIX}{}", base44_encode(&b)), id))
    }

    /// Read a handoff string. Fails on anything that is not exactly one: another
    /// version, a damaged or cut string, a note whose secret is not its nonce's.
    /// Returns the payload and its id.
    pub fn decode(text: &str) -> Result<(Payload, String), WalletError> {
        let clean: String = text
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        let Some(rest) = clean.strip_prefix("SPH") else {
            return Err(WalletError::Invalid(
                "this is not a handoff (it should start with SPH1:)".into(),
            ));
        };
        let mut chars = rest.chars();
        let version = chars.next();
        if chars.next() != Some(':') {
            return Err(WalletError::Invalid(
                "this is not a handoff (it should start with SPH1:)".into(),
            ));
        }
        if version != Some('1') {
            return Err(WalletError::Invalid(format!(
                "this handoff is version {}, and this wallet reads version 1 only. Update the older of the two wallets",
                version.unwrap_or('?')
            )));
        }
        let bytes = base44_decode(&rest[2..])?;
        if bytes.len() < 3 + CHECK_BYTES {
            return Err(WalletError::Invalid(
                "the handoff is cut short or damaged".into(),
            ));
        }
        let (body, check) = bytes.split_at(bytes.len() - CHECK_BYTES);
        let digest = Sha256::digest(body);
        if digest[..CHECK_BYTES] != *check {
            return Err(WalletError::Invalid(
                "the handoff is damaged (its check does not match): copy it again".into(),
            ));
        }
        let payload = parse_body(body)?;
        Ok((payload, hex::encode(&digest[..16])))
    }
}

fn keyset_bytes(id: &str) -> Result<[u8; 8], WalletError> {
    if !sp_wire::keyset::is_keyset_id(id) {
        return Err(WalletError::Invalid(format!(
            "`{id}` is not a key-set ID (16 hex characters)"
        )));
    }
    let raw = hex::decode(id).map_err(|e| WalletError::Invalid(e.to_string()))?;
    <[u8; 8]>::try_from(raw.as_slice()).map_err(|_| WalletError::Invalid("key-set ID".into()))
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WalletError> {
        if self.0.len() < n {
            return Err(WalletError::Invalid(
                "the handoff is cut short or damaged".into(),
            ));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, WalletError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WalletError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

fn parse_body(body: &[u8]) -> Result<Payload, WalletError> {
    let mut c = Cursor(body);
    let version = c.u8()?;
    if version != FORMAT_VERSION {
        return Err(WalletError::Invalid(format!(
            "this handoff is version {version}, and this wallet reads version {FORMAT_VERSION} only. Update the older of the two wallets"
        )));
    }
    let flags = c.u8()?;
    if flags & !1 != 0 {
        return Err(WalletError::Invalid(
            "this handoff uses a feature this wallet does not know. Update the older of the two wallets"
                .into(),
        ));
    }
    let group_count = usize::from(c.u8()?);
    let mut groups = Vec::new();
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    for _ in 0..group_count {
        let (kind, service) = match c.u8()? {
            0 => (Kind::Psp, None),
            1 => {
                let raw = c.take(32)?;
                let key = XOnlyPublicKey::from_slice(raw)
                    .map_err(|_| WalletError::Invalid("a service key in it is not valid".into()))?;
                (Kind::Fsp, Some(key))
            }
            other => {
                return Err(WalletError::Invalid(format!(
                    "a group of kind {other} is not one this wallet knows"
                )));
            }
        };
        let url_len = usize::from(c.u16()?);
        let mint = String::from_utf8(c.take(url_len)?.to_vec())
            .map_err(|_| WalletError::Invalid("a mint URL in it is not text".into()))?;
        if mint.is_empty() {
            return Err(WalletError::Invalid("a group names no mint".into()));
        }
        let keyset_count = usize::from(c.u8()?);
        let mut keysets = Vec::new();
        for _ in 0..keyset_count {
            keysets.push(hex::encode(c.take(8)?));
        }
        let count = usize::from(c.u16()?);
        if count == 0 {
            return Err(WalletError::Invalid("a group has no notes".into()));
        }
        total += count;
        if total > MAX_NOTES {
            return Err(WalletError::Invalid(format!(
                "a handoff holds at most {MAX_NOTES} notes"
            )));
        }
        let mut notes = Vec::with_capacity(count);
        for _ in 0..count {
            let exp = c.u8()?;
            if exp > 63 {
                return Err(WalletError::Invalid(
                    "a note's size in it is out of range".into(),
                ));
            }
            let at = usize::from(c.u8()?);
            let keyset = keysets
                .get(at)
                .ok_or_else(|| WalletError::Invalid("a note names a key set it lacks".into()))?
                .clone();
            let nonce = PublicKey::from_slice(c.take(33)?)
                .map_err(|_| WalletError::Invalid("a note's nonce in it is not valid".into()))?;
            let signature = PublicKey::from_slice(c.take(33)?).map_err(|_| {
                WalletError::Invalid("a note's signature in it is not valid".into())
            })?;
            let secret = SecretKey::from_slice(c.take(32)?)
                .map_err(|_| WalletError::Invalid("a note's secret in it is not valid".into()))?;
            if secret.public_key(SECP256K1) != nonce {
                return Err(WalletError::Invalid(
                    "a note's spend secret is not the one for its nonce: the handoff is damaged or forged"
                        .into(),
                ));
            }
            if !seen.insert(nonce.serialize()) {
                return Err(WalletError::Invalid(
                    "the same note is in the handoff twice".into(),
                ));
            }
            notes.push(PayloadNote {
                amount: 1u64 << exp,
                keyset,
                note: Note {
                    nonce: Nonce(nonce),
                    signature,
                },
                spend_secret: secret,
            });
        }
        groups.push(Group {
            kind,
            service,
            mint,
            notes,
        });
    }
    let did_key = if flags & 1 == 1 {
        Some(
            DidSecretKey::from_bytes(c.take(DID_KEY_BYTES)?)
                .map_err(|_| WalletError::Invalid("the DID key in it is not valid".into()))?,
        )
    } else {
        None
    };
    if !c.0.is_empty() {
        return Err(WalletError::Invalid(
            "the handoff has bytes after its end".into(),
        ));
    }
    if total == 0 && did_key.is_none() {
        return Err(WalletError::Invalid("the handoff holds nothing".into()));
    }
    Ok(Payload { groups, did_key })
}

// ---- what the wallet records -----------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffState {
    /// Exported; the sender's notes are held back in the record.
    Pending,
    /// The sender knows it was claimed and has dropped the notes.
    Done,
}

/// A handoff this wallet made. While `Pending` it holds the notes, so that
/// `cancel_handoff` can put them back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutgoingHandoff {
    pub id: String,
    pub state: HandoffState,
    /// PSP and FSP units in it.
    pub psp_units: u128,
    pub fsp_units: u128,
    /// How many notes it holds (kept after `Done`).
    pub note_count: usize,
    /// A DID key went with it.
    pub with_did_key: bool,
    /// The notes, until it is done.
    pub notes: Vec<StoredNote>,
}

/// A handoff this wallet imported. Its note ids are the notes' source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingHandoff {
    pub id: String,
    /// Who it came from, as the importer named them (may be empty).
    #[serde(default)]
    pub from: String,
    pub psp_units: u128,
    pub fsp_units: u128,
    /// The ids of the notes that were added, or swapped away at once.
    pub notes: Vec<String>,
    /// The notes were swapped at the mint for notes only this wallet knows.
    pub swapped: bool,
}

/// Which notes to hand off, by id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandoffSelection {
    pub psp: Vec<String>,
    pub fsp: Vec<String>,
}

/// What an export made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffExport {
    pub id: String,
    /// The handoff string.
    pub text: String,
    pub notes: usize,
    pub psp_units: u128,
    pub fsp_units: u128,
    pub with_did_key: bool,
    /// Bytes before encoding, and characters in `text`.
    pub bytes: usize,
    pub chars: usize,
    /// [`BEARER_WARNING`].
    pub warning: &'static str,
}

/// What an import did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    pub id: String,
    pub psp_units: u128,
    pub fsp_units: u128,
    /// The ids of the notes in the payload.
    pub notes: Vec<String>,
    /// The DID secret key the payload carried, if it did. The wallet does not
    /// keep it: the app or the AIR login does.
    pub did_key: Option<DidSecretKey>,
    /// Things the wallet could not check, or that differ from what it knew.
    pub warnings: Vec<String>,
    /// PSP mints and FSP (service, mint) pairs the notes are for, so a caller
    /// can read their keys.
    pub psp_mints: Vec<String>,
    pub fsp_mints: Vec<(XOnlyPublicKey, String)>,
    /// Stored PSP swaps to send (ids of pending rollovers). Only when the
    /// import asked to swap.
    pub psp_swaps: Vec<String>,
    /// The FSP notes in the wallet to swap, by service. Only when the import
    /// asked to swap.
    pub fsp_swaps: Vec<(XOnlyPublicKey, Vec<String>)>,
}

/// Read a handoff without changing anything: for a caller that must decide
/// something (such as where to put a DID key) before it imports.
pub fn inspect(text: &str) -> Result<(Payload, String), WalletError> {
    Payload::decode(text)
}

fn take_exact(mut free: Vec<&StoredNote>, amount: u128) -> Option<Vec<String>> {
    free.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.id().cmp(&b.id())));
    let (mut left, mut ids) = (amount, Vec::new());
    for n in free {
        if u128::from(n.amount) <= left {
            left -= u128::from(n.amount);
            ids.push(n.id());
        }
    }
    (left == 0 && !ids.is_empty()).then_some(ids)
}

impl Wallet {
    /// Pick free notes adding up to exactly `psp` PSP units, and exactly the
    /// units asked for each service in `fsp`. Largest notes first.
    pub fn select_handoff(
        &self,
        psp: u128,
        fsp: &[(XOnlyPublicKey, u128)],
    ) -> Result<HandoffSelection, WalletError> {
        let mut sel = HandoffSelection::default();
        if psp > 0 {
            let free = self
                .notes()
                .iter()
                .filter(|n| n.kind == Kind::Psp && n.reserved_by.is_none())
                .collect();
            sel.psp = take_exact(free, psp).ok_or_else(|| {
                WalletError::NotEnough(format!(
                    "no free PSP notes add up to exactly {psp}; swap for smaller notes first"
                ))
            })?;
        }
        for (service, units) in fsp {
            if *units == 0 {
                continue;
            }
            let free = self
                .notes()
                .iter()
                .filter(|n| {
                    n.kind == Kind::Fsp
                        && n.reserved_by.is_none()
                        && n.fsp_service() == Some(*service)
                })
                .collect();
            let ids = take_exact(free, *units).ok_or_else(|| {
                WalletError::NotEnough(format!(
                    "no free FSP notes for service {} add up to exactly {units}",
                    hex::encode(service.serialize())
                ))
            })?;
            sel.fsp.extend(ids);
        }
        Ok(sel)
    }

    /// The handoffs this wallet made, oldest first.
    pub fn handoffs_out(&self) -> &[OutgoingHandoff] {
        &self.data().handoffs_out
    }

    /// The handoffs this wallet imported, oldest first.
    pub fn handoffs_in(&self) -> &[IncomingHandoff] {
        &self.data().handoffs_in
    }

    /// Make a handoff of the selected notes (and, if given, a DID secret key),
    /// and take the notes out of this wallet in the same write. `psp_mint` is
    /// the PSP mint's URL, needed when PSP notes are selected; an FSP note's
    /// mint is the one the wallet has seen for its service.
    pub fn export_handoff(
        &mut self,
        selection: &HandoffSelection,
        psp_mint: &str,
        did_key: Option<&DidSecretKey>,
    ) -> Result<HandoffExport, WalletError> {
        let ids: BTreeSet<&String> = selection.psp.iter().chain(&selection.fsp).collect();
        if ids.len() != selection.psp.len() + selection.fsp.len() {
            return Err(WalletError::Invalid(
                "a note is selected twice for the handoff".into(),
            ));
        }
        let mut psp_notes = Vec::new();
        let mut fsp_notes: BTreeMap<[u8; 32], Vec<StoredNote>> = BTreeMap::new();
        let mut picked: Vec<StoredNote> = Vec::new();
        for id in selection.psp.iter().chain(&selection.fsp) {
            let n =
                self.notes().iter().find(|n| &n.id() == id).ok_or_else(|| {
                    WalletError::Unknown(format!("note {id} is not in this wallet"))
                })?;
            if n.reserved_by.is_some() {
                return Err(WalletError::Invalid(format!(
                    "note {id} is held back for a pending request"
                )));
            }
            picked.push(n.clone());
        }
        let mut groups: Vec<Group> = Vec::new();
        for n in &picked {
            let want_psp = selection.psp.contains(&n.id());
            match (n.kind, want_psp) {
                (Kind::Psp, true) => psp_notes.push(n.clone()),
                (Kind::Fsp, false) => {
                    let service = n.fsp_service().ok_or_else(|| {
                        WalletError::Invalid(format!(
                            "FSP note {} has no known service, so it cannot be handed off. Connect to its mint once (any `fsp` command) and try again",
                            n.id()
                        ))
                    })?;
                    fsp_notes
                        .entry(service.serialize())
                        .or_default()
                        .push(n.clone());
                }
                _ => {
                    return Err(WalletError::Invalid(format!(
                        "note {} is not a PSP or an FSP note of the kind it was selected as",
                        n.id()
                    )));
                }
            }
        }
        if !psp_notes.is_empty() {
            if psp_mint.trim().is_empty() {
                return Err(WalletError::Invalid(
                    "give the PSP mint's URL for the PSP notes".into(),
                ));
            }
            groups.push(Group {
                kind: Kind::Psp,
                service: None,
                mint: psp_mint.to_string(),
                notes: psp_notes
                    .iter()
                    .map(|n| self.payload_note(n, false))
                    .collect::<Result<_, _>>()?,
            });
        }
        for (service, notes) in &fsp_notes {
            let key = XOnlyPublicKey::from_slice(service).expect("it came from a key");
            let mint = self
                .fsp_mints()
                .get(&hex::encode(service))
                .map(|m| m.url.clone())
                .ok_or_else(|| {
                    WalletError::Invalid(format!(
                        "this wallet has not seen the FSP mint of service {}: connect to it once first",
                        hex::encode(service)
                    ))
                })?;
            groups.push(Group {
                kind: Kind::Fsp,
                service: Some(key),
                mint,
                notes: notes
                    .iter()
                    .map(|n| self.payload_note(n, true))
                    .collect::<Result<_, _>>()?,
            });
        }
        let payload = Payload {
            groups,
            did_key: did_key.copied(),
        };
        let (text, id) = payload.encode()?;
        let (psp_units, fsp_units) = (payload.units(Kind::Psp), payload.units(Kind::Fsp));
        let record = OutgoingHandoff {
            id: id.clone(),
            state: HandoffState::Pending,
            psp_units,
            fsp_units,
            note_count: payload.note_count(),
            with_did_key: payload.did_key.is_some(),
            notes: picked.clone(),
        };
        let gone: BTreeSet<String> = picked.iter().map(StoredNote::id).collect();
        self.update(|d| {
            if d.handoffs_out.iter().any(|h| h.id == id) {
                return Err(WalletError::Invalid("this handoff was already made".into()));
            }
            d.notes.retain(|n| !gone.contains(&n.id()));
            d.handoffs_out.push(record);
            Ok(())
        })?;
        let digits = text.len() - PREFIX.len();
        Ok(HandoffExport {
            id,
            bytes: digits / 3 * 2 + usize::from(digits % 3 == 2),
            chars: text.len(),
            notes: payload.note_count(),
            psp_units,
            fsp_units,
            with_did_key: payload.did_key.is_some(),
            text,
            warning: BEARER_WARNING,
        })
    }

    fn payload_note(&self, n: &StoredNote, fsp: bool) -> Result<PayloadNote, WalletError> {
        let keyset = if fsp {
            self.data().fsp_keysets.get(&n.id())
        } else {
            self.data().keysets.get(&n.id())
        };
        let keyset = keyset.cloned().ok_or_else(|| {
            WalletError::Invalid(format!(
                "note {} has no recorded key set, so it cannot be spent; it is not handed off",
                n.id()
            ))
        })?;
        Ok(PayloadNote {
            amount: n.amount,
            keyset,
            note: n.note,
            spend_secret: n.spend_secret,
        })
    }

    /// Put the notes of a pending handoff back. Local only: see the module
    /// documentation for what that means for a receiver that already has them.
    pub fn cancel_handoff(&mut self, id: &str) -> Result<usize, WalletError> {
        let h = self
            .data()
            .handoffs_out
            .iter()
            .find(|h| h.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no handoff {id}")))?;
        if h.state != HandoffState::Pending {
            return Err(WalletError::Invalid(format!(
                "handoff {id} is done: its notes are no longer kept"
            )));
        }
        let count = h.notes.len();
        self.update(|d| {
            d.handoffs_out.retain(|x| x.id != id);
            for n in h.notes {
                if !d.notes.iter().any(|x| x.id() == n.id()) {
                    d.notes.push(n);
                }
            }
            Ok(())
        })?;
        Ok(count)
    }

    /// The sender knows the handoff was claimed (the receiver swapped it, or told
    /// them): drop the notes it kept. After this it cannot be cancelled.
    pub fn finish_handoff(&mut self, id: &str) -> Result<(), WalletError> {
        self.data()
            .handoffs_out
            .iter()
            .find(|h| h.id == id && h.state == HandoffState::Pending)
            .ok_or_else(|| WalletError::Unknown(format!("no pending handoff {id}")))?;
        self.update(|d| {
            if let Some(h) = d.handoffs_out.iter_mut().find(|h| h.id == id) {
                h.state = HandoffState::Done;
                h.notes.clear();
            }
            Ok(())
        })
    }

    /// Take a handoff in. `from` names the sender for the record (may be empty).
    /// With `swap`, the PSP in it is not added: a swap at psp-mint for fresh
    /// notes is stored in the same write as the record, and the caller sends it
    /// (see `http::complete_import`); FSP is added and the caller swaps it.
    pub fn import_handoff(
        &mut self,
        text: &str,
        from: &str,
        swap: bool,
    ) -> Result<Imported, WalletError> {
        let (payload, id) = Payload::decode(text)?;
        if self.data().handoffs_in.iter().any(|h| h.id == id) {
            return Err(WalletError::Invalid(format!(
                "handoff {id} was imported already; nothing was added"
            )));
        }
        if self.data().handoffs_out.iter().any(|h| h.id == id) {
            return Err(WalletError::Invalid(
                "this wallet made this handoff; it is not imported into the wallet it came from. Cancel it to take the notes back"
                    .into(),
            ));
        }
        // None of its notes may be here, or have been here and left.
        let held: BTreeSet<String> = self
            .notes()
            .iter()
            .map(StoredNote::id)
            .chain(self.data().spent.iter().map(StoredNote::id))
            .chain(self.data().lost.iter().map(StoredNote::id))
            .chain(self.data().lost_fsp.iter().map(StoredNote::id))
            .collect();
        for g in &payload.groups {
            for n in &g.notes {
                let nid = hex::encode(n.note.nonce.0.serialize());
                if held.contains(&nid) || has_departed(self.data(), &nid) {
                    return Err(WalletError::Invalid(format!(
                        "note {nid} is already in this wallet, or was and has been spent or handed on. The handoff may have been imported before; nothing was added"
                    )));
                }
            }
        }
        // Check against what the wallet knows.
        let mut warnings = Vec::new();
        let mut psp_mints = Vec::new();
        let mut fsp_mints = Vec::new();
        for g in &payload.groups {
            match g.kind {
                Kind::Psp => {
                    psp_mints.push(g.mint.clone());
                    match self.data().live_keysets.get(&g.mint) {
                        Some((current, previous)) => {
                            if let Some(n) = g.notes.iter().find(|n| {
                                &n.keyset != current && Some(&n.keyset) != previous.as_ref()
                            }) {
                                return Err(WalletError::Invalid(format!(
                                    "a PSP note in the handoff is on key set {}, which {} no longer has live (it has {current}{}): the note has expired. Nothing was added",
                                    n.keyset,
                                    g.mint,
                                    previous
                                        .as_ref()
                                        .map(|p| format!(" and {p}"))
                                        .unwrap_or_default()
                                )));
                            }
                        }
                        None => warnings.push(format!(
                            "this wallet has not seen the PSP mint {}: its notes are not checked until it does",
                            g.mint
                        )),
                    }
                }
                Kind::Fsp => {
                    let service = g.service.expect("an FSP group has a service");
                    fsp_mints.push((service, g.mint.clone()));
                    let hexed = hex::encode(service.serialize());
                    match self.fsp_mints().get(&hexed) {
                        Some(m) => {
                            if let Some(n) = g.notes.iter().find(|n| {
                                n.keyset != m.current && Some(&n.keyset) != m.previous.as_ref()
                            }) {
                                return Err(WalletError::Invalid(format!(
                                    "an FSP note in the handoff is on key set {}, which the mint of service {hexed} no longer has live (it has {}{}): the note has expired. Nothing was added",
                                    n.keyset,
                                    m.current,
                                    m.previous
                                        .as_ref()
                                        .map(|p| format!(" and {p}"))
                                        .unwrap_or_default()
                                )));
                            }
                            if m.url.trim_end_matches('/') != g.mint.trim_end_matches('/') {
                                warnings.push(format!(
                                    "the handoff names {} for service {hexed}, and this wallet knows {}: the wallet keeps its own",
                                    g.mint, m.url
                                ));
                            }
                        }
                        None => warnings.push(format!(
                            "this wallet has not seen the FSP mint of service {hexed}: its notes are not checked until it does"
                        )),
                    }
                }
                Kind::Esp => unreachable!("decode never makes an ESP group"),
            }
        }

        let note_ids: Vec<String> = payload
            .groups
            .iter()
            .flat_map(|g| g.notes.iter())
            .map(|n| hex::encode(n.note.nonce.0.serialize()))
            .collect();
        let (psp_units, fsp_units) = (payload.units(Kind::Psp), payload.units(Kind::Fsp));
        let record = IncomingHandoff {
            id: id.clone(),
            from: from.trim().to_string(),
            psp_units,
            fsp_units,
            notes: note_ids.clone(),
            swapped: swap,
        };

        // Build the swaps first, so the write below is one step.
        let mut swaps = Vec::new();
        let mut psp_swaps = Vec::new();
        if swap {
            for (i, g) in payload
                .groups
                .iter()
                .filter(|g| g.kind == Kind::Psp)
                .enumerate()
            {
                let token_notes: Vec<crate::send::TokenNote> = g
                    .notes
                    .iter()
                    .map(|n| crate::send::TokenNote {
                        amount: n.amount,
                        note: n.note,
                        spend_secret: n.spend_secret,
                        keyset: n.keyset.clone(),
                    })
                    .collect();
                let current =
                    crate::send::swap_keyset(self.data().live_keysets.get(&g.mint), &token_notes);
                let p = crate::send::build_psp_swap(
                    &g.mint,
                    &token_notes,
                    format!("handoff|{id}|{i}"),
                    &current,
                )?;
                psp_swaps.push(p.id.clone());
                swaps.push(p);
            }
        }

        let mut fsp_swaps: BTreeMap<[u8; 32], Vec<String>> = BTreeMap::new();
        let add_psp = !swap;
        self.update(|d| {
            for g in &payload.groups {
                for n in &g.notes {
                    let (kind, terms) = match g.kind {
                        Kind::Psp => {
                            if !add_psp {
                                continue;
                            }
                            (Kind::Psp, None)
                        }
                        _ => (
                            Kind::Fsp,
                            Some(StoredTerms {
                                service: g.service.expect("an FSP group has a service"),
                                redeemable_after_day: 0,
                            }),
                        ),
                    };
                    let stored = StoredNote {
                        kind,
                        amount: n.amount,
                        note: n.note,
                        spend_secret: n.spend_secret,
                        terms,
                        reserved_by: None,
                    };
                    match kind {
                        Kind::Psp => {
                            d.keysets.insert(stored.id(), n.keyset.clone());
                        }
                        _ => {
                            d.fsp_keysets.insert(stored.id(), n.keyset.clone());
                            fsp_swaps
                                .entry(g.service.expect("service").serialize())
                                .or_default()
                                .push(stored.id());
                        }
                    }
                    d.notes.push(stored);
                }
            }
            d.pending_rollovers.extend(swaps);
            d.handoffs_in.push(record);
            Ok(())
        })?;

        Ok(Imported {
            id,
            psp_units,
            fsp_units,
            notes: note_ids,
            did_key: payload.did_key,
            warnings,
            psp_mints,
            fsp_mints,
            psp_swaps,
            fsp_swaps: if swap {
                fsp_swaps
                    .into_iter()
                    .map(|(s, ids)| (XOnlyPublicKey::from_slice(&s).expect("a key"), ids))
                    .collect()
            } else {
                Vec::new()
            },
        })
    }

    /// Build the stored swap of imported FSP notes (a spend that pays 0, so a
    /// normal swap at the service's fsp-mint). Returns the request's hash, to
    /// send with `http::settle_fsp`.
    pub fn build_fsp_swap_of(
        &mut self,
        service: XOnlyPublicKey,
        ids: &[String],
    ) -> Result<String, WalletError> {
        let chosen: Vec<StoredNote> = self
            .notes()
            .iter()
            .filter(|n| ids.contains(&n.id()) && n.reserved_by.is_none())
            .cloned()
            .collect();
        if chosen.is_empty() {
            return Err(WalletError::NotEnough("no notes to swap".into()));
        }
        let request = self.build_swap(service, chosen, 0, "handoff swap")?;
        Ok(request.hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blind::PendingOutput;
    use std::fs;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ecash-wallet-handoff-{}-{name}", {
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

    const KS_A: &str = "0123456789abcdef";
    const KS_B: &str = "fedcba9876543210";
    const PSP_URL: &str = "http://127.0.0.1:3000";
    const FSP_URL: &str = "http://127.0.0.1:3200";

    fn service(n: u8) -> XOnlyPublicKey {
        let sk = SecretKey::from_slice(&[n; 32]).unwrap();
        sk.public_key(SECP256K1).x_only_public_key().0
    }

    /// A note with a real key pair, so its secret matches its nonce.
    fn note(kind: Kind, amount: u64, service: Option<XOnlyPublicKey>) -> StoredNote {
        let out = PendingOutput::new(amount);
        let sk = SecretKey::new(&mut rand::rngs::OsRng);
        let sig = bdhke::sign_message(&sk, &out.blind_nonce.0);
        StoredNote {
            kind,
            amount,
            note: out.unblind(&sig, &sk.public_key(SECP256K1)),
            spend_secret: out.nonce_secret,
            terms: service.map(|s| StoredTerms {
                service: s,
                redeemable_after_day: 0,
            }),
            reserved_by: None,
        }
    }

    /// A wallet with PSP notes (4, 2, 1) and FSP notes for service 1 (8, 8) and
    /// service 2 (2), each with a key set, and the FSP mints seen.
    fn funded(dir: &PathBuf, name: &str) -> Wallet {
        let mut w = Wallet::open(&dir.join(name)).unwrap();
        w.update(|d| {
            for (kind, amount, svc, ks) in [
                (Kind::Psp, 4, None, KS_A),
                (Kind::Psp, 2, None, KS_A),
                (Kind::Psp, 1, None, KS_B),
                (Kind::Fsp, 8, Some(service(1)), KS_A),
                (Kind::Fsp, 8, Some(service(1)), KS_A),
                (Kind::Fsp, 2, Some(service(2)), KS_B),
            ] {
                let n = note(kind, amount, svc);
                if kind == Kind::Psp {
                    d.keysets.insert(n.id(), ks.to_string());
                } else {
                    d.fsp_keysets.insert(n.id(), ks.to_string());
                }
                d.notes.push(n);
            }
            for (i, s) in [service(1), service(2)].iter().enumerate() {
                d.fsp_mints.insert(
                    hex::encode(s.serialize()),
                    crate::fsp::FspMint {
                        url: format!("{FSP_URL}{i}"),
                        current: KS_A.into(),
                        previous: Some(KS_B.into()),
                        next_rotation: None,
                    },
                );
            }
            Ok(())
        })
        .unwrap();
        w
    }

    fn did() -> DidSecretKey {
        DidSecretKey::from_array([7u8; 32]).unwrap()
    }

    #[test]
    fn base44_round_trips_every_length() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let text = base44_encode(&bytes);
            assert_eq!(base44_decode(&text).unwrap(), bytes, "length {len}");
            // 3 characters per 2 bytes, 2 for a last byte
            assert_eq!(text.len(), len / 2 * 3 + (len % 2) * 2);
        }
        // every byte pair, at the edges
        for pair in [[0u8, 0], [255, 255], [0, 255], [255, 0]] {
            assert_eq!(base44_decode(&base44_encode(&pair)).unwrap(), pair);
        }
        assert!(base44_decode("ZZZ").is_err(), "above 65,535");
        assert!(base44_decode("A").is_err(), "one character alone");
        assert!(base44_decode("a b").is_err(), "not in the alphabet");
    }

    #[test]
    fn the_alphabet_is_the_qr_alphanumeric_set_without_the_space() {
        let qr = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        assert_eq!(ALPHABET.len(), 44);
        for c in ALPHABET {
            assert!(qr.contains(*c as char));
        }
        assert!(!ALPHABET.contains(&b' '));
    }

    #[test]
    fn a_handoff_round_trips_with_notes_services_and_a_did_key() {
        let dir = scratch("round");
        let mut a = funded(&dir, "a.json");
        let before = a.balance();
        let sel = a
            .select_handoff(5, &[(service(1), 16), (service(2), 2)])
            .unwrap();
        let out = a.export_handoff(&sel, PSP_URL, Some(&did())).unwrap();
        assert!(out.text.starts_with(PREFIX));
        assert_eq!(
            (out.notes, out.psp_units, out.fsp_units, out.with_did_key),
            (5, 5, 18, true)
        );
        assert_eq!(out.warning, BEARER_WARNING);
        assert!(out.text.bytes().all(|c| ALPHABET.contains(&c)
            || c == b'S'
            || c == b'P'
            || c == b'H'
            || c == b'1'));
        // taken out of the sender
        let after = a.balance();
        assert_eq!(after.psp, before.psp - 5);
        assert_eq!(after.fsp, before.fsp - 18);

        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        let got = b.import_handoff(&out.text, "alice", false).unwrap();
        assert_eq!(got.id, out.id);
        assert_eq!((got.psp_units, got.fsp_units), (5, 18));
        assert_eq!(got.did_key, Some(did()));
        assert_eq!(got.notes.len(), 5);
        let bal = b.balance();
        assert_eq!((bal.psp, bal.fsp, bal.notes), (5, 18, 5));
        // each FSP note kept its service, and every note its key set
        assert_eq!(bal.fsp_by_service[&hex::encode(service(1).serialize())], 16);
        assert_eq!(bal.fsp_by_service[&hex::encode(service(2).serialize())], 2);
        for n in b.notes() {
            match n.kind {
                Kind::Psp => assert!(b.data().keysets.contains_key(&n.id())),
                _ => assert!(b.data().fsp_keysets.contains_key(&n.id())),
            }
        }
        // the source is kept
        assert_eq!(b.handoffs_in().len(), 1);
        assert_eq!(b.handoffs_in()[0].from, "alice");
        assert_eq!(b.handoffs_in()[0].id, out.id);
        // and survives a reopen
        let again = Wallet::open(b.path()).unwrap();
        assert_eq!(again.handoffs_in(), b.handoffs_in());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_handoff_without_a_did_key_gives_none() {
        let dir = scratch("nodid");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(1, &[]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        assert!(!out.with_did_key);
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        assert_eq!(
            b.import_handoff(&out.text, "", false).unwrap().did_key,
            None
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_handoff_can_carry_only_a_did_key() {
        let payload = Payload {
            groups: vec![],
            did_key: Some(did()),
        };
        let (text, id) = payload.encode().unwrap();
        let (back, id2) = Payload::decode(&text).unwrap();
        assert_eq!((back, id2), (payload, id));
        assert!(
            Payload {
                groups: vec![],
                did_key: None
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn the_size_is_as_documented() {
        let dir = scratch("size");
        let mut a = funded(&dir, "a.json");
        // one PSP group, one key set, three notes: 3 + (1 + 2 + 21 + 1 + 8 + 2) + 3 * 100 + 4
        let sel = a.select_handoff(7, &[]).unwrap();
        assert_eq!(sel.psp.len(), 3);
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let header = 3 + (1 + 2 + PSP_URL.len() + 1 + 8 * 2 + 2);
        let raw = header + 3 * NOTE_BYTES + CHECK_BYTES;
        // two key sets are in use (A and B), so 16 bytes of key sets
        assert_eq!(base44_decode(&out.text[PREFIX.len()..]).unwrap().len(), raw);
        assert_eq!(out.chars, PREFIX.len() + raw / 2 * 3 + (raw % 2) * 2);
        // a DID key adds 32 bytes
        let mut b = funded(&dir, "b.json");
        let sel = b.select_handoff(7, &[]).unwrap();
        let with = b.export_handoff(&sel, PSP_URL, Some(&did())).unwrap();
        let raw_with = base44_decode(&with.text[PREFIX.len()..]).unwrap().len();
        assert_eq!(raw_with, raw + DID_KEY_BYTES);
        // and fits a QR code of alphanumeric characters
        assert!(with.chars < 3391);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn whitespace_and_lower_case_are_forgiven_but_not_a_changed_character() {
        let dir = scratch("clean");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(1, &[]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let wrapped: String = out
            .text
            .as_bytes()
            .chunks(40)
            .map(|c| format!("{}\n", String::from_utf8_lossy(c)))
            .collect();
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        b.import_handoff(&format!("  {}  ", wrapped.to_lowercase()), "", false)
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    fn damaged(text: &str, at: usize) -> String {
        let mut bytes = text.as_bytes().to_vec();
        bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn a_corrupt_payload_is_refused_and_adds_nothing() {
        let dir = scratch("corrupt");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(7, &[]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        let file_before = fs::read(b.path()).ok();
        // one changed character anywhere after the prefix
        for at in [
            PREFIX.len(),
            PREFIX.len() + 50,
            out.text.len() / 2,
            out.text.len() - 1,
        ] {
            let e = b
                .import_handoff(&damaged(&out.text, at), "", false)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("damaged") || e.contains("cut short") || e.contains("not valid"),
                "{at}: {e}"
            );
        }
        // cut short
        let e = b
            .import_handoff(&out.text[..out.text.len() - 7], "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("damaged") || e.contains("cut short"), "{e}");
        // extra characters
        assert!(
            b.import_handoff(&format!("{}AB", out.text), "", false)
                .is_err()
        );
        // not a handoff at all
        for junk in ["", "hello", "SPH", "SPH1", "SPH1:", "SPH1:!!!", "psp1abcd"] {
            assert!(b.import_handoff(junk, "", false).is_err(), "{junk}");
        }
        assert!(b.notes().is_empty());
        assert!(b.handoffs_in().is_empty());
        assert_eq!(
            fs::read(b.path()).ok(),
            file_before,
            "the file is untouched"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_payload_of_another_version_is_refused_and_says_so() {
        let dir = scratch("version");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(1, &[]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        // the prefix says version 2
        let e = b
            .import_handoff(&out.text.replacen("SPH1:", "SPH2:", 1), "", false)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("version 2") && e.contains("reads version 1 only"),
            "{e}"
        );
        // the prefix is right, the version inside is not (with a good check)
        let mut body = base44_decode(&out.text[PREFIX.len()..]).unwrap();
        body.truncate(body.len() - CHECK_BYTES);
        body[0] = 2;
        let digest = Sha256::digest(&body);
        body.extend_from_slice(&digest[..CHECK_BYTES]);
        let e = b
            .import_handoff(&format!("{PREFIX}{}", base44_encode(&body)), "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("version 2"), "{e}");
        // an unknown flag bit is a feature this wallet lacks
        body.truncate(body.len() - CHECK_BYTES);
        body[0] = 1;
        body[1] = 2;
        let digest = Sha256::digest(&body);
        body.extend_from_slice(&digest[..CHECK_BYTES]);
        let e = b
            .import_handoff(&format!("{PREFIX}{}", base44_encode(&body)), "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not know"), "{e}");
        assert!(b.notes().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_note_whose_secret_is_not_its_nonces_is_refused() {
        let dir = scratch("forged");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(1, &[]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let mut body = base44_decode(&out.text[PREFIX.len()..]).unwrap();
        body.truncate(body.len() - CHECK_BYTES);
        // the last 32 bytes are the note's secret: change one
        let at = body.len() - 1;
        body[at] ^= 1;
        let digest = Sha256::digest(&body);
        body.extend_from_slice(&digest[..CHECK_BYTES]);
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        let e = b
            .import_handoff(&format!("{PREFIX}{}", base44_encode(&body)), "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not the one for its nonce"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_double_import_is_refused() {
        let dir = scratch("double");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(7, &[(service(1), 8)]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        b.import_handoff(&out.text, "", false).unwrap();
        let held = b.balance();
        let e = b
            .import_handoff(&out.text, "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("imported already"), "{e}");
        assert_eq!(b.balance(), held, "nothing was added the second time");
        // still refused after the notes have been spent: the record stays
        let ids: Vec<String> = b.notes().iter().map(StoredNote::id).collect();
        b.update(|d| {
            d.notes.retain(|n| !ids.contains(&n.id()));
            Ok(())
        })
        .unwrap();
        assert!(b.import_handoff(&out.text, "", false).is_err());
        // another wallet that already holds one of the notes refuses too
        let mut c = Wallet::open(&dir.join("c.json")).unwrap();
        let first = a.handoffs_out()[0].notes[0].clone();
        c.update(|d| {
            d.notes.push(first);
            Ok(())
        })
        .unwrap();
        let e = c
            .import_handoff(&out.text, "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("already in this wallet"), "{e}");
        assert_eq!(c.notes().len(), 1);
        // the sender cannot import its own handoff
        let e = a
            .import_handoff(&out.text, "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("made this handoff"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_note_on_a_retired_key_set_is_refused_when_the_mint_is_known() {
        let dir = scratch("retired");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(7, &[(service(1), 16)]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();

        // FSP: the receiver knows service 1's mint, whose live sets are not A or B
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        b.update(|d| {
            d.fsp_mints.insert(
                hex::encode(service(1).serialize()),
                crate::fsp::FspMint {
                    url: FSP_URL.into(),
                    current: "1111111111111111".into(),
                    previous: None,
                    next_rotation: None,
                },
            );
            Ok(())
        })
        .unwrap();
        let e = b
            .import_handoff(&out.text, "", false)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("expired") && e.contains("1111111111111111"),
            "{e}"
        );
        assert!(b.notes().is_empty());

        // PSP: the receiver knows the PSP mint's live sets
        let mut c = Wallet::open(&dir.join("c.json")).unwrap();
        c.update(|d| {
            d.live_keysets.insert(
                PSP_URL.into(),
                ("2222222222222222".into(), Some("3333333333333333".into())),
            );
            Ok(())
        })
        .unwrap();
        let e = c
            .import_handoff(&out.text, "", false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("expired"), "{e}");
        assert!(c.notes().is_empty());

        // with the right sets known it is accepted, and a different URL for the
        // same service is a warning, not a refusal
        let mut d = Wallet::open(&dir.join("d.json")).unwrap();
        d.update(|w| {
            w.live_keysets
                .insert(PSP_URL.into(), (KS_A.into(), Some(KS_B.into())));
            w.fsp_mints.insert(
                hex::encode(service(1).serialize()),
                crate::fsp::FspMint {
                    url: "http://elsewhere".into(),
                    current: KS_A.into(),
                    previous: Some(KS_B.into()),
                    next_rotation: None,
                },
            );
            Ok(())
        })
        .unwrap();
        let got = d.import_handoff(&out.text, "", false).unwrap();
        assert!(
            got.warnings.iter().any(|w| w.contains("http://elsewhere")),
            "{:?}",
            got.warnings
        );
        assert_eq!(
            d.fsp_mints()[&hex::encode(service(1).serialize())].url,
            "http://elsewhere"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_mint_is_a_warning_not_a_refusal() {
        let dir = scratch("unknown");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(1, &[(service(2), 2)]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        let got = b.import_handoff(&out.text, "", false).unwrap();
        assert_eq!(got.warnings.len(), 2, "{:?}", got.warnings);
        assert_eq!(got.psp_mints, vec![PSP_URL.to_string()]);
        assert_eq!(got.fsp_mints.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cancelling_puts_the_notes_back_and_a_done_handoff_cannot_be_cancelled() {
        let dir = scratch("cancel");
        let mut a = funded(&dir, "a.json");
        let before = a.balance();
        let ids_before: BTreeSet<String> = a.notes().iter().map(StoredNote::id).collect();
        let sel = a.select_handoff(6, &[(service(1), 16)]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, Some(&did())).unwrap();
        assert_ne!(a.balance().notes, before.notes);
        assert_eq!(a.handoffs_out().len(), 1);
        assert_eq!(a.handoffs_out()[0].state, HandoffState::Pending);
        // the notes cannot be spent or handed off twice while it is out
        assert!(a.select_handoff(7, &[]).is_err());
        assert_eq!(a.cancel_handoff(&out.id).unwrap(), 4);
        assert_eq!(a.balance(), before);
        let ids_after: BTreeSet<String> = a.notes().iter().map(StoredNote::id).collect();
        assert_eq!(ids_after, ids_before);
        assert!(a.handoffs_out().is_empty());
        // the ledgers say the notes came back
        for id in &ids_before {
            assert!(!has_departed(a.data(), id));
        }
        assert!(a.cancel_handoff(&out.id).is_err(), "cancelled once");

        // a handoff that is done keeps no notes and cannot be cancelled
        let sel = a.select_handoff(1, &[]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        a.finish_handoff(&out.id).unwrap();
        assert_eq!(a.handoffs_out()[0].state, HandoffState::Done);
        assert!(a.handoffs_out()[0].notes.is_empty());
        assert_eq!(a.handoffs_out()[0].note_count, 1);
        assert!(a.cancel_handoff(&out.id).is_err());
        assert!(a.finish_handoff(&out.id).is_err());
        assert_eq!(a.balance().psp, before.psp - 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn export_refuses_what_it_cannot_hand_off() {
        let dir = scratch("refuse");
        let mut a = funded(&dir, "a.json");
        // not enough
        assert!(a.select_handoff(100, &[]).is_err());
        assert!(a.select_handoff(0, &[(service(1), 3)]).is_err());
        assert!(a.select_handoff(0, &[(service(9), 2)]).is_err());
        // nothing selected, and no DID key
        let e = a
            .export_handoff(&HandoffSelection::default(), PSP_URL, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("holds nothing"), "{e}");
        // PSP without a mint URL
        let sel = a.select_handoff(1, &[]).unwrap();
        assert!(a.export_handoff(&sel, " ", None).is_err());
        // a note that is not here, a note selected twice, a reserved note
        let bogus = HandoffSelection {
            psp: vec!["00".repeat(33)],
            fsp: vec![],
        };
        assert!(a.export_handoff(&bogus, PSP_URL, None).is_err());
        let twice = HandoffSelection {
            psp: vec![sel.psp[0].clone(), sel.psp[0].clone()],
            fsp: vec![],
        };
        assert!(a.export_handoff(&twice, PSP_URL, None).is_err());
        let id = sel.psp[0].clone();
        a.update(|d| {
            for n in d.notes.iter_mut().filter(|n| n.id() == id) {
                n.reserved_by = Some("x".into());
            }
            Ok(())
        })
        .unwrap();
        let e = a
            .export_handoff(&sel, PSP_URL, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("held back"), "{e}");
        // a PSP note selected as FSP, and an ESP note
        let wrong = HandoffSelection {
            psp: vec![],
            fsp: vec![sel.psp[0].clone()],
        };
        assert!(a.export_handoff(&wrong, PSP_URL, None).is_err());
        // an FSP note of an unknown service, and one with no key set
        let n = note(Kind::Fsp, 4, None);
        let nid = n.id();
        a.update(|d| {
            d.fsp_keysets.insert(nid.clone(), KS_A.into());
            d.notes.push(n);
            Ok(())
        })
        .unwrap();
        let unknown = HandoffSelection {
            psp: vec![],
            fsp: vec![nid.clone()],
        };
        let e = a
            .export_handoff(&unknown, PSP_URL, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no known service"), "{e}");
        let n = note(Kind::Psp, 8, None);
        let nid = n.id();
        a.update(|d| {
            d.notes.push(n);
            Ok(())
        })
        .unwrap();
        let nokeyset = HandoffSelection {
            psp: vec![nid],
            fsp: vec![],
        };
        let e = a
            .export_handoff(&nokeyset, PSP_URL, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no recorded key set"), "{e}");
        // nothing was taken out by any of these
        assert!(a.handoffs_out().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_note_that_is_not_a_power_of_two_is_not_encoded() {
        let n = note(Kind::Psp, 3, None);
        let payload = Payload {
            groups: vec![Group {
                kind: Kind::Psp,
                service: None,
                mint: PSP_URL.into(),
                notes: vec![PayloadNote {
                    amount: 3,
                    keyset: KS_A.into(),
                    note: n.note,
                    spend_secret: n.spend_secret,
                }],
            }],
            did_key: None,
        };
        assert!(payload.encode().is_err());
    }

    #[test]
    fn importing_with_a_swap_stores_the_swap_and_does_not_add_the_psp() {
        let dir = scratch("swap");
        let mut a = funded(&dir, "a.json");
        let sel = a.select_handoff(7, &[(service(1), 16)]).unwrap();
        let out = a.export_handoff(&sel, PSP_URL, None).unwrap();
        let mut b = Wallet::open(&dir.join("b.json")).unwrap();
        let got = b.import_handoff(&out.text, "dev", true).unwrap();
        // the PSP is a stored swap, not notes; the FSP is added, to be swapped
        assert_eq!(got.psp_swaps.len(), 1);
        assert_eq!(b.pending_rollovers().len(), 1);
        assert_eq!(b.pending_rollovers()[0].id, got.psp_swaps[0]);
        assert_eq!(b.pending_rollovers()[0].inputs.len(), 3);
        assert_eq!(b.balance().psp, 0);
        assert_eq!(b.balance().fsp, 16);
        assert_eq!(got.fsp_swaps.len(), 1);
        assert_eq!(got.fsp_swaps[0].1.len(), 2);
        assert!(b.handoffs_in()[0].swapped);
        // and a second import is refused
        assert!(b.import_handoff(&out.text, "dev", true).is_err());
        assert_eq!(b.pending_rollovers().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }
}
