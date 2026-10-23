//! Handoff: moving notes from one wallet to another without the AIR, in exactly
//! two kinds.
//!
//! An unfunded wallet cannot pay to read from the AIR, so a new user or a new
//! device gets its first notes from somewhere else, as a string or a QR code.
//! There are two valid handoffs. Every other mix is impossible to build in the
//! API, has no string format, and is refused if one is made by hand:
//!
//! | | PSP handoff | FSP handoff |
//! |---|---|---|
//! | between | a developer and a user (after an in-app purchase) | one person's old device and new device |
//! | carries | PSP notes only | FSP notes and the DID secret key |
//! | encrypted | always, to the recipient's DID public key | never (it carries the key it would be encrypted to) |
//! | swapped on import | always, at the PSP mint, for new notes | never (the owner does not change) |
//! | string starts | `SPHP2:` | `SPHF2:` |
//!
//! The command line is `handoff export-psp`, `handoff export-fsp`, `handoff
//! import`, `handoff check`, `handoff reclaim`, `handoff cancel`, `handoff done`
//! and `handoff list`. This module does no I/O of its own:
//! [`Wallet::export_psp_handoff`] and [`Wallet::export_fsp_handoff`] make a
//! handoff, [`Wallet::import_handoff`] (or the two kind-specific imports) takes
//! one in (`kind_of` says which a string needs), the swap that a PSP import stores is sent by
//! [`crate::mint_info::complete_import`], and the sender's questions to the mint are
//! asked by [`crate::mint_info::check_handoff`] and [`crate::mint_info::reclaim_handoff`].
//!
//! # PSP handoff
//!
//! Made by a developer's service for an app's user, whose DID public key the
//! app made locally (it costs nothing and needs no points). The notes' spend
//! secrets are sealed to that key with [`sp_wire::seal`], which is AIR's own
//! `PublicKey::encrypt` (ElligatorSwift key exchange and ChaCha20-Poly1305, a
//! fresh sender key every time), so only the holder of the matching DID secret
//! key can read it. Nothing here is new cryptography.
//!
//! On import the notes are added to the wallet as ordinary PSP notes, **and** a
//! swap at the PSP mint (`POST /rollover`, for notes of the same amounts on the
//! mint's current key set) is stored in the same write, which the caller sends
//! at once. The wallet swaps them first whenever the mint can be reached: on
//! import, then on every later connection (the startup sync,
//! [`crate::mint_info::rotation_sync`], sends stored swaps before anything else). Until
//! the swap goes through the notes are **unswapped**: they count in the
//! balance ([`crate::store::Balance::psp`], with
//! [`crate::store::Balance::unswapped_psp`] saying how much of it is still
//! unswapped) and can be spent. There is no lock on them, because none is needed:
//! spending a note at the mint burns it just as the swap does, so whichever
//! reaches the mint first wins and the other is told the note is spent. A swap
//! whose notes were spent in the meantime is rebuilt for the notes that are left
//! ([`Wallet::live_swap`]), and a note the mint says is spent is dropped from the
//! balance. What the mint's record says decides who has the notes: the receiver
//! (who swapped or spent them), or the sender (who reclaimed them first).
//!
//! # Reclaim
//!
//! While the receiver has not swapped, the sender can take the notes back. The
//! sender's record of a PSP handoff holds the notes (state
//! [`HandoffState::Pending`]) and the PSP mint. `handoff check` asks the mint
//! (`POST /check-state`) which of them are spent: **none** means the handoff is
//! still reclaimable; **all** means the receiver swapped (or spent) them, the
//! handoff is [`HandoffState::Done`] and the sender keeps nothing; **some** means
//! the others were spent elsewhere, those are dropped from the record
//! ([`Standing::Partly`]) and the rest is still reclaimable. `handoff reclaim`
//! stores a swap of what is left back to this wallet for fresh notes only it
//! knows ([`Wallet::begin_reclaim`], tag `reclaim|<id>`) and sends it. The mint
//! takes the first of the two swaps that reaches it (the receiver's or the
//! sender's) and refuses the other with nothing burned, so the record at the mint
//! decides, never a guess here. A reclaim that went through ends the handoff as
//! [`HandoffState::Reclaimed`]; one the mint refused (the receiver was first)
//! leaves it pending, and the next `check` finds the notes spent. The stored swap
//! is sent again after a crash or a lost reply, and the mint answers a repeat
//! from its record. An FSP handoff has no reclaim: the receiver holds the same
//! secrets and the mint has no record of who is whose.
//!
//! # FSP handoff
//!
//! Made on the old device of a user who is setting up a new one. It carries the
//! DID secret key and just enough FSP to pay to fetch the wallet from the AIR
//! (at least one note; the sender chooses how much). The new device then
//! fetches the full wallet and combines it with this small one with
//! [`Wallet::merge_file`] (`merge FILE` on the command line), net of the FSP
//! spent on the fetch. The fetch does not exist yet, so the merge is a separate
//! step that runs after it.
//!
//! It cannot be encrypted, because it carries the key it would be encrypted to,
//! so it is as sensitive as anything gets: whoever sees the string can spend the
//! notes and act as that DID. [`FSP_WARNING`] is shown on export and on import.
//! Move it in person, by QR code or on a trusted cable, never over a network.
//!
//! The FSP notes are added to the wallet as they are and are not swapped. Both
//! devices belong to one owner, so there is nobody to swap against, and a swap
//! could not be done before the new device can pay anyway.
//!
//! # Taking notes out, putting them back
//!
//! Export takes the notes out of the sender's `notes` in the same write that
//! records the handoff (state [`HandoffState::Pending`]), so the sender cannot
//! spend them while the handoff is out. [`Wallet::cancel_handoff`] puts them
//! back. That is a local act: it does not tell the mint or the receiver. For a
//! PSP handoff the receiver swaps at once, so after a cancel the first of the
//! two to spend or swap the notes wins and the other is told by the mint that
//! they are spent: for a PSP handoff use `handoff reclaim` instead, which makes
//! the mint decide before the notes come back, and cancel only when the mint
//! cannot be asked. For an FSP handoff the receiver holds the same secrets as
//! the sender until one of them spends, so the same applies, and the old device
//! should not spend what it handed over. [`Wallet::finish_handoff`] drops the
//! sender's record of the notes once the sender knows the handoff has been
//! claimed.
//!
//! # Importing
//!
//! Import refuses a payload that is damaged, of another version or kind,
//! already imported (by its id, or because any of its notes is already here or
//! was and has left), or whose note keys do not match their nonces. Against what
//! the wallet already knows it checks each note's key-set ID (a mint whose live
//! key sets the wallet has seen must still have the note's set live) and, for
//! FSP, the service and its mint. What it has not seen it cannot check, and says
//! so in [`Imported::warnings`]; the command line then reads the mint's keys
//! (`fsp_sync`), which moves notes on a retired set to the lost record. A blind
//! signature can only be checked by the mint, so a PSP note is known good only
//! once it is swapped.
//!
//! Each imported note keeps its source: the handoff id, in
//! [`crate::store::WalletData::handoffs_in`], with the sender's name if one was
//! given.
//!
//! # The encoding
//!
//! The prefix, then the bytes below in base 44 (the characters of a QR code's
//! alphanumeric mode, less the space, so the whole string is one QR segment and
//! survives being pasted: `0-9 A-Z $ % * + - . / :`). Three characters carry two
//! bytes. All numbers are big-endian. The prefix's digit is the format version.
//! The old combined `SPH1:` handoff of wallet 0.4.0 is refused with a message.
//!
//! ```text
//! PSP:  SPHP2:  base44( sealed ‖ check )
//!   sealed   the body below, sealed to the recipient's DID key (80 bytes longer)
//!   check    4  the first 4 bytes of SHA-256 of the sealed bytes
//!
//!   body:
//!   version      1   2
//!   kind         1   0 (PSP)
//!   mint         2+n the PSP's DID in lowercase hex (66 characters), a length
//!                and UTF-8: a name, not an address, since the PSP is reached
//!                over AIR. A handoff that names anything else there is refused.
//!   keysets      1+8k how many key sets the notes use, and each (8 bytes)
//!   notes        2   how many notes
//!     per note:
//!     size       1   the amount is 2 to this power
//!     keyset     1   which of the key sets
//!     nonce     33   the note's identity (compressed)
//!     sig       33   the mint's signature (compressed)
//!     secret    32   the spend secret
//!
//! FSP:  SPHF2:  base44( body ‖ check )
//!   check    4  the first 4 bytes of SHA-256 of the body
//!
//!   body:
//!   version      1   2
//!   kind         1   1 (FSP)
//!   groups       1   how many groups (1 to 255)
//!     per group:
//!     service   33   the service's AIR DID (compressed key)
//!     mint, keysets, notes   as for PSP; the mint is the service's DID in hex
//!                            (66 characters) and nothing else: a name, not an
//!                            address, since an FSP mint is reached through the
//!                            receiver's own `air.fsp` entry. A handoff that
//!                            names anything else there is refused.
//!   did key     32   the DID secret key
//! ```
//!
//! A note is [`NOTE_BYTES`] (100) bytes, 150 characters. The handoff's id is the
//! first 16 bytes of SHA-256 of the body (not of the sealed bytes, which change
//! every time they are sealed), in hex, so the sender and the receiver both
//! have it. A PSP handoff of N notes of one key set (the PSP named by its
//! 66-character DID) is about 254 + 150N characters, an FSP handoff of one service about 233 + 150N.
//! A QR code holds at most 4,296 alphanumeric characters (error correction L,
//! version 40) or 3,391 (M), so one code holds about 27 notes at L or 21 at M. A
//! funding handoff of $100 is 3 PSP notes (64, 32 and 4 PSP), about 640
//! characters. A handoff of more notes than a QR code holds is a string or a
//! file. An FSP handoff needs only a few notes.

use std::collections::{BTreeMap, BTreeSet};

use mint_types::{Nonce, Note};
use secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_wire::ServiceDid;
use sp_wire::seal::{PublicKey as DidPublicKey, SealError, SecretKey as DidSecretKey};

use crate::blind::PendingOutput;
use crate::error::WalletError;
use crate::rotate::PendingRollover;
use crate::store::{Kind, StoredNote, StoredTerms, Wallet, WalletData, has_departed};

/// Shown wherever a PSP handoff is made or opened.
pub const PSP_WARNING: &str = "This PSP handoff holds the secret keys that spend its notes, sealed to the recipient's DID key. Only the holder of that DID's secret key can open it, and whoever opens it can spend the notes until they are swapped, which the importing wallet does at once. Send it only to the DID it was made for.";

/// Shown wherever an FSP handoff is made or imported.
pub const FSP_WARNING: &str = "This FSP handoff holds the secret keys that spend its notes AND the DID secret key itself, and it is not encrypted. Anyone who sees it can spend the notes and act as this DID. Hand it over in person or by QR code between your own devices, never post or send it over a network, and delete it once it is imported.";

/// A PSP handoff string starts with this. The digit is the format version.
pub const PSP_PREFIX: &str = "SPHP2:";
/// An FSP handoff string starts with this. The digit is the format version.
pub const FSP_PREFIX: &str = "SPHF2:";
/// The combined handoff of wallet 0.4.0. It is refused.
pub const OLD_PREFIX: &str = "SPH1:";
/// The format version this wallet reads and writes, for both kinds.
pub const FORMAT_VERSION: u8 = 2;
/// Bytes of one note in the payload.
pub const NOTE_BYTES: usize = 100;
/// Bytes of a DID secret key in the payload.
pub const DID_KEY_BYTES: usize = 32;
/// The most notes in one handoff, as in a PSP token.
pub const MAX_NOTES: usize = 1000;
const CHECK_BYTES: usize = 4;
/// The kind byte inside a PSP body and an FSP body.
const KIND_PSP: u8 = 0;
const KIND_FSP: u8 = 1;
/// The tag of the stored swap of a PSP handoff the receiver imported
/// (`handoff|<id>|<n>`).
pub(crate) const SWAP_TAG: &str = "handoff|";
/// The tag of the stored swap with which the sender takes a PSP handoff back
/// (`reclaim|<id>`). The same tag the old `sent --reclaim` used.
pub(crate) const RECLAIM_TAG: &str = "reclaim|";

/// The two kinds of handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffKind {
    Psp,
    Fsp,
}

impl HandoffKind {
    pub fn label(self) -> &'static str {
        match self {
            HandoffKind::Psp => "PSP",
            HandoffKind::Fsp => "FSP",
        }
    }
}

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

// ---- the payloads ----------------------------------------------------------------

/// One note in a payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadNote {
    pub amount: u64,
    /// The key set that signed it (16 hex characters).
    pub keyset: String,
    pub note: Note,
    pub spend_secret: SecretKey,
}

/// What a PSP handoff holds: PSP notes of one mint, and nothing else. There is
/// no field for a DID key or for FSP, so such a handoff cannot be built. `mint`
/// is the PSP's DID in lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PspPayload {
    pub mint: String,
    pub notes: Vec<PayloadNote>,
}

/// FSP notes of one service and its mint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FspGroup {
    pub service: ServiceDid,
    pub mint: String,
    pub notes: Vec<PayloadNote>,
}

/// What an FSP handoff holds: FSP notes and the DID secret key, which is not
/// optional, so a handoff without one cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FspPayload {
    pub groups: Vec<FspGroup>,
    pub did_key: DidSecretKey,
}

fn units_of(notes: &[PayloadNote]) -> u128 {
    notes.iter().map(|n| u128::from(n.amount)).sum()
}

fn short() -> WalletError {
    WalletError::Invalid("the handoff is cut short or damaged".into())
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

/// The mint's name (a DID in hex), its key sets and its notes, as in both bodies.
fn write_notes(b: &mut Vec<u8>, mint: &str, notes: &[PayloadNote]) -> Result<(), WalletError> {
    let name = mint.as_bytes();
    if name.is_empty() || name.len() > 0xFFFF {
        return Err(WalletError::Invalid(
            "a handoff needs the mint's name (up to 65,535 bytes)".into(),
        ));
    }
    b.extend_from_slice(&(name.len() as u16).to_be_bytes());
    b.extend_from_slice(name);
    if notes.is_empty() {
        return Err(WalletError::Invalid("the handoff holds nothing".into()));
    }
    if notes.len() > MAX_NOTES {
        return Err(WalletError::Invalid(format!(
            "a handoff holds at most {MAX_NOTES} notes"
        )));
    }
    let mut keysets: Vec<&str> = Vec::new();
    for n in notes {
        if !keysets.contains(&n.keyset.as_str()) {
            keysets.push(&n.keyset);
        }
    }
    if keysets.len() > 255 {
        return Err(WalletError::Invalid(
            "a handoff uses at most 255 key sets".into(),
        ));
    }
    b.push(keysets.len() as u8);
    for k in &keysets {
        b.extend_from_slice(&keyset_bytes(k)?);
    }
    b.extend_from_slice(&(notes.len() as u16).to_be_bytes());
    for n in notes {
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
    Ok(())
}

impl PspPayload {
    /// The notes' units.
    pub fn units(&self) -> u128 {
        units_of(&self.notes)
    }

    fn body(&self) -> Result<Vec<u8>, WalletError> {
        let mut b = vec![FORMAT_VERSION, KIND_PSP];
        write_notes(&mut b, &self.mint, &self.notes)?;
        Ok(b)
    }

    /// The handoff string, sealed to `to`, and the handoff's id.
    pub fn seal(&self, to: &DidPublicKey) -> Result<(String, String), WalletError> {
        let plain = self.body()?;
        let id = id_of(&plain);
        let sealed = sp_wire::seal::encrypt(to, &plain)
            .map_err(|e| WalletError::Invalid(format!("could not seal the handoff: {e}")))?;
        Ok((frame(PSP_PREFIX, &sealed), id))
    }

    /// Open a PSP handoff string with the recipient's DID secret key. Fails on
    /// anything that is not exactly one, on a handoff sealed to another key,
    /// and on a note whose secret is not its nonce's. Returns the payload and
    /// its id.
    pub fn open(text: &str, key: &DidSecretKey) -> Result<(PspPayload, String), WalletError> {
        let clean = clean(text);
        let (kind, at) = classify(&clean)?;
        if kind != HandoffKind::Psp {
            return Err(WalletError::Invalid(
                "this is an FSP handoff, not a PSP handoff".into(),
            ));
        }
        let sealed = unframe(&clean[at..])?;
        let plain = sp_wire::seal::decrypt(key, &sealed).map_err(|e| match e {
            SealError::Undecryptable => WalletError::Invalid(
                "this PSP handoff cannot be opened with this DID key: it was sealed to a different DID, or it was altered".into(),
            ),
            _ => short(),
        })?;
        let payload = parse_psp_body(&plain)?;
        Ok((payload, id_of(&plain)))
    }
}

impl FspPayload {
    /// The notes' units.
    pub fn units(&self) -> u128 {
        self.groups.iter().map(|g| units_of(&g.notes)).sum()
    }

    /// How many notes are in all groups.
    pub fn note_count(&self) -> usize {
        self.groups.iter().map(|g| g.notes.len()).sum()
    }

    fn body(&self) -> Result<Vec<u8>, WalletError> {
        if self.groups.is_empty() {
            return Err(WalletError::Invalid(
                "an FSP handoff carries FSP: it holds nothing".into(),
            ));
        }
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
        let mut b = vec![FORMAT_VERSION, KIND_FSP, self.groups.len() as u8];
        for g in &self.groups {
            b.extend_from_slice(&g.service.serialize());
            write_notes(&mut b, &g.mint, &g.notes)?;
        }
        b.extend_from_slice(&self.did_key.to_array());
        Ok(b)
    }

    /// The handoff string (not encrypted) and the handoff's id.
    pub fn encode(&self) -> Result<(String, String), WalletError> {
        let body = self.body()?;
        let id = id_of(&body);
        Ok((frame(FSP_PREFIX, &body), id))
    }

    /// Read an FSP handoff string. Fails on anything that is not exactly one.
    /// Returns the payload and its id.
    pub fn decode(text: &str) -> Result<(FspPayload, String), WalletError> {
        let clean = clean(text);
        let (kind, at) = classify(&clean)?;
        if kind != HandoffKind::Fsp {
            return Err(WalletError::Invalid(
                "this is a PSP handoff, not an FSP handoff".into(),
            ));
        }
        let body = unframe(&clean[at..])?;
        let payload = parse_fsp_body(&body)?;
        Ok((payload, id_of(&body)))
    }
}

/// The text without whitespace, in upper case.
fn clean(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Which kind a cleaned string is, and where its bytes start. Refuses the old
/// combined `SPH1:` with a message, and any other version.
fn classify(clean: &str) -> Result<(HandoffKind, usize), WalletError> {
    let not_one = || {
        WalletError::Invalid(format!(
            "this is not a handoff (a PSP handoff starts with {PSP_PREFIX}, an FSP handoff with {FSP_PREFIX})"
        ))
    };
    let b = clean.as_bytes();
    if b.len() < 5 || &b[..3] != b"SPH" {
        return Err(not_one());
    }
    // `SPH1:` is the old combined handoff.
    if b[3].is_ascii_digit() && b[4] == b':' {
        if b[3] == b'1' {
            return Err(WalletError::Invalid(format!(
                "this is an old combined handoff ({OLD_PREFIX}, from wallet 0.4.0), which this wallet no longer reads: it could carry a mix that is not allowed. Ask the sender to make a PSP handoff ({PSP_PREFIX}) or an FSP handoff ({FSP_PREFIX}) instead"
            )));
        }
        return Err(WalletError::Invalid(format!(
            "this is a handoff of a format this wallet does not know (SPH{}). Update the wallet",
            b[3] as char
        )));
    }
    let kind = match b[3] {
        b'P' => HandoffKind::Psp,
        b'F' => HandoffKind::Fsp,
        _ => return Err(not_one()),
    };
    if !b[4].is_ascii_digit() || b.get(5) != Some(&b':') {
        return Err(not_one());
    }
    if b[4] != b'0' + FORMAT_VERSION {
        return Err(WalletError::Invalid(format!(
            "this handoff is version {}, and this wallet reads version {FORMAT_VERSION} only. Update the older of the two wallets",
            b[4] as char
        )));
    }
    Ok((kind, 6))
}

/// Which kind of handoff a string is, without opening it: a caller needs to
/// know whether to ask for the recipient's DID key (PSP) or for a place to
/// save the DID key (FSP) before it imports.
pub fn kind_of(text: &str) -> Result<HandoffKind, WalletError> {
    classify(&clean(text)).map(|(k, _)| k)
}

/// The handoff's id: the first 16 bytes of SHA-256 of its body, in hex.
fn id_of(body: &[u8]) -> String {
    hex::encode(&Sha256::digest(body)[..16])
}

/// `prefix`, then `bytes` and their 4-byte check, in base 44.
fn frame(prefix: &str, bytes: &[u8]) -> String {
    let mut b = bytes.to_vec();
    b.extend_from_slice(&Sha256::digest(bytes)[..CHECK_BYTES]);
    format!("{prefix}{}", base44_encode(&b))
}

/// The bytes of a string after its prefix, with the check verified.
fn unframe(rest: &str) -> Result<Vec<u8>, WalletError> {
    let bytes = base44_decode(rest)?;
    if bytes.len() < CHECK_BYTES + 1 {
        return Err(short());
    }
    let (body, check) = bytes.split_at(bytes.len() - CHECK_BYTES);
    if Sha256::digest(body)[..CHECK_BYTES] != *check {
        return Err(WalletError::Invalid(
            "the handoff is damaged (its check does not match): copy it again".into(),
        ));
    }
    Ok(body.to_vec())
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WalletError> {
        if self.0.len() < n {
            return Err(short());
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

/// The version and kind bytes that start both bodies.
fn read_head(c: &mut Cursor, want_kind: u8, label: &str) -> Result<(), WalletError> {
    let version = c.u8()?;
    if version != FORMAT_VERSION {
        return Err(WalletError::Invalid(format!(
            "this handoff is version {version}, and this wallet reads version {FORMAT_VERSION} only. Update the older of the two wallets"
        )));
    }
    if c.u8()? != want_kind {
        return Err(WalletError::Invalid(format!(
            "this is not a {label} handoff inside"
        )));
    }
    Ok(())
}

/// A mint's name, key sets and notes. `seen` and `total` run across groups.
fn read_notes(
    c: &mut Cursor,
    seen: &mut BTreeSet<[u8; 33]>,
    total: &mut usize,
) -> Result<(String, Vec<PayloadNote>), WalletError> {
    let name_len = usize::from(c.u16()?);
    let mint = String::from_utf8(c.take(name_len)?.to_vec())
        .map_err(|_| WalletError::Invalid("a mint name in it is not text".into()))?;
    if mint.is_empty() {
        return Err(WalletError::Invalid("the handoff names no mint".into()));
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
    *total += count;
    if *total > MAX_NOTES {
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
        let signature = PublicKey::from_slice(c.take(33)?)
            .map_err(|_| WalletError::Invalid("a note's signature in it is not valid".into()))?;
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
    Ok((mint, notes))
}

fn parse_psp_body(body: &[u8]) -> Result<PspPayload, WalletError> {
    let mut c = Cursor(body);
    read_head(&mut c, KIND_PSP, "PSP")?;
    let (mint, notes) = read_notes(&mut c, &mut BTreeSet::new(), &mut 0)?;
    if !c.0.is_empty() {
        return Err(WalletError::Invalid(
            "a PSP handoff holds PSP notes and nothing else, and this one has more after them"
                .into(),
        ));
    }
    Ok(PspPayload { mint, notes })
}

fn parse_fsp_body(body: &[u8]) -> Result<FspPayload, WalletError> {
    let mut c = Cursor(body);
    read_head(&mut c, KIND_FSP, "FSP")?;
    let group_count = usize::from(c.u8()?);
    if group_count == 0 {
        return Err(WalletError::Invalid(
            "an FSP handoff carries FSP: it holds nothing".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    let mut groups = Vec::new();
    for _ in 0..group_count {
        let service = ServiceDid::from_slice(c.take(33)?)
            .map_err(|_| WalletError::Invalid("a service ID in it is not valid".into()))?;
        let (mint, notes) = read_notes(&mut c, &mut seen, &mut total)?;
        let named = hex::encode(service.serialize());
        if mint != named {
            return Err(WalletError::Invalid(format!(
                "an FSP handoff names each mint by its service's DID in hex ({named}), and this one names {mint:?}"
            )));
        }
        groups.push(FspGroup {
            service,
            mint,
            notes,
        });
    }
    let did_key = DidSecretKey::from_bytes(c.take(DID_KEY_BYTES)?)
        .map_err(|_| WalletError::Invalid("the DID key in it is not valid".into()))?;
    if !c.0.is_empty() {
        return Err(WalletError::Invalid(
            "the handoff has bytes after its end".into(),
        ));
    }
    Ok(FspPayload { groups, did_key })
}

// ---- what the wallet records -----------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffState {
    /// Exported; the sender's notes are held back in the record.
    Pending,
    /// The sender knows it was claimed and has dropped the notes.
    Done,
    /// The sender swapped the notes back at the mint (`handoff reclaim`) and
    /// has dropped the old ones. Final.
    Reclaimed,
}

/// A handoff this wallet made. While `Pending` it holds the notes, so that
/// `cancel_handoff` can put them back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutgoingHandoff {
    pub id: String,
    pub state: HandoffState,
    /// Which kind it is.
    pub kind: HandoffKind,
    /// PSP and FSP units in it.
    pub psp_units: u128,
    pub fsp_units: u128,
    /// How many notes it holds (kept after `Done`).
    pub note_count: usize,
    /// A DID key went with it (every FSP handoff).
    pub with_did_key: bool,
    /// The notes, until it is done.
    pub notes: Vec<StoredNote>,
    /// The PSP mint the notes are for: where `handoff check` and `handoff
    /// reclaim` ask. Empty for an FSP handoff.
    pub mint: String,
    /// The id of the stored swap back to this wallet, while a reclaim is out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclaim: Option<String>,
    /// How many of its notes the mint has said were spent without this wallet
    /// reclaiming them (and which are no longer in `notes`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub spent_elsewhere: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Where a PSP handoff stands, as the mint's record tells the sender.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The mint has seen none of the notes spent: they are still the sender's
    /// to reclaim.
    Pending,
    /// Every note is spent at the mint: the receiver swapped (or spent) them.
    /// Final; the sender keeps nothing.
    Received,
    /// Some notes were spent at the mint, and `left` are not. `spent` counts
    /// all that were. The rest can still be reclaimed (or the receiver may
    /// still swap them: the first to reach the mint wins).
    Partly { spent: usize, left: usize },
    /// Swapped back to the sender. Final.
    Reclaimed,
}

/// A handoff this wallet imported. Its note ids are the notes' source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncomingHandoff {
    pub id: String,
    /// Which kind it was.
    pub kind: HandoffKind,
    /// Who it came from, as the importer named them (may be empty).
    pub from: String,
    pub psp_units: u128,
    pub fsp_units: u128,
    /// The ids of the notes that were added, or swapped away at once.
    pub notes: Vec<String>,
    /// The notes were swapped at the mint for notes only this wallet knows
    /// (every PSP handoff).
    pub swapped: bool,
}

/// What an export made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffExport {
    pub id: String,
    pub kind: HandoffKind,
    /// The handoff string.
    pub text: String,
    pub notes: usize,
    pub psp_units: u128,
    pub fsp_units: u128,
    pub with_did_key: bool,
    /// Bytes before encoding, and characters in `text`.
    pub bytes: usize,
    pub chars: usize,
    /// [`PSP_WARNING`] or [`FSP_WARNING`].
    pub warning: &'static str,
}

/// What an import did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    pub id: String,
    pub kind: HandoffKind,
    pub psp_units: u128,
    pub fsp_units: u128,
    /// The ids of the notes in the payload.
    pub notes: Vec<String>,
    /// The DID secret key an FSP handoff carried. The wallet does not keep it:
    /// the app or the AIR login does. A PSP handoff never has one.
    pub did_key: Option<DidSecretKey>,
    /// Things the wallet could not check, or that differ from what it knew.
    pub warnings: Vec<String>,
    /// The PSP mint and the FSP services the notes are for, so a
    /// caller can read their keys.
    pub psp_mints: Vec<String>,
    pub fsp_mints: Vec<ServiceDid>,
    /// Stored PSP swaps to send (ids of pending rollovers). A PSP handoff has
    /// one; an FSP handoff never does.
    pub psp_swaps: Vec<String>,
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

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Psp => "PSP",
        Kind::Esp => "ESP",
        Kind::Fsp => "FSP",
    }
}

impl Wallet {
    /// Pick free PSP notes adding up to exactly `units`. Largest notes first.
    pub fn select_psp_handoff(&self, units: u128) -> Result<Vec<String>, WalletError> {
        let free = self
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Psp && n.reserved_by.is_none())
            .collect();
        take_exact(free, units).ok_or_else(|| {
            WalletError::NotEnough(format!(
                "no free PSP notes add up to exactly {units}; swap for smaller notes first"
            ))
        })
    }

    /// Pick free FSP notes adding up to exactly the units asked for each
    /// service. Largest notes first.
    pub fn select_fsp_handoff(
        &self,
        fsp: &[(ServiceDid, u128)],
    ) -> Result<Vec<String>, WalletError> {
        let mut ids = Vec::new();
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
            ids.extend(take_exact(free, *units).ok_or_else(|| {
                WalletError::NotEnough(format!(
                    "no free FSP notes for service {} add up to exactly {units}",
                    hex::encode(service.serialize())
                ))
            })?);
        }
        if ids.is_empty() {
            return Err(WalletError::Invalid(
                "an FSP handoff carries FSP: choose at least one service and an amount".into(),
            ));
        }
        Ok(ids)
    }

    /// The handoffs this wallet made, oldest first.
    pub fn handoffs_out(&self) -> &[OutgoingHandoff] {
        &self.data().handoffs_out
    }

    /// The handoffs this wallet imported, oldest first.
    pub fn handoffs_in(&self) -> &[IncomingHandoff] {
        &self.data().handoffs_in
    }

    /// PSP units received in a handoff that the mint has not swapped yet. They
    /// are in the balance (and in [`crate::store::Balance::psp`]) and can be
    /// spent; the swap is sent again on every connection to the mint, and
    /// spending a note first makes the swap skip it.
    pub fn unswapped_psp(&self) -> u128 {
        self.pending_rollovers()
            .iter()
            .filter(|p| p.kind == Kind::Psp && p.schedule.starts_with(SWAP_TAG))
            .flat_map(|p| p.outputs.iter())
            .map(|o| u128::from(o.amount))
            .sum()
    }

    /// The notes of `ids`, all free and all of `kind`.
    fn pick_notes(&self, ids: &[String], kind: Kind) -> Result<Vec<StoredNote>, WalletError> {
        if ids.is_empty() {
            return Err(WalletError::Invalid("the handoff holds nothing".into()));
        }
        let unique: BTreeSet<&String> = ids.iter().collect();
        if unique.len() != ids.len() {
            return Err(WalletError::Invalid(
                "a note is selected twice for the handoff".into(),
            ));
        }
        let mut picked = Vec::new();
        for id in ids {
            let n =
                self.notes().iter().find(|n| &n.id() == id).ok_or_else(|| {
                    WalletError::Unknown(format!("note {id} is not in this wallet"))
                })?;
            if n.reserved_by.is_some() {
                return Err(WalletError::Invalid(format!(
                    "note {id} is held back for a pending request"
                )));
            }
            if n.kind != kind {
                return Err(WalletError::Invalid(format!(
                    "note {id} is a {} note, and this handoff carries {} notes only",
                    kind_label(n.kind),
                    kind_label(kind)
                )));
            }
            picked.push(n.clone());
        }
        Ok(picked)
    }

    /// Make a PSP handoff of the notes `ids`, sealed to `recipient`'s DID public
    /// key, and take the notes out of this wallet in the same write. `psp` is the
    /// PSP's DID: the handoff names the mint by it in lowercase hex, as the
    /// wallet's records do. A PSP handoff has no way to carry a DID key or FSP
    /// and cannot be made without the recipient's key.
    pub fn export_psp_handoff(
        &mut self,
        ids: &[String],
        psp: ServiceDid,
        recipient: &DidPublicKey,
    ) -> Result<HandoffExport, WalletError> {
        let psp_mint = crate::fsp::record_of(psp);
        let picked = self.pick_notes(ids, Kind::Psp)?;
        let payload = PspPayload {
            mint: psp_mint.clone(),
            notes: picked
                .iter()
                .map(|n| self.payload_note(n, false))
                .collect::<Result<_, _>>()?,
        };
        let (text, id) = payload.seal(recipient)?;
        self.record_out(
            HandoffKind::Psp,
            id,
            text,
            picked,
            (payload.units(), 0),
            false,
            psp_mint,
        )
    }

    /// Make an FSP handoff of the notes `ids` and the DID secret key, and take
    /// the notes out of this wallet in the same write. It is not encrypted. An
    /// FSP handoff cannot be made without a DID key or without FSP, and has no
    /// way to carry PSP.
    pub fn export_fsp_handoff(
        &mut self,
        ids: &[String],
        did_key: &DidSecretKey,
    ) -> Result<HandoffExport, WalletError> {
        let picked = self.pick_notes(ids, Kind::Fsp)?;
        let mut by_service: BTreeMap<[u8; 33], Vec<&StoredNote>> = BTreeMap::new();
        for n in &picked {
            let service = n.fsp_service().ok_or_else(|| {
                WalletError::Invalid(format!(
                    "FSP note {} has no known service, so it cannot be handed off. Connect to its mint once (any `fsp` command) and try again",
                    n.id()
                ))
            })?;
            by_service.entry(service.serialize()).or_default().push(n);
        }
        let mut groups = Vec::new();
        for (service, notes) in &by_service {
            // The handoff names the mint by its service (the group's mint field is
            // part of the format and is never empty); it is not an address, and
            // the receiver reaches the mint through its own `air.fsp` entry.
            self.fsp_mints().get(&hex::encode(service)).ok_or_else(|| {
                WalletError::Invalid(format!(
                    "this wallet has not seen the FSP mint of service {}: connect to it once first",
                    hex::encode(service)
                ))
            })?;
            let mint = hex::encode(service);
            groups.push(FspGroup {
                service: ServiceDid::from_slice(service).expect("it came from a service ID"),
                mint,
                notes: notes
                    .iter()
                    .map(|n| self.payload_note(n, true))
                    .collect::<Result<_, _>>()?,
            });
        }
        let payload = FspPayload {
            groups,
            did_key: *did_key,
        };
        let (text, id) = payload.encode()?;
        self.record_out(
            HandoffKind::Fsp,
            id,
            text,
            picked,
            (0, payload.units()),
            true,
            String::new(),
        )
    }

    /// Record an export and take its notes out, in one write.
    fn record_out(
        &mut self,
        kind: HandoffKind,
        id: String,
        text: String,
        picked: Vec<StoredNote>,
        (psp_units, fsp_units): (u128, u128),
        with_did_key: bool,
        mint: String,
    ) -> Result<HandoffExport, WalletError> {
        let (prefix, warning) = match kind {
            HandoffKind::Psp => (PSP_PREFIX, PSP_WARNING),
            _ => (FSP_PREFIX, FSP_WARNING),
        };
        let record = OutgoingHandoff {
            id: id.clone(),
            state: HandoffState::Pending,
            kind,
            psp_units,
            fsp_units,
            note_count: picked.len(),
            with_did_key,
            notes: picked.clone(),
            mint,
            reclaim: None,
            spent_elsewhere: 0,
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
        let digits = text.len() - prefix.len();
        Ok(HandoffExport {
            id,
            kind,
            bytes: digits / 3 * 2 + usize::from(digits % 3 == 2),
            chars: text.len(),
            notes: picked.len(),
            psp_units,
            fsp_units,
            with_did_key,
            text,
            warning,
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
                "handoff {id} is {}: its notes are no longer kept",
                match h.state {
                    HandoffState::Reclaimed => "reclaimed",
                    _ => "done",
                }
            )));
        }
        if h.reclaim.is_some() {
            return Err(WalletError::Invalid(format!(
                "a reclaim of handoff {id} is stored and may already have reached the mint: run `handoff reclaim {id}` to finish it, not cancel"
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
        let h = self
            .data()
            .handoffs_out
            .iter()
            .find(|h| h.id == id && h.state == HandoffState::Pending)
            .ok_or_else(|| WalletError::Unknown(format!("no pending handoff {id}")))?;
        if h.reclaim.is_some() {
            return Err(WalletError::Invalid(format!(
                "a reclaim of handoff {id} is stored: run `handoff reclaim {id}` to finish it"
            )));
        }
        self.update(|d| {
            if let Some(h) = d.handoffs_out.iter_mut().find(|h| h.id == id) {
                h.state = HandoffState::Done;
                h.notes.clear();
            }
            Ok(())
        })
    }

    /// The PSP handoff `id` this wallet made, which can be asked about at the
    /// mint (an FSP handoff cannot).
    fn askable(&self, id: &str) -> Result<OutgoingHandoff, WalletError> {
        let h = self
            .data()
            .handoffs_out
            .iter()
            .find(|h| h.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no handoff {id}")))?;
        if h.kind == HandoffKind::Fsp {
            return Err(WalletError::Invalid(format!(
                "handoff {id} is an FSP handoff. The mint keeps no record of who holds an FSP note, so there is nothing to check or reclaim there: use `handoff cancel {id}` if it never arrived, `handoff done {id}` once it did"
            )));
        }
        Ok(h)
    }

    /// What the sender knows of handoff `id` without asking the mint.
    pub fn handoff_standing(&self, id: &str) -> Result<Standing, WalletError> {
        let h = self.askable(id)?;
        Ok(match h.state {
            HandoffState::Done => Standing::Received,
            HandoffState::Reclaimed => Standing::Reclaimed,
            HandoffState::Pending if h.spent_elsewhere > 0 => Standing::Partly {
                spent: h.spent_elsewhere,
                left: h.notes.len(),
            },
            HandoffState::Pending => Standing::Pending,
        })
    }

    /// The mint's answer for a pending PSP handoff's notes (`spent[i]` for
    /// `notes[i]`, from `POST /check-state`), recorded. **None** spent: nothing
    /// changes. **All** spent: the receiver has them, the handoff is done and
    /// the notes are dropped. **Some**: those are dropped and counted, the rest
    /// stay reclaimable.
    pub fn settle_handoff(&mut self, id: &str, spent: &[bool]) -> Result<Standing, WalletError> {
        let h = self.askable(id)?;
        if h.state != HandoffState::Pending {
            return self.handoff_standing(id);
        }
        if spent.len() != h.notes.len() {
            return Err(WalletError::Mint(
                "check-state does not fit the handoff".into(),
            ));
        }
        let n = spent.iter().filter(|s| **s).count();
        if n == 0 {
            return self.handoff_standing(id);
        }
        self.update(|d| {
            let h = d
                .handoffs_out
                .iter_mut()
                .find(|h| h.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no handoff {id}")))?;
            h.spent_elsewhere += n;
            if n == spent.len() {
                h.notes.clear();
                h.state = HandoffState::Done;
                h.reclaim = None;
            } else {
                let mut k = 0;
                h.notes.retain(|_| {
                    let keep = !spent[k];
                    k += 1;
                    keep
                });
            }
            Ok(())
        })?;
        self.handoff_standing(id)
    }

    /// Store a swap of what is left of PSP handoff `id` back to this wallet, for
    /// fresh notes only this wallet knows, before anything is sent. Returns the
    /// stored swap's id; calling it again returns the same one while it is out.
    /// The caller sends it ([`crate::mint_info::reclaim_handoff`]).
    pub fn begin_reclaim(&mut self, id: &str) -> Result<String, WalletError> {
        let h = self.askable(id)?;
        if h.state != HandoffState::Pending {
            return Err(WalletError::Invalid(format!(
                "handoff {id} is {}: nothing is left to reclaim",
                match h.state {
                    HandoffState::Reclaimed => "reclaimed",
                    _ => "done",
                }
            )));
        }
        if let Some(r) = &h.reclaim {
            return Ok(r.clone());
        }
        if h.notes.is_empty() {
            return Err(WalletError::Invalid("nothing is left to reclaim".into()));
        }
        let notes = h
            .notes
            .iter()
            .map(|n| self.payload_note(n, false))
            .collect::<Result<Vec<_>, _>>()?;
        let current = swap_keyset(self.data().live_keysets.get(&h.mint), &notes);
        let p = build_psp_swap(&h.mint, &notes, format!("{RECLAIM_TAG}{id}"), &current)?;
        let rollover = p.id.clone();
        self.update(|d| {
            d.pending_rollovers.push(p);
            if let Some(h) = d.handoffs_out.iter_mut().find(|h| h.id == id) {
                h.reclaim = Some(rollover.clone());
            }
            Ok(())
        })?;
        Ok(rollover)
    }

    /// Before a stored swap of received notes is sent: make sure it still fits
    /// the wallet. A note of it that is gone (spent here, handed on) or held by
    /// another request would make the mint refuse the whole swap, so the stored
    /// swap is replaced by one for the notes that are left. Returns the id to
    /// send, or `None` if no note of it is left (it is dropped).
    pub(crate) fn live_swap(&mut self, id: &str) -> Result<Option<String>, WalletError> {
        let p = self
            .pending_rollovers()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending rollover {id}")))?;
        let free: Vec<StoredNote> = p
            .inputs
            .iter()
            .filter_map(|nid| {
                self.notes()
                    .iter()
                    .find(|n| &n.id() == nid && n.reserved_by.is_none())
                    .cloned()
            })
            .collect();
        if free.len() == p.inputs.len() {
            return Ok(Some(id.to_string()));
        }
        self.replace_swap(&p, &free)
    }

    /// Replace the stored swap `old` by one for `keep` (none if `keep` is
    /// empty), in one write. Returns the new swap's id.
    fn replace_swap(
        &mut self,
        old: &PendingRollover,
        keep: &[StoredNote],
    ) -> Result<Option<String>, WalletError> {
        let new = if keep.is_empty() {
            None
        } else {
            let notes = keep
                .iter()
                .map(|n| self.payload_note(n, false))
                .collect::<Result<Vec<_>, _>>()?;
            let current = swap_keyset(self.data().live_keysets.get(&old.record), &notes);
            Some(build_psp_swap(
                &old.record,
                &notes,
                old.schedule.clone(),
                &current,
            )?)
        };
        let id = new.as_ref().map(|q| q.id.clone());
        let gone = old.id.clone();
        self.update(|d| {
            d.pending_rollovers.retain(|q| q.id != gone);
            d.pending_rollovers.extend(new);
            Ok(())
        })?;
        Ok(id)
    }

    /// The mint refused the stored swap `id` of received notes because the
    /// notes at `positions` of its request are spent. Those notes are not this
    /// wallet's: they leave the balance for the spent record. The swap is
    /// replaced by one for the rest. Returns how many notes were dropped and the
    /// new swap's id (none if nothing is left, or if the mint named no note this
    /// wallet holds, in which case the swap is only dropped).
    pub(crate) fn swap_found_spent(
        &mut self,
        id: &str,
        positions: &[usize],
    ) -> Result<(usize, Option<String>), WalletError> {
        let p = self
            .pending_rollovers()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending rollover {id}")))?;
        let spent_ids: BTreeSet<String> = positions
            .iter()
            .filter_map(|&i| p.inputs.get(i).cloned())
            .filter(|nid| self.notes().iter().any(|n| &n.id() == nid))
            .collect();
        if spent_ids.is_empty() {
            self.cancel_rollover(id)?;
            return Ok((0, None));
        }
        self.update(|d| {
            for n in std::mem::take(&mut d.notes) {
                if spent_ids.contains(&n.id()) {
                    d.spent.push(n);
                } else {
                    d.notes.push(n);
                }
            }
            Ok(())
        })?;
        let rest: Vec<StoredNote> = p
            .inputs
            .iter()
            .filter(|nid| !spent_ids.contains(*nid))
            .filter_map(|nid| {
                self.notes()
                    .iter()
                    .find(|n| &n.id() == nid && n.reserved_by.is_none())
                    .cloned()
            })
            .collect();
        let new = self.replace_swap(&p, &rest)?;
        Ok((spent_ids.len(), new))
    }

    /// Take in a handoff of either kind. A PSP handoff needs `recipient`, the
    /// DID secret key it was sealed to, and `psp`, this wallet's PSP (its DID),
    /// which the handoff must name; an FSP handoff ignores both. `from` names
    /// the sender for the record (may be empty). Use [`kind_of`] first to know
    /// which key a string needs.
    pub fn import_handoff(
        &mut self,
        text: &str,
        recipient: Option<&DidSecretKey>,
        psp: ServiceDid,
        from: &str,
    ) -> Result<Imported, WalletError> {
        match kind_of(text)? {
            HandoffKind::Psp => {
                let key = recipient.ok_or_else(|| {
                    WalletError::Invalid(
                        "this is a PSP handoff, sealed to a DID key: give the DID secret key it was made for".into(),
                    )
                })?;
                self.import_psp_handoff(text, key, psp, from)
            }
            _ => self.import_fsp_handoff(text, from),
        }
    }

    /// Take in a PSP handoff, opened with the recipient's DID secret key. The
    /// notes are not added: a swap at the PSP mint is stored in the same write
    /// as the import record, and the caller sends it
    /// ([`crate::mint_info::complete_import`]). There is no way to import one
    /// without the swap. The handoff must name this wallet's PSP, `psp`, by its
    /// DID in lowercase hex and by nothing else (not a URL, a name, another DID
    /// or capitals); otherwise it is refused and nothing is added.
    pub fn import_psp_handoff(
        &mut self,
        text: &str,
        key: &DidSecretKey,
        psp: ServiceDid,
        from: &str,
    ) -> Result<Imported, WalletError> {
        let (payload, id) = PspPayload::open(text, key)?;
        let named = crate::fsp::record_of(psp);
        if payload.mint != named {
            return Err(WalletError::Invalid(format!(
                "a PSP handoff names the PSP by its DID in lowercase hex ({named}), and this one names {:?}. Nothing was imported",
                payload.mint
            )));
        }
        let group = Group {
            kind: Kind::Psp,
            service: None,
            mint: payload.mint,
            notes: payload.notes,
        };
        self.import_groups(id, HandoffKind::Psp, vec![group], None, from)
    }

    /// Take in an FSP handoff. Its FSP notes are added as they are (never
    /// swapped), and the DID secret key is in [`Imported::did_key`] for the
    /// caller to keep: the wallet does not.
    pub fn import_fsp_handoff(&mut self, text: &str, from: &str) -> Result<Imported, WalletError> {
        let (payload, id) = FspPayload::decode(text)?;
        let groups = payload
            .groups
            .into_iter()
            .map(|g| Group {
                kind: Kind::Fsp,
                service: Some(g.service),
                mint: g.mint,
                notes: g.notes,
            })
            .collect();
        self.import_groups(id, HandoffKind::Fsp, groups, Some(payload.did_key), from)
    }

    fn import_groups(
        &mut self,
        id: String,
        kind: HandoffKind,
        groups: Vec<Group>,
        did_key: Option<DidSecretKey>,
        from: &str,
    ) -> Result<Imported, WalletError> {
        let swap = kind == HandoffKind::Psp;
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
        for g in &groups {
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
        for g in &groups {
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
                    fsp_mints.push(service);
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
                        }
                        None => warnings.push(format!(
                            "this wallet has not seen the FSP mint of service {hexed}: its notes are not checked until it does"
                        )),
                    }
                }
                Kind::Esp => unreachable!("a handoff never has an ESP group"),
            }
        }

        let note_ids: Vec<String> = groups
            .iter()
            .flat_map(|g| g.notes.iter())
            .map(|n| hex::encode(n.note.nonce.0.serialize()))
            .collect();
        let units = |k: Kind| -> u128 {
            groups
                .iter()
                .filter(|g| g.kind == k)
                .map(|g| units_of(&g.notes))
                .sum()
        };
        let (psp_units, fsp_units) = (units(Kind::Psp), units(Kind::Fsp));
        let record = IncomingHandoff {
            id: id.clone(),
            kind,
            from: from.trim().to_string(),
            psp_units,
            fsp_units,
            notes: note_ids.clone(),
            swapped: swap,
        };

        // A PSP handoff: build the swap first, so the write below is one step.
        let mut swaps = Vec::new();
        let mut psp_swaps = Vec::new();
        if swap {
            for (i, g) in groups.iter().filter(|g| g.kind == Kind::Psp).enumerate() {
                let current = swap_keyset(self.data().live_keysets.get(&g.mint), &g.notes);
                let p = build_psp_swap(&g.mint, &g.notes, format!("{SWAP_TAG}{id}|{i}"), &current)?;
                psp_swaps.push(p.id.clone());
                swaps.push(p);
            }
        }

        self.update(|d| {
            for g in &groups {
                for n in &g.notes {
                    let mut stored = StoredNote {
                        kind: g.kind,
                        amount: n.amount,
                        note: n.note,
                        spend_secret: n.spend_secret,
                        terms: None,
                        reserved_by: None,
                    };
                    match g.kind {
                        Kind::Fsp => {
                            stored.terms = Some(StoredTerms {
                                service: g.service.expect("an FSP group has a service"),
                                redeemable_after_day: 0,
                            });
                            d.fsp_keysets.insert(stored.id(), n.keyset.clone());
                        }
                        // PSP is in the balance at once, with its key set, and
                        // the stored swap below replaces it with fresh notes.
                        _ => {
                            d.keysets.insert(stored.id(), n.keyset.clone());
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
            kind,
            psp_units,
            fsp_units,
            notes: note_ids,
            did_key,
            warnings,
            psp_mints,
            fsp_mints,
            psp_swaps,
        })
    }
}

/// A reclaim swap ended (`ok`: the mint swapped it) or was dropped (the mint
/// refused it): update the handoff it belongs to, in the same write that
/// removed the stored swap. Called by `finish_rollover`, `cancel_rollover` and
/// `mark_spent_in_rollover`; anything that is not a reclaim swap is ignored.
pub(crate) fn settle_reclaim(d: &mut WalletData, schedule: &str, ok: bool) {
    let Some(id) = schedule.strip_prefix(RECLAIM_TAG) else {
        return;
    };
    if let Some(h) = d.handoffs_out.iter_mut().find(|h| h.id == id) {
        h.reclaim = None;
        if ok {
            h.notes.clear();
            h.state = HandoffState::Reclaimed;
        }
    }
}

/// Build (not send) a psp-mint swap of `notes` for fresh notes of the same
/// amounts, for the wallet that will hold the fresh notes. The inputs are
/// signed with the notes' own spend secrets; the new notes' secrets and
/// blinding factors are stored with the swap, so a crash after sending is
/// finished by sending the same request again (the mint answers a repeat by
/// request hash). No fee.
pub(crate) fn build_psp_swap(
    record: &str,
    notes: &[PayloadNote],
    tag: String,
    current: &str,
) -> Result<PendingRollover, WalletError> {
    let outputs: Vec<PendingOutput> = notes.iter().map(|n| PendingOutput::new(n.amount)).collect();
    let mint_outputs: Vec<_> = outputs.iter().map(|o| o.mint_output()).collect();
    let mut inputs: Vec<mint_types::MintInput> = notes
        .iter()
        .map(|n| mint_types::MintInput {
            amount: mint_types::Amount::from_units(n.amount),
            note: n.note,
            spend_signature: secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).expect("64"),
        })
        .collect();
    let h = mint_types::transaction_sighash(&inputs, &mint_outputs);
    for (i, n) in inputs.iter_mut().zip(notes) {
        i.spend_signature =
            SECP256K1.sign_schnorr(&h, &Keypair::from_secret_key(SECP256K1, &n.spend_secret));
    }
    let r = sp_wire::psp::RolloverRequest {
        input_keysets: notes
            .iter()
            .map(|n| {
                if n.keyset.is_empty() {
                    Err(WalletError::Invalid(
                        "a note in the handoff names no key set; it is refused".into(),
                    ))
                } else {
                    Ok(n.keyset.clone())
                }
            })
            .collect::<Result<_, _>>()?,
        inputs,
        keyset: current.to_string(),
        outputs: mint_outputs,
    };
    Ok(PendingRollover {
        id: r.hash(),
        kind: Kind::Psp,
        record: record.to_string(),
        body: serde_json::to_value(&r).map_err(|e| WalletError::Invalid(e.to_string()))?,
        inputs: notes
            .iter()
            .map(|n| hex::encode(n.note.nonce.0.serialize()))
            .collect(),
        outputs,
        terms: None,
        schedule: tag,
    })
}

/// The key set a swap at the mint `record` asks its outputs to be signed with:
/// the mint's current key set as last seen, or, if this wallet has not seen it yet, the
/// first note's (the mint signs with any live key set named, and refuses one
/// that is retired or unknown).
pub(crate) fn swap_keyset(
    live: Option<&(String, Option<String>)>,
    notes: &[PayloadNote],
) -> String {
    live.map(|(c, _)| c.clone())
        .or_else(|| {
            notes
                .iter()
                .map(|n| n.keyset.clone())
                .find(|k| !k.is_empty())
        })
        .unwrap_or_default()
}

/// Notes of one mint (and, for FSP, one service), as the import works on them.
struct Group {
    kind: Kind,
    service: Option<ServiceDid>,
    mint: String,
    notes: Vec<PayloadNote>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::expect;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Open a wallet file of the test network.
    fn open_wallet(path: &std::path::Path) -> Result<crate::Wallet, crate::WalletError> {
        crate::Wallet::open(path, "regtest")
    }

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
    /// The PSP of the wallets under test, and the name its records and a PSP
    /// handoff give it: its DID in lowercase hex.
    fn the_psp() -> ServiceDid {
        service(9)
    }

    fn psp_name() -> String {
        crate::fsp::record_of(the_psp())
    }
    /// What an FSP group's mint field holds in these tests: a name, never dialled
    /// (a handoff this wallet exports names the service's DID there).

    fn service(n: u8) -> ServiceDid {
        let sk = SecretKey::from_slice(&[n; 32]).unwrap();
        ServiceDid::from(sk.public_key(SECP256K1))
    }

    /// A note with a real key pair, so its secret matches its nonce.
    fn note(kind: Kind, amount: u64, service: Option<ServiceDid>) -> StoredNote {
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
    fn funded(dir: &Path, name: &str) -> Wallet {
        let mut w = open_wallet(&dir.join(name)).unwrap();
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
            for s in [service(1), service(2)].iter() {
                d.fsp_mints.insert(
                    hex::encode(s.serialize()),
                    crate::fsp::FspMint {
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

    fn other_did() -> DidSecretKey {
        DidSecretKey::from_array([9u8; 32]).unwrap()
    }

    /// A PSP handoff of `units` PSP from a funded wallet, sealed to `did()`.
    fn psp_out(a: &mut Wallet, units: u128) -> HandoffExport {
        let ids = a.select_psp_handoff(units).unwrap();
        a.export_psp_handoff(&ids, the_psp(), &did().public_key())
            .unwrap()
    }

    /// An FSP handoff of the given units per service, with `did()`.
    fn fsp_out(a: &mut Wallet, fsp: &[(ServiceDid, u128)]) -> HandoffExport {
        let ids = a.select_fsp_handoff(fsp).unwrap();
        a.export_fsp_handoff(&ids, &did()).unwrap()
    }

    fn payload_note(n: &StoredNote) -> PayloadNote {
        PayloadNote {
            amount: n.amount,
            keyset: KS_A.into(),
            note: n.note,
            spend_secret: n.spend_secret,
        }
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

    // ---- PSP handoff ---------------------------------------------------------

    #[test]
    fn a_psp_handoff_is_sealed_to_the_recipient_and_counts_in_the_balance_until_swapped() {
        let dir = scratch("psp-round");
        let mut a = funded(&dir, "a.json");
        let before = a.balance();
        let out = psp_out(&mut a, 5);
        assert!(out.text.starts_with(PSP_PREFIX));
        assert_eq!(out.kind, HandoffKind::Psp);
        assert_eq!(
            (out.notes, out.psp_units, out.fsp_units, out.with_did_key),
            (2, 5, 0, false)
        );
        assert_eq!(out.warning, PSP_WARNING);
        // taken out of the sender
        assert_eq!(a.balance().psp, before.psp - 5);
        assert_eq!(a.balance().fsp, before.fsp, "no FSP went with it");
        assert_eq!(a.handoffs_out()[0].kind, HandoffKind::Psp);
        assert!(!a.handoffs_out()[0].with_did_key);

        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let got = b
            .import_psp_handoff(&out.text, &did(), the_psp(), "dev")
            .unwrap();
        assert_eq!(got.id, out.id);
        assert_eq!(got.kind, HandoffKind::Psp);
        assert_eq!((got.psp_units, got.fsp_units), (5, 0));
        assert_eq!(got.did_key, None, "a PSP handoff never carries a DID key");
        assert_eq!(got.notes.len(), 2);
        // in the balance at once, with a stored swap to send; no lock on them
        assert_eq!(got.psp_swaps.len(), 1);
        assert_eq!(b.pending_rollovers().len(), 1);
        assert_eq!(b.pending_rollovers()[0].id, got.psp_swaps[0]);
        assert_eq!(b.pending_rollovers()[0].inputs.len(), 2);
        assert_eq!(b.notes().len(), 2);
        assert!(b.notes().iter().all(|n| n.reserved_by.is_none()));
        assert_eq!(b.balance().psp, 5);
        assert_eq!(b.unswapped_psp(), 5);
        assert_eq!(b.balance().unswapped_psp, 5);
        let sets: BTreeSet<&str> = b
            .notes()
            .iter()
            .map(|n| b.data().keysets[&n.id()].as_str())
            .collect();
        assert_eq!(
            sets,
            BTreeSet::from([KS_A, KS_B]),
            "each note keeps its key set"
        );
        assert_eq!(
            b.select_psp_handoff(1).unwrap().len(),
            1,
            "unswapped notes can be spent or handed on"
        );
        // the record
        assert_eq!(b.handoffs_in().len(), 1);
        let rec = &b.handoffs_in()[0];
        assert_eq!(
            (rec.kind, rec.swapped, rec.from.as_str()),
            (HandoffKind::Psp, true, "dev")
        );
        // and survives a reopen
        let again = open_wallet(b.path()).unwrap();
        assert_eq!(again.handoffs_in(), b.handoffs_in());
        assert_eq!(again.unswapped_psp(), 5);
        assert_eq!(again.balance().psp, 5);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_the_recipients_key_opens_a_psp_handoff() {
        let dir = scratch("psp-key");
        let mut a = funded(&dir, "a.json");
        let out = psp_out(&mut a, 7);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let file_before = fs::read(b.path()).ok();
        let e = b
            .import_psp_handoff(&out.text, &other_did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("cannot be opened with this DID key"), "{e}");
        // the dispatcher needs a key for a PSP handoff
        let e = b
            .import_handoff(&out.text, None, the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("give the DID secret key"), "{e}");
        let e = b
            .import_handoff(&out.text, Some(&other_did()), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("cannot be opened"), "{e}");
        assert!(b.pending_rollovers().is_empty());
        assert!(b.handoffs_in().is_empty());
        assert_eq!(fs::read(b.path()).ok(), file_before, "nothing was written");
        // the right key opens it, through the dispatcher too
        let got = b
            .import_handoff(&out.text, Some(&did()), the_psp(), "")
            .unwrap();
        assert_eq!(got.kind, HandoffKind::Psp);
        assert_eq!(got.psp_units, 7);
        // the handoff holds no plain secret: the note's spend secret is not in
        // the text anywhere a reader could find it
        let secret = a.handoffs_out()[0].notes[0].spend_secret.secret_bytes();
        let raw = base44_decode(&out.text[PSP_PREFIX.len()..]).unwrap();
        assert!(!raw.windows(32).any(|w| w == &secret[..]));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_psp_handoff_that_is_not_sealed_is_refused() {
        let dir = scratch("psp-plain");
        let a = funded(&dir, "a.json");
        let notes: Vec<PayloadNote> = a
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Psp)
            .map(payload_note)
            .collect();
        let payload = PspPayload {
            mint: psp_name(),
            notes,
        };
        let plain = payload.body().unwrap();
        // the body, framed under the PSP prefix with a good check, unencrypted
        let text = frame(PSP_PREFIX, &plain);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let e = b
            .import_psp_handoff(&text, &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("cannot be opened") || e.contains("cut short"),
            "{e}"
        );
        assert!(b.notes().is_empty() && b.pending_rollovers().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_psp_body_with_a_did_key_or_fsp_in_it_is_refused() {
        let dir = scratch("psp-mix");
        let a = funded(&dir, "a.json");
        let psp_notes: Vec<PayloadNote> = a
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Psp)
            .map(payload_note)
            .collect();
        let body = PspPayload {
            mint: psp_name(),
            notes: psp_notes,
        }
        .body()
        .unwrap();
        let seal = |bytes: &[u8]| {
            frame(
                PSP_PREFIX,
                &sp_wire::seal::encrypt(&did().public_key(), bytes).unwrap(),
            )
        };
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        // a DID key after the notes
        let mut with_key = body.clone();
        with_key.extend_from_slice(&did().to_array());
        let e = b
            .import_psp_handoff(&seal(&with_key), &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("PSP notes and nothing else"), "{e}");
        // an FSP body sealed under the PSP prefix
        let fsp_body = FspPayload {
            groups: vec![FspGroup {
                service: service(1),
                mint: hex::encode(service(1).serialize()),
                notes: a
                    .notes()
                    .iter()
                    .filter(|n| n.kind == Kind::Fsp)
                    .take(1)
                    .map(payload_note)
                    .collect(),
            }],
            did_key: did(),
        }
        .body()
        .unwrap();
        let e = b
            .import_psp_handoff(&seal(&fsp_body), &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a PSP handoff inside"), "{e}");
        // the right body, as a control
        b.import_psp_handoff(&seal(&body), &did(), the_psp(), "")
            .unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_psp_handoff_holds_only_psp_notes_and_is_refused_for_anything_else() {
        let dir = scratch("psp-refuse");
        let mut a = funded(&dir, "a.json");
        let to = did().public_key();
        let psp_ids = a.select_psp_handoff(1).unwrap();
        let fsp_ids = a.select_fsp_handoff(&[(service(2), 2)]).unwrap();
        // an FSP note in a PSP handoff, alone or mixed in
        let e = a
            .export_psp_handoff(&fsp_ids, the_psp(), &to)
            .unwrap_err()
            .to_string();
        assert!(e.contains("carries PSP notes only"), "{e}");
        let mixed = [psp_ids[0].clone(), fsp_ids[0].clone()];
        let e = a
            .export_psp_handoff(&mixed, the_psp(), &to)
            .unwrap_err()
            .to_string();
        assert!(e.contains("carries PSP notes only"), "{e}");
        // nothing, a note twice, a note that is not here
        let e = expect::invalid(a.export_psp_handoff(&[], the_psp(), &to));
        assert!(e.contains("the handoff holds nothing"), "{e}");
        let twice = [psp_ids[0].clone(), psp_ids[0].clone()];
        let e = expect::invalid(a.export_psp_handoff(&twice, the_psp(), &to));
        assert!(e.contains("selected twice"), "{e}");
        let gone = "00".repeat(33);
        let e = expect::unknown(a.export_psp_handoff(&[gone.clone()], the_psp(), &to));
        assert!(
            e.contains(&format!("note {gone} is not in this wallet")),
            "{e}"
        );
        // a held-back note
        let id = psp_ids[0].clone();
        a.update(|d| {
            for n in d.notes.iter_mut().filter(|n| n.id() == id) {
                n.reserved_by = Some("x".into());
            }
            Ok(())
        })
        .unwrap();
        let e = a
            .export_psp_handoff(&psp_ids, the_psp(), &to)
            .unwrap_err()
            .to_string();
        assert!(e.contains("held back"), "{e}");
        // a PSP note with no recorded key set
        let n = note(Kind::Psp, 8, None);
        let nid = n.id();
        a.update(|d| {
            d.notes.push(n);
            Ok(())
        })
        .unwrap();
        let e = a
            .export_psp_handoff(&[nid], the_psp(), &to)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no recorded key set"), "{e}");
        // not enough
        let e = expect::not_enough(a.select_psp_handoff(1000));
        assert!(e.contains("add up to exactly 1000"), "{e}");
        assert!(a.handoffs_out().is_empty(), "nothing was taken out");
        fs::remove_dir_all(&dir).unwrap();
    }

    // ---- FSP handoff ---------------------------------------------------------

    #[test]
    fn an_fsp_handoff_carries_the_did_key_and_is_never_swapped() {
        let dir = scratch("fsp-round");
        let mut a = funded(&dir, "a.json");
        let before = a.balance();
        let out = fsp_out(&mut a, &[(service(1), 16), (service(2), 2)]);
        assert!(out.text.starts_with(FSP_PREFIX));
        assert_eq!(out.kind, HandoffKind::Fsp);
        assert_eq!(
            (out.notes, out.psp_units, out.fsp_units, out.with_did_key),
            (3, 0, 18, true)
        );
        assert_eq!(out.warning, FSP_WARNING);
        assert!(FSP_WARNING.contains("DID secret key") && FSP_WARNING.contains("not encrypted"));
        assert_eq!(a.balance().fsp, before.fsp - 18);
        assert_eq!(a.balance().psp, before.psp, "no PSP went with it");
        assert!(a.handoffs_out()[0].with_did_key);

        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let got = b.import_fsp_handoff(&out.text, "old phone").unwrap();
        assert_eq!(got.id, out.id);
        assert_eq!(got.kind, HandoffKind::Fsp);
        assert_eq!((got.psp_units, got.fsp_units), (0, 18));
        assert_eq!(got.did_key, Some(did()));
        assert!(got.psp_swaps.is_empty(), "an FSP handoff is never swapped");
        assert!(b.pending_rollovers().is_empty());
        assert!(!b.handoffs_in()[0].swapped);
        assert_eq!(b.handoffs_in()[0].kind, HandoffKind::Fsp);
        // the very notes the sender held, each with its service and key set
        let bal = b.balance();
        assert_eq!((bal.psp, bal.fsp, bal.notes), (0, 18, 3));
        assert_eq!(bal.unswapped_psp, 0);
        assert_eq!(bal.fsp_by_service[&hex::encode(service(1).serialize())], 16);
        assert_eq!(bal.fsp_by_service[&hex::encode(service(2).serialize())], 2);
        let sent: BTreeSet<String> = a.handoffs_out()[0]
            .notes
            .iter()
            .map(StoredNote::id)
            .collect();
        let got_ids: BTreeSet<String> = b.notes().iter().map(StoredNote::id).collect();
        assert_eq!(sent, got_ids);
        for n in b.notes() {
            assert!(b.data().fsp_keysets.contains_key(&n.id()));
        }
        // the dispatcher takes it with no key given, and a second import is refused
        let e = b
            .import_handoff(&out.text, None, the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("imported already"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_fsp_handoff_cannot_be_made_without_fsp_or_with_psp() {
        let dir = scratch("fsp-refuse");
        let mut a = funded(&dir, "a.json");
        // nothing chosen
        let e = expect::invalid(a.select_fsp_handoff(&[]));
        assert!(e.contains("choose at least one service"), "{e}");
        let e = expect::invalid(a.select_fsp_handoff(&[(service(1), 0)]));
        assert!(e.contains("choose at least one service"), "{e}");
        let e = expect::invalid(a.export_fsp_handoff(&[], &did()));
        assert!(e.contains("the handoff holds nothing"), "{e}");
        // not exact, and a service the wallet has no FSP for
        let e = expect::not_enough(a.select_fsp_handoff(&[(service(1), 3)]));
        assert!(
            e.contains(&hex::encode(service(1).serialize())) && e.contains("exactly 3"),
            "{e}"
        );
        let e = expect::not_enough(a.select_fsp_handoff(&[(service(9), 2)]));
        assert!(
            e.contains(&hex::encode(service(9).serialize())) && e.contains("exactly 2"),
            "{e}"
        );
        // a PSP note in an FSP handoff
        let psp = a.select_psp_handoff(1).unwrap();
        let e = a.export_fsp_handoff(&psp, &did()).unwrap_err().to_string();
        assert!(e.contains("carries FSP notes only"), "{e}");
        let fsp = a.select_fsp_handoff(&[(service(2), 2)]).unwrap();
        let mixed = [fsp[0].clone(), psp[0].clone()];
        let e = expect::invalid(a.export_fsp_handoff(&mixed, &did()));
        assert!(e.contains("carries FSP notes only"), "{e}");
        // an FSP note of an unknown service, and one whose mint was never seen
        let n = note(Kind::Fsp, 4, None);
        let nid = n.id();
        a.update(|d| {
            d.fsp_keysets.insert(nid.clone(), KS_A.into());
            d.notes.push(n);
            Ok(())
        })
        .unwrap();
        let e = a
            .export_fsp_handoff(&[nid], &did())
            .unwrap_err()
            .to_string();
        assert!(e.contains("no known service"), "{e}");
        let n = note(Kind::Fsp, 4, Some(service(5)));
        let nid = n.id();
        a.update(|d| {
            d.fsp_keysets.insert(nid.clone(), KS_A.into());
            d.notes.push(n);
            Ok(())
        })
        .unwrap();
        let e = a
            .export_fsp_handoff(&[nid], &did())
            .unwrap_err()
            .to_string();
        assert!(e.contains("has not seen the FSP mint"), "{e}");
        assert!(a.handoffs_out().is_empty(), "nothing was taken out");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_fsp_handoff_names_its_mint_by_the_services_did_and_nothing_else() {
        let dir = scratch("fsp-mint-name");
        let a = funded(&dir, "a.json");
        let notes: Vec<PayloadNote> = a
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Fsp)
            .take(1)
            .map(payload_note)
            .collect();
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let named = hex::encode(service(1).serialize());
        // a URL (what a pre-release handoff carried), a name, another
        // service's DID and the DID in capitals are all refused
        for mint in [
            "http://fsp.example:3200".to_string(),
            "fsp-mint".to_string(),
            hex::encode(service(2).serialize()),
            named.to_uppercase(),
        ] {
            let (text, _) = FspPayload {
                groups: vec![FspGroup {
                    service: service(1),
                    mint: mint.clone(),
                    notes: notes.clone(),
                }],
                did_key: did(),
            }
            .encode()
            .unwrap();
            let e = b.import_fsp_handoff(&text, "").unwrap_err();
            assert!(matches!(e, WalletError::Invalid(_)), "{e:?}");
            let e = e.to_string();
            assert!(e.contains(&format!("({named})")), "{e}");
            assert!(e.contains(&format!("names {mint:?}")), "{e}");
        }
        assert!(b.notes().is_empty(), "nothing was added");
        assert!(b.handoffs_in().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_psp_handoff_names_the_psp_by_its_did_and_nothing_else() {
        let dir = scratch("psp-mint-name");
        let a = funded(&dir, "a.json");
        let notes: Vec<PayloadNote> = a
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Psp)
            .take(1)
            .map(payload_note)
            .collect();
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let named = hex::encode(the_psp().serialize());
        // a URL (what a pre-release handoff carried), a name, another DID and the
        // PSP's DID in capitals are all refused, and nothing is added
        for mint in [
            "http://127.0.0.1:3000".to_string(),
            "psp-mint".to_string(),
            hex::encode(service(2).serialize()),
            named.to_uppercase(),
        ] {
            let (text, _) = PspPayload {
                mint: mint.clone(),
                notes: notes.clone(),
            }
            .seal(&did().public_key())
            .unwrap();
            let e = b
                .import_psp_handoff(&text, &did(), the_psp(), "")
                .unwrap_err();
            assert!(matches!(e, WalletError::Invalid(_)), "{e:?}");
            let e = e.to_string();
            assert!(e.contains(&format!("({named})")), "{e}");
            assert!(e.contains(&format!("names {mint:?}")), "{e}");
        }
        assert!(b.notes().is_empty(), "nothing was added");
        assert!(b.handoffs_in().is_empty());
        assert!(b.pending_rollovers().is_empty());
        // the PSP's DID in lowercase hex, as a control
        let (text, _) = PspPayload { mint: named, notes }
            .seal(&did().public_key())
            .unwrap();
        b.import_psp_handoff(&text, &did(), the_psp(), "").unwrap();
        assert_eq!(b.handoffs_in().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_fsp_body_without_a_did_key_or_notes_is_refused() {
        let dir = scratch("fsp-body");
        let a = funded(&dir, "a.json");
        let payload = FspPayload {
            groups: vec![FspGroup {
                service: service(1),
                mint: hex::encode(service(1).serialize()),
                notes: a
                    .notes()
                    .iter()
                    .filter(|n| n.kind == Kind::Fsp)
                    .take(1)
                    .map(payload_note)
                    .collect(),
            }],
            did_key: did(),
        };
        let body = payload.body().unwrap();
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        // the body less its DID key, with a good check: cut short
        let no_key = frame(FSP_PREFIX, &body[..body.len() - DID_KEY_BYTES]);
        let e = b.import_fsp_handoff(&no_key, "").unwrap_err().to_string();
        assert!(e.contains("cut short"), "{e}");
        // bytes after the key
        let mut more = body.clone();
        more.push(0);
        let e = b
            .import_fsp_handoff(&frame(FSP_PREFIX, &more), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("after its end"), "{e}");
        // no groups at all, in the API and in a hand-made body
        let empty = FspPayload {
            groups: vec![],
            did_key: did(),
        };
        assert!(empty.encode().is_err());
        let mut hand = vec![FORMAT_VERSION, KIND_FSP, 0];
        hand.extend_from_slice(&did().to_array());
        let e = b
            .import_fsp_handoff(&frame(FSP_PREFIX, &hand), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("holds nothing"), "{e}");
        // a PSP body under the FSP prefix
        let psp_body = PspPayload {
            mint: psp_name(),
            notes: a
                .notes()
                .iter()
                .filter(|n| n.kind == Kind::Psp)
                .take(1)
                .map(payload_note)
                .collect(),
        }
        .body()
        .unwrap();
        let e = b
            .import_fsp_handoff(&frame(FSP_PREFIX, &psp_body), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a FSP handoff inside"), "{e}");
        assert!(b.notes().is_empty() && b.handoffs_in().is_empty());
        // the right one, as a control
        assert!(b.import_fsp_handoff(&frame(FSP_PREFIX, &body), "").is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    // ---- both kinds ------------------------------------------------------------

    #[test]
    fn a_string_under_the_other_kinds_prefix_is_refused() {
        let dir = scratch("swap-prefix");
        let mut a = funded(&dir, "a.json");
        let psp = psp_out(&mut a, 3);
        let fsp = fsp_out(&mut a, &[(service(2), 2)]);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        // the PSP body under the FSP prefix, and the FSP body under the PSP
        // prefix, each with a good check
        let (psp_payload, _) = PspPayload::open(&psp.text, &did()).unwrap();
        let (fsp_payload, _) = FspPayload::decode(&fsp.text).unwrap();
        let as_fsp = frame(FSP_PREFIX, &psp_payload.body().unwrap());
        let as_psp = frame(PSP_PREFIX, &fsp_payload.body().unwrap());
        for e in [
            expect::invalid(b.import_fsp_handoff(&as_fsp, "")),
            expect::invalid(b.import_handoff(&as_fsp, None, the_psp(), "")),
        ] {
            assert!(e.contains("this is not a FSP handoff inside"), "{e}");
        }
        // the FSP body is not sealed, so no DID key opens it
        for e in [
            expect::invalid(b.import_psp_handoff(&as_psp, &did(), the_psp(), "")),
            expect::invalid(b.import_handoff(&as_psp, Some(&did()), the_psp(), "")),
        ] {
            assert!(e.contains("cannot be opened with this DID key"), "{e}");
        }
        // each kind's import refuses the other kind's string, by name
        let e = expect::invalid(b.import_fsp_handoff(&psp.text, ""));
        assert!(e.contains("PSP handoff, not an FSP"), "{e}");
        let e = expect::invalid(b.import_psp_handoff(&fsp.text, &did(), the_psp(), ""));
        assert!(e.contains("FSP handoff, not a PSP"), "{e}");
        assert!(b.notes().is_empty() && b.handoffs_in().is_empty());
        assert!(b.pending_rollovers().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_prefixes_are_distinct_and_the_kind_comes_from_the_prefix_and_the_old_prefix_is_refused()
    {
        let dir = scratch("kind");
        let mut a = funded(&dir, "a.json");
        // the prefixes are distinct, versioned and in the QR alphabet
        assert_ne!(PSP_PREFIX, FSP_PREFIX);
        assert_ne!(PSP_PREFIX, OLD_PREFIX);
        assert_ne!(FSP_PREFIX, OLD_PREFIX);
        for p in [PSP_PREFIX, FSP_PREFIX] {
            assert!(
                p.starts_with("SPH") && p.ends_with(&format!("{FORMAT_VERSION}:")),
                "{p}"
            );
            assert!(p.bytes().all(|c| ALPHABET.contains(&c)));
        }
        let psp = psp_out(&mut a, 1);
        let fsp = fsp_out(&mut a, &[(service(2), 2)]);
        assert_eq!(kind_of(&psp.text).unwrap(), HandoffKind::Psp);
        assert_eq!(kind_of(&fsp.text).unwrap(), HandoffKind::Fsp);
        assert_eq!(
            kind_of(&format!(" {}\n", psp.text.to_lowercase())).unwrap(),
            HandoffKind::Psp
        );
        // the old combined handoff
        let e = kind_of("SPH1:ABCDEF").unwrap_err().to_string();
        assert!(
            e.contains("old combined handoff") && e.contains("SPHP2:") && e.contains("SPHF2:"),
            "{e}"
        );
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let e = expect::invalid(b.import_handoff("sph1:abcdef", None, the_psp(), ""));
        assert!(e.contains("old combined handoff"), "{e}");
        // another version of either kind (1 is the one before service IDs were
        // DIDs), and a digit this wallet does not know
        for (t, n) in [
            ("SPHP1:AB", 1),
            ("SPHF1:AB", 1),
            ("SPHP3:AB", 3),
            ("SPHF3:AB", 3),
        ] {
            let e = kind_of(t).unwrap_err().to_string();
            assert!(
                e.contains(&format!("version {n}")) && e.contains("version 2 only"),
                "{e}"
            );
        }
        let e = kind_of("SPH2:AB").unwrap_err().to_string();
        assert!(e.contains("does not know"), "{e}");
        // not a handoff
        for junk in [
            "", "hello", "SPH", "SPHP", "SPHP2", "SPHX1:AB", "SPHPA:AB", "psp1abcd", "SPHÉ1:A",
        ] {
            assert!(kind_of(junk).is_err(), "{junk}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_size_is_as_documented() {
        let dir = scratch("size");
        let mut a = funded(&dir, "a.json");
        // PSP: version, kind, the mint, two key sets (A and B), the count, three
        // notes, then the seal's 80 bytes and the 4-byte check
        let out = psp_out(&mut a, 7);
        assert_eq!(out.notes, 3);
        let plain = 2 + (2 + 66) + (1 + 8 * 2) + 2 + 3 * NOTE_BYTES;
        let raw = plain + sp_wire::seal::OVERHEAD + CHECK_BYTES;
        assert_eq!(
            base44_decode(&out.text[PSP_PREFIX.len()..]).unwrap().len(),
            raw
        );
        assert_eq!(out.chars, PSP_PREFIX.len() + raw / 2 * 3 + (raw % 2) * 2);
        assert_eq!(out.bytes, raw);
        // FSP: version, kind, the group count, one group (service, mint, one key
        // set, the count, two notes), the DID key, the check
        let fsp = fsp_out(&mut a, &[(service(1), 16)]);
        // The mint field names the service: its DID in hex.
        let name = hex::encode(service(1).serialize());
        let raw =
            3 + (33 + 2 + name.len() + 1 + 8 + 2 + 2 * NOTE_BYTES) + DID_KEY_BYTES + CHECK_BYTES;
        assert_eq!(
            base44_decode(&fsp.text[FSP_PREFIX.len()..]).unwrap().len(),
            raw
        );
        assert_eq!(fsp.bytes, raw);
        // both fit a QR code of alphanumeric characters
        assert!(out.chars < 3391 && fsp.chars < 3391);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn whitespace_and_lower_case_are_forgiven_but_not_a_changed_character() {
        let dir = scratch("clean");
        let mut a = funded(&dir, "a.json");
        let psp = psp_out(&mut a, 1);
        let fsp = fsp_out(&mut a, &[(service(2), 2)]);
        let wrap = |t: &str| -> String {
            let wrapped: String = t
                .as_bytes()
                .chunks(40)
                .map(|c| format!("{}\n", String::from_utf8_lossy(c)))
                .collect();
            format!("  {}  ", wrapped.to_lowercase())
        };
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        b.import_psp_handoff(&wrap(&psp.text), &did(), the_psp(), "")
            .unwrap();
        b.import_fsp_handoff(&wrap(&fsp.text), "").unwrap();
        // a changed character is not forgiven, whatever the case and spacing
        let mut c = open_wallet(&dir.join("c.json")).unwrap();
        let e = expect::invalid(c.import_psp_handoff(
            &wrap(&damaged(&psp.text, PSP_PREFIX.len() + 50)),
            &did(),
            the_psp(),
            "",
        ));
        assert!(e.contains("damaged"), "{e}");
        let e = expect::invalid(
            c.import_fsp_handoff(&wrap(&damaged(&fsp.text, FSP_PREFIX.len() + 50)), ""),
        );
        assert!(e.contains("damaged"), "{e}");
        assert!(c.notes().is_empty() && c.handoffs_in().is_empty());
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
        let psp = psp_out(&mut a, 7);
        let fsp = fsp_out(&mut a, &[(service(1), 16)]);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let file_before = fs::read(b.path()).ok();
        let bad = |e: String, at: usize| {
            assert!(e.contains("damaged"), "{at}: {e}");
        };
        for (text, prefix) in [(&psp.text, PSP_PREFIX), (&fsp.text, FSP_PREFIX)] {
            // one changed character anywhere after the prefix
            for at in [
                prefix.len(),
                prefix.len() + 50,
                text.len() / 2,
                text.len() - 1,
            ] {
                let t = damaged(text, at);
                let e = if prefix == PSP_PREFIX {
                    b.import_psp_handoff(&t, &did(), the_psp(), "")
                } else {
                    b.import_fsp_handoff(&t, "")
                }
                .unwrap_err()
                .to_string();
                bad(e, at);
            }
            // cut short, and extra characters
            let cut = &text[..text.len() - 7];
            let e = if prefix == PSP_PREFIX {
                b.import_psp_handoff(cut, &did(), the_psp(), "")
            } else {
                b.import_fsp_handoff(cut, "")
            }
            .unwrap_err()
            .to_string();
            bad(e, 0);
            let extra = format!("{text}AB");
            let e = expect::invalid(if prefix == PSP_PREFIX {
                b.import_psp_handoff(&extra, &did(), the_psp(), "")
            } else {
                b.import_fsp_handoff(&extra, "")
            });
            bad(e, 0);
        }
        // not a handoff at all, or of another version: refused at the prefix, by
        // the import and by `kind_of` alike
        for (junk, says) in [
            ("", "this is not a handoff"),
            ("hello", "this is not a handoff"),
            ("SPH", "this is not a handoff"),
            ("SPHP2", "this is not a handoff"),
            ("SPHP3:", "this handoff is version 3"),
            ("SPHF3:", "this handoff is version 3"),
            ("psp1abcd", "this is not a handoff"),
        ] {
            let e = expect::invalid(b.import_handoff(junk, Some(&did()), the_psp(), ""));
            assert!(e.contains(says), "{junk}: {e}");
            let e = expect::invalid(kind_of(junk));
            assert!(e.contains(says), "{junk}: {e}");
        }
        // the current prefixes (version 2) are recognised, so `kind_of` accepts
        // them; what follows is then refused: nothing after the prefix is cut
        // short, and `!` is not a character of the handoff alphabet
        for (junk, kind, says) in [
            ("SPHP2:", HandoffKind::Psp, "cut short or damaged"),
            ("SPHF2:", HandoffKind::Fsp, "cut short or damaged"),
            (
                "SPHP2:!!!",
                HandoffKind::Psp,
                "character that does not belong in one: `!`",
            ),
            (
                "SPHF2:!!!",
                HandoffKind::Fsp,
                "character that does not belong in one: `!`",
            ),
        ] {
            assert_eq!(kind_of(junk).unwrap(), kind, "{junk}");
            let e = expect::invalid(b.import_handoff(junk, Some(&did()), the_psp(), ""));
            assert!(e.contains(says), "{junk}: {e}");
        }
        assert!(b.notes().is_empty());
        assert!(b.handoffs_in().is_empty() && b.pending_rollovers().is_empty());
        assert_eq!(
            fs::read(b.path()).ok(),
            file_before,
            "the file is untouched"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_payload_of_another_version_inside_is_refused_and_says_so() {
        let dir = scratch("version");
        let a = funded(&dir, "a.json");
        let fsp_notes: Vec<PayloadNote> = a
            .notes()
            .iter()
            .filter(|n| n.kind == Kind::Fsp)
            .take(1)
            .map(payload_note)
            .collect();
        let payload = FspPayload {
            groups: vec![FspGroup {
                service: service(1),
                mint: hex::encode(service(1).serialize()),
                notes: fsp_notes,
            }],
            did_key: did(),
        };
        let mut body = payload.body().unwrap();
        body[0] = FORMAT_VERSION + 1;
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let e = b
            .import_fsp_handoff(&frame(FSP_PREFIX, &body), "")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(&format!("version {}", FORMAT_VERSION + 1)),
            "{e}"
        );
        // the same inside a sealed PSP handoff
        let mut body = PspPayload {
            mint: psp_name(),
            notes: a
                .notes()
                .iter()
                .filter(|n| n.kind == Kind::Psp)
                .take(1)
                .map(payload_note)
                .collect(),
        }
        .body()
        .unwrap();
        body[0] = FORMAT_VERSION + 1;
        let sealed = sp_wire::seal::encrypt(&did().public_key(), &body).unwrap();
        let e = b
            .import_psp_handoff(&frame(PSP_PREFIX, &sealed), &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(&format!("version {}", FORMAT_VERSION + 1)),
            "{e}"
        );
        assert!(b.notes().is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_note_whose_secret_is_not_its_nonces_is_refused() {
        let dir = scratch("forged");
        let a = funded(&dir, "a.json");
        let mut forged = a
            .notes()
            .iter()
            .find(|n| n.kind == Kind::Psp)
            .map(payload_note)
            .unwrap();
        forged.spend_secret = SecretKey::new(&mut rand::rngs::OsRng);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let (text, _) = PspPayload {
            mint: psp_name(),
            notes: vec![forged.clone()],
        }
        .seal(&did().public_key())
        .unwrap();
        let e = b
            .import_psp_handoff(&text, &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("not the one for its nonce"), "{e}");
        let (text, _) = FspPayload {
            groups: vec![FspGroup {
                service: service(1),
                mint: hex::encode(service(1).serialize()),
                notes: vec![forged],
            }],
            did_key: did(),
        }
        .encode()
        .unwrap();
        let e = b.import_fsp_handoff(&text, "").unwrap_err().to_string();
        assert!(e.contains("not the one for its nonce"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_double_import_is_refused_for_both_kinds() {
        let dir = scratch("double");
        let mut a = funded(&dir, "a.json");
        let psp = psp_out(&mut a, 7);
        let fsp = fsp_out(&mut a, &[(service(1), 8)]);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        b.import_psp_handoff(&psp.text, &did(), the_psp(), "")
            .unwrap();
        b.import_fsp_handoff(&fsp.text, "").unwrap();
        let held = b.balance();
        let e = b
            .import_psp_handoff(&psp.text, &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("imported already"), "{e}");
        let e = b.import_fsp_handoff(&fsp.text, "").unwrap_err().to_string();
        assert!(e.contains("imported already"), "{e}");
        assert_eq!(b.balance(), held, "nothing was added the second time");
        assert_eq!(b.pending_rollovers().len(), 1);
        // still refused after the FSP notes have been spent: the record stays
        let ids: Vec<String> = b.notes().iter().map(StoredNote::id).collect();
        b.update(|d| {
            d.notes.retain(|n| !ids.contains(&n.id()));
            Ok(())
        })
        .unwrap();
        assert!(b.import_fsp_handoff(&fsp.text, "").is_err());
        // another wallet that already holds one of the notes refuses too
        let mut c = open_wallet(&dir.join("c.json")).unwrap();
        let first = a
            .handoffs_out()
            .iter()
            .find(|h| h.id == fsp.id)
            .unwrap()
            .notes[0]
            .clone();
        c.update(|d| {
            d.notes.push(first);
            Ok(())
        })
        .unwrap();
        let e = c.import_fsp_handoff(&fsp.text, "").unwrap_err().to_string();
        assert!(e.contains("already in this wallet"), "{e}");
        assert_eq!(c.notes().len(), 1);
        // the sender cannot import its own handoff
        let e = a.import_fsp_handoff(&fsp.text, "").unwrap_err().to_string();
        assert!(e.contains("made this handoff"), "{e}");
        let e = a
            .import_psp_handoff(&psp.text, &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("made this handoff"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_note_on_a_retired_key_set_is_refused_when_the_mint_is_known() {
        let dir = scratch("retired");
        let mut a = funded(&dir, "a.json");
        let psp = psp_out(&mut a, 7);
        let fsp = fsp_out(&mut a, &[(service(1), 16)]);

        // FSP: the receiver knows service 1's mint, whose live sets are not A or B
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        b.update(|d| {
            d.fsp_mints.insert(
                hex::encode(service(1).serialize()),
                crate::fsp::FspMint {
                    current: "1111111111111111".into(),
                    previous: None,
                    next_rotation: None,
                },
            );
            Ok(())
        })
        .unwrap();
        let e = b.import_fsp_handoff(&fsp.text, "").unwrap_err().to_string();
        assert!(
            e.contains("expired") && e.contains("1111111111111111"),
            "{e}"
        );
        assert!(b.notes().is_empty());

        // PSP: the receiver knows the PSP mint's live sets
        let mut c = open_wallet(&dir.join("c.json")).unwrap();
        c.update(|d| {
            d.live_keysets.insert(
                psp_name(),
                ("2222222222222222".into(), Some("3333333333333333".into())),
            );
            Ok(())
        })
        .unwrap();
        let e = c
            .import_psp_handoff(&psp.text, &did(), the_psp(), "")
            .unwrap_err()
            .to_string();
        assert!(e.contains("expired"), "{e}");
        assert!(c.pending_rollovers().is_empty());

        // with the right sets known it is accepted
        let mut d = open_wallet(&dir.join("d.json")).unwrap();
        d.update(|w| {
            w.live_keysets
                .insert(psp_name(), (KS_A.into(), Some(KS_B.into())));
            w.fsp_mints.insert(
                hex::encode(service(1).serialize()),
                crate::fsp::FspMint {
                    current: KS_A.into(),
                    previous: Some(KS_B.into()),
                    next_rotation: None,
                },
            );
            Ok(())
        })
        .unwrap();
        d.import_psp_handoff(&psp.text, &did(), the_psp(), "")
            .unwrap();
        let got = d.import_fsp_handoff(&fsp.text, "").unwrap();
        assert_eq!(got.fsp_mints, vec![service(1)]);
        assert!(got.warnings.is_empty(), "{:?}", got.warnings);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_unknown_mint_is_a_warning_not_a_refusal() {
        let dir = scratch("unknown");
        let mut a = funded(&dir, "a.json");
        let psp = psp_out(&mut a, 1);
        let fsp = fsp_out(&mut a, &[(service(2), 2)]);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let got = b
            .import_psp_handoff(&psp.text, &did(), the_psp(), "")
            .unwrap();
        assert_eq!(got.warnings.len(), 1, "{:?}", got.warnings);
        assert_eq!(got.psp_mints, vec![psp_name()]);
        assert!(got.fsp_mints.is_empty());
        let got = b.import_fsp_handoff(&fsp.text, "").unwrap();
        assert_eq!(got.warnings.len(), 1, "{:?}", got.warnings);
        assert_eq!(got.fsp_mints.len(), 1);
        assert!(got.psp_mints.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cancelling_puts_the_notes_back_and_a_done_handoff_cannot_be_cancelled() {
        let dir = scratch("cancel");
        let mut a = funded(&dir, "a.json");
        let before = a.balance();
        let ids_before: BTreeSet<String> = a.notes().iter().map(StoredNote::id).collect();
        let out = fsp_out(&mut a, &[(service(1), 16)]);
        assert_ne!(a.balance().notes, before.notes);
        assert_eq!(a.handoffs_out().len(), 1);
        assert_eq!(a.handoffs_out()[0].state, HandoffState::Pending);
        // the notes cannot be spent or handed off twice while it is out
        assert!(a.select_fsp_handoff(&[(service(1), 16)]).is_err());
        assert_eq!(a.cancel_handoff(&out.id).unwrap(), 2);
        assert_eq!(a.balance(), before);
        let ids_after: BTreeSet<String> = a.notes().iter().map(StoredNote::id).collect();
        assert_eq!(ids_after, ids_before);
        assert!(a.handoffs_out().is_empty());
        // the ledgers say the notes came back
        for id in &ids_before {
            assert!(!has_departed(a.data(), id));
        }
        assert!(a.cancel_handoff(&out.id).is_err(), "cancelled once");

        // a PSP handoff that is done keeps no notes and cannot be cancelled
        let out = psp_out(&mut a, 1);
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
    fn a_note_that_is_not_a_power_of_two_is_not_encoded() {
        let n = note(Kind::Psp, 3, None);
        let notes = vec![PayloadNote {
            amount: 3,
            keyset: KS_A.into(),
            note: n.note,
            spend_secret: n.spend_secret,
        }];
        let psp = PspPayload {
            mint: psp_name(),
            notes: notes.clone(),
        };
        assert!(psp.seal(&did().public_key()).is_err());
        let fsp = FspPayload {
            groups: vec![FspGroup {
                service: service(1),
                mint: hex::encode(service(1).serialize()),
                notes,
            }],
            did_key: did(),
        };
        assert!(fsp.encode().is_err());
    }

    // ---- reclaim -------------------------------------------------------------

    /// A PSP handoff of 5 PSP made by a funded wallet, recorded for a mint.
    fn pending_psp(a: &mut Wallet) -> HandoffExport {
        psp_out(a, 5)
    }

    #[test]
    fn the_record_keeps_the_mint_and_check_state_answers_settle_it() {
        let dir = scratch("settle");
        let mut a = funded(&dir, "a.json");
        let out = pending_psp(&mut a);
        let h = a.handoffs_out()[0].clone();
        assert_eq!(
            (h.mint.as_str(), h.reclaim.clone(), h.spent_elsewhere),
            (psp_name().as_str(), None, 0)
        );
        assert_eq!(a.handoff_standing(&out.id).unwrap(), Standing::Pending);
        // none spent: nothing changes
        let version = a.version();
        assert_eq!(
            a.settle_handoff(&out.id, &[false, false]).unwrap(),
            Standing::Pending
        );
        assert_eq!(a.version(), version, "nothing was written");
        // a wrong number of answers is refused
        assert!(a.settle_handoff(&out.id, &[true]).is_err());
        // one spent: it is dropped, the other stays reclaimable
        let first = a.handoffs_out()[0].notes[0].id();
        let st = a.settle_handoff(&out.id, &[true, false]).unwrap();
        assert_eq!(st, Standing::Partly { spent: 1, left: 1 });
        let h = &a.handoffs_out()[0];
        assert_eq!(
            (h.state, h.notes.len(), h.spent_elsewhere),
            (HandoffState::Pending, 1, 1)
        );
        assert_ne!(h.notes[0].id(), first);
        // the rest spent too: received, nothing is kept
        let st = a.settle_handoff(&out.id, &[true]).unwrap();
        assert_eq!(st, Standing::Received);
        let h = &a.handoffs_out()[0];
        assert_eq!(
            (h.state, h.notes.len(), h.spent_elsewhere),
            (HandoffState::Done, 0, 2)
        );
        // it survives a reopen, and a done handoff cannot be reclaimed
        let mut again = open_wallet(a.path()).unwrap();
        assert_eq!(again.handoff_standing(&out.id).unwrap(), Standing::Received);
        assert!(again.begin_reclaim(&out.id).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stored_reclaim_is_one_swap_and_its_outcome_is_recorded_in_the_same_write() {
        let dir = scratch("reclaim");
        let mut a = funded(&dir, "a.json");
        let out = pending_psp(&mut a);
        let id = a.begin_reclaim(&out.id).unwrap();
        assert_eq!(a.begin_reclaim(&out.id).unwrap(), id, "one stored swap");
        let p = a.pending_rollovers()[0].clone();
        assert_eq!(
            (p.id.as_str(), p.schedule.as_str()),
            (id.as_str(), format!("reclaim|{}", out.id).as_str())
        );
        assert_eq!(p.inputs.len(), 2);
        assert_eq!(a.handoffs_out()[0].reclaim.as_deref(), Some(id.as_str()));
        // a stored reclaim cannot be cancelled or finished from under it
        assert!(a.cancel_handoff(&out.id).is_err());
        assert!(a.finish_handoff(&out.id).is_err());
        // the mint refused it (the receiver was first): back to pending, in one write
        a.cancel_rollover(&id).unwrap();
        assert!(a.pending_rollovers().is_empty());
        assert_eq!(a.handoffs_out()[0].state, HandoffState::Pending);
        assert_eq!(a.handoffs_out()[0].reclaim, None);
        assert_eq!(
            a.handoffs_out()[0].notes.len(),
            2,
            "the notes are still kept"
        );
        // and again, this time the mint swapped it: reclaimed, notes dropped
        let id = a.begin_reclaim(&out.id).unwrap();
        let p = a.pending_rollovers()[0].clone();
        let sigs: Vec<PublicKey> = p
            .outputs
            .iter()
            .map(|o| {
                bdhke::sign_message(
                    &SecretKey::from_slice(&[5u8; 32]).unwrap(),
                    &o.blind_nonce.0,
                )
            })
            .collect();
        let key = SecretKey::from_slice(&[5u8; 32])
            .unwrap()
            .public_key(SECP256K1);
        a.finish_rollover(&id, 1, KS_A, &sigs, &vec![key; sigs.len()])
            .unwrap();
        let h = &a.handoffs_out()[0];
        assert_eq!(
            (h.state, h.reclaim.clone(), h.notes.len()),
            (HandoffState::Reclaimed, None, 0)
        );
        assert_eq!(a.handoff_standing(&out.id).unwrap(), Standing::Reclaimed);
        assert_eq!(
            a.balance().psp,
            7,
            "the swapped-back notes are in the balance"
        );
        assert!(a.begin_reclaim(&out.id).is_err());
        assert!(a.cancel_handoff(&out.id).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_fsp_handoff_cannot_be_asked_about_the_mint() {
        let dir = scratch("noreclaim");
        let mut a = funded(&dir, "a.json");
        let fsp = fsp_out(&mut a, &[(service(1), 8)]);
        let e = expect::invalid(a.begin_reclaim(&fsp.id));
        assert!(
            e.contains(&format!("handoff {} is an FSP handoff", fsp.id)),
            "{e}"
        );
        let e = expect::invalid(a.handoff_standing(&fsp.id));
        assert!(e.contains("is an FSP handoff"), "{e}");
        let e = expect::unknown(a.begin_reclaim("nope"));
        assert!(e.contains("no handoff nope"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stored_swap_follows_what_the_wallet_still_holds() {
        let dir = scratch("live");
        let mut a = funded(&dir, "a.json");
        let out = psp_out(&mut a, 7); // 4 + 2 + 1
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let got = b
            .import_psp_handoff(&out.text, &did(), the_psp(), "")
            .unwrap();
        let id = got.psp_swaps[0].clone();
        assert_eq!(b.balance().psp, 7);
        // nothing changed: the same swap is sent
        assert_eq!(b.live_swap(&id).unwrap(), Some(id.clone()));
        // one note was spent here first (handed on): the swap is rebuilt for the rest
        let spent = b.select_psp_handoff(4).unwrap();
        let handed = b
            .export_psp_handoff(&spent, the_psp(), &did().public_key())
            .unwrap();
        assert_eq!(handed.psp_units, 4);
        assert_eq!(b.balance().psp, 3);
        let now = b.live_swap(&id).unwrap().expect("two notes are left");
        assert_ne!(now, id);
        assert_eq!(b.pending_rollovers().len(), 1);
        let p = &b.pending_rollovers()[0];
        assert_eq!(p.inputs.len(), 2);
        assert!(p.schedule.starts_with(SWAP_TAG));
        assert_eq!(b.unswapped_psp(), 3);
        // all spent: the swap is dropped
        let rest = b.select_psp_handoff(3).unwrap();
        b.export_psp_handoff(&rest, the_psp(), &did().public_key())
            .unwrap();
        assert_eq!(b.live_swap(&now).unwrap(), None);
        assert!(b.pending_rollovers().is_empty());
        assert_eq!(b.unswapped_psp(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn notes_the_mint_says_are_spent_leave_the_balance_and_the_rest_are_swapped() {
        let dir = scratch("found-spent");
        let mut a = funded(&dir, "a.json");
        let out = psp_out(&mut a, 7);
        let mut b = open_wallet(&dir.join("b.json")).unwrap();
        let got = b
            .import_psp_handoff(&out.text, &did(), the_psp(), "")
            .unwrap();
        let id = got.psp_swaps[0].clone();
        let order: Vec<String> = b.pending_rollovers()[0].inputs.clone();
        // the mint names the first note of the request
        let (dropped, next) = b.swap_found_spent(&id, &[0]).unwrap();
        assert_eq!(dropped, 1);
        let next = next.expect("two notes are left");
        assert_eq!(b.notes().len(), 2);
        assert_eq!(b.spent_notes().len(), 1);
        assert_eq!(b.spent_notes()[0].id(), order[0]);
        assert_eq!(b.pending_rollovers().len(), 1);
        assert_eq!(b.pending_rollovers()[0].id, next);
        assert_eq!(b.pending_rollovers()[0].inputs, order[1..].to_vec());
        // a position the wallet does not hold: the swap is only dropped
        let (dropped, none) = b.swap_found_spent(&next, &[9]).unwrap();
        assert_eq!((dropped, none), (0, None));
        assert!(b.pending_rollovers().is_empty());
        assert_eq!(b.notes().len(), 2, "the notes stay as they are");
        fs::remove_dir_all(&dir).unwrap();
    }
}
