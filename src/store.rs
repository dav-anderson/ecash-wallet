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

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use air::names::secp256k1::SecretKey as DidSecretKey;
use esp_mint::exchange::ExchangeRequest;
use mint_types::Note;
use secp256k1::{SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTerms {
    pub service: XOnlyPublicKey,
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
}

/// A PSP purchase whose payload has been made and whose signatures have not
/// been claimed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingPurchase {
    /// SHA-256 of the sealed payload, as hex.
    pub id: String,
    pub reply_did: String,
    pub mint_did_pubkey: String,
    pub outputs: Vec<PendingOutput>,
}

/// An ESP exchange that has been built and has not been finished.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingExchange {
    /// The request hash, as the mint stores it.
    pub id: String,
    pub service: XOnlyPublicKey,
    pub input_ids: Vec<String>,
    pub outputs: Vec<PendingOutput>,
    /// Kept so that a retry sends exactly the same request.
    pub request: ExchangeRequest,
    /// ESP units among the outputs that are change (see `esp.rs`).
    #[serde(default)]
    pub change_esp: u128,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WalletData {
    /// A stand-in reply DID for the command line, made on first use. An app
    /// passes its own.
    #[serde(default)]
    pub reply_did: Option<String>,
    #[serde(default)]
    pub notes: Vec<StoredNote>,
    #[serde(default)]
    pub pending_purchases: Vec<PendingPurchase>,
    #[serde(default)]
    pub pending_exchanges: Vec<PendingExchange>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub psp: u128,
    pub esp: u128,
    pub fsp: u128,
    /// ESP units by service (hex) and redeemable-after day.
    pub esp_by_terms: BTreeMap<(String, u64), u128>,
    pub notes: usize,
    /// Notes held back for a pending request.
    pub reserved: usize,
    pub pending_purchases: usize,
    pub pending_exchanges: usize,
}

pub struct Wallet {
    path: PathBuf,
    data: WalletData,
}

impl Wallet {
    /// Open the wallet at `path`. A missing file is an empty wallet.
    pub fn open(path: &Path) -> Result<Self, WalletError> {
        let data = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| WalletError::Corrupt(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => WalletData::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Wallet {
            path: path.to_path_buf(),
            data,
        })
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

    pub fn pending_exchanges(&self) -> &[PendingExchange] {
        &self.data.pending_exchanges
    }

    /// Apply a change and save it. The change is made on a copy and only takes
    /// effect if the save succeeds, so memory never runs ahead of the file.
    pub(crate) fn update<T>(
        &mut self,
        change: impl FnOnce(&mut WalletData) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let mut next = self.data.clone();
        let out = change(&mut next)?;
        write_atomic(&self.path, &next)?;
        self.data = next;
        Ok(out)
    }

    /// The reply DID the command line uses by default: 33 bytes, made once and
    /// kept. It is only a stand-in until a wallet has a real AIR identity.
    pub fn reply_did(&mut self) -> Result<[u8; 33], WalletError> {
        if let Some(text) = &self.data.reply_did {
            return parse_did(text);
        }
        let made = DidSecretKey::new().public_key().to_string();
        let did = parse_did(&made)?;
        self.update(|d| {
            d.reply_did = Some(made.clone());
            Ok(())
        })?;
        Ok(did)
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
                Kind::Fsp => b.fsp += units,
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
        b.pending_purchases = self.data.pending_purchases.len();
        b.pending_exchanges = self.data.pending_exchanges.len();
        b
    }
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
        let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
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
        let dir = std::env::temp_dir().join(format!("ecash-wallet-{}-{name}", std::process::id()));
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
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
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
    fn the_reply_did_is_made_once_and_is_33_bytes() {
        let dir = scratch("did");
        let path = dir.join("wallet.json");
        let mut w = Wallet::open(&path).unwrap();
        let first = w.reply_did().unwrap();
        assert!(first[0] == 2 || first[0] == 3);
        assert_eq!(Wallet::open(&path).unwrap().reply_did().unwrap(), first);
        assert_eq!(w.reply_did().unwrap(), first);
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
        let service = XOnlyPublicKey::from_slice(
            &hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap(),
        )
        .unwrap();
        let mut esp = some_note(Kind::Esp, 3_000_000_000_000);
        esp.terms = Some(StoredTerms { service, redeemable_after_day: 21_100 });
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
