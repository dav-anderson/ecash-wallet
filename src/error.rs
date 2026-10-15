use std::error::Error;
use std::fmt;
use std::io;

use psp_mint::seal::SealError;

#[derive(Debug)]
pub enum WalletError {
    /// Reading or writing the note file.
    Io(io::Error),
    /// The note file is not valid. It is never replaced with an empty one.
    Corrupt(String),
    /// The caller's input is wrong.
    Invalid(String),
    /// The wallet does not hold what the request needs.
    NotEnough(String),
    /// Something named by the caller is not in the wallet.
    Unknown(String),
    /// Sealing the payload failed.
    Seal(SealError),
    /// The mint refused the request. Nothing was burned, so the pending request
    /// can be cancelled.
    Refused(String),
    /// The mint could not be reached, or answered with a fault. The outcome may
    /// be unknown, and retrying the same request is safe.
    Mint(String),
    /// A feature that waits on its mint.
    NotBuilt(&'static str),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::Io(e) => write!(f, "wallet file: {e}"),
            WalletError::Corrupt(e) => write!(f, "wallet file is not valid: {e}"),
            WalletError::Invalid(e) => write!(f, "{e}"),
            WalletError::NotEnough(e) => write!(f, "{e}"),
            WalletError::Unknown(e) => write!(f, "{e}"),
            WalletError::Seal(e) => write!(f, "could not seal the payload: {e}"),
            WalletError::Refused(e) => write!(f, "the mint refused the request: {e}"),
            WalletError::Mint(e) => write!(f, "{e}"),
            WalletError::NotBuilt(what) => write!(f, "not built yet: {what}"),
        }
    }
}

impl Error for WalletError {}

impl From<io::Error> for WalletError {
    fn from(e: io::Error) -> Self {
        WalletError::Io(e)
    }
}

impl From<SealError> for WalletError {
    fn from(e: SealError) -> Self {
        WalletError::Seal(e)
    }
}
