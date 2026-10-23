use std::error::Error;
use std::fmt;
use std::io;

use sp_wire::seal::SealError;

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
    /// The mint refused an exchange because PSP notes in it were spent by a
    /// different request, not by this exchange. `inputs` lists them by position
    /// in the request. Nothing was issued. Those notes are spent, so the wallet
    /// marks them spent (see `Wallet::mark_spent_elsewhere`) and frees the rest.
    SpentElsewhere { why: String, inputs: Vec<usize> },
    /// The ESP mint refused a redemption. Nothing was burned. `code` is the
    /// mint's code (`refund_required`, `below_fee`, ...). For `refund_required`
    /// and `outputs_over_limit`, `totals` is what the mint worked out, which the
    /// wallet rebuilds the request from (`Wallet::rebuild_redemption`).
    RedeemRefused {
        code: String,
        why: String,
        totals: Option<Box<sp_wire::esp::redeem::Totals>>,
        /// What the mint made of each note, in the request's order. Sent with
        /// `below_fee` (empty from a mint that does not send it), so the wallet
        /// can retire the notes the mint says are spent.
        notes: Vec<sp_wire::esp::redeem::NoteResult>,
    },
    /// The mint could not be reached, or answered with a fault. The outcome may
    /// be unknown, and retrying the same request is safe.
    Mint(String),
    /// The mint speaks another wire version than this wallet (or reports none).
    /// Nothing was sent. Update whichever is older.
    Wire {
        url: String,
        why: sp_wire::version::WireMismatch,
    },
}

/// A `400` from a mint's POST route as the wallet sees it, over HTTP or AIR (a
/// signed refusal carries the same JSON). `note_spent_elsewhere` with `spent` is
/// [`WalletError::SpentElsewhere`]. Anything else is [`WalletError::Refused`]
/// with the code in front of the reason, or the reason alone when the mint sent
/// no code.
pub(crate) fn mint_refusal(body: &serde_json::Value, code: &str, why: &str) -> WalletError {
    let spent: Vec<usize> = body["spent"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64())
                .map(|v| v as usize)
                .collect()
        })
        .unwrap_or_default();
    if code == sp_wire::codes::NOTE_SPENT_ELSEWHERE && !spent.is_empty() {
        return WalletError::SpentElsewhere {
            why: why.to_string(),
            inputs: spent,
        };
    }
    if code.is_empty() {
        WalletError::Refused(why.to_string())
    } else {
        WalletError::Refused(format!("{code}: {why}"))
    }
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
            WalletError::SpentElsewhere { why, .. } => {
                write!(f, "the mint refused the request: {why}")
            }
            WalletError::RedeemRefused { code, why, .. } => {
                write!(f, "the mint refused the redemption ({code}): {why}")
            }
            WalletError::Mint(e) => write!(f, "{e}"),
            WalletError::Wire { url, why } => {
                write!(
                    f,
                    "the mint at {url} cannot be used: {why}. Nothing was sent"
                )
            }
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

/// Helpers for tests: the message of a refused call, after checking which
/// error it is. A bare `is_err()` would pass for any failure.
#[cfg(test)]
pub(crate) mod expect {
    use super::WalletError;
    use std::fmt::Debug;

    pub fn invalid<T: Debug>(r: Result<T, WalletError>) -> String {
        match r {
            Err(WalletError::Invalid(m)) => m,
            other => panic!("expected WalletError::Invalid, got {other:?}"),
        }
    }

    pub fn unknown<T: Debug>(r: Result<T, WalletError>) -> String {
        match r {
            Err(WalletError::Unknown(m)) => m,
            other => panic!("expected WalletError::Unknown, got {other:?}"),
        }
    }

    pub fn mint<T: Debug>(r: Result<T, WalletError>) -> String {
        match r {
            Err(WalletError::Mint(m)) => m,
            other => panic!("expected WalletError::Mint, got {other:?}"),
        }
    }

    pub fn not_enough<T: Debug>(r: Result<T, WalletError>) -> String {
        match r {
            Err(WalletError::NotEnough(m)) => m,
            other => panic!("expected WalletError::NotEnough, got {other:?}"),
        }
    }
}
