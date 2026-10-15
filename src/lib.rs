//! ecash-wallet: one wallet library for PSP, ESP and FSP.
//!
//! All the logic is here. The command line (`src/main.rs`) only parses
//! arguments and prints. The library holds no BTC wallet: the app's own Bitcoin
//! wallet puts the bytes from [`Wallet::build_psp_payload`] in an OP_RETURN and
//! pays.
//!
//! - [`blind`]: blinding outputs and unblinding signatures.
//! - [`store`]: the note file, which holds each note with its spend key, amount
//!   and terms, and the requests waiting for a reply.
//! - [`psp`]: buying PSP (`build_psp_payload`, `claim_psp`).
//! - [`esp`]: exchanging PSP for ESP (`build_exchange`, `finish_exchange`).
//! - [`transfer`], [`redeem`], [`fsp`]: entry points for the features that are
//!   not built yet.
//! - [`http`] (feature `http`): the calls to the mints.

pub mod blind;
pub mod error;
pub mod esp;
pub mod fsp;
#[cfg(feature = "http")]
pub mod http;
pub mod psp;
pub mod redeem;
pub mod store;
pub mod transfer;

pub use error::WalletError;
pub use store::{Balance, Kind, Wallet};
