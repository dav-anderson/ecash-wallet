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
//! - [`transfer`]: handing ESP to the service it is named for
//!   (`hand_over_esp`), receiving it (`receive_handover`), and the service's swap
//!   at the ESP mint (`build_transfer`, `finish_transfer`).
//! - [`redeem`]: redeeming ESP with the Issuer.
//! - [`fsp`]: FSP from a service's fsp-mint: issue from ESP, spend with change,
//!   automatic rollover to the current keyset, and the ESP schedule.
//! - [`rotate`]: the automatic, staggered rollover of PSP and ESP (and the
//!   swap schedule FSP shares) when a mint rotates its keys.
//! - [`http`] (feature `http`): the calls to the mints.

pub mod blind;
pub mod date;
pub mod error;
pub mod esp;
pub mod fsp;
#[cfg(feature = "http")]
pub mod http;
pub mod psp;
pub mod redeem;
pub mod rotate;
pub mod send;
pub mod store;
pub mod transfer;

pub use error::WalletError;
pub use store::{Balance, EspLimits, Kind, Wallet};
