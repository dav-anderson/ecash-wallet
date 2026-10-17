//! ecash-wallet: one wallet library for PSP, ESP and FSP.
//!
//! All the logic is here. The command line (`src/main.rs`) only parses
//! arguments and prints. The library holds no BTC wallet: the app's own Bitcoin
//! wallet puts the bytes from [`Wallet::build_psp_payload`] in an OP_RETURN and
//! pays.
//!
//! - [`blind`]: blinding outputs and unblinding signatures.
//! - [`config`]: the wallet's settings, so far the storage policy (an ordered
//!   list of service IDs for the wallet's data and the app's), and the storage
//!   service that FSP fees are paid to.
//! - [`store`]: the note file, which holds each note with its spend key, amount
//!   and terms, and the requests waiting for a reply.
//! - [`psp`]: buying PSP (`build_psp_payload`, `claim_psp`).
//! - [`split`]: ESP note sizes are powers of two; totals are split into them.
//! - [`esp`]: exchanging PSP for ESP (`build_exchange`, `finish_exchange`).
//! - [`transfer`]: handing ESP to the service it is named for
//!   (`hand_over_esp`), receiving it (`receive_handover`), and the service's swap
//!   at the ESP mint (`build_transfer`, `finish_transfer`).
//! - [`redeem`]: redeeming ESP with the Issuer.
//! - [`fsp`]: FSP from a service's fsp-mint: issue from ESP, spend with change,
//!   automatic rollover to the current keyset, and the ESP schedule.
//! - [`handoff`]: moving notes from one wallet to another without the AIR, as a
//!   string or a QR code, in exactly two kinds: a PSP handoff (a developer to a
//!   user, sealed to the user's DID key, always swapped, and reclaimable by the
//!   sender until the receiver swaps) and an FSP handoff (a user's own new
//!   device: FSP and the DID key, never swapped).
//! - [`legacy`]: the records `send-psp` left in old wallet files, migrated to
//!   PSP handoff records when the file is opened.
//! - [`merge`]: reconciling a copy of the wallet retrieved from storage with
//!   the local one.
//! - [`rotate`]: the automatic, staggered rollover of PSP and ESP (and the
//!   swap schedule FSP shares) when a mint rotates its keys.
//! - [`http`] (feature `http`): the calls to the mints.

pub mod blind;
pub mod config;
pub mod date;
pub mod error;
pub mod esp;
pub mod fsp;
pub mod handoff;
#[cfg(feature = "http")]
pub mod http;
pub mod legacy;
pub mod merge;
pub mod psp;
pub mod redeem;
pub mod rotate;
pub mod split;
pub mod store;
pub mod transfer;

pub use error::WalletError;
pub use store::{Balance, EspLimits, Kind, Wallet};
