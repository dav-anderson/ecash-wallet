//! ecash-wallet: one wallet library for PSP, ESP and FSP.
//!
//! This crate is a library for apps (the RAMP apps build it in); the command
//! line (`src/main.rs`) is one caller among them. All the logic is here: the
//! command line only parses arguments and prints. The library holds no BTC wallet: the app's own Bitcoin
//! wallet puts the bytes from [`Wallet::build_psp_payload`] in an OP_RETURN and
//! pays.
//!
//! - [`blind`]: blinding outputs and unblinding signatures.
//! - [`config`]: the wallet's settings, so far the storage policy (an ordered
//!   list of service IDs for the wallet's data and the app's), and the storage
//!   service that FSP fees are paid to.
//! - [`store`]: the note file, which holds each note with its spend key, amount
//!   and terms, and the requests waiting for a reply.
//! - [`psp`]: buying PSP and claiming it (`build_psp_payload`, `apply_delivery`,
//!   `build_claim`, `apply_claim`): each purchase has a throwaway claim key of its
//!   own, and its payload is that key alone, with no amount. The PSP mint writes an
//!   owed record for each payment over AIR, and the wallet claims it with a claim
//!   (AIR kind 15) it builds when it claims, for exactly the units owed
//!   (`mint_info::psp_pickup` and `mint_info::psp_claim` for the whole step). A
//!   purchase of at least $5 (50 PSP) is recommended, and nothing enforces it.
//! - [`split`]: ESP note sizes are powers of two; totals are split into them.
//! - [`esp`]: exchanging PSP for ESP (`build_exchange`, `finish_exchange`).
//! - [`transfer`]: the service taking in the ESP an FSP mint kept for it
//!   (`receive_handover`, behind `receive`).
//! - [`redeem`]: redeeming ESP with the Issuer.
//! - [`fsp`]: FSP from a service's fsp-mint: issue from ESP, spend with change,
//!   automatic rollover to the current keyset, and the ESP schedule.
//! - [`handoff`]: moving notes from one wallet to another without the AIR, as a
//!   string or a QR code, in exactly two kinds: a PSP handoff (a developer to a
//!   user, sealed to the user's DID key, always swapped, and reclaimable by the
//!   sender until the receiver swaps) and an FSP handoff (a user's own new
//!   device: FSP and the DID key, never swapped).
//! - [`merge`]: reconciling a copy of the wallet retrieved from storage with
//!   the local one.
//! - [`rotate`]: the automatic, staggered rollover of PSP and ESP (and the
//!   swap schedule FSP shares) when a mint rotates its keys.
//! - [`mint_info`]: the PSP's, the ESP's and the FSP mints' calls (mint info,
//!   keys, keysets, rotation, fees, rollover, check-state, exchange,
//!   redeem, FSP issue and FSP spend), made over AIR and only over AIR (the
//!   wallet makes no HTTP call), and the rollover, handoff and FSP sync steps
//!   built on them.
//! - [`air`]: the AIR request and reply under those calls.
//! - [`esp_replies`]: how the ESP's fees reply and its refusals are read.

pub mod air;
pub mod blind;
pub mod config;
pub mod date;
pub mod error;
pub mod esp;
pub mod esp_replies;
pub mod fsp;
pub mod handoff;
pub mod lockfile;
pub mod merge;
pub mod mint_info;
pub mod psp;
pub mod redeem;
pub mod rotate;
pub mod split;
pub mod store;
pub mod transfer;
pub mod version;

pub use error::WalletError;
pub use store::{Balance, EspLimits, Kind, Wallet};
