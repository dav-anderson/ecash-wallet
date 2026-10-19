//! Which way the PSP's mint info is asked: over AIR when the wallet is
//! configured for it, otherwise over HTTP. This is the one place that decides,
//! so the library's callers (the command line, an app, the tests) all get the
//! same rule.
//!
//! **Over AIR** needs all of `air.psp_did`, `air.server` and `air.host`
//! ([`crate::config::AirSettings::is_configured`]) and the `air` feature. **Over
//! HTTP** is [`crate::http::verify_mint`], as before; it is also what every call
//! other than this one still uses. HTTP is to be removed completely once the AIR
//! integration is done: the HTTP branch is [`over_http`], one function with one
//! call, so removing it removes this module's fallback and nothing else.

use crate::Wallet;
use crate::config::AirSettings;
use crate::error::WalletError;

/// Check the PSP's wire version and network before anything else is sent to it:
/// over AIR (for `air.psp_did`) when `air` is configured, else over HTTP at
/// `base`. `expected_network` is `main`, `regtest`, `signet` or `testnet`.
pub fn verify_psp(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    expected_network: &str,
) -> Result<(), WalletError> {
    if !air.is_configured() {
        return over_http(base, expected_network);
    }
    over_air(wallet, air, expected_network)
}

#[cfg(feature = "air")]
fn over_air(wallet: &mut Wallet, air: &AirSettings, network: &str) -> Result<(), WalletError> {
    crate::air::verify_mint(wallet, air, network)
}

#[cfg(not(feature = "air"))]
fn over_air(_: &mut Wallet, _: &AirSettings, _: &str) -> Result<(), WalletError> {
    Err(WalletError::Invalid(
        "air.psp_did, air.server and air.host are set, but this build of the wallet has no AIR (the `air` feature is off). Unset them to use HTTP".into(),
    ))
}

/// The HTTP branch: the only call to `http::verify_mint` for the PSP. To remove
/// HTTP, delete this function and the `!air.is_configured()` line above.
#[cfg(feature = "http")]
fn over_http(base: &str, network: &str) -> Result<(), WalletError> {
    crate::http::verify_mint(base, network)
}

#[cfg(not(feature = "http"))]
fn over_http(_: &str, _: &str) -> Result<(), WalletError> {
    Err(WalletError::NotBuilt(
        "the HTTP calls (feature `http`) and AIR is not configured",
    ))
}
