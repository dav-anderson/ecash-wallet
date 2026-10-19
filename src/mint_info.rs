//! Which way the PSP's read-only calls are made: over AIR when the wallet is
//! configured for it, otherwise over HTTP. This is the one place that decides,
//! so the library's callers (the command line, an app, the tests) all get the
//! same rule. The calls are the PSP's mint info ([`verify_psp`]) and its keys,
//! keysets and rotation ([`psp_keys`], [`psp_keysets`], [`psp_window`], and the
//! calls built on them: [`sync_psp_limits`], [`psp_claim_keys`],
//! [`rotation_sync`], [`reclaim_handoff`]).
//!
//! **Over AIR** needs all of `air.psp_did`, `air.server` and `air.host`
//! ([`crate::config::AirSettings::is_configured`]) and the `air` feature. **Over
//! HTTP** is what the `http` functions do, as before; it is also what every call
//! other than these still uses (and the ESP and FSP mints, whose calls never go
//! over AIR here). HTTP is to be removed completely once the AIR integration is
//! done: each HTTP branch is one small function named `http_*` or
//! [`over_http`], with one call each, so removing HTTP removes these and the
//! `!air.is_configured()` lines and nothing else. Nothing is cached here, as
//! nothing was over HTTP: every call asks again.

use std::collections::BTreeMap;

use mint_types::Amount;
use secp256k1::PublicKey;
use sp_wire::air_request::{KIND_KEYS, KIND_KEYSETS, KIND_ROTATION};

use crate::Wallet;
use crate::config::AirSettings;
use crate::error::WalletError;
use crate::rotate::Window;

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

// ---------------------------------------------------------------- keys, keysets, rotation

/// A read-only question to the PSP over AIR, read as the type its HTTP route
/// returns.
#[cfg(feature = "air")]
fn air_fetch<T: serde::de::DeserializeOwned>(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: u8,
) -> Result<T, WalletError> {
    crate::air::fetch(wallet, air, kind)
}

#[cfg(not(feature = "air"))]
fn air_fetch<T>(_: &mut Wallet, _: &AirSettings, _: u8) -> Result<T, WalletError> {
    Err(WalletError::Invalid(
        "air.psp_did, air.server and air.host are set, but this build of the wallet has no AIR (the `air` feature is off). Unset them to use HTTP".into(),
    ))
}

/// The PSP's public key for each note size: `GET /keys`, or over AIR a signed
/// reply with the same body.
pub fn psp_keys(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    if !air.is_configured() {
        return http_keys(base);
    }
    let reply: sp_wire::keys::KeysResponse = air_fetch(wallet, air, KIND_KEYS)?;
    Ok(reply.keys)
}

/// The PSP's live keysets: `GET /keysets`, or over AIR.
pub fn psp_keysets(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<sp_wire::psp::KeysetsResponse, WalletError> {
    if !air.is_configured() {
        return http_keysets(base);
    }
    air_fetch(wallet, air, KIND_KEYSETS)
}

/// The PSP's rotation window: `GET /rotation`, or over AIR.
pub fn psp_window(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<Window, WalletError> {
    if !air.is_configured() {
        return http_window(base);
    }
    let reply: sp_wire::fsp::RotationResponse = air_fetch(wallet, air, KIND_ROTATION)?;
    Ok(reply.into())
}

/// Read the PSP's largest note size from its keys (the highest amount it has a
/// key for) and give it to the wallet, so no cap is written into the wallet.
pub fn sync_psp_limits(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<(), WalletError> {
    let keys = psp_keys(wallet, air, base)?;
    wallet.set_psp_max_denomination(keys.keys().map(|a| a.units).max());
    Ok(())
}

/// The keys to unblind a PSP settlement's signatures with (see
/// [`crate::psp::claim_keys_with`]), read over AIR when configured.
pub fn psp_claim_keys(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    settlement_text: &str,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    if !air.is_configured() {
        return http_claim_keys(base, settlement_text);
    }
    let wallet = std::cell::RefCell::new(wallet);
    crate::psp::claim_keys_with(
        settlement_text,
        || {
            let reply: sp_wire::keys::KeysResponse =
                air_fetch(&mut wallet.borrow_mut(), air, KIND_KEYS)?;
            Ok(reply.keys)
        },
        || air_fetch(&mut wallet.borrow_mut(), air, KIND_KEYSETS),
    )
}

/// Keep a PSP or ESP mint's notes on a live key set (see
/// [`crate::http::rotation_sync`]). For the PSP the window is read over AIR when
/// configured; the ESP's never is, and a rollover is HTTP either way.
#[cfg(feature = "http")]
pub fn rotation_sync(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: crate::Kind,
    base: &str,
) -> Result<Vec<String>, WalletError> {
    if kind != crate::Kind::Psp || !air.is_configured() {
        return crate::http::rotation_sync(wallet, kind, base);
    }
    crate::http::rotation_sync_with(wallet, kind, base, &mut |w| psp_window(w, air, base))
}

/// Take back what is left of a PSP handoff (see [`crate::http::reclaim_handoff`]);
/// the window the swap names is read over AIR when configured.
#[cfg(feature = "http")]
pub fn reclaim_handoff(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
) -> Result<crate::http::Reclaim, WalletError> {
    if !air.is_configured() {
        return crate::http::reclaim_handoff(wallet, id);
    }
    crate::http::reclaim_handoff_with(wallet, id, &mut |w, mint| psp_window(w, air, mint))
}

// The HTTP branches, one function each. To remove HTTP, delete these and the
// `!air.is_configured()` lines above.

#[cfg(feature = "http")]
fn http_keys(base: &str) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    crate::http::fetch_psp_keys(base)
}

#[cfg(feature = "http")]
fn http_keysets(base: &str) -> Result<sp_wire::psp::KeysetsResponse, WalletError> {
    crate::http::fetch_psp_keysets(base)
}

#[cfg(feature = "http")]
fn http_window(base: &str) -> Result<Window, WalletError> {
    crate::http::fetch_window(base)
}

#[cfg(feature = "http")]
fn http_claim_keys(
    base: &str,
    settlement_text: &str,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    crate::http::psp_claim_keys(base, settlement_text)
}

#[cfg(not(feature = "http"))]
const NO_HTTP: &str = "the HTTP calls (feature `http`) and AIR is not configured";

#[cfg(not(feature = "http"))]
fn http_keys(_: &str) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_keysets(_: &str) -> Result<sp_wire::psp::KeysetsResponse, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_window(_: &str) -> Result<Window, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_claim_keys(_: &str, _: &str) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}
