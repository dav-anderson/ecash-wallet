//! Which way the PSP's read-only calls are made: over AIR when the wallet is
//! configured for it, otherwise over HTTP. This is the one place that decides,
//! so the library's callers (the command line, an app, the tests) all get the
//! same rule. The calls are the PSP's mint info ([`verify_psp`]) and its keys,
//! keysets and rotation ([`psp_keys`], [`psp_keysets`], [`psp_window`], and the
//! calls built on them: [`sync_psp_limits`], [`psp_claim_keys`],
//! [`rotation_sync`], [`reclaim_handoff`]) and the PSP's two POSTs, rollover and
//! check-state ([`psp_post`], and the calls built on it: [`rotation_sync`],
//! [`reclaim_handoff`], [`check_handoff`], [`complete_import`]).
//!
//! **Over AIR** needs `air.server` and `air.host`
//! ([`crate::config::AirSettings::is_configured`]; the DID is `air.psp_did`, or
//! the built-in SPI DID, a PLACEHOLDER until the first SPI deploy) and the `air`
//! feature. **Over HTTP** is what the `http` functions do, as before; it is also what every call
//! other than these still uses (and the ESP and FSP mints, whose calls never go
//! over AIR here). HTTP is to be removed completely once the AIR integration is
//! done: each HTTP branch is one small function named `http_*` or
//! [`over_http`], with one call each, so removing HTTP removes these and the
//! `!air.is_configured()` lines and nothing else. Nothing is cached here, as
//! nothing was over HTTP: every call asks again.

use std::collections::BTreeMap;

use mint_types::Amount;
use secp256k1::PublicKey;
use sp_wire::air_request::{
    KIND_CHECK_STATE, KIND_KEYS, KIND_KEYSETS, KIND_ROLLOVER, KIND_ROTATION,
};

use crate::Wallet;
use crate::config::AirSettings;
use crate::error::WalletError;
use crate::rotate::Window;

/// Check the PSP's wire version and network before anything else is sent to it:
/// over AIR (to the SPI DID: `air.psp_did`, or the built-in one) when `air` is configured, else over HTTP at
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
        "air.server and air.host are set, but this build of the wallet has no AIR (the `air` feature is off). Unset them to use HTTP".into(),
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
    Err(WalletError::Invalid(NO_AIR.into()))
}

#[cfg(not(feature = "air"))]
const NO_AIR: &str = "air.server and air.host are set, but this build of the wallet has no AIR (the `air` feature is off). Unset them to use HTTP";

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

/// A POST to the PSP: `route` is `rollover` or `check-state`, `body` the request
/// JSON. Over AIR when configured (a sealed request, a signed reply, a refusal
/// that maps to the HTTP `400` of the same meaning), else the HTTP POST.
/// This is the [`crate::http::Post`] of every PSP call below.
pub fn psp_post(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    route: &str,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    if !air.is_configured() {
        return http_post(base, route, body);
    }
    let kind = match route {
        "rollover" => KIND_ROLLOVER,
        "check-state" => KIND_CHECK_STATE,
        other => {
            return Err(WalletError::Invalid(format!(
                "`{other}` is not a call the PSP takes over AIR (only rollover and check-state are)"
            )));
        }
    };
    air_post(wallet, air, kind, body)
}

#[cfg(feature = "air")]
fn air_post(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: u8,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    crate::air::post(wallet, air, kind, body)
}

#[cfg(not(feature = "air"))]
fn air_post(
    _: &mut Wallet,
    _: &AirSettings,
    _: u8,
    _: &[u8],
) -> Result<serde_json::Value, WalletError> {
    Err(WalletError::Invalid(NO_AIR.into()))
}

/// Keep a PSP or ESP mint's notes on a live key set (see
/// [`crate::http::rotation_sync`]). For the PSP the window is read, and the
/// rollovers are sent, over AIR when configured; the ESP's never is.
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
    crate::http::rotation_sync_with(
        wallet,
        kind,
        base,
        &mut |w| psp_window(w, air, base),
        &mut |w, base, route, body| psp_post(w, air, base, route, body),
    )
}

/// Take back what is left of a PSP handoff (see [`crate::http::reclaim_handoff`]);
/// the window the swap names, the swap and the check are over AIR when configured.
#[cfg(feature = "http")]
pub fn reclaim_handoff(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
) -> Result<crate::http::Reclaim, WalletError> {
    if !air.is_configured() {
        return crate::http::reclaim_handoff(wallet, id);
    }
    crate::http::reclaim_handoff_with(
        wallet,
        id,
        &mut |w, mint| psp_window(w, air, mint),
        &mut |w, base, route, body| psp_post(w, air, base, route, body),
    )
}

/// Ask the mint where a PSP handoff this wallet made stands (see
/// [`crate::http::check_handoff`]); `POST /check-state` is over AIR when
/// configured.
#[cfg(feature = "http")]
pub fn check_handoff(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
) -> Result<crate::handoff::Standing, WalletError> {
    if !air.is_configured() {
        return crate::http::check_handoff(wallet, id);
    }
    crate::http::check_handoff_with(wallet, id, &mut |w, base, route, body| {
        psp_post(w, air, base, route, body)
    })
}

/// Finish the import of a PSP handoff (see [`crate::http::complete_import`]); the
/// swap is sent over AIR when configured.
#[cfg(feature = "http")]
pub fn complete_import(
    wallet: &mut Wallet,
    air: &AirSettings,
    imported: &crate::handoff::Imported,
) -> Vec<String> {
    if !air.is_configured() {
        return crate::http::complete_import(wallet, imported);
    }
    crate::http::complete_import_with(wallet, imported, &mut |w, base, route, body| {
        psp_post(w, air, base, route, body)
    })
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
fn http_post(base: &str, route: &str, body: &[u8]) -> Result<serde_json::Value, WalletError> {
    crate::http::post_bytes(base, route, body)
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
fn http_post(_: &str, _: &str, _: &[u8]) -> Result<serde_json::Value, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

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
