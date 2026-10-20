//! Which way the wallet's calls to the PSP and the ESP are made: over AIR when
//! the wallet is configured for it, otherwise over HTTP. This is the one place
//! that decides, so the library's callers (the command line, an app, the tests)
//! all get the same rule.
//!
//! **The PSP's** calls are its mint info ([`verify_psp`]), its keys, keysets and
//! rotation ([`psp_keys`], [`psp_keysets`], [`psp_window`], and the calls built
//! on them: [`sync_psp_limits`], [`psp_claim_keys`], [`rotation_sync`],
//! [`reclaim_handoff`]) and its two POSTs, rollover and check-state
//! ([`psp_post`], and the calls built on it: [`rotation_sync`],
//! [`reclaim_handoff`], [`check_handoff`], [`complete_import`]).
//!
//! **The ESP's** are its mint info ([`verify_esp`]), keysets ([`sync_esp_keysets`]),
//! fees ([`sync_esp_limits`], [`fetch_redeem_fees`]), rotation ([`esp_window`])
//! and rollover ([`esp_post`], used by [`rotation_sync`]), and the three calls
//! that spend: [`send_exchange`], [`send_transfer`] and [`send_redeem`]. The ESP
//! has no `GET /keys` (its keys arrive in the replies) and its `GET /audit` is the
//! operator's, so neither is here.
//!
//! **Over AIR** needs `air.server` and `air.host`
//! ([`crate::config::AirSettings::is_configured`]; the DIDs are `air.psp_did` and
//! `air.esp_did`, or the built-in ones, PLACEHOLDERS until the first SPI deploy)
//! and the `air` feature. The PSP and the ESP share the AIR server and have their
//! own DIDs. **Over HTTP** is what the `http` functions do, as before; it is also
//! what every call other than these still uses (and the FSP mints, whose calls
//! never go over AIR here). HTTP is to be removed completely once the AIR
//! integration is done: each HTTP branch is one small function named `http_*` or
//! [`over_http`], with one call each, so removing HTTP removes these and the
//! `!air.is_configured()` lines and nothing else. Nothing is cached here, as
//! nothing was over HTTP: every call asks again.

use std::collections::BTreeMap;

use mint_types::Amount;
use secp256k1::PublicKey;
use sp_wire::air_request::{
    KIND_CHECK_STATE, KIND_EXCHANGE, KIND_FEES, KIND_KEYS, KIND_KEYSETS, KIND_REDEEM,
    KIND_ROLLOVER, KIND_ROTATION, KIND_TRANSFER,
};
use sp_wire::esp::exchange::{ExchangeRequest, ExchangeResponse};
use sp_wire::esp::redeem::RedeemResponse;
use sp_wire::esp::transfer::{TransferRequest, TransferResponse};

use crate::Wallet;
use crate::config::{AirSettings, Party};
use crate::error::WalletError;
use crate::redeem::RedeemFees;
use crate::rotate::Window;

/// Check a mint's wire version and network before anything else is sent to it:
/// over AIR (to the mint's DID) when `air` is configured, else over HTTP at
/// `base`. `expected_network` is `main`, `regtest`, `signet` or `testnet`.
fn verify(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    base: &str,
    expected_network: &str,
) -> Result<(), WalletError> {
    if !air.is_configured() {
        return over_http(base, expected_network);
    }
    over_air(wallet, air, party, expected_network)
}

/// Check the PSP's wire version and network before anything else is sent to it:
/// over AIR (to the PSP's DID: `air.psp_did`, or the built-in one) when `air` is
/// configured, else over HTTP at `base`.
pub fn verify_psp(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    expected_network: &str,
) -> Result<(), WalletError> {
    verify(wallet, air, Party::Psp, base, expected_network)
}

/// Check the ESP's wire version and network before anything else is sent to it:
/// over AIR (to the ESP's own DID: `air.esp_did`, or the built-in one) when `air`
/// is configured, else over HTTP at `base`.
pub fn verify_esp(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    expected_network: &str,
) -> Result<(), WalletError> {
    verify(wallet, air, Party::Esp, base, expected_network)
}

#[cfg(feature = "air")]
fn over_air(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    network: &str,
) -> Result<(), WalletError> {
    crate::air::verify_mint(wallet, air, party, network)
}

#[cfg(not(feature = "air"))]
fn over_air(_: &mut Wallet, _: &AirSettings, _: Party, _: &str) -> Result<(), WalletError> {
    Err(WalletError::Invalid(NO_AIR.into()))
}

/// The HTTP branch: the only call to `http::verify_mint`, for the PSP and the
/// ESP. To remove HTTP, delete this function and the `!air.is_configured()` line
/// above.
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

/// A read-only question to a mint over AIR, read as the type its HTTP route
/// returns.
#[cfg(feature = "air")]
fn air_fetch<T: serde::de::DeserializeOwned>(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
) -> Result<T, WalletError> {
    crate::air::fetch(wallet, air, party, kind)
}

#[cfg(not(feature = "air"))]
fn air_fetch<T>(_: &mut Wallet, _: &AirSettings, _: Party, _: u8) -> Result<T, WalletError> {
    Err(WalletError::Invalid(NO_AIR.into()))
}

/// [`air_fetch`] for a body the caller reads itself: its text.
#[cfg(feature = "air")]
fn air_text(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
) -> Result<String, WalletError> {
    crate::air::fetch_text(wallet, air, party, kind)
}

#[cfg(not(feature = "air"))]
fn air_text(_: &mut Wallet, _: &AirSettings, _: Party, _: u8) -> Result<String, WalletError> {
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
    let reply: sp_wire::keys::KeysResponse = air_fetch(wallet, air, Party::Psp, KIND_KEYS)?;
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
    air_fetch(wallet, air, Party::Psp, KIND_KEYSETS)
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
    let reply: sp_wire::fsp::RotationResponse = air_fetch(wallet, air, Party::Psp, KIND_ROTATION)?;
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
                air_fetch(&mut wallet.borrow_mut(), air, Party::Psp, KIND_KEYS)?;
            Ok(reply.keys)
        },
        || air_fetch(&mut wallet.borrow_mut(), air, Party::Psp, KIND_KEYSETS),
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
    air_post(wallet, air, Party::Psp, kind, body)
}

#[cfg(feature = "air")]
fn air_post(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    crate::air::post(wallet, air, party, kind, body)
}

#[cfg(not(feature = "air"))]
fn air_post(
    _: &mut Wallet,
    _: &AirSettings,
    _: Party,
    _: u8,
    _: &[u8],
) -> Result<serde_json::Value, WalletError> {
    Err(WalletError::Invalid(NO_AIR.into()))
}

// ---------------------------------------------------------------- the ESP

/// The ESP mint's live keyset IDs: `GET /keysets`, or over AIR; remembered in the
/// wallet (new outputs name the current one, and notes from before keysets were
/// recorded fall back to them). See [`crate::http::sync_esp_keysets`].
pub fn sync_esp_keysets(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<(), WalletError> {
    if !air.is_configured() {
        return http_sync_esp_keysets(wallet, base);
    }
    let v: serde_json::Value = air_fetch(wallet, air, Party::Esp, KIND_KEYSETS)?;
    let current = v["current"]
        .as_str()
        .ok_or_else(|| WalletError::Mint("keysets over AIR: no current keyset".into()))?;
    wallet.note_esp_keysets(base, current, v["previous"].as_str())
}

/// The ESP mint's note limits: `GET /fees`, or over AIR; given to the wallet (see
/// [`crate::store::EspLimits`]), so no limit is written into the wallet.
pub fn sync_esp_limits(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<(), WalletError> {
    if !air.is_configured() {
        return http_sync_esp_limits(wallet, base);
    }
    let text = air_text(wallet, air, Party::Esp, KIND_FEES)?;
    let limits = crate::esp_replies::parse_esp_limits(&text)
        .map_err(|why| WalletError::Mint(format!("fees over AIR: {why}")))?;
    wallet.set_esp_limits(limits);
    Ok(())
}

/// The ESP mint's redemption fee rate and ceilings: `GET /fees` (`redeem`), or
/// over AIR.
pub fn fetch_redeem_fees(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<RedeemFees, WalletError> {
    if !air.is_configured() {
        return http_fetch_redeem_fees(base);
    }
    let text = air_text(wallet, air, Party::Esp, KIND_FEES)?;
    crate::esp_replies::parse_redeem_fees(&text)
        .map_err(|why| WalletError::Mint(format!("fees over AIR: {why}")))
}

/// The ESP's rotation window: `GET /rotation`, or over AIR. A mint that does not
/// rotate answers `404` over HTTP and a signed refusal that says `404` over AIR:
/// an error either way.
pub fn esp_window(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<Window, WalletError> {
    if !air.is_configured() {
        return http_window(base);
    }
    let reply: sp_wire::fsp::RotationResponse = air_fetch(wallet, air, Party::Esp, KIND_ROTATION)?;
    Ok(reply.into())
}

/// A POST to the ESP: `route` is `rollover` (the one a [`crate::http::Post`]
/// makes), `body` the request JSON. Over AIR when configured, else the HTTP POST.
pub fn esp_post(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    route: &str,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    if !air.is_configured() {
        return http_post(base, route, body);
    }
    match route {
        "rollover" => air_post(wallet, air, Party::Esp, KIND_ROLLOVER, body),
        other => Err(WalletError::Invalid(format!(
            "`{other}` is not a call a rotation sync makes of the ESP over AIR (only rollover is)"
        ))),
    }
}

/// Send an exchange to the ESP mint: `POST /exchange`, or over AIR (a sealed
/// request, the same JSON body, a signed reply).
///
/// A `400` (over AIR a signed refusal without an `http_status`) is
/// [`WalletError::Refused`], or [`WalletError::SpentElsewhere`] with the PSP
/// notes the mint names: nothing was burned, and the pending exchange can be
/// cancelled. Anything else that goes wrong is [`WalletError::Mint`], where the
/// outcome may be unknown: a `409 in_progress` (over AIR a refusal that says
/// `"http_status": 409`), a `5xx` (over AIR a signed "unavailable", the `502` of
/// a PSP that could not be reached included), no reply. Send the same request
/// again: the mint stores its answers by request hash, over HTTP and over AIR.
pub fn send_exchange(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    request: &ExchangeRequest,
) -> Result<ExchangeResponse, WalletError> {
    if !air.is_configured() {
        return http_send_exchange(base, request);
    }
    let body = serde_json::to_vec(request)
        .map_err(|e| WalletError::Mint(format!("exchange over AIR: {e}")))?;
    air_send_esp(
        wallet,
        air,
        KIND_EXCHANGE,
        &body,
        &crate::esp_replies::exchange_refusal,
        &[400],
    )
}

/// Send a transfer to the ESP mint: `POST /transfer`, or over AIR. Refusals are
/// read as the exchange's are ([`send_exchange`]).
pub fn send_transfer(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    request: &TransferRequest,
) -> Result<TransferResponse, WalletError> {
    if !air.is_configured() {
        return http_send_transfer(base, request);
    }
    let body = serde_json::to_vec(request)
        .map_err(|e| WalletError::Mint(format!("transfer over AIR: {e}")))?;
    air_send_esp(
        wallet,
        air,
        KIND_TRANSFER,
        &body,
        &crate::esp_replies::exchange_refusal,
        &[400],
    )
}

/// Send a redemption to the ESP mint: `POST /redeem`, or over AIR; `body` is the
/// canonical encoding as built by `Wallet::build_redemption`, sent as it is.
///
/// A `400` or `413` is [`WalletError::RedeemRefused`]: nothing was burned.
/// Anything else that goes wrong is [`WalletError::Mint`], where the outcome may
/// be unknown: send the same bytes again, because the mint stores its answers by
/// request hash.
pub fn send_redeem(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
    body: &[u8],
) -> Result<RedeemResponse, WalletError> {
    if !air.is_configured() {
        return http_send_redeem(base, body);
    }
    air_send_esp(
        wallet,
        air,
        KIND_REDEEM,
        body,
        &crate::esp_replies::redeem_refusal,
        &[400, 413],
    )
}

#[cfg(feature = "air")]
fn air_send_esp<R: serde::de::DeserializeOwned>(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: u8,
    body: &[u8],
    refusal: &dyn Fn(&str) -> WalletError,
    refusal_statuses: &[u16],
) -> Result<R, WalletError> {
    crate::air::send_esp(wallet, air, kind, body, refusal, refusal_statuses)
}

#[cfg(not(feature = "air"))]
fn air_send_esp<R>(
    _: &mut Wallet,
    _: &AirSettings,
    _: u8,
    _: &[u8],
    _: &dyn Fn(&str) -> WalletError,
    _: &[u16],
) -> Result<R, WalletError> {
    Err(WalletError::Invalid(NO_AIR.into()))
}

// ---------------------------------------------------------------- rollover and handoffs

/// Keep a PSP or ESP mint's notes on a live key set (see
/// [`crate::http::rotation_sync`]). For the PSP and the ESP the window is read,
/// and the rollovers are sent, over AIR when configured (each to its own DID);
/// the FSP's never is.
#[cfg(feature = "http")]
pub fn rotation_sync(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: crate::Kind,
    base: &str,
) -> Result<Vec<String>, WalletError> {
    if !air.is_configured() {
        return crate::http::rotation_sync(wallet, kind, base);
    }
    match kind {
        crate::Kind::Psp => crate::http::rotation_sync_with(
            wallet,
            kind,
            base,
            &mut |w| psp_window(w, air, base),
            &mut |w, base, route, body| psp_post(w, air, base, route, body),
        ),
        crate::Kind::Esp => crate::http::rotation_sync_with(
            wallet,
            kind,
            base,
            &mut |w| esp_window(w, air, base),
            &mut |w, base, route, body| esp_post(w, air, base, route, body),
        ),
        crate::Kind::Fsp => crate::http::rotation_sync(wallet, kind, base),
    }
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

#[cfg(feature = "http")]
fn http_sync_esp_keysets(wallet: &mut Wallet, base: &str) -> Result<(), WalletError> {
    crate::http::sync_esp_keysets(wallet, base)
}

#[cfg(feature = "http")]
fn http_sync_esp_limits(wallet: &mut Wallet, base: &str) -> Result<(), WalletError> {
    crate::http::sync_esp_limits(wallet, base)
}

#[cfg(feature = "http")]
fn http_fetch_redeem_fees(base: &str) -> Result<RedeemFees, WalletError> {
    crate::http::fetch_redeem_fees(base)
}

#[cfg(feature = "http")]
fn http_send_exchange(
    base: &str,
    request: &ExchangeRequest,
) -> Result<ExchangeResponse, WalletError> {
    crate::http::send_exchange(base, request)
}

#[cfg(feature = "http")]
fn http_send_transfer(
    base: &str,
    request: &TransferRequest,
) -> Result<TransferResponse, WalletError> {
    crate::http::send_transfer(base, request)
}

#[cfg(feature = "http")]
fn http_send_redeem(base: &str, body: &[u8]) -> Result<RedeemResponse, WalletError> {
    crate::http::send_redeem(base, body)
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

#[cfg(not(feature = "http"))]
fn http_sync_esp_keysets(_: &mut Wallet, _: &str) -> Result<(), WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_sync_esp_limits(_: &mut Wallet, _: &str) -> Result<(), WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_fetch_redeem_fees(_: &str) -> Result<RedeemFees, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_send_exchange(_: &str, _: &ExchangeRequest) -> Result<ExchangeResponse, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_send_transfer(_: &str, _: &TransferRequest) -> Result<TransferResponse, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}

#[cfg(not(feature = "http"))]
fn http_send_redeem(_: &str, _: &[u8]) -> Result<RedeemResponse, WalletError> {
    Err(WalletError::NotBuilt(NO_HTTP))
}
