//! The wallet's calls to the mints, over HTTP. This is the only part of the
//! library that uses the network, and an app can leave it out (the `http`
//! feature) and send the requests its own way.
//!
//! The client is blocking, so do not call these on an async thread.

use std::collections::BTreeMap;
use std::time::Duration;

use esp_mint::exchange::{ExchangeRequest, ExchangeResponse};
use mint_server::api::KeysResponse;
use mint_types::Amount;
use secp256k1::PublicKey;

use crate::error::WalletError;

fn client() -> Result<reqwest::blocking::Client, WalletError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| WalletError::Mint(format!("could not make an HTTP client: {e}")))
}

/// The PSP's public key for each note size (`GET /keys`).
pub fn fetch_psp_keys(base: &str) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let url = format!("{}/keys", base.trim_end_matches('/'));
    let response = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Mint(format!("{url} returned {}", response.status())));
    }
    let keys: KeysResponse = response
        .json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    Ok(keys.keys)
}

/// Send an exchange to the ESP mint (`POST /exchange`).
///
/// A `400` is [`WalletError::Refused`]: nothing was burned, and the pending
/// exchange can be cancelled. Anything else that goes wrong is
/// [`WalletError::Mint`], where the outcome may be unknown. Send the same request
/// again, because the mint stores its answers by request hash.
pub fn send_exchange(base: &str, request: &ExchangeRequest) -> Result<ExchangeResponse, WalletError> {
    let url = format!("{}/exchange", base.trim_end_matches('/'));
    let response = client()?
        .post(&url)
        .json(request)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let status = response.status();
    if status.is_success() {
        return response
            .json()
            .map_err(|e| WalletError::Mint(format!("{url}: unreadable reply: {e}")));
    }
    let text = response.text().unwrap_or_default();
    if status.as_u16() == 400 {
        return Err(WalletError::Refused(text));
    }
    Err(WalletError::Mint(format!("{url} returned {status}: {text}")))
}
