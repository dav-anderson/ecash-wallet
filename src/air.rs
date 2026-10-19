//! The PSP's calls over AIR: the wallet's side of the calls between a wallet and
//! a mint that do not go over HTTP. Feature `air`.
//!
//! The calls are **mint info** (what `GET /health` reports, `wire_version` and
//! `network`, which `verify_mint` reads before anything else is sent to a mint),
//! the PSP's **keys**, **keysets** and **rotation** (`GET /keys`, `/keysets`,
//! `/rotation`) and the PSP's **rollover** and **check-state** (`POST /rollover`,
//! `/check-state`), whose reply bodies are the JSON the HTTP routes return. Over
//! AIR the wallet writes one sealed request into a mailbox of the mint's DID on
//! a configured AIR server and waits for the mint's signed reply in a cell only
//! it and the mint can find. The protocol, the checks on the reply and the reasons
//! are `sp_wire::air_request` and REQUEST-DESIGN.md (sandbox-mint,
//! `air-sandbox/`, sections 14 and 15); this module is the wallet's part around
//! them:
//!
//! - **The request is kept in the wallet file** ([`PendingAirRequest`]) from
//!   before the first write until it ends: its `request_id` and one-off key `r`
//!   are all that is needed to read the reply, so a reply that arrives while the
//!   wallet is not looking is read on the next call, and no second request is
//!   written for it (the reply cell is read first).
//! - **Retries:** `air.attempts` tries (3) of `air.reply_wait_secs` (30) each,
//!   the same request every time, each try in the next free mailbox slot. Then
//!   "mint unreachable", and the request stays in the file; the next call of
//!   the same kind resumes it. A read is kept once per mint and kind; a call
//!   with a body (rollover, check-state) once per mint, kind and body (the
//!   SHA-256 of the body is kept with it), so a second rollover is never
//!   mistaken for the first.
//! - **A request ends** when it is answered and checked (an answer or a signed
//!   refusal), or when a reply comes that fails a check (a write-once cell
//!   cannot be answered differently, so the request is dropped and the error
//!   says what was wrong). It does not end when the mint did not answer.
//! - **A kept request that is answered late is not trusted as current.** If the
//!   reply found is older than `air.max_skew_secs` the request is dropped and
//!   one new request is made in the same call: each of these calls is "how is
//!   the mint now", and a reply from hours ago says nothing about now (above
//!   all keys: an old reply is how a mint's retired keys would come back). For
//!   a rollover the new request has the same body, and the mint answers it from
//!   its stored answer (rollovers are idempotent by request hash), so nothing
//!   is applied twice.
//! - **No caching**, like the HTTP calls they replace: every call asks again.
//!
//! The call blocks (the wallet is blocking): the AIR client is async, so it runs
//! on a runtime built for the call, on a thread of its own, which also works
//! when the caller is inside another runtime.
//!
//! The mint's DID is the SPI's: `air.psp_did` if set, else the built-in one
//! ([`crate::config::BUILTIN_SPI_DID`], a PLACEHOLDER until the first SPI
//! deploy); the AIR server and its host are configuration (upstream item 4
//! will resolve them from the DID). Over AIR, only these calls change:
//! everything else the wallet sends the PSP (`/melt`, `/burns`, `/audit`) is
//! still HTTP, and so is every call to the ESP and the FSPs.

use sp_wire::air_request::ask::{AskConfig, AskError, InFlight, Verified, ask};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::{
    KIND_CHECK_STATE, KIND_KEYS, KIND_KEYSETS, KIND_MINT_INFO, KIND_ROLLOVER, KIND_ROTATION,
    STATUS_UNAVAILABLE, VerifyError, addr, check_mint_info,
};
use sp_wire::version::WireMismatch;

use crate::Wallet;
use crate::config::AirSettings;
use crate::error::WalletError;
use crate::store::PendingAirRequest;

/// What one run of a request came to, when it did not fail.
enum Ended {
    /// Answered and checked.
    Verified(Verified),
    /// The reply was too old to be a statement about now (only a kept request
    /// can be): the request is dropped and a new one is made.
    Stale,
}

/// What a kind of request is called in messages.
fn what(kind: u8) -> &'static str {
    match kind {
        KIND_MINT_INFO => "mint info",
        KIND_KEYS => "keys",
        KIND_KEYSETS => "keysets",
        KIND_ROTATION => "rotation",
        KIND_ROLLOVER => "rollover",
        KIND_CHECK_STATE => "check-state",
        _ => "a request",
    }
}

/// The PSP's DID as messages name it: the hex, and, when it is the built-in
/// PLACEHOLDER, that fact, so that a failure never leaves the reader thinking a
/// real SPI was asked.
fn mint_label(mint_hex: &str) -> String {
    if mint_hex == crate::config::BUILTIN_SPI_DID {
        format!(
            "{mint_hex} (the built-in PLACEHOLDER SPI DID, not a real one: set air.psp_did to the SPI's DID)"
        )
    } else {
        mint_hex.to_string()
    }
}

/// The SHA-256 of a request body, hex; empty for no body, so the plain reads
/// (and a wallet file from before there were bodies) match each other.
fn body_hash(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    if body.is_empty() {
        String::new()
    } else {
        hex::encode(Sha256::digest(body))
    }
}

fn ask_config(air: &AirSettings) -> Result<AskConfig, WalletError> {
    let missing = |what: &str| {
        WalletError::Invalid(format!(
            "AIR is not configured for the PSP: {what} is not set"
        ))
    };
    if air.server.is_empty() {
        return Err(missing("air.server"));
    }
    if air.host.is_empty() {
        return Err(missing("air.host"));
    }
    let mint = air.psp_did();
    Ok(AskConfig {
        server: ServerRef {
            name: air.server.clone(),
            host: air.host.clone(),
        },
        mint,
        // Only `ask_mint_info` reads these two; `verify_mint` checks them itself.
        wire_version: sp_wire::WIRE_VERSION,
        network: String::new(),
        reply_wait_secs: air.reply_wait_secs,
        attempts: air.attempts,
        max_skew_secs: air.max_skew_secs,
        timeout_secs: air.timeout_secs,
    })
}

fn pending_of(flight: &InFlight, cfg: &AskConfig, created_at: u64) -> PendingAirRequest {
    PendingAirRequest {
        request_id: hex::encode(flight.request_id),
        kind: flight.kind,
        mint: cfg.mint.to_hex(),
        r: addr::secret_to_hex(&flight.r),
        slots: flight.slots.clone(),
        created_at,
        body_hash: body_hash(&flight.body),
    }
}

/// The request kept in `pending`, with the body of the call that is being made
/// again (the body is not kept in the file: the caller rebuilds it, and the
/// request was found by its hash).
fn flight_of(pending: &PendingAirRequest, body: &[u8]) -> Result<InFlight, WalletError> {
    let corrupt = |what: &str| {
        WalletError::Corrupt(format!(
            "an AIR request in the wallet file has {what} (request {})",
            pending.request_id
        ))
    };
    let request_id: [u8; 32] = hex::decode(&pending.request_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| corrupt("a request id that is not 64 hex characters"))?;
    let r = addr::secret_from_hex(&pending.r).map_err(|_| corrupt("a key that is not valid"))?;
    Ok(InFlight {
        kind: pending.kind,
        request_id,
        r,
        slots: pending.slots.clone(),
        body: body.to_vec(),
    })
}

/// The async part of one run: connect, then the shared flow of
/// `sp_wire::air_request::ask`, saving the request to the wallet file before the
/// first write and after each one.
async fn run_async(
    wallet: &mut Wallet,
    cfg: &AskConfig,
    flight: &mut InFlight,
    created_at: u64,
) -> Result<Verified, AskError> {
    let mut save = |f: &InFlight| {
        wallet
            .save_air_request(pending_of(f, cfg, created_at))
            .map_err(|e| format!("the AIR request could not be saved to the wallet file: {e}"))
    };
    let client = client::connect(&cfg.server).await?;
    ask(&client, cfg, flight, &mut save).await
}

/// Run one request to its end (or to "unreachable") and settle the wallet file.
/// `resumed` is true for a request kept from an earlier call.
fn run_request(
    wallet: &mut Wallet,
    cfg: &AskConfig,
    mut flight: InFlight,
    created_at: u64,
    resumed: bool,
) -> Result<Ended, WalletError> {
    let request_id = hex::encode(flight.request_id);
    let what = what(flight.kind);
    let result = {
        let (wallet, flight) = (&mut *wallet, &mut flight);
        block_on_new_runtime(move || run_async(wallet, cfg, flight, created_at))
            .map_err(|e| WalletError::Mint(format!("{what} over AIR: {}", e.0)))?
    };
    match result {
        Ok(verified) => {
            wallet.end_air_request(&request_id)?;
            Ok(Ended::Verified(verified))
        }
        Err(AskError::Verify(VerifyError::Stale { .. })) if resumed => {
            wallet.end_air_request(&request_id)?;
            Ok(Ended::Stale)
        }
        Err(AskError::Unreachable { attempts, secs }) => Err(WalletError::Mint(format!(
            "the PSP {} did not answer {what} over AIR: no reply after {attempts} tries of {secs} s. The request is kept in the wallet file, and the next call carries on with it",
            mint_label(&cfg.mint.to_hex())
        ))),
        Err(AskError::Verify(e)) => {
            wallet.end_air_request(&request_id)?;
            Err(refusal(&cfg.mint.to_hex(), what, e))
        }
        Err(AskError::NotOpenable(e)) => {
            wallet.end_air_request(&request_id)?;
            Err(WalletError::Mint(format!(
                "the PSP's AIR reply cell does not hold a reply for this wallet: {e}. Nothing was sent"
            )))
        }
        Err(AskError::Other(e)) => Err(WalletError::Mint(format!("{what} over AIR: {e}"))),
    }
}

/// The wallet's error for a reply that failed a check: the same words and
/// kinds as the HTTP check for the two that `verify_mint` makes.
fn refusal(mint_hex: &str, what: &str, e: VerifyError) -> WalletError {
    let mint = format!("the PSP {} (over AIR)", mint_label(mint_hex));
    match e {
        VerifyError::Network { theirs, ours } => WalletError::Invalid(format!(
            "{mint} is on {theirs}, but this wallet is on {ours}. Nothing was sent. Pass the flag for its network (--regtest, --signet, --testnet; none means mainnet) or use another mint"
        )),
        VerifyError::WireVersion { theirs, .. } => WalletError::Wire {
            url: mint,
            why: WireMismatch::Different {
                mint: u64::from(theirs),
                ours: sp_wire::WIRE_VERSION,
            },
        },
        VerifyError::Refused(STATUS_UNAVAILABLE) => WalletError::Mint(format!(
            "{mint} could not answer {what} now (it said so in a signed reply). Nothing was sent. Try again later"
        )),
        other => WalletError::Mint(format!(
            "{mint} sent a reply to {what} that was refused: {other}. Nothing was sent"
        )),
    }
}

/// Ask the PSP one of the read-only questions (`KIND_MINT_INFO`, `KIND_KEYS`,
/// `KIND_KEYSETS`, `KIND_ROTATION`) over AIR and return the verified reply: the
/// mint's signature, the request, the status and the age are checked; the body
/// is the mint's and is read by the caller ([`fetch`], [`verify_mint`]).
///
/// Resumes a kept request of this kind for this PSP if there is one. Needs
/// `air.server` and `air.host` (the DID is `air.psp_did` or the built-in one).
pub fn call(wallet: &mut Wallet, air: &AirSettings, kind: u8) -> Result<Verified, WalletError> {
    call_with_body(wallet, air, kind, &[])
}

/// [`call`] for a request with a body (`KIND_ROLLOVER`, `KIND_CHECK_STATE`):
/// resumes a kept request of this kind **and this body** for this PSP if there
/// is one, so the same call made again carries on with the same request id and
/// key (and a different call never takes its place). A reply that is a signed
/// refusal is returned like an answer: [`Verified::refused`] says which.
pub fn call_with_body(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: u8,
    body: &[u8],
) -> Result<Verified, WalletError> {
    let cfg = ask_config(air)?;
    let mint = cfg.mint.to_hex();
    let hash = body_hash(body);
    let kept = wallet
        .air_requests()
        .iter()
        .find(|r| r.mint == mint && r.kind == kind && r.body_hash == hash)
        .cloned();
    if let Some(pending) = kept {
        let flight = flight_of(&pending, body)?;
        match run_request(wallet, &cfg, flight, pending.created_at, true)? {
            Ended::Verified(v) => return Ok(v),
            Ended::Stale => {} // fall through to a new request
        }
    }
    let flight = InFlight::with_body(kind, body.to_vec());
    match run_request(wallet, &cfg, flight, addr::now_secs(), false)? {
        Ended::Verified(v) => Ok(v),
        // Only a kept request is ever dropped as stale.
        Ended::Stale => Err(WalletError::Mint(format!(
            "{} over AIR: the reply was dated too far from now",
            what(kind)
        ))),
    }
}

/// The wallet's side of `POST /rollover` and `POST /check-state` over AIR (the
/// PSP's, `kind` `KIND_ROLLOVER` or `KIND_CHECK_STATE`): `body` is the request
/// JSON the HTTP call would post, and the answer is the mint's answer JSON.
/// A signed refusal is the wallet's error for the HTTP `400` of the same
/// meaning ([`crate::error::mint_refusal`]: `Refused`, or `SpentElsewhere` with
/// the notes), and `request_too_large` is a plain mint error, as the HTTP `413`
/// is, so everything that handles a refusal handles this one.
pub fn post(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: u8,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    let verified = call_with_body(wallet, air, kind, body)?;
    let mint = mint_label(&air.psp_did().to_hex());
    if verified.refused() {
        return Err(refused_by_mint(verified.body(), what(kind), &mint));
    }
    serde_json::from_slice(verified.body()).map_err(|e| {
        WalletError::Mint(format!(
            "{} over AIR: the PSP {mint} signed a reply that is not what was asked for: {e}",
            what(kind)
        ))
    })
}

/// The wallet's error for a signed refusal: the body is the JSON the HTTP route
/// answers its `4xx` with.
fn refused_by_mint(body: &[u8], what: &str, mint: &str) -> WalletError {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let code = value["code"].as_str().unwrap_or("").to_string();
    let why = value["error"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    if code == sp_wire::codes::REQUEST_TOO_LARGE {
        // The HTTP 413: not the mint refusing the notes, so nothing is cancelled.
        return WalletError::Mint(format!(
            "the PSP {mint} (over AIR) refused {what}: {code}: {why}"
        ));
    }
    crate::error::mint_refusal(&value, &code, &why)
}

/// [`call`], with the body read as JSON of type `T`: the type the HTTP call
/// reads. A signed body that is not that type is the mint's own fault and is
/// refused as such.
pub fn fetch<T: serde::de::DeserializeOwned>(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: u8,
) -> Result<T, WalletError> {
    let verified = call(wallet, air, kind)?;
    verified.json().map_err(|e| {
        WalletError::Mint(format!(
            "{} over AIR: the PSP signed a reply that is not what was asked for: {e}",
            what(kind)
        ))
    })
}

/// Ask the PSP for its mint info over AIR and refuse if its wire version is not
/// this wallet's or its network is not `expected_network` (`main`, `regtest`,
/// `signet` or `testnet`), the checks `http::verify_mint` makes on `/health`.
/// The status the mint reports is not an error here either (a mint that is
/// unwell still reports its wire version and network).
///
/// Resumes a kept request for this PSP if there is one. Needs `air.server` and
/// `air.host` (the DID is `air.psp_did` or the built-in one).
pub fn verify_mint(
    wallet: &mut Wallet,
    air: &AirSettings,
    expected_network: &str,
) -> Result<(), WalletError> {
    let verified = call(wallet, air, KIND_MINT_INFO)?;
    let mint = air.psp_did().to_hex();
    check_mint_info(verified.body(), sp_wire::WIRE_VERSION, expected_network)
        .map(|_| ())
        .map_err(|e| refusal(&mint, what(KIND_MINT_INFO), e))
}
