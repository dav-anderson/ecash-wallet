//! The PSP's and the ESP's calls over AIR: the wallet's side of the calls
//! between a wallet and a mint that do not go over HTTP. Feature `air`.
//!
//! The PSP's calls are **mint info** (what `GET /health` reports, `wire_version`
//! and `network`, which `verify_mint` reads before anything else is sent to a
//! mint), **keys**, **keysets** and **rotation** (`GET /keys`, `/keysets`,
//! `/rotation`) and **rollover** and **check-state** (`POST /rollover`,
//! `/check-state`). The ESP's are mint info, **keysets**, **rotation**, **fees**
//! (`GET /fees`), **rollover**, **exchange**, **transfer** and **redeem**
//! (`POST /rollover`, `/exchange`, `/transfer`, `/redeem`); the ESP has no
//! `GET /keys` (the keys arrive in the replies), and its `GET /audit` is the
//! operator's. The reply bodies are the JSON (for a redemption, the request
//! body is the binary encoding) the HTTP routes return. Over AIR the wallet
//! writes one sealed request into a mailbox of the mint's DID on a configured
//! AIR server and waits for the mint's signed reply in a cell only it and the
//! mint can find. The protocol, the checks on the reply and the reasons are
//! `sp_wire::air_request` and REQUEST-DESIGN.md (sandbox-mint, `air-sandbox/`,
//! sections 14 to 16); this module is the wallet's part around them:
//!
//! - **A kind names a call, not a mint.** The same kind goes to the PSP's DID or
//!   the ESP's, and each answers in its own shape. [`Party`] says which mint a
//!   call is for: its DID (`air.psp_did` or `air.esp_did`, else the built-in
//!   PLACEHOLDER), and the words of its messages.
//! - **The request is kept in the wallet file** ([`PendingAirRequest`]) from
//!   before the first write until it ends: its `request_id` and one-off key `r`
//!   are all that is needed to read the reply, so a reply that arrives while the
//!   wallet is not looking is read on the next call, and no second request is
//!   written for it (the reply cell is read first).
//! - **Retries:** `air.attempts` tries (3) of `air.reply_wait_secs` (30) each,
//!   the same request every time, each try in the next free mailbox slot. Then
//!   "mint unreachable", and the request stays in the file; the next call of
//!   the same kind resumes it. A read is kept once per mint and kind; a call
//!   with a body (rollover, check-state, exchange, transfer, redeem) once per
//!   mint, kind and body (the SHA-256 of the body is kept with it), so a second
//!   rollover is never mistaken for the first. The PSP and the ESP are two
//!   mints, so their requests never meet, even for the same kind.
//! - **A request ends** when it is answered and checked (an answer or a signed
//!   refusal), or when a reply comes that fails a check (a write-once cell
//!   cannot be answered differently, so the request is dropped and the error
//!   says what was wrong). It does not end when the mint did not answer.
//! - **A kept request that is answered late is not trusted as current.** If the
//!   reply found is older than `air.max_skew_secs` the request is dropped and
//!   one new request is made in the same call: each of these calls is "how is
//!   the mint now", and a reply from hours ago says nothing about now (above
//!   all keys: an old reply is how a mint's retired keys would come back). For
//!   a call with a body the new request has the same body, and the mint answers
//!   it from its stored answer (rollovers, exchanges, transfers and redemptions
//!   are idempotent by request hash), so nothing is applied twice.
//! - **Refusals map as the HTTP statuses do.** A signed `refused` reply is the
//!   route's `4xx` JSON. A `400` has the body as it is, and the wallet reads it
//!   as it reads the HTTP `400` ([`crate::error::mint_refusal`], or for the
//!   ESP's exchange, transfer and redeem the refusal readers of
//!   [`crate::esp_replies`]): the notes were not accepted, and a pending
//!   exchange may be cancelled. **Any other `4xx` carries `"http_status": N`**
//!   (`404` for the ESP's rotation on a mint that does not rotate, `409
//!   in_progress`, `413 request_too_large`) and is a plain [`WalletError::Mint`],
//!   as the HTTP status is, never a refusal of the notes: a refusal cancels
//!   work and frees notes, and a `409` must not. A signed `unavailable` (the
//!   mint's `5xx`, its PSP unreachable included) is a [`WalletError::Mint`] too,
//!   and a retry is safe.
//! - **No caching**, like the HTTP calls they replace: every call asks again.
//!
//! The call blocks (the wallet is blocking): the AIR client is async, so it runs
//! on a runtime built for the call, on a thread of its own, which also works
//! when the caller is inside another runtime.
//!
//! The mints' DIDs: `air.psp_did` and `air.esp_did` if set, else the built-in
//! ones ([`crate::config::BUILTIN_SPI_DID`], [`crate::config::BUILTIN_ESP_DID`],
//! PLACEHOLDERS until the first SPI deploy); the AIR server and its host are
//! configuration (upstream item 4 will resolve them from the DID) and are the
//! same for both mints. Over AIR, only these calls change: everything else the
//! wallet sends the PSP (`/melt`, `/burns`, `/audit`) or the ESP (`/audit`) is
//! still HTTP, and so is every call to the FSPs.

use sp_wire::air_request::ask::{AskConfig, AskError, InFlight, Verified, ask};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::{
    KIND_CHECK_STATE, KIND_EXCHANGE, KIND_FEES, KIND_KEYS, KIND_KEYSETS, KIND_MINT_INFO,
    KIND_REDEEM, KIND_ROLLOVER, KIND_ROTATION, KIND_TRANSFER, STATUS_UNAVAILABLE, VerifyError,
    addr, check_mint_info,
};
use sp_wire::version::WireMismatch;

use crate::Wallet;
use crate::config::AirSettings;
pub use crate::config::Party;
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
        KIND_FEES => "fees",
        KIND_EXCHANGE => "exchange",
        KIND_TRANSFER => "transfer",
        KIND_REDEEM => "redemption",
        _ => "a request",
    }
}

/// True for the calls that change the mint's state: when the mint cannot answer
/// one of these it may have applied it, so "nothing was sent" is not said.
fn changes_state(kind: u8) -> bool {
    matches!(
        kind,
        KIND_ROLLOVER | KIND_EXCHANGE | KIND_TRANSFER | KIND_REDEEM
    )
}

/// A mint's DID as messages name it: the hex, and, when it is the built-in
/// PLACEHOLDER of that party, that fact, so that a failure never leaves the
/// reader thinking a real mint was asked.
fn mint_label(party: Party, mint_hex: &str) -> String {
    if mint_hex == party.builtin() {
        format!(
            "{mint_hex} (the built-in PLACEHOLDER {} DID, not a real one: set {} to the mint's DID)",
            party.name(),
            party.setting()
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

fn ask_config(air: &AirSettings, party: Party) -> Result<AskConfig, WalletError> {
    let missing = |what: &str| {
        WalletError::Invalid(format!(
            "AIR is not configured for the {}: {what} is not set",
            party.name()
        ))
    };
    if air.server.is_empty() {
        return Err(missing("air.server"));
    }
    if air.host.is_empty() {
        return Err(missing("air.host"));
    }
    let mint = party.did(air);
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
    party: Party,
    mut flight: InFlight,
    created_at: u64,
    resumed: bool,
) -> Result<Ended, WalletError> {
    let request_id = hex::encode(flight.request_id);
    let kind = flight.kind;
    let what = what(kind);
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
            "the {} {} did not answer {what} over AIR: no reply after {attempts} tries of {secs} s. The request is kept in the wallet file, and the next call carries on with it",
            party.name(),
            mint_label(party, &cfg.mint.to_hex())
        ))),
        Err(AskError::Verify(e)) => {
            wallet.end_air_request(&request_id)?;
            Err(refusal(party, &cfg.mint.to_hex(), kind, e))
        }
        Err(AskError::NotOpenable(e)) => {
            wallet.end_air_request(&request_id)?;
            Err(WalletError::Mint(format!(
                "the {}'s AIR reply cell does not hold a reply for this wallet: {e}. {}",
                party.name(),
                if changes_state(kind) {
                    "Send the same request again"
                } else {
                    "Nothing was sent"
                }
            )))
        }
        Err(AskError::Other(e)) => Err(WalletError::Mint(format!("{what} over AIR: {e}"))),
    }
}

/// The wallet's error for a reply that failed a check: the same words and
/// kinds as the HTTP check for the two that `verify_mint` makes.
fn refusal(party: Party, mint_hex: &str, kind: u8, e: VerifyError) -> WalletError {
    let what = what(kind);
    let mint = format!(
        "the {} {} (over AIR)",
        party.name(),
        mint_label(party, mint_hex)
    );
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
        VerifyError::Refused(STATUS_UNAVAILABLE) if changes_state(kind) => {
            WalletError::Mint(format!(
                "{mint} could not answer {what} now (it said so in a signed reply). It may or may not have applied it. Send the same request again: the mint answers a repeated request from its stored answer, so nothing is applied twice"
            ))
        }
        VerifyError::Refused(STATUS_UNAVAILABLE) => WalletError::Mint(format!(
            "{mint} could not answer {what} now (it said so in a signed reply). Nothing was sent. Try again later"
        )),
        other => WalletError::Mint(format!(
            "{mint} sent a reply to {what} that was refused: {other}. {}",
            if changes_state(kind) {
                "The request may or may not have been applied: send it again"
            } else {
                "Nothing was sent"
            }
        )),
    }
}

/// Ask a mint one of the read-only questions (`KIND_MINT_INFO`, `KIND_KEYS`,
/// `KIND_KEYSETS`, `KIND_ROTATION`, `KIND_FEES`) over AIR and return the
/// verified reply: the mint's signature, the request, the status and the age are
/// checked; the body is the mint's and is read by the caller ([`fetch`],
/// [`verify_mint`]).
///
/// Resumes a kept request of this kind for this mint if there is one. Needs
/// `air.server` and `air.host` (the DID is the party's: `air.psp_did` or
/// `air.esp_did`, else the built-in one).
pub fn call(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
) -> Result<Verified, WalletError> {
    call_with_body(wallet, air, party, kind, &[])
}

/// [`call`] for a request with a body (`KIND_ROLLOVER`, `KIND_CHECK_STATE`, and
/// the ESP's `KIND_EXCHANGE`, `KIND_TRANSFER`, `KIND_REDEEM`): resumes a kept
/// request of this kind **and this body** for this mint if there is one, so the
/// same call made again carries on with the same request id and key (and a
/// different call never takes its place). A reply that is a signed refusal is
/// returned like an answer: [`Verified::refused`] says which.
pub fn call_with_body(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
    body: &[u8],
) -> Result<Verified, WalletError> {
    let cfg = ask_config(air, party)?;
    let mint = cfg.mint.to_hex();
    let hash = body_hash(body);
    let kept = wallet
        .air_requests()
        .iter()
        .find(|r| r.mint == mint && r.kind == kind && r.body_hash == hash)
        .cloned();
    if let Some(pending) = kept {
        let flight = flight_of(&pending, body)?;
        match run_request(wallet, &cfg, party, flight, pending.created_at, true)? {
            Ended::Verified(v) => return Ok(v),
            Ended::Stale => {} // fall through to a new request
        }
    }
    let flight = InFlight::with_body(kind, body.to_vec());
    match run_request(wallet, &cfg, party, flight, addr::now_secs(), false)? {
        Ended::Verified(v) => Ok(v),
        // Only a kept request is ever dropped as stale.
        Ended::Stale => Err(WalletError::Mint(format!(
            "{} over AIR: the reply was dated too far from now",
            what(kind)
        ))),
    }
}

/// A mint's reply to a call with a body, with the HTTP status it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    /// True for a signed refusal (a `4xx` over HTTP).
    pub refused: bool,
    /// The HTTP status it stands for: `200` for an answer; for a refusal the
    /// `http_status` the mint added (`404`, `409`, `413`), else `400`.
    pub status: u16,
    /// The body: the route's JSON, or for a refusal the route's JSON of the
    /// refusal (with `http_status`, when there is one).
    pub body: Vec<u8>,
}

impl Answered {
    /// The body as text, for the readers that take the HTTP body's text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The reason a refusal gives: its `error` field, else the whole body.
    pub fn why(&self) -> String {
        serde_json::from_slice::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or_else(|| self.text())
    }

    /// The wallet's error for a refusal that is not a `400`, and so does not mean
    /// "the mint did not take the notes": a plain mint error with the status, as
    /// the HTTP call's is.
    pub fn status_error(&self, party: Party, mint_hex: &str, kind: u8) -> WalletError {
        WalletError::Mint(format!(
            "the {} {} (over AIR) answered {} with {}: {}",
            party.name(),
            mint_label(party, mint_hex),
            what(kind),
            self.status,
            self.why()
        ))
    }
}

/// [`call_with_body`], with the reply read as the HTTP status it stands for.
pub fn answer(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
    body: &[u8],
) -> Result<Answered, WalletError> {
    let verified = call_with_body(wallet, air, party, kind, body)?;
    if !verified.refused() {
        return Ok(Answered {
            refused: false,
            status: 200,
            body: verified.body().to_vec(),
        });
    }
    let status = serde_json::from_slice::<serde_json::Value>(verified.body())
        .ok()
        .and_then(|v| v["http_status"].as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(400);
    Ok(Answered {
        refused: true,
        status,
        body: verified.body().to_vec(),
    })
}

/// The wallet's side of a POST over AIR whose answer is JSON (the rollover and
/// check-state of the PSP, the rollover of the ESP): `body` is the request JSON
/// the HTTP call would post, and the result is the mint's answer JSON. A signed
/// `400` is the wallet's error for the HTTP `400` of the same meaning
/// ([`crate::error::mint_refusal`]: `Refused`, or `SpentElsewhere` with the
/// notes); every other refusal (`request_too_large`, `409`, `404`) is a plain
/// mint error, as the HTTP status is, so everything that handles a refusal
/// handles this one.
pub fn post(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    let answered = answer(wallet, air, party, kind, body)?;
    let mint_hex = party.did(air).to_hex();
    if answered.refused {
        return Err(refused_by_mint(party, &mint_hex, kind, &answered));
    }
    serde_json::from_slice(&answered.body).map_err(|e| {
        WalletError::Mint(format!(
            "{} over AIR: the {} {} signed a reply that is not what was asked for: {e}",
            what(kind),
            party.name(),
            mint_label(party, &mint_hex)
        ))
    })
}

/// The wallet's error for a signed refusal: the body is the JSON the HTTP route
/// answers its `4xx` with.
fn refused_by_mint(party: Party, mint_hex: &str, kind: u8, answered: &Answered) -> WalletError {
    let value: serde_json::Value = serde_json::from_slice(&answered.body).unwrap_or_default();
    let code = value["code"].as_str().unwrap_or("").to_string();
    if answered.status != 400 || code == sp_wire::codes::REQUEST_TOO_LARGE {
        // Not the mint refusing the notes (an HTTP 404, 409 or 413): nothing is
        // cancelled. (psp-mint's 413 carries no `http_status`, so its code says.)
        return answered.status_error(party, mint_hex, kind);
    }
    crate::error::mint_refusal(&value, &code, &answered.why())
}

/// [`call`], with the body read as JSON of type `T`: the type the HTTP call
/// reads. A refusal (the `404` of the ESP's rotation on a mint that does not
/// rotate, say) is an error with its status, as over HTTP, and a signed body
/// that is not that type is the mint's own fault and is refused as such.
pub fn fetch<T: serde::de::DeserializeOwned>(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
) -> Result<T, WalletError> {
    let answered = answer(wallet, air, party, kind, &[])?;
    let mint_hex = party.did(air).to_hex();
    if answered.refused {
        return Err(answered.status_error(party, &mint_hex, kind));
    }
    serde_json::from_slice(&answered.body).map_err(|e| {
        WalletError::Mint(format!(
            "{} over AIR: the {} {} signed a reply that is not what was asked for: {e}",
            what(kind),
            party.name(),
            mint_label(party, &mint_hex)
        ))
    })
}

/// [`fetch`], for a body the caller reads itself: its text. Used for the ESP's
/// `GET /fees`, which the HTTP functions read from text too.
pub fn fetch_text(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    kind: u8,
) -> Result<String, WalletError> {
    let answered = answer(wallet, air, party, kind, &[])?;
    if answered.refused {
        let mint_hex = party.did(air).to_hex();
        return Err(answered.status_error(party, &mint_hex, kind));
    }
    Ok(answered.text())
}

/// The ESP's exchange, transfer and redemption over AIR: `body` is what the HTTP
/// call posts (JSON, or for the redemption the canonical binary encoding), and
/// the result is the answer read as `R`. A refusal whose HTTP status is in
/// `refusal_statuses` (the `400` of the exchange and the transfer; the `400` and
/// the `413` of the redemption) is read by `refusal` from the body's text, the
/// same reader the HTTP call uses, so that a refusal is the same
/// [`WalletError`] both ways; any other refusal (`409 in_progress`, say) is a
/// plain mint error with its status, never a refusal of the notes.
pub fn send_esp<R: serde::de::DeserializeOwned>(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: u8,
    body: &[u8],
    refusal: &dyn Fn(&str) -> WalletError,
    refusal_statuses: &[u16],
) -> Result<R, WalletError> {
    let party = Party::Esp;
    let answered = answer(wallet, air, party, kind, body)?;
    let mint_hex = party.did(air).to_hex();
    if answered.refused {
        if refusal_statuses.contains(&answered.status) {
            return Err(refusal(&answered.text()));
        }
        return Err(answered.status_error(party, &mint_hex, kind));
    }
    serde_json::from_slice(&answered.body).map_err(|e| {
        WalletError::Mint(format!(
            "{} over AIR: the {} {} signed a reply that is not what was asked for: {e}",
            what(kind),
            party.name(),
            mint_label(party, &mint_hex)
        ))
    })
}

/// Ask a mint for its mint info over AIR and refuse if its wire version is not
/// this wallet's or its network is not `expected_network` (`main`, `regtest`,
/// `signet` or `testnet`), the checks `http::verify_mint` makes on `/health`.
/// The status the mint reports is not an error here either (a mint that is
/// unwell still reports its wire version and network).
///
/// Resumes a kept request for this mint if there is one. Needs `air.server` and
/// `air.host` (the DID is the party's, or the built-in one).
pub fn verify_mint(
    wallet: &mut Wallet,
    air: &AirSettings,
    party: Party,
    expected_network: &str,
) -> Result<(), WalletError> {
    let verified = call(wallet, air, party, KIND_MINT_INFO)?;
    let mint = party.did(air).to_hex();
    check_mint_info(verified.body(), sp_wire::WIRE_VERSION, expected_network)
        .map(|_| ())
        .map_err(|e| refusal(party, &mint, KIND_MINT_INFO, e))
}
