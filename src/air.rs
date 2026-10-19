//! The PSP's mint info over AIR: the wallet's side of the first call between a
//! wallet and a mint that does not go over HTTP. Feature `air`.
//!
//! The call is what `GET /health` reports (`wire_version` and `network`), which
//! `verify_mint` reads before anything else is sent to a mint. Over AIR the
//! wallet writes one small sealed request into a mailbox of the mint's DID on a
//! configured AIR server and waits for the mint's signed reply in a cell only it
//! and the mint can find. The protocol, the checks on the reply and the reasons
//! are `sp_wire::air_request` and REQUEST-DESIGN.md (sandbox-mint,
//! `air-sandbox/`); this module is the wallet's part around them:
//!
//! - **The request is kept in the wallet file** ([`PendingAirRequest`]) from
//!   before the first write until it ends: its `request_id` and one-off key `r`
//!   are all that is needed to read the reply, so a reply that arrives while the
//!   wallet is not looking is read on the next call, and no second request is
//!   written for it (the reply cell is read first).
//! - **Retries:** `air.attempts` tries (3) of `air.reply_wait_secs` (30) each,
//!   the same request every time, each try in the next free mailbox slot. Then
//!   "mint unreachable", and the request stays in the file; the next call
//!   resumes it.
//! - **A request ends** when it is answered and checked, or when a reply comes
//!   that fails a check (a write-once cell cannot be answered differently, so
//!   the request is dropped and the error says what was wrong). It does not
//!   end when the mint did not answer.
//! - **A kept request that is answered late is not trusted as current.** If the
//!   reply found is older than `air.max_skew_secs` the request is dropped and
//!   one new request is made in the same call: mint info is "how is the mint
//!   now", and a reply from hours ago says nothing about now.
//!
//! The call blocks (the wallet is blocking): the AIR client is async, so it runs
//! on a runtime built for the call, on a thread of its own, which also works
//! when the caller is inside another runtime.
//!
//! The mint's DID is the one in `air.psp_did`; the AIR server and its host are
//! configuration (upstream item 4 will resolve them from the DID). Over AIR,
//! only this one call changes: everything else the wallet sends the PSP is
//! still HTTP.

use sp_wire::air_request::VerifyError;
use sp_wire::air_request::addr;
use sp_wire::air_request::ask::{AskConfig, AskError, InFlight, Outcome, ask_mint_info};
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::version::WireMismatch;

use crate::Wallet;
use crate::config::AirSettings;
use crate::error::WalletError;
use crate::store::PendingAirRequest;

/// What one run of a request came to, when it did not fail.
enum Ended {
    /// Answered and checked.
    Verified,
    /// The reply was too old to be a statement about now (only a kept request
    /// can be): the request is dropped and a new one is made.
    Stale,
}

fn ask_config(air: &AirSettings, expected_network: &str) -> Result<AskConfig, WalletError> {
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
    let mint = air.psp_did.ok_or_else(|| missing("air.psp_did"))?;
    Ok(AskConfig {
        server: ServerRef {
            name: air.server.clone(),
            host: air.host.clone(),
        },
        mint,
        wire_version: sp_wire::WIRE_VERSION,
        network: expected_network.to_string(),
        reply_wait_secs: air.reply_wait_secs,
        attempts: air.attempts,
        max_skew_secs: air.max_skew_secs,
        timeout_secs: air.timeout_secs,
    })
}

fn pending_of(flight: &InFlight, cfg: &AskConfig, created_at: u64) -> PendingAirRequest {
    PendingAirRequest {
        request_id: hex::encode(flight.request_id),
        mint: cfg.mint.to_hex(),
        r: addr::secret_to_hex(&flight.r),
        slots: flight.slots.clone(),
        created_at,
    }
}

fn flight_of(pending: &PendingAirRequest) -> Result<InFlight, WalletError> {
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
        request_id,
        r,
        slots: pending.slots.clone(),
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
) -> Result<Outcome, AskError> {
    let mut save = |f: &InFlight| {
        wallet
            .save_air_request(pending_of(f, cfg, created_at))
            .map_err(|e| format!("the AIR request could not be saved to the wallet file: {e}"))
    };
    let client = client::connect(&cfg.server).await?;
    ask_mint_info(&client, cfg, flight, &mut save).await
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
    let result = {
        let (wallet, flight) = (&mut *wallet, &mut flight);
        block_on_new_runtime(move || run_async(wallet, cfg, flight, created_at))
            .map_err(|e| WalletError::Mint(format!("mint info over AIR: {}", e.0)))?
    };
    match result {
        Ok(_) => {
            wallet.end_air_request(&request_id)?;
            Ok(Ended::Verified)
        }
        Err(AskError::Verify(VerifyError::Stale { .. })) if resumed => {
            wallet.end_air_request(&request_id)?;
            Ok(Ended::Stale)
        }
        Err(AskError::Unreachable { attempts, secs }) => Err(WalletError::Mint(format!(
            "the PSP {} did not answer over AIR: no reply after {attempts} tries of {secs} s. The request is kept in the wallet file, and the next call carries on with it",
            cfg.mint.to_hex()
        ))),
        Err(AskError::Verify(e)) => {
            wallet.end_air_request(&request_id)?;
            Err(refusal(cfg, e))
        }
        Err(AskError::NotOpenable(e)) => {
            wallet.end_air_request(&request_id)?;
            Err(WalletError::Mint(format!(
                "the PSP's AIR reply cell does not hold a reply for this wallet: {e}. Nothing was sent"
            )))
        }
        Err(AskError::Other(e)) => Err(WalletError::Mint(format!("mint info over AIR: {e}"))),
    }
}

/// The wallet's error for a reply that failed a check: the same words and
/// kinds as the HTTP check for the two that `verify_mint` makes.
fn refusal(cfg: &AskConfig, e: VerifyError) -> WalletError {
    let mint = format!("the PSP {} (over AIR)", cfg.mint.to_hex());
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
        other => WalletError::Mint(format!(
            "{mint} sent a reply that was refused: {other}. Nothing was sent"
        )),
    }
}

/// Ask the PSP for its mint info over AIR and refuse if its wire version is not
/// this wallet's or its network is not `expected_network` (`main`, `regtest`,
/// `signet` or `testnet`), the checks `http::verify_mint` makes on `/health`.
/// The status the mint reports is not an error here either (a mint that is
/// unwell still reports its wire version and network).
///
/// Resumes a kept request for this PSP if there is one. Needs all of
/// `air.psp_did`, `air.server` and `air.host`.
pub fn verify_mint(
    wallet: &mut Wallet,
    air: &AirSettings,
    expected_network: &str,
) -> Result<(), WalletError> {
    let cfg = ask_config(air, expected_network)?;
    let mint = cfg.mint.to_hex();
    let kept = wallet
        .air_requests()
        .iter()
        .find(|r| r.mint == mint)
        .cloned();
    if let Some(pending) = kept {
        let flight = flight_of(&pending)?;
        match run_request(wallet, &cfg, flight, pending.created_at, true)? {
            Ended::Verified => return Ok(()),
            Ended::Stale => {} // fall through to a new request
        }
    }
    match run_request(wallet, &cfg, InFlight::new(), addr::now_secs(), false)? {
        Ended::Verified => Ok(()),
        // Only a kept request is ever dropped as stale.
        Ended::Stale => Err(WalletError::Mint(
            "mint info over AIR: the reply was dated too far from now".into(),
        )),
    }
}
