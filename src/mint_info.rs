//! The wallet's calls to the PSP, the ESP and the FSP mints. They are made over
//! AIR and only over AIR: there is no HTTP form of any of them. This is the one place that
//! says which call goes to which mint, so the library's callers (the command
//! line, an app, the tests) all get the same rule.
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
//! has no keys call (its keys arrive in the replies).
//!
//! **An FSP mint's** are its mint info ([`verify_fsp`]), keys ([`fsp_keys`]),
//! rotation ([`fsp_rotation`], [`fsp_window`]), fees ([`fsp_fees`]) and its two
//! POSTs, issue and spend ([`send_fsp_issue`], [`send_fsp_spend`]), and the calls
//! built on them: [`settle_fsp`] and [`fsp_sync`]. An FSP mint is a service's own:
//! its DID is the service's, and the AIR server it is reached through is the
//! service's `air.fsp` entry.
//!
//! **The PSP's and the ESP's need `air.server` and `air.host`**
//! ([`AirSettings::require`]; the DIDs are `air.psp_did` and `air.esp_did`, or the
//! built-in ones, PLACEHOLDERS until the first SPI deploy). **An FSP mint's need
//! the `air.fsp` entry of its service** ([`AirSettings::fsp_for`]). A call made
//! without them fails with an error that names the missing setting. The PSP and
//! the ESP share the AIR server and have their own DIDs. The wallet makes no HTTP
//! call. Nothing is cached here: every call asks again.
//!
//! **`base` names a mint in the wallet's records** (its live keysets, its swap
//! times, the mint a handoff names); it is never dialled. The PSP and the ESP are
//! each one mint, found by their DID, so a record of either is found by its
//! kind. An FSP mint's record is the service's DID in hex.

use std::collections::BTreeMap;

use mint_types::Amount;
use secp256k1::PublicKey;
use sp_wire::ServiceDid;
use sp_wire::air_request::{
    KIND_CHECK_STATE, KIND_EXCHANGE, KIND_FEES, KIND_FSP_ISSUE, KIND_FSP_SPEND, KIND_KEYS,
    KIND_KEYSETS, KIND_REDEEM, KIND_ROLLOVER, KIND_ROTATION, KIND_TRANSFER,
};
use sp_wire::esp::exchange::{ExchangeRequest, ExchangeResponse};
use sp_wire::esp::redeem::RedeemResponse;
use sp_wire::esp::transfer::{TransferRequest, TransferResponse};
use sp_wire::keys::{CheckStateRequest, CheckStateResponse};

use crate::Wallet;
use crate::config::{AirSettings, Party};
use crate::error::WalletError;
use crate::redeem::RedeemFees;
use crate::rotate::Window;
use crate::store::Kind;

/// Check the PSP's wire version and network before anything else is sent to it,
/// over AIR (to the PSP's DID: `air.psp_did`, or the built-in one).
/// `expected_network` is `main`, `regtest`, `signet` or `testnet`.
pub fn verify_psp(
    wallet: &mut Wallet,
    air: &AirSettings,
    expected_network: &str,
) -> Result<(), WalletError> {
    crate::air::verify_mint(wallet, air, Party::Psp, expected_network)
}

/// Check the ESP's wire version and network before anything else is sent to it,
/// over AIR (to the ESP's own DID: `air.esp_did`, or the built-in one).
pub fn verify_esp(
    wallet: &mut Wallet,
    air: &AirSettings,
    expected_network: &str,
) -> Result<(), WalletError> {
    crate::air::verify_mint(wallet, air, Party::Esp, expected_network)
}

// ---------------------------------------------------------------- the PSP

/// The PSP's public key for each note size: a signed reply over AIR.
pub fn psp_keys(
    wallet: &mut Wallet,
    air: &AirSettings,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let reply: sp_wire::keys::KeysResponse = crate::air::fetch(wallet, air, Party::Psp, KIND_KEYS)?;
    Ok(reply.keys)
}

/// The PSP's live keysets.
pub fn psp_keysets(
    wallet: &mut Wallet,
    air: &AirSettings,
) -> Result<sp_wire::psp::KeysetsResponse, WalletError> {
    crate::air::fetch(wallet, air, Party::Psp, KIND_KEYSETS)
}

/// The PSP's rotation window.
pub fn psp_window(wallet: &mut Wallet, air: &AirSettings) -> Result<Window, WalletError> {
    let reply: sp_wire::fsp::RotationResponse =
        crate::air::fetch(wallet, air, Party::Psp, KIND_ROTATION)?;
    Ok(reply.into())
}

/// Read the PSP's largest note size from its keys (the highest amount it has a
/// key for) and give it to the wallet, so no cap is written into the wallet.
pub fn sync_psp_limits(wallet: &mut Wallet, air: &AirSettings) -> Result<(), WalletError> {
    let keys = psp_keys(wallet, air)?;
    wallet.set_psp_max_denomination(keys.keys().map(|a| a.units).max());
    Ok(())
}

/// The keys to unblind a PSP settlement's signatures with (see
/// [`crate::psp::claim_keys_with`]).
pub fn psp_claim_keys(
    wallet: &mut Wallet,
    air: &AirSettings,
    settlement_text: &str,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let wallet = std::cell::RefCell::new(wallet);
    crate::psp::claim_keys_with(
        settlement_text,
        || {
            let reply: sp_wire::keys::KeysResponse =
                crate::air::fetch(&mut wallet.borrow_mut(), air, Party::Psp, KIND_KEYS)?;
            Ok(reply.keys)
        },
        || crate::air::fetch(&mut wallet.borrow_mut(), air, Party::Psp, KIND_KEYSETS),
    )
}

/// A POST to the PSP: `route` is `rollover` or `check-state`, `body` the request
/// JSON. A sealed request, a signed reply, and a refusal that maps to the `400`
/// of the same meaning ([`WalletError::Refused`], or
/// [`WalletError::SpentElsewhere`] with the notes).
pub fn psp_post(
    wallet: &mut Wallet,
    air: &AirSettings,
    route: &str,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    let kind = match route {
        "rollover" => KIND_ROLLOVER,
        "check-state" => KIND_CHECK_STATE,
        other => {
            return Err(WalletError::Invalid(format!(
                "`{other}` is not a call the PSP takes (only rollover and check-state are)"
            )));
        }
    };
    crate::air::post(wallet, air, Party::Psp, kind, body)
}

// ---------------------------------------------------------------- the ESP

/// The ESP mint's live keyset IDs, remembered in the wallet under `base` (new
/// outputs name the current one, and notes from before keysets were recorded
/// fall back to them).
pub fn sync_esp_keysets(
    wallet: &mut Wallet,
    air: &AirSettings,
    base: &str,
) -> Result<(), WalletError> {
    let v: serde_json::Value = crate::air::fetch(wallet, air, Party::Esp, KIND_KEYSETS)?;
    let current = v["current"]
        .as_str()
        .ok_or_else(|| WalletError::Mint("keysets over AIR: no current keyset".into()))?;
    wallet.note_esp_keysets(base, current, v["previous"].as_str())
}

/// The ESP mint's note limits, given to the wallet (see
/// [`crate::store::EspLimits`]), so no limit is written into the wallet.
pub fn sync_esp_limits(wallet: &mut Wallet, air: &AirSettings) -> Result<(), WalletError> {
    let text = crate::air::fetch_text(wallet, air, Party::Esp, KIND_FEES)?;
    let limits = crate::esp_replies::parse_esp_limits(&text)
        .map_err(|why| WalletError::Mint(format!("fees over AIR: {why}")))?;
    wallet.set_esp_limits(limits);
    Ok(())
}

/// The ESP mint's redemption fee rate and ceilings (the `redeem` part of its
/// fees).
pub fn fetch_redeem_fees(
    wallet: &mut Wallet,
    air: &AirSettings,
) -> Result<RedeemFees, WalletError> {
    let text = crate::air::fetch_text(wallet, air, Party::Esp, KIND_FEES)?;
    crate::esp_replies::parse_redeem_fees(&text)
        .map_err(|why| WalletError::Mint(format!("fees over AIR: {why}")))
}

/// The ESP's rotation window. A mint that does not rotate answers with a signed
/// refusal that says `404`: an error.
pub fn esp_window(wallet: &mut Wallet, air: &AirSettings) -> Result<Window, WalletError> {
    let reply: sp_wire::fsp::RotationResponse =
        crate::air::fetch(wallet, air, Party::Esp, KIND_ROTATION)?;
    Ok(reply.into())
}

/// A POST to the ESP: `route` is `rollover` (the one a rotation sync makes),
/// `body` the request JSON.
pub fn esp_post(
    wallet: &mut Wallet,
    air: &AirSettings,
    route: &str,
    body: &[u8],
) -> Result<serde_json::Value, WalletError> {
    match route {
        "rollover" => crate::air::post(wallet, air, Party::Esp, KIND_ROLLOVER, body),
        other => Err(WalletError::Invalid(format!(
            "`{other}` is not a call a rotation sync makes of the ESP (only rollover is)"
        ))),
    }
}

/// Send an exchange to the ESP mint (a sealed request, the JSON body, a signed
/// reply).
///
/// A `400` (a signed refusal without an `http_status`) is
/// [`WalletError::Refused`], or [`WalletError::SpentElsewhere`] with the PSP
/// notes the mint names: nothing was burned, and the pending exchange can be
/// cancelled. Anything else that goes wrong is [`WalletError::Mint`], where the
/// outcome may be unknown: a refusal that says `"http_status": 409` (in
/// progress), a signed "unavailable" (the mint's `5xx`, the `502` of a PSP that
/// could not be reached included), no reply. Send the same request again: the
/// mint stores its answers by request hash.
pub fn send_exchange(
    wallet: &mut Wallet,
    air: &AirSettings,
    request: &ExchangeRequest,
) -> Result<ExchangeResponse, WalletError> {
    let body = serde_json::to_vec(request)
        .map_err(|e| WalletError::Mint(format!("exchange over AIR: {e}")))?;
    crate::air::send_esp(
        wallet,
        air,
        KIND_EXCHANGE,
        &body,
        &crate::esp_replies::exchange_refusal,
        &[400],
    )
}

/// Send a transfer to the ESP mint. Refusals are read as the exchange's are
/// ([`send_exchange`]).
pub fn send_transfer(
    wallet: &mut Wallet,
    air: &AirSettings,
    request: &TransferRequest,
) -> Result<TransferResponse, WalletError> {
    let body = serde_json::to_vec(request)
        .map_err(|e| WalletError::Mint(format!("transfer over AIR: {e}")))?;
    crate::air::send_esp(
        wallet,
        air,
        KIND_TRANSFER,
        &body,
        &crate::esp_replies::exchange_refusal,
        &[400],
    )
}

/// Send a redemption to the ESP mint; `body` is the canonical encoding as built
/// by `Wallet::build_redemption`, sent as it is.
///
/// A `400` or `413` is [`WalletError::RedeemRefused`]: nothing was burned.
/// Anything else that goes wrong is [`WalletError::Mint`], where the outcome may
/// be unknown: send the same bytes again, because the mint stores its answers by
/// request hash.
pub fn send_redeem(
    wallet: &mut Wallet,
    air: &AirSettings,
    body: &[u8],
) -> Result<RedeemResponse, WalletError> {
    crate::air::send_esp(
        wallet,
        air,
        KIND_REDEEM,
        body,
        &crate::esp_replies::redeem_refusal,
        &[400, 413],
    )
}

// ---------------------------------------------------------------- an FSP mint

/// Check a service's FSP mint's wire version and network before anything else is
/// sent to it, over AIR (to the service's DID, through its `air.fsp` entry).
/// `expected_network` is `main`, `regtest`, `signet` or `testnet`.
pub fn verify_fsp(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
    expected_network: &str,
) -> Result<(), WalletError> {
    crate::air::verify_mint(wallet, air, Party::Fsp(service), expected_network)
}

/// A service's FSP mint's keysets: a signed reply over AIR.
pub fn fsp_keys(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
) -> Result<sp_wire::fsp::KeysResponse, WalletError> {
    crate::air::fetch(wallet, air, Party::Fsp(service), KIND_KEYS)
}

/// A service's FSP mint's rotation schedule: a signed reply over AIR.
pub fn fsp_rotation(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
) -> Result<sp_wire::fsp::RotationResponse, WalletError> {
    crate::air::fetch(wallet, air, Party::Fsp(service), KIND_ROTATION)
}

/// [`fsp_rotation`], as the FSP sync needs it.
pub fn fsp_window(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
) -> Result<Window, WalletError> {
    fsp_rotation(wallet, air, service).map(Into::into)
}

/// A service's FSP mint's fees and limits: a signed reply over AIR.
pub fn fsp_fees(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
) -> Result<sp_wire::fsp::FeesResponse, WalletError> {
    crate::air::fetch(wallet, air, Party::Fsp(service), KIND_FEES)
}

/// A POST to an FSP mint over AIR: `request` as JSON, the answer read as `R`. A
/// signed `400` is the wallet's error for a refusal of the request
/// ([`crate::error::mint_refusal`]: `Refused`, or `SpentElsewhere` with the notes);
/// every other refusal and a signed "cannot answer now" (the mint's `5xx`, its ESP
/// mint not answering included) is a plain [`WalletError::Mint`], so a pending
/// request stays pending and the retry gets the mint's stored answer.
fn fsp_post<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
    kind: u8,
    request: &Q,
) -> Result<R, WalletError> {
    let body = serde_json::to_vec(request)
        .map_err(|e| WalletError::Mint(format!("the FSP request could not be encoded: {e}")))?;
    let value = crate::air::post(wallet, air, Party::Fsp(service), kind, &body)?;
    serde_json::from_value(value).map_err(|e| {
        WalletError::Mint(format!(
            "the FSP mint of service {} signed a reply that is not what was asked for: {e}",
            service.to_hex()
        ))
    })
}

/// An issue: ESP in, FSP out, at a service's FSP mint over AIR.
pub fn send_fsp_issue(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
    request: &sp_wire::fsp::IssueRequest,
) -> Result<sp_wire::fsp::IssueResponse, WalletError> {
    fsp_post(wallet, air, service, KIND_FSP_ISSUE, request)
}

/// A spend (a swap with change) at a service's FSP mint over AIR.
pub fn send_fsp_spend(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
    request: &sp_wire::fsp::SpendRequest,
) -> Result<sp_wire::fsp::SpendResponse, WalletError> {
    fsp_post(wallet, air, service, KIND_FSP_SPEND, request)
}

/// Send one pending FSP request (again) and settle it. A `400` cancels it
/// (nothing happened at the mint); anything else leaves it pending.
pub fn settle_fsp(wallet: &mut Wallet, air: &AirSettings, id: &str) -> Result<String, WalletError> {
    let p = wallet
        .pending_fsp()
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Unknown(format!("no pending FSP request {id}")))?;
    let sent = match &p.op {
        crate::fsp::FspOp::Issue { request, .. } => send_fsp_issue(wallet, air, p.service, request)
            .and_then(|r| {
                let o = wallet.finish_fsp_issue(id, &r)?;
                let mut text = format!("issued {} FSP (fee {})", o.fsp, o.fee);
                for r in &o.refused {
                    text.push_str(&format!("; not issued, ESP freed: {r}"));
                }
                Ok(text)
            }),
        crate::fsp::FspOp::Spend { request, .. } => {
            let rollover = request.pay == 0;
            send_fsp_spend(wallet, air, p.service, request).and_then(|r| {
                let paid = wallet.finish_fsp_spend(id, &r)?;
                Ok(if rollover {
                    "rolled over to the current keyset".to_string()
                } else {
                    format!("paid {paid} FSP")
                })
            })
        }
    };
    if let Err(WalletError::Refused(_)) = &sent {
        wallet.cancel_fsp(id)?;
    }
    sent
}

/// What happened when the wallet checked an FSP mint.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FspSync {
    /// Lines for the log: requests finished, rollovers, failures.
    pub log: Vec<String>,
    /// FSP units lost because their keyset was deleted.
    pub lost: u128,
}

/// Run every time the wallet talks to a service's FSP mint, and at startup:
/// finish the requests left pending (a crash or a lost reply), read the keys,
/// record FSP on deleted keysets as lost, and swap FSP on the previous keyset
/// to the current one. Nothing here asks the user. A failure is logged and
/// left pending, so the next connection tries again. The mint is the service's
/// (its DID, at its `air.fsp` entry).
pub fn fsp_sync(
    wallet: &mut Wallet,
    air: &AirSettings,
    service: ServiceDid,
) -> Result<FspSync, WalletError> {
    let mut out = FspSync::default();
    let keys = fsp_keys(wallet, air, service)?;
    out.lost = wallet.note_fsp_keys(service, &keys)?;
    if out.lost > 0 {
        out.log.push(format!(
            "{} FSP units were on a keyset the mint has deleted and are lost",
            out.lost
        ));
    }
    let ids: Vec<String> = wallet
        .pending_fsp()
        .iter()
        .filter(|p| p.service == service)
        .map(|p| p.id.clone())
        .collect();
    for id in ids {
        match settle_fsp(wallet, air, &id) {
            Ok(text) => out.log.push(format!("pending {id}: {text}")),
            Err(e) => out.log.push(format!(
                "pending {id} not finished, retried on the next connection: {e}"
            )),
        }
    }
    // Staggered: one random swap time per rotation, kept in the wallet file
    // until the swap is done (see `rotate.rs`). Never logged. The mint's record
    // is the service's DID.
    let record = crate::fsp::record_of(service);
    if let Ok(w) = fsp_window(wallet, air, service) {
        let has_old = w.previous_epoch.is_some()
            && wallet
                .fsp_mints()
                .get(&record)
                .and_then(|m| m.previous.clone())
                .is_some_and(|prev| {
                    wallet.notes().iter().any(|n| {
                        n.kind == crate::Kind::Fsp
                            && n.reserved_by.is_none()
                            && wallet.fsp_keyset(n) == Some(&prev)
                    })
                });
        wallet.drop_fsp_schedule(&record, &w.current_id, has_old)?;
        if has_old && w.now < wallet.swap_time(crate::Kind::Fsp, &record, &w)? {
            out.log.push(
                "FSP will be rolled over to the current keyset, staggered after the rotation"
                    .into(),
            );
            return Ok(out);
        }
    }
    if let Some(request) = wallet.build_fsp_rollover(service)? {
        let id = request.hash();
        match settle_fsp(wallet, air, &id) {
            Ok(text) => out.log.push(format!("rollover {id}: {text}")),
            Err(e) => out.log.push(format!(
                "rollover {id} failed, retried on the next connection: {e}"
            )),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- rollover and handoffs

/// Send one stored rollover and settle it. A refusal that burned nothing
/// cancels it and frees its notes; the next sync builds a new one from a fresh
/// read of the mint's window. The outputs name the keyset the wallet last saw,
/// and a mint signs with any live keyset, so a rotation after the rollover was
/// built does not refuse it.
///
/// A stored swap of notes received in a handoff (`handoff|...`) is different in
/// one way: its notes are in the wallet's balance and can be spent, so it is
/// first made to fit what the wallet still holds
/// ([`Wallet::live_swap`]), and a note the mint says is spent is dropped from
/// the balance instead of being freed (it was never this wallet's to free).
fn send_rollover(wallet: &mut Wallet, id: &str, post: Post<'_>) -> Result<String, WalletError> {
    let mut id = id.to_string();
    let first = wallet
        .pending_rollovers()
        .iter()
        .find(|p| p.id == id)
        .map(|p| p.schedule.starts_with(crate::handoff::SWAP_TAG));
    if first == Some(true) {
        match wallet.live_swap(&id)? {
            Some(live) => id = live,
            None => {
                return Ok(
                    "the notes of a stored swap were spent before it was sent, so there is nothing left to swap"
                        .into(),
                );
            }
        }
    }
    let p = wallet
        .pending_rollovers()
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Invalid(format!("no rollover {id}")))?;
    let received = p.schedule.starts_with(crate::handoff::SWAP_TAG);
    let body = serde_json::to_vec(&p.body)
        .map_err(|e| WalletError::Mint(format!("{}/rollover: {e}", p.url)))?;
    let reply: Result<serde_json::Value, WalletError> = post(wallet, "rollover", &body);
    match reply {
        Ok(v) => {
            let (epoch, keyset, sigs, keys) = match p.kind {
                Kind::Psp => {
                    let r: sp_wire::psp::RolloverResponse =
                        serde_json::from_value(v).map_err(|e| WalletError::Mint(e.to_string()))?;
                    (
                        r.epoch,
                        r.keyset,
                        r.outcomes.into_iter().map(|o| o.0).collect::<Vec<_>>(),
                        r.keys,
                    )
                }
                _ => {
                    let r: sp_wire::esp::rollover::RolloverResponse =
                        serde_json::from_value(v).map_err(|e| WalletError::Mint(e.to_string()))?;
                    (r.epoch, r.keyset, r.signatures, r.keys)
                }
            };
            wallet.finish_rollover(&id, epoch, &keyset, &sigs, &keys)?;
            if received {
                let units: u128 = p.outputs.iter().map(|o| u128::from(o.amount)).sum();
                return Ok(format!(
                    "swapped {units} PSP received in a handoff at the mint, for notes only this wallet knows: final"
                ));
            }
            if p.schedule.starts_with(crate::handoff::RECLAIM_TAG) {
                let units: u128 = p.outputs.iter().map(|o| u128::from(o.amount)).sum();
                return Ok(format!(
                    "reclaimed {units} PSP: the notes were swapped back at the mint for notes only this wallet knows"
                ));
            }
            Ok(format!(
                "rolled over {} note(s) to the current key set",
                p.inputs.len()
            ))
        }
        Err(WalletError::SpentElsewhere { why, inputs }) if received => {
            // The mint refused the whole swap and burned nothing. The notes it
            // names are spent: somebody reached the mint first (the sender
            // reclaimed, or a copy was received first). They leave the balance;
            // the rest are swapped now.
            let (dropped, rest) = wallet.swap_found_spent(&id, &inputs)?;
            if dropped == 0 {
                return Ok(format!(
                    "the mint refused the swap of received notes: {why}. The notes stay as they are"
                ));
            }
            let mut text = format!(
                "the mint says {dropped} note(s) received in a handoff were spent already ({why}), so they are not counted any more: whoever reached the mint first has them. Tell the sender"
            );
            if let Some(rest) = rest {
                text.push_str(&format!(
                    ". The rest: {}",
                    send_rollover(wallet, &rest, &mut *post)?
                ));
            }
            Ok(text)
        }
        Err(WalletError::Refused(why)) if received => {
            // Refused for another reason (say its key set is retired): nothing
            // was burned and the notes stay in the balance as they are.
            wallet.cancel_rollover(&id)?;
            Ok(format!(
                "the mint refused the swap of received notes, which stay in the balance as they are: {why}"
            ))
        }
        Err(WalletError::SpentElsewhere { why, .. } | WalletError::Refused(why))
            if p.schedule.starts_with(crate::legacy::RECEIVE_TAG) =>
        {
            // A swap that `receive-psp` (wallet 0.4.0) stored: nothing here was
            // ever this wallet's, so a refusal ends it.
            wallet.cancel_rollover(&id)?;
            Ok(format!(
                "the mint refused the swap of received notes, so none of them was kept: {why}. Tell the sender"
            ))
        }
        Err(WalletError::SpentElsewhere { why, inputs }) => {
            // Some notes are spent. They leave the balance; the rest are free.
            // (If this was a reclaim, the handoff goes back to pending in the
            // same write, and the next `handoff check` reads the mint's record.)
            let report = wallet.mark_spent_in_rollover(&id, &inputs)?;
            Ok(format!(
                "rollover refused ({why}): {} note(s) marked spent, {} freed",
                report.marked_spent, report.freed
            ))
        }
        Err(WalletError::Refused(why)) => {
            wallet.cancel_rollover(&id)?;
            Ok(format!("rollover refused, notes freed: {why}"))
        }
        Err(e) => Err(e),
    }
}

/// Keep a PSP or ESP mint's notes on a live key set: finish stored rollovers,
/// mark lost notes, and when this rotation's (random, stored) swap time has
/// come, roll the previous set's notes over. Called on every connection to
/// the mint and at startup. Never asks; a failure is logged and retried on the
/// next connection. The log never contains a swap time.
///
/// The window is read, and the rollovers are sent, over AIR to the DID of the
/// mint `kind` names. `base` names the mint in the wallet's records (its live
/// keysets, its swap times); it is not dialled. The FSP's notes are not rolled
/// over here but by [`fsp_sync`].
pub fn rotation_sync(
    wallet: &mut Wallet,
    air: &AirSettings,
    kind: Kind,
    base: &str,
) -> Result<Vec<String>, WalletError> {
    match kind {
        Kind::Psp => rotation_sync_with(
            wallet,
            kind,
            base,
            &mut |w| psp_window(w, air),
            &mut |w, route, body| psp_post(w, air, route, body),
        ),
        Kind::Esp => rotation_sync_with(
            wallet,
            kind,
            base,
            &mut |w| esp_window(w, air),
            &mut |w, route, body| esp_post(w, air, route, body),
        ),
        Kind::Fsp => Err(WalletError::Invalid(
            "FSP notes are rolled over by the FSP sync (`fsp sync`), not by the PSP and ESP rotation sync"
                .into(),
        )),
    }
}

/// How a rotation sync reads the mint's window: given the wallet (a read over
/// AIR keeps its request in the wallet file), the window as the mint says it is
/// now.
type WindowSource<'a> =
    &'a mut dyn FnMut(&mut Wallet) -> Result<crate::rotate::Window, WalletError>;

/// How a POST to the PSP or the ESP is made: given the wallet (an AIR request is
/// kept in the wallet file), the route (`rollover` or `check-state`) and the
/// request JSON, the mint's answer as JSON, or the wallet's error for a refusal.
/// A refusal is the same [`WalletError`] whichever mint it comes from, so
/// everything that reads one is the same.
type Post<'a> =
    &'a mut dyn FnMut(&mut Wallet, &str, &[u8]) -> Result<serde_json::Value, WalletError>;

/// [`rotation_sync`], with the mint's window read by `window` and its rollovers
/// sent by `post`.
fn rotation_sync_with(
    wallet: &mut Wallet,
    kind: Kind,
    base: &str,
    window: WindowSource<'_>,
    post: Post<'_>,
) -> Result<Vec<String>, WalletError> {
    let mut log = Vec::new();
    let pending: Vec<String> = wallet
        .pending_rollovers()
        .iter()
        .filter(|p| p.kind == kind)
        .map(|p| p.id.clone())
        .collect();
    for id in pending {
        match send_rollover(wallet, &id, &mut *post) {
            Ok(t) => log.push(t),
            Err(e) => log.push(format!(
                "rollover failed, retried on the next connection: {e}"
            )),
        }
    }
    let w = window(wallet)?;
    // Refreshed on every connection, so the cached live keysets never go stale.
    match kind {
        Kind::Psp => wallet.note_live_keysets(base, &w)?,
        Kind::Esp => wallet.note_esp_keysets(base, &w.current_id, w.previous_id.as_deref())?,
        Kind::Fsp => {}
    }
    let lost_before = wallet.lost().len();
    let old = wallet.prepare_rollover(kind, base, &w)?;
    if wallet.lost().len() > lost_before {
        log.push(format!(
            "{} note(s) expired: their key set was retired at a rotation before they were rolled over, and they are lost (not counted in the balance)",
            wallet.lost().len() - lost_before
        ));
    }
    if old.is_empty() {
        return Ok(log);
    }
    let at = wallet.swap_time(kind, base, &w)?;
    if w.now < at {
        log.push(format!(
            "{} note(s) will be rolled over to the current key set, staggered after the rotation",
            old.len()
        ));
        return Ok(log);
    }
    for id in wallet.build_rollovers(kind, base, &w, old)? {
        match send_rollover(wallet, &id, &mut *post) {
            Ok(t) => log.push(t),
            Err(e) => log.push(format!(
                "rollover failed, retried on the next connection: {e}"
            )),
        }
    }
    Ok(log)
}

// ---- PSP handed from wallet to wallet (see `handoff.rs`) ---------------------

/// Finish the import of a PSP handoff: send the stored PSP swap now. (An FSP
/// handoff has nothing to send: it is never swapped.) Returns lines for the log.
/// A mint that cannot be reached leaves the swap stored and the notes
/// **unswapped**: they are already in the balance and can be spent
/// ([`crate::store::Balance::unswapped_psp`] says how much is still waiting), and
/// the swap is sent again on every later connection to the mint
/// ([`rotation_sync`], which the command line runs at startup). The swap is what
/// makes the notes the receiver's alone: until it goes through, the sender can
/// still reclaim them.
pub fn complete_import(
    wallet: &mut Wallet,
    air: &AirSettings,
    imported: &crate::handoff::Imported,
) -> Vec<String> {
    complete_import_with(wallet, imported, &mut |w, route, body| {
        psp_post(w, air, route, body)
    })
}

/// [`complete_import`], with the swap sent by `post`.
fn complete_import_with(
    wallet: &mut Wallet,
    imported: &crate::handoff::Imported,
    post: Post<'_>,
) -> Vec<String> {
    let mut log = Vec::new();
    for id in &imported.psp_swaps {
        let amount: u128 = wallet
            .pending_rollovers()
            .iter()
            .find(|p| &p.id == id)
            .map(|p| p.outputs.iter().map(|o| u128::from(o.amount)).sum())
            .unwrap_or(0);
        match send_rollover(wallet, id, &mut *post) {
            Ok(text) => log.push(text),
            Err(e) => log.push(format!(
                "the mint could not be reached, so {amount} PSP stays unswapped: it is in your balance and can be spent, and the swap is sent again on the next connection to the mint: {e}"
            )),
        }
    }
    log
}

/// Ask the mint where a PSP handoff this wallet made stands, and record it.
/// The mint's record decides: none of the notes spent means it is still the
/// sender's to reclaim, all spent means the receiver has it (the handoff is
/// done), some spent means the rest can still be reclaimed. If a reclaim is
/// stored it is sent first (again, after a crash or a lost reply).
pub fn check_handoff(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
) -> Result<crate::handoff::Standing, WalletError> {
    check_handoff_with(wallet, id, &mut |w, route, body| {
        psp_post(w, air, route, body)
    })
}

/// [`check_handoff`], with the questions to the mint (check-state, and the swap
/// back if a reclaim is stored) sent by `post`.
fn check_handoff_with(
    wallet: &mut Wallet,
    id: &str,
    post: Post<'_>,
) -> Result<crate::handoff::Standing, WalletError> {
    use crate::handoff::{HandoffState, Standing};
    let h = wallet
        .handoffs_out()
        .iter()
        .find(|h| h.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Unknown(format!("no handoff {id}")))?;
    if h.state != HandoffState::Pending {
        return wallet.handoff_standing(id);
    }
    if let Some(rollover) = &h.reclaim {
        if wallet.pending_rollovers().iter().any(|p| &p.id == rollover) {
            send_rollover(wallet, rollover, &mut *post)?;
        }
        let now = wallet.handoff_standing(id)?;
        if now == Standing::Reclaimed {
            return Ok(now);
        }
    }
    let h = wallet
        .handoffs_out()
        .iter()
        .find(|h| h.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Unknown(format!("no handoff {id}")))?;
    if h.state != HandoffState::Pending || h.notes.is_empty() {
        return wallet.handoff_standing(id);
    }
    // Errors for an FSP handoff and a record without a mint, before any call.
    wallet.handoff_standing(id)?;
    let req = CheckStateRequest {
        nonces: h.notes.iter().map(|n| n.note.nonce).collect(),
    };
    let body = serde_json::to_vec(&req)
        .map_err(|e| WalletError::Mint(format!("{}/check-state: {e}", h.mint)))?;
    let answer = post(wallet, "check-state", &body)?;
    let r: CheckStateResponse = serde_json::from_value(answer).map_err(|e| {
        WalletError::Mint(format!("{}/check-state: {e}", h.mint.trim_end_matches('/')))
    })?;
    wallet.settle_handoff(id, &r.spent)
}

/// What a reclaim did: where the handoff stands afterwards, and what the mint
/// said about the swap back, if one was sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reclaim {
    pub standing: crate::handoff::Standing,
    pub log: Vec<String>,
}

/// Take back what is left of a PSP handoff the receiver has not swapped: the
/// notes are swapped at the mint for new ones only this wallet knows. The mint
/// takes whichever swap reaches it first. If the receiver swapped first, the
/// handoff is recorded as done and nothing comes back; the standing says so.
pub fn reclaim_handoff(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
) -> Result<Reclaim, WalletError> {
    reclaim_handoff_with(
        wallet,
        id,
        &mut |w| psp_window(w, air),
        &mut |w, route, body| psp_post(w, air, route, body),
    )
}

/// [`reclaim_handoff`], with the mint's window read by `window` and the swap and
/// the check sent by `post`.
fn reclaim_handoff_with(
    wallet: &mut Wallet,
    id: &str,
    window: WindowSource<'_>,
    post: Post<'_>,
) -> Result<Reclaim, WalletError> {
    use crate::handoff::Standing;
    let mut log = Vec::new();
    if let s @ (Standing::Received | Standing::Reclaimed) =
        check_handoff_with(wallet, id, &mut *post)?
    {
        return Ok(Reclaim { standing: s, log });
    }
    let h = wallet
        .handoffs_out()
        .iter()
        .find(|h| h.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Unknown(format!("no handoff {id}")))?;
    if h.reclaim.is_none() {
        // The swap names the mint's current key set, read fresh; the mint signs
        // with any live key set, so one rotation in between does not refuse it.
        if let Ok(w) = window(wallet) {
            wallet.note_live_keysets(&h.mint, &w)?;
        }
    }
    let rollover = wallet.begin_reclaim(id)?;
    log.push(send_rollover(wallet, &rollover, &mut *post)?);
    let standing = check_handoff_with(wallet, id, &mut *post)?;
    Ok(Reclaim { standing, log })
}
