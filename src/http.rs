//! The wallet's calls to the mints, over HTTP. This is the only part of the
//! library that uses the network, and an app can leave it out (the `http`
//! feature) and send the requests its own way.
//!
//! The client is blocking, so do not call these on an async thread.

use std::collections::BTreeMap;
use std::time::Duration;

use mint_types::Amount;
use secp256k1::PublicKey;
use sp_wire::esp::exchange::{ExchangeRequest, ExchangeResponse};
use sp_wire::esp::redeem::{RedeemResponse, Totals};
use sp_wire::esp::transfer::{TransferRequest, TransferResponse};
use sp_wire::keys::{CheckStateRequest, CheckStateResponse, KeysResponse};

use crate::Wallet;
use crate::error::WalletError;
use crate::redeem::RedeemFees;
use crate::store::Kind;

fn client() -> Result<reqwest::blocking::Client, WalletError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| WalletError::Mint(format!("could not make an HTTP client: {e}")))
}

/// Check a mint's network, as its `GET /health` reported it, against the
/// network this wallet runs on (`main`, `regtest`, `signet` or `testnet`).
pub fn check_network(url: &str, expected: &str, reported: Option<&str>) -> Result<(), WalletError> {
    match reported {
        Some(n) if n == expected => Ok(()),
        Some(n) => Err(WalletError::Invalid(format!(
            "the mint at {url} is on {n}, but this wallet is on {expected}. Nothing was sent. Pass the flag for its network (--regtest, --signet, --testnet; none means mainnet) or use another mint"
        ))),
        None => Err(WalletError::Mint(format!(
            "the mint at {url} does not say in /health which network it is on, so it cannot be checked against {expected}. Nothing was sent"
        ))),
    }
}

/// Check the `wire_version` a mint reported in its `GET /health` against the
/// wire version this wallet speaks (`sp_wire::WIRE_VERSION`). A mint that
/// reports another number, or none, is refused.
pub fn check_wire(url: &str, health: &serde_json::Value) -> Result<(), WalletError> {
    sp_wire::version::check_health(health).map_err(|why| WalletError::Wire {
        url: url.to_string(),
        why,
    })
}

/// Ask a mint (`GET /health`) which wire version it speaks and which network it
/// is on, and refuse if the wire version is not this wallet's or the network is
/// not `expected`. Called before anything else is sent to it. `/health` may
/// answer `503` while the mint is unwell; both fields are in that body too.
pub fn verify_mint(base: &str, expected: &str) -> Result<(), WalletError> {
    let url = format!("{}/health", base.trim_end_matches('/'));
    let response = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let body: serde_json::Value = response
        .json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    check_wire(base, &body)?;
    check_network(base, expected, body.get("network").and_then(|n| n.as_str()))
}

/// The PSP's public key for each note size (`GET /keys`).
/// The PSP's live keysets (`GET /keysets`).
pub fn fetch_psp_keysets(base: &str) -> Result<sp_wire::psp::KeysetsResponse, WalletError> {
    let url = format!("{}/keysets", base.trim_end_matches('/'));
    let response = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Mint(format!(
            "{url} returned {}",
            response.status()
        )));
    }
    response
        .json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))
}

/// The ESP mint's live keyset IDs (`GET /keysets`), remembered in the wallet:
/// new outputs name the current one, and notes from before keysets were
/// recorded fall back to them.
pub fn sync_esp_keysets(wallet: &mut Wallet, base: &str) -> Result<(), WalletError> {
    let url = format!("{}/keysets", base.trim_end_matches('/'));
    let response = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Mint(format!(
            "{url} returned {}",
            response.status()
        )));
    }
    let v: serde_json::Value = response
        .json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let current = v["current"]
        .as_str()
        .ok_or_else(|| WalletError::Mint(format!("{url}: no current keyset")))?;
    wallet.note_esp_keysets(base, current, v["previous"].as_str())
}

/// Read the ESP mint's note limits from `GET /fees` and give them to the wallet
/// (see [`crate::store::EspLimits`]), so no limit is written into the wallet.
pub fn sync_esp_limits(wallet: &mut Wallet, base: &str) -> Result<(), WalletError> {
    let url = format!("{}/fees", base.trim_end_matches('/'));
    let response = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Mint(format!(
            "{url} returned {}",
            response.status()
        )));
    }
    let text = response
        .text()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let limits =
        parse_esp_limits(&text).map_err(|why| WalletError::Mint(format!("{url}: {why}")))?;
    wallet.set_esp_limits(limits);
    Ok(())
}

/// The `exchange.max_items` and `transfer.max_items` of a `GET /fees` body.
pub fn parse_esp_limits(text: &str) -> Result<crate::store::EspLimits, String> {
    let body: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let read = |part: &str| -> Result<usize, String> {
        body[part]["max_items"]
            .as_u64()
            .map(|n| n as usize)
            .ok_or_else(|| format!("no {part}.max_items"))
    };
    Ok(crate::store::EspLimits {
        exchange_max_items: Some(read("exchange")?),
        transfer_max_items: Some(read("transfer")?),
    })
}

/// The keys to unblind a PSP settlement's signatures with: those of the
/// keyset the PSP printed (`keyset <id>`), read from `GET /keysets`, never
/// assumed to be the current set. Older output names none and was signed
/// with the keys of `GET /keys`. A printed keyset that is no longer live means
/// the outputs expired before they were claimed.
pub fn psp_claim_keys(
    base: &str,
    settlement_text: &str,
) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    match crate::psp::parse_keyset(settlement_text) {
        None => fetch_psp_keys(base),
        Some(id) => {
            let live = fetch_psp_keysets(base)?;
            let Some(keys) = live.keysets.get(&id) else {
                return Err(WalletError::Mint(format!(
                    "keyset {id}, which signed these, is no longer live at the PSP (it was retired at a rotation): the outputs expired before they were claimed and cannot be claimed now"
                )));
            };
            Ok(keys
                .iter()
                .map(|(u, k)| (Amount::from_units(*u), *k))
                .collect())
        }
    }
}

pub fn fetch_psp_keys(base: &str) -> Result<BTreeMap<Amount, PublicKey>, WalletError> {
    let url = format!("{}/keys", base.trim_end_matches('/'));
    let response = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Mint(format!(
            "{url} returned {}",
            response.status()
        )));
    }
    let keys: KeysResponse = response
        .json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    Ok(keys.keys)
}

/// Read the PSP's largest note size from `GET /keys` (the highest amount it has a
/// key for) and give it to the wallet, so no cap is written into the wallet.
pub fn sync_psp_limits(wallet: &mut Wallet, base: &str) -> Result<(), WalletError> {
    let keys = fetch_psp_keys(base)?;
    wallet.set_psp_max_denomination(keys.keys().map(|a| a.units).max());
    Ok(())
}

/// Send an exchange to the ESP mint (`POST /exchange`).
///
/// A `400` is [`WalletError::Refused`]: nothing was burned, and the pending
/// exchange can be cancelled. Anything else that goes wrong is
/// [`WalletError::Mint`], where the outcome may be unknown. Send the same request
/// again, because the mint stores its answers by request hash.
pub fn send_exchange(
    base: &str,
    request: &ExchangeRequest,
) -> Result<ExchangeResponse, WalletError> {
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
        return Err(exchange_refusal(&text));
    }
    Err(WalletError::Mint(format!(
        "{url} returned {status}: {text}"
    )))
}

/// Read the body of a `400` from `/exchange`. The ESP mint adds `code` and
/// `spent` when PSP notes in the request were spent by a different request. That
/// is [`WalletError::SpentElsewhere`]. Any other refusal, or a body that does not
/// say so, is [`WalletError::Refused`].
pub fn exchange_refusal(text: &str) -> WalletError {
    #[derive(serde::Deserialize)]
    struct Body {
        error: Option<String>,
        code: Option<String>,
        spent: Option<Vec<usize>>,
    }
    match serde_json::from_str::<Body>(text) {
        Ok(Body {
            error,
            code: Some(code),
            spent: Some(spent),
        }) if code == "note_spent_elsewhere" && !spent.is_empty() => WalletError::SpentElsewhere {
            why: error.unwrap_or_else(|| text.to_string()),
            inputs: spent,
        },
        _ => WalletError::Refused(text.to_string()),
    }
}

/// Send a transfer to the ESP mint (`POST /transfer`).
///
/// A `400` is [`WalletError::Refused`]: nothing was burned, and the pending
/// transfer can be cancelled. Anything else that goes wrong is
/// [`WalletError::Mint`], where the outcome may be unknown. Send the same request
/// again, because the mint stores its answers by request hash.
pub fn send_transfer(
    base: &str,
    request: &TransferRequest,
) -> Result<TransferResponse, WalletError> {
    let url = format!("{}/transfer", base.trim_end_matches('/'));
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
        // `note_spent_elsewhere` with `spent` names the notes to retire.
        return Err(exchange_refusal(&text));
    }
    Err(WalletError::Mint(format!(
        "{url} returned {status}: {text}"
    )))
}

/// The ESP mint's redemption fee rate and ceilings (`GET /fees`, `redeem`).
pub fn fetch_redeem_fees(base: &str) -> Result<RedeemFees, WalletError> {
    let url = format!("{}/fees", base.trim_end_matches('/'));
    let response = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !response.status().is_success() {
        return Err(WalletError::Mint(format!(
            "{url} returned {}",
            response.status()
        )));
    }
    let text = response
        .text()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    parse_redeem_fees(&text).map_err(|why| WalletError::Mint(format!("{url}: {why}")))
}

/// Read the `redeem` part of a `GET /fees` body. The rate is a decimal string,
/// like every `u128` the mint sends.
pub fn parse_redeem_fees(text: &str) -> Result<RedeemFees, String> {
    let body: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let redeem = &body["redeem"];
    let fee_per_byte = redeem["fee_per_byte"]
        .as_str()
        .and_then(|s| s.parse::<u128>().ok())
        .ok_or("no redeem.fee_per_byte")?;
    let max_request_bytes = redeem["max_request_bytes"]
        .as_u64()
        .ok_or("no redeem.max_request_bytes")?;
    let max_memo_bytes = redeem["max_memo_bytes"]
        .as_u64()
        .ok_or("no redeem.max_memo_bytes")? as usize;
    let size = &redeem["size"];
    let expected = [
        ("fixed", sp_wire::esp::redeem::FIXED_BYTES),
        ("per_input", sp_wire::esp::redeem::INPUT_BYTES),
        ("per_output", sp_wire::esp::redeem::OUTPUT_BYTES),
    ];
    for (name, bytes) in expected {
        if size[name].as_u64() != Some(bytes) {
            return Err(format!(
                "the mint sizes redemptions with {name} = {}, but this wallet builds them with {bytes}. Update the wallet",
                size[name]
            ));
        }
    }
    Ok(RedeemFees {
        fee_per_byte,
        max_request_bytes,
        max_memo_bytes,
    })
}

/// Send a redemption to the ESP mint (`POST /redeem`): the canonical encoding,
/// as built by `Wallet::build_redemption`.
///
/// A `400` or `413` is [`WalletError::RedeemRefused`]: nothing was burned.
/// Anything else that goes wrong is [`WalletError::Mint`], where the outcome may
/// be unknown: send the same bytes again, because the mint stores its answers by
/// request hash.
pub fn send_redeem(base: &str, body: &[u8]) -> Result<RedeemResponse, WalletError> {
    let url = format!("{}/redeem", base.trim_end_matches('/'));
    let response = client_for(body.len())?
        .post(&url)
        .header("content-type", "application/octet-stream")
        .body(body.to_vec())
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let status = response.status();
    if status.is_success() {
        return response
            .json()
            .map_err(|e| WalletError::Mint(format!("{url}: unreadable reply: {e}")));
    }
    let text = response.text().unwrap_or_default();
    if matches!(status.as_u16(), 400 | 413) {
        return Err(redeem_refusal(&text));
    }
    Err(WalletError::Mint(format!(
        "{url} returned {status}: {text}"
    )))
}

/// A client whose timeout allows for a large body: 30 s plus a second per MiB.
fn client_for(bytes: usize) -> Result<reqwest::blocking::Client, WalletError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30 + (bytes as u64 >> 20)))
        .build()
        .map_err(|e| WalletError::Mint(format!("could not make an HTTP client: {e}")))
}

/// Read the body of a refused redemption: `code`, `error`, and, for
/// `refund_required` and `outputs_over_limit`, `totals`.
pub fn redeem_refusal(text: &str) -> WalletError {
    #[derive(serde::Deserialize)]
    struct Body {
        error: Option<String>,
        code: Option<String>,
        totals: Option<Totals>,
        notes: Option<Vec<sp_wire::esp::redeem::NoteResult>>,
    }
    match serde_json::from_str::<Body>(text) {
        Ok(body) => WalletError::RedeemRefused {
            code: body.code.unwrap_or_else(|| "unknown".into()),
            why: body.error.unwrap_or_else(|| text.to_string()),
            totals: body.totals.map(Box::new),
            notes: body.notes.unwrap_or_default(),
        },
        Err(_) => WalletError::RedeemRefused {
            code: "unknown".into(),
            why: text.to_string(),
            totals: None,
            notes: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_below_fee_body_carries_the_per_note_reasons() {
        let body = r#"{"error":"x","code":"below_fee","value_esp":"10","fee_esp":"20","notes":[{"accepted":false,"reason":"already_spent","burned":false},{"accepted":false,"reason":null,"burned":false}]}"#;
        match redeem_refusal(body) {
            WalletError::RedeemRefused { code, notes, .. } => {
                assert_eq!(code, "below_fee");
                assert_eq!(notes.len(), 2);
                assert_eq!(
                    notes[0].reason,
                    Some(sp_wire::esp::redeem::Reason::AlreadySpent)
                );
                assert_eq!(notes[1].reason, None);
            }
            other => panic!("expected RedeemRefused, got {other:?}"),
        }
        // a mint that sends no list gives none
        match redeem_refusal(r#"{"error":"x","code":"below_fee"}"#) {
            WalletError::RedeemRefused { notes, .. } => assert!(notes.is_empty()),
            other => panic!("expected RedeemRefused, got {other:?}"),
        }
    }

    #[test]
    fn a_transfer_or_rollover_refusal_that_names_spent_inputs_is_read() {
        let body =
            r#"{"error":"note 1 is already spent","code":"note_spent_elsewhere","spent":[1]}"#;
        // a transfer's body goes through exchange_refusal
        match exchange_refusal(body) {
            WalletError::SpentElsewhere { inputs, .. } => assert_eq!(inputs, vec![1]),
            other => panic!("expected SpentElsewhere, got {other:?}"),
        }
        // a rollover's body goes through fsp_refusal
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        match fsp_refusal(
            &v,
            "note_spent_elsewhere",
            "input 1: the note is already spent",
        ) {
            WalletError::SpentElsewhere { inputs, why } => {
                assert_eq!(inputs, vec![1]);
                assert!(why.contains("already spent"));
            }
            other => panic!("expected SpentElsewhere, got {other:?}"),
        }
        // with no code the reason stands alone, without a stray ": "
        let v = serde_json::json!({});
        assert_eq!(
            fsp_refusal(&v, "", "input 0 is held").to_string(),
            "the mint refused the request: input 0 is held"
        );
        assert_eq!(
            fsp_refusal(&v, "refused", "input 0 is held").to_string(),
            "the mint refused the request: refused: input 0 is held"
        );
    }

    #[test]
    fn the_note_limits_are_read_from_the_fees_body() {
        let body = r#"{"exchange":{"max_items":50},"transfer":{"max_items":7},"redeem":{}}"#;
        let l = parse_esp_limits(body).unwrap();
        assert_eq!(l.exchange_max_items, Some(50));
        assert_eq!(l.transfer_max_items, Some(7));
        assert!(
            parse_esp_limits(r#"{"exchange":{"max_items":50}}"#)
                .unwrap_err()
                .contains("transfer.max_items")
        );
        assert!(parse_esp_limits("nope").is_err());
    }

    #[test]
    fn the_fees_body_is_read_and_a_different_size_formula_is_refused() {
        let body = r#"{"redeem":{"fee_per_byte":"1000000","max_request_bytes":67108864,"max_memo_bytes":256,"size":{"fixed":119,"per_input":186,"per_output":81,"plus":"the memo's length in bytes"}}}"#;
        let fees = parse_redeem_fees(body).unwrap();
        assert_eq!(fees.fee_per_byte, 1_000_000);
        assert_eq!(fees.max_request_bytes, 64 << 20);
        assert_eq!(fees.max_memo_bytes, 256);
        let changed = body.replace("\"per_input\":186", "\"per_input\":188");
        assert!(
            parse_redeem_fees(&changed)
                .unwrap_err()
                .contains("per_input")
        );
        assert!(parse_redeem_fees("{}").is_err());
    }

    #[test]
    fn a_redeem_refusal_keeps_its_code_and_totals() {
        let body = r#"{"error":"refund_outputs are needed","code":"refund_required","totals":{"notes":[{"accepted":false,"reason":"immature","burned":true}],"accepted_esp":"0","rejected_esp":"5","fee_esp":"3","size_bytes":300,"fee_per_byte":"1","accepted_by_terms":[],"rejected_by_terms":[]}}"#;
        match redeem_refusal(body) {
            WalletError::RedeemRefused { code, totals, .. } => {
                assert_eq!(code, "refund_required");
                let t = totals.unwrap();
                assert_eq!((t.rejected_esp, t.fee_esp, t.size_bytes), (5, 3, 300));
            }
            other => panic!("{other:?}"),
        }
        match redeem_refusal(r#"{"error":"x","code":"below_fee","value_esp":"1","fee_esp":"2"}"#) {
            WalletError::RedeemRefused { code, totals, .. } => {
                assert_eq!(code, "below_fee");
                assert!(totals.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            redeem_refusal("junk"),
            WalletError::RedeemRefused { .. }
        ));
    }

    #[test]
    fn a_spent_elsewhere_refusal_carries_which_notes() {
        let body = r#"{"error":"a PSP note was spent by a different request","code":"note_spent_elsewhere","spent":[1,3]}"#;
        match exchange_refusal(body) {
            WalletError::SpentElsewhere { why, inputs } => {
                assert_eq!(why, "a PSP note was spent by a different request");
                assert_eq!(inputs, vec![1, 3]);
            }
            other => panic!("expected SpentElsewhere, got {other:?}"),
        }
    }

    #[test]
    fn every_other_400_is_an_ordinary_refusal() {
        for body in [
            r#"{"error":"an exchange must be exact"}"#,
            r#"{"error":"x","code":"something_else","spent":[0]}"#,
            r#"{"error":"x","code":"note_spent_elsewhere"}"#,
            r#"{"error":"x","code":"note_spent_elsewhere","spent":[]}"#,
            "not json",
            "",
        ] {
            assert!(
                matches!(exchange_refusal(body), WalletError::Refused(ref t) if t == body),
                "{body}"
            );
        }
    }
}

// ---- FSP ----

fn fsp_post<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
    base: &str,
    route: &str,
    request: &Q,
) -> Result<R, WalletError> {
    let url = format!("{}/{route}", base.trim_end_matches('/'));
    let response = client()?
        .post(&url)
        .json(request)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let status = response.status();
    let text = response.text().unwrap_or_default();
    if status.is_success() {
        return serde_json::from_str(&text).map_err(|e| WalletError::Mint(format!("{url}: {e}")));
    }
    let body: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let code = body["code"].as_str().unwrap_or("").to_string();
    let why = body["error"].as_str().unwrap_or(&text).to_string();
    if status.as_u16() == 400 {
        Err(fsp_refusal(&body, &code, &why))
    } else {
        Err(WalletError::Mint(format!("{url} returned {status}: {why}")))
    }
}

/// A `400` from a mint's POST route as the wallet sees it. `note_spent_elsewhere`
/// with `spent` is [`WalletError::SpentElsewhere`]. Anything else is
/// [`WalletError::Refused`] with the code in front of the reason, or the reason
/// alone when the mint sent no code.
fn fsp_refusal(body: &serde_json::Value, code: &str, why: &str) -> WalletError {
    let spent: Vec<usize> = body["spent"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_u64())
                .map(|v| v as usize)
                .collect()
        })
        .unwrap_or_default();
    if code == "note_spent_elsewhere" && !spent.is_empty() {
        return WalletError::SpentElsewhere {
            why: why.to_string(),
            inputs: spent,
        };
    }
    if code.is_empty() {
        WalletError::Refused(why.to_string())
    } else {
        WalletError::Refused(format!("{code}: {why}"))
    }
}

/// An FSP mint's keysets (`GET /keys`).
pub fn fetch_fsp_keys(base: &str) -> Result<sp_wire::fsp::KeysResponse, WalletError> {
    let url = format!("{}/keys", base.trim_end_matches('/'));
    let r = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !r.status().is_success() {
        return Err(WalletError::Mint(format!("{url} returned {}", r.status())));
    }
    r.json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))
}

/// An FSP mint's rotation schedule (`GET /rotation`).
pub fn fetch_fsp_rotation(base: &str) -> Result<sp_wire::fsp::RotationResponse, WalletError> {
    let url = format!("{}/rotation", base.trim_end_matches('/'));
    let r = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    if !r.status().is_success() {
        return Err(WalletError::Mint(format!("{url} returned {}", r.status())));
    }
    r.json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))
}

pub fn fetch_fsp_fees(base: &str) -> Result<sp_wire::fsp::FeesResponse, WalletError> {
    let url = format!("{}/fees", base.trim_end_matches('/'));
    let r = client()?
        .get(&url)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    r.json()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))
}

pub fn send_fsp_issue(
    base: &str,
    request: &sp_wire::fsp::IssueRequest,
) -> Result<sp_wire::fsp::IssueResponse, WalletError> {
    fsp_post(base, "issue", request)
}

pub fn send_fsp_spend(
    base: &str,
    request: &sp_wire::fsp::SpendRequest,
) -> Result<sp_wire::fsp::SpendResponse, WalletError> {
    fsp_post(base, "spend", request)
}

/// Send one pending FSP request (again) and settle it. A `400` cancels it
/// (nothing happened at the mint); anything else leaves it pending.
pub fn settle_fsp(wallet: &mut crate::Wallet, base: &str, id: &str) -> Result<String, WalletError> {
    let p = wallet
        .pending_fsp()
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Unknown(format!("no pending FSP request {id}")))?;
    let sent = match &p.op {
        crate::fsp::FspOp::Issue { request, .. } => send_fsp_issue(base, request).and_then(|r| {
            let o = wallet.finish_fsp_issue(id, &r)?;
            let mut text = format!("issued {} FSP (fee {})", o.fsp, o.fee);
            for r in &o.refused {
                text.push_str(&format!("; not issued, ESP freed: {r}"));
            }
            Ok(text)
        }),
        crate::fsp::FspOp::Spend { request, .. } => {
            let rollover = request.pay == 0;
            send_fsp_spend(base, request).and_then(|r| {
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
/// finish the requests left pending (a crash or a lost reply), read `/keys`,
/// record FSP on deleted keysets as lost, and swap FSP on the previous keyset
/// to the current one. Nothing here asks the user. A failure is logged and
/// left pending, so the next connection tries again.
pub fn fsp_sync(
    wallet: &mut crate::Wallet,
    service: secp256k1::XOnlyPublicKey,
    base: &str,
) -> Result<FspSync, WalletError> {
    let mut out = FspSync::default();
    let keys = fetch_fsp_keys(base)?;
    out.lost = wallet.note_fsp_keys(service, base, &keys)?;
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
        match settle_fsp(wallet, base, &id) {
            Ok(text) => out.log.push(format!("pending {id}: {text}")),
            Err(e) => out.log.push(format!(
                "pending {id} not finished, retried on the next connection: {e}"
            )),
        }
    }
    // Staggered: one random swap time per rotation, kept in the wallet file
    // until the swap is done (see `rotate.rs`). Never logged.
    if let Ok(w) = fetch_window(base) {
        let url = base.to_string();
        let has_old = w.previous_epoch.is_some()
            && wallet
                .fsp_mints()
                .get(&hex::encode(service.serialize()))
                .and_then(|m| m.previous.clone())
                .is_some_and(|prev| {
                    wallet.notes().iter().any(|n| {
                        n.kind == crate::Kind::Fsp
                            && n.reserved_by.is_none()
                            && wallet.fsp_keyset(n) == Some(&prev)
                    })
                });
        wallet.drop_fsp_schedule(&url, &w.current_id, has_old)?;
        if has_old && w.now < wallet.swap_time(crate::Kind::Fsp, &url, &w)? {
            out.log.push(
                "FSP will be rolled over to the current keyset, staggered after the rotation"
                    .into(),
            );
            return Ok(out);
        }
    }
    if let Some(request) = wallet.build_fsp_rollover(service)? {
        let id = request.hash();
        match settle_fsp(wallet, base, &id) {
            Ok(text) => out.log.push(format!("rollover {id}: {text}")),
            Err(e) => out.log.push(format!(
                "rollover {id} failed, retried on the next connection: {e}"
            )),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod network_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A health body for `network`, with a `wire_version`.
    fn body(network: &str, wire: impl std::fmt::Display) -> String {
        format!(r#"{{"status":"ok","network":"{network}","wire_version":{wire}}}"#)
    }

    /// A one-request server that answers `/health` with `body`.
    fn health(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let reply = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(reply.as_bytes()).unwrap();
        });
        base
    }

    #[test]
    fn a_mint_on_another_network_is_refused() {
        let base = health(body("regtest", sp_wire::WIRE_VERSION));
        let e = verify_mint(&base, "main").unwrap_err();
        assert!(matches!(e, WalletError::Invalid(_)), "{e}");
        assert!(
            e.to_string()
                .contains("is on regtest, but this wallet is on main"),
            "{e}"
        );
        let base = health(body("regtest", sp_wire::WIRE_VERSION));
        verify_mint(&base, "regtest").unwrap();
        let base = health(format!(
            r#"{{"status":"ok","wire_version":{}}}"#,
            sp_wire::WIRE_VERSION
        ));
        assert!(verify_mint(&base, "regtest").is_err());
    }

    #[test]
    fn a_mint_on_another_wire_version_is_refused_with_a_clear_error() {
        let other = u64::from(sp_wire::WIRE_VERSION) + 1;
        let base = health(body("regtest", other));
        let e = verify_mint(&base, "regtest").unwrap_err();
        assert!(matches!(e, WalletError::Wire { .. }), "{e}");
        let text = e.to_string();
        assert!(
            text.contains(&format!("wire version {other}"))
                && text.contains(&format!("speaks {}", sp_wire::WIRE_VERSION))
                && text.contains("update whichever is older")
                && text.contains("Nothing was sent"),
            "{text}"
        );
        assert!(text.contains(&base), "{text}");
    }

    #[test]
    fn a_mint_that_reports_no_wire_version_is_refused() {
        let base = health(r#"{"status":"ok","network":"regtest"}"#.to_string());
        let e = verify_mint(&base, "regtest").unwrap_err();
        assert!(matches!(e, WalletError::Wire { .. }), "{e}");
        assert!(
            e.to_string().contains("does not report a wire_version"),
            "{e}"
        );
        // not an integer
        let base = health(body("regtest", "\"1\""));
        assert!(matches!(
            verify_mint(&base, "regtest").unwrap_err(),
            WalletError::Wire { .. }
        ));
    }

    #[test]
    fn the_wire_version_is_checked_before_the_network() {
        // An old mint on the wrong network is told it is old, which is the
        // thing to fix first.
        let base = health(r#"{"status":"ok","network":"regtest"}"#.to_string());
        let e = verify_mint(&base, "main").unwrap_err();
        assert!(matches!(e, WalletError::Wire { .. }), "{e}");
    }

    #[test]
    fn check_wire_reads_the_health_body() {
        let ok: serde_json::Value =
            serde_json::from_str(&body("main", sp_wire::WIRE_VERSION)).unwrap();
        assert!(check_wire("http://m", &ok).is_ok());
        let bad: serde_json::Value = serde_json::from_str(&body("main", 99)).unwrap();
        assert!(check_wire("http://m", &bad).is_err());
    }
}

// ---- PSP and ESP rollover ----------------------------------------------------

/// A mint's `GET /rotation`, as the rollover needs it. psp-mint, esp-mint and
/// fsp-mint answer it in the same shape.
pub fn fetch_window(base: &str) -> Result<crate::rotate::Window, WalletError> {
    let w = fetch_fsp_rotation(base)?;
    Ok(crate::rotate::Window {
        current_epoch: w.current.epoch,
        current_id: w.current.id,
        current_starts: w.current.starts,
        previous_epoch: w.previous.as_ref().map(|p| p.epoch),
        previous_id: w.previous.map(|p| p.id),
        period_hours: w.rotation_period_hours,
        now: w.now,
    })
}

/// Send one stored rollover and settle it. A refusal that burned nothing
/// cancels it and frees its notes; the next sync builds a new one from a fresh
/// read of the mint's window. The outputs name the keyset the wallet last saw,
/// and a mint signs with any live keyset, so a rotation after the rollover was
/// built does not refuse it.
fn send_rollover(wallet: &mut Wallet, id: &str) -> Result<String, WalletError> {
    let p = wallet
        .pending_rollovers()
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Invalid(format!("no rollover {id}")))?;
    let reply: Result<serde_json::Value, WalletError> = fsp_post(&p.url, "rollover", &p.body);
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
            wallet.finish_rollover(id, epoch, &keyset, &sigs, &keys)?;
            wallet.after_swap(&p.schedule, true)?;
            Ok(format!(
                "rolled over {} note(s) to the current key set",
                p.inputs.len()
            ))
        }
        Err(WalletError::SpentElsewhere { why, inputs }) => {
            // Some notes are spent. They leave the balance; the rest are free.
            let report = wallet.mark_spent_in_rollover(id, &inputs)?;
            wallet.after_swap(&p.schedule, false)?;
            Ok(format!(
                "rollover refused ({why}): {} note(s) marked spent, {} freed",
                report.marked_spent, report.freed
            ))
        }
        Err(WalletError::Refused(why)) => {
            wallet.cancel_rollover(id)?;
            wallet.after_swap(&p.schedule, false)?;
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
pub fn rotation_sync(
    wallet: &mut Wallet,
    kind: Kind,
    base: &str,
) -> Result<Vec<String>, WalletError> {
    let mut log = Vec::new();
    let pending: Vec<String> = wallet
        .pending_rollovers()
        .iter()
        .filter(|p| p.kind == kind && p.url == base)
        .map(|p| p.id.clone())
        .collect();
    for id in pending {
        match send_rollover(wallet, &id) {
            Ok(t) => log.push(t),
            Err(e) => log.push(format!(
                "rollover failed, retried on the next connection: {e}"
            )),
        }
    }
    let w = fetch_window(base)?;
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
        match send_rollover(wallet, &id) {
            Ok(t) => log.push(t),
            Err(e) => log.push(format!(
                "rollover failed, retried on the next connection: {e}"
            )),
        }
    }
    Ok(log)
}

// ---- PSP handed from wallet to wallet (see `send.rs`) ------------------------

/// Import a PSP token and swap it at its mint at once. The swap is stored
/// before it is sent, so after a crash calling this again with the same token
/// (or the next startup sync) finishes it. `Rejected` means the mint found a
/// note spent: nothing was kept.
pub fn receive_psp(wallet: &mut Wallet, token: &str) -> Result<crate::send::Received, WalletError> {
    let t = crate::send::Token::decode(token)?;
    // The swap's outputs name the mint's current keyset, read fresh; the mint
    // signs with any live keyset, so one rotation in between does not refuse it.
    if let Ok(w) = fetch_window(&t.mint) {
        wallet.note_live_keysets(&t.mint, &w)?;
    }
    let id = wallet.begin_receive(&t)?;
    settle_receive_swap(wallet, &id, t.total())
}

/// Send a stored swap of received notes (a PSP token's, or a handoff's) and
/// settle it. A note of it spent already (a copy was received first) is a
/// refusal: nothing was burned and nothing here was ever the receiver's, so the
/// stored swap is dropped and the receive is rejected like any other refusal.
/// Anything else leaves the swap stored, to be sent again.
fn settle_receive_swap(
    wallet: &mut Wallet,
    id: &str,
    amount: u128,
) -> Result<crate::send::Received, WalletError> {
    let p = wallet
        .pending_rollovers()
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Unknown(format!("no stored swap {id}")))?;
    match fsp_post::<_, sp_wire::psp::RolloverResponse>(&p.url, "rollover", &p.body) {
        Ok(r) => {
            let sigs: Vec<_> = r.outcomes.into_iter().map(|o| o.0).collect();
            wallet.finish_rollover(id, r.epoch, &r.keyset, &sigs, &r.keys)?;
            Ok(crate::send::Received::Final { amount })
        }
        Err(WalletError::Refused(why)) | Err(WalletError::SpentElsewhere { why, .. }) => {
            wallet.cancel_rollover(id)?;
            Ok(crate::send::Received::Rejected { why })
        }
        Err(e) => Err(e),
    }
}

/// Finish an import made with a swap (`Wallet::import_handoff(.., swap = true)`):
/// send the stored PSP swaps, and swap the imported FSP notes at their
/// services' fsp-mints (a normal swap that pays 0). Returns lines for the log.
/// A mint that cannot be reached leaves its swap stored (PSP) or the notes
/// imported and unswapped (FSP), which is allowed: the next run sends the stored
/// swap again, and the notes are good meanwhile.
pub fn complete_import(wallet: &mut Wallet, imported: &crate::handoff::Imported) -> Vec<String> {
    let mut log = Vec::new();
    for id in &imported.psp_swaps {
        let amount: u128 = wallet
            .pending_rollovers()
            .iter()
            .find(|p| &p.id == id)
            .map(|p| p.outputs.iter().map(|o| u128::from(o.amount)).sum())
            .unwrap_or(0);
        match settle_receive_swap(wallet, id, amount) {
            Ok(crate::send::Received::Final { amount }) => {
                log.push(format!("swapped {amount} PSP at the mint: final"))
            }
            Ok(crate::send::Received::Rejected { why }) => log.push(format!(
                "the mint refused the PSP swap, so none of it was kept: {why}. Tell the sender"
            )),
            Err(e) => log.push(format!(
                "the PSP swap was not finished and is kept to be sent again on the next run: {e}"
            )),
        }
    }
    for (service, ids) in &imported.fsp_swaps {
        let known = wallet
            .fsp_mints()
            .get(&hex::encode(service.serialize()))
            .map(|m| m.url.clone());
        let named = imported
            .fsp_mints
            .iter()
            .find(|(s, _)| s == service)
            .map(|(_, u)| u.clone());
        let Some(url) = known.or(named) else {
            log.push("no FSP mint is known for an imported service, so it was not swapped".into());
            continue;
        };
        match wallet.build_fsp_swap_of(*service, ids) {
            Ok(rid) => match settle_fsp(wallet, &url, &rid) {
                Ok(text) => log.push(format!("FSP swap {rid}: {text}")),
                Err(e) => log.push(format!(
                    "the FSP swap was not finished and is kept to be sent again on the next run: {e}"
                )),
            },
            Err(e) => log.push(format!("the FSP notes were not swapped: {e}")),
        }
    }
    log
}

/// Ask the mint where a token this wallet sent stands, and record it.
pub fn check_sent(
    wallet: &mut Wallet,
    token_id: &str,
) -> Result<crate::send::SentState, WalletError> {
    use crate::send::SentState;
    let t = wallet
        .sent_tokens()
        .iter()
        .find(|t| t.id == token_id)
        .cloned()
        .ok_or_else(|| WalletError::Invalid(format!("no sent token {token_id}")))?;
    if let SentState::Reclaiming { rollover } = &t.state {
        send_rollover(wallet, rollover)?;
        let now = wallet
            .sent_tokens()
            .iter()
            .find(|t| t.id == token_id)
            .expect("kept");
        if now.state == SentState::Reclaimed {
            return Ok(SentState::Reclaimed);
        }
        return check_sent(wallet, token_id);
    }
    if t.notes.is_empty() {
        return Ok(t.state);
    }
    let req = CheckStateRequest {
        nonces: t.notes.iter().map(|n| n.note.nonce).collect(),
    };
    let r: CheckStateResponse = fsp_post(&t.mint, "check-state", &req)?;
    wallet.settle_sent(token_id, &r.spent)
}

/// Take back what is left of a sent token that was never swapped: the notes
/// are swapped at the mint for new ones only this wallet knows. If the
/// receiver swapped first, the token is recorded as received instead.
pub fn reclaim_sent(
    wallet: &mut Wallet,
    token_id: &str,
) -> Result<crate::send::SentState, WalletError> {
    use crate::send::SentState;
    match check_sent(wallet, token_id)? {
        s @ (SentState::Received | SentState::Reclaimed) => return Ok(s),
        SentState::Conflict { .. }
            if wallet
                .sent_tokens()
                .iter()
                .any(|t| t.id == token_id && t.notes.is_empty()) =>
        {
            return check_sent(wallet, token_id);
        }
        _ => {}
    }
    if let Some(url) = wallet
        .sent_tokens()
        .iter()
        .find(|t| t.id == token_id)
        .map(|t| t.mint.clone())
    {
        if let Ok(w) = fetch_window(&url) {
            wallet.note_live_keysets(&url, &w)?;
        }
    }
    let id = wallet.begin_reclaim(token_id)?;
    send_rollover(wallet, &id)?;
    check_sent(wallet, token_id)
}
