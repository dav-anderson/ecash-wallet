//! How the wallet reads what the ESP mint says, whichever way it was said. The
//! readers take the text of an HTTP body or the body of a signed AIR reply (the
//! same JSON), and do no I/O, so they are here and not in `http.rs` (which is
//! behind the `http` feature, and which re-exports them under their old names):
//!
//! - [`parse_esp_limits`] and [`parse_redeem_fees`] read `GET /fees` (HTTP or
//!   AIR kind 7),
//! - [`exchange_refusal`] reads the body of a `400` from `/exchange` or
//!   `/transfer`, and [`redeem_refusal`] that of a `400` or `413` from `/redeem`.
//!
//! A refusal that is not a `400` (and for the redemption not a `413`) is not read
//! here at all: it is a plain [`WalletError::Mint`], over HTTP and over AIR.

use sp_wire::esp::redeem::Totals;

use crate::error::WalletError;
use crate::redeem::RedeemFees;

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
