//! How the wallet reads what the ESP mint says. The readers take the body of a
//! signed AIR reply (JSON, as text) and do no I/O:
//!
//! - [`parse_esp_limits`] and [`parse_redeem_fees`] read the fees reply (AIR
//!   kind 7),
//! - [`exchange_refusal`] reads the body of a `400`-equivalent refusal of an
//!   exchange or a transfer, and [`redeem_refusal`] that of a `400` or `413` of a
//!   redemption.
//!
//! A refusal that is not a `400` (and for the redemption not a `413`) is not read
//! here at all: it is a plain [`WalletError::Mint`].

use sp_wire::esp::redeem::Totals;

use crate::error::WalletError;
use crate::redeem::RedeemFees;

/// The `exchange.max_items` and `transfer.max_items` of a fees body.
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

/// Read the body of a `400` refusal of an exchange or a transfer. The ESP mint adds `code` and
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
    fn a_transfer_refusal_that_names_spent_inputs_is_read() {
        let body =
            r#"{"error":"note 1 is already spent","code":"note_spent_elsewhere","spent":[1]}"#;
        // a transfer's body goes through exchange_refusal
        match exchange_refusal(body) {
            WalletError::SpentElsewhere { inputs, .. } => assert_eq!(inputs, vec![1]),
            other => panic!("expected SpentElsewhere, got {other:?}"),
        }
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
        let body = r#"{"redeem":{"fee_per_byte":"1000000","max_request_bytes":15728640,"max_memo_bytes":256,"size":{"fixed":120,"per_input":187,"per_output":82,"plus":"the memo's length in bytes"}}}"#;
        let fees = parse_redeem_fees(body).unwrap();
        assert_eq!(fees.fee_per_byte, 1_000_000);
        assert_eq!(fees.max_request_bytes, 15 << 20);
        assert_eq!(fees.max_memo_bytes, 256);
        let changed = body.replace("\"per_input\":187", "\"per_input\":188");
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
