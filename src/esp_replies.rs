//! How the wallet reads what the ESP mint says. The readers take the body of a
//! signed AIR reply (JSON, as text) and do no I/O:
//!
//! - [`parse_esp_limits`] and [`parse_redeem_fees`] read the fees reply (AIR
//!   kind 7),
//! - [`exchange_refusal`] reads the body of a `400`-equivalent refusal of an
//!   exchange, and [`redeem_refusal`] that of a `400` or `413` of a
//!   redemption.
//!
//! A refusal that is not a `400` (and for the redemption not a `413`) is not read
//! here at all: it is a plain [`WalletError::Mint`].

use sp_wire::esp::redeem::Totals;

use crate::error::WalletError;
use crate::redeem::RedeemFees;

/// The `exchange.max_items` of a fees body. (The body also carries the ESP's
/// transfer limit; the wallet makes no transfer, so it does not read it.)
pub fn parse_esp_limits(text: &str) -> Result<crate::store::EspLimits, String> {
    let body: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let exchange = body["exchange"]["max_items"]
        .as_u64()
        .map(|n| n as usize)
        .ok_or_else(|| "no exchange.max_items".to_string())?;
    Ok(crate::store::EspLimits {
        exchange_max_items: Some(exchange),
    })
}

/// Read the body of a `400` refusal of an exchange. The ESP mint adds `code` and
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
        caller_max_bytes: None,
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
    use esp_mint::config::Config;
    use esp_mint::exchange::Rejection;
    use esp_mint::redeem::RedeemRejection;
    use serde_json::{Value, json};
    use sp_wire::esp::redeem::{NoteResult, Reason};

    /// The body esp-mint answers a refused redemption with: the rejection's own
    /// details, its text and its code.
    fn redeem_body(r: &RedeemRejection) -> Value {
        let mut body = r.details();
        body["error"] = json!(r.to_string());
        body["code"] = json!(r.code());
        body
    }

    /// The fees body of an esp-mint with these limits and rates.
    fn fees_of(exchange_items: usize, transfer_items: usize) -> Value {
        let config = Config {
            exchange_max_items: exchange_items,
            transfer_max_items: transfer_items,
            redeem_fee_per_byte: 1_000_000,
            redeem_max_request_bytes: 15 << 20,
            redeem_max_memo_bytes: 256,
            ..Config::default()
        };
        esp_mint::server::fees_body(&config)
    }

    #[test]
    fn a_below_fee_body_carries_the_per_note_reasons() {
        let r = RedeemRejection::BelowFee {
            value: 10,
            fee: 20,
            notes: vec![
                NoteResult {
                    accepted: false,
                    reason: Some(Reason::AlreadySpent),
                    burned: false,
                },
                NoteResult {
                    accepted: false,
                    reason: None,
                    burned: false,
                },
            ],
        };
        let body = redeem_body(&r);
        match redeem_refusal(&body.to_string()) {
            WalletError::RedeemRefused {
                code, why, notes, ..
            } => {
                assert_eq!(code, "below_fee");
                assert_eq!(why, r.to_string());
                assert_eq!(notes.len(), 2);
                assert_eq!(notes[0].reason, Some(Reason::AlreadySpent));
                assert_eq!(notes[1].reason, None);
            }
            other => panic!("expected RedeemRefused, got {other:?}"),
        }
        // every other refusal has no `notes`: esp-mint adds the list to
        // `below_fee` only (`RedeemRejection::details`)
        let bad = RedeemRejection::BadServiceSignature;
        match redeem_refusal(&redeem_body(&bad).to_string()) {
            WalletError::RedeemRefused {
                code, why, notes, ..
            } => {
                assert_eq!(code, "bad_service_signature");
                assert_eq!(why, bad.to_string());
                assert!(notes.is_empty());
            }
            other => panic!("expected RedeemRefused, got {other:?}"),
        }
    }

    #[test]
    fn the_note_limits_are_read_from_the_fees_body() {
        let body = fees_of(50, 7);
        let l = parse_esp_limits(&body.to_string()).unwrap();
        assert_eq!(l.exchange_max_items, Some(50));
        // the body's transfer section is the mint's own and is not read: a body
        // without it is as good
        let mut without = body;
        without.as_object_mut().unwrap().remove("transfer").unwrap();
        assert_eq!(
            parse_esp_limits(&without.to_string())
                .unwrap()
                .exchange_max_items,
            Some(50)
        );
        without.as_object_mut().unwrap().remove("exchange").unwrap();
        assert_eq!(
            parse_esp_limits(&without.to_string()).unwrap_err(),
            "no exchange.max_items"
        );
        let e = parse_esp_limits("nope").unwrap_err();
        assert!(e.starts_with("not JSON:"), "{e}");
    }

    #[test]
    fn the_fees_body_is_read_and_a_different_size_formula_is_refused() {
        let body = fees_of(50, 7);
        let fees = parse_redeem_fees(&body.to_string()).unwrap();
        assert_eq!(fees.fee_per_byte, 1_000_000);
        assert_eq!(fees.max_request_bytes, 15 << 20);
        assert_eq!(fees.max_memo_bytes, 256);
        let mut changed = body;
        changed["redeem"]["size"]["per_input"] = json!(188);
        let e = parse_redeem_fees(&changed.to_string()).unwrap_err();
        assert!(
            e.contains("per_input = 188, but this wallet builds them with 187"),
            "{e}"
        );
        // a body with no redeem part at all
        assert_eq!(
            parse_redeem_fees("{}").unwrap_err(),
            "no redeem.fee_per_byte"
        );
    }

    #[test]
    fn a_redeem_refusal_keeps_its_code_and_totals() {
        let r = RedeemRejection::RefundRequired {
            totals: Totals {
                notes: vec![NoteResult {
                    accepted: false,
                    reason: Some(Reason::Immature),
                    burned: true,
                }],
                accepted_esp: 0,
                rejected_esp: 5,
                fee_esp: 3,
                size_bytes: 300,
                fee_per_byte: 1,
                accepted_by_terms: vec![],
                rejected_by_terms: vec![],
            },
        };
        match redeem_refusal(&redeem_body(&r).to_string()) {
            WalletError::RedeemRefused { code, totals, .. } => {
                assert_eq!(code, "refund_required");
                let t = totals.unwrap();
                assert_eq!((t.rejected_esp, t.fee_esp, t.size_bytes), (5, 3, 300));
                assert_eq!(t.notes[0].reason, Some(Reason::Immature));
            }
            other => panic!("{other:?}"),
        }
        // a refusal with no totals has none
        let r = RedeemRejection::BelowFee {
            value: 1,
            fee: 2,
            notes: vec![],
        };
        match redeem_refusal(&redeem_body(&r).to_string()) {
            WalletError::RedeemRefused { code, totals, .. } => {
                assert_eq!(code, "below_fee");
                assert!(totals.is_none());
            }
            other => panic!("{other:?}"),
        }
        // not JSON at all (deliberately): the text is kept as it came
        match redeem_refusal("junk") {
            WalletError::RedeemRefused {
                code, why, totals, ..
            } => assert_eq!(
                (code.as_str(), why.as_str(), totals),
                ("unknown", "junk", None)
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_spent_elsewhere_refusal_carries_which_notes() {
        let r = Rejection::NoteSpentElsewhere { spent: vec![1, 3] };
        // as esp-mint builds it for an exchange
        let body = json!({
            "error": r.to_string(),
            "code": sp_wire::codes::NOTE_SPENT_ELSEWHERE,
            "spent": [1, 3],
        });
        match exchange_refusal(&body.to_string()) {
            WalletError::SpentElsewhere { why, inputs } => {
                assert_eq!(why, r.to_string());
                assert_eq!(inputs, vec![1, 3]);
            }
            other => panic!("expected SpentElsewhere, got {other:?}"),
        }
    }

    #[test]
    fn every_other_400_is_an_ordinary_refusal() {
        let plain = json!({"error": Rejection::NoInputs.to_string()}).to_string();
        // Off the contract on purpose: another code with indexes, the spent code
        // with no indexes, the spent code with an empty list, and text that is
        // not a body at all.
        let off_contract = [
            r#"{"error":"x","code":"something_else","spent":[0]}"#,
            r#"{"error":"x","code":"note_spent_elsewhere"}"#,
            r#"{"error":"x","code":"note_spent_elsewhere","spent":[]}"#,
            "not json",
            "",
        ];
        for body in std::iter::once(plain.as_str()).chain(off_contract) {
            assert!(
                matches!(exchange_refusal(body), WalletError::Refused(ref t) if t == body),
                "{body}"
            );
        }
    }
}
