//! The wallet's calls to the FSP mints, over HTTP. This is the only part of the
//! library that uses the network by itself, and an app can leave it out (the
//! `http` feature) and send the requests its own way. The calls to the PSP and
//! the ESP are over AIR only (`mint_info`, `air`).
//!
//! The client is blocking, so do not call these on an async thread.

use std::time::Duration;

use crate::error::WalletError;

fn client() -> Result<reqwest::blocking::Client, WalletError> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| WalletError::Mint(format!("could not make an HTTP client: {e}")))
}

/// Check an FSP mint's network, as its `GET /health` reported it, against the
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

/// Ask an FSP mint (`GET /health`) which wire version it speaks and which network it
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

// ---- FSP ----

fn fsp_post<Q: serde::Serialize, R: serde::de::DeserializeOwned>(
    base: &str,
    route: &str,
    request: &Q,
) -> Result<R, WalletError> {
    let url = format!("{}/{route}", base.trim_end_matches('/'));
    let bytes =
        serde_json::to_vec(request).map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let text = fsp_send(base, route, bytes)?;
    serde_json::from_str(&text).map_err(|e| WalletError::Mint(format!("{url}: {e}")))
}

/// POST `body` (JSON, already encoded) to `route` of the mint at `base` and
/// return the text of a success. A `400` is the mint's refusal
/// ([`fsp_refusal`]); any other status is a [`WalletError::Mint`].
fn fsp_send(base: &str, route: &str, body: Vec<u8>) -> Result<String, WalletError> {
    let url = format!("{}/{route}", base.trim_end_matches('/'));
    let response = client()?
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .map_err(|e| WalletError::Mint(format!("{url}: {e}")))?;
    let status = response.status();
    let text = response.text().unwrap_or_default();
    if status.is_success() {
        return Ok(text);
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

/// A `400` from a mint's POST route as the wallet sees it (see
/// [`crate::error::mint_refusal`], which the AIR path shares).
fn fsp_refusal(body: &serde_json::Value, code: &str, why: &str) -> WalletError {
    crate::error::mint_refusal(body, code, why)
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
    service: sp_wire::ServiceDid,
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

// ---- FSP rotation window ---------------------------------------------------

/// An FSP mint's `GET /rotation`, as the FSP sync needs it.
pub fn fetch_window(base: &str) -> Result<crate::rotate::Window, WalletError> {
    fetch_fsp_rotation(base).map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rollover_refusal_that_names_spent_inputs_is_read() {
        let body =
            r#"{"error":"note 1 is already spent","code":"note_spent_elsewhere","spent":[1]}"#;
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
}
