//! The wallet's calls to the PSP, the ESP and the FSP mints. They are made over
//! AIR and only over AIR: there is no HTTP form of any of them. This is the one place that
//! says which call goes to which mint, so the library's callers (the command
//! line, an app, the tests) all get the same rule.
//!
//! **The PSP's** calls are its mint info ([`verify_psp`]), its keys, keysets and
//! rotation ([`psp_keys`], [`psp_keysets`], [`psp_window`], and the calls built
//! on them: [`sync_psp_limits`], [`rotation_sync`], [`reclaim_handoff`]) and its
//! two POSTs, rollover and check-state
//! ([`psp_post`], and the calls built on it: [`rotation_sync`],
//! [`reclaim_handoff`], [`check_handoff`], [`complete_import`]). **The PSP's
//! delivery** is not a call: the PSP writes each purchase's signatures to the
//! SPI's AIR server, and [`psp_pickup`] reads those records (the AIR server is
//! `air.server` and `air.host`, as for every PSP call). **The PSP's
//! reconciliation** (AIR kind 15) settles a payment the PSP held or rejected, or
//! a credit it owes: [`psp_reconcile`] builds the request from the record's
//! rules, sends it and applies the answer.
//!
//! **The ESP's** are its mint info ([`verify_esp`]), keysets ([`sync_esp_keysets`]),
//! fees ([`sync_esp_limits`], [`fetch_redeem_fees`]), rotation ([`esp_window`])
//! and rollover ([`esp_post`], used by [`rotation_sync`]), and the two calls
//! that spend: [`send_exchange`] and [`send_redeem`]. The ESP
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
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::delivery;
use sp_wire::air_request::{
    KIND_CHECK_STATE, KIND_EXCHANGE, KIND_FEES, KIND_FSP_ISSUE, KIND_FSP_SPEND, KIND_KEYS,
    KIND_KEYSETS, KIND_PSP_RECONCILE, KIND_REDEEM, KIND_ROLLOVER, KIND_ROTATION,
};
use sp_wire::esp::exchange::{ExchangeRequest, ExchangeResponse};
use sp_wire::esp::redeem::RedeemResponse;
use sp_wire::keys::{CheckStateRequest, CheckStateResponse};
use sp_wire::psp::ReconcileResponse;

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

/// What picking up one pending purchase's record came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickedUp {
    /// The pending purchase's id.
    pub id: String,
    pub what: Pickup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pickup {
    /// The record was there: the notes were claimed (and the purchase cleared).
    Claimed(crate::psp::Claimed),
    /// The record said the PSP holds the payment, or rejected the purchase, and
    /// nothing was signed. The purchase and its key are kept open until the
    /// window closes ([`Wallet::close_expired`]).
    Open(crate::store::OpenPurchase),
    /// An open purchase from an earlier pickup, not read again: its record is
    /// written once, and a reconciliation request settles it
    /// ([`psp_reconcile`]).
    StillOpen(crate::store::OpenPurchase),
    /// The PSP has not written the record yet (a payment settles at 6
    /// confirmations).
    NotThere,
    /// The record was there and was not accepted (it did not open, was not the
    /// PSP's, or did not match the purchase). Nothing changed.
    Bad(String),
}

/// Read the PSP's record for every pending purchase that has none yet and apply
/// it: the notes are claimed and the purchase cleared, or the purchase is marked
/// open with what the PSP said (held, or rejected) and kept. A purchase that is
/// open already is reported ([`Pickup::StillOpen`]) and not read. Each
/// purchase's address is computed from the PSP's DID, the purchase's own reply
/// DID and the purchase id; the record is opened with the purchase's one-off key
/// and the PSP's signature is checked ([`delivery::open_record`]). A record that
/// is not there yet is waited for, for `wait_secs` in all (0 reads once and
/// returns). Reading again changes nothing: a purchase that was claimed is no
/// longer pending, and one that is open is not read.
///
/// With no purchase to read nothing is asked of the network and the AIR settings
/// are not needed. Otherwise they are, and a missing `air.server` or `air.host`
/// is an error that names it. An unreachable AIR server is [`WalletError::Mint`]
/// and changes nothing; a record that fails a check is that purchase's
/// [`Pickup::Bad`] and the others are still picked up.
pub fn psp_pickup(
    wallet: &mut Wallet,
    air: &AirSettings,
    wait_secs: u64,
) -> Result<Vec<PickedUp>, WalletError> {
    struct Job {
        id: String,
        address: sp_wire::seal::PublicKey,
        reply_key: sp_wire::seal::SecretKey,
        psp: ServiceDid,
        purchase: [u8; 32],
    }
    let mut out: Vec<PickedUp> = Vec::new();
    let mut jobs: Vec<Job> = Vec::new();
    for p in wallet.pending_purchases() {
        if let Some(open) = &p.open {
            out.push(PickedUp {
                id: p.id.clone(),
                what: Pickup::StillOpen(open.clone()),
            });
            continue;
        }
        let made = (|| -> Result<Job, String> {
            let reply_key = sp_wire::air_request::addr::secret_from_hex(&p.reply_secret)
                .map_err(|e| format!("the saved reply key: {e}"))?;
            let purchase: [u8; 32] = hex::decode(&p.delivery_id)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or("the saved delivery id is not 32 bytes of hex")?;
            let psp = ServiceDid::parse(&p.mint_did_pubkey)
                .map_err(|e| format!("the PSP key the purchase was sealed to: {e}"))?;
            let reply = sp_wire::air_request::addr::key_to_did(&reply_key.public_key());
            Ok(Job {
                id: p.id.clone(),
                address: delivery::delivery_address(&psp, &reply, &purchase),
                reply_key,
                psp,
                purchase,
            })
        })();
        match made {
            Ok(job) => jobs.push(job),
            Err(why) => out.push(PickedUp {
                id: p.id.clone(),
                what: Pickup::Bad(why),
            }),
        }
    }
    if jobs.is_empty() {
        return Ok(out);
    }

    let (name, host) = crate::config::Party::Psp
        .address(air)
        .map_err(WalletError::Invalid)?;
    let server = ServerRef { name, host };
    let addresses: Vec<_> = jobs.iter().map(|j| j.address).collect();
    let read_secs = air.timeout_secs;
    let found = block_on_new_runtime(|| async {
        let client = client::connect(&server).await.map_err(|e| e.0)?;
        delivery::read_records(&client, &addresses, read_secs, wait_secs)
            .await
            .map_err(|e| e.0)
    })
    .map_err(|e| WalletError::Mint(e.0))?
    .map_err(|e| {
        WalletError::Mint(format!(
            "the PSP's records could not be read from the AIR server: {e}"
        ))
    })?;

    for (job, sealed) in jobs.into_iter().zip(found) {
        let what = match sealed {
            None => Pickup::NotThere,
            Some(bytes) => {
                match delivery::open_record(&job.reply_key, &job.psp, &job.purchase, &bytes) {
                    Err(e) => Pickup::Bad(format!("the record was not accepted: {e}")),
                    Ok(opened) => match wallet.apply_delivery(&job.id, &opened.outcome) {
                        Ok(crate::psp::Delivered::Claimed(c)) => Pickup::Claimed(c),
                        Ok(crate::psp::Delivered::Open(open)) => Pickup::Open(open),
                        // Applied by a copy of this wallet meanwhile.
                        Ok(crate::psp::Delivered::AlreadyDone) => continue,
                        Err(e) => Pickup::Bad(format!("the record could not be applied: {e}")),
                    },
                }
            }
        };
        out.push(PickedUp { id: job.id, what });
    }
    Ok(out)
}

/// What the reconciliation of one open payment came to this time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// The purchase's id.
    pub id: String,
    pub what: Reconciled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciled {
    /// The PSP answered: the notes were stored, and the purchase or credit, its
    /// key and the saved request were removed.
    Settled(crate::psp::Settled),
    /// The rules' `due_units` is 0: the PSP's fees take the whole amount, so
    /// nothing was built or sent, and the payment is lost at `open_until`. Said
    /// once; the wallet remembers it told the user.
    NothingDue(crate::psp::Loss),
    /// The request was sent and the PSP did not answer. It answers an accepted
    /// request only, so this is also what a refused one looks like. The identical
    /// request is sent again at the next start, until `open_until` (`attempts`
    /// requests have been built).
    Waiting { attempts: u32, open_until: u64 },
    /// The PSP did not answer, and every request the rules allow has been built:
    /// the PSP did not accept the request, and the payment is lost at
    /// `open_until`. Said once. The saved request is still sent again, in case it
    /// was accepted and its answer lost.
    NotAccepted {
        loss: crate::psp::Loss,
        attempts: u32,
    },
    /// Nothing was sent, and why (the purchase was sealed to another PSP than
    /// `air.psp_did`, say).
    NotSent(String),
    /// The call failed or the answer was refused; the text says which. The
    /// payment is as it was, with its key, and is tried again at the next start.
    /// A bad answer stores nothing.
    /// (At the close of the window, [`psp_close_expired`], a refused or bad
    /// answer deletes the payment all the same, and a failed call keeps it for the
    /// next start.)
    Failed(String),
}

/// What sending a saved request came to.
enum Step {
    Settled(crate::psp::Settled),
    /// The payment was settled already (by a copy of this wallet).
    Already,
    NoReply,
    /// The call failed (`network`: the AIR server or the PSP could not be
    /// reached, so the others will fail too) or the answer was refused.
    Failed {
        why: String,
        network: bool,
    },
}

/// Send the request saved for `id` as it is, and apply the answer.
fn send_saved(wallet: &mut Wallet, air: &AirSettings, id: &str) -> Result<Step, WalletError> {
    let to_send = wallet.reconcile_to_send(id)?;
    let sent = match crate::air::call_with_key(
        wallet,
        air,
        Party::Psp,
        KIND_PSP_RECONCILE,
        &to_send.body,
        &to_send.key,
    ) {
        Ok(sent) => sent,
        Err(e) => {
            return Ok(Step::Failed {
                why: e.to_string(),
                network: true,
            });
        }
    };
    let verified = match sent {
        crate::air::Sent::NoReply(_) => {
            wallet.note_unanswered(id, true)?;
            return Ok(Step::NoReply);
        }
        crate::air::Sent::Answered(verified) => verified,
    };
    wallet.note_unanswered(id, false)?;
    if verified.refused() {
        return Ok(Step::Failed {
            why: format!(
                "the PSP refused the reconciliation request in a signed reply: {}",
                String::from_utf8_lossy(verified.body())
            ),
            network: false,
        });
    }
    let response: ReconcileResponse = match serde_json::from_slice(verified.body()) {
        Ok(response) => response,
        Err(e) => {
            return Ok(Step::Failed {
                why: format!(
                    "PSP reconciliation over AIR: the PSP signed a reply that is not what was asked for: {e}"
                ),
                network: false,
            });
        }
    };
    Ok(match wallet.apply_reconcile(id, &response) {
        Ok(crate::psp::Applied::Settled(settled)) => Step::Settled(settled),
        Ok(crate::psp::Applied::AlreadyDone) => Step::Already,
        Err(e) => Step::Failed {
            why: e.to_string(),
            network: false,
        },
    })
}

/// Tell the user, once, about every open payment with nothing due (the PSP's fees
/// take the whole amount): [`Reconciled::NothingDue`], and nothing else. It asks
/// nothing of the network and needs no AIR settings. A payment it has told about
/// before is not reported again ([`psp_reconcile`] calls this first, so the two
/// never say it twice). The command line calls it by itself so that this is said
/// even when the PSP cannot be reached for the others.
pub fn psp_nothing_due(wallet: &mut Wallet) -> Result<Vec<ReconcileReport>, WalletError> {
    use crate::psp::ReconcileStatus;
    let now = sp_wire::air_request::addr::now_secs();
    let mut out = Vec::new();
    for open in wallet.open_reconciliations(now) {
        if open.state == ReconcileStatus::NothingDue && !open.told_lost {
            wallet.note_told_lost(&open.id)?;
            if let Some(loss) = wallet.reconcile_loss(&open.id) {
                out.push(ReconcileReport {
                    id: open.id,
                    what: Reconciled::NothingDue(loss),
                });
            }
        }
    }
    Ok(out)
}

/// Settle every open payment the PSP holds, rejected or owes a credit for, with a
/// reconciliation request (AIR kind 15), without being asked: this runs at every
/// wallet start and in `claim-psp`.
///
/// For each payment still open ([`Wallet::open_reconciliations`]):
///
/// - **Nothing due** (the rules' `due_units` is 0): nothing is built and nothing
///   is sent. The user is told once ([`Reconciled::NothingDue`]).
/// - **No request saved yet:** read the PSP's keysets (fresh), build the request
///   on its current keyset ([`Wallet::build_reconcile`]; it is saved before
///   anything is sent) and send it.
/// - **A request saved and unanswered:** send the identical request, once
///   (`air.attempts` tries of `air.reply_wait_secs`). The PSP answers a repeat
///   of an accepted request from its stored answer and counts nothing twice.
/// - **The answer** is checked and applied in one write
///   ([`Wallet::apply_reconcile`]): the notes are stored, and the purchase or
///   credit, its key and the saved request are removed.
/// - **No answer:** the PSP answers an accepted request only. The keysets are
///   read again; when the saved request's keyset is neither the PSP's current nor
///   its previous one, the one second request the rules allow is built on the
///   current keyset and sent once, in the same run. Otherwise only the identical
///   request is sent again, at the next start. When every request the rules
///   allow has gone unanswered the user is told once that the PSP did not accept
///   it ([`Reconciled::NotAccepted`]).
///
/// Nothing loops: each payment's request is sent once per call, and the second
/// one only after a rotation. With no open payment nothing is asked of the
/// network and the AIR settings are not needed; with nothing to send (every
/// payment has nothing due) neither. A request is for the PSP the purchase was
/// sealed to, and is not sent to another one ([`Reconciled::NotSent`]). A failed
/// call is that payment's [`Reconciled::Failed`] and stops the others (the AIR
/// server cannot be reached); the payment is tried again at the next start.
pub fn psp_reconcile(
    wallet: &mut Wallet,
    air: &AirSettings,
) -> Result<Vec<ReconcileReport>, WalletError> {
    use crate::psp::ReconcileStatus;
    let now = sp_wire::air_request::addr::now_secs();
    let mut out = psp_nothing_due(wallet)?;
    let to_do: Vec<_> = wallet
        .open_reconciliations(now)
        .into_iter()
        .filter(|o| o.state != ReconcileStatus::NothingDue)
        .collect();
    if to_do.is_empty() {
        return Ok(out);
    }
    // The settings are needed from here on: a missing one is named.
    Party::Psp.address(air).map_err(WalletError::Invalid)?;
    let psp = Party::Psp.did(air).to_hex();

    let push = |out: &mut Vec<ReconcileReport>, id: &str, what: Reconciled| {
        out.push(ReconcileReport {
            id: id.to_string(),
            what,
        });
    };
    for open in to_do {
        let id = open.id.clone();
        if open.mint != psp {
            push(
                &mut out,
                &id,
                Reconciled::NotSent(format!(
                    "purchase {id} was sealed to the PSP {}, but air.psp_did is {psp}. A reconciliation request is for the PSP the purchase was sent to, so nothing was sent",
                    open.mint
                )),
            );
            continue;
        }
        if open.state == ReconcileStatus::Due {
            let keysets = match psp_keysets(wallet, air) {
                Ok(keysets) => keysets,
                Err(e) => {
                    push(&mut out, &id, Reconciled::Failed(e.to_string()));
                    break;
                }
            };
            if let Err(e) = wallet.build_reconcile(&id, &keysets, now) {
                push(&mut out, &id, Reconciled::Failed(e.to_string()));
                continue;
            }
        }
        let mut step = send_saved(wallet, air, &id)?;
        if matches!(step, Step::NoReply) {
            // A request the PSP refused gets no reply, so what is left to ask is
            // whether the request's keyset is still one the PSP signs with.
            if let Ok(keysets) = psp_keysets(wallet, air) {
                let sent = wallet.reconcile_to_send(&id)?;
                if !crate::psp::keyset_is_live(&keysets, &sent.keyset)
                    && wallet.build_reconcile(&id, &keysets, now).is_ok()
                {
                    step = send_saved(wallet, air, &id)?;
                }
            }
        }
        match step {
            Step::Settled(settled) => push(&mut out, &id, Reconciled::Settled(settled)),
            Step::Already => {}
            Step::NoReply => {
                let open = wallet
                    .open_reconciliations(now)
                    .into_iter()
                    .find(|o| o.id == id);
                match open {
                    // nothing more can be built and nothing came back: said once
                    Some(o) if o.state == ReconcileStatus::Lost && !o.told_lost => {
                        wallet.note_told_lost(&id)?;
                        let loss = wallet.reconcile_loss(&id).expect("the payment is open");
                        let what = Reconciled::NotAccepted {
                            loss,
                            attempts: o.attempts,
                        };
                        push(&mut out, &id, what);
                    }
                    Some(o) => push(
                        &mut out,
                        &id,
                        Reconciled::Waiting {
                            attempts: o.attempts,
                            open_until: o.open_until,
                        },
                    ),
                    None => {}
                }
            }
            Step::Failed { why, network } => {
                push(&mut out, &id, Reconciled::Failed(why));
                if network {
                    break;
                }
            }
        }
    }
    Ok(out)
}

/// What closing the reconciliation window came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    /// The payments the last resend settled ([`Reconciled::Settled`]), and the
    /// ones whose last resend was answered with a refusal or a bad answer
    /// ([`Reconciled::Failed`]); the failed ones are deleted all the same, and
    /// reported in `lost`.
    pub reports: Vec<ReconcileReport>,
    /// The payments kept, with their key and saved request, because the last
    /// resend could not be sent: [`Reconciled::Failed`] for the one whose call
    /// failed, [`Reconciled::NotSent`] for the others (the AIR settings are
    /// missing, or an earlier call failed and the AIR server cannot be reached).
    /// They are closed at the next start.
    pub kept: Vec<ReconcileReport>,
    /// What [`Wallet::close_expired`] deleted, one [`crate::psp::Loss`] each.
    pub lost: Vec<crate::psp::Loss>,
}

/// Close the reconciliation window at `now`: send each expired payment's saved
/// request one last time, then delete what is left ([`Wallet::close_expired`]).
///
/// The PSP answers an identical resend of a request it took even after the
/// deadline (it holds the stored answer, or the record it saved before signing),
/// and never forfeits a payment with such a record, so a payment whose last
/// answer was lost can still be settled here. For each payment whose `open_until`
/// is `now` or earlier and that has a saved request:
///
/// - the saved bytes are sent once, as they are, with the usual `air.attempts`
///   tries ([`psp_reconcile`] does the same before the close). No request is
///   built, even when the request's keyset has left the PSP's live set, and
///   nothing loops;
/// - an answer is checked and applied by [`Wallet::apply_reconcile`], as on any
///   settle: the payment is settled and is not reported lost;
/// - no answer, a refusal or a bad answer: the payment is deleted and reported
///   lost, as before;
/// - **the send could not be made** (the AIR settings are missing, or the call
///   failed, which stops the sends: the AIR server cannot be reached): the
///   payment is **not deleted**. It is kept with its key and its saved request
///   ([`Closed::kept`]), and so is every later expired payment that was not
///   tried, and the close is tried again at the next start. Deleting it would
///   lose a payment the PSP may have settled already.
///
/// A payment with no saved request (nothing due, or none built) is deleted with
/// nothing sent. A request is for the PSP the purchase was sealed to; a payment
/// sealed to another one than `air.psp_did` is deleted with nothing sent.
pub fn psp_close_expired(
    wallet: &mut Wallet,
    air: &AirSettings,
    now: u64,
) -> Result<Closed, WalletError> {
    let mut reports = Vec::new();
    let mut kept: Vec<ReconcileReport> = Vec::new();
    let psp = Party::Psp.did(air).to_hex();
    let address = Party::Psp.address(air);
    let mut unreachable = false;
    for (id, mint) in wallet.expired_requests(now) {
        if mint != psp {
            continue;
        }
        let not_sent = |why: String| ReconcileReport {
            id: id.clone(),
            what: Reconciled::NotSent(why),
        };
        if let Err(e) = &address {
            kept.push(not_sent(format!(
                "the saved request was not sent one last time: {e}"
            )));
            continue;
        }
        if unreachable {
            kept.push(not_sent(
                "the saved request was not sent one last time: an earlier call failed and the AIR server cannot be reached"
                    .into(),
            ));
            continue;
        }
        match send_saved(wallet, air, &id)? {
            Step::Settled(settled) => reports.push(ReconcileReport {
                id,
                what: Reconciled::Settled(settled),
            }),
            Step::Already | Step::NoReply => {}
            Step::Failed { why, network } => {
                let report = ReconcileReport {
                    id,
                    what: Reconciled::Failed(why),
                };
                if network {
                    unreachable = true;
                    kept.push(report);
                } else {
                    reports.push(report);
                }
            }
        }
    }
    let keep: Vec<String> = kept.iter().map(|r| r.id.clone()).collect();
    let lost = wallet.close_expired_keeping(now, &keep)?;
    Ok(Closed {
        reports,
        kept,
        lost,
    })
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
/// outputs name the current one).
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
/// (nothing happened at the mint), unless the mint names notes that are spent
/// (`note_spent_elsewhere` and `spent`): those leave the balance and the request's
/// other notes are free again (see below). Anything else leaves it pending.
pub fn settle_fsp(wallet: &mut Wallet, air: &AirSettings, id: &str) -> Result<String, WalletError> {
    settle_fsp_with(wallet, id, &mut |w, service, op| match op {
        crate::fsp::FspOp::Issue { request, .. } => {
            send_fsp_issue(w, air, service, request).map(FspReply::Issue)
        }
        crate::fsp::FspOp::Spend { request, .. } => {
            send_fsp_spend(w, air, service, request).map(FspReply::Spend)
        }
    })
}

/// What the FSP mint answered to a pending request.
pub(crate) enum FspReply {
    Issue(sp_wire::fsp::IssueResponse),
    Spend(sp_wire::fsp::SpendResponse),
}

/// [`settle_fsp`], with the request sent by `send`.
///
/// **Notes the mint says are spent.** An FSP spend (a payment or a rollover) or
/// issue that the mint refuses with `note_spent_elsewhere` names every input that
/// is already spent. They go to the spent record and leave the balance, the
/// request's other notes are free again, and the request is dropped, as the ESP
/// rollover does (`send_rollover`). Without this the notes were freed like those of
/// any refusal and picked again: a stale FSP rollover was built and refused on every
/// connection, and `fsp pay` chose the same spent note on every attempt.
///
/// A refusal that names no note, or a position the request does not have, is a
/// `Mint` error and nothing is marked spent: the request is cancelled and its
/// notes are free, as after a plain refusal, so it is not sent again on every
/// connection. That holds for a rollover, a payment and an issue alike.
///
/// What it returns differs by who is waiting. A rollover is nobody's request, so
/// it is `Ok` with a line for the log. A payment or an issue did not happen, so it
/// is `Err(SpentElsewhere)`, whose text says what was done with the notes.
pub(crate) fn settle_fsp_with(
    wallet: &mut Wallet,
    id: &str,
    send: &mut dyn FnMut(
        &mut Wallet,
        ServiceDid,
        &crate::fsp::FspOp,
    ) -> Result<FspReply, WalletError>,
) -> Result<String, WalletError> {
    let p = wallet
        .pending_fsp()
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| WalletError::Unknown(format!("no pending FSP request {id}")))?;
    let rollover = matches!(&p.op, crate::fsp::FspOp::Spend { request, .. } if request.pay == 0);
    let sent = send(wallet, p.service, &p.op).and_then(|reply| match (&p.op, reply) {
        (crate::fsp::FspOp::Issue { .. }, FspReply::Issue(r)) => {
            let o = wallet.finish_fsp_issue(id, &r)?;
            let mut text = format!("issued {} FSP (fee {})", o.fsp, o.fee);
            for r in &o.refused {
                text.push_str(&format!("; not issued, ESP freed: {r}"));
            }
            Ok(text)
        }
        (crate::fsp::FspOp::Spend { .. }, FspReply::Spend(r)) => {
            let paid = wallet.finish_fsp_spend(id, &r)?;
            Ok(if rollover {
                "rolled over to the current keyset".to_string()
            } else {
                format!("paid {paid} FSP")
            })
        }
        _ => Err(WalletError::Mint(
            "the FSP mint answered with the other kind of reply".into(),
        )),
    });
    match sent {
        Err(WalletError::Refused(why)) => {
            wallet.cancel_fsp(id)?;
            Err(WalletError::Refused(why))
        }
        Err(WalletError::SpentElsewhere { why, inputs }) => {
            // A mint that names no note, or one the request does not have, has
            // given an answer that cannot be used: nothing is marked spent. The
            // request is cancelled and its notes freed, as for a plain refusal,
            // so it is not sent again on every connection.
            let notes = p.op.note_ids().len();
            if inputs.is_empty() || inputs.iter().any(|&i| i >= notes) {
                wallet.cancel_fsp(id)?;
                return Err(WalletError::Mint(format!(
                    "the mint named a note the request did not have: it named positions {inputs:?} of a request of {notes} note(s) ({why}). The request is cancelled, nothing is marked spent, and its notes are free again"
                )));
            }
            let report = wallet.mark_spent_in_fsp(id, &inputs)?;
            if rollover {
                Ok(format!(
                    "rollover refused ({why}): {} note(s) marked spent, {} freed",
                    report.marked_spent, report.freed
                ))
            } else {
                Err(WalletError::SpentElsewhere {
                    why: format!(
                        "{why}. {} note(s) are marked spent in the wallet, {} other note(s) are free again",
                        report.marked_spent, report.freed
                    ),
                    inputs,
                })
            }
        }
        other => other,
    }
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
            Err(e) => out
                .log
                .push(fsp_failure(wallet, "pending", "not finished", &id, &e)),
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
            Err(e) => out
                .log
                .push(fsp_failure(wallet, "rollover", "failed", &id, &e)),
        }
    }
    Ok(out)
}

/// The log line for an FSP request that `settle_fsp` could not finish. A request
/// that is still pending is tried again on the next connection. One the wallet
/// cancelled on the way (the mint named a position the request did not have, see
/// `settle_fsp_with`) is gone, so it is not retried and the line says so.
pub(crate) fn fsp_failure(
    wallet: &Wallet,
    what: &str,
    unfinished: &str,
    id: &str,
    e: &WalletError,
) -> String {
    if wallet.pending_fsp().iter().any(|p| p.id == id) {
        format!("{what} {id} {unfinished}, retried on the next connection: {e}")
    } else {
        format!("{what} {id} cancelled, not retried: {e}")
    }
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
        .ok_or_else(|| WalletError::Unknown(format!("no pending rollover {id}")))?;
    let received = p.schedule.starts_with(crate::handoff::SWAP_TAG);
    let body = serde_json::to_vec(&p.body)
        .map_err(|e| WalletError::Mint(format!("rollover at {}: {e}", p.record)))?;
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
