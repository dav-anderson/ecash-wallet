//! The wallet's calls to the PSP, the ESP and the FSP mints. They are made over
//! AIR and only over AIR: there is no HTTP form of any of them. This is the one place that
//! says which call goes to which mint, so the library's callers (the command
//! line, an app, the tests) all get the same rule.
//!
//! **The PSP's** calls are its mint info ([`verify_psp`]), its keys, keysets and
//! rotation ([`psp_keys`], [`psp_keysets`], [`psp_window`], and the calls built
//! on them: [`rotation_sync`], [`reclaim_handoff`]) and its two POSTs, rollover
//! and check-state ([`psp_post`], and the calls built on it: [`rotation_sync`],
//! [`reclaim_handoff`], [`check_handoff`], [`complete_import`]). **What the PSP
//! mint owes for a purchase** is not a call: the PSP mint writes an owed record
//! for each payment to the SPI's AIR server, and [`psp_pickup`] reads those
//! records (the AIR server is `air.server` and `air.host`, as for every PSP
//! call). **The PSP's claim** (AIR kind 15) is how the notes are had: [`psp_claim`]
//! builds the claim from the record, sends it and applies the answer, and
//! [`psp_close_expired`] closes the records whose window has passed.
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
use std::time::Duration;

use mint_types::Amount;
use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use secp256k1::PublicKey;
use sp_wire::ServiceDid;
use sp_wire::air_request::client::{self, ServerRef, block_on_new_runtime};
use sp_wire::air_request::delivery;
use sp_wire::air_request::{
    KIND_CHECK_STATE, KIND_EXCHANGE, KIND_FEES, KIND_FSP_ISSUE, KIND_FSP_SPEND, KIND_KEYS,
    KIND_KEYSETS, KIND_PSP_CLAIM, KIND_REDEEM, KIND_ROLLOVER, KIND_ROTATION,
};
use sp_wire::esp::exchange::{ExchangeRequest, ExchangeResponse};
use sp_wire::esp::redeem::RedeemResponse;
use sp_wire::keys::{CheckStateRequest, CheckStateResponse};
use sp_wire::psp::ClaimResponse;

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

/// What picking up one claim key's owed records came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickedUp {
    /// The claim key's id (the purchase).
    pub id: String,
    /// The records read for the first time, in order.
    pub new: Vec<crate::store::OwedClaim>,
    /// The cells that did not open (a mint error or a forged write) and were
    /// skipped for good: the cell's index and why.
    pub skipped: Vec<(u32, String)>,
    /// True when the key holds no record at all: the PSP mint has not written
    /// one yet (a payment is settled at the confirmations its tier asks for), or
    /// the payload was never paid.
    pub no_record: bool,
    /// Why the key could not be read, if it could not (a claim key or a PSP mint
    /// key in the wallet file that is not valid, or an AIR failure after the
    /// first read). The key is as it was.
    pub problem: Option<String>,
}

/// The shortest pause between two purchases, in seconds: in [`psp_pickup`]
/// between the AIR sessions of two purchases, and in [`psp_claim`] between the
/// claims of two purchases. Fixed: there is no setting for it.
const PURCHASE_GAP_MIN_SECS: u64 = 1;

/// The longest pause between two purchases, in seconds (see
/// [`PURCHASE_GAP_MIN_SECS`]).
const PURCHASE_GAP_MAX_SECS: u64 = 30;

/// One pause between two purchases: drawn uniformly from
/// [`PURCHASE_GAP_MIN_SECS`] to [`PURCHASE_GAP_MAX_SECS`], to the millisecond,
/// with the operating system's random numbers. Two purchases read or claimed one
/// right after the other would tell the Issuer, who runs the AIR server, that
/// they are one buyer's.
fn purchase_gap() -> Duration {
    Duration::from_millis(
        OsRng.gen_range(PURCHASE_GAP_MIN_SECS * 1_000..=PURCHASE_GAP_MAX_SECS * 1_000),
    )
}

/// The cells of one purchase that [`read_purchase`] reads: the PSP mint's DID and
/// the purchase's claim DID give every one of them (`delivery::owed_address`).
struct PurchaseCells {
    /// The purchase's place in [`psp_pickup`]'s list.
    job: usize,
    psp: ServiceDid,
    claim: ServiceDid,
    /// The first cell to read: the claim key's `next_index`.
    next: u32,
    /// Whether the first read is held: the key holds no record yet.
    hold: bool,
}

/// What a purchase's session sends back to [`pick_up_each`].
enum Found {
    /// The record in cell `index` of purchase `job`. The session reads the next
    /// cell when `go_on` says `true`, and ends when it says `false`.
    Record {
        job: usize,
        index: u32,
        sealed: Vec<u8>,
        go_on: tokio::sync::oneshot::Sender<bool>,
    },
    /// The purchase's session has ended: at an empty cell (`None`), or because
    /// the AIR server could not be reached or read (`Some`, why).
    Ended { job: usize, failed: Option<String> },
}

/// Read the owed records of ONE purchase, on an AIR session of its own. Every
/// address read here is a cell of this one purchase (`cells`: its PSP mint, its
/// claim DID, its indexes); never pass the cells of two purchases. The session
/// is opened here and dropped here, so no other purchase's read can share it:
/// one session reading the cells of two purchases would tell the Issuer, who
/// runs the AIR server, that they are one buyer's. This is the only place the
/// wallet reads delivery cells.
///
/// The cells are read in order from `cells.next`. Each record found is sent to
/// [`pick_up_each`], which applies it, and the next cell is read only when that
/// says so. The first read is held for `hold_secs` when `cells.hold` (0 reads
/// once); every later one is read once. The session ends at the first empty
/// cell.
async fn read_purchase(
    server: ServerRef,
    cells: PurchaseCells,
    read_secs: u64,
    hold_secs: u64,
    found: tokio::sync::mpsc::UnboundedSender<Found>,
) {
    let job = cells.job;
    let read = async {
        let client = client::connect(&server).await.map_err(|e| e.0)?;
        let mut index = cells.next;
        let mut wait = if cells.hold { hold_secs } else { 0 };
        loop {
            let address = delivery::owed_address(&cells.psp, &cells.claim, index);
            let sealed = delivery::read_record(&client, &address, read_secs, wait)
                .await
                .map_err(|e| e.0)?;
            wait = 0;
            let Some(sealed) = sealed else {
                return Ok(());
            };
            let (go_on, answer) = tokio::sync::oneshot::channel();
            let sent = found.send(Found::Record {
                job,
                index,
                sealed,
                go_on,
            });
            if sent.is_err() || !matches!(answer.await, Ok(true)) {
                return Ok(());
            }
            index += 1;
        }
    };
    let failed: Option<String> = read.await.err();
    // The receiver is gone only when the pickup has ended already.
    let _ = found.send(Found::Ended { job, failed });
}

/// [`psp_pickup`]'s reads: one session per purchase ([`read_purchase`]), opened
/// in the order of `jobs`, the first at once and each later one after a pause of
/// its own ([`purchase_gap`]). The records found are applied here, one at a
/// time, as they come. A purchase with no record yet is held until `wait_secs`
/// after the start, counted from when its session is opened; one opened after
/// that is read once.
///
/// A session that fails stops the opening of more: the purchases not opened yet
/// get a [`PickedUp::problem`] and are read at the next start. When every session
/// opened failed and no record was read, the AIR server could not be reached and
/// that is the error.
async fn pick_up_each(
    wallet: &mut Wallet,
    out: &mut [PickedUp],
    jobs: Vec<(usize, String, PurchaseCells)>,
    server: ServerRef,
    read_secs: u64,
    wait_secs: u64,
    now: u64,
) -> Result<(), WalletError> {
    use tokio::time::Instant;
    let start = Instant::now();
    let deadline = start.checked_add(Duration::from_secs(wait_secs));
    let mut purchases: Vec<(usize, String)> = Vec::with_capacity(jobs.len());
    let mut waiting = std::collections::VecDeque::with_capacity(jobs.len());
    for (at, id, cells) in jobs {
        purchases.push((at, id));
        waiting.push_back(cells);
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut tx = Some(tx);
    let mut next_open = start;
    let mut stopped: Option<String> = None;
    let (mut opened, mut failed, mut read_any) = (0usize, 0usize, false);
    let mut ended = vec![false; purchases.len()];
    loop {
        if stopped.is_some() || waiting.is_empty() {
            // No session is opened any more: the channel closes when the last
            // open one has ended.
            tx = None;
        }
        let found = match &tx {
            Some(sender) => match tokio::time::timeout_at(next_open, rx.recv()).await {
                Ok(found) => found,
                Err(_) => {
                    let cells = waiting.pop_front().expect("a purchase is waiting");
                    let hold_secs = deadline.map_or(wait_secs, |d| {
                        d.saturating_duration_since(Instant::now()).as_secs()
                    });
                    tokio::spawn(read_purchase(
                        server.clone(),
                        cells,
                        read_secs,
                        hold_secs,
                        sender.clone(),
                    ));
                    opened += 1;
                    next_open = Instant::now() + purchase_gap();
                    continue;
                }
            },
            None => rx.recv().await,
        };
        let Some(found) = found else {
            break;
        };
        match found {
            Found::Record {
                job,
                index,
                sealed,
                go_on,
            } => {
                read_any = true;
                let (at, id) = &purchases[job];
                let more = match wallet.apply_delivery(id, index, &sealed, now) {
                    Ok(crate::psp::Delivered::Stored(record)) => {
                        out[*at].new.push(record);
                        true
                    }
                    Ok(crate::psp::Delivered::AlreadyDone) => true,
                    Err(WalletError::Mint(why)) => {
                        out[*at].skipped.push((index, why));
                        wallet.skip_record(id, index)?;
                        true
                    }
                    Err(e) => {
                        out[*at].problem = Some(e.to_string());
                        false
                    }
                };
                // The session is gone only when it has ended already.
                let _ = go_on.send(more);
            }
            Found::Ended { job, failed: None } => ended[job] = true,
            Found::Ended {
                job,
                failed: Some(why),
            } => {
                ended[job] = true;
                failed += 1;
                let why =
                    format!("the PSP mint's records could not be read from the AIR server: {why}");
                out[purchases[job].0].problem = Some(WalletError::Mint(why.clone()).to_string());
                stopped.get_or_insert(why);
            }
        }
    }
    // A purchase whose session ended without a word (it panicked) was not read to
    // its end: it must not look like a purchase with no record yet, which is
    // dropped as unpaid after `psp.unpaid_key_days`.
    for (job, (at, _)) in purchases.iter().enumerate() {
        if !ended[job] && out[*at].problem.is_none() {
            out[*at].problem =
                Some("not read to its end this time, and read again at the next start".into());
        }
    }
    let Some(why) = stopped else {
        return Ok(());
    };
    if failed == opened && !read_any {
        return Err(WalletError::Mint(why));
    }
    for cells in waiting {
        out[purchases[cells.job].0].problem = Some(format!(
            "not read this time, and read again at the next start: an earlier read failed ({why})"
        ));
    }
    Ok(())
}

/// Read the next owed record of every claim key and apply what is there.
///
/// Each key's records are the cells 0, 1, 2 and so on of the PSP mint, computed
/// from its DID, the key's claim DID and the index
/// (`sp_wire::air_request::delivery::owed_address`). The wallet reads from the
/// key's `next_index`, opens each cell with the claim key and the PSP mint's
/// signature is checked ([`Wallet::apply_delivery`]), skips a cell that does not
/// open ([`PickedUp::skipped`]) and reads on, and stops at the first cell that is
/// empty, which it will read again the next time. A key that holds no record yet
/// is waited for (0 reads once and returns); a key that holds records is read
/// once. Reading again changes nothing: a cell that was applied or skipped is not
/// read again.
///
/// **One AIR session per purchase.** Each claim key (purchase) is read on an AIR
/// session of its own, and no session reads or holds the cells of two purchases:
/// the Issuer runs the AIR server and would otherwise learn which purchases are
/// one buyer's. The purchases are taken in a random order, and each session after
/// the first is opened after a random pause of 1 to 30 seconds. So the call takes
/// up to about 30 seconds for each purchase after the first, and blocks the
/// calling thread for that long (an app may call it from a thread of its own).
/// The sessions that wait run side by side: each waits until `wait_secs` after
/// the call began, counted from when its session is opened, and one opened later
/// than that is read once. The result is in the order of
/// [`Wallet::claim_keys`], whatever order the purchases were read in.
///
/// With no claim key nothing is asked of the network and the AIR settings are not
/// needed. Otherwise they are, and a missing `air.server` or `air.host` is an
/// error that names it. An unreachable AIR server is [`WalletError::Mint`] and
/// changes nothing; a record that fails a check is that key's
/// [`PickedUp::skipped`] and the others are still picked up. A read that fails
/// after another purchase was read is that purchase's [`PickedUp::problem`], and
/// the purchases not read yet are left for the next start (their `problem` says
/// so).
pub fn psp_pickup(
    wallet: &mut Wallet,
    air: &AirSettings,
    wait_secs: u64,
) -> Result<Vec<PickedUp>, WalletError> {
    pickup_of(wallet, air, wait_secs, None)
}

/// [`psp_pickup`] for every claim key (`only` is `None`), or for the one claim key
/// `only` names ([`psp_one_purchase`]): then the result holds that key alone.
fn pickup_of(
    wallet: &mut Wallet,
    air: &AirSettings,
    wait_secs: u64,
    only: Option<&str>,
) -> Result<Vec<PickedUp>, WalletError> {
    let mut out: Vec<PickedUp> = Vec::new();
    let mut jobs: Vec<(usize, String, PurchaseCells)> = Vec::new();
    for key in wallet.claim_keys() {
        if only.is_some_and(|id| key.id != id) {
            continue;
        }
        out.push(PickedUp {
            id: key.id.clone(),
            new: Vec::new(),
            skipped: Vec::new(),
            no_record: false,
            problem: None,
        });
        let made = (|| -> Result<PurchaseCells, String> {
            let psp = ServiceDid::parse(&key.psp_did)
                .map_err(|e| format!("the PSP mint key the purchase was sealed to: {e}"))?;
            let claim = ServiceDid::parse(&key.claim_did)
                .map_err(|e| format!("the saved claim DID: {e}"))?;
            Ok(PurchaseCells {
                // set below, once the order is drawn
                job: 0,
                psp,
                claim,
                next: key.next_index,
                hold: key.records.is_empty(),
            })
        })();
        match made {
            Ok(cells) => jobs.push((out.len() - 1, key.id.clone(), cells)),
            Err(why) => {
                let last = out.len() - 1;
                out[last].problem = Some(why);
            }
        }
    }
    if jobs.is_empty() {
        return Ok(out);
    }

    let (name, host) = crate::config::Party::Psp
        .address(air)
        .map_err(WalletError::Invalid)?;
    let server = ServerRef { name, host };
    let read_secs = air.timeout_secs;
    let now = sp_wire::air_request::addr::now_secs();
    // A random order, not the order the purchases were made in. Each keeps its
    // place in `jobs` (`PurchaseCells::job`), and `out` keeps the claim keys'.
    let mut order = jobs;
    order.shuffle(&mut OsRng);
    let mut jobs: Vec<(usize, String, PurchaseCells)> = Vec::with_capacity(order.len());
    for (job, (at, id, mut cells)) in order.into_iter().enumerate() {
        cells.job = job;
        jobs.push((at, id, cells));
    }
    {
        let (wallet, out) = (&mut *wallet, &mut out[..]);
        block_on_new_runtime(move || {
            pick_up_each(wallet, out, jobs, server, read_secs, wait_secs, now)
        })
        .map_err(|e| WalletError::Mint(e.0))??;
    }
    for p in out.iter_mut() {
        if let Some(key) = wallet.claim_keys().iter().find(|k| k.id == p.id) {
            p.no_record = key.records.is_empty() && p.problem.is_none();
        }
    }
    Ok(out)
}

/// What claiming one owed record came to this time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimReport {
    /// The claim key's id (the purchase).
    pub id: String,
    /// The record's index under the claim key.
    pub index: u32,
    pub what: ClaimOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The PSP mint answered: the notes were stored and the record is done.
    Claimed(crate::psp::Settled),
    /// The claim was sent and the PSP mint did not answer. It answers an accepted
    /// claim only, so this is also what a refused one looks like. The identical
    /// claim is sent again at the next start, until the window closes
    /// (`attempts` claims have been built).
    Waiting { attempts: u32, window_ends: u64 },
    /// The PSP mint did not answer, and every claim the record allows has been
    /// built: the PSP mint did not accept the claim. Said once. The saved claim is
    /// still sent again, in case it was accepted and its answer lost.
    NotAccepted {
        loss: crate::psp::Loss,
        attempts: u32,
    },
    /// Nothing was sent, and why (the purchase was sealed to another PSP mint than
    /// `air.psp_did`, say).
    NotSent(String),
    /// The call failed or the answer was refused; the text says which. The record
    /// is as it was, with its key, and is tried again at the next start. A bad
    /// answer stores nothing. (At the close of the window, [`psp_close_expired`], a
    /// refused or bad answer gives the claim up all the same, and a failed call
    /// keeps it for the next start.)
    Failed(String),
}

/// What sending a saved claim came to.
enum Step {
    Settled(crate::psp::Settled),
    /// The record was done already (by a copy of this wallet).
    Already,
    NoReply,
    /// The call failed (`network`: the AIR server or the PSP mint could not be
    /// reached, so the others will fail too) or the answer was refused.
    Failed {
        why: String,
        network: bool,
    },
}

/// Send the claim saved for record `index` of purchase `id` as it is, and apply
/// the answer.
fn send_saved(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
    index: u32,
) -> Result<Step, WalletError> {
    send_saved_of(wallet, air, id, index, None)
}

/// [`send_saved`] for the saved claim whose hash is `other` (one of the record's
/// other saved claims, which a merge kept), or the main one for `None`. Only the
/// main one's silence is recorded (`unanswered`).
fn send_saved_of(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
    index: u32,
    other: Option<&str>,
) -> Result<Step, WalletError> {
    let to_send = wallet.claim_to_send_of(id, index, other)?;
    let sent = match crate::air::call_with_key(
        wallet,
        air,
        Party::Psp,
        KIND_PSP_CLAIM,
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
            if other.is_none() {
                wallet.note_unanswered(id, index, true)?;
            }
            return Ok(Step::NoReply);
        }
        crate::air::Sent::Answered(verified) => verified,
    };
    if other.is_none() {
        wallet.note_unanswered(id, index, false)?;
    }
    if verified.refused() {
        return Ok(Step::Failed {
            why: format!(
                "the PSP mint refused the claim in a signed reply: {}",
                String::from_utf8_lossy(verified.body())
            ),
            network: false,
        });
    }
    let response: ClaimResponse = match serde_json::from_slice(verified.body()) {
        Ok(response) => response,
        Err(e) => {
            return Ok(Step::Failed {
                why: format!(
                    "PSP claim over AIR: the PSP mint signed a reply that is not what was asked for: {e}"
                ),
                network: false,
            });
        }
    };
    Ok(match wallet.apply_claim_to(id, index, other, &response) {
        Ok(crate::psp::Applied::Settled(settled)) => Step::Settled(settled),
        Ok(crate::psp::Applied::AlreadyDone) => Step::Already,
        Err(e) => Step::Failed {
            why: e.to_string(),
            network: false,
        },
    })
}

/// Send each other saved claim of record `index` of purchase `id` (the ones a
/// merge kept beside the main one, [`crate::store::OwedClaim::others`]), first.
/// The first one the PSP mint answers is applied: the record is done and every
/// saved claim of it is dropped, so the main one is not sent and nothing is told
/// lost. One refused in a signed reply is dropped. One with no reply is kept and
/// sent again at the next start (or, at the close, given up: `closing`). Returns
/// what settled the record, if one did, and whether a call failed for the network.
fn send_others(
    wallet: &mut Wallet,
    air: &AirSettings,
    id: &str,
    index: u32,
    closing: bool,
) -> Result<(Option<Step>, bool), WalletError> {
    for hash in wallet.other_claims(id, index) {
        match send_saved_of(wallet, air, id, index, Some(&hash))? {
            step @ (Step::Settled(_) | Step::Already) => return Ok((Some(step), false)),
            Step::NoReply => {
                if closing {
                    wallet.drop_other_claim(id, index, &hash)?;
                }
            }
            Step::Failed { network: true, .. } => return Ok((None, true)),
            Step::Failed { network: false, .. } => wallet.drop_other_claim(id, index, &hash)?,
        }
    }
    Ok((None, false))
}

/// The PSP mint's current keyset and its epoch (rotation, kind 4) and that
/// keyset's keys (kind 2), as a claim is built from them.
fn current_keys(
    wallet: &mut Wallet,
    air: &AirSettings,
) -> Result<(Window, BTreeMap<Amount, PublicKey>), WalletError> {
    let window = psp_window(wallet, air)?;
    let keys = psp_keys(wallet, air)?;
    Ok((window, keys))
}

/// Claim every owed record the PSP mint has written, without being asked: this
/// runs at every wallet start and in `claim-psp`, after [`psp_pickup`].
///
/// For each record that is still open ([`Wallet::open_claims`]):
///
/// - **No claim saved yet:** read the PSP mint's current keyset (rotation, kind 4)
///   and its keys (kind 2), build the claim on that keyset
///   ([`Wallet::build_claim`]; it is saved before anything is sent) and send it as
///   AIR kind 15.
/// - **A claim saved and unanswered:** send the identical claim, once
///   (`air.attempts` tries of `air.reply_wait_secs`). The PSP mint answers a repeat
///   of an accepted claim from its stored answer and counts nothing twice.
/// - **The answer** is checked and applied in one write
///   ([`Wallet::apply_claim`]): the notes are stored and the record is done.
/// - **No answer:** the PSP mint answers an accepted claim only. The current
///   keyset is read again. When it is not the keyset the saved claim names (the
///   keyset rotated between the two), the claim is built again on the current one
///   and sent once, in the same run, as long as the record's `max_attempts` allow
///   it. Otherwise the identical claim is sent once more. When every claim the
///   record allows has gone unanswered the user is told once that the PSP mint did
///   not accept it ([`ClaimOutcome::NotAccepted`]).
///
/// Nothing loops: each record's claim is sent at most twice per call. With no
/// record to claim nothing is asked of the network and the AIR settings are not
/// needed. A claim is for the PSP mint the purchase was sealed to, and is not sent
/// to another one ([`ClaimOutcome::NotSent`]). A failed call is that record's
/// [`ClaimOutcome::Failed`] and stops the others (the AIR server cannot be
/// reached); the record is tried again at the next start.
///
/// **The purchases are taken in a random order**, each purchase's records in
/// order, and before the first call for a purchase after the first one the wallet
/// pauses for a random 1 to 30 seconds: claims of two purchases sent one right
/// after the other would tell the Issuer they are one buyer's. Every call is on an
/// AIR session of its own. So the call takes up to about 30 seconds for each
/// purchase after the first, and blocks the calling thread for that long (an app
/// may call it from a thread of its own). The reports are in the order the
/// records were taken: each purchase's in index order, the purchases in the
/// random order.
pub fn psp_claim(wallet: &mut Wallet, air: &AirSettings) -> Result<Vec<ClaimReport>, WalletError> {
    claim_of(wallet, air, None)
}

/// [`psp_claim`] for every purchase (`only` is `None`), or for the records of the
/// one purchase `only` names ([`psp_one_purchase`]).
fn claim_of(
    wallet: &mut Wallet,
    air: &AirSettings,
    only: Option<&str>,
) -> Result<Vec<ClaimReport>, WalletError> {
    use crate::psp::ClaimStatus;
    let now = sp_wire::air_request::addr::now_secs();
    let mut to_do = wallet.open_claims(now);
    if let Some(id) = only {
        to_do.retain(|o| o.id == id);
    }
    let mut out = Vec::new();
    if to_do.is_empty() {
        return Ok(out);
    }
    // The settings are needed from here on: a missing one is named.
    Party::Psp.address(air).map_err(WalletError::Invalid)?;
    let psp = Party::Psp.did(air).to_hex();

    let push = |out: &mut Vec<ClaimReport>, id: &str, index: u32, what: ClaimOutcome| {
        out.push(ClaimReport {
            id: id.to_string(),
            index,
            what,
        });
    };
    // One list per purchase, each in the order of its records, and the purchases
    // in a random order.
    let mut purchases: Vec<Vec<crate::psp::OpenClaim>> = Vec::new();
    for open in to_do {
        match purchases.iter_mut().find(|p| p[0].id == open.id) {
            Some(records) => records.push(open),
            None => purchases.push(vec![open]),
        }
    }
    purchases.shuffle(&mut OsRng);
    let mut called = false;
    'purchases: for records in purchases {
        let mut this_called = false;
        for open in records {
            let (id, index) = (open.id.clone(), open.index);
            if open.psp != psp {
                push(
                    &mut out,
                    &id,
                    index,
                    ClaimOutcome::NotSent(format!(
                        "purchase {id} was sealed to the PSP mint {}, but air.psp_did is {psp}. A claim is for the PSP mint the purchase was sent to, so nothing was sent",
                        open.psp
                    )),
                );
                continue;
            }
            // A pause before this purchase's first call, when an earlier purchase made
            // one: none before the first purchase, none between records of one.
            if !this_called {
                if called {
                    std::thread::sleep(purchase_gap());
                }
                this_called = true;
                called = true;
            }
            // The other saved claims a merge kept go first: if the PSP mint signed one
            // of them, the record is done with it and the main one is not sent.
            match send_others(wallet, air, &id, index, false)? {
                (Some(Step::Settled(settled)), _) => {
                    push(&mut out, &id, index, ClaimOutcome::Claimed(settled));
                    continue;
                }
                (Some(_), _) => continue,
                (None, true) => {
                    push(
                        &mut out,
                        &id,
                        index,
                        ClaimOutcome::Failed(
                            "an other saved claim could not be sent: the AIR server cannot be reached"
                                .into(),
                        ),
                    );
                    break 'purchases;
                }
                (None, false) => {}
            }
            if open.status == ClaimStatus::Due {
                let (window, keys) = match current_keys(wallet, air) {
                    Ok(read) => read,
                    Err(e) => {
                        push(&mut out, &id, index, ClaimOutcome::Failed(e.to_string()));
                        break 'purchases;
                    }
                };
                if let Err(e) = wallet.build_claim(&id, index, &window, &keys, now) {
                    push(&mut out, &id, index, ClaimOutcome::Failed(e.to_string()));
                    continue;
                }
            }
            let mut step = send_saved(wallet, air, &id, index)?;
            if matches!(step, Step::NoReply) {
                // A claim the PSP mint refused gets no reply, so what is left to ask is
                // whether the keyset the claim names is still the one it signs with.
                if let Ok(window) = psp_window(wallet, air) {
                    let sent = wallet.claim_to_send(&id, index)?;
                    if window.current_id != sent.keyset {
                        if let Ok(keys) = psp_keys(wallet, air)
                            && wallet.build_claim(&id, index, &window, &keys, now).is_ok()
                        {
                            step = send_saved(wallet, air, &id, index)?;
                        }
                    } else {
                        step = send_saved(wallet, air, &id, index)?;
                    }
                }
            }
            match step {
                Step::Settled(settled) => {
                    push(&mut out, &id, index, ClaimOutcome::Claimed(settled))
                }
                Step::Already => {}
                Step::NoReply => {
                    let open = wallet
                        .open_claims(now)
                        .into_iter()
                        .find(|o| o.id == id && o.index == index);
                    match open {
                        // nothing more can be built and nothing came back: said once
                        Some(o) if o.status == ClaimStatus::Refused && !o.told_lost => {
                            wallet.note_told_lost(&id, index)?;
                            let loss = wallet.refused_loss(&id, index).expect("the record is open");
                            let what = ClaimOutcome::NotAccepted {
                                loss,
                                attempts: o.attempts,
                            };
                            push(&mut out, &id, index, what);
                        }
                        Some(o) => push(
                            &mut out,
                            &id,
                            index,
                            ClaimOutcome::Waiting {
                                attempts: o.attempts,
                                window_ends: o.window_ends,
                            },
                        ),
                        None => {}
                    }
                }
                Step::Failed { why, network } => {
                    push(&mut out, &id, index, ClaimOutcome::Failed(why));
                    if network {
                        break 'purchases;
                    }
                }
            }
        }
    }
    Ok(out)
}

/// What closing the claim windows came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    /// The records the last resend settled ([`ClaimOutcome::Claimed`]), and the
    /// ones whose last resend was answered with a refusal or a bad answer
    /// ([`ClaimOutcome::Failed`]); the failed ones are given up all the same, and
    /// reported in `lost`.
    pub reports: Vec<ClaimReport>,
    /// The records kept, with their key and saved claim, because the last resend
    /// could not be sent: [`ClaimOutcome::Failed`] for the one whose call failed,
    /// [`ClaimOutcome::NotSent`] for the others (the AIR settings are missing, or
    /// an earlier call failed and the AIR server cannot be reached). They are
    /// closed at the next start.
    pub kept: Vec<ClaimReport>,
    /// What [`Wallet::close_expired`] reported lost, one [`crate::psp::Loss`] each.
    pub lost: Vec<crate::psp::Loss>,
}

/// Close the claim windows at `now`: send each expired record's saved claim one
/// last time, then delete what is left ([`Wallet::close_expired`]).
///
/// The PSP mint answers an identical resend of a claim it took even after the
/// deadline (it holds the stored answer), so a record whose last answer was lost
/// can still be settled here. For each record whose window has closed and that has
/// a saved claim:
///
/// - the saved bytes are sent once, as they are, with the usual `air.attempts`
///   tries ([`psp_claim`] does the same before the close). No claim is built, even
///   when the claim's keyset has left the PSP mint's live set, and nothing loops;
/// - an answer is checked and applied by [`Wallet::apply_claim`], as on any claim:
///   the record is done and is not reported lost;
/// - no answer, a refusal or a bad answer: the claim is given up, and the record
///   is reported lost by [`Wallet::close_expired`];
/// - **the send could not be made** (the AIR settings are missing, or the call
///   failed, which stops the sends: the AIR server cannot be reached): the claim
///   key is **not deleted**. It is kept with its secret and its saved claim
///   ([`Closed::kept`]), and so is every later expired record that was not tried,
///   and the close is tried again at the next start. Deleting it would lose a
///   payment the PSP mint may have settled already.
///
/// A record sealed to another PSP mint than `air.psp_did` has its claim given up
/// with nothing sent.
///
/// **The purchases are taken in a random order**, each purchase's records in
/// order, and before the first resend of each purchase after the first one the
/// wallet pauses for a random 1 to 30 seconds, as [`psp_claim`] does: last resends
/// of two purchases sent one right after the other would tell the Issuer they are
/// one buyer's. Every resend is on an AIR session of its own. So the call takes up
/// to about 30 seconds for each purchase after the first that has a resend to
/// send, and blocks the calling thread for that long. [`Closed::reports`] and
/// [`Closed::kept`] are in the order the records were taken.
pub fn psp_close_expired(
    wallet: &mut Wallet,
    air: &AirSettings,
    now: u64,
) -> Result<Closed, WalletError> {
    close_of(wallet, air, now, None)
}

/// [`psp_close_expired`] for every purchase (`only` is `None`), or with the last
/// resends of the one purchase `only` names ([`psp_one_purchase`]). Either way the
/// close that needs no network ([`Wallet::close_expired`]) is made for every key:
/// a record that still holds a saved claim is not lost or deleted by it, so
/// another purchase's last resend waits for its own turn.
fn close_of(
    wallet: &mut Wallet,
    air: &AirSettings,
    now: u64,
    only: Option<&str>,
) -> Result<Closed, WalletError> {
    let mut reports = Vec::new();
    let mut kept: Vec<ClaimReport> = Vec::new();
    let psp = Party::Psp.did(air).to_hex();
    let address = Party::Psp.address(air);
    let mut unreachable = false;
    // One list per purchase, each in the order of its records, and the purchases
    // in a random order, as in `psp_claim`.
    let mut purchases: Vec<Vec<(String, u32, String)>> = Vec::new();
    for record in wallet.expired_claims(now) {
        if only.is_some_and(|id| record.0 != id) {
            continue;
        }
        match purchases.iter_mut().find(|p| p[0].0 == record.0) {
            Some(records) => records.push(record),
            None => purchases.push(vec![record]),
        }
    }
    purchases.shuffle(&mut OsRng);
    let mut called = false;
    for records in purchases {
        let mut this_called = false;
        for (id, index, mint) in records {
            if mint != psp {
                wallet.give_up_claim(&id, index)?;
                continue;
            }
            let not_sent = |why: String| ClaimReport {
                id: id.clone(),
                index,
                what: ClaimOutcome::NotSent(why),
            };
            if let Err(e) = &address {
                kept.push(not_sent(format!(
                    "the saved claim was not sent one last time: {e}"
                )));
                continue;
            }
            if unreachable {
                kept.push(not_sent(
                    "the saved claim was not sent one last time: an earlier call failed and the AIR server cannot be reached"
                        .into(),
                ));
                continue;
            }
            // A pause before this purchase's first resend, when an earlier purchase
            // sent one: none before the first purchase, none between records of one.
            if !this_called {
                if called {
                    std::thread::sleep(purchase_gap());
                }
                this_called = true;
                called = true;
            }
            match send_others(wallet, air, &id, index, true)? {
                (Some(Step::Settled(settled)), _) => {
                    reports.push(ClaimReport {
                        id,
                        index,
                        what: ClaimOutcome::Claimed(settled),
                    });
                    continue;
                }
                (Some(_), _) => continue,
                (None, true) => {
                    unreachable = true;
                    kept.push(ClaimReport {
                        id: id.clone(),
                        index,
                        what: ClaimOutcome::Failed(
                            "the last resend of an other saved claim could not be sent: the AIR server cannot be reached"
                                .into(),
                        ),
                    });
                    continue;
                }
                (None, false) => {}
            }
            if wallet.claim_to_send(&id, index).is_err() {
                // only other saved claims were left, and none was answered
                wallet.give_up_claim(&id, index)?;
                continue;
            }
            match send_saved(wallet, air, &id, index)? {
                Step::Settled(settled) => reports.push(ClaimReport {
                    id,
                    index,
                    what: ClaimOutcome::Claimed(settled),
                }),
                Step::Already => {}
                Step::NoReply => wallet.give_up_claim(&id, index)?,
                Step::Failed { why, network } => {
                    let report = ClaimReport {
                        id: id.clone(),
                        index,
                        what: ClaimOutcome::Failed(why),
                    };
                    if network {
                        unreachable = true;
                        kept.push(report);
                    } else {
                        wallet.give_up_claim(&id, index)?;
                        reports.push(report);
                    }
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

/// What [`psp_one_purchase`] did: one purchase's close, pickup and claims.
#[derive(Debug)]
pub struct OnePurchase {
    /// The purchase drawn (its claim key's id), or `None` when the wallet holds no
    /// claim key and nothing was done.
    pub id: Option<String>,
    /// The close of the drawn purchase's records whose window has passed (its
    /// last resends), and what the close without network reported lost for every
    /// key, as [`psp_close_expired`] says it.
    pub closed: Closed,
    /// The drawn purchase's pickup ([`psp_pickup`], one purchase, no waiting):
    /// `None` when it was not read (its key went with the close, or `air.server`
    /// or `air.host` is not set), `Some(Err)` when the AIR server could not be
    /// read.
    pub picked: Option<Result<PickedUp, WalletError>>,
    /// The claims of the drawn purchase's open records ([`psp_claim`], one
    /// purchase): `None` when it was not read or has no open record, `Some(Err)`
    /// when the PSP mint's wire version or network did not check out or a claim
    /// could not be made.
    pub claims: Option<Result<Vec<ClaimReport>, WalletError>>,
    /// How many other purchases (claim keys) are held and were not touched: a
    /// later call, or [`psp_pickup`] and [`psp_claim`], takes them.
    pub others_pending: usize,
}

/// The quick start step for the PSP purchases, for an app and for the command
/// line's start: **one** purchase, drawn at random (`OsRng`) among every claim key
/// the wallet holds (each one's next cell still needs a read), has its closed
/// windows' last resends sent ([`psp_close_expired`]), is picked up with no
/// waiting ([`psp_pickup`]) and has its open records claimed ([`psp_claim`]), each
/// call on an AIR session of its own and with no pause. The other purchases are not
/// touched: [`OnePurchase::others_pending`] says how many, and a later call (one
/// purchase each time) or [`psp_pickup`] and [`psp_claim`] (all of them, with a
/// random pause of 1 to 30 seconds between two) take them. Handling one purchase
/// per call is what keeps the Issuer, who runs the AIR server, from seeing two
/// purchases read or claimed together, without making the caller wait out the
/// pauses.
///
/// Before a claim is sent the PSP mint's wire version and network are checked
/// ([`verify_psp`], against `expected_network`). With no claim key nothing is done
/// and nothing is asked of the network. Without `air.server` and `air.host` only
/// the close is made (its resends are kept, [`Closed::kept`]). An error is
/// returned only when the wallet file could not be written in the close; a failed
/// pickup or claim is in the result.
pub fn psp_one_purchase(
    wallet: &mut Wallet,
    air: &AirSettings,
    expected_network: &str,
    now: u64,
) -> Result<OnePurchase, WalletError> {
    let ids: Vec<String> = wallet.claim_keys().iter().map(|k| k.id.clone()).collect();
    let Some(id) = ids.choose(&mut OsRng).cloned() else {
        return Ok(OnePurchase {
            id: None,
            closed: Closed {
                reports: Vec::new(),
                kept: Vec::new(),
                lost: Vec::new(),
            },
            picked: None,
            claims: None,
            others_pending: 0,
        });
    };
    let closed = close_of(wallet, air, now, Some(&id))?;
    let held = |w: &Wallet| w.claim_keys().iter().any(|k| k.id == id);
    let mut one = OnePurchase {
        id: Some(id.clone()),
        closed,
        picked: None,
        claims: None,
        others_pending: 0,
    };
    if held(wallet) && Party::Psp.address(air).is_ok() {
        let picked = pickup_of(wallet, air, 0, Some(&id)).and_then(|mut p| {
            p.pop()
                .ok_or_else(|| WalletError::Unknown(format!("purchase {id} was not read")))
        });
        let read = picked.is_ok();
        one.picked = Some(picked);
        let open = wallet.open_claims(now).iter().any(|o| o.id == id);
        if read && open {
            one.claims = Some(
                verify_psp(wallet, air, expected_network)
                    .and_then(|()| claim_of(wallet, air, Some(&id))),
            );
        }
    }
    one.others_pending = wallet.claim_keys().len() - usize::from(held(wallet));
    Ok(one)
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
    // The time of the first send, saved before it (a resend keeps it): the day
    // the ESP gives is checked against the days from here to the reply.
    let id = sp_wire::esp::exchange::request_hash(request)
        .map_err(|e| WalletError::Invalid(e.to_string()))?;
    wallet.mark_exchange_sent(&id)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The pause between two purchases is 1 to 30 seconds, fixed in code. Fails if
    /// either bound is changed, or the two are swapped.
    #[test]
    fn the_pause_between_purchases_is_one_to_thirty_seconds() {
        assert_eq!(PURCHASE_GAP_MIN_SECS, 1);
        assert_eq!(PURCHASE_GAP_MAX_SECS, 30);
        const {
            assert!(1 <= PURCHASE_GAP_MIN_SECS);
            assert!(PURCHASE_GAP_MIN_SECS <= PURCHASE_GAP_MAX_SECS);
            assert!(PURCHASE_GAP_MAX_SECS <= 30);
        }
    }
}
