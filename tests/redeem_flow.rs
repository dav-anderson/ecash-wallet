//! Redemption over AIR, end to end, the way the `redeem` command does it: an ESP
//! mint answering on its real AIR listener, the operator's admin routes (HTTP,
//! local to the SPI), and a service wallet that reads the ESP's fees, builds and
//! signs the canonical request, sends it, and collects the outcome by sending it
//! again.
//!
//! One test starts from fsp-mint instead of from notes the fixture signs: the ESP
//! that fsp-mint kept is written by its `export_kept` and `deliver`, taken in
//! by a service's wallet and redeemed.
//!
//! A redemption never calls the PSP, so the PSP stand-in refuses every call.
//! These are plain tests with their own runtime, because the operator's calls
//! use the blocking HTTP client. The AIR client always dials port 5702, so they
//! need that port free, and they take turns on one `air_server` (see
//! `common/mod.rs`); they are built only with the `air-listener-tests` feature.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use ecash_wallet::config::AirSettings;
use ecash_wallet::mint_info::{fetch_redeem_fees, send_redeem, settle_fsp, sync_esp_keysets};
use ecash_wallet::redeem::{EntryOutcome, RedeemOutcome, RedemptionState};
use ecash_wallet::store::{HandedNote, Handover, StoredTerms};
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::admin::{self, AdminState};
use esp_mint::config::Config;
use esp_mint::queue::Queue;
use esp_mint::redeem::{self, Reason};
use esp_mint::server::EspState;
use esp_mint::terms::Terms;
use fsp_mint::export;
use fsp_mint::issue::Issues;
use mint_types::{Amount, Note};
use secp256k1::{Keypair, SECP256K1, SecretKey};
use serde_json::{Value, json};
use sp_wire::ServiceDid;
use tokio::runtime::Runtime;

use common::air::{EspAt, Mints, service_keypair};
use common::{EspMint, NoPsp, esp_record, open_wallet, scratch};

/// A test amount, a power of two (about $1.10). Every ESP note is one.
const ONE: u64 = 1 << 40;
/// Days long past, so these notes are mature on the mint's clock.
/// A note smaller than the fee of a request.
const SMALL: u64 = 1 << 27;
const PAST: u64 = 100;
const PAST2: u64 = 200;
/// A day far ahead: not mature on the mint's clock.
const FUTURE: u64 = 1_000_000;
const RATE: u128 = 1_000_000;
const MEMO: &str = "btc:bc1qpayhere";
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn secret(n: u8) -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    SecretKey::from_slice(&bytes).unwrap()
}

fn service() -> ServiceDid {
    ServiceDid::from(Keypair::from_secret_key(SECP256K1, &secret(1)).public_key())
}

fn serve(rt: &Runtime, app: Router) -> String {
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

struct Mint {
    /// The wallet's `[air]` settings pointing at the ESP mint.
    air: AirSettings,
    admin: String,
    esp: EspMint,
    state: Arc<EspState>,
    queue_path: PathBuf,
    /// Last, so the turn on the AIR server ends after the rest is dropped.
    _esp: EspAt,
}

fn start(rt: &Runtime, dir: &Path, max_bytes: usize) -> Mint {
    // A redemption never calls the PSP.
    let esp = EspMint::open(
        &dir.join("esp"),
        Box::new(NoPsp),
        Config {
            redeem_fee_per_byte: RATE as u64,
            redeem_max_request_bytes: max_bytes,
            ..Config::default()
        },
        0,
    );
    let state = Arc::clone(&esp.state);
    let queue_path = state.queue_path.clone();
    // The listener keeps its state in a folder of its own, outside `dir`, which a
    // test removes while the listener is still running.
    let at = EspAt::new(Arc::clone(&state), &scratch("airstate"));
    let air = at.air(10, 3);
    let admin = serve(
        rt,
        admin::router(Arc::new(AdminState {
            queue_path: queue_path.clone(),
            lock: Mutex::new(()),
            token: None,
            esp: Arc::clone(&state),
        })),
    );
    Mint {
        air,
        admin,
        esp,
        state,
        queue_path,
        _esp: at,
    }
}

/// A note the mint has issued for `service` and `day`, handed over as a
/// customer would.
fn handed(mint: &Mint, units: u64, day: u64) -> HandedNote {
    mint.esp.handed(&service(), units, day)
}

fn give(wallet: &mut Wallet, day: u64, notes: Vec<HandedNote>) {
    wallet
        .receive_handover(&Handover {
            service: service(),
            redeemable_after_day: day,
            notes,
        })
        .unwrap();
}

fn is_spent(mint: &Mint, note: &Note) -> bool {
    mint.esp.is_spent(note)
}

/// True when the mint signed this wallet note under its service and day.
fn mint_signed(mint: &Mint, n: &ecash_wallet::store::StoredNote) -> bool {
    let t = n.terms.unwrap();
    let terms = Terms {
        service: t.service,
        redeemable_after_day: t.redeemable_after_day,
    };
    let sk = mint
        .state
        .master
        .key_for(Amount::from_units(n.amount), &terms);
    bdhke::verify_message(&sk, n.note.signature, &n.note.nonce.as_hash_preimage())
}

fn admin_post(mint: &Mint, path: &str, body: &Value) -> Value {
    let response = reqwest::blocking::Client::new()
        .post(format!("{}{path}", mint.admin))
        .json(body)
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    response.json().unwrap()
}

/// Send one built request the way the command does: on `refund_required` or
/// `outputs_over_limit` rebuild from the mint's totals and send again.
fn send(mint: &Mint, wallet: &mut Wallet, id: String) -> RedeemOutcome {
    send_to(&mint.air, wallet, id)
}

/// As [`send`], to the ESP mint the `[air]` settings `air` point at.
fn send_to(air: &AirSettings, wallet: &mut Wallet, mut id: String) -> RedeemOutcome {
    for _ in 0..4 {
        let body = wallet
            .pending_redemptions()
            .iter()
            .find(|p| p.id == id)
            .unwrap()
            .body()
            .unwrap();
        match send_redeem(wallet, air, &body) {
            Ok(response) => return wallet.finish_redemption(&id, &response).unwrap(),
            Err(WalletError::RedeemRefused {
                code,
                totals: Some(totals),
                ..
            }) if code == "refund_required" || code == "outputs_over_limit" => {
                id = wallet
                    .rebuild_redemption(&id, &secret(1), &totals)
                    .unwrap()
                    .id;
            }
            Err(e) => panic!("{e}"),
        }
    }
    panic!("no answer after 4 tries");
}

#[test]
fn queued_then_declined_then_collected_with_the_fee_shown_and_retries_idempotent() {
    let dir = scratch("decline");
    let rt = Runtime::new().unwrap();
    let mint = start(&rt, &dir, 1 << 20);
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();
    sync_esp_keysets(&mut wallet, &mint.air, &esp_record(&mint.air)).unwrap();
    let a = handed(&mint, 4 * ONE, PAST);
    let b = handed(&mint, 2 * ONE, PAST2);
    let (na, nb) = (a.note, b.note);
    give(&mut wallet, PAST, vec![a]);
    give(&mut wallet, PAST2, vec![b]);

    let fees = fetch_redeem_fees(&mut wallet, &mint.air).unwrap();
    assert_eq!(fees.fee_per_byte, RATE);
    assert_eq!(fees.max_request_bytes, 1 << 20);
    let built = wallet
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap();
    assert_eq!(built.len(), 1);
    let b0 = built[0].clone();
    // one decline output for each power of two the rest is made of
    let declines = sp_wire::esp::redeem::decode(&b0.body)
        .unwrap()
        .decline_outputs
        .len();
    assert!(declines >= 2);
    assert_eq!(
        b0.size_bytes,
        120 + 2 * 187 + MEMO.len() as u64 + declines as u64 * 82
    );
    assert_eq!(b0.fee_esp, RATE * u128::from(b0.size_bytes));

    let done = send(&mint, &mut wallet, b0.id.clone());
    assert_eq!(done.id, b0.id);
    assert_eq!(done.message, "payout queued");
    assert_eq!(done.fee_esp, b0.fee_esp);
    assert_eq!(done.owed_esp, u128::from(6 * ONE) - b0.fee_esp);
    assert_eq!(done.entry, Some(EntryOutcome::Open));
    assert!(is_spent(&mint, &na) && is_spent(&mint, &nb));
    assert!(wallet.notes().is_empty());
    assert_eq!(
        wallet.pending_redemptions()[0].state,
        RedemptionState::Queued
    );
    assert_eq!(Queue::open(&mint.queue_path).unwrap().len(), 1);

    // collecting while it is open: the same answer, nothing more queued
    let again = send(&mint, &mut wallet, b0.id.clone());
    assert_eq!(again.entry, Some(EntryOutcome::Open));
    assert_eq!(Queue::open(&mint.queue_path).unwrap().len(), 1);
    // and the wallet survives a reopen with the redemption still waiting
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();
    sync_esp_keysets(&mut wallet, &mint.air, &esp_record(&mint.air)).unwrap();
    assert_eq!(wallet.pending_redemptions().len(), 1);

    admin_post(
        &mint,
        "/payouts/decline",
        &json!({"entry_id": b0.id, "reason": "uptime terms were not met"}),
    );
    let collected = send(&mint, &mut wallet, b0.id.clone());
    match collected.entry {
        Some(EntryOutcome::Declined {
            reason,
            reissued,
            reissued_esp,
        }) => {
            assert_eq!(reason.as_deref(), Some("uptime terms were not met"));
            assert_eq!(reissued.len(), declines);
            assert_eq!(reissued_esp, done.owed_esp);
        }
        other => panic!("{other:?}"),
    }
    assert!(wallet.pending_redemptions().is_empty());
    assert_eq!(wallet.balance().esp, done.owed_esp);
    assert!(wallet.notes().iter().all(|n| mint_signed(&mint, n)));
    // the reissued notes can be redeemed again
    let next = wallet
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap();
    let r = send(&mint, &mut wallet, next[0].id.clone());
    assert_eq!(r.message, "payout queued");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_paid_entry_is_collected_as_completed() {
    let dir = scratch("paid");
    let rt = Runtime::new().unwrap();
    let mint = start(&rt, &dir, 1 << 20);
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();
    sync_esp_keysets(&mut wallet, &mint.air, &esp_record(&mint.air)).unwrap();
    give(&mut wallet, PAST, vec![handed(&mint, ONE, PAST)]);
    let fees = fetch_redeem_fees(&mut wallet, &mint.air).unwrap();
    let b = wallet
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap()
        .remove(0);
    send(&mint, &mut wallet, b.id.clone());
    let paid = admin_post(
        &mint,
        "/payouts/pay",
        &json!({"service": hex::encode(service().serialize()), "payment_ref": "tx-1", "entry_ids": [b.id]}),
    );
    assert!(paid.to_string().contains("tx-1"), "{paid}");
    let done = send(&mint, &mut wallet, b.id.clone());
    assert_eq!(
        done.entry,
        Some(EntryOutcome::Completed {
            payment_ref: Some("tx-1".into())
        })
    );
    assert!(wallet.pending_redemptions().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_note_immature_at_the_mint_is_refunded_and_nothing_owed_fee_taken() {
    let dir = scratch("refund");
    let rt = Runtime::new().unwrap();
    let mint = start(&rt, &dir, 1 << 20);
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();
    sync_esp_keysets(&mut wallet, &mint.air, &esp_record(&mint.air)).unwrap();
    // a small mature note that cannot pay the fee, and a large one the mint
    // will find immature
    let small = handed(&mint, SMALL, PAST);
    let big = handed(&mint, ONE, FUTURE);
    let (ns, nb) = (small.note, big.note);
    give(&mut wallet, PAST, vec![small]);
    give(&mut wallet, FUTURE, vec![big]);
    let fees = fetch_redeem_fees(&mut wallet, &mint.air).unwrap();
    // On the wallet's own clock the big note is not mature, so it is left out
    // and the small one alone is below the fee.
    assert!(matches!(
        wallet.build_redemption(&secret(1), MEMO, &fees, now()),
        Err(WalletError::NotEnough(_))
    ));
    assert!(wallet.pending_redemptions().is_empty());
    // A wallet clock far ahead of the mint's includes it; the mint refuses
    // (refund required), the wallet rebuilds from the mint's totals.
    let late = (FUTURE + 1) * 86_400;
    let b = wallet
        .build_redemption(&secret(1), MEMO, &fees, late)
        .unwrap()
        .remove(0);
    let done = send(&mint, &mut wallet, b.id.clone());
    assert_ne!(done.id, b.id);
    assert_eq!(done.message, "nothing owed, fee taken");
    assert_eq!(done.owed_esp, 0);
    assert!(done.entry.is_none());
    assert_eq!(
        done.notes
            .iter()
            .find(|n| n.1 == Some(Reason::Immature))
            .map(|n| n.2),
        Some(true)
    );
    assert!(!done.refunded.is_empty());
    assert!(done.refunded.len() > 1);
    assert!(is_spent(&mint, &ns) && is_spent(&mint, &nb));
    assert!(wallet.pending_redemptions().is_empty());
    assert_eq!(
        wallet.balance().esp,
        u128::from(ONE) + u128::from(SMALL) - done.fee_esp
    );
    let n = &wallet.notes()[0];
    assert_eq!(n.terms.unwrap().redeemable_after_day, FUTURE);
    assert!(mint_signed(&mint, n));
    assert_eq!(Queue::open(&mint.queue_path).unwrap().len(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_note_spent_elsewhere_is_dropped_on_rebuild_and_the_rest_is_queued() {
    let dir = scratch("spent");
    let rt = Runtime::new().unwrap();
    let mint = start(&rt, &dir, 1 << 20);
    let x = handed(&mint, ONE, PAST);
    let copy = HandedNote {
        amount: x.amount,
        note: x.note,
        spend_secret: x.spend_secret,
        keyset: x.keyset.clone(),
    };
    let mut first = open_wallet(&dir.join("first.json")).unwrap();
    sync_esp_keysets(&mut first, &mint.air, &esp_record(&mint.air)).unwrap();
    give(&mut first, PAST, vec![x]);
    let fees = fetch_redeem_fees(&mut first, &mint.air).unwrap();
    let b = first
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap()
        .remove(0);
    send(&mint, &mut first, b.id);
    // a second copy of the wallet still holds the same note, and one more
    let mut second = open_wallet(&dir.join("second.json")).unwrap();
    sync_esp_keysets(&mut second, &mint.air, &esp_record(&mint.air)).unwrap();
    give(&mut second, PAST, vec![copy, handed(&mint, 2 * ONE, PAST)]);
    let b = second
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap()
        .remove(0);
    let done = send(&mint, &mut second, b.id.clone());
    assert_ne!(done.id, b.id);
    assert_eq!(done.message, "payout queued");
    assert_eq!(second.spent_notes().len(), 1);
    assert!(second.notes().is_empty());
    assert_eq!(Queue::open(&mint.queue_path).unwrap().len(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_below_fee_refusal_moves_the_notes_the_mint_calls_spent_to_the_spent_record() {
    let dir = scratch("below-fee-spent");
    let rt = Runtime::new().unwrap();
    let mint = start(&rt, &dir, 1 << 20);
    let x = handed(&mint, ONE, PAST);
    let copy = HandedNote {
        amount: x.amount,
        note: x.note,
        spend_secret: x.spend_secret,
        keyset: x.keyset.clone(),
    };
    let mut first = open_wallet(&dir.join("first.json")).unwrap();
    sync_esp_keysets(&mut first, &mint.air, &esp_record(&mint.air)).unwrap();
    give(&mut first, PAST, vec![x]);
    let fees = fetch_redeem_fees(&mut first, &mint.air).unwrap();
    let b = first
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap()
        .remove(0);
    send(&mint, &mut first, b.id);
    assert!(is_spent(&mint, &copy.note));

    // a second wallet holds only a copy of the spent note. It looks worth the
    // fee to the wallet, but to the mint it is worth nothing: below_fee
    let mut second = open_wallet(&dir.join("second.json")).unwrap();
    sync_esp_keysets(&mut second, &mint.air, &esp_record(&mint.air)).unwrap();
    give(&mut second, PAST, vec![copy]);
    let b = second
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap()
        .remove(0);
    let body = second
        .pending_redemptions()
        .iter()
        .find(|p| p.id == b.id)
        .unwrap()
        .body()
        .unwrap();
    let refused = send_redeem(&mut second, &mint.air, &body).unwrap_err();
    let WalletError::RedeemRefused { code, notes, .. } = &refused else {
        panic!("expected a refusal, got {refused:?}");
    };
    assert_eq!(code, "below_fee");
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].reason, Some(Reason::AlreadySpent));
    let report = second.refuse_redemption(&b.id, notes).unwrap();
    assert_eq!((report.marked_spent, report.freed), (1, 0));
    assert_eq!(second.spent_notes().len(), 1);
    assert!(second.notes().is_empty());
    assert!(second.pending_redemptions().is_empty());
    // the wallet does not offer the spent note again
    match second.build_redemption(&secret(1), MEMO, &fees, now()) {
        Err(WalletError::NotEnough(why)) => {
            assert!(why.contains("holds no free ESP for that service"), "{why}")
        }
        other => panic!("expected no free ESP, got {other:?}"),
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_redemption_over_the_ceiling_is_split_and_each_part_is_queued() {
    let dir = scratch("split");
    let rt = Runtime::new().unwrap();
    // room for two notes of one day with the most outputs a day can need, but
    // not three, and not notes of two days together: the notes go two of the
    // first day, one, and two of the second
    let most = ecash_wallet::redeem::MAX_OUTPUTS_PER_TERMS;
    let ceiling = redeem::encoded_len(2, MEMO.len(), most, most);
    let mint = start(&rt, &dir, ceiling as usize);
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();
    sync_esp_keysets(&mut wallet, &mint.air, &esp_record(&mint.air)).unwrap();
    give(
        &mut wallet,
        PAST,
        (0..3).map(|_| handed(&mint, ONE, PAST)).collect(),
    );
    give(
        &mut wallet,
        PAST2,
        (0..2).map(|_| handed(&mint, ONE, PAST2)).collect(),
    );
    let fees = fetch_redeem_fees(&mut wallet, &mint.air).unwrap();
    assert_eq!(fees.max_request_bytes, ceiling);
    let built = wallet
        .build_redemption(&secret(1), MEMO, &fees, now())
        .unwrap();
    assert_eq!(built.len(), 3);
    let mut owed = 0;
    for b in &built {
        assert!(b.size_bytes <= ceiling);
        let done = send(&mint, &mut wallet, b.id.clone());
        assert_eq!(done.message, "payout queued");
        owed += done.owed_esp;
    }
    let fee: u128 = built.iter().map(|b| b.fee_esp).sum();
    assert_eq!(owed, u128::from(5 * ONE) - fee);
    assert_eq!(Queue::open(&mint.queue_path).unwrap().len(), 3);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn notes_below_the_fee_and_notes_of_another_service_are_refused_locally() {
    let dir = scratch("below");
    let rt = Runtime::new().unwrap();
    let mint = start(&rt, &dir, 1 << 20);
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();
    sync_esp_keysets(&mut wallet, &mint.air, &esp_record(&mint.air)).unwrap();
    give(&mut wallet, PAST, vec![handed(&mint, 1_000, PAST)]);
    let fees = fetch_redeem_fees(&mut wallet, &mint.air).unwrap();
    assert!(matches!(
        wallet.build_redemption(&secret(1), MEMO, &fees, now()),
        Err(WalletError::NotEnough(_))
    ));
    assert!(matches!(
        wallet.build_redemption(&secret(2), MEMO, &fees, now()),
        Err(WalletError::NotEnough(_))
    ));
    assert!(wallet.pending_redemptions().is_empty());
    assert!(wallet.notes().iter().all(|n| n.reserved_by.is_none()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn esp_that_fsp_mint_kept_is_exported_received_and_redeemed_once_mature() {
    let dir = scratch("export-esp");
    // Both mints are real and rotate; the FSP mint first issued at `NOW`.
    let m = Mints::start(&dir, "20", "2", None);
    let service = common::air::service();

    // A customer hands ESP over to the service's FSP mint, on two days: one long
    // past, one far ahead of any clock.
    let mut user = m.wallet_on_days(&dir, "user", &[(PAST, &[2 * ONE, ONE]), (FUTURE, &[ONE])]);
    let issue = user.build_fsp_issue(service, None, 0).unwrap();
    settle_fsp(&mut user, &m.air, &issue.hash()).unwrap();
    assert_eq!(user.balance().fsp, u128::from(4 * ONE));
    assert_eq!(user.balance().esp, 0, "the ESP went to the FSP mint");

    // What fsp-mint kept, as its own file holds it.
    let data = dir.join("fsp");
    let kept = Issues::open(&data).unwrap().data.kept;
    let on = |day: u64| kept.iter().filter(move |k| k.redeemable_after_day == day);
    assert_eq!(
        on(PAST).map(|k| u128::from(k.amount)).sum::<u128>(),
        u128::from(3 * ONE)
    );
    assert_eq!(
        on(FUTURE).map(|k| u128::from(k.amount)).sum::<u128>(),
        u128::from(ONE)
    );
    assert_eq!(on(PAST).count() + on(FUTURE).count(), kept.len());
    assert!(kept.iter().all(|k| !k.exported));

    // `export_kept` writes one file for each day and `deliver` moves them to
    // `out`, as `export-esp` does: nothing here is made by hand.
    let out = scratch("export-esp-out");
    let mut issues = Issues::open(&data).unwrap();
    export::export_kept(&mut issues, &export::folder(&data), service, 1_234).unwrap();
    let written = export::deliver(&export::folder(&data), &out).unwrap();
    let (past_file, future_file) = (
        out.join(format!("esp-{PAST}-1234.json")),
        out.join(format!("esp-{FUTURE}-1234.json")),
    );
    assert_eq!(
        written,
        vec![
            (past_file.clone(), on(PAST).count()),
            (future_file.clone(), on(FUTURE).count()),
        ]
    );

    // The service's wallet takes both files in with `receive_handover`, read as
    // the command reads them.
    let mut svc = open_wallet(&dir.join("service.json")).unwrap();
    for file in [&past_file, &future_file] {
        let handover = Handover::read(&std::fs::read(file).unwrap()).unwrap();
        svc.receive_handover(&handover).unwrap();
    }
    // Every kept note is in the wallet: its amount, spend secret, service, day and
    // the ESP keyset that signed it.
    assert_eq!(svc.notes().len(), kept.len());
    let keysets = svc.snapshot().keysets;
    for k in &kept {
        let held = svc
            .notes()
            .iter()
            .find(|n| n.note == k.note)
            .expect("a kept note is in the wallet");
        assert_eq!(
            (held.kind, held.amount, held.spend_secret, held.terms),
            (
                Kind::Esp,
                k.amount,
                k.spend_secret,
                Some(StoredTerms {
                    service,
                    redeemable_after_day: k.redeemable_after_day,
                })
            )
        );
        assert_eq!(keysets[&held.id()], k.keyset);
    }

    // The same file again adds nothing: it is refused, and the wallet file is as
    // it was.
    let before = std::fs::read(svc.path()).unwrap();
    let again = Handover::read(&std::fs::read(&past_file).unwrap()).unwrap();
    match svc.receive_handover(&again) {
        Err(WalletError::Invalid(why)) => {
            assert!(why.contains("is already in this wallet"), "{why}")
        }
        other => panic!("expected the file to be refused the second time, got {other:?}"),
    }
    assert_eq!(svc.notes().len(), kept.len());
    assert_eq!(std::fs::read(svc.path()).unwrap(), before);

    // The service redeems what is mature at the ESP mint. The notes of the far
    // day are not offered; they stay in the wallet.
    let air = m.esp_at.air(10, 3);
    sync_esp_keysets(&mut svc, &air, &esp_record(&air)).unwrap();
    let fees = fetch_redeem_fees(&mut svc, &air).unwrap();
    assert_eq!(fees.fee_per_byte, 0, "the ESP mint charges no fee here");
    let built = svc
        .build_redemption(&service_keypair().secret_key(), MEMO, &fees, now())
        .unwrap();
    assert_eq!(built.len(), 1);
    let done = send_to(&air, &mut svc, built[0].id.clone());
    assert_eq!(done.message, "payout queued");
    assert_eq!(done.accepted_esp, u128::from(3 * ONE));
    assert_eq!((done.rejected_esp, done.fee_esp), (0, 0));
    assert_eq!(done.owed_esp, u128::from(3 * ONE));
    for k in &kept {
        assert_eq!(
            m.esp.is_spent(&k.note),
            k.redeemable_after_day == PAST,
            "note of day {}",
            k.redeemable_after_day
        );
    }
    assert_eq!(svc.notes().len(), on(FUTURE).count());
    assert!(
        svc.notes()
            .iter()
            .all(|n| n.terms.unwrap().redeemable_after_day == FUTURE)
    );
    assert_eq!(Queue::open(&m.esp.state.queue_path).unwrap().len(), 1);
    std::fs::remove_dir_all(&dir).unwrap();
}
