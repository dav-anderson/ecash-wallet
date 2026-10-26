//! The wallet's automatic, staggered rollover of PSP and ESP against real
//! psp-mint and esp-mint servers that rotate their keys (fixed clocks), reached
//! over AIR on their real listeners (see `common/mod.rs`). The AIR client always
//! dials port 5702, so these tests need that port free, and they take turns on
//! one `air_server`; they are built only with the `air-listener-tests` feature.

mod common;

use std::path::Path;
use std::sync::Arc;

use ecash_wallet::mint_info::{
    ClaimOutcome, psp_claim, psp_pickup, psp_post, psp_window, rotation_sync,
};
use ecash_wallet::store::{HandedNote, Handover, WalletData};
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::config::Config;
use psp_mint::settle::Settlement;
use secp256k1::{Keypair, SECP256K1};
use sp_wire::ServiceDid;

use common::air::{EspAt, PspUp};
use common::{EspMint, NoPsp, T0 as T, esp_record, open_wallet, psp_record, scratch};

const H: u64 = 3600;
/// Past the stagger window of a 1-hour period (0.5% = 18 s, and a swap time is
/// 1 to 18 s after the set starts).
const LATER: u64 = 100;

fn file_text(w: &Wallet) -> String {
    std::fs::read_to_string(w.path()).unwrap()
}

#[test]
fn psp_rolls_over_after_its_staggered_time_and_the_time_is_then_forgotten() {
    let dir = scratch("psp");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let record = psp_record(&air);
    let a = m.note(4);
    let b = m.note(1);
    let mut w = m.wallet(&dir, "w", vec![a.clone(), b.clone()]);
    // Before any rotation: one set, nothing to do, nothing scheduled.
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(log.is_empty(), "{log:?}");
    assert_eq!(w.swap_schedule_len(), 0);
    assert_eq!(w.epoch_of(&w.notes()[0]), Some(0));

    // The rotation: one random swap time, stored, inside the window.
    m.set_clock(T + H);
    let win = psp_window(&mut w, &air).unwrap();
    assert_eq!((win.current_epoch, win.previous_epoch), (1, Some(0)));
    let start = win.current_starts.unwrap();
    let at = w.swap_time(Kind::Psp, &record, &win).unwrap();
    // Strictly after the start: a delay of 0 would make a wallet that syncs the
    // second the set starts swap at once, and this test would then see no
    // "will be rolled over" step to wait through.
    assert!(at > start && at <= start + 18, "0.5% of a 1-hour period");
    assert_eq!(
        w.swap_time(Kind::Psp, &record, &win).unwrap(),
        at,
        "drawn once"
    );
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    for l in &log {
        assert!(
            !l.contains(&at.to_string()),
            "a swap time is never logged: {l}"
        );
    }

    // Past the swap time: rolled over without a prompt, and the swap time is
    // gone in the same write that recorded the new notes.
    m.set_clock(T + H + LATER);
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{log:?}"
    );
    assert!(m.spent(&a) && m.spent(&b));
    assert_eq!(w.notes().len(), 2);
    assert!(w.notes().iter().all(|n| w.epoch_of(n) == Some(1)));
    assert_eq!(w.swap_schedule_len(), 0);
    assert!(
        !file_text(&w).contains(&at.to_string()),
        "no history of the swap time in the file"
    );
    let again = open_wallet(w.path()).unwrap();
    assert_eq!(again.swap_schedule_len(), 0);

    // The next rotation retires generation 0; this wallet's notes are on 1.
    m.set_clock(T + 2 * H + LATER);
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{log:?}"
    );
    assert!(w.lost().is_empty());
}

#[test]
fn psp_left_offline_through_a_full_cycle_is_lost_and_its_schedule_dropped() {
    let dir = scratch("psp-lost");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let record = psp_record(&air);
    let n = m.note(2);
    let mut w = m.wallet(&dir, "w", vec![n]);
    rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap(); // stamped epoch 0
    m.set_clock(T + H);
    let win = psp_window(&mut w, &air).unwrap();
    w.swap_time(Kind::Psp, &record, &win).unwrap();
    assert_eq!(w.swap_schedule_len(), 1);
    // Offline past the next rotation: generation 0 is deleted.
    m.set_clock(T + 2 * H);
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(log.iter().any(|l| l.contains("lost")), "{log:?}");
    assert_eq!(w.lost().len(), 1);
    assert!(w.notes().is_empty());
    assert_eq!(
        w.swap_schedule_len(),
        0,
        "the old set retired: its schedule goes"
    );
}

#[test]
fn a_crash_before_the_send_or_after_the_mint_answered_is_finished_on_the_next_connection() {
    let dir = scratch("psp-crash");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let record = psp_record(&air);
    let (a, b) = (m.note(1), m.note(2));
    let mut w = m.wallet(&dir, "w", vec![a.clone(), b.clone()]);
    rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    m.set_clock(T + H + LATER);
    let win = psp_window(&mut w, &air).unwrap();
    let old = w.prepare_rollover(Kind::Psp, &record, &win).unwrap();
    w.swap_time(Kind::Psp, &record, &win).unwrap();
    let ids = w.build_rollovers(Kind::Psp, &record, &win, old).unwrap();
    // The mint answers, but the wallet dies before it finishes the rollover (the
    // reply is as good as lost): the same body, sent by hand, is applied by the
    // mint and its answer stored.
    let body = serde_json::to_vec(&w.pending_rollovers()[0].body).unwrap();
    psp_post(&mut w, &air, "rollover", &body).unwrap();
    drop(w);
    // Restart: the stored request is sent again and finished from the mint's
    // stored answer.
    let mut w = open_wallet(&dir.join("w.json")).unwrap();
    assert_eq!(w.pending_rollovers()[0].id, ids[0]);
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 2 note(s)")),
        "{log:?}"
    );
    assert!(w.pending_rollovers().is_empty());
    assert_eq!(w.swap_schedule_len(), 0);
    assert_eq!(w.notes().len(), 2);
}

#[test]
fn a_failed_rollover_is_logged_and_retried_on_the_next_connection() {
    let dir = scratch("psp-fail");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let record = psp_record(&air);
    let mut w = m.wallet(&dir, "w", vec![m.note(8)]);
    rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    m.set_clock(T + H + LATER);
    let win = psp_window(&mut w, &air).unwrap();
    let old = w.prepare_rollover(Kind::Psp, &record, &win).unwrap();
    w.swap_time(Kind::Psp, &record, &win).unwrap();
    w.build_rollovers(Kind::Psp, &record, &win, old).unwrap();
    // The mint is not answering: one short try, then "unreachable". The request
    // is kept in the wallet file.
    m.at.silence();
    let quick = m.at.air(1, 1);
    match rotation_sync(&mut w, &quick, Kind::Psp, &psp_record(&quick)) {
        Err(WalletError::Mint(why)) => assert!(why.contains("did not answer"), "{why}"),
        other => panic!("expected the silent PSP to be unreachable, got {other:?}"),
    }
    assert_eq!(w.pending_rollovers().len(), 1, "kept for the retry");
    assert_eq!(w.swap_schedule_len(), 1, "kept until the swap is done");
    // Back online: the next connection carries on with the kept request.
    m.at.listen();
    let mut w = open_wallet(w.path()).unwrap();
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 1 note(s)")),
        "{log:?}"
    );
    assert_eq!(w.swap_schedule_len(), 0);
}

// ---- ESP ---------------------------------------------------------------------

fn service() -> ServiceDid {
    ServiceDid::from(
        Keypair::from_seckey_slice(SECP256K1, &[7u8; 32])
            .unwrap()
            .public_key(),
    )
}

/// A rotating ESP mint (1-hour periods from `T`) with its listener, and three
/// notes of its first set for `service()`: 4 and 4 on day 100, 2 on day 200 (ESP
/// notes are powers of two).
fn start_esp(dir: &Path) -> (EspAt, EspMint, Vec<(u64, HandedNote)>) {
    let mint = EspMint::open(&dir.join("esp"), Box::new(NoPsp), Config::default(), T);
    let notes = [(4u64, 100u64), (4, 100), (2, 200)]
        .into_iter()
        .map(|(units, day)| (day, mint.handed(&service(), units, day)))
        .collect();
    // The listener keeps its state in a folder of its own, outside `dir`.
    let at = EspAt::new(Arc::clone(&mint.state), &scratch("airstate-esp"));
    (at, mint, notes)
}

#[test]
fn esp_rolls_over_keeping_its_service_and_day() {
    let dir = scratch("esp");
    let (esp, mint, notes) = start_esp(&dir);
    let air = esp.air(10, 3);
    let mut w = open_wallet(&dir.join("w.json")).unwrap();
    for day in [100, 200] {
        w.receive_handover(&Handover {
            service: service(),
            redeemable_after_day: day,
            notes: notes
                .iter()
                .filter(|(d, _)| *d == day)
                .map(|(_, n)| n.clone())
                .collect(),
        })
        .unwrap();
    }
    rotation_sync(&mut w, &air, Kind::Esp, &esp_record(&air)).unwrap();
    mint.set_clock(T + H + LATER);
    let log = rotation_sync(&mut w, &air, Kind::Esp, &esp_record(&air)).unwrap();
    assert!(
        log.iter().filter(|l| l.contains("rolled over")).count() == 2,
        "one per day: {log:?}"
    );
    let mut terms: Vec<(u64, u64)> = w
        .notes()
        .iter()
        .map(|n| (n.amount, n.terms.unwrap().redeemable_after_day))
        .collect();
    terms.sort();
    assert_eq!(
        terms,
        vec![(2, 200), (4, 100), (4, 100)],
        "same amounts, same days"
    );
    assert!(
        w.notes()
            .iter()
            .all(|n| n.terms.unwrap().service == service() && w.epoch_of(n) == Some(1))
    );
    assert_eq!(w.swap_schedule_len(), 0);
}

#[test]
fn a_note_claimed_after_a_psp_rotation_is_on_the_current_set_and_is_not_rolled_over() {
    let dir = scratch("psp-claim");
    let m = PspUp::start(&dir.join("psp"), T);
    // A note of the first set, issued at `T`: that starts the mint's rotation
    // clock, so its first set rotates an hour after it.
    let old_note = m.note(2);
    let mut w = m.wallet(&dir, "w", vec![old_note.clone()]);
    let mint_key = m.at.key();
    let build = w.build_psp_payload(&mint_key.public_key()).unwrap();
    let air = m.air();
    let old = psp_window(&mut w, &air).unwrap().current_id;

    // 64,000 sats at $10,000 a BTC are 64 units, and the fees come off: 64 - 4 = 60
    // are owed. The record is written before the rotation, the claim is made after
    // it.
    let settled = m.pay(&mint_key, "aa", 64_000, build.payload);
    assert!(matches!(settled, Settlement::Owed(_)), "{settled:?}");
    assert_eq!(m.deliver().delivered, 1);
    m.set_clock(T + H);
    let win = psp_window(&mut w, &air).unwrap();
    assert_eq!((win.current_epoch, win.previous_epoch), (1, Some(0)));
    assert_ne!(win.current_id, old);

    let found = psp_pickup(&mut w, &air, 0).unwrap();
    assert_eq!(found[0].new.len(), 1);
    let reports = psp_claim(&mut w, &air).unwrap();
    let [report] = &reports[..] else {
        panic!("one record: {reports:?}");
    };
    // 32 + 16 + 8 + 4 = 60
    assert!(matches!(&report.what, ClaimOutcome::Claimed(s) if s.units == 60));

    // The claim names the set that is current when it is sent, so every fresh note
    // is on it, stamped with its epoch; the first note is still on the old set.
    let fresh: Vec<_> = w
        .notes()
        .iter()
        .filter(|n| n.amount != 2)
        .cloned()
        .collect();
    let mut sizes: Vec<u64> = fresh.iter().map(|n| n.amount).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![4, 8, 16, 32]);
    for n in &fresh {
        assert_eq!(w.psp_keyset_of(n).unwrap(), win.current_id);
        assert_eq!(w.epoch_of(n), Some(1));
    }
    assert_eq!(w.psp_keyset_of(&old_note).unwrap(), old);
    // The first note was never stamped (only a rollover pass stamps, and none has
    // run yet): rotate.rs treats an unstamped note as previous-set.
    assert_eq!(w.epoch_of(&old_note), None);
    assert_eq!(w.balance().psp, 62);

    // The rollover rolls the previous-set note and leaves the fresh ones alone.
    rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    m.set_clock(T + H + LATER);
    let log = rotation_sync(&mut w, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(
        log.iter().any(|l| l.contains("rolled over 1 note(s)")),
        "{log:?}"
    );
    assert!(m.spent(&old_note));
    for n in &fresh {
        assert!(!m.spent(n), "a fresh note of {} units was rolled", n.amount);
    }
    assert_eq!(w.balance().psp, 62);
}

#[test]
fn a_note_without_a_recorded_keyset_is_refused_not_guessed() {
    let dir = scratch("psp-noks");
    let m = PspUp::start(&dir.join("psp"), T);
    let n = m.note(4);
    // Written straight to the file with no keyset, as an old wallet would have.
    let path = dir.join("old.json");
    let data = WalletData {
        network: common::NETWORK.into(),
        notes: vec![n.clone()],
        ..Default::default()
    };
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    let w = open_wallet(&path).unwrap();
    let e = w.psp_keyset_of(&n).unwrap_err().to_string();
    assert!(e.contains("no recorded keyset"), "{e}");
    let e = w.esp_keyset_of(&n).unwrap_err().to_string();
    assert!(e.contains("cannot be spent"), "{e}");
}
