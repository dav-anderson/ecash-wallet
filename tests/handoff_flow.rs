//! Value handed from wallet to wallet as a string, with no AIR in between, in
//! the two valid kinds: a PSP handoff (sealed to the recipient's DID key,
//! in the balance at once and swapped at a real psp-mint) and an FSP handoff (the
//! DID key and a little FSP, never swapped, usable at a real fsp-mint), and the
//! sender's side (notes taken out, check, reclaim before and after the receiver's
//! swap, cancel, done).
//!
//! The PSP mint is reached over AIR, on its real listener against a real
//! `air_server` started in this process (see `common/mod.rs`); so is the ESP mint
//! behind the fsp-mint of the FSP test, whose Issuer is the real `AirIssuer`. The
//! AIR client always dials port 5702, so these tests need that port free, and they
//! take turns on the one shared server; they are built only with the
//! `air-listener-tests` feature. The wallet reaches the FSP mint over AIR too: fsp-mint
//! answers on its own real listener, and the wallet's `air.fsp` entry points at it.

mod common;

use ecash_wallet::config::AirSettings;
use ecash_wallet::handoff::{
    FSP_PREFIX, FSP_WARNING, HandoffKind, HandoffState, PSP_PREFIX, PSP_WARNING, Standing,
};
use ecash_wallet::mint_info::{
    check_handoff, complete_import, fsp_sync, reclaim_handoff, rotation_sync, settle_fsp,
};
use ecash_wallet::{Kind, Wallet, WalletError};
use sp_wire::ServiceDid;
use sp_wire::seal::SecretKey as DidSecretKey;

use common::air::{Mints, PspUp, service};
use common::{T0 as T, open_wallet, psp_record, scratch};

// ---- PSP ---------------------------------------------------------------------------

fn psp_total(w: &Wallet) -> u64 {
    w.notes()
        .iter()
        .filter(|n| n.kind == Kind::Psp)
        .map(|n| n.amount)
        .sum()
}

/// The message of an `Invalid` refusal; anything else fails the test.
fn invalid<V: std::fmt::Debug>(result: Result<V, WalletError>) -> String {
    match result {
        Err(WalletError::Invalid(why)) => why,
        other => panic!("expected an Invalid refusal, got {other:?}"),
    }
}

fn did(n: u8) -> DidSecretKey {
    DidSecretKey::from_array([n; 32]).unwrap()
}

/// Export `units` PSP of the PSP `psp` from `dev` to `to`; returns the handoff
/// (id and string).
fn make(
    dev: &mut Wallet,
    psp: ServiceDid,
    units: u128,
    to: &DidSecretKey,
) -> ecash_wallet::handoff::HandoffExport {
    let ids = dev.select_psp_handoff(units).unwrap();
    dev.export_psp_handoff(&ids, psp, &to.public_key()).unwrap()
}

#[test]
fn a_psp_handoff_sealed_to_the_user_counts_at_once_and_is_swapped_at_the_mint() {
    let dir = scratch("psp");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let (a, b, c) = (m.note(4), m.note(1), m.note(2));
    let mut dev = m.wallet(&dir, "dev", vec![a.clone(), b.clone(), c]);
    let mut user = m.wallet(&dir, "user", vec![]);
    let (user_key, other_key) = (did(7), did(9));

    let ids = dev.select_psp_handoff(5).unwrap();
    let out = dev
        .export_psp_handoff(&ids, m.at.did, &user_key.public_key())
        .unwrap();
    assert!(out.text.starts_with(PSP_PREFIX));
    assert_eq!(out.kind, HandoffKind::Psp);
    assert_eq!((out.notes, out.psp_units, out.fsp_units), (2, 5, 0));
    assert!(!out.with_did_key, "a PSP handoff never carries a DID key");
    assert_eq!(out.warning, PSP_WARNING);
    assert_eq!(psp_total(&dev), 2, "the handed-off notes leave the balance");
    assert_eq!(dev.handoffs_out()[0].state, HandoffState::Pending);
    assert_eq!(
        dev.handoffs_out()[0].mint,
        psp_record(&air),
        "the mint is kept for check and reclaim"
    );

    // Only the user's DID key opens it, and a failed attempt changes nothing.
    let err = user
        .import_psp_handoff(&out.text, &other_key, m.at.did, "dev")
        .unwrap_err();
    assert!(err.to_string().contains("cannot be opened"), "{err}");
    assert!(user.handoffs_in().is_empty() && user.pending_rollovers().is_empty());

    // The string survives being written down and typed back in.
    let typed = format!("  {}\n", out.text.to_lowercase());
    let imported = user
        .import_psp_handoff(&typed, &user_key, m.at.did, "dev")
        .unwrap();
    assert_eq!(imported.psp_units, 5);
    assert_eq!(imported.psp_swaps.len(), 1, "the swap is stored first");
    // In the balance at once: no lock on notes that are not swapped yet.
    assert_eq!(psp_total(&user), 5);
    assert_eq!(user.balance().psp, 5);
    assert_eq!(user.unswapped_psp(), 5);
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(psp_total(&user), 5);
    assert_eq!(user.unswapped_psp(), 0);
    assert!(user.pending_rollovers().is_empty());
    assert!(m.spent(&a) && m.spent(&b), "the old notes are burned");
    let nonces: Vec<_> = user.notes().iter().map(|n| n.note.nonce).collect();
    assert!(!nonces.contains(&a.note.nonce) && !nonces.contains(&b.note.nonce));
    assert_eq!(user.handoffs_in()[0].from, "dev");
    assert!(user.handoffs_in()[0].swapped);
    assert_eq!(user.handoffs_in()[0].kind, HandoffKind::Psp);

    // The same string again: refused, and nothing is added.
    let err = user
        .import_psp_handoff(&out.text, &user_key, m.at.did, "dev")
        .unwrap_err();
    assert!(err.to_string().contains("imported already"), "{err}");
    assert_eq!(psp_total(&user), 5);
    // Someone who got hold of the string and the key too late has the notes in
    // the balance for a moment, then the mint says they are spent and they
    // leave it again: none of it is kept.
    let mut thief = m.wallet(&dir, "thief", vec![]);
    let imported = thief
        .import_psp_handoff(&out.text, &user_key, m.at.did, "")
        .unwrap();
    assert_eq!(psp_total(&thief), 5);
    let log = complete_import(&mut thief, &air, &imported);
    assert!(
        log.iter().any(|l| l.contains("spent already")),
        "the mint refuses a second swap: {log:?}"
    );
    assert_eq!(psp_total(&thief), 0, "none of it is kept");
    assert_eq!(thief.unswapped_psp(), 0);
    assert!(thief.pending_rollovers().is_empty());
    assert_eq!(thief.spent_notes().len(), 2);

    // The sender asks the mint and learns it was claimed.
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Received
    );
    assert_eq!(dev.handoffs_out()[0].state, HandoffState::Done);
    assert!(dev.handoffs_out()[0].notes.is_empty());
    let why = invalid(dev.cancel_handoff(&out.id));
    assert!(
        why.contains("is done: its notes are no longer kept"),
        "{why}"
    );
}

#[test]
fn unswapped_psp_is_in_the_balance_and_spendable_and_is_swapped_when_the_mint_answers() {
    let dir = scratch("unswapped");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let key = did(7);

    // The mint is not answering: the swap cannot go through (one short try).
    m.at.silence();
    let quick = m.at.air(1, 1);
    let mut dev = m.wallet(&dir, "dev", vec![m.note(8), m.note(2)]);
    let ids = dev.select_psp_handoff(10).unwrap();
    let out = dev
        .export_psp_handoff(&ids, m.at.did, &key.public_key())
        .unwrap();
    let mut user = m.wallet(&dir, "user", vec![]);
    let imported = user
        .import_psp_handoff(&out.text, &key, m.at.did, "")
        .unwrap();
    let log = complete_import(&mut user, &quick, &imported);
    assert!(log.iter().any(|l| l.contains("stays unswapped")), "{log:?}");
    assert_eq!(psp_total(&user), 10);
    assert_eq!(user.balance().psp, 10, "counted, not locked");
    assert_eq!(user.balance().unswapped_psp, 10);
    assert_eq!(user.pending_rollovers().len(), 1, "the swap is kept");
    assert_eq!(
        user.select_psp_handoff(2).unwrap().len(),
        1,
        "unswapped notes can be spent or handed on"
    );
    // The state survives a restart.
    let again = open_wallet(&dir.join("user.json")).unwrap();
    assert_eq!(again.unswapped_psp(), 10);
    assert_eq!(again.balance().psp, 10);

    // The same notes with the mint answering: the swap is sent again by the
    // next sync (what the command line does at every start), and then it is final.
    m.at.listen();
    let mut dev2 = m.wallet(&dir, "dev2", vec![m.note(8), m.note(2)]);
    let out = make(&mut dev2, m.at.did, 10, &key);
    let mut user2 = m.wallet(&dir, "user2", vec![]);
    let imported = user2
        .import_psp_handoff(&out.text, &key, m.at.did, "")
        .unwrap();
    assert_eq!(user2.unswapped_psp(), 10, "stored and not sent yet");
    assert_eq!(psp_total(&user2), 10, "and already counted");
    let log = rotation_sync(&mut user2, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(log.iter().any(|l| l.contains("swapped 10 PSP")), "{log:?}");
    assert_eq!(imported.psp_swaps.len(), 1);
    assert_eq!(psp_total(&user2), 10);
    assert_eq!(user2.unswapped_psp(), 0);
    assert!(user2.pending_rollovers().is_empty());

    // Spending first: a note handed on before the swap is sent is left out of
    // it, and the one who got it can still swap it, because the mint has not
    // seen it yet.
    let mut dev3 = m.wallet(&dir, "dev3", vec![m.note(8), m.note(2)]);
    let out = make(&mut dev3, m.at.did, 10, &key);
    let mut user3 = m.wallet(&dir, "user3", vec![]);
    user3
        .import_psp_handoff(&out.text, &key, m.at.did, "")
        .unwrap();
    let onward = make(&mut user3, m.at.did, 2, &did(8));
    assert_eq!(psp_total(&user3), 8);
    let log = rotation_sync(&mut user3, &air, Kind::Psp, &psp_record(&air)).unwrap();
    assert!(log.iter().any(|l| l.contains("swapped 8 PSP")), "{log:?}");
    assert_eq!(psp_total(&user3), 8);
    assert!(user3.pending_rollovers().is_empty());
    let mut friend = m.wallet(&dir, "friend", vec![]);
    let imported = friend
        .import_psp_handoff(&onward.text, &did(8), m.at.did, "")
        .unwrap();
    let log = complete_import(&mut friend, &air, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(psp_total(&friend), 2);
}

#[test]
fn the_sender_reclaims_a_handoff_the_receiver_has_not_swapped() {
    let dir = scratch("reclaim-before");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let (a, b, c) = (m.note(4), m.note(1), m.note(2));
    let mut dev = m.wallet(&dir, "dev", vec![a.clone(), b.clone(), c]);
    let key = did(7);
    let out = make(&mut dev, m.at.did, 5, &key);
    assert_eq!(psp_total(&dev), 2);

    // Nothing is spent at the mint yet: it is still the sender's.
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Pending
    );
    let done = reclaim_handoff(&mut dev, &air, &out.id).unwrap();
    assert_eq!(done.standing, Standing::Reclaimed);
    assert!(
        done.log.iter().any(|l| l.contains("reclaimed 5 PSP")),
        "{:?}",
        done.log
    );
    assert_eq!(psp_total(&dev), 7, "the notes are back, as fresh ones");
    assert!(
        m.spent(&a) && m.spent(&b),
        "the handed-off notes are burned"
    );
    assert!(dev.pending_rollovers().is_empty());
    let h = &dev.handoffs_out()[0];
    assert_eq!(
        (h.state, h.reclaim.clone(), h.notes.len()),
        (HandoffState::Reclaimed, None, 0)
    );
    let why = invalid(dev.cancel_handoff(&out.id));
    assert!(
        why.contains("is reclaimed: its notes are no longer kept"),
        "{why}"
    );
    // asking again changes nothing
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Reclaimed
    );
    assert_eq!(
        reclaim_handoff(&mut dev, &air, &out.id).unwrap().standing,
        Standing::Reclaimed
    );
    assert_eq!(psp_total(&dev), 7);
    // and it is in the file
    let again = open_wallet(&dir.join("dev.json")).unwrap();
    assert_eq!(again.handoffs_out()[0].state, HandoffState::Reclaimed);

    // The receiver comes late: its notes are in the balance for a moment, then
    // the mint says they are spent, and they leave it.
    let mut user = m.wallet(&dir, "user", vec![]);
    let imported = user
        .import_psp_handoff(&out.text, &key, m.at.did, "dev")
        .unwrap();
    assert_eq!(psp_total(&user), 5);
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("spent already")), "{log:?}");
    assert_eq!(psp_total(&user), 0);
    assert!(user.pending_rollovers().is_empty());
    assert_eq!(user.spent_notes().len(), 2);
}

#[test]
fn a_reclaim_after_the_receiver_swapped_finds_the_notes_gone_and_takes_nothing() {
    let dir = scratch("reclaim-after");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let mut dev = m.wallet(&dir, "dev", vec![m.note(4), m.note(1), m.note(2)]);
    let key = did(7);
    let out = make(&mut dev, m.at.did, 5, &key);
    let mut user = m.wallet(&dir, "user", vec![]);
    let imported = user
        .import_psp_handoff(&out.text, &key, m.at.did, "")
        .unwrap();
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");

    let done = reclaim_handoff(&mut dev, &air, &out.id).unwrap();
    assert_eq!(done.standing, Standing::Received);
    assert!(done.log.is_empty(), "no swap was sent: {:?}", done.log);
    assert_eq!(psp_total(&dev), 2, "nothing came back");
    assert!(dev.pending_rollovers().is_empty());
    let h = &dev.handoffs_out()[0];
    assert_eq!(
        (h.state, h.notes.len(), h.spent_elsewhere),
        (HandoffState::Done, 0, 2)
    );
    assert_eq!(psp_total(&user), 5, "the receiver kept what it swapped");
    // asking again, and cancelling, change nothing
    assert_eq!(
        reclaim_handoff(&mut dev, &air, &out.id).unwrap().standing,
        Standing::Received
    );
    let why = invalid(dev.cancel_handoff(&out.id));
    assert!(
        why.contains("is done: its notes are no longer kept"),
        "{why}"
    );
}

#[test]
fn a_note_spent_elsewhere_drops_out_and_the_rest_is_still_reclaimed_or_swapped() {
    let dir = scratch("partly");
    let m = PspUp::start(&dir.join("psp"), T);
    let air = m.air();
    let (c, d) = (m.note(2), m.note(8));
    let key = did(7);

    // Handoff H of c and d; then c is spent at the mint by someone who held a copy.
    let mut dev = m.wallet(&dir, "dev", vec![c.clone(), d.clone()]);
    let out = make(&mut dev, m.at.did, 10, &key);
    let mut copy = m.wallet(&dir, "copy", vec![c.clone()]);
    let c_out = make(&mut copy, m.at.did, 2, &did(5));
    let mut holder = m.wallet(&dir, "holder", vec![]);
    let imported = holder
        .import_psp_handoff(&c_out.text, &did(5), m.at.did, "")
        .unwrap();
    assert!(
        complete_import(&mut holder, &air, &imported)
            .iter()
            .any(|l| l.contains("final"))
    );
    assert!(m.spent(&c) && !m.spent(&d));

    // The sender sees one of two spent and takes the other back.
    assert_eq!(
        check_handoff(&mut dev, &air, &out.id).unwrap(),
        Standing::Partly { spent: 1, left: 1 }
    );
    assert_eq!(dev.handoffs_out()[0].notes.len(), 1);
    let done = reclaim_handoff(&mut dev, &air, &out.id).unwrap();
    assert_eq!(done.standing, Standing::Reclaimed);
    assert_eq!(psp_total(&dev), 8, "the unspent note is back");
    assert!(m.spent(&d));

    // The same on the receiving side, with a fresh pair: the note spent
    // elsewhere leaves the balance and the other is swapped in the same run.
    let (e, f) = (m.note(2), m.note(8));
    let mut dev2 = m.wallet(&dir, "dev2", vec![e.clone(), f.clone()]);
    let out2 = make(&mut dev2, m.at.did, 10, &key);
    let mut copy2 = m.wallet(&dir, "copy2", vec![e.clone()]);
    let e_out = make(&mut copy2, m.at.did, 2, &did(5));
    let mut holder2 = m.wallet(&dir, "holder2", vec![]);
    let imported = holder2
        .import_psp_handoff(&e_out.text, &did(5), m.at.did, "")
        .unwrap();
    complete_import(&mut holder2, &air, &imported);
    let mut user = m.wallet(&dir, "user", vec![]);
    let imported = user
        .import_psp_handoff(&out2.text, &key, m.at.did, "")
        .unwrap();
    assert_eq!(psp_total(&user), 10);
    let log = complete_import(&mut user, &air, &imported);
    assert!(log.iter().any(|l| l.contains("spent already")), "{log:?}");
    assert!(log.iter().any(|l| l.contains("final")), "{log:?}");
    assert_eq!(
        psp_total(&user),
        8,
        "only the note nobody else spent is kept"
    );
    assert_eq!(user.spent_notes().len(), 1);
    assert_eq!(user.unswapped_psp(), 0);
    assert!(user.pending_rollovers().is_empty());
    assert_eq!(
        check_handoff(&mut dev2, &air, &out2.id).unwrap(),
        Standing::Received
    );
}

#[test]
fn a_cancelled_psp_handoff_returns_the_notes() {
    let dir = scratch("cancel");
    let m = PspUp::start(&dir.join("psp"), T);
    let mut dev = m.wallet(&dir, "dev", vec![m.note(8), m.note(2)]);
    let ids = dev.select_psp_handoff(10).unwrap();
    let out = dev
        .export_psp_handoff(&ids, m.at.did, &did(7).public_key())
        .unwrap();
    assert_eq!(psp_total(&dev), 0);
    assert_eq!(dev.cancel_handoff(&out.id).unwrap(), 2);
    assert_eq!(psp_total(&dev), 10);
    assert!(dev.handoffs_out().is_empty());
    // The reopened wallet file holds the same.
    let again = open_wallet(&dir.join("dev.json")).unwrap();
    assert_eq!(psp_total(&again), 10);
}

// ---- FSP ---------------------------------------------------------------------------

fn fsp_total(w: &Wallet) -> u128 {
    w.balance().fsp
}

#[test]
fn an_fsp_handoff_carries_the_did_key_and_the_notes_work_at_the_fsp_mint() {
    let dir = scratch("fsp");
    let m = Mints::start(&dir, "20", "2", None);
    let mut a = m.wallet(&dir, "a", &[8, 4, 1]);
    fsp_sync(&mut a, &m.air, service()).unwrap();
    let req = a.build_fsp_issue(service(), None, 0).unwrap();
    settle_fsp(&mut a, &m.air, &req.hash()).unwrap();
    assert_eq!(fsp_total(&a), 13);
    let hex = hex::encode(service().serialize());
    assert_eq!(a.balance().fsp_by_service[&hex], 13, "grouped by service");
    assert_eq!(a.fsp_unknown_service(), (0, 0));

    // Hand over all of it, with the DID key.
    let key = did(7);
    let ids = a.select_fsp_handoff(&[(service(), 13)]).unwrap();
    let out = a.export_fsp_handoff(&ids, &key).unwrap();
    assert!(out.text.starts_with(FSP_PREFIX));
    assert_eq!(out.kind, HandoffKind::Fsp);
    assert!(out.with_did_key);
    assert_eq!((out.psp_units, out.fsp_units), (0, 13));
    assert_eq!(out.warning, FSP_WARNING);
    assert_eq!(fsp_total(&a), 0);
    assert!(a.balance().fsp_by_service.get(&hex).copied().unwrap_or(0) == 0);

    // A wallet that has never seen this mint takes it in. Nothing is swapped.
    let mut b = m.wallet(&dir, "b", &[]);
    let imported = b.import_fsp_handoff(&out.text, "a").unwrap();
    assert_eq!(imported.fsp_units, 13);
    assert_eq!(
        imported.did_key.as_ref().map(|k| k.to_array()),
        Some([7u8; 32])
    );
    assert!(imported.psp_swaps.is_empty());
    assert!(complete_import(&mut b, &AirSettings::default(), &imported).is_empty());
    assert!(b.pending_rollovers().is_empty() && b.pending_fsp().is_empty());
    assert_eq!(fsp_total(&b), 13);
    assert_eq!(b.balance().fsp_by_service[&hex], 13);
    assert_eq!(b.fsp_unknown_service(), (0, 0));
    assert!(!b.handoffs_in()[0].swapped);
    // They are the very notes a sent.
    let sent: Vec<String> = a.handoffs_out()[0].notes.iter().map(|n| n.id()).collect();
    for id in &sent {
        assert!(b.notes().iter().any(|n| &n.id() == id));
    }
    assert_eq!(b.handoffs_in()[0].id, out.id);

    // And they pay at the service's mint, once the new wallet has read its keys.
    fsp_sync(&mut b, &m.air, service()).unwrap();
    let req = b.build_fsp_spend(service(), 5, "coffee").unwrap();
    settle_fsp(&mut b, &m.air, &req.hash()).unwrap();
    assert_eq!(fsp_total(&b), 8);

    // The old device lets go of what it handed over: after this it cannot be
    // cancelled, so the old copy cannot be put back by mistake.
    a.finish_handoff(&out.id).unwrap();
    let why = invalid(a.cancel_handoff(&out.id));
    assert!(
        why.contains("is done: its notes are no longer kept"),
        "{why}"
    );
}

#[test]
fn the_old_combined_handoff_and_wrong_kinds_are_refused_at_the_wallet() {
    let dir = scratch("wrong");
    let m = PspUp::start(&dir.join("psp"), T);
    let mut dev = m.wallet(&dir, "dev", vec![m.note(4), m.note(2)]);
    let mut user = m.wallet(&dir, "user", vec![]);
    let ids = dev.select_psp_handoff(6).unwrap();
    let out = dev
        .export_psp_handoff(&ids, m.at.did, &did(7).public_key())
        .unwrap();
    // A PSP string is not an FSP handoff, and the old prefix is gone.
    let why = invalid(user.import_fsp_handoff(&out.text, ""));
    assert_eq!(why, "this is a PSP handoff, not an FSP handoff");
    let e = user
        .import_handoff("SPH1:ABCDEF", None, m.at.did, "")
        .unwrap_err()
        .to_string();
    assert!(e.contains("old combined handoff"), "{e}");
    let e = user
        .import_handoff(&out.text, None, m.at.did, "")
        .unwrap_err()
        .to_string();
    assert!(e.contains("give the DID secret key"), "{e}");
    assert!(user.handoffs_in().is_empty() && user.pending_rollovers().is_empty());
}
