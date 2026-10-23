//! The wallet against the real mint code, in one process: buy PSP with an
//! encrypted payload, settle it as the PSP mint does, claim the notes, exchange
//! them for ESP, and check every note against the mint's own keys.
//!
//! No Bitcoin node: the OP_RETURN is skipped (the payload goes straight into a
//! `Received`). The exchange goes the way a wallet sends one: `build_exchange`,
//! then `send_exchange` over AIR to the ESP mint, which runs its real exchange
//! route; the mint reaches the PSP through a local stand-in for its HTTP client.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};

use ecash_wallet::mint_info::send_exchange;
use ecash_wallet::psp::Delivered;
use ecash_wallet::{Kind, WalletError};
use esp_mint::config::Config as EspConfig;
use esp_mint::exchange::{Burn, Psp};
use esp_mint::terms::Terms;
use mint_core::state::AppState;
use mint_types::{Amount, MintInput, Nonce};
use psp_mint::scan::Received;
use psp_mint::settle::Settlement;
use sp_wire::ServiceDid;
use sp_wire::air_request::delivery::Outcome;
use sp_wire::seal::SecretKey as DidSecretKey;

use common::air::EspAt;
use common::{EspMint, PspMint, open_wallet, scratch};

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_PSP_ESP: u128 = 100_000_000_000;

fn service() -> ServiceDid {
    ServiceDid::parse(&format!("02{G_X}")).unwrap()
}

/// The PSP mint in process, in place of the HTTP client. It keeps the memo of
/// each burn, as the real PSP does.
struct LocalPsp {
    state: Arc<AppState>,
    memos: Mutex<BTreeMap<String, String>>,
}

impl LocalPsp {
    fn new(state: Arc<AppState>) -> Self {
        LocalPsp {
            state,
            memos: Mutex::new(BTreeMap::new()),
        }
    }
}

fn nonce_key(nonce: &Nonce) -> String {
    hex::encode(nonce.0.serialize())
}

impl Psp for LocalPsp {
    fn melt(&self, inputs: &[MintInput], memo: &str) -> Result<Amount, String> {
        let logic = self.state.logic.lock().map_err(|e| e.to_string())?;
        for input in inputs {
            if !logic
                .is_spent(input.note.nonce)
                .map_err(|e| e.to_string())?
            {
                self.memos
                    .lock()
                    .unwrap()
                    .insert(nonce_key(&input.note.nonce), memo.to_string());
            }
        }
        logic
            .melt(inputs, memo.as_bytes())
            .map_err(|e| e.to_string())
    }

    fn burns(&self, nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
        let logic = self.state.logic.lock().map_err(|e| e.to_string())?;
        nonces
            .iter()
            .map(|n| {
                let spent = logic.is_spent(*n).map_err(|e| e.to_string())?;
                let memo = if spent {
                    self.memos.lock().unwrap().get(&nonce_key(n)).cloned()
                } else {
                    None
                };
                Ok(Burn { spent, memo })
            })
            .collect()
    }
}

#[test]
fn buy_claim_and_exchange_end_to_end() {
    let dir = scratch("e2e");
    let mint_key = DidSecretKey::new();
    let psp = PspMint::open(&dir.join("psp"));
    let esp = EspMint::open(
        &dir.join("esp"),
        Box::new(LocalPsp::new(Arc::clone(&psp.state))),
        EspConfig::default(),
        0,
    );
    let wallet_file = dir.join("wallet.json");
    let mut wallet = open_wallet(&wallet_file).unwrap();

    // buy 50 PSP (the least the wallet builds) as 32, 8, two 4s and two 1s, so
    // that the exchange below still has a 4 and a 1 to spend
    let build = wallet
        .build_psp_payload(&[32, 8, 4, 4, 1, 1], &mint_key.public_key())
        .unwrap();
    assert_eq!(wallet.balance().pending_purchases, 1);

    // the wallet is closed and reopened before the signatures arrive
    drop(wallet);
    let mut wallet = open_wallet(&wallet_file).unwrap();
    assert_eq!(wallet.balance().pending_purchases, 1);
    // The ESP mint's current keyset, which new ESP outputs name.
    wallet.note_esp_keysets("esp", &esp.keyset, None).unwrap();

    // The PSP mint settles the payment: 6 confirmations, $10,000 a BTC.
    let settled = psp.pay(&mint_key, "aa", 50_000, build.payload);
    assert!(matches!(settled, Settlement::Issued(_)), "{settled:?}");
    // what the PSP stores for the payer: the signatures
    let outcome = psp.delivery_of("aa");
    let Outcome::Signed(signed) = &outcome else {
        panic!("expected signatures, got {outcome:?}");
    };
    assert_eq!(signed.signatures.len(), 6);

    // the record's signatures and keysets are all the wallet needs
    let Delivered::Claimed(claimed) = wallet.apply_delivery(&build.id, &outcome).unwrap() else {
        panic!("expected the purchase to be claimed");
    };
    let claim = claimed.claim;
    assert_eq!(claim.claimed_units, 50);
    assert_eq!(claim.still_pending, 0);
    let balance = wallet.balance();
    assert_eq!((balance.psp, balance.pending_purchases), (50, 0));

    // every PSP note passes the mint's own check
    let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
    {
        let psp_logic = psp.state.logic.lock().unwrap();
        for stored in wallet.notes() {
            assert_eq!(stored.kind, Kind::Psp);
            psp_logic
                .verify_note(&MintInput {
                    amount: Amount::from_units(stored.amount),
                    note: stored.note,
                    spend_signature: dummy,
                })
                .unwrap();
        }
    }
    let psp_spent = |n: &ecash_wallet::store::StoredNote| {
        psp.state
            .logic
            .lock()
            .unwrap()
            .is_spent(n.note.nonce)
            .unwrap()
    };

    // the same record again changes nothing
    let before = wallet.balance();
    assert_eq!(
        wallet.apply_delivery(&build.id, &outcome).unwrap(),
        Delivered::AlreadyDone
    );
    assert_eq!(wallet.balance(), before);

    // The ESP mint answers over AIR, as it does for a wallet: its real exchange
    // route, with the PSP mint behind a stand-in for its HTTP client.
    let at = EspAt::new(Arc::clone(&esp.state), &dir.join("esp-air"));
    let air = at.air(10, 3);

    // Exchange 3 PSP for ESP bound to the service. No set of the wallet's notes
    // (32, 8, 4, 4, 1, 1) adds up to 3, so it spends one 4 and asks the mint for
    // all of it: 3 PSP of ESP for the service and 1 PSP of change, as ESP under
    // the same terms.
    let built = wallet.build_exchange(3, service(), None).unwrap();
    assert_eq!((built.psp_spent, built.change_esp), (4, ONE_PSP_ESP));
    assert_eq!(wallet.balance().reserved, 1);

    // a request that asks for more than the PSP is worth (an output doubled,
    // still a power of two) is refused before anything is burned
    let mut off = built.request.clone();
    off.outputs[0].amount = Amount::from_units(off.outputs[0].amount.units * 2);
    let extra = built.request.outputs[0].amount.units;
    let refused = match send_exchange(&mut wallet, &air, &off).unwrap_err() {
        WalletError::Refused(body) => body,
        other => panic!("expected the mint to refuse the exchange, got {other:?}"),
    };
    // the mint's refusal is its JSON body: `not exact`, short by what was added
    let refused: serde_json::Value = serde_json::from_str(&refused).unwrap();
    let why = refused["error"].as_str().unwrap();
    assert!(why.contains("an exchange must be exact"), "{why}");
    assert!(why.contains(&format!("short by {extra}")), "{why}");
    assert!(why.contains("Nothing was burned"), "{why}");
    for stored in wallet.notes() {
        assert!(!psp_spent(stored));
    }
    assert!(esp.state.responses.lock().unwrap().is_empty());

    let response = send_exchange(&mut wallet, &air, &built.request).unwrap();
    // one 4 is burned at the PSP and no other note is
    let burned: Vec<u64> = wallet
        .notes()
        .iter()
        .filter(|n| psp_spent(n))
        .map(|n| n.amount)
        .collect();
    assert_eq!(burned, vec![4]);

    // a lost reply: the same request gets the same answer, burning nothing more
    let again = send_exchange(&mut wallet, &air, &built.request).unwrap();
    assert_eq!(response, again);

    // every output is a power of two: 3 PSP and 1 PSP of change are 10^11 x 4
    // ESP units, as several notes
    assert!(
        built
            .request
            .outputs
            .iter()
            .all(|o| o.amount.units.is_power_of_two())
    );
    let first_notes = built.request.outputs.len();
    assert!(first_notes > 2);
    // 3 PSP is 3 x 10^11 ESP units, which has 15 bits set, so 15 notes; the
    // 1 PSP of change is 10^11, also 15 bits, so 15 more: 30 ESP notes.
    assert_eq!(first_notes, 30);
    let done = wallet.finish_exchange(&built.id, &response).unwrap();
    assert_eq!(done.esp_units, 4 * ONE_PSP_ESP);
    assert_eq!(done.change_esp, ONE_PSP_ESP);
    let balance = wallet.balance();
    // `notes` counts every note the wallet holds: the 30 ESP notes and the 5 PSP
    // notes that were not spent (32, 8, 4, 1 and 1).
    assert_eq!(
        (balance.psp, balance.esp, balance.notes),
        (46, 4 * ONE_PSP_ESP, first_notes + 5)
    );
    assert_eq!(balance.pending_exchanges, 0);

    // a 1 is exactly 1 PSP, the smallest exchange: no change
    let last = wallet.build_exchange(1, service(), None).unwrap();
    assert_eq!((last.psp_spent, last.change_esp), (1, 0));
    let response = send_exchange(&mut wallet, &air, &last.request).unwrap();
    let done = wallet.finish_exchange(&last.id, &response).unwrap();
    assert_eq!((done.esp_units, done.change_esp), (ONE_PSP_ESP, 0));
    let balance = wallet.balance();
    assert_eq!(
        (balance.psp, balance.esp, balance.notes),
        // 32, 8, 4 and 1 PSP are left, with the 30 ESP notes from before and the
        // 15 of the last 1 PSP
        (
            45,
            5 * ONE_PSP_ESP,
            first_notes + last.request.outputs.len() + 4
        )
    );

    // every ESP note, change included, verifies against the key the mint derives
    // for its terms
    let mut checked = 0;
    for note in wallet.notes().iter().filter(|n| n.kind == Kind::Esp) {
        let terms = Terms {
            service: service(),
            redeemable_after_day: note.terms.as_ref().unwrap().redeemable_after_day,
        };
        let sk = esp
            .state
            .master
            .key_for(Amount::from_units(note.amount), &terms);
        assert!(bdhke::verify_message(
            &sk,
            note.note.signature,
            &note.note.nonce.as_hash_preimage()
        ));
        checked += 1;
    }
    // all of them: the 30 from the first exchange and the 15 from the last
    assert_eq!(checked, first_notes + last.request.outputs.len());

    // the mint's listener stops before the folder goes
    drop(at);

    // the file on disk has the same balance
    let reopened = open_wallet(&wallet_file).unwrap();
    assert_eq!(reopened.balance(), wallet.balance());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_payload_sealed_to_another_key_is_ignored_and_the_wallet_keeps_waiting() {
    let dir = scratch("other-key");
    let mint_key = DidSecretKey::new();
    let wrong_key = DidSecretKey::new();
    let psp = PspMint::open(&dir.join("psp"));
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();

    let build = wallet
        .build_psp_payload(&[32, 16, 2], &wrong_key.public_key())
        .unwrap();
    let (opened, ignored) = psp_mint::seal::open_payloads(
        &mint_key,
        vec![Received {
            txid: "bb".into(),
            confirmations: 6,
            value_sats: 50_000,
            payload: Some(build.payload),
        }],
    );
    assert!(opened.is_empty());
    assert_eq!(ignored, 1);
    // nothing was recorded and nothing was issued
    assert!(psp.records.lock().unwrap().get("bb").is_none());
    assert_eq!(wallet.balance().pending_purchases, 1);
    assert_eq!(wallet.balance().psp, 0);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_record_for_a_purchase_the_wallet_does_not_hold_changes_nothing() {
    let dir = scratch("stray");
    let mut wallet = open_wallet(&dir.join("wallet.json")).unwrap();
    let stray = Outcome::Signed(sp_wire::air_request::delivery::Signed {
        keyset: "0123456789abcdef".to_string(),
        signatures: vec![sp_wire::air_request::delivery::SignedOutput {
            blind_nonce: format!("02{G_X}"),
            signature: format!("02{G_X}"),
        }],
        keysets: sp_wire::psp::KeysetsResponse {
            current: "0123456789abcdef".to_string(),
            previous: None,
            keysets: Default::default(),
        },
        skipped_units: 0,
        credit_cents: 0,
        open_until: 0,
        rules: None,
    });
    assert_eq!(
        wallet.apply_delivery("no-such-purchase", &stray).unwrap(),
        Delivered::AlreadyDone
    );
    assert_eq!(wallet.balance().notes, 0);
    fs::remove_dir_all(&dir).unwrap();
}
