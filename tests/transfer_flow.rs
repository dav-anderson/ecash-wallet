//! ESP from the PSP to a service, in one process, against the real mint code:
//! buy PSP, exchange it for ESP, hand ESP to a service, and have the service
//! swap the notes at the ESP mint for notes only it controls.
//!
//! No network and no Bitcoin node, as in `flow.rs`: the PSP purchase is settled
//! with the PSP's own settlement code and the ESP mint reaches the PSP through a
//! local stand-in for its HTTP client.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ecash_wallet::psp::parse_signatures;
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::exchange::{self, Burn, Psp};
use esp_mint::keys::MasterSecret;
use esp_mint::responses::Responses;
use esp_mint::terms::Terms;
use esp_mint::transfer::{self, TransferError, TransferRejection};
use mint_core::MintLogic;
use mint_types::{Amount, MintInput, Nonce};
use psp_mint::records::Records;
use psp_mint::scan::Received;
use psp_mint::settle::{self, Settlement};
use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use sp_wire::seal::SecretKey as DidSecretKey;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_PSP: u64 = 100_000_000_000;

/// $10,000 per BTC in cents. A PSP is $0.10, so 1,000 sats is exactly 1 PSP and
/// 5,000 sats is exactly 5 PSP.
const BTC_10K: u64 = 1_000_000;

fn service() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
}

/// The service's DID secret key. Secret key 1 is the generator point, whose
/// x-only public key is `G_X`.
fn service_secret() -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    SecretKey::from_slice(&bytes).unwrap()
}

fn other_secret() -> SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = 2;
    SecretKey::from_slice(&bytes).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ecash-wallet-transfer-{}-{name}", {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The PSP mint in process, in place of the HTTP client. It keeps the memo of
/// each burn, as the real PSP does.
struct LocalPsp<'a> {
    logic: &'a MintLogic,
    memos: RefCell<BTreeMap<String, String>>,
}

impl<'a> LocalPsp<'a> {
    fn new(logic: &'a MintLogic) -> Self {
        LocalPsp {
            logic,
            memos: RefCell::new(BTreeMap::new()),
        }
    }
}

fn nonce_key(nonce: &Nonce) -> String {
    hex::encode(nonce.0.serialize())
}

impl Psp for LocalPsp<'_> {
    fn melt(&self, inputs: &[MintInput], memo: &str) -> Result<Amount, String> {
        for input in inputs {
            if !self
                .logic
                .is_spent(input.note.nonce)
                .map_err(|e| e.to_string())?
            {
                self.memos
                    .borrow_mut()
                    .insert(nonce_key(&input.note.nonce), memo.to_string());
            }
        }
        self.logic
            .melt(inputs, memo.as_bytes())
            .map_err(|e| e.to_string())
    }

    fn burns(&self, nonces: &[Nonce]) -> Result<Vec<Burn>, String> {
        nonces
            .iter()
            .map(|n| {
                let spent = self.logic.is_spent(*n).map_err(|e| e.to_string())?;
                let memo = if spent {
                    self.memos.borrow().get(&nonce_key(n)).cloned()
                } else {
                    None
                };
                Ok(Burn { spent, memo })
            })
            .collect()
    }
}

/// What the PSP mint does with a payment that has 6 confirmations: open the
/// payload, settle it, and return the signature lines it prints.
fn settle_payment(
    logic: &MintLogic,
    records: &mut Records,
    mint_key: &DidSecretKey,
    txid: &str,
    value_sats: u64,
    payload: Vec<u8>,
) -> Vec<String> {
    let (opened, ignored) = psp_mint::seal::open_payloads(
        mint_key,
        vec![Received {
            txid: txid.to_string(),
            confirmations: 6,
            value_sats,
            payload: Some(payload),
        }],
    );
    assert_eq!(ignored, 0);
    let mut lines = Vec::new();
    for received in &opened {
        let settlement = settle::settle(logic, records, received, &mut || Ok(BTC_10K)).unwrap();
        assert!(
            matches!(settlement, Settlement::Issued(_)),
            "{settlement:?}"
        );
        lines.extend(psp_mint::service::describe(received, &settlement));
    }
    lines
}

/// Exchange `psp_units` PSP for ESP bound to the service, through the real
/// exchange code.
fn exchange_psp(
    wallet: &mut Wallet,
    psp: &MintLogic,
    esp: &MintLogic,
    master: &MasterSecret,
    responses: &mut Responses,
    psp_units: u64,
) {
    let built = wallet.build_exchange(psp_units, service(), None).unwrap();
    let response = exchange::exchange_gens(
        &esp_mint::rotation::Gens::only(esp, master),
        &LocalPsp::new(psp),
        responses,
        now(),
        &built.request,
        &exchange::ExchangeSettings::default(),
    )
    .unwrap();
    wallet.finish_exchange(&built.id, &response).unwrap();
}

/// (issued, redeemed) ESP units at the mint.
fn totals(esp: &MintLogic) -> (u64, u64) {
    let (issued, redeemed) = esp.audit_totals().unwrap();
    (issued.units, redeemed.units)
}

#[test]
fn exchange_hand_over_and_transfer_end_to_end() {
    let dir = scratch("e2e");
    let mint_key = DidSecretKey::new();
    let psp = psp_mint::mint::open(&dir.join("psp"), Amount::from_units(1024)).unwrap();
    let mut records = Records::open(&dir.join("psp").join("settlements.json")).unwrap();
    let (esp, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    let mut responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let mut app = Wallet::open(&dir.join("app.json")).unwrap();
    let esp_keyset = esp_mint::rotation::keyset_id(&master);
    app.note_esp_keysets("esp", &esp_keyset, None).unwrap();

    assert_eq!(
        Keypair::from_secret_key(SECP256K1, &service_secret())
            .x_only_public_key()
            .0,
        service()
    );

    // The app buys 5 PSP as a 4 and a 1 and exchanges them for ESP bound to the
    // service: 3 PSP asked for and 1 PSP of change from the 4, then the last 1.
    // It ends up holding ESP notes of 3, 1 and 1 PSP.
    let reply = app.reply_did().unwrap();
    let build = app
        .build_psp_payload(&[4, 1], &reply, &mint_key.public_key())
        .unwrap();
    let lines = settle_payment(&psp, &mut records, &mint_key, "aa", 5_000, build.payload);
    let signatures = parse_signatures(&lines.join("\n")).unwrap();
    let keys = psp.public_keys().clone();
    app.claim_psp(&signatures, &keys).unwrap();
    exchange_psp(&mut app, &psp, &esp, &master, &mut responses, 3);
    exchange_psp(&mut app, &psp, &esp, &master, &mut responses, 1);
    let b = app.balance();
    assert_eq!((b.psp, b.esp, b.notes), (0, 5 * u128::from(ONE_PSP), 3));
    let (issued0, redeemed0) = totals(&esp);
    assert_eq!((issued0, redeemed0), (5 * ONE_PSP, 0));

    // An amount the notes cannot make is refused, and nothing changes.
    let before = app.balance();
    let err = app
        .hand_over_esp(service(), 1_500_000_000_000, None)
        .unwrap_err();
    assert!(matches!(err, WalletError::NotEnough(_)), "{err}");
    assert_eq!(app.balance(), before);

    // The app hands the service 3 PSP of ESP: the 3 PSP note.
    let handover = app
        .hand_over_esp(service(), 3 * u128::from(ONE_PSP), None)
        .unwrap();
    assert_eq!(handover.service, service());
    assert_eq!(handover.notes.len(), 1);
    let handed = handover.notes[0].note;
    assert_eq!(
        handover.notes[0].keyset, esp_keyset,
        "the hand-over names the keyset"
    );
    let b = app.balance();
    assert_eq!(
        (b.esp, b.notes, b.handed_over),
        (2 * u128::from(ONE_PSP), 2, 1)
    );

    // The service takes the notes in and swaps them at the ESP mint.
    let svc_file = dir.join("svc.json");
    let mut svc = Wallet::open(&svc_file).unwrap();
    svc.note_esp_keysets("esp", &esp_keyset, None).unwrap();
    let (count, units) = svc.receive_handover(&handover).unwrap();
    assert_eq!((count, units), (1, 3 * u128::from(ONE_PSP)));
    let built = svc.build_transfer(&service_secret(), None, None).unwrap();
    assert_eq!(built.esp_units, 3 * u128::from(ONE_PSP));
    assert_eq!(svc.balance().reserved, 1);

    let response = transfer::transfer(&esp, &master, &mut responses, &built.request).unwrap();
    // Nothing is created and nothing leaves circulation: the same amount is
    // issued and redeemed, so the outstanding total is where it was.
    let (issued1, redeemed1) = totals(&esp);
    assert_eq!(issued1 - issued0, 3 * ONE_PSP);
    assert_eq!(redeemed1 - redeemed0, 3 * ONE_PSP);
    assert_eq!(issued1 - redeemed1, issued0 - redeemed0);
    // The old note is spent. The PSP is not involved at all.
    assert!(esp.is_spent(handed.nonce).unwrap());
    // A lost reply: the same request gets the same answer and burns nothing more.
    let again = transfer::transfer(&esp, &master, &mut responses, &built.request).unwrap();
    assert_eq!(response, again);
    assert_eq!(totals(&esp), (issued1, redeemed1));

    let done = svc.finish_transfer(&built.id, &response).unwrap();
    assert_eq!(done.esp_units, 3 * u128::from(ONE_PSP));
    let b = svc.balance();
    assert_eq!(
        (b.esp, b.notes, b.reserved, b.pending_transfers),
        (3 * u128::from(ONE_PSP), 1, 0, 0)
    );
    let new_note = svc.notes()[0].clone();
    assert_eq!(new_note.kind, Kind::Esp);
    assert_eq!(
        svc.esp_keyset_of(&new_note).unwrap(),
        esp_keyset,
        "recorded from the reply"
    );
    assert_ne!(new_note.note.nonce, handed.nonce);
    assert!(!esp.is_spent(new_note.note.nonce).unwrap());
    // The new note has the same service and day, and the mint's own key for those
    // terms accepts it.
    let terms = new_note.terms.unwrap();
    assert_eq!(terms.service, service());
    assert_eq!(terms.redeemable_after_day, handover.redeemable_after_day);
    let key = master.key_for(
        Amount::from_units(new_note.amount),
        &Terms {
            service: terms.service,
            redeemable_after_day: terms.redeemable_after_day,
        },
    );
    assert!(bdhke::verify_message(
        &key,
        new_note.note.signature,
        &new_note.note.nonce.as_hash_preimage()
    ));

    // The same handover presented to the mint a second time is a double
    // presentation: the note is spent, the mint refuses, and the wallet frees it.
    let mut svc2 = Wallet::open(&dir.join("svc2.json")).unwrap();
    svc2.note_esp_keysets("esp", &esp_keyset, None).unwrap();
    svc2.receive_handover(&handover).unwrap();
    let dup = svc2.build_transfer(&service_secret(), None, None).unwrap();
    let totals_before = totals(&esp);
    let err = transfer::transfer(&esp, &master, &mut responses, &dup.request).unwrap_err();
    assert!(
        matches!(
            err,
            TransferError::Rejected(TransferRejection::AlreadySpent { index: 0 })
        ),
        "{err}"
    );
    assert_eq!(totals(&esp), totals_before);
    svc2.cancel_transfer(&dup.id).unwrap();
    assert_eq!(svc2.balance().reserved, 0);

    // Another service's key finds nothing to swap: the notes name this service.
    let mut other = Wallet::open(&dir.join("other.json")).unwrap();
    other.receive_handover(&handover).unwrap();
    let err = other
        .build_transfer(&other_secret(), None, None)
        .unwrap_err();
    assert!(matches!(err, WalletError::NotEnough(_)), "{err}");

    // The new note moves again, and can be split in the same swap.
    let split = svc
        .build_transfer(&service_secret(), None, Some(&[ONE_PSP, 2 * ONE_PSP]))
        .unwrap();
    let response = transfer::transfer(&esp, &master, &mut responses, &split.request).unwrap();
    let done = svc.finish_transfer(&split.id, &response).unwrap();
    assert_eq!(
        (done.esp_units, done.notes.len()),
        (3 * u128::from(ONE_PSP), 2)
    );
    assert!(esp.is_spent(new_note.note.nonce).unwrap());
    let (issued2, redeemed2) = totals(&esp);
    assert_eq!(issued2 - redeemed2, issued0 - redeemed0);

    // The file on disk has the same balance.
    let reopened = Wallet::open(&svc_file).unwrap();
    assert_eq!(reopened.balance(), svc.balance());
    fs::remove_dir_all(&dir).unwrap();
}
