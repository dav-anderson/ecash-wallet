//! The wallet against the real mint code, in one process: buy PSP with an
//! encrypted payload, settle it as the PSP mint does, claim the notes, exchange
//! them for ESP, and check every note against the mint's own keys.
//!
//! No network and no Bitcoin node: the OP_RETURN is skipped (the payload goes
//! straight into a `Received`) and the ESP mint reaches the PSP through a local
//! stand-in for its HTTP client.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ecash_wallet::psp::parse_signatures;
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::exchange::{self, Burn, ExchangeError, Psp, Rejection};
use esp_mint::responses::Responses;
use esp_mint::terms::Terms;
use mint_core::MintLogic;
use mint_types::{Amount, BlindNonce, MintInput, Nonce};
use psp_mint::records::Records;
use psp_mint::scan::Received;
use psp_mint::settle::{self, Settlement};
use secp256k1::{PublicKey, XOnlyPublicKey};
use sp_wire::seal::SecretKey as DidSecretKey;

const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONE_PSP_ESP: u128 = 100_000_000_000;

/// $10,000 per BTC in cents. A PSP is $0.10, so 1,000 sats is exactly 1 PSP and
/// 5,000 sats is exactly 5 PSP.
const BTC_10K: u64 = 1_000_000;

fn service() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&hex::decode(G_X).unwrap()).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ecash-wallet-flow-{}-{name}", {
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
) -> (usize, Vec<String>) {
    let (opened, ignored) = psp_mint::seal::open_payloads(
        mint_key,
        vec![Received {
            txid: txid.to_string(),
            confirmations: 6,
            value_sats,
            payload: Some(payload),
        }],
    );
    let mut lines = Vec::new();
    for received in &opened {
        let settlement = settle::settle(logic, records, received, &mut || Ok(BTC_10K)).unwrap();
        assert!(
            matches!(settlement, Settlement::Issued(_)),
            "{settlement:?}"
        );
        lines.extend(psp_mint::service::describe(received, &settlement));
    }
    (ignored, lines)
}

#[test]
fn buy_claim_and_exchange_end_to_end() {
    let dir = scratch("e2e");
    let mint_key = DidSecretKey::new();
    let psp = psp_mint::mint::open(&dir.join("psp"), Amount::from_units(1024)).unwrap();
    let mut records = Records::open(&dir.join("psp").join("settlements.json")).unwrap();
    let (esp_logic, master) = esp_mint::mint::open(&dir.join("esp")).unwrap();
    let mut responses = Responses::open(&dir.join("esp").join("responses.json")).unwrap();
    let wallet_file = dir.join("wallet.json");
    let mut wallet = Wallet::open(&wallet_file).unwrap();

    // buy 5 PSP as a 4 and a 1
    let reply = wallet.reply_did().unwrap();
    let build = wallet
        .build_psp_payload(&[4, 1], &reply, &mint_key.public_key())
        .unwrap();
    assert_eq!(wallet.balance().pending_purchases, 1);

    // the wallet is closed and reopened before the signatures arrive
    drop(wallet);
    let mut wallet = Wallet::open(&wallet_file).unwrap();
    assert_eq!(wallet.balance().pending_purchases, 1);
    // The ESP mint's current keyset, which new ESP outputs name.
    wallet
        .note_esp_keysets("esp", &esp_mint::rotation::keyset_id(&master), None)
        .unwrap();

    let (ignored, lines) =
        settle_payment(&psp, &mut records, &mint_key, "aa", 5_000, build.payload);
    assert_eq!(ignored, 0);
    let text = lines.join("\n");
    let signatures = parse_signatures(&text).unwrap();
    assert_eq!(signatures.len(), 2);

    let keys = psp.public_keys().clone();
    let claim = wallet.claim_psp(&signatures, &keys).unwrap();
    assert_eq!(claim.claimed_units, 5);
    assert_eq!(claim.still_pending, 0);
    let balance = wallet.balance();
    assert_eq!((balance.psp, balance.pending_purchases), (5, 0));

    // every PSP note passes the mint's own check
    let dummy = secp256k1::schnorr::Signature::from_slice(&[0u8; 64]).unwrap();
    for stored in wallet.notes() {
        assert_eq!(stored.kind, Kind::Psp);
        psp.verify_note(&MintInput {
            amount: Amount::from_units(stored.amount),
            note: stored.note,
            spend_signature: dummy,
        })
        .unwrap();
    }

    // a second claim of the same signatures finds nothing pending
    assert!(wallet.claim_psp(&signatures, &keys).is_err());

    // Exchange 3 PSP for ESP bound to the service. The wallet holds a 4 and a 1,
    // so it spends the 4 and asks the mint for all of it: 3 PSP of ESP for the
    // service and 1 PSP of change, as ESP under the same terms.
    let built = wallet.build_exchange(3, service(), None).unwrap();
    assert_eq!((built.psp_spent, built.change_esp), (4, ONE_PSP_ESP));
    assert_eq!(wallet.balance().reserved, 1);

    // a request that is off by one ESP unit is refused before anything is burned
    let mut off = built.request.clone();
    off.outputs[0].amount = Amount::from_units(off.outputs[0].amount.units + 1);
    let refused = exchange::exchange_gens(
        &esp_mint::rotation::Gens::only(&esp_logic, &master),
        &LocalPsp::new(&psp),
        &mut responses,
        now(),
        &off,
        &exchange::ExchangeSettings::default(),
    )
    .unwrap_err();
    assert!(
        matches!(refused, ExchangeError::Rejected(Rejection::NotExact { .. })),
        "{refused}"
    );
    for stored in wallet.notes() {
        assert!(!psp.is_spent(stored.note.nonce).unwrap());
    }
    assert!(responses.is_empty());

    let response = exchange::exchange_gens(
        &esp_mint::rotation::Gens::only(&esp_logic, &master),
        &LocalPsp::new(&psp),
        &mut responses,
        now(),
        &built.request,
        &exchange::ExchangeSettings::default(),
    )
    .unwrap();
    // the 4 is burned at the PSP and the 1 is not
    for stored in wallet.notes() {
        assert_eq!(psp.is_spent(stored.note.nonce).unwrap(), stored.amount == 4);
    }

    // a lost reply: the same request gets the same answer, burning nothing more
    let again = exchange::exchange_gens(
        &esp_mint::rotation::Gens::only(&esp_logic, &master),
        &LocalPsp::new(&psp),
        &mut responses,
        now(),
        &built.request,
        &exchange::ExchangeSettings::default(),
    )
    .unwrap();
    assert_eq!(response, again);

    let done = wallet.finish_exchange(&built.id, &response).unwrap();
    assert_eq!(done.esp_units, 4 * ONE_PSP_ESP);
    assert_eq!(done.change_esp, ONE_PSP_ESP);
    let balance = wallet.balance();
    assert_eq!(
        (balance.psp, balance.esp, balance.notes),
        (1, 4 * ONE_PSP_ESP, 3)
    );
    assert_eq!(balance.pending_exchanges, 0);

    // the last PSP note is exactly 1 PSP, the smallest exchange: no change
    let last = wallet.build_exchange(1, service(), None).unwrap();
    assert_eq!((last.psp_spent, last.change_esp), (1, 0));
    let response = exchange::exchange_gens(
        &esp_mint::rotation::Gens::only(&esp_logic, &master),
        &LocalPsp::new(&psp),
        &mut responses,
        now(),
        &last.request,
        &exchange::ExchangeSettings::default(),
    )
    .unwrap();
    let done = wallet.finish_exchange(&last.id, &response).unwrap();
    assert_eq!((done.esp_units, done.change_esp), (ONE_PSP_ESP, 0));
    let balance = wallet.balance();
    assert_eq!(
        (balance.psp, balance.esp, balance.notes),
        (0, 5 * ONE_PSP_ESP, 3)
    );

    // every ESP note, change included, verifies against the key the mint derives
    // for its terms
    let mut checked = 0;
    for note in wallet.notes() {
        assert_eq!(note.kind, Kind::Esp);
        let terms = Terms {
            service: service(),
            redeemable_after_day: note.terms.as_ref().unwrap().redeemable_after_day,
        };
        let sk = master.key_for(Amount::from_units(note.amount), &terms);
        assert!(bdhke::verify_message(
            &sk,
            note.note.signature,
            &note.note.nonce.as_hash_preimage()
        ));
        checked += 1;
    }
    assert_eq!(checked, 3);

    // the file on disk has the same balance
    let reopened = Wallet::open(&wallet_file).unwrap();
    assert_eq!(reopened.balance(), wallet.balance());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_payload_sealed_to_another_key_is_ignored_and_the_wallet_keeps_waiting() {
    let dir = scratch("other-key");
    let mint_key = DidSecretKey::new();
    let wrong_key = DidSecretKey::new();
    let psp = psp_mint::mint::open(&dir.join("psp"), Amount::from_units(1024)).unwrap();
    let mut records = Records::open(&dir.join("psp").join("settlements.json")).unwrap();
    let mut wallet = Wallet::open(&dir.join("wallet.json")).unwrap();
    let reply = wallet.reply_did().unwrap();

    let build = wallet
        .build_psp_payload(&[1], &reply, &wrong_key.public_key())
        .unwrap();
    let (opened, ignored) = psp_mint::seal::open_payloads(
        &mint_key,
        vec![Received {
            txid: "bb".into(),
            confirmations: 6,
            value_sats: 1_000,
            payload: Some(build.payload),
        }],
    );
    assert!(opened.is_empty());
    assert_eq!(ignored, 1);
    // nothing was recorded and nothing was issued
    assert!(records.get("bb").is_none());
    assert_eq!(wallet.balance().pending_purchases, 1);
    assert_eq!(wallet.balance().psp, 0);
    let _ = (&psp, &mut records);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_tampered_payload_is_ignored_at_every_byte() {
    let dir = scratch("tamper");
    let mint_key = DidSecretKey::new();
    let mut wallet = Wallet::open(&dir.join("wallet.json")).unwrap();
    let reply = wallet.reply_did().unwrap();
    let build = wallet
        .build_psp_payload(&[2, 1], &reply, &mint_key.public_key())
        .unwrap();
    for at in 0..build.payload.len() {
        let mut bad = build.payload.clone();
        bad[at] ^= 0x01;
        let (opened, ignored) = psp_mint::seal::open_payloads(
            &mint_key,
            vec![Received {
                txid: "cc".into(),
                confirmations: 6,
                value_sats: 3_000,
                payload: Some(bad),
            }],
        );
        assert!(opened.is_empty() && ignored == 1, "byte {at} was accepted");
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_exchange_without_enough_psp_is_refused_before_anything_is_reserved() {
    let dir = scratch("short");
    let mut wallet = Wallet::open(&dir.join("wallet.json")).unwrap();
    let err = wallet.build_exchange(1, service(), None).unwrap_err();
    assert!(matches!(err, WalletError::NotEnough(_)), "{err}");
    assert_eq!(wallet.balance().pending_exchanges, 0);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn signatures_for_outputs_the_wallet_did_not_ask_for_change_nothing() {
    let dir = scratch("stray");
    let mut wallet = Wallet::open(&dir.join("wallet.json")).unwrap();
    let stray: Vec<(BlindNonce, PublicKey)> = vec![(
        BlindNonce(PublicKey::from_slice(&hex::decode(format!("02{G_X}")).unwrap()).unwrap()),
        PublicKey::from_slice(&hex::decode(format!("02{G_X}")).unwrap()).unwrap(),
    )];
    let keys = Default::default();
    assert!(wallet.claim_psp(&stray, &keys).is_err());
    assert_eq!(wallet.balance().notes, 0);
    fs::remove_dir_all(&dir).unwrap();
}
