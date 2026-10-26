//! The mints the wallet's integration tests run, and the AIR plumbing they share.
//!
//! **One psp-mint fixture and one esp-mint fixture** live here, and every test
//! file builds its mints with them, so a change to how a mint is put together
//! touches this file only. Both are built as the mints' own `main` builds them,
//! and so both rotate:
//!
//! - [`PspMint`]: `Rotor::open_at`, `Rollovers::open`, `Rotating::new`, the
//!   shared settlement records and `Health`, and settlement through
//!   `settle_ruled` under the policy `Config::policy` gives (what `psp-mint serve`
//!   runs);
//! - [`EspMint`]: `EspState::open`, esp-mint's own constructor (what `esp-mint
//!   serve` calls), with the rotation settings set to an hour to the first
//!   rotation and an hour between rotations.
//!
//! The part that needs the mints' `air_listener` (the shared `air_server`, the
//! listeners, the wallet's `[air]` settings, `Mints` for fsp-mint) is in `air.rs`
//! and is built only with the `air-listener-tests` feature. Every test file that
//! uses this module needs that feature (`cli.rs` and `keyset_refusals.rs` use no
//! mint and do not include it).

#![allow(dead_code)]

#[cfg(feature = "air-listener-tests")]
pub mod air;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ecash_wallet::config::AirSettings;
use ecash_wallet::store::{HandedNote, StoredNote, WalletData};
use ecash_wallet::{Kind, Wallet, WalletError};
use esp_mint::config::Config as EspConfig;
use esp_mint::exchange::{Burn, Psp};
use esp_mint::ledger::Movements;
use esp_mint::responses::Entry;
use esp_mint::server::EspState;
use esp_mint::terms::Terms;
use mint_core::state::AppState;
use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use psp_mint::records::{Records, SharedRecords};
use psp_mint::rotation::{Rollovers, Rotor};
use psp_mint::scan::Received;
use psp_mint::server::{Health, Limits, Rotating, SharedRotating};
use psp_mint::settle::{self, Policy, Settlement};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
use sp_wire::ServiceDid;
use sp_wire::air_request::delivery::Outcome;
use sp_wire::esp::exchange::ExchangeResponse;
use sp_wire::seal::SecretKey as DidKey;

/// What the wallet's records call the PSP (its live keysets, its swap times, the
/// mint a handoff names): its DID in lowercase hex, as the command line names it.
/// Nothing dials it; the PSP is reached by DID.
pub fn psp_record(air: &AirSettings) -> String {
    ecash_wallet::fsp::record_of(air.psp_did())
}

/// The same for the ESP.
pub fn esp_record(air: &AirSettings) -> String {
    ecash_wallet::fsp::record_of(air.esp_did())
}

/// The network every test PSP mint is on, as its `Health` and the wallet's checks
/// agree on it.
pub const NETWORK: &str = "regtest";

/// Open the wallet file at `path` for [`NETWORK`] (a new file is made with it).
pub fn open_wallet(path: &Path) -> Result<Wallet, WalletError> {
    Wallet::open(path, NETWORK)
}

/// The clock a mint with a fixed clock starts at (2027-01-15), for the tests that
/// move it across a rotation.
pub const T0: u64 = 1_800_000_000;

/// $10,000 per BTC in cents: a PSP is $0.10, so 1,000 sats is exactly 1 PSP and
/// 5,000 sats is exactly 5 PSP.
pub const BTC_10K: u64 = 1_000_000;

/// A folder of its own for one test, empty. `name` says whose.
pub fn scratch(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ecash-wallet-it-{}-{}-{name}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------- the PSP mint

/// The fee of the one kind 15 write (`claim.write_fee`), in PSP units, as the
/// live system has it on.
pub const WRITE_FEE: u64 = 2;

/// The fee of each of the two reads (`delivery.read_fee`), in PSP units.
pub const READ_FEE: u64 = 1;

/// What the two reads and the write come to, which comes off every payment.
pub const FEES: u64 = 2 * READ_FEE + WRITE_FEE;

/// The psp-mint settings a test mint runs under: the fees are on, as they are in
/// the live system (the units a payment owes are what it buys less
/// [`FEES`]). The only payment settled with no fee is the genesis purchase.
pub fn fees_on() -> psp_mint::config::Config {
    let mut config = psp_mint::config::Config::defaults("");
    config.claim_write_fee = WRITE_FEE;
    config.delivery_read_fee = READ_FEE;
    config
}

/// A PSP mint wired as `psp-mint serve` wires it: it rotates (1 hour to the first
/// rotation, then every hour), its settlement records are shared the way the
/// listener shares them with the scan, and it settles under [`fees_on`].
///
/// `clock` is `0` for the system clock, or a fixed time a test moves with
/// [`PspMint::set_clock`].
pub struct PspMint {
    pub dir: PathBuf,
    pub state: Arc<AppState>,
    pub rot: SharedRotating,
    pub records: SharedRecords,
    pub health: Arc<Health>,
    pub limits: Limits,
    policy: Policy,
    /// The keyset that signed each note this mint issued by [`PspMint::note`],
    /// by note ID, as the wallet records it on every note.
    signed_by: Mutex<BTreeMap<String, String>>,
}

impl PspMint {
    /// A mint in `dir` on the system clock.
    pub fn open(dir: &Path) -> PspMint {
        PspMint::open_at(dir, 0)
    }

    /// A mint in `dir` on a fixed clock (`0` is the system clock).
    pub fn open_at(dir: &Path, clock: u64) -> PspMint {
        PspMint::open_with(dir, clock, Limits::default())
    }

    /// As [`PspMint::open_at`], with these request ceilings.
    pub fn open_with(dir: &Path, clock: u64, limits: Limits) -> PspMint {
        PspMint::build(dir, clock, limits, fees_on())
    }

    /// As [`PspMint::open_at`], with this psp-mint `Config`: the settlement
    /// policy it gives (`Config::policy`) is the one payments are settled under,
    /// as `psp-mint serve` runs it. A test that needs fees sets them here
    /// (`reconciliation_fee` and the others), since they are 0 by default.
    pub fn open_configured(dir: &Path, clock: u64, config: psp_mint::config::Config) -> PspMint {
        PspMint::build(dir, clock, Limits::default(), config)
    }

    fn build(dir: &Path, clock: u64, limits: Limits, config: psp_mint::config::Config) -> PspMint {
        let (rotor, logic) = Rotor::open_at(dir, 1, 1, clock).unwrap();
        let rot = Rotating::new(rotor, Rollovers::open(dir).unwrap());
        let records: SharedRecords = Arc::new(Mutex::new(
            Records::open(&dir.join("settlements.json")).unwrap(),
        ));
        let health = Health::for_network(100, NETWORK);
        health.record_scan_at(psp_mint::server::now_secs());
        PspMint {
            dir: dir.to_path_buf(),
            state: psp_mint::server::app_state(logic),
            rot,
            records,
            health,
            limits,
            policy: config.policy(),
            signed_by: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn set_clock(&self, t: u64) {
        self.rot
            .rotor
            .lock()
            .unwrap()
            .clock
            .store(t, Ordering::SeqCst);
    }

    /// The ID of the keyset the mint signs with now.
    pub fn keyset(&self) -> String {
        psp_mint::rotation::keyset_id(self.state.logic.lock().unwrap().public_keys())
    }

    /// A note of `units` this mint issued, as the wallet stores it.
    pub fn note(&self, units: u64) -> StoredNote {
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(kp.public_key());
        let (b, r) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let logic = self.state.logic.lock().unwrap();
        let out = logic
            .issue(&MintOutput {
                amount,
                blind_nonce: BlindNonce(b),
            })
            .unwrap();
        let note = StoredNote {
            kind: Kind::Psp,
            amount: units,
            note: Note {
                nonce,
                signature: bdhke::unblind_message(&out.0, &r, &logic.public_keys()[&amount]),
            },
            spend_secret: kp.secret_key(),
            terms: None,
            reserved_by: None,
        };
        let keyset = psp_mint::rotation::keyset_id(logic.public_keys());
        self.signed_by.lock().unwrap().insert(note.id(), keyset);
        note
    }

    /// Whether the mint has this note as spent, in the current set or the previous
    /// one.
    pub fn spent(&self, n: &StoredNote) -> bool {
        let logic = self.state.logic.lock().unwrap();
        let rotor = self.rot.rotor.lock().unwrap();
        logic.is_spent(n.note.nonce).unwrap()
            || rotor
                .previous
                .as_ref()
                .is_some_and(|(_, l)| l.is_spent(n.note.nonce).unwrap())
    }

    /// A wallet file in `dir` holding `notes` (all from [`PspMint::note`]), each
    /// recorded under the keyset that signed it, and the wallet opened on it.
    pub fn wallet(&self, dir: &Path, name: &str, notes: Vec<StoredNote>) -> Wallet {
        let path = dir.join(format!("{name}.json"));
        let signed = self.signed_by.lock().unwrap();
        let data = WalletData {
            keysets: notes
                .iter()
                .map(|n| {
                    let keyset = signed
                        .get(&n.id())
                        .expect("a note this mint issued with PspMint::note");
                    (n.id(), keyset.clone())
                })
                .collect(),
            notes,
            network: NETWORK.into(),
            ..Default::default()
        };
        std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        open_wallet(&path).unwrap()
    }

    /// Settle `received` at `price_cents` a BTC, as the scan does: the lock order
    /// is the records, then the mint, then the rotor, and a payload that names the
    /// previous set is signed by it.
    pub fn settle(&self, received: &Received, price_cents: u64) -> Settlement {
        let mut records = self.records.lock().unwrap();
        settle::settle_ruled(
            &mut records,
            received,
            &mut || Ok(price_cents),
            &self.policy,
            sp_wire::air_request::addr::now_secs(),
        )
        .unwrap()
    }

    /// What the mint does with a payment of `sats` that has 6 confirmations and
    /// carries `payload`: open the payload with `mint_key` (the DID key it was
    /// sealed to) and settle it at $10,000 a BTC.
    pub fn pay(&self, mint_key: &DidKey, txid: &str, sats: u64, payload: Vec<u8>) -> Settlement {
        let (opened, ignored) = psp_mint::seal::open_payloads(
            mint_key,
            vec![Received {
                txid: txid.to_string(),
                confirmations: 6,
                value_sats: sats,
                payload: Some(payload),
                block_time: Some(sp_wire::air_request::addr::now_secs()),
            }],
        );
        assert_eq!(ignored, 0, "the payload opens with the mint's DID key");
        assert_eq!(opened.len(), 1);
        self.settle(&opened[0], BTC_10K)
    }

    /// What the mint stored for the payer of `txid`: the outcome it writes to the
    /// payer's AIR record. The wallet applies it as it would the opened record.
    pub fn delivery_of(&self, txid: &str) -> Outcome {
        self.records
            .lock()
            .unwrap()
            .get(txid)
            .and_then(|r| r.delivery.as_ref())
            .expect("psp-mint stored a delivery for the payer")
            .outcome
            .clone()
    }

    /// The records read again from their file, as after a restart of the mint.
    pub fn reopen_records(&self) {
        *self.records.lock().unwrap() = Records::open(&self.dir.join("settlements.json")).unwrap();
    }
}

// ---------------------------------------------------------------- the ESP mint

/// An ESP mint wired as `esp-mint serve` wires it: it rotates (1 hour to the
/// first rotation, then every hour). Dereferences to its [`EspState`].
pub struct EspMint {
    pub state: Arc<EspState>,
    /// The keyset the mint started on.
    pub keyset: String,
}

impl std::ops::Deref for EspMint {
    type Target = EspState;

    fn deref(&self) -> &EspState {
        &self.state
    }
}

impl EspMint {
    /// A mint with its data in `data`, calling `psp` for the PSP side of an
    /// exchange, under `config`, on a fixed clock (`0` is the system clock). Opened
    /// with the library's own constructor, as `esp-mint serve` opens it; only the
    /// rotation settings are the fixture's (see [`EspMint`]).
    pub fn open(
        data: &Path,
        psp: Box<dyn Psp + Send + Sync>,
        mut config: EspConfig,
        clock: u64,
    ) -> EspMint {
        config.rotation_activation_hours = 1;
        config.rotation_period_hours = 1;
        let state = Arc::new(EspState::open(data, psp, config, clock).unwrap());
        let keyset = state.rotor.lock().unwrap().current.id.clone();
        EspMint { state, keyset }
    }

    /// A mint whose PSP side refuses every call, for the tests that never
    /// exchange PSP.
    pub fn open_without_psp(data: &Path) -> EspMint {
        EspMint::open(data, Box::new(NoPsp), EspConfig::default(), 0)
    }

    pub fn set_clock(&self, t: u64) {
        self.state
            .rotor
            .lock()
            .unwrap()
            .clock
            .store(t, Ordering::SeqCst);
    }

    /// An ESP note the mint has issued for `service` and `day`, handed over as a
    /// customer would. The mint's own key signs it, as a real exchange would, and
    /// the issue is booked in the mint's ledger (see [`book_issued`]), so the
    /// mint's counters, ledger and `/audit` agree about it.
    pub fn handed(&self, service: &ServiceDid, units: u64, day: u64) -> HandedNote {
        let terms = Terms {
            service: *service,
            redeemable_after_day: day,
        };
        let keypair = Keypair::new(SECP256K1, &mut OsRng);
        let nonce = Nonce(keypair.public_key());
        let (blind_point, blinding_key) = bdhke::blind_message(&nonce.as_hash_preimage(), None);
        let amount = Amount::from_units(units);
        let sk = self.state.master.key_for(amount, &terms);
        let outcome = self
            .state
            .logic
            .lock()
            .unwrap()
            .issue_with_key(
                &sk,
                &MintOutput {
                    amount,
                    blind_nonce: BlindNonce(blind_point),
                },
            )
            .unwrap();
        let signature =
            bdhke::unblind_message(&outcome.0, &blinding_key, &sk.public_key(SECP256K1));
        book_issued(&self.state, &self.keyset, *service, day, units);
        HandedNote {
            amount: units,
            note: Note { nonce, signature },
            spend_secret: keypair.secret_key(),
            keyset: self.keyset.clone(),
        }
    }

    /// Whether the mint has the note as spent in either live generation.
    pub fn is_spent(&self, note: &Note) -> bool {
        let logic = self.state.logic.lock().unwrap();
        let rotor = self.state.rotor.lock().unwrap();
        rotor.gens(&logic).is_spent(note.nonce).unwrap()
    }
}

/// Book in the ESP mint's ledger an ESP note a test signed straight from the mint
/// (`issue_with_key`), the way an exchange books the outputs it signs: the entry
/// is put, then finished with its movements, in one write.
///
/// Why the note is booked at all: the tests need notes of chosen amounts on
/// chosen days, which an exchange (exact, at least 10^11 units) cannot give, so
/// they sign the note themselves. A note signed past the ledger leaves the mint's
/// counters saying the ESP is outstanding and its ledger saying it is not, so
/// its `/audit` and a redemption of the note would disagree with what was
/// issued. Booking it makes the mint look as it does after a real exchange. This
/// is esp-mint's own `tests/common::record_issued` (and fsp-mint's copy of it),
/// copied: a test cannot share a helper across crates without putting test-only
/// code in the library.
fn book_issued(state: &EspState, keyset: &str, service: ServiceDid, day: u64, units: u64) {
    static BOOKED: AtomicU64 = AtomicU64::new(0);
    let hash = format!("fixture-issue-{}", BOOKED.fetch_add(1, Ordering::Relaxed));
    let mut movements = Movements::new();
    movements.issue(day, u128::from(units));
    let mut responses = state.responses.lock().unwrap();
    responses
        .put(
            &hash,
            Entry::Pending {
                redeemable_after_day: day,
                inputs: vec![],
                outputs: vec![],
            },
        )
        .unwrap();
    responses
        .finish(
            &hash,
            Entry::Done(ExchangeResponse {
                keyset: keyset.to_string(),
                service,
                redeemable_after_day: day,
                signatures: vec![],
                keys: vec![],
                fee_per_byte: 0,
                fee_esp: 0,
                size_bytes: 0,
            }),
            &movements,
        )
        .unwrap();
}

/// The PSP side of an ESP mint that never exchanges PSP: every call is refused.
pub struct NoPsp;

impl Psp for NoPsp {
    fn melt(&self, _: &[MintInput], _: &str) -> Result<Amount, String> {
        Err("this test does not use the PSP".into())
    }

    fn burns(&self, _: &[Nonce]) -> Result<Vec<Burn>, String> {
        Err("this test does not use the PSP".into())
    }
}
