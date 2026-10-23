//! The command line, as a person at a keyboard meets it when they get a command
//! wrong. Each test runs the real binary with an empty environment (so nothing of
//! the machine's own settings leaks in), on a wallet file of its own, and checks
//! three things: the exit status is a failure, stderr says what was wrong in the
//! words the command uses, and the wallet file is exactly as it was (or was
//! never created). None of them needs a mint or a network.
//!
//! The wallet files are made with the library (`Wallet::open`, `receive_handover`),
//! not written by hand.

use ecash_wallet::Wallet;
use ecash_wallet::store::{HandedNote, Handover};
use mint_types::{Nonce, Note};
use rand::rngs::OsRng;
use secp256k1::{Keypair, SECP256K1};
use sp_wire::ServiceDid;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The network every run here is on (`--regtest`), and so the one the wallet
/// files are made for.
const NETWORK: &str = "regtest";

fn scratch(name: &str) -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "wallet-cli-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What one run of the command printed and how it ended.
struct Ran {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Run the binary on `wallet` on regtest with `args`, and nothing else in its
/// environment.
fn run(wallet: &Path, args: &[&str]) -> Ran {
    run_env(wallet, &[], args)
}

/// As [`run`], with these environment variables set (settings, say).
fn run_env(wallet: &Path, envs: &[(&str, &str)], args: &[&str]) -> Ran {
    let out = Command::new(env!("CARGO_BIN_EXE_ecash-wallet"))
        .env_clear()
        .env("ECASH_WALLET_FILE", wallet)
        .envs(envs.iter().copied())
        .arg("--regtest")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Ran {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// The command fails with an `error: ` message containing every part of `says`,
/// and the wallet file is as `before` (`None`: there is no file).
fn refused(wallet: &Path, before: &Option<Vec<u8>>, args: &[&str], says: &[&str]) {
    refused_env(wallet, before, &[], args, says);
}

/// As [`refused`], with these environment variables set.
fn refused_env(
    wallet: &Path,
    before: &Option<Vec<u8>>,
    envs: &[(&str, &str)],
    args: &[&str],
    says: &[&str],
) {
    let r = run_env(wallet, envs, args);
    assert!(!r.ok, "{args:?} went through: {}", r.stderr);
    // The command's own error is the last thing it says; start-up notes come before.
    let Some(at) = r.stderr.find("error: ") else {
        panic!("{args:?}: no `error: ` line in: {}", r.stderr);
    };
    let error = &r.stderr[at..];
    for part in says {
        assert!(
            error.contains(part),
            "{args:?}: expected `{part}` in: {error}"
        );
    }
    assert_eq!(
        &std::fs::read(wallet).ok(),
        before,
        "{args:?} changed the wallet"
    );
}

/// A wallet file that holds two ESP notes (made by the library) for [`NETWORK`].
fn wallet_with_notes(dir: &Path) -> PathBuf {
    let path = dir.join("wallet.json");
    notes_wallet(&path, NETWORK);
    path
}

/// A wallet file at `path` for `network` that holds two ESP notes (made by the
/// library).
fn notes_wallet(path: &Path, network: &str) {
    let mut w = Wallet::open(path, network).unwrap();
    let notes = (0..2)
        .map(|_| {
            let kp = Keypair::new(SECP256K1, &mut OsRng);
            HandedNote {
                amount: 4,
                note: Note {
                    nonce: Nonce(kp.public_key()),
                    signature: Keypair::new(SECP256K1, &mut OsRng).public_key(),
                },
                spend_secret: kp.secret_key(),
                keyset: "ab".repeat(8),
            }
        })
        .collect();
    let handover = Handover {
        service: sp_wire::ServiceDid::from(Keypair::new(SECP256K1, &mut OsRng).public_key()),
        redeemable_after_day: 100,
        notes,
    };
    w.receive_handover(&handover).unwrap();
    assert!(path.exists(), "the library saved the wallet");
}

/// As [`wallet_with_notes`], with a PSP purchase that waits for its delivery
/// (built by the library). A command that gets as far as its start-up steps says
/// so on stderr, because this wallet has no AIR settings; a command that is
/// refused for its arguments says nothing before its error.
fn wallet_with_waiting_purchase(dir: &Path) -> PathBuf {
    let path = wallet_with_notes(dir);
    let mut w = Wallet::open(&path, NETWORK).unwrap();
    w.build_psp_payload(&[32, 16, 2], &sp_wire::seal::SecretKey::new().public_key())
        .unwrap();
    path
}

fn mint_key_hex() -> String {
    hex::encode(Keypair::new(SECP256K1, &mut OsRng).public_key().serialize())
}

#[test]
fn the_removed_commands_say_what_replaced_them() {
    let dir = scratch("removed");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    for command in ["send-psp", "receive-psp", "sent"] {
        refused(
            &wallet,
            &before,
            &[command],
            &[
                &format!("`{command}` was removed"),
                "handoff export-psp",
                "handoff import",
                "handoff check",
                "handoff reclaim",
            ],
        );
    }
}

#[test]
fn buy_psp_refuses_a_missing_or_bad_key_a_bad_amount_and_the_removed_flag() {
    let dir = scratch("buy");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    let key = mint_key_hex();
    refused(
        &wallet,
        &before,
        &["buy-psp", "4"],
        &["--mint-key HEX is required"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", "not-a-key", "4"],
        &["not a public key"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "four"],
        &["an amount must be a whole number, got `four`"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "0"],
        &["0 is not a PSP note size: use a power of two"],
    );
    // `--sync` asks the PSP over AIR, but only after every flag has been read:
    // these are refused for their own faults, not for the missing AIR settings.
    refused(
        &wallet,
        &before,
        &["buy-psp", "--sync", "--mint-key", "not-a-key", "4"],
        &["not a public key"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--sync", "--mint-key", &key],
        &["a purchase needs at least one output"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--sync", "--mint-key", &key, "0"],
        &["0 is not a PSP note size: use a power of two"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "--reply-did", "02ab", "4"],
        &["--reply-did was removed", "claim-psp"],
    );
}

#[test]
fn claim_psp_refuses_signatures_and_a_bad_wait() {
    let dir = scratch("claim");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    refused(
        &wallet,
        &before,
        &["claim-psp", "--file", "sigs.txt"],
        &["claim-psp takes no signatures any more"],
    );
    refused(
        &wallet,
        &before,
        &["claim-psp", "02aa", "03bb"],
        &["claim-psp takes no signatures any more"],
    );
    refused(
        &wallet,
        &before,
        &["claim-psp", "--wait", "abc"],
        &["--wait must be a whole number, got `abc`"],
    );
}

#[test]
fn receive_balance_exchange_redeem_and_fsp_refuse_bad_arguments_before_any_network() {
    let dir = scratch("args");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    let receive = "receive takes one file: ecash-wallet receive FILE";
    refused(&wallet, &before, &["receive"], &[receive]);
    refused(
        &wallet,
        &before,
        &["receive", "a.json", "b.json"],
        &[receive],
    );
    let not_a_handover = dir.join("other.json");
    std::fs::write(&not_a_handover, r#"{"hello": 1}"#).unwrap();
    let path = not_a_handover.to_string_lossy().to_string();
    refused(
        &wallet,
        &before,
        &["receive", &path],
        &[&format!(
            "{path}: not a hand-over file: missing field `service`"
        )],
    );
    // The files that fsp-mint writes, made with the real type, that sp-wire's
    // reader refuses: a note without a keyset (an empty one) and no notes at all.
    let service = ServiceDid::from(Keypair::new(SECP256K1, &mut OsRng).public_key());
    let note_without_keyset = {
        let kp = Keypair::new(SECP256K1, &mut OsRng);
        HandedNote {
            amount: 4,
            note: Note {
                nonce: Nonce(kp.public_key()),
                signature: Keypair::new(SECP256K1, &mut OsRng).public_key(),
            },
            spend_secret: kp.secret_key(),
            keyset: String::new(),
        }
    };
    for (name, notes, says) in [
        (
            "blank-keyset.json",
            vec![note_without_keyset],
            "note 1 of the hand-over file names no keyset (its keyset is empty)",
        ),
        ("no-notes.json", vec![], "the hand-over file holds no notes"),
    ] {
        let file = dir.join(name);
        let handover = Handover {
            service,
            redeemable_after_day: 100,
            notes,
        };
        std::fs::write(&file, serde_json::to_vec(&handover).unwrap()).unwrap();
        let path = file.to_string_lossy().to_string();
        refused(
            &wallet,
            &before,
            &["receive", &path],
            &[&format!("{path}: {says}")],
        );
    }
    refused(
        &wallet,
        &before,
        &["balance", "--verbose"],
        &[
            "balance: unexpected argument `--verbose`",
            "ecash-wallet balance",
        ],
    );

    // `exchange` and `redeem` read their own flags before the ESP is asked
    // anything. This wallet has no AIR settings, so a command that got as far as
    // the ESP would say "air.server and air.host are not set"; none of these does.
    let service = ServiceDid::from(Keypair::new(SECP256K1, &mut OsRng).public_key()).to_hex();
    let key = "11".repeat(32);
    refused(
        &wallet,
        &before,
        &["exchange"],
        &["--service DID is required"],
    );
    refused(
        &wallet,
        &before,
        &["exchange", "--service", &service],
        &["--psp N is required"],
    );
    refused(
        &wallet,
        &before,
        &["exchange", "--service", &service, "--psp", "four"],
        &["--psp must be a whole number, got `four`"],
    );
    refused(
        &wallet,
        &before,
        &[
            "exchange",
            "--service",
            &service,
            "--psp",
            "4",
            "--amounts",
            "2,x",
        ],
        &["an amount must be a whole number, got `x`"],
    );
    refused(
        &wallet,
        &before,
        &["exchange", "--service", &service, "--psp", "4", "extra"],
        &[
            "exchange: unexpected argument `extra`",
            "ecash-wallet exchange --service DID --psp N",
        ],
    );
    refused(
        &wallet,
        &before,
        &["exchange", "--resume", "nope"],
        &["no pending exchange nope"],
    );
    refused(
        &wallet,
        &before,
        &["redeem"],
        &["--service-key HEX is required"],
    );
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key", "zz"],
        &["the service key must be hex"],
    );
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key", &key],
        &["--memo TEXT (where the payout goes) is required"],
    );
    refused(
        &wallet,
        &before,
        &[
            "redeem",
            "--service-key",
            &key,
            "--memo",
            "m",
            "--max-bytes",
            "lots",
        ],
        &["--max-bytes must be a whole number, got `lots`"],
    );
    refused(
        &wallet,
        &before,
        &["redeem", "--collect", "extra"],
        &["redeem: unexpected argument `extra`", "ecash-wallet redeem"],
    );
    // The same commands with every flag right do reach the ESP, and with no AIR
    // settings it is the missing setting that is named.
    for args in [
        vec!["exchange", "--service", &service, "--psp", "4"],
        vec!["redeem", "--service-key", &key, "--memo", "m"],
    ] {
        refused(
            &wallet,
            &before,
            &args,
            &["air.server and air.host are not set"],
        );
    }

    // The fsp commands do the same before the service's mint is asked.
    refused(
        &wallet,
        &before,
        &[
            "fsp",
            "issue",
            "--service",
            &service,
            "--esp",
            "1",
            "--psp",
            "1",
        ],
        &["give --esp or --psp, not both"],
    );
    refused(
        &wallet,
        &before,
        &["fsp", "pay", "--service", &service],
        &["--units N is needed"],
    );
    refused(
        &wallet,
        &before,
        &["fsp", "pay", "--service", &service, "--units", "many"],
        &["--units must be a whole number, got `many`"],
    );
    refused(
        &wallet,
        &before,
        &["fsp", "sync", "--service", &service, "extra"],
        &[
            "fsp sync: unexpected argument `extra`",
            "ecash-wallet fsp sync --service DID",
        ],
    );
    refused(
        &wallet,
        &before,
        &["fsp", "frobnicate", "--service", &service],
        &["unknown fsp command `frobnicate`"],
    );
}

#[test]
fn handoff_refuses_a_missing_part_and_explains_the_old_export() {
    let dir = scratch("handoff");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    refused(
        &wallet,
        &before,
        &["handoff"],
        &[
            "handoff needs export-psp, export-fsp, import, check, reclaim, list, cancel or done",
            "Run with --help",
        ],
    );
    refused(
        &wallet,
        &before,
        &["handoff", "export"],
        &[
            "`handoff export` was split in two",
            "handoff export-psp",
            "handoff export-fsp",
        ],
    );
    refused(
        &wallet,
        &before,
        &["handoff", "export-psp", "--psp", "4"],
        &["a PSP handoff is sealed to the recipient", "--to"],
    );
    refused(
        &wallet,
        &before,
        &["handoff", "check"],
        &["handoff check takes one handoff ID: ecash-wallet handoff check ID"],
    );
    refused(
        &wallet,
        &before,
        &["handoff", "reclaim"],
        &["handoff reclaim takes one handoff ID: ecash-wallet handoff reclaim ID"],
    );
    refused(
        &wallet,
        &before,
        &["handoff", "frobnicate"],
        &["unknown handoff command `frobnicate`"],
    );
}

#[test]
fn merge_refuses_a_damaged_file_and_leaves_the_wallet_alone() {
    let dir = scratch("merge");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    let good = std::fs::read_to_string(&wallet).unwrap();
    let damaged = dir.join("other.json");
    // A copy cut off halfway through.
    std::fs::write(&damaged, &good[..good.len() / 2]).unwrap();
    let path = damaged.to_string_lossy().to_string();
    refused(
        &wallet,
        &before,
        &["merge", &path],
        &["wallet file is not valid", &path],
    );
    // A file that is not there.
    let missing = dir.join("missing.json").to_string_lossy().to_string();
    refused(&wallet, &before, &["merge", &missing], &["wallet file:"]);
    refused(
        &wallet,
        &before,
        &["merge"],
        &["merge takes one wallet file: ecash-wallet merge FILE"],
    );
}

#[test]
fn a_bad_config_file_is_refused_naming_the_setting_and_the_file() {
    let dir = scratch("config");
    let wallet = dir.join("wallet.json");
    let config = dir.join("bad.toml");
    let path = config.to_string_lossy().to_string();
    std::fs::write(&config, "[air]\nbogus = \"x\"\n").unwrap();
    refused(
        &wallet,
        &None,
        &["--config", &path, "balance"],
        &["settings:", &path, "unknown setting `air.bogus`"],
    );
    std::fs::write(&config, "[air\nserver = ").unwrap();
    refused(
        &wallet,
        &None,
        &["--config", &path, "balance"],
        &["settings:", &path, "not valid TOML"],
    );
    let missing = dir.join("missing.toml").to_string_lossy().to_string();
    refused(
        &wallet,
        &None,
        &["--config", &missing, "balance"],
        &["cannot read config file", &missing],
    );
}

#[test]
fn an_unknown_command_and_two_network_flags_are_refused() {
    let dir = scratch("unknown");
    let wallet = dir.join("wallet.json");
    refused(
        &wallet,
        &None,
        &["frobnicate"],
        &["unknown command `frobnicate`", "Run with --help"],
    );
    refused(
        &wallet,
        &None,
        &["--signet", "balance"],
        &["give at most one of --mainnet, --regtest, --signet, --testnet"],
    );
}

#[test]
fn a_wallet_file_of_another_network_or_with_no_network_is_refused_and_left_alone() {
    let dir = scratch("network");

    // A file made for signet, on a run for regtest: the message names both, for
    // a command that opens the wallet and for a merge of it into a regtest wallet.
    let signet = dir.join("signet.json");
    notes_wallet(&signet, "signet");
    let signet_path = signet.to_string_lossy().to_string();
    let before = std::fs::read(&signet).ok();
    let other = [
        signet_path.as_str(),
        "this wallet file is for the signet network, but it was opened for the regtest network",
        "Nothing was changed",
    ];
    refused(&signet, &before, &["balance"], &other);

    let regtest = wallet_with_notes(&dir);
    let regtest_before = std::fs::read(&regtest).ok();
    refused(
        &regtest,
        &regtest_before,
        &["merge", &signet_path],
        &[
            "the copy to merge is a wallet of the signet network, but this wallet is on the regtest network",
            "Nothing was merged",
        ],
    );

    // A file with no network (written by a pre-release version: the real file,
    // with the field taken out): refused, with what to do, on a command and as
    // the copy to merge.
    let old = dir.join("old.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&regtest).unwrap()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("network")
        .expect("the wallet file records its network");
    std::fs::write(&old, serde_json::to_vec(&value).unwrap()).unwrap();
    let old_path = old.to_string_lossy().to_string();
    let old_before = std::fs::read(&old).ok();
    let no_network = [
        old_path.as_str(),
        "it records no network",
        "pre-release version",
        "Start a new wallet file, or merge from a backup written by this version",
    ];
    refused(&old, &old_before, &["balance"], &no_network);
    refused(
        &regtest,
        &regtest_before,
        &["merge", &old_path],
        &no_network,
    );
}

#[test]
fn buy_psp_below_the_minimum_is_refused_naming_the_setting_before_any_network() {
    let dir = scratch("buy-minimum");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    let key = mint_key_hex();
    let below = [
        "buy-psp: a purchase of 49 PSP is below the minimum of 50 PSP",
        "psp.min_purchase",
        "ECASH_PSP_MIN_PURCHASE",
        "100 PSP is a realistic purchase",
    ];
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "32", "16", "1"],
        &below,
    );
    // the total is what counts, however it is split
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "16", "16", "16", "1"],
        &below,
    );
    // `--sync` asks the PSP, but only after the amounts have been checked: this
    // wallet has no AIR settings, and it is the minimum that is named
    refused(
        &wallet,
        &before,
        &["buy-psp", "--sync", "--mint-key", &key, "32", "16", "1"],
        &below,
    );
    // a higher setting moves the line
    refused_env(
        &wallet,
        &before,
        &[("ECASH_PSP_MIN_PURCHASE", "60")],
        &["buy-psp", "--mint-key", &key, "32", "16", "2"],
        &[
            "a purchase of 50 PSP is below the minimum of 60 PSP",
            "psp.min_purchase",
        ],
    );
    // and so does one in the config file
    let config = dir.join("config.toml");
    std::fs::write(&config, "[psp]\nmin_purchase = 64\n").unwrap();
    let path = config.to_string_lossy().to_string();
    refused(
        &wallet,
        &before,
        &[
            "--config",
            &path,
            "buy-psp",
            "--mint-key",
            &key,
            "32",
            "16",
            "2",
        ],
        &["a purchase of 50 PSP is below the minimum of 64 PSP"],
    );
}

#[test]
fn buy_psp_prints_the_one_time_use_warning_with_the_purchase_id_and_the_hex() {
    let dir = scratch("buy-warning");
    // no wallet file yet: nothing is waiting, so nothing is asked of the network
    let wallet = dir.join("wallet.json");
    let key = mint_key_hex();
    let r = run(&wallet, &["buy-psp", "--mint-key", &key, "32", "16", "2"]);
    assert!(r.ok, "{}", r.stderr);
    let warning = ecash_wallet::psp::ONE_TIME_USE;
    assert!(r.stderr.contains(warning), "{}", r.stderr);
    // the purchase's id is said, then the warning, then the payload on stdout
    let w = Wallet::open(&wallet, NETWORK).unwrap();
    let [purchase] = w.pending_purchases() else {
        panic!("one purchase was saved");
    };
    let id_at = r.stderr.find(&format!("purchase {}", purchase.id));
    let warning_at = r.stderr.find(warning);
    assert!(id_at.is_some() && id_at < warning_at, "{}", r.stderr);
    let hex_out = r.stdout.trim();
    assert!(
        !hex_out.is_empty() && hex::decode(hex_out).is_ok(),
        "{hex_out}"
    );
    assert_eq!(
        r.stdout.lines().count(),
        1,
        "standard output holds the hex and nothing else"
    );

    // a lower setting is honoured: 4 PSP is a purchase when the minimum is 4
    let r = run_env(
        &wallet,
        &[("ECASH_PSP_MIN_PURCHASE", "4")],
        &["buy-psp", "--mint-key", &key, "4"],
    );
    assert!(r.ok, "{}", r.stderr);
    assert!(r.stderr.contains(warning), "{}", r.stderr);
    assert_eq!(
        Wallet::open(&wallet, NETWORK)
            .unwrap()
            .pending_purchases()
            .len(),
        2
    );
    // and 3 is not
    let before = std::fs::read(&wallet).ok();
    refused_env(
        &wallet,
        &before,
        &[("ECASH_PSP_MIN_PURCHASE", "4")],
        &["buy-psp", "--mint-key", &key, "2", "1"],
        &["a purchase of 3 PSP is below the minimum of 4 PSP"],
    );
}

#[test]
fn a_bad_psp_min_purchase_is_refused_by_the_settings_naming_it() {
    let dir = scratch("min-purchase-bad");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    for bad in ["0", "-5", "many", "1.5"] {
        refused_env(
            &wallet,
            &before,
            &[("ECASH_PSP_MIN_PURCHASE", bad)],
            &["balance"],
            &[
                "settings:",
                "ECASH_PSP_MIN_PURCHASE",
                "psp.min_purchase",
                "must be a whole number from 1 to",
            ],
        );
    }
    let config = dir.join("config.toml");
    let path = config.to_string_lossy().to_string();
    std::fs::write(&config, "[psp]\nmin_purchase = 0\n").unwrap();
    refused(
        &wallet,
        &before,
        &["--config", &path, "balance"],
        &[
            "settings:",
            "psp.min_purchase",
            "must be a whole number from 1 to",
        ],
    );
    std::fs::write(&config, "[psp]\nminimum = 5\n").unwrap();
    refused(
        &wallet,
        &before,
        &["--config", &path, "balance"],
        &["unknown setting `psp.minimum`"],
    );
}

#[test]
fn a_usage_error_is_said_first_with_nothing_asked_of_the_network_before_it() {
    let dir = scratch("usage-first");
    let wallet = wallet_with_waiting_purchase(&dir);
    let before = std::fs::read(&wallet).ok();
    let key = mint_key_hex();
    let service = ServiceDid::from(Keypair::new(SECP256K1, &mut OsRng).public_key()).to_hex();

    // A command that gets through its arguments runs the start-up steps, and this
    // wallet has a purchase waiting for the PSP, so it says so first.
    let r = run(&wallet, &["balance"]);
    assert!(r.ok, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("psp: 1 purchase(s) are waiting for the PSP's delivery"),
        "{}",
        r.stderr
    );

    // Every command checks its own arguments before the start-up steps: its error
    // is the first thing on stderr, and the wallet is as it was.
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec!["buy-psp", "--mint-key", &key, "32", "16", "1"],
            "below the minimum of 50 PSP",
        ),
        (
            vec!["buy-psp", "--mint-key", &key, "four"],
            "an amount must be a whole number, got `four`",
        ),
        (
            vec!["buy-psp", "--sync", "--mint-key", &key],
            "a purchase needs at least one output",
        ),
        (
            vec!["claim-psp", "--wait", "abc"],
            "--wait must be a whole number, got `abc`",
        ),
        (
            vec!["claim-psp", "02aa"],
            "claim-psp takes no signatures any more",
        ),
        (
            vec!["balance", "--verbose"],
            "balance: unexpected argument `--verbose`",
        ),
        (vec!["receive"], "receive takes one file"),
        (vec!["exchange"], "--service DID is required"),
        (
            vec!["exchange", "--service", &service, "--psp", "four"],
            "--psp must be a whole number, got `four`",
        ),
        (vec!["redeem"], "--service-key HEX is required"),
        (
            vec!["fsp", "pay", "--service", &service],
            "--units N is needed",
        ),
        (
            vec!["fsp", "sync", "--service", &service, "extra"],
            "fsp sync: unexpected argument `extra`",
        ),
        (vec!["handoff"], "handoff needs export-psp"),
        (
            vec!["handoff", "check"],
            "handoff check takes one handoff ID",
        ),
        (vec!["merge"], "merge takes one wallet file"),
    ];
    for (args, says) in cases {
        let r = run(&wallet, &args);
        assert!(!r.ok, "{args:?} went through: {}", r.stderr);
        assert!(
            r.stderr.starts_with("error: "),
            "{args:?}: something was said before the error: {}",
            r.stderr
        );
        assert!(r.stderr.contains(says), "{args:?}: {}", r.stderr);
        assert_eq!(
            &std::fs::read(&wallet).ok(),
            &before,
            "{args:?} changed the wallet"
        );
    }
}
