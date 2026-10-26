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
use sp_wire::psp::{HandedPspNote, PspHandover};
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

/// A service key file in `dir` holding `text`, with this Unix mode. Returns its path.
fn key_file_in(dir: &Path, name: &str, text: &str, mode: u32) -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path.to_str().unwrap().to_string()
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
    w.build_psp_payload(&sp_wire::seal::SecretKey::new().public_key())
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
    for command in ["send-psp", "sent"] {
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
fn buy_psp_refuses_a_missing_or_bad_key_an_amount_and_the_removed_flags() {
    let dir = scratch("buy");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    let key = mint_key_hex();
    refused(
        &wallet,
        &before,
        &["buy-psp"],
        &["--mint-key HEX is required"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", "not-a-key"],
        &["not a public key"],
    );
    // the payload names no amount, so an amount is refused, with what replaced it
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "4"],
        &[
            "buy-psp takes no AMOUNT any more",
            "the PSP mint decides what the payment is worth",
        ],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "four"],
        &["buy-psp: unexpected argument `four`"],
    );
    // `--sync` is gone: the payload names no keyset, so there is nothing to sync
    refused(
        &wallet,
        &before,
        &["buy-psp", "--sync", "--mint-key", &key],
        &["--sync was removed", "claim-psp"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--sync", "--mint-key", "not-a-key"],
        &["--sync was removed"],
    );
    refused(
        &wallet,
        &before,
        &["buy-psp", "--mint-key", &key, "--reply-did", "02ab"],
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
    let key_file = key_file_in(&dir, "service_key.hex", &"11".repeat(32), 0o600);
    let key_file = key_file.as_str();
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
        &["--service-key-file FILE is required"],
    );
    // The old flag is gone: nothing reads a key typed on the command line.
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key", &"11".repeat(32)],
        &["--service-key-file FILE is required"],
    );
    let missing = dir.join("no-such-key.hex");
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key-file", missing.to_str().unwrap()],
        &["cannot read the service key file"],
    );
    let not_hex = key_file_in(&dir, "not-hex.hex", "zz", 0o600);
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key-file", &not_hex],
        &["must hold hex"],
    );
    let short = key_file_in(&dir, "short.hex", &"11".repeat(16), 0o600);
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key-file", &short],
        &["must hold a 32 byte secret key (64 hex characters)"],
    );
    // A key file that group or others can read is refused, and the message says
    // why and how to fix it, even though the key in it is fine.
    let open_file = key_file_in(&dir, "readable.hex", &"11".repeat(32), 0o644);
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key-file", &open_file, "--memo", "m"],
        &["can be read by group or others (mode 644)", "chmod 600"],
    );
    refused(
        &wallet,
        &before,
        &["redeem", "--service-key-file", key_file],
        &["--memo TEXT (where the payout goes) is required"],
    );
    refused(
        &wallet,
        &before,
        &[
            "redeem",
            "--service-key-file",
            key_file,
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
        vec!["redeem", "--service-key-file", key_file, "--memo", "m"],
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

/// A DID key file that group or others can read is refused before it is read,
/// as the service key file is, and before any network; an owner-only file is
/// read (here it holds no key, which is the next refusal).
#[test]
fn a_did_key_file_others_can_read_is_refused_before_it_is_read() {
    let dir = scratch("did-key-file");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    let service = ServiceDid::from(Keypair::new(SECP256K1, &mut OsRng).public_key()).to_string();
    let fsp = format!("{service}:1");
    let open_file = key_file_in(&dir, "did-open.hex", &"11".repeat(32), 0o644);
    refused(
        &wallet,
        &before,
        &[
            "handoff",
            "export-fsp",
            "--fsp",
            &fsp,
            "--did-key-file",
            &open_file,
        ],
        &[
            &format!("the DID key file {open_file} can be read by group or others (mode 644)"),
            &format!("chmod 600 {open_file}"),
        ],
    );
    let not_hex = key_file_in(&dir, "did-not-hex.hex", "not hex", 0o600);
    refused(
        &wallet,
        &before,
        &[
            "handoff",
            "export-fsp",
            "--fsp",
            &fsp,
            "--did-key-file",
            &not_hex,
        ],
        &[&format!("{not_hex}: a DID secret key is 64 hex characters")],
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

/// What `buy-psp` says about the size of a purchase, written out: a change to the
/// words is a change to this line.
const RECOMMENDATION: &str = "We recommend a PSP purchase of at least $5 (50 PSP): the PSP mint's fees come out of what a payment buys, so a smaller payment can buy little or nothing. This is a recommendation; nothing enforces it.";

/// What `buy-psp` says about paying the payload, written out.
const PAY_ONCE_TEXT: &str = "Pay this payload once. Each purchase has a key of its own so the PSP mint cannot link your purchases; a second payment to the same payload is still owed to you and claimed with the first, but it links the two.";

#[test]
fn buy_psp_says_pay_once_and_recommends_five_dollars_and_nothing_enforces_it() {
    let dir = scratch("buy-warning");
    // no wallet file yet: nothing is waiting, so nothing is asked of the network
    let wallet = dir.join("wallet.json");
    let key = mint_key_hex();
    let r = run(&wallet, &["buy-psp", "--mint-key", &key]);
    assert!(r.ok, "{}", r.stderr);
    let w = Wallet::open(&wallet, NETWORK).unwrap();
    let [purchase] = w.claim_keys() else {
        panic!("one purchase was saved");
    };
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
    // The lines, in order: the purchase, pay once, the bytes, the recommendation.
    let bytes = format!(
        "{} bytes. Put the hex below in an OP_RETURN of a Bitcoin payment to the PSP mint's wallet. Once the payment has its confirmations the PSP mint writes what you are owed over AIR: `claim-psp` reads it and claims your notes, and any command does so when it starts. Each payment's record must be claimed within 30 days of the PSP mint writing it.",
        hex_out.len() / 2
    );
    let lines: Vec<&str> = r.stderr.lines().collect();
    let at = |line: &str| lines.iter().position(|l| *l == line);
    let id = at(&format!("purchase {}", purchase.id));
    assert!(id.is_some(), "{}", r.stderr);
    assert_eq!(at(PAY_ONCE_TEXT), id.map(|i| i + 1), "{}", r.stderr);
    assert_eq!(at(&bytes), id.map(|i| i + 2), "{}", r.stderr);
    assert_eq!(at(RECOMMENDATION), id.map(|i| i + 3), "{}", r.stderr);
    // the claim key's secret is never printed
    assert!(
        !r.stderr.contains(&purchase.claim_secret) && !r.stdout.contains(&purchase.claim_secret)
    );

    // There is no minimum: a second purchase is built the same way, whatever the
    // settings were (the setting that set one is gone).
    let r = run(&wallet, &["buy-psp", "--mint-key", &key]);
    assert!(r.ok, "{}", r.stderr);
    assert!(
        r.stderr.lines().any(|l| l == RECOMMENDATION),
        "{}",
        r.stderr
    );
    let w = Wallet::open(&wallet, NETWORK).unwrap();
    assert_eq!(w.claim_keys().len(), 2);
    assert_ne!(w.claim_keys()[0].claim_did, w.claim_keys()[1].claim_did);
}

/// The words that refuse `psp.min_purchase`, written out.
const MIN_PURCHASE_REMOVED: &str = "psp.min_purchase was removed in ecash-wallet 0.8.0: buy-psp takes no amounts, so there is no purchase size to check. We recommend a PSP purchase of at least $5 (50 PSP): the PSP mint's fees come out of what a payment buys, so a smaller payment can buy little or nothing. Nothing enforces it. Remove it";

#[test]
fn the_removed_psp_min_purchase_is_refused_with_the_removed_message() {
    let dir = scratch("min-purchase-removed");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    // whatever the value was, it is refused: it is not read as a number
    for value in ["20", "0", "many"] {
        refused_env(
            &wallet,
            &before,
            &[("ECASH_PSP_MIN_PURCHASE", value)],
            &["balance"],
            &[
                "settings:",
                "environment variable ECASH_PSP_MIN_PURCHASE: ",
                MIN_PURCHASE_REMOVED,
            ],
        );
    }
    let config = dir.join("config.toml");
    let path = config.to_string_lossy().to_string();
    std::fs::write(&config, "[psp]\nmin_purchase = 64\n").unwrap();
    refused(
        &wallet,
        &before,
        &["--config", &path, "balance"],
        &["settings:", MIN_PURCHASE_REMOVED],
    );
    // another key in the section is still just unknown
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
        r.stderr.contains(
            "psp: 1 purchase(s) are held, and the PSP mint's records for them are not checked"
        ),
        "{}",
        r.stderr
    );

    // Every command checks its own arguments before the start-up steps: its error
    // is the first thing on stderr, and the wallet is as it was.
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec!["buy-psp", "--mint-key", &key, "32"],
            "buy-psp takes no AMOUNT any more",
        ),
        (
            vec!["buy-psp", "--mint-key", &key, "four"],
            "buy-psp: unexpected argument `four`",
        ),
        (
            vec!["buy-psp", "--sync", "--mint-key", &key],
            "--sync was removed",
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
        (vec!["redeem"], "--service-key-file FILE is required"),
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

/// A PSP hand-over file with one note of 4 PSP, as psp-mint writes it. The
/// note's spend secret is its nonce's unless `forged`.
fn psp_file(dir: &Path, name: &str, forged: bool) -> PathBuf {
    let kp = Keypair::new(SECP256K1, &mut OsRng);
    let file = PspHandover {
        notes: vec![HandedPspNote {
            amount: 4,
            note: Note {
                nonce: Nonce(kp.public_key()),
                signature: Keypair::new(SECP256K1, &mut OsRng).public_key(),
            },
            spend_secret: if forged {
                Keypair::new(SECP256K1, &mut OsRng).secret_key()
            } else {
                kp.secret_key()
            },
            keyset: "ab".repeat(8),
        }],
    };
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    path
}

#[test]
fn receive_psp_refuses_a_missing_a_bad_and_a_forged_file_before_any_mint_is_asked() {
    let dir = scratch("receive-psp");
    let wallet = wallet_with_notes(&dir);
    let before = std::fs::read(&wallet).ok();
    refused(
        &wallet,
        &before,
        &["receive-psp"],
        &["receive-psp takes one file"],
    );
    let missing = dir.join("none.json");
    refused(
        &wallet,
        &before,
        &["receive-psp", missing.to_str().unwrap()],
        &["No such file"],
    );
    let junk = dir.join("junk.json");
    std::fs::write(&junk, "{}").unwrap();
    refused(
        &wallet,
        &before,
        &["receive-psp", junk.to_str().unwrap()],
        &["junk.json: not a PSP hand-over file"],
    );
    let forged = psp_file(&dir, "forged.json", true);
    refused(
        &wallet,
        &before,
        &["receive-psp", forged.to_str().unwrap()],
        &[
            "forged.json: note 1 of the PSP hand-over file has a spend secret that is not the one for its nonce",
            "Nothing was added",
        ],
    );
}

#[test]
fn version_names_the_wallet_and_its_libraries_and_reads_and_writes_nothing() {
    let dir = scratch("version");
    let wallet = dir.join("wallet.json");
    let long = run(&wallet, &["--version"]);
    let short = run(&wallet, &["-V"]);
    assert!(long.ok && short.ok, "{} {}", long.stderr, short.stderr);
    assert_eq!(long.stdout, short.stdout);
    assert_eq!(long.stderr, "");
    let lines: Vec<&str> = long.stdout.lines().collect();
    assert_eq!(
        lines[0],
        format!("ecash-wallet {}", env!("CARGO_PKG_VERSION"))
    );
    for line in &lines[1..] {
        let (name, version) = line.split_once(' ').expect(line);
        assert!(
            !name.is_empty() && version.split('.').count() == 3,
            "{line}"
        );
    }
    assert!(
        lines.iter().any(|l| l.starts_with("sp-wire ")),
        "no sp-wire line in {lines:?}"
    );
    assert!(!wallet.exists(), "--version made a wallet file");
}
