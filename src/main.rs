//! The command line. It parses arguments and prints; every step is a call into
//! the library.

use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ecash_wallet::config::{self, AirSettings};
use ecash_wallet::esp::ExchangeBuild;
use ecash_wallet::psp::parse_signatures;
use ecash_wallet::redeem::{EntryOutcome, RedeemOutcome, RedemptionState};
use ecash_wallet::store::{Handover, parse_did};
use ecash_wallet::transfer::TransferBuild;
use ecash_wallet::{Wallet, WalletError, http};
use secp256k1::SecretKey;
use sp_wire::ServiceDid;
use sp_wire::seal::SecretKey as DidSecretKey;
use sp_wire::units::ESP_PER_PSP;

const DEFAULT_PSP_URL: &str = "http://127.0.0.1:3000";
const DEFAULT_ESP_URL: &str = "http://127.0.0.1:3100";

const USAGE: &str = "\
ecash-wallet [--wallet FILE] [--config FILE] [--regtest|--signet|--testnet] <command>

  The network defaults to mainnet (--mainnet may be given; at most one network
  flag). Before talking to a mint the wallet asks
  its GET /health which network it is on and refuses if it is another.

  buy-psp --mint-key HEX [--reply-did HEX] [--psp-url URL] AMOUNT...
      Make the encrypted payload for a PSP purchase and print it as hex, for
      the OP_RETURN. AMOUNT is each note's size in PSP (a power of two). The
      payload names the PSP's current keyset, read from --psp-url (or as last
      seen), so the mint signs with it while it is live.
  claim-psp [--psp-url URL] [--file FILE|-] [BLIND_NONCE:SIGNATURE...]
      Turn the PSP's signatures into notes. Paste the PSP's output into a file,
      or pass pairs. With neither, reads standard input.
  exchange --service DID --psp N [--amounts A,B,C] [--esp-url URL] [--resume ID]
      Exchange at least N PSP for ESP bound to a service (its 33-byte AIR DID,
      66 hex characters). The smallest exchange is 1 PSP. The mint's exchange is exact, so the
      wallet spends whole PSP notes worth at least N and asks for all of their
      value: N PSP of ESP, plus any difference as extra ESP notes (change) under
      the same terms. ESP notes are powers of two: the wallet splits the amount
      (and the change) into the fewest of them. --amounts picks other sizes,
      each a power of two, adding up to the same total.
  hand-over --service DID (--esp UNITS | --psp N) [--day D] --out FILE
      Hand whole ESP notes bound to a service to that service, worth exactly
      UNITS ESP units (or N PSP). Notes cannot be split, so the wallet needs a
      set that adds up to the amount. The notes leave this wallet and are
      written, with their spend secrets, to FILE (private: keep it so). FILE is
      a development stand-in for an AIR message to the service.
  receive FILE
      As the service: take a hand-over file into this wallet.
  transfer --service-key HEX [--day D] [--amounts A,B,C] [--esp-url URL] [--resume ID]
      As the service (HEX is its 32 byte secret key): swap every free ESP note
      this wallet holds for that service and day for fresh notes only it
      controls, with the same service, the same day and the same total.
      The new notes are powers of two, the fewest that make the total.
      --amounts picks other sizes (each a power of two, same total).
      --resume sends a pending request again.
  balance
      What the wallet holds and what is waiting.
  handoff export-psp --to DID --psp N [--psp-url URL] [--out FILE]
      A PSP handoff, developer to user (after an in-app purchase): free PSP
      notes adding up to exactly N, sealed to the recipient's DID public key
      (DID, 66 hex characters), so only the holder of the matching secret key
      can open it. It carries PSP only, never a DID key. The notes leave this
      wallet, kept as a pending handoff until you reclaim, cancel or finish it.
      The string starts SPHP1:. This replaces the old send-psp token.
  handoff export-fsp --fsp SERVICE:UNITS... --did-key-file FILE [--out FILE]
      An FSP handoff, to your own new device: a little FSP (enough to pay to
      fetch your wallet from the AIR) and the DID secret key from FILE (64 hex
      characters). NOT ENCRYPTED: it holds the key it would be encrypted to.
      Anyone who sees it can spend the notes and act as your DID. Move it in
      person or by QR code, never over a network. The string starts SPHF1:.
      To show either as a QR code, pipe the output to `qrencode -t ANSIUTF8`
      (about 20 notes fit one code; see DESIGN.md).
  handoff import STRING|FILE|- [--did-key-file FILE] [--did-key-out FILE]
                 [--from NAME]
      Take a handoff in; the kind is read from its start. It is checked against
      the key sets this wallet has seen, and refused if damaged, of another
      version, or imported before. The old SPH1: handoff is refused.
      A PSP handoff (SPHP1:) needs --did-key-file, the secret key of the DID it
      was sealed to. The notes count in the balance at once and are swapped at
      the PSP mint for fresh notes only this wallet knows, now and at every
      start while the mint is out of reach (`balance` shows how much is still
      unswapped). Until the swap goes through the sender can still reclaim.
      An FSP handoff (SPHF1:) is never swapped. Its DID key is written to
      --did-key-out (required), never printed. Fetch your wallet from the AIR
      afterwards and run `merge FILE` on it.
  handoff list
      The handoffs made and taken in.
  handoff check ID
      Ask the PSP mint where a PSP handoff you made stands, from its record of
      which notes are spent: none (still yours to reclaim), all (the receiver
      has it: the handoff is done), or some (the rest can be reclaimed). Old
      send-psp tokens in a wallet file are PSP handoffs now and work here too.
  handoff reclaim ID
      Swap what is left of a PSP handoff back to this wallet at the mint, while
      the receiver has not swapped. The mint takes whichever swap reaches it
      first: if the receiver was first the handoff is recorded as done and
      nothing comes back. Run it again after a crash or a lost reply.
  handoff cancel ID | handoff done ID
      cancel puts a pending handoff's notes back without asking the mint (local
      only: if the other wallet already has the notes, the first to swap or
      spend wins; prefer reclaim for a PSP handoff); done drops the notes it
      kept once you know it was claimed.
  merge FILE
      Merge a copy of this wallet retrieved from storage (a wallet file) into
      this one: notes united, anything spent in either copy stays spent,
      pending requests merged once each. Save this wallet back to storage.
  redeem --service-key HEX --memo TEXT [--max-bytes N] [--esp-url URL]
      As the service (HEX is its 32 byte secret key): redeem every free ESP
      note for that service whose redeemable-after day has come, mixed days
      allowed, for a payout to TEXT (for example btc:ADDRESS). The fee rate and
      the ceiling on one request come from the mint's GET /fees (--max-bytes
      lowers the ceiling). A redemption over the ceiling is split into several
      requests, each with its own fee and payout entry. Shows the size and fee
      of each request before it is sent.
  redeem --service-key HEX --resume ID [--esp-url URL]
      Send a pending redemption again (after a lost reply or a fault).
  redeem --collect [--esp-url URL]
      Ask the mint about every redemption queued for payout: completed ones end,
      declined ones give the reissued notes back with the operator's reason.
  config
      Print the settings in use and where each came from: the storage policy
      (storage.wallet, the AIR services that back up the wallet, and
      storage.app, each an ordered list of service IDs, first preferred),
      from config.toml beside the wallet file (or --config FILE, or
      $ECASH_CONFIG) and $ECASH_STORAGE_WALLET and $ECASH_STORAGE_APP.
      Nothing reads or writes the AIR yet.
  fsp issue --service DID [--esp UNITS | --psp N] [--fsp-url URL]
      Hand ESP for a service to its FSP mint for FSP, 1:1 less its issue fee.
      All of the service's ESP by default, any day, mature or not.
  fsp pay --service DID --units N [--memo TEXT] [--fsp-url URL]
      Pay N FSP units to the service, with change.
  fsp sync --service DID [--fsp-url URL]
      What runs on its own: finish pending FSP requests, read the mint's keys,
      and swap FSP on the previous keyset to the current one.
  fsp-window --service DID [--fsp-url URL]
      The FSP mint's rotation schedule (GET /rotation): current and previous
      keysets with their start and retire times, and the next rotation.
  esp-schedule [--by YYYY-MM-DD]
      When this wallet's ESP is redeemable: now, by DATE, and by month.
  migrate
      Move a wallet file from before the networks had their own folders,
      ~/.ecash-wallet/wallet.json, into regtest/.

  The fsp commands always need --service: there is no default. storage.wallet
  lists the AIR services that back up the wallet; it is not the service FSP is
  paid to.

  At startup, and every time it talks to an FSP mint, the wallet checks that
  mint's keys and rolls FSP on the previous keyset over to the current one.
  It asks nothing; a failure is logged and tried again next time.

The wallet file is --wallet, else $ECASH_WALLET_FILE, else
~/.ecash-wallet/<network>/wallet.json (main, regtest, signet, testnet; an old
~/.ecash-wallet/wallet.json is refused until `ecash-wallet migrate` moves it to
regtest/). URLs default to $ECASH_PSP_URL / $ECASH_ESP_URL,
else http://127.0.0.1:3000 and http://127.0.0.1:3100.

The PSP's wire version and network (what its GET /health says), its keys
(GET /keys), its keysets (GET /keysets), its rotation window (GET /rotation) and
its rollover and check-state (POST /rollover, POST /check-state), and the ESP's
wire version and network, keysets, rotation window, fees (GET /fees), rollover,
exchange, transfer and redeem (POST /rollover, /exchange, /transfer, /redeem), are
asked over AIR instead of HTTP when config.toml's [air] section (or
ECASH_AIR_SERVER and ECASH_AIR_HOST) names an AIR server and its host. The PSP
and the ESP each have their own DID, built in (PLACEHOLDERS until the first SPI
deploy, and the wallet says so whenever one is in use); air.psp_did
(ECASH_AIR_PSP_DID) and air.esp_did (ECASH_AIR_ESP_DID) override them. Every
other call is HTTP (the ESP's /audit and the FSP's calls among them). `config`
prints every setting.";

/// The arguments left after flags are taken out.
struct Args(Vec<String>);

impl Args {
    /// Take `--name VALUE`, if present.
    fn flag(&mut self, name: &str) -> Result<Option<String>, WalletError> {
        let Some(at) = self.0.iter().position(|a| a == name) else {
            return Ok(None);
        };
        if at + 1 >= self.0.len() {
            return Err(WalletError::Invalid(format!("{name} needs a value")));
        }
        let value = self.0.remove(at + 1);
        self.0.remove(at);
        Ok(Some(value))
    }

    fn rest(self) -> Vec<String> {
        self.0
    }

    /// Fail if anything is left over.
    fn done(self) -> Result<(), WalletError> {
        match self.0.first() {
            Some(extra) => Err(WalletError::Invalid(format!(
                "unexpected argument `{extra}`"
            ))),
            None => Ok(()),
        }
    }
}

fn number(text: &str, what: &str) -> Result<u64, WalletError> {
    text.trim()
        .parse::<u64>()
        .map_err(|_| WalletError::Invalid(format!("{what} must be a whole number, got `{text}`")))
}

fn wallet_path(flag: Option<String>) -> Result<PathBuf, WalletError> {
    if let Some(path) = flag.or_else(|| env::var("ECASH_WALLET_FILE").ok()) {
        return Ok(PathBuf::from(path));
    }
    let home = env::var("HOME")
        .map_err(|_| WalletError::Invalid("HOME is not set: use --wallet FILE".into()))?;
    let base = PathBuf::from(home).join(".ecash-wallet");
    if base.join("wallet.json").exists() {
        return Err(WalletError::Invalid(format!(
            "{} is a wallet file from before each network had its own. It is a regtest wallet. Run `ecash-wallet migrate` once to move it to {} (nothing is deleted)",
            base.join("wallet.json").display(),
            base.join("regtest").join("wallet.json").display()
        )));
    }
    Ok(base.join(network()).join("wallet.json"))
}

/// Move a pre-network `~/.ecash-wallet/wallet.json` to `regtest/wallet.json`.
/// A rename; refused if the target exists.
fn migrate_wallet() -> Result<(), WalletError> {
    let home = env::var("HOME").map_err(|_| WalletError::Invalid("HOME is not set".into()))?;
    let base = PathBuf::from(home).join(".ecash-wallet");
    let (from, to) = (
        base.join("wallet.json"),
        base.join("regtest").join("wallet.json"),
    );
    if !from.exists() {
        return Err(WalletError::Invalid(format!(
            "nothing to migrate: {} does not exist",
            from.display()
        )));
    }
    if to.exists() {
        return Err(WalletError::Invalid(format!(
            "{} already exists: nothing was moved",
            to.display()
        )));
    }
    std::fs::create_dir_all(base.join("regtest"))?;
    std::fs::rename(&from, &to)?;
    println!("moved {} to {}", from.display(), to.display());
    Ok(())
}

fn url(flag: Option<String>, var: &str, default: &str) -> String {
    flag.or_else(|| env::var(var).ok())
        .unwrap_or_else(|| default.to_string())
}

/// The network this run is on: `--regtest`, `--signet` or `--testnet`, else
/// mainnet. Set once in `run`.
static NETWORK: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

fn network() -> &'static str {
    NETWORK.get().copied().unwrap_or("main")
}

/// Take the network flags out of the arguments. At most one may be given.
fn take_network(args: &mut Args) -> Result<&'static str, WalletError> {
    let mut found = None;
    for (flag, name) in [
        ("--mainnet", "main"),
        ("--regtest", "regtest"),
        ("--signet", "signet"),
        ("--testnet", "testnet"),
    ] {
        while let Some(at) = args.0.iter().position(|a| a == flag) {
            args.0.remove(at);
            if found.is_some_and(|f| f != name) {
                return Err(WalletError::Invalid(
                    "give at most one of --mainnet, --regtest, --signet, --testnet".into(),
                ));
            }
            found = Some(name);
        }
    }
    Ok(found.unwrap_or("main"))
}

/// The `[air]` settings of this run, set once in `run`. Empty (AIR off) until then.
static AIR: std::sync::OnceLock<AirSettings> = std::sync::OnceLock::new();

/// The `[air]` settings of this run (empty before `run` sets them: AIR off).
fn air_settings() -> AirSettings {
    AIR.get().cloned().unwrap_or_default()
}

/// What the first check of each mint (the PSP, the ESP) in this run came to,
/// with the URL it was for: a mint is checked at startup and again by the
/// command, and with AIR a dead mint costs `air.attempts` tries of
/// `air.reply_wait_secs` each time, so the answer is kept for the run. (HTTP is
/// checked every time, as before.)
static CHECKED: std::sync::Mutex<Vec<(config::Party, String, Result<(), String>)>> =
    std::sync::Mutex::new(Vec::new());

/// Check a mint's wire version and network before anything else is sent to it:
/// over AIR when `[air]` is configured (to that mint's own DID: see
/// `ecash_wallet::mint_info`), else over HTTP.
fn verify_mint_of(
    wallet: &mut Wallet,
    party: config::Party,
    base: &str,
) -> Result<(), WalletError> {
    let air = air_settings();
    let check = |wallet: &mut Wallet| match party {
        config::Party::Psp => ecash_wallet::mint_info::verify_psp(wallet, &air, base, network()),
        config::Party::Esp => ecash_wallet::mint_info::verify_esp(wallet, &air, base, network()),
    };
    if !air.is_configured() {
        return check(wallet);
    }
    let mut checked = CHECKED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, result)) = checked.iter().find(|(p, u, _)| *p == party && u == base) {
        return result.clone().map_err(WalletError::Mint);
    }
    let result = check(wallet);
    checked.push((
        party,
        base.to_string(),
        result.as_ref().map(|_| ()).map_err(|e| e.to_string()),
    ));
    result
}

/// Check the PSP (`verify_mint_of`).
fn verify_psp(wallet: &mut Wallet, base: &str) -> Result<(), WalletError> {
    verify_mint_of(wallet, config::Party::Psp, base)
}

/// The PSP's URL, after checking it (`verify_psp`).
fn psp_base(wallet: &mut Wallet, flag: Option<String>) -> Result<String, WalletError> {
    let base = url(flag, "ECASH_PSP_URL", DEFAULT_PSP_URL);
    verify_psp(wallet, &base)?;
    Ok(base)
}

/// The ESP's URL, after checking it: over AIR to the ESP's own DID when `[air]`
/// is configured, else `GET /health`.
fn esp_base(wallet: &mut Wallet, flag: Option<String>) -> Result<String, WalletError> {
    let base = url(flag, "ECASH_ESP_URL", DEFAULT_ESP_URL);
    verify_mint_of(wallet, config::Party::Esp, &base)?;
    Ok(base)
}

/// A mint's URL, after checking (`GET /health`) that the mint is on this
/// run's network. Nothing is sent to a mint on another network. (Not for the
/// PSP or the ESP, whose checks can go over AIR: see `psp_base`, `esp_base`.)
fn mint_url(flag: Option<String>, var: &str, default: &str) -> Result<String, WalletError> {
    let base = url(flag, var, default);
    http::verify_mint(&base, network())?;
    Ok(base)
}

fn buy_psp(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let mint_key = args
        .flag("--mint-key")?
        .ok_or_else(|| WalletError::Invalid("--mint-key HEX is required".into()))?;
    if let Some(base) = args.flag("--psp-url")? {
        verify_psp(wallet, &base)?;
        let air = air_settings();
        let w = ecash_wallet::mint_info::psp_window(wallet, &air, &base)?;
        wallet.note_live_keysets(&base, &w)?;
        ecash_wallet::mint_info::sync_psp_limits(wallet, &air, &base)?;
    }
    let reply = match args.flag("--reply-did")? {
        Some(text) => parse_did(&text)?,
        None => wallet.reply_did()?,
    };
    let amounts = args
        .rest()
        .iter()
        .map(|a| number(a, "an amount"))
        .collect::<Result<Vec<_>, _>>()?;
    let mint_key = sp_wire::seal::parse_public_key(&mint_key)
        .map_err(|e| WalletError::Invalid(e.to_string()))?;
    let built = wallet.build_psp_payload(&amounts, &reply, &mint_key)?;
    eprintln!("purchase {}", built.id);
    eprintln!(
        "{} bytes. Put the hex below in an OP_RETURN and pay the PSP.",
        built.payload.len()
    );
    println!("{}", hex::encode(&built.payload));
    Ok(())
}

fn claim_psp(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let base = psp_base(wallet, args.flag("--psp-url")?)?;
    let file = args.flag("--file")?;
    let pairs = args.rest();
    let text = match (file, pairs.is_empty()) {
        (Some(f), true) if f != "-" => std::fs::read_to_string(&f)?,
        (Some(_), true) | (None, true) => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            text
        }
        (None, false) => pairs.join("\n"),
        (Some(_), false) => {
            return Err(WalletError::Invalid(
                "give --file or pairs, not both".into(),
            ));
        }
    };
    let all = parse_signatures(&text)?;
    // The PSP's output holds every payer's signatures. Keep this wallet's.
    let signatures = wallet.ours(&all);
    if signatures.is_empty() {
        return Err(WalletError::Unknown(format!(
            "none of the {} signature(s) read are for this wallet's pending purchases",
            all.len()
        )));
    }
    if signatures.len() < all.len() {
        eprintln!(
            "skipped {} signature(s) that are not for this wallet",
            all.len() - signatures.len()
        );
    }
    // Unblind with the keys of the keyset the PSP printed; older output names
    // none and was signed with the keys of `GET /keys`.
    let keys = ecash_wallet::mint_info::psp_claim_keys(wallet, &air_settings(), &base, &text)?;
    let claimed = wallet.claim_psp(&signatures, &keys)?;
    println!(
        "claimed {} PSP in {} note(s); {} output(s) still waiting",
        claimed.claimed_units,
        claimed.claimed.len(),
        claimed.still_pending
    );
    Ok(())
}

fn exchange(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let base = esp_base(wallet, args.flag("--esp-url")?)?;
    let resume = args.flag("--resume")?;
    let built: ExchangeBuild = match resume {
        Some(id) => {
            args.done()?;
            let pending = wallet
                .pending_exchanges()
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no pending exchange {id}")))?;
            ExchangeBuild {
                id: pending.id.clone(),
                request: pending.request.clone(),
                psp_spent: pending
                    .request
                    .psp_inputs
                    .iter()
                    .map(|i| i.amount.units)
                    .sum(),
                change_esp: pending.change_esp,
            }
        }
        None => {
            let service = args
                .flag("--service")?
                .ok_or_else(|| WalletError::Invalid("--service DID is required".into()))?;
            let psp = number(
                &args
                    .flag("--psp")?
                    .ok_or_else(|| WalletError::Invalid("--psp N is required".into()))?,
                "--psp",
            )?;
            let amounts = match args.flag("--amounts")? {
                Some(list) => Some(
                    list.split(',')
                        .map(|a| number(a, "an amount"))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                None => None,
            };
            args.done()?;
            let service = service_did(&service)?;
            ecash_wallet::mint_info::sync_esp_keysets(wallet, &air_settings(), &base)?;
            ecash_wallet::mint_info::sync_esp_limits(wallet, &air_settings(), &base)?;
            wallet.build_exchange(psp, service, amounts.as_deref())?
        }
    };
    eprintln!("exchange {} (spends {} PSP)", built.id, built.psp_spent);
    match ecash_wallet::mint_info::send_exchange(wallet, &air_settings(), &base, &built.request) {
        Ok(response) => {
            let done = wallet.finish_exchange(&built.id, &response)?;
            println!(
                "received {} ESP in {} note(s), redeemable after day {}",
                done.esp_units,
                done.notes.len(),
                done.redeemable_after_day
            );
            if done.change_esp > 0 {
                println!(
                    "{} of that is change: the PSP notes spent were worth more than the amount asked for, and the rest came back as ESP under the same terms",
                    done.change_esp
                );
            }
            Ok(())
        }
        Err(WalletError::SpentElsewhere { why, inputs }) => {
            // Some of the PSP notes were spent by a different request. They are
            // spent, so they leave the balance. The others go back to the wallet.
            let report = wallet.mark_spent_elsewhere(&built.id, &inputs)?;
            eprintln!(
                "{} PSP note(s) were spent by a different request and are marked spent in the wallet. {} other note(s) are free again",
                report.marked_spent, report.freed
            );
            Err(WalletError::SpentElsewhere { why, inputs })
        }
        Err(WalletError::Refused(why)) => {
            // Nothing was burned, so the PSP notes go back to the wallet.
            wallet.cancel_exchange(&built.id)?;
            Err(WalletError::Refused(why))
        }
        Err(e) => {
            eprintln!(
                "the outcome is unknown. Send the same request again with: exchange --resume {}",
                built.id
            );
            Err(e)
        }
    }
}

/// A service as typed: its 33-byte AIR DID, 66 hex characters. The old 32-byte
/// x-only form is refused, and the error says what to use instead. (Not to be
/// confused with `--service-key`, a service's secret key, see `secret_key`.)
fn service_did(text: &str) -> Result<ServiceDid, WalletError> {
    ServiceDid::parse(text).map_err(|e| WalletError::Invalid(e.to_string()))
}

fn secret_key(text: &str) -> Result<SecretKey, WalletError> {
    let bytes = hex::decode(text.trim())
        .map_err(|_| WalletError::Invalid("the service key must be hex".into()))?;
    SecretKey::from_slice(&bytes).map_err(|_| {
        WalletError::Invalid(
            "the service key must be a 32 byte secret key (64 hex characters)".into(),
        )
    })
}

/// Write a file that holds secrets: new, and readable by the owner only.
fn write_private(path: &std::path::Path, text: &str) -> Result<(), std::io::Error> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn hand_over(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let service = service_did(
        &args
            .flag("--service")?
            .ok_or_else(|| WalletError::Invalid("--service DID is required".into()))?,
    )?;
    let units: u128 = match (args.flag("--esp")?, args.flag("--psp")?) {
        (Some(esp), None) => esp.trim().parse::<u128>().map_err(|_| {
            WalletError::Invalid(format!(
                "--esp must be a whole number of ESP units, got `{esp}`"
            ))
        })?,
        (None, Some(psp)) => u128::from(number(&psp, "--psp")?) * u128::from(ESP_PER_PSP),
        _ => {
            return Err(WalletError::Invalid(
                "give exactly one of --esp UNITS or --psp N".into(),
            ));
        }
    };
    let day = match args.flag("--day")? {
        Some(d) => Some(number(&d, "--day")?),
        None => None,
    };
    let out = args
        .flag("--out")?
        .ok_or_else(|| WalletError::Invalid("--out FILE is required".into()))?;
    args.done()?;
    let path = PathBuf::from(&out);
    if path.exists() {
        return Err(WalletError::Invalid(format!(
            "{out} already exists. Pick a new file name"
        )));
    }
    // The mint's note limit is read when it can be; a hand-over works offline,
    // and then the mint's own check decides.
    let esp = url(None, "ECASH_ESP_URL", DEFAULT_ESP_URL);
    if let Err(e) = ecash_wallet::mint_info::sync_esp_limits(wallet, &air_settings(), &esp) {
        eprintln!("the mint's note limit was not read ({e}); the mint will check it");
    }
    let handover = wallet.hand_over_esp(service, units, day)?;
    let text = serde_json::to_string_pretty(&handover)
        .map_err(|e| WalletError::Invalid(format!("could not write the hand-over: {e}")))?;
    write_private(&path, &text).map_err(|e| {
        WalletError::Invalid(format!(
            "the notes were handed over and are kept in the wallet file, but writing {out} failed: {e}"
        ))
    })?;
    let handed: u128 = handover.notes.iter().map(|n| u128::from(n.amount)).sum();
    println!(
        "handed over {handed} ESP in {} note(s), redeemable after day {}",
        handover.notes.len(),
        handover.redeemable_after_day
    );
    println!(
        "wrote {out}. It holds the notes' spend secrets: give it to the service, and keep it private"
    );
    Ok(())
}

fn receive(wallet: &mut Wallet, args: Args) -> Result<(), WalletError> {
    let rest = args.rest();
    let [path] = rest.as_slice() else {
        return Err(WalletError::Invalid("receive takes one file".into()));
    };
    let text = std::fs::read_to_string(path)?;
    let handover: Handover = serde_json::from_str(&text)
        .map_err(|e| WalletError::Invalid(format!("{path}: not a hand-over file: {e}")))?;
    let (count, units) = wallet.receive_handover(&handover)?;
    println!(
        "received {units} ESP in {count} note(s) for {}, redeemable after day {}",
        hex::encode(handover.service.serialize()),
        handover.redeemable_after_day
    );
    Ok(())
}

fn transfer(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let base = esp_base(wallet, args.flag("--esp-url")?)?;
    let resume = args.flag("--resume")?;
    // The service key signs a new transfer (not needed with --resume).
    let key = args
        .flag("--service-key")?
        .map(|k| secret_key(&k))
        .transpose()?;
    let built: TransferBuild = match resume {
        Some(id) => {
            args.done()?;
            let pending = wallet
                .pending_transfers()
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no pending transfer {id}")))?;
            TransferBuild {
                id: pending.id.clone(),
                request: pending.request.clone(),
                esp_units: pending
                    .request
                    .inputs
                    .iter()
                    .map(|i| u128::from(i.amount.units))
                    .sum(),
            }
        }
        None => {
            let key =
                key.ok_or_else(|| WalletError::Invalid("--service-key HEX is required".into()))?;
            let day = match args.flag("--day")? {
                Some(d) => Some(number(&d, "--day")?),
                None => None,
            };
            let amounts = match args.flag("--amounts")? {
                Some(list) => Some(
                    list.split(',')
                        .map(|a| number(a, "an amount"))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                None => None,
            };
            args.done()?;
            ecash_wallet::mint_info::sync_esp_keysets(wallet, &air_settings(), &base)?;
            ecash_wallet::mint_info::sync_esp_limits(wallet, &air_settings(), &base)?;
            wallet.build_transfer(&key, day, amounts.as_deref())?
        }
    };
    eprintln!(
        "transfer {} ({} ESP in {} note(s))",
        built.id,
        built.esp_units,
        built.request.inputs.len()
    );
    match ecash_wallet::mint_info::send_transfer(wallet, &air_settings(), &base, &built.request) {
        Ok(response) => {
            let done = wallet.finish_transfer(&built.id, &response)?;
            println!(
                "transferred {} ESP to {} new note(s) that only this service controls, redeemable after day {}",
                done.esp_units,
                done.notes.len(),
                done.redeemable_after_day
            );
            Ok(())
        }
        Err(WalletError::SpentElsewhere { why, inputs }) => {
            // Some notes are spent. They leave the balance; the others are free.
            let report = wallet.mark_spent_in_transfer(&built.id, &inputs)?;
            eprintln!(
                "{} note(s) were spent by a different request and are marked spent in the wallet. {} other note(s) are free again",
                report.marked_spent, report.freed
            );
            Err(WalletError::SpentElsewhere { why, inputs })
        }
        Err(WalletError::Refused(why)) => {
            // Nothing was burned, so the notes go back to the wallet.
            wallet.cancel_transfer(&built.id)?;
            Err(WalletError::Refused(why))
        }
        Err(e) => {
            eprintln!(
                "the outcome is unknown. Send the same request again with: transfer --resume {}",
                built.id
            );
            Err(e)
        }
    }
}

/// ESP units as US dollars ($1 = 10^12 units; 1 PSP is $0.10 = 10^11 units), all
/// 12 decimals. It divides by the ESP-per-dollar rate, not the ESP-per-PSP one.
fn usd(units: u128) -> String {
    let per = sp_wire::units::ESP_PER_USD;
    format!("${}.{:012}", units / per, units % per)
}

fn print_outcome(done: &RedeemOutcome) {
    let accepted = done.notes.iter().filter(|n| n.0).count();
    println!(
        "redemption {}: {} of {} note(s) accepted, {} ESP ({}). Fee {} ESP ({}): {} bytes at {} a byte",
        done.id,
        accepted,
        done.notes.len(),
        done.accepted_esp,
        usd(done.accepted_esp),
        done.fee_esp,
        usd(done.fee_esp),
        done.size_bytes,
        done.fee_per_byte
    );
    for (i, (ok, reason, burned)) in done.notes.iter().enumerate() {
        if !ok {
            let reason = reason
                .map(|r| r.to_string())
                .unwrap_or_else(|| "no reason given".into());
            let burned = if *burned { ", burned for the fee" } else { "" };
            println!("  note {i} rejected: {reason}{burned}");
        }
    }
    if !done.refunded.is_empty() {
        println!(
            "  {} refund note(s) back from the rejected notes",
            done.refunded.len()
        );
    }
    if done.marked_spent > 0 {
        println!(
            "  {} note(s) already spent: marked spent in the wallet",
            done.marked_spent
        );
    }
    if done.freed > 0 {
        println!("  {} note(s) not burned: free again", done.freed);
    }
    println!(
        "  {}: owed {} ESP ({})",
        done.message,
        done.owed_esp,
        usd(done.owed_esp)
    );
    match &done.entry {
        None => {}
        Some(EntryOutcome::Open) => {
            println!("  payout is open. Check later with: redeem --collect")
        }
        Some(EntryOutcome::Completed { payment_ref }) => println!(
            "  payout completed, payment reference {}",
            payment_ref.as_deref().unwrap_or("(none)")
        ),
        Some(EntryOutcome::Declined {
            reason,
            reissued,
            reissued_esp,
        }) => println!(
            "  payout declined: {}. {} note(s) worth {} ESP reissued to this wallet",
            reason.as_deref().unwrap_or("no reason given"),
            reissued.len(),
            reissued_esp
        ),
    }
}

/// Send one pending redemption, and rebuild it if the mint asks for other
/// outputs. Returns whether it went through.
fn send_redemption(
    wallet: &mut Wallet,
    base: &str,
    key: Option<&SecretKey>,
    mut id: String,
) -> Result<(), WalletError> {
    for _ in 0..5 {
        let pending = wallet
            .pending_redemptions()
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .ok_or_else(|| WalletError::Unknown(format!("no pending redemption {id}")))?;
        match ecash_wallet::mint_info::send_redeem(wallet, &air_settings(), base, &pending.body()?)
        {
            Ok(response) => {
                let done = wallet.finish_redemption(&id, &response)?;
                print_outcome(&done);
                return Ok(());
            }
            Err(WalletError::RedeemRefused {
                code,
                why,
                totals: Some(totals),
                ..
            }) if matches!(code.as_str(), "refund_required" | "outputs_over_limit")
                && key.is_some() =>
            {
                eprintln!(
                    "the mint asks for other outputs ({code}): {why}. Rebuilding the request"
                );
                let key = key.unwrap_or_else(|| unreachable!());
                let built = wallet.rebuild_redemption(&id, key, &totals)?;
                eprintln!(
                    "redemption {}: {} note(s), {} bytes, fee {} ESP ({}), {} decline and {} refund output(s)",
                    built.id,
                    built.notes,
                    built.size_bytes,
                    built.fee_esp,
                    usd(built.fee_esp),
                    built.decline_outputs,
                    built.refund_outputs
                );
                id = built.id;
            }
            Err(e @ WalletError::RedeemRefused { .. }) => {
                if pending.state == RedemptionState::Sent {
                    // Nothing was burned, so the notes go back to the wallet.
                    // Notes the mint says are spent leave the balance instead.
                    let notes = match &e {
                        WalletError::RedeemRefused { notes, .. } => notes.as_slice(),
                        _ => &[],
                    };
                    let report = wallet.refuse_redemption(&id, notes)?;
                    if report.marked_spent > 0 {
                        eprintln!(
                            "{} note(s) the mint says are already spent: marked spent in the wallet. {} other note(s) are free again",
                            report.marked_spent, report.freed
                        );
                    }
                }
                return Err(e);
            }
            Err(e) => {
                eprintln!(
                    "the outcome is unknown. Send the same request again with: redeem --service-key HEX --resume {id}"
                );
                return Err(e);
            }
        }
    }
    Err(WalletError::Mint(format!(
        "the mint kept asking for other outputs. Redemption {id} is pending: try --resume"
    )))
}

fn redeem(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let base = esp_base(wallet, args.flag("--esp-url")?)?;
    let collect = match args.0.iter().position(|a| a == "--collect") {
        Some(at) => {
            args.0.remove(at);
            true
        }
        None => false,
    };
    if collect {
        args.done()?;
        let queued: Vec<String> = wallet
            .pending_redemptions()
            .iter()
            .filter(|p| p.state == RedemptionState::Queued)
            .map(|p| p.id.clone())
            .collect();
        if queued.is_empty() {
            println!("no redemption is waiting for a payout");
        }
        for id in queued {
            send_redemption(wallet, &base, None, id)?;
        }
        return Ok(());
    }
    let key = match args.flag("--service-key")? {
        Some(k) => Some(secret_key(&k)?),
        None => None,
    };
    if let Some(id) = args.flag("--resume")? {
        args.done()?;
        return send_redemption(wallet, &base, key.as_ref(), id);
    }
    let key = key.ok_or_else(|| WalletError::Invalid("--service-key HEX is required".into()))?;
    let memo = args.flag("--memo")?.ok_or_else(|| {
        WalletError::Invalid("--memo TEXT (where the payout goes) is required".into())
    })?;
    let max_bytes = match args.flag("--max-bytes")? {
        Some(n) => Some(number(&n, "--max-bytes")?),
        None => None,
    };
    args.done()?;
    let mut fees = ecash_wallet::mint_info::fetch_redeem_fees(wallet, &air_settings(), &base)?;
    if let Some(n) = max_bytes {
        fees.max_request_bytes = fees.max_request_bytes.min(n);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ecash_wallet::mint_info::sync_esp_keysets(wallet, &air_settings(), &base)?;
    let plan = wallet.plan_redemption(&key, &memo, &fees, now)?;
    for why in &plan.skipped {
        eprintln!("{why}");
    }
    let built = plan.built;
    eprintln!(
        "fee rate {} ESP units a byte; at most {} bytes a request; {} request(s)",
        fees.fee_per_byte,
        fees.max_request_bytes,
        built.len()
    );
    for b in &built {
        eprintln!(
            "redemption {}: {} note(s) worth {} ESP ({}), {} bytes, fee {} ESP ({}), expected payout {} ESP ({})",
            b.id,
            b.notes,
            b.esp_units,
            usd(b.esp_units),
            b.size_bytes,
            b.fee_esp,
            usd(b.fee_esp),
            b.owed_esp,
            usd(b.owed_esp)
        );
    }
    let mut first_error = None;
    for b in built {
        if let Err(e) = send_redemption(wallet, &base, Some(&key), b.id) {
            if let Some(line) = later_failure_line(&mut first_error, e) {
                eprintln!("{line}");
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Remember a failed redemption request. The first failure is kept, and `main`
/// prints it once as the command's error, so it gets no line here. A later one
/// would be lost, so it gets a line.
fn later_failure_line(first: &mut Option<WalletError>, e: WalletError) -> Option<String> {
    if first.is_some() {
        return Some(format!("error: {e}"));
    }
    *first = Some(e);
    None
}

fn balance(wallet: &Wallet, args: Args) -> Result<(), WalletError> {
    args.done()?;
    let b = wallet.balance();
    println!("psp  {}", b.psp);
    println!("esp  {}", b.esp);
    for ((service, day), units) in &b.esp_by_terms {
        println!("       {units} for {service}, redeemable after day {day}");
    }
    println!("fsp  {}", b.fsp);
    let by_keyset = wallet.fsp_by_keyset();
    for (service, units) in &b.fsp_by_service {
        println!("       {units} for service {service}");
        for ((_, keyset), units) in by_keyset.iter().filter(|((s, _), _)| s == service) {
            let role = match wallet.fsp_mints().get(service) {
                Some(m) if &m.current == keyset => "current",
                Some(m) if m.previous.as_deref() == Some(keyset.as_str()) => "previous",
                _ => "not checked yet",
            };
            println!("         {units} on keyset {keyset} ({role})");
        }
    }
    let (unknown, unknown_units) = wallet.fsp_unknown_service();
    if unknown > 0 {
        println!(
            "       {unknown_units} FSP in {unknown} note(s) whose service is not known yet: they are not spent until it is. Connect to their mint (any `fsp` command) to fill it in"
        );
    }
    for p in wallet.pending_fsp() {
        println!("pending fsp {}", p.id);
    }
    if !wallet.lost_fsp().is_empty() {
        let units: u128 = wallet.lost_fsp().iter().map(|n| u128::from(n.amount)).sum();
        println!("lost fsp {units} (their keyset was deleted by the mint; not counted above)");
    }
    println!(
        "notes {} ({} held for a pending request)",
        b.notes, b.reserved
    );
    for p in wallet.pending_purchases() {
        println!(
            "pending purchase {} ({} output(s) unsigned)",
            p.id,
            p.outputs.len()
        );
    }
    for p in wallet.pending_exchanges() {
        println!("pending exchange {}", p.id);
    }
    for p in wallet.pending_transfers() {
        println!("pending transfer {}", p.id);
    }
    for p in wallet.pending_redemptions() {
        match p.state {
            RedemptionState::Sent => println!("pending redemption {} (not answered yet)", p.id),
            RedemptionState::Queued => println!(
                "pending redemption {} (payout of {} ESP queued at the mint)",
                p.id, p.owed_esp
            ),
        }
    }
    if b.bad_proof > 0 {
        println!(
            "bad proof {} note(s) worth {} ESP: the mint rejected their proof, so redeem leaves them out (counted above)",
            b.bad_proof, b.bad_proof_esp
        );
    }
    if b.spent_elsewhere > 0 {
        println!(
            "spent elsewhere {} note(s): the mint says they were spent by a different request, so they are not counted above",
            b.spent_elsewhere
        );
    }
    if b.handed_over > 0 {
        println!(
            "handed over {} time(s); the hand-overs are kept in the wallet file",
            b.handed_over
        );
    }
    if b.unswapped_psp > 0 {
        println!(
            "unswapped {} PSP of the PSP above was received in a handoff and the mint has not swapped it yet (it could not be reached). It can be spent; until it is swapped the sender could still reclaim it. The swap is sent again at the next start",
            b.unswapped_psp
        );
    }
    if wallet.legacy_receive_psp() > 0 {
        println!(
            "waiting {} PSP from an old receive-psp token: its swap is stored and sent again at the next start. It is not counted above until the swap goes through",
            wallet.legacy_receive_psp()
        );
    }
    let pending = wallet
        .handoffs_out()
        .iter()
        .filter(|h| h.state == ecash_wallet::handoff::HandoffState::Pending)
        .count();
    if pending > 0 {
        println!(
            "handoffs {pending} pending: their notes are held back until you reclaim, cancel or finish them (`handoff list`)"
        );
    }
    Ok(())
}

/// A DID secret key from a file of 64 hex characters.
fn did_key_from_file(path: &str) -> Result<DidSecretKey, WalletError> {
    let text = std::fs::read_to_string(path)?;
    let bytes = hex::decode(text.trim()).map_err(|_| {
        WalletError::Invalid(format!("{path}: a DID secret key is 64 hex characters"))
    })?;
    DidSecretKey::from_bytes(&bytes)
        .map_err(|_| WalletError::Invalid(format!("{path}: a DID secret key is 64 hex characters")))
}

fn handoff(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    if args.0.is_empty() {
        return Err(WalletError::Invalid(
            "handoff needs export-psp, export-fsp, import, check, reclaim, list, cancel or done. Run with --help"
                .into(),
        ));
    }
    let what = args.0.remove(0);
    match what.as_str() {
        "export-psp" => handoff_export_psp(wallet, args),
        "export-fsp" => handoff_export_fsp(wallet, args),
        "export" => Err(WalletError::Invalid(
            "`handoff export` was split in two, because the combined handoff could be built in ways that are not allowed. Use `handoff export-psp` (a developer to a user: PSP only, sealed to the user's DID) or `handoff export-fsp` (your own new device: FSP and your DID key)".into(),
        )),
        "import" => handoff_import(wallet, args),
        "list" => {
            args.done()?;
            for h in wallet.handoffs_out() {
                println!(
                    "out {} {} {:?} {} PSP {} FSP in {} note(s){}{}{}",
                    h.id,
                    h.kind.label(),
                    h.state,
                    h.psp_units,
                    h.fsp_units,
                    h.note_count,
                    if h.with_did_key {
                        ", with a DID key"
                    } else {
                        ""
                    },
                    if h.reclaim.is_some() {
                        ", reclaim stored (run `handoff reclaim` again)"
                    } else {
                        ""
                    },
                    if h.spent_elsewhere > 0 {
                        format!(", {} note(s) spent at the mint", h.spent_elsewhere)
                    } else {
                        String::new()
                    }
                );
            }
            for h in wallet.handoffs_in() {
                println!(
                    "in  {} {} from {} {} PSP {} FSP in {} note(s){}",
                    h.id,
                    h.kind.label(),
                    if h.from.is_empty() {
                        "(unnamed)"
                    } else {
                        &h.from
                    },
                    h.psp_units,
                    h.fsp_units,
                    h.notes.len(),
                    if h.swapped { ", swapped" } else { "" }
                );
            }
            if wallet.unswapped_psp() > 0 {
                println!(
                    "{} PSP received in a handoff is in your balance and still waiting to be swapped; the swap is sent again at the next start",
                    wallet.unswapped_psp()
                );
            }
            Ok(())
        }
        "check" => {
            let rest = args.rest();
            let [id] = rest.as_slice() else {
                return Err(WalletError::Invalid("handoff check takes an ID".into()));
            };
            let standing = ecash_wallet::mint_info::check_handoff(wallet, &air_settings(), id)?;
            print_standing(id, &standing);
            Ok(())
        }
        "reclaim" => {
            let rest = args.rest();
            let [id] = rest.as_slice() else {
                return Err(WalletError::Invalid("handoff reclaim takes an ID".into()));
            };
            let done = ecash_wallet::mint_info::reclaim_handoff(wallet, &air_settings(), id)?;
            for line in &done.log {
                println!("{line}");
            }
            print_standing(id, &done.standing);
            Ok(())
        }
        "cancel" => {
            let rest = args.rest();
            let [id] = rest.as_slice() else {
                return Err(WalletError::Invalid("handoff cancel takes an ID".into()));
            };
            let n = wallet.cancel_handoff(id)?;
            println!(
                "put back {n} note(s) without asking the mint. If the other wallet already has the handoff, it holds the same secrets: the first of you to swap or spend a note wins. For a PSP handoff, `handoff reclaim` lets the mint decide first"
            );
            Ok(())
        }
        "done" => {
            let rest = args.rest();
            let [id] = rest.as_slice() else {
                return Err(WalletError::Invalid("handoff done takes an ID".into()));
            };
            wallet.finish_handoff(id)?;
            println!("handoff {id} is done; its notes are no longer kept here");
            Ok(())
        }
        other => Err(WalletError::Invalid(format!(
            "unknown handoff command `{other}`"
        ))),
    }
}

/// What a check or a reclaim found, in words.
fn print_standing(id: &str, standing: &ecash_wallet::handoff::Standing) {
    use ecash_wallet::handoff::Standing;
    match standing {
        Standing::Pending => println!(
            "{id}: pending. The mint has seen none of the notes spent, so the receiver has not swapped yet and you can still take it back with `handoff reclaim {id}`"
        ),
        Standing::Received => println!(
            "{id}: received. Every note is spent at the mint: the receiver swapped (or spent) them. Nothing is left to reclaim"
        ),
        Standing::Partly { spent, left } => println!(
            "{id}: partly spent. {spent} note(s) are spent at the mint and are not yours any more; {left} are not, and `handoff reclaim {id}` takes those back if the receiver has not swapped them"
        ),
        Standing::Reclaimed => println!(
            "{id}: reclaimed. The notes were swapped back to this wallet at the mint and are in your balance"
        ),
    }
}

/// Print an export and write it to `--out` or to standard output.
fn handoff_deliver(
    made: &ecash_wallet::handoff::HandoffExport,
    out: Option<String>,
) -> Result<(), WalletError> {
    eprintln!("handoff {}: {}", made.id, made.warning);
    eprintln!(
        "{} {} handoff, {} note(s): {} PSP, {} FSP{}; {} characters ({} bytes). The notes are held back here until you reclaim (`handoff reclaim {}`, PSP), cancel (`handoff cancel {}`) or finish (`handoff done {}`) it.",
        made.kind.label(),
        made.id,
        made.notes,
        made.psp_units,
        made.fsp_units,
        if made.with_did_key {
            ", and the DID key"
        } else {
            ""
        },
        made.chars,
        made.bytes,
        made.id,
        made.id,
        made.id
    );
    match out {
        Some(path) => {
            if let Err(e) = write_private(std::path::Path::new(&path), &made.text) {
                println!("{}", made.text);
                return Err(WalletError::Invalid(format!(
                    "could not write {path}: {e}. The handoff is printed above; it is kept as pending here"
                )));
            }
            eprintln!("written to {path} (private: it holds secrets)");
        }
        None => println!("{}", made.text),
    }
    Ok(())
}

fn check_out_file(out: &Option<String>) -> Result<(), WalletError> {
    if let Some(path) = out {
        if std::path::Path::new(path).exists() {
            return Err(WalletError::Invalid(format!(
                "{path} exists; not overwritten"
            )));
        }
    }
    Ok(())
}

fn handoff_export_psp(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let to = args.flag("--to")?.ok_or_else(|| {
        WalletError::Invalid(
            "a PSP handoff is sealed to the recipient: give their DID public key with --to (66 hex characters)".into(),
        )
    })?;
    let psp = args
        .flag("--psp")?
        .ok_or_else(|| WalletError::Invalid("give the amount with --psp N".into()))?;
    let psp = u128::from(number(&psp, "--psp")?);
    let psp_url = args.flag("--psp-url")?;
    let out = args.flag("--out")?;
    args.done()?;
    check_out_file(&out)?;
    let recipient = sp_wire::seal::parse_public_key(&to)
        .map_err(|e| WalletError::Invalid(format!("--to: {e}")))?;
    let ids = wallet.select_psp_handoff(psp)?;
    let mint = psp_base(wallet, psp_url)?;
    let made = wallet.export_psp_handoff(&ids, &mint, &recipient)?;
    handoff_deliver(&made, out)
}

fn handoff_export_fsp(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let mut fsp = Vec::new();
    while let Some(v) = args.flag("--fsp")? {
        let (service, units) = v
            .split_once(':')
            .ok_or_else(|| WalletError::Invalid("--fsp takes SERVICE:UNITS".into()))?;
        fsp.push((
            service_did(service)?,
            u128::from(number(units, "the FSP units")?),
        ));
    }
    let did_file = args.flag("--did-key-file")?.ok_or_else(|| {
        WalletError::Invalid(
            "an FSP handoff carries the DID secret key: give the file with --did-key-file".into(),
        )
    })?;
    let out = args.flag("--out")?;
    args.done()?;
    check_out_file(&out)?;
    let key = did_key_from_file(&did_file)?;
    let ids = wallet.select_fsp_handoff(&fsp)?;
    let made = wallet.export_fsp_handoff(&ids, &key)?;
    handoff_deliver(&made, out)
}

/// The handoff text for `handoff import`: `-` is standard input, a path that
/// exists is read, anything else is the handoff itself.
fn handoff_text(arg: &str) -> Result<String, WalletError> {
    if arg == "-" {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        return Ok(text);
    }
    let path = std::path::Path::new(arg);
    if path.is_file() {
        return Ok(std::fs::read_to_string(path)?);
    }
    Ok(arg.to_string())
}

fn handoff_import(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    use ecash_wallet::handoff::{FSP_WARNING, HandoffKind, PSP_WARNING};
    let from = args.flag("--from")?.unwrap_or_default();
    let did_out = args.flag("--did-key-out")?;
    let did_file = args.flag("--did-key-file")?;
    let rest = args.rest();
    let [arg] = rest.as_slice() else {
        return Err(WalletError::Invalid(
            "handoff import takes the handoff string, a file, or -".into(),
        ));
    };
    let text = handoff_text(arg)?;
    // Everything that can be refused is checked before anything is added: a
    // second import is refused, so a key could not be asked for again.
    let got = match ecash_wallet::handoff::kind_of(&text)? {
        HandoffKind::Psp => {
            if did_out.is_some() {
                return Err(WalletError::Invalid(
                    "a PSP handoff carries no DID key, so --did-key-out does not apply".into(),
                ));
            }
            let file = did_file.ok_or_else(|| {
                WalletError::Invalid(
                    "this is a PSP handoff, sealed to a DID key: give the secret key of that DID with --did-key-file. Nothing was imported".into(),
                )
            })?;
            let key = did_key_from_file(&file)?;
            wallet.import_psp_handoff(&text, &key, &from)?
        }
        _ => {
            if did_file.is_some() {
                return Err(WalletError::Invalid(
                    "an FSP handoff is not encrypted and carries its own DID key, so --did-key-file does not apply".into(),
                ));
            }
            match &did_out {
                None => {
                    return Err(WalletError::Invalid(
                        "this FSP handoff carries a DID secret key. Give --did-key-out FILE to save it (it is never printed). Nothing was imported".into(),
                    ));
                }
                Some(path) if std::path::Path::new(path).exists() => {
                    return Err(WalletError::Invalid(format!(
                        "{path} exists; not overwritten. Nothing was imported"
                    )));
                }
                Some(_) => {}
            }
            wallet.import_fsp_handoff(&text, &from)?
        }
    };
    if let (Some(key), Some(path)) = (&got.did_key, &did_out) {
        write_private(std::path::Path::new(path), &hex::encode(key.to_array()))?;
        eprintln!("DID secret key written to {path} (private)");
    }
    eprintln!(
        "{}",
        if got.kind == HandoffKind::Psp {
            PSP_WARNING
        } else {
            FSP_WARNING
        }
    );
    println!(
        "imported {} handoff {}: {} PSP and {} FSP in {} note(s){}",
        got.kind.label(),
        got.id,
        got.psp_units,
        got.fsp_units,
        got.notes.len(),
        if got.kind == HandoffKind::Psp {
            " (in your balance; swapping at the mint)"
        } else {
            ""
        }
    );
    for w in &got.warnings {
        eprintln!("warning: {w}");
    }
    // Read the FSP mints' keys: this checks the notes against live key sets,
    // moves those on a retired set to the lost record, and fills in what was
    // unknown.
    for (service, url) in &got.fsp_mints {
        let known = wallet
            .fsp_mints()
            .get(&hex::encode(service.serialize()))
            .map(|m| m.url.clone());
        sync_and_log(wallet, *service, &known.unwrap_or_else(|| url.clone()));
    }
    // A PSP handoff is swapped now. If the mint cannot be reached the swap
    // stays stored and the notes stay unswapped (in the balance, spendable), and
    // the startup sync sends it.
    for line in ecash_wallet::mint_info::complete_import(wallet, &air_settings(), &got) {
        println!("{line}");
    }
    if got.kind == HandoffKind::Fsp {
        println!(
            "Next: fetch your wallet from the AIR, then run `merge FILE` on the copy you fetched."
        );
    }
    Ok(())
}

fn merge_command(wallet: &mut Wallet, args: Args) -> Result<(), WalletError> {
    let rest = args.rest();
    let [path] = rest.as_slice() else {
        return Err(WalletError::Invalid("merge takes one wallet file".into()));
    };
    let r = wallet.merge_file(std::path::Path::new(path))?;
    println!(
        "merged {path}: {} note(s) added, {} removed because the other copy spent them, {} pending request(s) added, {} ended; version {}",
        r.notes_added, r.notes_removed, r.requests_added, r.requests_dropped, r.version
    );
    println!("Save this wallet back to storage: it is now the current copy.");
    Ok(())
}

const DEFAULT_FSP_URL: &str = "http://127.0.0.1:3200";

fn today() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

/// The FSP mint for a service: the flag, else the one used before, else
/// `$ECASH_FSP_URL`, else the default. Checked for the network first.
fn fsp_url(
    wallet: &Wallet,
    service: &ServiceDid,
    flag: Option<String>,
) -> Result<String, WalletError> {
    let known = wallet
        .fsp_mints()
        .get(&hex::encode(service.serialize()))
        .map(|m| m.url.clone());
    mint_url(flag.or(known), "ECASH_FSP_URL", DEFAULT_FSP_URL)
}

/// Check every FSP mint this wallet has used. Nothing is asked; problems are
/// logged and tried again next time.
/// At startup: keep PSP and ESP on a live key set (see `rotate.rs`), for the
/// mints in `$ECASH_PSP_URL` / `$ECASH_ESP_URL` (or the defaults), when this
/// wallet holds notes of that kind. Quiet when the mint is not reachable.
fn startup_rotation_sync(wallet: &mut Wallet) {
    for kind in [ecash_wallet::Kind::Psp, ecash_wallet::Kind::Esp] {
        let holds = wallet.notes().iter().any(|n| n.kind == kind)
            || wallet.pending_rollovers().iter().any(|p| p.kind == kind);
        if !holds {
            continue;
        }
        let checked = if kind == ecash_wallet::Kind::Psp {
            psp_base(wallet, None)
        } else {
            esp_base(wallet, None)
        };
        let Ok(base) = checked else {
            continue;
        };
        match ecash_wallet::mint_info::rotation_sync(wallet, &air_settings(), kind, &base) {
            Ok(lines) => {
                for l in lines {
                    eprintln!("{base}: {l}");
                }
            }
            Err(e) => eprintln!("{base}: key rotation check failed, retried on the next run: {e}"),
        }
    }
}

fn startup_fsp_sync(wallet: &mut Wallet) {
    let mints: Vec<(String, String)> = wallet
        .fsp_mints()
        .iter()
        .map(|(s, m)| (s.clone(), m.url.clone()))
        .collect();
    for (service, url) in mints {
        let Ok(key) = service_did(&service) else {
            continue;
        };
        sync_and_log(wallet, key, &url);
    }
}

fn sync_and_log(wallet: &mut Wallet, service: ServiceDid, url: &str) {
    let result =
        http::verify_mint(url, network()).and_then(|_| http::fsp_sync(wallet, service, url));
    match result {
        Ok(sync) => {
            for line in sync.log {
                eprintln!("fsp {url}: {line}");
            }
        }
        Err(e) => eprintln!("fsp {url}: not checked, tried again next time: {e}"),
    }
}

/// The service of an `fsp` command: `--service DID`, always given. There is no
/// default: `storage.wallet` lists the wallet's backups, not the service FSP is
/// paid to.
fn fsp_service(args: &mut Args) -> Result<ServiceDid, WalletError> {
    match args.flag("--service")? {
        Some(text) => service_did(&text),
        None => Err(WalletError::Invalid(
            "the fsp commands need --service DID (the service whose FSP this is); there is no default"
                .into(),
        )),
    }
}

fn fsp(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    if args.0.is_empty() {
        return Err(WalletError::Invalid(
            "fsp needs issue, pay or sync. Run with --help".into(),
        ));
    }
    let what = args.0.remove(0);
    let service = fsp_service(&mut args)?;
    let flag = args.flag("--fsp-url")?;
    let base = fsp_url(wallet, &service, flag)?;
    // Every connection: pending requests, keys, rollover.
    let sync = http::fsp_sync(wallet, service, &base)?;
    for line in sync.log {
        eprintln!("fsp {base}: {line}");
    }
    match what.as_str() {
        "sync" => {
            args.done()?;
            Ok(())
        }
        "issue" => {
            let units: Option<u128> = match (args.flag("--esp")?, args.flag("--psp")?) {
                (Some(e), None) => Some(u128::from(number(&e, "--esp")?)),
                (None, Some(p)) => Some(u128::from(number(&p, "--psp")?) * u128::from(ESP_PER_PSP)),
                (None, None) => None,
                _ => return Err(WalletError::Invalid("give --esp or --psp, not both".into())),
            };
            args.done()?;
            let fees = http::fetch_fsp_fees(&base)?;
            // Notes from before keysets were recorded name the ESP mint's
            // live set; best effort, the Issuer refuses a missing one.
            if let Ok(esp) = esp_base(wallet, None) {
                if let Err(e) =
                    ecash_wallet::mint_info::sync_esp_keysets(wallet, &air_settings(), &esp)
                {
                    eprintln!("esp {esp}: keysets not read: {e}");
                }
            }
            let request = wallet.build_fsp_issue(service, units, fees.issue_fee_per_byte)?;
            let id = request.hash();
            println!("issue {id}: {} group(s)", request.groups.len());
            println!("{}", http::settle_fsp(wallet, &base, &id)?);
            Ok(())
        }
        "pay" => {
            let units = number(
                &args
                    .flag("--units")?
                    .ok_or_else(|| WalletError::Invalid("--units N is needed".into()))?,
                "--units",
            )?;
            let memo = args.flag("--memo")?.unwrap_or_default();
            args.done()?;
            let request = wallet.build_fsp_spend(service, units, &memo)?;
            let id = request.hash();
            println!("spend {id}");
            println!("{}", http::settle_fsp(wallet, &base, &id)?);
            Ok(())
        }
        other => Err(WalletError::Invalid(format!(
            "unknown fsp command `{other}`"
        ))),
    }
}

fn fsp_window(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let service = service_did(
        &args
            .flag("--service")?
            .ok_or_else(|| WalletError::Invalid("--service DID is needed".into()))?,
    )?;
    let flag = args.flag("--fsp-url")?;
    args.done()?;
    let base = fsp_url(wallet, &service, flag)?;
    sync_and_log(wallet, service, &base);
    let w = http::fetch_fsp_rotation(&base)?;
    let when = |t: Option<u64>| match t {
        Some(t) => format!("{} (day {})", t, t / 86_400),
        None => "not set yet".into(),
    };
    println!(
        "rotation {}",
        if w.active { "active" } else { "not active" }
    );
    if w.rotation_activation_hours == 0 {
        println!("activation off (rotation.activation_hours = 0)");
    } else {
        println!(
            "activation {} hours after the first issue",
            w.rotation_activation_hours
        );
        println!("first issue {}", when(w.first_issue));
        println!("activates {}", when(w.activation));
    }
    println!("period {} hours", w.rotation_period_hours);
    for (name, k) in [
        ("current", Some(&w.current)),
        ("previous", w.previous.as_ref()),
    ] {
        if let Some(k) = k {
            println!(
                "{name} {} (epoch {}): started {}, current until {}, retires {}",
                k.id,
                k.epoch,
                k.starts
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "at genesis".into()),
                when(k.current_until),
                when(k.retires)
            );
        }
    }
    println!("next rotation {}", when(w.next_rotation));
    Ok(())
}

fn esp_schedule(wallet: &Wallet, mut args: Args) -> Result<(), WalletError> {
    let by = match args.flag("--by")? {
        Some(d) => Some(ecash_wallet::date::parse_date(&d).map_err(WalletError::Invalid)?),
        None => None,
    };
    args.done()?;
    let s = wallet.esp_schedule(today(), by);
    println!("esp held      {}", s.total);
    println!("mature now    {}", s.mature_now);
    if let Some((day, units)) = s.by {
        println!("mature by {} {}", ecash_wallet::fsp::month_of(day), units);
        println!("  (day {day})");
    }
    for (month, units) in &s.months {
        println!("  {month}  {units}");
    }
    Ok(())
}

/// The settings: `config.toml` beside the wallet file (or `--config`, or
/// `$ECASH_CONFIG`), then the `ECASH_STORAGE_...` variables.
fn load_settings(wallet: &Path, flag: Option<String>) -> Result<config::Loaded, WalletError> {
    let dir = wallet.parent().unwrap_or(Path::new(""));
    config::load(dir, flag.as_deref().map(Path::new), &|name| {
        env::var(name).ok()
    })
    .map_err(|problems| WalletError::Invalid(format!("settings:\n  {}", problems.join("\n  "))))
}

fn config_command(loaded: &config::Loaded, args: Args) -> Result<(), WalletError> {
    args.done()?;
    match &loaded.file {
        Some(path) => println!(
            "ecash-wallet settings from {}, then the environment:",
            path.display()
        ),
        None => println!("ecash-wallet settings: no config file, so defaults and the environment:"),
    }
    for line in loaded.describe() {
        println!("{line}");
    }
    println!(
        "storage.wallet: {}",
        loaded.settings.storage_wallet.describe()
    );
    println!("storage.app: {}", loaded.settings.storage_app.describe());
    println!("Storage settings only: nothing reads or writes the AIR for storage yet.");
    let air = &loaded.settings.air;
    if air.is_configured() {
        println!(
            "PSP mint info, keys, keysets, rotation, rollover and check-state, and ESP mint info, keysets, rotation, fees, rollover, exchange, transfer and redeem: over AIR (air.server and air.host are set); every other call is HTTP"
        );
        println!(
            "PSP DID in use: {} ({})",
            air.psp_did().to_hex(),
            if air.uses_builtin_did() {
                "the built-in PLACEHOLDER"
            } else {
                "air.psp_did"
            }
        );
        println!(
            "ESP DID in use: {} ({})",
            air.esp_did().to_hex(),
            if air.uses_builtin_esp_did() {
                "the built-in PLACEHOLDER"
            } else {
                "air.esp_did"
            }
        );
        for warning in air.placeholder_warnings() {
            eprintln!("{warning}");
        }
    } else {
        println!(
            "PSP mint info, keys, keysets, rotation, rollover and check-state, and ESP mint info, keysets, rotation, fees, rollover, exchange, transfer and redeem: over HTTP (air.server and air.host are not set)"
        );
    }
    Ok(())
}

fn run(raw: Vec<String>) -> Result<(), WalletError> {
    let mut args = Args(raw);
    let wallet_flag = args.flag("--wallet")?;
    let config_flag = args.flag("--config")?;
    let _ = NETWORK.set(take_network(&mut args)?);
    if args.0.is_empty() || args.0.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.0.remove(0);
    if command == "migrate" {
        return migrate_wallet();
    }
    let path = wallet_path(wallet_flag)?;
    let loaded = load_settings(&path, config_flag)?;
    if command == "config" {
        return config_command(&loaded, args);
    }
    let settings = loaded.settings;
    let _ = AIR.set(settings.air.clone());
    // AIR on with a built-in PLACEHOLDER DID (the PSP's, the ESP's) must never
    // pass silently.
    for warning in settings.air.placeholder_warnings() {
        eprintln!("{warning}");
    }
    let mut wallet = Wallet::open(&path)?;
    // A wallet file from before an FSP note's service was kept: fill it in from
    // the mints seen, and leave the rest marked unknown.
    match wallet.fill_fsp_services() {
        Ok(0) => {}
        Ok(n) => eprintln!("the service of {n} FSP note(s) was filled in from the mints seen"),
        Err(e) => eprintln!("FSP services not filled in: {e}"),
    }
    startup_fsp_sync(&mut wallet);
    startup_rotation_sync(&mut wallet);
    match command.as_str() {
        "fsp" => fsp(&mut wallet, args),
        "fsp-window" => fsp_window(&mut wallet, args),
        "esp-schedule" => esp_schedule(&wallet, args),
        "buy-psp" => buy_psp(&mut wallet, args),
        "claim-psp" => claim_psp(&mut wallet, args),
        "exchange" => exchange(&mut wallet, args),
        "hand-over" => hand_over(&mut wallet, args),
        "receive" => receive(&mut wallet, args),
        "transfer" => transfer(&mut wallet, args),
        "redeem" => redeem(&mut wallet, args),
        "balance" => balance(&wallet, args),
        "send-psp" | "receive-psp" | "sent" => Err(WalletError::Invalid(format!(
            "`{command}` was removed. A PSP handoff replaces it: `handoff export-psp --to DID --psp N` to give PSP, `handoff import` to take it, `handoff check ID` and `handoff reclaim ID` for what `sent --check` and `sent --reclaim` did. Tokens in an old wallet file are PSP handoffs now (see `handoff list`)"
        ))),
        "handoff" => handoff(&mut wallet, args),
        "merge" => merge_command(&mut wallet, args),
        other => Err(WalletError::Invalid(format!(
            "unknown command `{other}`. Run with --help"
        ))),
    }
}

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_redeem_request_is_printed_once_not_twice() {
        let mut first = None;
        // the first failure is kept for `main` to print as the command's error:
        // no line here, or it would show twice
        assert_eq!(
            later_failure_line(&mut first, WalletError::Mint("one".into())),
            None
        );
        assert!(matches!(&first, Some(WalletError::Mint(m)) if m == "one"));
        // a later failure would be lost, so it gets its own line, and the
        // first stays the one returned
        assert_eq!(
            later_failure_line(&mut first, WalletError::Mint("two".into())),
            Some("error: two".to_string())
        );
        assert!(matches!(&first, Some(WalletError::Mint(m)) if m == "one"));
    }

    #[test]
    fn an_fsp_command_without_service_is_refused() {
        let mut args = Args(vec!["--units".into(), "5".into()]);
        match fsp_service(&mut args) {
            Err(WalletError::Invalid(m)) => assert!(m.contains("--service"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // the other flags are left for the command
        assert_eq!(args.0, vec!["--units".to_string(), "5".to_string()]);
    }

    #[test]
    fn an_fsp_command_takes_the_service_it_is_given() {
        let did = config::BUILTIN_SPI_DID.to_string();
        let mut args = Args(vec![
            "--service".into(),
            did.clone(),
            "--units".into(),
            "5".into(),
        ]);
        assert_eq!(fsp_service(&mut args).unwrap().to_hex(), did);
        assert_eq!(args.0, vec!["--units".to_string(), "5".to_string()]);
    }
}
