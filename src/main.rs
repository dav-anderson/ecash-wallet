//! The command line. It parses arguments and prints; every step is a call into
//! the library.

use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ecash_wallet::config::{self, AirSettings};
use ecash_wallet::date::format_utc;
use ecash_wallet::esp::ExchangeBuild;
use ecash_wallet::redeem::{EntryOutcome, RedeemOutcome, RedemptionState};
use ecash_wallet::store::Handover;
use ecash_wallet::{Wallet, WalletError};
use secp256k1::SecretKey;
use sp_wire::ServiceDid;
use sp_wire::seal::SecretKey as DidSecretKey;
use sp_wire::units::ESP_PER_PSP;

const USAGE: &str = "\
ecash-wallet [--wallet FILE] [--config FILE] [--regtest|--signet|--testnet] <command>

  The network defaults to mainnet (--mainnet may be given; at most one network
  flag). Before talking to a mint the wallet asks it which network it is on
  and refuses if it is another. The PSP and the ESP are asked over AIR, so
  every command that talks to either needs air.server and air.host, and the
  FSP mints too are asked over AIR, so every fsp command needs the air.fsp
  entry of its service (see the end of this text).

  buy-psp --mint-key HEX
      Make the encrypted payload for a PSP purchase and print it as hex, for
      the OP_RETURN. No amount is given: the payload is the purchase's claim key
      and nothing more, and the PSP mint decides what the payment is worth when
      it handles it. Each purchase gets a throwaway claim key of its own, kept in
      the wallet file, so the PSP mint cannot link two purchases. Pay the payload
      once: a second payment to it is still owed to you and claimed with the
      first, but it links the two. We recommend a PSP purchase of at least $5
      (50 PSP): the PSP mint's fees come out of what a payment buys, so a
      smaller payment can buy little or nothing. Nothing enforces it.
  claim-psp [--wait SECONDS]
      Read what the PSP mint owes for your purchases and claim it. When the PSP
      mint has handled a payment it writes an owed record to the AIR server. This
      reads each purchase's records (a purchase may have several: one for each
      payment to its payload), waiting up to SECONDS (default 60) for a purchase
      whose first record is not there yet, and claims the notes of each record
      with a claim it builds and sends itself: it saves the claim before it sends
      it, and sends the same claim again while the PSP mint has not answered. One
      line is printed for each record: claimed N units, waiting, expired or
      refused. A record must be claimed within 30 days of the wallet first
      reading it; after that the PSP mint keeps the payment, the wallet says so
      with the units, and deletes the purchase's key once every record of it is
      past its window. Needs air.server and air.host. Any other command also
      picks up and claims what is already there when it starts. There is nothing
      to paste. Each purchase is read and claimed on AIR sessions of its own, in
      a random order, with a random 1 to 30 second pause between two purchases
      (so the AIR server cannot tell they are one buyer's): with several
      purchases this takes that much longer. A start of any other command takes
      one purchase only, with no pause, and says how many others are waiting.
  exchange --service DID --psp N [--amounts A,B,C] [--resume ID]
      Exchange at least N PSP for ESP bound to a service (its 33-byte AIR DID,
      66 hex characters). The smallest exchange is 1 PSP. The mint's exchange is exact, so the
      wallet spends whole PSP notes worth at least N and asks for all of their
      value: N PSP of ESP, plus any difference as extra ESP notes (change) under
      the same terms. ESP notes are powers of two: the wallet splits the amount
      (and the change) into the fewest of them. --amounts picks other sizes,
      each a power of two, adding up to the same total.
  --version, -V
      Print ecash-wallet's version, then the version of sp-wire, mint-core and
      air that Cargo.lock locked for this build, one `name version` per line.
      It reads no wallet and no settings and changes nothing.
  receive-psp FILE
      As the SPI's own wallet: take in the PSP that psp-mint reissued to it
      instead of burning (`revenue/<request hash>.json` in the PSP mint's data
      folder, a file with the notes' spend secrets). It is imported and
      swapped at the PSP mint for notes only this wallet knows, the way a PSP
      handoff is, so the file is worth nothing afterwards. The same file taken
      in twice is refused (\"imported already\") and adds nothing. Prints
      `received N PSP in M note(s)`, then the swap's result. Needs air.server
      and air.host for the swap; if the PSP cannot be reached the PSP is in the
      balance, unswapped, and the swap is sent again at the next start.
  receive FILE
      As the service: take the ESP that fsp-mint's `export-esp` wrote (a file
      per redeemable-after day, with the notes' spend secrets) into this wallet,
      so it can be redeemed. This is its only use: the wallet no longer writes
      such files (the old `hand-over` and `transfer` commands are gone; `fsp
      issue` carries the ESP to the FSP mint over AIR).
  balance
      What the wallet holds and what is waiting.
  handoff export-psp --to DID --psp N [--out FILE]
      A PSP handoff, developer to user (after an in-app purchase): free PSP
      notes adding up to exactly N, sealed to the recipient's DID public key
      (DID, 66 hex characters), so only the holder of the matching secret key
      can open it. It carries PSP only, never a DID key. The notes leave this
      wallet, kept as a pending handoff until you reclaim, cancel or finish it.
      The string starts SPHP2:. This replaces the old send-psp token.
  handoff export-fsp --fsp SERVICE:UNITS... --did-key-file FILE [--out FILE]
      An FSP handoff, to your own new device: a little FSP (enough to pay to
      fetch your wallet from the AIR) and the DID secret key from FILE (64 hex
      characters). NOT ENCRYPTED: it holds the key it would be encrypted to.
      Anyone who sees it can spend the notes and act as your DID. Move it in
      person or by QR code, never over a network. The string starts SPHF2:.
      To show either as a QR code, pipe the output to `qrencode -t ANSIUTF8`
      (about 20 notes fit one code; see DESIGN.md).
  handoff import STRING|FILE|- [--did-key-file FILE] [--did-key-out FILE]
                 [--from NAME]
      Take a handoff in; the kind is read from its start. It is checked against
      the key sets this wallet has seen, and refused if damaged, of another
      version, or imported before. The old SPH1: handoff is refused.
      A PSP handoff (SPHP2:) needs --did-key-file, the secret key of the DID it
      was sealed to. The notes count in the balance at once and are swapped at
      the PSP mint for fresh notes only this wallet knows, now and at every
      start while the mint is out of reach (`balance` shows how much is still
      unswapped). Until the swap goes through the sender can still reclaim.
      An FSP handoff (SPHF2:) is never swapped. Its DID key is written to
      --did-key-out (required), never printed. Fetch your wallet from the AIR
      afterwards and run `merge FILE` on it.
  handoff list
      The handoffs made and taken in.
  handoff check ID
      Ask the PSP mint where a PSP handoff you made stands, from its record of
      which notes are spent: none (still yours to reclaim), all (the receiver
      has it: the handoff is done), or some (the rest can be reclaimed).
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
  blacklist list
      The FSP mints this wallet blacklisted after they failed the key check (see
      fsp.blacklist_on_key_mismatch), with when, where and what failed.
  blacklist remove --service DID
      Take an FSP mint off the blacklist, by hand: the only way an entry is ever
      removed. Its dropped notes are not brought back.
  merge FILE
      Merge a copy of this wallet retrieved from storage (a wallet file) into
      this one: notes united, anything spent in either copy stays spent,
      pending requests merged once each. Save this wallet back to storage.
  redeem --service-key-file FILE --memo TEXT [--max-bytes N]
      As the service (FILE holds its 32 byte secret key as 64 hex characters,
      like fsp-mint's service_key.hex; a file that group or others can read is
      refused, and the key is never typed on the command line): redeem every free ESP
      note for that service whose redeemable-after day has come, mixed days
      allowed, for a payout to TEXT (for example btc:ADDRESS). The fee rate and
      the ceiling on one request come from the mint's GET /fees (--max-bytes
      lowers the ceiling). A redemption over the ceiling is split into several
      requests, each with its own fee and payout entry. Shows the size and fee
      of each request before it is sent.
  redeem --service-key-file FILE --resume ID
      Send a pending redemption again (after a lost reply or a fault).
  redeem --collect
      Ask the mint about every redemption queued for payout: completed ones end,
      declined ones give the reissued notes back with the operator's reason.
  config
      Print the settings in use and where each came from: the storage policy
      (storage.wallet, the AIR services that back up the wallet, and
      storage.app, each an ordered list of service IDs, first preferred),
      from config.toml beside the wallet file (or --config FILE, or
      $ECASH_CONFIG) and $ECASH_STORAGE_WALLET and $ECASH_STORAGE_APP.
      Nothing reads or writes the AIR yet.
  fsp issue --service DID [--esp UNITS | --psp N]
      Hand ESP for a service to its FSP mint for FSP, 1:1 less its issue fee.
      All of the service's ESP by default, any day, mature or not.
  fsp pay --service DID --units N [--memo TEXT]
      Pay N FSP units to the service, with change.
  fsp sync --service DID
      What runs on its own: finish pending FSP requests, read the mint's keys,
      and swap FSP on the previous keyset to the current one.
  fsp-window --service DID
      The FSP mint's rotation schedule (its rotation call): current and previous
      keysets with their start and retire times, and the next rotation.
  esp-schedule [--by YYYY-MM-DD]
      When this wallet's ESP is redeemable: now, by DATE, and by month.

  The fsp commands always need --service: there is no default. storage.wallet
  lists the AIR services that back up the wallet; it is not the service FSP is
  paid to.

  At startup, and every time it talks to an FSP mint, the wallet checks that
  mint's keys and rolls FSP on the previous keyset over to the current one.
  It asks nothing; a failure is logged and tried again next time.

  Every mint publishes its keys on AIR, and before anything from a mint's reply
  is stored the wallet checks that each key the mint signed with is the key it
  published (the PSP's and the FSP mints' key sets; the ESP's keys for the
  service and day, and the redeemable day of a new exchange). A mint that fails
  is warned about loudly, naming it, what failed and where; nothing from its
  reply is stored, and the notes and the pending request are kept. With
  fsp.blacklist_on_key_mismatch on (an ASO's setting, off by default) a failing
  FSP mint is also blacklisted and its notes are dropped; the SPI's PSP and ESP
  mints are never blacklisted.

The wallet file is --wallet, else $ECASH_WALLET_FILE, else
~/.ecash-wallet/<network>/wallet.json (main, regtest, signet, testnet).

The PSP and the ESP are reached over AIR only: their mint info (which network and
wire version), keys, keysets, rotation window, fees, rollover, check-state,
exchange and redeem are all AIR requests. config.toml's [air] section
(or ECASH_AIR_SERVER and ECASH_AIR_HOST) must name the AIR server and its host;
without them a command that talks to the PSP or the ESP fails, saying which
setting is missing. The PSP and the ESP each have their own DID, built in
(PLACEHOLDERS until the first SPI deploy, and the wallet says so whenever one is
in use); air.psp_did (ECASH_AIR_PSP_DID) and air.esp_did (ECASH_AIR_ESP_DID)
override them. The FSP mints are reached over AIR too: a service's mint is the
service's DID, on the AIR server of its air.fsp entry (ECASH_AIR_FSP), written
<service DID>@<AIR server key>@<host>, one entry for each service (`fsp-mint
serve` prints its entry). An fsp command for a service with no entry is refused,
naming air.fsp. No call the wallet makes is HTTP. `config` prints every setting.";

/// The arguments left after flags are taken out, and the name of the command
/// they belong to (`balance`, `handoff check`, `fsp pay`), so an error about
/// them can say which command it is. The name is empty until the command is known.
struct Args(Vec<String>, String);

impl Args {
    /// Take `--name VALUE`, if present.
    fn flag(&mut self, name: &str) -> Result<Option<String>, WalletError> {
        let Some(at) = self.0.iter().position(|a| a == name) else {
            return Ok(None);
        };
        if at + 1 >= self.0.len() {
            return Err(WalletError::Invalid(match self.1.as_str() {
                "" => format!("{name} needs a value"),
                command => format!("{command}: {name} needs a value"),
            }));
        }
        let value = self.0.remove(at + 1);
        self.0.remove(at);
        Ok(Some(value))
    }

    /// Take `--name`, which has no value, if present.
    fn switch(&mut self, name: &str) -> bool {
        match self.0.iter().position(|a| a == name) {
            Some(at) => {
                self.0.remove(at);
                true
            }
            None => false,
        }
    }

    fn rest(self) -> Vec<String> {
        self.0
    }

    /// Fail if anything is left over.
    fn done(self) -> Result<(), WalletError> {
        match self.0.first() {
            Some(extra) => Err(WalletError::Invalid(format!(
                "{}: unexpected argument `{extra}`. It is run as: {}",
                self.1,
                run_as(&self.1)
            ))),
            None => Ok(()),
        }
    }
}

/// How a command is run, from its line in the help text (the first, for a
/// command with several): `ecash-wallet handoff check ID`.
fn run_as(command: &str) -> String {
    let line = USAGE.lines().find(|l| {
        l.starts_with("  ")
            && !l.starts_with("   ")
            && (l.trim() == command
                || l.trim().starts_with(&format!("{command} "))
                || l.contains(&format!("| {command} ")))
    });
    match line {
        Some(l) => format!("ecash-wallet {}", l.trim()),
        None => format!("ecash-wallet {command} (see --help)"),
    }
}

/// The error for a command given the wrong number of arguments: which command it
/// is, what it takes, and how it is run.
fn takes(command: &str, what: &str) -> WalletError {
    WalletError::Invalid(format!("{command} takes {what}: {}", run_as(command)))
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
    Ok(base.join(network()).join("wallet.json"))
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

/// The `[air]` settings of this run, set once in `run`. Empty until then, and a
/// call to the PSP or the ESP made with them empty fails, naming what is missing.
static AIR: std::sync::OnceLock<AirSettings> = std::sync::OnceLock::new();

/// `psp.unpaid_key_days` of this run, set once in `run`.
static UNPAID_KEY_DAYS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// `psp.unpaid_key_days` of this run (the default before `run` sets it).
fn unpaid_key_days() -> u64 {
    UNPAID_KEY_DAYS
        .get()
        .copied()
        .unwrap_or(ecash_wallet::psp::DEFAULT_UNPAID_KEY_DAYS)
}

/// Drop the claim keys that the pickup just found with no record and that are
/// older than `psp.unpaid_key_days`, and say so once for each. Returns the ids
/// dropped.
fn expire_unpaid(
    wallet: &mut Wallet,
    picked: &[ecash_wallet::mint_info::PickedUp],
    prefix: &str,
) -> Vec<String> {
    let checked: Vec<String> = picked
        .iter()
        .filter(|p| p.no_record)
        .map(|p| p.id.clone())
        .collect();
    match wallet.expire_unpaid(now_secs(), unpaid_key_days(), &checked) {
        Ok(lost) => {
            for loss in &lost {
                eprintln!("{prefix}WARNING: {}", loss.said());
            }
            lost.into_iter().map(|l| l.id).collect()
        }
        Err(e) => {
            eprintln!("{prefix}unpaid purchases not expired, retried on the next run: {e}");
            Vec::new()
        }
    }
}

/// The `[air]` settings of this run (empty before `run` sets them).
fn air_settings() -> AirSettings {
    AIR.get().cloned().unwrap_or_default()
}

/// What the first check of each mint (the PSP, the ESP) in this run came to: a
/// mint is checked at startup and again by the command, and a dead mint costs
/// `air.attempts` tries of `air.reply_wait_secs` each time, so the answer is
/// kept for the run.
static CHECKED: std::sync::Mutex<Vec<(config::Party, Result<(), String>)>> =
    std::sync::Mutex::new(Vec::new());

/// Check a mint's wire version and network over AIR before anything else is sent
/// to it (to that mint's own DID: see `ecash_wallet::mint_info`).
fn verify_mint_of(wallet: &mut Wallet, party: config::Party) -> Result<(), WalletError> {
    let air = air_settings();
    let mut checked = CHECKED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, result)) = checked.iter().find(|(p, _)| *p == party) {
        return result.clone().map_err(WalletError::Mint);
    }
    let result = match party {
        config::Party::Psp => ecash_wallet::mint_info::verify_psp(wallet, &air, network()),
        config::Party::Esp => ecash_wallet::mint_info::verify_esp(wallet, &air, network()),
        config::Party::Fsp(service) => {
            ecash_wallet::mint_info::verify_fsp(wallet, &air, service, network())
        }
    };
    checked.push((
        party,
        result.as_ref().map(|_| ()).map_err(|e| e.to_string()),
    ));
    result
}

/// Check the PSP (`verify_mint_of`) and give the name its records use (its live
/// keysets, its swap times, the mint a handoff names): the PSP's DID in lowercase
/// hex, as for an FSP. The PSP is never dialled; it is reached over AIR, by DID.
fn psp_base(wallet: &mut Wallet) -> Result<String, WalletError> {
    verify_mint_of(wallet, config::Party::Psp)?;
    Ok(ecash_wallet::fsp::record_of(air_settings().psp_did()))
}

/// Check the ESP (`verify_mint_of`) and give the name its records use: the ESP's
/// DID in lowercase hex, as for the PSP.
fn esp_base(wallet: &mut Wallet) -> Result<String, WalletError> {
    verify_mint_of(wallet, config::Party::Esp)?;
    Ok(ecash_wallet::fsp::record_of(air_settings().esp_did()))
}

/// The steps every command that uses the wallet starts with, and that use the
/// network: the FSP mints are checked, what the PSP mint owes is picked up and
/// claimed, and the PSP and ESP key sets are kept live. A command takes a `Startup` and runs it once its own arguments have been
/// read and checked (a command that forgot to would leave the value unused, which
/// the compiler warns about), so a user error never waits on the network.
#[must_use = "a command runs the startup steps once its arguments are checked"]
struct Startup(());

impl Startup {
    fn new() -> Startup {
        Startup(())
    }

    /// Run the startup steps.
    fn run(self, wallet: &mut Wallet) {
        startup_fsp_sync(wallet);
        startup_psp(wallet);
        startup_rotation_sync(wallet);
    }

    /// The same without the pickup and the claim, for `claim-psp`, which reads
    /// and claims the PSP mint's records itself, waits for the first record of a
    /// purchase and says every result. The windows that have closed are still
    /// closed first.
    fn run_for_claim(self, wallet: &mut Wallet) {
        startup_fsp_sync(wallet);
        close_expired_psp(wallet);
        startup_rotation_sync(wallet);
    }
}

fn buy_psp(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    if args.switch("--sync") {
        return Err(WalletError::Invalid(
            "--sync was removed: the payload names no keyset and buy-psp asks the PSP mint nothing, so there is nothing to sync. `claim-psp` reads the PSP mint's current keyset when it claims"
                .into(),
        ));
    }
    if args.flag("--reply-did")?.is_some() {
        return Err(WalletError::Invalid(
            "--reply-did was removed: every purchase makes a throwaway claim key of its own (so the PSP mint cannot link two purchases) and keeps its secret in the wallet file. What the PSP mint owes is picked up and claimed with `claim-psp`"
                .into(),
        ));
    }
    let mint_key = args
        .flag("--mint-key")?
        .ok_or_else(|| WalletError::Invalid("--mint-key HEX is required".into()))?;
    if args.0.first().is_some_and(|a| a.parse::<u64>().is_ok()) {
        return Err(WalletError::Invalid(format!(
            "buy-psp takes no AMOUNT any more: the payload is the purchase's claim key alone, and the PSP mint decides what the payment is worth. It is run as: {}",
            run_as("buy-psp")
        )));
    }
    args.done()?;
    let mint_key = sp_wire::seal::parse_public_key(&mint_key)
        .map_err(|e| WalletError::Invalid(e.to_string()))?;
    // Every flag is read before the network is used: a user error never depends
    // on it.
    start.run(wallet);
    let built = wallet.build_psp_payload(&mint_key)?;
    eprintln!("purchase {}", built.id);
    eprintln!("{}", ecash_wallet::psp::PAY_ONCE);
    eprintln!(
        "{} bytes. Put the hex below in an OP_RETURN of a Bitcoin payment to the PSP mint's wallet. Once the payment has its confirmations the PSP mint writes what you are owed over AIR: `claim-psp` reads it and claims your notes, and any command does so when it starts. Each payment's record must be claimed within 30 days of the PSP mint writing it.",
        built.payload.len()
    );
    eprintln!("{}", ecash_wallet::psp::RECOMMENDED_PURCHASE);
    println!("{}", hex::encode(&built.payload));
    Ok(())
}

/// How long `claim-psp` waits for the PSP mint's first record of a purchase, in
/// seconds, when `--wait` does not say.
const PICKUP_WAIT_SECS: u64 = 60;

/// The lines about one purchase's pickup: each cell that did not open, a record
/// with nothing due, and a purchase that could not be read. A record that was read
/// is said by its claim, and a purchase with no record yet only when `waiting` asks
/// (`claim-psp` does; a start does not mention it).
fn pickup_lines(p: &ecash_wallet::mint_info::PickedUp, waiting: bool) -> Vec<String> {
    let id = &p.id;
    let mut lines = Vec::new();
    for (index, why) in &p.skipped {
        lines.push(format!(
            "purchase {id}: record {index} was skipped, and the next record is read: {why}"
        ));
    }
    for r in p.new.iter().filter(|r| r.due_units == 0) {
        lines.push(format!(
            "purchase {id}, record {} (payment {}): nothing is due. The PSP mint's fees take the whole payment, so nothing can be claimed and the payment is lost",
            r.index, r.txid
        ));
    }
    if let Some(why) = &p.problem {
        lines.push(format!("purchase {id}: not read: {why}"));
    }
    if waiting && p.no_record {
        lines.push(format!(
            "purchase {id}: no record from the PSP mint yet. It writes the record once the payment has its confirmations; run `claim-psp` again later"
        ));
    }
    lines
}

/// Seconds since the Unix epoch.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One line about one record's claim.
fn claim_line(r: &ecash_wallet::mint_info::ClaimReport) -> String {
    use ecash_wallet::mint_info::ClaimOutcome;
    let (id, index) = (&r.id, r.index);
    match &r.what {
        ClaimOutcome::Claimed(s) => format!(
            "purchase {id}, record {index}: claimed {} units in {} note(s)",
            s.units,
            s.claimed.len()
        ),
        ClaimOutcome::Waiting {
            attempts,
            window_ends,
        } => format!(
            "purchase {id}, record {index}: waiting: the claim ({attempts} built) is sent and the PSP mint has not answered. The same claim is sent again at the next start, until {}",
            format_utc(*window_ends)
        ),
        ClaimOutcome::NotAccepted { loss, attempts } => loss.not_accepted(*attempts),
        ClaimOutcome::NotSent(why) => format!("purchase {id}, record {index}: not sent: {why}"),
        ClaimOutcome::Failed(why) => format!(
            "purchase {id}, record {index}: not claimed, tried again at the next start: {why}"
        ),
    }
}

/// Claim the PSP mint's owed records (see `mint_info::psp_claim`), checking the
/// PSP mint's network first when there is something to send.
fn claim_records(
    wallet: &mut Wallet,
) -> Result<Vec<ecash_wallet::mint_info::ClaimReport>, WalletError> {
    if wallet.open_claims(now_secs()).is_empty() {
        return Ok(Vec::new());
    }
    air_settings().require().map_err(WalletError::Invalid)?;
    psp_base(wallet)?;
    ecash_wallet::mint_info::psp_claim(wallet, &air_settings())
}

/// At startup, and before anything is read: close the claim window of the records
/// whose window has passed. Each one that still has a saved claim gets it sent one
/// last time, identical (the PSP mint answers it even after the deadline); an
/// answer settles the record. What is left is forgotten: the PSP mint keeps a
/// payment that is still unclaimed then, so nothing can come for it, and a
/// purchase's key goes once every record of it is past its window. A record whose
/// last resend could not be sent (the AIR settings are missing, or the AIR server
/// cannot be reached) is not forgotten: it is kept and closed at the next start.
/// Says what it settled, what it kept and what it lost; changes nothing otherwise.
fn close_expired_psp(wallet: &mut Wallet) {
    match ecash_wallet::mint_info::psp_close_expired(wallet, &air_settings(), now_secs()) {
        Ok(closed) => say_closed(closed),
        Err(e) => eprintln!("psp: closed records not deleted, retried on the next run: {e}"),
    }
}

/// The lines about a close: what the last resends settled, what was kept for the
/// next start and what was lost.
fn say_closed(closed: ecash_wallet::mint_info::Closed) {
    use ecash_wallet::mint_info::ClaimOutcome;
    for r in &closed.reports {
        match &r.what {
            ClaimOutcome::Failed(why) => eprintln!(
                "psp: purchase {}, record {}: the last resend before the window closed failed: {why}",
                r.id, r.index
            ),
            _ => eprintln!("psp: {}", claim_line(r)),
        }
    }
    for r in &closed.kept {
        let (ClaimOutcome::Failed(why) | ClaimOutcome::NotSent(why)) = &r.what else {
            continue;
        };
        eprintln!(
            "psp: purchase {}, record {}: its window has closed, and the last resend of its claim could not be sent ({why}). The purchase is kept, and the resend is tried again at the next start",
            r.id, r.index
        );
    }
    for loss in closed.lost {
        eprintln!("psp: {}", loss.said());
    }
}

fn claim_psp(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    let wait = match args.flag("--wait")? {
        Some(text) => number(&text, "--wait")?,
        None => PICKUP_WAIT_SECS,
    };
    if args.flag("--file")?.is_some() || !args.0.is_empty() {
        return Err(WalletError::Invalid(
            "claim-psp takes no signatures any more (no --file, no standard input, no pairs). The PSP mint writes what each purchase is owed to the AIR server and this command reads it and claims it: run it with nothing, or with --wait SECONDS"
                .into(),
        ));
    }
    start.run_for_claim(wallet);
    if wallet.claim_keys().is_empty() {
        println!("no pending purchases");
        return Ok(());
    }
    air_settings().require().map_err(WalletError::Invalid)?;
    psp_base(wallet)?;
    let picked = ecash_wallet::mint_info::psp_pickup(wallet, &air_settings(), wait)?;
    let expired = expire_unpaid(wallet, &picked, "");
    let mut said = !expired.is_empty();
    let mut no_record = 0;
    for p in picked.iter().filter(|p| !expired.contains(&p.id)) {
        for line in pickup_lines(p, true) {
            println!("{line}");
            said = true;
        }
        if p.no_record {
            no_record += 1;
        }
    }
    let mut unclaimed = 0;
    let reports = claim_records(wallet)?;
    for r in &reports {
        println!("{}", claim_line(r));
        said = true;
        if !matches!(r.what, ecash_wallet::mint_info::ClaimOutcome::Claimed(_)) {
            unclaimed += 1;
        }
    }
    // What is owed and was not claimed or said above (the AIR server could not be
    // reached part way): with the date its window ends.
    for open in wallet.open_claims(now_secs()) {
        if reports
            .iter()
            .any(|r| r.id == open.id && r.index == open.index)
        {
            continue;
        }
        println!(
            "purchase {}, record {} (payment {}): {} PSP owed, not claimed yet. It can be claimed until {}",
            open.id,
            open.index,
            open.txid,
            open.due_units,
            format_utc(open.window_ends)
        );
        said = true;
        unclaimed += 1;
    }
    if !said {
        println!("nothing to claim");
    }
    if no_record > 0 {
        return Err(WalletError::Unknown(format!(
            "{no_record} purchase(s) have no record from the PSP mint yet (waited {wait} s)"
        )));
    }
    if unclaimed > 0 {
        return Err(WalletError::Unknown(format!(
            "{unclaimed} record(s) are not claimed yet"
        )));
    }
    Ok(())
}

/// What `exchange` was asked to do, read from its flags before the ESP is
/// contacted.
enum ExchangeAsk {
    /// `--resume ID`: send a pending exchange again.
    Resume(ExchangeBuild),
    /// `--service DID --psp N [--amounts A,B,C]`: build a new one.
    New {
        service: ServiceDid,
        psp: u64,
        amounts: Option<Vec<u64>>,
    },
}

fn exchange(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    // Every flag is read, and a missing or bad one refused, before the ESP is
    // asked anything: a user error never depends on the network.
    let ask = match args.flag("--resume")? {
        Some(id) => {
            args.done()?;
            let pending = wallet
                .pending_exchanges()
                .iter()
                .find(|p| p.id == id)
                .ok_or_else(|| WalletError::Unknown(format!("no pending exchange {id}")))?;
            ExchangeAsk::Resume(ExchangeBuild {
                id: pending.id.clone(),
                request: pending.request.clone(),
                psp_spent: pending
                    .request
                    .psp_inputs
                    .iter()
                    .map(|i| i.amount.units)
                    .sum(),
                change_esp: pending.change_esp,
            })
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
            ExchangeAsk::New {
                service: service_did(&service)?,
                psp,
                amounts,
            }
        }
    };
    start.run(wallet);
    let base = esp_base(wallet)?;
    let built: ExchangeBuild = match ask {
        ExchangeAsk::Resume(built) => built,
        ExchangeAsk::New {
            service,
            psp,
            amounts,
        } => {
            ecash_wallet::mint_info::sync_esp_keysets(wallet, &air_settings(), &base)?;
            ecash_wallet::mint_info::sync_esp_limits(wallet, &air_settings())?;
            wallet.build_exchange(psp, service, amounts.as_deref())?
        }
    };
    eprintln!("exchange {} (spends {} PSP)", built.id, built.psp_spent);
    match ecash_wallet::mint_info::send_exchange(wallet, &air_settings(), &built.request) {
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
/// confused with `--service-key-file`, a service's secret key, see
/// `service_key_from_file`.)
fn service_did(text: &str) -> Result<ServiceDid, WalletError> {
    ServiceDid::parse(text).map_err(|e| WalletError::Invalid(e.to_string()))
}

/// The service's secret key from a file of 64 hex characters (as fsp-mint's
/// `service_key.hex`). A file that group or others can read is refused: the key
/// is the service's identity, and a key typed on a command line stays in the
/// shell history and shows in the process list.
fn service_key_from_file(path: &str) -> Result<SecretKey, WalletError> {
    owner_only_key_file(path, "the service key file", "the service's secret key")?;
    let text = std::fs::read_to_string(path).map_err(|e| {
        WalletError::Invalid(format!("cannot read the service key file {path}: {e}"))
    })?;
    let bytes = hex::decode(text.trim())
        .map_err(|_| WalletError::Invalid(format!("the service key file {path} must hold hex")))?;
    SecretKey::from_slice(&bytes).map_err(|_| {
        WalletError::Invalid(format!(
            "the service key file {path} must hold a 32 byte secret key (64 hex characters)"
        ))
    })
}

/// Refuse a key file that group or others can read (any of mode `0o077`),
/// before it is read: `what` names the file, `holds` what is in it.
fn owner_only_key_file(path: &str, what: &str, holds: &str) -> Result<(), WalletError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| WalletError::Invalid(format!("cannot read {what} {path}: {e}")))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(WalletError::Invalid(format!(
            "{what} {path} can be read by group or others (mode {:03o}): it holds {holds}. Make it owner-only: chmod 600 {path}",
            mode & 0o777
        )));
    }
    Ok(())
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

/// Take the ESP an FSP mint kept for this service (`fsp-mint export-esp`) into
/// the wallet.
fn receive(wallet: &mut Wallet, args: Args, start: Startup) -> Result<(), WalletError> {
    let rest = args.rest();
    let [path] = rest.as_slice() else {
        return Err(takes("receive", "one file"));
    };
    let text = std::fs::read_to_string(path)?;
    // sp-wire's own parse of the file `fsp-mint export-esp` writes.
    let handover = Handover::read(text.as_bytes())
        .map_err(|e| WalletError::Invalid(format!("{path}: {e}")))?;
    start.run(wallet);
    let (count, units) = wallet.receive_handover(&handover)?;
    println!(
        "received {units} ESP in {count} note(s) for {}, redeemable after day {}",
        hex::encode(handover.service.serialize()),
        handover.redeemable_after_day
    );
    Ok(())
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
        match ecash_wallet::mint_info::send_redeem(wallet, &air_settings(), &pending.body()?) {
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
                    "the outcome is unknown. Send the same request again with: redeem --service-key-file FILE --resume {id}"
                );
                return Err(e);
            }
        }
    }
    Err(WalletError::Mint(format!(
        "the mint kept asking for other outputs. Redemption {id} is pending: try --resume"
    )))
}

fn redeem(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    // Every flag is read, and a missing or bad one refused, before the ESP is
    // asked anything: a user error never depends on the network.
    let collect = match args.0.iter().position(|a| a == "--collect") {
        Some(at) => {
            args.0.remove(at);
            true
        }
        None => false,
    };
    if collect {
        args.done()?;
        start.run(wallet);
        esp_base(wallet)?;
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
            send_redemption(wallet, None, id)?;
        }
        return Ok(());
    }
    let key = match args.flag("--service-key-file")? {
        Some(file) => Some(service_key_from_file(&file)?),
        None => None,
    };
    if let Some(id) = args.flag("--resume")? {
        args.done()?;
        start.run(wallet);
        esp_base(wallet)?;
        return send_redemption(wallet, key.as_ref(), id);
    }
    let key =
        key.ok_or_else(|| WalletError::Invalid("--service-key-file FILE is required".into()))?;
    let memo = args.flag("--memo")?.ok_or_else(|| {
        WalletError::Invalid("--memo TEXT (where the payout goes) is required".into())
    })?;
    let max_bytes = match args.flag("--max-bytes")? {
        Some(n) => Some(number(&n, "--max-bytes")?),
        None => None,
    };
    args.done()?;
    start.run(wallet);
    let base = esp_base(wallet)?;
    let mut fees = ecash_wallet::mint_info::fetch_redeem_fees(wallet, &air_settings())?;
    fees.caller_max_bytes = max_bytes;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ecash_wallet::mint_info::sync_esp_keysets(wallet, &air_settings(), &base)?;
    let plan = wallet.plan_redemption(&key, &memo, &fees, now)?;
    for line in plan.lines(&fees) {
        eprintln!("{line}");
    }
    let built = plan.built;
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
        if let Err(e) = send_redemption(wallet, Some(&key), b.id)
            && let Some(line) = later_failure_line(&mut first_error, e)
        {
            eprintln!("{line}");
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

fn balance(wallet: &mut Wallet, args: Args, start: Startup) -> Result<(), WalletError> {
    args.done()?;
    start.run(wallet);
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
            "       {unknown_units} FSP in {unknown} note(s) whose service is not known (from a wallet file written before FSP notes recorded their service): they are not spent"
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
    let now = now_secs();
    for k in wallet.claim_keys() {
        let owed: Vec<_> = k
            .records
            .iter()
            .filter(|r| !r.done && r.is_open(now))
            .collect();
        if k.records.is_empty() {
            println!(
                "pending purchase {} (no record from the PSP mint yet)",
                k.id
            );
        } else if !owed.is_empty() {
            println!(
                "pending purchase {} ({} PSP owed in {} record(s), not claimed yet)",
                k.id,
                owed.iter().map(|r| u128::from(r.due_units)).sum::<u128>(),
                owed.len()
            );
        }
    }
    for p in wallet.pending_exchanges() {
        println!("pending exchange {}", p.id);
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

/// A DID secret key from a file of 64 hex characters. A file that group or
/// others can read is refused, as the service key file is: the key is the DID,
/// and the wallet writes it owner-only itself (`--did-key-out`).
fn did_key_from_file(path: &str) -> Result<DidSecretKey, WalletError> {
    owner_only_key_file(path, "the DID key file", "your DID's secret key")?;
    let text = std::fs::read_to_string(path)?;
    let bytes = hex::decode(text.trim()).map_err(|_| {
        WalletError::Invalid(format!("{path}: a DID secret key is 64 hex characters"))
    })?;
    DidSecretKey::from_bytes(&bytes)
        .map_err(|_| WalletError::Invalid(format!("{path}: a DID secret key is 64 hex characters")))
}

fn handoff(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    if args.0.is_empty() {
        return Err(WalletError::Invalid(
            "handoff needs export-psp, export-fsp, import, check, reclaim, list, cancel or done. Run with --help"
                .into(),
        ));
    }
    let what = args.0.remove(0);
    args.1 = format!("handoff {what}");
    match what.as_str() {
        "export-psp" => handoff_export_psp(wallet, args, start),
        "export-fsp" => handoff_export_fsp(wallet, args, start),
        "export" => Err(WalletError::Invalid(
            "`handoff export` was split in two, because the combined handoff could be built in ways that are not allowed. Use `handoff export-psp` (a developer to a user: PSP only, sealed to the user's DID) or `handoff export-fsp` (your own new device: FSP and your DID key)".into(),
        )),
        "import" => handoff_import(wallet, args, start),
        "list" => {
            args.done()?;
            start.run(wallet);
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
                return Err(takes("handoff check", "one handoff ID"));
            };
            start.run(wallet);
            let standing = ecash_wallet::mint_info::check_handoff(wallet, &air_settings(), id)?;
            print_standing(id, &standing);
            Ok(())
        }
        "reclaim" => {
            let rest = args.rest();
            let [id] = rest.as_slice() else {
                return Err(takes("handoff reclaim", "one handoff ID"));
            };
            start.run(wallet);
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
                return Err(takes("handoff cancel", "one handoff ID"));
            };
            start.run(wallet);
            let n = wallet.cancel_handoff(id)?;
            println!(
                "put back {n} note(s) without asking the mint. If the other wallet already has the handoff, it holds the same secrets: the first of you to swap or spend a note wins. For a PSP handoff, `handoff reclaim` lets the mint decide first"
            );
            Ok(())
        }
        "done" => {
            let rest = args.rest();
            let [id] = rest.as_slice() else {
                return Err(takes("handoff done", "one handoff ID"));
            };
            start.run(wallet);
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
    if let Some(path) = out
        && std::path::Path::new(path).exists()
    {
        return Err(WalletError::Invalid(format!(
            "{path} exists; not overwritten"
        )));
    }
    Ok(())
}

fn handoff_export_psp(
    wallet: &mut Wallet,
    mut args: Args,
    start: Startup,
) -> Result<(), WalletError> {
    let to = args.flag("--to")?.ok_or_else(|| {
        WalletError::Invalid(
            "a PSP handoff is sealed to the recipient: give their DID public key with --to (66 hex characters)".into(),
        )
    })?;
    let psp = args
        .flag("--psp")?
        .ok_or_else(|| WalletError::Invalid("give the amount with --psp N".into()))?;
    let psp = u128::from(number(&psp, "--psp")?);
    let out = args.flag("--out")?;
    args.done()?;
    check_out_file(&out)?;
    let recipient = sp_wire::seal::parse_public_key(&to)
        .map_err(|e| WalletError::Invalid(format!("--to: {e}")))?;
    start.run(wallet);
    let ids = wallet.select_psp_handoff(psp)?;
    psp_base(wallet)?;
    let made = wallet.export_psp_handoff(&ids, air_settings().psp_did(), &recipient)?;
    handoff_deliver(&made, out)
}

fn handoff_export_fsp(
    wallet: &mut Wallet,
    mut args: Args,
    start: Startup,
) -> Result<(), WalletError> {
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
    start.run(wallet);
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

fn handoff_import(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
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
            start.run(wallet);
            wallet.import_psp_handoff(&text, &key, air_settings().psp_did(), &from)?
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
            start.run(wallet);
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
    for service in &got.fsp_mints {
        sync_and_log(wallet, *service);
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

/// `receive-psp FILE`: take in the file psp-mint wrote for the SPI's own wallet.
/// The file is read and checked as far as it can be without the wallet
/// ([`ecash_wallet::handoff::check_psp_file`]) before the startup steps use the
/// network; the import then checks it against the wallet and stores the swap
/// ([`Wallet::import_psp_file`]), and the swap at the PSP is sent like a PSP
/// handoff's. A file taken in before is refused and nothing changes.
fn receive_psp(wallet: &mut Wallet, args: Args, start: Startup) -> Result<(), WalletError> {
    let rest = args.rest();
    let [path] = rest.as_slice() else {
        return Err(takes("receive-psp", "one file"));
    };
    let bytes = std::fs::read(path)?;
    let named = |e: WalletError| match e {
        WalletError::Invalid(why) => WalletError::Invalid(format!("{path}: {why}")),
        other => other,
    };
    ecash_wallet::handoff::check_psp_file(&bytes).map_err(named)?;
    start.run(wallet);
    let got = wallet
        .import_psp_file(&bytes, air_settings().psp_did(), "psp-mint")
        .map_err(named)?;
    println!(
        "received {} PSP in {} note(s) (handoff {}, swapping at the mint)",
        got.psp_units,
        got.notes.len(),
        got.id
    );
    for w in &got.warnings {
        eprintln!("warning: {w}");
    }
    for line in ecash_wallet::mint_info::complete_import(wallet, &air_settings(), &got) {
        println!("{line}");
    }
    Ok(())
}

fn merge_command(wallet: &mut Wallet, args: Args, start: Startup) -> Result<(), WalletError> {
    let rest = args.rest();
    let [path] = rest.as_slice() else {
        return Err(takes("merge", "one wallet file"));
    };
    start.run(wallet);
    let r = wallet.merge_file(std::path::Path::new(path))?;
    println!(
        "merged {path}: {} note(s) added, {} removed because the other copy spent them, {} pending request(s) added, {} ended, {} purchase key(s) added; version {}",
        r.notes_added,
        r.notes_removed,
        r.requests_added,
        r.requests_dropped,
        r.claim_keys_added,
        r.version
    );
    println!("Save this wallet back to storage: it is now the current copy.");
    Ok(())
}

/// `blacklist list` and `blacklist remove --service DID`: the FSP mints this
/// wallet blacklisted after a failed key check. Nothing removes an entry but
/// `remove`.
fn blacklist_command(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    if args.0.is_empty() {
        return Err(WalletError::Invalid(
            "blacklist needs list or remove. Run with --help".into(),
        ));
    }
    let what = args.0.remove(0);
    args.1 = format!("blacklist {what}");
    match what.as_str() {
        "list" => {
            args.done()?;
            if wallet.blacklist().is_empty() {
                println!("no FSP mint is blacklisted");
            }
            for entry in wallet.blacklist() {
                println!(
                    "{}: blacklisted {} at {}: {}",
                    entry.service.to_hex(),
                    format_utc(entry.at),
                    entry.site,
                    entry.what
                );
            }
            Ok(())
        }
        "remove" => {
            let service = match args.flag("--service")? {
                Some(text) => service_did(&text)?,
                None => {
                    return Err(WalletError::Invalid(format!(
                        "blacklist remove needs --service DID: {}",
                        run_as("blacklist remove")
                    )));
                }
            };
            args.done()?;
            if wallet.unblacklist(&service)? {
                println!(
                    "removed the FSP mint of service {} from the blacklist. Requests to it are sent again; the notes dropped when it was blacklisted are not brought back",
                    service.to_hex()
                );
                Ok(())
            } else {
                Err(WalletError::Unknown(format!(
                    "the FSP mint of service {} is not blacklisted",
                    service.to_hex()
                )))
            }
        }
        other => Err(WalletError::Invalid(format!(
            "blacklist {other} is not a command: blacklist list, blacklist remove --service DID"
        ))),
    }
}

fn today() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

/// Check every FSP mint this wallet has used. Nothing is asked; problems are
/// logged and tried again next time.
/// At startup: keep PSP and ESP on a live key set (see `rotate.rs`), for the
/// mints (over AIR), when this wallet holds notes of that kind. Quiet when the
/// mint is not reachable; a missing `air.server` or `air.host` is said.
fn startup_rotation_sync(wallet: &mut Wallet) {
    for kind in [ecash_wallet::Kind::Psp, ecash_wallet::Kind::Esp] {
        let holds = wallet.notes().iter().any(|n| n.kind == kind)
            || wallet.pending_rollovers().iter().any(|p| p.kind == kind);
        if !holds {
            continue;
        }
        let (name, checked) = if kind == ecash_wallet::Kind::Psp {
            ("psp", psp_base(wallet))
        } else {
            ("esp", esp_base(wallet))
        };
        let base = match checked {
            Ok(base) => base,
            Err(e @ WalletError::Invalid(_)) => {
                eprintln!("{name}: key rotation not checked: {e}");
                continue;
            }
            Err(_) => continue,
        };
        match ecash_wallet::mint_info::rotation_sync(wallet, &air_settings(), kind, &base) {
            Ok(lines) => {
                for l in lines {
                    eprintln!("{name}: {l}");
                }
            }
            Err(e) => eprintln!("{name}: key rotation check failed, retried on the next run: {e}"),
        }
    }
}

/// At startup: ONE purchase, drawn at random, has what its closed windows leave
/// closed, its next record read (one read, no waiting; `claim-psp` waits for the
/// first record of a purchase) and what it is owed claimed, with no pause
/// (`mint_info::psp_one_purchase`). The other purchases wait for a later start, or
/// for `claim-psp`, which takes them all with a random pause of 1 to 30 seconds
/// between two; a line says how many are waiting. A purchase with no record yet,
/// and a claim that is waiting for the PSP mint's answer, are not mentioned (the
/// same claim is sent again at the next start). A missing `air.server` or
/// `air.host` is said, as a note.
fn startup_psp(wallet: &mut Wallet) {
    let purchases = wallet.claim_keys().len();
    if purchases == 0 {
        return;
    }
    let air = air_settings();
    let one = match ecash_wallet::mint_info::psp_one_purchase(wallet, &air, network(), now_secs()) {
        Ok(one) => one,
        Err(e) => {
            eprintln!("psp: closed records not deleted, retried on the next run: {e}");
            return;
        }
    };
    say_closed(one.closed);
    if let Err(e) = air.require() {
        eprintln!(
            "psp: {purchases} purchase(s) are held, and the PSP mint's records for them are not checked: {e}"
        );
        return;
    }
    match &one.picked {
        Some(Ok(p)) => {
            let expired = expire_unpaid(wallet, std::slice::from_ref(p), "psp: ");
            if !expired.contains(&p.id) {
                for line in pickup_lines(p, false) {
                    eprintln!("psp: {line}");
                }
            }
        }
        Some(Err(e)) => {
            eprintln!("psp: the PSP mint's records were not checked, retried on the next run: {e}")
        }
        None => {}
    }
    match &one.claims {
        Some(Ok(reports)) => {
            for r in reports {
                if !matches!(
                    r.what,
                    ecash_wallet::mint_info::ClaimOutcome::Waiting { .. }
                ) {
                    eprintln!("psp: {}", claim_line(r));
                }
            }
        }
        Some(Err(e @ WalletError::Invalid(_))) => {
            eprintln!("psp: the records waiting to be claimed were not checked: {e}")
        }
        Some(Err(e)) => eprintln!(
            "psp: the records waiting to be claimed were not checked, retried on the next run: {e}"
        ),
        None => {}
    }
    if one.others_pending > 0 {
        eprintln!(
            "psp: {} other purchase(s) are pending and were not checked at this start (one is checked per start, so the AIR server cannot tie them together); run claim-psp to check them all now",
            one.others_pending
        );
    }
}

fn startup_fsp_sync(wallet: &mut Wallet) {
    let services: Vec<String> = wallet.fsp_mints().keys().cloned().collect();
    for service in services {
        let Ok(key) = service_did(&service) else {
            continue;
        };
        sync_and_log(wallet, key);
    }
}

/// Check a service's FSP mint (its network and wire version first, over AIR) and
/// run the FSP sync, logging what it did. A failure, a service with no `air.fsp`
/// entry included, is logged and tried again next time.
fn sync_and_log(wallet: &mut Wallet, service: ServiceDid) {
    let air = air_settings();
    let result = verify_mint_of(wallet, config::Party::Fsp(service))
        .and_then(|_| ecash_wallet::mint_info::fsp_sync(wallet, &air, service));
    match result {
        Ok(sync) => {
            for line in sync.log {
                eprintln!("fsp {service}: {line}");
            }
        }
        Err(e) => eprintln!("fsp {service}: not checked, tried again next time: {e}"),
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

fn fsp(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    if args.0.is_empty() {
        return Err(WalletError::Invalid(
            "fsp needs issue, pay or sync. Run with --help".into(),
        ));
    }
    let what = args.0.remove(0);
    args.1 = format!("fsp {what}");
    let service = fsp_service(&mut args)?;
    // Every flag is read, and a missing or bad one refused, before any mint is
    // asked anything: a user error never depends on the network.
    let ask = match what.as_str() {
        "sync" => {
            args.done()?;
            FspAsk::Sync
        }
        "issue" => {
            let units: Option<u128> = match (args.flag("--esp")?, args.flag("--psp")?) {
                (Some(e), None) => Some(u128::from(number(&e, "--esp")?)),
                (None, Some(p)) => Some(u128::from(number(&p, "--psp")?) * u128::from(ESP_PER_PSP)),
                (None, None) => None,
                _ => return Err(WalletError::Invalid("give --esp or --psp, not both".into())),
            };
            args.done()?;
            FspAsk::Issue(units)
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
            FspAsk::Pay { units, memo }
        }
        other => {
            return Err(WalletError::Invalid(format!(
                "unknown fsp command `{other}`"
            )));
        }
    };
    // The service's mint is reached through its air.fsp entry: without one the
    // command is refused here, naming the setting, before anything is sent.
    let air = air_settings();
    air.fsp_for(service).map_err(WalletError::Invalid)?;
    start.run(wallet);
    verify_mint_of(wallet, config::Party::Fsp(service))?;
    // Every connection: pending requests, keys, rollover.
    let sync = ecash_wallet::mint_info::fsp_sync(wallet, &air, service)?;
    for line in sync.log {
        eprintln!("fsp {service}: {line}");
    }
    match ask {
        FspAsk::Sync => Ok(()),
        FspAsk::Issue(units) => {
            let fees = ecash_wallet::mint_info::fsp_fees(wallet, &air, service)?;
            let request = wallet.build_fsp_issue(service, units, fees.issue_fee_per_byte)?;
            let id = request.hash();
            println!("issue {id}: {} group(s)", request.groups.len());
            println!(
                "{}",
                ecash_wallet::mint_info::settle_fsp(wallet, &air, &id)?
            );
            Ok(())
        }
        FspAsk::Pay { units, memo } => {
            let request = wallet.build_fsp_spend(service, units, &memo)?;
            let id = request.hash();
            println!("spend {id}");
            println!(
                "{}",
                ecash_wallet::mint_info::settle_fsp(wallet, &air, &id)?
            );
            Ok(())
        }
    }
}

/// What `fsp` was asked to do, read from its flags before any mint is contacted.
enum FspAsk {
    Sync,
    Issue(Option<u128>),
    Pay { units: u64, memo: String },
}

fn fsp_window(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    let service = service_did(
        &args
            .flag("--service")?
            .ok_or_else(|| WalletError::Invalid("--service DID is needed".into()))?,
    )?;
    args.done()?;
    let air = air_settings();
    air.fsp_for(service).map_err(WalletError::Invalid)?;
    start.run(wallet);
    sync_and_log(wallet, service);
    let w = ecash_wallet::mint_info::fsp_rotation(wallet, &air, service)?;
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

fn esp_schedule(wallet: &mut Wallet, mut args: Args, start: Startup) -> Result<(), WalletError> {
    let by = match args.flag("--by")? {
        Some(d) => Some(ecash_wallet::date::parse_date(&d).map_err(WalletError::Invalid)?),
        None => None,
    };
    args.done()?;
    start.run(wallet);
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
    println!(
        "PSP and ESP calls (mint info, keys, keysets, rotation, fees, rollover, check-state, exchange, redeem): over AIR only, through air.server and air.host"
    );
    println!(
        "FSP mint calls (mint info, keys, rotation, fees, issue, spend): over AIR only, through the air.fsp entry of the service ({} entries)",
        air.fsp.len()
    );
    if let Err(why) = air.require() {
        println!("WARNING: {why}");
    }
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
    Ok(())
}

fn run(raw: Vec<String>) -> Result<(), WalletError> {
    // `--version` reads no wallet and no settings and touches nothing.
    if raw.iter().any(|a| a == "--version" || a == "-V") {
        for line in ecash_wallet::version::lines() {
            println!("{line}");
        }
        return Ok(());
    }
    let mut args = Args(raw, String::new());
    let wallet_flag = args.flag("--wallet")?;
    let config_flag = args.flag("--config")?;
    let _ = NETWORK.set(take_network(&mut args)?);
    if args.0.is_empty() || args.0.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.0.remove(0);
    args.1 = command.clone();
    let path = wallet_path(wallet_flag)?;
    let loaded = load_settings(&path, config_flag)?;
    if command == "config" {
        return config_command(&loaded, args);
    }
    let settings = loaded.settings;
    let _ = AIR.set(settings.air.clone());
    let _ = UNPAID_KEY_DAYS.set(settings.psp_unpaid_key_days);
    // AIR on with a built-in PLACEHOLDER DID (the PSP's, the ESP's) must never
    // pass silently.
    for warning in settings.air.placeholder_warnings() {
        eprintln!("{warning}");
    }
    let mut wallet = Wallet::open(&path, network())?;
    // What to do about a mint that fails the key check, and the threads that
    // follow the mints' key streams (a command that asks no mint skips them).
    wallet.set_key_policy(settings.key_policy());
    if command != "blacklist" {
        wallet.start_key_feed(&settings.air)?;
    }
    // The startup steps use the network, so a command runs them itself once its
    // own arguments are read and checked: a user error never waits on the network.
    let start = Startup::new();
    match command.as_str() {
        "fsp" => fsp(&mut wallet, args, start),
        "fsp-window" => fsp_window(&mut wallet, args, start),
        "esp-schedule" => esp_schedule(&mut wallet, args, start),
        "buy-psp" => buy_psp(&mut wallet, args, start),
        "claim-psp" => claim_psp(&mut wallet, args, start),
        "exchange" => exchange(&mut wallet, args, start),
        "receive" => receive(&mut wallet, args, start),
        "redeem" => redeem(&mut wallet, args, start),
        "balance" => balance(&mut wallet, args, start),
        "receive-psp" => receive_psp(&mut wallet, args, start),
        "send-psp" | "sent" => Err(WalletError::Invalid(format!(
            "`{command}` was removed. A PSP handoff replaces it: `handoff export-psp --to DID --psp N` to give PSP, `handoff import` to take it, `handoff check ID` and `handoff reclaim ID` for what `sent --check` and `sent --reclaim` did."
        ))),
        "handoff" => handoff(&mut wallet, args, start),
        "merge" => merge_command(&mut wallet, args, start),
        "blacklist" => blacklist_command(&mut wallet, args),
        other => Err(WalletError::Invalid(format!(
            "unknown command `{other}`. Run with --help"
        ))),
    }
}

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(WalletError::KeyMismatch(_)) => {
            // The warning was printed when the check failed; once is enough.
            eprintln!(
                "error: the key check failed. Nothing from the reply was stored. See the warning above"
            );
            ExitCode::FAILURE
        }
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
        let mut args = Args(vec!["--units".into(), "5".into()], String::new());
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
        let mut args = Args(
            vec![
                "--service".into(),
                did.clone(),
                "--units".into(),
                "5".into(),
            ],
            String::new(),
        );
        assert_eq!(fsp_service(&mut args).unwrap().to_hex(), did);
        assert_eq!(args.0, vec!["--units".to_string(), "5".to_string()]);
    }
}
