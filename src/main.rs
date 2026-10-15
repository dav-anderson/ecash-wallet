//! The command line. It parses arguments and prints; every step is a call into
//! the library.

use std::env;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use ecash_wallet::esp::ExchangeBuild;
use ecash_wallet::psp::parse_signatures;
use ecash_wallet::store::parse_did;
use ecash_wallet::{Wallet, WalletError, http};
use secp256k1::XOnlyPublicKey;

const DEFAULT_PSP_URL: &str = "http://127.0.0.1:3000";
const DEFAULT_ESP_URL: &str = "http://127.0.0.1:3100";

const USAGE: &str = "\
ecash-wallet [--wallet FILE] <command>

  buy-psp --mint-key HEX [--reply-did HEX] AMOUNT...
      Make the encrypted payload for a PSP purchase and print it as hex, for
      the OP_RETURN. AMOUNT is each note's size in PSP (a power of two).
  claim-psp [--psp-url URL] [--file FILE|-] [BLIND_NONCE:SIGNATURE...]
      Turn the PSP's signatures into notes. Paste the PSP's output into a file,
      or pass pairs. With neither, reads standard input.
  exchange --service HEX --psp N [--amounts A,B,C] [--esp-url URL] [--resume ID]
      Exchange N PSP for ESP bound to a service (32 byte x-only key, hex).
  balance
      What the wallet holds and what is waiting.
  transfer | redeem | fsp
      Not built yet.

The wallet file is --wallet, else $ECASH_WALLET_FILE, else
~/.ecash-wallet/wallet.json. URLs default to $ECASH_PSP_URL / $ECASH_ESP_URL,
else http://127.0.0.1:3000 and http://127.0.0.1:3100.";

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
            Some(extra) => Err(WalletError::Invalid(format!("unexpected argument `{extra}`"))),
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
    Ok(PathBuf::from(home).join(".ecash-wallet").join("wallet.json"))
}

fn url(flag: Option<String>, var: &str, default: &str) -> String {
    flag.or_else(|| env::var(var).ok())
        .unwrap_or_else(|| default.to_string())
}

fn buy_psp(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let mint_key = args
        .flag("--mint-key")?
        .ok_or_else(|| WalletError::Invalid("--mint-key HEX is required".into()))?;
    let reply = match args.flag("--reply-did")? {
        Some(text) => parse_did(&text)?,
        None => wallet.reply_did()?,
    };
    let amounts = args
        .rest()
        .iter()
        .map(|a| number(a, "an amount"))
        .collect::<Result<Vec<_>, _>>()?;
    let mint_key = psp_mint::seal::parse_public_key(&mint_key)
        .map_err(|e| WalletError::Invalid(e.to_string()))?;
    let built = wallet.build_psp_payload(&amounts, &reply, &mint_key)?;
    eprintln!("purchase {}", built.id);
    eprintln!("{} bytes. Put the hex below in an OP_RETURN and pay the PSP.", built.payload.len());
    println!("{}", hex::encode(&built.payload));
    Ok(())
}

fn claim_psp(wallet: &mut Wallet, mut args: Args) -> Result<(), WalletError> {
    let base = url(args.flag("--psp-url")?, "ECASH_PSP_URL", DEFAULT_PSP_URL);
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
            return Err(WalletError::Invalid("give --file or pairs, not both".into()));
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
        eprintln!("skipped {} signature(s) that are not for this wallet", all.len() - signatures.len());
    }
    let keys = http::fetch_psp_keys(&base)?;
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
    let base = url(args.flag("--esp-url")?, "ECASH_ESP_URL", DEFAULT_ESP_URL);
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
            }
        }
        None => {
            let service = args
                .flag("--service")?
                .ok_or_else(|| WalletError::Invalid("--service HEX is required".into()))?;
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
            let bytes = hex::decode(service.trim())
                .map_err(|_| WalletError::Invalid("the service must be hex".into()))?;
            let service = XOnlyPublicKey::from_slice(&bytes).map_err(|_| {
                WalletError::Invalid("the service must be a 32 byte x-only key (64 hex characters)".into())
            })?;
            wallet.build_exchange(psp, service, amounts.as_deref())?
        }
    };
    eprintln!("exchange {}", built.id);
    match http::send_exchange(&base, &built.request) {
        Ok(response) => {
            let done = wallet.finish_exchange(&built.id, &response)?;
            println!(
                "received {} ESP in {} note(s), redeemable after day {}",
                done.esp_units,
                done.notes.len(),
                done.redeemable_after_day
            );
            if done.credit_esp > 0 {
                println!("the mint recorded {} ESP as credit", done.credit_esp);
            }
            Ok(())
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

fn balance(wallet: &Wallet, args: Args) -> Result<(), WalletError> {
    args.done()?;
    let b = wallet.balance();
    println!("psp  {}", b.psp);
    println!("esp  {}", b.esp);
    for ((service, day), units) in &b.esp_by_terms {
        println!("       {units} for {service}, redeemable after day {day}");
    }
    println!("fsp  {}", b.fsp);
    println!("notes {} ({} held for a pending request)", b.notes, b.reserved);
    for p in wallet.pending_purchases() {
        println!("pending purchase {} ({} output(s) unsigned)", p.id, p.outputs.len());
    }
    for p in wallet.pending_exchanges() {
        println!("pending exchange {}", p.id);
    }
    Ok(())
}

fn run(raw: Vec<String>) -> Result<(), WalletError> {
    let mut args = Args(raw);
    let wallet_flag = args.flag("--wallet")?;
    if args.0.is_empty() || args.0.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.0.remove(0);
    if matches!(command.as_str(), "transfer" | "redeem" | "fsp") {
        let mut wallet = Wallet::open(&wallet_path(wallet_flag)?)?;
        return match command.as_str() {
            "transfer" => wallet.transfer_esp(),
            "redeem" => wallet.redeem_esp(),
            _ => wallet.get_fsp(),
        };
    }
    let mut wallet = Wallet::open(&wallet_path(wallet_flag)?)?;
    match command.as_str() {
        "buy-psp" => buy_psp(&mut wallet, args),
        "claim-psp" => claim_psp(&mut wallet, args),
        "exchange" => exchange(&mut wallet, args),
        "balance" => balance(&wallet, args),
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
