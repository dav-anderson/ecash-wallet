# ecash-wallet

One wallet library for PSP, ESP and FSP (Primary, Encumbered and Fast Service Points), with a thin command line. AIR apps embed the library. The command line only parses arguments and prints, so everything it does is a call into the library.

The library holds no BTC wallet. The app's own Bitcoin wallet puts the bytes from `build_psp_payload` in an OP_RETURN and pays.

## Status

Built and tested: the library, the command line and the end-to-end regtest runs in [REGTEST.md](REGTEST.md) (steps 0 to 49: purchase, claim, exchange, transfer, redemption, FSP, refusals, splitting, and key rotation). What each release contains is in [CHANGELOG.md](CHANGELOG.md). What is not built is in [ROADMAP.md](../sandbox-mint/ROADMAP.md).

## Setup

The wallet builds from tagged dependencies: mint-core at `v0.1.3` and `sp-wire` at `v0.2.0` (git tags), and, through `sp-wire`'s `seal` feature, the `air` crate at commit `8e281d5` (AIR 2.0.3; AIR has no tags). **It does not depend on the mint crates.** Every type it exchanges with the mints, the PSP payload and its encryption, the request hashes, the unit constants and the error codes come from `sp-wire` (see "Wire format and versions"). The mints (`psp-mint`, `esp-mint`, `fsp-mint`, each `v0.1.2`) are dev-dependencies only: the tests start real ones in the process, and nothing in the library or the command line links them.

AIR 2.0.3 has no path dependencies, so nothing needs patching to build it from git. To test against unpushed local copies of `sp-wire`, the mints or mint-core, `source ~/sandbox-mint/scripts/local-git.sh` points git at the local folders and their local tags.

```
cd ~/ecash-wallet
cargo test
```

The `http` feature is on by default. It adds the HTTP client and the command line. An app that sends requests its own way can turn it off and use only the library.

## Settings

| Setting | Default | What it is |
|---|---|---|
| `--wallet FILE`, or `$ECASH_WALLET_FILE` | `~/.ecash-wallet/<network>/wallet.json` | The wallet file: notes, spend keys and requests in flight. One file per network (`main`, `regtest`, `signet`, `testnet`). `0600` permissions. |
| `--regtest`, `--signet`, `--testnet` (`--mainnet` may be given) | mainnet | The network. At most one. The wallet asks each mint's `GET /health` for its network and wire version and stops on a mismatch. |
| `$ECASH_PSP_URL` | `http://127.0.0.1:3000` | The PSP mint. |
| `$ECASH_ESP_URL` | `http://127.0.0.1:3100` | The ESP mint. |
| `$ECASH_FSP_URL` | `http://127.0.0.1:3200` | An FSP mint (one used before is remembered per service). |
| the `http` cargo feature | on | The HTTP client and the command line. An app that sends requests its own way can turn it off and use only the library. |

The wallet file holds spend keys. Losing it loses the notes and the blinding factors for anything in flight. A missing file is an empty wallet; a file that cannot be read is an error and is never replaced. More in [DESIGN.md](DESIGN.md), "Notes and the wallet file".

## Wire version

Every mint's `GET /health` returns `wire_version`, and the wallet refuses a mint whose number is not its own (`WalletError::Wire`, naming both). The types come from [`sp-wire`](../sp-wire/README.md). Details in [DESIGN.md](DESIGN.md), "Wire format and versions".

## Command line

**Network.** The wallet is on mainnet unless given `--regtest`, `--signet` or `--testnet` (`--mainnet` may be given; at most one). Before it sends anything to a mint it asks the mint's `GET /health` which wire version it speaks and which network it is on, and stops if the mint is on another wire version or network or does not say; nothing is sent. Every walkthrough below passes `--regtest`. The wallet file is per network (see "Notes and the wallet file").

```
ecash-wallet [--wallet FILE] [--regtest|--signet|--testnet] <command>
```

| Command | What it does |
|---|---|
| `buy-psp --mint-key HEX [--reply-did HEX] [--psp-url URL] AMOUNT...` | Prints the encrypted payload as hex on standard output and the purchase id on standard error. With `--psp-url` it first reads the PSP's live key sets and its largest note size; the payload names the PSP's key set, and a size above the PSP's largest is refused. Without it the payload names the key set the wallet last saw, if any, and only the power of two is checked. |
| `claim-psp [--psp-url URL] [--file FILE\|-] [BLIND_NONCE:SIGNATURE...]` | Claims the PSP's signatures. With no file or pairs it reads standard input. |
| `exchange --service HEX --psp N [--amounts A,B,C] [--esp-url URL] [--resume ID]` | Exchanges at least N PSP (N is 1 or more) for ESP bound to a service (32-byte x-only key, hex). Whole PSP notes are spent and the difference comes back as ESP change. `--resume` sends a pending request again. |
| `hand-over --service HEX (--esp UNITS \| --psp N) [--day D] --out FILE` | As the app: take whole ESP notes for that service that add up to exactly the amount out of the wallet and write them, with their spend secrets, to a new file (`0600`; an existing file is never replaced). Refused if no set of notes adds up to the amount. |
| `receive FILE` | As the service: take a hand-over file into this wallet. |
| `transfer --service-key HEX [--day D] [--amounts A,B,C] [--esp-url URL] [--resume ID]` | As the service: swap every free ESP note this wallet holds for the service (the one the 32-byte secret key belongs to) for fresh notes of the same total. `--amounts` chooses the new sizes, which must add up to the same total. `--resume` sends a pending request again. |
| `balance` | PSP, ESP (by service and day) and FSP held, and what is waiting. |
| `redeem --service-key HEX --memo TEXT [--max-bytes N] [--esp-url URL]` | As the service: redeem every mature free ESP note for that service (mixed days allowed) for a payout to TEXT. Reads the rate and ceiling from `GET /fees`, prints each request's size and fee, splits over the ceiling, and on `refund_required` or `outputs_over_limit` rebuilds from the mint's totals and sends again. |
| `redeem --service-key HEX --resume ID [--esp-url URL]` | Send a pending redemption again after a lost reply or fault. |
| `redeem --collect [--esp-url URL]` | Ask about every redemption waiting for payout: completed ones end, declined ones give back the reissued notes with the reason. |
| `fsp issue --service HEX [--esp UNITS \| --psp N] [--fsp-url URL]` | Issue FSP from this wallet's free ESP for the service (all of it if no amount). |
| `fsp pay --service HEX --units N [--memo TEXT] [--fsp-url URL]` | Pay N FSP units to the service, with change. |
| `fsp sync --service HEX [--fsp-url URL]` | Finish pending FSP requests and roll previous-keyset FSP over now (it also happens on every connection and at startup). |
| `fsp-window --service HEX [--fsp-url URL]` | Print the FSP mint's rotation schedule (`GET /rotation`). |
| `esp-schedule --service HEX [--by YYYY-MM-DD]` | ESP mature now, mature by the date, and by month, from the wallet's notes. |
| `migrate` | Move a pre-network `~/.ecash-wallet/wallet.json` to `regtest/`. |

URLs default to `$ECASH_PSP_URL`, `$ECASH_ESP_URL` and `$ECASH_FSP_URL`, else `http://127.0.0.1:3000`, `http://127.0.0.1:3100` and `http://127.0.0.1:3200` (an FSP mint used before is remembered per service).

`--service-key` is a secret key, passed on the command line only because this is a development tool. A real service keeps its DID key in the AIR and never types it. Shell history keeps what is typed, so use it for test keys only.

## Regtest walkthrough

The end-to-end runs (steps 0 to 49: purchase, claim, exchange, transfer, redemption, FSP, refusals, splitting, and key rotation on ESP and FSP) are in [REGTEST.md](REGTEST.md). They were run against a real Bitcoin Core regtest node. Run them in order: each continues the one before.

## Tests

```
cargo test --all-features
cargo fmt --check
```

The tests run in one process with real mints (psp-mint, esp-mint and fsp-mint are dev-dependencies at their release tags) and no network. What they cover is in [DESIGN.md](DESIGN.md), "Tests". The regtest runs in [REGTEST.md](REGTEST.md) are the end-to-end tests with a real Bitcoin node.

## Documentation

- [DESIGN.md](DESIGN.md): how each part of the library works and why.
- [CHANGELOG.md](CHANGELOG.md): what was built and what changed.
- [REGTEST.md](REGTEST.md): the end-to-end walkthrough.
- [ROADMAP.md](../sandbox-mint/ROADMAP.md) (in `sandbox-mint`): left to do and not decided yet, for every repo.
- [sandbox-mint README](../sandbox-mint/README.md): the family of repos.
