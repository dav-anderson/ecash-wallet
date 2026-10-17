# ecash-wallet

One wallet library for PSP, ESP and FSP (Primary, Encumbered and Fast Service Points), with a thin command line. AIR apps embed the library. The command line only parses arguments and prints, so everything it does is a call into the library.

The library holds no BTC wallet. The app's own Bitcoin wallet puts the bytes from `build_psp_payload` in an OP_RETURN and pays.

## Status

Built and tested: the library, the command line and the end-to-end regtest runs in [REGTEST.md](REGTEST.md) (steps 0 to 49: purchase, claim, exchange, transfer, redemption, FSP, refusals, splitting, and key rotation). What each release contains is in [CHANGELOG.md](CHANGELOG.md). What is not built is in [ROADMAP.md](../sandbox-mint/ROADMAP.md).

## Setup

The wallet builds from tagged dependencies: mint-core at `v0.1.3` and `sp-wire` at `v0.4.0` (git tags), and, through `sp-wire`'s `seal` feature, the `air` crate at commit `8e281d5` (AIR 2.0.3; AIR has no tags). **It does not depend on the mint crates.** Every type it exchanges with the mints, the PSP payload and its encryption, the request hashes, the unit constants and the error codes come from `sp-wire` (see "Wire format and versions"). The mints (`psp-mint` `v0.2.1`, `esp-mint` `v0.3.0`, `fsp-mint` `v0.2.1`) are dev-dependencies only: the tests start real ones in the process, and nothing in the library or the command line links them.

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
| `--config FILE`, or `$ECASH_CONFIG` | `config.toml` beside the wallet file | The settings file (TOML). If named, it must exist. |
| `$ECASH_STORAGE_WALLET`, or `[storage] wallet` in the file | none (local only) | Which AIR services will keep the wallet file: service IDs (64 hex), comma-separated in the environment, an array or one string in the file. Index 0 is the primary; one is valid; at most 8. **The primary is the storage service that FSP fees are paid to** (the default `--service` of the `fsp` commands). **Setting only: nothing reads or writes the AIR yet.** |
| `$ECASH_STORAGE_APP`, or `[storage] app` | none (local only) | The same for the app's own data. Checked and reported; the app uses it. |
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
| `exchange --service HEX --psp N [--amounts A,B,C] [--esp-url URL] [--resume ID]` | Exchanges at least N PSP (N is 1 or more) for ESP bound to a service (32-byte x-only key, hex). Whole PSP notes are spent and the difference comes back as ESP change. ESP notes are powers of two, so the amount and the change are each split into the fewest of them (`--amounts` picks other sizes, each a power of two, with the same total). `--resume` sends a pending request again. There is no command to split ESP you hold: convert it to FSP straight away (see DESIGN.md). |
| `hand-over --service HEX (--esp UNITS \| --psp N) [--day D] --out FILE` | As the app: take whole ESP notes for that service that add up to exactly the amount out of the wallet and write them, with their spend secrets, to a new file (`0600`; an existing file is never replaced). Refused if no set of notes adds up to the amount. |
| `receive FILE` | As the service: take a hand-over file into this wallet. |
| `transfer --service-key HEX [--day D] [--amounts A,B,C] [--esp-url URL] [--resume ID]` | As the service: swap every free ESP note this wallet holds for the service (the one the 32-byte secret key belongs to) for fresh notes of the same total, split into the fewest powers of two. `--amounts` chooses other sizes, each a power of two, which must add up to the same total. `--resume` sends a pending request again. |
| `balance` | PSP, ESP (by service and day) and FSP held, and what is waiting. Shows the storage service and the FSP held for it. |
| `config` | The settings in use and where each came from, and the storage service for FSP fees. |
| `redeem --service-key HEX --memo TEXT [--max-bytes N] [--esp-url URL]` | As the service: redeem every mature free ESP note for that service (mixed days allowed) for a payout to TEXT. Reads the rate and ceiling from `GET /fees`, prints each request's size and fee, splits over the ceiling, and on `refund_required` or `outputs_over_limit` rebuilds from the mint's totals and sends again. |
| `redeem --service-key HEX --resume ID [--esp-url URL]` | Send a pending redemption again after a lost reply or fault. |
| `redeem --collect [--esp-url URL]` | Ask about every redemption waiting for payout: completed ones end, declined ones give back the reissued notes with the reason. |
| `fsp issue --service HEX [--esp UNITS \| --psp N] [--fsp-url URL]` | Issue FSP from this wallet's free ESP for the service (all of it if no amount). |
| `fsp pay --service HEX --units N [--memo TEXT] [--fsp-url URL]` | Pay N FSP units to the service, with change. |
| `fsp sync --service HEX [--fsp-url URL]` | Finish pending FSP requests and roll previous-keyset FSP over now (it also happens on every connection and at startup). |
| `fsp-window --service HEX [--fsp-url URL]` | Print the FSP mint's rotation schedule (`GET /rotation`). |
| `handoff export [--psp N] [--fsp SERVICE:UNITS]... [--psp-url URL] [--did-key-file FILE] [--out FILE]` | Hand value and identity to another wallet without the AIR: take free notes adding up to exactly those amounts (and, if given, a DID secret key) out of this wallet and print them as one string (`SPH1:...`) on standard output. The warning and the size go to standard error. **The string holds the keys that spend the notes: anyone who sees it can spend them.** See "Handoff between wallets". |
| `handoff import STRING\|FILE\|- [--swap] [--from NAME] [--did-key-out FILE]` | Take a handoff in. Checks it, refuses one imported before, adds the notes and records where they came from. `--swap` swaps them at their mint for notes only this wallet knows (PSP like a received token, FSP as a normal swap), which is what makes them final. A DID key is written to `--did-key-out` (`0600`, never replaced) and is refused without it. |
| `handoff list`, `handoff cancel ID`, `handoff done ID` | The handoffs made and imported. `cancel` puts an unclaimed handoff's notes back. `done` drops them once you know the other wallet has swapped. |
| `merge FILE` | Merge a wallet file retrieved from storage into this wallet (see "Merging two copies of a wallet"). |
| `esp-schedule --service HEX [--by YYYY-MM-DD]` | ESP mature now, mature by the date, and by month, from the wallet's notes. |
| `migrate` | Move a pre-network `~/.ecash-wallet/wallet.json` to `regtest/`. |

URLs default to `$ECASH_PSP_URL`, `$ECASH_ESP_URL` and `$ECASH_FSP_URL`, else `http://127.0.0.1:3000`, `http://127.0.0.1:3100` and `http://127.0.0.1:3200` (an FSP mint used before is remembered per service).

`--service-key` is a secret key, passed on the command line only because this is a development tool. A real service keeps its DID key in the AIR and never types it. Shell history keeps what is typed, so use it for test keys only.

## Handoff between wallets

`handoff export` and `handoff import` move PSP notes, FSP notes and a DID secret key from one wallet to another as one string, with no AIR, mint or network in between (a QR code works too: see below). The notes leave the sender's balance when the string is made. The receiver checks the string and adds the notes. Without `--swap` they are the same secrets as the sender's, so whoever spends first wins; with `--swap` the receiver swaps them at the mint for fresh notes, and then only the receiver can spend them.

**The string is a bearer secret.** It contains each note's spend key and, if added, the DID secret key. Hand it over in person or on a channel you trust, do not post it, and delete it once it is imported. The command prints this warning on standard error every time.

Size, for the QR code: about 60 + 150 × N characters for N notes of one mint with a 22-character URL, and 48 more with a DID key. One QR code in alphanumeric mode holds about 28 notes at error correction L, or 22 at M; a DID key alone is about 65 characters. More than that goes in a file (`--out`) or several handoffs. The wallet draws no QR code. Pipe the string to a tool: `ecash-wallet handoff export --psp 5 | qrencode -t ANSIUTF8`.

## Merging two copies of a wallet

`merge FILE` merges a wallet file retrieved from storage (an AIR backup, a copy from another device) into this one. Notes are united by identity, a note spent or handed off in either copy stays gone, pending requests are united without duplicates, and the wallet file's `version` counter goes up with every change. Details in [DESIGN.md](DESIGN.md), "Handoff, merge and the service ID".

## Regtest walkthrough

The end-to-end runs (steps 0 to 49: purchase, claim, exchange, transfer, redemption, FSP, refusals, splitting, and key rotation on ESP and FSP) are in [REGTEST.md](REGTEST.md). They were run against a real Bitcoin Core regtest node. Run them in order: each continues the one before.

## Tests

```
cargo test --all-features
cargo fmt --check
```

The tests run in one process with real mints (psp-mint, esp-mint and fsp-mint are dev-dependencies at their release tags) and no network. What they cover is in [DESIGN.md](DESIGN.md), "Tests". Because the mints are at their tags, a change in a mint is not exercised until the tag moves: before a release in which a mint and the wallet change together, run `sh ~/sandbox-mint/scripts/test-wallet-against-local-mints.sh`, which runs these tests against the esp-mint, psp-mint and fsp-mint folders on this machine without changing any repo (and then fsp-mint's, psp-mint's and esp-mint's tests). It also takes `sp-wire` from its folder, because `Cargo.toml` names the `v0.4.0` tag, which does not exist until sp-wire is released. Until the tags move, the wallet's `redeem_flow`, `fsp_flow`, `rotation_flow` and `handoff_flow` build only this way, because they set a field the esp-mint tag does not have. The regtest runs in [REGTEST.md](REGTEST.md) are the end-to-end tests with a real Bitcoin node.

## Documentation

- [DESIGN.md](DESIGN.md): how each part of the library works and why.
- [CHANGELOG.md](CHANGELOG.md): what was built and what changed.
- [REGTEST.md](REGTEST.md): the end-to-end walkthrough.
- [ROADMAP.md](../sandbox-mint/ROADMAP.md) (in `sandbox-mint`): left to do and not decided yet, for every repo.
- [sandbox-mint README](../sandbox-mint/README.md): the family of repos.
