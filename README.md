# ecash-wallet

One wallet library for PSP, ESP and FSP (Primary, Encumbered and Fast Service Points), with a thin command line. AIR apps embed the library. The command line only parses arguments and prints, so everything it does is a call into the library.

The library holds no BTC wallet. The app's own Bitcoin wallet puts the bytes from `build_psp_payload` in an OP_RETURN and pays.

## Status

Built and tested: the library, the command line and the end-to-end regtest runs in [REGTEST.md](REGTEST.md) (steps 0 to 49: purchase, claim, exchange, transfer, redemption, FSP, refusals, splitting, and key rotation). What each release contains is in [CHANGELOG.md](CHANGELOG.md). What is not built is in [ROADMAP.md](../sandbox-mint/ROADMAP.md).

## Setup

The wallet builds from tagged dependencies: mint-core at `v0.1.3` and `sp-wire` at `v0.4.0` (git tags), and, through `sp-wire`'s `seal` feature, the `air` crate at commit `8e281d5` (AIR 2.0.3; AIR has no tags). The next sp-wire (0.4.1) moves it to AIR 2.1.0 (commit `741b1cf`) with the same sealed bytes, the same key types and `WIRE_VERSION` 2, and the wallet's code does not change for it. **It does not depend on the mint crates.** Every type it exchanges with the mints, the PSP payload and its encryption, the request hashes, the unit constants and the error codes come from `sp-wire` (see "Wire format and versions"). The mints (`psp-mint` `v0.3.0`, `esp-mint` `v0.5.0`, `fsp-mint` `v0.4.0`) are dev-dependencies only: the tests start real ones in the process, and nothing in the library or the command line links them.

AIR has no path dependencies, so nothing needs patching to build it from git as it is. AIR 2.1.0 does not export `SecretKey` yet, so until sp-wire 0.4.1 is tagged and its AIR pin is a commit that does, the wallet is built against the local `sp-wire` and AIR folders with a git-ignored `.cargo/config.toml` (sp-wire's README shows the AIR block). The repo's committed `Cargo.lock` keeps sp-wire at `v0.4.0` and cargo then reports the patch as "was not used", so run `cargo update -p sp-wire` once after adding the patches, check that `cargo tree --all-features -i air` shows the local AIR folder, and run `git restore Cargo.lock` before committing (a lock file that names a local path would not build from GitHub). To test against unpushed local copies of `sp-wire`, the mints or mint-core, `source ~/sandbox-mint/scripts/local-git.sh` points git at the local folders and their local tags.

```
cd ~/ecash-wallet
cargo test
```

The `http` feature is on by default. It adds the HTTP client and the command line. An app that sends requests its own way can turn it off and use only the library.

The `air` feature is on by default too. It adds the PSP's mint info, keys, keysets, rotation, rollover and check-state over AIR (see "The PSP's calls over AIR"), through sp-wire's `air-client` feature, which builds `air_server`. `air_server` names AIR as `path = "../air"` (upstream issue 3), so building with `air` takes a local patch for it beside the AIR one in the git-ignored `.cargo/config.toml`, and the AIR patch must be the folder `<air_server>/../air`, or two `air` crates are built and their types do not match. For now both are the sandbox checkouts (`.../sandbox-mint/air-sandbox/air` and `.../air_server`; sp-wire's README, "The AIR request", shows the blocks). An app that does not want AIR turns the feature off (`default-features = false, features = ["http"]`). `cargo update -p sp-wire` and `git restore Cargo.lock` apply as above.

## Settings

| Setting | Default | What it is |
|---|---|---|
| `--wallet FILE`, or `$ECASH_WALLET_FILE` | `~/.ecash-wallet/<network>/wallet.json` | The wallet file: notes, spend keys and requests in flight. One file per network (`main`, `regtest`, `signet`, `testnet`). `0600` permissions. |
| `--regtest`, `--signet`, `--testnet` (`--mainnet` may be given) | mainnet | The network. At most one. The wallet asks each mint's `GET /health` for its network and wire version and stops on a mismatch. |
| `--config FILE`, or `$ECASH_CONFIG` | `config.toml` beside the wallet file | The settings file (TOML). If named, it must exist. |
| `$ECASH_STORAGE_WALLET`, or `[storage] wallet` in the file | none (local only) | Which AIR services will keep the wallet file: service DIDs (66 hex: a 33-byte AIR DID, `02` or `03` then the 64 hex characters of its x coordinate), comma-separated in the environment, an array or one string in the file. Index 0 is the primary; one is valid; at most 8. **The primary is the storage service that FSP fees are paid to** (the default `--service` of the `fsp` commands). **Setting only: nothing reads or writes the AIR yet.** |
| `$ECASH_STORAGE_APP`, or `[storage] app` | none (local only) | The same for the app's own data. Checked and reported; the app uses it. |
| `$ECASH_PSP_URL` | `http://127.0.0.1:3000` | The PSP mint. |
| `$ECASH_ESP_URL` | `http://127.0.0.1:3100` | The ESP mint. |
| `$ECASH_FSP_URL` | `http://127.0.0.1:3200` | An FSP mint (one used before is remembered per service). |
| `$ECASH_AIR_PSP_DID`, or `[air] psp_did` | the built-in SPI DID | The SPI's DID (66 hex), replacing the one built into the wallet. **The built-in one is a PLACEHOLDER until the first SPI deploy**, and the wallet warns at every start and in `config` while AIR is on and it is the one in use. Setting it without `air.server` and `air.host` is an error. |
| `$ECASH_AIR_SERVER`, or `[air] server` | none | The AIR server's name: its public key, compressed hex (66 characters). The client checks the server's signed challenge against it. **With `air.host`, it turns AIR on** for the PSP's mint info, keys, keysets, rotation, rollover and check-state; both or neither. None: HTTP. |
| `$ECASH_AIR_HOST`, or `[air] host` | none | The AIR server's host name or IP, no port (the AIR client always dials port 5702). `127.0.0.1` for a server on this machine. |
| `$ECASH_AIR_REPLY_WAIT_SECS`, or `[air] reply_wait_secs` | `30` | How long to wait for the reply to one try. 1 to 600. |
| `$ECASH_AIR_ATTEMPTS`, or `[air] attempts` | `3` | Tries before "the PSP did not answer". 1 to 10. |
| `$ECASH_AIR_MAX_SKEW_SECS`, or `[air] max_skew_secs` | `300` | How far the reply's `issued_at` may be from this clock. 1 to 86400. |
| `$ECASH_AIR_TIMEOUT_SECS`, or `[air] timeout_secs` | `10` | How long the AIR server may take to answer one step. 1 to 600. |
| the `http` cargo feature | on | The HTTP client and the command line. An app that sends requests its own way can turn it off and use only the library. |
| the `air` cargo feature | on | The PSP's mint info, keys, keysets, rotation, rollover and check-state over AIR (needs the local patches above for now). With it off and the `[air]` settings set, `verify_mint` refuses with a message that says so. |

The wallet file holds spend keys. Losing it loses the notes and the blinding factors for anything in flight. A missing file is an empty wallet; a file that cannot be read is an error and is never replaced. More in [DESIGN.md](DESIGN.md), "Notes and the wallet file".

## The PSP's calls over AIR

Six calls to the PSP can go over AIR. The first four are read-only: its **mint info** (what `GET /health` reports: `wire_version`, `network`, which the wallet asks before it sends anything to the PSP), its **keys** (`GET /keys`), its **keysets** (`GET /keysets`) and its **rotation window** (`GET /rotation`). The other two have a body, and the first changes state: its **rollover** (`POST /rollover`, the swap of old-keyset notes for new, sent by the rotation sync, on import of a handoff and on reclaim) and its **check-state** (`POST /check-state`, `handoff check` and the check inside `handoff reclaim`). **When `air.server` and `air.host` are both set**, these go over AIR instead (the DID is the SPI's: built in, or `air.psp_did`): the wallet writes a small sealed request into a mailbox of the PSP's DID on the configured AIR server and verifies the PSP's signed reply (the signature is the PSP DID key's, checked against the 33-byte DID alone). The reply body is the JSON the HTTP route returns, so the wallet reads it with the types it already uses. Every other call to the PSP (`/melt`, `/burns`, `/audit`), and every call to the ESP and FSP mints, is still HTTP; so is a call that is local (the wallet's own files never go over AIR).

- **Where the calls are made.** The keys are read when the wallet learns the PSP's largest note size and live keysets (`buy-psp --psp-url`), when it unblinds a settlement (`claim-psp`: the keys of the keyset the PSP printed, from the keysets, or `GET /keys` for older output), and when it keeps notes on a live key set (`rotation_sync`, at startup and in `handoff reclaim`: the rotation window). The code that picks the way is `mint_info` (`psp_keys`, `psp_keysets`, `psp_window`, `sync_psp_limits`, `psp_claim_keys`, `rotation_sync`, `reclaim_handoff`).
- **What the signed reply adds.** Over HTTP the wallet trusts the network path to the PSP for its keys; over AIR the keys come in a reply signed by the PSP's DID key, so nothing in between, not the AIR server and not a man in the middle, can substitute keys.
- **No caching.** As over HTTP, every call asks again; nothing is remembered between calls except the run's first mint-info answer (below).
- **A PSP that cannot answer** (its mint lock is poisoned, a rotation step failed) says so in a signed reply, and the wallet fails at once with "could not answer keys now" instead of waiting out its tries.

- **The request is kept in the wallet file** (`air_requests`: the request kind, the request id, the one-off key, the slots written) from before the first write until it is answered, so a reply that comes while the wallet is not looking is read on the next call without writing a second request.
- **Retry:** 3 tries of 30 s (`air.attempts`, `air.reply_wait_secs`), the same request each time in the next free slot; then "the PSP did not answer over AIR" and the request stays. The next call of the same kind carries on with it (one kept request per PSP and kind).
- **A reply that fails a check ends the request** and says what was wrong: a network or wire version that is not this wallet's is the same error as over HTTP; a bad signature, another mint's, another request's, or a bad body is "a reply that was refused". A reply older than `air.max_skew_secs` when it is found is dropped and one new request is made in the same call.
- **The command line asks once per run** (the first answer is kept for the run): with the PSP down, AIR costs 3 x 30 s once, not at the startup check and again at the command. HTTP is checked every time, as before.
- **Rollover and check-state.** The request JSON the HTTP call would post is the request body, sealed to the SPI's DID with the rest of the request (the notes in it are readable by the mint only), and the reply body is the JSON it would return. A signed refusal is the same wallet error as the HTTP `400` (`Refused`, `SpentElsewhere` with the positions), so a refused rollover is cancelled and its notes freed, and spent notes are marked, exactly as over HTTP. A rollover sent again is **not applied twice**: the mint answers a body it has already answered from what it stored. The kept request is found by its body (its SHA-256 is kept with it), so the same rollover resumes and a different call never takes its place. The same ceilings apply as over HTTP (the mint's, 1 MiB and 1000 notes by default); a chunk of 1000 notes is about half a megabyte.
- **The built-in SPI DID is a PLACEHOLDER.** The wallet ships with the SPI's DID built in (`config::BUILTIN_SPI_DID`; it covers the PSP and later the ESP), and `air.psp_did` overrides it. Until the first SPI deploy puts the real one in (sandbox-mint OPERATIONS.md, "First SPI deploy", step 0) it is a point with no known private key: nothing sealed to it can be read and no reply from it can verify. It never passes silently: while AIR is on and it is in use the wallet prints a warning at every start and in `config`, and a call that fails says the DID is the placeholder.
- **HTTP is to be removed** when the AIR integration is done; for each of these calls it is one small function (`mint_info::over_http` for mint info; `http_keys`, `http_keysets`, `http_window`, `http_claim_keys` and `http_post` for the rest), and the HTTP functions themselves are unchanged.
- `ecash-wallet config` shows which way the PSP is asked.

## Wire version

Every mint's `GET /health` returns `wire_version`, and the wallet refuses a mint whose number is not its own (`WalletError::Wire`, naming both). The types come from [`sp-wire`](../sp-wire/README.md). Details in [DESIGN.md](DESIGN.md), "Wire format and versions".

## Command line

**Network.** The wallet is on mainnet unless given `--regtest`, `--signet` or `--testnet` (`--mainnet` may be given; at most one). Before it sends anything to a mint it asks the mint's `GET /health` which wire version it speaks and which network it is on, and stops if the mint is on another wire version or network or does not say; nothing is sent. Every walkthrough below passes `--regtest`. The wallet file is per network (see "Notes and the wallet file").

```
ecash-wallet [--wallet FILE] [--config FILE] [--regtest|--signet|--testnet] <command>
```

| Command | What it does |
|---|---|
| `buy-psp --mint-key HEX [--reply-did HEX] [--psp-url URL] AMOUNT...` | Prints the encrypted payload as hex on standard output and the purchase id on standard error. With `--psp-url` it first reads the PSP's live key sets and its largest note size; the payload names the PSP's key set, and a size above the PSP's largest is refused. Without it the payload names the key set the wallet last saw, if any, and only the power of two is checked. |
| `claim-psp [--psp-url URL] [--file FILE\|-] [BLIND_NONCE:SIGNATURE...]` | Claims the PSP's signatures. With no file or pairs it reads standard input. |
| `exchange --service DID --psp N [--amounts A,B,C] [--esp-url URL] [--resume ID]` | Exchanges at least N PSP (N is 1 or more) for ESP bound to a service (its 33-byte AIR DID, 66 hex characters; the old 32-byte x-only form is refused with a message that says so). Whole PSP notes are spent and the difference comes back as ESP change. ESP notes are powers of two, so the amount and the change are each split into the fewest of them (`--amounts` picks other sizes, each a power of two, with the same total). `--resume` sends a pending request again. There is no command to split ESP you hold: convert it to FSP straight away (see DESIGN.md). |
| `hand-over --service HEX (--esp UNITS \| --psp N) [--day D] --out FILE` | As the app: take whole ESP notes for that service that add up to exactly the amount out of the wallet and write them, with their spend secrets, to a new file (`0600`; an existing file is never replaced). Refused if no set of notes adds up to the amount. |
| `receive FILE` | As the service: take a hand-over file into this wallet. |
| `transfer --service-key HEX [--day D] [--amounts A,B,C] [--esp-url URL] [--resume ID]` | As the service: swap every free ESP note this wallet holds for the service (the one the 32-byte secret key belongs to) for fresh notes of the same total, split into the fewest powers of two. `--amounts` chooses other sizes, each a power of two, which must add up to the same total. `--resume` sends a pending request again. |
| `balance` | PSP, ESP (by service and day) and FSP held, and what is waiting. Shows the storage service and the FSP held for it. |
| `config` | The settings in use and where each came from, and the storage service for FSP fees. |
| `redeem --service-key HEX --memo TEXT [--max-bytes N] [--esp-url URL]` | As the service: redeem every mature free ESP note for that service (mixed days allowed) for a payout to TEXT. Reads the rate and ceiling from `GET /fees`, prints each request's size and fee, splits over the ceiling, and on `refund_required` or `outputs_over_limit` rebuilds from the mint's totals and sends again. |
| `redeem --service-key HEX --resume ID [--esp-url URL]` | Send a pending redemption again after a lost reply or fault. |
| `redeem --collect [--esp-url URL]` | Ask about every redemption waiting for payout: completed ones end, declined ones give back the reissued notes with the reason. |
| `fsp issue [--service HEX] [--esp UNITS \| --psp N] [--fsp-url URL]` | Issue FSP from this wallet's free ESP for the service (all of it if no amount). Without `--service`, the storage service (the primary of `storage.wallet`) is used, and the command says so; with `storage.wallet` empty, `--service` is needed. The same holds for `fsp pay` and `fsp sync`. |
| `fsp pay [--service HEX] --units N [--memo TEXT] [--fsp-url URL]` | Pay N FSP units to the service, with change. |
| `fsp sync [--service HEX] [--fsp-url URL]` | Finish pending FSP requests and roll previous-keyset FSP over now (it also happens on every connection and at startup). |
| `fsp-window --service HEX [--fsp-url URL]` | Print the FSP mint's rotation schedule (`GET /rotation`). |
| `handoff export-psp --to DID --psp N [--psp-url URL] [--out FILE]` | A **PSP handoff**, a developer to a user (for example after an in-app purchase): take free PSP notes adding up to exactly N out of this wallet and print them as one string (`SPHP1:...`), sealed to the recipient's DID public key `DID` (66 hex characters), so only the holder of the matching secret key can open it. It carries PSP only, never a DID key or FSP. The warning and the size go to standard error. See "Handoff between wallets". |
| `handoff export-fsp --fsp SERVICE:UNITS... --did-key-file FILE [--out FILE]` | An **FSP handoff**, to your own new device: a little FSP (enough to pay to fetch your wallet from the AIR) and your DID secret key from `FILE` (64 hex characters), as one string (`SPHF1:...`). **Not encrypted**, because it carries the key it would be encrypted to: anyone who sees it can spend the notes and act as your DID. |
| `handoff import STRING\|FILE\|- [--did-key-file FILE] [--did-key-out FILE] [--from NAME]` | Take a handoff in; the kind is read from its start. Checks it, refuses one imported before and the old `SPH1:` kind, and records where the notes came from. A PSP handoff needs `--did-key-file` (the secret key of the DID it was sealed to). Its notes are **in the balance at once** and are **always swapped** at the PSP mint for notes only this wallet knows, now and at every start while the mint cannot be reached (`balance` shows how much is still unswapped). An FSP handoff is **never swapped**; its DID key is written to `--did-key-out` (`0600`, never replaced) and is refused without it. |
| `handoff check ID` | Ask the PSP mint where a PSP handoff you made stands, from its record of which notes are spent: **none** (still yours to reclaim), **all** (the receiver swapped or spent them: the handoff is done) or **some** (those are dropped from the record, the rest can be reclaimed). |
| `handoff reclaim ID` | Take back what is left of a PSP handoff the receiver has not swapped: swap the notes back to this wallet at the mint, for fresh notes only it knows. The mint takes whichever of the two swaps reaches it first; if the receiver was first, the handoff is recorded as done and nothing comes back. Run it again after a crash or a lost reply. |
| `handoff list`, `handoff cancel ID`, `handoff done ID` | The handoffs made and imported. `cancel` puts an unclaimed handoff's notes back **without asking the mint** (use `reclaim` for a PSP handoff). `done` drops them once you know the other wallet has swapped. |
| `merge FILE` | Merge a wallet file retrieved from storage into this wallet (see "Merging two copies of a wallet"). |
| `esp-schedule [--by YYYY-MM-DD]` | ESP mature now, mature by the date, and by month, from the wallet's notes (all services). |
| `migrate` | Move a pre-network `~/.ecash-wallet/wallet.json` to `regtest/`. |

URLs default to `$ECASH_PSP_URL`, `$ECASH_ESP_URL` and `$ECASH_FSP_URL`, else `http://127.0.0.1:3000`, `http://127.0.0.1:3100` and `http://127.0.0.1:3200` (an FSP mint used before is remembered per service).

`--service-key` is a secret key, passed on the command line only because this is a development tool. A real service keeps its DID key in the AIR and never types it. Shell history keeps what is typed, so use it for test keys only.

## Handoff between wallets

A handoff moves notes from one wallet to another as one string, with no AIR, mint or network in between (a QR code works too: see below). There are exactly two kinds. The API, the command line and the string format make every other mix impossible, and a hand-made one is refused.

| | PSP handoff | FSP handoff |
|---|---|---|
| For | a developer to a user, after an in-app purchase | one person's old device to their new device |
| Carries | PSP notes only | FSP notes and the DID secret key |
| Encrypted | always, to the recipient's DID public key | never (it carries the key it would be encrypted to) |
| On import | in the balance at once, and always swapped at the PSP mint, no opt-out | never swapped |
| Taken back | `handoff reclaim` (the mint decides who wins) until the receiver swaps | `handoff cancel` (local only) |
| Starts with | `SPHP2:` | `SPHF2:` |
| Made with | `handoff export-psp --to DID --psp N` | `handoff export-fsp --fsp SERVICE:UNITS --did-key-file FILE` |

The old combined `SPH1:` handoff of 0.4.0 (PSP, FSP and an optional key, swapped only if asked) is refused with a message that names the two new kinds.

**PSP handoff.** The notes' spend secrets are sealed to the recipient's DID key with `sp_wire::seal`, which is AIR's own `PublicKey::encrypt` (no new cryptography). The app makes its DID locally and tells the developer's service the public key; the service runs `export-psp`. The user's wallet opens it with the DID secret key, counts the notes in its balance, and swaps them at the PSP mint first thing, whenever the mint can be reached (`POST /rollover`, same amounts): on import, then at every start and on every connection to the mint. The handoff is final for the receiver when the swap succeeds. If the mint cannot be reached, the notes stay **unswapped**: they are in the balance and can be spent, `balance` prints how much of it is still unswapped, and the swap is sent again at every start. There is no lock on unswapped notes, because none is needed: spending a note at the mint burns it exactly as the swap does, so whichever reaches the mint first wins and the other is told the note is spent. A swap whose notes were spent meanwhile is rebuilt for the rest. If the mint says a note was spent already (the sender reclaimed it, or a copy was received first), that note leaves the balance and the user receives nothing for it.

**Reclaim.** While the receiver has not swapped, the sender can take the notes back with `handoff reclaim ID`, and `handoff check ID` says where it stands. Both ask the PSP mint's record of which notes are spent (`POST /check-state`), and the mint decides who wins: a reclaim is a swap of the same notes back to the sender, and the mint takes the first swap that reaches it and refuses the other with nothing burned. All notes spent means the receiver has them (the sender gets nothing, and the handoff is done); none spent means the sender can still reclaim; some spent means those are gone and the rest can be reclaimed (or swapped by the receiver: first to the mint wins). The stored swap is sent again after a crash, and the mint answers a repeat from its record. An FSP handoff has no reclaim: the mint has no record of who holds an FSP note.

**FSP handoff.** For a user setting up a new device that holds nothing yet: the old device hands over the DID key and just enough FSP to pay to fetch the wallet from the AIR. Both devices are one owner's, so nothing is swapped. After the fetch, run `merge FILE` on the wallet you fetched: the small wallet from the handoff and the full one are united, net of the FSP spent on the fetch. The AIR fetch does not exist yet, so the merge is a separate step that runs after it.

**Both strings are bearer secrets**, and an FSP handoff is worse: it also holds the DID secret key and is not encrypted. Hand it over in person or by QR code between your own devices, never post it or send it over a network, and delete it once it is imported. The warning is printed on standard error on every export and every import (`PSP_WARNING`, `FSP_WARNING`).

Reclaim, cancel and done: the notes leave the sender's balance when the string is made. For a PSP handoff, `handoff reclaim` brings them back through the mint, which is the safe way. `handoff cancel` puts them back locally, without asking the mint; if the other wallet already has the handoff, the first of the two to swap or spend wins, so cancel is for a string that was lost or never delivered, and for an FSP handoff. `handoff done` drops the sender's copy once it knows the handoff was claimed.

Size, for the QR code: about 188 + 150 × N characters for a PSP handoff of N notes of one key set with a 22-character URL (the seal adds 80 bytes), and about 166 + 150 × N for an FSP handoff of one service (the key adds 32). One QR code in alphanumeric mode holds about 27 notes at error correction L, or 21 at M. More than that goes in a file (`--out`). The wallet draws no QR code. Pipe the string to a tool: `ecash-wallet handoff export-psp --to DID --psp 5 | qrencode -t ANSIUTF8`.

**`send-psp` is gone.** `send-psp`, `receive-psp`, `sent` and the `psp1` token are removed; the PSP handoff does the same job, sealed to one DID, with the reclaim and check brought over from `sent --reclaim` and `sent --check`. The commands now print a message naming their replacements. **Old records are migrated, not kept:** a wallet file that still has `send-psp` tokens in `sent` (pending, reclaiming, received, conflict, reclaimed) is read as before, and each becomes a PSP handoff record with the token's id when the file is opened (the file is rewritten without `sent` at the next save), so `handoff check ID` and `handoff reclaim ID` work on it, including a reclaim that was stored and not sent. A swap that `receive-psp` stored and did not send is still sent at the next start; `balance` shows it as waiting and does not count it, because the wallet never held those notes' secrets. A `psp1` token string itself can no longer be imported: ask the sender to reclaim it and send a handoff.

## Merging two copies of a wallet

`merge FILE` merges a wallet file retrieved from storage (an AIR backup, a copy from another device) into this one. Notes are united by identity, a note spent or handed off in either copy stays gone, pending requests are united without duplicates, and the wallet file's `version` counter goes up with every change. Details in [DESIGN.md](DESIGN.md), "Handoff, merge and the service ID".

## Regtest walkthrough

The end-to-end runs (steps 0 to 49: purchase, claim, exchange, transfer, redemption, FSP, refusals, splitting, and key rotation on ESP and FSP) are in [REGTEST.md](REGTEST.md). They were run against a real Bitcoin Core regtest node. Run them in order: each continues the one before.

## Tests

```
cargo test --all-features
cargo fmt --check
```

`cargo test --all-features` also runs `tests/air_flow.rs`: an `air_server` started in the test process (on port 5702, which the AIR client always dials, so the port must be free), psp-mint's real AIR listener, and the wallet's mint info, keys, keysets, rotation, rollover and check-state over AIR (keys and the rest against a real rotating mint whose HTTP routes run in the process, so the two ways are compared). That file uses psp-mint's `air_listener`, which no tag has yet, so it is built only with the `air-listener-tests` feature (`--all-features` has it); plain `cargo test` skips it. It needs the patches described under "Setup" and a psp-mint that has the listener, which today means the local-mints script below.

The tests run in one process with real mints (psp-mint, esp-mint and fsp-mint are dev-dependencies at their release tags) and no network. What they cover is in [DESIGN.md](DESIGN.md), "Tests". Because the mints are at their tags, a change in a mint is not exercised until the tag moves: before a release in which a mint and the wallet change together, run `sh ~/sandbox-mint/scripts/test-wallet-against-local-mints.sh` (with `SP_LOCAL_AIR` and `SP_LOCAL_AIR_SERVER` set to the AIR and air_server checkouts while the AIR request needs them; the script's header says how), which runs these tests against the esp-mint, psp-mint and fsp-mint folders on this machine without changing any repo (and then fsp-mint's, psp-mint's and esp-mint's tests). The regtest runs in [REGTEST.md](REGTEST.md) are the end-to-end tests with a real Bitcoin node.

## Documentation

- [DESIGN.md](DESIGN.md): how each part of the library works and why.
- [CHANGELOG.md](CHANGELOG.md): what was built and what changed.
- [REGTEST.md](REGTEST.md): the end-to-end walkthrough.
- [ROADMAP.md](../sandbox-mint/ROADMAP.md) (in `sandbox-mint`): left to do and not decided yet, for every repo.
- [sandbox-mint README](../sandbox-mint/README.md): the family of repos.
