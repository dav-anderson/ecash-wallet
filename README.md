# ecash-wallet

One wallet library for PSP, ESP and FSP (Primary, Encumbered and Fast Service Points), with a thin command line. AIR apps embed the library. The command line only parses arguments and prints, so everything it does is a call into the library.

The library holds no BTC wallet. The app's own Bitcoin wallet puts the bytes from `build_psp_payload` in an OP_RETURN and pays.

## Status

The regtest runs in [REGTEST.md](REGTEST.md) cover purchase, encryption, claim, exact exchange with change (2026-10-15), the ESP transfer (2026-10-15, steps 13 to 20), redemption and FSP (2026-10-16, steps 21 to 37), and refusals, splitting, kept ESP and key rotation on ESP and FSP (steps 38 to 49). Each matched the expected output at every step.

Built:

- Blinding and unblinding (`src/blind.rs`).
- The note file (`src/store.rs`).
- PSP purchase: `build_psp_payload` and `claim_psp` (`src/psp.rs`).
- ESP exchange: `build_exchange`, `finish_exchange` and `cancel_exchange` (`src/esp.rs`), and the HTTP calls (`src/http.rs`).
- ESP transfer to the service: `hand_over_esp`, `receive_handover`, `build_transfer`, `finish_transfer` and `cancel_transfer` (`src/transfer.rs`), and the HTTP call (`src/http.rs`).
- ESP redemption by the service: `build_redemption`, `rebuild_redemption`, `finish_redemption` and `cancel_redemption` (`src/redeem.rs`), and the HTTP calls `fetch_redeem_fees` and `send_redeem` (`src/http.rs`).
- FSP: `build_fsp_issue`, `build_fsp_spend`, `build_fsp_rollover`, `finish_fsp_*` and `cancel_fsp` (`src/fsp.rs`), the HTTP calls and the automatic rollover `fsp_sync` (`src/http.rs`), and `esp_schedule`.
- The command line: `buy-psp`, `claim-psp`, `exchange`, `hand-over`, `receive`, `transfer`, `redeem`, `balance`, `fsp issue|pay|sync`, `fsp-window`, `esp-schedule`, `migrate`.

FSP has unit tests and HTTP flow tests against a real esp-mint and fsp-mint in one process (`tests/fsp_flow.rs`), and a regtest run (steps 35 to 37, 42, 43 and 48 in [REGTEST.md](REGTEST.md)). Redemption has unit and HTTP flow tests (`tests/redeem_flow.rs`) and a regtest run (steps 21 to 34 and 38 to 41).

## Setup

The crate depends on its sibling crates by path, so these folders must sit next to `ecash-wallet`: `psp-mint`, `esp-mint`, `air` and `substance` (which `air` needs). The mint-core crates come from git, tag `v0.1.2`.

```
cd ~/ecash-wallet
cargo test
```

The `http` feature is on by default. It adds the HTTP client and the command line. An app that sends requests its own way can turn it off and use only the library.

## Notes and the wallet file

Each note is stored with its spend key, its amount and its terms (an ESP note has a service and a redeemable-after day). The notes, and the requests that have been sent and are waiting for a reply, are one JSON file:

- `--wallet FILE`, else `$ECASH_WALLET_FILE`, else `~/.ecash-wallet/<network>/wallet.json` (`main`, `regtest`, `signet`, `testnet`, from the network flag). *Why per network:* notes of one network are worthless on another, and one file for all of them made it easy to send regtest notes to a mainnet mint.
- A wallet file from before the split (`~/.ecash-wallet/wallet.json`) is refused with a message, never read or moved silently. `ecash-wallet migrate` moves it to `~/.ecash-wallet/regtest/wallet.json` (all development so far was regtest); it moves nothing if the target exists, and never deletes.
- It holds spend keys, so it is created with `0600` permissions.
- Every change is written to a temporary file, fsynced and renamed over the old file, and the directory is fsynced. A change is saved before the call that made it returns. In particular `build_psp_payload` and `build_exchange` save the blinding factors before they hand out the bytes or the request.
- A missing file is an empty wallet. A file that cannot be read is an error and is never replaced.
- Moving the note store into the AIR is deferred. The file is a development placeholder.

Losing the file loses the notes and the blinding factors for anything in flight.

## Library

### PSP

```
build_psp_payload(outputs, reply_did, mint_did_pubkey) -> PurchaseBuild { id, payload }
claim_psp(signatures, keys) -> ClaimResult
```

`build_psp_payload`:

1. Takes the note sizes in PSP (powers of two from 1 to 16,777,216, at most 255; a PSP is $0.10, so 10 PSP are $1) and a 33-byte `reply_did`.
2. Blinds each output with a fresh spend key and blinding factor.
3. Encodes the payload with psp-mint's `payload::encode` (reply DID, then each amount and blind nonce).
4. Encrypts it to `mint_did_pubkey` with AIR's secp256k1 encryption (psp-mint's `seal::encrypt`).
5. Saves the pending purchase (the blinding factors and spend keys), then returns the bytes.

`id` is the SHA-256 of the sealed payload. `claim_psp` takes the pairs the PSP prints, `signature <blind nonce> <signature>`, and the PSP's public keys from `GET /keys`. It matches each pair to the pending output by blind nonce, unblinds it and stores the note. It is all or nothing: a pair that matches no pending output, or an amount the PSP has no key for, changes nothing. A signature can be claimed once. When the PSP signed only some outputs (a payment short by more than 1%), the rest stay pending.

`parse_signatures(text)` reads the PSP's printed output. Other lines are skipped, so the whole output can be passed in. `ours(signatures)` keeps only the pairs for this wallet's pending outputs, because the PSP prints every payer's signatures. `discard_purchase(id)` drops a purchase that was never paid.

### ESP exchange

```
build_exchange(psp_units, service, esp_amounts) -> ExchangeBuild { id, request }
finish_exchange(id, response) -> FinishResult
cancel_exchange(id)
```

The mint's exchange is exact, and the smallest exchange is 1 PSP ($0.10, 10^11 ESP), set by the mint's `exchange.min_psp`. So `build_exchange` always asks for the full value of the PSP notes it spends. It picks PSP notes with the smallest total that is at least `psp_units` (exactly `psp_units` whenever some set of its notes adds up to it). The amount asked for becomes the service's ESP notes: `esp_amounts` splits it (default one note of `psp_units * 10^11`, which fits up to 184,467,440 PSP). Anything the chosen notes are worth beyond `psp_units` is added as extra ESP notes under the same terms (the same service and redeemable-after day), so the request always matches. That change is ESP, not PSP, and cannot be turned back into PSP, which is why the wallet looks for the tightest cover. It signs every PSP input over the exchange memo and reserves the notes. `ExchangeBuild` reports `psp_spent` and `change_esp`, and `FinishResult` reports `change_esp`. `finish_exchange` unblinds the mint's reply into ESP notes, each with the service and redeemable-after day, and removes the PSP notes that paid for them. `cancel_exchange` frees the reserved notes, and is only safe when the mint refused the request. After a timeout or a fault, send the same request again: the mint stores its answers by request hash.

`http::fetch_psp_keys(base)` and `http::send_exchange(base, &request)` make the two HTTP calls. A `400` is `WalletError::Refused`. Nothing was burned by the request, with one exception: `NoteSpentElsewhere` means that on a retry the ESP mint found some of its PSP notes spent under another memo (the holder spent them somewhere else), and signed nothing. The `400` body names those notes. `http::exchange_refusal` reads it into `WalletError::SpentElsewhere { why, inputs }`, and `mark_spent_elsewhere(id, inputs) -> SpentReport { marked_spent, freed }` drops the pending exchange, moves the named notes out of the wallet's notes into a record of spent notes (`spent_notes()`), which the balance does not count and exchanges cannot pick, and frees the request's other notes. It changes nothing if the mint names no note, or a position the request does not have. See the esp-mint README, "Burn memos". Anything else that goes wrong is `WalletError::Mint` (the outcome may be unknown).

### Transfer to the service

```
hand_over_esp(service, esp_units, day) -> Handover
receive_handover(&handover) -> (count, units)
build_transfer(service_secret, day, esp_amounts) -> TransferBuild { id, request, esp_units }
finish_transfer(id, response) -> TransferDone { notes, esp_units, redeemable_after_day }
cancel_transfer(id)
```

A payment of ESP is a transfer to the service the notes are named for. The mint swaps the notes for new notes owned by that service, with the same service, the same redeemable-after day and exactly the same total. Nothing is burned out of circulation and no value is created, so the ESP mint's outstanding total does not change. The mint charges no fee (the AIR send fee covers it). Only the named service can ask for the swap, and the app cannot move ESP to another service or to a peer.

There are two sides, and one wallet can play either:

1. **The app (the payer)** calls `hand_over_esp`. A holder cannot split an ESP note, so the payment is a set of whole notes that adds up to exactly `esp_units` (a depth-first search with a budget of 100,000 steps; if no set adds up, it is refused and nothing changes). The notes leave the wallet and become a `Handover`: the service, the day, and for each note its amount, the note and its spend secret. The hand-over is also kept in the wallet file, in case the file is lost on the way. `day` can be left out when the wallet holds ESP for that service with only one day.
2. **The service** calls `receive_handover`. It checks that each spend secret matches its note's nonce, refuses a note it already holds, and adds the notes to its wallet. Then `build_transfer` takes every free ESP note the wallet holds for that service and day and builds the request: it signs each input over the transfer digest with the note's own key, signs the whole request with the service's DID secret key, blinds the new outputs (by default one for each old note, same amounts; `esp_amounts` chooses other sizes that add up to the same total), reserves the old notes and saves the pending transfer, all before it returns the request.
3. `http::send_transfer(base, &request)` posts it to the ESP mint's `/transfer`. `finish_transfer` unblinds the reply into new notes (each checked against the key the mint derives for its terms) and removes the old notes. `cancel_transfer` frees the reserved notes, and is only safe when the mint refused the request (a `400`, `WalletError::Refused`). After a timeout or a fault, send the same request again: the mint stores its answers by request hash, and it reserves the notes of a pending transfer so no other request can take them.

The hand-over file carries spend secrets, so it is written with `0600` permissions and must be given only to the service. It is a file for now. Delivering it as an AIR message to the service's DID is deferred (see Left to do).

### Redemption

```
fetch_redeem_fees(esp_url) -> RedeemFees { fee_per_byte, max_request_bytes, max_memo_bytes }
build_redemption(service_secret, memo, fees, now_unix) -> Vec<RedeemBuild>
send_redeem(esp_url, body) -> RedeemResponse            (or WalletError::RedeemRefused)
rebuild_redemption(id, service_secret, totals) -> RedeemBuild
finish_redemption(id, response) -> RedeemOutcome
cancel_redemption(id)
pending_redemptions() -> &[PendingRedemption]
```

This follows esp-mint's `POST /redeem` as it is built (see "Redemption" in the esp-mint README). Only the service redeems: the request names the service, every input is signed over the request digest with the note's own key, and the whole request is signed with the service's DID key. The wallet builds the mint's canonical binary encoding (`esp_mint::redeem::encode`) and sends it as `application/octet-stream`.

What goes in. `build_redemption` takes every free ESP note for the service whose key is `service_secret` and whose redeemable-after day has come on the wallet's clock (`now_unix / 86400 >= day`). Mixed days are allowed. Notes of other services, and notes not yet mature, are left alone. The memo says where the payout goes (for example `btc:ADDRESS`). It must not be empty or blank and must fit `max_memo_bytes`.

Size and fee. The size is exact: `119 + 186 per input + memo bytes + 81 per output` (decline and refund outputs alike), which is `esp_mint::redeem::encoded_len`. The fee is `size × fee_per_byte`, with the rate taken from `GET /fees` (the `redeem` block, whose size constants the wallet checks against 119, 186 and 81). `RedeemBuild` and `RedeemOutcome` report `size_bytes`, `fee_per_byte` and `fee_esp`, and the command prints them before sending.

Outputs. The accepted value minus the fee comes back as decline outputs, held under each note's own service and day (the mint checks the total against what it owes and each day against what it accepted). The fee is taken from the service and day with the most value first, then the next largest, so small days keep their value. The mint does not fix where the fee comes from: it checks only the total and each day's cap. Amounts over `u64::MAX` are split into several outputs. The output count changes the size and so the fee, so the wallet repeats the sum until it settles. If the notes are worth less than the fee, or the fee would take all of them so that the mint would owe nothing, that request is not sent and the wallet says why (`not sent: ...`, printed by the command). Its notes stay free. When no request is left the result is `NotEnough` with the same reason. `plan_redemption` returns the built requests together with these reasons; `build_redemption` returns just the requests.

Splitting. If the request would be larger than `max_request_bytes` (from `/fees`, or lower with `--max-bytes`), the notes are split, oldest day first, into several requests that each fit, counting the worst case for outputs. Each part is its own request with its own fee and its own payout entry. A ceiling too small for one note is refused.

Crash safety. Each request is stored in the wallet file by its request hash (`esp_mint::redeem::request_hash`, also the mint's entry id) with its exact bytes, and its notes are reserved by that id before it is sent. The blinding factors for its decline and refund outputs are stored with it. After a lost reply or a fault, send the same bytes again: the mint keeps its answers by request hash, so nothing is burned or queued twice. `finish_redemption` can be given the same answer more than once.

Bad proofs. A note the mint rejects for a bad proof (in a reply or in a refusal's totals) stays in the wallet and in the balance, but its id is saved in the wallet file (`bad_proof`) and redemptions no longer pick it. `balance` prints `bad proof N note(s) worth X ESP`. `is_flagged_bad_proof(id)` checks the flag and `clear_bad_proof(id)` clears it.

The answer. Each note gets a decision: accepted, or rejected with a reason (`wrong_service`, `bad_proof`, `already_spent`, `immature`) and whether it was burned. `finish_redemption` removes burned notes, moves `already_spent` notes to the spent record, flags `bad_proof` notes, and frees the rest. Refund outputs the mint signed are unblinded into notes. With an owed amount the message is "payout queued" and the entry is open. When the fee takes everything the message is "nothing owed, fee taken", there is no entry, and the redemption ends.

Refused requests. A `400` or `413` is `WalletError::RedeemRefused { code, why, totals }`. For `refund_required` and `outputs_over_limit` the mint sends its `totals` (each note's decision and the accepted and rejected value by service and day). `rebuild_redemption` drops `already_spent` notes to the spent record, frees `wrong_service` notes, flags `bad_proof` notes (below), and builds a new request from the mint's figures: if the accepted notes cannot pay the fee, the genuine rejected ones (for example, immature on the mint's clock) pay the shortfall and the rest comes back as refund outputs. The old request is replaced. The command does this up to 4 times. Any other refusal frees the notes (`cancel_redemption`). `below_fee` means even all the genuine notes do not cover the fee.

Collecting. A queued redemption stays in the wallet with its notes gone. Sending the same request again returns the entry's state: `open` (nothing to do), `completed` (with the operator's payment reference; the redemption ends) or `declined` (the operator's reason and the mint's signatures on the stored decline outputs, which the wallet unblinds into notes under the original days; the redemption ends). `cancel_redemption` refuses a queued redemption.

### FSP

The decisions behind FSP (the eight answers, the crash ordering, rotation) are in the fsp-mint README; this is the wallet's side.

- **Issue.** `build_fsp_issue(service, units, fee_per_byte)` takes the app's free ESP for that service (any days mixed: FSP ignores maturity), groups it by day, makes power-of-two FSP outputs worth the ESP less the fee, and stores the request as pending (notes reserved) before it is sent. `fsp issue` sends it to `POST /issue`.
- **Pay.** `build_fsp_spend(service, units, memo)` picks FSP notes on the current or previous keyset, adds change outputs on the current one, and stores the request. `fsp pay` sends it to `POST /spend`.
- **Crash safety.** Every FSP request is stored with its request hash before it is sent. A crash, a lost reply or a `502`/`409` leaves it pending; the next connection sends the same request again and finishes from the mint's stored answer. A `400` frees the notes.
- **Automatic rollover.** On every connection to an FSP mint, and at startup for every FSP mint the wallet knows, `fsp_sync` reads `/keys`, finishes pending requests, marks notes on a keyset the mint no longer has as lost (kept in `lost_fsp`, shown by `balance`), and swaps every note on the previous keyset for the current one (`build_fsp_rollover`: a spend that pays 0). No prompt. A failure is logged and retried on the next connection. The swap is staggered: each wallet waits its own delay after the rotation, at most 0.5% of the period and never more than 72 hours (drawn at random once and kept only until the swap is done; see "Swap times are not kept" below; using the mint's clock from `GET /rotation`), so all wallets do not swap at once. *Why automatic:* a note left on the previous set through the next rotation is lost, and a holder should not have to know about rotation.
- **Lost FSP.** FSP that sat in a wallet that never connected for a full cycle (one to two periods, one to two years by default) cannot be used; the mint has deleted its keyset and its spent list.
- **The window.** `fetch_fsp_rotation` reads `GET /rotation`; `fsp-window` prints it.
- **ESP schedule.** `esp_schedule(service, by)` reads the wallet's own ESP notes (no mint call) and gives what is mature now, what is mature by a date, and a by-month breakdown. It is for the service, which holds the ESP it took in for FSP until it matures.

### Rotation of PSP and ESP

psp-mint and esp-mint rotate the same way (activation 8760 hours after the first issue, period 87600 hours, two key sets and two spent lists). At startup, for `$ECASH_PSP_URL` and `$ECASH_ESP_URL` when the wallet holds that kind, `rotation_sync` reads `GET /rotation`, finishes pending rollovers, marks notes beyond the window as lost, and after this wallet's staggered time swaps previous-set notes with `POST /rollover` (batches of up to 1000 notes; ESP per service and day, keeping both). A failure is logged and retried at the next start. - **Keysets are recorded and named.** The wallet records the keyset of every PSP and ESP note: from the keys a claim was unblinded with, or from the mint's reply to a rollover or hand-over swap. Every PSP request names them (`input_keysets` and `keyset` on `/rollover`, `psp_input_keysets` on the ESP exchange), and the outputs of a swap name the PSP's current keyset, read fresh from `/rotation` at each connection (the cached live keysets are replaced every time, so they cannot go stale). A token carries each note's keyset. *What changed in the old rule:* "a note with no recorded set counts as previous" now applies only to notes from before keysets were recorded, and a wrong guess burns nothing (the mint refuses a note that does not verify under the keyset named).
- **ESP keysets.** ESP notes are keyset-addressed too. The wallet reads the ESP mint's live keysets (`GET /keysets`, and `/rotation` on each rotation sync) before an exchange, transfer or redemption, names the current one for new outputs (exchange `keyset`, transfer `keyset`, the redemption's output keyset) and each note's recorded keyset for its inputs (transfer and rollover `input_keysets`, one keyset per redemption input, and `keyset` on each FSP issue note and hand-over note). New ESP notes record the keyset the mint's reply names (transfer, exchange and rollover replies, and each decline or refund signature), which can differ from the one asked for (a queued decline signed after that set retired), and they are unblinded with that reply's keys. A PSP claim is unblinded with the keys of the keyset the PSP printed, from `GET /keysets`, never the current set by assumption. A redemption without a known current ESP keyset is refused locally ("connect to the mint first").
- **Re-blind on `keyset_not_current`.** Mints sign new outputs with their current keyset only. When a mint refuses a request `keyset_not_current` (it rotated after the wallet read its keysets; nothing was burned), the wallet reads the keysets again, rebuilds the same request with the same notes and amounts, fresh blinded outputs and the current keyset (`reblind_exchange`, `reblind_transfer`, `reblind_redemption`; rollovers and the PSP receive swap are rebuilt the same way), and sends it once more. `transfer --resume` re-blinds only when `--service-key` is given.
- **No keyset guessing.** Every note the wallet stores records its keyset (from the reply that signed it, the PSP claim, or the hand-over/token that brought it). A note without one is refused with "note X has no recorded keyset, so it cannot be spent"; it is not picked for rollovers. A hand-over or token note without a keyset is refused, and a mint reply that names no keyset is not stored. Redemption sizes are now `119 + 186 × notes + memo + 81 × outputs` (format version 2); exchange `48 + 146 × notes + 41 × outputs`, transfer `120 + 146 × notes + 41 × outputs`.
- **A note claimed on the current set after a rotation is not rolled over.** The rollover picks notes by their recorded keyset (any but the current set); a note with no recorded keyset is never picked.
- **Expired notes are written off with a message.** A note whose recorded keyset is neither current nor previous was retired: it is moved to `lost` (not in the balance), and the sync says "N note(s) expired: their key set was retired at a rotation before they were rolled over". Claim signatures printed for a retired keyset are refused with a message saying the outputs expired. A mint's `unknown_keyset` answer means junk or the wrong mint, not expiry.

- **Swap times are not kept (privacy).** Each rotation's swap time is a random delay (at most 0.5% of the period, capped at 72 hours, from the mint's clock) drawn once and stored in `swap_schedule`, for FSP, PSP and ESP alike. It is deleted in the same atomic write that records the new notes when the rotation's last batch completes, and the whole entry is dropped when the old set retires. No history is kept, and the logs never print a swap time.

### Handing PSP to another wallet

For a developer that sells PSP to its users by in-app purchase, with this wallet inside the app (`send.rs`; command line `send-psp`, `receive-psp`, `sent`).

- **Send.** `export_psp` / `export_psp_amount` writes chosen free PSP notes (with their spend secrets) as a token (`psp1` + hex JSON: the mint URL and the notes) and moves them to `sent` in the same write: pending-sent, out of the balance. A token is a bearer token; whoever has it can swap it.
- **Receive.** `http::receive_psp` stores a swap of every note for fresh notes (`POST /rollover` at psp-mint: same amounts, no fee) before sending it, then sends it. The swap is what makes the receive final. If the mint finds any note spent it refuses the whole swap, nothing is burned and the receiver keeps nothing (`Received::Rejected`, with the mint's reason, to pass on to the sender).
- **Crash between import and swap.** The stored swap is sent again by importing the same token again or by the startup sync; the mint answers a repeat from its record by request hash.
- **The sender learns the outcome from the mint.** `http::check_sent` asks `/check-state`: all notes spent = `received` (final; the notes and their secrets are dropped); none = still `pending`; some = `conflict` (notes used elsewhere, so the receiver was refused; the rest can be reclaimed). `http::reclaim_sent` swaps what is left back to this wallet (`reclaimed`); if the receiver swapped first, the token is recorded as received instead.
- *Why always a swap at the mint:* a developer who double-spends only hurts its own users, but the swap costs almost nothing and protects against accidents such as a wallet restored from an old backup or a bug that reuses notes. ESP and FSP still always go through their mints.

### The reply DID

`build_psp_payload` takes the reply DID from the caller. The command line uses a stand-in, a made-up 33-byte key kept in the wallet file (`reply_did`), until a wallet has a real AIR identity. The PSP mint treats the field as opaque bytes, and the signatures are not delivered to it yet (see Left to do).

## Command line

**Network.** The wallet is on mainnet unless given `--regtest`, `--signet` or `--testnet` (`--mainnet` may be given; at most one). Before it sends anything to a mint it asks the mint's `GET /health` which network it is on, and stops if the mint is on another network or does not say; nothing is sent. Every walkthrough below passes `--regtest`. The wallet file is per network (see "Notes and the wallet file"). *Why mainnet by default:* the default should be the network a real user is on; development passes a flag.


```
ecash-wallet [--wallet FILE] [--regtest|--signet|--testnet] <command>
```

| Command | What it does |
|---|---|
| `buy-psp --mint-key HEX [--reply-did HEX] AMOUNT...` | Prints the encrypted payload as hex on standard output and the purchase id on standard error. |
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

URLs default to `$ECASH_PSP_URL`, `$ECASH_ESP_URL` and `$ECASH_FSP_URL`, else `http://127.0.0.1:3000`, `http://127.0.0.1:3100` and `http://127.0.0.1:3200` (an FSP mint used before is remembered per service). On a `400` the exchange or transfer frees its notes. The exception is a request the mint says had notes spent by a different request: those notes are marked spent (they leave the balance and `balance` prints "spent elsewhere N note(s)"), and the request's other notes are freed. The mint names them in the refusal (`code: note_spent_elsewhere`, `spent`: positions in the request) on an exchange, a transfer and a rollover (PSP and ESP). A redemption refused for being `below_fee` carries a reason for every note (`notes`), and the wallet moves the notes marked `already_spent` to its spent record, flags the ones marked `bad_proof`, and frees the rest. Before this the wallet kept offering such notes and was refused every time. On any other failure it keeps the request and prints the `--resume` command.

**Note limits.** The wallet holds no limit of its own for ESP. Before an exchange or a transfer it reads `exchange.max_items` and `transfer.max_items` from the ESP mint's `GET /fees` (`http::sync_esp_limits`) and refuses a request over them, naming the mint's setting. Offline it builds the request and lets the mint decide. The one count the wallet does hold is `psp::MAX_OUTPUTS`, 255 outputs in a purchase: that is not a setting but the payload format, whose output count is one byte.

`--service-key` is a secret key, passed on the command line only because this is a development tool. A real service keeps its DID key in the AIR and never types it. Shell history keeps what is typed, so use it for test keys only.

## Regtest walkthrough

The end-to-end runs (steps 0 to 49: purchase, claim, exchange, transfer, redemption, FSP, refusals, splitting, and key rotation on ESP and FSP) are in [REGTEST.md](REGTEST.md). They were run against a real Bitcoin Core regtest node. Run them in order: each continues the one before.

## Tests

`cargo test` runs:

- **Blinding.** An unblinded signature verifies against the mint's key. A wrong key or wrong blinding factor does not.
- **Note file.** A change is saved before the call returns. A reopened wallet has the same notes. A corrupt file is an error and is not replaced. The file is `0600`.
- **PSP.** A payload round trip: build, decrypt with the mint's key, decode, and the outputs match. A payload sealed to another key does not decrypt. Claimed signatures become notes the PSP accepts. A partial claim leaves the rest pending. A signature cannot be claimed twice. A bad claim changes nothing. The denomination and output-count limits.
- **ESP.** The request is always exact: the PSP notes spent, times 10^11, equal the outputs' total, with and without change. The cover is the exact set when one exists and otherwise the tightest the wallet can find, checked on several holdings. The memo and request hash match the ESP mint's. Spend signatures cover the memo. A refused exchange frees the reserved notes. A finished one swaps PSP notes for ESP notes, change included. The asked-for split must add up. Not enough PSP, and an exchange below 1 PSP, are refused before anything is reserved. **Spent elsewhere.** `mark_spent_elsewhere` moves the notes the mint names out of the balance into the spent record and frees the others, survives a reopen, leaves them out of later exchanges, and changes nothing when the mint names no note, a position the request lacks, or an exchange the wallet does not have. `exchange_refusal` reads the mint's `400` body: the spent-elsewhere answer carries the positions, and every other `400`, or a body that does not say so, is an ordinary refusal.
- **`tests/flow.rs`, in one process, with no network.** Build the payload, reopen the wallet, open the payload as the mint does, settle it with the PSP's real settlement code, read the printed signature lines, claim, check every note with the PSP's own check, then exchange against the ESP mint's real exchange code: 3 PSP from a 4 and a 1 (the 4 is spent, 3 PSP of ESP plus 1 PSP of change), a request made one ESP unit off is refused before anything is burned, and the last 1 PSP is exchanged exactly. Every ESP note, change included, is checked against the key the mint derives for its terms. A retry gets the same reply and burns nothing more. Also: a payload sealed to another key is ignored and leaves no record, a payload with any one byte flipped is ignored, an exchange without enough PSP is refused before anything is reserved, and a signature the wallet did not ask for is refused.
- **Transfer** (`src/transfer.rs`). The hand-over picks an exact set, refuses an amount no set adds up to, and prefers the notes of one service and one day. It refuses a day when the wallet holds several and none is named. Receiving checks each spend secret against its note and refuses a duplicate. A transfer request is signed by the service and by every input, and the signatures match the ESP mint's digest. The wallet with no matching key, or none for that service, builds nothing. New sizes must add up to the old total. A finished transfer swaps the notes and checks each new note against the mint's key. A reply with a wrong total, a wrong signature or the wrong number of notes changes nothing. A cancelled transfer frees the notes. A pending transfer survives a reopen and can be resumed.
- **`tests/fsp_flow.rs`, in one process, with a real esp-mint and fsp-mint over local HTTP.** Issue FSP from ESP of mixed days, pay with change, the automatic rollover after a rotation (staggered, then swapped without a prompt), a crash after the mint answered finished from the stored answer, offline within the window rolls over and beyond it is lost, a failed rollover logged and retried on the next connection, and the ESP schedule.
- **`tests/transfer_flow.rs`, in one process, with no network.** Buy 5 PSP as a 4 and a 1 and settle. Exchange 3 PSP and then 1 PSP, which gives ESP notes of 3, 1 and 1 PSP. An inexact hand-over is refused. Hand over 3 PSP, receive it as the service, build the transfer and run the ESP mint's real transfer code. The mint's supply is unchanged, a retry gets the same reply, and the new note verifies against the mint's key. Presenting the same notes again is refused as already spent, and cancelling frees them. A different service key finds nothing. The new note can be split into 1 and 2 PSP. A reopened wallet equals the one in memory.
- **Spent notes the mint names** (`src/redeem.rs`, `src/transfer.rs`, `src/rotate.rs`, `src/http.rs`, `tests/redeem_flow.rs`). `refuse_redemption` moves the notes a `below_fee` refusal calls `already_spent` to the spent record, flags a bad proof, frees the rest, and with no list just frees the notes. `mark_spent_in_transfer` and `mark_spent_in_rollover` do the same for the positions the mint names, and refuse a position the request lacks. The refusal bodies are read (`redeem_refusal`, `exchange_refusal`, and the rollover reader, with no stray `: ` when the mint sends no code). `tests/redeem_flow.rs` runs it against a real esp-mint: a copy of a spent note is refused `below_fee`, moved to the spent record, and not offered again.
- **Single error print** (`src/main.rs`). A failed redemption request is printed once, by `main`; later failures get their own line.
- **Note limits** (`src/esp.rs`, `src/http.rs`). The exchange limit is the mint's, read from `/fees`; with none read the wallet checks nothing of its own.

The regtest runs in [REGTEST.md](REGTEST.md) are the end-to-end tests with a real Bitcoin node.

## Left to do

The items every repo shares (all traffic over the AIR except local processes on one machine, the local store and the AIR storage rule, the AIR path dependency, the shared wire format, and the mint-core swap limit) are listed once in the top-level `~/sandbox-mint/README.md`. This list has only this repo's own items.

- **Note store (deferred to the AIR).** The wallet file is a local JSON file.
- **Signature delivery (deferred to the AIR).** The PSP prints its signatures and `claim-psp` reads them from a file. They will arrive as an AIR DID message to the reply DID, and the wallet will claim them without a file.
- **A real reply DID.** The command line uses a made-up one. An AIR app passes its own.
- **Hand-over delivery (deferred to the AIR).** The app gives the service its notes in a file. It will be an AIR message to the service's DID. Until then the file stands in for it, and holds spend secrets.
- **Service key handling.** `transfer --service-key` takes the DID secret key on the command line. The AIR will hold it and sign for the wallet.
- **Splitting ESP.** A holder cannot split an ESP note, so a payment is a set of whole notes that adds up to the price. Exchange in the sizes you will pay (`--amounts`). A way to split is not decided.
- **Redemption decline delivery.** A decline is collected by sending the request again. esp-mint calls its decline route a stand-in for delivery over AIR.
- **Key protection.** Spend keys are stored in plain JSON with `0600` permissions. How they are protected in the AIR store is not decided.
- **Change is ESP.** When no set of PSP notes adds up to the amount, the difference comes back as ESP bound to the same service, not as PSP. The PSP's only swap is `POST /rollover` (`src/rotate.rs`), and it replaces notes with notes of the same amounts on the current key set, so it cannot make change. Making PSP change would need a swap that changes the amounts, which the PSP does not offer. Buy PSP in the sizes you will exchange to avoid locking value to a service.

## Not decided yet

Whether the wallet should be able to ask for a PSP purchase to be rebuilt after the file is lost. Today the blinding factors exist only in the wallet file, so a lost file means the signatures cannot be turned into notes.
