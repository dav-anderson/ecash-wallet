# Regtest walkthrough

The wallet's end-to-end runs against a real Bitcoin Core regtest node, with the PSP, ESP and FSP mints. Steps 0 to 49, in four parts:

1. Purchase to ESP (steps 0 to 12): buy PSP, claim it, exchange it for ESP.
2. Restart on the new build (step 13). Steps 14 to 20, the stand-alone hand-over, receive and transfer, were removed with those commands; the service now gets its ESP through FSP issue (step 26). Step numbers are not reused.
3. Redemption and FSP (steps 21 to 37): the service's ESP through the FSP mint, redeem, decline, pay, the size ceiling, FSP issue and pay.
4. Refusals, splitting, kept ESP and rotation (steps 38 to 49): spent notes, a request split over a small ceiling, key rotation on ESP and FSP, and the cleanup.

The wallet itself is described in [README.md](README.md). The mints are in [psp-mint](../psp-mint/README.md), [esp-mint](../esp-mint/README.md) and [fsp-mint](../fsp-mint/README.md). Each part continues the one before it, with the same terminals and the same shell variables, so run them in order.

**The amounts were recomputed for 10 PSP = $1 (1 PSP = $0.10 = 10^11 ESP), and the runs were not repeated.** The runs below were captured on 2026-10-15 and 2026-10-16 at the old rate of 1 PSP = $1. When the rate changed, each ESP, FSP and USD amount and each audit total here was recomputed from the recorded one (a tenth of it, with the fees, which are per byte, kept as they were), the sats and over/under figures were recomputed for a purchase a tenth the size, and step 23 now buys 3 PSP instead of 2 (see there). They are calculated, not captured: the first run at the new rate may differ in small ways (a rounded sat or a basis point), and a difference should be looked at, not matched. Use fresh data folders for it. Wallets and mints from the old rate hold amounts at the old rate and are not valid now (there is no migration, the system is pre-release).

## Regtest, from purchase to ESP

This runs PSP purchase, encryption, claiming and the exact exchange together against a real Bitcoin Core regtest node. It was run end to end on 2026-10-15 (macOS, Apple Silicon, Bitcoin Core 31.1, cargo 1.93.1) and every output below is what that run printed, apart from values that differ each run (the price, the transaction id, the keys and signatures, the redeemable-after day).

Use four terminals and keep them open:

| Terminal | Used for |
|---|---|
| T1 | The Bitcoin node (running in the background), `bitcoin-cli`, and `curl` for the audits. |
| T2 | The PSP mint (`psp-mint serve`). |
| T3 | The ESP mint (`esp-mint serve`). |
| T4 | The wallet. Shell variables set here (`ECASH_WALLET_FILE`, `HEX`, `CLI`, `PAYER`, `SERVICE`) are used by later steps. |

`balance` prints the service as its full 66-character DID (the 33-byte compressed key: `02` or `03`, then 64 hex characters). The outputs below show it shortened as `0279be...1798`.

**Wire version 3 (sp-wire 0.5.0).** A service is its DID, so `$SERVICE` below is `02` and the generator's x coordinate, and a command given the old 64-character form is refused with a message that says to use the DID. The outputs below are wire version 2 captures. The 2026-10-22 run, at wire version 3, checked the flow but did not re-record them, so they have **not been run again**: every number that comes from a size moves with the new sizes. A redemption of one note with one decline output is 3 bytes larger (`120 + 187 + memo + 82`, was `119 + 186 + memo + 81`), so its size, its fee (the size times the rate) and the payout (the note less the fee) change by that many bytes and `rate × 3` ESP units, and the audit totals that follow from them move with them. The exchange and transfer sizes are one byte larger (`49` and `121` fixed). Re-run the walkthrough to capture the new figures.

**Rewritten when the `hand-over` and `transfer` commands were removed, and not run.** The wallet no longer writes hand-over files or swaps notes for a service by itself. The service's ESP now comes from `fsp issue`, which hands ESP to the FSP mint over AIR; the FSP mint swaps it at the ESP mint; and `fsp-mint export-esp` writes it out for the service's wallet to `receive` (that is all `receive` is for now). So steps 14 to 20 are gone, step 26 is rebuilt around the FSP mint (which is now set up there, not in step 35), and every figure that followed from the old transfers moved: steps 27 to 28, 31, 33 and 35 to 48 are changed and marked as such where they are. The audit totals were recomputed by hand (issued and redeemed each 3×10^11 lower than the recorded run through step 36, then by the rounds added in steps 38 and 40), not captured. Steps 39 to 41 no longer split a note with `transfer --amounts`: step 40 splits a redemption over two notes instead. Re-run the walkthrough to capture the real output, and look at a difference rather than matching it.

**Corrected after the first end-to-end run (2026-10-22, regtest round 1, ROADMAP item 18), and not rerun.** That run followed this file on release builds and its report lists where the file had drifted. The listen lines, the payload sizes, the note counts, the ceiling of step 27, the `pgrep` pattern of step 22, the `ESP_NETWORK` of `esp-mint pubkey`, the balance of step 25, the wording of steps 30, 38, 42, 45 and 46 and the size ceiling of step 40 are corrected below from that report. What the report did not print is not guessed: it is marked `not rerun` where it stands. Three behaviours changed in the same round, and the text of the steps they touch was rewritten for them without a run: every `esp-mint` command says its network on standard error (`esp-mint on regtest: data in …`); a stale ESP rollover now names every spent note, and an FSP refusal that names spent notes marks them spent in the wallet (steps 46 and 48); and `redeem --max-bytes` names the limit in force and prints its summary first (step 40). The observed audit totals of that run are in its report; the totals in this file from step 26 on are calculated and differ with the number and size of the notes each step makes.

The commands that need `bitcoin-cli` use `CLI=~/bitcoin-core/bitcoin-31.1/bin/bitcoin-cli`, set in the terminal that runs them.

### 0. Check the machine

```
cargo --version
rustc --version
~/bitcoin-core/bitcoin-31.1/bin/bitcoind --version | head -1
~/bitcoin-core/bitcoin-31.1/bin/bitcoin-cli getblockchaininfo 2>&1 | head -3
ls -d ~/.psp-mint ~/.esp-mint /tmp/wallet-regtest.json ~/psp-serve.log 2>&1
pgrep -l "bitcoind|psp-mint|esp-mint"
```

Expected: cargo and rustc print versions, `bitcoind` prints `Bitcoin Core daemon version v31.1.0`, `getblockchaininfo` fails with `Could not connect to the server` (no node yet), the `ls` paths do not exist, and `pgrep` prints nothing. Bitcoin Core must already be installed and `bitcoin.conf` created (psp-mint README, steps 1 and 2). The folders `psp-mint`, `esp-mint`, `air` and `substance` must sit next to `ecash-wallet` (see Setup in [README.md](README.md)).

### 1. Start from a clean state

State left over from earlier runs does not break the run, but a clean start tests the setup steps too. Move it aside instead of deleting it (the node must not be running):

```
mv ~/.psp-mint ~/.psp-mint.old   # the mint now keeps regtest data in ~/.psp-mint/regtest
mv ~/Library/Application\ Support/Bitcoin/regtest ~/Library/Application\ Support/Bitcoin/regtest.old
```

`bitcoin.conf` (the single line `regtest=1`) stays. The mints keep their data in `~/.psp-mint` and `~/.esp-mint`, and the wallet file in this run is `/tmp/wallet-regtest.json`, so a repeat run needs those moved aside too.

### 2. Node and wallets (T1)

```
~/bitcoin-core/bitcoin-31.1/bin/bitcoind -daemon
sleep 3
CLI=~/bitcoin-core/bitcoin-31.1/bin/bitcoin-cli
$CLI getblockchaininfo | grep -E '"chain"|"blocks"'
$CLI createwallet psp-regtest
$CLI createwallet payer
PAYER=$($CLI -rpcwallet=payer getnewaddress)
$CLI -rpcwallet=payer generatetoaddress 101 $PAYER > /dev/null
$CLI -rpcwallet=payer getbalance
$CLI getblockcount
$CLI listwallets
```

Expected: `"chain": "regtest"` and `"blocks": 0`, then `{"name": "psp-regtest"}` and `{"name": "payer"}`, a balance of `50.00000000`, block count `101`, and a wallet list with `psp` and `payer`. Mining 101 blocks is needed because a block reward can be spent only after 100 more.

### 2a. The AIR server (T6)

Every mint is reached over AIR only: the wallet's calls to the PSP, the ESP and a service's FSP mint, and the FSP's calls to the ESP, all go through an AIR server (there is no HTTP route for them any more, and no `--psp-url`, `--esp-url` or `--fsp-url`). Start the AIR server the way sandbox-mint's OPERATIONS.md says (the one bundled with the SPI, or `air_server` from the sandbox checkouts) on this machine, and note its public key, the 66 hex characters it prints:

```
export AIR_SERVER=<the AIR server's key>
```

Set the same shell variable in every terminal below (T1 to T5). The mints take it as `PSP_AIR_SERVER`, `ESP_AIR_SERVER` and `FSP_AIR_SERVER` with the host `127.0.0.1` (the FSP mint also as `FSP_AIR_ESP_SERVER` and `FSP_AIR_ESP_HOST`, for its calls to the ESP; here the same server carries both), and the wallet as `ECASH_AIR_SERVER` and `ECASH_AIR_HOST` (step 5), plus `ECASH_AIR_FSP` for the FSP mint (step 35). Without them `psp-mint serve`, `esp-mint serve` and `fsp-mint serve` refuse to start, and a wallet command that calls the PSP or the ESP stops with an error that names `air.server` and `air.host`, and an `fsp` command for a service with no `air.fsp` entry stops with an error that names `air.fsp`. The mint's local HTTP (`/audit`, `/health` for the PSP and the ESP, `/melt`, `/burns` and the operator's routes) is unchanged; fsp-mint's HTTP routes are `/audit` and `/health`. Start the mints in the order of steps 3, 4 and 35: the FSP asks the ESP over AIR at startup and exits if it cannot be reached.

### 3. The PSP mint (T2)

The log is teed to a file so the settlement and delivery lines can be read back. The signatures also go to the payer over AIR as a record on the AIR server, which is how the wallet claims them (step 9). The first build takes a few minutes.

```
cd ~/psp-mint
PSP_AIR_SERVER=$AIR_SERVER PSP_AIR_HOST=127.0.0.1 PSP_SCAN_INTERVAL_SECS=10 cargo run -- --regtest serve 2>&1 | tee ~/psp-serve.log
```

Expected: `scanning wallet psp-regtest every 10 s` and the api line, which the 2026-10-22 run printed as `local api (melt, burns, audit, health)` with the address (the whole line was not captured; **not rerun**). In T1, `curl -s http://127.0.0.1:3000/health` returns `"status":"ok"` and `"wire_version":3`, and `/audit` returns `issued`, `redeemed` and `outstanding` all 0, with further fields (the reconciliation counts) that are not listed here.

### 4. The ESP mint (T3)

```
cd ~/esp-mint
ESP_AIR_SERVER=$AIR_SERVER ESP_AIR_HOST=127.0.0.1 ESP_NETWORK=regtest ESP_REDEEM_FEE_PER_BYTE=1000000 cargo run -- serve
```

Every fee in esp-mint defaults to 0. This walkthrough sets the redemption fee to 10^6 ESP units a byte (`ESP_REDEEM_FEE_PER_BYTE`) so that the redemption steps below show a fee being taken; the figures in them depend on it. Start the mint the same way each time it is restarted.

Expected: first, on standard error, the network the mint runs on (every `esp-mint` command says it, as psp-mint does): `esp-mint on regtest: data in <home>/.esp-mint/regtest`. Then the api and admin lines. The 2026-10-22 run printed `api (/audit, /health)` for the api line, with its address; the whole lines were not captured, and the old `esp-mint api listening on http://127.0.0.1:3100, burning PSP at …` is gone (**not rerun**).

In T1, `curl -s http://127.0.0.1:3100/health` returns `"status":"ok"` and `"wire_version":3`, and `/audit` returns `issued`, `outstanding` and `redeemed` all 0, with further fields that are not listed here.

### 5. Build the purchase payload (T4)

Run this once. A second run makes a second pending purchase in the wallet file.

```
cd ~/ecash-wallet
export ECASH_WALLET_FILE=/tmp/wallet-regtest.json
MINT_KEY=$(cd ~/psp-mint && cargo run -q -- --regtest pubkey)
ESP_DID=$(cd ~/esp-mint && ESP_NETWORK=regtest cargo run -q -- pubkey)
export ECASH_AIR_SERVER=$AIR_SERVER ECASH_AIR_HOST=127.0.0.1 ECASH_AIR_PSP_DID=$MINT_KEY ECASH_AIR_ESP_DID=$ESP_DID
echo ${#MINT_KEY}
# this walkthrough buys 5 PSP on purpose, below the 50 PSP default of psp.min_purchase
HEX=$(ECASH_PSP_MIN_PURCHASE=5 cargo run -q -- --regtest buy-psp --mint-key $MINT_KEY 4 1)
echo ${#HEX}
```

The wallet takes both mints' DIDs from the settings (the built-in ones are placeholders until the first SPI deploy). `esp-mint pubkey` takes its network from `ESP_NETWORK`: without it, it makes and prints a mainnet DID (and a mainnet key file under `~/.esp-mint/main`), which is the wrong DID here. It says its network on standard error and prints only the DID on standard output, so `$(…)` takes just the DID. Expected: `66` (the mint's public key in hex), then `purchase <id>` and `197 bytes. Put the hex below in an OP_RETURN and pay the PSP.` and a sentence saying the notes arrive over AIR (both on standard error, so they show on the screen but are not in `HEX`), then `394`. A payload of a 4 and a 1 is 197 bytes (the encryption adds 82), 394 hex characters (the 2026-10-22 run; the earlier 199 and 398 were for the old wire).

### 6. Pay the PSP (T4)

Pay a little over $0.50 of BTC (5 PSP at 10 to the dollar) with the payload in an OP_RETURN. This takes the live Coinbase price and pays 1% over, which the mint keeps:

```
CLI=~/bitcoin-core/bitcoin-31.1/bin/bitcoin-cli
PRICE=$(curl -s https://api.coinbase.com/v2/prices/BTC-USD/spot | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["amount"])')
echo $PRICE
AMOUNT=$(python3 -c "print(f'{0.505/$PRICE:.8f}')")
echo $AMOUNT
PSP_ADDR=$($CLI -rpcwallet=psp-regtest getnewaddress)
$CLI -rpcwallet=payer -named send outputs="[{\"$PSP_ADDR\":$AMOUNT},{\"data\":\"$HEX\"}]" fee_rate=10
```

Expected: the price (for example `82357.555`), the BTC amount (for example `0.00000613`, which is 613 sats), and JSON with a `txid` and `"complete": true`. Note the `txid`. Nothing is printed in T3. Within one scan (10 s) T2 logs the payment at `confirmations=0`, before any block is mined (the exact line was not captured; **not rerun**).

### 7. Lock the price at 1 confirmation (T4)

```
PAYER=$($CLI -rpcwallet=payer getnewaddress)
$CLI -rpcwallet=payer generatetoaddress 1 $PAYER > /dev/null
$CLI -rpcwallet=psp-regtest gettransaction <txid> | grep confirmations
```

Expected in T4: `"confirmations": 1,`. Within one scan (10 s), T2 prints:

```
<txid> confirmations=1 value_sats=613
  price locked at 82313.33 USD/BTC, waiting: 1 of 6 confirmations
```

The locked price is the median of Coinbase, Bitstamp and Gemini, so it differs a little from the Coinbase price used to size the payment. T2 also prints a line saying the payment is within the price tolerance (1%); its wording was not captured (**not rerun**).

### 8. Settle at 6 confirmations (T4)

```
$CLI -rpcwallet=payer generatetoaddress 5 $PAYER > /dev/null
$CLI -rpcwallet=psp-regtest gettransaction <txid> | grep confirmations
```

Expected in T4: `"confirmations": 6,`. Within one scan, T2 prints the settlement:

```
<txid> confirmations=6 value_sats=613
  over/under: 91 bps
delivery <txid>: record written
```

The over/under is the payment against the request at the locked price: 613 sats at 82313.33 USD/BTC is about $0.5046, so about +91 basis points. That is within the price tolerance (`settle.price_tolerance`, 1% by default, 100 basis points), so the mint settles it as if it were exact: it signs every requested note, keeps the extra and records no credit. (The reconciliation target, `settle.payment_reconciliation_target`, 10%, is for payments outside the tolerance, as in the reconciliation cases of the run's report.) The mint no longer logs one `signature` line for each note; the payer gets the signatures over AIR. There is no credit, rejection or error message. The lines of this step are the 2026-10-15 ones with the signature lines removed and the tolerance sentence changed, **not rerun**.

### 9. Claim the notes and check the balance (T4)

```
cargo run -q -- --regtest claim-psp
cargo run -q -- --regtest balance
```

Nothing is pasted: the wallet computes the record's address from its purchase and reads it. `claim-psp` waits up to 60 seconds for a record that is not there yet (`--wait SECONDS`). The 2026-10-22 run printed the claim line in other words than below (not captured, **not rerun**). Expected:

```
purchase <id>: claimed 5 PSP in 2 note(s)
psp  5
esp  0
fsp  0
notes 2 (0 held for a pending request)
```

### 10. Exchange 3 PSP (T4)

The wallet holds a 4 and a 1. No set of its notes makes exactly 3, so it spends the 4. The exchange is exact, so it asks for the full 4 PSP of ESP, and the 1 PSP over what was asked for comes back as ESP change. The service below is the generator point, a test value.

```
SERVICE=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
cargo run -q -- --regtest exchange --service $SERVICE --psp 3
cargo run -q -- --regtest balance
```

Expected:

```
exchange <id> (spends 4 PSP)
received 400000000000 ESP in 30 note(s), redeemable after day 21106
100000000000 of that is change: the PSP notes spent were worth more than the amount asked for, and the rest came back as ESP under the same terms

psp  1
esp  400000000000
       400000000000 for 0279be...1798, redeemable after day 21106
fsp  0
notes 31 (0 held for a pending request)
```

The redeemable-after day is today's day number plus 365 (the placeholder redeem window in the esp-mint README). `balance` lists ESP by service and day.

### 11. Audit both mints (T1)

```
curl -s http://127.0.0.1:3000/audit
curl -s http://127.0.0.1:3100/audit
```

Expected: `{"issued":5,"redeemed":4,"outstanding":1}` for the PSP, in whole PSP units, and `{"issued":400000000000,"outstanding":400000000000,"redeemed":0}` for the ESP mint, in ESP units. The 4 PSP burned match the 4 PSP of ESP issued.

### 12. Exchange the last 1 PSP (T4)

```
cargo run -q -- --regtest exchange --service $SERVICE --psp 1
cargo run -q -- --regtest balance
```

Expected:

```
exchange <id> (spends 1 PSP)
received 100000000000 ESP in 15 note(s), redeemable after day 21106

psp  0
esp  500000000000
       500000000000 for 0279be...1798, redeemable after day 21106
fsp  0
notes 45 (0 held for a pending request)
```

There is no change line, because the 1 PSP note is exactly the amount asked for. The mint issues ESP in many small notes, not one: the 2026-10-22 run got 30 and 15, and the `notes` counts above (31 and 45) are worked out from those (**not rerun**). The 45 ESP notes are all bound to the same service and day.

### Notes

- If `exchange` times out, run it again with `--resume <id>` (the id was printed). It sends the same request and gets the same answer, and nothing is burned twice.
- The PSP writes each payer's signatures to a record only that payer can find, so `claim-psp` reads its own purchases' records and no one else's. Any wallet command also picks up a delivery when it starts, so the line above may be printed by the command that ran first, and `claim-psp` then says there is nothing pending.
- A payment the PSP holds (paid, but short beyond its reconciliation target) or rejects is delivered too, so the wallet shows `the PSP is holding the payment` or `the PSP rejected it`, with what was paid and the time it stays open until, and keeps the purchase and its key. The wallet settles it by itself at every start, right after the pickup, with a reconciliation request (AIR kind 15) built from the rules in the PSP's record, and prints what came of it (this was built after the runs in this file and has not been run on regtest). When the time passes with the payment still open, the PSP forfeits it and the next wallet command says `The PSP forfeited the payment: the funds are lost`, with the amount, and deletes the purchase and the key. `buy-psp` also prints `ONE-TIME USE`: pay a payload once. The PSP's window is `PSP_RECONCILIATION_WINDOW_DAYS` (14); set `1` on the PSP to see it close sooner.
- Stop the servers with Ctrl-C in T2 and T3, and the node with `$CLI stop`.

## Regtest, restart on the new build

This continues the run above, with the app wallet still holding 5 PSP of ESP (500000000000 ESP units, in 45 notes) for the service below. It needs T1 to T4 as before. T2 (the PSP mint) is restarted in step 13 and otherwise only answers the ESP mint. The Bitcoin node (T1) must be running, because the PSP scans it. The service's secret key in this run is the test key `000...01`, whose public key is the generator point used as the service in step 10. Step 13 was run on 2026-10-15 (macOS, Apple Silicon) and its output is what that run printed.

The app wallet is `$ECASH_WALLET_FILE` (`/tmp/wallet-regtest.json`, exported in step 5 and used so far in T4). The service has its own wallet file, set per command with `ECASH_WALLET_FILE=...` in front.

### 13. Restart both mints on the new build (T2, T3)

The PSP now keeps the memo of each burn and has `POST /burns`, and the ESP mint has the transfer call and asks the PSP for the memo. Restart the PSP first, then the ESP mint. Their data in `~/.psp-mint` and `~/.esp-mint` is kept.

In T2, stop the PSP with Ctrl-C and start it again:

```
cd ~/psp-mint
PSP_AIR_SERVER=$AIR_SERVER PSP_AIR_HOST=127.0.0.1 PSP_SCAN_INTERVAL_SECS=10 cargo run -- --regtest serve 2>&1 | tee ~/psp-serve.log
```

Expected: `scanning wallet psp-regtest every 10 s` and `psp-mint api listening on http://127.0.0.1:3000`. In T1, check the new route (an empty list is a valid question):

```
curl -s -X POST http://127.0.0.1:3000/burns -H 'content-type: application/json' -d '{"nonces":[]}'
```

Expected: `{"burns":[]}`.

In T3, stop the ESP mint with Ctrl-C and start it again:

```
cd ~/esp-mint
ESP_AIR_SERVER=$AIR_SERVER ESP_AIR_HOST=127.0.0.1 ESP_NETWORK=regtest ESP_REDEEM_FEE_PER_BYTE=1000000 cargo run -- serve
```

Expected: the same two lines as in step 4. In T1, `curl -s http://127.0.0.1:3100/audit` still returns `{"issued":500000000000,"outstanding":500000000000,"redeemed":0}`.

The two exchanges made earlier were burned before the PSP kept memos, so the PSP has no memo for those notes. That does not matter: they were finished, and a finished exchange is never asked about again.

### Steps 14 to 20 (removed)

These were the wallet's stand-alone `hand-over --out FILE`, `receive` and `transfer`: an inexact hand-over refused, a hand-over of 3 PSP, the service taking it in, the service's transfer at the ESP mint, the audit after it, the same notes presented twice and a wrong service key. The commands are gone (CHANGELOG 0.6.0). The transfer at the ESP mint is now made by the FSP mint when `fsp issue` hands it ESP (step 26), and its refusals (a note already spent, a wrong service key) are covered by the ESP mint's tests and `tests/esp_air_flow.rs` here. The step numbers 14 to 20 are not reused, so the later steps keep theirs.

### Notes

- If `exchange` times out, run it again with `--resume <id>`, as in step 10.
- The wallet files are test data. Delete `/tmp/wallet-service.json` when done (step 49 does).

## Regtest, redemption and FSP

This continues the two runs above (purchase to ESP, then the restart), with the same four terminals, the Bitcoin node, the PSP mint (T2) and the ESP mint (T3) running, and one more terminal, T5, for the FSP mint. It was run end to end on 2026-10-16 (macOS, Apple Silicon) from a clean start (step 1 moved the old data aside) **before the hand-over and transfer commands were removed; steps 26 to 28, 31, 33 and 35 to 37 were rewritten for that and are not run** (see the note at the top). Elsewhere every output below is what that run printed, apart from values that differ each run (ids, transaction ids, keys, the price, the day numbers). Today's day number in that run was 20742, so notes issued after step 22 are "redeemable after day 20742" and the year-out notes are day 21107. Use your own: the day is the number of days since 1970-01-01, and the first run's notes carry today plus 365.

The app wallet is `/tmp/wallet-regtest.json`, the `ECASH_WALLET_FILE` exported in step 5 and still set in T4 (the default wallet, `~/.ecash-wallet/regtest/wallet.json`, is used only when that variable is not set). The service has its own wallet file, set per command with `ECASH_WALLET_FILE=/tmp/wallet-service.json`, which overrides the exported one for that command. `$SERVICE` is the generator point `0279be…1798` and `$KEY` its secret key `000…01` (see "Regtest, restart on the new build"). `$CLI`, `$PAYER`, `$HEX` and `$TXID` are shell variables in T4.

### 21. The ESP mint's rates (no command)

The ESP's rates are an AIR call now (`GET /fees` is gone from HTTP), and the wallet reads them when it needs them: `redeem` prints each request's size and fee, and `exchange` checks the mint's item limits before building. The mint's settings are what they were: `exchange` with `fee_per_byte "0"`, `maturity_days 365`, `max_items 1000`, `max_request_bytes 1048576`, `min_psp 1` and size `49 + 146 per input + 41 per output`; the `transfer` call (made by the FSP mint when it swaps handed ESP; the wallet no longer has a command for it) with fee `"0"`, ceiling 1048576 and size `121 + 146 + 41`; `redeem` with `fee_per_byte "1000000"` (set by `ESP_REDEEM_FEE_PER_BYTE` in step 4; the default is `"0"`), `max_memo_bytes 256`, `max_request_bytes 15728640` and size `120 + 187 per input + 82 per output + the memo` (esp-mint README, "Settings and fees"). Nothing to run here; the fee shows in step 23's redemption.

### 22. Make new notes mature the day they are issued (T1)

A redemption needs notes whose day has come, and the notes so far are a year out. Change the setting and reload the running mint with `SIGHUP`, with no restart:

```
cat > ~/.esp-mint/esp-mint.toml <<'EOT'
[terms]
maturity_days = 0
EOT
kill -HUP $(pgrep -f 'esp-mint serve')
sleep 1
```

The pattern `esp-mint serve` matches a debug and a release build alike (`target/debug/esp-mint serve` matched only the debug one). Expected: T3 prints `esp-mint: SIGHUP, settings read again:` and `  terms.maturity_days changed from 365 to 0 days`. Notes already issued keep their day, and an exchange from now on gives notes that mature the day they are issued.

### 23. Buy 3 more PSP, a 2 and a 1 (T4)

```
cd ~/ecash-wallet
MINT_KEY=$(cd ~/psp-mint && cargo run -q -- --regtest pubkey 2>/dev/null)
echo ${#MINT_KEY}
# 3 PSP is below the 50 PSP default of psp.min_purchase; lowered for this command only
HEX=$(ECASH_PSP_MIN_PURCHASE=3 cargo run -q -- --regtest buy-psp --mint-key $MINT_KEY 2 1)
echo ${#HEX}
```

Expected: `66`, `purchase <id>`, `205 bytes. Put the hex below in an OP_RETURN and pay the PSP.` and a sentence saying the notes arrive over AIR, and `410` (a payload of a 2 and a 1 is 205 bytes, not the 197 of step 5). The purchase is 3 PSP and not 2 because of the dust limit: Bitcoin Core will not send an output below 294 sats (for this address type), which is about $0.24 at this price, so 2 PSP ($0.20) could only be paid by overpaying. 3 PSP ($0.30) is paid with 368 sats. `2>/dev/null` hides the banner `pubkey` prints on standard error.

### 24. Pay and settle (T4)

```
PRICE=$(curl -s https://api.coinbase.com/v2/prices/BTC-USD/spot | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["amount"])')
AMOUNT=$(python3 -c "print(f'{0.303/$PRICE:.8f}')")
PSP_ADDR=$($CLI -rpcwallet=psp-regtest getnewaddress)
$CLI -rpcwallet=payer -named send outputs="[{\"$PSP_ADDR\":$AMOUNT},{\"data\":\"$HEX\"}]" fee_rate=10
```

Note the `txid`, then mine six blocks and check:

```
TXID=<txid>
PAYER=$($CLI -rpcwallet=payer getnewaddress)
$CLI -rpcwallet=payer generatetoaddress 6 $PAYER > /dev/null
$CLI -rpcwallet=psp-regtest gettransaction $TXID | grep confirmations
```

Expected in T4: `"confirmations": 6,`. Within a scan T2 prints the settlement (the price is locked and settled in one pass when all six blocks arrive at once): `<txid> confirmations=6 value_sats=368`, `over/under: 83 bps` (within the 1% price tolerance, so settled as exact and no credit), `keyset <id>` and `delivery <txid>: record written` (no `signature` lines; not rerun).

### 25. Claim and exchange (T4)

```
cargo run -q -- --regtest claim-psp
cargo run -q -- --regtest exchange --service $SERVICE --psp 2
cargo run -q -- --regtest balance
```

Expected: `purchase <id>: claimed 3 PSP in 2 note(s)` (the earlier purchase was claimed in step 9 and is not asked for again); then `received 200000000000 ESP in 1 note(s), redeemable after day 20742`. The balance shows ESP 7×10^11: the 5×10^11 of steps 10 and 12 at day 21107 (the year-out notes) and the 2×10^11 of this exchange at day 20742, and `psp  1` (the 1 PSP note of the purchase is not exchanged).

### 26. Give the service its mature ESP through the FSP mint (T1, T5, T4)

**Rewritten, not run.** The service's ESP reaches it in three moves: `fsp issue` hands ESP for the service to the FSP mint over AIR, the FSP mint swaps it at the ESP mint for new ESP that only the service controls, and `fsp-mint export-esp` writes that ESP out for the service's wallet to `receive`. This step sets the FSP mint up (it was step 35) and runs the first round.

The FSP mint holds the service's DID key, `service_key.hex`. For this run it holds the test key, so the ESP the app already has can be used. A real service makes its own with `fsp-mint service-key`. In T1:

```
mkdir -p ~/.fsp-mint/regtest
umask 077
echo 0000000000000000000000000000000000000000000000000000000000000001 > ~/.fsp-mint/regtest/service_key.hex
cd ~/fsp-mint
FSP_NETWORK=regtest cargo run -q -- service-key
```

Expected: the settings, then `service.did = 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`. In T5:

```
cd ~/fsp-mint
ESP_DID=$(cd ~/esp-mint && ESP_NETWORK=regtest cargo run -q -- pubkey)
FSP_AIR_ESP_DID=$ESP_DID FSP_AIR_ESP_SERVER=$AIR_SERVER FSP_AIR_ESP_HOST=127.0.0.1 FSP_AIR_SERVER=$AIR_SERVER FSP_AIR_HOST=127.0.0.1 FSP_NETWORK=regtest FSP_SERVICE_DID=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 cargo run -- serve
```

Expected: the settings (with `service.did` from the environment), `fsp-mint api listening on http://127.0.0.1:3200` (the operator's `/audit` and `/health`; the line's exact wording in the 2026-10-22 run was not captured, **not rerun**) and `fsp-mint AIR listener: wallets reach this service with the air.fsp entry 0279be…1798@<AIR server key>@127.0.0.1 (ECASH_AIR_FSP, air.fsp; …)`. The entry is what the wallet needs: it is the service's DID, the AIR server the FSP mint listens on, and the host. In T1, `curl -s http://127.0.0.1:3200/audit` returns the FSP mint's counts. The FSP mint's other calls (`/keys`, `/fees`, `/rotation`, `/issue`, `/spend`) are AIR calls, so there is no `curl` for them. In T4, give the wallet the entry (the same variable for every `fsp` command below):

```
export ECASH_AIR_FSP=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798@$AIR_SERVER@127.0.0.1
```

Without it `fsp issue --service $SERVICE ...` stops with an error that names `air.fsp` and the service, and sends nothing.

**The round.** The app holds ESP of 2×10^11 at day 20742 and 5×10^11 at day 21107, in many small notes. `fsp issue --esp N` takes the largest notes first, across days, so asking for 2×10^11 takes notes of both days (the 2026-10-22 run mixed day 20748 and day 21113 notes). The issue has one group for each redeemable-after day it takes. In T4:

```
cd ~/ecash-wallet
cargo run -q -- --regtest fsp issue --service $SERVICE --esp 200000000000
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: `issue <id>: 2 group(s)` (one for each day: N group(s) in general) and `issued 200000000000 FSP (fee 0)`, and the audit `{"issued":900000000000,"outstanding":700000000000,"redeemed":200000000000}`: the FSP mint swapped the note at the ESP mint, so issued and redeemed each rose by 2×10^11 and outstanding did not change. The app's `balance` now shows `fsp  200000000000`, a line `handed over N time(s); the hand-overs are kept in the wallet file`, and less ESP at both days (how much of each depends on the notes taken; **not rerun**).

`export-esp` needs the FSP mint stopped (its README says so). Ctrl-C in T5, then in T1:

```
mkdir -p /tmp/fsp-esp-1
cd ~/fsp-mint
FSP_NETWORK=regtest FSP_SERVICE_DID=$SERVICE cargo run -q -- export-esp --out /tmp/fsp-esp-1
```

Expected: one `wrote …` line for each redeemable-after day the FSP mint holds, for example `wrote /tmp/fsp-esp-1/esp-20742-<time>.json (N notes)` and `wrote /tmp/fsp-esp-1/esp-21107-<time>.json (N notes)`: `export-esp` writes one file for each day (two files in the 2026-10-22 run), and only ESP it has not written before, so a later export holds only what came after. In T4, the service takes each file in with `receive`, which takes one file at a time and nothing else:

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest receive /tmp/fsp-esp-1/esp-20742-<time>.json   # and the same for the day-21107 file
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
```

Expected: for each file, `received N ESP in N note(s) for <service>, redeemable after day D`, and a service balance of the sum of the files, the day-20742 part mature today and the other year-out (**not rerun**: the figures here were for one note).

Steps 38, 40 and 43 repeat this round (steps 23 to 25 to get a fresh note, then the issue, the export and the `receive`, with the next export folder, `/tmp/fsp-esp-2` and so on). The FSP mint is stopped now; step 35 starts it again.

### 27. Redeem (T4)

The wallet redeems every mature free note for the service, here the one from step 26. The memo says where the payout goes.

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qwalkthrough'
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
```

Expected:

```
fee rate 1000000 ESP units a byte; at most 15728640 bytes a request; 1 request(s)
redemption <id>: 1 note(s) worth 200000000000 ESP ($0.200000000000), 407 bytes, fee 407000000 ESP ($0.000407000000), expected payout 199593000000 ESP ($0.199593000000)
redemption <id>: 1 of 1 note(s) accepted, 200000000000 ESP ($0.200000000000). Fee 407000000 ESP ($0.000407000000): 407 bytes at 1000000 a byte
  payout queued: owed 199593000000 ESP ($0.199593000000)
  payout is open. Check later with: redeem --collect
```

The size is `120 + 187 for each note + 21 (the memo) + 82 for each decline output`, and the fee is the size times 10^6. The block above is for one note and one decline output (`120 + 187 + 21 + 82 = 410` bytes at this build, not the 407 shown, which is the old wire's); it was calculated, not run. The 2026-10-22 run redeemed many notes at once and the request was 3054 bytes (fee 3054000000), and 4177 bytes after the decline of step 30, because the decline reissues many small notes (**not rerun** for this build). The summary line comes first, before any `not sent` line. The balance no longer has the day-20742 note and lists `pending redemption <id> (payout of 199593000000 ESP queued at the mint)`. The redemption id is the request hash.

### 28. The operator's report and the audit (T1)

```
cd ~/esp-mint
ESP_NETWORK=regtest cargo run -q -- payouts
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: one open entry for the service, owed 0.199593 USD (199593000000 ESP), memo `btc:bcrt1qwalkthrough`, the entry id equal to the redemption id; and `{"issued":900000000000,"outstanding":500000000000,"redeemed":400000000000}` (**rewritten, not run**: it was `1200…`, `500…`, `700…` when the service's note came by a transfer in the wallet, which swapped 3×10^11 more).

### 29. Collect while the payout is open (T4)

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --collect
```

Expected: the same two lines as step 27 and `payout is open`. Resending the identical request burns nothing again.

### 30. The operator declines (T1)

This is a development stand-in for delivery over the AIR.

```
ESP_NETWORK=regtest cargo run -q -- decline <redemption id> --reason "terms not met: service was offline"
ESP_NETWORK=regtest cargo run -q -- payouts
```

Expected: `declined entry <id>: 15 output(s) reissued, <owed> ESP units` (15 outputs in the 2026-10-22 run; the owed amount depends on the redemption of step 27) and then `nothing is owed: no open redemption entries`.

### 31. The service collects the decline (T4)

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --collect
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: `payout declined: terms not met: service was offline. 15 note(s) worth <owed> ESP reissued to this wallet` (15 notes, following the 15 outputs of step 30; the owed amount and the figures after it are for one note and were calculated, **not rerun**). The balance has 199,593,000,000 at day 20742 (the original day), and the audit is `{"issued":1099593000000,"outstanding":699593000000,"redeemed":400000000000}` (**rewritten, not run**). Only the fee, 407,000,000, is lost.

### 32. Redeem again and pay (T4, then T1)

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qsecondpayout'
```

Expected: 408 bytes (the memo is one byte longer), fee 408000000, payout queued `199185000000`. Then in T1, with the new id:

```
cd ~/esp-mint
ESP_NETWORK=regtest cargo run -q -- payouts
ESP_NETWORK=regtest cargo run -q -- pay $SERVICE regtest-demo-payment-1 <redemption id>
ESP_NETWORK=regtest cargo run -q -- payouts
```

Expected: one entry owed 0.199185 USD, then `marked 1 entry completed for 0279be…1798: 0.199185000000 USD (199185000000 ESP), payment reference regtest-demo-payment-1`, then `nothing is owed: no open redemption entries`.

### 33. The service sees it completed (T4)

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --collect
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: `payout completed, payment reference regtest-demo-payment-1`, an empty ESP balance (`esp  0`), and `{"issued":1099593000000,"outstanding":500000000000,"redeemed":599593000000}` (**rewritten, not run**).

### 34. The size ceiling (no command)

A request over the route's ceiling is refused before it is parsed. This was a `curl` of 1048577 bytes at the ESP's `POST /exchange`; that route is gone, and the same ceiling now applies to the sealed request the ESP's AIR listener opens: a request over it is answered with a signed refusal that carries `"http_status": 413` and the code `request_too_large`, which the wallet reads as a plain mint error and never as a refusal of the notes (README, "The ESP's calls over AIR"). It cannot be made with `curl`. It is covered by esp-mint's AIR tests and by `tests/esp_air_flow.rs` here. Nothing to run.

### 35. The FSP mint again (T5)

The FSP mint was set up in step 26 (its service key and `ECASH_AIR_FSP`) and stopped there for `export-esp`. Its data and key are kept. Start it again in T5 with the same command:

```
cd ~/fsp-mint
ESP_DID=$(cd ~/esp-mint && ESP_NETWORK=regtest cargo run -q -- pubkey)
FSP_AIR_ESP_DID=$ESP_DID FSP_AIR_ESP_SERVER=$AIR_SERVER FSP_AIR_ESP_HOST=127.0.0.1 FSP_AIR_SERVER=$AIR_SERVER FSP_AIR_HOST=127.0.0.1 FSP_NETWORK=regtest FSP_SERVICE_DID=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 cargo run -- serve
```

Expected: the same listening lines as in step 26. `ECASH_AIR_FSP` is still exported in T4.

### 36. Issue FSP from ESP (T4)

```
cd ~/ecash-wallet
cargo run -q -- --regtest fsp issue --service $SERVICE --esp 200000000000
cargo run -q -- --regtest balance
curl -s http://127.0.0.1:3100/audit; echo
```

Expected (**rewritten, not run**): `issue <id>: 1 group(s)` and `issued 200000000000 FSP (fee 0)`. This takes the app's two 10^11 notes at day 21107, the only ESP left. The balance has `esp  0` and `fsp  400000000000` (the 2×10^11 of step 26 and this 2×10^11) on a key set (`keyset <16 hex> (current)`); the number of notes depends on the amounts and was not recomputed. The ESP mint moved the two notes to a fresh note only the service controls, so the audit is `{"issued":1299593000000,"outstanding":500000000000,"redeemed":799593000000}`: issued and redeemed each rose by 2×10^11 and the outstanding total did not change.

### 37. Pay with FSP (T4)

```
cargo run -q -- --regtest fsp pay --service $SERVICE --units 50000000000 --memo "regtest coffee"
cargo run -q -- --regtest balance
```

Expected: `spend <id>` and `paid 50000000000 FSP`; the balance has `fsp  350000000000` on the current key set (**rewritten, not run**: it was `150000000000` before step 26 added 2×10^11). The spend is a swap with change: the notes in equal the change out plus the amount paid, exactly.

### Notes

- Tidy up: `rm /tmp/wallet-service*.json` and `rm -rf /tmp/fsp-esp-*`, delete `~/.esp-mint/esp-mint.toml` to put the 365-day maturity back (then `kill -HUP` the ESP mint), and stop the mints with Ctrl-C and the node with `bitcoin-cli stop`.
- Run live in the next section (steps 38 to 49): a note the mint has already burned, a redemption split over a small ceiling, `fsp-mint export-esp` and redeeming the kept ESP, and key rotation for the ESP and FSP mints. Still only in the automated tests (`tests/redeem_flow.rs`, `tests/fsp_flow.rs`): a note the mint calls immature or wrong-service, a redemption that needs refund outputs, and a mint that rotates between a wallet reading its key set and sending (`keyset_not_current`).


## Regtest, refusals, splitting, kept ESP and rotation

This continues the run above, with the same terminals (T1 to T5), the node, the PSP mint (T2), the ESP mint (T3) and the FSP mint (T5). It was run end to end on 2026-10-16 (macOS, Apple Silicon), and every output below is what that run printed, apart from values that differ each run (ids, transaction ids, hashes, times). The service wallet is `ECASH_WALLET_FILE=/tmp/wallet-service.json`, and `$SERVICE`, `$KEY`, `$CLI` are as in the earlier sections. Today's day number was 20742. **Steps 38 to 48 were run before the `hand-over` and `transfer` commands were removed. Steps 38 to 41, 45 to 48 and the figures in them were rewritten for that and are not run** (see the note at the top).

What the command line cannot reach: a note the mint calls `immature` (the wallet checks maturity on its own clock first and does not send such a note), a note for the `wrong_service` (the wallet only picks notes for the key it is given), and so a redemption that needs refund outputs. They are in the automated tests (`tests/redeem_flow.rs`).

### 38. A note the mint has already burned (T4)

A wallet restored from an old backup holds notes the mint has burned. This keeps a copy of the service wallet before a redemption and puts it back afterwards. The service wallet must hold one mature note: repeat steps 23 to 25 (the ESP mint is still on `maturity_days = 0`), stop the FSP mint, and run the round of step 26 again with `/tmp/fsp-esp-2` for the export (issue, export-esp, `receive`), then start the FSP mint again as in step 35. (The audit before this step is then `{"issued":1699593000000,"outstanding":700000000000,"redeemed":999593000000}`.)

```
cp /tmp/wallet-service.json /tmp/wallet-service.stale.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qrefusal'
cp /tmp/wallet-service.json /tmp/wallet-service.after.json
cp /tmp/wallet-service.stale.json /tmp/wallet-service.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qreplay'
```

Expected: the first redemption is accepted (`403 bytes`, fee 403000000, payout queued 199597000000). The second, built from the stale copy, is refused: `the mint refused the redemption (below_fee): the genuine, unspent notes are worth 0 ESP units, less than the fee of 402000000. Nothing was burned and no fee was taken`. The refusal is printed once (the 2026-10-22 run). The audit does not move. The refusal lists a reason for every note, and the wallet moves the notes the mint marks `already_spent` to its spent record: they leave the balance, `balance` prints `spent elsewhere N note(s)`, and the other notes are freed (the doc used to say the wallet could not tell; the wording of the refusal in this build was not captured, **not rerun**). Put the real wallet back with `cp /tmp/wallet-service.after.json /tmp/wallet-service.json`.

### 39. The operator declines (T1, then T4)

In T1:

```
cd ~/esp-mint
ESP_NETWORK=regtest cargo run -q -- decline <redemption id of step 38> --reason "dev test: splitting next"
```

In T4, after restoring the real wallet (the last command of step 38):

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --collect
```

Expected: `payout declined: dev test: splitting next. 1 note(s) worth 199597000000 ESP reissued to this wallet`. The service wallet now holds that one note, mature (day 20742). This step used to split it into three with `transfer --amounts`; the wallet cannot do that any more, so step 40 gets a second note from another round instead.

### 40. Redeem over a small ceiling (T4)

`--max-bytes` lowers the ceiling on one request, so the wallet has to split. The split sizes each request for the worst case, the most decline and refund outputs a service and day can need (64 of each), so even one note counts as 10,803 bytes plus its memo, and a ceiling below that is refused. The service needs more mature notes than fit in one request: the reissued notes of step 39 and those of another round (steps 23 to 25, then the round of step 26 with `/tmp/fsp-esp-3`, then the FSP mint started again as in step 35).

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --max-bytes 12000 --memo 'btc:bcrt1qsplit'
```

Expected (**rewritten, not run**): first the summary, `fee rate 1000000 ESP units a byte; at most 12000 bytes a request (--max-bytes); N request(s)`, then a `not sent: …` line for each part that would owe nothing, then each request that is sent, with the actual size of its request (a few thousand bytes, not the worst case). A request holds up to 7 notes at this ceiling (`120 + 187 × 7 + 15 (the memo) + 128 × 82 = 11940` fits 12000, 8 notes (12127) do not); the notes go in order, oldest day first and the largest first. In the 2026-10-22 run the first request took 7 large notes (2592 bytes) and the later parts held small notes worth less than the fee (`not sent: … less than the fee of 1444000000`, and one of 448 ESP units, less than the fee of 696000000), so only one request was sent; the small notes stay in the wallet. With `--max-bytes 500`, as this step used to say, the command now stops: `error: --max-bytes 500 is too small for even one note: a request for one note can need <n> bytes` (it used to name the mint's ceiling); a ceiling that is the mint's own is named as `the mint's ceiling of N bytes`. Each request that is sent is its own entry at the mint.

### 41. The operator pays two entries in one call (T1, then T4)

```
cd ~/esp-mint
ESP_NETWORK=regtest cargo run -q -- payouts
ESP_NETWORK=regtest cargo run -q -- pay $SERVICE regtest-split-payment <id1> <id2>
```

This step needs two entries. In the 2026-10-22 run the split sent only one request, so the two-entry call was **not run**; with notes that make two requests that each owe something it reads as follows. Expected (**rewritten, not run**): `payouts` shows one service, owed 0.398795 USD in 2 entries with one memo, and `pay` prints `marked 2 entries completed for 0279be…1798: 0.398795000000 USD (398795000000 ESP), payment reference regtest-split-payment`. Entries with different memos need `--mixed-memos`. In T4, `redeem --collect` prints `payout completed, payment reference regtest-split-payment` twice. The audit was `{"issued":2299190000000,"outstanding":500000000000,"redeemed":1799190000000}`: the decline issued 199597000000 again, and the two redemptions burned that note and the second round's.

### 42. ESP the FSP mint has kept, not yet mature (T1, then T4)

`export-esp` writes the ESP the FSP mint kept for the service and has not written before, one file per redeemable-after day. Stop the FSP mint first (Ctrl-C in T5), as its README says.

```
mkdir -p /tmp/fsp-export
cd ~/fsp-mint
FSP_NETWORK=regtest FSP_SERVICE_DID=$SERVICE cargo run -q -- export-esp --out /tmp/fsp-export
```

Expected: `wrote /tmp/fsp-export/esp-21107-<time>.json (2 notes)` (when the FSP mint has kept no ESP it has not written before, `export-esp` writes nothing and says `no ESP to export`): the FSP issue in step 36 used the two year-out notes, since FSP ignores maturity (the day-20742 ESP of the earlier rounds was exported in step 26 and the rounds after it, and is not written again). In T4:

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest receive /tmp/fsp-export/esp-21107-<time>.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest esp-schedule
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qkept'
```

Expected: `received 200000000000 ESP in 2 note(s) ... redeemable after day 21107`, a schedule with `esp held 200000000000`, `mature now 0` and `2027-10  200000000000`, and `error: this wallet holds no free ESP for that service whose redeemable-after day has come`. Nothing is sent to the mint.

### 43. Mature ESP kept by the FSP mint, redeemed (T4, T5, T1)

Buy 3 PSP (a 2 and a 1), settle and exchange 2 (steps 23 to 25, with the ESP mint still on `maturity_days = 0`), then issue FSP from the new ESP:

```
cargo run -q -- --regtest fsp issue --service $SERVICE --esp 200000000000
```

Expected: `issued 200000000000 FSP (fee 0)`. The audit's issued and redeemed each rise by 2×10^11 more (the ESP mint moves the note to a fresh one that only the service controls), and outstanding is unchanged. Stop the FSP mint (Ctrl-C in T5), then in T1:

```
mkdir -p /tmp/fsp-export2
cd ~/fsp-mint
FSP_NETWORK=regtest FSP_SERVICE_DID=$SERVICE cargo run -q -- export-esp --out /tmp/fsp-export2
```

Expected: `wrote /tmp/fsp-export2/esp-20742-<time>.json (1 notes)`. In T4:

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest receive /tmp/fsp-export2/esp-20742-<time>.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qkept'
```

Expected: `esp held 400000000000`, `mature now 200000000000`, then a redemption of 1 note worth 2×10^11, `400 bytes`, fee 400000000, payout queued 199600000000. In T1, `payouts` shows the entry and `pay $SERVICE regtest-kept-payment <id>` marks it completed; in T4, `redeem --collect` ends with `payout completed, payment reference regtest-kept-payment`. Run the `receive` and the `redeem` once. A second `receive` of the same file puts a burned note back in the wallet, and the next redemption is refused (`below_fee`, as in step 38); the mint's `transfer` route says it more clearly (`note 0 is already spent`).

### 44. ESP key rotation: make the mint rotate (T1, T3)

The settings are `rotation.activation_hours` (from the first issue to the first rotation) and `rotation.period_hours`. Both are restart-only, with a minimum of 1 hour for the period. To see a rotation without waiting, give the mint a one-hour period and back-date its recorded first issue by 90 minutes. First make a test wallet from the year-out ESP exported in step 42, and keep a copy of it. These notes are signed by the key set that is current now (T4):

```
ECASH_WALLET_FILE=/tmp/wallet-rot.json cargo run -q -- --regtest receive /tmp/fsp-export/esp-21107-<time>.json
cp /tmp/wallet-rot.json /tmp/wallet-rot.pre.json
```

Then stop the ESP mint (Ctrl-C in T3), copy its data aside, and in T1:

```
cp -R ~/.esp-mint ~/.esp-mint.pre-rotation
python3 -c 'import json,time,os; p=os.path.expanduser("~/.esp-mint/regtest/first_issue.json"); json.dump({"first_issue":int(time.time())-5400}, open(p,"w"), indent=2)'
```

In T3 (the PSP mint must be running, because the ESP mint checks its network at startup):

```
cd ~/esp-mint
ESP_AIR_SERVER=$AIR_SERVER ESP_AIR_HOST=127.0.0.1 ESP_NETWORK=regtest ESP_REDEEM_FEE_PER_BYTE=1000000 ESP_ROTATION_ACTIVATION_HOURS=1 ESP_ROTATION_PERIOD_HOURS=1 cargo run -- serve
```

Expected: `key rotation: keyset <new> (epoch 1) is now current; 507d6862e19bf815 (epoch 0) is previous`, then `previous keyset 507d6862e19bf815 (epoch 0), retires at <time>`. The wallet reads the rotation window and the keysets over AIR (step 45 runs it); the mint's `GET /rotation` and `/keysets` are gone from HTTP. The audit is unchanged.

### 45. The wallet rolls its notes over (T4)

At startup the wallet reads the ESP mint's rotation over AIR and swaps notes from the previous set to the current one. It uses the AIR settings exported in step 5 (T4):

```
ECASH_WALLET_FILE=/tmp/wallet-rot.json cargo run -q -- --regtest balance
```

Expected: `esp: rolled over N note(s) to the current key set` (not `http://127.0.0.1:3100: …`; 17 notes in the 2026-10-22 run, and no noticeable delay), and the balance is still 2×10^11. A second run prints no message. The audit counts the rollover as a burn and a re-issue: issued and redeemed each rise by the notes' value and outstanding is unchanged (here `{"issued":2899190000000,"outstanding":500000000000,"redeemed":2399190000000}`, **recomputed, not run**).

### 46. Notes from before the rotation (T4)

The stale copy's notes were burned by the rollover. The wallet's own sync tries to roll them over and the mint refuses:

```
ECASH_WALLET_FILE=/tmp/wallet-rot.pre.json cargo run -q -- --regtest balance
```

Expected (**rewritten, not run**): `esp: rollover refused (inputs 0, 1, …: the notes are already spent): N note(s) marked spent, 0 freed`, and a `spent elsewhere N note(s)` line from `balance`. The mint names every spent input of the rollover (this round), and the wallet marks all of them spent, so one run settles the stale copy and the next prints no refusal. In the 2026-10-22 run, before that change, the mint named only `input 0`, so the line read `esp: rollover refused (input 0: the note is already spent): 1 note(s) marked spent, 16 freed` and it took 17 runs for the balance to come down. The step used to run `transfer` here; `balance` prints no second line. Nothing is burned or charged.

### 47. The old key set retires, live (T1, then T4)

The mint needs no restart. At the end of the previous set's life (the `retires` time in the rotation window, here 1792166073), it deletes the key set and its spent list and lists the id as retired:

```
ECASH_WALLET_FILE=/tmp/wallet-rot.pre.json cargo run -q -- --regtest balance
ECASH_WALLET_FILE=/tmp/wallet-rot.json cargo run -q -- --regtest balance
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: the mint now has epoch 2 as current, `5e81c980bed405b1` (epoch 1) as previous and `507d…` gone (the wallet's `balance` reads the window over AIR; there is no `GET /rotation` to `curl` any more). The stale wallet says `2 note(s) expired: their key set was retired at a rotation before they were rolled over, and they are lost (not counted in the balance)` and shows `esp  0`. The other wallet rolls its notes over again (`esp: rolled over N note(s) to the current key set`) and keeps 2×10^11. The audit rose by 2×10^11 on each side for the second rollover (`{"issued":3099190000000,"outstanding":500000000000,"redeemed":2599190000000}`, **recomputed, not run**).

### 48. FSP key rotation (T1, T5, T4)

The same method for the FSP mint (FSP_ROTATION_ACTIVATION_HOURS and FSP_ROTATION_PERIOD_HOURS, a period of 1 hour at least). Stop the FSP mint, then:

```
cp -R ~/.fsp-mint ~/.fsp-mint.pre-rotation
python3 -c 'import json,time,os; p=os.path.expanduser("~/.fsp-mint/regtest/first_issue.json"); json.dump({"first_issue":int(time.time())-5400}, open(p,"w"))'
cd ~/fsp-mint
FSP_AIR_ESP_DID=$ESP_DID FSP_AIR_ESP_SERVER=$AIR_SERVER FSP_AIR_ESP_HOST=127.0.0.1 FSP_AIR_SERVER=$AIR_SERVER FSP_AIR_HOST=127.0.0.1 FSP_NETWORK=regtest FSP_SERVICE_DID=$SERVICE FSP_ROTATION_ACTIVATION_HOURS=1 FSP_ROTATION_PERIOD_HOURS=1 cargo run -- serve
```

In T4: `cargo run -q -- --regtest fsp-window --service $SERVICE` and `cargo run -q -- --regtest balance`. Expected: `fsp-window` lists the new current set (epoch 1) and the previous one `8fa2a88519b4bef5`; the first command that connects prints `fsp 0279be…1798: rollover <id>: rolled over to the current keyset` after the wallet's delay, and `balance` shows the same FSP on the new key set (550000000000 FSP: **recomputed, not run**, it was 350000000000 before step 26 added 2×10^11; the 2026-10-22 run, with extra rounds, had 750000000000: 4 × 2×10^11 issued less 5×10^10 paid) in fewer notes (the count depends on the amounts and was not recomputed). The second run prints nothing.

A stale copy of the FSP wallet (one made before the rollover, as step 44 does for the ESP) is refused at the FSP mint. In the 2026-10-22 run the mint answered `already_spent` for note 0 only, the wallet read it as a plain refusal and tried again on every connection, and `balance` kept the old FSP. The FSP mint now answers `note_spent_elsewhere` and names every spent input, and the wallet marks them spent and frees the rest: the connection logs a line `rollover refused (…): N note(s) marked spent, M freed` and the next one does not repeat it (**rewritten, not run**).

### 49. Put it away (T1)

Both mints' data now belongs to the rotated key sets, and the app wallet's FSP notes are on the FSP mint's new key set, so the data folders must go together: restoring only one of them would leave notes the mint does not know. Stop the three mints (Ctrl-C) and the node (`bitcoin-cli stop`), then move everything aside under one dated name instead of deleting it:

```
for d in .psp-mint .esp-mint .fsp-mint; do mv ~/$d ~/$d.run-20261016; done
mv ~/.ecash-wallet ~/.ecash-wallet.run-20261016   # only if a default wallet was made
mv /tmp/wallet-regtest.json /tmp/wallet-regtest.run-20261016.json
rm -f /tmp/wallet-service*.json /tmp/wallet-rot*.json
rm -rf /tmp/fsp-export /tmp/fsp-export2 /tmp/fsp-esp-*
unset ECASH_WALLET_FILE ECASH_AIR_SERVER ECASH_AIR_HOST ECASH_AIR_PSP_DID ECASH_AIR_ESP_DID ECASH_AIR_FSP AIR_SERVER ESP_DID
```

The node's regtest folder moves aside in step 1 of the next run. The copies `~/.esp-mint.pre-rotation` and `~/.fsp-mint.pre-rotation` made in steps 44 and 48 are the state from just before the rotations, and can be removed when this run's data is no longer needed. Delete `~/.esp-mint/esp-mint.toml` if you restore any of it, so the 365-day maturity applies again.
