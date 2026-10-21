# Regtest walkthrough

The wallet's end-to-end runs against a real Bitcoin Core regtest node, with the PSP, ESP and FSP mints. Steps 0 to 49, in four parts:

1. Purchase to ESP (steps 0 to 12): buy PSP, claim it, exchange it for ESP.
2. ESP transfer (steps 13 to 20): hand over, receive, transfer to the service.
3. Redemption and FSP (steps 21 to 37): redeem, decline, pay, the size ceiling, FSP issue and pay.
4. Refusals, splitting, kept ESP and rotation (steps 38 to 49): spent notes, splitting, key rotation on ESP and FSP, and the cleanup.

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

**Wire version 3 (sp-wire 0.5.0).** A service is its DID, so `$SERVICE` below is `02` and the generator's x coordinate, and a command given the old 64-character form is refused with a message that says to use the DID. The outputs below were recorded at wire version 2 and have **not been run again**: every number that comes from a size moves with the new sizes. A redemption of one note with one decline output is 3 bytes larger (`120 + 187 + memo + 82`, was `119 + 186 + memo + 81`), so its size, its fee (the size times the rate) and the payout (the note less the fee) change by that many bytes and `rate × 3` ESP units, and the audit totals that follow from them move with them. The exchange and transfer sizes are one byte larger (`49` and `121` fixed). Re-run the walkthrough to capture the new figures.

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

Set the same shell variable in every terminal below (T1 to T5). The mints take it as `PSP_AIR_SERVER`, `ESP_AIR_SERVER` and `FSP_AIR_SERVER` with the host `127.0.0.1` (the FSP mint also as `FSP_AIR_ESP_SERVER` and `FSP_AIR_ESP_HOST`, for its calls to the ESP; here the same server carries both), and the wallet as `ECASH_AIR_SERVER` and `ECASH_AIR_HOST` (step 5), plus `ECASH_AIR_FSP` for the FSP mint (step 35). Without them `psp-mint serve`, `esp-mint serve` and `fsp-mint serve` refuse to start, and a wallet command that calls the PSP or the ESP stops with an error that names `air.server` and `air.host`, and an `fsp` command for a service with no `air.fsp` entry stops with an error that names `air.fsp`. The mint's local HTTP (`/audit`, `/health` for the PSP and the ESP, `/melt`, `/burns` and the operator's routes) is unchanged; fsp-mint's only HTTP route is `/audit`. Start the mints in the order of steps 3, 4 and 35: the FSP asks the ESP over AIR at startup and exits if it cannot be reached.

### 3. The PSP mint (T2)

The log is teed to a file so the settlement and delivery lines can be read back. The signatures also go to the payer over AIR as a record on the AIR server, which is how the wallet claims them (step 9). The first build takes a few minutes.

```
cd ~/psp-mint
PSP_AIR_SERVER=$AIR_SERVER PSP_AIR_HOST=127.0.0.1 PSP_SCAN_INTERVAL_SECS=10 cargo run -- --regtest serve 2>&1 | tee ~/psp-serve.log
```

Expected: `scanning wallet psp-regtest every 10 s` and `psp-mint api listening on http://127.0.0.1:3000`. In T1, `curl -s http://127.0.0.1:3000/health` returns `"status":"ok"` and `/audit` returns `{"issued":0,"redeemed":0,"outstanding":0}`.

### 4. The ESP mint (T3)

```
cd ~/esp-mint
ESP_AIR_SERVER=$AIR_SERVER ESP_AIR_HOST=127.0.0.1 ESP_NETWORK=regtest ESP_REDEEM_FEE_PER_BYTE=1000000 cargo run -- serve
```

Every fee in esp-mint defaults to 0. This walkthrough sets the redemption fee to 10^6 ESP units a byte (`ESP_REDEEM_FEE_PER_BYTE`) so that the redemption steps below show a fee being taken; the figures in them depend on it. Start the mint the same way each time it is restarted.

Expected:

```
esp-mint api listening on http://127.0.0.1:3100, burning PSP at http://127.0.0.1:3000
esp-mint admin listening on http://127.0.0.1:3101
```

In T1, `curl -s http://127.0.0.1:3100/health` returns `{"status":"ok"}` and `/audit` returns `issued`, `outstanding` and `redeemed` all 0.

### 5. Build the purchase payload (T4)

Run this once. A second run makes a second pending purchase in the wallet file.

```
cd ~/ecash-wallet
export ECASH_WALLET_FILE=/tmp/wallet-regtest.json
MINT_KEY=$(cd ~/psp-mint && cargo run -q -- --regtest pubkey)
ESP_DID=$(cd ~/esp-mint && cargo run -q -- pubkey)
export ECASH_AIR_SERVER=$AIR_SERVER ECASH_AIR_HOST=127.0.0.1 ECASH_AIR_PSP_DID=$MINT_KEY ECASH_AIR_ESP_DID=$ESP_DID
echo ${#MINT_KEY}
HEX=$(cargo run -q -- --regtest buy-psp --mint-key $MINT_KEY 4 1)
echo ${#HEX}
```

The wallet takes both mints' DIDs from the settings (the built-in ones are placeholders until the first SPI deploy). Expected: `66` (the mint's public key in hex), then `purchase <id>` and `199 bytes. Put the hex below in an OP_RETURN and pay the PSP.` and a sentence saying the notes arrive over AIR (both on standard error, so they show on the screen but are not in `HEX`), then `398`. The payload is 117 bytes plus 82 for the encryption: 199 bytes, 398 hex characters.

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

Expected: the price (for example `82357.555`), the BTC amount (for example `0.00000613`, which is 613 sats), and JSON with a `txid` and `"complete": true`. Note the `txid`. Nothing is printed in T2 or T3 yet.

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

The locked price is the median of Coinbase, Bitstamp and Gemini, so it differs a little from the Coinbase price used to size the payment.

### 8. Settle at 6 confirmations (T4)

```
$CLI -rpcwallet=payer generatetoaddress 5 $PAYER > /dev/null
$CLI -rpcwallet=psp-regtest gettransaction <txid> | grep confirmations
```

Expected in T4: `"confirmations": 6,`. Within one scan, T2 prints the settlement:

```
<txid> confirmations=6 value_sats=613
  over/under: 91 bps
  signature <blind nonce hex> <signature hex>
  signature <blind nonce hex> <signature hex>
delivery <txid>: record written
```

The over/under is the payment against the request at the locked price: 613 sats at 82313.33 USD/BTC is about $0.5046, so about +91 basis points. That is within the 0.10 reconciliation target (`settle.payment_reconciliation_target`), so the mint keeps the extra and records no credit. Two signature lines are printed (a log; the payer gets the same signatures over AIR), one for the 4 and one for the 1, then `delivery <txid>: record written`. There is no credit, rejection or error message.

### 9. Claim the notes and check the balance (T4)

```
cargo run -q -- --regtest claim-psp
cargo run -q -- --regtest balance
```

Nothing is pasted: the wallet computes the record's address from its purchase and reads it. `claim-psp` waits up to 60 seconds for a record that is not there yet (`--wait SECONDS`). Expected:

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
received 400000000000 ESP in 2 note(s), redeemable after day 21106
100000000000 of that is change: the PSP notes spent were worth more than the amount asked for, and the rest came back as ESP under the same terms

psp  1
esp  400000000000
       400000000000 for 0279be...1798, redeemable after day 21106
fsp  0
notes 3 (0 held for a pending request)
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
received 100000000000 ESP in 1 note(s), redeemable after day 21106

psp  0
esp  500000000000
       500000000000 for 0279be...1798, redeemable after day 21106
fsp  0
notes 3 (0 held for a pending request)
```

There is no change line, because the 1 PSP note is exactly the amount asked for. The three ESP notes (a 3 PSP note and a 1 PSP note from the first exchange, and a 1 PSP note from this one) are all bound to the same service and day.

### Notes

- If `exchange` times out, run it again with `--resume <id>` (the id was printed). It sends the same request and gets the same answer, and nothing is burned twice.
- The PSP writes each payer's signatures to a record only that payer can find, so `claim-psp` reads its own purchases' records and no one else's. Any wallet command also picks up a delivery when it starts, so the line above may be printed by the command that ran first, and `claim-psp` then says there is nothing pending.
- A payment the PSP holds (paid, but short beyond its reconciliation target) or rejects is delivered too, so the wallet shows `the PSP is holding the payment` or `the PSP rejected it`, with what was paid and the time it stays open until, and keeps the purchase and its key. When that time passes the PSP forfeits the payment and the next wallet command prints `its reconciliation window has closed` and deletes the purchase and the key. The PSP's window is `PSP_RECONCILIATION_WINDOW_DAYS` (7); set `1` on the PSP to see it close sooner.
- Stop the servers with Ctrl-C in T2 and T3, and the node with `$CLI stop`.

## Regtest, ESP transfer

This continues the run above, with the app wallet still holding 5 PSP of ESP (notes of 3, 1 and 1 PSP) for the service below. It needs T1 to T4 as before. T2 (the PSP mint) is restarted in step 13 and otherwise only answers the ESP mint. The Bitcoin node (T1) must be running, because the PSP scans it. The service's secret key in this run is the test key `000...01`, whose public key is the generator point used as the service in step 10. It was run end to end on 2026-10-15 (macOS, Apple Silicon) and every output below is what that run printed, apart from values that differ each run (the transfer id) and the service key, which the wallet prints in full.

The app wallet is `$ECASH_WALLET_FILE` (the one used so far in T4). The service has its own wallet files, set per command with `ECASH_WALLET_FILE=...` in front.

### 13. Restart both mints on the new build (T2, T3)

The PSP now keeps the memo of each burn and has `POST /burns`, and the ESP mint now has the transfer call and asks the PSP for the memo. Restart the PSP first, then the ESP mint. Their data in `~/.psp-mint` and `~/.esp-mint` is kept.

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

### 14. An inexact hand-over is refused (T4)

The app holds notes of 3, 1 and 1 PSP. No set of them adds up to 1.5 PSP.

```
cd ~/ecash-wallet
cargo run -q -- --regtest hand-over --service $SERVICE --esp 150000000000 --out /tmp/handover.json
```

Expected, and no file is written:

```
error: no set of this wallet's ESP notes for that service and day adds up to exactly 150000000000 ESP units (it holds 500000000000 in notes of [300000000000, 100000000000, 100000000000]). A transfer is exact and a note cannot be split, so ask for an amount the notes add up to
```

### 15. Hand over 3 PSP (T4)

```
cargo run -q -- --regtest hand-over --service $SERVICE --psp 3 --out /tmp/handover.json
cargo run -q -- --regtest balance
```

Expected:

```
handed over 300000000000 ESP in 1 note(s), redeemable after day 21106
wrote /tmp/handover.json. It holds the notes' spend secrets: give it to the service, and keep it private

psp  0
esp  200000000000
       200000000000 for 0279be...1798, redeemable after day 21106
fsp  0
notes 2 (0 held for a pending request)
handed over 1 time(s); the hand-overs are kept in the wallet file
```

### 16. The service receives it (T4)

The service is a second wallet file.

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest receive /tmp/handover.json
```

Expected:

```
received 300000000000 ESP in 1 note(s) for 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, redeemable after day 21106
```

Running it a second time on the same wallet file is refused, because the wallet already holds that note.

### 17. The service transfers (T4)

The service signs with its secret key, `000...01`. The ESP mint (T3) must be running.

```
KEY=0000000000000000000000000000000000000000000000000000000000000001
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest transfer --service-key $KEY
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
```

Expected (the first line goes to standard error, and the id differs each run):

```
transfer <id> (300000000000 ESP in 1 note(s))
transferred 300000000000 ESP to 1 new note(s) that only this service controls, redeemable after day 21106

psp  0
esp  300000000000
       300000000000 for 0279be...1798, redeemable after day 21106
fsp  0
notes 1 (0 held for a pending request)
```

The note the service now holds is new. The old one was burned, and the app's copy of its secret is useless.

### 18. Audit the ESP mint (T1)

```
curl -s http://127.0.0.1:3100/audit
```

Expected: `{"issued":800000000000,"outstanding":500000000000,"redeemed":300000000000}`. The 3 PSP of ESP was burned and 3 PSP of new ESP was issued, so issued and redeemed both rose by 3 PSP and the outstanding total is still the 5 PSP it was before the transfer. The PSP audit on port 3000 is unchanged from the end of step 12: `{"issued":5,"redeemed":5,"outstanding":0}`, since all 5 PSP bought have been burned and a transfer never touches the PSP.

### 19. Presenting the same notes again (T4)

The app could have kept a copy of the hand-over file. A third wallet takes it in and tries to transfer the notes that were already swapped.

```
ECASH_WALLET_FILE=/tmp/wallet-service2.json cargo run -q -- --regtest receive /tmp/handover.json
ECASH_WALLET_FILE=/tmp/wallet-service2.json cargo run -q -- --regtest transfer --service-key $KEY
ECASH_WALLET_FILE=/tmp/wallet-service2.json cargo run -q -- --regtest balance
```

Expected: the receive line from step 16, then

```
transfer <id> (300000000000 ESP in 1 note(s))
error: the mint refused the request: {"error":"note 0 is already spent"}
```

and then a balance of `esp  300000000000` with `notes 1 (0 held for a pending request)`. The mint refused, so nothing was burned and the wallet freed the note. The audit in step 18 is unchanged.

### 20. The wrong service key (T4)

The wallet from step 17 holds ESP for the generator point. A different key is a different service.

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest transfer --service-key 0000000000000000000000000000000000000000000000000000000000000002
```

Expected, and nothing is sent:

```
error: no free ESP for that service in this wallet
```

### Notes

- If `transfer` times out, run it again with `--resume <id>`. It sends the same request and gets the same answer, and nothing is burned twice.
- The hand-over file and the wallet files are test data. Delete `/tmp/handover.json`, `/tmp/wallet-service.json` and `/tmp/wallet-service2.json` when done.

## Regtest, redemption and FSP

This continues the two runs above (purchase to ESP, then the transfer), with the same four terminals, the Bitcoin node, the PSP mint (T2) and the ESP mint (T3) running, and one more terminal, T5, for the FSP mint. It was run end to end on 2026-10-16 (macOS, Apple Silicon) from a clean start (step 1 moved the old data aside), and every output below is what that run printed, apart from values that differ each run (ids, transaction ids, keys, the price, the day numbers). Today's day number in that run was 20742, so notes issued after step 22 are "redeemable after day 20742" and the year-out notes are day 21107. Use your own: the day is the number of days since 1970-01-01, and the first run's notes carry today plus 365.

The app wallet is the default one, `~/.ecash-wallet/regtest/wallet.json`. The service has its own wallet file, set per command with `ECASH_WALLET_FILE=/tmp/wallet-service.json`. `$SERVICE` is the generator point `0279be…1798` and `$KEY` its secret key `000…01` (see "Regtest, ESP transfer"). `$CLI`, `$PAYER`, `$HEX` and `$TXID` are shell variables in T4.

### 21. The ESP mint's rates (no command)

The ESP's rates are an AIR call now (`GET /fees` is gone from HTTP), and the wallet reads them when it needs them: `redeem` prints each request's size and fee, and `exchange` and `transfer` check the mint's item limits before building. The mint's settings are what they were: `exchange` with `fee_per_byte "0"`, `maturity_days 365`, `max_items 1000`, `max_request_bytes 1048576`, `min_psp 1` and size `49 + 146 per input + 41 per output`; `transfer` with fee `"0"`, ceiling 1048576 and size `121 + 146 + 41`; `redeem` with `fee_per_byte "1000000"` (set by `ESP_REDEEM_FEE_PER_BYTE` in step 4; the default is `"0"`), `max_memo_bytes 256`, `max_request_bytes 15728640` and size `120 + 187 per input + 82 per output + the memo` (esp-mint README, "Settings and fees"). Nothing to run here; the fee shows in step 23's redemption.

### 22. Make new notes mature the day they are issued (T1)

A redemption needs notes whose day has come, and the notes so far are a year out. Change the setting and reload the running mint with `SIGHUP`, with no restart:

```
cat > ~/.esp-mint/esp-mint.toml <<'EOT'
[terms]
maturity_days = 0
EOT
kill -HUP $(pgrep -f 'target/debug/esp-mint serve')
sleep 1
```

Expected: T3 prints `esp-mint: SIGHUP, settings read again:` and `  terms.maturity_days changed from 365 to 0 days`. Notes already issued keep their day, and an exchange from now on gives notes that mature the day they are issued.

### 23. Buy 3 more PSP, a 2 and a 1 (T4)

```
cd ~/ecash-wallet
MINT_KEY=$(cd ~/psp-mint && cargo run -q -- --regtest pubkey 2>/dev/null)
echo ${#MINT_KEY}
HEX=$(cargo run -q -- --regtest buy-psp --mint-key $MINT_KEY 2 1)
echo ${#HEX}
```

Expected: `66`, `purchase <id>`, `199 bytes. Put the hex below in an OP_RETURN and pay the PSP.` and a sentence saying the notes arrive over AIR, and `398` (two outputs, the same size as in step 5). The purchase is 3 PSP and not 2 because of the dust limit: Bitcoin Core will not send an output below 294 sats (for this address type), which is about $0.24 at this price, so 2 PSP ($0.20) could only be paid by overpaying. 3 PSP ($0.30) is paid with 368 sats. `2>/dev/null` hides the banner `pubkey` prints on standard error.

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

Expected in T4: `"confirmations": 6,`. Within a scan T2 prints the settlement (the price is locked and settled in one pass when all six blocks arrive at once): `<txid> confirmations=6 value_sats=368`, `over/under: 83 bps` (within the 0.10 reconciliation target, so no credit), `keyset <id>`, two `signature` lines and `delivery <txid>: record written`.

### 25. Claim and exchange (T4)

```
cargo run -q -- --regtest claim-psp
cargo run -q -- --regtest exchange --service $SERVICE --psp 2
cargo run -q -- --regtest balance
```

Expected: `purchase <id>: claimed 3 PSP in 2 note(s)` (the earlier purchase was claimed in step 9 and is not asked for again); then `received 200000000000 ESP in 1 note(s), redeemable after day 20742`. The balance shows ESP 4×10^11: 2×10^11 at day 20742 and 2×10^11 at day 21107, and `psp  1` (the 1 PSP note of the purchase is not exchanged).

### 26. Hand over, receive, and transfer the mature note (T4)

```
cargo run -q -- --regtest hand-over --service $SERVICE --psp 2 --day 20742 --out /tmp/handover2.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest receive /tmp/handover2.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest transfer --service-key $KEY --day 20742
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
```

Expected: the hand-over and receive lines for 2×10^11 at day 20742, then `transferred 200000000000 ESP to 1 new note(s) that only this service controls, redeemable after day 20742`. The service wallet holds 2×10^11 at day 20742 and 3×10^11 at day 21107 (`esp  500000000000`, `notes 2`).

### 27. Redeem (T4)

The wallet redeems every mature free note for the service and leaves the day-21107 note alone. The memo says where the payout goes.

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qwalkthrough'
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
```

Expected:

```
fee rate 1000000 ESP units a byte; at most 67108864 bytes a request; 1 request(s)
redemption <id>: 1 note(s) worth 200000000000 ESP ($0.200000000000), 407 bytes, fee 407000000 ESP ($0.000407000000), expected payout 199593000000 ESP ($0.199593000000)
redemption <id>: 1 of 1 note(s) accepted, 200000000000 ESP ($0.200000000000). Fee 407000000 ESP ($0.000407000000): 407 bytes at 1000000 a byte
  payout queued: owed 199593000000 ESP ($0.199593000000)
  payout is open. Check later with: redeem --collect
```

The size is `119 + 186 + 21 (memo) + 81 (one decline output) = 407`, so the fee is `407 × 10^6`. The balance no longer has the day-20742 note and lists `pending redemption <id> (payout of 199593000000 ESP queued at the mint)`. The redemption id is the request hash.

### 28. The operator's report and the audit (T1)

```
cd ~/esp-mint
ESP_NETWORK=regtest cargo run -q -- payouts
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: one open entry for the service, owed 0.199593 USD (199593000000 ESP), memo `btc:bcrt1qwalkthrough`, the entry id equal to the redemption id; and `{"issued":1200000000000,"outstanding":500000000000,"redeemed":700000000000}`.

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

Expected: `declined entry <id>: 1 output(s) reissued, 199593000000 ESP units` and then `nothing is owed: no open redemption entries`.

### 31. The service collects the decline (T4)

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --collect
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest balance
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: `payout declined: terms not met: service was offline. 1 note(s) worth 199593000000 ESP reissued to this wallet`. The balance has 199,593,000,000 at day 20742 (the original day) and 3×10^11 at day 21107, and the audit is `{"issued":1399593000000,"outstanding":699593000000,"redeemed":700000000000}`. Only the fee, 407,000,000, is lost.

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

Expected: `payout completed, payment reference regtest-demo-payment-1`, a balance of only the 3×10^11 at day 21107, and `{"issued":1399593000000,"outstanding":500000000000,"redeemed":899593000000}`.

### 34. The size ceiling (no command)

A request over the route's ceiling is refused before it is parsed. This was a `curl` of 1048577 bytes at the ESP's `POST /exchange`; that route is gone, and the same ceiling now applies to the sealed request the ESP's AIR listener opens: a request over it is answered with a signed refusal that carries `"http_status": 413` and the code `request_too_large`, which the wallet reads as a plain mint error and never as a refusal of the notes (README, "The ESP's calls over AIR"). It cannot be made with `curl`. It is covered by esp-mint's AIR tests and by `tests/esp_air_flow.rs` here. Nothing to run.

### 35. The FSP mint (T1, then T5)

The FSP mint holds the service's DID key, `service_key.hex`. For this run it holds the test key, so the ESP the app already has can be used. A real service makes its own with `fsp-mint service-key`.

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
ESP_DID=$(cd ~/esp-mint && cargo run -q -- pubkey)
FSP_AIR_ESP_DID=$ESP_DID FSP_AIR_ESP_SERVER=$AIR_SERVER FSP_AIR_ESP_HOST=127.0.0.1 FSP_AIR_SERVER=$AIR_SERVER FSP_AIR_HOST=127.0.0.1 FSP_NETWORK=regtest FSP_SERVICE_DID=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 cargo run -- serve
```

Expected: the settings (with `service.did` from the environment), `fsp-mint api listening on http://127.0.0.1:3200` (the operator's `/audit` only) and `fsp-mint AIR listener: wallets reach this service with the air.fsp entry 0279be…1798@<AIR server key>@127.0.0.1 (ECASH_AIR_FSP, air.fsp; …)`. The entry is what the wallet needs: it is the service's DID, the AIR server the FSP mint listens on, and the host. In T1, `curl -s http://127.0.0.1:3200/audit` returns the FSP mint's counts. The FSP mint's other calls (`/health`, `/keys`, `/fees`, `/rotation`, `/issue`, `/spend`) are AIR calls now, so there is no `curl` for them. In T4, give the wallet the entry (the same variable for every `fsp` command below; the service wallet too, if it uses `fsp`):

```
export ECASH_AIR_FSP=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798@$AIR_SERVER@127.0.0.1
```

Without it `fsp issue --service $SERVICE ...` stops with an error that names `air.fsp` and the service, and sends nothing.

### 36. Issue FSP from ESP (T4)

```
cd ~/ecash-wallet
cargo run -q -- --regtest fsp issue --service $SERVICE --esp 200000000000
cargo run -q -- --regtest balance
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: `issue <id>: 1 group(s)` and `issued 200000000000 FSP (fee 0)`. The balance has `esp  0` and `fsp  200000000000` on a key set (`keyset <16 hex> (current)`) in 15 power-of-two notes. The ESP mint moved the app's 2 PSP note to a fresh note only the service controls, so the audit is `{"issued":1599593000000,"outstanding":500000000000,"redeemed":1099593000000}`: issued and redeemed each rose by 2×10^11 and the outstanding total did not change.

### 37. Pay with FSP (T4)

```
cargo run -q -- --regtest fsp pay --service $SERVICE --units 50000000000 --memo "regtest coffee"
cargo run -q -- --regtest balance
```

Expected: `spend <id>` and `paid 50000000000 FSP`; the balance has `fsp  150000000000` on the current key set. The spend is a swap with change: the notes in equal the change out plus the amount paid, exactly.

### Notes

- Tidy up: `rm /tmp/handover*.json /tmp/wallet-service*.json`, delete `~/.esp-mint/esp-mint.toml` to put the 365-day maturity back (then `kill -HUP` the ESP mint), and stop the mints with Ctrl-C and the node with `bitcoin-cli stop`.
- Run live in the next section (steps 38 to 49): a note the mint has already burned, a split over a small ceiling, `fsp-mint export-esp` and redeeming the kept ESP, and key rotation for the ESP and FSP mints. Still only in the automated tests (`tests/redeem_flow.rs`, `tests/fsp_flow.rs`): a note the mint calls immature or wrong-service, a redemption that needs refund outputs, and a mint that rotates between a wallet reading its key set and sending (`keyset_not_current`).


## Regtest, refusals, splitting, kept ESP and rotation

This continues the run above, with the same terminals (T1 to T5), the node, the PSP mint (T2), the ESP mint (T3) and the FSP mint (T5). It was run end to end on 2026-10-16 (macOS, Apple Silicon), and every output below is what that run printed, apart from values that differ each run (ids, transaction ids, hashes, times). The service wallet is `ECASH_WALLET_FILE=/tmp/wallet-service.json`, and `$SERVICE`, `$KEY`, `$CLI` are as in the earlier sections. Today's day number was 20742.

What the command line cannot reach: a note the mint calls `immature` (the wallet checks maturity on its own clock first and does not send such a note), a note for the `wrong_service` (the wallet only picks notes for the key it is given), and so a redemption that needs refund outputs. They are in the automated tests (`tests/redeem_flow.rs`).

### 38. A note the mint has already burned (T4)

A wallet restored from an old backup holds notes the mint has burned. This keeps a copy of the service wallet before a redemption and puts it back afterwards. The service wallet must hold one mature note (hand-over, receive and transfer as in step 26).

```
cp /tmp/wallet-service.json /tmp/wallet-service.stale.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qrefusal'
cp /tmp/wallet-service.json /tmp/wallet-service.after.json
cp /tmp/wallet-service.stale.json /tmp/wallet-service.json
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --memo 'btc:bcrt1qreplay'
```

Expected: the first redemption is accepted (`403 bytes`, fee 403000000, payout queued 199597000000). The second, built from the stale copy, is refused: `the mint refused the redemption (below_fee): the genuine, unspent notes are worth 0 ESP units, less than the fee of 402000000. Nothing was burned and no fee was taken`. The refusal is printed twice (once per request, once at exit). The audit does not move. The wallet still lists the note as free: `below_fee` says only that no genuine unspent note is left, not which note is the problem, so the wallet cannot tell that this note was burned. Put the real wallet back with `cp /tmp/wallet-service.after.json /tmp/wallet-service.json`.

### 39. The operator declines, and the service splits the note (T1, then T4)

In T1:

```
cd ~/esp-mint
ESP_NETWORK=regtest cargo run -q -- decline <redemption id of step 38> --reason "dev test: splitting next"
```

In T4, after restoring the real wallet (the last command of step 38):

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --collect
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest transfer --service-key $KEY --amounts 100000000000,60000000000,39597000000
```

Expected: `payout declined: dev test: splitting next. 1 note(s) worth 199597000000 ESP reissued to this wallet`, then `transferred 199597000000 ESP to 3 new note(s) that only this service controls`. The amounts must add up to the note's value exactly (a transfer is exact); a transfer made from the stale copy would say so.

### 40. Redeem over a small ceiling (T4)

`--max-bytes` lowers the ceiling on one request, so the wallet has to split.

```
ECASH_WALLET_FILE=/tmp/wallet-service.json cargo run -q -- --regtest redeem --service-key $KEY --max-bytes 600 --memo 'btc:bcrt1qsplit'
```

Expected: `at most 600 bytes a request; 3 request(s)`, then three redemptions of one note each, every one `401 bytes` (119 + 186 + 15 for the memo + 81 for one decline output), fee 401000000, with payouts 99599000000, 59599000000 and 39196000000 queued. Each request is its own entry at the mint.

### 41. The operator pays three entries in one call (T1, then T4)

```
cd ~/esp-mint
ESP_NETWORK=regtest cargo run -q -- payouts
ESP_NETWORK=regtest cargo run -q -- pay $SERVICE regtest-split-payment <id1> <id2> <id3>
```

Expected: `payouts` shows one service, owed 0.198394 USD in 3 entries with one memo, and `pay` prints `marked 3 entries completed for 0279be…1798: 0.198394000000 USD (198394000000 ESP), payment reference regtest-split-payment`. Entries with different memos need `--mixed-memos`. In T4, `redeem --collect` prints `payout completed, payment reference regtest-split-payment` three times. The audit was `{"issued":2398787000000,"outstanding":500000000000,"redeemed":1898787000000}`: the decline and the transfer each issued 199597000000 again, and the three redemptions burned it.

### 42. ESP the FSP mint has kept, not yet mature (T1, then T4)

`export-esp` writes the ESP the FSP mint kept for the service, one hand-over file per redeemable-after day. Stop the FSP mint first (Ctrl-C in T5), as its README says.

```
mkdir -p /tmp/fsp-export
cd ~/fsp-mint
FSP_NETWORK=regtest FSP_SERVICE_DID=$SERVICE cargo run -q -- export-esp --out /tmp/fsp-export
```

Expected: `wrote /tmp/fsp-export/esp-21107-<time>.json (2 notes)`: the FSP issue in step 36 used the year-out ESP, since FSP ignores maturity. In T4:

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

Expected: after a pause (the wallet's own random delay, at most 0.5% of the period, 18 seconds here) `http://127.0.0.1:3100: rolled over 2 note(s) to the current key set`, and the balance is still 2×10^11. A second run prints no message. The audit counts the rollover as a burn and a re-issue: issued and redeemed each rise by the notes' value and outstanding is unchanged (here `{"issued":2998787000000,"outstanding":500000000000,"redeemed":2498787000000}`).

### 46. Notes from before the rotation (T4)

The stale copy's notes were burned by the rollover. The wallet's own sync tries to roll them over and the mint refuses:

```
ECASH_WALLET_FILE=/tmp/wallet-rot.pre.json cargo run -q -- --regtest transfer --service-key $KEY --day 21107
```

Expected: `rollover refused, notes freed: : input 0: the note is already spent`, then `error: the mint refused the request: {"error":"note 0 is already spent"}`. Nothing is burned or charged. The wallet cannot tell the notes are spent and tries the same rollover on every run.

### 47. The old key set retires, live (T1, then T4)

The mint needs no restart. At the end of the previous set's life (the `retires` time in the rotation window, here 1792166073), it deletes the key set and its spent list and lists the id as retired:

```
ECASH_WALLET_FILE=/tmp/wallet-rot.pre.json cargo run -q -- --regtest balance
ECASH_WALLET_FILE=/tmp/wallet-rot.json cargo run -q -- --regtest balance
curl -s http://127.0.0.1:3100/audit; echo
```

Expected: the mint now has epoch 2 as current, `5e81c980bed405b1` (epoch 1) as previous and `507d…` gone (the wallet's `balance` reads the window over AIR; there is no `GET /rotation` to `curl` any more). The stale wallet says `2 note(s) expired: their key set was retired at a rotation before they were rolled over, and they are lost (not counted in the balance)` and shows `esp  0`. The other wallet rolls its notes over again (`rolled over 2 note(s) to the current key set`) and keeps 2×10^11. The audit rose by 2×10^11 on each side for the second rollover (`{"issued":3198787000000,"outstanding":500000000000,"redeemed":2698787000000}`).

### 48. FSP key rotation (T1, T5, T4)

The same method for the FSP mint (FSP_ROTATION_ACTIVATION_HOURS and FSP_ROTATION_PERIOD_HOURS, a period of 1 hour at least). Stop the FSP mint, then:

```
cp -R ~/.fsp-mint ~/.fsp-mint.pre-rotation
python3 -c 'import json,time,os; p=os.path.expanduser("~/.fsp-mint/regtest/first_issue.json"); json.dump({"first_issue":int(time.time())-5400}, open(p,"w"))'
cd ~/fsp-mint
FSP_AIR_ESP_DID=$ESP_DID FSP_AIR_ESP_SERVER=$AIR_SERVER FSP_AIR_ESP_HOST=127.0.0.1 FSP_AIR_SERVER=$AIR_SERVER FSP_AIR_HOST=127.0.0.1 FSP_NETWORK=regtest FSP_SERVICE_DID=$SERVICE FSP_ROTATION_ACTIVATION_HOURS=1 FSP_ROTATION_PERIOD_HOURS=1 cargo run -- serve
```

In T4: `cargo run -q -- --regtest fsp-window --service $SERVICE` and `cargo run -q -- --regtest balance`. Expected: `fsp-window` lists the new current set (epoch 1) and the previous one `8fa2a88519b4bef5`; the first command that connects prints `fsp 0279be…1798: rollover <id>: rolled over to the current keyset` after the wallet's delay, and `balance` shows the same 350000000000 FSP on the new key set in fewer notes (the count depends on the amounts and was not recomputed). The second run prints nothing.

### 49. Put it away (T1)

Both mints' data now belongs to the rotated key sets, and the app wallet's FSP notes are on the FSP mint's new key set, so the data folders must go together: restoring only one of them would leave notes the mint does not know. Stop the three mints (Ctrl-C) and the node (`bitcoin-cli stop`), then move everything aside under one dated name instead of deleting it:

```
for d in .psp-mint .esp-mint .fsp-mint; do mv ~/$d ~/$d.run-20261016; done
mv ~/.ecash-wallet ~/.ecash-wallet.run-20261016
rm -f /tmp/handover*.json /tmp/wallet-service*.json /tmp/wallet-rot*.json
rm -rf /tmp/fsp-export /tmp/fsp-export2
unset ECASH_AIR_SERVER ECASH_AIR_HOST ECASH_AIR_PSP_DID ECASH_AIR_ESP_DID ECASH_AIR_FSP AIR_SERVER ESP_DID
```

The node's regtest folder moves aside in step 1 of the next run. The copies `~/.esp-mint.pre-rotation` and `~/.fsp-mint.pre-rotation` made in steps 44 and 48 are the state from just before the rotations, and can be removed when this run's data is no longer needed. Delete `~/.esp-mint/esp-mint.toml` if you restore any of it, so the 365-day maturity applies again.
