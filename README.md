# ecash-wallet

One wallet library for PSP, ESP and FSP (Primary, Encumbered and Fast Service Points), with a thin command line. AIR apps embed the library. The command line only parses arguments and prints, so everything it does is a call into the library.

The library holds no BTC wallet. The app's own Bitcoin wallet puts the bytes from `build_psp_payload` in an OP_RETURN and pays.

## Status

Nothing here has been compiled or run yet. Run `cargo test` first (see "Tests").

Built:

- Blinding and unblinding (`src/blind.rs`).
- The note file (`src/store.rs`).
- PSP purchase: `build_psp_payload` and `claim_psp` (`src/psp.rs`).
- ESP exchange: `build_exchange`, `finish_exchange` and `cancel_exchange` (`src/esp.rs`), and the HTTP calls (`src/http.rs`).
- The command line: `buy-psp`, `claim-psp`, `exchange`, `balance`.

Entry points that return "not built": `transfer_esp` (`src/transfer.rs`), `redeem_esp` (`src/redeem.rs`), `get_fsp` and `spend_fsp` (`src/fsp.rs`). The commands `transfer`, `redeem` and `fsp` call them.

## Setup

The crate depends on its sibling crates by path, so these folders must sit next to `ecash-wallet`: `psp-mint`, `esp-mint`, `air` and `substance` (which `air` needs). The mint-core crates come from git, tag `v0.1.2`.

```
cd ~/ecash-wallet
cargo test
```

The `http` feature is on by default. It adds the HTTP client and the command line. An app that sends requests its own way can turn it off and use only the library.

## Notes and the wallet file

Each note is stored with its spend key, its amount and its terms (an ESP note has a service and a redeemable-after day). The notes, and the requests that have been sent and are waiting for a reply, are one JSON file:

- `--wallet FILE`, else `$ECASH_WALLET_FILE`, else `~/.ecash-wallet/wallet.json`.
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

1. Takes the note sizes in PSP (powers of two from 1 to 1,048,576, at most 255) and a 33-byte `reply_did`.
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

`build_exchange` picks PSP notes that add up to exactly `psp_units`, so the mint never sees an excess. It splits the ESP into `esp_amounts` (default one note of `psp_units * 10^12`, which fits up to 18,446,744 PSP), signs every PSP input over the exchange memo, and reserves the notes. `finish_exchange` unblinds the mint's reply into ESP notes, each with the service and redeemable-after day, and removes the PSP notes that paid for them. `cancel_exchange` frees the reserved notes, and is only safe when the mint refused the request. After a timeout or a fault, send the same request again: the mint stores its answers by request hash.

`http::fetch_psp_keys(base)` and `http::send_exchange(base, &request)` make the two HTTP calls. A `400` is `WalletError::Refused` (nothing was burned). Anything else that goes wrong is `WalletError::Mint` (the outcome may be unknown).

### Transfer, redemption and FSP

Not built. `transfer_esp`, `redeem_esp`, `get_fsp` and `spend_fsp` exist so the shape of the API is fixed, and return `WalletError::NotBuilt`. Their docs say what each will do. They wait on the ESP mint's `/transfer` and `/redeem` and on fsp-mint.

### The reply DID

`build_psp_payload` takes the reply DID from the caller. The command line uses a stand-in, a made-up 33-byte key kept in the wallet file (`reply_did`), until a wallet has a real AIR identity. The PSP mint treats the field as opaque bytes, and the signatures are not delivered to it yet (see Left to do).

## Command line

```
ecash-wallet [--wallet FILE] <command>
```

| Command | What it does |
|---|---|
| `buy-psp --mint-key HEX [--reply-did HEX] AMOUNT...` | Prints the encrypted payload as hex on standard output and the purchase id on standard error. |
| `claim-psp [--psp-url URL] [--file FILE\|-] [BLIND_NONCE:SIGNATURE...]` | Claims the PSP's signatures. With no file or pairs it reads standard input. |
| `exchange --service HEX --psp N [--amounts A,B,C] [--esp-url URL] [--resume ID]` | Exchanges N PSP for ESP bound to a service (32-byte x-only key, hex). `--resume` sends a pending request again. |
| `balance` | PSP, ESP (by service and day) and FSP held, and what is waiting. |
| `transfer`, `redeem`, `fsp` | Print "not built yet". |

URLs default to `$ECASH_PSP_URL` and `$ECASH_ESP_URL`, else `http://127.0.0.1:3000` and `http://127.0.0.1:3100`. On a `400` the exchange frees its PSP notes. On any other failure it keeps the request and prints the `--resume` command.

## Regtest, from purchase to ESP

This assumes the psp-mint README steps 1 to 4 are done (the node is running, the `psp` and `payer` wallets exist and `payer` is funded). Use four terminals. In each one that needs it: `CLI=~/bitcoin-core/bitcoin-31.1/bin/bitcoin-cli`.

Stop any one-shot `psp-mint` run, and use fresh data directories if you tested before. Old settlements are not a problem, but an old wallet file will show old pending purchases.

**Terminal 1, the PSP.** The log is teed to a file because the signatures are printed there, a development stand-in for delivery over the AIR.

```
cd ~/psp-mint
PSP_SCAN_INTERVAL_SECS=10 cargo run -- serve 2>&1 | tee ~/psp-serve.log
```

**Terminal 2, the ESP.**

```
cd ~/esp-mint
cargo run -- serve
```

**Terminal 3, the wallet.** Get the mint's key and make the payload for 5 PSP, a 4 and a 1. The payload goes on standard output and the purchase id on standard error.

```
cd ~/ecash-wallet
export ECASH_WALLET_FILE=/tmp/wallet-regtest.json
MINT_KEY=$(cd ~/psp-mint && cargo run -q -- pubkey)
HEX=$(cargo run -q -- buy-psp --mint-key $MINT_KEY 4 1)
echo ${#HEX}
```

`echo` should print 380 (a 158-byte payload plus 82 for the encryption would be 240, so for two outputs it is 117 + 82 = 199 bytes, 398 hex characters). If it prints 398, the payload is the expected size.

Pay the PSP address with a little over $5 of BTC. This takes the live price and pays 1% over, which the mint keeps:

```
PRICE=$(curl -s https://api.coinbase.com/v2/prices/BTC-USD/spot | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["amount"])')
AMOUNT=$(python3 -c "print(f'{5.05/$PRICE:.8f}')")
PSP_ADDR=$($CLI -rpcwallet=psp getnewaddress)
$CLI -rpcwallet=payer -named send outputs="[{\"$PSP_ADDR\":$AMOUNT},{\"data\":\"$HEX\"}]" fee_rate=10
```

Mine one block, wait for terminal 1 to print `price locked`, then mine five more and wait for the next scan:

```
PAYER=$($CLI -rpcwallet=payer getnewaddress)
$CLI -rpcwallet=payer generatetoaddress 1 $PAYER > /dev/null
# wait for "price locked" in terminal 1
$CLI -rpcwallet=payer generatetoaddress 5 $PAYER > /dev/null
# wait for the two "signature" lines in terminal 1
```

Claim the notes, exchange them for ESP bound to a service (the key below is the generator point, a test value), and look at the balance:

```
cargo run -q -- claim-psp --file ~/psp-serve.log
cargo run -q -- balance
SERVICE=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
cargo run -q -- exchange --service $SERVICE --psp 5
cargo run -q -- balance
```

Expected:

- `claim-psp` prints `claimed 5 PSP in 2 note(s); 0 output(s) still waiting`. The first `balance` shows `psp 5`.
- `exchange` prints `received 5000000000000 ESP in 1 note(s), redeemable after day ...`. The second `balance` shows `psp 0` and `esp 5000000000000`.
- Terminal 2's `curl -s http://127.0.0.1:3100/audit` shows `issued` 5000000000000, and terminal 1's `/audit` on port 3000 shows the 5 PSP as `redeemed`.

If `exchange` times out, run it again with `--resume <id>` (the id was printed). It sends the same request and gets the same answer, and nothing is burned twice.

## Tests

`cargo test` runs:

- **Blinding.** An unblinded signature verifies against the mint's key. A wrong key or wrong blinding factor does not.
- **Note file.** A change is saved before the call returns. A reopened wallet has the same notes. A corrupt file is an error and is not replaced. The file is `0600`.
- **PSP.** A payload round trip: build, decrypt with the mint's key, decode, and the outputs match. A payload sealed to another key does not decrypt. Claimed signatures become notes the PSP accepts. A partial claim leaves the rest pending. A signature cannot be claimed twice. A bad claim changes nothing. The denomination and output-count limits.
- **ESP.** The PSP notes are chosen to add up exactly. The memo and request hash match the ESP mint's. Spend signatures verify with mint-core's own check. A refused exchange frees the reserved notes. A finished one swaps PSP notes for ESP notes. The ESP amounts must add up.
- **`tests/flow.rs`, in one process, with no network.** Build the payload, reopen the wallet, open the payload as the mint does, settle it with the PSP's real settlement code, read the printed signature lines, claim, check every note with the PSP's own check, then exchange against the ESP mint's real exchange code and check the ESP note against the key the mint derives for its terms. A retry gets the same reply and burns nothing more. Also: a payload sealed to another key is ignored and leaves no record, a payload with any one byte flipped is ignored, an exchange without enough PSP is refused before anything is reserved, and a signature the wallet did not ask for is refused.

The regtest run above is the end-to-end test with a real Bitcoin node.

## Left to do

- **Note store (deferred to the AIR).** The wallet file is a local JSON file.
- **Signature delivery (deferred to the AIR).** The PSP prints its signatures and `claim-psp` reads them from a file. They will arrive as an AIR DID message to the reply DID, and the wallet will claim them without a file.
- **A real reply DID.** The command line uses a made-up one. An AIR app passes its own.
- **Mint API calls over the AIR (deferred).** The HTTP client is the development transport.
- **Transfer, redemption and FSP.** The entry points are there. They wait on the ESP mint and fsp-mint.
- **Shared wire crate.** The library depends on `psp-mint` and `esp-mint` by path for the payload format, the sealing and the exchange types, so it pulls in their servers and the AIR tree. A small crate for just the wire format would be lighter for apps that embed the wallet. Not decided.
- **AIR as a path dependency.** It builds only with `../air` and `../substance` beside it.
- **Key protection.** Spend keys are stored in plain JSON with `0600` permissions. How they are protected in the AIR store is not decided.
- **Amount selection.** PSP notes are chosen to add up exactly, and the exchange fails when no exact subset exists. Splitting a note needs a PSP-side swap, which the PSP does not offer (the PSP has no `/swap`).

## Not decided yet

Whether the wallet should be able to ask for a PSP purchase to be rebuilt after the file is lost. Today the blinding factors exist only in the wallet file, so a lost file means the signatures cannot be turned into notes.
