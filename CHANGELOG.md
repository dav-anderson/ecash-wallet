# Changelog

ecash-wallet 0.1.2 builds on `sp-wire` 0.2.0 (wire version 2) and the 0.1.2 mints. 0.1.1 moved the types to `sp-wire`, added the wire-version check and removed the mint crates from the library. 0.1.0 is the first release. Nothing was recorded per version before this file; the section below is everything the README said about what was built and when.

## 0.3.0 (2026-10-16)

- **ESP notes are powers of two.** The ESP mint now refuses any ESP amount that is not a power of two (`bad_denomination`), so the wallet only builds those. New `src/split.rs`: `split` (a total into the fewest powers of two, largest first), `split_into` (the same total in exactly n notes, by halving the largest) and `check_denomination`. `build_exchange` splits the amount and the change; `build_transfer` splits the total; an explicit `--amounts` list is refused if any size is not a power of two, and a chosen input note that is not one is refused. A redemption's decline and refund outputs are split the same way: the count of outputs and the fee depend on each other, so `allocate` tries counts upward for the smallest that fits (see the ESP DESIGN.md). `redeem::MAX_OUTPUTS_PER_TERMS` (64, one per size) is public and is the worst case the group-size estimate uses.
- Tests: `split` and `split_into` (round-trip, largest first, above 2^63, the limit); an amount that is not a power of two is refused in the exchange and the transfer; a total above one note splits over several notes, and so does the change; the redemption fee and count tests and the end-to-end flows moved to power-of-two sizes. **Needs esp-mint with the same change:** the integration tests use the mints at their git tags, so they see the new check only after the tag moves.
- Tests can be run against the local mint folders with `sandbox-mint/scripts/test-wallet-against-local-mints.sh` (see the README), for a release where the wallet and a mint change together. The script runs every test file to the end (`--no-fail-fast`) and also runs fsp-mint's tests.
- Tests: the wallet's three mint-hosting tests (`redeem_flow`, `fsp_flow`, `rotation_flow`) set esp-mint's new `in_flight` field, so they build against esp-mint after the lock change, not the `v0.2.0` tag. `rotation_flow` uses ESP notes of 4, 4 and 2 (powers of two); `flow` counts every note it holds.
- Docs: why there is no ESP split command (holders convert ESP to FSP straight away), and why a lost wallet file is not rebuilt (the AIR keeps the storage redundant).
- **A swap time is never the second the set starts.** The random delay is now 1 to the window (0.5% of the period, at most 72 h), not 0 to the window. With 0 possible, a wallet that synced the second a set started swapped at once, for about 1 wallet in 19 on a 1-hour period (1 in 4,321 on the 240-hour test period). It showed as a rare failure in `rotation_flow`: the rotation tests set the mint's clock to the start and expect "will be rolled over" before the swap, and the first sync had already done it. A unit test checks 20,000 draws.

## 0.2.0

- **No re-blinding.** `reblind_exchange`, `reblind_transfer`, `reblind_redemption` and `error::is_keyset_not_current` are removed, with their tests and the retry in the command line (`exchange`, `transfer`, `redeem`), in rollovers and in the PSP receive swap. Mints now sign with whichever live keyset a request names, so a pending request keeps the keyset its outputs name and is sent as it is. A request whose keyset has been deleted is refused `keyset_retired` before anything is burned, the notes are freed, and the request is built again. The staggered rollover is unchanged.
- Against a mint of an earlier release (which still answers `keyset_not_current` for the previous set) a stale request is a plain refusal with nothing burned; build it again.
- Test: a transfer built from the stale cache after the ESP mint rotated is signed by the set it names, and the new notes record that set.
- **The wallet links no mint crate.** `mint-server` is now a dev-dependency only; `http` is just `reqwest`. `GET /keys` and `POST /check-state` use `KeysResponse`, `CheckStateRequest` and `CheckStateResponse` from the new `sp_wire::keys` module (same JSON as mint-server's types).
- **A PSP purchase names a key set.** `build_psp_payload` puts the PSP's key set the wallet last saw in the payload (the single live one it knows; none if it knows none or two), and the mint signs with it while it is live. `buy-psp` has a `--psp-url` flag that reads the PSP's live sets first. Test: `a_purchase_names_the_psp_keyset_the_wallet_last_saw`.
- **No fixed cap of 2^24 on a PSP note.** `psp::MAX_PSP_DENOMINATION` is removed. `buy-psp --psp-url` reads the PSP's largest note from `GET /keys` (`http::sync_psp_limits`, `Wallet::psp_max_denomination`) and refuses a larger one; offline only the power of two is checked. Test: `the_largest_note_is_the_one_the_psp_says`.

## Moved from the README

The sections and sentences below were in the README and describe what was built, when, or what changed. They are kept here word for word. A short fragment is a part of a sentence that was cut out; the rest of the sentence stays in the README or DESIGN.md under the same heading.

### Status

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

### Rotation of PSP and ESP

*What changed in the old rule:* "a note with no recorded set counts as previous" now applies only to notes from before keysets were recorded, and a wrong guess burns nothing (the mint refuses a note that does not verify under the keyset named).

### Command line

Before this the wallet kept offering such notes and was refused every time.
