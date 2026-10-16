# Changelog

ecash-wallet 0.1.2 builds on `sp-wire` 0.2.0 (wire version 2) and the 0.1.2 mints. 0.1.1 moved the types to `sp-wire`, added the wire-version check and removed the mint crates from the library. 0.1.0 is the first release. Nothing was recorded per version before this file; the section below is everything the README said about what was built and when.

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
