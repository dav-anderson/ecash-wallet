//! The wallet's settings: `config.toml` beside the wallet file (or the file
//! `ECASH_CONFIG` or `--config` names), then `ECASH_...` environment variables,
//! then checks. The same shape as the mints': every setting is in `SPECS`, an
//! unknown key, a wrong type or a bad value is refused with every problem listed,
//! and `ecash-wallet config` prints the values in use and where each came from.
//!
//! The settings are about storage and AIR.
//!
//! # Storage policy
//!
//! One setting per kind of data the wallet keeps, each an ordered list of AIR
//! service IDs (see [`sp_wire::storage`]):
//!
//! - `storage.wallet`: the AIR services that back up the wallet state (notes,
//!   keys, requests in flight), and nothing else. The wallet should always keep a
//!   copy on the AIR: index 0 is the preferred service for that copy and the rest
//!   are further backups, in order. The local file stays the primary ledger. Two
//!   backup services are plenty; the limit is 8.
//! - `storage.app`: where the app's own data is kept.
//!
//! One entry is valid and means one service plus the local copy; an empty list
//! (the default) means local only. **This is configuration and validation only:
//! nothing reads or writes the AIR yet**, and the wallet file is still the local
//! file.
//!
//! `storage.wallet` is **not** the service FSP fees are paid to. The `fsp`
//! commands take `--service` and have no default. The service for FSP top-up
//! will be a setting of its own (planned, not built).
//!
//! The planned behaviour is in the mints' DESIGN.md files ("Storage policy").
//!
//! # AIR (`[air]`)
//!
//! The wallet reaches the PSP, the ESP and the FSP mints over AIR and only over
//! AIR. The calls
//! are the **PSP's mint info** (what `/health` reports: `wire_version` and
//! `network`, asked by `verify_psp` before anything else is sent to the PSP),
//! its **keys**, **keysets** and **rotation** and its **rollover** and
//! **check-state**, and the **ESP's** mint info, keysets, rotation, fees,
//! rollover, exchange, transfer and redeem, and an **FSP mint's** mint info,
//! keys, rotation, fees, issue and spend. **The PSP's and the ESP's need
//! `air.server` (the AIR server's name, its public key) and `air.host` (where to
//! reach it)**, for the two alike (one local AIR service carries both); a call made
//! without them fails with an error that names the missing setting
//! ([`AirSettings::require`]). **The PSP and the ESP each have their own DID**
//! (their own `mint_did_key.json`): the requests to a mint are sealed to its DID
//! and its replies are signed under it. The wallet ships with both built in
//! ([`BUILTIN_SPI_DID`] for the PSP, [`BUILTIN_ESP_DID`] for the ESP), and
//! `air.psp_did` and `air.esp_did` override them. Setting only one of the server
//! and the host is an error, and so is setting a DID without them, so a
//! half-written config is not mistaken for a complete one. **An FSP mint is a
//! service's own, so each service has its own entry** in `air.fsp`: the service's
//! DID, the AIR server its mint listens on and where that is, written
//! `<service DID>@<AIR server key>@<host>` ([`FspAir`]). An `fsp` command for a
//! service with no entry is refused, naming the setting
//! ([`AirSettings::fsp_for`]). Like `air.server` and `air.host`, the entry is to
//! be replaced by DID resolution (upstream item 4). No call is made over HTTP. The
//! other `air.*` settings tune the request and have defaults. See `air.rs` and
//! the README.
//!
//! **Both built-in DIDs are PLACEHOLDERS** until the first SPI deploy
//! (sandbox-mint OPERATIONS.md, step 0, replaces them with the real ones). They
//! must never pass for real DIDs silently: whenever AIR is configured and a
//! built-in DID is the one in use, [`AirSettings::placeholder_warnings`] says
//! so (one warning for each), the command line prints them at every start and
//! in `config`, and the errors of a call that fails name it.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sp_wire::ServiceDid;
use sp_wire::storage::{DataKind, StoragePolicy};

/// The PSP's DID, built in: the key the wallet seals its AIR requests to the
/// PSP to and checks the PSP's replies against, when `air.psp_did` is not set.
/// (The SPI hosts the PSP and the ESP, and each has its own DID: the ESP's is
/// [`BUILTIN_ESP_DID`].)
///
/// **PLACEHOLDER. This is not a real SPI's key.** It is a point with no known
/// private key, derived so that anyone can see nothing was hidden in it: the
/// compressed point whose x is `sha256("ecash-wallet placeholder SPI DID v0" ||
/// [c])` for the first byte `c` (0, 1, 2, ...) that gives an x on the curve
/// (`c` = 3 here). Nobody can open what is sealed to it and nobody can sign a
/// reply for it, so nothing sent to it can be read by anyone and no reply from
/// "it" can ever verify: the failure is safe, and loud (see
/// [`AirSettings::placeholder_warning`]). The real DID goes in here at the first
/// SPI deploy (sandbox-mint OPERATIONS.md, "First SPI deploy", step 0), and this
/// comment goes with it.
pub const BUILTIN_SPI_DID: &str =
    "02aea5bd26a26bc83518e74bde96bb36e8cd45ff1cca0a8dcd246b764dae5daf7a";

/// The ESP's DID, built in: the key the wallet seals its AIR requests to the ESP
/// to and checks the ESP's replies against, when `air.esp_did` is not set. The
/// ESP has its own DID, not the PSP's (its own `mint_did_key.json`, printed by
/// `esp-mint pubkey`), so both mints can share one AIR service.
///
/// **PLACEHOLDER. This is not a real ESP's key.** Derived as
/// [`BUILTIN_SPI_DID`] is, with another label: the compressed point whose x is
/// `sha256("ecash-wallet placeholder ESP DID v0" || [c])` for the first byte `c`
/// that gives an x on the curve (`c` = 0 here). Nobody knows its private key, so
/// nothing sent to it can be read and no reply from "it" can verify: the failure
/// is safe, and loud (see [`AirSettings::placeholder_warnings`]). The real DID
/// goes in here at the first SPI deploy (sandbox-mint OPERATIONS.md, "First SPI
/// deploy", step 0), and this comment goes with it.
pub const BUILTIN_ESP_DID: &str =
    "020b8daca33f2c1677c8a79978610f935126afcf787731c70561756bb35a574801";

/// What is said whenever the placeholder DID is the one in use.
pub const PLACEHOLDER_WARNING: &str = "WARNING: the PSP's DID is the wallet's built-in PLACEHOLDER (air.psp_did is not set). It is not a real SPI's key: nothing sealed to it can be read and no reply from it can verify. Set air.psp_did to the PSP's DID";

/// What is said whenever the placeholder ESP DID is the one in use.
pub const ESP_PLACEHOLDER_WARNING: &str = "WARNING: the ESP's DID is the wallet's built-in PLACEHOLDER (air.esp_did is not set). It is not a real SPI's key: nothing sealed to it can be read and no reply from it can verify. Set air.esp_did to the ESP's DID (esp-mint pubkey)";

/// The name of the file looked for beside the wallet file.
pub const FILE_NAME: &str = "config.toml";
/// The environment variable that names a config file elsewhere (it must exist).
pub const FILE_ENV: &str = "ECASH_CONFIG";

/// One setting, as documented.
pub struct Spec {
    /// `section.name`, as in the file.
    pub key: &'static str,
    /// The environment variable that overrides it.
    pub env: &'static str,
    /// The default, as written in the file.
    pub default: &'static str,
    pub units: &'static str,
    pub what: &'static str,
}

pub const SPECS: &[Spec] = &[
    Spec {
        key: "storage.wallet",
        env: "ECASH_STORAGE_WALLET",
        default: "",
        units: "service DIDs (66 hex characters)",
        what: "The AIR services that back up the wallet state, and nothing else, as an ordered list of service IDs: the wallet should always keep a copy on the AIR, index 0 is the preferred service for that copy and the rest are further backups, in order. A service ID is the service's AIR DID, a 33-byte compressed key in hex (66 characters, starting 02 or 03); the old 32-byte x-only form is refused. In the environment the IDs are separated by commas; in the file it is an array of strings or one such string. One entry: that service holds a copy beside the local ledger. Empty (the default): local only. At most 8, no duplicates; two backup services are plenty. FSP fees are not paid to these services: the fsp commands need --service. Setting only for now: nothing reads or writes the AIR yet.",
    },
    Spec {
        key: "storage.app",
        env: "ECASH_STORAGE_APP",
        default: "",
        units: "service DIDs (66 hex characters)",
        what: "Which AIR services will keep the app's own data, in the same form as storage.wallet. The wallet only checks and reports it; it is for the app that embeds the library. Setting only for now.",
    },
    Spec {
        key: "air.psp_did",
        env: "ECASH_AIR_PSP_DID",
        default: "",
        units: "service DID (66 hex characters)",
        what: "The SPI's DID, overriding the one built into the wallet: the 33-byte compressed key of the mint's mint_did_key.json, in hex. Empty (the default): the built-in SPI DID, which is a PLACEHOLDER until the first SPI deploy (the wallet warns whenever it is in use). It only matters with air.server and air.host set, which the PSP's and the ESP's calls need; setting it without them is an error.",
    },
    Spec {
        key: "air.esp_did",
        env: "ECASH_AIR_ESP_DID",
        default: "",
        units: "service DID (66 hex characters)",
        what: "The ESP's DID, overriding the one built into the wallet: the 33-byte compressed key of esp-mint's mint_did_key.json (`esp-mint pubkey` prints it), in hex. It is not the PSP's: the two mints have their own DIDs and can share one AIR server. Empty (the default): the built-in ESP DID, which is a PLACEHOLDER until the first SPI deploy (the wallet warns whenever it is in use). It only matters with air.server and air.host set, which the PSP's and the ESP's calls need; setting it without them is an error.",
    },
    Spec {
        key: "air.server",
        env: "ECASH_AIR_SERVER",
        default: "",
        units: "AIR server name (66 hex characters)",
        what: "The name of the AIR server that carries the request: its public key, the compressed hex AIR prints (66 characters, starting 02 or 03). The wallet checks the server's signed challenge against it, so only the server with this key is accepted. Resolving a mint's DID to its AIR server is not built, so it is configuration for now. With air.host it is required by every call to the PSP (mint info, keys, keysets, rotation, rollover, check-state) and to the ESP (mint info, keysets, rotation, fees, rollover, exchange, transfer, redeem); both mints can use the same server, their DIDs differ. Set both or neither (neither: those calls fail and name the missing setting).",
    },
    Spec {
        key: "air.host",
        env: "ECASH_AIR_HOST",
        default: "",
        units: "host name or IP, no port",
        what: "Where to reach that AIR server: a host name or an IP with no scheme, no path and no port (the AIR client always dials port 5702 for ws). 127.0.0.1 for a server on this machine. Required with air.server, for the same calls; both or neither.",
    },
    Spec {
        key: "air.fsp",
        env: "ECASH_AIR_FSP",
        default: "",
        units: "entries service DID@AIR server@host",
        what: "Where each service's FSP mint is reached over AIR, as a list of entries `<service DID>@<AIR server name>@<host>`: the service's DID (66 hex characters, the mint's `service.did`, which its replies are signed under and the requests to it are sealed to), the name of the AIR server its listener is on (a public key, 66 hex characters) and where that server is (a host name or IP, no scheme, no path, no port). `fsp-mint serve` prints its entry when it starts. The `fsp` commands need one for the service they name, and refuse without it, naming this setting. In the environment the entries are separated by commas; in the file it is an array of strings or one string. At most one entry for a service; no duplicates. Resolving a DID to its AIR server is not built, so this is configuration for now, and is to be replaced by DID resolution. Empty (the default): no FSP mint can be reached.",
    },
    Spec {
        key: "air.reply_wait_secs",
        env: "ECASH_AIR_REPLY_WAIT_SECS",
        default: "30",
        units: "seconds (1 to 600)",
        what: "How long to wait for the mint's reply to one try of a request (mint info, keys, keysets, rotation, fees, rollover, check-state, exchange, transfer, redeem, FSP issue or FSP spend). After that the same request is written again, in the next free mailbox slot.",
    },
    Spec {
        key: "air.attempts",
        env: "ECASH_AIR_ATTEMPTS",
        default: "3",
        units: "tries (1 to 10)",
        what: "How many tries one call makes before it gives up with \"mint unreachable\". The request is kept in the wallet file, so the next call carries on with the same one and picks up a late reply.",
    },
    Spec {
        key: "air.max_skew_secs",
        env: "ECASH_AIR_MAX_SKEW_SECS",
        default: "300",
        units: "seconds (1 to 86400)",
        what: "How far the reply's issued_at (the mint's clock) may be from this wallet's clock before the reply is refused as stale. A reply that is older than this when it is read (a request kept from days ago) is dropped and the call starts a new request.",
    },
    Spec {
        key: "air.timeout_secs",
        env: "ECASH_AIR_TIMEOUT_SECS",
        default: "10",
        units: "seconds (1 to 600)",
        what: "How long the AIR server may take to answer one Create or Read before that step fails.",
    },
];

/// Which mint a call is for. A kind of AIR request names a call, not a mint, so
/// the same kind goes to either, sealed to that mint's DID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    /// The PSP (`air.psp_did`, else [`BUILTIN_SPI_DID`]).
    Psp,
    /// The ESP (`air.esp_did`, else [`BUILTIN_ESP_DID`]).
    Esp,
    /// The FSP mint of a service: the service's DID, at the AIR server of its
    /// `air.fsp` entry.
    Fsp(ServiceDid),
}

impl Party {
    /// What messages call it.
    pub fn name(self) -> &'static str {
        match self {
            Party::Psp => "PSP",
            Party::Esp => "ESP",
            Party::Fsp(_) => "FSP mint",
        }
    }

    /// The DID the requests to it are sealed to and its replies are checked under.
    pub fn did(self, air: &AirSettings) -> ServiceDid {
        match self {
            Party::Psp => air.psp_did(),
            Party::Esp => air.esp_did(),
            Party::Fsp(service) => service,
        }
    }

    /// The setting that overrides its built-in DID.
    pub fn setting(self) -> &'static str {
        match self {
            Party::Psp => "air.psp_did",
            Party::Esp => "air.esp_did",
            Party::Fsp(_) => "air.fsp",
        }
    }

    /// Its built-in PLACEHOLDER DID, hex (an FSP mint has none: its service's DID
    /// is in its `air.fsp` entry, or there is no way to reach it).
    pub fn builtin(self) -> &'static str {
        match self {
            Party::Psp => BUILTIN_SPI_DID,
            Party::Esp => BUILTIN_ESP_DID,
            Party::Fsp(_) => "",
        }
    }

    /// The AIR server (its name and its host) the calls to it go through: the
    /// PSP's and the ESP's are `air.server` and `air.host`, an FSP mint's are the
    /// ones in its service's `air.fsp` entry. An error that names the missing
    /// setting when there are none.
    pub fn address(self, air: &AirSettings) -> Result<(String, String), String> {
        match self {
            Party::Psp | Party::Esp => {
                air.require()?;
                Ok((air.server.clone(), air.host.clone()))
            }
            Party::Fsp(service) => {
                let entry = air.fsp_for(service)?;
                Ok((entry.server.clone(), entry.host.clone()))
            }
        }
    }
}

/// Where one service's FSP mint is reached over AIR: one entry of `air.fsp`,
/// written `<service DID>@<AIR server key>@<host>`. To be replaced by DID
/// resolution (upstream item 4): until then the wallet is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FspAir {
    /// The service's DID: what the requests are sealed to and the replies are
    /// signed under (the mint's `service.did`).
    pub service: ServiceDid,
    /// The name of the AIR server the mint's listener is on (a public key).
    pub server: String,
    /// Where that server is: a host name or IP, no port.
    pub host: String,
}

impl FspAir {
    /// Read one entry, `<service DID>@<AIR server key>@<host>`, checking each part
    /// the way `air.server` and `air.host` are checked.
    pub fn parse(text: &str) -> Result<FspAir, String> {
        let parts: Vec<&str> = text.trim().split('@').collect();
        let [service, server, host] = parts.as_slice() else {
            return Err(format!(
                "`{}` is not an entry of the form <service DID>@<AIR server key>@<host>",
                text.trim()
            ));
        };
        let service = ServiceDid::parse(service.trim())
            .map_err(|e| format!("`{}`: the service DID is not valid: {e}", text.trim()))?;
        let server = server.trim();
        sp_wire::seal::parse_public_key(server).map_err(|e| {
            format!(
                "`{}`: the AIR server name is not a public key (66 hex characters): {e}",
                text.trim()
            )
        })?;
        let host = host.trim();
        if host.is_empty() {
            return Err(format!("`{}`: the host is empty", text.trim()));
        }
        if let Some(why) = sp_wire::air_request::host_problem(host) {
            return Err(format!("`{}`: the host {why}", text.trim()));
        }
        Ok(FspAir {
            service,
            server: server.to_string(),
            host: host.to_string(),
        })
    }

    /// The entry as it is written.
    pub fn to_config_string(&self) -> String {
        format!("{}@{}@{}", self.service.to_hex(), self.server, self.host)
    }
}

/// The `[air]` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirSettings {
    /// The PSP's DID, if set.
    pub psp_did: Option<ServiceDid>,
    /// The ESP's DID, if set.
    pub esp_did: Option<ServiceDid>,
    /// The AIR server's name (its public key), or empty.
    pub server: String,
    /// The AIR server's host or IP, or empty.
    pub host: String,
    /// Where each service's FSP mint is (`air.fsp`), one entry per service.
    pub fsp: Vec<FspAir>,
    pub reply_wait_secs: u64,
    pub attempts: u32,
    pub max_skew_secs: u64,
    pub timeout_secs: u64,
}

impl Default for AirSettings {
    fn default() -> Self {
        AirSettings {
            psp_did: None,
            esp_did: None,
            server: String::new(),
            host: String::new(),
            fsp: Vec::new(),
            reply_wait_secs: 30,
            attempts: 3,
            max_skew_secs: 300,
            timeout_secs: 10,
        }
    }
}

impl AirSettings {
    /// True when the server and the host are both set. (The DIDs are not a
    /// condition: they default to the built-in ones. [`Settings::problems`]
    /// refuses one of the two without the other, and a DID without either.)
    pub fn is_configured(&self) -> bool {
        !self.server.is_empty() && !self.host.is_empty()
    }

    /// Every call to the PSP or the ESP needs the AIR server and its host. `Ok`
    /// when both are set; otherwise an error that names the missing setting or
    /// settings and where to set them.
    pub fn require(&self) -> Result<(), String> {
        let unset = self.unset();
        if unset.is_empty() {
            return Ok(());
        }
        Err(format!(
            "the PSP and the ESP are reached over AIR only, and {} {} not set. Set {} in config.toml ([air]) or with {}",
            unset.join(" and "),
            if unset.len() == 1 { "is" } else { "are" },
            if unset.len() == 1 { "it" } else { "them" },
            unset
                .iter()
                .map(|k| if *k == "air.server" {
                    "ECASH_AIR_SERVER"
                } else {
                    "ECASH_AIR_HOST"
                })
                .collect::<Vec<_>>()
                .join(" and ")
        ))
    }

    /// The `air.fsp` entry of a service, or an error that names the setting and
    /// says what to put in it.
    pub fn fsp_for(&self, service: ServiceDid) -> Result<&FspAir, String> {
        self.fsp.iter().find(|e| e.service == service).ok_or_else(|| {
            format!(
                "no air.fsp entry for the FSP mint of service {}. FSP mints are reached over AIR only, so the wallet needs the service's DID, the AIR server its mint listens on and where that is. Add `{}@<AIR server key>@<host>` to air.fsp (config.toml, [air] fsp = [\"...\"], or ECASH_AIR_FSP); `fsp-mint serve` prints the whole entry when it starts",
                service.to_hex(),
                service.to_hex()
            )
        })
    }

    /// The PSP's DID the requests are sealed to: `air.psp_did` if it is set, else
    /// the built-in one ([`BUILTIN_SPI_DID`], a PLACEHOLDER).
    pub fn psp_did(&self) -> ServiceDid {
        self.psp_did.unwrap_or_else(builtin_spi_did)
    }

    /// The ESP's DID the requests are sealed to: `air.esp_did` if it is set, else
    /// the built-in one ([`BUILTIN_ESP_DID`], a PLACEHOLDER).
    pub fn esp_did(&self) -> ServiceDid {
        self.esp_did.unwrap_or_else(builtin_esp_did)
    }

    /// True when the PSP's DID in use is the built-in placeholder (`air.psp_did`
    /// is not set, or is set to the placeholder itself).
    pub fn uses_builtin_did(&self) -> bool {
        self.psp_did() == builtin_spi_did()
    }

    /// True when the ESP's DID in use is the built-in placeholder (`air.esp_did`
    /// is not set, or is set to the placeholder itself).
    pub fn uses_builtin_esp_did(&self) -> bool {
        self.esp_did() == builtin_esp_did()
    }

    /// The warning to show when AIR is on and the PSP's DID in use is the
    /// placeholder, else `None`. (The ESP's is [`Self::esp_placeholder_warning`];
    /// [`Self::placeholder_warnings`] has both.)
    pub fn placeholder_warning(&self) -> Option<&'static str> {
        (self.is_configured() && self.uses_builtin_did()).then_some(PLACEHOLDER_WARNING)
    }

    /// The warning to show when AIR is on and the ESP's DID in use is the
    /// placeholder, else `None`.
    pub fn esp_placeholder_warning(&self) -> Option<&'static str> {
        (self.is_configured() && self.uses_builtin_esp_did()).then_some(ESP_PLACEHOLDER_WARNING)
    }

    /// Every warning to show: one for each placeholder DID in use while AIR is
    /// on. The command line prints them at every start; an app that embeds the
    /// library should show them too.
    pub fn placeholder_warnings(&self) -> Vec<&'static str> {
        [self.placeholder_warning(), self.esp_placeholder_warning()]
            .into_iter()
            .flatten()
            .collect()
    }

    /// The names of the two connection settings that are not set.
    fn unset(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.server.is_empty() {
            out.push("air.server");
        }
        if self.host.is_empty() {
            out.push("air.host");
        }
        out
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    pub storage_wallet: StoragePolicy,
    pub storage_app: StoragePolicy,
    pub air: AirSettings,
}

impl Settings {
    /// The current value of a setting, as it is written in the file.
    pub fn get(&self, key: &str) -> Option<String> {
        Some(match key {
            "storage.wallet" => self.storage_wallet.to_config_string(),
            "storage.app" => self.storage_app.to_config_string(),
            "air.psp_did" => self.air.psp_did.map(|d| d.to_hex()).unwrap_or_default(),
            "air.esp_did" => self.air.esp_did.map(|d| d.to_hex()).unwrap_or_default(),
            "air.server" => self.air.server.clone(),
            "air.host" => self.air.host.clone(),
            "air.fsp" => self
                .air
                .fsp
                .iter()
                .map(FspAir::to_config_string)
                .collect::<Vec<_>>()
                .join(","),
            "air.reply_wait_secs" => self.air.reply_wait_secs.to_string(),
            "air.attempts" => self.air.attempts.to_string(),
            "air.max_skew_secs" => self.air.max_skew_secs.to_string(),
            "air.timeout_secs" => self.air.timeout_secs.to_string(),
            _ => return None,
        })
    }

    /// Set one setting from text. The text is checked as it is read.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let policy = |value: &str| {
            StoragePolicy::parse(value).map_err(|e| format!("{key} = `{value}`: {e}"))
        };
        match key {
            "storage.wallet" => self.storage_wallet = policy(value)?,
            "storage.app" => self.storage_app = policy(value)?,
            "air.psp_did" => {
                let text = value.trim();
                self.air.psp_did = if text.is_empty() {
                    None
                } else {
                    Some(ServiceDid::parse(text).map_err(|e| format!("{key} = `{value}`: {e}"))?)
                };
            }
            "air.esp_did" => {
                let text = value.trim();
                self.air.esp_did = if text.is_empty() {
                    None
                } else {
                    Some(ServiceDid::parse(text).map_err(|e| format!("{key} = `{value}`: {e}"))?)
                };
            }
            "air.server" => {
                let text = value.trim();
                if !text.is_empty() {
                    sp_wire::seal::parse_public_key(text).map_err(|e| {
                        format!(
                            "{key} = `{value}` is not an AIR server name (a public key, 66 hex characters): {e}"
                        )
                    })?;
                }
                self.air.server = text.to_string();
            }
            "air.host" => {
                let text = value.trim();
                if let Some(why) = sp_wire::air_request::host_problem(text) {
                    return Err(format!("{key} = `{value}` {why}"));
                }
                self.air.host = text.to_string();
            }
            "air.fsp" => {
                let mut entries: Vec<FspAir> = Vec::new();
                for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let entry = FspAir::parse(item).map_err(|e| format!("{key}: {e}"))?;
                    if entries.iter().any(|e| e.service == entry.service) {
                        return Err(format!(
                            "{key} names the FSP mint of service {} twice: one entry for each service",
                            entry.service.to_hex()
                        ));
                    }
                    entries.push(entry);
                }
                self.air.fsp = entries;
            }
            "air.reply_wait_secs" => self.air.reply_wait_secs = number(key, value, 1, 600)?,
            "air.attempts" => self.air.attempts = number(key, value, 1, 10)? as u32,
            "air.max_skew_secs" => self.air.max_skew_secs = number(key, value, 1, 86_400)?,
            "air.timeout_secs" => self.air.timeout_secs = number(key, value, 1, 600)?,
            other => return Err(format!("unknown setting `{other}`")),
        }
        Ok(())
    }

    /// Mistakes that involve more than one setting: the server and the host go
    /// together, and a DID without them would be ignored.
    pub fn problems(&self) -> Vec<String> {
        let unset = self.air.unset();
        match unset.len() {
            1 => vec![format!(
                "air.server and air.host go together (the PSP's and the ESP's calls need both), but {} is not set",
                unset[0]
            )],
            2 => {
                let mut out = Vec::new();
                if self.air.psp_did.is_some() {
                    out.push("air.psp_did is set, but air.server and air.host are not: it only replaces the built-in PSP DID, and is used only with the server and the host. Set both, or unset air.psp_did".to_string());
                }
                if self.air.esp_did.is_some() {
                    out.push("air.esp_did is set, but air.server and air.host are not: it only replaces the built-in ESP DID, and is used only with the server and the host. Set both, or unset air.esp_did".to_string());
                }
                out
            }
            _ => vec![],
        }
    }

    /// The policy for a kind of data, if the wallet has a setting for it. A
    /// mint's state is not the wallet's, so it has none here.
    pub fn policy(&self, kind: DataKind) -> Option<&StoragePolicy> {
        match kind {
            DataKind::Wallet => Some(&self.storage_wallet),
            DataKind::App => Some(&self.storage_app),
            DataKind::MintState => None,
        }
    }
}

/// [`BUILTIN_SPI_DID`] as a [`ServiceDid`].
fn builtin_spi_did() -> ServiceDid {
    ServiceDid::parse(BUILTIN_SPI_DID).expect("the built-in SPI DID is a valid DID")
}

/// [`BUILTIN_ESP_DID`] as a [`ServiceDid`].
fn builtin_esp_did() -> ServiceDid {
    ServiceDid::parse(BUILTIN_ESP_DID).expect("the built-in ESP DID is a valid DID")
}

/// A whole number in `min..=max`, read from text.
fn number(key: &str, value: &str, min: u64, max: u64) -> Result<u64, String> {
    match value.trim().parse::<u64>() {
        Ok(n) if (min..=max).contains(&n) => Ok(n),
        _ => Err(format!(
            "{key} = `{value}` must be a whole number from {min} to {max}"
        )),
    }
}

/// Where a value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Default,
    File,
    Env(&'static str),
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Default => write!(f, "default"),
            Source::File => write!(f, "file"),
            Source::Env(n) => write!(f, "env {n}"),
        }
    }
}

#[derive(Debug)]
pub struct Loaded {
    pub settings: Settings,
    pub sources: BTreeMap<&'static str, Source>,
    /// The file that was read, if there was one.
    pub file: Option<PathBuf>,
}

impl Loaded {
    /// One line per setting: its value and where it came from.
    pub fn describe(&self) -> Vec<String> {
        SPECS
            .iter()
            .map(|s| {
                let src = self.sources.get(s.key).cloned().unwrap_or(Source::Default);
                format!(
                    "  {} = {} {} ({src})",
                    s.key,
                    self.settings.get(s.key).unwrap_or_default(),
                    s.units
                )
            })
            .collect()
    }
}

fn parse_file(text: &str) -> Result<Vec<(String, String)>, Vec<String>> {
    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| vec![format!("not valid TOML: {}", e.message())])?;
    let (mut pairs, mut problems) = (Vec::new(), Vec::new());
    for (section, body) in &table {
        let Some(body) = body.as_table() else {
            problems.push(format!(
                "`{section}` must be a [section] of settings, not a single value"
            ));
            continue;
        };
        for (name, value) in body {
            let key = format!("{section}.{name}");
            if !SPECS.iter().any(|s| s.key == key) {
                problems.push(format!("unknown setting `{key}`"));
                continue;
            }
            match value {
                toml::Value::String(s) => pairs.push((key, s.clone())),
                toml::Value::Integer(n) => pairs.push((key, n.to_string())),
                toml::Value::Array(items) => {
                    let ids: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
                    if ids.len() == items.len() {
                        pairs.push((key, ids.join(",")));
                    } else {
                        problems.push(format!(
                            "{key} must be a list of strings (service IDs, or air.fsp entries), not {items:?}"
                        ));
                    }
                }
                _ => problems.push(format!(
                    "{key} must be a list of strings or one string, not {}",
                    value.type_str()
                )),
            }
        }
    }
    if problems.is_empty() {
        Ok(pairs)
    } else {
        Err(problems)
    }
}

/// Load the settings: defaults, then the file, then the environment. `dir` is
/// the folder of the wallet file, where `config.toml` is looked for. `file`
/// (from `--config`) or `$ECASH_CONFIG` names a file elsewhere, which must
/// exist; `file` wins. `env` looks up an environment variable.
pub fn load(
    dir: &Path,
    file: Option<&Path>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Loaded, Vec<String>> {
    let (path, must_exist) = match file {
        Some(p) => (p.to_path_buf(), true),
        None => match env(FILE_ENV) {
            Some(p) if !p.is_empty() => (PathBuf::from(p), true),
            _ => (dir.join(FILE_NAME), false),
        },
    };
    let mut settings = Settings::default();
    let mut sources = BTreeMap::new();
    let mut problems = Vec::new();
    let mut read = None;
    match fs::read_to_string(&path) {
        Ok(text) => {
            read = Some(path.clone());
            match parse_file(&text) {
                Ok(pairs) => {
                    for (key, value) in pairs {
                        match settings.set(&key, &value) {
                            Ok(()) => {
                                if let Some(s) = SPECS.iter().find(|s| s.key == key) {
                                    sources.insert(s.key, Source::File);
                                }
                            }
                            Err(e) => problems.push(format!("{}: {e}", path.display())),
                        }
                    }
                }
                Err(list) => {
                    problems.extend(list.into_iter().map(|p| format!("{}: {p}", path.display())))
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound && !must_exist => {}
        Err(e) => problems.push(format!("cannot read config file {}: {e}", path.display())),
    }
    for spec in SPECS {
        if let Some(value) = env(spec.env).filter(|v| !v.is_empty()) {
            match settings.set(spec.key, &value) {
                Ok(()) => {
                    sources.insert(spec.key, Source::Env(spec.env));
                }
                Err(e) => problems.push(format!("environment variable {}: {e}", spec.env)),
            }
        }
    }
    if problems.is_empty() {
        problems.extend(settings.problems());
    }
    if problems.is_empty() {
        Ok(Loaded {
            settings,
            sources,
            file: read,
        })
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const B: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wallet-config-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn with_no_file_and_no_environment_the_wallet_is_local_only() {
        let d = dir("defaults");
        let l = load(&d, None, &no_env).unwrap();
        assert_eq!(l.settings, Settings::default());
        assert!(l.file.is_none() && l.sources.is_empty());
        assert!(l.settings.storage_wallet.is_local_only());
        for s in SPECS {
            assert_eq!(
                l.settings.get(s.key).as_deref(),
                Some(s.default),
                "{}",
                s.key
            );
            let mut c = Settings::default();
            c.set(s.key, s.default).unwrap();
            assert_eq!(c, l.settings);
        }
        assert_eq!(l.describe().len(), SPECS.len());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_file_then_the_environment_with_their_sources() {
        let d = dir("order");
        fs::write(
            d.join(FILE_NAME),
            format!("[storage]\nwallet = [\"{A}\", \"{B}\"]\napp = \"{B}\"\n"),
        )
        .unwrap();
        let l = load(&d, None, &no_env).unwrap();
        assert_eq!(l.file.as_deref(), Some(d.join(FILE_NAME).as_path()));
        let s = &l.settings;
        assert_eq!(s.storage_wallet.primary().unwrap().to_hex(), A);
        assert_eq!(s.storage_wallet.secondaries().len(), 1);
        assert_eq!(s.storage_app.to_config_string(), B);
        assert_eq!(l.sources["storage.wallet"], Source::File);
        assert_eq!(
            s.policy(DataKind::App).unwrap().to_config_string(),
            B.to_string()
        );
        assert!(s.policy(DataKind::MintState).is_none());

        // The environment wins. The parity byte is part of the ID: 03 is not 02.
        let did = format!("03{}", &B[2..]);
        let l = load(&d, None, &env_of(&[("ECASH_STORAGE_WALLET", did.as_str())])).unwrap();
        assert_eq!(l.settings.storage_wallet.to_config_string(), did);
        assert_ne!(l.settings.storage_wallet.to_config_string(), B);
        assert_eq!(
            l.sources["storage.wallet"],
            Source::Env("ECASH_STORAGE_WALLET")
        );
        assert_eq!(l.sources["storage.app"], Source::File);
        assert!(l.describe().iter().any(
            |x| x == &format!("  storage.wallet = {did} service DIDs (66 hex characters) (env ECASH_STORAGE_WALLET)")
        ));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_named_file_must_exist_and_wins_over_the_variable() {
        let d = dir("named");
        let other = d.join("other.toml");
        fs::write(&other, format!("[storage]\nwallet = \"{A}\"\n")).unwrap();
        let by_env = env_of(&[(FILE_ENV, other.to_str().unwrap())]);
        let l = load(&d, None, &by_env).unwrap();
        assert_eq!(l.settings.storage_wallet.to_config_string(), A);
        // --config wins over the variable.
        let flag = d.join("flag.toml");
        fs::write(&flag, format!("[storage]\nwallet = \"{B}\"\n")).unwrap();
        let l = load(&d, Some(&flag), &by_env).unwrap();
        assert_eq!(l.settings.storage_wallet.to_config_string(), B);
        // A named file that is not there is an error, unlike the default one.
        assert!(load(&d, Some(&d.join("nope.toml")), &no_env).is_err());
        let gone = env_of(&[(FILE_ENV, "/nonexistent/config.toml")]);
        assert!(load(&d, None, &gone).is_err());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn every_mistake_is_listed() {
        let d = dir("bad");
        fs::write(
            d.join(FILE_NAME),
            format!("[storage]\nwallet = [\"{A}\", \"{A}\"]\n"),
        )
        .unwrap();
        let p = load(&d, None, &no_env).unwrap_err();
        assert!(p.iter().any(|x| x.contains("listed twice")), "{p:?}");
        fs::write(d.join(FILE_NAME), "[storage]\napp = [1]\nnope = \"x\"\n").unwrap();
        let p = load(&d, None, &no_env).unwrap_err();
        assert!(p.iter().any(|x| x.contains("list of strings")), "{p:?}");
        assert!(
            p.iter()
                .any(|x| x.contains("unknown setting `storage.nope`")),
            "{p:?}"
        );
        fs::write(d.join(FILE_NAME), "storage = 3\n").unwrap();
        let p = load(&d, None, &no_env).unwrap_err();
        assert!(p.iter().any(|x| x.contains("[section]")), "{p:?}");
        fs::write(d.join(FILE_NAME), "[storage\n").unwrap();
        let p = load(&d, None, &no_env).unwrap_err();
        assert!(p.iter().any(|x| x.contains("not valid TOML")), "{p:?}");
        fs::remove_file(d.join(FILE_NAME)).unwrap();
        let p = load(&d, None, &env_of(&[("ECASH_STORAGE_APP", "zz")])).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("ECASH_STORAGE_APP") && x.contains("must be hex")),
            "{p:?}"
        );
        let gap = format!("{A},,{B}");
        let p = load(&d, None, &env_of(&[("ECASH_STORAGE_WALLET", gap.as_str())])).unwrap_err();
        assert!(p.iter().any(|x| x.contains("entry 2")), "{p:?}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn air_is_off_by_default_and_on_with_the_server_and_the_host() {
        let d = dir("air-on");
        let l = load(&d, None, &no_env).unwrap();
        assert!(!l.settings.air.is_configured());
        assert_eq!(l.settings.air, AirSettings::default());
        assert_eq!(l.settings.air.reply_wait_secs, 30);
        assert_eq!(l.settings.air.attempts, 3);
        // Off, so there is nothing to warn about, though the DID is the built-in one.
        assert!(l.settings.air.uses_builtin_did());
        assert_eq!(l.settings.air.placeholder_warning(), None);

        fs::write(
            d.join(FILE_NAME),
            format!(
                "[air]\npsp_did = \"{A}\"\nserver = \"{B}\"\nhost = \"127.0.0.1\"\nattempts = 5\nreply_wait_secs = 12\n"
            ),
        )
        .unwrap();
        let l = load(&d, None, &no_env).unwrap();
        let air = &l.settings.air;
        assert!(air.is_configured());
        assert_eq!(air.psp_did.unwrap().to_hex(), A);
        assert_eq!(air.server, B);
        assert_eq!(air.host, "127.0.0.1");
        assert_eq!((air.attempts, air.reply_wait_secs), (5, 12));
        assert_eq!(l.sources["air.host"], Source::File);
        // The DID is the override, and it is not the placeholder: no warning.
        assert_eq!(air.psp_did().to_hex(), A);
        assert!(!air.uses_builtin_did());
        assert_eq!(air.placeholder_warning(), None);

        let l = load(&d, None, &env_of(&[("ECASH_AIR_HOST", "air.example.org")])).unwrap();
        assert_eq!(l.settings.air.host, "air.example.org");
        assert_eq!(l.sources["air.host"], Source::Env("ECASH_AIR_HOST"));
        assert_eq!(l.sources["air.server"], Source::File);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_server_and_the_host_alone_turn_air_on_with_the_builtin_placeholder_did() {
        let d = dir("air-builtin");
        let both = [("ECASH_AIR_HOST", "127.0.0.1"), ("ECASH_AIR_SERVER", B)];
        let l = load(&d, None, &env_of(&both)).unwrap();
        let air = &l.settings.air;
        assert!(air.is_configured());
        assert_eq!(air.psp_did, None);
        assert_eq!(air.psp_did().to_hex(), BUILTIN_SPI_DID);
        assert!(air.uses_builtin_did());
        // AIR on with the placeholder in use is never silent.
        let warning = air.placeholder_warning().expect("a warning");
        assert!(warning.contains("PLACEHOLDER"), "{warning}");
        // Setting the override to the placeholder itself is the same thing.
        let same = [
            ("ECASH_AIR_HOST", "127.0.0.1"),
            ("ECASH_AIR_SERVER", B),
            ("ECASH_AIR_PSP_DID", BUILTIN_SPI_DID),
        ];
        let l = load(&d, None, &env_of(&same)).unwrap();
        assert!(l.settings.air.placeholder_warning().is_some());
        // A real override replaces it.
        let real = [
            ("ECASH_AIR_HOST", "127.0.0.1"),
            ("ECASH_AIR_SERVER", B),
            ("ECASH_AIR_PSP_DID", A),
        ];
        let l = load(&d, None, &env_of(&real)).unwrap();
        assert_eq!(l.settings.air.psp_did().to_hex(), A);
        assert_eq!(l.settings.air.placeholder_warning(), None);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_builtin_did_is_a_valid_point_and_the_derivation_in_its_comment_holds() {
        use sha2::{Digest, Sha256};
        let did = ServiceDid::parse(BUILTIN_SPI_DID).unwrap();
        // Sealing to it works: it is a point on the curve.
        sp_wire::seal::parse_public_key(BUILTIN_SPI_DID).unwrap();
        assert_eq!(did.to_hex(), BUILTIN_SPI_DID);
        // x = sha256(label || [3]), with an even-y prefix.
        let mut hasher = Sha256::new();
        hasher.update(b"ecash-wallet placeholder SPI DID v0");
        hasher.update([3u8]);
        assert_eq!(
            BUILTIN_SPI_DID,
            format!("02{}", hex::encode(hasher.finalize()))
        );
    }
    #[test]
    fn the_builtin_esp_did_is_a_valid_point_other_than_the_psps_and_its_derivation_holds() {
        use sha2::{Digest, Sha256};
        let did = ServiceDid::parse(BUILTIN_ESP_DID).unwrap();
        sp_wire::seal::parse_public_key(BUILTIN_ESP_DID).unwrap();
        assert_eq!(did.to_hex(), BUILTIN_ESP_DID);
        assert_ne!(BUILTIN_ESP_DID, BUILTIN_SPI_DID);
        // x = sha256(label || [0]), with an even-y prefix; 0 is the first counter
        // that lands on the curve (the PSP's needed 3).
        let mut hasher = Sha256::new();
        hasher.update(b"ecash-wallet placeholder ESP DID v0");
        hasher.update([0u8]);
        assert_eq!(
            BUILTIN_ESP_DID,
            format!("02{}", hex::encode(hasher.finalize()))
        );
    }

    #[test]
    fn the_esp_has_its_own_did_setting_and_its_own_placeholder_warning() {
        let d = dir("air-esp-did");
        let both = [("ECASH_AIR_HOST", "127.0.0.1"), ("ECASH_AIR_SERVER", B)];
        // Neither DID set: both placeholders are in use, two warnings.
        let l = load(&d, None, &env_of(&both)).unwrap();
        let air = &l.settings.air;
        assert_eq!(air.esp_did, None);
        assert_eq!(air.esp_did().to_hex(), BUILTIN_ESP_DID);
        assert!(air.uses_builtin_esp_did());
        assert_ne!(air.esp_did(), air.psp_did());
        let warnings = air.placeholder_warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("PSP") && warnings[0].contains("air.psp_did"));
        assert!(warnings[1].contains("ESP") && warnings[1].contains("air.esp_did"));
        assert!(warnings.iter().all(|w| w.contains("PLACEHOLDER")));

        // A real ESP DID alone quiets only the ESP's warning, and the other way round.
        let esp_only = [both[0], both[1], ("ECASH_AIR_ESP_DID", A)];
        let l = load(&d, None, &env_of(&esp_only)).unwrap();
        let air = &l.settings.air;
        assert_eq!(air.esp_did().to_hex(), A);
        assert!(!air.uses_builtin_esp_did());
        assert_eq!(air.esp_placeholder_warning(), None);
        assert_eq!(air.placeholder_warnings(), vec![PLACEHOLDER_WARNING]);
        assert_eq!(l.sources["air.esp_did"], Source::Env("ECASH_AIR_ESP_DID"));
        let psp_only = [both[0], both[1], ("ECASH_AIR_PSP_DID", A)];
        let l = load(&d, None, &env_of(&psp_only)).unwrap();
        assert_eq!(
            l.settings.air.placeholder_warnings(),
            vec![ESP_PLACEHOLDER_WARNING]
        );
        // Both real: no warning. (The same DID twice is odd, but it is the user's.)
        let real = [
            both[0],
            both[1],
            ("ECASH_AIR_PSP_DID", A),
            ("ECASH_AIR_ESP_DID", A),
        ];
        let l = load(&d, None, &env_of(&real)).unwrap();
        assert!(l.settings.air.placeholder_warnings().is_empty());
        // Setting the ESP's DID to the placeholder itself is still the placeholder.
        let same = [both[0], both[1], ("ECASH_AIR_ESP_DID", BUILTIN_ESP_DID)];
        let l = load(&d, None, &env_of(&same)).unwrap();
        assert!(l.settings.air.esp_placeholder_warning().is_some());
        // With the server and the host unset nothing is said.
        let l = load(&d, None, &env_of(&[])).unwrap();
        assert!(l.settings.air.placeholder_warnings().is_empty());

        // From the file.
        fs::write(
            d.join(FILE_NAME),
            format!("[air]\nesp_did = \"{A}\"\nserver = \"{B}\"\nhost = \"127.0.0.1\"\n"),
        )
        .unwrap();
        let l = load(&d, None, &env_of(&[])).unwrap();
        assert_eq!(l.settings.air.esp_did.unwrap().to_hex(), A);
        assert_eq!(l.sources["air.esp_did"], Source::File);
        assert_eq!(l.settings.get("air.esp_did").unwrap(), A);

        // A DID that is not one is refused.
        let p = load(&d, None, &env_of(&[("ECASH_AIR_ESP_DID", "zz")])).unwrap_err();
        assert!(p.iter().any(|x| x.contains("air.esp_did")), "{p:?}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_esp_did_without_the_server_and_the_host_is_an_error_like_the_psps() {
        let d = dir("air-esp-did-alone");
        let p = load(&d, None, &env_of(&[("ECASH_AIR_ESP_DID", A)])).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("air.esp_did is set, but air.server and air.host are not")),
            "{p:?}"
        );
        // Both DIDs alone: two problems, one each.
        let both = [("ECASH_AIR_ESP_DID", A), ("ECASH_AIR_PSP_DID", A)];
        let p = load(&d, None, &env_of(&both)).unwrap_err();
        assert!(p.iter().any(|x| x.contains("air.esp_did is set")), "{p:?}");
        assert!(p.iter().any(|x| x.contains("air.psp_did is set")), "{p:?}");
        // With one of the pair the pair is the problem.
        let one = [("ECASH_AIR_ESP_DID", A), ("ECASH_AIR_HOST", "127.0.0.1")];
        let p = load(&d, None, &env_of(&one)).unwrap_err();
        assert!(
            p.iter().any(|x| x.contains("air.server is not set")),
            "{p:?}"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn some_but_not_all_of_the_air_connection_settings_is_an_error() {
        let d = dir("air-partial");
        let p = load(&d, None, &env_of(&[("ECASH_AIR_HOST", "127.0.0.1")])).unwrap_err();
        assert!(
            p.iter().any(|x| x.contains("air.server is not set")),
            "{p:?}"
        );
        let p = load(&d, None, &env_of(&[("ECASH_AIR_SERVER", B)])).unwrap_err();
        assert!(p.iter().any(|x| x.contains("air.host is not set")), "{p:?}");
        // The DID alone would be ignored (AIR needs a server): so it is refused.
        let p = load(&d, None, &env_of(&[("ECASH_AIR_PSP_DID", A)])).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("air.psp_did is set, but air.server and air.host are not")),
            "{p:?}"
        );
        // The DID with only one of the two: the pair is the problem.
        let one = [("ECASH_AIR_PSP_DID", A), ("ECASH_AIR_HOST", "127.0.0.1")];
        let p = load(&d, None, &env_of(&one)).unwrap_err();
        assert!(
            p.iter().any(|x| x.contains("air.server is not set")),
            "{p:?}"
        );
        // The tuning settings alone are fine: AIR stays off.
        let l = load(&d, None, &env_of(&[("ECASH_AIR_ATTEMPTS", "2")])).unwrap();
        assert!(!l.settings.air.is_configured());
        assert_eq!(l.settings.air.attempts, 2);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn every_air_mistake_is_refused_naming_the_setting() {
        let d = dir("air-bad");
        let bad = [
            ("ECASH_AIR_SERVER", "zz", "air.server"),
            ("ECASH_AIR_PSP_DID", "zz", "air.psp_did"),
            ("ECASH_AIR_PSP_DID", &A[2..], "air.psp_did"),
            ("ECASH_AIR_HOST", "ws://127.0.0.1", "air.host"),
            ("ECASH_AIR_HOST", "127.0.0.1:5702", "air.host"),
            ("ECASH_AIR_HOST", "a b", "air.host"),
            ("ECASH_AIR_ATTEMPTS", "0", "air.attempts"),
            ("ECASH_AIR_ATTEMPTS", "11", "air.attempts"),
            ("ECASH_AIR_REPLY_WAIT_SECS", "0", "air.reply_wait_secs"),
            ("ECASH_AIR_REPLY_WAIT_SECS", "soon", "air.reply_wait_secs"),
            ("ECASH_AIR_MAX_SKEW_SECS", "86401", "air.max_skew_secs"),
            ("ECASH_AIR_TIMEOUT_SECS", "-1", "air.timeout_secs"),
        ];
        for (var, value, setting) in bad {
            let p = load(&d, None, &env_of(&[(var, value)])).unwrap_err();
            assert!(
                p.iter().any(|x| x.contains(var) && x.contains(setting)),
                "{var}={value}: {p:?}"
            );
        }
        // A bad value in the file names the setting. (An unknown key is a
        // problem with the file itself, found before any value is applied, so it
        // is checked on its own.)
        fs::write(d.join(FILE_NAME), "[air]\nattempts = \"many\"\n").unwrap();
        let p = load(&d, None, &no_env).unwrap_err();
        assert!(p.iter().any(|x| x.contains("air.attempts")), "{p:?}");
        fs::write(d.join(FILE_NAME), "[air]\nnope = 1\n").unwrap();
        let p = load(&d, None, &no_env).unwrap_err();
        assert!(
            p.iter().any(|x| x.contains("unknown setting `air.nope`")),
            "{p:?}"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_psp_and_the_esp_need_the_server_and_the_host_and_the_error_names_what_is_missing() {
        let mut air = AirSettings::default();
        let both = air.require().unwrap_err();
        assert!(
            both.contains("air.server and air.host are not set")
                && both.contains("ECASH_AIR_SERVER")
                && both.contains("ECASH_AIR_HOST"),
            "{both}"
        );
        air.server = "02".repeat(33);
        let host = air.require().unwrap_err();
        assert!(
            host.contains("air.host is not set") && !host.contains("air.server"),
            "{host}"
        );
        air.server.clear();
        air.host = "127.0.0.1".into();
        let server = air.require().unwrap_err();
        assert!(
            server.contains("air.server is not set") && !server.contains("air.host"),
            "{server}"
        );
        air.server = "02".repeat(33);
        assert_eq!(air.require(), Ok(()));
    }

    #[test]
    fn every_spec_has_its_own_variable() {
        let mut seen = std::collections::HashSet::new();
        for s in SPECS {
            assert!(s.env.starts_with("ECASH_"), "{}", s.env);
            assert!(seen.insert(s.env), "{} used twice", s.env);
            assert!(seen.insert(s.key), "{} used twice", s.key);
        }
    }

    #[test]
    fn an_empty_list_in_the_file_is_local_only() {
        let d = dir("empty");
        fs::write(d.join(FILE_NAME), "[storage]\nwallet = []\napp = \"\"\n").unwrap();
        let l = load(&d, None, &no_env).unwrap();
        assert!(l.settings.storage_wallet.is_local_only());
        assert!(l.settings.storage_app.is_local_only());
        fs::remove_dir_all(&d).unwrap();
    }

    /// The `air.fsp` entry of service `A`, on AIR server `B`.
    fn entry_a() -> String {
        format!("{A}@{B}@127.0.0.1")
    }

    #[test]
    fn air_fsp_entries_come_from_the_file_and_the_environment_with_their_sources() {
        let d = dir("fsp-entries");
        fs::write(
            d.join(FILE_NAME),
            format!(
                "[air]\nfsp = [\"{}\", \"{B}@{A}@air.example.org\"]\n",
                entry_a()
            ),
        )
        .unwrap();
        let l = load(&d, None, &no_env).unwrap();
        let air = &l.settings.air;
        assert_eq!(air.fsp.len(), 2);
        assert_eq!(l.sources["air.fsp"], Source::File);
        let one = air.fsp_for(ServiceDid::parse(A).unwrap()).unwrap();
        assert_eq!((one.server.as_str(), one.host.as_str()), (B, "127.0.0.1"));
        let two = air.fsp_for(ServiceDid::parse(B).unwrap()).unwrap();
        assert_eq!(
            (two.server.as_str(), two.host.as_str()),
            (A, "air.example.org")
        );
        // A single string is one entry, and the environment replaces the file's list.
        fs::write(
            d.join(FILE_NAME),
            format!("[air]\nfsp = \"{}\"\n", entry_a()),
        )
        .unwrap();
        assert_eq!(load(&d, None, &no_env).unwrap().settings.air.fsp.len(), 1);
        let other = format!("{B}@{A}@127.0.0.1");
        let env = env_of(&[("ECASH_AIR_FSP", other.as_str())]);
        let l = load(&d, None, &env).unwrap();
        assert_eq!(l.settings.air.fsp.len(), 1);
        assert_eq!(l.settings.air.fsp[0].service.to_hex(), B);
        assert_eq!(l.sources["air.fsp"], Source::Env("ECASH_AIR_FSP"));
        // Two entries in the environment, comma separated; the value reads back.
        let both = format!("{}, {B}@{A}@127.0.0.1", entry_a());
        let l = load(&d, None, &env_of(&[("ECASH_AIR_FSP", both.as_str())])).unwrap();
        assert_eq!(
            l.settings.get("air.fsp").unwrap(),
            format!("{},{B}@{A}@127.0.0.1", entry_a())
        );
        // The FSP entries need neither air.server nor air.host.
        assert!(!l.settings.air.is_configured());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn air_fsp_is_checked_like_air_server_and_air_host_and_has_no_duplicates() {
        let mut s = Settings::default();
        for (bad, says) in [
            (A.to_string(), "<service DID>@<AIR server key>@<host>"),
            (format!("{A}@{B}"), "<service DID>@<AIR server key>@<host>"),
            (
                format!("{A}@{B}@h@x"),
                "<service DID>@<AIR server key>@<host>",
            ),
            (format!("zz@{B}@127.0.0.1"), "service DID is not valid"),
            (format!("{A}@zz@127.0.0.1"), "not a public key"),
            (format!("{A}@{B}@"), "the host is empty"),
            (format!("{A}@{B}@127.0.0.1:5702"), "the host"),
            (format!("{A}@{B}@ws://127.0.0.1"), "the host"),
        ] {
            let e = s.set("air.fsp", &bad).unwrap_err();
            assert!(e.contains("air.fsp") && e.contains(says), "{bad}: {e}");
        }
        assert!(s.air.fsp.is_empty(), "a bad value changes nothing");
        // One entry for each service: the same service twice is refused, even on
        // another server.
        let twice = format!("{},{A}@{A}@10.0.0.9", entry_a());
        let e = s.set("air.fsp", &twice).unwrap_err();
        assert!(e.contains("twice") && e.contains(A), "{e}");
        // Empty clears.
        s.set("air.fsp", &entry_a()).unwrap();
        assert_eq!(s.air.fsp.len(), 1);
        s.set("air.fsp", "").unwrap();
        assert!(s.air.fsp.is_empty());
        // The load lists the problem with where it came from.
        let d = dir("fsp-bad");
        let p = load(&d, None, &env_of(&[("ECASH_AIR_FSP", "nonsense")])).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("ECASH_AIR_FSP") && x.contains("air.fsp")),
            "{p:?}"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_service_with_no_air_fsp_entry_is_refused_naming_the_setting() {
        let mut air = AirSettings::default();
        let service = ServiceDid::parse(A).unwrap();
        // Even with the PSP's and the ESP's server set: that is not the FSP's.
        air.server = B.to_string();
        air.host = "127.0.0.1".into();
        let e = air.fsp_for(service).unwrap_err();
        assert!(
            e.contains("air.fsp") && e.contains("ECASH_AIR_FSP") && e.contains(A),
            "{e}"
        );
        let e = Party::Fsp(service).address(&air).unwrap_err();
        assert!(e.contains("air.fsp"), "{e}");
        // The PSP and the ESP still go through air.server and air.host.
        let psp = Party::Psp.address(&air).unwrap();
        assert_eq!(psp, (B.to_string(), "127.0.0.1".to_string()));
        // With the entry, the FSP mint's address is the entry's, and its DID the service's.
        air.fsp
            .push(FspAir::parse(&format!("{A}@{A}@10.0.0.9")).unwrap());
        assert_eq!(
            Party::Fsp(service).address(&air).unwrap(),
            (A.to_string(), "10.0.0.9".to_string())
        );
        assert_eq!(Party::Fsp(service).did(&air), service);
        assert_eq!(Party::Fsp(service).setting(), "air.fsp");
    }
}
