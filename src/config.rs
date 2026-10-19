//! The wallet's settings: `config.toml` beside the wallet file (or the file
//! `ECASH_CONFIG` or `--config` names), then `ECASH_...` environment variables,
//! then checks. The same shape as the mints': every setting is in `SPECS`, an
//! unknown key, a wrong type or a bad value is refused with every problem listed,
//! and `ecash-wallet config` prints the values in use and where each came from.
//!
//! Until now the wallet had only flags and the URL variables. These are its first
//! settings with a file, and they are all about storage.
//!
//! # Storage policy
//!
//! One setting per kind of data the wallet keeps, each an ordered list of AIR
//! service IDs (index 0 the primary; see [`sp_wire::storage`]):
//!
//! - `storage.wallet`: where the wallet file (notes, keys, requests in flight)
//!   is kept.
//! - `storage.app`: where the app's own data is kept.
//!
//! One entry is valid and means one service plus a local backup copy; an empty
//! list (the default) means local only. **This is configuration and validation
//! only: nothing reads or writes the AIR yet**, and the wallet file is still the
//! local file.
//!
//! The one thing the wallet does with the list today: **the service FSP fees for
//! storage are paid to is the primary of `storage.wallet`**
//! ([`Settings::storage_service`]), never whichever service the wallet happens to
//! hold FSP for. With the list empty there is no storage service, and the
//! wallet says so rather than choosing one. The command line uses it as the
//! default `--service` of the `fsp` commands.
//!
//! The planned behaviour is in the mints' DESIGN.md files ("Storage policy").
//!
//! # AIR (`[air]`)
//!
//! The calls between the wallet and a mint that do not go over HTTP are the
//! **PSP's mint info** (what `GET /health` reports: `wire_version` and
//! `network`, asked by `verify_mint` before anything else is sent to the PSP) and
//! its **keys**, **keysets** and **rotation** (`GET /keys`, `/keysets`,
//! `/rotation`). They go over AIR when the wallet knows how to reach the PSP there, which
//! takes three settings together: `air.psp_did` (the PSP's DID), `air.server`
//! (the AIR server's name, its public key) and `air.host` (where to reach it).
//! With none of the three set (the default) the call is HTTP, as before. Setting
//! only one or two is an error, so a half-written config is not mistaken for
//! "AIR is off". Every other call stays HTTP. The other `air.*` settings tune
//! the request and have defaults. See `air.rs` and the README.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sp_wire::ServiceDid;
use sp_wire::storage::{DataKind, StoragePolicy};

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
        what: "Which AIR services will keep the wallet file, as an ordered list of service IDs: index 0 is the primary and the rest are secondaries, in the order they would be promoted. A service ID is the service's AIR DID, a 33-byte compressed key in hex (66 characters, starting 02 or 03); the old 32-byte x-only form is refused. In the environment the IDs are separated by commas; in the file it is an array of strings or one such string. One entry: that service holds the wallet and the wallet keeps a local backup copy. Empty (the default): local only. At most 8, no duplicates. The primary is also the service that FSP fees for storage are paid to. Setting only for now: nothing reads or writes the AIR yet.",
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
        what: "The PSP's DID: the 33-byte compressed key of its mint_did_key.json, in hex. With air.server and air.host also set, the PSP's mint info, keys, keysets and rotation are asked over AIR instead of HTTP. All three or none: setting only some is an error. Empty (the default): HTTP.",
    },
    Spec {
        key: "air.server",
        env: "ECASH_AIR_SERVER",
        default: "",
        units: "AIR server name (66 hex characters)",
        what: "The name of the AIR server that carries the request: its public key, the compressed hex AIR prints (66 characters, starting 02 or 03). The wallet checks the server's signed challenge against it, so only the server with this key is accepted. Resolving a mint's DID to its AIR server is not built, so it is configuration for now. All of air.psp_did, air.server and air.host or none.",
    },
    Spec {
        key: "air.host",
        env: "ECASH_AIR_HOST",
        default: "",
        units: "host name or IP, no port",
        what: "Where to reach that AIR server: a host name or an IP with no scheme, no path and no port (the AIR client always dials port 5702 for ws). 127.0.0.1 for a server on this machine. All of air.psp_did, air.server and air.host or none.",
    },
    Spec {
        key: "air.reply_wait_secs",
        env: "ECASH_AIR_REPLY_WAIT_SECS",
        default: "30",
        units: "seconds (1 to 600)",
        what: "How long to wait for the mint's reply to one try of a request (mint info, keys, keysets or rotation). After that the same request is written again, in the next free mailbox slot.",
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

/// The `[air]` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirSettings {
    /// The PSP's DID, if set.
    pub psp_did: Option<ServiceDid>,
    /// The AIR server's name (its public key), or empty.
    pub server: String,
    /// The AIR server's host or IP, or empty.
    pub host: String,
    pub reply_wait_secs: u64,
    pub attempts: u32,
    pub max_skew_secs: u64,
    pub timeout_secs: u64,
}

impl Default for AirSettings {
    fn default() -> Self {
        AirSettings {
            psp_did: None,
            server: String::new(),
            host: String::new(),
            reply_wait_secs: 30,
            attempts: 3,
            max_skew_secs: 300,
            timeout_secs: 10,
        }
    }
}

impl AirSettings {
    /// True when the PSP's mint info, keys, keysets and rotation are asked over AIR: the DID, the server and
    /// the host are all set. ([`Settings::problems`] refuses some but not all.)
    pub fn is_configured(&self) -> bool {
        self.psp_did.is_some() && !self.server.is_empty() && !self.host.is_empty()
    }

    /// The names of the three connection settings that are not set.
    fn unset(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.psp_did.is_none() {
            out.push("air.psp_did");
        }
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
            "air.server" => self.air.server.clone(),
            "air.host" => self.air.host.clone(),
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
            "air.reply_wait_secs" => self.air.reply_wait_secs = number(key, value, 1, 600)?,
            "air.attempts" => self.air.attempts = number(key, value, 1, 10)? as u32,
            "air.max_skew_secs" => self.air.max_skew_secs = number(key, value, 1, 86_400)?,
            "air.timeout_secs" => self.air.timeout_secs = number(key, value, 1, 600)?,
            other => return Err(format!("unknown setting `{other}`")),
        }
        Ok(())
    }

    /// Mistakes that involve more than one setting: the three connection
    /// settings go together.
    pub fn problems(&self) -> Vec<String> {
        let unset = self.air.unset();
        if unset.is_empty() || unset.len() == 3 {
            return vec![];
        }
        vec![format!(
            "air.psp_did, air.server and air.host go together (all three ask the PSP's mint info, keys, keysets and rotation over AIR, none leaves them on HTTP), but {} not set",
            if unset.len() == 1 {
                format!("{} is", unset[0])
            } else {
                format!("{} are", unset.join(" and "))
            }
        )]
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

    /// The service that FSP fees for storage are paid to: the primary of
    /// `storage.wallet`. `None` when that list is empty (local only).
    pub fn storage_service(&self) -> Option<ServiceDid> {
        self.storage_wallet.primary().copied()
    }
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
                            "{key} must be a list of strings (service IDs), not {items:?}"
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
        assert_eq!(l.settings.storage_service(), None);
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
        // The storage service is the wallet policy's primary, not the app's.
        assert_eq!(s.storage_service().unwrap().to_hex(), A);
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
    fn air_is_off_by_default_and_on_with_the_did_the_server_and_the_host() {
        let d = dir("air-on");
        let l = load(&d, None, &no_env).unwrap();
        assert!(!l.settings.air.is_configured());
        assert_eq!(l.settings.air, AirSettings::default());
        assert_eq!(l.settings.air.reply_wait_secs, 30);
        assert_eq!(l.settings.air.attempts, 3);

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

        let l = load(&d, None, &env_of(&[("ECASH_AIR_HOST", "air.example.org")])).unwrap();
        assert_eq!(l.settings.air.host, "air.example.org");
        assert_eq!(l.sources["air.host"], Source::Env("ECASH_AIR_HOST"));
        assert_eq!(l.sources["air.server"], Source::File);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn some_but_not_all_of_the_air_connection_settings_is_an_error() {
        let d = dir("air-partial");
        let p = load(&d, None, &env_of(&[("ECASH_AIR_HOST", "127.0.0.1")])).unwrap_err();
        assert!(
            p.iter()
                .any(|x| x.contains("air.psp_did and air.server are not set")),
            "{p:?}"
        );
        let both = [("ECASH_AIR_HOST", "127.0.0.1"), ("ECASH_AIR_SERVER", B)];
        let p = load(&d, None, &env_of(&both)).unwrap_err();
        assert!(
            p.iter().any(|x| x.contains("air.psp_did is not set")),
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
        assert_eq!(l.settings.storage_service(), None);
        fs::remove_dir_all(&d).unwrap();
    }
}
