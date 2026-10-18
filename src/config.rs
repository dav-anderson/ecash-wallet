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
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    pub storage_wallet: StoragePolicy,
    pub storage_app: StoragePolicy,
}

impl Settings {
    /// The current value of a setting, as it is written in the file.
    pub fn get(&self, key: &str) -> Option<String> {
        Some(match key {
            "storage.wallet" => self.storage_wallet.to_config_string(),
            "storage.app" => self.storage_app.to_config_string(),
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
            other => return Err(format!("unknown setting `{other}`")),
        }
        Ok(())
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
