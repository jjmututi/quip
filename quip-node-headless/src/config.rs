//! Configuration file schema and loading.
//!
//! The file is TOML. Two modes, `Development` and `Production`,
//! selected by the `mode` field. See `docs/M9.7-design.md` §1 for the
//! full field table and the reason each mode differs.
//!
//! `witness_ring` and `trust_at_start` are two fields, not one. The
//! first names the ring whose `WitnessStatement`s the node accepts for
//! `Verified` computation; the second names peers the application trusts
//! as peers. Both resolve to NodeIds in the parser, and both are
//! validated the same way, but they play different roles and a future
//! revision that merged them would make the two roles one field. The
//! distinction is M9.6c's; see `docs/M9.6c-design.md` §4.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use quip_net::handshake::{Capabilities, Handshake};
use serde::Deserialize;

/// Which mode the node runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Development,
    Production,
}

/// A peer to dial at startup.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    pub addr: SocketAddr,
    #[serde(default = "default_server_name")]
    pub server_name: String,
}

fn default_server_name() -> String {
    String::from("localhost")
}

/// The parsed configuration file.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    pub mode: Mode,
    #[serde(default)]
    pub bind: Option<SocketAddr>,
    #[serde(default)]
    pub seed: Option<SeedConfig>,
    #[serde(default)]
    pub store_path: Option<PathBuf>,
    #[serde(default)]
    pub capabilities: Option<CapabilityConfig>,
    #[serde(default)]
    pub auto_serve_pins: Option<bool>,
    #[serde(default)]
    pub relay_capable: Option<bool>,
    #[serde(default)]
    pub force_relay: Option<bool>,
    #[serde(default)]
    pub witness_ring: Option<Vec<String>>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub trust: Option<TrustConfig>,
}

/// Where the seed comes from.
///
/// The value is one TOML string. A 64-character hex string is a literal
/// seed (Development only); anything else is a path to a seed file.
/// `serde`'s untagged enum cannot tell a `String` from a `PathBuf` —
/// both are TOML strings, and the first variant would always win — so
/// the classification is by shape, in [`SeedConfig::classify`].
#[derive(Debug, Clone, Deserialize)]
pub struct SeedConfig(pub String);

/// A seed setting classified by shape.
#[derive(Debug, Clone)]
pub enum ClassifiedSeed {
    /// 64 hex characters.
    Literal(String),
    /// Anything else: a path.
    File(PathBuf),
}

impl SeedConfig {
    /// Classify the setting as a literal seed or a file path.
    pub fn classify(&self) -> ClassifiedSeed {
        let s = self.0.trim();
        if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            ClassifiedSeed::Literal(s.to_string())
        } else {
            ClassifiedSeed::File(PathBuf::from(s))
        }
    }
}

/// The `[capabilities]` section: what the node advertises.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CapabilityConfig {
    /// Additional capability names beyond baseline + NAT_TRAVERSAL +
    /// DHT_DISCOVERY, e.g. `["BFT_CHECKPOINT", "MERKLE_RANGE"]`.
    #[serde(default)]
    pub extra: Vec<String>,
}

/// The `[trust]` section. Parsed and validated in M9.7, consumed in M9.6c.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustConfig {
    /// Peers trusted at startup, hex-encoded NodeIds.
    #[serde(default)]
    pub trust_at_start: Vec<String>,
}

/// A fully validated, mode-resolved configuration ready to build a node.
#[derive(Debug)]
pub struct Config {
    pub mode: Mode,
    pub bind: SocketAddr,
    pub seed: [u8; 32],
    pub store_path: Option<PathBuf>,
    pub capabilities: Capabilities,
    pub auto_serve_pins: bool,
    pub relay_capable: bool,
    pub force_relay: bool,
    pub peers: Vec<PeerConfig>,
    /// The configured witness ring, resolved from `witness_ring`.
    ///
    /// M9.6c: these are the peers whose statements the node accepts for
    /// `Verified` computation. The node seeds each of them as `Trusted`
    /// at first contact — see `quip-node-headless/src/shutdown.rs`.
    pub witness_ring: Vec<[u8; 32]>,
    /// Peers the application trusts as peers at startup, hex-encoded
    /// NodeIds. Parsed and resolved but **not yet consumed**: M9.6c
    /// consumes `witness_ring`, not this. The field is the
    /// `known_hosts` half of the trust configuration — who the operator
    /// trusts as peers — as distinct from `witness_ring`, which names the
    /// ring whose statements the node accepts. See
    /// `docs/M9.6c-design.md` §4.
    pub trust_at_start: Vec<[u8; 32]>,
}

impl Config {
    /// Load a config file and validate every field for its mode.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Io(path.to_path_buf(), e.to_string()))?;
        let file: ConfigFile =
            toml::from_str(&text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        Self::resolve(file)
    }

    fn resolve(file: ConfigFile) -> Result<Config, ConfigError> {
        let bind = match (file.mode, file.bind) {
            (_, Some(b)) => b,
            (Mode::Development, None) => "127.0.0.1:0".parse().expect("valid dev bind"),
            (Mode::Production, None) => {
                return Err(ConfigError::Missing("bind".into()));
            }
        };

        let seed = match (file.mode, file.seed.as_ref().map(SeedConfig::classify)) {
            (_, Some(ClassifiedSeed::Literal(s))) => {
                if file.mode == Mode::Production {
                    return Err(ConfigError::Invalid(
                        "production mode requires `seed` to be a file path, not a literal".into(),
                    ));
                }
                decode_hex_seed(&s)?
            }
            (_, Some(ClassifiedSeed::File(p))) => read_seed_file(&p)?,
            (Mode::Development, None) => {
                // A dev node that restarts with a new identity is what a
                // dev node should do; a dev node that requires a seed file
                // is not the mode a new contributor can run.
                tracing::warn!("development mode: no seed configured; using a fixed dev seed");
                let mut s = [0u8; 32];
                s[0] = 0x42;
                s
            }
            (Mode::Production, None) => {
                return Err(ConfigError::Missing("seed".into()));
            }
        };

        let store_path = match (file.mode, file.store_path) {
            (_, Some(p)) => Some(p),
            (Mode::Development, None) => None,
            (Mode::Production, None) => {
                return Err(ConfigError::Missing("store_path".into()));
            }
        };

        let base = Capabilities::baseline()
            | Capabilities(Capabilities::NAT_TRAVERSAL)
            | Capabilities(Capabilities::DHT_DISCOVERY);
        let extra = file.capabilities.unwrap_or_default();
        let mut caps_raw = base.0;
        for name in &extra.extra {
            let bit = capability_bit_for(name)
                .ok_or_else(|| ConfigError::Invalid(format!("unknown capability: {name}")))?;
            caps_raw |= bit;
        }
        let caps = Capabilities(caps_raw);
        // Row 4: the closure check. A locally-configured set whose
        // dependencies are not advertised is rejected here, at
        // configuration time, not at the first handshake.
        Handshake::new_checked(caps).map_err(|e| {
            ConfigError::Invalid(format!(
                "capability set rejected by Handshake::new_checked: {e}"
            ))
        })?;

        let auto_serve_pins = match (file.mode, file.auto_serve_pins) {
            (_, Some(b)) => b,
            (Mode::Development, None) => true,
            (Mode::Production, None) => {
                return Err(ConfigError::Missing("auto_serve_pins".into()));
            }
        };

        let relay_capable = match (file.mode, file.relay_capable) {
            (_, Some(b)) => b,
            (Mode::Development, None) => false,
            (Mode::Production, None) => {
                return Err(ConfigError::Missing("relay_capable".into()));
            }
        };

        let force_relay = file.force_relay.unwrap_or(false);

        let trust_at_start = match file.trust {
            Some(t) => t
                .trust_at_start
                .iter()
                .map(|h| decode_hex_node_id(h))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };

        // M9.6c: `witness_ring` is resolved and consumed. Every entry
        // must be a valid 32-byte NodeId; the resolved `Config` carries
        // them so the node can seed its trust policy at first contact.
        let witness_ring = match &file.witness_ring {
            Some(ring) => ring
                .iter()
                .map(|h| decode_hex_node_id(h))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };

        Ok(Config {
            mode: file.mode,
            bind,
            seed,
            store_path,
            capabilities: caps,
            auto_serve_pins,
            relay_capable,
            force_relay,
            peers: file.peers,
            witness_ring,
            trust_at_start,
        })
    }
}

/// Errors from config loading.
#[derive(Debug)]
pub enum ConfigError {
    Io(PathBuf, String),
    Parse(String),
    Missing(String),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(p, e) => write!(f, "cannot read {}: {e}", p.display()),
            ConfigError::Parse(e) => write!(f, "config parse: {e}"),
            ConfigError::Missing(field) => write!(f, "missing required field: {field}"),
            ConfigError::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn decode_hex_seed(s: &str) -> Result<[u8; 32], ConfigError> {
    let bytes = hex::decode(s).map_err(|e| ConfigError::Invalid(format!("seed hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ConfigError::Invalid(format!(
            "seed must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_node_id(s: &str) -> Result<[u8; 32], ConfigError> {
    decode_hex_seed(s)
}

fn read_seed_file(path: &Path) -> Result<[u8; 32], ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| ConfigError::Io(path.to_path_buf(), e.to_string()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::Invalid(format!(
                "seed file {} must not be group- or world-readable; mode is {:o}",
                path.display(),
                mode
            )));
        }
    }
    let raw =
        std::fs::read(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e.to_string()))?;
    if raw.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        return Ok(out);
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| ConfigError::Invalid("seed file must be 32 raw bytes or hex".into()))?
        .trim();
    decode_hex_seed(text)
}

/// Map a capability name to its bit, for names the binary knows.
///
/// The mapping is the binary's own; the bit values come from
/// `Capabilities`'s public constants. An application that needs a
/// capability not in this list adds it here in the same commit that
/// adds the capability to `quip-net`.
fn capability_bit_for(name: &str) -> Option<u64> {
    Some(match name {
        "BFT_CHECKPOINT" => Capabilities::BFT_CHECKPOINT,
        "MERKLE_RANGE" => Capabilities::MERKLE_RANGE,
        "BLAKE3" => Capabilities::BLAKE3,
        "CIDV1" => Capabilities::CIDV1,
        "CID_ADDRESSING" => Capabilities::CID_ADDRESSING,
        "DHT_DISCOVERY" => Capabilities::DHT_DISCOVERY,
        "GOVERNANCE" => Capabilities::GOVERNANCE,
        "NAT_TRAVERSAL" => Capabilities::NAT_TRAVERSAL,
        "RBSR_SYNC" => Capabilities::RBSR_SYNC,
        "RESOURCE_PIN" => Capabilities::RESOURCE_PIN,
        _ => return None,
    })
}
