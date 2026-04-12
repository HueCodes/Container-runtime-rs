//! Configuration file support for the container runtime.
//!
//! Loads configuration from `/etc/crate/config.toml` or `~/.crate/config.toml`,
//! with sensible defaults for all values.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    /// Root directory for runtime state (containers, locks).
    pub root: PathBuf,

    /// Directory for image storage.
    pub image_root: PathBuf,

    /// Logging configuration.
    pub log: LogConfig,

    /// Default cgroup resource limits.
    pub cgroup: CgroupDefaults,

    /// Default security settings.
    pub security: SecurityDefaults,

    /// Default network settings.
    pub network: NetworkDefaults,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Log level filter (e.g., "info", "debug", "crate_runtime=debug").
    pub level: String,
}

/// Default cgroup resource limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CgroupDefaults {
    /// Default memory limit in bytes (0 = unlimited).
    pub memory_limit: u64,

    /// Default memory high watermark in bytes (0 = unlimited).
    pub memory_high: u64,

    /// Default CPU quota in microseconds per period (0 = unlimited).
    pub cpu_quota: u64,

    /// CPU period in microseconds.
    pub cpu_period: u64,

    /// Default PID limit (0 = unlimited).
    pub pids_max: u64,
}

/// Default security settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityDefaults {
    /// Whether to drop capabilities by default.
    pub drop_capabilities: bool,

    /// Whether to apply seccomp filters by default.
    pub enable_seccomp: bool,

    /// Whether to use read-only rootfs by default.
    pub read_only_rootfs: bool,
}

/// Default network settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkDefaults {
    /// Bridge interface name.
    pub bridge_name: String,

    /// Subnet for container networking (CIDR notation).
    pub subnet: String,

    /// Gateway IP address.
    pub gateway: String,

    /// Whether to enable networking by default.
    pub enabled: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        Self {
            root: PathBuf::from("/run/crate"),
            image_root: home.join(".crate/images"),
            log: LogConfig::default(),
            cgroup: CgroupDefaults::default(),
            security: SecurityDefaults::default(),
            network: NetworkDefaults::default(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "crate_runtime=info".to_string(),
        }
    }
}

impl Default for CgroupDefaults {
    fn default() -> Self {
        Self {
            memory_limit: 0,
            memory_high: 0,
            cpu_quota: 0,
            cpu_period: 100_000,
            pids_max: 0,
        }
    }
}

impl Default for SecurityDefaults {
    fn default() -> Self {
        Self {
            drop_capabilities: true,
            enable_seccomp: true,
            read_only_rootfs: false,
        }
    }
}

impl Default for NetworkDefaults {
    fn default() -> Self {
        Self {
            bridge_name: "crate0".to_string(),
            subnet: "172.28.0.0/16".to_string(),
            gateway: "172.28.0.1".to_string(),
            enabled: true,
        }
    }
}

impl RuntimeConfig {
    /// Load configuration from the standard paths.
    ///
    /// Checks in order:
    /// 1. `/etc/crate/config.toml`
    /// 2. `~/.crate/config.toml`
    ///
    /// If neither exists, returns defaults.
    pub fn load() -> Self {
        let paths = Self::config_paths();
        for path in &paths {
            if path.exists() {
                match Self::load_from(path) {
                    Ok(config) => {
                        tracing::info!(path = %path.display(), "Loaded configuration");
                        return config;
                    }
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "Failed to load config, using defaults"
                        );
                    }
                }
            }
        }
        tracing::debug!("No config file found, using defaults");
        Self::default()
    }

    /// Load configuration from a specific path.
    pub fn load_from(path: &Path) -> std::result::Result<Self, String> {
        let contents =
            std::fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;
        toml::from_str(&contents).map_err(|e| format!("Failed to parse config: {}", e))
    }

    /// Returns the list of standard config file paths to check.
    fn config_paths() -> Vec<PathBuf> {
        let mut paths = vec![PathBuf::from("/etc/crate/config.toml")];
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(".crate/config.toml"));
        }
        paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RuntimeConfig::default();
        assert_eq!(config.root, PathBuf::from("/run/crate"));
        assert_eq!(config.log.level, "crate_runtime=info");
        assert_eq!(config.cgroup.cpu_period, 100_000);
        assert!(config.security.drop_capabilities);
        assert!(config.security.enable_seccomp);
        assert_eq!(config.network.bridge_name, "crate0");
        assert_eq!(config.network.subnet, "172.28.0.0/16");
    }

    #[test]
    fn test_config_deserialization() {
        let toml_str = r#"
            root = "/var/run/crate"

            [log]
            level = "debug"

            [cgroup]
            memory_limit = 536870912
            pids_max = 100

            [security]
            drop_capabilities = false

            [network]
            bridge_name = "crate1"
            subnet = "10.0.0.0/8"
        "#;

        let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.root, PathBuf::from("/var/run/crate"));
        assert_eq!(config.log.level, "debug");
        assert_eq!(config.cgroup.memory_limit, 536870912);
        assert_eq!(config.cgroup.pids_max, 100);
        assert!(!config.security.drop_capabilities);
        assert_eq!(config.network.bridge_name, "crate1");
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = RuntimeConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: RuntimeConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(config.root, deserialized.root);
        assert_eq!(config.log.level, deserialized.log.level);
    }

    #[test]
    fn test_partial_config() {
        let toml_str = r#"
            [cgroup]
            memory_limit = 1073741824
        "#;

        let config: RuntimeConfig = toml::from_str(toml_str).unwrap();
        // Unspecified fields should use defaults
        assert_eq!(config.cgroup.memory_limit, 1073741824);
        assert_eq!(config.cgroup.cpu_period, 100_000);
        assert_eq!(config.network.bridge_name, "crate0");
    }
}
