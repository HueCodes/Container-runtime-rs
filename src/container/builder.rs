//! Container builder for configuring and creating containers.
//!
//! Provides a builder-pattern API for constructing [`Container`] instances
//! with validated configuration including command, hostname, rootfs path,
//! and environment variables.

use crate::container::Container;
use crate::error::{ContainerError, Result};
use std::path::PathBuf;
use uuid::Uuid;

/// Configuration for a container.
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub id: String,
    pub hostname: String,
    pub command: Vec<String>,
    pub rootfs: Option<PathBuf>,
    pub env: Vec<(String, String)>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string()[..12].to_string(),
            hostname: "container".to_string(),
            command: vec!["/bin/sh".to_string()],
            rootfs: None,
            env: vec![
                (
                    "PATH".to_string(),
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                ),
                ("TERM".to_string(), "xterm".to_string()),
            ],
        }
    }
}

/// Builder pattern for creating containers.
pub struct ContainerBuilder {
    config: ContainerConfig,
}

impl ContainerBuilder {
    /// Create a new container builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: ContainerConfig::default(),
        }
    }

    /// Set the command to run inside the container.
    pub fn command(mut self, command: Vec<String>) -> Self {
        if !command.is_empty() {
            self.config.command = command;
        }
        self
    }

    /// Set the hostname for the container.
    pub fn hostname(mut self, hostname: String) -> Self {
        if !hostname.is_empty() {
            self.config.hostname = hostname;
        }
        self
    }

    /// Set the root filesystem path.
    pub fn rootfs(mut self, rootfs: String) -> Self {
        if !rootfs.is_empty() {
            self.config.rootfs = Some(PathBuf::from(rootfs));
        }
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: String, value: String) -> Self {
        self.config.env.push((key, value));
        self
    }

    /// Set the container ID.
    pub fn id(mut self, id: String) -> Self {
        self.config.id = id;
        self
    }

    /// Build the container.
    pub fn build(self) -> Result<Container> {
        // Validate command
        if self.config.command.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "Command cannot be empty".to_string(),
            ));
        }
        if self.config.command.iter().all(|s| s.is_empty()) {
            return Err(ContainerError::InvalidConfig(
                "Command must contain at least one non-empty argument".to_string(),
            ));
        }

        // Validate hostname (POSIX: max 255 chars, alphanumeric + hyphens)
        let hostname = &self.config.hostname;
        if hostname.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "Hostname cannot be empty".to_string(),
            ));
        }
        if hostname.len() > 255 {
            return Err(ContainerError::InvalidConfig(
                "Hostname exceeds maximum length of 255 characters".to_string(),
            ));
        }
        if !hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(ContainerError::InvalidConfig(
                "Hostname contains invalid characters (only alphanumeric, hyphens, and dots allowed)".to_string(),
            ));
        }

        // Validate rootfs path
        if let Some(ref rootfs) = self.config.rootfs {
            let path_str = rootfs.to_string_lossy();
            if path_str.is_empty() {
                return Err(ContainerError::InvalidConfig(
                    "Root filesystem path cannot be empty".to_string(),
                ));
            }
            if !rootfs.is_absolute() {
                return Err(ContainerError::InvalidConfig(
                    "Root filesystem path must be absolute".to_string(),
                ));
            }
            // Reject path traversal
            if path_str.contains("..") {
                return Err(ContainerError::InvalidConfig(
                    "Root filesystem path must not contain '..' components".to_string(),
                ));
            }
        }

        Ok(Container::new(self.config))
    }
}

impl Default for ContainerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_builder() {
        let builder = ContainerBuilder::new();
        let container = builder.build().unwrap();
        assert_eq!(container.config.command, vec!["/bin/sh"]);
        assert_eq!(container.config.hostname, "container");
        assert!(container.config.rootfs.is_none());
        assert_eq!(container.config.id.len(), 12);
    }

    #[test]
    fn test_builder_chaining() {
        let container = ContainerBuilder::new()
            .command(vec!["echo".into(), "hello".into()])
            .hostname("test-host".into())
            .id("test-id".into())
            .env("FOO".into(), "bar".into())
            .build()
            .unwrap();

        assert_eq!(container.config.command, vec!["echo", "hello"]);
        assert_eq!(container.config.hostname, "test-host");
        assert_eq!(container.config.id, "test-id");
        assert!(container
            .config
            .env
            .iter()
            .any(|(k, v)| k == "FOO" && v == "bar"));
    }

    #[test]
    fn test_empty_command_uses_default() {
        // Empty vec passed to .command() should keep the default
        let container = ContainerBuilder::new().command(vec![]).build().unwrap();
        assert_eq!(container.config.command, vec!["/bin/sh"]);
    }

    #[test]
    fn test_all_empty_strings_rejected() {
        let result = ContainerBuilder::new().command(vec!["".into()]).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_too_long() {
        let long_name = "a".repeat(256);
        let result = ContainerBuilder::new().hostname(long_name).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_invalid_chars() {
        let result = ContainerBuilder::new()
            .hostname("host name!".into())
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_valid() {
        let result = ContainerBuilder::new()
            .hostname("my-host.local".into())
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_rootfs_relative_path_rejected() {
        let result = ContainerBuilder::new()
            .rootfs("relative/path".into())
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_rootfs_traversal_rejected() {
        let result = ContainerBuilder::new()
            .rootfs("/some/../etc/shadow".into())
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_rootfs_absolute_path_accepted() {
        let result = ContainerBuilder::new()
            .rootfs("/var/lib/containers/rootfs".into())
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_hostname_ignored() {
        let container = ContainerBuilder::new().hostname("".into()).build().unwrap();
        assert_eq!(container.config.hostname, "container");
    }

    #[test]
    fn test_default_env() {
        let config = ContainerConfig::default();
        assert!(config.env.iter().any(|(k, _)| k == "PATH"));
        assert!(config.env.iter().any(|(k, _)| k == "TERM"));
    }
}
