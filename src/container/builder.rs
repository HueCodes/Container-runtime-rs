//! Container builder for configuring and creating containers.

use crate::error::{ContainerError, Result};
use crate::container::Container;
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
                ("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()),
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
        self.config.hostname = hostname;
        self
    }

    /// Set the root filesystem path.
    pub fn rootfs(mut self, rootfs: String) -> Self {
        self.config.rootfs = Some(PathBuf::from(rootfs));
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
        // Validate configuration
        if self.config.command.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "Command cannot be empty".to_string(),
            ));
        }

        Ok(Container::new(self.config))
    }
}

impl Default for ContainerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
