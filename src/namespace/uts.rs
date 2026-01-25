//! UTS namespace management.
//!
//! The UTS namespace isolates hostname and domain name, allowing each
//! container to have its own hostname.

#![cfg(target_os = "linux")]

use crate::error::{ContainerError, Result};
use nix::unistd::sethostname;

/// Set the hostname for the current UTS namespace.
pub fn set_hostname(hostname: &str) -> Result<()> {
    sethostname(hostname)
        .map_err(|e| ContainerError::Namespace(format!("Failed to set hostname: {}", e)))?;
    Ok(())
}

/// Get the current hostname.
pub fn get_hostname() -> Result<String> {
    let hostname = nix::unistd::gethostname()
        .map_err(|e| ContainerError::Namespace(format!("Failed to get hostname: {}", e)))?;

    hostname
        .into_string()
        .map_err(|e| ContainerError::Namespace(format!("Invalid hostname encoding: {:?}", e)))
}
