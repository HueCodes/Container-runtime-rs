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

/// Validate a hostname string.
///
/// Returns `Ok(())` if the hostname is valid per POSIX rules (max 255 chars,
/// alphanumeric plus hyphens and dots only).
pub fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() {
        return Err(ContainerError::Namespace("Hostname cannot be empty".into()));
    }
    if hostname.len() > 255 {
        return Err(ContainerError::Namespace("Hostname too long".into()));
    }
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(ContainerError::Namespace(
            "Hostname contains invalid characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hostname_valid() {
        assert!(validate_hostname("my-host").is_ok());
        assert!(validate_hostname("host.local").is_ok());
        assert!(validate_hostname("a").is_ok());
    }

    #[test]
    fn test_validate_hostname_empty() {
        assert!(validate_hostname("").is_err());
    }

    #[test]
    fn test_validate_hostname_too_long() {
        let long = "a".repeat(256);
        assert!(validate_hostname(&long).is_err());
    }

    #[test]
    fn test_validate_hostname_invalid_chars() {
        assert!(validate_hostname("host name").is_err());
        assert!(validate_hostname("host!name").is_err());
        assert!(validate_hostname("host_name").is_err());
    }

    #[test]
    fn test_validate_hostname_max_length() {
        let max = "a".repeat(255);
        assert!(validate_hostname(&max).is_ok());
    }
}
