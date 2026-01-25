//! Utility functions and types.

use std::path::Path;

/// Check if the current process is running as root.
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Check if we're running on Linux.
pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Check if a path exists and is a directory.
pub fn is_directory(path: &Path) -> bool {
    path.exists() && path.is_dir()
}

/// Generate a random container ID.
pub fn generate_container_id() -> String {
    uuid::Uuid::new_v4().to_string()[..12].to_string()
}
