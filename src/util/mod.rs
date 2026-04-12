//! Utility functions and types.

use std::path::Path;

/// Check if the current process is running as root.
pub fn is_root() -> bool {
    #[cfg(target_os = "linux")]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Check if we're running on Linux.
pub fn is_linux() -> bool {
    cfg!(target_os = "linux")
}

/// Check if a path exists and is a directory.
pub fn is_directory(path: &Path) -> bool {
    path.exists() && path.is_dir()
}

/// Generate a random container ID (12-character hex string).
pub fn generate_container_id() -> String {
    uuid::Uuid::new_v4().to_string()[..12].to_string()
}

/// Detect the current system architecture and return the library path suffix.
///
/// Returns the architecture-specific library directory name used by multi-arch
/// Linux distributions (e.g., `x86_64-linux-gnu`, `aarch64-linux-gnu`).
pub fn detect_arch_lib_dir() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64-linux-gnu"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64-linux-gnu"
    }
    #[cfg(target_arch = "arm")]
    {
        "arm-linux-gnueabihf"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "riscv64-linux-gnu"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )))]
    {
        "unknown-linux-gnu"
    }
}

/// Returns the dynamic linker path for the current architecture.
pub fn dynamic_linker_path() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "/lib64/ld-linux-x86-64.so.2"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "/lib/ld-linux-aarch64.so.1"
    }
    #[cfg(target_arch = "arm")]
    {
        "/lib/ld-linux-armhf.so.3"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
    {
        "/lib/ld-linux.so.2"
    }
}

/// Returns the standard library search paths for the current architecture.
pub fn lib_search_paths() -> Vec<String> {
    let arch_dir = detect_arch_lib_dir();
    vec![
        format!("/lib/{}", arch_dir),
        "/lib64".to_string(),
        format!("/usr/lib/{}", arch_dir),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_container_id_length() {
        let id = generate_container_id();
        assert_eq!(id.len(), 12);
    }

    #[test]
    fn test_generate_container_id_uniqueness() {
        let id1 = generate_container_id();
        let id2 = generate_container_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_is_linux() {
        let result = is_linux();
        if cfg!(target_os = "linux") {
            assert!(result);
        } else {
            assert!(!result);
        }
    }

    #[test]
    fn test_is_directory() {
        assert!(is_directory(Path::new("/")));
        assert!(!is_directory(Path::new("/nonexistent_path_for_test")));
    }

    #[test]
    fn test_detect_arch_lib_dir() {
        let dir = detect_arch_lib_dir();
        assert!(!dir.is_empty());
        assert!(dir.contains("linux"));
    }

    #[test]
    fn test_lib_search_paths_nonempty() {
        let paths = lib_search_paths();
        assert!(!paths.is_empty());
    }
}
