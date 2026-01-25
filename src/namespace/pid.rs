//! PID namespace management.
//!
//! The PID namespace isolates the process ID number space, meaning that
//! processes in different PID namespaces can have the same PID.

#![cfg(target_os = "linux")]

/// Information about a PID namespace.
#[derive(Debug)]
pub struct PidNamespace {
    /// The PID of the init process in this namespace (always 1 from inside).
    pub init_pid: i32,
}

impl PidNamespace {
    /// Create a new PID namespace representation.
    pub fn new(init_pid: i32) -> Self {
        Self { init_pid }
    }

    /// Check if the current process is the init process (PID 1) in its namespace.
    pub fn is_init() -> bool {
        nix::unistd::getpid().as_raw() == 1
    }

    /// Get the current PID within the namespace.
    pub fn current_pid() -> i32 {
        nix::unistd::getpid().as_raw()
    }
}
