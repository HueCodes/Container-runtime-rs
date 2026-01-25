//! Linux namespace management.
//!
//! This module provides utilities for creating and managing Linux namespaces
//! for container isolation.
//!
//! Note: This module only compiles on Linux.

#[cfg(target_os = "linux")]
pub mod mount;
#[cfg(target_os = "linux")]
pub mod pid;
#[cfg(target_os = "linux")]
pub mod uts;
