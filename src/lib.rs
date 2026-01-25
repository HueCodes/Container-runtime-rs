//! # crate-runtime
//!
//! A minimal OCI-compatible container runtime written in Rust.
//!
//! This crate provides low-level container primitives using Linux namespaces,
//! cgroups, and filesystem isolation.

pub mod container;
pub mod error;
pub mod namespace;
pub mod util;

// Re-export main types
pub use container::{Container, ContainerBuilder};
pub use error::{ContainerError, Result};
