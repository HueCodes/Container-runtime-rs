//! # crate-runtime
//!
//! A minimal OCI-compatible container runtime written in Rust.
//!
//! This crate provides low-level container primitives using Linux namespaces,
//! cgroups, and filesystem isolation.

pub mod cgroup;
pub mod config;
pub mod container;
pub mod error;
pub mod filesystem;
pub mod image;
pub mod namespace;
pub mod network;
pub mod runtime;
pub mod security;
pub mod util;

// Re-export main types
pub use container::{Container, ContainerBuilder};
pub use error::{ContainerError, Result};
