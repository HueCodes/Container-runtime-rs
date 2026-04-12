//! Integration tests for crate-runtime.

#[cfg(target_os = "linux")]
#[path = "integration/lifecycle.rs"]
mod lifecycle;

#[path = "integration/builder.rs"]
mod builder;

#[path = "integration/config.rs"]
mod config;
