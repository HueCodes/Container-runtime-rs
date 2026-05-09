//! Container module -- handles container creation and lifecycle.
//!
//! The primary entry point is [`ContainerBuilder`], which configures and
//! creates [`Container`] instances. Containers are executed via
//! [`Container::run()`], which clones into new Linux namespaces and
//! executes the specified command.

mod builder;
mod process;

pub use builder::{ContainerBuilder, ContainerConfig};
pub use process::{init_container, Container};

#[cfg(target_os = "linux")]
pub use process::spawn_container_process;
