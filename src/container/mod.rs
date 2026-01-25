//! Container module - handles container creation and lifecycle.

mod builder;
mod process;

pub use builder::ContainerBuilder;
pub use process::{init_container, Container};
