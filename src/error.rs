//! Error types for the container runtime.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContainerError {
    #[error("Namespace error: {0}")]
    Namespace(String),

    #[error("Mount error: {0}")]
    Mount(String),

    #[error("Filesystem error: {0}")]
    Filesystem(String),

    #[error("Process error: {0}")]
    Process(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Nix error: {0}")]
    Nix(#[from] nix::Error),

    #[error("Container not found: {0}")]
    NotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, ContainerError>;
