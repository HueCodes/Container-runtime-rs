//! Error types for the container runtime.

use thiserror::Error;

/// Errors that can occur during container operations.
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

    #[error("Cgroup error: {0}")]
    Cgroup(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Security error: {0}")]
    Security(String),

    #[error("Image error: {0}")]
    Image(String),

    #[error("Runtime error: {0}")]
    Runtime(String),

    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("HTTP error: {0}")]
    Http(String),
}

pub type Result<T> = std::result::Result<T, ContainerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ContainerError::Namespace("test error".into());
        assert_eq!(err.to_string(), "Namespace error: test error");
    }

    #[test]
    fn test_error_display_variants() {
        assert!(ContainerError::Mount("m".into())
            .to_string()
            .contains("Mount"));
        assert!(ContainerError::Filesystem("f".into())
            .to_string()
            .contains("Filesystem"));
        assert!(ContainerError::Process("p".into())
            .to_string()
            .contains("Process"));
        assert!(ContainerError::NotFound("n".into())
            .to_string()
            .contains("not found"));
        assert!(ContainerError::InvalidConfig("c".into())
            .to_string()
            .contains("Invalid"));
        assert!(ContainerError::Cgroup("cg".into())
            .to_string()
            .contains("Cgroup"));
        assert!(ContainerError::Network("net".into())
            .to_string()
            .contains("Network"));
        assert!(ContainerError::Security("sec".into())
            .to_string()
            .contains("Security"));
        assert!(ContainerError::Image("img".into())
            .to_string()
            .contains("Image"));
        assert!(ContainerError::Runtime("rt".into())
            .to_string()
            .contains("Runtime"));
        assert!(ContainerError::Http("h".into())
            .to_string()
            .contains("HTTP"));
    }

    #[test]
    fn test_invalid_state_transition_display() {
        let err = ContainerError::InvalidStateTransition {
            from: "Created".into(),
            to: "Stopped".into(),
        };
        assert!(err.to_string().contains("Created"));
        assert!(err.to_string().contains("Stopped"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err: ContainerError = io_err.into();
        assert!(matches!(err, ContainerError::Io(_)));
    }

    #[test]
    fn test_nix_error_conversion() {
        let nix_err = nix::Error::ENOENT;
        let err: ContainerError = nix_err.into();
        assert!(matches!(err, ContainerError::Nix(_)));
    }

    #[test]
    fn test_serde_error_conversion() {
        let serde_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err: ContainerError = serde_err.into();
        assert!(matches!(err, ContainerError::Serialization(_)));
    }
}
