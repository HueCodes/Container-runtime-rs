//! Filesystem management for container rootfs.
//!
//! Provides OverlayFS mount support for combining image layers (lowerdir)
//! with a writable upper layer, or mounting as a read-only overlay.

use std::path::{Path, PathBuf};

use crate::error::{ContainerError, Result};

/// Directory paths created for a container's overlay filesystem.
///
/// Contains the upper (writable), work (overlay internal), and merged
/// (final mountpoint) directories under a container-specific base path.
#[derive(Debug, Clone)]
pub struct OverlayDirs {
    /// Writable upper layer directory.
    pub upper: PathBuf,
    /// OverlayFS work directory (used internally by the kernel).
    pub work: PathBuf,
    /// Merged mountpoint where the final filesystem is visible.
    pub merged: PathBuf,
}

/// An OverlayFS mount configuration.
///
/// Represents a configured overlay mount with lower (read-only) layers,
/// an optional upper (writable) layer, and the final mountpoint.
/// Use [`OverlayMount::builder()`] to construct instances.
#[derive(Debug, Clone)]
pub struct OverlayMount {
    /// Final mountpoint path.
    mountpoint: PathBuf,
    /// Read-only lower layers, ordered bottom to top.
    lower_dirs: Vec<PathBuf>,
    /// Writable upper directory (None in read-only mode).
    upper_dir: Option<PathBuf>,
    /// OverlayFS work directory (None in read-only mode).
    work_dir: Option<PathBuf>,
    /// Whether this is a read-only mount (no upperdir).
    read_only: bool,
}

impl OverlayMount {
    /// Returns a new [`OverlayMountBuilder`].
    pub fn builder() -> OverlayMountBuilder {
        OverlayMountBuilder::default()
    }

    /// Constructs the mount options string for the overlay mount.
    ///
    /// For read-write mounts: `lowerdir=l1:l2,upperdir=...,workdir=...`
    /// For read-only mounts: `lowerdir=l1:l2`
    pub fn mount_options(&self) -> String {
        let lower = self
            .lower_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(":");

        if self.read_only {
            format!("lowerdir={lower}")
        } else {
            let upper = self
                .upper_dir
                .as_ref()
                .expect("upper_dir required for read-write mount");
            let work = self
                .work_dir
                .as_ref()
                .expect("work_dir required for read-write mount");
            format!(
                "lowerdir={lower},upperdir={},workdir={}",
                upper.display(),
                work.display()
            )
        }
    }

    /// Performs the overlay mount.
    ///
    /// Creates the mountpoint directory if it does not exist, then calls
    /// `mount(2)` with fstype `"overlay"`.
    #[cfg(target_os = "linux")]
    pub fn mount(&self) -> Result<()> {
        use nix::mount::MsFlags;
        use tracing::info;

        let options = self.mount_options();

        info!(
            mountpoint = %self.mountpoint.display(),
            lower_count = self.lower_dirs.len(),
            read_only = self.read_only,
            "mounting overlayfs"
        );

        std::fs::create_dir_all(&self.mountpoint).map_err(|e| {
            ContainerError::Filesystem(format!(
                "failed to create mountpoint {}: {e}",
                self.mountpoint.display()
            ))
        })?;

        let mut flags = MsFlags::empty();
        if self.read_only {
            flags |= MsFlags::MS_RDONLY;
        }

        nix::mount::mount(
            Some("overlay"),
            &self.mountpoint,
            Some("overlay"),
            flags,
            Some(options.as_str()),
        )
        .map_err(|e| {
            ContainerError::Mount(format!(
                "failed to mount overlay at {}: {e}",
                self.mountpoint.display()
            ))
        })?;

        info!(mountpoint = %self.mountpoint.display(), "overlayfs mounted");
        Ok(())
    }

    /// Stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn mount(&self) -> Result<()> {
        tracing::warn!(
            mountpoint = %self.mountpoint.display(),
            "overlayfs mount is only supported on Linux"
        );
        Err(ContainerError::Mount(
            "overlayfs is only supported on Linux".to_string(),
        ))
    }

    /// Unmounts the overlay filesystem.
    #[cfg(target_os = "linux")]
    pub fn unmount(&self) -> Result<()> {
        use tracing::info;

        info!(mountpoint = %self.mountpoint.display(), "unmounting overlayfs");

        nix::mount::umount(&self.mountpoint).map_err(|e| {
            ContainerError::Mount(format!(
                "failed to unmount overlay at {}: {e}",
                self.mountpoint.display()
            ))
        })?;

        info!(mountpoint = %self.mountpoint.display(), "overlayfs unmounted");
        Ok(())
    }

    /// Stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn unmount(&self) -> Result<()> {
        tracing::warn!(
            mountpoint = %self.mountpoint.display(),
            "overlayfs unmount is only supported on Linux"
        );
        Err(ContainerError::Mount(
            "overlayfs is only supported on Linux".to_string(),
        ))
    }
}

/// Builder for [`OverlayMount`].
///
/// Accumulates lower layers, optional upper/work directories, the mountpoint,
/// and a read-only flag before validating and producing an `OverlayMount`.
#[derive(Debug, Default)]
pub struct OverlayMountBuilder {
    mountpoint: Option<PathBuf>,
    lower_dirs: Vec<PathBuf>,
    upper_dir: Option<PathBuf>,
    work_dir: Option<PathBuf>,
    read_only: bool,
}

impl OverlayMountBuilder {
    /// Adds a lower (read-only) layer directory.
    ///
    /// Layers are stacked in the order they are added (first = bottom).
    pub fn lower_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.lower_dirs.push(path.into());
        self
    }

    /// Sets the writable upper directory.
    pub fn upper_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.upper_dir = Some(path.into());
        self
    }

    /// Sets the overlay work directory.
    pub fn work_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.work_dir = Some(path.into());
        self
    }

    /// Sets the final mountpoint path.
    pub fn mount_point(mut self, path: impl Into<PathBuf>) -> Self {
        self.mountpoint = Some(path.into());
        self
    }

    /// Sets whether the overlay should be mounted read-only.
    ///
    /// When `true`, no upper or work directory is required.
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Validates and builds the [`OverlayMount`].
    ///
    /// Returns an error if the mountpoint is missing, no lower layers are
    /// provided, or a read-write mount is missing upper/work directories.
    pub fn build(self) -> Result<OverlayMount> {
        let mountpoint = self.mountpoint.ok_or_else(|| {
            ContainerError::InvalidConfig("overlay mount requires a mountpoint".to_string())
        })?;

        if self.lower_dirs.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "overlay mount requires at least one lower directory".to_string(),
            ));
        }

        if !self.read_only {
            if self.upper_dir.is_none() {
                return Err(ContainerError::InvalidConfig(
                    "read-write overlay mount requires an upper directory".to_string(),
                ));
            }
            if self.work_dir.is_none() {
                return Err(ContainerError::InvalidConfig(
                    "read-write overlay mount requires a work directory".to_string(),
                ));
            }
        }

        Ok(OverlayMount {
            mountpoint,
            lower_dirs: self.lower_dirs,
            upper_dir: self.upper_dir,
            work_dir: self.work_dir,
            read_only: self.read_only,
        })
    }
}

/// Creates the upper, work, and merged directories for a container's overlay.
///
/// Directories are created under `base_dir/<container_id>/{upper,work,merged}`.
/// All directories are created with standard permissions.
pub fn prepare_overlay_dirs(container_id: &str, base_dir: &Path) -> Result<OverlayDirs> {
    let container_dir = base_dir.join(container_id);
    let upper = container_dir.join("upper");
    let work = container_dir.join("work");
    let merged = container_dir.join("merged");

    tracing::info!(
        container_id = container_id,
        base = %base_dir.display(),
        "preparing overlay directories"
    );

    for dir in [&upper, &work, &merged] {
        std::fs::create_dir_all(dir).map_err(|e| {
            ContainerError::Filesystem(format!(
                "failed to create overlay directory {}: {e}",
                dir.display()
            ))
        })?;
    }

    tracing::debug!(
        upper = %upper.display(),
        work = %work.display(),
        merged = %merged.display(),
        "overlay directories created"
    );

    Ok(OverlayDirs {
        upper,
        work,
        merged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_options_read_write() {
        let overlay = OverlayMount::builder()
            .lower_dir("/layers/base")
            .lower_dir("/layers/app")
            .upper_dir("/containers/abc/upper")
            .work_dir("/containers/abc/work")
            .mount_point("/containers/abc/merged")
            .build()
            .unwrap();

        let opts = overlay.mount_options();
        assert_eq!(
            opts,
            "lowerdir=/layers/base:/layers/app,upperdir=/containers/abc/upper,workdir=/containers/abc/work"
        );
    }

    #[test]
    fn mount_options_read_only() {
        let overlay = OverlayMount::builder()
            .lower_dir("/layers/base")
            .lower_dir("/layers/app")
            .mount_point("/containers/abc/merged")
            .read_only(true)
            .build()
            .unwrap();

        let opts = overlay.mount_options();
        assert_eq!(opts, "lowerdir=/layers/base:/layers/app");
    }

    #[test]
    fn mount_options_single_lower() {
        let overlay = OverlayMount::builder()
            .lower_dir("/layers/only")
            .mount_point("/mnt")
            .read_only(true)
            .build()
            .unwrap();

        assert_eq!(overlay.mount_options(), "lowerdir=/layers/only");
    }

    #[test]
    fn builder_missing_mountpoint() {
        let result = OverlayMount::builder()
            .lower_dir("/layers/base")
            .upper_dir("/upper")
            .work_dir("/work")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("mountpoint"),
            "expected mountpoint error: {err}"
        );
    }

    #[test]
    fn builder_empty_layers() {
        let result = OverlayMount::builder()
            .mount_point("/mnt")
            .upper_dir("/upper")
            .work_dir("/work")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("lower directory"),
            "expected lower dir error: {err}"
        );
    }

    #[test]
    fn builder_rw_missing_upper() {
        let result = OverlayMount::builder()
            .lower_dir("/layers/base")
            .work_dir("/work")
            .mount_point("/mnt")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("upper directory"),
            "expected upper dir error: {err}"
        );
    }

    #[test]
    fn builder_rw_missing_workdir() {
        let result = OverlayMount::builder()
            .lower_dir("/layers/base")
            .upper_dir("/upper")
            .mount_point("/mnt")
            .build();

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("work directory"),
            "expected work dir error: {err}"
        );
    }

    #[test]
    fn builder_read_only_no_upper_ok() {
        let result = OverlayMount::builder()
            .lower_dir("/layers/base")
            .mount_point("/mnt")
            .read_only(true)
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn prepare_overlay_dirs_creates_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = prepare_overlay_dirs("test-container-123", tmp.path()).unwrap();

        assert_eq!(
            dirs.upper,
            tmp.path().join("test-container-123").join("upper")
        );
        assert_eq!(
            dirs.work,
            tmp.path().join("test-container-123").join("work")
        );
        assert_eq!(
            dirs.merged,
            tmp.path().join("test-container-123").join("merged")
        );

        assert!(dirs.upper.is_dir());
        assert!(dirs.work.is_dir());
        assert!(dirs.merged.is_dir());
    }

    #[test]
    fn prepare_overlay_dirs_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs1 = prepare_overlay_dirs("ctr", tmp.path()).unwrap();
        let dirs2 = prepare_overlay_dirs("ctr", tmp.path()).unwrap();

        assert_eq!(dirs1.upper, dirs2.upper);
        assert_eq!(dirs1.work, dirs2.work);
        assert_eq!(dirs1.merged, dirs2.merged);
    }
}
