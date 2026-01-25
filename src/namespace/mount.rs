//! Mount namespace management.
//!
//! The mount namespace isolates the set of filesystem mount points,
//! allowing each container to have its own filesystem view.

#![cfg(target_os = "linux")]

use crate::error::{ContainerError, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::{chdir, pivot_root};
use std::fs;
use std::path::Path;

/// Set up the mount namespace for a container.
///
/// This function:
/// 1. Makes all mounts private to prevent propagation
/// 2. Bind mounts the new root
/// 3. Sets up essential filesystems (/proc, /sys, /dev)
/// 4. Performs pivot_root to change the root filesystem
/// 5. Unmounts the old root
pub fn setup_mount_namespace(new_root: &Path) -> Result<()> {
    tracing::debug!("Setting up mount namespace with root: {:?}", new_root);

    // Make the mount namespace private (no propagation)
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| ContainerError::Mount(format!("Failed to make root private: {}", e)))?;

    // Bind mount the new root to itself (required for pivot_root)
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| ContainerError::Mount(format!("Failed to bind mount new root: {}", e)))?;

    // Create put_old directory for pivot_root
    let put_old = new_root.join(".pivot_root");
    fs::create_dir_all(&put_old).map_err(|e| {
        ContainerError::Filesystem(format!("Failed to create pivot_root dir: {}", e))
    })?;

    // Pivot root
    pivot_root(new_root, &put_old)
        .map_err(|e| ContainerError::Mount(format!("Failed to pivot_root: {}", e)))?;

    // Change to new root
    chdir("/").map_err(|e| ContainerError::Filesystem(format!("Failed to chdir to /: {}", e)))?;

    // Mount proc filesystem
    mount_proc()?;

    // Mount sysfs (read-only for security)
    mount_sysfs()?;

    // Set up /dev
    setup_dev()?;

    // Unmount old root
    umount2("/.pivot_root", MntFlags::MNT_DETACH)
        .map_err(|e| ContainerError::Mount(format!("Failed to unmount old root: {}", e)))?;

    // Remove the old root directory
    fs::remove_dir("/.pivot_root").ok(); // Ignore errors

    Ok(())
}

/// Mount the proc filesystem.
fn mount_proc() -> Result<()> {
    // Ensure /proc exists
    fs::create_dir_all("/proc").ok();

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .map_err(|e| ContainerError::Mount(format!("Failed to mount /proc: {}", e)))?;

    tracing::debug!("Mounted /proc");
    Ok(())
}

/// Mount the sysfs filesystem.
fn mount_sysfs() -> Result<()> {
    // Ensure /sys exists
    fs::create_dir_all("/sys").ok();

    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|e| ContainerError::Mount(format!("Failed to mount /sys: {}", e)))?;

    tracing::debug!("Mounted /sys");
    Ok(())
}

/// Set up the /dev directory with essential device nodes.
fn setup_dev() -> Result<()> {
    // Ensure /dev exists
    fs::create_dir_all("/dev").ok();

    // Mount a tmpfs on /dev
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
        Some("mode=755,size=65536k"),
    )
    .map_err(|e| ContainerError::Mount(format!("Failed to mount tmpfs on /dev: {}", e)))?;

    // Create essential device nodes
    create_dev_nodes()?;

    // Create /dev/pts for pseudoterminals
    fs::create_dir_all("/dev/pts").ok();
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )
    .ok(); // Ignore errors if devpts is not available

    // Create /dev/shm for shared memory
    fs::create_dir_all("/dev/shm").ok();
    mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        Some("mode=1777,size=65536k"),
    )
    .ok();

    tracing::debug!("Set up /dev");
    Ok(())
}

/// Create essential device nodes in /dev.
fn create_dev_nodes() -> Result<()> {
    use nix::sys::stat::{makedev, mknod, Mode, SFlag};
    use std::os::unix::fs::symlink;

    // Device nodes: (path, major, minor)
    let devices = [
        ("/dev/null", 1, 3),
        ("/dev/zero", 1, 5),
        ("/dev/full", 1, 7),
        ("/dev/random", 1, 8),
        ("/dev/urandom", 1, 9),
        ("/dev/tty", 5, 0),
    ];

    let mode = Mode::from_bits_truncate(0o666);

    for (path, major, minor) in &devices {
        let dev = makedev(*major, *minor);
        // Remove existing node if any
        fs::remove_file(path).ok();

        mknod(Path::new(path), SFlag::S_IFCHR, mode, dev).map_err(|e| {
            ContainerError::Filesystem(format!("Failed to create device node {}: {}", path, e))
        })?;
    }

    // Create symlinks
    symlink("/proc/self/fd", "/dev/fd").ok();
    symlink("/proc/self/fd/0", "/dev/stdin").ok();
    symlink("/proc/self/fd/1", "/dev/stdout").ok();
    symlink("/proc/self/fd/2", "/dev/stderr").ok();

    // Create /dev/console (needed for some applications)
    let console_dev = makedev(5, 1);
    fs::remove_file("/dev/console").ok();
    mknod(Path::new("/dev/console"), SFlag::S_IFCHR, mode, console_dev).ok();

    Ok(())
}

/// Bind mount a path into the container.
pub fn bind_mount(source: &Path, target: &Path, readonly: bool) -> Result<()> {
    // Create target if it doesn't exist
    if source.is_dir() {
        fs::create_dir_all(target)?;
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, "")?; // Create empty file
    }

    let mut flags = MsFlags::MS_BIND;
    if readonly {
        flags |= MsFlags::MS_RDONLY;
    }

    mount(Some(source), target, None::<&str>, flags, None::<&str>)
        .map_err(|e| ContainerError::Mount(format!("Failed to bind mount {:?}: {}", source, e)))?;

    // Remount to apply readonly flag (bind mounts ignore flags on first mount)
    if readonly {
        mount(
            None::<&str>,
            target,
            None::<&str>,
            flags | MsFlags::MS_REMOUNT,
            None::<&str>,
        )
        .map_err(|e| {
            ContainerError::Mount(format!("Failed to remount {:?} readonly: {}", target, e))
        })?;
    }

    Ok(())
}
