//! Container process management - fork, namespace setup, and exec.

use crate::container::builder::ContainerConfig;
use crate::error::{ContainerError, Result};

#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    fs,
    os::unix::fs as unix_fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use nix::{
    mount::{umount2, MntFlags},
    sched::{clone, CloneFlags},
    sys::{
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::{chdir, execvp, sethostname, Pid},
};

#[cfg(target_os = "linux")]
use crate::namespace;

#[cfg(target_os = "linux")]
const STACK_SIZE: usize = 1024 * 1024; // 1MB stack for child

/// Represents a container instance.
pub struct Container {
    pub config: ContainerConfig,
    #[cfg(target_os = "linux")]
    rootfs_path: PathBuf,
    /// True when this Container created its own temporary rootfs and is
    /// responsible for tearing it down on exit. False when the user provided
    /// `--rootfs` and owns the directory.
    #[cfg(target_os = "linux")]
    owns_rootfs: bool,
}

impl Container {
    /// Create a new container with the given configuration.
    #[cfg(target_os = "linux")]
    pub fn new(config: ContainerConfig) -> Self {
        let (rootfs_path, owns_rootfs) = if let Some(ref path) = config.rootfs {
            (path.clone(), false)
        } else {
            // Create temporary rootfs using a restrictive temp directory
            let temp_path = PathBuf::from(format!("/tmp/crate-{}", config.id));
            (temp_path, true)
        };

        Self {
            config,
            rootfs_path,
            owns_rootfs,
        }
    }

    /// Create a new container - stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn new(config: ContainerConfig) -> Self {
        Self { config }
    }

    /// Run the container and return the exit code.
    #[cfg(target_os = "linux")]
    pub fn run(&self) -> Result<i32> {
        let _span = tracing::info_span!(
            "container.run",
            container_id = %self.config.id,
            command = ?self.config.command,
        )
        .entered();

        let start = std::time::Instant::now();

        // Prepare the root filesystem
        self.prepare_rootfs()?;

        // Set up the clone flags for namespace isolation
        let clone_flags = CloneFlags::CLONE_NEWPID  // New PID namespace
            | CloneFlags::CLONE_NEWNS               // New mount namespace
            | CloneFlags::CLONE_NEWUTS              // New UTS namespace (hostname)
            | CloneFlags::CLONE_NEWIPC; // New IPC namespace

        // Allocate stack for child process
        let mut stack = vec![0u8; STACK_SIZE];

        // Clone configuration
        let config = self.config.clone();
        let rootfs = self.rootfs_path.clone();

        // Clone into new namespaces
        let callback = Box::new(move || match container_init(&config, &rootfs) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("Container init error: {}", e);
                1
            }
        });

        let child_pid = unsafe {
            clone(
                callback,
                &mut stack,
                clone_flags,
                Some(Signal::SIGCHLD as i32),
            )
        }
        .map_err(|e| ContainerError::Process(format!("Failed to clone: {}", e)))?;

        tracing::info!(
            container_id = %self.config.id,
            pid = child_pid.as_raw(),
            "Container process started"
        );

        // Wait for child to exit
        let exit_code = self.wait_for_child(child_pid)?;

        let elapsed = start.elapsed();
        tracing::info!(
            container_id = %self.config.id,
            exit_code = exit_code,
            elapsed_ms = elapsed.as_millis() as u64,
            "Container exited"
        );

        // Cleanup
        if self.owns_rootfs {
            self.cleanup_rootfs()?;
        }

        Ok(exit_code)
    }

    /// Run the container - stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn run(&self) -> Result<i32> {
        Err(ContainerError::Process(
            "Container runtime only supported on Linux".to_string(),
        ))
    }

    /// Prepare the root filesystem for the container.
    #[cfg(target_os = "linux")]
    fn prepare_rootfs(&self) -> Result<()> {
        if self.owns_rootfs {
            // Create a minimal rootfs structure
            create_minimal_rootfs(&self.rootfs_path)?;
        }
        Ok(())
    }

    /// Wait for the child process and return its exit code.
    #[cfg(target_os = "linux")]
    fn wait_for_child(&self, pid: Pid) -> Result<i32> {
        loop {
            match waitpid(pid, None) {
                Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => {
                    return Ok(128 + signal as i32);
                }
                Ok(_) => continue,
                Err(nix::Error::EINTR) => continue,
                Err(e) => {
                    return Err(ContainerError::Process(format!(
                        "Failed to wait for child: {}",
                        e
                    )));
                }
            }
        }
    }

    /// Clean up the temporary rootfs.
    #[cfg(target_os = "linux")]
    fn cleanup_rootfs(&self) -> Result<()> {
        if self.rootfs_path.exists() {
            // Attempt to unmount any remaining mounts
            if let Err(e) = umount2(&self.rootfs_path, MntFlags::MNT_DETACH) {
                tracing::warn!(
                    rootfs = ?self.rootfs_path,
                    error = %e,
                    "Failed to unmount rootfs during cleanup"
                );
            }

            // Remove the directory
            fs::remove_dir_all(&self.rootfs_path).map_err(|e| {
                ContainerError::Filesystem(format!(
                    "Failed to cleanup rootfs at {:?}: {}",
                    self.rootfs_path, e
                ))
            })?;
        }
        Ok(())
    }
}

/// Initialize the container from inside the new namespaces.
///
/// This runs inside the cloned child process with new namespaces active.
/// Order of operations:
/// 1. Set hostname (UTS namespace)
/// 2. Set up mount namespace (pivot_root, /proc, /dev, etc.)
/// 3. Drop capabilities to Docker-default set
/// 4. Apply seccomp BPF filter
/// 5. exec the container command
#[cfg(target_os = "linux")]
fn container_init(config: &ContainerConfig, rootfs: &Path) -> Result<()> {
    let _span = tracing::info_span!(
        "container_init",
        container_id = %config.id,
        command = ?config.command,
    )
    .entered();

    // Set hostname
    sethostname(&config.hostname)
        .map_err(|e| ContainerError::Namespace(format!("Failed to set hostname: {}", e)))?;
    tracing::debug!(hostname = %config.hostname, "Set hostname");

    // Set up mount namespace
    namespace::mount::setup_mount_namespace(rootfs)?;

    // Change to root directory
    chdir("/").map_err(|e| ContainerError::Filesystem(format!("Failed to chdir: {}", e)))?;

    // Drop capabilities to minimal set
    if let Err(e) = crate::security::drop_capabilities() {
        tracing::warn!(error = %e, "Failed to drop capabilities (may need root)");
    }

    // Apply seccomp filter
    if let Err(e) = crate::security::apply_seccomp_filter() {
        tracing::warn!(error = %e, "Failed to apply seccomp filter");
    }

    // Execute the command
    exec_command(&config.command, &config.env)?;

    Ok(())
}

/// Public function called from main for the init subcommand.
#[cfg(target_os = "linux")]
pub fn init_container(command: &[String], hostname: &str, rootfs: &str) -> Result<()> {
    let config = ContainerConfig {
        id: "init".to_string(),
        hostname: hostname.to_string(),
        command: command.to_vec(),
        rootfs: Some(PathBuf::from(rootfs)),
        ..ContainerConfig::default()
    };

    container_init(&config, Path::new(rootfs))
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn init_container(_command: &[String], _hostname: &str, _rootfs: &str) -> Result<()> {
    Err(ContainerError::Process(
        "Container runtime only supported on Linux".to_string(),
    ))
}

/// Execute the command with the given environment.
#[cfg(target_os = "linux")]
fn exec_command(command: &[String], env: &[(String, String)]) -> Result<()> {
    // Set environment variables
    for (key, value) in env {
        std::env::set_var(key, value);
    }

    // Convert command to CStrings
    let cmd = CString::new(command[0].as_str())
        .map_err(|e| ContainerError::Process(format!("Invalid command: {}", e)))?;

    let args: Vec<CString> = command
        .iter()
        .map(|s| {
            CString::new(s.as_str())
                .map_err(|e| ContainerError::Process(format!("Invalid argument {:?}: {}", s, e)))
        })
        .collect::<Result<Vec<_>>>()?;

    // Execute
    execvp(&cmd, &args)
        .map_err(|e| ContainerError::Process(format!("Failed to exec {:?}: {}", command, e)))?;

    // execvp doesn't return on success
    unreachable!()
}

/// Create a minimal root filesystem for testing.
#[cfg(target_os = "linux")]
fn create_minimal_rootfs(rootfs: &Path) -> Result<()> {
    tracing::debug!(rootfs = ?rootfs, "Creating minimal rootfs");

    // Create directory structure
    let dirs = [
        "bin", "dev", "etc", "lib", "lib64", "proc", "sys", "tmp", "usr/bin", "usr/lib",
    ];

    for dir in &dirs {
        fs::create_dir_all(rootfs.join(dir))
            .map_err(|e| ContainerError::Filesystem(format!("Failed to create {}: {}", dir, e)))?;
    }

    // Copy essential binaries from host (for testing without a full rootfs)
    let binaries = ["/bin/sh", "/bin/ls", "/bin/cat", "/bin/ps", "/usr/bin/env"];

    for binary in &binaries {
        let src = Path::new(binary);
        if src.exists() {
            let dest = rootfs.join(binary.trim_start_matches('/'));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            if !dest.exists() {
                fs::copy(src, &dest).map_err(|e| {
                    ContainerError::Filesystem(format!("Failed to copy {}: {}", binary, e))
                })?;
            }
        }
    }

    // Copy required shared libraries (this is simplified - a real implementation
    // would use ldd to find all dependencies)
    copy_library_dependencies(rootfs)?;

    Ok(())
}

/// Copy library dependencies for the basic binaries.
///
/// Uses architecture-detected library paths rather than hardcoded x86_64 paths.
#[cfg(target_os = "linux")]
fn copy_library_dependencies(rootfs: &Path) -> Result<()> {
    let lib_paths = crate::util::lib_search_paths();

    // Essential libraries -- names are mostly arch-independent
    let essential_libs = ["libc.so.6", "libdl.so.2", "libpthread.so.0", "libm.so.6"];

    for lib_path in &lib_paths {
        let src_dir = Path::new(lib_path);
        if !src_dir.exists() {
            continue;
        }

        let dest_dir = rootfs.join(lib_path.trim_start_matches('/'));
        fs::create_dir_all(&dest_dir)?;

        for lib in &essential_libs {
            let src = src_dir.join(lib);
            let dest = dest_dir.join(lib);
            if src.exists() && !dest.exists() {
                if let Ok(real_path) = fs::canonicalize(&src) {
                    let real_name = real_path.file_name().ok_or_else(|| {
                        ContainerError::Filesystem(format!(
                            "Canonicalized path {:?} has no filename",
                            real_path
                        ))
                    })?;
                    let real_dest = dest_dir.join(real_name);

                    if !real_dest.exists() {
                        fs::copy(&real_path, &real_dest)?;
                    }

                    let real_name_str = real_name.to_str().ok_or_else(|| {
                        ContainerError::Filesystem(format!("Non-UTF8 filename: {:?}", real_name))
                    })?;
                    if *lib != real_name_str && !dest.exists() {
                        unix_fs::symlink(real_name, &dest)?;
                    }
                }
            }
        }
    }

    // Set up the dynamic linker using architecture-detected path
    let ld_path = crate::util::dynamic_linker_path();
    let ld_src = Path::new(ld_path);
    if ld_src.exists() {
        let ld_dest = rootfs.join(ld_path.trim_start_matches('/'));
        if let Some(ld_dest_dir) = ld_dest.parent() {
            fs::create_dir_all(ld_dest_dir)?;
        }
        if !ld_dest.exists() {
            if let Ok(real_path) = fs::canonicalize(ld_src) {
                fs::copy(&real_path, &ld_dest)?;
            }
        }
    }

    Ok(())
}
