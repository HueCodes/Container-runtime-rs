//! Cgroups v2 management for container resource limiting.
//!
//! This module implements the Linux cgroups v2 unified hierarchy for constraining
//! container resource usage. It supports memory, CPU, and PID limits via control
//! files under `/sys/fs/cgroup/`.
//!
//! All Linux-specific functionality is gated behind `#[cfg(target_os = "linux")]`.

#[cfg(target_os = "linux")]
use crate::error::ContainerError;
#[cfg(target_os = "linux")]
use crate::error::Result;

/// Base path for the cgroup v2 unified hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Subdirectory under the cgroup root where this runtime places its cgroups.
const CGROUP_RUNTIME_PREFIX: &str = "crate";

/// Memory limit configuration for a cgroup.
#[derive(Debug, Clone, Default)]
pub struct MemoryLimit {
    /// Hard memory limit in bytes. Written to `memory.max`.
    /// When the cgroup exceeds this, the OOM killer is invoked.
    pub max_bytes: Option<u64>,

    /// High memory threshold in bytes. Written to `memory.high`.
    /// When exceeded, the kernel throttles allocations and reclaims memory
    /// aggressively, but does not kill processes.
    pub high_bytes: Option<u64>,
}

/// CPU limit configuration for a cgroup.
#[derive(Debug, Clone)]
pub struct CpuLimit {
    /// CPU quota in microseconds per period. Written as the first value in `cpu.max`.
    /// For example, 50000 with a period of 100000 grants 50% of one CPU.
    pub quota_us: u64,

    /// CPU period in microseconds. Written as the second value in `cpu.max`.
    /// Defaults to 100000 (100ms), the standard Linux scheduling period.
    pub period_us: u64,
}

impl Default for CpuLimit {
    fn default() -> Self {
        Self {
            quota_us: 100_000,
            period_us: 100_000,
        }
    }
}

/// PID limit configuration for a cgroup.
#[derive(Debug, Clone, Default)]
pub struct PidLimit {
    /// Maximum number of processes. Written to `pids.max`.
    pub max: Option<u64>,
}

/// Manages a cgroup v2 directory for a single container.
///
/// Use the builder methods to configure resource limits, then call [`apply`](CgroupManager::apply)
/// to create the cgroup directory and write the control files. Call [`add_process`](CgroupManager::add_process)
/// to move a process into the cgroup, and [`cleanup`](CgroupManager::cleanup) to remove it.
///
/// # Example
///
/// ```no_run
/// # use crate_runtime::cgroup::CgroupManager;
/// let mgr = CgroupManager::new("my-container-id")
///     .with_memory_max(256 * 1024 * 1024)
///     .with_memory_high(200 * 1024 * 1024)
///     .with_cpu_quota(50_000, 100_000)
///     .with_pid_max(128);
/// ```
#[derive(Debug, Clone)]
pub struct CgroupManager {
    /// Container identifier, used as the cgroup directory name.
    container_id: String,

    /// Full path to this container's cgroup directory.
    cgroup_path: std::path::PathBuf,

    /// Memory limits to apply.
    memory: MemoryLimit,

    /// CPU limits to apply.
    cpu: Option<CpuLimit>,

    /// PID limits to apply.
    pids: PidLimit,
}

impl CgroupManager {
    /// Creates a new `CgroupManager` for the given container ID.
    ///
    /// The cgroup directory will be placed at
    /// `/sys/fs/cgroup/crate/{container_id}`.
    pub fn new(container_id: impl Into<String>) -> Self {
        let id = container_id.into();
        let cgroup_path = std::path::PathBuf::from(CGROUP_ROOT)
            .join(CGROUP_RUNTIME_PREFIX)
            .join(&id);
        Self {
            container_id: id,
            cgroup_path,
            memory: MemoryLimit::default(),
            cpu: None,
            pids: PidLimit::default(),
        }
    }

    /// Sets the hard memory limit (`memory.max`) in bytes.
    pub fn with_memory_max(mut self, bytes: u64) -> Self {
        self.memory.max_bytes = Some(bytes);
        self
    }

    /// Sets the high memory threshold (`memory.high`) in bytes.
    pub fn with_memory_high(mut self, bytes: u64) -> Self {
        self.memory.high_bytes = Some(bytes);
        self
    }

    /// Sets the CPU quota and period for `cpu.max`.
    ///
    /// `quota_us` is the allowed CPU time per `period_us` microseconds.
    /// For 50% of one CPU core, use `quota_us = 50_000, period_us = 100_000`.
    pub fn with_cpu_quota(mut self, quota_us: u64, period_us: u64) -> Self {
        self.cpu = Some(CpuLimit {
            quota_us,
            period_us,
        });
        self
    }

    /// Sets the maximum number of processes (`pids.max`).
    pub fn with_pid_max(mut self, max: u64) -> Self {
        self.pids.max = Some(max);
        self
    }

    /// Returns the container ID.
    pub fn container_id(&self) -> &str {
        &self.container_id
    }

    /// Returns the full filesystem path to this container's cgroup directory.
    pub fn cgroup_path(&self) -> &std::path::Path {
        &self.cgroup_path
    }

    /// Returns the configured memory limits.
    pub fn memory_limit(&self) -> &MemoryLimit {
        &self.memory
    }

    /// Returns the configured CPU limit, if any.
    pub fn cpu_limit(&self) -> Option<&CpuLimit> {
        self.cpu.as_ref()
    }

    /// Returns the configured PID limit.
    pub fn pid_limit(&self) -> &PidLimit {
        &self.pids
    }
}

// --- Formatting helpers (used on Linux and in tests) ---

/// Formats the value to write to `memory.max` or `memory.high`.
///
/// Returns the byte count as a decimal string, or `"max"` if `None` (unlimited).
#[cfg(any(target_os = "linux", test))]
fn format_memory_value(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => b.to_string(),
        None => "max".to_string(),
    }
}

/// Formats the value to write to `cpu.max`.
///
/// Returns `"{quota} {period}"`, e.g. `"50000 100000"`.
#[cfg(any(target_os = "linux", test))]
fn format_cpu_max(cpu: &CpuLimit) -> String {
    format!("{} {}", cpu.quota_us, cpu.period_us)
}

/// Formats the value to write to `pids.max`.
///
/// Returns the count as a decimal string, or `"max"` if `None` (unlimited).
#[cfg(any(target_os = "linux", test))]
fn format_pid_max(limit: Option<u64>) -> String {
    match limit {
        Some(n) => n.to_string(),
        None => "max".to_string(),
    }
}

// --- Linux-only implementation ---

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tracing::{info, instrument, warn};

    /// Verifies that `/sys/fs/cgroup` is mounted as a cgroup2 filesystem.
    ///
    /// Reads `/proc/mounts` and checks for a `cgroup2` entry at the expected
    /// mount point. Returns an error if cgroups v2 is not available.
    #[instrument(name = "cgroup.verify_v2")]
    pub fn verify_cgroup_v2() -> Result<()> {
        let mounts = fs::read_to_string("/proc/mounts")
            .map_err(|e| ContainerError::Cgroup(format!("failed to read /proc/mounts: {e}")))?;

        let has_cgroup2 = mounts.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 3 && parts[1] == CGROUP_ROOT && parts[2] == "cgroup2"
        });

        if !has_cgroup2 {
            return Err(ContainerError::Cgroup(
                "cgroups v2 is not mounted at /sys/fs/cgroup; this runtime requires the unified hierarchy".to_string(),
            ));
        }

        info!("cgroups v2 verified at {}", CGROUP_ROOT);
        Ok(())
    }

    impl CgroupManager {
        /// Creates the cgroup directory and writes all configured resource limits.
        ///
        /// This verifies cgroups v2 availability, creates the cgroup directory under
        /// `/sys/fs/cgroup/crate/{container_id}`, and writes each configured limit
        /// to its corresponding control file.
        #[instrument(
            name = "cgroup.apply",
            skip(self),
            fields(container_id = %self.container_id, path = %self.cgroup_path.display())
        )]
        pub fn apply(&self) -> Result<()> {
            verify_cgroup_v2()?;

            // Ensure the runtime prefix directory exists.
            let parent = self
                .cgroup_path
                .parent()
                .ok_or_else(|| ContainerError::Cgroup("invalid cgroup path".to_string()))?;
            fs::create_dir_all(parent).map_err(|e| {
                ContainerError::Cgroup(format!(
                    "failed to create runtime cgroup prefix {}: {e}",
                    parent.display()
                ))
            })?;

            // Create the container's cgroup directory.
            fs::create_dir_all(&self.cgroup_path).map_err(|e| {
                ContainerError::Cgroup(format!(
                    "failed to create cgroup directory {}: {e}",
                    self.cgroup_path.display()
                ))
            })?;
            info!("created cgroup directory");

            // Write memory limits.
            if let Some(max) = self.memory.max_bytes {
                write_control_file(
                    &self.cgroup_path,
                    "memory.max",
                    &format_memory_value(Some(max)),
                )?;
            }
            if let Some(high) = self.memory.high_bytes {
                write_control_file(
                    &self.cgroup_path,
                    "memory.high",
                    &format_memory_value(Some(high)),
                )?;
            }

            // Write CPU limits.
            if let Some(ref cpu) = self.cpu {
                write_control_file(&self.cgroup_path, "cpu.max", &format_cpu_max(cpu))?;
            }

            // Write PID limits.
            if let Some(max) = self.pids.max {
                write_control_file(&self.cgroup_path, "pids.max", &format_pid_max(Some(max)))?;
            }

            info!("applied cgroup resource limits");
            Ok(())
        }

        /// Adds a process to this cgroup by writing its PID to `cgroup.procs`.
        ///
        /// The cgroup must have been created via [`apply`](CgroupManager::apply) first.
        #[instrument(
            name = "cgroup.add_process",
            skip(self),
            fields(container_id = %self.container_id, pid = pid)
        )]
        pub fn add_process(&self, pid: u32) -> Result<()> {
            write_control_file(&self.cgroup_path, "cgroup.procs", &pid.to_string())?;
            info!("added process to cgroup");
            Ok(())
        }

        /// Removes the cgroup directory, cleaning up on container teardown.
        ///
        /// The cgroup must be empty (no processes) before it can be removed.
        /// If the directory does not exist, this is a no-op.
        #[instrument(
            name = "cgroup.cleanup",
            skip(self),
            fields(container_id = %self.container_id, path = %self.cgroup_path.display())
        )]
        pub fn cleanup(&self) -> Result<()> {
            if !self.cgroup_path.exists() {
                warn!("cgroup directory does not exist, skipping cleanup");
                return Ok(());
            }

            fs::remove_dir(&self.cgroup_path).map_err(|e| {
                ContainerError::Cgroup(format!(
                    "failed to remove cgroup directory {} (are all processes terminated?): {e}",
                    self.cgroup_path.display()
                ))
            })?;

            info!("removed cgroup directory");
            Ok(())
        }
    }

    /// Writes a value to a cgroup control file.
    ///
    /// The file is located at `{cgroup_dir}/{filename}`.
    #[instrument(
        name = "cgroup.write_control_file",
        fields(file = %Path::new(cgroup_dir.as_ref()).join(filename).display())
    )]
    fn write_control_file(
        cgroup_dir: impl AsRef<Path> + std::fmt::Debug,
        filename: &str,
        value: &str,
    ) -> Result<()> {
        let path = cgroup_dir.as_ref().join(filename);
        fs::write(&path, value).map_err(|e| {
            ContainerError::Cgroup(format!(
                "failed to write '{}' to {}: {e}",
                value,
                path.display()
            ))
        })?;
        info!(value = value, "wrote control file");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::verify_cgroup_v2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let mgr = CgroupManager::new("test-container");
        assert_eq!(mgr.container_id(), "test-container");
        assert!(mgr.memory_limit().max_bytes.is_none());
        assert!(mgr.memory_limit().high_bytes.is_none());
        assert!(mgr.cpu_limit().is_none());
        assert!(mgr.pid_limit().max.is_none());
    }

    #[test]
    fn test_builder_with_all_limits() {
        let mgr = CgroupManager::new("abc123")
            .with_memory_max(512 * 1024 * 1024)
            .with_memory_high(400 * 1024 * 1024)
            .with_cpu_quota(25_000, 100_000)
            .with_pid_max(64);

        assert_eq!(mgr.memory_limit().max_bytes, Some(512 * 1024 * 1024));
        assert_eq!(mgr.memory_limit().high_bytes, Some(400 * 1024 * 1024));

        let cpu = mgr.cpu_limit().unwrap();
        assert_eq!(cpu.quota_us, 25_000);
        assert_eq!(cpu.period_us, 100_000);

        assert_eq!(mgr.pid_limit().max, Some(64));
    }

    #[test]
    fn test_builder_chaining_overwrites() {
        let mgr = CgroupManager::new("c1")
            .with_memory_max(100)
            .with_memory_max(200);
        assert_eq!(mgr.memory_limit().max_bytes, Some(200));
    }

    #[test]
    fn test_cgroup_path_construction() {
        let mgr = CgroupManager::new("my-container");
        let expected = std::path::PathBuf::from("/sys/fs/cgroup/crate/my-container");
        assert_eq!(mgr.cgroup_path(), expected.as_path());
    }

    #[test]
    fn test_cgroup_path_with_complex_id() {
        let mgr = CgroupManager::new("abc-123-def-456");
        assert!(mgr.cgroup_path().ends_with("crate/abc-123-def-456"));
        assert!(mgr.cgroup_path().starts_with("/sys/fs/cgroup"));
    }

    #[test]
    fn test_format_memory_value_some() {
        assert_eq!(format_memory_value(Some(1024)), "1024");
        assert_eq!(format_memory_value(Some(0)), "0");
        assert_eq!(format_memory_value(Some(256 * 1024 * 1024)), "268435456");
    }

    #[test]
    fn test_format_memory_value_none() {
        assert_eq!(format_memory_value(None), "max");
    }

    #[test]
    fn test_format_cpu_max() {
        let cpu = CpuLimit {
            quota_us: 50_000,
            period_us: 100_000,
        };
        assert_eq!(format_cpu_max(&cpu), "50000 100000");
    }

    #[test]
    fn test_format_cpu_max_full_core() {
        let cpu = CpuLimit {
            quota_us: 100_000,
            period_us: 100_000,
        };
        assert_eq!(format_cpu_max(&cpu), "100000 100000");
    }

    #[test]
    fn test_format_pid_max_some() {
        assert_eq!(format_pid_max(Some(128)), "128");
        assert_eq!(format_pid_max(Some(1)), "1");
    }

    #[test]
    fn test_format_pid_max_none() {
        assert_eq!(format_pid_max(None), "max");
    }

    #[test]
    fn test_cpu_limit_default() {
        let cpu = CpuLimit::default();
        assert_eq!(cpu.quota_us, 100_000);
        assert_eq!(cpu.period_us, 100_000);
    }

    #[test]
    fn test_memory_limit_default() {
        let mem = MemoryLimit::default();
        assert!(mem.max_bytes.is_none());
        assert!(mem.high_bytes.is_none());
    }

    #[test]
    fn test_pid_limit_default() {
        let pid = PidLimit::default();
        assert!(pid.max.is_none());
    }
}
