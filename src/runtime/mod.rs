//! OCI runtime lifecycle implementation.
//!
//! Implements the OCI runtime specification state machine and container
//! lifecycle operations: create, start, stop, delete, state, and list.
//! Container state is persisted as JSON under the runtime root directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument, warn};

use crate::error::{ContainerError, Result};

/// OCI container lifecycle states.
///
/// The state machine follows: Creating -> Created -> Running -> Stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerState {
    /// The container is being set up.
    Creating,
    /// The container has been created but its user process has not started.
    Created,
    /// The container's user process is running.
    Running,
    /// The container's user process has exited.
    Stopped,
}

impl std::fmt::Display for ContainerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerState::Creating => write!(f, "creating"),
            ContainerState::Created => write!(f, "created"),
            ContainerState::Running => write!(f, "running"),
            ContainerState::Stopped => write!(f, "stopped"),
        }
    }
}

impl ContainerState {
    /// Returns true if transitioning from `self` to `next` is valid per OCI spec.
    pub fn can_transition_to(&self, next: &ContainerState) -> bool {
        matches!(
            (self, next),
            (ContainerState::Creating, ContainerState::Created)
                | (ContainerState::Created, ContainerState::Running)
                | (ContainerState::Running, ContainerState::Stopped)
        )
    }
}

/// Persistent status record for a managed container.
///
/// Serialized to disk as JSON so that the runtime can recover container
/// state across restarts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerStatus {
    /// Unique container identifier.
    pub id: String,
    /// Current lifecycle state.
    pub state: ContainerState,
    /// PID of the container init process, if running.
    pub pid: Option<u32>,
    /// Absolute path to the OCI bundle directory.
    pub bundle: PathBuf,
    /// RFC 3339 timestamp of when the container was created.
    pub created: String,
    /// Arbitrary annotations from the OCI config.
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

/// Manages OCI container lifecycles with on-disk state persistence.
///
/// State files are stored under `{root}/containers/{id}/state.json`.
pub struct RuntimeManager {
    root: PathBuf,
}

impl RuntimeManager {
    /// Create a new `RuntimeManager` rooted at the given path (e.g. `/run/crate`).
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Returns the directory used to store state for a given container id.
    fn container_dir(&self, id: &str) -> PathBuf {
        self.root.join("containers").join(id)
    }

    /// Returns the path to the state file for a given container id.
    fn state_path(&self, id: &str) -> PathBuf {
        self.container_dir(id).join("state.json")
    }

    /// Persist a `ContainerStatus` to disk.
    fn save_status(&self, status: &ContainerStatus) -> Result<()> {
        let dir = self.container_dir(&status.id);
        std::fs::create_dir_all(&dir)?;
        let json = serde_json::to_string_pretty(status)?;
        std::fs::write(self.state_path(&status.id), json)?;
        debug!(id = %status.id, state = %status.state, "persisted container state");
        Ok(())
    }

    /// Load a `ContainerStatus` from disk.
    fn load_status(&self, id: &str) -> Result<ContainerStatus> {
        let path = self.state_path(id);
        if !path.exists() {
            return Err(ContainerError::NotFound(id.to_string()));
        }
        let data = std::fs::read_to_string(&path)?;
        let status: ContainerStatus = serde_json::from_str(&data)?;
        Ok(status)
    }

    /// Transition a container to a new state, validating the transition.
    fn transition(&self, status: &mut ContainerStatus, to: ContainerState) -> Result<()> {
        if !status.state.can_transition_to(&to) {
            return Err(ContainerError::InvalidStateTransition {
                from: status.state.to_string(),
                to: to.to_string(),
            });
        }
        info!(
            id = %status.id,
            from = %status.state,
            to = %to,
            "state transition"
        );
        status.state = to;
        self.save_status(status)?;
        Ok(())
    }

    /// Create a new container from an OCI bundle.
    ///
    /// Loads `config.json` from `bundle_path`, validates it, and persists an
    /// initial state of `Created`. Runs prestart hooks if present.
    #[instrument(skip(self), fields(container_id = %id))]
    pub fn create(&self, id: &str, bundle_path: &Path) -> Result<ContainerStatus> {
        if self.state_path(id).exists() {
            return Err(ContainerError::Runtime(format!(
                "container '{}' already exists",
                id
            )));
        }

        let spec = load_oci_spec(bundle_path)?;

        let annotations = spec.annotations().clone().unwrap_or_default();

        let now = now_rfc3339();

        let mut status = ContainerStatus {
            id: id.to_string(),
            state: ContainerState::Creating,
            pid: None,
            bundle: bundle_path.to_path_buf(),
            created: now,
            annotations,
        };

        self.save_status(&status)?;

        // Run prestart hooks if configured.
        #[allow(deprecated)]
        if let Some(hooks) = spec.hooks().as_ref() {
            if let Some(prestart) = hooks.prestart().as_ref() {
                info!(id = %id, count = prestart.len(), "running prestart hooks");
                run_hooks(prestart, &status)?;
            }
        }

        self.transition(&mut status, ContainerState::Created)?;

        info!(id = %id, "container created");
        Ok(status)
    }

    /// Start a created container.
    ///
    /// Transitions state from `Created` to `Running`. On Linux, builds a
    /// `ContainerConfig` from the bundle's OCI spec, clones into new
    /// namespaces, and records the child's real PID. The child execs the
    /// user's command and never returns; this method returns to its caller
    /// as soon as the child exists.
    ///
    /// On non-Linux platforms (where `clone(CLONE_NEW*)` is unavailable),
    /// only the state-machine transition runs; the recorded PID is the
    /// runtime's own PID as a placeholder. Tests that exercise the lifecycle
    /// on macOS rely on this path.
    ///
    /// Runs poststart hooks if present.
    #[instrument(skip(self), fields(container_id = %id))]
    pub fn start(&self, id: &str) -> Result<()> {
        let mut status = self.load_status(id)?;

        let spec = load_oci_spec(&status.bundle)?;

        self.transition(&mut status, ContainerState::Running)?;

        #[cfg(target_os = "linux")]
        {
            let (config, rootfs) = container_config_from_spec(id, &status.bundle, &spec)?;
            let pid = crate::container::spawn_container_process(config, rootfs)?;
            status.pid = Some(pid.as_raw() as u32);
        }

        #[cfg(not(target_os = "linux"))]
        {
            // No real fork/exec available; record runtime PID as placeholder.
            status.pid = Some(std::process::id());
        }

        self.save_status(&status)?;

        // Run poststart hooks.
        if let Some(hooks) = spec.hooks().as_ref() {
            if let Some(poststart) = hooks.poststart().as_ref() {
                info!(id = %id, count = poststart.len(), "running poststart hooks");
                if let Err(e) = run_hooks(poststart, &status) {
                    // OCI spec: poststart hook failures are logged but do not
                    // stop the container.
                    warn!(id = %id, error = %e, "poststart hook failed (non-fatal)");
                }
            }
        }

        info!(id = %id, "container started");
        Ok(())
    }

    /// Stop a running container.
    ///
    /// On Linux, sends `signal` to the container init process and waits up to
    /// `timeout` for it to exit before forcibly killing it. On non-Linux
    /// platforms, simply transitions state to `Stopped`.
    #[instrument(skip(self), fields(container_id = %id))]
    pub fn stop(&self, id: &str, signal: Option<i32>, timeout: Option<Duration>) -> Result<()> {
        let mut status = self.load_status(id)?;

        #[cfg(target_os = "linux")]
        {
            if let Some(pid) = status.pid {
                let sig = signal.unwrap_or(libc::SIGTERM);
                let timeout = timeout.unwrap_or(Duration::from_secs(10));
                linux_stop_process(pid, sig, timeout)?;
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (signal, timeout);
            debug!(id = %id, "non-linux: skipping signal delivery");
        }

        self.transition(&mut status, ContainerState::Stopped)?;
        status.pid = None;
        self.save_status(&status)?;

        // Run poststop hooks.
        let spec = load_oci_spec(&status.bundle)?;
        if let Some(hooks) = spec.hooks().as_ref() {
            if let Some(poststop) = hooks.poststop().as_ref() {
                info!(id = %id, count = poststop.len(), "running poststop hooks");
                if let Err(e) = run_hooks(poststop, &status) {
                    warn!(id = %id, error = %e, "poststop hook failed (non-fatal)");
                }
            }
        }

        info!(id = %id, "container stopped");
        Ok(())
    }

    /// Delete a stopped container.
    ///
    /// Removes the on-disk state directory. The container must be in the
    /// `Stopped` state.
    #[instrument(skip(self), fields(container_id = %id))]
    pub fn delete(&self, id: &str) -> Result<()> {
        let status = self.load_status(id)?;

        if status.state != ContainerState::Stopped {
            return Err(ContainerError::Runtime(format!(
                "cannot delete container '{}' in state '{}'; must be stopped",
                id, status.state
            )));
        }

        let dir = self.container_dir(id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }

        info!(id = %id, "container deleted");
        Ok(())
    }

    /// Query the current status of a container.
    #[instrument(skip(self), fields(container_id = %id))]
    pub fn state(&self, id: &str) -> Result<ContainerStatus> {
        let status = self.load_status(id)?;
        debug!(id = %id, state = %status.state, "queried container state");
        Ok(status)
    }

    /// List all known containers.
    #[instrument(skip(self))]
    pub fn list(&self) -> Result<Vec<ContainerStatus>> {
        let containers_dir = self.root.join("containers");
        if !containers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        for entry in std::fs::read_dir(&containers_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                match self.load_status(&id) {
                    Ok(status) => result.push(status),
                    Err(e) => {
                        warn!(id = %id, error = %e, "skipping container with unreadable state");
                    }
                }
            }
        }

        debug!(count = result.len(), "listed containers");
        Ok(result)
    }
}

/// Translate an OCI `Spec` into the `ContainerConfig` consumed by
/// `spawn_container_process`, plus the absolute rootfs path.
///
/// The OCI spec's `root.path` is interpreted relative to the bundle
/// directory unless it is already absolute (per the runtime spec).
#[cfg(target_os = "linux")]
fn container_config_from_spec(
    id: &str,
    bundle: &Path,
    spec: &oci_spec::runtime::Spec,
) -> Result<(crate::container::ContainerConfig, PathBuf)> {
    let process = spec.process().as_ref().ok_or_else(|| {
        ContainerError::Runtime("OCI spec is missing the 'process' section".into())
    })?;

    let command = process
        .args()
        .as_ref()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| ContainerError::Runtime("OCI process.args is empty".into()))?
        .clone();

    let env: Vec<(String, String)> = process
        .env()
        .as_ref()
        .map(|vars| {
            vars.iter()
                .filter_map(|v| {
                    v.split_once('=')
                        .map(|(k, val)| (k.to_string(), val.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    let hostname = spec.hostname().as_deref().unwrap_or(id).to_string();

    let root = spec
        .root()
        .as_ref()
        .ok_or_else(|| ContainerError::Runtime("OCI spec is missing the 'root' section".into()))?;

    let rootfs = if root.path().is_absolute() {
        root.path().clone()
    } else {
        bundle.join(root.path())
    };

    let config = crate::container::ContainerConfig {
        id: id.to_string(),
        hostname,
        command,
        rootfs: Some(rootfs.clone()),
        env,
    };

    Ok((config, rootfs))
}

/// Load and parse an OCI `config.json` from a bundle directory.
pub fn load_oci_spec(bundle: &Path) -> Result<oci_spec::runtime::Spec> {
    let config_path = bundle.join("config.json");
    if !config_path.exists() {
        return Err(ContainerError::Runtime(format!(
            "config.json not found in bundle: {}",
            bundle.display()
        )));
    }
    let spec = oci_spec::runtime::Spec::load(&config_path)
        .map_err(|e| ContainerError::Runtime(format!("failed to parse config.json: {}", e)))?;
    debug!(bundle = %bundle.display(), "loaded OCI spec");
    Ok(spec)
}

/// Execute a list of OCI hooks as child processes.
///
/// Each hook's `path` is executed with optional `args` and `env`. The
/// container state JSON is provided on stdin. If a hook specifies a
/// `timeout`, the child is killed after that duration.
pub fn run_hooks(hooks: &[oci_spec::runtime::Hook], state: &ContainerStatus) -> Result<()> {
    let state_json = serde_json::to_string(state)?;

    for hook in hooks {
        let path = hook.path();
        debug!(hook = %path.display(), "executing hook");

        let mut cmd = std::process::Command::new(path);

        if let Some(args) = hook.args() {
            // args[0] is typically the binary name; skip it since Command
            // already sets argv[0] from the program path.
            if args.len() > 1 {
                cmd.args(&args[1..]);
            }
        }

        if let Some(env_vars) = hook.env() {
            for var in env_vars {
                if let Some((key, value)) = var.split_once('=') {
                    cmd.env(key, value);
                }
            }
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            ContainerError::Runtime(format!("failed to spawn hook '{}': {}", path.display(), e))
        })?;

        // Write container state to the hook's stdin.
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(state_json.as_bytes());
        }

        let timeout = hook.timeout().map(|t| Duration::from_secs(t.max(0) as u64));

        if let Some(dur) = timeout {
            // Poll with timeout.
            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(exit)) => {
                        if !exit.success() {
                            return Err(ContainerError::Runtime(format!(
                                "hook '{}' exited with status: {}",
                                path.display(),
                                exit
                            )));
                        }
                        break;
                    }
                    Ok(None) => {
                        if start.elapsed() > dur {
                            let _ = child.kill();
                            return Err(ContainerError::Runtime(format!(
                                "hook '{}' timed out after {:?}",
                                path.display(),
                                dur
                            )));
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => {
                        return Err(ContainerError::Runtime(format!(
                            "error waiting on hook '{}': {}",
                            path.display(),
                            e
                        )));
                    }
                }
            }
        } else {
            let exit = child.wait().map_err(|e| {
                ContainerError::Runtime(format!(
                    "error waiting on hook '{}': {}",
                    path.display(),
                    e
                ))
            })?;
            if !exit.success() {
                return Err(ContainerError::Runtime(format!(
                    "hook '{}' exited with status: {}",
                    path.display(),
                    exit
                )));
            }
        }

        debug!(hook = %path.display(), "hook completed successfully");
    }

    Ok(())
}

/// Send a signal to a process and wait for it to exit, with a timeout.
#[cfg(target_os = "linux")]
fn linux_stop_process(pid: u32, signal: i32, timeout: Duration) -> Result<()> {
    use nix::sys::signal::{self, Signal};
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);

    let sig = Signal::try_from(signal)
        .map_err(|e| ContainerError::Runtime(format!("invalid signal {}: {}", signal, e)))?;

    signal::kill(nix_pid, Some(sig)).map_err(|e| {
        ContainerError::Runtime(format!("failed to send signal to pid {}: {}", pid, e))
    })?;

    let start = std::time::Instant::now();
    loop {
        match nix::sys::wait::waitpid(nix_pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, _))
            | Ok(nix::sys::wait::WaitStatus::Signaled(_, _, _)) => {
                return Ok(());
            }
            Ok(_) => {}
            Err(nix::Error::ECHILD) => {
                // Process already gone.
                return Ok(());
            }
            Err(e) => {
                return Err(ContainerError::Runtime(format!(
                    "waitpid error for pid {}: {}",
                    pid, e
                )));
            }
        }

        if start.elapsed() > timeout {
            // Force kill.
            let _ = signal::kill(nix_pid, Some(Signal::SIGKILL));
            warn!(pid = pid, "forcibly killed container process after timeout");
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Returns the current UTC time as an RFC 3339 timestamp.
///
/// Implemented manually so the runtime does not pull in `chrono` for one
/// timestamp string. See `days_to_ymd` for the date conversion algorithm.
fn now_rfc3339() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Convert to a basic UTC timestamp.
    let days = secs / 86400;
    let day_secs = secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Compute year/month/day from days since epoch (1970-01-01).
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's chrono-compatible date library.
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Minimal OCI config.json for testing.
    fn mock_config_json() -> &'static str {
        r#"{
            "ociVersion": "1.0.2",
            "process": {
                "terminal": false,
                "user": { "uid": 0, "gid": 0 },
                "args": ["/bin/sh"],
                "cwd": "/"
            },
            "root": {
                "path": "rootfs",
                "readonly": true
            }
        }"#
    }

    /// Create a temporary bundle directory with a config.json.
    fn setup_bundle(dir: &Path) {
        fs::create_dir_all(dir.join("rootfs")).unwrap();
        fs::write(dir.join("config.json"), mock_config_json()).unwrap();
    }

    // -- State transition tests --

    #[test]
    fn test_valid_transitions() {
        assert!(ContainerState::Creating.can_transition_to(&ContainerState::Created));
        assert!(ContainerState::Created.can_transition_to(&ContainerState::Running));
        assert!(ContainerState::Running.can_transition_to(&ContainerState::Stopped));
    }

    #[test]
    fn test_invalid_transitions() {
        assert!(!ContainerState::Creating.can_transition_to(&ContainerState::Running));
        assert!(!ContainerState::Creating.can_transition_to(&ContainerState::Stopped));
        assert!(!ContainerState::Created.can_transition_to(&ContainerState::Stopped));
        assert!(!ContainerState::Created.can_transition_to(&ContainerState::Creating));
        assert!(!ContainerState::Running.can_transition_to(&ContainerState::Created));
        assert!(!ContainerState::Stopped.can_transition_to(&ContainerState::Running));
        assert!(!ContainerState::Stopped.can_transition_to(&ContainerState::Creating));
    }

    #[test]
    fn test_state_display() {
        assert_eq!(ContainerState::Creating.to_string(), "creating");
        assert_eq!(ContainerState::Created.to_string(), "created");
        assert_eq!(ContainerState::Running.to_string(), "running");
        assert_eq!(ContainerState::Stopped.to_string(), "stopped");
    }

    // -- Serialization tests --

    #[test]
    fn test_container_status_serialization_roundtrip() {
        let mut annotations = HashMap::new();
        annotations.insert("org.example.key".to_string(), "value".to_string());

        let status = ContainerStatus {
            id: "test-container-1".to_string(),
            state: ContainerState::Running,
            pid: Some(12345),
            bundle: PathBuf::from("/var/lib/containers/test"),
            created: "2026-04-11T12:00:00Z".to_string(),
            annotations,
        };

        let json = serde_json::to_string_pretty(&status).unwrap();
        let deserialized: ContainerStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, "test-container-1");
        assert_eq!(deserialized.state, ContainerState::Running);
        assert_eq!(deserialized.pid, Some(12345));
        assert_eq!(
            deserialized.bundle,
            PathBuf::from("/var/lib/containers/test")
        );
        assert_eq!(deserialized.created, "2026-04-11T12:00:00Z");
        assert_eq!(
            deserialized.annotations.get("org.example.key"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_container_status_deserialize_without_annotations() {
        let json = r#"{
            "id": "minimal",
            "state": "stopped",
            "pid": null,
            "bundle": "/tmp/bundle",
            "created": "2026-01-01T00:00:00Z"
        }"#;
        let status: ContainerStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.id, "minimal");
        assert_eq!(status.state, ContainerState::Stopped);
        assert!(status.annotations.is_empty());
    }

    #[test]
    fn test_state_enum_serde() {
        let json = serde_json::to_string(&ContainerState::Created).unwrap();
        assert_eq!(json, "\"created\"");
        let parsed: ContainerState = serde_json::from_str("\"running\"").unwrap();
        assert_eq!(parsed, ContainerState::Running);
    }

    // -- OCI spec loading tests --

    #[test]
    fn test_load_oci_spec_valid() {
        let tmp = tempfile::tempdir().unwrap();
        setup_bundle(tmp.path());
        let spec = load_oci_spec(tmp.path()).unwrap();
        assert_eq!(spec.version(), "1.0.2");
    }

    #[test]
    fn test_load_oci_spec_missing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let result = load_oci_spec(tmp.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("config.json not found"));
    }

    #[test]
    fn test_load_oci_spec_invalid_json() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("config.json"), "{ invalid json }").unwrap();
        let result = load_oci_spec(tmp.path());
        assert!(result.is_err());
    }

    // -- Lifecycle integration tests --

    #[test]
    fn test_create_and_state() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("runtime");
        let bundle = tmp.path().join("bundle");
        setup_bundle(&bundle);

        let mgr = RuntimeManager::new(root);
        let status = mgr.create("c1", &bundle).unwrap();
        assert_eq!(status.state, ContainerState::Created);
        assert_eq!(status.id, "c1");

        let queried = mgr.state("c1").unwrap();
        assert_eq!(queried.state, ContainerState::Created);
    }

    #[test]
    fn test_create_duplicate_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("runtime");
        let bundle = tmp.path().join("bundle");
        setup_bundle(&bundle);

        let mgr = RuntimeManager::new(root);
        mgr.create("dup", &bundle).unwrap();
        let result = mgr.create("dup", &bundle);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("runtime");
        let bundle = tmp.path().join("bundle");
        setup_bundle(&bundle);

        let mgr = RuntimeManager::new(root);

        // Create
        mgr.create("lifecycle", &bundle).unwrap();

        // Start
        mgr.start("lifecycle").unwrap();
        let status = mgr.state("lifecycle").unwrap();
        assert_eq!(status.state, ContainerState::Running);
        assert!(status.pid.is_some());

        // Stop
        mgr.stop("lifecycle", None, None).unwrap();
        let status = mgr.state("lifecycle").unwrap();
        assert_eq!(status.state, ContainerState::Stopped);
        assert!(status.pid.is_none());

        // Delete
        mgr.delete("lifecycle").unwrap();
        let result = mgr.state("lifecycle");
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_non_stopped_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("runtime");
        let bundle = tmp.path().join("bundle");
        setup_bundle(&bundle);

        let mgr = RuntimeManager::new(root);
        mgr.create("running", &bundle).unwrap();
        mgr.start("running").unwrap();

        let result = mgr.delete("running");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be stopped"));
    }

    #[test]
    fn test_invalid_start_transition() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("runtime");
        let bundle = tmp.path().join("bundle");
        setup_bundle(&bundle);

        let mgr = RuntimeManager::new(root);
        mgr.create("c", &bundle).unwrap();
        mgr.start("c").unwrap();

        // Starting an already-running container should fail.
        let result = mgr.start("c");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("running") && err.contains("Invalid state transition"));
    }

    #[test]
    fn test_list_containers() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("runtime");
        let bundle = tmp.path().join("bundle");
        setup_bundle(&bundle);

        let mgr = RuntimeManager::new(root);
        assert_eq!(mgr.list().unwrap().len(), 0);

        mgr.create("a", &bundle).unwrap();
        mgr.create("b", &bundle).unwrap();

        let list = mgr.list().unwrap();
        assert_eq!(list.len(), 2);

        let ids: Vec<&str> = list.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
    }

    #[test]
    fn test_state_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = RuntimeManager::new(tmp.path().to_path_buf());
        let result = mgr.state("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_now_rfc3339_format() {
        let ts = now_rfc3339();
        // Should match YYYY-MM-DDTHH:MM:SSZ pattern.
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn test_state_persistence_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("runtime");
        let bundle = tmp.path().join("bundle");
        setup_bundle(&bundle);

        let mgr = RuntimeManager::new(root.clone());
        mgr.create("persist", &bundle).unwrap();

        // Verify the file exists.
        let state_file = root.join("containers/persist/state.json");
        assert!(state_file.exists());

        // Read it back with a fresh manager to confirm persistence.
        let mgr2 = RuntimeManager::new(root);
        let status = mgr2.state("persist").unwrap();
        assert_eq!(status.id, "persist");
        assert_eq!(status.state, ContainerState::Created);
    }
}
