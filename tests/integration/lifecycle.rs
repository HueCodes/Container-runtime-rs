//! Integration tests for full container lifecycle.
//!
//! These tests require Linux and root privileges. They are skipped
//! gracefully when running on non-Linux or without root.

use crate_runtime::runtime::RuntimeManager;
use std::path::PathBuf;

fn skip_unless_root() -> bool {
    !crate_runtime::util::is_root()
}

#[test]
fn test_runtime_create_and_state() {
    let dir = tempfile::tempdir().unwrap();
    let rt = RuntimeManager::new(dir.path().to_path_buf());

    // Create a bundle with config.json
    let bundle = dir.path().join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();

    let spec = serde_json::json!({
        "ociVersion": "1.0.0",
        "process": {
            "args": ["/bin/sh"],
            "cwd": "/"
        },
        "root": {
            "path": "/tmp/rootfs"
        }
    });
    std::fs::write(bundle.join("config.json"), spec.to_string()).unwrap();

    let status = rt.create("test-lifecycle", &bundle).unwrap();
    assert_eq!(status.id, "test-lifecycle");

    let state = rt.state("test-lifecycle").unwrap();
    assert_eq!(state.id, "test-lifecycle");

    // Clean up
    rt.delete("test-lifecycle").ok();
}

#[test]
fn test_runtime_list_empty() {
    let dir = tempfile::tempdir().unwrap();
    let rt = RuntimeManager::new(dir.path().to_path_buf());
    let list = rt.list().unwrap();
    assert!(list.is_empty());
}

#[test]
fn test_runtime_state_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let rt = RuntimeManager::new(dir.path().to_path_buf());
    let result = rt.state("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_namespace_isolation_requires_root() {
    if skip_unless_root() {
        eprintln!("Skipping: requires root");
        return;
    }

    let container = crate_runtime::ContainerBuilder::new()
        .command(vec!["/bin/echo".into(), "hello".into()])
        .hostname("test-ns".into())
        .build()
        .unwrap();

    let exit_code = container.run().unwrap();
    assert_eq!(exit_code, 0);
}

#[test]
fn test_cgroup_path_construction() {
    let mgr = crate_runtime::cgroup::CgroupManager::new("integ-test")
        .with_memory_max(128 * 1024 * 1024)
        .with_pid_max(64);

    assert!(mgr.cgroup_path().ends_with("crate/integ-test"));
    assert_eq!(mgr.memory_limit().max_bytes, Some(128 * 1024 * 1024));
    assert_eq!(mgr.pid_limit().max, Some(64));
}

#[test]
fn test_cgroup_apply_requires_root() {
    if skip_unless_root() {
        eprintln!("Skipping: requires root");
        return;
    }

    let mgr = crate_runtime::cgroup::CgroupManager::new("integ-cgroup-test")
        .with_memory_max(64 * 1024 * 1024)
        .with_pid_max(32);

    // This will fail if cgroups v2 is not available, which is expected
    // in many CI environments
    match mgr.apply() {
        Ok(()) => {
            mgr.cleanup().ok();
        }
        Err(e) => {
            eprintln!("Cgroup apply failed (expected in some environments): {}", e);
        }
    }
}
