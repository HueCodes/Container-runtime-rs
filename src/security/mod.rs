//! Security hardening for the container runtime.
//!
//! This module provides capability dropping, seccomp BPF filtering, and
//! path validation to reduce the attack surface of containerized processes.
//!
//! All Linux-specific functionality is gated behind `#[cfg(target_os = "linux")]`.
//! On non-Linux platforms, stub implementations return errors.

use std::path::Path;

use crate::error::{ContainerError, Result};

// ---------------------------------------------------------------------------
// Capability management
// ---------------------------------------------------------------------------

/// The default set of Linux capabilities retained in the container.
///
/// This mirrors Docker's default capability set, providing a minimal but
/// functional set of privileges for most containerized workloads.
#[cfg(target_os = "linux")]
pub const DEFAULT_CAPABILITIES: &[caps::Capability] = &[
    caps::Capability::CAP_CHOWN,
    caps::Capability::CAP_DAC_OVERRIDE,
    caps::Capability::CAP_FSETID,
    caps::Capability::CAP_FOWNER,
    caps::Capability::CAP_MKNOD,
    caps::Capability::CAP_NET_RAW,
    caps::Capability::CAP_SETGID,
    caps::Capability::CAP_SETUID,
    caps::Capability::CAP_SETFCAP,
    caps::Capability::CAP_SETPCAP,
    caps::Capability::CAP_NET_BIND_SERVICE,
    caps::Capability::CAP_SYS_CHROOT,
    caps::Capability::CAP_KILL,
    caps::Capability::CAP_AUDIT_WRITE,
];

/// Apply a restricted capability set to the current process.
///
/// Retains only [`DEFAULT_CAPABILITIES`] plus any capabilities listed in
/// `additional_caps`. All other capabilities are dropped from the effective,
/// permitted, and inheritable sets.
///
/// This should be called after `fork()` but before `exec()`.
///
/// # Errors
///
/// Returns [`ContainerError::Security`] if capability manipulation fails.
#[cfg(target_os = "linux")]
pub fn apply_capabilities(additional_caps: &[caps::Capability]) -> Result<()> {
    use std::collections::HashSet;

    let allowed: HashSet<caps::Capability> = DEFAULT_CAPABILITIES
        .iter()
        .chain(additional_caps.iter())
        .copied()
        .collect();

    tracing::info!(
        additional = additional_caps.len(),
        total = allowed.len(),
        "applying capability restrictions"
    );

    // Iterate over all known capabilities and drop those not in the allowed set.
    for cap_value in 0..=caps::Capability::CAP_LAST_CAP as u32 {
        let cap = match caps::Capability::try_from(cap_value) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if allowed.contains(&cap) {
            continue;
        }

        for set in &[
            caps::CapSet::Effective,
            caps::CapSet::Permitted,
            caps::CapSet::Inheritable,
        ] {
            caps::drop(None, *set, cap).map_err(|e| {
                ContainerError::Security(format!(
                    "failed to drop capability {:?} from {:?}: {}",
                    cap, set, e
                ))
            })?;
        }
    }

    tracing::debug!("capabilities restricted successfully");
    Ok(())
}

/// Drop all capabilities except the Docker-default minimal set.
///
/// Convenience wrapper around [`apply_capabilities`] with no additional caps.
///
/// # Errors
///
/// Returns [`ContainerError::Security`] if capability manipulation fails.
#[cfg(target_os = "linux")]
pub fn drop_capabilities() -> Result<()> {
    apply_capabilities(&[])
}

#[cfg(not(target_os = "linux"))]
pub fn apply_capabilities(_additional_caps: &[&str]) -> Result<()> {
    Err(ContainerError::Security(
        "capability management is only supported on Linux".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn drop_capabilities() -> Result<()> {
    Err(ContainerError::Security(
        "capability management is only supported on Linux".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Seccomp BPF filtering
// ---------------------------------------------------------------------------

/// Syscall numbers (x86_64) for the denied syscalls.
///
/// These are dangerous syscalls that should not be available inside a
/// container under normal circumstances.
#[cfg(target_os = "linux")]
mod syscall_nr {
    // Module / kernel manipulation
    pub const SYS_INIT_MODULE: u32 = libc::SYS_init_module as u32;
    pub const SYS_FINIT_MODULE: u32 = libc::SYS_finit_module as u32;
    pub const SYS_DELETE_MODULE: u32 = libc::SYS_delete_module as u32;

    // Reboot / kexec
    pub const SYS_REBOOT: u32 = libc::SYS_reboot as u32;
    pub const SYS_KEXEC_LOAD: u32 = libc::SYS_kexec_load as u32;
    pub const SYS_KEXEC_FILE_LOAD: u32 = libc::SYS_kexec_file_load as u32;

    // Tracing / debugging
    pub const SYS_PTRACE: u32 = libc::SYS_ptrace as u32;

    // Key management
    pub const SYS_ADD_KEY: u32 = libc::SYS_add_key as u32;
    pub const SYS_REQUEST_KEY: u32 = libc::SYS_request_key as u32;
    pub const SYS_KEYCTL: u32 = libc::SYS_keyctl as u32;

    // Performance / BPF
    pub const SYS_PERF_EVENT_OPEN: u32 = libc::SYS_perf_event_open as u32;
    pub const SYS_BPF: u32 = libc::SYS_bpf as u32;
    pub const SYS_USERFAULTFD: u32 = libc::SYS_userfaultfd as u32;

    // Accounting / time
    pub const SYS_ACCT: u32 = libc::SYS_acct as u32;
    pub const SYS_SETTIMEOFDAY: u32 = libc::SYS_settimeofday as u32;
    pub const SYS_CLOCK_SETTIME: u32 = libc::SYS_clock_settime as u32;

    // Swap
    pub const SYS_SWAPON: u32 = libc::SYS_swapon as u32;
    pub const SYS_SWAPOFF: u32 = libc::SYS_swapoff as u32;

    // Mount (redundant with namespace restriction, but defense in depth)
    pub const SYS_MOUNT: u32 = libc::SYS_mount as u32;
}

/// Apply a seccomp BPF filter that blocks dangerous syscalls.
///
/// The filter operates in a denylist mode: all syscalls are allowed by default
/// except those on the explicit blocklist. Blocked syscalls receive `EPERM`.
///
/// This must be called **after** [`drop_capabilities`] and **before** `exec()`.
///
/// # Errors
///
/// Returns [`ContainerError::Security`] if the filter cannot be installed.
///
/// # Platform
///
/// Only available on Linux. The non-Linux stub returns an error.
#[cfg(target_os = "linux")]
pub fn apply_seccomp_filter() -> Result<()> {
    use std::mem;

    // BPF instruction helpers matching the kernel's sock_filter layout.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    // BPF opcodes used in this filter.
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    // Seccomp return values.
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

    // Offset of `nr` in seccomp_data for x86_64 (native endian).
    // struct seccomp_data { int nr; ... } -- nr is at offset 0.
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;

    // SECCOMP_MODE_FILTER = 2
    const SECCOMP_MODE_FILTER: libc::c_int = 2;

    let denied_syscalls: &[u32] = &[
        syscall_nr::SYS_REBOOT,
        syscall_nr::SYS_KEXEC_LOAD,
        syscall_nr::SYS_KEXEC_FILE_LOAD,
        syscall_nr::SYS_MOUNT,
        syscall_nr::SYS_PTRACE,
        syscall_nr::SYS_ADD_KEY,
        syscall_nr::SYS_REQUEST_KEY,
        syscall_nr::SYS_KEYCTL,
        syscall_nr::SYS_PERF_EVENT_OPEN,
        syscall_nr::SYS_BPF,
        syscall_nr::SYS_USERFAULTFD,
        syscall_nr::SYS_INIT_MODULE,
        syscall_nr::SYS_FINIT_MODULE,
        syscall_nr::SYS_DELETE_MODULE,
        syscall_nr::SYS_ACCT,
        syscall_nr::SYS_SETTIMEOFDAY,
        syscall_nr::SYS_CLOCK_SETTIME,
        syscall_nr::SYS_SWAPON,
        syscall_nr::SYS_SWAPOFF,
    ];

    tracing::info!(
        blocked_syscalls = denied_syscalls.len(),
        "installing seccomp BPF filter"
    );

    // Build the BPF program.
    //
    // Structure:
    //   [0]       LD  ABS  seccomp_data.nr       -- load syscall number
    //   [1..N]    JEQ denied_nr => jump to KILL  -- one instruction per denied syscall
    //   [N+1]     RET ALLOW                      -- allow everything else
    //   [N+2]     RET ERRNO(EPERM)               -- deny target
    let deny_count = denied_syscalls.len();
    let total_insns = 1 + deny_count + 2; // load + jumps + allow + deny

    let mut filter: Vec<SockFilter> = Vec::with_capacity(total_insns);

    // Instruction 0: load syscall number.
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });

    // Instructions 1..=deny_count: conditional jumps.
    // If the syscall matches, jump forward to the DENY return (at the end).
    // The DENY instruction is at index (deny_count + 1), so from instruction i
    // (1-indexed within the jump block), jump-true = (deny_count - i) + 1
    // which simplifies to deny_count - (i - 1).
    for (i, &nr) in denied_syscalls.iter().enumerate() {
        let jt = (deny_count - i) as u8; // jump to deny (skip remaining jumps + allow)
        filter.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt,
            jf: 0,
            k: nr,
        });
    }

    // ALLOW instruction.
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // DENY instruction: return EPERM.
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff),
    });

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS) is a well-defined Linux system call
    // that sets a process attribute. The arguments are constant integers.
    // This must be called before installing a seccomp filter.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(ContainerError::Security(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: prctl(PR_SET_SECCOMP) installs the BPF program pointed to by
    // `prog`. The SockFprog struct and the filter array it references are
    // valid for the duration of this call. The kernel copies the program
    // data, so no lifetime concerns exist after the call returns.
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        )
    };
    if ret != 0 {
        return Err(ContainerError::Security(format!(
            "prctl(PR_SET_SECCOMP) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Prevent the optimizer from dropping `filter` before prctl reads it.
    drop(filter);
    // Suppress unused variable warning; `prog` must live until after prctl.
    let _ = mem::size_of_val(&prog);

    tracing::info!("seccomp BPF filter installed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn apply_seccomp_filter() -> Result<()> {
    Err(ContainerError::Security(
        "seccomp filtering is only supported on Linux".to_string(),
    ))
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Validate a filesystem path for use inside a container.
///
/// Rejects paths that:
/// - Are not absolute (do not start with `/`)
/// - Contain `..` components (directory traversal)
/// - Resolve through symlinks to a location outside the path's parent directory
///
/// # Arguments
///
/// * `path` - The path to validate.
/// * `description` - A human-readable label for the path, used in error messages
///   (e.g. `"rootfs"`, `"bind mount source"`).
///
/// # Errors
///
/// Returns [`ContainerError::Security`] if the path fails validation.
pub fn validate_path(path: &Path, description: &str) -> Result<()> {
    tracing::debug!(
        path = %path.display(),
        description,
        "validating path"
    );

    // Reject non-absolute paths.
    if !path.is_absolute() {
        return Err(ContainerError::Security(format!(
            "{} path must be absolute, got: {}",
            description,
            path.display()
        )));
    }

    // Reject paths containing ".." components.
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(ContainerError::Security(format!(
                "{} path contains directory traversal (..): {}",
                description,
                path.display()
            )));
        }
    }

    // If the path exists, verify that symlink resolution does not escape
    // the expected parent directory.
    if path.exists() {
        let canonical = path.canonicalize().map_err(|e| {
            ContainerError::Security(format!(
                "failed to canonicalize {} path {}: {}",
                description,
                path.display(),
                e
            ))
        })?;

        // The canonical path must still start with the same parent directory
        // as the original path's parent. This catches symlinks that escape
        // the intended directory tree.
        if let Some(parent) = path.parent() {
            if parent.exists() {
                let canonical_parent = parent.canonicalize().map_err(|e| {
                    ContainerError::Security(format!(
                        "failed to canonicalize parent of {} path {}: {}",
                        description,
                        parent.display(),
                        e
                    ))
                })?;

                if !canonical.starts_with(&canonical_parent) {
                    return Err(ContainerError::Security(format!(
                        "{} path {} resolves to {} which escapes its parent directory {}",
                        description,
                        path.display(),
                        canonical.display(),
                        canonical_parent.display()
                    )));
                }
            }
        }
    }

    tracing::debug!(
        path = %path.display(),
        description,
        "path validated successfully"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -- Path validation tests --

    #[test]
    fn validate_path_accepts_absolute_path() {
        // A simple absolute path with no traversal should pass.
        let path = PathBuf::from("/usr/bin/env");
        // This may or may not exist depending on the platform, but the
        // structural checks (absolute, no ..) should pass regardless.
        // We only care that it does not error on the structural checks.
        // If the path doesn't exist, symlink checks are skipped.
        let result = validate_path(&path, "test binary");
        // On systems where /usr/bin/env exists this succeeds; on others
        // it still succeeds because we skip symlink checks for missing paths.
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[test]
    fn validate_path_rejects_relative_path() {
        let path = PathBuf::from("relative/path");
        let result = validate_path(&path, "relative");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("must be absolute"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn validate_path_rejects_traversal() {
        let path = PathBuf::from("/var/lib/../../etc/shadow");
        let result = validate_path(&path, "shadow");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("directory traversal"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn validate_path_rejects_dot_dot_at_start() {
        let path = PathBuf::from("/../etc/passwd");
        let result = validate_path(&path, "passwd");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("directory traversal"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn validate_path_accepts_existing_absolute_path() {
        // Use a path that exists on virtually all unix-like systems.
        let path = PathBuf::from("/tmp");
        let result = validate_path(&path, "tmpdir");
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[test]
    fn validate_path_accepts_nonexistent_absolute_path() {
        let path = PathBuf::from("/nonexistent/path/that/does/not/exist");
        let result = validate_path(&path, "missing");
        assert!(
            result.is_ok(),
            "expected Ok for non-existent path, got: {:?}",
            result
        );
    }

    // -- Capability list tests --

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use std::collections::HashSet;

        #[test]
        fn default_capabilities_contains_expected_set() {
            let caps_set: HashSet<_> = DEFAULT_CAPABILITIES.iter().collect();

            // Verify the count matches Docker's default (14 capabilities).
            assert_eq!(
                DEFAULT_CAPABILITIES.len(),
                14,
                "expected 14 default capabilities"
            );

            // Spot-check a few critical ones.
            assert!(caps_set.contains(&caps::Capability::CAP_NET_BIND_SERVICE));
            assert!(caps_set.contains(&caps::Capability::CAP_CHOWN));
            assert!(caps_set.contains(&caps::Capability::CAP_SETUID));
            assert!(caps_set.contains(&caps::Capability::CAP_SETGID));
            assert!(caps_set.contains(&caps::Capability::CAP_KILL));
        }

        #[test]
        fn default_capabilities_excludes_dangerous_caps() {
            let caps_set: HashSet<_> = DEFAULT_CAPABILITIES.iter().collect();

            // These should never be in the default set.
            assert!(!caps_set.contains(&caps::Capability::CAP_SYS_ADMIN));
            assert!(!caps_set.contains(&caps::Capability::CAP_SYS_PTRACE));
            assert!(!caps_set.contains(&caps::Capability::CAP_SYS_RAWIO));
            assert!(!caps_set.contains(&caps::Capability::CAP_SYS_MODULE));
            assert!(!caps_set.contains(&caps::Capability::CAP_SYS_BOOT));
            assert!(!caps_set.contains(&caps::Capability::CAP_NET_ADMIN));
        }

        #[test]
        fn default_capabilities_has_no_duplicates() {
            let caps_set: HashSet<_> = DEFAULT_CAPABILITIES.iter().collect();
            assert_eq!(
                caps_set.len(),
                DEFAULT_CAPABILITIES.len(),
                "default capabilities list contains duplicates"
            );
        }
    }
}
