# crate-runtime

A minimal OCI-compatible container runtime written in Rust.

## Features

- **Namespace isolation** -- PID, mount, UTS, IPC, and network namespaces via `clone()`
- **Cgroups v2** -- Memory, CPU, and PID limits via the unified hierarchy
- **OverlayFS** -- Layered filesystem with read-only and read-write modes
- **OCI image pulling** -- Docker Hub registry v2 API with SHA256 verification
- **OCI lifecycle** -- Full state machine (create/start/stop/delete) with on-disk persistence
- **Bridge networking** -- veth pairs, IP allocation, NAT via iptables
- **Security hardening** -- Capability dropping (Docker-default set), seccomp BPF filtering, path validation
- **Configuration** -- TOML config file with defaults for all settings

## Building

```sh
cargo build --release
```

The binary is built as `target/release/crate`.

## Usage

```sh
# Run a command in a new container
sudo crate run /bin/sh

# Run with a specific rootfs and hostname
sudo crate run -r /path/to/rootfs -H myhost /bin/sh

# Pull an image from Docker Hub
sudo crate pull alpine:latest

# OCI lifecycle commands
sudo crate create mycontainer --bundle /path/to/bundle
sudo crate start mycontainer
sudo crate state mycontainer
sudo crate stop mycontainer
sudo crate delete mycontainer
sudo crate list
```

Cgroup, networking, and security policies are exposed as library APIs
(`crate_runtime::cgroup`, `::network`, `::security`) and via the OCI
`config.json` for `create` / `start`; the `run` subcommand is intentionally
minimal. See the module docs for usage.

## Architecture

```
src/
  main.rs           -- CLI entry point (clap)
  lib.rs            -- Crate root, module declarations
  error.rs          -- Error types (thiserror)
  config/           -- TOML configuration
  container/
    builder.rs      -- ContainerBuilder with validation
    process.rs      -- clone(), namespace init, exec
  namespace/
    mount.rs        -- Mount namespace, pivot_root, /proc, /dev
    pid.rs          -- PID namespace
    uts.rs          -- UTS namespace (hostname)
  cgroup/           -- Cgroups v2 (memory, CPU, PID)
  filesystem/       -- OverlayFS mount management
  image/            -- OCI registry client, content-addressable store
  network/          -- Bridge networking, veth, IP allocation
  runtime/          -- OCI lifecycle state machine
  security/         -- Capabilities, seccomp, path validation
  util/             -- Architecture detection, helpers
```

## Security model

Containers run with reduced privileges:

- **Capabilities**: All capabilities are dropped except a minimal set matching Docker's defaults (14 capabilities including CAP_NET_BIND_SERVICE, CAP_CHOWN, CAP_SETUID, etc.)
- **Seccomp**: A BPF filter blocks dangerous syscalls (reboot, kexec_load, ptrace, bpf, mount outside namespace, kernel module operations, etc.)
- **Filesystem**: OverlayFS provides copy-on-write isolation. Read-only rootfs mode is supported.
- **Namespaces**: PID, mount, UTS, IPC, and network namespaces provide process and resource isolation.
- **Cgroups**: Resource limits prevent containers from consuming unbounded host resources.

## Comparison to runc/crun

crate-runtime is an educational/minimal implementation. Key differences from production runtimes:

| Feature | crate-runtime | runc | crun |
|---------|--------------|------|------|
| Language | Rust | Go | C |
| OCI compliance | Partial | Full | Full |
| User namespaces | Not yet | Yes | Yes |
| Rootless containers | Not yet | Yes | Yes |
| Checkpoint/restore | No | Yes (CRIU) | Yes (CRIU) |
| Binary size | ~5 MB | ~10 MB | ~100 KB |

## Testing

```sh
# Unit tests (no privileges needed)
cargo test --lib

# All tests including integration
make test

# Integration tests (requires Linux + root)
make test-integration

# Lint
make lint
```

## License

MIT
