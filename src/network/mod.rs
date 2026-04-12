//! Container networking.
//!
//! Provides bridge networking with veth pairs for container isolation.
//! Each container gets a veth pair: one end stays in the host namespace
//! attached to the `crate0` bridge, the other moves into the container's
//! network namespace.
//!
//! IP addresses are allocated from a 172.28.0.0/16 subnet using a simple
//! atomic counter. NAT is configured via iptables for outbound connectivity.
//!
//! Note on CLONE_NEWNET: the actual namespace flag is set in `process.rs`
//! when spawning the container process. This module handles interface and
//! routing setup that happens after the namespace is created.

use std::net::Ipv4Addr;
#[cfg(any(target_os = "linux", test))]
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{ContainerError, Result};

// ---------------------------------------------------------------------------
// IP allocator
// ---------------------------------------------------------------------------

/// Atomic counter for IP allocation within a /16 subnet.
///
/// Starts at 2 (reserving .0 for the network and .1 for the gateway) and
/// increments monotonically. The host part is a 16-bit value packed into the
/// lower two octets of the subnet.
#[cfg(any(target_os = "linux", test))]
static IP_COUNTER: AtomicU32 = AtomicU32::new(2);

/// Reset the IP counter to its initial value (for testing).
#[cfg(test)]
fn reset_ip_counter() {
    IP_COUNTER.store(2, Ordering::SeqCst);
}

/// Allocate the next IP address from the configured subnet.
///
/// Returns an error if the allocatable range is exhausted (> 65534 addresses).
#[cfg(any(target_os = "linux", test))]
fn allocate_ip(config: &NetworkConfig) -> Result<Ipv4Addr> {
    let host = IP_COUNTER.fetch_add(1, Ordering::SeqCst);
    if host > 0xFFFE {
        return Err(ContainerError::Network(
            "IP address pool exhausted".to_string(),
        ));
    }
    let base = u32::from(config.subnet);
    let addr = Ipv4Addr::from(base + host);
    Ok(addr)
}

// ---------------------------------------------------------------------------
// Name helpers
// ---------------------------------------------------------------------------

/// Generate the host-side veth name for a container.
///
/// Uses the first 8 characters of the container ID to stay within the 15-char
/// Linux interface name limit. Format: `veth<id prefix>`.
#[cfg(any(target_os = "linux", test))]
fn veth_host_name(container_id: &str) -> String {
    let short = &container_id[..container_id.len().min(8)];
    format!("veth{short}")
}

/// Generate the container-side veth name. Always `eth0`.
#[cfg(any(target_os = "linux", test))]
fn veth_container_name() -> &'static str {
    "eth0"
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the container bridge network.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Base address of the subnet (e.g. 172.28.0.0).
    pub subnet: Ipv4Addr,
    /// CIDR prefix length (e.g. 16).
    pub prefix_len: u8,
    /// Name of the bridge interface.
    pub bridge_name: String,
    /// Gateway address (assigned to the bridge).
    pub gateway: Ipv4Addr,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            subnet: Ipv4Addr::new(172, 28, 0, 0),
            prefix_len: 16,
            bridge_name: "crate0".to_string(),
            gateway: Ipv4Addr::new(172, 28, 0, 1),
        }
    }
}

// ---------------------------------------------------------------------------
// ContainerNetwork
// ---------------------------------------------------------------------------

/// Represents the network resources allocated to a single container.
///
/// Holds the veth pair names, assigned IP, and associated configuration so
/// that everything can be cleaned up when the container stops.
#[derive(Debug, Clone)]
pub struct ContainerNetwork {
    /// Container identifier.
    pub container_id: String,
    /// Host-side veth interface name.
    pub veth_host: String,
    /// Container-side veth interface name (always `eth0`).
    pub veth_container: String,
    /// IP address assigned to the container.
    pub ip_address: Ipv4Addr,
    /// Reference to the bridge name (for iptables cleanup).
    pub bridge_name: String,
    /// Subnet in CIDR notation string (e.g. "172.28.0.0/16").
    pub subnet_cidr: String,
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use futures::stream::TryStreamExt;
    use rtnetlink::Handle;
    use std::process::Command;

    /// Manages the bridge network and per-container veth pairs.
    ///
    /// Create one instance with a [`NetworkConfig`], call [`setup_bridge`] once,
    /// then [`create_container_network`] for each container.
    #[derive(Debug)]
    pub struct NetworkManager {
        config: NetworkConfig,
    }

    impl NetworkManager {
        /// Create a new network manager with the given configuration.
        pub fn new(config: NetworkConfig) -> Self {
            Self { config }
        }

        /// Create a new network manager with default configuration.
        pub fn with_defaults() -> Self {
            Self::new(NetworkConfig::default())
        }

        /// Return a reference to the current configuration.
        pub fn config(&self) -> &NetworkConfig {
            &self.config
        }

        // -- internal helpers -----------------------------------------------

        /// Get an rtnetlink connection handle. Returns (connection_task, handle).
        fn connect() -> Result<(tokio::task::JoinHandle<()>, Handle)> {
            let (conn, handle, _) = rtnetlink::new_connection().map_err(|e| {
                ContainerError::Network(format!("Failed to open netlink connection: {e}"))
            })?;
            let join = tokio::spawn(conn);
            Ok((join, handle))
        }

        /// Look up a link index by name.
        async fn link_index(handle: &Handle, name: &str) -> Result<u32> {
            let mut links = handle.link().get().match_name(name.to_string()).execute();
            match links.try_next().await {
                Ok(Some(link)) => Ok(link.header.index),
                _ => Err(ContainerError::Network(format!(
                    "Interface {name} not found"
                ))),
            }
        }

        /// Run an iptables command, returning an error on failure.
        fn iptables(args: &[&str]) -> Result<()> {
            let output = Command::new("iptables")
                .args(args)
                .output()
                .map_err(|e| ContainerError::Network(format!("Failed to run iptables: {e}")))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // Duplicate-rule errors on -A are harmless; only treat real
                // failures as errors.
                if !stderr.contains("already exists") {
                    return Err(ContainerError::Network(format!(
                        "iptables {args:?} failed: {stderr}"
                    )));
                }
            }
            Ok(())
        }

        // -- public API -----------------------------------------------------

        /// Create the bridge interface and assign the gateway address.
        ///
        /// If the bridge already exists this is a no-op.
        pub async fn setup_bridge(&self) -> Result<()> {
            let (_conn, handle) = Self::connect()?;
            let bridge = &self.config.bridge_name;

            // Create bridge (ignore "already exists").
            if let Err(e) = handle.link().add().bridge(bridge.clone()).execute().await {
                let msg = format!("{e}");
                if !msg.contains("File exists") {
                    return Err(ContainerError::Network(format!(
                        "Failed to create bridge {bridge}: {e}"
                    )));
                }
                tracing::debug!(bridge, "Bridge already exists, skipping creation");
            }

            // Bring bridge up.
            let idx = Self::link_index(&handle, bridge).await?;
            handle.link().set(idx).up().execute().await.map_err(|e| {
                ContainerError::Network(format!("Failed to bring up bridge {bridge}: {e}"))
            })?;

            // Assign gateway address.
            let gw = self.config.gateway;
            if let Err(e) = handle
                .address()
                .add(idx, std::net::IpAddr::V4(gw), self.config.prefix_len)
                .execute()
                .await
            {
                let msg = format!("{e}");
                if !msg.contains("File exists") {
                    return Err(ContainerError::Network(format!(
                        "Failed to add address {gw} to {bridge}: {e}"
                    )));
                }
            }

            tracing::info!(bridge, %gw, "Bridge network ready");

            // NAT masquerade rule for outbound traffic.
            let cidr = format!("{}/{}", self.config.subnet, self.config.prefix_len);
            Self::iptables(&[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &cidr,
                "-j",
                "MASQUERADE",
            ])?;

            // Enable IP forwarding.
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| {
                ContainerError::Network(format!("Failed to enable IP forwarding: {e}"))
            })?;

            Ok(())
        }

        /// Create a veth pair, attach one end to the bridge, allocate an IP,
        /// and return a [`ContainerNetwork`] that can clean itself up later.
        ///
        /// The container-side veth (`eth0`) must be moved into the container's
        /// network namespace by the caller (typically in process.rs after
        /// `CLONE_NEWNET`).
        pub async fn create_container_network(
            &self,
            container_id: &str,
        ) -> Result<ContainerNetwork> {
            let (_conn, handle) = Self::connect()?;
            let host_veth = veth_host_name(container_id);
            let cont_veth = veth_container_name().to_string();

            // Create veth pair.
            handle
                .link()
                .add()
                .veth(host_veth.clone(), cont_veth.clone())
                .execute()
                .await
                .map_err(|e| ContainerError::Network(format!("Failed to create veth pair: {e}")))?;

            // Attach host-side veth to bridge.
            let bridge_idx = Self::link_index(&handle, &self.config.bridge_name).await?;
            let host_idx = Self::link_index(&handle, &host_veth).await?;
            handle
                .link()
                .set(host_idx)
                .controller(bridge_idx)
                .execute()
                .await
                .map_err(|e| {
                    ContainerError::Network(format!("Failed to attach {host_veth} to bridge: {e}"))
                })?;

            // Bring host-side veth up.
            handle
                .link()
                .set(host_idx)
                .up()
                .execute()
                .await
                .map_err(|e| {
                    ContainerError::Network(format!("Failed to bring up {host_veth}: {e}"))
                })?;

            // Allocate IP.
            let ip = allocate_ip(&self.config)?;

            // Add IP to the container-side veth (will be visible after ns move).
            let cont_idx = Self::link_index(&handle, &cont_veth).await?;
            handle
                .address()
                .add(cont_idx, std::net::IpAddr::V4(ip), self.config.prefix_len)
                .execute()
                .await
                .map_err(|e| {
                    ContainerError::Network(format!("Failed to assign {ip} to {cont_veth}: {e}"))
                })?;

            let cidr = format!("{}/{}", self.config.subnet, self.config.prefix_len);

            tracing::info!(
                container_id,
                %ip,
                host_veth = %host_veth,
                "Container network created"
            );

            Ok(ContainerNetwork {
                container_id: container_id.to_string(),
                veth_host: host_veth,
                veth_container: cont_veth,
                ip_address: ip,
                bridge_name: self.config.bridge_name.clone(),
                subnet_cidr: cidr,
            })
        }
    }

    impl ContainerNetwork {
        /// Remove the veth pair and associated iptables rules.
        ///
        /// Deleting the host-side veth automatically removes the peer, so only
        /// one deletion is needed.
        pub async fn cleanup(&self) -> Result<()> {
            let (_conn, handle) = NetworkManager::connect()?;

            // Delete host-side veth (peer is removed automatically).
            match NetworkManager::link_index(&handle, &self.veth_host).await {
                Ok(idx) => {
                    handle.link().del(idx).execute().await.map_err(|e| {
                        ContainerError::Network(format!(
                            "Failed to delete veth {}: {e}",
                            self.veth_host
                        ))
                    })?;
                }
                Err(_) => {
                    tracing::debug!(
                        veth = %self.veth_host,
                        "Veth already removed, skipping"
                    );
                }
            }

            // Remove MASQUERADE rule (best-effort, may be shared).
            let _ = NetworkManager::iptables(&[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &self.subnet_cidr,
                "-j",
                "MASQUERADE",
            ]);

            tracing::info!(
                container_id = %self.container_id,
                "Container network cleaned up"
            );

            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Non-Linux stubs
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::*;

    /// Stub network manager for non-Linux platforms.
    ///
    /// All operations return an error -- container networking requires Linux.
    #[derive(Debug)]
    pub struct NetworkManager {
        config: NetworkConfig,
    }

    impl NetworkManager {
        /// Create a new network manager (stub).
        pub fn new(config: NetworkConfig) -> Self {
            Self { config }
        }

        /// Create a new network manager with default configuration (stub).
        pub fn with_defaults() -> Self {
            Self::new(NetworkConfig::default())
        }

        /// Return a reference to the current configuration.
        pub fn config(&self) -> &NetworkConfig {
            &self.config
        }

        /// Stub -- returns error on non-Linux.
        pub async fn setup_bridge(&self) -> Result<()> {
            Err(ContainerError::Network(
                "Bridge networking is only supported on Linux".to_string(),
            ))
        }

        /// Stub -- returns error on non-Linux.
        pub async fn create_container_network(
            &self,
            _container_id: &str,
        ) -> Result<ContainerNetwork> {
            Err(ContainerError::Network(
                "Container networking is only supported on Linux".to_string(),
            ))
        }
    }

    impl ContainerNetwork {
        /// Stub -- returns error on non-Linux.
        pub async fn cleanup(&self) -> Result<()> {
            Err(ContainerError::Network(
                "Container networking is only supported on Linux".to_string(),
            ))
        }
    }
}

// Re-export the appropriate implementation.
#[cfg(target_os = "linux")]
pub use linux::NetworkManager;
#[cfg(not(target_os = "linux"))]
pub use stub::NetworkManager;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.subnet, Ipv4Addr::new(172, 28, 0, 0));
        assert_eq!(cfg.prefix_len, 16);
        assert_eq!(cfg.bridge_name, "crate0");
        assert_eq!(cfg.gateway, Ipv4Addr::new(172, 28, 0, 1));
    }

    #[test]
    fn ip_allocation_sequential() {
        reset_ip_counter();
        let cfg = NetworkConfig::default();

        let ip1 = allocate_ip(&cfg).unwrap();
        let ip2 = allocate_ip(&cfg).unwrap();
        let ip3 = allocate_ip(&cfg).unwrap();

        assert_eq!(ip1, Ipv4Addr::new(172, 28, 0, 2));
        assert_eq!(ip2, Ipv4Addr::new(172, 28, 0, 3));
        assert_eq!(ip3, Ipv4Addr::new(172, 28, 0, 4));
    }

    #[test]
    fn ip_allocation_wraps_octets() {
        reset_ip_counter();
        // Force counter to 256 to cross into the second octet.
        IP_COUNTER.store(256, Ordering::SeqCst);
        let cfg = NetworkConfig::default();
        let ip = allocate_ip(&cfg).unwrap();
        assert_eq!(ip, Ipv4Addr::new(172, 28, 1, 0));
    }

    #[test]
    fn ip_allocation_exhaustion() {
        reset_ip_counter();
        // Set counter just past the valid range.
        IP_COUNTER.store(0xFFFF, Ordering::SeqCst);
        let cfg = NetworkConfig::default();
        let result = allocate_ip(&cfg);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exhausted"), "unexpected error: {err}");
    }

    #[test]
    fn veth_host_name_truncates() {
        let name = veth_host_name("abcdefghijklmnop");
        assert_eq!(name, "vethabcdefgh");
        // Must fit in 15 chars (Linux IFNAMSIZ).
        assert!(name.len() <= 15);
    }

    #[test]
    fn veth_host_name_short_id() {
        let name = veth_host_name("abc");
        assert_eq!(name, "vethabc");
    }

    #[test]
    fn veth_container_name_is_eth0() {
        assert_eq!(veth_container_name(), "eth0");
    }

    #[test]
    fn custom_config() {
        let cfg = NetworkConfig {
            subnet: Ipv4Addr::new(10, 0, 0, 0),
            prefix_len: 24,
            bridge_name: "mybridge".to_string(),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
        };
        assert_eq!(cfg.subnet, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(cfg.prefix_len, 24);
        assert_eq!(cfg.bridge_name, "mybridge");
    }

    #[test]
    fn ip_allocation_custom_subnet() {
        reset_ip_counter();
        let cfg = NetworkConfig {
            subnet: Ipv4Addr::new(10, 99, 0, 0),
            prefix_len: 16,
            bridge_name: "br0".to_string(),
            gateway: Ipv4Addr::new(10, 99, 0, 1),
        };
        let ip = allocate_ip(&cfg).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 99, 0, 2));
    }

    #[test]
    fn network_manager_holds_config() {
        let cfg = NetworkConfig::default();
        let mgr = NetworkManager::new(cfg.clone());
        assert_eq!(mgr.config().bridge_name, cfg.bridge_name);
        assert_eq!(mgr.config().gateway, cfg.gateway);
    }

    #[test]
    fn network_manager_defaults() {
        let mgr = NetworkManager::with_defaults();
        assert_eq!(mgr.config().bridge_name, "crate0");
    }
}
