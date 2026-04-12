use crate_runtime::config::RuntimeConfig;

#[test]
fn test_config_defaults_are_sensible() {
    let config = RuntimeConfig::default();
    assert!(!config.log.level.is_empty());
    assert_eq!(config.cgroup.cpu_period, 100_000);
    assert!(config.security.drop_capabilities);
    assert!(config.security.enable_seccomp);
    assert_eq!(config.network.bridge_name, "crate0");
}

#[test]
fn test_config_from_toml_string() {
    let toml = r#"
        root = "/tmp/crate-test"

        [cgroup]
        memory_limit = 268435456
        pids_max = 50

        [network]
        enabled = false
    "#;

    let config: RuntimeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.root, std::path::PathBuf::from("/tmp/crate-test"));
    assert_eq!(config.cgroup.memory_limit, 268435456);
    assert_eq!(config.cgroup.pids_max, 50);
    assert!(!config.network.enabled);
}
