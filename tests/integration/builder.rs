use crate_runtime::ContainerBuilder;

#[test]
fn test_builder_produces_valid_container() {
    let container = ContainerBuilder::new()
        .command(vec!["/bin/echo".into(), "hello".into()])
        .hostname("integration-test".into())
        .id("integ-001".into())
        .build()
        .unwrap();

    assert_eq!(container.config.id, "integ-001");
    assert_eq!(container.config.hostname, "integration-test");
    assert_eq!(container.config.command, vec!["/bin/echo", "hello"]);
}

#[test]
fn test_builder_rejects_invalid_rootfs() {
    let result = ContainerBuilder::new().rootfs("../escape".into()).build();
    assert!(result.is_err());
}

#[test]
fn test_builder_rejects_bad_hostname() {
    let result = ContainerBuilder::new().hostname("bad host!".into()).build();
    assert!(result.is_err());
}
