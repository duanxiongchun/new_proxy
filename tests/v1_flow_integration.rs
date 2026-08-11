use new_proxy::flow_plane::{IoOwnerKey, IoRegistry};

#[test]
fn v1_integration_equal_queue_ids_on_different_interfaces_have_distinct_owners() {
    let intercept = IoOwnerKey::new(10, 0);
    let tunnel = IoOwnerKey::new(20, 0);
    let mut registry = IoRegistry::new();

    registry.register(intercept, "intercept").unwrap();
    registry.register(tunnel, "tunnel").unwrap();

    assert_eq!(registry.len(), 2);
    assert_eq!(registry.get(intercept), Some(&"intercept"));
    assert_eq!(registry.get(tunnel), Some(&"tunnel"));
}
