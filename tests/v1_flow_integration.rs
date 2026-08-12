use bytes::Bytes;
use new_proxy::flow_plane::{
    bounded_flow_channels, DispatchOutcome, FlowMessage, FlowWorkerError, FlowWorkerState,
    IoOwnerKey, IoRegistry, QuicFlow, QuicFlowId,
};
use std::net::{IpAddr, Ipv4Addr};

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

fn ipv4_tcp_packet(source_port: u16) -> Bytes {
    let mut packet = vec![0u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[203, 0, 113, 10]);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 0x50;
    Bytes::from(packet)
}

fn ipv4_icmp_echo(source: [u8; 4], destination: [u8; 4], identifier: u16, reply: bool) -> Bytes {
    let mut packet = vec![0u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20] = if reply { 0 } else { 8 };
    packet[24..26].copy_from_slice(&identifier.to_be_bytes());
    Bytes::from(packet)
}

fn quic_flow(worker_id: usize) -> QuicFlow {
    QuicFlow::new(QuicFlowId(7), worker_id, b"integration-flow", 4).unwrap()
}

#[test]
fn v1_integration_bounded_dispatch_never_changes_the_selected_owner() {
    let (dispatcher, receivers) = bounded_flow_channels(2, 1).unwrap();
    let owner = IoOwnerKey::new(10, 3);
    let packet = ipv4_tcp_packet(10001);

    assert_eq!(
        dispatcher.dispatch_to(
            1,
            FlowMessage::InterceptIngress {
                io_owner: owner,
                packet: packet.clone(),
            },
        ),
        DispatchOutcome::Accepted
    );
    assert_eq!(
        dispatcher.dispatch_to(
            1,
            FlowMessage::InterceptIngress {
                io_owner: owner,
                packet,
            },
        ),
        DispatchOutcome::DroppedFull
    );
    assert!(receivers[0].try_recv().is_err());
    assert!(matches!(
        receivers[1].try_recv().unwrap(),
        FlowMessage::InterceptIngress { io_owner, .. } if io_owner == owner
    ));
    assert_eq!(dispatcher.stats().channel_full_drops, 1);
}

#[test]
fn v1_integration_session_owner_and_local_return_io_stay_stable() {
    let mut worker =
        FlowWorkerState::new(1, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);
    let packet = ipv4_tcp_packet(10001);
    let quic_flow = quic_flow(1);

    let first = worker
        .handle_intercept(intercept, packet.clone(), &quic_flow, tunnel)
        .unwrap();
    let repeated = worker
        .handle_intercept(intercept, packet, &quic_flow, tunnel)
        .unwrap();

    assert_eq!(first.session_id, repeated.session_id);
    assert_eq!(first.transmit.target, tunnel);
    assert_eq!(
        new_proxy::flow_plane::parse_flow_key(&first.transmit.packet)
            .unwrap()
            .source,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(
        new_proxy::flow_plane::parse_flow_key(&first.transmit.packet)
            .unwrap()
            .source_port,
        40000
    );
    assert_eq!(
        worker.local_return_target(first.session_id),
        Some(intercept)
    );
    assert_eq!(worker.session(first.session_id).unwrap().flow_worker_id, 1);
}

#[test]
fn v1_integration_flow_worker_rejects_quic_flow_owned_by_another_worker() {
    let mut worker =
        FlowWorkerState::new(1, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let foreign_flow = quic_flow(0);

    let result = worker.handle_intercept(
        IoOwnerKey::new(10, 3),
        ipv4_tcp_packet(10001),
        &foreign_flow,
        IoOwnerKey::new(20, 1),
    );

    assert!(matches!(
        result,
        Err(FlowWorkerError::WrongQuicFlowOwner {
            expected: 1,
            actual: 0
        })
    ));
}

#[test]
fn v1_integration_reverse_nat_restores_original_return_tuple() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);
    let original = ipv4_tcp_packet(10001);
    let quic_flow = quic_flow(0);
    let handled = worker
        .handle_intercept(intercept, original.clone(), &quic_flow, tunnel)
        .unwrap();
    let translated = new_proxy::flow_plane::parse_flow_key(&handled.transmit.packet).unwrap();
    let mut reply = ipv4_tcp_packet(443).to_vec();
    let reply_tuple = translated.reverse();
    new_proxy::flow_plane::rewrite_packet(&mut reply, &reply_tuple).unwrap();

    let restored = worker
        .handle_reverse(Bytes::from(reply))
        .unwrap()
        .expect("reverse NAT hit");

    assert_eq!(restored.local_target, intercept);
    assert_eq!(restored.quic_flow_id, QuicFlowId(7));
    assert_eq!(
        new_proxy::flow_plane::parse_flow_key(&restored.packet).unwrap(),
        new_proxy::flow_plane::parse_flow_key(&original)
            .unwrap()
            .reverse()
    );
}

#[test]
fn v1_integration_icmp_reverse_nat_restores_identifier_and_keeps_reply_type() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);
    let original = ipv4_icmp_echo([10, 0, 0, 2], [203, 0, 113, 10], 17592, false);
    let quic_flow = quic_flow(0);
    let handled = worker
        .handle_intercept(intercept, original, &quic_flow, tunnel)
        .unwrap();
    let translated = new_proxy::flow_plane::parse_flow_key(&handled.transmit.packet).unwrap();
    let reply = ipv4_icmp_echo(
        [203, 0, 113, 10],
        [192, 0, 2, 1],
        translated.source_port,
        true,
    );

    let restored = worker
        .handle_reverse(reply)
        .unwrap()
        .expect("reverse NAT hit");
    let restored_flow = new_proxy::flow_plane::parse_flow_key(&restored.packet).unwrap();

    assert_eq!(
        restored_flow.source,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
    );
    assert_eq!(
        restored_flow.destination,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(restored_flow.source_port, 17592);
    assert_eq!(restored_flow.destination_port, 0);
}

#[test]
fn v1_integration_server_default_queue_is_corrected_once() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let default_intercept = IoOwnerKey::new(10, 0);
    let tunnel = IoOwnerKey::new(20, 0);
    let quic_flow = quic_flow(0);
    let handled = worker
        .handle_intercept(
            default_intercept,
            ipv4_tcp_packet(10001),
            &quic_flow,
            tunnel,
        )
        .unwrap();

    assert!(worker.correct_server_return_io(handled.session_id, IoOwnerKey::new(10, 3)));
    assert!(!worker.correct_server_return_io(handled.session_id, IoOwnerKey::new(10, 4)));
    assert_eq!(
        worker.local_return_target(handled.session_id),
        Some(IoOwnerKey::new(10, 3))
    );
    assert_eq!(worker.stats().queue_mismatch_drops, 1);
}

#[test]
fn v1_integration_same_interface_keeps_tunnel_and_intercept_queues_distinct() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(10, 1);
    let quic_flow = quic_flow(0);

    let handled = worker
        .handle_intercept(intercept, ipv4_tcp_packet(10001), &quic_flow, tunnel)
        .unwrap();

    assert_eq!(handled.transmit.target, tunnel);
    assert_eq!(
        worker.local_return_target(handled.session_id),
        Some(intercept)
    );
}
