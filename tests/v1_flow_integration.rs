use bytes::Bytes;
use new_proxy::flow_plane::{
    bounded_flow_channels, DispatchOutcome, DnsFlowConfig, FlowMessage, FlowWorkerError,
    FlowWorkerState, HandledDnsQuery, IoOwnerKey, IoRegistry, QuicFlow, QuicFlowId,
    TCP_MAX_SAFE_MSS,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

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
    finalize_packet(packet)
}

fn ipv4_udp_packet(
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Bytes {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    finalize_packet(packet)
}

fn ipv6_udp_packet(
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Bytes {
    let udp_len = 8 + payload.len();
    let mut packet = vec![0u8; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&destination);
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[48..].copy_from_slice(payload);
    finalize_packet(packet)
}

fn ipv6_hop_by_hop_udp_packet(
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Bytes {
    let udp_len = 8 + payload.len();
    let payload_len = 8 + udp_len;
    let mut packet = vec![0u8; 40 + payload_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    packet[6] = 0;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&destination);
    packet[40] = 17;
    packet[41] = 0;
    packet[48..50].copy_from_slice(&source_port.to_be_bytes());
    packet[50..52].copy_from_slice(&destination_port.to_be_bytes());
    packet[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[56..].copy_from_slice(payload);
    finalize_packet(packet)
}

fn dns_query(id: u16, qname: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.') {
        payload.push(label.len() as u8);
        payload.extend_from_slice(label.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload
}

fn dns_response(id: u16, qname: &str) -> Vec<u8> {
    let mut payload = dns_query(id, qname);
    payload[2] = 0x80;
    payload
}

fn dns_query_with_edns(id: u16, qname: &str, advertised: u16) -> Vec<u8> {
    let mut payload = dns_query(id, qname);
    payload[11] = 1;
    payload.push(0);
    payload.extend_from_slice(&41u16.to_be_bytes());
    payload.extend_from_slice(&advertised.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload
}

fn dns_config() -> DnsFlowConfig {
    DnsFlowConfig {
        listen: "10.0.0.53:53".parse().unwrap(),
        local_resolver: "192.0.2.53:53".parse().unwrap(),
        remote_resolver: "1.1.1.1:53".parse().unwrap(),
        remote_domains: vec!["google.com".to_string()].into(),
        transaction_capacity: 16,
        timeout: std::time::Duration::from_secs(5),
        remote_available: true,
    }
}

fn dns_config_v6() -> DnsFlowConfig {
    DnsFlowConfig {
        listen: "[2001:db8:30::53]:53".parse().unwrap(),
        local_resolver: "[2001:db8:53::53]:53".parse().unwrap(),
        remote_resolver: "[2001:4860:4860::8888]:53".parse().unwrap(),
        remote_domains: vec!["google.com".to_string()].into(),
        transaction_capacity: 16,
        timeout: std::time::Duration::from_secs(5),
        remote_available: true,
    }
}

fn dns_rcode(packet: &[u8]) -> u8 {
    packet[31] & 0x0f
}

fn dns_edns_advertised(packet: &[u8]) -> u16 {
    let payload = new_proxy::flow_plane::udp_payload(packet).unwrap();
    let offset = payload.len() - 11;
    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]])
}

fn checksum_add(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    sum
}

fn checksum_finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn assert_ipv6_udp_checksum(packet: &[u8]) {
    let total_len = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let mut next_header = packet[6];
    let mut udp_offset = 40;
    while matches!(next_header, 0 | 43 | 60) {
        next_header = packet[udp_offset];
        udp_offset += (usize::from(packet[udp_offset + 1]) + 1) * 8;
    }
    assert_eq!(next_header, 17);
    let udp_len = total_len - udp_offset;
    let mut sum = checksum_add(0, &packet[8..40]);
    sum = checksum_add(sum, &(udp_len as u32).to_be_bytes());
    sum = checksum_add(sum, &[0, 0, 0, 17]);
    sum = checksum_add(sum, &packet[udp_offset..total_len]);
    assert_eq!(checksum_finish(sum), 0);
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
    finalize_packet(packet)
}

fn finalize_packet(mut packet: Vec<u8>) -> Bytes {
    let flow = new_proxy::flow_plane::parse_flow_key(&packet).unwrap();
    new_proxy::flow_plane::rewrite_packet(&mut packet, &flow).unwrap();
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
                expected_locator: None,
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
                expected_locator: None,
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
fn v1_integration_nat_exhaustion_rejects_new_flow_and_preserves_existing_flow() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);
    let quic_flow = quic_flow(0);

    let established = worker
        .handle_intercept(intercept, ipv4_tcp_packet(10001), &quic_flow, tunnel)
        .unwrap();
    let translated = new_proxy::flow_plane::parse_flow_key(&established.transmit.packet).unwrap();
    let rejected = worker.handle_intercept(intercept, ipv4_tcp_packet(10002), &quic_flow, tunnel);

    assert!(matches!(
        rejected,
        Err(FlowWorkerError::Session(
            new_proxy::flow_plane::SessionError::Nat(
                new_proxy::flow_plane::NatError::PortRangeExhausted
            )
        ))
    ));
    assert_eq!(worker.stats().session_nat_exhausted, 1);
    assert_eq!(worker.sessions().count(), 1);
    assert_eq!(worker.nat_count(), 1);

    let mut reply = ipv4_tcp_packet(443).to_vec();
    new_proxy::flow_plane::rewrite_packet(&mut reply, &translated.reverse()).unwrap();
    let restored = worker
        .handle_reverse(Bytes::from(reply))
        .unwrap()
        .expect("established flow remains usable after exhaustion");
    assert_eq!(restored.session_id, established.session_id);
    assert_eq!(restored.local_target, intercept);
}

#[test]
fn v1_integration_invalid_udp_length_creates_no_session_or_nat() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);
    let quic_flow = quic_flow(0);
    let mut packet =
        ipv4_udp_packet([10, 0, 0, 2], [203, 0, 113, 10], 10001, 443, b"payload").to_vec();
    packet[24..26].copy_from_slice(&0u16.to_be_bytes());
    packet[26..28].copy_from_slice(&0u16.to_be_bytes());

    assert!(worker
        .handle_intercept(intercept, Bytes::from(packet), &quic_flow, tunnel)
        .is_err());
    assert_eq!(worker.sessions().count(), 0);
    assert_eq!(worker.nat_count(), 0);
    assert_eq!(worker.reverse_nat_count(), 0);
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
    let quic_flow = quic_flow(0);
    let handled = worker
        .handle_server_inner(default_intercept, ipv4_tcp_packet(10001), &quic_flow)
        .unwrap();

    assert!(worker.correct_server_return_io(handled.session_id, IoOwnerKey::new(10, 3)));
    assert!(!worker.correct_server_return_io(handled.session_id, IoOwnerKey::new(10, 4)));
    let repeated = worker
        .handle_server_inner(default_intercept, ipv4_tcp_packet(10001), &quic_flow)
        .unwrap();

    assert_eq!(repeated.session_id, handled.session_id);
    assert_eq!(repeated.transmit.target, IoOwnerKey::new(10, 3));
    assert_eq!(
        worker.local_return_target(handled.session_id),
        Some(IoOwnerKey::new(10, 3))
    );
    assert_eq!(worker.stats().queue_mismatch_drops, 1);
}

#[test]
fn v1_integration_invalid_server_return_does_not_consume_queue_correction() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let default_intercept = IoOwnerKey::new(10, 0);
    let quic_flow = quic_flow(0);
    let handled = worker
        .handle_server_inner(default_intercept, ipv4_tcp_packet(10001), &quic_flow)
        .unwrap();
    let translated = new_proxy::flow_plane::parse_flow_key(&handled.transmit.packet).unwrap();
    let return_tuple = translated.reverse();
    let locator = worker.lookup_reverse_locator(&return_tuple).unwrap();
    let mut invalid_reply = ipv4_tcp_packet(443).to_vec();
    new_proxy::flow_plane::rewrite_packet(&mut invalid_reply, &return_tuple).unwrap();
    invalid_reply[10] ^= 0xff;

    assert!(worker
        .handle_server_reverse(IoOwnerKey::new(10, 3), Bytes::from(invalid_reply), locator)
        .is_err());
    assert_eq!(
        worker.local_return_target(handled.session_id),
        Some(default_intercept)
    );

    let mut valid_reply = ipv4_tcp_packet(443).to_vec();
    new_proxy::flow_plane::rewrite_packet(&mut valid_reply, &return_tuple).unwrap();
    assert!(worker
        .handle_server_reverse(IoOwnerKey::new(10, 4), Bytes::from(valid_reply), locator)
        .unwrap()
        .is_some());
    assert_eq!(
        worker.local_return_target(handled.session_id),
        Some(IoOwnerKey::new(10, 4))
    );
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

#[test]
fn v1_integration_dns_local_query_uses_client_resolver_and_restores_vip_response() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(7, "local.example"),
    );

    let outbound = worker
        .handle_dns_query(intercept, query, &config)
        .expect("local DNS query handled");
    let local = match outbound {
        HandledDnsQuery::Local { transmit, .. } => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let translated = new_proxy::flow_plane::parse_flow_key(&local.packet).unwrap();

    assert_eq!(local.target, intercept);
    assert_eq!(translated.source, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(translated.source_port, 40000);
    assert_eq!(translated.destination, config.local_resolver.ip());
    assert_eq!(translated.destination_port, 53);

    let reply = ipv4_udp_packet(
        [192, 0, 2, 53],
        [192, 0, 2, 1],
        53,
        translated.source_port,
        &dns_response(7, "local.example"),
    );
    let restored = worker
        .handle_dns_response(reply)
        .unwrap()
        .expect("DNS reverse hit");
    let restored_flow = new_proxy::flow_plane::parse_flow_key(&restored.packet).unwrap();

    assert_eq!(restored.local_target, intercept);
    assert_eq!(restored_flow.source, config.listen.ip());
    assert_eq!(restored_flow.source_port, 53);
    assert_eq!(
        restored_flow.destination,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(restored_flow.destination_port, 53000);
}

#[test]
fn v1_integration_dns_ipv6_local_query_restores_vip_response() {
    let mut worker = FlowWorkerState::new_dual(
        0,
        None,
        Some("2001:db8:30::1".parse().unwrap()),
        40000..=40010,
    )
    .unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config_v6();
    let client = Ipv6Addr::new(0x2001, 0xdb8, 0x30, 0, 0, 0, 0, 2).octets();
    let vip = Ipv6Addr::new(0x2001, 0xdb8, 0x30, 0, 0, 0, 0, 0x53).octets();
    let resolver = Ipv6Addr::new(0x2001, 0xdb8, 0x53, 0, 0, 0, 0, 0x53).octets();
    let query = ipv6_udp_packet(client, vip, 53000, 53, &dns_query(21, "local.example"));

    let local = match worker.handle_dns_query(intercept, query, &config).unwrap() {
        HandledDnsQuery::Local { transmit, .. } => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let translated = new_proxy::flow_plane::parse_flow_key(&local.packet).unwrap();

    assert_eq!(
        translated.source,
        IpAddr::V6("2001:db8:30::1".parse().unwrap())
    );
    assert_eq!(translated.destination, config.local_resolver.ip());

    let reply = ipv6_udp_packet(
        resolver,
        Ipv6Addr::new(0x2001, 0xdb8, 0x30, 0, 0, 0, 0, 1).octets(),
        53,
        translated.source_port,
        &dns_response(21, "local.example"),
    );
    let restored = worker
        .handle_dns_response(reply)
        .unwrap()
        .expect("IPv6 DNS reverse hit");
    let restored_flow = new_proxy::flow_plane::parse_flow_key(&restored.packet).unwrap();

    assert_eq!(restored.local_target, intercept);
    assert_eq!(restored_flow.source, config.listen.ip());
    assert_eq!(
        restored_flow.destination,
        IpAddr::V6(Ipv6Addr::from(client))
    );
    assert_eq!(worker.stats().dns_response_local, 1);
}

#[test]
fn v1_integration_dns_remote_query_uses_remote_resolver_and_reuses_retransmit_port() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(9, "www.google.com"),
    );

    let first = match worker
        .handle_dns_query(intercept, query.clone(), &config)
        .expect("remote DNS query handled")
    {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let repeated = match worker
        .handle_dns_query(intercept, query, &config)
        .expect("remote DNS retransmit handled")
    {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let first_flow = new_proxy::flow_plane::parse_flow_key(&first).unwrap();
    let repeated_flow = new_proxy::flow_plane::parse_flow_key(&repeated).unwrap();

    assert_eq!(first_flow.source_port, repeated_flow.source_port);
    assert_eq!(first_flow.destination, config.remote_resolver.ip());
    assert_eq!(first_flow.destination_port, 53);

    let resolver = match config.remote_resolver {
        SocketAddr::V4(address) => address.ip().octets(),
        SocketAddr::V6(_) => unreachable!("test uses IPv4 resolver"),
    };
    assert_eq!(
        worker
            .handle_dns_response(ipv4_udp_packet(
                resolver,
                [192, 0, 2, 1],
                53,
                first_flow.source_port,
                &dns_response(10, "www.google.com"),
            ))
            .unwrap(),
        None
    );
    assert_eq!(worker.stats().dns_spoofed_response_drop, 1);
    assert_eq!(worker.stats().dns_transactions_active, 1);

    let reply = ipv4_udp_packet(
        resolver,
        [192, 0, 2, 1],
        53,
        first_flow.source_port,
        &dns_response(9, "www.google.com"),
    );
    let restored = worker
        .handle_dns_response(reply)
        .unwrap()
        .expect("remote DNS reverse hit");
    let restored_flow = new_proxy::flow_plane::parse_flow_key(&restored.packet).unwrap();

    assert_eq!(restored.local_target, intercept);
    assert_eq!(restored_flow.source, config.listen.ip());
    assert_eq!(
        restored_flow.destination,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(
        worker
            .handle_dns_response(ipv4_udp_packet(
                resolver,
                [192, 0, 2, 1],
                53,
                first_flow.source_port,
                &dns_response(9, "www.google.com"),
            ))
            .unwrap(),
        None
    );
    assert_eq!(worker.stats().dns_query_remote, 1);
    assert_eq!(worker.stats().dns_response_remote, 1);
    assert_eq!(worker.stats().dns_spoofed_response_drop, 1);
    assert_eq!(worker.stats().dns_late_response_drop, 1);
    assert_eq!(worker.stats().dns_transactions_active, 0);
}

#[test]
fn v1_integration_dns_capacity_and_nat_exhaustion_return_servfail() {
    let intercept = IoOwnerKey::new(10, 3);
    let mut capacity_worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let mut capacity_config = dns_config();
    capacity_config.transaction_capacity = 0;
    let capacity_query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(11, "www.google.com"),
    );

    let servfail = match capacity_worker
        .handle_dns_query(intercept, capacity_query, &capacity_config)
        .unwrap()
    {
        HandledDnsQuery::Servfail(transmit) => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let servfail_flow = new_proxy::flow_plane::parse_flow_key(&servfail.packet).unwrap();

    assert_eq!(servfail_flow.source, capacity_config.listen.ip());
    assert_eq!(
        servfail_flow.destination,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(dns_rcode(&servfail.packet), 2);
    assert_eq!(capacity_worker.stats().dns_capacity_exhausted, 1);
    assert_eq!(capacity_worker.stats().dns_servfail, 1);

    let mut nat_worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let config = dns_config();
    let first = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(12, "www.google.com"),
    );
    assert!(matches!(
        nat_worker
            .handle_dns_query(intercept, first, &config)
            .unwrap(),
        HandledDnsQuery::Remote { .. }
    ));
    let second = ipv4_udp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 53],
        53001,
        53,
        &dns_query(13, "www.google.com"),
    );
    let servfail = match nat_worker
        .handle_dns_query(intercept, second, &config)
        .unwrap()
    {
        HandledDnsQuery::Servfail(transmit) => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };

    assert_eq!(dns_rcode(&servfail.packet), 2);
    assert_eq!(nat_worker.stats().dns_nat_exhausted, 1);
    assert_eq!(nat_worker.stats().dns_servfail, 1);
    assert_eq!(nat_worker.stats().dns_transactions_active, 1);
}

#[test]
fn v1_integration_dns_edns_is_clamped_and_oversized_query_servfails() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let edns_query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query_with_edns(17, "local.example", 4096),
    );

    let local = match worker
        .handle_dns_query(intercept, edns_query, &config)
        .unwrap()
    {
        HandledDnsQuery::Local { transmit, .. } => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };

    assert_eq!(dns_edns_advertised(&local.packet), 1232);
    assert_eq!(worker.stats().dns_edns_clamped, 1);

    let oversized = ipv4_udp_packet([10, 0, 0, 2], [10, 0, 0, 53], 53001, 53, &vec![0u8; 1233]);
    let servfail = match worker
        .handle_dns_query(intercept, oversized, &config)
        .unwrap()
    {
        HandledDnsQuery::Servfail(transmit) => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    assert_eq!(dns_rcode(&servfail.packet), 2);
    assert_eq!(worker.stats().dns_servfail, 1);
}

#[test]
fn v1_integration_dns_ipv6_edns_clamp_keeps_udp_checksum_valid() {
    let mut worker = FlowWorkerState::new_dual(
        0,
        None,
        Some("2001:db8:30::1".parse().unwrap()),
        40000..=40010,
    )
    .unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config_v6();
    let client = Ipv6Addr::new(0x2001, 0xdb8, 0x30, 0, 0, 0, 0, 2).octets();
    let vip = Ipv6Addr::new(0x2001, 0xdb8, 0x30, 0, 0, 0, 0, 0x53).octets();
    let query = ipv6_udp_packet(
        client,
        vip,
        53000,
        53,
        &dns_query_with_edns(31, "local.example", 4096),
    );

    let local = match worker.handle_dns_query(intercept, query, &config).unwrap() {
        HandledDnsQuery::Local { transmit, .. } => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };

    assert_eq!(dns_edns_advertised(&local.packet), 1232);
    assert_ipv6_udp_checksum(&local.packet);
    assert_eq!(worker.stats().dns_edns_clamped, 1);
}

#[test]
fn v1_integration_short_malformed_dns_query_returns_valid_servfail() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let query = ipv4_udp_packet([10, 0, 0, 2], [10, 0, 0, 53], 53000, 53, &[0x12, 0x34]);

    let servfail = match worker
        .handle_dns_query(intercept, query, &dns_config())
        .unwrap()
    {
        HandledDnsQuery::Servfail(transmit) => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let payload = new_proxy::flow_plane::udp_payload(&servfail.packet).unwrap();

    assert_eq!(payload.len(), 12);
    assert_eq!(&payload[..2], &[0x12, 0x34]);
    assert_eq!(u16::from_be_bytes([payload[2], payload[3]]), 0x8002);
    assert_eq!(&payload[4..], &[0; 8]);
}

#[test]
fn v1_integration_short_ipv6_extension_dns_query_returns_valid_servfail() {
    let mut worker = FlowWorkerState::new_dual(
        0,
        None,
        Some("2001:db8:30::1".parse().unwrap()),
        40000..=40010,
    )
    .unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let client = "2001:db8:30::2".parse::<Ipv6Addr>().unwrap().octets();
    let vip = "2001:db8:30::53".parse::<Ipv6Addr>().unwrap().octets();
    let query = ipv6_hop_by_hop_udp_packet(client, vip, 53000, 53, &[0x12, 0x34]);

    let servfail = match worker
        .handle_dns_query(intercept, query, &dns_config_v6())
        .unwrap()
    {
        HandledDnsQuery::Servfail(transmit) => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let payload = new_proxy::flow_plane::udp_payload(&servfail.packet).unwrap();

    assert_eq!(payload.len(), 12);
    assert_eq!(&payload[..2], &[0x12, 0x34]);
    assert_eq!(u16::from_be_bytes([payload[2], payload[3]]), 0x8002);
    assert_eq!(&payload[4..], &[0; 8]);
    assert_ipv6_udp_checksum(&servfail.packet);
}

#[test]
fn v1_integration_dns_malformed_oversized_response_is_rejected_without_consuming_state() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(32, "www.google.com"),
    );
    let outbound = match worker.handle_dns_query(intercept, query, &config).unwrap() {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let translated = new_proxy::flow_plane::parse_flow_key(&outbound).unwrap();
    let mut response = dns_response(32, "www.google.com");
    response.resize(1233, 0);

    let malformed = worker
        .handle_dns_response(ipv4_udp_packet(
            [1, 1, 1, 1],
            [192, 0, 2, 1],
            53,
            translated.source_port,
            &response,
        ))
        .unwrap();

    assert_eq!(malformed, None);
    assert_eq!(worker.stats().dns_spoofed_response_drop, 1);
    assert_eq!(worker.stats().dns_transactions_active, 1);

    let valid = ipv4_udp_packet(
        [1, 1, 1, 1],
        [192, 0, 2, 1],
        53,
        translated.source_port,
        &dns_response(32, "www.google.com"),
    );
    assert!(worker.handle_dns_response(valid).unwrap().is_some());
    assert_eq!(worker.stats().dns_transactions_active, 0);
}

#[test]
fn v1_integration_dns_fragmented_response_does_not_consume_transaction() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(34, "www.google.com"),
    );
    let outbound = match worker.handle_dns_query(intercept, query, &config).unwrap() {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let translated = new_proxy::flow_plane::parse_flow_key(&outbound).unwrap();
    let mut fragmented = ipv4_udp_packet(
        [1, 1, 1, 1],
        [192, 0, 2, 1],
        53,
        translated.source_port,
        &dns_response(34, "www.google.com"),
    )
    .to_vec();
    fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());

    assert_eq!(
        worker.handle_dns_response(Bytes::from(fragmented)).unwrap(),
        None
    );
    assert_eq!(worker.stats().dns_transactions_active, 1);
    assert_eq!(worker.stats().dns_spoofed_response_drop, 1);

    let correct = ipv4_udp_packet(
        [1, 1, 1, 1],
        [192, 0, 2, 1],
        53,
        translated.source_port,
        &dns_response(34, "www.google.com"),
    );
    assert!(worker.handle_dns_response(correct).unwrap().is_some());
    assert_eq!(worker.stats().dns_transactions_active, 0);
}

#[test]
fn v1_integration_dns_parseable_fallback_is_local_and_unverifiable_query_servfails() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let mut response_like = dns_query(35, "www.google.com");
    response_like[2] = 0x80;
    let response_like_packet =
        ipv4_udp_packet([10, 0, 0, 2], [10, 0, 0, 53], 53000, 53, &response_like);

    assert!(matches!(
        worker
            .handle_dns_query(intercept, response_like_packet.clone(), &config)
            .unwrap(),
        HandledDnsQuery::Servfail(_)
    ));
    assert_eq!(worker.stats().dns_malformed_local_fallback, 0);

    let malformed = ipv4_udp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 53],
        53001,
        53,
        b"\x12\x34\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00",
    );
    assert!(matches!(
        worker
            .handle_dns_query(intercept, malformed, &config)
            .unwrap(),
        HandledDnsQuery::Servfail(_)
    ));
    assert_eq!(worker.stats().dns_nat_exhausted, 0);
    assert_eq!(worker.stats().dns_servfail, 2);
    assert_eq!(worker.stats().dns_transactions_active, 0);
}

#[test]
fn v1_integration_dns_remote_query_servfails_when_quic_unavailable() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let mut config = dns_config();
    config.remote_available = false;
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(14, "www.google.com"),
    );

    let servfail = match worker.handle_dns_query(intercept, query, &config).unwrap() {
        HandledDnsQuery::Servfail(transmit) => transmit,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let servfail_flow = new_proxy::flow_plane::parse_flow_key(&servfail.packet).unwrap();

    assert_eq!(servfail_flow.source, config.listen.ip());
    assert_eq!(
        servfail_flow.destination,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    );
    assert_eq!(dns_rcode(&servfail.packet), 2);
    assert_eq!(worker.stats().dns_servfail, 1);
    assert_eq!(worker.stats().dns_transactions_active, 0);
}

#[test]
fn v1_integration_dns_timeout_quarantines_reverse_tuple() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let mut config = dns_config();
    config.timeout = Duration::from_secs(5);
    let now = Instant::now();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(15, "www.google.com"),
    );

    let outbound = match worker
        .handle_dns_query_at(intercept, query, &config, now)
        .unwrap()
    {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let outbound_flow = new_proxy::flow_plane::parse_flow_key(&outbound).unwrap();
    assert_eq!(outbound_flow.source_port, 40000);
    assert!(worker
        .expire_dns_transactions(now + Duration::from_secs(4), &config)
        .unwrap()
        .is_empty());

    let expired = worker
        .expire_dns_transactions(now + Duration::from_secs(5), &config)
        .unwrap();

    assert_eq!(expired.len(), 1);
    assert_eq!(dns_rcode(&expired[0].transmit.packet), 2);
    assert_eq!(worker.stats().dns_timeout, 1);
    assert_eq!(worker.stats().dns_servfail, 1);
    assert_eq!(worker.stats().dns_transactions_active, 0);

    let second = ipv4_udp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 53],
        53001,
        53,
        &dns_query(16, "www.google.com"),
    );
    let second = worker.handle_dns_query(intercept, second, &config).unwrap();
    assert!(matches!(second, HandledDnsQuery::Servfail(_)));
    assert_eq!(worker.stats().dns_nat_exhausted, 1);
}

#[test]
fn v1_integration_dns_remove_transactions_clears_state_and_quarantines_tuple() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(18, "www.google.com"),
    );
    let outbound = match worker.handle_dns_query(intercept, query, &config).unwrap() {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    assert_eq!(
        new_proxy::flow_plane::parse_flow_key(&outbound)
            .unwrap()
            .source_port,
        40000
    );

    let removed = worker.remove_dns_transactions().unwrap();

    assert_eq!(removed.len(), 1);
    assert_eq!(worker.stats().dns_transactions_active, 0);
    assert_eq!(worker.nat_count(), 0);
    assert_eq!(worker.reverse_nat_count(), 0);
    let second = ipv4_udp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 53],
        53001,
        53,
        &dns_query(19, "www.google.com"),
    );
    let second = worker.handle_dns_query(intercept, second, &config).unwrap();
    assert!(matches!(second, HandledDnsQuery::Servfail(_)));
    assert_eq!(worker.stats().dns_nat_exhausted, 1);
}

#[test]
fn v1_integration_dns_spoofed_response_is_counted() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let spoofed = ipv4_udp_packet(
        [8, 8, 8, 8],
        [192, 0, 2, 1],
        53,
        40999,
        &dns_query(99, "www.google.com"),
    );

    assert_eq!(worker.handle_dns_response(spoofed).unwrap(), None);
    assert_eq!(worker.stats().dns_spoofed_response_drop, 1);
}

#[test]
fn v1_integration_dns_wrong_wire_id_does_not_consume_transaction() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(21, "www.google.com"),
    );
    let outbound = match worker.handle_dns_query(intercept, query, &config).unwrap() {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let translated = new_proxy::flow_plane::parse_flow_key(&outbound).unwrap();

    let wrong_id = ipv4_udp_packet(
        [1, 1, 1, 1],
        [192, 0, 2, 1],
        53,
        translated.source_port,
        &dns_response(22, "www.google.com"),
    );
    assert_eq!(worker.handle_dns_response(wrong_id).unwrap(), None);
    assert_eq!(worker.stats().dns_transactions_active, 1);

    let correct = ipv4_udp_packet(
        [1, 1, 1, 1],
        [192, 0, 2, 1],
        53,
        translated.source_port,
        &dns_response(21, "www.google.com"),
    );
    assert!(worker.handle_dns_response(correct).unwrap().is_some());
    assert_eq!(worker.stats().dns_transactions_active, 0);
}

#[test]
fn v1_integration_dns_same_query_on_two_intercepts_has_independent_return_owner() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001).unwrap();
    let first_intercept = IoOwnerKey::new(10, 3);
    let second_intercept = IoOwnerKey::new(11, 3);
    let config = dns_config();
    let query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(23, "www.google.com"),
    );

    let first = match worker
        .handle_dns_query(first_intercept, query.clone(), &config)
        .unwrap()
    {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let second = match worker
        .handle_dns_query(second_intercept, query, &config)
        .unwrap()
    {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let first_flow = new_proxy::flow_plane::parse_flow_key(&first).unwrap();
    let second_flow = new_proxy::flow_plane::parse_flow_key(&second).unwrap();
    assert_ne!(first_flow.source_port, second_flow.source_port);

    let first_response = ipv4_udp_packet(
        [1, 1, 1, 1],
        [192, 0, 2, 1],
        53,
        first_flow.source_port,
        &dns_response(23, "www.google.com"),
    );
    let second_response = ipv4_udp_packet(
        [1, 1, 1, 1],
        [192, 0, 2, 1],
        53,
        second_flow.source_port,
        &dns_response(23, "www.google.com"),
    );

    assert_eq!(
        worker
            .handle_dns_response(first_response)
            .unwrap()
            .unwrap()
            .local_target,
        first_intercept
    );
    assert_eq!(
        worker
            .handle_dns_response(second_response)
            .unwrap()
            .unwrap()
            .local_target,
        second_intercept
    );
}

#[test]
fn v1_integration_dns_abort_quarantines_reverse_tuple() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let first_query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(24, "www.google.com"),
    );
    let binding = match worker
        .handle_dns_query(intercept, first_query, &config)
        .unwrap()
    {
        HandledDnsQuery::Remote { binding, .. } => binding,
        other => panic!("unexpected DNS route: {other:?}"),
    };

    let aborted = worker
        .abort_dns_transaction(&binding, &config)
        .unwrap()
        .expect("transaction can be aborted");
    assert_eq!(dns_rcode(&aborted.transmit.packet), 2);
    assert_eq!(worker.stats().dns_transactions_active, 0);

    let second_query = ipv4_udp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 53],
        53001,
        53,
        &dns_query(25, "www.google.com"),
    );
    let second = worker
        .handle_dns_query(intercept, second_query, &config)
        .unwrap();
    assert!(matches!(second, HandledDnsQuery::Servfail(_)));
    assert_eq!(worker.stats().dns_nat_exhausted, 1);
}

#[test]
fn v1_integration_dns_completed_reverse_tuple_is_quarantined() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40000).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let first_query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(26, "www.google.com"),
    );
    let first = match worker
        .handle_dns_query(intercept, first_query, &config)
        .unwrap()
    {
        HandledDnsQuery::Remote { packet, .. } => packet,
        other => panic!("unexpected DNS route: {other:?}"),
    };
    let first_flow = new_proxy::flow_plane::parse_flow_key(&first).unwrap();
    let resolver = match config.remote_resolver {
        SocketAddr::V4(address) => address.ip().octets(),
        SocketAddr::V6(_) => unreachable!("test uses IPv4 resolver"),
    };
    let first_response = ipv4_udp_packet(
        resolver,
        [192, 0, 2, 1],
        53,
        first_flow.source_port,
        &dns_response(26, "www.google.com"),
    );
    assert!(worker
        .handle_dns_response(first_response)
        .unwrap()
        .is_some());

    let second_query = ipv4_udp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 53],
        53001,
        53,
        &dns_query(27, "www.google.com"),
    );
    let second = worker
        .handle_dns_query(intercept, second_query, &config)
        .unwrap();
    assert!(matches!(second, HandledDnsQuery::Servfail(_)));

    let late_response = ipv4_udp_packet(
        resolver,
        [192, 0, 2, 1],
        53,
        first_flow.source_port,
        &dns_response(26, "www.google.com"),
    );
    assert_eq!(worker.handle_dns_response(late_response).unwrap(), None);
    assert_eq!(worker.stats().dns_late_response_drop, 1);
    assert_eq!(worker.stats().dns_spoofed_response_drop, 0);
}

#[test]
fn v1_integration_dns_quic_close_aborts_only_remote_transactions() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let config = dns_config();
    let local_query = ipv4_udp_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 53],
        53000,
        53,
        &dns_query(26, "local.example"),
    );
    let remote_query = ipv4_udp_packet(
        [10, 0, 0, 3],
        [10, 0, 0, 53],
        53001,
        53,
        &dns_query(27, "www.google.com"),
    );
    assert!(matches!(
        worker
            .handle_dns_query(intercept, local_query, &config)
            .unwrap(),
        HandledDnsQuery::Local { .. }
    ));
    assert!(matches!(
        worker
            .handle_dns_query(intercept, remote_query, &config)
            .unwrap(),
        HandledDnsQuery::Remote { .. }
    ));

    let aborted = worker
        .abort_remote_dns_transactions(&config)
        .expect("remote DNS transactions can be aborted");

    assert_eq!(aborted.len(), 1);
    assert_eq!(dns_rcode(&aborted[0].transmit.packet), 2);
    assert_eq!(worker.stats().dns_transactions_active, 1);
}

#[test]
fn v1_integration_tcp_mss_clamping_on_intercept_and_reverse() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);

    // Build TCP SYN with MSS = 1460 (kind 2, len 4, val 1460)
    let mut packet = vec![0u8; 44];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&44u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[203, 0, 113, 10]);
    packet[20..22].copy_from_slice(&10001u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 0x60; // 24 bytes TCP header
    packet[33] = 0x02; // SYN
    packet[40] = 2; // Option Kind MSS
    packet[41] = 4; // Option Length 4
    packet[42..44].copy_from_slice(&1460u16.to_be_bytes());
    let packet = finalize_packet(packet);

    let quic_flow = quic_flow(0);
    let handled = worker
        .handle_intercept(intercept, packet, &quic_flow, tunnel)
        .unwrap();

    let tx_packet = &handled.transmit.packet;
    assert_eq!(
        u16::from_be_bytes([tx_packet[42], tx_packet[43]]),
        TCP_MAX_SAFE_MSS
    );

    // Reverse SYN-ACK with MSS = 1460
    let mut reply = vec![0u8; 44];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&44u16.to_be_bytes());
    reply[8] = 64;
    reply[9] = 6;
    reply[12..16].copy_from_slice(&[203, 0, 113, 10]);
    reply[16..20].copy_from_slice(&[192, 0, 2, 1]);
    reply[20..22].copy_from_slice(&443u16.to_be_bytes());
    reply[22..24].copy_from_slice(&40000u16.to_be_bytes());
    reply[32] = 0x60;
    reply[33] = 0x12; // SYN-ACK
    reply[40] = 2;
    reply[41] = 4;
    reply[42..44].copy_from_slice(&1460u16.to_be_bytes());
    let reply = finalize_packet(reply);

    let restored = worker
        .handle_reverse(reply)
        .unwrap()
        .expect("reverse NAT hit");
    assert_eq!(
        u16::from_be_bytes([restored.packet[42], restored.packet[43]]),
        TCP_MAX_SAFE_MSS
    );
}

#[test]
fn v1_integration_tcp_fin_and_rst_accelerate_session_lifecycle() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);

    let quic_flow = quic_flow(0);
    let original = ipv4_tcp_packet(10001);
    let handled = worker
        .handle_intercept(intercept, original, &quic_flow, tunnel)
        .unwrap();

    let session = worker.session(handled.session_id).unwrap();
    assert_eq!(
        session.tcp_state,
        Some(new_proxy::flow_plane::TcpSessionState::Established)
    );

    // Send FIN from client
    let mut fin_forward = ipv4_tcp_packet(10001).to_vec();
    fin_forward[33] = 0x11; // FIN-ACK
    let fin_forward = finalize_packet(fin_forward);
    worker
        .handle_intercept(intercept, fin_forward, &quic_flow, tunnel)
        .unwrap();
    let session = worker.session(handled.session_id).unwrap();
    assert_eq!(
        session.tcp_state,
        Some(new_proxy::flow_plane::TcpSessionState::FinSeenForward)
    );

    // Send FIN from target (reverse)
    let mut fin_reverse = ipv4_tcp_packet(443).to_vec();
    fin_reverse[33] = 0x11; // FIN-ACK
    let reply_tuple = session.nat.translated.reverse();
    new_proxy::flow_plane::rewrite_packet(&mut fin_reverse, &reply_tuple).unwrap();
    let fin_reverse = finalize_packet(fin_reverse);
    worker
        .handle_reverse(fin_reverse)
        .unwrap()
        .expect("reverse NAT hit");

    let session = worker.session(handled.session_id).unwrap();
    assert_eq!(
        session.tcp_state,
        Some(new_proxy::flow_plane::TcpSessionState::Closing)
    );
}

#[test]
fn v1_integration_quic_rebind_flow_preserves_active_tcp_sessions() {
    let mut worker =
        FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40010).unwrap();
    let intercept = IoOwnerKey::new(10, 3);
    let tunnel = IoOwnerKey::new(20, 1);
    let quic_flow_old = quic_flow(0);

    let original = ipv4_tcp_packet(10001);
    let handled = worker
        .handle_intercept(intercept, original, &quic_flow_old, tunnel)
        .unwrap();

    let session_id = handled.session_id;
    assert_eq!(
        worker.session(session_id).unwrap().quic_flow_id,
        quic_flow_old.id()
    );

    // Rebind to new QuicFlowId on reconnect
    let new_flow_id = QuicFlowId(100);
    let rebound_count = worker
        .rebind_quic_flow(quic_flow_old.id(), new_flow_id)
        .unwrap();
    assert_eq!(rebound_count, 1);

    let session_after = worker.session(session_id).unwrap();
    assert_eq!(session_after.quic_flow_id, new_flow_id);

    // Reverse return packet still hits NAT and succeeds
    let mut reply = ipv4_tcp_packet(443).to_vec();
    let reply_tuple = session_after.nat.translated.reverse();
    new_proxy::flow_plane::rewrite_packet(&mut reply, &reply_tuple).unwrap();
    let reply = finalize_packet(reply);
    let restored = worker
        .handle_reverse(reply)
        .unwrap()
        .expect("reverse NAT hit");
    assert_eq!(restored.quic_flow_id, new_flow_id);
    assert_eq!(restored.session_id, session_id);
}
