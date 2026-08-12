use crate::flow_plane::{
    bootstrap_owner, parse_flow_key, ActiveDcidIndex, DispatchOutcome, FlowDispatcher, FlowMessage,
    IoOwnerKey, ReverseNatDirectory,
};
use bytes::Bytes;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const ETHERNET_HEADER_LEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IP_PROTOCOL_UDP: u8 = 17;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterceptPolicy {
    AllowedIps(Vec<IpNet>),
    All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoClassifierConfig {
    pub owner: IoOwnerKey,
    pub tunnel: bool,
    pub intercept: bool,
    pub tunnel_port: u16,
    pub tunnel_local_ips: Vec<IpAddr>,
    pub dcid_len: usize,
    pub flow_worker_count: usize,
    pub intercept_policy: InterceptPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DropReason {
    MalformedEthernet,
    MalformedIp,
    MalformedUdp,
    InvalidQuic,
    UnknownDcid,
    InvalidFlow,
    DispatchRejected(DispatchOutcome),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressOutcome {
    Passed,
    Dispatched { worker_id: usize },
    Dropped(DropReason),
}

pub struct IoWorker {
    config: IoClassifierConfig,
    dispatcher: FlowDispatcher,
}

impl IoWorker {
    pub fn new(config: IoClassifierConfig, dispatcher: FlowDispatcher) -> Self {
        Self { config, dispatcher }
    }

    pub fn handle_frame(
        &self,
        frame: &[u8],
        active_dcids: &ActiveDcidIndex,
        reverse_nat: &ReverseNatDirectory,
    ) -> IngressOutcome {
        let parsed = match parse_ip_frame(frame) {
            Ok(parsed) => parsed,
            Err(reason) => return IngressOutcome::Dropped(reason),
        };

        if self.config.tunnel && self.config.tunnel_local_ips.contains(&parsed.destination) {
            match parse_outer_quic(&parsed, self.config.tunnel_port, self.config.dcid_len) {
                Ok(Some(outer)) => {
                    log::trace!(
                        "outer QUIC owner={:?} dcid={:02x?} bootstrap={} bytes={}",
                        self.config.owner,
                        outer.dcid,
                        outer.bootstrap,
                        outer.payload.len()
                    );
                    let worker_id = match active_dcids.resolve(&outer.dcid) {
                        Some(owner) => owner.flow_worker_id,
                        None if outer.bootstrap => {
                            match bootstrap_owner(&outer.dcid, self.config.flow_worker_count) {
                                Ok(worker_id) => worker_id,
                                Err(_) => {
                                    return IngressOutcome::Dropped(DropReason::InvalidQuic);
                                }
                            }
                        }
                        None => return IngressOutcome::Dropped(DropReason::UnknownDcid),
                    };
                    let outcome = self.dispatcher.dispatch_to(
                        worker_id,
                        FlowMessage::TunnelIngress {
                            io_owner: self.config.owner,
                            dcid: outer.dcid,
                            remote: outer.remote,
                            local_ip: outer.local_ip,
                            packet: outer.payload,
                        },
                    );
                    return dispatch_outcome(worker_id, outcome);
                }
                Ok(None) => {}
                Err(reason) => {
                    let payload = parsed
                        .ip_packet
                        .get(parsed.transport_offset + 8..)
                        .unwrap_or_default();
                    log::trace!(
                        "outer QUIC rejected owner={:?} reason={reason:?} bytes={} prefix={:02x?}",
                        self.config.owner,
                        payload.len(),
                        &payload[..payload.len().min(16)]
                    );
                    return IngressOutcome::Dropped(reason);
                }
            }
        }

        if !self.config.intercept || !self.intercept_allowed(parsed.ip_packet) {
            return IngressOutcome::Passed;
        }
        let flow = match parse_flow_key(parsed.ip_packet) {
            Ok(flow) => flow,
            Err(_) => return IngressOutcome::Dropped(DropReason::InvalidFlow),
        };
        let worker_id = reverse_nat
            .lookup(&flow)
            .map(|locator| locator.flow_worker_id)
            .unwrap_or_else(|| stable_flow_owner(&flow, self.config.flow_worker_count));
        let outcome = self.dispatcher.dispatch_to(
            worker_id,
            FlowMessage::InterceptIngress {
                io_owner: self.config.owner,
                packet: Bytes::copy_from_slice(parsed.ip_packet),
            },
        );
        dispatch_outcome(worker_id, outcome)
    }

    fn intercept_allowed(&self, packet: &[u8]) -> bool {
        match &self.config.intercept_policy {
            InterceptPolicy::All => true,
            InterceptPolicy::AllowedIps(prefixes) => {
                destination_ip(packet).is_some_and(|destination| {
                    prefixes.iter().any(|prefix| prefix.contains(&destination))
                })
            }
        }
    }
}

fn dispatch_outcome(worker_id: usize, outcome: DispatchOutcome) -> IngressOutcome {
    match outcome {
        DispatchOutcome::Accepted => IngressOutcome::Dispatched { worker_id },
        other => IngressOutcome::Dropped(DropReason::DispatchRejected(other)),
    }
}

struct ParsedIpFrame<'a> {
    ip_packet: &'a [u8],
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    transport_offset: usize,
}

fn parse_ip_frame(frame: &[u8]) -> Result<ParsedIpFrame<'_>, DropReason> {
    let ethernet = frame
        .get(..ETHERNET_HEADER_LEN)
        .ok_or(DropReason::MalformedEthernet)?;
    let ether_type = u16::from_be_bytes([ethernet[12], ethernet[13]]);
    let packet = &frame[ETHERNET_HEADER_LEN..];
    match ether_type {
        ETH_P_IPV4 => parse_ipv4_frame(packet),
        ETH_P_IPV6 => parse_ipv6_frame(packet),
        _ => Err(DropReason::MalformedIp),
    }
}

fn parse_ipv4_frame(packet: &[u8]) -> Result<ParsedIpFrame<'_>, DropReason> {
    let header = packet.get(..20).ok_or(DropReason::MalformedIp)?;
    if header[0] >> 4 != 4 {
        return Err(DropReason::MalformedIp);
    }
    let header_len = usize::from(header[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if header_len < 20 || total_len < header_len || packet.len() < total_len {
        return Err(DropReason::MalformedIp);
    }
    Ok(ParsedIpFrame {
        ip_packet: &packet[..total_len],
        source: IpAddr::V4(Ipv4Addr::new(
            header[12], header[13], header[14], header[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            header[16], header[17], header[18], header[19],
        )),
        protocol: header[9],
        transport_offset: header_len,
    })
}

fn parse_ipv6_frame(packet: &[u8]) -> Result<ParsedIpFrame<'_>, DropReason> {
    let header = packet.get(..40).ok_or(DropReason::MalformedIp)?;
    if header[0] >> 4 != 6 {
        return Err(DropReason::MalformedIp);
    }
    let total_len = 40usize
        .checked_add(usize::from(u16::from_be_bytes([header[4], header[5]])))
        .filter(|length| *length <= packet.len())
        .ok_or(DropReason::MalformedIp)?;
    Ok(ParsedIpFrame {
        ip_packet: &packet[..total_len],
        source: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[8..24]).expect("fixed IPv6 source"),
        )),
        destination: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[24..40]).expect("fixed IPv6 destination"),
        )),
        protocol: header[6],
        transport_offset: 40,
    })
}

struct OuterQuic {
    dcid: Bytes,
    remote: SocketAddr,
    local_ip: IpAddr,
    payload: Bytes,
    bootstrap: bool,
}

fn parse_outer_quic(
    frame: &ParsedIpFrame<'_>,
    tunnel_port: u16,
    fixed_dcid_len: usize,
) -> Result<Option<OuterQuic>, DropReason> {
    if frame.protocol != IP_PROTOCOL_UDP {
        return Ok(None);
    }
    let udp = frame
        .ip_packet
        .get(frame.transport_offset..)
        .ok_or(DropReason::MalformedUdp)?;
    let header = udp.get(..8).ok_or(DropReason::MalformedUdp)?;
    let source_port = u16::from_be_bytes([header[0], header[1]]);
    let destination_port = u16::from_be_bytes([header[2], header[3]]);
    if destination_port != tunnel_port {
        return Ok(None);
    }
    let udp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let payload = udp
        .get(8..udp_len)
        .filter(|_| udp_len >= 8)
        .ok_or(DropReason::MalformedUdp)?;
    let (dcid, bootstrap) = parse_quic_dcid(payload, fixed_dcid_len)?;
    Ok(Some(OuterQuic {
        dcid,
        remote: SocketAddr::new(frame.source, source_port),
        local_ip: frame.destination,
        payload: Bytes::copy_from_slice(payload),
        bootstrap,
    }))
}

fn parse_quic_dcid(packet: &[u8], fixed_len: usize) -> Result<(Bytes, bool), DropReason> {
    let first = *packet.first().ok_or(DropReason::InvalidQuic)?;
    if fixed_len == 0 || fixed_len > 20 {
        return Err(DropReason::InvalidQuic);
    }
    if first & 0x80 != 0 {
        packet.get(1..5).ok_or(DropReason::InvalidQuic)?;
        let dcid_len = usize::from(*packet.get(5).ok_or(DropReason::InvalidQuic)?);
        if dcid_len == 0 || dcid_len > 20 {
            return Err(DropReason::InvalidQuic);
        }
        let dcid =
            Bytes::copy_from_slice(packet.get(6..6 + dcid_len).ok_or(DropReason::InvalidQuic)?);
        let packet_type = (first >> 4) & 0x03;
        Ok((dcid, packet_type == 0))
    } else {
        Ok((
            Bytes::copy_from_slice(
                packet
                    .get(1..1 + fixed_len)
                    .ok_or(DropReason::InvalidQuic)?,
            ),
            false,
        ))
    }
}

fn destination_ip(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            *packet.get(16)?,
            *packet.get(17)?,
            *packet.get(18)?,
            *packet.get(19)?,
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(packet.get(24..40)?).ok()?,
        ))),
        _ => None,
    }
}

fn stable_flow_owner(flow: &crate::flow_plane::FlowKey, worker_count: usize) -> usize {
    if worker_count == 0 {
        return 0;
    }
    let mut bytes = Vec::with_capacity(40);
    match flow.source {
        IpAddr::V4(address) => bytes.extend_from_slice(&address.octets()),
        IpAddr::V6(address) => bytes.extend_from_slice(&address.octets()),
    }
    match flow.destination {
        IpAddr::V4(address) => bytes.extend_from_slice(&address.octets()),
        IpAddr::V6(address) => bytes.extend_from_slice(&address.octets()),
    }
    bytes.extend_from_slice(&flow.source_port.to_be_bytes());
    bytes.extend_from_slice(&flow.destination_port.to_be_bytes());
    bytes.push(flow.protocol as u8);
    let hash = bytes.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    });
    (hash % worker_count as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_plane::{bounded_flow_channels, DcidOwner, QuicFlowId};

    fn config(tunnel: bool, intercept: bool) -> IoClassifierConfig {
        IoClassifierConfig {
            owner: IoOwnerKey::new(10, 0),
            tunnel,
            intercept,
            tunnel_port: 4433,
            tunnel_local_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))],
            dcid_len: 8,
            flow_worker_count: 2,
            intercept_policy: InterceptPolicy::AllowedIps(vec!["203.0.113.0/24".parse().unwrap()]),
        }
    }

    fn ipv4_udp_frame(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + total_len];
        frame[12..14].copy_from_slice(&ETH_P_IPV4.to_be_bytes());
        let ip = &mut frame[ETHERNET_HEADER_LEN..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = IP_PROTOCOL_UDP;
        ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
        ip[16..20].copy_from_slice(&[192, 0, 2, 20]);
        ip[20..22].copy_from_slice(&source_port.to_be_bytes());
        ip[22..24].copy_from_slice(&destination_port.to_be_bytes());
        ip[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        ip[28..].copy_from_slice(payload);
        frame
    }

    fn inner_tcp_frame(destination: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + 40];
        frame[12..14].copy_from_slice(&ETH_P_IPV4.to_be_bytes());
        let ip = &mut frame[ETHERNET_HEADER_LEN..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
        ip[16..20].copy_from_slice(&destination);
        ip[20..22].copy_from_slice(&10000u16.to_be_bytes());
        ip[22..24].copy_from_slice(&443u16.to_be_bytes());
        frame
    }

    #[test]
    fn v1_unit_io_worker_allowed_intercept_is_dispatched() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(false, true), dispatcher);

        let outcome = worker.handle_frame(
            &inner_tcp_frame([203, 0, 113, 9]),
            &ActiveDcidIndex::default(),
            &ReverseNatDirectory::default(),
        );

        let worker_id = match outcome {
            IngressOutcome::Dispatched { worker_id } => worker_id,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert!(matches!(
            receivers[worker_id].try_recv().unwrap(),
            FlowMessage::InterceptIngress { io_owner, .. } if io_owner == IoOwnerKey::new(10, 0)
        ));
    }

    #[test]
    fn v1_unit_io_worker_non_allowed_intercept_passes() {
        let (dispatcher, _) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(false, true), dispatcher);

        assert_eq!(
            worker.handle_frame(
                &inner_tcp_frame([198, 51, 100, 9]),
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Passed
        );
    }

    #[test]
    fn v1_unit_io_worker_same_interface_prioritizes_outer_quic() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(true, true), dispatcher);
        let dcid = b"12345678";
        let mut index = ActiveDcidIndex::default();
        index
            .publish(
                dcid,
                DcidOwner {
                    flow_worker_id: 1,
                    quic_flow_id: QuicFlowId(7),
                },
            )
            .unwrap();
        let mut short = vec![0x40];
        short.extend_from_slice(dcid);
        short.extend_from_slice(b"ciphertext");

        assert_eq!(
            worker.handle_frame(
                &ipv4_udp_frame(50000, 4433, &short),
                &index,
                &ReverseNatDirectory::default()
            ),
            IngressOutcome::Dispatched { worker_id: 1 }
        );
        assert!(matches!(
            receivers[1].try_recv().unwrap(),
            FlowMessage::TunnelIngress { dcid: received, .. } if received.as_ref() == dcid
        ));
    }

    #[test]
    fn v1_unit_io_worker_same_interface_tunnel_port_to_remote_ip_is_intercepted() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(true, true);
        worker_config.intercept_policy = InterceptPolicy::All;
        let worker = IoWorker::new(worker_config, dispatcher);
        let frame = ipv4_udp_frame(50000, 4433, b"ordinary application datagram");
        let ip = &mut frame[ETHERNET_HEADER_LEN..].to_vec();
        ip[16..20].copy_from_slice(&[203, 0, 113, 20]);
        let mut frame = frame;
        frame[ETHERNET_HEADER_LEN..].copy_from_slice(ip);

        let outcome = worker.handle_frame(
            &frame,
            &ActiveDcidIndex::default(),
            &ReverseNatDirectory::default(),
        );

        let worker_id = match outcome {
            IngressOutcome::Dispatched { worker_id } => worker_id,
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert!(matches!(
            receivers[worker_id].try_recv().unwrap(),
            FlowMessage::InterceptIngress { .. }
        ));
    }

    #[test]
    fn v1_unit_io_worker_accepts_greased_short_header_for_active_dcid() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(true, false), dispatcher);
        let dcid = b"12345678";
        let mut index = ActiveDcidIndex::default();
        index
            .publish(
                dcid,
                DcidOwner {
                    flow_worker_id: 1,
                    quic_flow_id: QuicFlowId(7),
                },
            )
            .unwrap();
        let mut short = vec![0x00];
        short.extend_from_slice(dcid);
        short.extend_from_slice(b"ciphertext");

        assert_eq!(
            worker.handle_frame(
                &ipv4_udp_frame(50000, 4433, &short),
                &index,
                &ReverseNatDirectory::default()
            ),
            IngressOutcome::Dispatched { worker_id: 1 }
        );
        assert!(matches!(
            receivers[1].try_recv().unwrap(),
            FlowMessage::TunnelIngress { dcid: received, .. } if received.as_ref() == dcid
        ));
    }

    #[test]
    fn v1_unit_io_worker_accepts_greased_long_header_for_active_dcid() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(true, false), dispatcher);
        let dcid = b"12345678";
        let mut index = ActiveDcidIndex::default();
        index
            .publish(
                dcid,
                DcidOwner {
                    flow_worker_id: 1,
                    quic_flow_id: QuicFlowId(7),
                },
            )
            .unwrap();
        let mut long = vec![0xa0, 0, 0, 0, 1, 8];
        long.extend_from_slice(dcid);
        long.push(0);

        assert_eq!(
            worker.handle_frame(
                &ipv4_udp_frame(50000, 4433, &long),
                &index,
                &ReverseNatDirectory::default()
            ),
            IngressOutcome::Dispatched { worker_id: 1 }
        );
        assert!(matches!(
            receivers[1].try_recv().unwrap(),
            FlowMessage::TunnelIngress { dcid: received, .. } if received.as_ref() == dcid
        ));
    }

    #[test]
    fn v1_unit_io_worker_only_long_initial_bootstraps_unknown_dcid() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(true, false), dispatcher);
        let mut initial = vec![0xc0, 0, 0, 0, 1, 8];
        initial.extend_from_slice(b"abcdefgh");
        initial.push(0);

        assert!(matches!(
            worker.handle_frame(
                &ipv4_udp_frame(50000, 4433, &initial),
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dispatched { .. }
        ));
        assert_eq!(
            receivers.iter().filter_map(|rx| rx.try_recv().ok()).count(),
            1
        );

        let mut short = vec![0x40];
        short.extend_from_slice(b"unknown!");
        assert_eq!(
            worker.handle_frame(
                &ipv4_udp_frame(50000, 4433, &short),
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dropped(DropReason::UnknownDcid)
        );
    }

    #[test]
    fn v1_unit_io_worker_reverse_nat_uses_session_owner_before_flow_hash() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(false, true), dispatcher);
        let frame = inner_tcp_frame([203, 0, 113, 9]);
        let parsed = parse_ip_frame(&frame).unwrap();
        let flow = parse_flow_key(parsed.ip_packet).unwrap();
        let translated = crate::flow_plane::NatBinding {
            original: flow.clone(),
            translated: flow.reverse(),
        };
        let mut reverse_nat = ReverseNatDirectory::default();
        reverse_nat
            .publish(
                &translated,
                crate::flow_plane::SessionLocator {
                    flow_worker_id: 1,
                    session_id: crate::flow_plane::SessionId(7),
                },
            )
            .unwrap();

        assert_eq!(
            worker.handle_frame(&frame, &ActiveDcidIndex::default(), &reverse_nat),
            IngressOutcome::Dispatched { worker_id: 1 }
        );
        assert!(receivers[1].try_recv().is_ok());
        assert!(receivers[0].try_recv().is_err());
    }
}
