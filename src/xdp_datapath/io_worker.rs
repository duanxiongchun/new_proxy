use crate::flow_plane::{
    bootstrap_owner, parse_flow_key, transaction_key, ActiveDcidIndex, DispatchOutcome,
    FlowDispatcher, FlowMessage, IoOwnerKey, ReverseNatDirectory,
};
use bytes::Bytes;
use ipnet::IpNet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;

const ETHERNET_HEADER_LEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ROUTING: u8 = 43;
const IP_PROTOCOL_FRAGMENT: u8 = 44;
const IP_PROTOCOL_AH: u8 = 51;
const IP_PROTOCOL_DESTINATION_OPTIONS: u8 = 60;
const IP_PROTOCOL_HOP_BY_HOP: u8 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterceptPolicy {
    TunnelPrefixes(Vec<IpNet>),
    DirectPrefixes(Vec<IpNet>),
    All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsLocalResponseClassifier {
    pub resolver: SocketAddr,
    pub nat_ip: IpAddr,
    pub nat_ports: RangeInclusive<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoClassifierConfig {
    pub owner: IoOwnerKey,
    pub tunnel: bool,
    pub intercept: bool,
    pub tunnel_port: u16,
    pub tunnel_local_ips: Vec<IpAddr>,
    pub nat_return_ips: Vec<IpAddr>,
    pub dns_listen: Option<SocketAddr>,
    pub dns_local_response: Option<DnsLocalResponseClassifier>,
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
    UnknownDnsTransaction,
    UnknownNatTuple,
    FragmentedDns,
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
            return IngressOutcome::Passed;
        }

        if !self.config.intercept {
            return IngressOutcome::Passed;
        }
        if self.is_dns_vip_query(&parsed) {
            if parsed.fragmented {
                return IngressOutcome::Dropped(DropReason::FragmentedDns);
            }
            let flow = match parse_flow_key(parsed.ip_packet) {
                Ok(flow) => flow,
                Err(_) => return IngressOutcome::Dropped(DropReason::InvalidFlow),
            };
            let payload = match udp_payload(&parsed) {
                Ok(payload) => payload,
                Err(reason) => return IngressOutcome::Dropped(reason),
            };
            let worker_id = stable_dns_owner(
                self.config.owner,
                &flow,
                payload,
                self.config.flow_worker_count,
            );
            let outcome = self.dispatcher.dispatch_to(
                worker_id,
                FlowMessage::InterceptIngress {
                    io_owner: self.config.owner,
                    packet: Bytes::copy_from_slice(parsed.ip_packet),
                    expected_locator: None,
                },
            );
            return dispatch_outcome(worker_id, outcome);
        }
        if self.is_dns_local_resolver_response(&parsed) {
            if parsed.fragmented {
                return IngressOutcome::Dropped(DropReason::FragmentedDns);
            }
            let flow = match parse_flow_key(parsed.ip_packet) {
                Ok(flow) => flow,
                Err(_) => return IngressOutcome::Dropped(DropReason::InvalidFlow),
            };
            let Some(locator) = reverse_nat.lookup(&flow) else {
                return IngressOutcome::Dropped(DropReason::UnknownDnsTransaction);
            };
            let outcome = self.dispatcher.dispatch_to(
                locator.flow_worker_id,
                FlowMessage::InterceptIngress {
                    io_owner: self.config.owner,
                    packet: Bytes::copy_from_slice(parsed.ip_packet),
                    expected_locator: Some(locator),
                },
            );
            return dispatch_outcome(locator.flow_worker_id, outcome);
        }
        let flow = match parse_flow_key(parsed.ip_packet) {
            Ok(flow) => flow,
            Err(_) => return IngressOutcome::Dropped(DropReason::InvalidFlow),
        };
        if let Some(locator) = reverse_nat.lookup(&flow) {
            let outcome = self.dispatcher.dispatch_to(
                locator.flow_worker_id,
                FlowMessage::InterceptIngress {
                    io_owner: self.config.owner,
                    packet: Bytes::copy_from_slice(parsed.ip_packet),
                    expected_locator: Some(locator),
                },
            );
            return dispatch_outcome(locator.flow_worker_id, outcome);
        }
        if self.config.nat_return_ips.contains(&parsed.destination) {
            return IngressOutcome::Dropped(DropReason::UnknownNatTuple);
        }
        if !self.intercept_allowed(parsed.ip_packet) {
            return IngressOutcome::Passed;
        }
        let worker_id = stable_flow_owner(&flow, self.config.flow_worker_count);
        let outcome = self.dispatcher.dispatch_to(
            worker_id,
            FlowMessage::InterceptIngress {
                io_owner: self.config.owner,
                packet: Bytes::copy_from_slice(parsed.ip_packet),
                expected_locator: None,
            },
        );
        dispatch_outcome(worker_id, outcome)
    }

    fn intercept_allowed(&self, packet: &[u8]) -> bool {
        match &self.config.intercept_policy {
            InterceptPolicy::All => true,
            InterceptPolicy::TunnelPrefixes(prefixes) => {
                destination_ip(packet).is_some_and(|destination| {
                    prefixes.iter().any(|prefix| prefix.contains(&destination))
                })
            }
            InterceptPolicy::DirectPrefixes(prefixes) => {
                destination_ip(packet).is_some_and(|destination| {
                    is_public_destination(destination)
                        && !prefixes.iter().any(|prefix| prefix.contains(&destination))
                })
            }
        }
    }

    fn is_dns_vip_query(&self, parsed: &ParsedIpFrame<'_>) -> bool {
        let Some(listen) = self.config.dns_listen else {
            return false;
        };
        if parsed.destination != listen.ip() || parsed.protocol != IP_PROTOCOL_UDP {
            return false;
        }
        let Some(udp) = parsed
            .ip_packet
            .get(parsed.transport_offset..parsed.transport_offset + 4)
        else {
            return false;
        };
        u16::from_be_bytes([udp[2], udp[3]]) == listen.port()
    }

    fn is_dns_local_resolver_response(&self, parsed: &ParsedIpFrame<'_>) -> bool {
        let Some(classifier) = &self.config.dns_local_response else {
            return false;
        };
        if parsed.source != classifier.resolver.ip()
            || parsed.destination != classifier.nat_ip
            || parsed.protocol != IP_PROTOCOL_UDP
        {
            return false;
        }
        let Some(udp) = parsed
            .ip_packet
            .get(parsed.transport_offset..parsed.transport_offset + 4)
        else {
            return false;
        };
        let source_port = u16::from_be_bytes([udp[0], udp[1]]);
        let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
        source_port == classifier.resolver.port()
            && classifier.nat_ports.contains(&destination_port)
    }
}

fn is_public_destination(destination: IpAddr) -> bool {
    match destination {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            a != 0
                && !address.is_loopback()
                && !address.is_private()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && c == 0)
                && !(a == 192 && b == 0 && c == 2)
                && !(a == 192 && b == 31 && c == 196)
                && !(a == 192 && b == 52 && c == 193)
                && !(a == 192 && b == 88 && c == 99)
                && !(a == 192 && b == 175 && c == 48)
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 198 && b == 51 && c == 100)
                && !(a == 203 && b == 0 && c == 113)
                && a < 240
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && (segments[0] & 0xffc0 != 0xfe80)
                && (segments[0] & 0xffc0 != 0xfec0)
                && (segments[0] & 0xfe00 != 0xfc00)
                && !(segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0xffff)
                && !(segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && !(segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0)
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
    fragmented: bool,
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
    let fragment = u16::from_be_bytes([header[6], header[7]]);
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
        fragmented: fragment & 0x3fff != 0,
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
    let (protocol, transport_offset, fragmented) =
        ipv6_transport_offset(packet, total_len, header[6], 40)?;
    Ok(ParsedIpFrame {
        ip_packet: &packet[..total_len],
        source: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[8..24]).expect("fixed IPv6 source"),
        )),
        destination: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&header[24..40]).expect("fixed IPv6 destination"),
        )),
        protocol,
        transport_offset,
        fragmented,
    })
}

fn ipv6_transport_offset(
    packet: &[u8],
    total_len: usize,
    mut next_header: u8,
    mut offset: usize,
) -> Result<(u8, usize, bool), DropReason> {
    let mut fragmented = false;
    for _ in 0..8 {
        match next_header {
            IP_PROTOCOL_HOP_BY_HOP | IP_PROTOCOL_ROUTING | IP_PROTOCOL_DESTINATION_OPTIONS => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(DropReason::MalformedIp)?;
                next_header = header[0];
                let header_len = (usize::from(header[1]) + 1) * 8;
                offset = offset
                    .checked_add(header_len)
                    .filter(|end| *end <= total_len)
                    .ok_or(DropReason::MalformedIp)?;
            }
            IP_PROTOCOL_FRAGMENT => {
                let header = packet
                    .get(offset..offset + 8)
                    .ok_or(DropReason::MalformedIp)?;
                fragmented = true;
                next_header = header[0];
                offset = offset
                    .checked_add(8)
                    .filter(|end| *end <= total_len)
                    .ok_or(DropReason::MalformedIp)?;
            }
            IP_PROTOCOL_AH => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(DropReason::MalformedIp)?;
                next_header = header[0];
                let header_len = (usize::from(header[1]) + 2) * 4;
                offset = offset
                    .checked_add(header_len)
                    .filter(|end| *end <= total_len)
                    .ok_or(DropReason::MalformedIp)?;
            }
            _ => return Ok((next_header, offset, fragmented)),
        }
    }
    Err(DropReason::MalformedIp)
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

fn stable_dns_owner(
    owner: IoOwnerKey,
    flow: &crate::flow_plane::FlowKey,
    payload: &[u8],
    worker_count: usize,
) -> usize {
    if worker_count == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    owner.hash(&mut hasher);
    transaction_key(SocketAddr::new(flow.source, flow.source_port), payload).hash(&mut hasher);
    (hasher.finish() % worker_count as u64) as usize
}

fn udp_payload<'a>(parsed: &ParsedIpFrame<'a>) -> Result<&'a [u8], DropReason> {
    let udp = parsed
        .ip_packet
        .get(parsed.transport_offset..)
        .ok_or(DropReason::MalformedUdp)?;
    let header = udp.get(..8).ok_or(DropReason::MalformedUdp)?;
    let udp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    udp.get(8..udp_len)
        .filter(|_| udp_len >= 8)
        .ok_or(DropReason::MalformedUdp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_plane::{
        bounded_flow_channels, FlowKey, NatBinding, QuicFlow, QuicFlowId, SessionId,
        SessionLocator, TransportProtocol,
    };

    fn config(tunnel: bool, intercept: bool) -> IoClassifierConfig {
        IoClassifierConfig {
            owner: IoOwnerKey::new(10, 0),
            tunnel,
            intercept,
            tunnel_port: 4433,
            tunnel_local_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20))],
            nat_return_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            dns_listen: None,
            dns_local_response: None,
            dcid_len: 8,
            flow_worker_count: 2,
            intercept_policy: InterceptPolicy::TunnelPrefixes(vec!["203.0.113.0/24"
                .parse()
                .unwrap()]),
        }
    }

    fn indexed_flow() -> QuicFlow {
        QuicFlow::new(QuicFlowId(7), 1, b"io-worker-flow", 4).unwrap()
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

    fn ipv6_udp_hop_frame(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let payload_len = 8 + udp_len;
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + 40 + payload_len];
        frame[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let ip = &mut frame[ETHERNET_HEADER_LEN..];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        ip[6] = IP_PROTOCOL_HOP_BY_HOP;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        ip[24..40].copy_from_slice(
            &Ipv6Addr::from([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
            ])
            .octets(),
        );
        ip[40] = IP_PROTOCOL_UDP;
        ip[41] = 0;
        ip[48..50].copy_from_slice(&source_port.to_be_bytes());
        ip[50..52].copy_from_slice(&destination_port.to_be_bytes());
        ip[52..54].copy_from_slice(&(udp_len as u16).to_be_bytes());
        ip[56..].copy_from_slice(payload);
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
        ip[32] = 0x50;
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
    fn v1_unit_io_worker_five_tuple_stably_distributes_across_lanes() {
        let mut flow = FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            source_port: 10_000,
            destination_port: 443,
            protocol: TransportProtocol::Tcp,
        };
        let owner = stable_flow_owner(&flow, 2);
        assert_eq!(stable_flow_owner(&flow, 2), owner);

        let mut observed = [false; 2];
        for source_port in 10_000..10_100 {
            flow.source_port = source_port;
            observed[stable_flow_owner(&flow, 2)] = true;
        }
        assert_eq!(observed, [true, true]);
    }

    #[test]
    fn v1_unit_io_worker_borrowed_frame_dispatches_owned_ip_packet() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(false, true), dispatcher);
        let frame = inner_tcp_frame([203, 0, 113, 9]);
        let expected = frame[ETHERNET_HEADER_LEN..].to_vec();

        let outcome = worker.handle_frame(
            &frame,
            &ActiveDcidIndex::default(),
            &ReverseNatDirectory::default(),
        );
        drop(frame);

        let worker_id = match outcome {
            IngressOutcome::Dispatched { worker_id } => worker_id,
            other => panic!("unexpected outcome: {other:?}"),
        };
        let FlowMessage::InterceptIngress { packet, .. } = receivers[worker_id].try_recv().unwrap()
        else {
            panic!("expected intercept ingress");
        };
        assert_eq!(packet.as_ref(), expected);
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
    fn v1_unit_io_worker_direct_prefix_policy_redirects_only_public_non_direct() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(false, true);
        worker_config.intercept_policy =
            InterceptPolicy::DirectPrefixes(vec!["203.0.113.0/24".parse().unwrap()]);
        let worker = IoWorker::new(worker_config, dispatcher);

        assert_eq!(
            worker.handle_frame(
                &inner_tcp_frame([203, 0, 113, 9]),
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Passed
        );
        assert!(matches!(
            worker.handle_frame(
                &inner_tcp_frame([8, 8, 8, 8]),
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dispatched { .. }
        ));
        assert_eq!(
            worker.handle_frame(
                &inner_tcp_frame([10, 0, 0, 1]),
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Passed
        );
        assert_eq!(
            receivers.iter().filter_map(|rx| rx.try_recv().ok()).count(),
            1
        );
    }

    #[test]
    fn v1_unit_io_worker_direct_policy_keeps_reserved_ranges_local() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 16).unwrap();
        let mut worker_config = config(false, true);
        worker_config.intercept_policy = InterceptPolicy::DirectPrefixes(vec![]);
        worker_config.nat_return_ips.clear();
        let worker = IoWorker::new(worker_config, dispatcher);

        for destination in [
            [0, 1, 2, 3],
            [192, 0, 2, 1],
            [198, 18, 0, 1],
            [198, 51, 100, 1],
            [203, 0, 113, 1],
            [240, 0, 0, 1],
        ] {
            assert_eq!(
                worker.handle_frame(
                    &inner_tcp_frame(destination),
                    &ActiveDcidIndex::default(),
                    &ReverseNatDirectory::default(),
                ),
                IngressOutcome::Passed
            );
        }
        assert!(receivers
            .iter()
            .all(|receiver| receiver.try_recv().is_err()));

        let ipv6_reserved = "2001:2::1".parse().unwrap();
        let ipv6_public = "2001:2:1::1".parse().unwrap();
        assert!(!is_public_destination(ipv6_reserved));
        assert!(is_public_destination(ipv6_public));
    }

    #[test]
    fn v1_unit_io_worker_unknown_nat_tuple_fails_closed() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(false, true);
        worker_config.intercept_policy = InterceptPolicy::DirectPrefixes(vec![]);
        worker_config
            .nat_return_ips
            .push("198.51.100.20".parse().unwrap());
        let worker = IoWorker::new(worker_config, dispatcher);

        for destination in [[192, 0, 2, 1], [198, 51, 100, 20]] {
            assert_eq!(
                worker.handle_frame(
                    &inner_tcp_frame(destination),
                    &ActiveDcidIndex::default(),
                    &ReverseNatDirectory::default(),
                ),
                IngressOutcome::Dropped(DropReason::UnknownNatTuple)
            );
        }
        assert!(receivers
            .iter()
            .all(|receiver| receiver.try_recv().is_err()));
    }

    #[test]
    fn v1_unit_io_worker_reverse_nat_precedes_forced_local_address() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(false, true);
        worker_config.intercept_policy = InterceptPolicy::DirectPrefixes(vec![]);
        let worker = IoWorker::new(worker_config, dispatcher);
        let binding = NatBinding {
            original: FlowKey {
                source: "10.0.0.2".parse().unwrap(),
                destination: "8.8.8.8".parse().unwrap(),
                source_port: 10000,
                destination_port: 443,
                protocol: TransportProtocol::Tcp,
            },
            translated: FlowKey {
                source: "192.0.2.1".parse().unwrap(),
                destination: "8.8.8.8".parse().unwrap(),
                source_port: 40000,
                destination_port: 443,
                protocol: TransportProtocol::Tcp,
            },
        };
        let mut directory = ReverseNatDirectory::default();
        directory
            .publish(
                &binding,
                SessionLocator {
                    flow_worker_id: 1,
                    session_id: SessionId(42),
                },
            )
            .unwrap();
        let mut frame = inner_tcp_frame([192, 0, 2, 1]);
        let ip = &mut frame[ETHERNET_HEADER_LEN..];
        ip[12..16].copy_from_slice(&[8, 8, 8, 8]);
        ip[20..22].copy_from_slice(&443u16.to_be_bytes());
        ip[22..24].copy_from_slice(&40000u16.to_be_bytes());

        assert_eq!(
            worker.handle_frame(&frame, &ActiveDcidIndex::default(), &directory),
            IngressOutcome::Dispatched { worker_id: 1 }
        );
        assert!(matches!(
            receivers[1].try_recv().unwrap(),
            FlowMessage::InterceptIngress { .. }
        ));
    }

    #[test]
    fn v1_unit_io_worker_dns_vip_query_bypasses_private_direct_policy() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(false, true);
        worker_config.dns_listen = Some("10.0.0.53:53".parse().unwrap());
        worker_config.intercept_policy =
            InterceptPolicy::DirectPrefixes(vec!["10.0.0.0/8".parse().unwrap()]);
        let worker = IoWorker::new(worker_config, dispatcher);
        let mut frame = ipv4_udp_frame(53000, 53, b"dns payload");
        frame[ETHERNET_HEADER_LEN + 16..ETHERNET_HEADER_LEN + 20].copy_from_slice(&[10, 0, 0, 53]);

        assert!(matches!(
            worker.handle_frame(
                &frame,
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dispatched { .. }
        ));
        assert_eq!(
            receivers.iter().filter_map(|rx| rx.try_recv().ok()).count(),
            1
        );
    }

    #[test]
    fn v1_unit_io_worker_dns_vip_fragment_is_dropped() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(false, true);
        worker_config.dns_listen = Some("10.0.0.53:53".parse().unwrap());
        let worker = IoWorker::new(worker_config, dispatcher);
        let mut frame = ipv4_udp_frame(53000, 53, b"dns payload");
        frame[ETHERNET_HEADER_LEN + 6..ETHERNET_HEADER_LEN + 8]
            .copy_from_slice(&0x2000u16.to_be_bytes());
        frame[ETHERNET_HEADER_LEN + 16..ETHERNET_HEADER_LEN + 20].copy_from_slice(&[10, 0, 0, 53]);

        assert_eq!(
            worker.handle_frame(
                &frame,
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dropped(DropReason::FragmentedDns)
        );
        assert_eq!(
            receivers.iter().filter_map(|rx| rx.try_recv().ok()).count(),
            0
        );
    }

    #[test]
    fn v1_unit_io_worker_dns_vip_ipv6_extension_header_is_dispatched() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(false, true);
        worker_config.dns_listen = Some("[2001:db8::53]:53".parse().unwrap());
        let worker = IoWorker::new(worker_config, dispatcher);
        let frame = ipv6_udp_hop_frame(53000, 53, b"dns payload");

        assert!(matches!(
            worker.handle_frame(
                &frame,
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dispatched { .. }
        ));
        assert_eq!(
            receivers.iter().filter_map(|rx| rx.try_recv().ok()).count(),
            1
        );
    }

    #[test]
    fn v1_unit_io_worker_dns_local_resolver_response_uses_reverse_directory() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(false, true);
        worker_config.dns_local_response = Some(DnsLocalResponseClassifier {
            resolver: "192.0.2.53:53".parse().unwrap(),
            nat_ip: "192.0.2.1".parse().unwrap(),
            nat_ports: 40000..=40010,
        });
        worker_config.intercept_policy = InterceptPolicy::TunnelPrefixes(vec![]);
        let worker = IoWorker::new(worker_config, dispatcher);
        let binding = NatBinding {
            original: FlowKey {
                source: "192.0.2.10".parse().unwrap(),
                destination: "192.0.2.53".parse().unwrap(),
                source_port: 53000,
                destination_port: 53,
                protocol: TransportProtocol::Udp,
            },
            translated: FlowKey {
                source: "192.0.2.1".parse().unwrap(),
                destination: "192.0.2.53".parse().unwrap(),
                source_port: 40000,
                destination_port: 53,
                protocol: TransportProtocol::Udp,
            },
        };
        let mut directory = ReverseNatDirectory::default();
        directory
            .publish(
                &binding,
                SessionLocator {
                    flow_worker_id: 1,
                    session_id: SessionId(99),
                },
            )
            .unwrap();
        let mut frame = ipv4_udp_frame(53, 40000, b"dns response");
        frame[ETHERNET_HEADER_LEN + 12..ETHERNET_HEADER_LEN + 16].copy_from_slice(&[192, 0, 2, 53]);
        frame[ETHERNET_HEADER_LEN + 16..ETHERNET_HEADER_LEN + 20].copy_from_slice(&[192, 0, 2, 1]);

        assert_eq!(
            worker.handle_frame(&frame, &ActiveDcidIndex::default(), &directory),
            IngressOutcome::Dispatched { worker_id: 1 }
        );
        assert!(matches!(
            receivers[1].try_recv().unwrap(),
            FlowMessage::InterceptIngress { io_owner, .. } if io_owner == IoOwnerKey::new(10, 0)
        ));

        assert_eq!(
            worker.handle_frame(
                &frame,
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dropped(DropReason::UnknownDnsTransaction)
        );

        let mut wrong_nat = frame.clone();
        wrong_nat[ETHERNET_HEADER_LEN + 16..ETHERNET_HEADER_LEN + 20]
            .copy_from_slice(&[192, 0, 2, 99]);
        assert_eq!(
            worker.handle_frame(
                &wrong_nat,
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Passed
        );

        let mut wrong_port = frame;
        wrong_port[ETHERNET_HEADER_LEN + 22..ETHERNET_HEADER_LEN + 24]
            .copy_from_slice(&39999u16.to_be_bytes());
        assert_eq!(
            worker.handle_frame(
                &wrong_port,
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Dropped(DropReason::UnknownNatTuple)
        );
    }

    #[test]
    fn v1_unit_io_worker_same_interface_prioritizes_outer_quic() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(true, true), dispatcher);
        let dcid = b"12345678";
        let mut index = ActiveDcidIndex::default();
        index.publish_for_flow(dcid, &indexed_flow()).unwrap();
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
    fn v1_unit_io_worker_same_interface_local_non_tunnel_traffic_passes() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let mut worker_config = config(true, true);
        worker_config.intercept_policy = InterceptPolicy::All;
        let worker = IoWorker::new(worker_config, dispatcher);

        assert_eq!(
            worker.handle_frame(
                &inner_tcp_frame([192, 0, 2, 20]),
                &ActiveDcidIndex::default(),
                &ReverseNatDirectory::default(),
            ),
            IngressOutcome::Passed
        );
        assert!(receivers
            .iter()
            .all(|receiver| receiver.try_recv().is_err()));
    }

    #[test]
    fn v1_unit_io_worker_accepts_greased_short_header_for_active_dcid() {
        let (dispatcher, receivers) = bounded_flow_channels(2, 2).unwrap();
        let worker = IoWorker::new(config(true, false), dispatcher);
        let dcid = b"12345678";
        let mut index = ActiveDcidIndex::default();
        index.publish_for_flow(dcid, &indexed_flow()).unwrap();
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
        index.publish_for_flow(dcid, &indexed_flow()).unwrap();
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
