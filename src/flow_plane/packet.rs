use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Range;

const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ROUTING: u8 = 43;
const IP_PROTOCOL_FRAGMENT: u8 = 44;
const IP_PROTOCOL_ESP: u8 = 50;
const IP_PROTOCOL_AH: u8 = 51;
const IP_PROTOCOL_ICMPV6: u8 = 58;
const IP_PROTOCOL_NO_NEXT_HEADER: u8 = 59;
const IP_PROTOCOL_DESTINATION_OPTIONS: u8 = 60;
const IP_PROTOCOL_HOP_BY_HOP: u8 = 0;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: TransportProtocol,
}

impl FlowKey {
    pub fn reverse(&self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            protocol: self.protocol,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PacketError {
    #[error("IP header is truncated")]
    TruncatedIpHeader,
    #[error("IP packet length is invalid")]
    InvalidIpLength,
    #[error("transport header is truncated")]
    TruncatedTransportHeader,
    #[error("IP version {0} is unsupported")]
    UnsupportedIpVersion(u8),
    #[error("IP protocol {0} is unsupported")]
    UnsupportedProtocol(u8),
    #[error("ICMP type {0} is unsupported; v1 supports echo only")]
    UnsupportedIcmpType(u8),
    #[error("fragmented IP packets are unsupported in v1")]
    NonInitialFragment,
    #[error("IPv6 extension header chain is too long")]
    ExtensionHeaderChainTooLong,
    #[error("translated flow uses a different IP version or transport protocol")]
    InvalidTranslation,
    #[error("IP header checksum is invalid")]
    InvalidIpChecksum,
    #[error("transport checksum is invalid")]
    InvalidTransportChecksum,
    #[error("IP packet hop limit is exhausted")]
    HopLimitExceeded,
}

pub fn parse_flow_key(packet: &[u8]) -> Result<FlowKey, PacketError> {
    let version = packet.first().ok_or(PacketError::TruncatedIpHeader)? >> 4;
    match version {
        4 => parse_ipv4_flow_key(packet),
        6 => parse_ipv6_flow_key(packet),
        other => Err(PacketError::UnsupportedIpVersion(other)),
    }
}

pub fn ip_packet_is_fragmented(packet: &[u8]) -> Result<bool, PacketError> {
    let version = packet.first().ok_or(PacketError::TruncatedIpHeader)? >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return Err(PacketError::TruncatedIpHeader);
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len {
                return Err(PacketError::TruncatedIpHeader);
            }
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total_len < header_len || total_len > packet.len() {
                return Err(PacketError::InvalidIpLength);
            }
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            Ok(fragment & 0x3fff != 0)
        }
        6 => {
            if packet.len() < 40 {
                return Err(PacketError::TruncatedIpHeader);
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let total_len = 40usize
                .checked_add(payload_len)
                .ok_or(PacketError::InvalidIpLength)?;
            if total_len > packet.len() {
                return Err(PacketError::InvalidIpLength);
            }
            ipv6_has_fragment_header(packet, total_len, packet[6], 40)
        }
        other => Err(PacketError::UnsupportedIpVersion(other)),
    }
}

pub fn udp_payload(packet: &[u8]) -> Result<&[u8], PacketError> {
    let range = udp_payload_range(packet)?;
    Ok(&packet[range])
}

pub const TCP_MAX_SAFE_MSS: u16 = 1333;

pub fn parse_tcp_flags(packet: &[u8]) -> Result<Option<u8>, PacketError> {
    let (protocol, transport_offset, total_len) = transport_metadata(packet)?;
    if protocol != IP_PROTOCOL_TCP {
        return Ok(None);
    }
    let header = packet
        .get(transport_offset..transport_offset + 20)
        .ok_or(PacketError::TruncatedTransportHeader)?;
    let header_len = usize::from(header[12] >> 4) * 4;
    if header_len < 20 || transport_offset + header_len > total_len {
        return Err(PacketError::TruncatedTransportHeader);
    }
    Ok(Some(header[13]))
}

pub fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> Result<bool, PacketError> {
    let (protocol, transport_offset, total_len) = transport_metadata(packet)?;
    if protocol != IP_PROTOCOL_TCP {
        return Ok(false);
    }
    let header = packet
        .get(transport_offset..transport_offset + 20)
        .ok_or(PacketError::TruncatedTransportHeader)?;
    let flags = header[13];
    if flags & 0x02 == 0 {
        return Ok(false);
    }
    let header_len = usize::from(header[12] >> 4) * 4;
    if header_len < 20 || transport_offset + header_len > total_len {
        return Err(PacketError::TruncatedTransportHeader);
    }
    let mut modified = false;
    let mut opt_offset = transport_offset + 20;
    let opt_end = transport_offset + header_len;
    while opt_offset < opt_end {
        let kind = packet[opt_offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            opt_offset += 1;
            continue;
        }
        if opt_offset + 1 >= opt_end {
            break;
        }
        let len = packet[opt_offset + 1] as usize;
        if len < 2 || opt_offset + len > opt_end {
            break;
        }
        if kind == 2 && len == 4 {
            let current_mss = u16::from_be_bytes([packet[opt_offset + 2], packet[opt_offset + 3]]);
            if current_mss > max_mss {
                packet[opt_offset + 2..opt_offset + 4].copy_from_slice(&max_mss.to_be_bytes());
                modified = true;
            }
        }
        opt_offset += len;
    }
    Ok(modified)
}

pub fn udp_payload_mut(packet: &mut [u8]) -> Result<&mut [u8], PacketError> {
    let range = udp_payload_range(packet)?;
    Ok(&mut packet[range])
}

pub fn ensure_udp_payload_len(packet: &mut Vec<u8>, minimum: usize) -> Result<(), PacketError> {
    let (protocol, transport_offset, total_len) = transport_metadata(packet)?;
    if protocol != IP_PROTOCOL_UDP {
        return Err(PacketError::UnsupportedProtocol(protocol));
    }
    let udp_len = validate_udp_layout(packet, transport_offset, total_len)?;
    let payload_len = udp_len - 8;
    if payload_len >= minimum {
        return Ok(());
    }
    let missing = minimum - payload_len;
    let new_udp_len = udp_len
        .checked_add(missing)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(PacketError::InvalidIpLength)?;
    packet.resize(
        total_len
            .checked_add(missing)
            .ok_or(PacketError::InvalidIpLength)?,
        0,
    );
    packet[transport_offset + 4..transport_offset + 6].copy_from_slice(&new_udp_len.to_be_bytes());
    match packet[0] >> 4 {
        4 => {
            let new_total_len = total_len
                .checked_add(missing)
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(PacketError::InvalidIpLength)?;
            packet[2..4].copy_from_slice(&new_total_len.to_be_bytes());
        }
        6 => {
            let new_payload_len = total_len
                .checked_sub(40)
                .and_then(|length| length.checked_add(missing))
                .and_then(|length| u16::try_from(length).ok())
                .ok_or(PacketError::InvalidIpLength)?;
            packet[4..6].copy_from_slice(&new_payload_len.to_be_bytes());
        }
        version => return Err(PacketError::UnsupportedIpVersion(version)),
    }
    Ok(())
}

pub fn rewrite_packet(packet: &mut [u8], translated: &FlowKey) -> Result<(), PacketError> {
    let original = parse_flow_key(packet)?;
    if original.protocol != translated.protocol
        || !matches!(
            (original.source, translated.source),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
        || !matches!(
            (original.destination, translated.destination),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    {
        return Err(PacketError::InvalidTranslation);
    }

    match (original.source, translated.source) {
        (IpAddr::V4(_), IpAddr::V4(source)) => {
            let destination = match translated.destination {
                IpAddr::V4(destination) => destination,
                IpAddr::V6(_) => return Err(PacketError::InvalidTranslation),
            };
            rewrite_ipv4_packet(packet, source, destination, translated)
        }
        (IpAddr::V6(_), IpAddr::V6(source)) => {
            let destination = match translated.destination {
                IpAddr::V6(destination) => destination,
                IpAddr::V4(_) => return Err(PacketError::InvalidTranslation),
            };
            rewrite_ipv6_packet(packet, source, destination, translated)
        }
        _ => Err(PacketError::InvalidTranslation),
    }
}

pub fn prepare_forwarded_packet(packet: &mut [u8]) -> Result<(), PacketError> {
    if ip_packet_is_fragmented(packet)? {
        return Err(PacketError::NonInitialFragment);
    }
    validate_packet_checksums(packet)?;
    match packet.first().ok_or(PacketError::TruncatedIpHeader)? >> 4 {
        4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len {
                return Err(PacketError::TruncatedIpHeader);
            }
            if packet[8] <= 1 {
                return Err(PacketError::HopLimitExceeded);
            }
            packet[8] -= 1;
            packet[10..12].fill(0);
            let checksum = internet_checksum(&packet[..header_len]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            Ok(())
        }
        6 => {
            if packet.len() < 40 {
                return Err(PacketError::TruncatedIpHeader);
            }
            if packet[7] <= 1 {
                return Err(PacketError::HopLimitExceeded);
            }
            packet[7] -= 1;
            Ok(())
        }
        other => Err(PacketError::UnsupportedIpVersion(other)),
    }
}

fn validate_packet_checksums(packet: &[u8]) -> Result<(), PacketError> {
    let (protocol, transport_offset, total_len) = transport_metadata(packet)?;
    if protocol == IP_PROTOCOL_UDP {
        validate_udp_layout(packet, transport_offset, total_len)?;
    }
    match packet[0] >> 4 {
        4 => {
            if internet_checksum(&packet[..transport_offset]) != 0 {
                return Err(PacketError::InvalidIpChecksum);
            }
            if protocol == IP_PROTOCOL_UDP
                && packet
                    .get(transport_offset + 6..transport_offset + 8)
                    .is_some_and(|checksum| checksum == [0, 0])
            {
                return Ok(());
            }
            let valid = if protocol == IP_PROTOCOL_ICMP {
                internet_checksum(&packet[transport_offset..total_len]) == 0
            } else {
                let mut sum = checksum_add(0, &packet[12..20]);
                sum += u32::from(protocol);
                sum += (total_len - transport_offset) as u32;
                sum = checksum_add(sum, &packet[transport_offset..total_len]);
                checksum_finish(sum) == 0
            };
            if valid {
                Ok(())
            } else {
                Err(PacketError::InvalidTransportChecksum)
            }
        }
        6 => {
            let checksum_offset = checksum_offset(protocol)?;
            if protocol == IP_PROTOCOL_UDP
                && packet
                    .get(transport_offset + checksum_offset..transport_offset + checksum_offset + 2)
                    .is_some_and(|checksum| checksum == [0, 0])
            {
                return Err(PacketError::InvalidTransportChecksum);
            }
            let mut sum = checksum_add(0, &packet[8..40]);
            sum = checksum_add(sum, &((total_len - transport_offset) as u32).to_be_bytes());
            sum = checksum_add(sum, &[0, 0, 0, protocol]);
            sum = checksum_add(sum, &packet[transport_offset..total_len]);
            if checksum_finish(sum) == 0 {
                Ok(())
            } else {
                Err(PacketError::InvalidTransportChecksum)
            }
        }
        other => Err(PacketError::UnsupportedIpVersion(other)),
    }
}

fn udp_payload_range(packet: &[u8]) -> Result<Range<usize>, PacketError> {
    let (protocol, transport_offset, total_len) = transport_metadata(packet)?;
    if protocol != IP_PROTOCOL_UDP {
        return Err(PacketError::UnsupportedProtocol(protocol));
    }
    let udp_len = validate_udp_layout(packet, transport_offset, total_len)?;
    Ok(transport_offset + 8..transport_offset + udp_len)
}

fn validate_udp_layout(
    packet: &[u8],
    transport_offset: usize,
    total_len: usize,
) -> Result<usize, PacketError> {
    let header = packet
        .get(transport_offset..transport_offset + 8)
        .ok_or(PacketError::TruncatedTransportHeader)?;
    let udp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if udp_len < 8 {
        return Err(PacketError::InvalidIpLength);
    }
    let udp_end = transport_offset
        .checked_add(udp_len)
        .filter(|end| *end == total_len)
        .ok_or(PacketError::InvalidIpLength)?;
    if udp_end > packet.len() {
        return Err(PacketError::InvalidIpLength);
    }
    Ok(udp_len)
}

fn transport_metadata(packet: &[u8]) -> Result<(u8, usize, usize), PacketError> {
    let version = packet.first().ok_or(PacketError::TruncatedIpHeader)? >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return Err(PacketError::TruncatedIpHeader);
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len {
                return Err(PacketError::TruncatedIpHeader);
            }
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total_len < header_len || total_len > packet.len() {
                return Err(PacketError::InvalidIpLength);
            }
            Ok((packet[9], header_len, total_len))
        }
        6 => {
            if packet.len() < 40 {
                return Err(PacketError::TruncatedIpHeader);
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            let total_len = 40usize
                .checked_add(payload_len)
                .ok_or(PacketError::InvalidIpLength)?;
            if total_len > packet.len() {
                return Err(PacketError::InvalidIpLength);
            }
            let (protocol, transport_offset) =
                ipv6_transport_offset(packet, total_len, packet[6], 40)?;
            Ok((protocol, transport_offset, total_len))
        }
        other => Err(PacketError::UnsupportedIpVersion(other)),
    }
}

fn rewrite_ipv4_packet(
    packet: &mut [u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    translated: &FlowKey,
) -> Result<(), PacketError> {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    rewrite_transport_fields(&mut packet[header_len..total_len], translated)?;

    packet[10..12].fill(0);
    let header_checksum = internet_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let protocol = packet[9];
    let preserve_zero_udp = protocol == IP_PROTOCOL_UDP
        && packet
            .get(header_len + 6..header_len + 8)
            .is_some_and(|checksum| checksum == [0, 0]);
    if !preserve_zero_udp {
        write_transport_checksum_ipv4(packet, header_len, total_len, protocol)?;
    }
    Ok(())
}

fn rewrite_ipv6_packet(
    packet: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    translated: &FlowKey,
) -> Result<(), PacketError> {
    let total_len = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let (protocol, transport_offset) = ipv6_transport_offset(packet, total_len, packet[6], 40)?;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    rewrite_transport_fields(&mut packet[transport_offset..total_len], translated)?;
    write_transport_checksum_ipv6(packet, transport_offset, total_len, protocol)
}

fn rewrite_transport_fields(transport: &mut [u8], translated: &FlowKey) -> Result<(), PacketError> {
    match translated.protocol {
        TransportProtocol::Tcp | TransportProtocol::Udp => {
            let ports = transport
                .get_mut(..4)
                .ok_or(PacketError::TruncatedTransportHeader)?;
            ports[..2].copy_from_slice(&translated.source_port.to_be_bytes());
            ports[2..4].copy_from_slice(&translated.destination_port.to_be_bytes());
        }
        TransportProtocol::Icmp | TransportProtocol::Icmpv6 => {
            let icmp = transport
                .get_mut(..8)
                .ok_or(PacketError::TruncatedTransportHeader)?;
            let [message_type, code] = translated.destination_port.to_be_bytes();
            icmp[0] = message_type;
            icmp[1] = code;
            icmp[4..6].copy_from_slice(&translated.source_port.to_be_bytes());
        }
    }
    Ok(())
}

fn write_transport_checksum_ipv4(
    packet: &mut [u8],
    transport_offset: usize,
    total_len: usize,
    protocol: u8,
) -> Result<(), PacketError> {
    let checksum_offset = checksum_offset(protocol)?;
    let transport_len = total_len - transport_offset;
    packet[transport_offset + checksum_offset..transport_offset + checksum_offset + 2].fill(0);
    if protocol == IP_PROTOCOL_ICMP {
        let checksum = internet_checksum(&packet[transport_offset..total_len]);
        packet[transport_offset + checksum_offset..transport_offset + checksum_offset + 2]
            .copy_from_slice(&checksum.to_be_bytes());
        return Ok(());
    }
    let mut sum = 0u32;
    sum = checksum_add(sum, &packet[12..20]);
    sum += u32::from(protocol);
    sum += transport_len as u32;
    sum = checksum_add(sum, &packet[transport_offset..total_len]);
    let checksum = encode_udp_zero_checksum(protocol, checksum_finish(sum));
    packet[transport_offset + checksum_offset..transport_offset + checksum_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn write_transport_checksum_ipv6(
    packet: &mut [u8],
    transport_offset: usize,
    total_len: usize,
    protocol: u8,
) -> Result<(), PacketError> {
    let checksum_offset = checksum_offset(protocol)?;
    let transport_len = total_len - transport_offset;
    packet[transport_offset + checksum_offset..transport_offset + checksum_offset + 2].fill(0);
    let mut sum = 0u32;
    sum = checksum_add(sum, &packet[8..40]);
    sum = checksum_add(sum, &(transport_len as u32).to_be_bytes());
    sum = checksum_add(sum, &[0, 0, 0, protocol]);
    sum = checksum_add(sum, &packet[transport_offset..total_len]);
    let checksum = encode_udp_zero_checksum(protocol, checksum_finish(sum));
    packet[transport_offset + checksum_offset..transport_offset + checksum_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn checksum_offset(protocol: u8) -> Result<usize, PacketError> {
    match protocol {
        IP_PROTOCOL_TCP => Ok(16),
        IP_PROTOCOL_UDP => Ok(6),
        IP_PROTOCOL_ICMP | IP_PROTOCOL_ICMPV6 => Ok(2),
        other => Err(PacketError::UnsupportedProtocol(other)),
    }
}

fn encode_udp_zero_checksum(protocol: u8, checksum: u16) -> u16 {
    if protocol == IP_PROTOCOL_UDP && checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_finish(checksum_add(0, bytes))
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

fn parse_ipv4_flow_key(packet: &[u8]) -> Result<FlowKey, PacketError> {
    if packet.len() < 20 {
        return Err(PacketError::TruncatedIpHeader);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Err(PacketError::TruncatedIpHeader);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len > packet.len() {
        return Err(PacketError::InvalidIpLength);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return Err(PacketError::NonInitialFragment);
    }

    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    build_flow_key(
        source,
        destination,
        packet[9],
        &packet[header_len..total_len],
    )
}

fn parse_ipv6_flow_key(packet: &[u8]) -> Result<FlowKey, PacketError> {
    if packet.len() < 40 {
        return Err(PacketError::TruncatedIpHeader);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = 40usize
        .checked_add(payload_len)
        .ok_or(PacketError::InvalidIpLength)?;
    if total_len > packet.len() {
        return Err(PacketError::InvalidIpLength);
    }

    let source = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).expect("fixed IPv6 source slice"),
    ));
    let destination = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[24..40]).expect("fixed IPv6 destination slice"),
    ));
    let (protocol, transport_offset) = ipv6_transport_offset(packet, total_len, packet[6], 40)?;
    build_flow_key(
        source,
        destination,
        protocol,
        &packet[transport_offset..total_len],
    )
}

fn ipv6_transport_offset(
    packet: &[u8],
    total_len: usize,
    mut next_header: u8,
    mut offset: usize,
) -> Result<(u8, usize), PacketError> {
    for _ in 0..8 {
        match next_header {
            IP_PROTOCOL_HOP_BY_HOP | IP_PROTOCOL_ROUTING | IP_PROTOCOL_DESTINATION_OPTIONS => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
                next_header = header[0];
                let header_len = (usize::from(header[1]) + 1) * 8;
                offset = offset
                    .checked_add(header_len)
                    .filter(|end| *end <= total_len)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
            }
            IP_PROTOCOL_FRAGMENT => {
                let header = packet
                    .get(offset..offset + 8)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
                let _ = header;
                return Err(PacketError::NonInitialFragment);
            }
            IP_PROTOCOL_AH => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
                next_header = header[0];
                let header_len = (usize::from(header[1]) + 2) * 4;
                offset = offset
                    .checked_add(header_len)
                    .filter(|end| *end <= total_len)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
            }
            IP_PROTOCOL_ESP | IP_PROTOCOL_NO_NEXT_HEADER => {
                return Err(PacketError::UnsupportedProtocol(next_header));
            }
            _ => return Ok((next_header, offset)),
        }
    }
    Err(PacketError::ExtensionHeaderChainTooLong)
}

fn ipv6_has_fragment_header(
    packet: &[u8],
    total_len: usize,
    mut next_header: u8,
    mut offset: usize,
) -> Result<bool, PacketError> {
    for _ in 0..8 {
        match next_header {
            IP_PROTOCOL_HOP_BY_HOP | IP_PROTOCOL_ROUTING | IP_PROTOCOL_DESTINATION_OPTIONS => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
                next_header = header[0];
                let header_len = (usize::from(header[1]) + 1) * 8;
                offset = offset
                    .checked_add(header_len)
                    .filter(|end| *end <= total_len)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
            }
            IP_PROTOCOL_FRAGMENT => return Ok(true),
            IP_PROTOCOL_AH => {
                let header = packet
                    .get(offset..offset + 2)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
                next_header = header[0];
                let header_len = (usize::from(header[1]) + 2) * 4;
                offset = offset
                    .checked_add(header_len)
                    .filter(|end| *end <= total_len)
                    .ok_or(PacketError::TruncatedTransportHeader)?;
            }
            _ => return Ok(false),
        }
    }
    Err(PacketError::ExtensionHeaderChainTooLong)
}

fn build_flow_key(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    transport: &[u8],
) -> Result<FlowKey, PacketError> {
    let (source_port, destination_port, protocol) = match protocol {
        IP_PROTOCOL_TCP => {
            let header = transport
                .get(..20)
                .ok_or(PacketError::TruncatedTransportHeader)?;
            let header_len = usize::from(header[12] >> 4) * 4;
            if header_len < 20 || header_len > transport.len() {
                return Err(PacketError::TruncatedTransportHeader);
            }
            (
                u16::from_be_bytes([header[0], header[1]]),
                u16::from_be_bytes([header[2], header[3]]),
                TransportProtocol::Tcp,
            )
        }
        IP_PROTOCOL_UDP => {
            let ports = transport
                .get(..8)
                .ok_or(PacketError::TruncatedTransportHeader)?;
            let udp_len = usize::from(u16::from_be_bytes([ports[4], ports[5]]));
            if udp_len < 8 || udp_len != transport.len() {
                return Err(PacketError::InvalidIpLength);
            }
            (
                u16::from_be_bytes([ports[0], ports[1]]),
                u16::from_be_bytes([ports[2], ports[3]]),
                TransportProtocol::Udp,
            )
        }
        IP_PROTOCOL_ICMP | IP_PROTOCOL_ICMPV6 => {
            let icmp = transport
                .get(..8)
                .ok_or(PacketError::TruncatedTransportHeader)?;
            let supported = match protocol {
                IP_PROTOCOL_ICMP => matches!(icmp[0], 0 | 8),
                IP_PROTOCOL_ICMPV6 => matches!(icmp[0], 128 | 129),
                _ => false,
            };
            if !supported || icmp[1] != 0 {
                return Err(PacketError::UnsupportedIcmpType(icmp[0]));
            }
            let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
            let type_and_code = u16::from_be_bytes([icmp[0], icmp[1]]);
            let protocol = if protocol == IP_PROTOCOL_ICMP {
                TransportProtocol::Icmp
            } else {
                TransportProtocol::Icmpv6
            };
            (identifier, type_and_code, protocol)
        }
        other => return Err(PacketError::UnsupportedProtocol(other)),
    };

    Ok(FlowKey {
        source,
        destination,
        source_port,
        destination_port,
        protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ipv4_packet(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let total_len = 20 + transport.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 20]);
        packet[20..].copy_from_slice(transport);
        if protocol == IP_PROTOCOL_UDP && transport.len() >= 8 {
            packet[24..26].copy_from_slice(&(transport.len() as u16).to_be_bytes());
        }
        packet
    }

    fn ipv6_packet(next_header: u8, transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + transport.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
        packet[40..].copy_from_slice(transport);
        if next_header == IP_PROTOCOL_UDP && transport.len() >= 8 {
            packet[44..46].copy_from_slice(&(transport.len() as u16).to_be_bytes());
        }
        packet
    }

    fn ipv6_packet_with_hop_by_hop(next_header: u8, transport: &[u8]) -> Vec<u8> {
        let extension_len = 8;
        let mut packet = vec![0u8; 40 + extension_len + transport.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((extension_len + transport.len()) as u16).to_be_bytes());
        packet[6] = IP_PROTOCOL_HOP_BY_HOP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
        packet[40] = next_header;
        packet[41] = 0;
        packet[48..].copy_from_slice(transport);
        packet
    }

    fn assert_ipv4_checksums(packet: &[u8]) {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        assert_eq!(internet_checksum(&packet[..header_len]), 0);
        if packet[9] == IP_PROTOCOL_ICMP {
            assert_eq!(internet_checksum(&packet[header_len..total_len]), 0);
            return;
        }
        let mut sum = checksum_add(0, &packet[12..20]);
        sum += u32::from(packet[9]);
        sum += (total_len - header_len) as u32;
        sum = checksum_add(sum, &packet[header_len..total_len]);
        assert_eq!(checksum_finish(sum), 0);
    }

    fn assert_ipv6_transport_checksum(packet: &[u8]) {
        let total_len = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        let (protocol, offset) = ipv6_transport_offset(packet, total_len, packet[6], 40).unwrap();
        let mut sum = checksum_add(0, &packet[8..40]);
        sum = checksum_add(sum, &((total_len - offset) as u32).to_be_bytes());
        sum = checksum_add(sum, &[0, 0, 0, protocol]);
        sum = checksum_add(sum, &packet[offset..total_len]);
        assert_eq!(checksum_finish(sum), 0);
    }

    fn finalize_checksums(packet: &mut [u8]) {
        let flow = parse_flow_key(packet).unwrap();
        rewrite_packet(packet, &flow).unwrap();
    }

    #[test]
    fn v1_unit_parse_flow_key_ipv4_tcp() {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;

        let key = parse_flow_key(&ipv4_packet(6, &tcp)).unwrap();

        assert_eq!(
            key,
            FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
                source_port: 12345,
                destination_port: 443,
                protocol: TransportProtocol::Tcp,
            }
        );
    }

    #[test]
    fn v1_unit_parse_flow_key_ipv4_udp() {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());

        let key = parse_flow_key(&ipv4_packet(17, &udp)).unwrap();

        assert_eq!(key.source_port, 5353);
        assert_eq!(key.destination_port, 53);
        assert_eq!(key.protocol, TransportProtocol::Udp);
    }

    #[test]
    fn v1_unit_parse_flow_key_ipv4_icmp_echo() {
        let mut icmp = [0u8; 8];
        icmp[0] = 8;
        icmp[1] = 0;
        icmp[4..6].copy_from_slice(&77u16.to_be_bytes());

        let key = parse_flow_key(&ipv4_packet(1, &icmp)).unwrap();

        assert_eq!(key.source_port, 77);
        assert_eq!(key.destination_port, 8u16 << 8);
        assert_eq!(key.protocol, TransportProtocol::Icmp);
    }

    #[test]
    fn v1_unit_parse_flow_key_ipv6_tcp() {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&23456u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&8443u16.to_be_bytes());
        tcp[12] = 0x50;

        let key = parse_flow_key(&ipv6_packet(6, &tcp)).unwrap();

        assert_eq!(key.source, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(key.destination, "2001:db8::20".parse::<IpAddr>().unwrap());
        assert_eq!(key.source_port, 23456);
        assert_eq!(key.destination_port, 8443);
        assert_eq!(key.protocol, TransportProtocol::Tcp);
    }

    #[test]
    fn v1_unit_parse_flow_key_ipv6_udp() {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&60000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&9000u16.to_be_bytes());

        let key = parse_flow_key(&ipv6_packet(17, &udp)).unwrap();

        assert_eq!(key.source_port, 60000);
        assert_eq!(key.destination_port, 9000);
        assert_eq!(key.protocol, TransportProtocol::Udp);
    }

    #[test]
    fn v1_unit_udp_payload_uses_ipv6_extension_transport_offset() {
        let mut udp = [0u8; 12];
        udp[0..2].copy_from_slice(&60000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&12u16.to_be_bytes());
        udp[8..12].copy_from_slice(b"dns!");
        let packet = ipv6_packet_with_hop_by_hop(IP_PROTOCOL_UDP, &udp);

        assert_eq!(udp_payload(&packet), Ok(&b"dns!"[..]));
        assert!(!ip_packet_is_fragmented(&packet).unwrap());
        assert_eq!(parse_flow_key(&packet).unwrap().destination_port, 53);
    }

    #[test]
    fn v1_unit_ensure_udp_payload_len_uses_ipv6_extension_transport_offset() {
        let mut udp = [0u8; 10];
        udp[0..2].copy_from_slice(&60000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&10u16.to_be_bytes());
        udp[8..10].copy_from_slice(&[0x12, 0x34]);
        let mut packet = ipv6_packet_with_hop_by_hop(IP_PROTOCOL_UDP, &udp);

        ensure_udp_payload_len(&mut packet, 12).unwrap();

        assert_eq!(udp_payload(&packet).unwrap().len(), 12);
        assert_eq!(&udp_payload(&packet).unwrap()[..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([packet[52], packet[53]]), 20);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 28);
    }

    #[test]
    fn v1_unit_ip_packet_is_fragmented_detects_first_fragments() {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&60000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());

        let mut ipv4 = ipv4_packet(IP_PROTOCOL_UDP, &udp);
        ipv4[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(ip_packet_is_fragmented(&ipv4).unwrap());

        let mut fragment = [0u8; 16];
        fragment[0] = IP_PROTOCOL_UDP;
        fragment[8..].copy_from_slice(&udp);
        let ipv6 = ipv6_packet(IP_PROTOCOL_FRAGMENT, &fragment);
        assert!(ip_packet_is_fragmented(&ipv6).unwrap());
    }

    #[test]
    fn v1_unit_parse_flow_key_ipv6_icmp_echo() {
        let mut icmp = [0u8; 8];
        icmp[0] = 128;
        icmp[1] = 0;
        icmp[4..6].copy_from_slice(&88u16.to_be_bytes());

        let key = parse_flow_key(&ipv6_packet(58, &icmp)).unwrap();

        assert_eq!(key.source_port, 88);
        assert_eq!(key.destination_port, 128u16 << 8);
        assert_eq!(key.protocol, TransportProtocol::Icmpv6);
    }

    #[test]
    fn v1_unit_parse_flow_key_rejects_non_echo_icmp() {
        let mut destination_unreachable = [0u8; 8];
        destination_unreachable[0] = 3;
        assert_eq!(
            parse_flow_key(&ipv4_packet(IP_PROTOCOL_ICMP, &destination_unreachable)),
            Err(PacketError::UnsupportedIcmpType(3))
        );

        let mut packet_too_big = [0u8; 8];
        packet_too_big[0] = 2;
        assert_eq!(
            parse_flow_key(&ipv6_packet(IP_PROTOCOL_ICMPV6, &packet_too_big)),
            Err(PacketError::UnsupportedIcmpType(2))
        );
    }

    #[test]
    fn v1_unit_parse_flow_key_rejects_truncated_packets() {
        assert_eq!(
            parse_flow_key(&[0x45, 0, 0]),
            Err(PacketError::TruncatedIpHeader)
        );
        assert_eq!(
            parse_flow_key(&ipv4_packet(17, &[0, 1, 2])),
            Err(PacketError::TruncatedTransportHeader)
        );
    }

    #[test]
    fn v1_unit_parse_flow_key_rejects_tcp_shorter_than_minimum_header() {
        let mut truncated_tcp = [0u8; 17];
        truncated_tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        truncated_tcp[2..4].copy_from_slice(&443u16.to_be_bytes());

        assert_eq!(
            parse_flow_key(&ipv4_packet(IP_PROTOCOL_TCP, &truncated_tcp)),
            Err(PacketError::TruncatedTransportHeader)
        );
        assert_eq!(
            parse_flow_key(&ipv6_packet(IP_PROTOCOL_TCP, &truncated_tcp)),
            Err(PacketError::TruncatedTransportHeader)
        );
    }

    #[test]
    fn v1_unit_prepare_forwarded_packet_validates_checksums_and_decrements_ttl() {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        let mut packet = ipv4_packet(IP_PROTOCOL_TCP, &tcp);
        finalize_checksums(&mut packet);

        prepare_forwarded_packet(&mut packet).unwrap();

        assert_eq!(packet[8], 63);
        assert_ipv4_checksums(&packet);

        packet[30] ^= 1;
        assert_eq!(
            prepare_forwarded_packet(&mut packet),
            Err(PacketError::InvalidTransportChecksum)
        );
    }

    #[test]
    fn v1_unit_prepare_forwarded_packet_rejects_all_fragments() {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());

        let mut ipv4 = ipv4_packet(IP_PROTOCOL_UDP, &udp);
        finalize_checksums(&mut ipv4);
        ipv4[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        ipv4[10..12].fill(0);
        let header_checksum = internet_checksum(&ipv4[..20]);
        ipv4[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        assert_eq!(
            prepare_forwarded_packet(&mut ipv4),
            Err(PacketError::NonInitialFragment)
        );

        let mut ipv6 = ipv6_packet(IP_PROTOCOL_UDP, &udp);
        finalize_checksums(&mut ipv6);
        ipv6.splice(40..40, [IP_PROTOCOL_UDP, 0, 0, 0, 0, 0, 0, 1]);
        ipv6[4..6].copy_from_slice(&16u16.to_be_bytes());
        ipv6[6] = IP_PROTOCOL_FRAGMENT;
        assert_eq!(
            prepare_forwarded_packet(&mut ipv6),
            Err(PacketError::NonInitialFragment)
        );
    }

    #[test]
    fn v1_unit_prepare_forwarded_packet_rejects_bad_ipv4_header_and_exhausted_hops() {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        let mut bad_header = ipv4_packet(IP_PROTOCOL_UDP, &udp);
        finalize_checksums(&mut bad_header);
        bad_header[1] ^= 1;
        assert_eq!(
            prepare_forwarded_packet(&mut bad_header),
            Err(PacketError::InvalidIpChecksum)
        );

        let mut exhausted = ipv4_packet(IP_PROTOCOL_UDP, &udp);
        exhausted[8] = 1;
        finalize_checksums(&mut exhausted);
        assert_eq!(
            prepare_forwarded_packet(&mut exhausted),
            Err(PacketError::HopLimitExceeded)
        );
    }

    #[test]
    fn v1_unit_prepare_forwarded_packet_requires_ipv6_udp_checksum_and_decrements_hop_limit() {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        let mut missing_checksum = ipv6_packet(IP_PROTOCOL_UDP, &udp);
        assert_eq!(
            prepare_forwarded_packet(&mut missing_checksum),
            Err(PacketError::InvalidTransportChecksum)
        );

        let mut packet = ipv6_packet(IP_PROTOCOL_UDP, &udp);
        finalize_checksums(&mut packet);
        prepare_forwarded_packet(&mut packet).unwrap();
        assert_eq!(packet[7], 63);
        assert_ipv6_transport_checksum(&packet);
    }

    #[test]
    fn v1_unit_rewrite_packet_ipv4_tcp_forward_and_reverse_are_checksum_safe() {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        let mut packet = ipv4_packet(IP_PROTOCOL_TCP, &tcp);
        let original = parse_flow_key(&packet).unwrap();
        let translated = FlowKey {
            source: "192.0.2.200".parse().unwrap(),
            source_port: 40000,
            ..original.clone()
        };

        rewrite_packet(&mut packet, &translated).unwrap();
        assert_eq!(parse_flow_key(&packet).unwrap(), translated);
        assert_ipv4_checksums(&packet);

        let restored = original.reverse();
        let translated_reply = translated.reverse();
        let mut reply = packet;
        rewrite_packet(&mut reply, &translated_reply).unwrap();
        rewrite_packet(&mut reply, &restored).unwrap();
        assert_eq!(parse_flow_key(&reply).unwrap(), restored);
        assert_ipv4_checksums(&reply);
    }

    #[test]
    fn v1_unit_rewrite_packet_ipv4_udp_preserves_disabled_checksum() {
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        let mut packet = ipv4_packet(IP_PROTOCOL_UDP, &udp);
        let original = parse_flow_key(&packet).unwrap();
        let translated = FlowKey {
            source: "192.0.2.201".parse().unwrap(),
            source_port: 40001,
            ..original
        };

        rewrite_packet(&mut packet, &translated).unwrap();

        assert_eq!(parse_flow_key(&packet).unwrap(), translated);
        assert_eq!(&packet[26..28], &[0, 0]);
        assert_eq!(internet_checksum(&packet[..20]), 0);
    }

    #[test]
    fn v1_unit_rewrite_packet_ipv4_icmp_updates_identifier_and_checksum() {
        let mut icmp = [0u8; 8];
        icmp[0] = 8;
        icmp[4..6].copy_from_slice(&77u16.to_be_bytes());
        let mut packet = ipv4_packet(IP_PROTOCOL_ICMP, &icmp);
        let original = parse_flow_key(&packet).unwrap();
        let translated = FlowKey {
            source: "192.0.2.202".parse().unwrap(),
            source_port: 40002,
            ..original
        };

        rewrite_packet(&mut packet, &translated).unwrap();

        assert_eq!(parse_flow_key(&packet).unwrap(), translated);
        assert_ipv4_checksums(&packet);
    }

    #[test]
    fn v1_unit_rewrite_packet_ipv6_tcp_udp_and_icmpv6_are_checksum_safe() {
        let cases = [
            (IP_PROTOCOL_TCP, 20usize, TransportProtocol::Tcp),
            (IP_PROTOCOL_UDP, 8usize, TransportProtocol::Udp),
            (IP_PROTOCOL_ICMPV6, 8usize, TransportProtocol::Icmpv6),
        ];
        for (protocol, transport_len, expected_protocol) in cases {
            let mut transport = vec![0u8; transport_len];
            match expected_protocol {
                TransportProtocol::Tcp | TransportProtocol::Udp => {
                    transport[0..2].copy_from_slice(&12345u16.to_be_bytes());
                    transport[2..4].copy_from_slice(&443u16.to_be_bytes());
                    if expected_protocol == TransportProtocol::Tcp {
                        transport[12] = 0x50;
                    }
                }
                TransportProtocol::Icmpv6 => {
                    transport[0] = 128;
                    transport[4..6].copy_from_slice(&77u16.to_be_bytes());
                }
                TransportProtocol::Icmp => unreachable!(),
            }
            let mut packet = ipv6_packet(protocol, &transport);
            let original = parse_flow_key(&packet).unwrap();
            let translated = FlowKey {
                source: "2001:db8:ffff::1".parse().unwrap(),
                source_port: 40000,
                ..original
            };

            rewrite_packet(&mut packet, &translated).unwrap();

            assert_eq!(parse_flow_key(&packet).unwrap(), translated);
            assert_ipv6_transport_checksum(&packet);
        }
    }
    #[test]
    fn v1_unit_quic_safe_tcp_mss_fits_ipv4_and_ipv6_in_one_datagram() {
        assert_eq!(TCP_MAX_SAFE_MSS, 1333);
        assert!(usize::from(TCP_MAX_SAFE_MSS) + 40 + 20 <= 1393);
        assert!(usize::from(TCP_MAX_SAFE_MSS) + 20 + 20 <= 1393);
    }

    #[test]
    fn v1_unit_clamp_tcp_mss_rewrites_syn_options_above_limit() {
        let mut tcp = vec![0u8; 24];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x60; // 24 bytes header (6 * 4)
        tcp[13] = 0x02; // SYN
        tcp[20] = 2; // Option Kind 2 (MSS)
        tcp[21] = 4; // Option Len 4
        tcp[22..24].copy_from_slice(&1460u16.to_be_bytes());

        let mut packet = ipv4_packet(IP_PROTOCOL_TCP, &tcp);
        assert_eq!(parse_tcp_flags(&packet), Ok(Some(0x02)));
        assert_eq!(clamp_tcp_mss(&mut packet, 1360), Ok(true));
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 1360);

        let mut no_syn = packet.clone();
        no_syn[33] = 0x10; // ACK only
        assert_eq!(clamp_tcp_mss(&mut no_syn, 1200), Ok(false));

        let mut small_mss = packet.clone();
        small_mss[42..44].copy_from_slice(&1200u16.to_be_bytes());
        assert_eq!(clamp_tcp_mss(&mut small_mss, 1360), Ok(false));
    }
}
