use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    #[error("non-initial IP fragments do not contain a complete flow key")]
    NonInitialFragment,
    #[error("IPv6 extension header chain is too long")]
    ExtensionHeaderChainTooLong,
}

pub fn parse_flow_key(packet: &[u8]) -> Result<FlowKey, PacketError> {
    let version = packet.first().ok_or(PacketError::TruncatedIpHeader)? >> 4;
    match version {
        4 => parse_ipv4_flow_key(packet),
        6 => parse_ipv6_flow_key(packet),
        other => Err(PacketError::UnsupportedIpVersion(other)),
    }
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
    if fragment & 0x1fff != 0 {
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
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                if fragment & 0xfff8 != 0 {
                    return Err(PacketError::NonInitialFragment);
                }
                next_header = header[0];
                offset += 8;
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

fn build_flow_key(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    transport: &[u8],
) -> Result<FlowKey, PacketError> {
    let (source_port, destination_port, protocol) = match protocol {
        IP_PROTOCOL_TCP => {
            let ports = transport
                .get(..4)
                .ok_or(PacketError::TruncatedTransportHeader)?;
            (
                u16::from_be_bytes([ports[0], ports[1]]),
                u16::from_be_bytes([ports[2], ports[3]]),
                TransportProtocol::Tcp,
            )
        }
        IP_PROTOCOL_UDP => {
            let ports = transport
                .get(..8)
                .ok_or(PacketError::TruncatedTransportHeader)?;
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
        packet
    }

    #[test]
    fn v1_unit_parse_flow_key_ipv4_tcp() {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());

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
}
