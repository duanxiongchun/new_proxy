/// Clamps the TCP Maximum Segment Size (MSS) option in IPv4/IPv6 TCP SYN or SYN-ACK packets
/// to a specified maximum value to prevent IP packet fragmentation.
/// Returns true if the packet was modified.
pub fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) -> bool {
    if packet.len() < 20 {
        return false;
    }

    let version = packet[0] >> 4;
    if version == 4 {
        let ihl = (packet[0] & 0x0f) as usize;
        let ip_hdr_len = ihl * 4;
        if packet.len() < ip_hdr_len + 20 {
            return false;
        }
        let protocol = packet[9];
        if protocol != 6 {
            return false;
        }

        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let packet_len = packet.len().min(total_len);
        if packet_len < ip_hdr_len + 20 {
            return false;
        }

        let (ip_hdr, tcp_data) = packet[..packet_len].split_at_mut(ip_hdr_len);
        if modify_tcp_mss(tcp_data, max_mss) {
            calculate_tcp_checksum_ipv4(ip_hdr, tcp_data);
            calculate_ipv4_checksum(ip_hdr);
            return true;
        }
    } else if version == 6 {
        if packet.len() < 40 + 20 {
            return false;
        }
        let next_header = packet[6];
        if next_header != 6 {
            // Skip packets with IPv6 extension headers for simplicity
            return false;
        }

        let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let packet_len = packet.len().min(40 + payload_len);
        if packet_len < 40 + 20 {
            return false;
        }

        let (ip_hdr, tcp_data) = packet[..packet_len].split_at_mut(40);
        if modify_tcp_mss(tcp_data, max_mss) {
            calculate_tcp_checksum_ipv6(ip_hdr, tcp_data);
            return true;
        }
    }

    false
}

fn modify_tcp_mss(tcp_data: &mut [u8], max_mss: u16) -> bool {
    if tcp_data.len() < 20 {
        return false;
    }

    let flags = tcp_data[13];
    let is_syn = (flags & 0x02) != 0;
    if !is_syn {
        return false;
    }

    let data_offset = ((tcp_data[12] >> 4) as usize) * 4;
    if tcp_data.len() < data_offset {
        return false;
    }

    let mut modified = false;
    let mut opt_idx = 20;
    while opt_idx < data_offset {
        let kind = tcp_data[opt_idx];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            opt_idx += 1;
            continue;
        }

        if opt_idx + 1 >= data_offset {
            break;
        }
        let len = tcp_data[opt_idx + 1] as usize;
        if len < 2 || opt_idx + len > data_offset {
            break;
        }

        if kind == 2 {
            if len == 4 {
                let current_mss =
                    u16::from_be_bytes([tcp_data[opt_idx + 2], tcp_data[opt_idx + 3]]);
                if current_mss > max_mss {
                    let bytes = max_mss.to_be_bytes();
                    tcp_data[opt_idx + 2] = bytes[0];
                    tcp_data[opt_idx + 3] = bytes[1];
                    modified = true;
                }
            }
            break;
        }

        opt_idx += len;
    }

    modified
}

fn calculate_ipv4_checksum(ip_header: &mut [u8]) {
    ip_header[10] = 0;
    ip_header[11] = 0;

    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < ip_header.len() {
        sum += u16::from_be_bytes([ip_header[i], ip_header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let bytes = csum.to_be_bytes();
    ip_header[10] = bytes[0];
    ip_header[11] = bytes[1];
}

fn calculate_tcp_checksum_ipv4(ip_header: &[u8], tcp_data: &mut [u8]) {
    tcp_data[16] = 0;
    tcp_data[17] = 0;

    let src_ip = &ip_header[12..16];
    let dst_ip = &ip_header[16..20];
    let proto = 6u16;
    let tcp_len = tcp_data.len() as u16;

    let mut sum = 0u32;
    for i in (0..4).step_by(2) {
        sum += u16::from_be_bytes([src_ip[i], src_ip[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[i], dst_ip[i + 1]]) as u32;
    }
    sum += proto as u32;
    sum += tcp_len as u32;

    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let bytes = csum.to_be_bytes();
    tcp_data[16] = bytes[0];
    tcp_data[17] = bytes[1];
}

fn calculate_tcp_checksum_ipv6(ip_header: &[u8], tcp_data: &mut [u8]) {
    tcp_data[16] = 0;
    tcp_data[17] = 0;

    let src_ip = &ip_header[8..24];
    let dst_ip = &ip_header[24..40];
    let proto = 6u16;
    let tcp_len = tcp_data.len() as u32;

    let mut sum = 0u32;
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src_ip[i], src_ip[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[i], dst_ip[i + 1]]) as u32;
    }
    sum += tcp_len >> 16;
    sum += tcp_len & 0xffff;
    sum += proto as u32;

    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += u16::from_be_bytes([tcp_data[i], tcp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp_data.len() {
        sum += (tcp_data[i] as u32) << 8;
    }

    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let bytes = csum.to_be_bytes();
    tcp_data[16] = bytes[0];
    tcp_data[17] = bytes[1];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mss_clamping_ipv4_syn() {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 44;
        pkt[9] = 0x06;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

        let tcp_offset = 20;
        pkt[tcp_offset] = 0x30;
        pkt[tcp_offset + 1] = 0x39;
        pkt[tcp_offset + 2] = 0x00;
        pkt[tcp_offset + 3] = 0x50;
        pkt[tcp_offset + 12] = 0x60;
        pkt[tcp_offset + 13] = 0x02;

        pkt[tcp_offset + 20] = 2;
        pkt[tcp_offset + 21] = 4;
        pkt[tcp_offset + 22] = 0x05;
        pkt[tcp_offset + 23] = 0xB4;

        let modified = clamp_tcp_mss(&mut pkt, 1160);
        assert!(modified, "Packet should have been modified");
        assert_eq!(pkt[tcp_offset + 22], 0x04);
        assert_eq!(pkt[tcp_offset + 23], 0x88);
    }

    #[test]
    fn test_mss_clamping_ipv4_non_syn() {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 44;
        pkt[9] = 0x06;
        let tcp_offset = 20;
        pkt[tcp_offset + 12] = 0x60;
        pkt[tcp_offset + 13] = 0x10; // ACK only, not SYN

        let modified = clamp_tcp_mss(&mut pkt, 1160);
        assert!(!modified, "Non-SYN packet should not be modified");
    }
}
