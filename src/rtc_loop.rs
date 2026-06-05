pub fn get_ip_protocol(packet: &[u8]) -> Option<u8> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() >= 20 {
                Some(packet[9])
            } else {
                None
            }
        }
        6 => {
            if packet.len() >= 40 {
                Some(packet[6])
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_classification() {
        let ipv4_tcp_packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            127, 0, 0, 1, 127, 0, 0, 1
        ];
        assert_eq!(get_ip_protocol(&ipv4_tcp_packet), Some(6)); // TCP protocol number is 6
    }
}
