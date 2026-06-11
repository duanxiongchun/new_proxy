use crate::config::{self, GatewayConfig};
use crate::control;
use crate::routing::AllowedIPsRouter;
use crate::telemetry::WgPeerStats;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    Server,
    Client,
}

pub fn encode_base64_32(bytes: &[u8; 32]) -> String {
    let mut out = String::new();
    let mut temp = 0u32;
    let mut bits = 0;
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for &b in bytes {
        temp = (temp << 8) | b as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(chars[((temp >> bits) & 0x3F) as usize] as char);
        }
    }
    if bits > 0 {
        temp <<= 6 - bits;
        out.push(chars[(temp & 0x3F) as usize] as char);
    }
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

pub fn interface_name_from_config_path(config_path: &str) -> Result<String, String> {
    let name = std::path::Path::new(config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("tun0")
        .to_string();
    validate_interface_name(&name)?;
    Ok(name)
}

fn validate_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!(
            "Invalid interface name '{}': Linux interface names must be 1..=15 bytes",
            name
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
    {
        return Err(format!(
            "Invalid interface name '{}': allowed characters are [A-Za-z0-9_.:-]",
            name
        ));
    }
    Ok(())
}

pub fn api_socket_path(interface_name: &str) -> String {
    format!("/run/new_proxy/{}.sock", interface_name)
}

pub fn validate_gateway_config(config: &GatewayConfig) -> Result<RuntimeMode, String> {
    if let Some(table) = config.interface.table.as_deref() {
        if !table.eq_ignore_ascii_case("auto") && !table.eq_ignore_ascii_case("off") {
            return Err(format!(
                "Invalid Table value '{}': expected auto or off",
                table
            ));
        }
    }
    let mut seen_quic_ports = HashSet::new();
    for port in &config.quic_pool.listen_ports {
        if !seen_quic_ports.insert(*port) {
            return Err(format!("Duplicate QUICPool ListenPorts entry: {}", port));
        }
    }
    let mut seen_peer_keys = HashSet::new();
    let mut seen_allowed_ips: HashMap<ipnet::IpNet, [u8; 32]> = HashMap::new();
    for peer in &config.peers {
        if !seen_peer_keys.insert(peer.public_key) {
            return Err(format!(
                "Duplicate Peer PublicKey: {}",
                encode_base64_32(&peer.public_key)
            ));
        }
        if peer.allowed_ips.is_empty() {
            return Err(format!(
                "Peer {} has no AllowedIPs",
                encode_base64_32(&peer.public_key)
            ));
        }
        for allowed_ip in &peer.allowed_ips {
            if let Some(existing_peer) = seen_allowed_ips.get(allowed_ip) {
                return Err(format!(
                    "Duplicate AllowedIPs entry {} used by peers {} and {}",
                    allowed_ip,
                    encode_base64_32(existing_peer),
                    encode_base64_32(&peer.public_key)
                ));
            }
            for (existing_ip, existing_peer) in &seen_allowed_ips {
                if ipnets_overlap(*allowed_ip, *existing_ip) {
                    return Err(format!(
                        "Overlapping AllowedIPs entries {} and {} used by peers {} and {}",
                        existing_ip,
                        allowed_ip,
                        encode_base64_32(existing_peer),
                        encode_base64_32(&peer.public_key)
                    ));
                }
            }
            seen_allowed_ips.insert(*allowed_ip, peer.public_key);
        }
    }
    determine_runtime_mode(config)
}

fn ipnets_overlap(a: ipnet::IpNet, b: ipnet::IpNet) -> bool {
    match (a, b) {
        (ipnet::IpNet::V4(a), ipnet::IpNet::V4(b)) => {
            a.contains(&b.network()) || b.contains(&a.network())
        }
        (ipnet::IpNet::V6(a), ipnet::IpNet::V6(b)) => {
            a.contains(&b.network()) || b.contains(&a.network())
        }
        _ => false,
    }
}

pub fn determine_runtime_mode(config: &GatewayConfig) -> Result<RuntimeMode, String> {
    let server_mode =
        config.interface.listen_control_port.is_some() || !config.quic_pool.listen_ports.is_empty();
    if server_mode {
        if config.interface.listen_control_port.is_none() && config.interface.listen_port.is_none()
        {
            return Err(
                "Invalid server config: Either ListenControlPort or ListenPort must be set when QUICPool.ListenPorts is set"
                    .to_string(),
            );
        }
        if config.quic_pool.listen_ports.is_empty() {
            return Err(
                "Invalid server config: QUICPool.ListenPorts must contain at least one port"
                    .to_string(),
            );
        }
        return Ok(RuntimeMode::Server);
    }

    if config.peers.is_empty() {
        return Err("Invalid client config: at least one [Peer] is required".to_string());
    }
    for peer in &config.peers {
        if peer.proxy_port.is_some() && peer.endpoint.is_none() {
            return Err(format!(
                "Invalid client config: peer {} specifies ProxyPort but is missing Endpoint",
                encode_base64_32(&peer.public_key)
            ));
        }
    }
    Ok(RuntimeMode::Client)
}

pub fn peer_has_l4_proxy(peer: &config::PeerConfig) -> bool {
    peer.endpoint.is_some()
}

pub fn rebuild_l4_router(peers: &[config::PeerConfig]) -> AllowedIPsRouter<[u8; 32]> {
    let mut router = AllowedIPsRouter::new();
    for peer in peers {
        for &allowed_ip in &peer.allowed_ips {
            router.insert(allowed_ip, peer.public_key);
        }
    }
    router
}

pub fn telemetry_sources(
    peers: &[config::PeerConfig],
    l3_stats: &HashMap<[u8; 32], WgPeerStats>,
) -> HashMap<[u8; 32], String> {
    let mut sources = HashMap::new();
    for peer in peers {
        if l3_stats.contains_key(&peer.public_key) {
            sources.insert(peer.public_key, "both".to_string());
        } else {
            sources.insert(peer.public_key, "proxy".to_string());
        }
    }
    for pub_key in l3_stats.keys() {
        sources
            .entry(*pub_key)
            .or_insert_with(|| "wireguard".to_string());
    }
    sources
}

pub fn select_quic_endpoint_ip(
    control_response: &control::ControlResponse,
    fallback_endpoint: SocketAddr,
) -> Result<IpAddr, String> {
    if fallback_endpoint.is_ipv6() {
        if let Some(public_ipv6) = &control_response.public_ipv6 {
            return public_ipv6
                .parse::<Ipv6Addr>()
                .map(IpAddr::V6)
                .map_err(|e| format!("Invalid server PublicIPv6 '{}': {}", public_ipv6, e));
        }
    } else if let Some(public_ipv4) = &control_response.public_ipv4 {
        return public_ipv4
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|e| format!("Invalid server PublicIPv4 '{}': {}", public_ipv4, e));
    }
    Ok(fallback_endpoint.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceConfig, PeerConfig, QUICPoolConfig, XdpConfig};

    fn client_config(peers: Vec<PeerConfig>) -> GatewayConfig {
        GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.2/24".parse().unwrap()],
                listen_port: None,
                listen_control_port: None,
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
                mode: "tun".to_string(),
            },
            peers,
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![],
            },
            xdp: XdpConfig::default(),
        }
    }

    #[test]
    fn test_base64_encode_roundtrip_and_padding() {
        let bytes = [0x55u8; 32];
        let encoded = encode_base64_32(&bytes);
        let decoded = crate::config::decode_base64_32(&encoded).unwrap();
        assert_eq!(bytes, decoded);

        let zero_encoded = encode_base64_32(&[0u8; 32]);
        assert_eq!(zero_encoded.len(), 44);
        assert!(zero_encoded.ends_with('='));
    }

    #[test]
    fn test_l4_router_contains_all_peers() {
        let proxy_peer = PeerConfig {
            public_key: [1u8; 32],
            allowed_ips: vec!["10.10.0.0/16".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: Some(51821),
        };
        let wg_only_peer = PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: vec!["10.20.0.0/16".parse().unwrap()],
            endpoint: None,
            proxy_port: None,
        };

        let router = rebuild_l4_router(&[proxy_peer, wg_only_peer]);

        assert_eq!(
            router.longest_match("10.10.1.1".parse().unwrap()),
            Some([1u8; 32])
        );
        assert_eq!(
            router.longest_match("10.20.1.1".parse().unwrap()),
            Some([2u8; 32])
        );
    }

    #[test]
    fn test_client_mode_peer_proxy_fields_must_be_paired() {
        let mut config = client_config(vec![PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: Some(51821),
        }]);

        assert_eq!(determine_runtime_mode(&config), Ok(RuntimeMode::Client));
        config.peers[0].proxy_port = None;
        assert_eq!(determine_runtime_mode(&config), Ok(RuntimeMode::Client));
        config.peers[0].endpoint = None;
        config.peers[0].proxy_port = Some(51821);
        assert!(determine_runtime_mode(&config)
            .unwrap_err()
            .contains("specifies ProxyPort but is missing Endpoint"));
    }

    #[test]
    fn interface_name_from_config_path_validates_linux_ifname_rules() {
        assert_eq!(
            interface_name_from_config_path("/etc/new_proxy/client-a.conf").unwrap(),
            "client-a"
        );
        assert_eq!(
            interface_name_from_config_path("/etc/new_proxy/tun_0.conf").unwrap(),
            "tun_0"
        );
        assert!(
            interface_name_from_config_path("/etc/new_proxy/this-name-is-too-long.conf")
                .unwrap_err()
                .contains("1..=15 bytes")
        );
        assert!(
            interface_name_from_config_path("/etc/new_proxy/bad name.conf")
                .unwrap_err()
                .contains("allowed characters")
        );
    }

    #[test]
    fn validate_gateway_config_rejects_invalid_table_and_server_mode_gaps() {
        let peer = PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
            endpoint: None,
            proxy_port: None,
        };
        let mut config = client_config(vec![peer]);
        config.interface.table = Some("manual".to_string());
        assert!(validate_gateway_config(&config)
            .unwrap_err()
            .contains("Invalid Table value"));

        config.interface.table = None;
        config.interface.listen_control_port = Some(51820);
        assert!(determine_runtime_mode(&config)
            .unwrap_err()
            .contains("QUICPool.ListenPorts must contain at least one port"));

        config.interface.listen_control_port = None;
        config.interface.listen_port = None;
        config.quic_pool.listen_ports = vec![40001];
        assert!(determine_runtime_mode(&config)
            .unwrap_err()
            .contains("Either ListenControlPort or ListenPort must be set"));
    }

    #[test]
    fn test_validate_gateway_config_rejects_duplicate_quic_ports_and_empty_allowed_ips() {
        let mut server_config = GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.1/24".parse().unwrap()],
                listen_port: None,
                listen_control_port: Some(51820),
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
                mode: "tun".to_string(),
            },
            peers: vec![PeerConfig {
                public_key: [2u8; 32],
                allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
                endpoint: None,
                proxy_port: None,
            }],
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![40001, 40001],
            },
            xdp: XdpConfig::default(),
        };

        assert!(validate_gateway_config(&server_config)
            .unwrap_err()
            .contains("Duplicate QUICPool ListenPorts"));

        server_config.quic_pool.listen_ports = vec![40001];
        server_config.peers[0].allowed_ips.clear();
        assert!(validate_gateway_config(&server_config)
            .unwrap_err()
            .contains("has no AllowedIPs"));
    }

    #[test]
    fn test_validate_gateway_config_rejects_duplicate_peers_and_overlapping_allowed_ips() {
        let peer1 = PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: Some(51821),
        };
        let mut peer2 = PeerConfig {
            public_key: [3u8; 32],
            allowed_ips: vec!["10.0.0.128/25".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: Some(51821),
        };
        let mut config = client_config(vec![peer1.clone(), peer2.clone()]);

        assert!(validate_gateway_config(&config)
            .unwrap_err()
            .contains("Overlapping AllowedIPs"));

        peer2.public_key = peer1.public_key;
        peer2.allowed_ips = vec!["10.1.0.0/24".parse().unwrap()];
        config.peers = vec![peer1.clone(), peer2.clone()];
        assert!(validate_gateway_config(&config)
            .unwrap_err()
            .contains("Duplicate Peer PublicKey"));

        peer2.public_key = [3u8; 32];
        peer2.allowed_ips = peer1.allowed_ips.clone();
        config.peers = vec![peer1, peer2];
        assert!(validate_gateway_config(&config)
            .unwrap_err()
            .contains("Duplicate AllowedIPs"));
    }

    #[test]
    fn test_select_quic_endpoint_ip_rejects_invalid_advertised_public_ips() {
        let fallback_v4 = "10.0.2.2:51820".parse::<SocketAddr>().unwrap();
        let fallback_v6 = "[fd00:2::2]:51820".parse::<SocketAddr>().unwrap();

        let mut resp = control::ControlResponse {
            session_psk: [1u8; 32],
            server_nonce: [4u8; 16],
            port_pool: vec![40001],
            public_ipv4: Some("not-an-ipv4".to_string()),
            public_ipv6: None,
            quic_cert_sha256: [2u8; 32],
        };
        assert!(select_quic_endpoint_ip(&resp, fallback_v4)
            .unwrap_err()
            .contains("Invalid server PublicIPv4"));

        resp.public_ipv4 = None;
        resp.public_ipv6 = Some("not-an-ipv6".to_string());
        assert!(select_quic_endpoint_ip(&resp, fallback_v6)
            .unwrap_err()
            .contains("Invalid server PublicIPv6"));

        resp.public_ipv6 = None;
        assert_eq!(
            select_quic_endpoint_ip(&resp, fallback_v6).unwrap(),
            fallback_v6.ip()
        );
    }

    #[test]
    fn test_select_quic_endpoint_ip_prefers_matching_advertised_public_ip() {
        let fallback_v4 = "10.0.2.2:51820".parse::<SocketAddr>().unwrap();
        let fallback_v6 = "[fd00:2::2]:51820".parse::<SocketAddr>().unwrap();
        let resp = control::ControlResponse {
            session_psk: [1u8; 32],
            server_nonce: [4u8; 16],
            port_pool: vec![40001],
            public_ipv4: Some("203.0.113.10".to_string()),
            public_ipv6: Some("2001:db8::10".to_string()),
            quic_cert_sha256: [2u8; 32],
        };

        assert_eq!(
            select_quic_endpoint_ip(&resp, fallback_v4).unwrap(),
            "203.0.113.10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            select_quic_endpoint_ip(&resp, fallback_v6).unwrap(),
            "2001:db8::10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_telemetry_sources_classifies_config_and_wireguard_peers() {
        let peers = vec![PeerConfig {
            public_key: [1u8; 32],
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            endpoint: None,
            proxy_port: None,
        }];
        let mut l3_stats = HashMap::new();
        l3_stats.insert(
            [1u8; 32],
            WgPeerStats {
                allowed_ips: vec!["10.0.0.1/32".to_string()],
                endpoint: None,
                rx_bytes: 1,
                tx_bytes: 2,
                last_handshake: 0,
                unknown_handshake_drops: 0,
            },
        );
        l3_stats.insert(
            [2u8; 32],
            WgPeerStats {
                allowed_ips: vec!["10.0.0.2/32".to_string()],
                endpoint: None,
                rx_bytes: 3,
                tx_bytes: 4,
                last_handshake: 0,
                unknown_handshake_drops: 0,
            },
        );

        let sources = telemetry_sources(&peers, &l3_stats);
        assert_eq!(sources.get(&[1u8; 32]).map(String::as_str), Some("both"));
        assert_eq!(
            sources.get(&[2u8; 32]).map(String::as_str),
            Some("wireguard")
        );
    }
}
