use ini::Ini;
use ipnet::IpNet;
use std::net::SocketAddr;
use std::str::FromStr;

const DEFAULT_PACKET_BUFFER_OVERHEAD: usize = 256;
const MIN_PACKET_BUFFER_BYTES: usize = 1500;
const MAX_PACKET_BUFFER_BYTES: usize = 65535;
const PACKET_BUFFER_BYTES_ENV: &str = "NEW_PROXY_PACKET_BUFFER_BYTES";

#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    pub private_key: [u8; 32],
    pub addresses: Vec<IpNet>,
    pub listen_port: Option<u16>,
    pub listen_control_port: Option<u16>,
    pub mtu: u16,
    pub table: Option<String>,
    pub pre_script: Option<String>,
    pub post_script: Option<String>,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct XdpConfig {
    pub quic_interface: Option<String>,
    pub intercept_interfaces: Vec<String>,
    pub xdp_mode: String,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            quic_interface: None,
            intercept_interfaces: Vec::new(),
            xdp_mode: "native".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Option<SocketAddr>,
    pub proxy_port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct QUICPoolConfig {
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub listen_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
    pub quic_pool: QUICPoolConfig,
    pub xdp: XdpConfig,
}

pub fn packet_buffer_size_for_mtu(mtu: u16) -> usize {
    let override_bytes = std::env::var(PACKET_BUFFER_BYTES_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| (MIN_PACKET_BUFFER_BYTES..=MAX_PACKET_BUFFER_BYTES).contains(value));
    packet_buffer_size_for_mtu_with_override(mtu, override_bytes)
}

fn packet_buffer_size_for_mtu_with_override(mtu: u16, override_bytes: Option<usize>) -> usize {
    if let Some(value) = override_bytes {
        return value;
    }

    (mtu as usize)
        .saturating_add(DEFAULT_PACKET_BUFFER_OVERHEAD)
        .clamp(MIN_PACKET_BUFFER_BYTES, MAX_PACKET_BUFFER_BYTES)
}

// 极其高效轻量的内置 Base64 解码器 (免引入额外 Base64 库)
pub fn decode_base64_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    let mut buffer = Vec::with_capacity(32);
    let mut temp = 0u32;
    let mut bits = 0;

    for &byte in s.as_bytes() {
        if byte == b'=' {
            break;
        }
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return Err(format!("Invalid base64 character: 0x{:02x}", byte)),
        };
        temp = (temp << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buffer.push((temp >> bits) as u8);
        }
    }

    if buffer.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&buffer);
        Ok(key)
    } else {
        Err(format!(
            "Invalid key length: expected 32 bytes, got {}",
            buffer.len()
        ))
    }
}

impl GatewayConfig {
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let ini =
            Ini::load_from_file(path).map_err(|e| format!("Failed to parse config file: {}", e))?;
        Self::load_from_ini(ini)
    }

    pub fn load_from_str(content: &str) -> Result<Self, String> {
        let ini = Ini::load_from_str(content)
            .map_err(|e| format!("Failed to parse config string: {}", e))?;
        Self::load_from_ini(ini)
    }

    pub fn load_from_ini(ini: Ini) -> Result<Self, String> {
        // 1. 解析 Interface
        let interface_section = ini
            .section(Some("Interface"))
            .ok_ok_or_else(|| "Missing [Interface] section".to_string())?;

        let priv_key_str = interface_section
            .get("PrivateKey")
            .ok_ok_or_else(|| "Missing PrivateKey in [Interface]".to_string())?;
        let private_key = decode_base64_32(priv_key_str)?;

        let addresses_str = interface_section
            .get("Address")
            .ok_ok_or_else(|| "Missing Address in [Interface]".to_string())?;
        let mut addresses = Vec::new();
        for addr in addresses_str.split(',') {
            let parsed =
                IpNet::from_str(addr.trim()).map_err(|e| format!("Invalid Address: {}", e))?;
            addresses.push(parsed);
        }

        let listen_port = interface_section
            .get("ListenPort")
            .map(|s| {
                s.parse::<u16>()
                    .map_err(|e| format!("Invalid ListenPort: {}", e))
            })
            .transpose()?;

        let listen_control_port = interface_section
            .get("ListenControlPort")
            .map(|s| {
                s.parse::<u16>()
                    .map_err(|e| format!("Invalid ListenControlPort: {}", e))
            })
            .transpose()?;

        let mtu = interface_section
            .get("MTU")
            .map(|s| s.parse::<u16>().map_err(|e| format!("Invalid MTU: {}", e)))
            .transpose()?
            .unwrap_or(1280);

        let table = interface_section
            .get("Table")
            .or_else(|| interface_section.get("table"))
            .map(|s| s.trim().to_string());

        let pre_script = interface_section
            .get("PreScript")
            .or_else(|| interface_section.get("pre_script"))
            .map(|s| s.trim().to_string());

        let post_script = interface_section
            .get("PostScript")
            .or_else(|| interface_section.get("post_script"))
            .map(|s| s.trim().to_string());

        let mode = interface_section
            .get("Mode")
            .or_else(|| interface_section.get("mode"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "tun".to_string());

        let interface = InterfaceConfig {
            private_key,
            addresses,
            listen_port,
            listen_control_port,
            mtu,
            table,
            pre_script,
            post_script,
            mode,
        };

        // 2. 解析 Peers
        let mut peers = Vec::new();
        for (section_name, section) in ini.iter() {
            if section_name == Some("Peer") {
                let pub_key_str = section
                    .get("PublicKey")
                    .ok_ok_or_else(|| "Missing PublicKey in [Peer]".to_string())?;
                let public_key = decode_base64_32(pub_key_str)?;

                let allowed_ips_str = section
                    .get("AllowedIPs")
                    .ok_ok_or_else(|| "Missing AllowedIPs in [Peer]".to_string())?;
                let mut allowed_ips = Vec::new();
                for cidr in allowed_ips_str.split(',') {
                    let parsed = IpNet::from_str(cidr.trim())
                        .map_err(|e| format!("Invalid AllowedIPs: {}", e))?;
                    allowed_ips.push(parsed);
                }

                let endpoint = section
                    .get("Endpoint")
                    .map(|s| {
                        SocketAddr::from_str(s.trim())
                            .map_err(|e| format!("Invalid Endpoint: {}", e))
                    })
                    .transpose()?;

                let proxy_port = section
                    .get("ProxyPort")
                    .map(|s| {
                        s.parse::<u16>()
                            .map_err(|e| format!("Invalid ProxyPort: {}", e))
                    })
                    .transpose()?;

                peers.push(PeerConfig {
                    public_key,
                    allowed_ips,
                    endpoint,
                    proxy_port,
                });
            }
        }

        // 3. 解析 QUICPool
        let quic_pool_section = ini.section(Some("QUICPool"));
        let public_ipv4 =
            quic_pool_section.and_then(|s| s.get("PublicIPv4").map(|v| v.trim().to_string()));
        let public_ipv6 =
            quic_pool_section.and_then(|s| s.get("PublicIPv6").map(|v| v.trim().to_string()));
        let listen_ports = quic_pool_section
            .and_then(|s| s.get("ListenPorts"))
            .map(|ports_str| {
                ports_str
                    .split(',')
                    .filter(|p| !p.trim().is_empty())
                    .map(|p| {
                        p.trim().parse::<u16>().map_err(|e| {
                            format!("Invalid QUICPool ListenPorts entry '{}': {}", p, e)
                        })
                    })
                    .collect::<Result<Vec<u16>, String>>()
            })
            .transpose()?
            .unwrap_or_default();
        let quic_pool = QUICPoolConfig {
            public_ipv4,
            public_ipv6,
            listen_ports,
        };

        // 4. 解析 XDP
        let xdp_section = ini.section(Some("XDP"));
        let quic_interface = xdp_section
            .and_then(|s| s.get("QuicInterface").or_else(|| s.get("quic_interface")))
            .map(|v| v.trim().to_string());

        let intercept_interfaces = xdp_section
            .and_then(|s| {
                s.get("InterceptInterfaces")
                    .or_else(|| s.get("intercept_interfaces"))
            })
            .map(|interfaces_str| {
                interfaces_str
                    .split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        let xdp_mode = xdp_section
            .and_then(|s| s.get("XdpMode").or_else(|| s.get("xdp_mode")))
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|| "native".to_string());

        let xdp = XdpConfig {
            quic_interface,
            intercept_interfaces,
            xdp_mode,
        };

        Ok(GatewayConfig {
            interface,
            peers,
            quic_pool,
            xdp,
        })
    }
}

// 辅助方法，将 Option 转换为 Result
trait OptionExt<T> {
    fn ok_ok_or_else<F, E>(self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> E;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_ok_or_else<F, E>(self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> E,
    {
        match self {
            Some(v) => Ok(v),
            None => Err(f()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_key() -> String {
        crate::app_config::encode_base64_32(&[0xabu8; 32])
    }

    #[test]
    fn test_base64_decode_success() {
        let encoded = test_key();
        let decoded = decode_base64_32(&encoded).unwrap();
        assert_eq!(decoded[0], 171);
        assert_eq!(decoded[1], 171);
        assert_eq!(decoded[2], 171);
    }

    #[test]
    fn test_base64_decode_invalid_length() {
        let test_key = "q8vLy8vLy8s=";
        let decoded = decode_base64_32(test_key);
        assert!(decoded.is_err());
    }

    #[test]
    fn packet_buffer_size_follows_mtu_with_headroom() {
        assert_eq!(packet_buffer_size_for_mtu_with_override(1400, None), 1656);
        assert_eq!(packet_buffer_size_for_mtu_with_override(1280, None), 1536);
        assert_eq!(packet_buffer_size_for_mtu_with_override(9000, None), 9256);
        assert_eq!(
            packet_buffer_size_for_mtu_with_override(9000, Some(12000)),
            12000
        );
    }

    #[test]
    fn test_load_config_success() {
        let path = "test_temp_success.conf";
        let key = test_key();
        let content = format!(
            r#"
[Interface]
PrivateKey = {key}
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
ListenControlPort = 51821
MTU = 1280

[Peer]
PublicKey = {key}
AllowedIPs = 10.0.0.2/32, fd00::2/128
Endpoint = 1.2.3.4:51820
ProxyPort = 40001

[QUICPool]
PublicIPv4 = 1.2.3.4
PublicIPv6 = 2001:db8::1
ListenPorts = 40001, 40002
"#
        );
        fs::write(path, content).unwrap();

        let config = GatewayConfig::load_from_file(path).unwrap();
        assert_eq!(config.interface.listen_port, Some(51820));
        assert_eq!(config.interface.listen_control_port, Some(51821));
        assert_eq!(config.interface.mtu, 1280);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].proxy_port, Some(40001));
        assert_eq!(config.quic_pool.public_ipv4, Some("1.2.3.4".to_string()));
        assert_eq!(config.quic_pool.listen_ports, vec![40001, 40002]);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_config_missing_interface() {
        let path = "test_temp_missing_if.conf";
        let key = test_key();
        let content = format!(
            r#"
[Peer]
PublicKey = {key}
AllowedIPs = 10.0.0.2/32
"#
        );
        fs::write(path, content).unwrap();

        let res = GatewayConfig::load_from_file(path);
        assert!(res.is_err());
        assert!(res.err().unwrap().contains("Missing [Interface] section"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_config_invalid_address() {
        let path = "test_temp_invalid_addr.conf";
        let key = test_key();
        let content = format!(
            r#"
[Interface]
PrivateKey = {key}
Address = 10.0.0.1/33
"#
        );
        fs::write(path, content).unwrap();

        let res = GatewayConfig::load_from_file(path);
        assert!(res.is_err());
        assert!(res.err().unwrap().contains("Invalid Address"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_load_config_default_mtu() {
        let path = "test_temp_mtu.conf";
        let key = test_key();
        let content = format!(
            r#"
[Interface]
PrivateKey = {key}
Address = 10.0.0.1/24
MTU = 1500
"#
        );
        fs::write(path, content).unwrap();
        let config = GatewayConfig::load_from_file(path).unwrap();
        assert_eq!(config.interface.mtu, 1500); // Manually set remains 1500

        let content_no_mtu = format!(
            r#"
[Interface]
PrivateKey = {key}
Address = 10.0.0.1/24
"#
        );
        fs::write(path, content_no_mtu).unwrap();
        let config_no_mtu = GatewayConfig::load_from_file(path).unwrap();
        assert_eq!(config_no_mtu.interface.mtu, 1280); // Defaults to 1280

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_xdp_config_parse() {
        let key = test_key();
        let conf = format!(
            r#"
[Interface]
PrivateKey = {}
Address = 10.0.0.1/24
Mode = af_xdp

[XDP]
QuicInterface = eth0
InterceptInterfaces = eth0, lo
XdpMode = native
"#,
            key
        );
        let gateway_conf = GatewayConfig::load_from_str(&conf).unwrap();
        assert_eq!(gateway_conf.interface.mode, "af_xdp");
        assert_eq!(gateway_conf.xdp.quic_interface, Some("eth0".to_string()));
        assert_eq!(
            gateway_conf.xdp.intercept_interfaces,
            vec!["eth0".to_string(), "lo".to_string()]
        );
        assert_eq!(gateway_conf.xdp.xdp_mode, "native");
    }
}
