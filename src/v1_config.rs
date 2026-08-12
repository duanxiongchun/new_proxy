use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpAttachMode {
    Native,
    Skb,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let value = value.trim();
        if value.is_empty() || value.len() > 15 || value.contains(char::is_whitespace) {
            return Err(ConfigError::InvalidInterface(value.to_string()));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        let octets = value
            .split(':')
            .map(|octet| u8::from_str_radix(octet, 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError::InvalidMacAddress(value.to_string()))?;
        let octets: [u8; 6] = octets
            .try_into()
            .map_err(|_| ConfigError::InvalidMacAddress(value.to_string()))?;
        if octets == [0; 6] || octets[0] & 1 != 0 {
            return Err(ConfigError::InvalidMacAddress(value.to_string()));
        }
        Ok(Self(octets))
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterceptConfig {
    pub interface: InterfaceName,
    pub next_hop_mac: MacAddress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NatConfig {
    pub address_v4: Option<Ipv4Addr>,
    pub address_v6: Option<Ipv6Addr>,
    pub ports: RangeInclusive<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplianceConfig {
    pub role: Role,
    pub tunnel_interface: InterfaceName,
    pub tunnel_next_hop_mac: MacAddress,
    pub intercept_interfaces: Vec<InterceptConfig>,
    pub endpoint: Option<SocketAddr>,
    pub listen: Option<SocketAddr>,
    pub flow_worker_count: usize,
    pub channel_capacity: usize,
    pub dcid_len: usize,
    pub stats_path: String,
    pub shared_key: [u8; 32],
    pub server_certificate: Option<String>,
    pub server_private_key: Option<String>,
    pub server_certificate_sha256: Option<[u8; 32]>,
    pub nat: NatConfig,
    pub allowed_ips: Vec<IpNet>,
    pub xdp_mode: XdpAttachMode,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config: {0}")]
    Io(String),
    #[error("invalid INI syntax: {0}")]
    Syntax(String),
    #[error("missing required field {0}")]
    MissingField(&'static str),
    #[error("unknown section [{0}]")]
    UnknownSection(String),
    #[error("unknown field {section}.{field}")]
    UnknownField { section: String, field: String },
    #[error("legacy field {section}.{field} is not supported")]
    UnsupportedLegacyField { section: String, field: String },
    #[error("invalid role {0}")]
    InvalidRole(String),
    #[error("invalid interface name {0:?}")]
    InvalidInterface(String),
    #[error("invalid unicast MAC address {0:?}")]
    InvalidMacAddress(String),
    #[error("invalid integer for {0}")]
    InvalidInteger(String),
    #[error("Appliance.SharedKey must not use the packaged placeholder")]
    PlaceholderSharedKey,
    #[error("invalid socket address for {0}")]
    InvalidSocketAddress(String),
    #[error("invalid IP address for {0}")]
    InvalidIpAddress(String),
    #[error("NAT requires AddressV4 and/or AddressV6")]
    MissingNatAddress,
    #[error("invalid CIDR in AllowedIPs: {0}")]
    InvalidAllowedIp(String),
    #[error("server requires exactly one intercept interface")]
    ServerInterceptCount,
    #[error("interface {0} is declared more than once")]
    DuplicateInterface(String),
    #[error("client requires Endpoint and forbids Listen")]
    InvalidClientAddressing,
    #[error("server requires Listen and forbids Endpoint")]
    InvalidServerAddressing,
    #[error("flow_worker_count must be greater than zero")]
    ZeroFlowWorkers,
    #[error("channel_capacity must be greater than zero")]
    ZeroChannelCapacity,
    #[error("dcid_len must be greater than zero")]
    ZeroDcidLength,
    #[error("dcid_len must be at most 20 bytes")]
    InvalidDcidLength,
    #[error("dcid_len must be at least 8 bytes")]
    InsecureDcidLength,
    #[error("NAT port range is invalid")]
    InvalidNatPortRange,
    #[error("NAT port range must provide at least one port per Flow worker")]
    NatRangeTooSmall,
    #[error("AllowedIPs must not be empty")]
    EmptyAllowedIps,
}

impl ApplianceConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|error| ConfigError::Io(error.to_string()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let sections = parse_ini(text)?;
        reject_unknown_sections(&sections)?;
        let appliance = section(&sections, "Appliance")?;
        let tunnel = section(&sections, "Tunnel")?;
        let nat = section(&sections, "NAT")?;
        let allowed = section(&sections, "AllowedIPs")?;
        let xdp = section(&sections, "XDP")?;
        validate_fields(
            "Appliance",
            appliance,
            &[
                "Role",
                "FlowWorkerCount",
                "ChannelCapacity",
                "DcidLength",
                "StatsPath",
                "SharedKey",
            ],
        )?;
        validate_fields(
            "Tunnel",
            tunnel,
            &[
                "Interface",
                "Endpoint",
                "Listen",
                "ServerCertificate",
                "ServerPrivateKey",
                "ServerCertificateSha256",
                "NextHopMac",
            ],
        )?;
        validate_fields(
            "NAT",
            nat,
            &["AddressV4", "AddressV6", "PortStart", "PortEnd"],
        )?;
        validate_fields("AllowedIPs", allowed, &["Prefixes"])?;
        validate_fields("XDP", xdp, &["Mode"])?;

        let intercepts = sections
            .iter()
            .filter(|(name, _)| name.starts_with("Intercept"))
            .map(|(name, fields)| {
                validate_fields(name, fields, &["Interface", "NextHopMac"])?;
                Ok(InterceptConfig {
                    interface: InterfaceName::parse(required(fields, "Interface")?)?,
                    next_hop_mac: MacAddress::parse(required(fields, "NextHopMac")?)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if intercepts.is_empty() {
            return Err(ConfigError::MissingField("Intercept.Interface"));
        }

        let role = match required(appliance, "Role")?.to_ascii_lowercase().as_str() {
            "client" => Role::Client,
            "server" => Role::Server,
            value => return Err(ConfigError::InvalidRole(value.to_string())),
        };
        let flow_worker_count = parse_usize(appliance, "FlowWorkerCount")?;
        let channel_capacity = parse_usize(appliance, "ChannelCapacity")?;
        let dcid_len = parse_usize(appliance, "DcidLength")?;
        let stats_path = required(appliance, "StatsPath")?.to_string();
        if flow_worker_count == 0 {
            return Err(ConfigError::ZeroFlowWorkers);
        }
        if channel_capacity == 0 {
            return Err(ConfigError::ZeroChannelCapacity);
        }
        if dcid_len == 0 {
            return Err(ConfigError::ZeroDcidLength);
        }
        if dcid_len > 20 {
            return Err(ConfigError::InvalidDcidLength);
        }
        if dcid_len < 8 {
            return Err(ConfigError::InsecureDcidLength);
        }
        let tunnel_interface = InterfaceName::parse(required(tunnel, "Interface")?)?;
        let tunnel_next_hop_mac = MacAddress::parse(required(tunnel, "NextHopMac")?)?;
        let endpoint = optional(tunnel, "Endpoint")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::InvalidSocketAddress("Tunnel.Endpoint".to_string()))
            })
            .transpose()?;
        let listen = optional(tunnel, "Listen")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::InvalidSocketAddress("Tunnel.Listen".to_string()))
            })
            .transpose()?;
        match role {
            Role::Client
                if endpoint.is_none()
                    || listen.is_some()
                    || optional(tunnel, "ServerCertificateSha256").is_none()
                    || optional(tunnel, "ServerCertificate").is_some()
                    || optional(tunnel, "ServerPrivateKey").is_some() =>
            {
                return Err(ConfigError::InvalidClientAddressing)
            }
            Role::Server
                if listen.is_none()
                    || endpoint.is_some()
                    || optional(tunnel, "ServerCertificate").is_none()
                    || optional(tunnel, "ServerPrivateKey").is_none()
                    || optional(tunnel, "ServerCertificateSha256").is_some() =>
            {
                return Err(ConfigError::InvalidServerAddressing)
            }
            _ => {}
        }
        if role == Role::Server && intercepts.len() != 1 {
            return Err(ConfigError::ServerInterceptCount);
        }
        let mut interfaces = HashSet::new();
        for interface in &intercepts {
            if !interfaces.insert(interface.interface.as_str()) {
                return Err(ConfigError::DuplicateInterface(
                    interface.interface.as_str().to_string(),
                ));
            }
        }
        let nat_address_v4 = optional(nat, "AddressV4")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::InvalidIpAddress("NAT.AddressV4".to_string()))
            })
            .transpose()?;
        let nat_address_v6 = optional(nat, "AddressV6")
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::InvalidIpAddress("NAT.AddressV6".to_string()))
            })
            .transpose()?;
        if nat_address_v4.is_none() && nat_address_v6.is_none() {
            return Err(ConfigError::MissingNatAddress);
        }
        let port_start = parse_u16(nat, "PortStart")?;
        let port_end = parse_u16(nat, "PortEnd")?;
        if port_start == 0 || port_start > port_end {
            return Err(ConfigError::InvalidNatPortRange);
        }
        if usize::from(port_end - port_start) + 1 < flow_worker_count {
            return Err(ConfigError::NatRangeTooSmall);
        }
        let allowed_ips = required(allowed, "Prefixes")?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::InvalidAllowedIp(value.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if allowed_ips.is_empty() {
            return Err(ConfigError::EmptyAllowedIps);
        }
        let xdp_mode = match required(xdp, "Mode")?.to_ascii_lowercase().as_str() {
            "native" | "driver" => XdpAttachMode::Native,
            "skb" | "generic" => XdpAttachMode::Skb,
            value => {
                return Err(ConfigError::UnknownField {
                    section: "XDP".to_string(),
                    field: value.to_string(),
                })
            }
        };
        let shared_key = parse_hex_key(required(appliance, "SharedKey")?)?;
        if shared_key == [0u8; 32] {
            return Err(ConfigError::PlaceholderSharedKey);
        }
        let server_certificate = optional(tunnel, "ServerCertificate").map(str::to_string);
        let server_private_key = optional(tunnel, "ServerPrivateKey").map(str::to_string);
        let server_certificate_sha256 = optional(tunnel, "ServerCertificateSha256")
            .map(parse_hex_key)
            .transpose()?;

        Ok(Self {
            role,
            tunnel_interface,
            tunnel_next_hop_mac,
            intercept_interfaces: intercepts,
            endpoint,
            listen,
            flow_worker_count,
            channel_capacity,
            dcid_len,
            stats_path,
            shared_key,
            server_certificate,
            server_private_key,
            server_certificate_sha256,
            nat: NatConfig {
                address_v4: nat_address_v4,
                address_v6: nat_address_v6,
                ports: port_start..=port_end,
            },
            allowed_ips,
            xdp_mode,
        })
    }
}

type Sections = HashMap<String, HashMap<String, String>>;

fn parse_ini(text: &str) -> Result<Sections, ConfigError> {
    let mut sections = Sections::new();
    let mut current = None::<String>;
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim();
            if name.is_empty() || sections.contains_key(name) {
                return Err(ConfigError::Syntax(format!(
                    "invalid or duplicate section on line {}",
                    index + 1
                )));
            }
            sections.insert(name.to_string(), HashMap::new());
            current = Some(name.to_string());
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            ConfigError::Syntax(format!("expected key=value on line {}", index + 1))
        })?;
        let section_name = current.as_ref().ok_or_else(|| {
            ConfigError::Syntax(format!("field before section on line {}", index + 1))
        })?;
        let fields = sections
            .get_mut(section_name)
            .expect("current section is present");
        let key = key.trim();
        if key.is_empty()
            || fields
                .insert(key.to_string(), value.trim().to_string())
                .is_some()
        {
            return Err(ConfigError::Syntax(format!(
                "invalid or duplicate field on line {}",
                index + 1
            )));
        }
    }
    Ok(sections)
}

fn reject_unknown_sections(sections: &Sections) -> Result<(), ConfigError> {
    for name in sections.keys() {
        if matches!(name.as_str(), "Interface" | "Peer" | "QUICPool") {
            return Err(ConfigError::UnsupportedLegacyField {
                section: name.clone(),
                field: "*".to_string(),
            });
        }
        if !matches!(
            name.as_str(),
            "Appliance" | "Tunnel" | "NAT" | "AllowedIPs" | "XDP"
        ) && !name.starts_with("Intercept")
        {
            return Err(ConfigError::UnknownSection(name.clone()));
        }
    }
    Ok(())
}

fn section<'a>(
    sections: &'a Sections,
    name: &'static str,
) -> Result<&'a HashMap<String, String>, ConfigError> {
    sections.get(name).ok_or(ConfigError::MissingField(name))
}

fn validate_fields(
    section: &str,
    fields: &HashMap<String, String>,
    allowed: &[&str],
) -> Result<(), ConfigError> {
    for field in fields.keys() {
        if matches!(
            field.as_str(),
            "PrivateKey" | "PublicKey" | "WgListenPort" | "Mode" if section != "XDP"
        ) {
            return Err(ConfigError::UnsupportedLegacyField {
                section: section.to_string(),
                field: field.clone(),
            });
        }
        if !allowed.contains(&field.as_str()) {
            return Err(ConfigError::UnknownField {
                section: section.to_string(),
                field: field.clone(),
            });
        }
    }
    Ok(())
}

fn required<'a>(
    fields: &'a HashMap<String, String>,
    field: &'static str,
) -> Result<&'a str, ConfigError> {
    fields
        .get(field)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::MissingField(field))
}

fn optional<'a>(fields: &'a HashMap<String, String>, field: &str) -> Option<&'a str> {
    fields
        .get(field)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn parse_usize(
    fields: &HashMap<String, String>,
    field: &'static str,
) -> Result<usize, ConfigError> {
    required(fields, field)?
        .parse()
        .map_err(|_| ConfigError::InvalidInteger(field.to_string()))
}

fn parse_u16(fields: &HashMap<String, String>, field: &'static str) -> Result<u16, ConfigError> {
    required(fields, field)?
        .parse()
        .map_err(|_| ConfigError::InvalidInteger(field.to_string()))
}

fn parse_hex_key(value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::InvalidInteger(
            "Appliance.SharedKey".to_string(),
        ));
    }
    let mut key = [0u8; 32];
    for (index, output) in key.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| ConfigError::InvalidInteger("Appliance.SharedKey".to_string()))?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(role: &str, addressing: &str, intercepts: &str) -> String {
        format!(
            "[Appliance]\nRole={role}\nFlowWorkerCount=2\nChannelCapacity=64\nDcidLength=8\nStatsPath=/tmp/new-proxy-test-stats.json\nSharedKey=0101010101010101010101010101010101010101010101010101010101010101\n\
             [Tunnel]\nInterface=eth0\nNextHopMac=02:00:00:00:00:01\n{addressing}\n\
             {intercepts}\
             [NAT]\nAddressV4=192.0.2.1\nAddressV6=2001:db8:ffff::1\nPortStart=40000\nPortEnd=41000\n\
             [AllowedIPs]\nPrefixes=0.0.0.0/0,::/0\n[XDP]\nMode=skb\n"
        )
    }

    #[test]
    fn v1_unit_config_parses_client_and_server() {
        let client = ApplianceConfig::parse(&valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n[Intercept.2]\nInterface=eth2\nNextHopMac=02:00:00:00:00:03\n",
        ))
        .unwrap();
        assert_eq!(client.role, Role::Client);
        assert_eq!(client.intercept_interfaces.len(), 2);

        let server = ApplianceConfig::parse(&valid(
            "server",
            "Listen=0.0.0.0:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        ))
        .unwrap();
        assert_eq!(server.role, Role::Server);
    }

    #[test]
    fn v1_unit_config_examples_match_the_strict_v1_schema() {
        let placeholder =
            "SharedKey=0000000000000000000000000000000000000000000000000000000000000000";
        let configured =
            "SharedKey=0101010101010101010101010101010101010101010101010101010101010101";
        assert_eq!(
            ApplianceConfig::parse(include_str!("../conf/client.conf")),
            Err(ConfigError::PlaceholderSharedKey)
        );
        assert_eq!(
            ApplianceConfig::parse(include_str!("../conf/server.conf")),
            Err(ConfigError::PlaceholderSharedKey)
        );
        let client = ApplianceConfig::parse(
            &include_str!("../conf/client.conf").replace(placeholder, configured),
        )
        .unwrap();
        let server = ApplianceConfig::parse(
            &include_str!("../conf/server.conf").replace(placeholder, configured),
        )
        .unwrap();

        assert_eq!(client.role, Role::Client);
        assert_eq!(server.role, Role::Server);
        assert_eq!(client.shared_key, server.shared_key);
        assert_eq!(client.dcid_len, server.dcid_len);
    }

    #[test]
    fn v1_unit_config_rejects_server_multi_intercept_and_bad_counts() {
        assert_eq!(
            ApplianceConfig::parse(&valid(
                "server",
                "Listen=0.0.0.0:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der",
                "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n[Intercept.2]\nInterface=eth2\nNextHopMac=02:00:00:00:00:03\n",
            )),
            Err(ConfigError::ServerInterceptCount)
        );
        for (field, expected) in [
            ("FlowWorkerCount=2", ConfigError::ZeroFlowWorkers),
            ("ChannelCapacity=64", ConfigError::ZeroChannelCapacity),
            ("DcidLength=8", ConfigError::ZeroDcidLength),
        ] {
            let config = valid(
                "client",
                "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
                "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
            )
            .replace(field, &format!("{}=0", field.split('=').next().unwrap()));
            assert_eq!(ApplianceConfig::parse(&config), Err(expected));
        }
    }

    #[test]
    fn v1_unit_config_rejects_dcid_length_above_quic_limit() {
        let config = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace("DcidLength=8", "DcidLength=21");

        assert_eq!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::InvalidDcidLength)
        );
    }

    #[test]
    fn v1_unit_config_rejects_insecure_dcid_length() {
        let config = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace("DcidLength=8", "DcidLength=1");

        assert_eq!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::InsecureDcidLength)
        );
    }

    #[test]
    fn v1_unit_config_rejects_nat_range_smaller_than_flow_worker_count() {
        let config = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace("PortEnd=41000", "PortEnd=40000");

        assert_eq!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::NatRangeTooSmall)
        );
    }

    #[test]
    fn v1_unit_config_rejects_role_irrelevant_tunnel_tls_fields() {
        let client_with_server_key = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202\nServerCertificate=server-cert.der",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );
        assert_eq!(
            ApplianceConfig::parse(&client_with_server_key),
            Err(ConfigError::InvalidClientAddressing)
        );

        let server_with_client_pin = valid(
            "server",
            "Listen=0.0.0.0:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );
        assert_eq!(
            ApplianceConfig::parse(&server_with_client_pin),
            Err(ConfigError::InvalidServerAddressing)
        );
    }

    #[test]
    fn v1_unit_config_rejects_packaged_shared_key_placeholder() {
        let config = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "SharedKey=0101010101010101010101010101010101010101010101010101010101010101",
            "SharedKey=0000000000000000000000000000000000000000000000000000000000000000",
        );

        assert_eq!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::PlaceholderSharedKey)
        );
    }

    #[test]
    fn v1_unit_config_rejects_legacy_and_unknown_fields() {
        let mut legacy = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );
        legacy.push_str("[Peer]\nPublicKey=old\n");
        assert!(matches!(
            ApplianceConfig::parse(&legacy),
            Err(ConfigError::UnsupportedLegacyField { .. })
        ));

        let unknown = legacy.replace("[Peer]\nPublicKey=old\n", "Unexpected=yes\n");
        assert!(matches!(
            ApplianceConfig::parse(&unknown),
            Err(ConfigError::UnknownField { .. })
        ));
    }

    #[test]
    fn v1_unit_config_allows_same_logical_interface_and_rejects_nat_range() {
        let duplicate = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth0\nNextHopMac=02:00:00:00:00:02\n",
        );
        assert!(ApplianceConfig::parse(&duplicate).is_ok());

        let invalid_nat = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace("PortStart=40000", "PortStart=42000");
        assert_eq!(
            ApplianceConfig::parse(&invalid_nat),
            Err(ConfigError::InvalidNatPortRange)
        );
    }
}
