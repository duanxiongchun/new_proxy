use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::Path;

const LPM_PREFIX_CAPACITY_PER_FAMILY: usize = 65_536;

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
pub enum IpPolicy {
    TunnelPrefixes(Vec<IpNet>),
    DirectPrefixes(Vec<IpNet>),
}

impl IpPolicy {
    pub fn prefixes(&self) -> &[IpNet] {
        match self {
            Self::TunnelPrefixes(prefixes) | Self::DirectPrefixes(prefixes) => prefixes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsConfig {
    pub listen: SocketAddr,
    pub local_resolver: SocketAddr,
    pub remote_resolver: SocketAddr,
    pub remote_domains: Vec<String>,
    pub transaction_capacity: usize,
    pub timeout_seconds: u64,
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
    pub ip_policy: IpPolicy,
    pub dns: Option<DnsConfig>,
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
    #[error("failed to read AllowedIPs file: {0}")]
    AllowedIpFile(String),
    #[error("AllowedIPs.Prefixes must not mix inline, file: and !file: modes")]
    MixedAllowedIpModes,
    #[error("invalid DNS config: {0}")]
    InvalidDns(String),
    #[error("invalid remote domain: {0}")]
    InvalidRemoteDomain(String),
    #[error("duplicate remote domain: {0}")]
    DuplicateRemoteDomain(String),
    #[error("server requires exactly one intercept interface")]
    ServerInterceptCount,
    #[error("interface {0} is declared more than once")]
    DuplicateInterface(String),
    #[error("client requires Endpoint and forbids Listen")]
    InvalidClientAddressing,
    #[error("server requires Listen and forbids Endpoint")]
    InvalidServerAddressing,
    #[error("Tunnel.Listen must use a concrete unicast address")]
    WildcardListen,
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
    #[error("AllowedIPs exceeds the {family} LPM capacity of {capacity}")]
    AllowedIpCapacity {
        family: &'static str,
        capacity: usize,
    },
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
        let allowed = sections.get("AllowedIPs");
        let dns = sections.get("DNS");
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
        if let Some(allowed) = allowed {
            validate_fields("AllowedIPs", allowed, &["Prefixes"])?;
        }
        if let Some(dns) = dns {
            validate_fields(
                "DNS",
                dns,
                &[
                    "Listen",
                    "LocalResolver",
                    "RemoteResolver",
                    "RemoteDomainsFile",
                    "TransactionCapacity",
                    "TimeoutSeconds",
                ],
            )?;
        }
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
        if role == Role::Server && allowed.is_some() {
            return Err(ConfigError::UnknownSection("AllowedIPs".to_string()));
        }
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
                    .parse::<SocketAddr>()
                    .map_err(|_| ConfigError::InvalidSocketAddress("Tunnel.Endpoint".to_string()))
            })
            .transpose()?;
        let listen = optional(tunnel, "Listen")
            .map(|value| {
                value
                    .parse::<SocketAddr>()
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
        if listen.is_some_and(|address| address.ip().is_unspecified()) {
            return Err(ConfigError::WildcardListen);
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
        let ip_policy = match (role, allowed) {
            (Role::Client, Some(allowed)) => parse_ip_policy(required(allowed, "Prefixes")?)?,
            (Role::Client, None) => return Err(ConfigError::MissingField("AllowedIPs")),
            (Role::Server, Some(_)) => unreachable!("server AllowedIPs rejected above"),
            (Role::Server, None) => IpPolicy::TunnelPrefixes(Vec::new()),
        };
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
        let nat_config = NatConfig {
            address_v4: nat_address_v4,
            address_v6: nat_address_v6,
            ports: port_start..=port_end,
        };
        if endpoint.or(listen).is_some_and(|tunnel| {
            Some(tunnel.ip()) == nat_config.address_v4.map(IpAddr::V4)
                || Some(tunnel.ip()) == nat_config.address_v6.map(IpAddr::V6)
        }) {
            return Err(ConfigError::InvalidIpAddress(
                "NAT address must not equal Tunnel.Endpoint or Tunnel.Listen".to_string(),
            ));
        }
        let dns = parse_dns_config(role, dns, &nat_config)?;
        if dns.as_ref().is_some_and(|dns| {
            endpoint
                .or(listen)
                .is_some_and(|tunnel| tunnel.ip() == dns.listen.ip())
        }) {
            return Err(ConfigError::InvalidDns(
                "DNS.Listen must not equal Tunnel.Endpoint or Tunnel.Listen".to_string(),
            ));
        }

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
            nat: nat_config,
            ip_policy,
            dns,
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
            "Appliance" | "Tunnel" | "NAT" | "AllowedIPs" | "DNS" | "XDP"
        ) && !is_intercept_section(name)
        {
            return Err(ConfigError::UnknownSection(name.clone()));
        }
    }
    Ok(())
}

fn is_intercept_section(name: &str) -> bool {
    if name == "Intercept" {
        return true;
    }
    let Some(index) = name.strip_prefix("Intercept.") else {
        return false;
    };
    !index.is_empty() && !index.starts_with('0') && index.bytes().all(|byte| byte.is_ascii_digit())
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

fn parse_optional_usize(
    fields: &HashMap<String, String>,
    field: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    optional(fields, field)
        .map(|value| {
            value
                .parse()
                .map_err(|_| ConfigError::InvalidInteger(field.to_string()))
        })
        .unwrap_or(Ok(default))
}

fn parse_optional_u64(
    fields: &HashMap<String, String>,
    field: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    optional(fields, field)
        .map(|value| {
            value
                .parse()
                .map_err(|_| ConfigError::InvalidInteger(field.to_string()))
        })
        .unwrap_or(Ok(default))
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

fn parse_ip_policy(value: &str) -> Result<IpPolicy, ConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ConfigError::EmptyAllowedIps);
    }
    let terms = value
        .split(',')
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return Err(ConfigError::EmptyAllowedIps);
    }
    let file_terms = terms
        .iter()
        .filter(|term| term.starts_with("file:") || term.starts_with("!file:"))
        .count();
    if file_terms > 0 && (file_terms != 1 || terms.len() != 1) {
        return Err(ConfigError::MixedAllowedIpModes);
    }
    if let Some(path) = terms[0].strip_prefix("file:") {
        return Ok(IpPolicy::TunnelPrefixes(load_cidr_file(path)?));
    }
    if let Some(path) = terms[0].strip_prefix("!file:") {
        return Ok(IpPolicy::DirectPrefixes(load_cidr_file(path)?));
    }
    Ok(IpPolicy::TunnelPrefixes(parse_cidr_terms(&terms)?))
}

fn load_cidr_file(path: &str) -> Result<Vec<IpNet>, ConfigError> {
    let path = path.trim();
    if path.is_empty() {
        return Err(ConfigError::AllowedIpFile(path.to_string()));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::AllowedIpFile(error.to_string()))?;
    let terms = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    parse_cidr_terms(&terms)
}

fn parse_cidr_terms(terms: &[&str]) -> Result<Vec<IpNet>, ConfigError> {
    let mut seen = HashSet::new();
    let mut prefixes = Vec::new();
    let mut ipv4_count = 0usize;
    let mut ipv6_count = 0usize;
    for term in terms {
        if term.starts_with("file:") || term.starts_with("!file:") {
            return Err(ConfigError::MixedAllowedIpModes);
        }
        let prefix = term
            .parse::<IpNet>()
            .map(normalize_prefix)
            .map_err(|_| ConfigError::InvalidAllowedIp((*term).to_string()))?;
        if seen.insert(prefix) {
            let (family, count) = match prefix {
                IpNet::V4(_) => ("IPv4", &mut ipv4_count),
                IpNet::V6(_) => ("IPv6", &mut ipv6_count),
            };
            *count += 1;
            if *count > LPM_PREFIX_CAPACITY_PER_FAMILY {
                return Err(ConfigError::AllowedIpCapacity {
                    family,
                    capacity: LPM_PREFIX_CAPACITY_PER_FAMILY,
                });
            }
            prefixes.push(prefix);
        }
    }
    if prefixes.is_empty() {
        return Err(ConfigError::EmptyAllowedIps);
    }
    Ok(prefixes)
}

fn normalize_prefix(prefix: IpNet) -> IpNet {
    match prefix {
        IpNet::V4(prefix) => IpNet::V4(
            Ipv4Net::new(prefix.network(), prefix.prefix_len())
                .expect("existing IPv4 prefix length is valid"),
        ),
        IpNet::V6(prefix) => IpNet::V6(
            Ipv6Net::new(prefix.network(), prefix.prefix_len())
                .expect("existing IPv6 prefix length is valid"),
        ),
    }
}

fn parse_dns_config(
    role: Role,
    fields: Option<&HashMap<String, String>>,
    nat: &NatConfig,
) -> Result<Option<DnsConfig>, ConfigError> {
    let Some(fields) = fields else {
        return Ok(None);
    };
    if role != Role::Client {
        return Err(ConfigError::InvalidDns(
            "[DNS] is only valid for client configs".to_string(),
        ));
    }
    let listen = parse_dns_socket(fields, "Listen")?;
    if listen.port() != 53 || listen.ip().is_unspecified() {
        return Err(ConfigError::InvalidDns(
            "DNS.Listen must use a concrete UDP/53 VIP".to_string(),
        ));
    }
    let local_resolver = parse_dns_socket(fields, "LocalResolver")?;
    let remote_resolver = parse_dns_socket(fields, "RemoteResolver")?;
    if local_resolver.port() != 53 || remote_resolver.port() != 53 {
        return Err(ConfigError::InvalidDns(
            "DNS resolvers must use UDP port 53".to_string(),
        ));
    }
    ensure_resolver_family("DNS.LocalResolver", local_resolver.ip(), nat)?;
    ensure_resolver_family("DNS.RemoteResolver", remote_resolver.ip(), nat)?;
    if Some(listen.ip()) == nat.address_v4.map(IpAddr::V4)
        || Some(listen.ip()) == nat.address_v6.map(IpAddr::V6)
    {
        return Err(ConfigError::InvalidDns(
            "DNS.Listen must not equal a NAT address".to_string(),
        ));
    }
    if listen.ip() == local_resolver.ip() || listen.ip() == remote_resolver.ip() {
        return Err(ConfigError::InvalidDns(
            "DNS.Listen must not equal a resolver address".to_string(),
        ));
    }
    let transaction_capacity = parse_optional_usize(fields, "TransactionCapacity", 4096)?;
    if transaction_capacity == 0 {
        return Err(ConfigError::InvalidDns(
            "DNS.TransactionCapacity must be greater than zero".to_string(),
        ));
    }
    let timeout_seconds = parse_optional_u64(fields, "TimeoutSeconds", 5)?;
    if timeout_seconds == 0 {
        return Err(ConfigError::InvalidDns(
            "DNS.TimeoutSeconds must be greater than zero".to_string(),
        ));
    }
    let remote_domains = load_remote_domains(required(fields, "RemoteDomainsFile")?)?;
    Ok(Some(DnsConfig {
        listen,
        local_resolver,
        remote_resolver,
        remote_domains,
        transaction_capacity,
        timeout_seconds,
    }))
}

fn parse_dns_socket(
    fields: &HashMap<String, String>,
    field: &'static str,
) -> Result<SocketAddr, ConfigError> {
    required(fields, field)?
        .parse::<SocketAddr>()
        .map_err(|_| ConfigError::InvalidSocketAddress(format!("DNS.{field}")))
}

fn ensure_resolver_family(
    field: &str,
    address: IpAddr,
    nat: &NatConfig,
) -> Result<(), ConfigError> {
    match address {
        IpAddr::V4(_) if nat.address_v4.is_none() => Err(ConfigError::InvalidDns(format!(
            "{field} requires NAT.AddressV4"
        ))),
        IpAddr::V6(_) if nat.address_v6.is_none() => Err(ConfigError::InvalidDns(format!(
            "{field} requires NAT.AddressV6"
        ))),
        _ => Ok(()),
    }
}

fn load_remote_domains(path: &str) -> Result<Vec<String>, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        ConfigError::InvalidDns(format!("failed to read RemoteDomainsFile: {error}"))
    })?;
    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for line in text.lines() {
        let value = line.split('#').next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        let domain = normalize_domain(value)?;
        if !seen.insert(domain.clone()) {
            return Err(ConfigError::DuplicateRemoteDomain(domain));
        }
        domains.push(domain);
    }
    if domains.is_empty() {
        return Err(ConfigError::InvalidRemoteDomain(
            "RemoteDomainsFile must not be empty".to_string(),
        ));
    }
    Ok(domains)
}

fn normalize_domain(value: &str) -> Result<String, ConfigError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 || value.contains('*') {
        return Err(ConfigError::InvalidRemoteDomain(value));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ConfigError::InvalidRemoteDomain(value));
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn valid(role: &str, addressing: &str, intercepts: &str) -> String {
        let allowed_ips = if role == "client" {
            "[AllowedIPs]\nPrefixes=0.0.0.0/0,::/0\n"
        } else {
            ""
        };
        format!(
            "[Appliance]\nRole={role}\nFlowWorkerCount=2\nChannelCapacity=64\nDcidLength=8\nStatsPath=/tmp/new-proxy-test-stats.json\nSharedKey=0101010101010101010101010101010101010101010101010101010101010101\n\
             [Tunnel]\nInterface=eth0\nNextHopMac=02:00:00:00:00:01\n{addressing}\n\
             {intercepts}\
             [NAT]\nAddressV4=192.0.2.1\nAddressV6=2001:db8:ffff::1\nPortStart=40000\nPortEnd=41000\n\
             {allowed_ips}[XDP]\nMode=skb\n"
        )
    }

    fn temp_file(name: &str, contents: &str) -> String {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "new-proxy-v1-config-test-{}-{}-{name}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
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
            "Listen=192.0.2.20:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        ))
        .unwrap();
        assert_eq!(server.role, Role::Server);
    }

    #[test]
    fn v1_unit_config_parses_allowed_ip_file_modes() {
        let tunnel_file = temp_file(
            "tunnel-cidrs.txt",
            "# tunnel prefixes\n203.0.113.0/24\n203.0.113.0/24\n2001:db8:2::/64\n",
        );
        let direct_file = temp_file(
            "direct-cidrs.txt",
            "# direct prefixes\n10.0.0.0/8\n2001:db8:10::/48\n",
        );
        let base = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );

        let tunnel = ApplianceConfig::parse(&base.replace(
            "Prefixes=0.0.0.0/0,::/0",
            &format!("Prefixes=file:{tunnel_file}"),
        ))
        .unwrap();
        assert_eq!(
            tunnel.ip_policy,
            IpPolicy::TunnelPrefixes(vec![
                "203.0.113.0/24".parse().unwrap(),
                "2001:db8:2::/64".parse().unwrap(),
            ])
        );

        let direct = ApplianceConfig::parse(&base.replace(
            "Prefixes=0.0.0.0/0,::/0",
            &format!("Prefixes=!file:{direct_file}"),
        ))
        .unwrap();
        assert_eq!(
            direct.ip_policy,
            IpPolicy::DirectPrefixes(vec![
                "10.0.0.0/8".parse().unwrap(),
                "2001:db8:10::/48".parse().unwrap(),
            ])
        );
    }

    #[test]
    fn v1_unit_config_rejects_mixed_allowed_ip_modes() {
        let cidr_file = temp_file("cidrs.txt", "203.0.113.0/24\n");
        let config = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "Prefixes=0.0.0.0/0,::/0",
            &format!("Prefixes=file:{cidr_file},203.0.113.0/24"),
        );

        assert_eq!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::MixedAllowedIpModes)
        );
    }

    #[test]
    fn v1_unit_config_rejects_bad_allowed_ip_files() {
        let bad_file = temp_file("bad-cidrs.txt", "not-a-cidr\n");
        let base = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );

        let missing = base.replace(
            "Prefixes=0.0.0.0/0,::/0",
            "Prefixes=file:/tmp/new-proxy-missing-cidrs.txt",
        );
        assert!(matches!(
            ApplianceConfig::parse(&missing),
            Err(ConfigError::AllowedIpFile(_))
        ));

        let bad = base.replace(
            "Prefixes=0.0.0.0/0,::/0",
            &format!("Prefixes=!file:{bad_file}"),
        );
        assert!(matches!(
            ApplianceConfig::parse(&bad),
            Err(ConfigError::InvalidAllowedIp(_))
        ));
    }

    #[test]
    fn v1_unit_config_rejects_allowed_ip_capacity_overflow() {
        let prefixes = (0..=LPM_PREFIX_CAPACITY_PER_FAMILY)
            .map(|index| {
                format!(
                    "10.{}.{}.{}/32",
                    (index >> 16) & 0xff,
                    (index >> 8) & 0xff,
                    index & 0xff
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let cidr_file = temp_file("too-many-cidrs.txt", &prefixes);
        let config = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "Prefixes=0.0.0.0/0,::/0",
            &format!("Prefixes=!file:{cidr_file}"),
        );

        assert_eq!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::AllowedIpCapacity {
                family: "IPv4",
                capacity: LPM_PREFIX_CAPACITY_PER_FAMILY,
            })
        );
    }

    #[test]
    fn v1_unit_config_allows_server_without_allowed_ips() {
        let config = valid(
            "server",
            "Listen=192.0.2.20:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace("[AllowedIPs]\nPrefixes=0.0.0.0/0,::/0\n", "");
        let parsed = ApplianceConfig::parse(&config).unwrap();

        assert_eq!(parsed.role, Role::Server);
        assert_eq!(parsed.ip_policy, IpPolicy::TunnelPrefixes(Vec::new()));
    }

    #[test]
    fn v1_unit_config_rejects_server_allowed_ips() {
        let config = valid(
            "server",
            "Listen=192.0.2.20:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "[XDP]",
            "[AllowedIPs]\nPrefixes=0.0.0.0/0,::/0\n[XDP]",
        );

        assert!(matches!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::UnknownSection(section)) if section == "AllowedIPs"
        ));
    }

    #[test]
    fn v1_unit_config_rejects_malformed_intercept_section_names() {
        let base = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );

        for malformed in ["Interception", "InterceptFoo", "Intercept.", "Intercept.0"] {
            let config = base.replace("[Intercept]", &format!("[{malformed}]"));
            assert_eq!(
                ApplianceConfig::parse(&config),
                Err(ConfigError::UnknownSection(malformed.to_string()))
            );
        }
    }

    #[test]
    fn v1_unit_config_parses_client_dns_config_and_domains() {
        let domains = temp_file(
            "remote-domains.txt",
            "# domains\nGoogle.COM.\nyoutube.com\nsub.github.com\n",
        );
        let config = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "[NAT]\n",
            &format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=[2001:db8:53::1]:53\nRemoteDomainsFile={domains}\nTransactionCapacity=128\nTimeoutSeconds=3\n[NAT]\n"
            ),
        );
        let parsed = ApplianceConfig::parse(&config).unwrap();
        let dns = parsed.dns.unwrap();

        assert_eq!(dns.listen, "192.168.1.53:53".parse().unwrap());
        assert_eq!(dns.transaction_capacity, 128);
        assert_eq!(dns.timeout_seconds, 3);
        assert_eq!(
            dns.remote_domains,
            vec!["google.com", "youtube.com", "sub.github.com"]
        );
    }

    #[test]
    fn v1_unit_config_rejects_dns_on_server_and_duplicate_remote_domains() {
        let duplicate_domains = temp_file("duplicate-domains.txt", "Google.COM.\ngoogle.com\n");
        let client = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "[NAT]\n",
            &format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={duplicate_domains}\n[NAT]\n"
            ),
        );
        assert!(matches!(
            ApplianceConfig::parse(&client),
            Err(ConfigError::DuplicateRemoteDomain(domain)) if domain == "google.com"
        ));

        let domains = temp_file("server-domains.txt", "google.com\n");
        let server = valid(
            "server",
            "Listen=192.0.2.20:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "[NAT]\n",
            &format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={domains}\n[NAT]\n"
            ),
        );
        assert!(matches!(
            ApplianceConfig::parse(&server),
            Err(ConfigError::InvalidDns(_))
        ));
    }

    #[test]
    fn v1_unit_config_rejects_invalid_dns_fields() {
        let domains = temp_file("valid-dns-domains.txt", "google.com\n");
        let base = valid(
            "client",
            "Endpoint=127.0.0.1:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );
        for dns in [
            format!(
                "[DNS]\nListen=0.0.0.0:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={domains}\n[NAT]\n"
            ),
            format!(
                "[DNS]\nListen=192.0.2.1:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={domains}\n[NAT]\n"
            ),
            format!(
                "[DNS]\nListen=192.168.1.53:5353\nLocalResolver=192.0.2.53:53\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={domains}\n[NAT]\n"
            ),
            format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:5353\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={domains}\n[NAT]\n"
            ),
            format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=[2001:db8:53::1]:53\nRemoteDomainsFile={domains}\nTransactionCapacity=0\n[NAT]\n"
            ),
            format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=[2001:db8:53::1]:53\nRemoteDomainsFile={domains}\nTimeoutSeconds=0\n[NAT]\n"
            ),
        ] {
            let config = base.replace("[NAT]\n", &dns);
            assert!(matches!(
                ApplianceConfig::parse(&config),
                Err(ConfigError::InvalidDns(_))
                    | Err(ConfigError::InvalidSocketAddress(_))
            ));
        }
    }

    #[test]
    fn v1_unit_config_rejects_dns_vip_equal_to_tunnel_address() {
        let domains = temp_file("dns-tunnel-conflict-domains.txt", "google.com\n");
        let config = valid(
            "client",
            "Endpoint=192.168.1.53:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        )
        .replace(
            "[NAT]\n",
            &format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={domains}\n[NAT]\n"
            ),
        );

        assert!(matches!(
            ApplianceConfig::parse(&config),
            Err(ConfigError::InvalidDns(message))
                if message.contains("Tunnel.Endpoint")
        ));
    }

    #[test]
    fn v1_unit_config_rejects_address_role_collisions() {
        let domains = temp_file("dns-address-collision-domains.txt", "google.com\n");
        let base = valid(
            "client",
            "Endpoint=198.51.100.20:4433\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
            "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
        );

        let nat_tunnel_collision = base.replace("AddressV4=192.0.2.1", "AddressV4=198.51.100.20");
        assert!(matches!(
            ApplianceConfig::parse(&nat_tunnel_collision),
            Err(ConfigError::InvalidIpAddress(message))
                if message.contains("Tunnel.Endpoint")
        ));

        for resolver in ["LocalResolver", "RemoteResolver"] {
            let dns = format!(
                "[DNS]\nListen=192.168.1.53:53\nLocalResolver=192.0.2.53:53\nRemoteResolver=1.1.1.1:53\nRemoteDomainsFile={domains}\n[NAT]\n"
            )
            .replace(
                &format!("{resolver}=192.0.2.53:53"),
                &format!("{resolver}=192.168.1.53:53"),
            )
            .replace(
                &format!("{resolver}=1.1.1.1:53"),
                &format!("{resolver}=192.168.1.53:53"),
            );
            let config = base.replace("[NAT]\n", &dns);
            assert!(matches!(
                ApplianceConfig::parse(&config),
                Err(ConfigError::InvalidDns(message))
                    if message.contains("resolver address")
            ));
        }
    }

    #[test]
    fn v1_unit_config_rejects_wildcard_server_listen() {
        for listen in ["0.0.0.0:4433", "[::]:4433"] {
            let config = valid(
                "server",
                &format!(
                    "Listen={listen}\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der"
                ),
                "[Intercept]\nInterface=eth1\nNextHopMac=02:00:00:00:00:02\n",
            );

            assert!(ApplianceConfig::parse(&config).is_err());
        }
    }

    #[test]
    fn v1_unit_config_examples_match_the_strict_v1_schema() {
        let placeholder =
            "SharedKey=0000000000000000000000000000000000000000000000000000000000000000";
        let configured =
            "SharedKey=0101010101010101010101010101010101010101010101010101010101010101";
        let direct_cidrs = temp_file("example-direct-cidrs.txt", "203.0.113.0/24\n");
        let remote_domains = temp_file("example-remote-domains.txt", "google.com\n");
        let client_example = include_str!("../conf/client.conf")
            .replace("/etc/new_proxy/direct-cidrs.txt", &direct_cidrs)
            .replace("/etc/new_proxy/remote-domains.txt", &remote_domains);
        assert_eq!(
            ApplianceConfig::parse(&client_example),
            Err(ConfigError::PlaceholderSharedKey)
        );
        assert_eq!(
            ApplianceConfig::parse(include_str!("../conf/server.conf")),
            Err(ConfigError::PlaceholderSharedKey)
        );
        let client =
            ApplianceConfig::parse(&client_example.replace(placeholder, configured)).unwrap();
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
                "Listen=192.0.2.20:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der",
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
            "Listen=192.0.2.20:4433\nServerCertificate=server-cert.der\nServerPrivateKey=server-key.der\nServerCertificateSha256=0202020202020202020202020202020202020202020202020202020202020202",
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
