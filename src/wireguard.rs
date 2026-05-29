use crate::config::{decode_base64_32, PeerConfig};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Default)]
pub struct WgPeerStats {
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: u64,
}

const NETLINK_GENERIC: libc::c_int = 16;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 0x02;
const NLMSG_DONE: u16 = 0x03;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NLA_F_NESTED: u16 = 0x8000;

const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;
const WG_GENL_VERSION: u8 = 1;

const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PEERS: u16 = 8;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;

pub async fn get_wg_dump_stats(interface: &str) -> Result<HashMap<[u8; 32], WgPeerStats>, String> {
    let interface = interface.to_string();
    tokio::task::spawn_blocking(move || get_wg_dump_stats_blocking(&interface))
        .await
        .map_err(|e| format!("Failed to join WireGuard netlink worker: {}", e))?
}

fn get_wg_dump_stats_blocking(interface: &str) -> Result<HashMap<[u8; 32], WgPeerStats>, String> {
    if let Ok(path) = std::env::var("NEW_PROXY_WG_MOCK_DUMP") {
        return parse_wg_dump_text(&fs::read_to_string(path).map_err(|e| e.to_string())?);
    }

    match NetlinkSocket::connect().and_then(|mut sock| {
        wireguard_family_id(&mut sock).and_then(|family| get_device(&mut sock, family, interface))
    }) {
        Ok(stats) => Ok(stats),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(format!("WireGuard netlink query failed: {}", e)),
    }
}

pub fn sync_peer_to_kernel(interface_name: &str, peer: &PeerConfig) -> Result<(), String> {
    if std::env::var_os("NEW_PROXY_WG_SKIP_KERNEL_SYNC").is_some() {
        return Ok(());
    }
    let mut sock = NetlinkSocket::connect().map_err(|e| e.to_string())?;
    let family = wireguard_family_id(&mut sock).map_err(|e| e.to_string())?;
    set_peer(&mut sock, family, interface_name, peer).map_err(|e| e.to_string())
}

pub fn remove_peer_from_kernel(interface_name: &str, pub_key: [u8; 32]) -> Result<(), String> {
    if std::env::var_os("NEW_PROXY_WG_SKIP_KERNEL_SYNC").is_some() {
        return Ok(());
    }
    let mut sock = NetlinkSocket::connect().map_err(|e| e.to_string())?;
    let family = wireguard_family_id(&mut sock).map_err(|e| e.to_string())?;
    remove_peer(&mut sock, family, interface_name, pub_key).map_err(|e| e.to_string())
}

fn parse_wg_dump_text(text: &str) -> Result<HashMap<[u8; 32], WgPeerStats>, String> {
    let mut stats = HashMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 8 {
            continue;
        }
        let endpoint = if parts[2] == "(none)" || parts[2].is_empty() {
            None
        } else {
            Some(parts[2].to_string())
        };
        let allowed_ips = if parts[3] == "(none)" || parts[3].is_empty() {
            Vec::new()
        } else {
            parts[3].split(',').map(|s| s.trim().to_string()).collect()
        };
        if let Ok(pub_key) = decode_base64_32(parts[0]) {
            stats.insert(
                pub_key,
                WgPeerStats {
                    allowed_ips,
                    endpoint,
                    rx_bytes: parts[5].parse().unwrap_or(0),
                    tx_bytes: parts[6].parse().unwrap_or(0),
                    last_handshake: parts[4].parse().unwrap_or(0),
                },
            );
        }
    }
    Ok(stats)
}

struct NetlinkSocket {
    fd: libc::c_int,
    seq: u32,
}

impl NetlinkSocket {
    fn connect() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = 0;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        Ok(Self { fd, seq: 1 })
    }

    fn request(
        &mut self,
        nlmsg_type: u16,
        flags: u16,
        genl_cmd: u8,
        genl_version: u8,
        attrs: Vec<u8>,
    ) -> io::Result<Vec<Vec<u8>>> {
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let mut msg = Vec::with_capacity(20 + attrs.len());
        let len = (16 + 4 + attrs.len()) as u32;
        msg.extend_from_slice(&len.to_ne_bytes());
        msg.extend_from_slice(&nlmsg_type.to_ne_bytes());
        msg.extend_from_slice(&flags.to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.push(genl_cmd);
        msg.push(genl_version);
        msg.extend_from_slice(&0u16.to_ne_bytes());
        msg.extend_from_slice(&attrs);

        let rc = unsafe { libc::send(self.fd, msg.as_ptr() as *const _, msg.len(), 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut responses = Vec::new();
        loop {
            let mut buf = vec![0u8; 65536];
            let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            buf.truncate(n as usize);
            let mut offset = 0;
            while offset + 16 <= buf.len() {
                let nl_len = read_u32(&buf[offset..]) as usize;
                if nl_len < 16 || offset + nl_len > buf.len() {
                    break;
                }
                let msg_type = read_u16(&buf[offset + 4..]);
                let msg_seq = read_u32(&buf[offset + 8..]);
                if msg_seq != seq {
                    offset += align4(nl_len);
                    continue;
                }
                let payload = &buf[offset + 16..offset + nl_len];
                match msg_type {
                    NLMSG_DONE => return Ok(responses),
                    NLMSG_ERROR => {
                        if payload.len() >= 4 {
                            let error = i32::from_ne_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            if error == 0 {
                                return Ok(responses);
                            }
                            return Err(io::Error::from_raw_os_error(-error));
                        }
                        return Err(io::Error::new(io::ErrorKind::Other, "netlink error"));
                    }
                    _ => responses.push(payload.to_vec()),
                }
                offset += align4(nl_len);
            }
            if flags & NLM_F_DUMP == 0 {
                return Ok(responses);
            }
        }
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn wireguard_family_id(sock: &mut NetlinkSocket) -> io::Result<u16> {
    let attrs = attr_string(CTRL_ATTR_FAMILY_NAME, "wireguard");
    let responses = sock.request(GENL_ID_CTRL, NLM_F_REQUEST, CTRL_CMD_GETFAMILY, 1, attrs)?;
    for payload in responses {
        if payload.len() < 4 {
            continue;
        }
        for attr in parse_attrs(&payload[4..]) {
            if attr.kind == CTRL_ATTR_FAMILY_ID && attr.payload.len() >= 2 {
                return Ok(read_u16(attr.payload));
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "wireguard generic netlink family not found",
    ))
}

fn get_device(
    sock: &mut NetlinkSocket,
    family: u16,
    interface: &str,
) -> io::Result<HashMap<[u8; 32], WgPeerStats>> {
    let responses = sock.request(
        family,
        NLM_F_REQUEST | NLM_F_DUMP,
        WG_CMD_GET_DEVICE,
        WG_GENL_VERSION,
        attr_string(WGDEVICE_A_IFNAME, interface),
    )?;
    let mut out = HashMap::new();
    for payload in responses {
        if payload.len() < 4 {
            continue;
        }
        for attr in parse_attrs(&payload[4..]) {
            if attr.kind == WGDEVICE_A_PEERS {
                parse_peers(attr.payload, &mut out);
            }
        }
    }
    Ok(out)
}

fn set_peer(
    sock: &mut NetlinkSocket,
    family: u16,
    interface: &str,
    peer: &PeerConfig,
) -> io::Result<()> {
    let mut peer_attrs = Vec::new();
    peer_attrs.extend(attr_bytes(WGPEER_A_PUBLIC_KEY, &peer.public_key));
    peer_attrs.extend(attr_u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS));
    if let Some(endpoint) = peer.endpoint {
        peer_attrs.extend(attr_bytes(WGPEER_A_ENDPOINT, &sockaddr_bytes(endpoint)));
    }
    let mut allowed_children = Vec::new();
    for (i, allowed_ip) in peer.allowed_ips.iter().enumerate() {
        let mut allowed_attrs = Vec::new();
        match allowed_ip {
            ipnet::IpNet::V4(net) => {
                allowed_attrs.extend(attr_u16(WGALLOWEDIP_A_FAMILY, libc::AF_INET as u16));
                allowed_attrs.extend(attr_bytes(WGALLOWEDIP_A_IPADDR, &net.addr().octets()));
                allowed_attrs.extend(attr_u8(WGALLOWEDIP_A_CIDR_MASK, net.prefix_len()));
            }
            ipnet::IpNet::V6(net) => {
                allowed_attrs.extend(attr_u16(WGALLOWEDIP_A_FAMILY, libc::AF_INET6 as u16));
                allowed_attrs.extend(attr_bytes(WGALLOWEDIP_A_IPADDR, &net.addr().octets()));
                allowed_attrs.extend(attr_u8(WGALLOWEDIP_A_CIDR_MASK, net.prefix_len()));
            }
        }
        allowed_children.extend(attr_nested(i as u16, allowed_attrs));
    }
    peer_attrs.extend(attr_nested(WGPEER_A_ALLOWEDIPS, allowed_children));

    let mut peers = Vec::new();
    peers.extend(attr_nested(0, peer_attrs));
    let mut attrs = Vec::new();
    attrs.extend(attr_string(WGDEVICE_A_IFNAME, interface));
    attrs.extend(attr_nested(WGDEVICE_A_PEERS, peers));
    let _ = sock.request(
        family,
        NLM_F_REQUEST | NLM_F_ACK,
        WG_CMD_SET_DEVICE,
        WG_GENL_VERSION,
        attrs,
    )?;
    Ok(())
}

fn remove_peer(
    sock: &mut NetlinkSocket,
    family: u16,
    interface: &str,
    pub_key: [u8; 32],
) -> io::Result<()> {
    let mut peer_attrs = Vec::new();
    peer_attrs.extend(attr_bytes(WGPEER_A_PUBLIC_KEY, &pub_key));
    peer_attrs.extend(attr_u32(WGPEER_A_FLAGS, WGPEER_F_REMOVE_ME));
    let mut peers = Vec::new();
    peers.extend(attr_nested(0, peer_attrs));
    let mut attrs = Vec::new();
    attrs.extend(attr_string(WGDEVICE_A_IFNAME, interface));
    attrs.extend(attr_nested(WGDEVICE_A_PEERS, peers));
    let _ = sock.request(
        family,
        NLM_F_REQUEST | NLM_F_ACK,
        WG_CMD_SET_DEVICE,
        WG_GENL_VERSION,
        attrs,
    )?;
    Ok(())
}

fn parse_peers(payload: &[u8], out: &mut HashMap<[u8; 32], WgPeerStats>) {
    for peer in parse_attrs(payload) {
        let mut pub_key = None;
        let mut stats = WgPeerStats::default();
        for attr in parse_attrs(peer.payload) {
            match attr.kind {
                WGPEER_A_PUBLIC_KEY if attr.payload.len() >= 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&attr.payload[..32]);
                    pub_key = Some(key);
                }
                WGPEER_A_ENDPOINT => {
                    stats.endpoint = parse_sockaddr(attr.payload).map(|addr| addr.to_string());
                }
                WGPEER_A_LAST_HANDSHAKE_TIME if attr.payload.len() >= 8 => {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&attr.payload[..8]);
                    stats.last_handshake = i64::from_ne_bytes(bytes).max(0) as u64;
                }
                WGPEER_A_RX_BYTES if attr.payload.len() >= 8 => {
                    stats.rx_bytes = read_u64(attr.payload);
                }
                WGPEER_A_TX_BYTES if attr.payload.len() >= 8 => {
                    stats.tx_bytes = read_u64(attr.payload);
                }
                WGPEER_A_ALLOWEDIPS => {
                    stats.allowed_ips = parse_allowed_ips(attr.payload);
                }
                _ => {}
            }
        }
        if let Some(key) = pub_key {
            out.insert(key, stats);
        }
    }
}

fn parse_allowed_ips(payload: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for item in parse_attrs(payload) {
        let mut family = 0u16;
        let mut ip = None;
        let mut cidr = 0u8;
        for attr in parse_attrs(item.payload) {
            match attr.kind {
                WGALLOWEDIP_A_FAMILY if attr.payload.len() >= 2 => family = read_u16(attr.payload),
                WGALLOWEDIP_A_IPADDR => {
                    ip = match (family as i32, attr.payload.len()) {
                        (libc::AF_INET, n) if n >= 4 => Some(IpAddr::V4(Ipv4Addr::new(
                            attr.payload[0],
                            attr.payload[1],
                            attr.payload[2],
                            attr.payload[3],
                        ))),
                        (libc::AF_INET6, n) if n >= 16 => {
                            let mut bytes = [0u8; 16];
                            bytes.copy_from_slice(&attr.payload[..16]);
                            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
                        }
                        _ => None,
                    };
                }
                WGALLOWEDIP_A_CIDR_MASK if !attr.payload.is_empty() => cidr = attr.payload[0],
                _ => {}
            }
        }
        if let Some(ip) = ip {
            out.push(format!("{}/{}", ip, cidr));
        }
    }
    out
}

fn parse_sockaddr(payload: &[u8]) -> Option<SocketAddr> {
    if payload.len() < 2 {
        return None;
    }
    let family = read_u16(payload);
    match family as i32 {
        libc::AF_INET if payload.len() >= 8 => {
            let port = u16::from_be_bytes([payload[2], payload[3]]);
            let ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 if payload.len() >= 28 => {
            let port = u16::from_be_bytes([payload[2], payload[3]]);
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&payload[8..24]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

fn sockaddr_bytes(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(addr) => {
            let mut out = Vec::with_capacity(16);
            out.extend_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&[0u8; 8]);
            out
        }
        SocketAddr::V6(addr) => {
            let mut out = Vec::with_capacity(28);
            out.extend_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&addr.flowinfo().to_ne_bytes());
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.scope_id().to_ne_bytes());
            out
        }
    }
}

#[derive(Clone, Copy)]
struct Attr<'a> {
    kind: u16,
    payload: &'a [u8],
}

fn parse_attrs(mut data: &[u8]) -> Vec<Attr<'_>> {
    let mut attrs = Vec::new();
    while data.len() >= 4 {
        let len = read_u16(data) as usize;
        if len < 4 || len > data.len() {
            break;
        }
        let kind = read_u16(&data[2..]) & !NLA_F_NESTED;
        attrs.push(Attr {
            kind,
            payload: &data[4..len],
        });
        let step = align4(len);
        if step > data.len() {
            break;
        }
        data = &data[step..];
    }
    attrs
}

fn attr_string(kind: u16, value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    attr_bytes(kind, &bytes)
}

fn attr_u8(kind: u16, value: u8) -> Vec<u8> {
    attr_bytes(kind, &[value])
}

fn attr_u16(kind: u16, value: u16) -> Vec<u8> {
    attr_bytes(kind, &value.to_ne_bytes())
}

fn attr_u32(kind: u16, value: u32) -> Vec<u8> {
    attr_bytes(kind, &value.to_ne_bytes())
}

fn attr_nested(kind: u16, payload: Vec<u8>) -> Vec<u8> {
    attr_raw(kind | NLA_F_NESTED, &payload)
}

fn attr_bytes(kind: u16, payload: &[u8]) -> Vec<u8> {
    attr_raw(kind, payload)
}

fn attr_raw(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = 4 + payload.len();
    let mut out = Vec::with_capacity(align4(len));
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(len), 0);
    out
}

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

fn read_u16(data: &[u8]) -> u16 {
    u16::from_ne_bytes([data[0], data[1]])
}

fn read_u32(data: &[u8]) -> u32 {
    u32::from_ne_bytes([data[0], data[1], data[2], data[3]])
}

fn read_u64(data: &[u8]) -> u64 {
    u64::from_ne_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wg_dump_text() {
        let text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t(none)\t1.2.3.4:51820\t10.0.0.2/32,fd00::2/128\t123\t456\t789\t(none)\n";
        let parsed = parse_wg_dump_text(text).unwrap();
        let peer = parsed.get(&[0u8; 32]).unwrap();
        assert_eq!(peer.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(peer.allowed_ips, vec!["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(peer.last_handshake, 123);
        assert_eq!(peer.rx_bytes, 456);
        assert_eq!(peer.tx_bytes, 789);
    }

    #[test]
    fn test_sockaddr_roundtrip_ipv4() {
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        assert_eq!(parse_sockaddr(&sockaddr_bytes(addr)), Some(addr));
    }
}
