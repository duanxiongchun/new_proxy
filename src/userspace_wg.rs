use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::PeerConfig;
use crate::routing::AllowedIPsRouter;
use crate::tun_io::AsyncTunIo;
use crate::wireguard::WgPeerStats;

const RECEIVER_INDEX_TTL_SECS: u64 = 180;
const RECEIVER_INDEX_CLEANUP_INTERVAL_SECS: u64 = 60;
const RECEIVER_INDEX_MAX_ENTRIES: usize = 65536;

pub struct UserspaceWg {
    tunn: Tunn,
}

impl UserspaceWg {
    pub fn new(private_key: StaticSecret, peer_public_key: PublicKey) -> Result<Self, String> {
        let tunn = Tunn::new(private_key, peer_public_key, None, None, 1, None);
        Ok(Self { tunn })
    }

    pub fn decapsulate<'a>(
        &mut self,
        src_ip: Option<IpAddr>,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.tunn.decapsulate(src_ip, src, dst)
    }

    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.encapsulate(src, dst)
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.update_timers(dst)
    }
}

struct UserspaceWgPeer {
    allowed_ips: Vec<ipnet::IpNet>,
    endpoint: parking_lot::RwLock<Option<SocketAddr>>,
    tunn: parking_lot::Mutex<UserspaceWg>,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    last_handshake: AtomicU64,
}

#[derive(Clone, Copy)]
struct ReceiverIndexEntry {
    public_key: [u8; 32],
    last_seen: u64,
}

#[derive(Clone)]
pub struct UserspaceWgRegistry {
    private_key: [u8; 32],
    peers: Arc<parking_lot::RwLock<HashMap<[u8; 32], Arc<UserspaceWgPeer>>>>,
    router: Arc<parking_lot::RwLock<AllowedIPsRouter<[u8; 32]>>>,
    endpoint_index: Arc<parking_lot::RwLock<HashMap<SocketAddr, [u8; 32]>>>,
    receiver_index: Arc<parking_lot::RwLock<HashMap<u32, ReceiverIndexEntry>>>,
    receiver_index_last_cleanup: Arc<AtomicU64>,
}

impl UserspaceWgRegistry {
    pub fn new(private_key: [u8; 32], peers: &[PeerConfig]) -> Result<Self, String> {
        let registry = Self {
            private_key,
            peers: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            router: Arc::new(parking_lot::RwLock::new(AllowedIPsRouter::new())),
            endpoint_index: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            receiver_index: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            receiver_index_last_cleanup: Arc::new(AtomicU64::new(0)),
        };
        for peer in peers {
            registry.add_or_replace_peer(peer.clone())?;
        }
        Ok(registry)
    }

    pub fn add_or_replace_peer(&self, peer: PeerConfig) -> Result<(), String> {
        self.receiver_index
            .write()
            .retain(|_, entry| entry.public_key != peer.public_key);
        self.endpoint_index
            .write()
            .retain(|_, public_key| *public_key != peer.public_key);
        let wg = UserspaceWg::new(
            StaticSecret::from(self.private_key),
            PublicKey::from(peer.public_key),
        )?;
        let endpoint = peer.endpoint;
        let peer_state = Arc::new(UserspaceWgPeer {
            allowed_ips: peer.allowed_ips.clone(),
            endpoint: parking_lot::RwLock::new(endpoint),
            tunn: parking_lot::Mutex::new(wg),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            last_handshake: AtomicU64::new(0),
        });

        self.peers.write().insert(peer.public_key, peer_state);
        if let Some(endpoint) = endpoint {
            self.endpoint_index
                .write()
                .insert(endpoint, peer.public_key);
        }
        self.rebuild_router();
        Ok(())
    }

    pub fn remove_peer(&self, public_key: &[u8; 32]) {
        self.peers.write().remove(public_key);
        self.endpoint_index
            .write()
            .retain(|_, entry_public_key| entry_public_key != public_key);
        self.receiver_index
            .write()
            .retain(|_, entry| entry.public_key != *public_key);
        self.rebuild_router();
    }

    pub fn snapshot(&self) -> HashMap<[u8; 32], WgPeerStats> {
        self.peers
            .read()
            .iter()
            .map(|(public_key, peer)| {
                (
                    *public_key,
                    WgPeerStats {
                        allowed_ips: peer.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
                        endpoint: peer.endpoint.read().map(|addr| addr.to_string()),
                        rx_bytes: peer.rx_bytes.load(Ordering::Relaxed),
                        tx_bytes: peer.tx_bytes.load(Ordering::Relaxed),
                        last_handshake: peer.last_handshake.load(Ordering::Relaxed),
                    },
                )
            })
            .collect()
    }

    fn rebuild_router(&self) {
        let mut router = AllowedIPsRouter::new();
        for (public_key, peer) in self.peers.read().iter() {
            for allowed_ip in &peer.allowed_ips {
                router.insert(*allowed_ip, *public_key);
            }
        }
        *self.router.write() = router;
    }

    fn peer_for_tunnel_packet(&self, packet: &[u8]) -> Option<Arc<UserspaceWgPeer>> {
        let dst = Tunn::dst_address(packet)?;
        let key = self.router.read().longest_match(dst)?;
        self.peers.read().get(&key).cloned()
    }

    fn peer_list(&self) -> Vec<Arc<UserspaceWgPeer>> {
        self.peers.read().values().cloned().collect()
    }

    fn receiver_index(packet: &[u8]) -> Option<u32> {
        match Tunn::parse_incoming_packet(packet).ok()? {
            Packet::HandshakeInit(_) => None,
            Packet::HandshakeResponse(packet) => Some(packet.receiver_idx),
            Packet::PacketCookieReply(packet) => Some(packet.receiver_idx),
            Packet::PacketData(packet) => Some(packet.receiver_idx),
        }
    }

    fn remember_receiver_index(&self, receiver_index: u32, public_key: [u8; 32]) {
        let now = now_unix_secs();
        let last_cleanup = self.receiver_index_last_cleanup.load(Ordering::Relaxed);
        let should_cleanup = now.saturating_sub(last_cleanup)
            >= RECEIVER_INDEX_CLEANUP_INTERVAL_SECS
            && self
                .receiver_index_last_cleanup
                .compare_exchange(last_cleanup, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok();
        let mut index = self.receiver_index.write();
        if should_cleanup || index.len() >= RECEIVER_INDEX_MAX_ENTRIES {
            index.retain(|_, entry| now.saturating_sub(entry.last_seen) <= RECEIVER_INDEX_TTL_SECS);
        }
        if index.len() >= RECEIVER_INDEX_MAX_ENTRIES {
            if let Some(oldest) = index
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(receiver_index, _)| *receiver_index)
            {
                index.remove(&oldest);
            }
        }
        index.insert(
            receiver_index,
            ReceiverIndexEntry {
                public_key,
                last_seen: now,
            },
        );
    }

    pub fn encapsulate_tunnel_packet(
        &self,
        packet: &[u8],
        wg_buf: &mut [u8],
    ) -> Option<(SocketAddr, Vec<u8>)> {
        let peer = self.peer_for_tunnel_packet(packet)?;
        let endpoint = (*peer.endpoint.read())?;
        let enc_packet = {
            let mut tunn = peer.tunn.lock();
            match tunn.encapsulate(packet, wg_buf) {
                TunnResult::WriteToNetwork(enc_pkt) => Some(enc_pkt.to_vec()),
                _ => None,
            }
        }?;
        peer.tx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        Some((endpoint, enc_packet))
    }

    pub fn decapsulate_network_packet(
        &self,
        endpoint: SocketAddr,
        incoming: &[u8],
        wg_buf: &mut [u8],
    ) -> Option<(SocketAddr, UserspaceWgAction)> {
        let receiver_index = Self::receiver_index(incoming);
        if let Some(receiver_index) = receiver_index {
            let indexed_peer = {
                let key = self
                    .receiver_index
                    .read()
                    .get(&receiver_index)
                    .map(|entry| entry.public_key);
                key.and_then(|key| self.peers.read().get(&key).cloned().map(|peer| (key, peer)))
            };
            if let Some((public_key, peer)) = indexed_peer {
                if let Some(action) =
                    self.decapsulate_with_peer(public_key, peer, endpoint, incoming, wg_buf)
                {
                    return Some((endpoint, action));
                }
            }
            if matches!(
                Tunn::parse_incoming_packet(incoming).ok(),
                Some(Packet::PacketData(_))
            ) {
                return None;
            }
        }

        let endpoint_peer = {
            let key = self.endpoint_index.read().get(&endpoint).copied();
            key.and_then(|key| self.peers.read().get(&key).cloned().map(|peer| (key, peer)))
        };
        if let Some((public_key, peer)) = endpoint_peer {
            if let Some(action) =
                self.decapsulate_with_peer(public_key, peer, endpoint, incoming, wg_buf)
            {
                if let Some(receiver_index) = receiver_index {
                    self.remember_receiver_index(receiver_index, public_key);
                }
                return Some((endpoint, action));
            }
        }

        for (public_key, peer) in self
            .peers
            .read()
            .iter()
            .map(|(public_key, peer)| (*public_key, peer.clone()))
            .collect::<Vec<_>>()
        {
            if let Some(action) =
                self.decapsulate_with_peer(public_key, peer, endpoint, incoming, wg_buf)
            {
                if let Some(receiver_index) = receiver_index {
                    self.remember_receiver_index(receiver_index, public_key);
                }
                return Some((endpoint, action));
            }
        }
        None
    }

    fn decapsulate_with_peer(
        &self,
        public_key: [u8; 32],
        peer: Arc<UserspaceWgPeer>,
        endpoint: SocketAddr,
        incoming: &[u8],
        wg_buf: &mut [u8],
    ) -> Option<UserspaceWgAction> {
        let action = {
            let mut tunn = peer.tunn.lock();
            match tunn.decapsulate(Some(endpoint.ip()), incoming, wg_buf) {
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    Some(UserspaceWgAction::WriteToTunnel(packet.to_vec()))
                }
                TunnResult::WriteToNetwork(response) => {
                    Some(UserspaceWgAction::WriteToNetwork(response.to_vec()))
                }
                TunnResult::Done | TunnResult::Err(_) => None,
            }
        };
        if let Some(action) = action {
            let old_endpoint = {
                let mut endpoint_guard = peer.endpoint.write();
                let old_endpoint = *endpoint_guard;
                *endpoint_guard = Some(endpoint);
                old_endpoint
            };
            let mut endpoint_index = self.endpoint_index.write();
            if let Some(old_endpoint) = old_endpoint.filter(|old| *old != endpoint) {
                endpoint_index.remove(&old_endpoint);
            }
            endpoint_index.insert(endpoint, public_key);
            peer.last_handshake
                .store(now_unix_secs(), Ordering::Relaxed);
            if let Some(receiver_index) = Self::receiver_index(incoming) {
                self.remember_receiver_index(receiver_index, public_key);
            }
            if let UserspaceWgAction::WriteToTunnel(packet) = &action {
                peer.rx_bytes
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
            }
            return Some(action);
        }
        None
    }

    pub fn timer_packets(&self, wg_buf: &mut [u8]) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut packets = Vec::new();
        for peer in self.peer_list() {
            let endpoint = *peer.endpoint.read();
            let Some(endpoint) = endpoint else {
                continue;
            };
            let packet = {
                let mut tunn = peer.tunn.lock();
                match tunn.update_timers(wg_buf) {
                    TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                    _ => None,
                }
            };
            if let Some(packet) = packet {
                packets.push((endpoint, packet));
            }
        }
        packets
    }
}

pub enum UserspaceWgAction {
    WriteToTunnel(Vec<u8>),
    WriteToNetwork(Vec<u8>),
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(not(tarpaulin))]
pub async fn run_userspace_wg_loop(
    tun_io: Arc<AsyncTunIo>,
    udp_socket: Arc<tokio::net::UdpSocket>,
    registry: UserspaceWgRegistry,
) -> Result<(), String> {
    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];
    let mut wg_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            read_res = tun_io.read(&mut tun_buf) => {
                let Ok(n) = read_res else {
                    continue;
                };
                if n == 0 {
                    continue;
                }
                match registry.encapsulate_tunnel_packet(&tun_buf[..n], &mut wg_buf) {
                    Some((endpoint, enc_packet)) => {
                        if let Err(e) = udp_socket.send_to(&enc_packet, endpoint).await {
                            log::warn!("Failed to send userspace WireGuard packet to {}: {}", endpoint, e);
                        }
                    }
                    None => {
                        log::debug!("No userspace WireGuard peer route or endpoint for TUN packet");
                    }
                }
            }

            udp_res = udp_socket.recv_from(&mut udp_buf) => {
                let Ok((n, endpoint)) = udp_res else {
                    continue;
                };
                if n == 0 {
                    continue;
                }
                if let Some((reply_endpoint, action)) =
                    registry.decapsulate_network_packet(endpoint, &udp_buf[..n], &mut wg_buf)
                {
                    match action {
                        UserspaceWgAction::WriteToTunnel(packet) => {
                            if let Err(e) = tun_io.write_packet(&packet).await {
                                log::warn!("Failed to write userspace WireGuard packet to TUN: {}", e);
                            }
                        }
                        UserspaceWgAction::WriteToNetwork(packet) => {
                            if let Err(e) = udp_socket.send_to(&packet, reply_endpoint).await {
                                log::warn!("Failed to send userspace WireGuard response to {}: {}", reply_endpoint, e);
                            }
                        }
                    }
                }
            }

        }
    }
}

#[cfg(not(tarpaulin))]
pub async fn run_userspace_wg_timer_loop(
    udp_socket: Arc<tokio::net::UdpSocket>,
    registry: UserspaceWgRegistry,
) {
    let mut wg_buf = vec![0u8; 65535];
    let mut timer = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        timer.tick().await;
        for (endpoint, packet) in registry.timer_packets(&mut wg_buf) {
            if let Err(e) = udp_socket.send_to(&packet, endpoint).await {
                log::warn!(
                    "Failed to send userspace WireGuard timer packet to {}: {}",
                    endpoint,
                    e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet_to(dst: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    #[test]
    fn test_boringtun_state() {
        let private_key = StaticSecret::from([1u8; 32]);
        let public_key = PublicKey::from(&private_key);
        let tunn = UserspaceWg::new(private_key, public_key);
        assert!(tunn.is_ok());
    }

    #[test]
    fn receiver_index_cache_is_removed_with_peer() {
        let private_key = StaticSecret::from([1u8; 32]);
        let public_key = PublicKey::from(&private_key).to_bytes();
        let endpoint = "127.0.0.1:51820".parse().unwrap();
        let peer = PeerConfig {
            public_key,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            endpoint: Some(endpoint),
            proxy_port: None,
        };
        let registry = UserspaceWgRegistry::new(private_key.to_bytes(), &[peer]).unwrap();

        assert_eq!(
            registry.endpoint_index.read().get(&endpoint).copied(),
            Some(public_key)
        );
        registry.remember_receiver_index(42, public_key);
        assert!(registry.receiver_index.read().contains_key(&42));
        registry.remove_peer(&public_key);
        assert!(!registry.receiver_index.read().contains_key(&42));
        assert!(!registry.endpoint_index.read().contains_key(&endpoint));
    }

    #[test]
    fn receiver_index_cache_prunes_expired_entries() {
        let private_key = StaticSecret::from([1u8; 32]);
        let public_key = PublicKey::from(&private_key).to_bytes();
        let peer = PeerConfig {
            public_key,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: None,
        };
        let registry = UserspaceWgRegistry::new(private_key.to_bytes(), &[peer]).unwrap();

        registry.receiver_index.write().insert(
            7,
            ReceiverIndexEntry {
                public_key,
                last_seen: now_unix_secs() - RECEIVER_INDEX_TTL_SECS - 1,
            },
        );
        registry
            .receiver_index_last_cleanup
            .store(0, Ordering::Relaxed);

        registry.remember_receiver_index(8, public_key);
        let index = registry.receiver_index.read();
        assert!(!index.contains_key(&7));
        assert!(index.contains_key(&8));
    }

    #[test]
    fn registry_add_replace_and_remove_updates_snapshot() {
        let private_key = StaticSecret::from([1u8; 32]);
        let public_key = PublicKey::from(&private_key).to_bytes();
        let registry = UserspaceWgRegistry::new(private_key.to_bytes(), &[]).unwrap();

        registry
            .add_or_replace_peer(PeerConfig {
                public_key,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                endpoint: Some("127.0.0.1:51820".parse().unwrap()),
                proxy_port: None,
            })
            .unwrap();
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[&public_key].allowed_ips, vec!["10.0.0.0/24"]);
        assert_eq!(
            snapshot[&public_key].endpoint.as_deref(),
            Some("127.0.0.1:51820")
        );

        registry
            .add_or_replace_peer(PeerConfig {
                public_key,
                allowed_ips: vec!["10.1.0.0/24".parse().unwrap()],
                endpoint: Some("127.0.0.1:51821".parse().unwrap()),
                proxy_port: None,
            })
            .unwrap();
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[&public_key].allowed_ips, vec!["10.1.0.0/24"]);
        assert_eq!(
            snapshot[&public_key].endpoint.as_deref(),
            Some("127.0.0.1:51821")
        );

        registry.remove_peer(&public_key);
        assert!(registry.snapshot().is_empty());
    }

    #[test]
    fn encapsulate_tunnel_packet_returns_none_without_route_or_endpoint() {
        let private_key = StaticSecret::from([1u8; 32]);
        let public_key = PublicKey::from(&private_key).to_bytes();
        let registry = UserspaceWgRegistry::new(private_key.to_bytes(), &[]).unwrap();
        let mut wg_buf = vec![0u8; 2048];

        assert!(registry
            .encapsulate_tunnel_packet(&ipv4_packet_to([10, 0, 0, 10]), &mut wg_buf)
            .is_none());

        registry
            .add_or_replace_peer(PeerConfig {
                public_key,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                endpoint: None,
                proxy_port: None,
            })
            .unwrap();
        assert!(registry
            .encapsulate_tunnel_packet(&ipv4_packet_to([10, 0, 0, 10]), &mut wg_buf)
            .is_none());
    }

    #[test]
    fn timer_packets_skip_peers_without_endpoint() {
        let private_key = StaticSecret::from([1u8; 32]);
        let public_key = PublicKey::from(&private_key).to_bytes();
        let peer = PeerConfig {
            public_key,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            endpoint: None,
            proxy_port: None,
        };
        let registry = UserspaceWgRegistry::new(private_key.to_bytes(), &[peer]).unwrap();
        let mut wg_buf = vec![0u8; 2048];

        assert!(registry.timer_packets(&mut wg_buf).is_empty());
    }
}
