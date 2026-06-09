use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::buffer_pool::{BufferPool, PooledBuf};
use crate::config::PeerConfig;
use crate::routing::AllowedIPsRouter;
use crate::tun_io::AsyncTunIo;
use crate::wireguard::WgPeerStats;

const RECEIVER_INDEX_TTL_SECS: u64 = 180;
const RECEIVER_INDEX_CLEANUP_INTERVAL_SECS: u64 = 60;
const RECEIVER_INDEX_MAX_ENTRIES: usize = 65536;
const UNKNOWN_HANDSHAKE_BURST: f64 = 20.0;
const UNKNOWN_HANDSHAKE_REFILL_PER_SEC: f64 = 10.0;
const UNKNOWN_HANDSHAKE_BURST_ENV: &str = "NEW_PROXY_UNKNOWN_HANDSHAKE_BURST";
const UNKNOWN_HANDSHAKE_REFILL_ENV: &str = "NEW_PROXY_UNKNOWN_HANDSHAKE_REFILL_PER_SEC";

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
    unknown_handshake_limiter: Arc<IpTokenBucket>,
}

struct IpTokenBucket {
    history: parking_lot::Mutex<HashMap<IpAddr, (Instant, f64)>>,
    burst: f64,
    refill_per_sec: f64,
    dropped: AtomicU64,
}

impl IpTokenBucket {
    fn new() -> Self {
        Self::new_with_limits(
            env_f64(UNKNOWN_HANDSHAKE_BURST_ENV, UNKNOWN_HANDSHAKE_BURST),
            env_f64(
                UNKNOWN_HANDSHAKE_REFILL_ENV,
                UNKNOWN_HANDSHAKE_REFILL_PER_SEC,
            ),
        )
    }

    fn new_with_limits(burst: f64, refill_per_sec: f64) -> Self {
        Self {
            history: parking_lot::Mutex::new(HashMap::new()),
            burst: burst.max(1.0),
            refill_per_sec: refill_per_sec.max(0.1),
            dropped: AtomicU64::new(0),
        }
    }

    fn allow_scan(&self, ip: IpAddr) -> bool {
        let mut history = self.history.lock();
        if history.len() > 10000 {
            let now = Instant::now();
            history.retain(|_, (last_seen, _)| now.duration_since(*last_seen).as_secs() < 60);
        }
        let now = Instant::now();
        let (last_seen, tokens) = history.entry(ip).or_insert((now, self.burst));
        let elapsed = now.duration_since(*last_seen).as_secs_f64();
        *last_seen = now;
        *tokens = (*tokens + elapsed * self.refill_per_sec).min(self.burst);
        if *tokens >= 1.0 {
            true
        } else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    fn penalize_failed_scan(&self, ip: IpAddr) {
        let mut history = self.history.lock();
        let now = Instant::now();
        let (last_seen, tokens) = history.entry(ip).or_insert((now, self.burst));
        let elapsed = now.duration_since(*last_seen).as_secs_f64();
        *last_seen = now;
        *tokens = (*tokens + elapsed * self.refill_per_sec).min(self.burst);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
        }
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
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
            unknown_handshake_limiter: Arc::new(IpTokenBucket::new()),
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
                        unknown_handshake_drops: self.unknown_handshake_limiter.dropped(),
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
        {
            let index = self.receiver_index.read();
            if let Some(entry) = index.get(&receiver_index) {
                if entry.public_key == public_key && now.saturating_sub(entry.last_seen) < 30 {
                    return;
                }
            }
        }
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
        pool: &BufferPool,
    ) -> Option<(SocketAddr, PooledBuf)> {
        let peer = self.peer_for_tunnel_packet(packet)?;
        let endpoint = (*peer.endpoint.read())?;
        let mut enc_packet = pool.get();
        let enc_len = {
            let mut tunn = peer.tunn.lock();
            match tunn.encapsulate(packet, enc_packet.as_mut_capacity()) {
                TunnResult::WriteToNetwork(enc_pkt) => Some(enc_pkt.len()),
                _ => None,
            }
        }?;
        enc_packet.set_len(enc_len);
        peer.tx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        Some((endpoint, enc_packet))
    }

    pub fn decapsulate_network_packet(
        &self,
        endpoint: SocketAddr,
        incoming: &[u8],
        pool: &BufferPool,
    ) -> Option<(SocketAddr, Vec<UserspaceWgAction>)> {
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
                    self.decapsulate_with_peer(public_key, peer, endpoint, incoming, pool)
                {
                    self.remember_receiver_index(receiver_index, public_key);
                    return Some((endpoint, action));
                }
            }
        }

        let endpoint_peer = {
            let key = self.endpoint_index.read().get(&endpoint).copied();
            key.and_then(|key| self.peers.read().get(&key).cloned().map(|peer| (key, peer)))
        };
        if let Some((public_key, peer)) = endpoint_peer {
            if let Some(action) =
                self.decapsulate_with_peer(public_key, peer, endpoint, incoming, pool)
            {
                if let Some(receiver_index) = receiver_index {
                    self.remember_receiver_index(receiver_index, public_key);
                }
                return Some((endpoint, action));
            }
        }
        if matches!(
            Tunn::parse_incoming_packet(incoming).ok(),
            Some(Packet::PacketData(_))
        ) {
            return None;
        }

        if !self.unknown_handshake_limiter.allow_scan(endpoint.ip()) {
            log::debug!(
                "Rate limit exceeded for unknown userspace WireGuard packet from {}",
                endpoint
            );
            return None;
        }

        for (public_key, peer) in self
            .peers
            .read()
            .iter()
            .map(|(public_key, peer)| (*public_key, peer.clone()))
            .collect::<Vec<_>>()
        {
            if let Some(action) =
                self.decapsulate_with_peer(public_key, peer, endpoint, incoming, pool)
            {
                if let Some(receiver_index) = receiver_index {
                    self.remember_receiver_index(receiver_index, public_key);
                }
                return Some((endpoint, action));
            }
        }
        self.unknown_handshake_limiter
            .penalize_failed_scan(endpoint.ip());
        None
    }

    fn decapsulate_with_peer(
        &self,
        public_key: [u8; 32],
        peer: Arc<UserspaceWgPeer>,
        endpoint: SocketAddr,
        incoming: &[u8],
        pool: &BufferPool,
    ) -> Option<Vec<UserspaceWgAction>> {
        let actions = {
            let mut tunn = peer.tunn.lock();
            let mut actions = Vec::new();
            let mut first = true;
            loop {
                let mut out = pool.get();
                let result = if first {
                    first = false;
                    tunn.decapsulate(Some(endpoint.ip()), incoming, out.as_mut_capacity())
                } else {
                    tunn.decapsulate(None, &[], out.as_mut_capacity())
                };
                let action = match result {
                    TunnResult::WriteToTunnelV4(packet, _)
                    | TunnResult::WriteToTunnelV6(packet, _) => Some((true, packet.len())),
                    TunnResult::WriteToNetwork(response) => Some((false, response.len())),
                    TunnResult::Done => break,
                    TunnResult::Err(_) => break,
                };
                if let Some((write_to_tunnel, len)) = action {
                    out.set_len(len);
                    if write_to_tunnel {
                        actions.push(UserspaceWgAction::WriteToTunnel(out));
                    } else {
                        actions.push(UserspaceWgAction::WriteToNetwork(out));
                    }
                }
            }
            (!actions.is_empty()).then_some(actions)
        };
        if let Some(actions) = actions {
            let endpoint_changed = {
                let endpoint_guard = peer.endpoint.read();
                *endpoint_guard != Some(endpoint)
            };
            if endpoint_changed {
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
            }
            peer.last_handshake
                .store(now_unix_secs(), Ordering::Relaxed);
            if let Some(receiver_index) = Self::receiver_index(incoming) {
                self.remember_receiver_index(receiver_index, public_key);
            }
            for action in &actions {
                if let UserspaceWgAction::WriteToTunnel(packet) = action {
                    peer.rx_bytes
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                }
            }
            return Some(actions);
        }
        None
    }

    pub fn timer_packets(&self, pool: &BufferPool) -> Vec<(SocketAddr, PooledBuf)> {
        let mut packets = Vec::new();
        for peer in self.peer_list() {
            let endpoint = *peer.endpoint.read();
            let Some(endpoint) = endpoint else {
                continue;
            };
            let mut packet = pool.get();
            let packet_len = {
                let mut tunn = peer.tunn.lock();
                match tunn.update_timers(packet.as_mut_capacity()) {
                    TunnResult::WriteToNetwork(packet) => Some(packet.len()),
                    _ => None,
                }
            };
            if let Some(packet_len) = packet_len {
                packet.set_len(packet_len);
                packets.push((endpoint, packet));
            }
        }
        packets
    }
}

pub enum UserspaceWgAction {
    WriteToTunnel(PooledBuf),
    WriteToNetwork(PooledBuf),
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(default)
}

fn push_pending_udp(
    pending: &mut VecDeque<(SocketAddr, PooledBuf)>,
    pending_bytes: &mut usize,
    endpoint: SocketAddr,
    packet: PooledBuf,
    context: &str,
) {
    if pending_bytes.saturating_add(packet.len()) > 64 * 1024 {
        log::warn!(
            "{} UDP pending byte limit reached for {}; dropping packet",
            context,
            endpoint
        );
        return;
    }
    *pending_bytes += packet.len();
    pending.push_back((endpoint, packet));
}

fn push_pending_tun(
    pending: &mut VecDeque<PooledBuf>,
    pending_bytes: &mut usize,
    packet: PooledBuf,
    context: &str,
) {
    if pending_bytes.saturating_add(packet.len()) > 64 * 1024 {
        log::warn!(
            "{} TUN pending byte limit reached; dropping packet",
            context
        );
        return;
    }
    *pending_bytes += packet.len();
    pending.push_back(packet);
}

fn send_or_queue_udp_packet(
    udp_socket: &crate::virtual_tunnel::TunnelSocket,
    endpoint: SocketAddr,
    packet: PooledBuf,
    pending: &mut VecDeque<(SocketAddr, PooledBuf)>,
    pending_bytes: &mut usize,
    context: &str,
) {
    match udp_socket.try_send_to(packet.as_slice(), endpoint) {
        Ok(n) if n == packet.len() => {}
        Ok(n) => {
            log::warn!(
                "{} sent short UDP datagram to {}: {} of {} bytes",
                context,
                endpoint,
                n,
                packet.len()
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            push_pending_udp(pending, pending_bytes, endpoint, packet, context);
        }
        Err(e) => {
            log::warn!(
                "{} failed to send UDP packet to {}: {}",
                context,
                endpoint,
                e
            );
        }
    }
}

fn write_or_queue_tun_packet(
    tun_io: &AsyncTunIo,
    packet: PooledBuf,
    pending: &mut VecDeque<PooledBuf>,
    pending_bytes: &mut usize,
    context: &str,
) {
    match tun_io.try_write_packet(packet.as_slice()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            push_pending_tun(pending, pending_bytes, packet, context);
        }
        Err(e) => {
            log::warn!("{} failed to write packet to TUN: {}", context, e);
        }
    }
}

fn flush_pending_udp(
    udp_socket: &crate::virtual_tunnel::TunnelSocket,
    pending: &mut VecDeque<(SocketAddr, PooledBuf)>,
    pending_bytes: &mut usize,
) {
    while let Some((endpoint, packet)) = pending.pop_front() {
        *pending_bytes = pending_bytes.saturating_sub(packet.len());
        match udp_socket.try_send_to(packet.as_slice(), endpoint) {
            Ok(n) if n == packet.len() => {}
            Ok(n) => {
                log::warn!(
                    "pending userspace WireGuard UDP sent short datagram to {}: {} of {} bytes",
                    endpoint,
                    n,
                    packet.len()
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                *pending_bytes += packet.len();
                pending.push_front((endpoint, packet));
                break;
            }
            Err(e) => {
                log::warn!(
                    "pending userspace WireGuard UDP failed to send packet to {}: {}",
                    endpoint,
                    e
                );
            }
        }
    }
}

fn flush_pending_tun(
    tun_io: &AsyncTunIo,
    pending: &mut VecDeque<PooledBuf>,
    pending_bytes: &mut usize,
) {
    while let Some(packet) = pending.pop_front() {
        *pending_bytes = pending_bytes.saturating_sub(packet.len());
        match tun_io.try_write_packet(packet.as_slice()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                *pending_bytes += packet.len();
                pending.push_front(packet);
                break;
            }
            Err(e) => {
                log::warn!(
                    "pending userspace WireGuard TUN failed to write packet: {}",
                    e
                );
            }
        }
    }
}

#[cfg(not(tarpaulin))]
pub async fn run_userspace_wg_loop(
    tun_io: Arc<AsyncTunIo>,
    udp_socket: crate::virtual_tunnel::TunnelSocket,
    registry: UserspaceWgRegistry,
    mtu: u16,
) -> Result<(), String> {
    let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(mtu);
    let buffer_pool = BufferPool::new(packet_buffer_size);
    let mut tun_buf = buffer_pool.get();
    let mut udp_buf = buffer_pool.get();
    let mut pending_tun = VecDeque::new();
    let mut pending_udp = VecDeque::new();
    let mut pending_tun_bytes = 0usize;
    let mut pending_udp_bytes = 0usize;

    loop {
        flush_pending_tun(&tun_io, &mut pending_tun, &mut pending_tun_bytes);
        flush_pending_udp(&udp_socket, &mut pending_udp, &mut pending_udp_bytes);
        let tun_io_for_writable = tun_io.clone();
        let udp_socket_for_writable = udp_socket.clone();
        tokio::select! {
            writable = tun_io_for_writable.writable(), if !pending_tun.is_empty() => {
                if writable.is_ok() {
                    flush_pending_tun(&tun_io, &mut pending_tun, &mut pending_tun_bytes);
                }
            }

            writable = udp_socket_for_writable.writable(), if !pending_udp.is_empty() => {
                if writable.is_ok() {
                    flush_pending_udp(&udp_socket, &mut pending_udp, &mut pending_udp_bytes);
                }
            }

            read_res = tun_io.read(tun_buf.as_mut_capacity()) => {
                let Ok(n) = read_res else {
                    continue;
                };
                if n == 0 {
                    continue;
                }
                tun_buf.set_len(n);
                match registry.encapsulate_tunnel_packet(tun_buf.as_slice(), &buffer_pool) {
                    Some((endpoint, enc_packet)) => {
                        send_or_queue_udp_packet(
                            &udp_socket,
                            endpoint,
                            enc_packet,
                            &mut pending_udp,
                            &mut pending_udp_bytes,
                            "userspace WireGuard",
                        );
                    }
                    None => {
                        log::debug!("No userspace WireGuard peer route or endpoint for TUN packet");
                    }
                }
            }

            udp_res = udp_socket.recv_from(udp_buf.as_mut_capacity()) => {
                let Ok((n, endpoint)) = udp_res else {
                    continue;
                };
                if n == 0 {
                    continue;
                }
                udp_buf.set_len(n);
                if n >= 4 && &udp_buf.as_slice()[..4] == b"PING" {
                    if let Some(pong) = buffer_pool.copy_from_slice(b"PONG") {
                        send_or_queue_udp_packet(
                            &udp_socket,
                            endpoint,
                            pong,
                            &mut pending_udp,
                            &mut pending_udp_bytes,
                            "userspace WireGuard PONG",
                        );
                    }
                    continue;
                }
                if let Some((reply_endpoint, actions)) =
                    registry.decapsulate_network_packet(endpoint, udp_buf.as_slice(), &buffer_pool)
                {
                    for action in actions {
                        match action {
                            UserspaceWgAction::WriteToTunnel(packet) => {
                                write_or_queue_tun_packet(
                                    &tun_io,
                                    packet,
                                    &mut pending_tun,
                                    &mut pending_tun_bytes,
                                    "userspace WireGuard",
                                );
                            }
                            UserspaceWgAction::WriteToNetwork(packet) => {
                                send_or_queue_udp_packet(
                                    &udp_socket,
                                    reply_endpoint,
                                    packet,
                                    &mut pending_udp,
                                    &mut pending_udp_bytes,
                                    "userspace WireGuard response",
                                );
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
    udp_socket: crate::virtual_tunnel::TunnelSocket,
    registry: UserspaceWgRegistry,
    mtu: u16,
) {
    let buffer_pool = BufferPool::new(crate::config::packet_buffer_size_for_mtu(mtu));
    let mut timer = tokio::time::interval(std::time::Duration::from_millis(100));
    let mut pending_udp = VecDeque::new();
    let mut pending_udp_bytes = 0usize;
    loop {
        flush_pending_udp(&udp_socket, &mut pending_udp, &mut pending_udp_bytes);
        let udp_socket_for_writable = udp_socket.clone();
        tokio::select! {
            _ = timer.tick() => {
                for (endpoint, packet) in registry.timer_packets(&buffer_pool) {
                    send_or_queue_udp_packet(
                        &udp_socket,
                        endpoint,
                        packet,
                        &mut pending_udp,
                        &mut pending_udp_bytes,
                        "userspace WireGuard timer",
                    );
                }
            }

            writable = udp_socket_for_writable.writable(), if !pending_udp.is_empty() => {
                if writable.is_ok() {
                    flush_pending_udp(&udp_socket, &mut pending_udp, &mut pending_udp_bytes);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(20u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    fn ipv4_packet_to(dst: [u8; 4]) -> Vec<u8> {
        ipv4_packet([10, 0, 0, 2], dst)
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
    fn unknown_handshake_limiter_rejects_after_burst() {
        let limiter = IpTokenBucket::new_with_limits(UNKNOWN_HANDSHAKE_BURST, 0.1);
        let ip = "192.0.2.10".parse().unwrap();

        for _ in 0..(UNKNOWN_HANDSHAKE_BURST as usize) {
            assert!(limiter.allow_scan(ip));
            limiter.penalize_failed_scan(ip);
        }
        assert!(!limiter.allow_scan(ip));
        assert_eq!(limiter.dropped(), 1);
    }

    #[test]
    fn unknown_handshake_limiter_does_not_penalize_successful_scans() {
        let limiter = IpTokenBucket::new_with_limits(2.0, 0.1);
        let ip = "192.0.2.10".parse().unwrap();

        assert!(limiter.allow_scan(ip));
        assert!(limiter.allow_scan(ip));
        assert!(limiter.allow_scan(ip));
        assert_eq!(limiter.dropped(), 0);
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
        let pool = BufferPool::new(2048);

        assert!(registry
            .encapsulate_tunnel_packet(&ipv4_packet_to([10, 0, 0, 10]), &pool)
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
            .encapsulate_tunnel_packet(&ipv4_packet_to([10, 0, 0, 10]), &pool)
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
        let pool = BufferPool::new(2048);

        assert!(registry.timer_packets(&pool).is_empty());
    }

    #[test]
    fn decapsulate_flushes_queued_packet_after_handshake_response() {
        let client_private = StaticSecret::from([1u8; 32]);
        let server_private = StaticSecret::from([2u8; 32]);
        let client_public = PublicKey::from(&client_private).to_bytes();
        let server_public = PublicKey::from(&server_private).to_bytes();
        let client_endpoint = "127.0.0.1:41000".parse::<SocketAddr>().unwrap();
        let server_endpoint = "127.0.0.1:51820".parse::<SocketAddr>().unwrap();

        let client = UserspaceWgRegistry::new(
            client_private.to_bytes(),
            &[PeerConfig {
                public_key: server_public,
                allowed_ips: vec!["10.40.0.1/32".parse().unwrap()],
                endpoint: Some(server_endpoint),
                proxy_port: None,
            }],
        )
        .unwrap();
        let server = UserspaceWgRegistry::new(
            server_private.to_bytes(),
            &[PeerConfig {
                public_key: client_public,
                allowed_ips: vec!["10.40.0.2/32".parse().unwrap()],
                endpoint: None,
                proxy_port: None,
            }],
        )
        .unwrap();

        let original = ipv4_packet([10, 40, 0, 2], [10, 40, 0, 1]);
        let client_pool = BufferPool::new(2048);
        let server_pool = BufferPool::new(2048);
        let (endpoint, handshake_init) = client
            .encapsulate_tunnel_packet(&original, &client_pool)
            .unwrap();
        assert_eq!(endpoint, server_endpoint);

        let (_, server_actions) = server
            .decapsulate_network_packet(client_endpoint, handshake_init.as_slice(), &server_pool)
            .unwrap();
        let handshake_response = server_actions
            .into_iter()
            .find_map(|action| match action {
                UserspaceWgAction::WriteToNetwork(packet) => Some(packet),
                UserspaceWgAction::WriteToTunnel(_) => None,
            })
            .unwrap();

        let (_, client_actions) = client
            .decapsulate_network_packet(
                server_endpoint,
                handshake_response.as_slice(),
                &client_pool,
            )
            .unwrap();
        let network_packets = client_actions
            .into_iter()
            .filter_map(|action| match action {
                UserspaceWgAction::WriteToNetwork(packet) => Some(packet),
                UserspaceWgAction::WriteToTunnel(_) => None,
            })
            .collect::<Vec<_>>();
        assert!(
            network_packets.len() >= 2,
            "client must send handshake keepalive and flushed queued tunnel packet"
        );

        let mut delivered = None;
        for packet in network_packets {
            if let Some((_, actions)) =
                server.decapsulate_network_packet(client_endpoint, packet.as_slice(), &server_pool)
            {
                for action in actions {
                    if let UserspaceWgAction::WriteToTunnel(packet) = action {
                        delivered = Some(packet);
                    }
                }
            }
        }
        assert_eq!(
            delivered.map(|packet| packet.as_slice().to_vec()),
            Some(original)
        );
    }
}
