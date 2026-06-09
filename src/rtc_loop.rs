use crate::buffer_pool::{BufferPool, PooledBuf};
use crate::proxy_proto::write_target_addr;
use crate::quic_pool::{PoolState, QuicConnStats};
use crate::relay::PeerL4Stats;
use crate::telemetry::WorkerTelemetrySnapshot;
use crate::tun_io::AsyncTunIo;
use crate::userspace_tcp::UserspaceTcpStack;
use crate::userspace_wg::{UserspaceWgAction, UserspaceWgRegistry};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::socket::AnySocket;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::{Context, Poll, Wake};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::timeout;

type NatKey = (IpAddr, u16, u16);
type FlowKey = (IpAddr, u16, IpAddr, u16);
const DEFAULT_BRIDGE_PENDING_LIMIT: usize = 64;
const DEFAULT_BRIDGE_PENDING_BYTES_LIMIT: usize = 64 * 1024;
const HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_WORKER_TCP_FLOWS: usize = 1024;
const DEFAULT_USERSPACE_TCP_SOCKET_BUFFER_BYTES: usize = 32 * 1024;

const BRIDGE_PENDING_LIMIT_ENV: &str = "NEW_PROXY_BRIDGE_PENDING_LIMIT";
const BRIDGE_PENDING_BYTES_LIMIT_ENV: &str = "NEW_PROXY_BRIDGE_PENDING_BYTES_LIMIT";
const MAX_WORKER_TCP_FLOWS_ENV: &str = "NEW_PROXY_MAX_WORKER_TCP_FLOWS";
const USERSPACE_TCP_SOCKET_BUFFER_BYTES_ENV: &str = "NEW_PROXY_TCP_SOCKET_BUFFER_BYTES";

fn bridge_pending_limit() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| env_usize(BRIDGE_PENDING_LIMIT_ENV, DEFAULT_BRIDGE_PENDING_LIMIT, 1))
}

fn bridge_pending_bytes_limit() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        env_usize(
            BRIDGE_PENDING_BYTES_LIMIT_ENV,
            DEFAULT_BRIDGE_PENDING_BYTES_LIMIT,
            1500,
        )
    })
}

fn max_worker_tcp_flows() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| env_usize(MAX_WORKER_TCP_FLOWS_ENV, DEFAULT_MAX_WORKER_TCP_FLOWS, 1))
}

fn userspace_tcp_socket_buffer_bytes() -> usize {
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        env_usize(
            USERSPACE_TCP_SOCKET_BUFFER_BYTES_ENV,
            DEFAULT_USERSPACE_TCP_SOCKET_BUFFER_BYTES,
            4096,
        )
    })
}

fn env_usize(name: &str, default: usize, min: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value >= min)
        .unwrap_or(default)
}

struct NotifyWake {
    notify: Arc<Notify>,
}

impl Wake for NotifyWake {
    fn wake(self: Arc<Self>) {
        self.notify.notify_one();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify.notify_one();
    }
}

fn with_notify_context<R>(notify: &Arc<Notify>, f: impl FnOnce(&mut Context<'_>) -> R) -> R {
    let waker = std::task::Waker::from(Arc::new(NotifyWake {
        notify: notify.clone(),
    }));
    let mut cx = Context::from_waker(&waker);
    f(&mut cx)
}

async fn establish_quic_bridge(
    original_dest: SocketAddr,
    peer_pub_key: [u8; 32],
    data_plane: Arc<crate::L4DataPlaneSnapshot>,
    peer_telemetry: Option<Arc<crate::telemetry::TelemetryRegistry>>,
) -> Option<ActiveQuicBridge> {
    let quic_pool = data_plane.client_quic_pools.get(&peer_pub_key).cloned()?;
    if !matches!(quic_pool.get_state(), PoolState::Active) {
        log::warn!(
            "QUIC pool is not active, dropping userspace stream to {}",
            original_dest
        );
        return None;
    }
    let stats = peer_telemetry
        .as_ref()
        .map(|telemetry| telemetry.get_or_create(peer_pub_key))
        .unwrap_or_else(|| Arc::new(PeerL4Stats::default()));

    match quic_pool.open_mux_stream().await {
        Ok((mut send, mut recv, conn_stat)) => {
            if write_target_addr(&mut send, original_dest).await.is_err() {
                quic_pool.enter_fallback("failed to write userspace stream target address");
                return None;
            }
            let mut status = [0u8; 1];
            match timeout(Duration::from_secs(5), recv.read_exact(&mut status)).await {
                Ok(Ok(_)) if status[0] == 1 => {
                    stats.active_streams.fetch_add(1, Ordering::Relaxed);
                    conn_stat.active_streams.fetch_add(1, Ordering::Relaxed);
                    Some(ActiveQuicBridge {
                        send,
                        recv,
                        stats,
                        conn_stat,
                    })
                }
                Ok(Ok(_)) => {
                    log::warn!("Server rejected userspace target {}", original_dest);
                    None
                }
                Ok(Err(e)) => {
                    log::warn!(
                        "Failed to read userspace target proxy status for {}: {}",
                        original_dest,
                        e
                    );
                    quic_pool.enter_fallback("failed to read userspace stream proxy status");
                    None
                }
                Err(_) => {
                    log::warn!(
                        "Timed out waiting for userspace target proxy status for {}",
                        original_dest
                    );
                    quic_pool.enter_fallback("failed to complete userspace stream proxy setup");
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to open stream for userspace bridge: {}", e);
            quic_pool.enter_fallback("failed to open userspace QUIC mux stream");
            None
        }
    }
}

#[derive(Clone, Copy)]
pub struct NatEntry {
    pub original_dst_ip: IpAddr,
    pub original_dst_port: u16,
    pub peer_pub_key: [u8; 32],
    pub flow_key: FlowKey,
    pub last_seen: Instant,
}

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

pub fn parse_tcp_packet(packet: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, bool)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            let proto = packet[9];
            if proto != 6 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 {
                return None;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len < ihl + 20 || packet.len() < total_len {
                return None;
            }
            if packet.len() < ihl + 20 {
                return None;
            }
            let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            ));
            let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));

            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            let flags = packet[ihl + 13];
            let is_syn = (flags & 0x02) != 0;
            Some((src_ip, src_port, dst_ip, dst_port, is_syn))
        }
        6 => {
            if packet.len() < 60 {
                return None;
            }
            let proto = packet[6];
            if proto != 6 {
                return None;
            }
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&packet[8..24]);
            let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(src_bytes));

            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&packet[24..40]);
            let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(dst_bytes));

            let src_port = u16::from_be_bytes([packet[40], packet[41]]);
            let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
            let flags = packet[53];
            let is_syn = (flags & 0x02) != 0;
            Some((src_ip, src_port, dst_ip, dst_port, is_syn))
        }
        _ => None,
    }
}

fn smoltcp_ip_to_std(addr: smoltcp::wire::IpAddress) -> IpAddr {
    match addr {
        smoltcp::wire::IpAddress::Ipv4(a) => IpAddr::V4(a),
        smoltcp::wire::IpAddress::Ipv6(a) => IpAddr::V6(a),
    }
}

pub fn rewrite_destination_ip(packet: &mut [u8], new_dst: IpAddr) {
    let version = packet[0] >> 4;
    match (version, new_dst) {
        (4, IpAddr::V4(addr)) => {
            let octets = addr.octets();
            packet[16..20].copy_from_slice(&octets);
        }
        (6, IpAddr::V6(addr)) => {
            let octets = addr.octets();
            packet[24..40].copy_from_slice(&octets);
        }
        _ => {}
    }
}

pub fn rewrite_source_ip(packet: &mut [u8], new_src: IpAddr) {
    let version = packet[0] >> 4;
    match (version, new_src) {
        (4, IpAddr::V4(addr)) => {
            let octets = addr.octets();
            packet[12..16].copy_from_slice(&octets);
        }
        (6, IpAddr::V6(addr)) => {
            let octets = addr.octets();
            packet[8..24].copy_from_slice(&octets);
        }
        _ => {}
    }
}

pub fn rewrite_destination_port(packet: &mut [u8], new_dst_port: u16) {
    let version = packet[0] >> 4;
    let offset = match version {
        4 if packet.len() >= 20 => (packet[0] & 0x0f) as usize * 4,
        6 if packet.len() >= 60 => 40,
        _ => return,
    };
    if packet.len() >= offset + 4 {
        packet[offset + 2..offset + 4].copy_from_slice(&new_dst_port.to_be_bytes());
    }
}

pub fn rewrite_source_port(packet: &mut [u8], new_src_port: u16) {
    let version = packet[0] >> 4;
    let offset = match version {
        4 if packet.len() >= 20 => (packet[0] & 0x0f) as usize * 4,
        6 if packet.len() >= 60 => 40,
        _ => return,
    };
    if packet.len() >= offset + 2 {
        packet[offset..offset + 2].copy_from_slice(&new_src_port.to_be_bytes());
    }
}

fn add_ones_complement(sum: u32, bytes: &[u8]) -> u32 {
    let mut sum = sum;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    sum
}

fn finish_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn repair_tcp_checksums(packet: &mut [u8]) {
    if packet.is_empty() {
        return;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 || packet[9] != 6 {
                return;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if ihl < 20 || packet.len() < ihl + 20 {
                return;
            }
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if total_len < ihl + 20 || packet.len() < total_len {
                return;
            }
            packet[10] = 0;
            packet[11] = 0;
            let ip_checksum = finish_checksum(add_ones_complement(0, &packet[..ihl]));
            packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

            packet[ihl + 16] = 0;
            packet[ihl + 17] = 0;
            let tcp_len = total_len - ihl;
            let mut sum = 0u32;
            sum = add_ones_complement(sum, &packet[12..20]);
            sum += 6;
            sum += tcp_len as u32;
            sum = add_ones_complement(sum, &packet[ihl..total_len]);
            let tcp_checksum = finish_checksum(sum);
            packet[ihl + 16..ihl + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        }
        6 => {
            if packet.len() < 60 || packet[6] != 6 {
                return;
            }
            let tcp_offset = 40;
            let tcp_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if tcp_len < 20 || packet.len() < tcp_offset + tcp_len {
                return;
            }
            packet[tcp_offset + 16] = 0;
            packet[tcp_offset + 17] = 0;
            let mut sum = 0u32;
            sum = add_ones_complement(sum, &packet[8..40]);
            sum = add_ones_complement(sum, &(tcp_len as u32).to_be_bytes());
            sum += 6;
            sum = add_ones_complement(sum, &packet[tcp_offset..tcp_offset + tcp_len]);
            let tcp_checksum = finish_checksum(sum);
            packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        }
        _ => {}
    }
}

pub struct BridgeChannels {
    pub nat_key: NatKey,
    pub quic: BridgeQuicState,
    pub recv_buf: PooledBuf,
    pub quic_recv_buf: PooledBuf,
    pub to_quic_pending: VecDeque<PooledBuf>,
    pub from_quic_pending: VecDeque<PooledBuf>,
    pub to_quic_pending_bytes: usize,
    pub from_quic_pending_bytes: usize,
    pub quic_rx_closed: bool,
}

pub enum BridgeQuicState {
    Inactive,
    Opening(Pin<Box<dyn Future<Output = Option<ActiveQuicBridge>> + Send>>),
    Active(ActiveQuicBridge),
}

pub struct ActiveQuicBridge {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    pub stats: Arc<PeerL4Stats>,
    pub conn_stat: Arc<QuicConnStats>,
}

impl Drop for ActiveQuicBridge {
    fn drop(&mut self) {
        self.stats.active_streams.fetch_sub(1, Ordering::Relaxed);
        self.conn_stat
            .active_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl BridgeChannels {
    fn push_to_quic_pending(&mut self, data: PooledBuf) -> bool {
        if self.to_quic_pending.len() >= bridge_pending_limit()
            || self.to_quic_pending_bytes.saturating_add(data.len()) > bridge_pending_bytes_limit()
        {
            return false;
        }
        self.to_quic_pending_bytes += data.len();
        self.to_quic_pending.push_back(data);
        true
    }

    fn consume_to_quic_front(&mut self, consumed: usize) {
        self.to_quic_pending_bytes = self.to_quic_pending_bytes.saturating_sub(consumed);
        if let Some(front) = self.to_quic_pending.front_mut() {
            if consumed >= front.len() {
                self.to_quic_pending.pop_front();
            } else {
                front.consume_front(consumed);
            }
        }
    }

    fn has_from_quic_pending_capacity(&self) -> bool {
        let chunk_capacity = self.recv_buf.capacity().max(1);
        self.from_quic_pending.len() < bridge_pending_limit()
            && self.from_quic_pending_bytes + chunk_capacity <= bridge_pending_bytes_limit()
    }

    fn push_from_quic_pending(&mut self, data: PooledBuf) -> bool {
        if self.from_quic_pending.len() >= bridge_pending_limit()
            || self.from_quic_pending_bytes.saturating_add(data.len())
                > bridge_pending_bytes_limit()
        {
            return false;
        }
        self.from_quic_pending_bytes += data.len();
        self.from_quic_pending.push_back(data);
        true
    }

    fn consume_from_quic_front(&mut self, consumed: usize) {
        self.from_quic_pending_bytes = self.from_quic_pending_bytes.saturating_sub(consumed);
        if let Some(front) = self.from_quic_pending.front_mut() {
            if consumed >= front.len() {
                self.from_quic_pending.pop_front();
            } else {
                front.consume_front(consumed);
            }
        }
    }
}

pub struct RtcWorker {
    pub tun_io: Arc<AsyncTunIo>,
    pub udp_socket: crate::virtual_tunnel::TunnelSocket,
    pub l3_registry: UserspaceWgRegistry,
    pub tcp_stack: UserspaceTcpStack,
    pub bridges: HashMap<SocketHandle, BridgeChannels>,
    pending_bridge_handles: HashSet<SocketHandle>,
    pub nat_map: HashMap<NatKey, NatEntry>,
    pub flow_map: HashMap<FlowKey, u16>,
    used_local_ports: HashSet<u16>,
    next_local_port: u16,
    local_ipv4: Option<IpAddr>,
    local_ipv6: Option<IpAddr>,
    packet_buffer_size: usize,
    buffer_pool: BufferPool,
    pending_tun: VecDeque<PooledBuf>,
    pending_udp: VecDeque<(SocketAddr, PooledBuf)>,
    pending_tun_bytes: usize,
    pending_udp_bytes: usize,
    last_housekeeping: Instant,
    worker_stats: Option<Arc<crate::telemetry::WorkerTelemetry>>,
    worker_stats_local: Option<WorkerTelemetrySnapshot>,
    worker_stats_dirty: bool,
    peer_telemetry: Option<Arc<crate::telemetry::TelemetryRegistry>>,
    l3_rx_enabled: bool,
    l3_timer_enabled: bool,
    bridge_notify: Arc<Notify>,
}

pub struct RtcWorkerConfig {
    pub local_ipv4: Option<IpAddr>,
    pub local_ipv6: Option<IpAddr>,
    pub mtu: usize,
    pub buffer_pool: BufferPool,
}

impl RtcWorker {
    pub fn new(
        tun_io: Arc<AsyncTunIo>,
        udp_socket: crate::virtual_tunnel::TunnelSocket,
        l3_registry: UserspaceWgRegistry,
        tcp_stack: UserspaceTcpStack,
        config: RtcWorkerConfig,
    ) -> Self {
        let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(config.mtu as u16);
        Self {
            tun_io,
            udp_socket,
            l3_registry,
            tcp_stack,
            bridges: HashMap::new(),
            pending_bridge_handles: HashSet::new(),
            nat_map: HashMap::new(),
            flow_map: HashMap::new(),
            used_local_ports: HashSet::new(),
            next_local_port: 49152,
            local_ipv4: config.local_ipv4,
            local_ipv6: config.local_ipv6,
            packet_buffer_size,
            buffer_pool: config.buffer_pool,
            pending_tun: VecDeque::new(),
            pending_udp: VecDeque::new(),
            pending_tun_bytes: 0,
            pending_udp_bytes: 0,
            last_housekeeping: Instant::now(),
            worker_stats: None,
            worker_stats_local: None,
            worker_stats_dirty: false,
            peer_telemetry: None,
            l3_rx_enabled: true,
            l3_timer_enabled: true,
            bridge_notify: Arc::new(Notify::new()),
        }
    }

    pub fn set_worker_stats(&mut self, worker_stats: Arc<crate::telemetry::WorkerTelemetry>) {
        self.worker_stats_local = Some(WorkerTelemetrySnapshot {
            worker_id: worker_stats.worker_id(),
            ..WorkerTelemetrySnapshot::default()
        });
        self.worker_stats = Some(worker_stats);
        self.worker_stats_dirty = true;
    }

    pub fn set_peer_telemetry(&mut self, peer_telemetry: Arc<crate::telemetry::TelemetryRegistry>) {
        self.peer_telemetry = Some(peer_telemetry);
    }

    pub fn set_l3_rx_enabled(&mut self, enabled: bool) {
        self.l3_rx_enabled = enabled;
    }

    pub fn set_l3_timer_enabled(&mut self, enabled: bool) {
        self.l3_timer_enabled = enabled;
    }

    fn publish_worker_stats(&mut self) {
        if !self.worker_stats_dirty {
            return;
        }
        if let (Some(handle), Some(local)) = (&self.worker_stats, &self.worker_stats_local) {
            handle.publish(local);
            self.worker_stats_dirty = false;
        }
    }

    fn record_tun_rx(&mut self, bytes: usize) {
        if let Some(stats) = &mut self.worker_stats_local {
            stats.tun_rx_packets += 1;
            stats.tun_rx_bytes += bytes as u64;
            self.worker_stats_dirty = true;
        }
    }

    fn record_tcp_offload(&mut self, bytes: usize) {
        if let Some(stats) = &mut self.worker_stats_local {
            stats.tcp_offload_packets += 1;
            stats.tcp_offload_bytes += bytes as u64;
            self.worker_stats_dirty = true;
        }
    }

    fn record_l3_packet(&mut self, bytes: usize) {
        if let Some(stats) = &mut self.worker_stats_local {
            stats.l3_packets += 1;
            stats.l3_bytes += bytes as u64;
            self.worker_stats_dirty = true;
        }
    }

    fn push_pending_tun(&mut self, packet: PooledBuf, context: &str) {
        if self.pending_tun_bytes.saturating_add(packet.len()) > bridge_pending_bytes_limit() {
            log::warn!(
                "{} TUN pending byte limit reached; dropping packet",
                context
            );
            return;
        }
        self.pending_tun_bytes += packet.len();
        self.pending_tun.push_back(packet);
    }

    fn push_pending_udp(&mut self, endpoint: SocketAddr, packet: PooledBuf, context: &str) {
        if self.pending_udp_bytes.saturating_add(packet.len()) > bridge_pending_bytes_limit() {
            log::warn!(
                "{} UDP pending byte limit reached for {}; dropping packet",
                context,
                endpoint
            );
            return;
        }
        self.pending_udp_bytes += packet.len();
        self.pending_udp.push_back((endpoint, packet));
    }

    fn send_or_queue_udp_packet(&mut self, endpoint: SocketAddr, packet: PooledBuf, context: &str) {
        match self.udp_socket.try_send_to(packet.as_slice(), endpoint) {
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
                self.push_pending_udp(endpoint, packet, context);
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

    fn write_or_queue_tun_packet(&mut self, packet: PooledBuf, context: &str) {
        match self.tun_io.try_write_packet(packet.as_slice()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.push_pending_tun(packet, context);
            }
            Err(e) => {
                log::warn!("{} failed to write packet to TUN: {}", context, e);
            }
        }
    }

    fn flush_pending_udp(&mut self) {
        while let Some((endpoint, packet)) = self.pending_udp.pop_front() {
            self.pending_udp_bytes = self.pending_udp_bytes.saturating_sub(packet.len());
            match self.udp_socket.try_send_to(packet.as_slice(), endpoint) {
                Ok(n) if n == packet.len() => {}
                Ok(n) => {
                    log::warn!(
                        "pending UDP sent short datagram to {}: {} of {} bytes",
                        endpoint,
                        n,
                        packet.len()
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.pending_udp_bytes += packet.len();
                    self.pending_udp.push_front((endpoint, packet));
                    break;
                }
                Err(e) => {
                    log::warn!("pending UDP failed to send packet to {}: {}", endpoint, e);
                }
            }
        }
    }

    fn flush_pending_tun(&mut self) {
        while let Some(packet) = self.pending_tun.pop_front() {
            self.pending_tun_bytes = self.pending_tun_bytes.saturating_sub(packet.len());
            match self.tun_io.try_write_packet(packet.as_slice()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.pending_tun_bytes += packet.len();
                    self.pending_tun.push_front(packet);
                    break;
                }
                Err(e) => {
                    log::warn!("pending TUN failed to write packet: {}", e);
                }
            }
        }
    }

    fn record_new_tcp_flow(&mut self) {
        if let Some(stats) = &mut self.worker_stats_local {
            stats.new_tcp_flows += 1;
            self.worker_stats_dirty = true;
        }
    }

    fn record_current_tcp_flows(&mut self) {
        if let Some(stats) = &mut self.worker_stats_local {
            let current = self.flow_map.len() as u64;
            if stats.current_tcp_flows != current {
                stats.current_tcp_flows = current;
                self.worker_stats_dirty = true;
            }
        }
    }

    fn local_ip_for(&self, dst_ip: IpAddr) -> Option<IpAddr> {
        if dst_ip.is_ipv4() {
            self.local_ipv4
        } else {
            self.local_ipv6
        }
    }

    fn allocate_local_port(&mut self) -> Option<u16> {
        for _ in 49152..=65535 {
            let port = self.next_local_port;
            self.next_local_port = if self.next_local_port == 65535 {
                49152
            } else {
                self.next_local_port + 1
            };
            if self.used_local_ports.contains(&port) {
                continue;
            }
            return Some(port);
        }
        None
    }

    fn insert_flow_port(&mut self, flow_key: FlowKey, port: u16) {
        debug_assert!(
            !self
                .flow_map
                .iter()
                .any(|(existing_flow, existing_port)| *existing_flow != flow_key
                    && *existing_port == port),
            "local port {} is already assigned to another flow",
            port
        );
        if let Some(old_port) = self.flow_map.insert(flow_key, port) {
            self.used_local_ports.remove(&old_port);
        }
        self.used_local_ports.insert(port);
    }

    fn release_flow_port(&mut self, flow_key: &FlowKey) -> Option<u16> {
        let port = self.flow_map.remove(flow_key)?;
        self.used_local_ports.remove(&port);
        Some(port)
    }

    #[cfg(test)]
    fn assert_port_index_consistent(&self) {
        let flow_ports = self.flow_map.values().copied().collect::<HashSet<_>>();
        assert_eq!(flow_ports.len(), self.flow_map.len());
        assert_eq!(self.used_local_ports, flow_ports);
    }

    fn release_nat_key(&mut self, nat_key: &NatKey) -> Option<NatEntry> {
        let entry = self.nat_map.remove(nat_key)?;
        self.release_flow_port(&entry.flow_key);
        Some(entry)
    }

    fn should_route_via_smoltcp(
        &self,
        flow_key: &FlowKey,
        is_syn: bool,
        offload_available_for_new_flow: bool,
    ) -> bool {
        self.flow_map.contains_key(flow_key) || (is_syn && offload_available_for_new_flow)
    }

    fn tcp_flow_limit_reached_for_new_flow(&self, flow_key: &FlowKey, is_syn: bool) -> bool {
        is_syn
            && !self.flow_map.contains_key(flow_key)
            && self.flow_map.len() >= max_worker_tcp_flows()
    }

    pub async fn run_one_iteration(&mut self) -> Result<std::time::Duration, String> {
        self.flush_pending_tun();
        self.flush_pending_udp();
        self.cleanup_stale_flows();
        self.record_current_tcp_flows();
        self.publish_worker_stats();
        let now = smoltcp::time::Instant::now();
        self.tcp_stack
            .iface
            .poll(now, &mut self.tcp_stack.device, &mut self.tcp_stack.sockets);

        // Flush outgoing TCP packets from smoltcp to TUN
        while let Some(mut pkt) = self.tcp_stack.device.tx_queue.pop_front() {
            if let Some((_src_ip, src_port, dst_ip, dst_port, _)) = parse_tcp_packet(pkt.as_slice())
            {
                let key = (dst_ip, dst_port, src_port);
                if let Some(entry) = self.nat_map.get(&key) {
                    rewrite_source_ip(pkt.as_mut_slice(), entry.original_dst_ip);
                    rewrite_source_port(pkt.as_mut_slice(), entry.original_dst_port);
                    repair_tcp_checksums(pkt.as_mut_slice());
                }
            }
            self.write_or_queue_tun_packet(pkt, "smoltcp");
        }

        // Handle active TCP bridges
        self.handle_bridges(None);

        let poll_delay = self
            .tcp_stack
            .iface
            .poll_delay(now, &self.tcp_stack.sockets)
            .unwrap_or(smoltcp::time::Duration::from_millis(10));
        Ok(std::time::Duration::from_millis(poll_delay.total_millis()))
    }

    #[cfg(not(tarpaulin))]
    pub async fn run_loop(&mut self, data_plane: crate::L4DataPlane) -> Result<(), String> {
        let mut tun_buf = self.buffer_pool.get();
        let mut udp_buf = self.buffer_pool.get();
        let mut l3_timer = tokio::time::interval(std::time::Duration::from_millis(100));

        loop {
            self.flush_pending_tun();
            self.flush_pending_udp();
            self.cleanup_stale_flows();
            self.record_current_tcp_flows();
            self.publish_worker_stats();
            let now = smoltcp::time::Instant::now();
            self.tcp_stack
                .iface
                .poll(now, &mut self.tcp_stack.device, &mut self.tcp_stack.sockets);

            // Flush outgoing TCP packets from smoltcp to TUN, applying NAT reverse rewrite
            while let Some(mut pkt) = self.tcp_stack.device.tx_queue.pop_front() {
                if let Some((_src_ip, src_port, dst_ip, dst_port, _)) =
                    parse_tcp_packet(pkt.as_slice())
                {
                    let key = (dst_ip, dst_port, src_port);
                    if let Some(entry) = self.nat_map.get(&key) {
                        rewrite_source_ip(pkt.as_mut_slice(), entry.original_dst_ip);
                        rewrite_source_port(pkt.as_mut_slice(), entry.original_dst_port);
                        repair_tcp_checksums(pkt.as_mut_slice());
                    }
                }
                self.write_or_queue_tun_packet(pkt, "smoltcp");
            }

            self.handle_bridges(Some(&data_plane));

            let poll_delay = self
                .tcp_stack
                .iface
                .poll_delay(now, &self.tcp_stack.sockets)
                .unwrap_or(smoltcp::time::Duration::from_millis(10));
            let delay_duration = std::time::Duration::from_millis(poll_delay.total_millis());
            let tun_io_for_writable = self.tun_io.clone();
            let udp_socket_for_writable = self.udp_socket.clone();
            let bridge_notify = self.bridge_notify.clone();

            tokio::select! {
                _ = bridge_notify.notified(), if !self.bridges.is_empty() => {}

                writable = tun_io_for_writable.writable(), if !self.pending_tun.is_empty() => {
                    if writable.is_ok() {
                        self.flush_pending_tun();
                    }
                }

                writable = udp_socket_for_writable.writable(), if !self.pending_udp.is_empty() => {
                    if writable.is_ok() {
                        self.flush_pending_udp();
                    }
                }

                _ = l3_timer.tick(), if self.l3_timer_enabled => {
                    self.udp_socket.tick_control();
                    for (endpoint, packet) in self.l3_registry.timer_packets(&self.buffer_pool) {
                        self.send_or_queue_udp_packet(endpoint, packet, "userspace WireGuard timer");
                    }
                }

                read_res = self.tun_io.read(tun_buf.as_mut_capacity()) => {
                    match read_res {
                        Ok(n) if n > 0 => {
                            tun_buf.set_len(n);
                            self.record_tun_rx(n);
                            let packet = tun_buf.as_mut_slice();
                            if let Some((src_ip, src_port, dst_ip, dst_port, is_syn)) = parse_tcp_packet(packet) {
                                let flow_key = (src_ip, src_port, dst_ip, dst_port);
                                let existing_flow = self.flow_map.contains_key(&flow_key);
                                let offload_peer_for_new_flow = if !existing_flow && is_syn {
                                    let snapshot = data_plane.load();
                                    snapshot
                                        .userspace_tcp_offload_enabled
                                        .then(|| snapshot.router.longest_match(dst_ip))
                                        .flatten()
                                        .filter(|peer_pub_key| {
                                            snapshot
                                                .client_quic_pools
                                                .get(peer_pub_key)
                                                .map(|pool| matches!(pool.get_state(), crate::quic_pool::PoolState::Active))
                                                .unwrap_or(false)
                                        })
                                } else {
                                    None
                                };
                                let offload_available_for_new_flow =
                                    offload_peer_for_new_flow.is_some();

                                if self.should_route_via_smoltcp(
                                    &flow_key,
                                    is_syn,
                                    offload_available_for_new_flow,
                                ) {
                                    let Some(local_ip) = self.local_ip_for(dst_ip) else {
                                        log::warn!(
                                            "No configured smoltcp local address for {}; using userspace WireGuard L3",
                                            dst_ip
                                        );
                                        if let Some((endpoint, enc_pkt)) =
                                            self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                        {
                                            self.record_l3_packet(n);
                                            self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard fallback");
                                        }
                                        continue;
                                    };
                                    if self.tcp_flow_limit_reached_for_new_flow(&flow_key, is_syn) {
                                        log::warn!(
                                            "Userspace TCP flow limit reached; falling back to userspace WireGuard L3"
                                        );
                                        if let Some((endpoint, enc_pkt)) =
                                            self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                        {
                                            self.record_l3_packet(n);
                                            self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard fallback");
                                        }
                                        continue;
                                    }

                                    let local_port = if is_syn {
                                        match self.flow_map.get(&flow_key).copied() {
                                            Some(port) => port,
                                            None => match self.allocate_local_port() {
                                                Some(port) => {
                                                    self.insert_flow_port(flow_key, port);
                                                    self.record_new_tcp_flow();
                                                    port
                                                }
                                                None => {
                                                    log::warn!("No free smoltcp local ports; falling back to userspace WireGuard L3");
                                                    if let Some((endpoint, enc_pkt)) =
                                                        self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                                    {
                                                        self.record_l3_packet(n);
                                                        self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard fallback");
                                                    }
                                                    continue;
                                                }
                                            },
                                        }
                                    } else if let Some(port) = self.flow_map.get(&flow_key).copied() {
                                        port
                                    } else {
                                        log::debug!("No userspace TCP flow state for non-SYN packet; using userspace WireGuard L3");
                                        if let Some((endpoint, enc_pkt)) =
                                            self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                        {
                                            self.record_l3_packet(n);
                                            self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard fallback");
                                        }
                                        continue;
                                    };

                                    if is_syn {
                                        let has_listening = self.tcp_stack.sockets.iter().any(|(_, s)| {
                                            if let Some(s) = tcp::Socket::downcast(s) {
                                                s.state() == tcp::State::Listen && s.local_endpoint().map(|ep| ep.port == local_port).unwrap_or(false)
                                            } else {
                                                false
                                            }
                                        });
                                        if !has_listening {
                                            match self.tcp_stack.create_tcp_socket(
                                                userspace_tcp_socket_buffer_bytes(),
                                                userspace_tcp_socket_buffer_bytes(),
                                            ) {
                                                Ok(handle) => {
                                                    let listen_result = {
                                                        let s = self
                                                            .tcp_stack
                                                            .sockets
                                                            .get_mut::<tcp::Socket>(handle);
                                                        s.listen(local_port)
                                                    };
                                                    if let Err(e) = listen_result {
                                                        self.tcp_stack.sockets.remove(handle);
                                                        self.release_flow_port(&flow_key);
                                                        log::warn!(
                                                            "Failed to create userspace TCP listener on port {}: {}; falling back to userspace WireGuard L3",
                                                            local_port,
                                                            e
                                                        );
                                                        if let Some((endpoint, enc_pkt)) =
                                                            self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                                        {
                                                            self.record_l3_packet(n);
                                                            self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard fallback");
                                                        }
                                                        continue;
                                                    }
                                                    log::debug!(
                                                        "Created userspace listening TCP socket on port {}",
                                                        local_port
                                                    );
                                                    self.pending_bridge_handles.insert(handle);
                                                }
                                                Err(e) => {
                                                    self.release_flow_port(&flow_key);
                                                    log::warn!(
                                                        "Failed to allocate userspace TCP socket: {}; falling back to userspace WireGuard L3",
                                                        e
                                                    );
                                                    if let Some((endpoint, enc_pkt)) =
                                                        self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                                    {
                                                        self.record_l3_packet(n);
                                                        self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard fallback");
                                                    }
                                                    continue;
                                                }
                                            }
                                        }
                                    }

                                    let peer_pub_key = offload_peer_for_new_flow
                                        .or_else(|| {
                                            self.nat_map
                                                .get(&(src_ip, src_port, local_port))
                                                .map(|entry| entry.peer_pub_key)
                                        });
                                    let Some(peer_pub_key) = peer_pub_key else {
                                        log::warn!(
                                            "No QUIC peer mapping for userspace TCP flow; falling back to userspace WireGuard L3"
                                        );
                                        if let Some((endpoint, enc_pkt)) =
                                            self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                        {
                                            self.record_l3_packet(n);
                                            self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard fallback");
                                        }
                                        continue;
                                    };

                                    self.nat_map.insert(
                                        (src_ip, src_port, local_port),
                                        NatEntry {
                                            original_dst_ip: dst_ip,
                                            original_dst_port: dst_port,
                                            peer_pub_key,
                                            flow_key,
                                            last_seen: Instant::now(),
                                        },
                                    );

                                    rewrite_destination_ip(packet, local_ip);
                                    rewrite_destination_port(packet, local_port);

                                    self.record_tcp_offload(n);
                                    let packet = std::mem::replace(&mut tun_buf, self.buffer_pool.get());
                                    self.tcp_stack.process_input_packet(packet);
                                } else {
                                    if let Some((endpoint, enc_pkt)) =
                                        self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                    {
                                        self.record_l3_packet(n);
                                        self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard");
                                    }
                                }
                            } else {
                                if let Some((endpoint, enc_pkt)) =
                                    self.l3_registry.encapsulate_tunnel_packet(packet, &self.buffer_pool)
                                {
                                    self.record_l3_packet(n);
                                    self.send_or_queue_udp_packet(endpoint, enc_pkt, "userspace WireGuard");
                                }
                            }
                        }
                        _ => {}
                    }
                }

                udp_res = self.udp_socket.recv_from(udp_buf.as_mut_capacity()), if self.l3_rx_enabled => {
                    if let Ok((n, addr)) = udp_res {
                        udp_buf.set_len(n);
                        if let Some((reply_endpoint, actions)) =
                            self.l3_registry.decapsulate_network_packet(addr, udp_buf.as_slice(), &self.buffer_pool)
                        {
                            for action in actions {
                                match action {
                                    UserspaceWgAction::WriteToTunnel(dec_pkt) => {
                                        self.write_or_queue_tun_packet(dec_pkt, "userspace WireGuard");
                                    }
                                    UserspaceWgAction::WriteToNetwork(resp_pkt) => {
                                        self.send_or_queue_udp_packet(reply_endpoint, resp_pkt, "userspace WireGuard response");
                                    }
                                }
                            }
                        }
                    }
                }

                _ = tokio::time::sleep(delay_duration) => {}
            }
        }
    }

    fn handle_bridges(&mut self, data_plane: Option<&crate::L4DataPlane>) {
        let mut closed_handles = Vec::new();

        let mut new_connections = Vec::new();
        let mut checked_handles = Vec::with_capacity(self.pending_bridge_handles.len());
        checked_handles.extend(self.pending_bridge_handles.iter().copied());
        for handle in checked_handles {
            if self.bridges.contains_key(&handle) {
                self.pending_bridge_handles.remove(&handle);
                continue;
            }
            let socket = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);
            if !socket.is_active() {
                continue;
            }
            if let (Some(local_endpoint), Some(remote_endpoint)) =
                (socket.local_endpoint(), socket.remote_endpoint())
            {
                let client_ip = smoltcp_ip_to_std(remote_endpoint.addr);
                let key = (client_ip, remote_endpoint.port, local_endpoint.port);
                if let Some(entry) = self.nat_map.get(&key) {
                    let original_dest =
                        SocketAddr::new(entry.original_dst_ip, entry.original_dst_port);
                    new_connections.push((handle, original_dest, key, entry.peer_pub_key));
                    self.pending_bridge_handles.remove(&handle);
                } else {
                    log::warn!(
                        "No NAT mapping found for userspace TCP socket {}:{} -> local port {}; skipping QUIC bridge",
                        client_ip,
                        remote_endpoint.port,
                        local_endpoint.port
                    );
                    self.pending_bridge_handles.remove(&handle);
                }
            } else {
                self.pending_bridge_handles.remove(&handle);
            }
        }

        for (handle, original_dest, nat_key, peer_pub_key) in new_connections {
            if let Some(data_plane) = data_plane {
                let opening = establish_quic_bridge(
                    original_dest,
                    peer_pub_key,
                    data_plane.load_full(),
                    self.peer_telemetry.clone(),
                );
                self.bridges.insert(
                    handle,
                    BridgeChannels {
                        nat_key,
                        quic: BridgeQuicState::Opening(Box::pin(opening)),
                        recv_buf: self.buffer_pool.get(),
                        quic_recv_buf: self.buffer_pool.get(),
                        to_quic_pending: VecDeque::new(),
                        from_quic_pending: VecDeque::new(),
                        to_quic_pending_bytes: 0,
                        from_quic_pending_bytes: 0,
                        quic_rx_closed: false,
                    },
                );
            } else {
                self.bridges.insert(
                    handle,
                    BridgeChannels {
                        nat_key,
                        quic: BridgeQuicState::Inactive,
                        recv_buf: self.buffer_pool.get(),
                        quic_recv_buf: self.buffer_pool.get(),
                        to_quic_pending: VecDeque::new(),
                        from_quic_pending: VecDeque::new(),
                        to_quic_pending_bytes: 0,
                        from_quic_pending_bytes: 0,
                        quic_rx_closed: false,
                    },
                );
            }
        }

        // Process existing bridges
        for (&handle, bridge) in self.bridges.iter_mut() {
            let socket = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);

            if !socket.is_active() {
                if !closed_handles.contains(&handle) {
                    closed_handles.push(handle);
                }
                continue;
            }

            if let BridgeQuicState::Opening(opening) = &mut bridge.quic {
                match with_notify_context(&self.bridge_notify, |cx| opening.as_mut().poll(cx)) {
                    Poll::Ready(Some(active)) => {
                        bridge.quic = BridgeQuicState::Active(active);
                    }
                    Poll::Ready(None) => {
                        if !closed_handles.contains(&handle) {
                            closed_handles.push(handle);
                        }
                        continue;
                    }
                    Poll::Pending => {}
                }
            }

            while !bridge.to_quic_pending.is_empty() {
                let BridgeQuicState::Active(active) = &mut bridge.quic else {
                    break;
                };
                let poll_result = {
                    let front = bridge.to_quic_pending.front().expect("front exists");
                    with_notify_context(&self.bridge_notify, |cx| {
                        Pin::new(&mut active.send).poll_write(cx, front.as_slice())
                    })
                };
                match poll_result {
                    Poll::Ready(Ok(0)) | Poll::Pending => break,
                    Poll::Ready(Ok(n)) => {
                        active.stats.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        active
                            .conn_stat
                            .tx_bytes
                            .fetch_add(n as u64, Ordering::Relaxed);
                        bridge.consume_to_quic_front(n);
                    }
                    Poll::Ready(Err(_)) => {
                        if !closed_handles.contains(&handle) {
                            closed_handles.push(handle);
                        }
                        break;
                    }
                }
            }

            while bridge.has_from_quic_pending_capacity() && !bridge.quic_rx_closed {
                let BridgeQuicState::Active(active) = &mut bridge.quic else {
                    break;
                };
                let poll_result = with_notify_context(&self.bridge_notify, |cx| {
                    let mut read_buf = ReadBuf::new(bridge.quic_recv_buf.as_mut_capacity());
                    match Pin::new(&mut active.recv).poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                    }
                });
                match poll_result {
                    Poll::Ready(Ok(n)) if n > 0 => {
                        active.stats.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        active
                            .conn_stat
                            .rx_bytes
                            .fetch_add(n as u64, Ordering::Relaxed);
                        let mut data =
                            std::mem::replace(&mut bridge.quic_recv_buf, self.buffer_pool.get());
                        data.set_len(n);
                        if !bridge.push_from_quic_pending(data) {
                            log::warn!("Userspace TCP bridge from-QUIC queue byte limit reached; closing bridge");
                            if !closed_handles.contains(&handle) {
                                closed_handles.push(handle);
                            }
                            break;
                        }
                    }
                    Poll::Ready(Ok(_)) => {
                        bridge.quic_rx_closed = true;
                        break;
                    }
                    Poll::Ready(Err(_)) => {
                        if !closed_handles.contains(&handle) {
                            closed_handles.push(handle);
                        }
                        break;
                    }
                    Poll::Pending => break,
                }
            }

            while socket.can_send() {
                let Some(front_len) = bridge.from_quic_pending.front().map(|front| front.len())
                else {
                    break;
                };
                let send_result = {
                    let front = bridge.from_quic_pending.front_mut().expect("front exists");
                    socket.send_slice(front.as_slice())
                };
                match send_result {
                    Ok(0) => break,
                    Ok(n) if n >= front_len => {
                        bridge.consume_from_quic_front(n);
                    }
                    Ok(n) => {
                        bridge.consume_from_quic_front(n);
                    }
                    Err(_) => break,
                }
            }
            if bridge.quic_rx_closed && bridge.from_quic_pending.is_empty() {
                socket.close();
            }

            while socket.can_recv()
                && bridge.to_quic_pending.len() < bridge_pending_limit()
                && bridge.to_quic_pending_bytes < bridge_pending_bytes_limit()
            {
                let remaining = bridge_pending_bytes_limit() - bridge.to_quic_pending_bytes;
                let read_len = self.packet_buffer_size.min(remaining);
                if read_len == 0 {
                    break;
                }
                if let Ok(n) = socket.recv_slice(&mut bridge.recv_buf.as_mut_capacity()[..read_len])
                {
                    if n > 0 {
                        let mut data =
                            std::mem::replace(&mut bridge.recv_buf, self.buffer_pool.get());
                        data.set_len(n);
                        if !bridge.push_to_quic_pending(data) {
                            log::warn!("Userspace TCP bridge to-QUIC queue byte limit reached; closing bridge");
                            if !closed_handles.contains(&handle) {
                                closed_handles.push(handle);
                            }
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        for handle in closed_handles {
            self.pending_bridge_handles.remove(&handle);
            if let Some(bridge) = self.bridges.remove(&handle) {
                let _ = self.release_nat_key(&bridge.nat_key);
            }
            let socket = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);
            socket.abort();
            self.tcp_stack.sockets.remove(handle);
        }
    }

    fn cleanup_stale_flows(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_housekeeping) < HOUSEKEEPING_INTERVAL {
            return;
        }
        self.last_housekeeping = now;

        let bridged_nat_keys = self
            .bridges
            .values()
            .map(|bridge| bridge.nat_key)
            .collect::<HashSet<_>>();
        let stale_nat_keys = self
            .nat_map
            .iter()
            .filter_map(|(key, entry)| {
                if !bridged_nat_keys.contains(key)
                    && now.duration_since(entry.last_seen) >= HALF_OPEN_TIMEOUT
                {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for nat_key in stale_nat_keys {
            if let Some(entry) = self.release_nat_key(&nat_key) {
                self.remove_socket_for_local_port(nat_key.2);
                log::debug!(
                    "Cleaned stale userspace TCP flow {:?} on local port {}",
                    entry.flow_key,
                    nat_key.2
                );
            }
        }
    }

    fn remove_socket_for_local_port(&mut self, local_port: u16) {
        let handles = self
            .tcp_stack
            .sockets
            .iter()
            .filter_map(|(handle, socket)| {
                let socket = tcp::Socket::downcast(socket)?;
                let endpoint = socket.local_endpoint()?;
                if endpoint.port == local_port && !self.bridges.contains_key(&handle) {
                    Some(handle)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for handle in handles {
            self.pending_bridge_handles.remove(&handle);
            let socket = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);
            socket.abort();
            self.tcp_stack.sockets.remove(handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ipv4_tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(40u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x02;
        repair_tcp_checksums(&mut packet);
        packet
    }

    fn ipv6_tcp_packet(src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(20u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = 0x02;
        packet
    }

    fn ipv4_header_checksum_valid(packet: &[u8]) -> bool {
        let ihl = (packet[0] & 0x0f) as usize * 4;
        finish_checksum(add_ones_complement(0, &packet[..ihl])) == 0
    }

    fn ipv4_tcp_checksum_valid(packet: &[u8]) -> bool {
        let ihl = (packet[0] & 0x0f) as usize * 4;
        let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        let tcp_len = total_len - ihl;
        let mut sum = 0u32;
        sum = add_ones_complement(sum, &packet[12..20]);
        sum += 6;
        sum += tcp_len as u32;
        sum = add_ones_complement(sum, &packet[ihl..total_len]);
        finish_checksum(sum) == 0
    }

    fn ipv6_tcp_checksum_valid(packet: &[u8]) -> bool {
        if packet.len() < 60 {
            return false;
        }
        let tcp_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        let mut sum = 0u32;
        sum = add_ones_complement(sum, &packet[8..40]);
        sum = add_ones_complement(sum, &(tcp_len as u32).to_be_bytes());
        sum += 6;
        sum = add_ones_complement(sum, &packet[40..40 + tcp_len]);
        finish_checksum(sum) == 0
    }

    fn test_worker() -> RtcWorker {
        let private_key = boringtun::x25519::StaticSecret::from([1u8; 32]);
        let public_key = boringtun::x25519::PublicKey::from(&private_key);
        let peer = crate::config::PeerConfig {
            public_key: public_key.to_bytes(),
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: Some(51821),
        };
        let l3_registry = UserspaceWgRegistry::new(private_key.to_bytes(), &[peer]).unwrap();
        let ip_cidr = smoltcp::wire::IpCidr::from_str("10.0.0.2/24").unwrap();
        let buffer_pool = BufferPool::new(crate::config::packet_buffer_size_for_mtu(1400));
        let tcp_stack = UserspaceTcpStack::new(vec![ip_cidr], 1400, buffer_pool.clone()).unwrap();
        let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
        sock1.set_nonblocking(true).unwrap();
        let tun_fd = std::os::unix::io::IntoRawFd::into_raw_fd(sock1.try_clone().unwrap());
        let tun_io = Arc::new(AsyncTunIo::new(tun_fd).unwrap());
        let udp_socket = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        udp_socket.set_nonblocking(true).unwrap();
        let tokio_udp =
            Arc::new(tokio::net::UdpSocket::from_std((*udp_socket).try_clone().unwrap()).unwrap());

        RtcWorker::new(
            tun_io,
            crate::virtual_tunnel::TunnelSocket::Single(tokio_udp),
            l3_registry,
            tcp_stack,
            RtcWorkerConfig {
                local_ipv4: Some("10.0.0.2".parse().unwrap()),
                local_ipv6: None,
                mtu: 1400,
                buffer_pool,
            },
        )
    }

    #[test]
    fn bridge_pending_queues_are_capped_by_bytes() {
        let pool = BufferPool::new(bridge_pending_bytes_limit());
        let mut bridge = BridgeChannels {
            nat_key: ("10.0.0.2".parse().unwrap(), 40000, 49152),
            quic: BridgeQuicState::Inactive,
            recv_buf: pool.get(),
            quic_recv_buf: pool.get(),
            to_quic_pending: VecDeque::new(),
            from_quic_pending: VecDeque::new(),
            to_quic_pending_bytes: 0,
            from_quic_pending_bytes: 0,
            quic_rx_closed: false,
        };

        let mut full = pool.get();
        full.set_len(bridge_pending_bytes_limit());
        assert!(bridge.push_to_quic_pending(full));
        let mut one = pool.get();
        one.set_len(1);
        assert!(!bridge.push_to_quic_pending(one));
        bridge.consume_to_quic_front(bridge_pending_bytes_limit());
        assert!(bridge.to_quic_pending.is_empty());
        assert_eq!(bridge.to_quic_pending_bytes, 0);

        let mut full = pool.get();
        full.set_len(bridge_pending_bytes_limit());
        assert!(bridge.push_from_quic_pending(full));
        let mut one = pool.get();
        one.set_len(1);
        assert!(!bridge.push_from_quic_pending(one));
        bridge.consume_from_quic_front(1024);
        assert_eq!(
            bridge.from_quic_pending_bytes,
            bridge_pending_bytes_limit() - 1024
        );
    }

    #[test]
    fn test_packet_classification() {
        let ipv4_tcp_packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 127, 0, 0, 1,
            127, 0, 0, 1,
        ];
        assert_eq!(get_ip_protocol(&ipv4_tcp_packet), Some(6));
        assert_eq!(get_ip_protocol(&[]), None);
        assert_eq!(get_ip_protocol(&[0x45, 0x00]), None);
        assert_eq!(get_ip_protocol(&[0x70; 40]), None);
    }

    #[test]
    fn parse_ipv6_tcp_rejects_short_header_without_panicking() {
        let mut packet = vec![0u8; 53];
        packet[0] = 0x60;
        packet[6] = 6;

        assert_eq!(parse_tcp_packet(&packet), None);
    }

    #[test]
    fn parse_ipv6_tcp_with_extension_header_falls_back_to_l3() {
        let mut packet = ipv6_tcp_packet(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            12345,
            443,
        );
        packet[6] = 0;

        assert_eq!(get_ip_protocol(&packet), Some(0));
        assert_eq!(parse_tcp_packet(&packet), None);
    }

    #[test]
    fn parse_tcp_packet_handles_ipv4_options_and_ipv6_syn() {
        let mut ipv4 = vec![0u8; 44];
        ipv4[0] = 0x46;
        ipv4[2..4].copy_from_slice(&(44u16).to_be_bytes());
        ipv4[9] = 6;
        ipv4[12..16].copy_from_slice(&[10, 0, 0, 10]);
        ipv4[16..20].copy_from_slice(&[10, 0, 0, 20]);
        ipv4[24..26].copy_from_slice(&40000u16.to_be_bytes());
        ipv4[26..28].copy_from_slice(&443u16.to_be_bytes());
        ipv4[37] = 0x02;
        assert_eq!(
            parse_tcp_packet(&ipv4),
            Some((
                "10.0.0.10".parse().unwrap(),
                40000,
                "10.0.0.20".parse().unwrap(),
                443,
                true,
            ))
        );

        let ipv6 = ipv6_tcp_packet(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            12345,
            8443,
        );
        assert_eq!(
            parse_tcp_packet(&ipv6),
            Some((
                "2001:db8::1".parse().unwrap(),
                12345,
                "2001:db8::2".parse().unwrap(),
                8443,
                true,
            ))
        );
    }

    #[test]
    fn parse_tcp_packet_rejects_malformed_ipv4_lengths() {
        let mut bad_ihl = ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443);
        bad_ihl[0] = 0x44;
        assert_eq!(parse_tcp_packet(&bad_ihl), None);

        let mut bad_total_len = ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443);
        bad_total_len[2..4].copy_from_slice(&(30u16).to_be_bytes());
        assert_eq!(parse_tcp_packet(&bad_total_len), None);

        let mut truncated = ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 443);
        truncated[2..4].copy_from_slice(&(60u16).to_be_bytes());
        assert_eq!(parse_tcp_packet(&truncated), None);
    }

    #[test]
    fn rewrites_repair_ipv4_tcp_checksums() {
        let mut packet = ipv4_tcp_packet([10, 1, 0, 2], [10, 2, 0, 1], 40000, 443);
        rewrite_destination_ip(&mut packet, "10.0.0.2".parse().unwrap());
        rewrite_destination_port(&mut packet, 50000);
        repair_tcp_checksums(&mut packet);
        assert!(ipv4_header_checksum_valid(&packet));
        assert!(ipv4_tcp_checksum_valid(&packet));

        rewrite_source_ip(&mut packet, "10.2.0.1".parse().unwrap());
        rewrite_source_port(&mut packet, 443);
        repair_tcp_checksums(&mut packet);
        assert!(ipv4_header_checksum_valid(&packet));
        assert!(ipv4_tcp_checksum_valid(&packet));
    }

    #[test]
    fn rewrites_repair_ipv6_tcp_checksums() {
        let mut packet = ipv6_tcp_packet(
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            12345,
            8443,
        );
        repair_tcp_checksums(&mut packet);
        assert!(ipv6_tcp_checksum_valid(&packet));

        rewrite_destination_ip(&mut packet, "2001:db8::3".parse().unwrap());
        rewrite_destination_port(&mut packet, 9000);
        repair_tcp_checksums(&mut packet);
        assert!(ipv6_tcp_checksum_valid(&packet));

        rewrite_source_ip(&mut packet, "2001:db8::4".parse().unwrap());
        rewrite_source_port(&mut packet, 54321);
        repair_tcp_checksums(&mut packet);
        assert!(ipv6_tcp_checksum_valid(&packet));
    }

    #[tokio::test]
    async fn existing_flow_keeps_smoltcp_path_when_new_offload_is_disabled() {
        let mut worker = test_worker();
        let flow_key = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );

        assert!(!worker.should_route_via_smoltcp(&flow_key, false, false));
        assert!(worker.should_route_via_smoltcp(&flow_key, true, true));

        worker.insert_flow_port(flow_key, 49152);
        worker.assert_port_index_consistent();
        assert!(worker.should_route_via_smoltcp(&flow_key, false, false));
    }

    #[tokio::test]
    async fn new_syn_falls_back_when_worker_flow_limit_is_reached() {
        let mut worker = test_worker();
        let flow_key = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );

        for i in 0..max_worker_tcp_flows() {
            let existing_flow = (
                "10.0.0.10".parse().unwrap(),
                10000 + i as u16,
                "10.9.0.1".parse().unwrap(),
                443,
            );
            worker.insert_flow_port(existing_flow, 49152 + i as u16);
        }

        worker.assert_port_index_consistent();
        assert!(worker.tcp_flow_limit_reached_for_new_flow(&flow_key, true));
        assert!(!worker.tcp_flow_limit_reached_for_new_flow(&flow_key, false));
        worker.insert_flow_port(flow_key, 49152 + max_worker_tcp_flows() as u16);
        worker.assert_port_index_consistent();
        assert!(!worker.tcp_flow_limit_reached_for_new_flow(&flow_key, true));
    }

    #[tokio::test]
    async fn stale_cleanup_preserves_bridged_flow() {
        let mut worker = test_worker();
        let flow_key = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );
        let nat_key = ("10.0.0.10".parse().unwrap(), 40000, 49152);
        worker.insert_flow_port(flow_key, 49152);
        worker.nat_map.insert(
            nat_key,
            NatEntry {
                original_dst_ip: "10.9.0.1".parse().unwrap(),
                original_dst_port: 443,
                peer_pub_key: [2u8; 32],
                flow_key,
                last_seen: Instant::now() - HALF_OPEN_TIMEOUT - Duration::from_secs(1),
            },
        );
        let handle = worker.tcp_stack.create_tcp_socket(1024, 1024).unwrap();
        worker.bridges.insert(
            handle,
            BridgeChannels {
                nat_key,
                quic: BridgeQuicState::Inactive,
                recv_buf: worker.buffer_pool.get(),
                quic_recv_buf: worker.buffer_pool.get(),
                to_quic_pending: VecDeque::new(),
                from_quic_pending: VecDeque::new(),
                to_quic_pending_bytes: 0,
                from_quic_pending_bytes: 0,
                quic_rx_closed: false,
            },
        );
        worker.last_housekeeping = Instant::now() - HOUSEKEEPING_INTERVAL - Duration::from_secs(1);

        worker.cleanup_stale_flows();

        assert!(worker.nat_map.contains_key(&nat_key));
        assert_eq!(worker.flow_map.get(&flow_key), Some(&49152));
        worker.assert_port_index_consistent();
    }

    #[tokio::test]
    async fn allocate_local_port_uses_flow_port_index_instead_of_scanning_nat_map() {
        let mut worker = test_worker();
        let flow_key = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );
        worker.nat_map.insert(
            ("10.0.0.10".parse().unwrap(), 40000, 49152),
            NatEntry {
                original_dst_ip: "10.9.0.1".parse().unwrap(),
                original_dst_port: 443,
                peer_pub_key: [2u8; 32],
                flow_key,
                last_seen: Instant::now(),
            },
        );

        assert_eq!(worker.allocate_local_port(), Some(49152));
    }

    #[tokio::test]
    async fn allocate_local_port_skips_ports_claimed_by_flow_set() {
        let mut worker = test_worker();
        let flow_key = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );

        worker.insert_flow_port(flow_key, 49152);
        worker.assert_port_index_consistent();
        assert_eq!(worker.allocate_local_port(), Some(49153));
        assert_eq!(worker.release_flow_port(&flow_key), Some(49152));
        worker.assert_port_index_consistent();
        assert_eq!(worker.allocate_local_port(), Some(49154));
    }

    #[tokio::test]
    #[should_panic(expected = "already assigned to another flow")]
    async fn insert_flow_port_rejects_duplicate_port_in_debug_builds() {
        let mut worker = test_worker();
        let first_flow = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );
        let second_flow = (
            "10.0.0.11".parse().unwrap(),
            40001,
            "10.9.0.1".parse().unwrap(),
            443,
        );

        worker.insert_flow_port(first_flow, 49152);
        worker.insert_flow_port(second_flow, 49152);
    }

    #[tokio::test]
    async fn allocate_local_port_can_use_final_ephemeral_port() {
        let mut worker = test_worker();
        for port in 49152..65535 {
            worker.used_local_ports.insert(port);
        }

        assert_eq!(worker.allocate_local_port(), Some(65535));
    }

    #[tokio::test]
    async fn cleanup_stale_flows_removes_half_open_nat_entries() {
        let mut worker = test_worker();
        let flow_key = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );
        let nat_key = ("10.0.0.10".parse().unwrap(), 40000, 49152);
        worker.insert_flow_port(flow_key, 49152);
        worker.nat_map.insert(
            nat_key,
            NatEntry {
                original_dst_ip: "10.9.0.1".parse().unwrap(),
                original_dst_port: 443,
                peer_pub_key: [2u8; 32],
                flow_key,
                last_seen: Instant::now() - HALF_OPEN_TIMEOUT - Duration::from_secs(1),
            },
        );
        worker.last_housekeeping = Instant::now() - HOUSEKEEPING_INTERVAL - Duration::from_secs(1);

        worker.cleanup_stale_flows();

        assert!(!worker.nat_map.contains_key(&nat_key));
        assert!(!worker.flow_map.contains_key(&flow_key));
        assert!(!worker.used_local_ports.contains(&49152));
        worker.assert_port_index_consistent();
    }

    #[tokio::test]
    async fn cleanup_stale_flows_removes_half_open_socket_for_local_port() {
        let mut worker = test_worker();
        let flow_key = (
            "10.0.0.10".parse().unwrap(),
            40000,
            "10.9.0.1".parse().unwrap(),
            443,
        );
        let nat_key = ("10.0.0.10".parse().unwrap(), 40000, 49152);
        worker.insert_flow_port(flow_key, 49152);
        worker.nat_map.insert(
            nat_key,
            NatEntry {
                original_dst_ip: "10.9.0.1".parse().unwrap(),
                original_dst_port: 443,
                peer_pub_key: [2u8; 32],
                flow_key,
                last_seen: Instant::now() - HALF_OPEN_TIMEOUT - Duration::from_secs(1),
            },
        );
        let handle = worker
            .tcp_stack
            .create_tcp_socket(1024, 1024)
            .expect("create test socket");
        worker
            .tcp_stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .listen(49152)
            .expect("listen on local test port");
        worker.last_housekeeping = Instant::now() - HOUSEKEEPING_INTERVAL - Duration::from_secs(1);

        worker.cleanup_stale_flows();

        assert!(!worker.nat_map.contains_key(&nat_key));
        assert!(!worker.flow_map.contains_key(&flow_key));
        assert!(!worker.used_local_ports.contains(&49152));
        worker.assert_port_index_consistent();
        assert!(worker
            .tcp_stack
            .sockets
            .iter()
            .filter_map(|(_, socket)| tcp::Socket::downcast(socket))
            .all(|socket| socket
                .local_endpoint()
                .map(|endpoint| endpoint.port != 49152)
                .unwrap_or(true)));
    }

    #[test]
    fn test_rtc_worker_creation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut worker = test_worker();
            assert_eq!(
                worker.local_ip_for("10.9.0.1".parse().unwrap()),
                Some("10.0.0.2".parse().unwrap())
            );
            assert_eq!(worker.local_ip_for("fd00::1".parse().unwrap()), None);

            let flow_key = (
                "10.0.0.10".parse().unwrap(),
                40000,
                "10.9.0.1".parse().unwrap(),
                443,
            );
            let nat_key = ("10.0.0.10".parse().unwrap(), 40000, 49152);
            worker.insert_flow_port(flow_key, 49152);
            worker.nat_map.insert(
                nat_key,
                NatEntry {
                    original_dst_ip: "10.9.0.1".parse().unwrap(),
                    original_dst_port: 443,
                    peer_pub_key: [2u8; 32],
                    flow_key,
                    last_seen: Instant::now() - HALF_OPEN_TIMEOUT - Duration::from_secs(1),
                },
            );
            worker.last_housekeeping =
                Instant::now() - HOUSEKEEPING_INTERVAL - Duration::from_secs(1);
            worker.cleanup_stale_flows();
            assert!(worker.nat_map.is_empty());
            assert!(worker.flow_map.is_empty());
            worker.assert_port_index_consistent();

            let result = worker.run_one_iteration().await;
            assert!(result.is_ok());
        });
    }
}
