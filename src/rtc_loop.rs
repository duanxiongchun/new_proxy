use crate::tun_io::AsyncTunIo;
use crate::userspace_tcp::UserspaceTcpStack;
use crate::userspace_wg::{UserspaceWgAction, UserspaceWgRegistry};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::socket::AnySocket;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify};

type ActiveConnHandler = Arc<
    dyn Fn(SocketAddr, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>, Arc<Notify>) + Send + Sync,
>;
type NatKey = (IpAddr, u16, u16);
type FlowKey = (IpAddr, u16, IpAddr, u16);
const BRIDGE_PENDING_LIMIT: usize = 256;
const HALF_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const HOUSEKEEPING_INTERVAL: Duration = Duration::from_secs(1);
const MAX_WORKER_TCP_FLOWS: usize = 4096;

#[derive(Clone, Copy)]
pub struct NatEntry {
    pub original_dst_ip: IpAddr,
    pub original_dst_port: u16,
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
    pub tx_sender: mpsc::Sender<Vec<u8>>,
    pub rx_receiver: mpsc::Receiver<Vec<u8>>,
    pub nat_key: NatKey,
    pub recv_buf: Vec<u8>,
    pub to_quic_pending: VecDeque<Vec<u8>>,
    pub from_quic_pending: VecDeque<Vec<u8>>,
    pub quic_rx_closed: bool,
}

pub struct RtcWorker {
    pub tun_io: Arc<AsyncTunIo>,
    pub udp_socket: Arc<tokio::net::UdpSocket>,
    pub l3_registry: UserspaceWgRegistry,
    pub tcp_stack: UserspaceTcpStack,
    pub bridges: HashMap<SocketHandle, BridgeChannels>,
    pub active_conn_handler: Option<ActiveConnHandler>,
    pub nat_map: HashMap<NatKey, NatEntry>,
    pub flow_map: HashMap<FlowKey, u16>,
    next_local_port: u16,
    local_ipv4: Option<IpAddr>,
    local_ipv6: Option<IpAddr>,
    mtu: usize,
    last_housekeeping: Instant,
    bridge_notify: Arc<Notify>,
    worker_stats: Option<Arc<crate::telemetry::WorkerTelemetry>>,
}

impl RtcWorker {
    pub fn new(
        tun_io: Arc<AsyncTunIo>,
        udp_socket: Arc<tokio::net::UdpSocket>,
        l3_registry: UserspaceWgRegistry,
        tcp_stack: UserspaceTcpStack,
        local_ipv4: Option<IpAddr>,
        local_ipv6: Option<IpAddr>,
        mtu: usize,
    ) -> Self {
        Self {
            tun_io,
            udp_socket,
            l3_registry,
            tcp_stack,
            bridges: HashMap::new(),
            active_conn_handler: None,
            nat_map: HashMap::new(),
            flow_map: HashMap::new(),
            next_local_port: 49152,
            local_ipv4,
            local_ipv6,
            mtu,
            last_housekeeping: Instant::now(),
            bridge_notify: Arc::new(Notify::new()),
            worker_stats: None,
        }
    }

    pub fn set_worker_stats(&mut self, worker_stats: Arc<crate::telemetry::WorkerTelemetry>) {
        self.worker_stats = Some(worker_stats);
    }

    fn record_tun_rx(&self, bytes: usize) {
        if let Some(stats) = &self.worker_stats {
            stats.tun_rx_packets.fetch_add(1, Ordering::Relaxed);
            stats
                .tun_rx_bytes
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    fn record_tcp_offload(&self, bytes: usize) {
        if let Some(stats) = &self.worker_stats {
            stats.tcp_offload_packets.fetch_add(1, Ordering::Relaxed);
            stats
                .tcp_offload_bytes
                .fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    fn record_l3_packet(&self, bytes: usize) {
        if let Some(stats) = &self.worker_stats {
            stats.l3_packets.fetch_add(1, Ordering::Relaxed);
            stats.l3_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    fn record_new_tcp_flow(&self) {
        if let Some(stats) = &self.worker_stats {
            stats.new_tcp_flows.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_current_tcp_flows(&self) {
        if let Some(stats) = &self.worker_stats {
            stats
                .current_tcp_flows
                .store(self.flow_map.len() as u64, Ordering::Relaxed);
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
        for _ in 0..(65535 - 49152) {
            let port = self.next_local_port;
            self.next_local_port = if self.next_local_port == 65535 {
                49152
            } else {
                self.next_local_port + 1
            };
            if self
                .nat_map
                .keys()
                .any(|(_, _, local_port)| *local_port == port)
            {
                continue;
            }
            let socket_port_in_use = self.tcp_stack.sockets.iter().any(|(_, socket)| {
                tcp::Socket::downcast(socket)
                    .and_then(|socket| socket.local_endpoint())
                    .map(|endpoint| endpoint.port == port)
                    .unwrap_or(false)
            });
            if !socket_port_in_use {
                return Some(port);
            }
        }
        None
    }

    fn should_route_via_smoltcp(
        &self,
        flow_key: &FlowKey,
        is_syn: bool,
        offload_available_for_new_flow: bool,
    ) -> bool {
        self.flow_map.contains_key(flow_key) || (is_syn && offload_available_for_new_flow)
    }

    pub async fn run_one_iteration(&mut self) -> Result<std::time::Duration, String> {
        self.cleanup_stale_flows();
        let now = smoltcp::time::Instant::now();
        self.tcp_stack
            .iface
            .poll(now, &mut self.tcp_stack.device, &mut self.tcp_stack.sockets);

        // Flush outgoing TCP packets from smoltcp to TUN
        while let Some(mut pkt) = self.tcp_stack.device.tx_queue.pop_front() {
            if let Some((_src_ip, src_port, dst_ip, dst_port, _)) = parse_tcp_packet(&pkt) {
                let key = (dst_ip, dst_port, src_port);
                if let Some(entry) = self.nat_map.get(&key) {
                    rewrite_source_ip(&mut pkt, entry.original_dst_ip);
                    rewrite_source_port(&mut pkt, entry.original_dst_port);
                    repair_tcp_checksums(&mut pkt);
                }
            }
            if let Err(e) = self.tun_io.write_packet(&pkt).await {
                log::warn!("Failed to write smoltcp packet to TUN: {}", e);
            }
        }

        // Handle active TCP bridges
        self.handle_bridges().await;

        let poll_delay = self
            .tcp_stack
            .iface
            .poll_delay(now, &self.tcp_stack.sockets)
            .unwrap_or(smoltcp::time::Duration::from_millis(10));
        Ok(std::time::Duration::from_millis(poll_delay.total_millis()))
    }

    #[cfg(not(tarpaulin))]
    pub async fn run_loop(
        &mut self,
        gateway_state: Arc<parking_lot::RwLock<crate::GatewayState>>,
        client_quic_pools: crate::PeerQuicPools,
    ) -> Result<(), String> {
        let mut tun_buf = vec![0u8; 65535];
        let mut udp_buf = vec![0u8; 65535];
        let mut wg_buf = vec![0u8; 65535];

        loop {
            self.cleanup_stale_flows();
            self.record_current_tcp_flows();
            let now = smoltcp::time::Instant::now();
            self.tcp_stack
                .iface
                .poll(now, &mut self.tcp_stack.device, &mut self.tcp_stack.sockets);

            // Flush outgoing TCP packets from smoltcp to TUN, applying NAT reverse rewrite
            while let Some(mut pkt) = self.tcp_stack.device.tx_queue.pop_front() {
                if let Some((_src_ip, src_port, dst_ip, dst_port, _)) = parse_tcp_packet(&pkt) {
                    let key = (dst_ip, dst_port, src_port);
                    if let Some(entry) = self.nat_map.get(&key) {
                        rewrite_source_ip(&mut pkt, entry.original_dst_ip);
                        rewrite_source_port(&mut pkt, entry.original_dst_port);
                        repair_tcp_checksums(&mut pkt);
                    }
                }
                if let Err(e) = self.tun_io.write_packet(&pkt).await {
                    log::warn!("Failed to write smoltcp packet to TUN: {}", e);
                }
            }

            self.handle_bridges().await;

            let poll_delay = self
                .tcp_stack
                .iface
                .poll_delay(now, &self.tcp_stack.sockets)
                .unwrap_or(smoltcp::time::Duration::from_millis(10));
            let delay_duration = std::time::Duration::from_millis(poll_delay.total_millis());

            tokio::select! {
                read_res = self.tun_io.read(&mut tun_buf) => {
                    match read_res {
                        Ok(n) if n > 0 => {
                            self.record_tun_rx(n);
                            let packet = &mut tun_buf[..n];
                            if let Some((src_ip, src_port, dst_ip, dst_port, is_syn)) = parse_tcp_packet(packet) {
                                let flow_key = (src_ip, src_port, dst_ip, dst_port);
                                let offload_available_for_new_flow = {
                                    let peer_pub_key = {
                                        let state = gateway_state.read();
                                        state
                                            .userspace_tcp_offload_enabled
                                            .then(|| state.router.longest_match(dst_ip))
                                            .flatten()
                                    };
                                    if let Some(peer_pub_key) = peer_pub_key {
                                        let pools = client_quic_pools.read();
                                        pools
                                            .get(&peer_pub_key)
                                            .map(|pool| matches!(pool.get_state(), crate::quic_pool::PoolState::Active))
                                            .unwrap_or(false)
                                    } else {
                                        false
                                    }
                                };

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
                                            self.l3_registry.encapsulate_tunnel_packet(packet, &mut wg_buf)
                                        {
                                            self.record_l3_packet(n);
                                            if let Err(e) = self.udp_socket.send_to(&enc_pkt, endpoint).await {
                                                log::warn!("Failed to send userspace WireGuard fallback packet to {}: {}", endpoint, e);
                                            }
                                        }
                                        continue;
                                    };
                                    if is_syn
                                        && !self.flow_map.contains_key(&flow_key)
                                        && self.flow_map.len() >= MAX_WORKER_TCP_FLOWS
                                    {
                                        log::warn!(
                                            "Userspace TCP flow limit reached; falling back to userspace WireGuard L3"
                                        );
                                        if let Some((endpoint, enc_pkt)) =
                                            self.l3_registry.encapsulate_tunnel_packet(packet, &mut wg_buf)
                                        {
                                            self.record_l3_packet(n);
                                            if let Err(e) = self.udp_socket.send_to(&enc_pkt, endpoint).await {
                                                log::warn!("Failed to send userspace WireGuard fallback packet to {}: {}", endpoint, e);
                                            }
                                        }
                                        continue;
                                    }

                                    let local_port = if is_syn {
                                        match self.flow_map.get(&flow_key).copied() {
                                            Some(port) => port,
                                            None => match self.allocate_local_port() {
                                                Some(port) => {
                                                    self.flow_map.insert(flow_key, port);
                                                    self.record_new_tcp_flow();
                                                    port
                                                }
                                                None => {
                                                    log::warn!("No free smoltcp local ports; falling back to userspace WireGuard L3");
                                                    if let Some((endpoint, enc_pkt)) =
                                                        self.l3_registry.encapsulate_tunnel_packet(packet, &mut wg_buf)
                                                    {
                                                        self.record_l3_packet(n);
                                                        if let Err(e) = self.udp_socket.send_to(&enc_pkt, endpoint).await {
                                                            log::warn!("Failed to send userspace WireGuard fallback packet to {}: {}", endpoint, e);
                                                        }
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
                                            self.l3_registry.encapsulate_tunnel_packet(packet, &mut wg_buf)
                                        {
                                            self.record_l3_packet(n);
                                            if let Err(e) = self.udp_socket.send_to(&enc_pkt, endpoint).await {
                                                log::warn!("Failed to send userspace WireGuard fallback packet to {}: {}", endpoint, e);
                                            }
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
                                            if let Ok(handle) = self.tcp_stack.create_tcp_socket(131072, 131072) {
                                                let s = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);
                                                let _ = s.listen(local_port);
                                                log::debug!("Created userspace listening TCP socket on port {}", local_port);
                                            }
                                        }
                                    }

                                    self.nat_map.insert(
                                        (src_ip, src_port, local_port),
                                        NatEntry {
                                            original_dst_ip: dst_ip,
                                            original_dst_port: dst_port,
                                            flow_key,
                                            last_seen: Instant::now(),
                                        },
                                    );

                                    rewrite_destination_ip(packet, local_ip);
                                    rewrite_destination_port(packet, local_port);

                                    self.record_tcp_offload(n);
                                    self.tcp_stack.process_input_packet(packet.to_vec());
                                } else {
                                    if let Some((endpoint, enc_pkt)) =
                                        self.l3_registry.encapsulate_tunnel_packet(packet, &mut wg_buf)
                                    {
                                        self.record_l3_packet(n);
                                        if let Err(e) = self.udp_socket.send_to(&enc_pkt, endpoint).await {
                                            log::warn!("Failed to send userspace WireGuard packet to {}: {}", endpoint, e);
                                        }
                                    }
                                }
                            } else {
                                if let Some((endpoint, enc_pkt)) =
                                    self.l3_registry.encapsulate_tunnel_packet(packet, &mut wg_buf)
                                {
                                    self.record_l3_packet(n);
                                    if let Err(e) = self.udp_socket.send_to(&enc_pkt, endpoint).await {
                                        log::warn!("Failed to send userspace WireGuard packet to {}: {}", endpoint, e);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                udp_res = self.udp_socket.recv_from(&mut udp_buf) => {
                    if let Ok((n, addr)) = udp_res {
                        if let Some((reply_endpoint, actions)) =
                            self.l3_registry.decapsulate_network_packet(addr, &udp_buf[..n], &mut wg_buf)
                        {
                            for action in actions {
                                match action {
                                    UserspaceWgAction::WriteToTunnel(dec_pkt) => {
                                        if let Err(e) = self.tun_io.write_packet(&dec_pkt).await {
                                            log::warn!("Failed to write userspace WireGuard packet to TUN: {}", e);
                                        }
                                    }
                                    UserspaceWgAction::WriteToNetwork(resp_pkt) => {
                                        if let Err(e) = self.udp_socket.send_to(&resp_pkt, reply_endpoint).await {
                                            log::warn!("Failed to send userspace WireGuard response to {}: {}", reply_endpoint, e);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                _ = tokio::time::sleep(delay_duration) => {}

                _ = self.bridge_notify.notified() => {}

            }
        }
    }

    async fn handle_bridges(&mut self) {
        let mut closed_handles = Vec::new();

        // Check for new connections in smoltcp
        let mut new_connections = Vec::new();
        for (handle, socket) in self.tcp_stack.sockets.iter_mut() {
            if let Some(socket) = tcp::Socket::downcast_mut(socket) {
                if socket.is_active() && !self.bridges.contains_key(&handle) {
                    if let (Some(local_endpoint), Some(remote_endpoint)) =
                        (socket.local_endpoint(), socket.remote_endpoint())
                    {
                        let client_ip = smoltcp_ip_to_std(remote_endpoint.addr);
                        let key = (client_ip, remote_endpoint.port, local_endpoint.port);
                        if let Some(entry) = self.nat_map.get(&key) {
                            let original_dest =
                                SocketAddr::new(entry.original_dst_ip, entry.original_dst_port);
                            new_connections.push((handle, original_dest, key));
                        } else {
                            log::warn!(
                                "No NAT mapping found for userspace TCP socket {}:{} -> local port {}; skipping QUIC bridge",
                                client_ip,
                                remote_endpoint.port,
                                local_endpoint.port
                            );
                        }
                    }
                }
            }
        }

        for (handle, original_dest, nat_key) in new_connections {
            if let Some(ref handler) = self.active_conn_handler {
                let (tx_sender, tx_receiver) = mpsc::channel(100);
                let (rx_sender, rx_receiver) = mpsc::channel(100);
                self.bridges.insert(
                    handle,
                    BridgeChannels {
                        tx_sender,
                        rx_receiver,
                        nat_key,
                        recv_buf: vec![0u8; self.mtu],
                        to_quic_pending: VecDeque::new(),
                        from_quic_pending: VecDeque::new(),
                        quic_rx_closed: false,
                    },
                );
                let handler_clone = handler.clone();
                let notify = self.bridge_notify.clone();
                tokio::spawn(async move {
                    handler_clone(original_dest, tx_receiver, rx_sender, notify);
                });
            } else {
                if let Some(entry) = self.nat_map.remove(&nat_key) {
                    self.flow_map.remove(&entry.flow_key);
                }
                if !closed_handles.contains(&handle) {
                    closed_handles.push(handle);
                }
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

            while let Some(data) = bridge.to_quic_pending.pop_front() {
                match bridge.tx_sender.try_send(data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(data)) => {
                        bridge.to_quic_pending.push_front(data);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        if !closed_handles.contains(&handle) {
                            closed_handles.push(handle);
                        }
                        break;
                    }
                }
            }

            while bridge.from_quic_pending.len() < BRIDGE_PENDING_LIMIT {
                match bridge.rx_receiver.try_recv() {
                    Ok(data) => bridge.from_quic_pending.push_back(data),
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        bridge.quic_rx_closed = true;
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }

            while socket.can_send() {
                let Some(front) = bridge.from_quic_pending.front_mut() else {
                    break;
                };
                match socket.send_slice(front) {
                    Ok(0) => break,
                    Ok(n) if n >= front.len() => {
                        bridge.from_quic_pending.pop_front();
                    }
                    Ok(n) => {
                        front.drain(..n);
                    }
                    Err(_) => break,
                }
            }
            if bridge.quic_rx_closed && bridge.from_quic_pending.is_empty() {
                socket.close();
            }

            while socket.can_recv() && bridge.to_quic_pending.len() < BRIDGE_PENDING_LIMIT {
                if bridge.recv_buf.len() != self.mtu {
                    bridge.recv_buf.resize(self.mtu, 0);
                }
                if let Ok(n) = socket.recv_slice(&mut bridge.recv_buf) {
                    if n > 0 {
                        bridge
                            .to_quic_pending
                            .push_back(bridge.recv_buf[..n].to_vec());
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        for handle in closed_handles {
            if let Some(bridge) = self.bridges.remove(&handle) {
                if let Some(entry) = self.nat_map.remove(&bridge.nat_key) {
                    self.flow_map.remove(&entry.flow_key);
                }
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
            if let Some(entry) = self.nat_map.remove(&nat_key) {
                self.flow_map.remove(&entry.flow_key);
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
        let tcp_stack = UserspaceTcpStack::new(vec![ip_cidr], 1400).unwrap();
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
            tokio_udp,
            l3_registry,
            tcp_stack,
            Some("10.0.0.2".parse().unwrap()),
            None,
            1400,
        )
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

        worker.flow_map.insert(flow_key, 49152);
        assert!(worker.should_route_via_smoltcp(&flow_key, false, false));
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
        worker.flow_map.insert(flow_key, 49152);
        worker.nat_map.insert(
            nat_key,
            NatEntry {
                original_dst_ip: "10.9.0.1".parse().unwrap(),
                original_dst_port: 443,
                flow_key,
                last_seen: Instant::now() - HALF_OPEN_TIMEOUT - Duration::from_secs(1),
            },
        );
        let handle = worker.tcp_stack.create_tcp_socket(1024, 1024).unwrap();
        let (tx_sender, _tx_receiver) = mpsc::channel(1);
        let (_rx_sender, rx_receiver) = mpsc::channel(1);
        worker.bridges.insert(
            handle,
            BridgeChannels {
                tx_sender,
                rx_receiver,
                nat_key,
                recv_buf: vec![0; 1400],
                to_quic_pending: VecDeque::new(),
                from_quic_pending: VecDeque::new(),
                quic_rx_closed: false,
            },
        );
        worker.last_housekeeping = Instant::now() - HOUSEKEEPING_INTERVAL - Duration::from_secs(1);

        worker.cleanup_stale_flows();

        assert!(worker.nat_map.contains_key(&nat_key));
        assert_eq!(worker.flow_map.get(&flow_key), Some(&49152));
    }

    #[tokio::test]
    async fn allocate_local_port_skips_ports_already_in_nat_map() {
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
                flow_key,
                last_seen: Instant::now(),
            },
        );

        assert_eq!(worker.allocate_local_port(), Some(49153));
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
        worker.flow_map.insert(flow_key, 49152);
        worker.nat_map.insert(
            nat_key,
            NatEntry {
                original_dst_ip: "10.9.0.1".parse().unwrap(),
                original_dst_port: 443,
                flow_key,
                last_seen: Instant::now() - HALF_OPEN_TIMEOUT - Duration::from_secs(1),
            },
        );
        worker.last_housekeeping = Instant::now() - HOUSEKEEPING_INTERVAL - Duration::from_secs(1);

        worker.cleanup_stale_flows();

        assert!(!worker.nat_map.contains_key(&nat_key));
        assert!(!worker.flow_map.contains_key(&flow_key));
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
            worker.flow_map.insert(flow_key, 49152);
            worker.nat_map.insert(
                nat_key,
                NatEntry {
                    original_dst_ip: "10.9.0.1".parse().unwrap(),
                    original_dst_port: 443,
                    flow_key,
                    last_seen: Instant::now() - HALF_OPEN_TIMEOUT - Duration::from_secs(1),
                },
            );
            worker.last_housekeeping =
                Instant::now() - HOUSEKEEPING_INTERVAL - Duration::from_secs(1);
            worker.cleanup_stale_flows();
            assert!(worker.nat_map.is_empty());
            assert!(worker.flow_map.is_empty());

            let result = worker.run_one_iteration().await;
            assert!(result.is_ok());
        });
    }
}
