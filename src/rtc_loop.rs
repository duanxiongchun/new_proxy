use crate::buffer_pool::BufferPool;
use crate::quic_pool::PeerConnRegistry;
use crate::tun_io::AsyncTunIo;
use quinn::Connection;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Notify;

pub struct RtcWorkerConfig {
    pub mtu: usize,
    pub buffer_pool: BufferPool,
}

#[derive(Clone)]
struct ActiveConn {
    conn: Connection,
    stats: Arc<crate::quic_pool::QuicConnStats>,
    peer_stats: Option<Arc<crate::telemetry::PeerL4Stats>>,
    _pub_key: [u8; 32],
}

#[derive(Clone)]
pub enum WorkerRole {
    Client,
    Server {
        peer_conn_registry: PeerConnRegistry,
        listen_ports: Vec<u16>,
    },
}

impl std::fmt::Debug for WorkerRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerRole::Client => write!(f, "Client"),
            WorkerRole::Server { .. } => write!(f, "Server"),
        }
    }
}

pub struct RtcWorker {
    pub tun_io: Arc<AsyncTunIo>,
    pub worker_id: usize,
    pub buffer_pool: BufferPool,
    pub packet_buffer_size: usize,
    pub worker_stats: Option<Arc<crate::telemetry::WorkerTelemetry>>,
    pub peer_telemetry: Option<Arc<crate::telemetry::TelemetryRegistry>>,
    pub role: WorkerRole,
    pub bridge_notify: Arc<Notify>,
}

impl RtcWorker {
    pub fn new(
        tun_io: Arc<AsyncTunIo>,
        worker_id: usize,
        role: WorkerRole,
        config: RtcWorkerConfig,
    ) -> Self {
        let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(config.mtu as u16);
        Self {
            tun_io,
            worker_id,
            buffer_pool: config.buffer_pool,
            packet_buffer_size,
            worker_stats: None,
            peer_telemetry: None,
            role,
            bridge_notify: Arc::new(Notify::new()),
        }
    }

    pub fn set_worker_stats(&mut self, stats: Arc<crate::telemetry::WorkerTelemetry>) {
        self.worker_stats = Some(stats);
    }

    pub fn set_peer_telemetry(&mut self, telemetry: Arc<crate::telemetry::TelemetryRegistry>) {
        self.peer_telemetry = Some(telemetry);
    }

    fn get_active_connection(
        &self,
        data_plane: &crate::L4DataPlaneSnapshot,
        dst_ip: IpAddr,
    ) -> Option<ActiveConn> {
        match &self.role {
            WorkerRole::Client => {
                let peer_pub_key = data_plane.router.longest_match(dst_ip)?;
                let pool = data_plane.client_quic_pools.get(&peer_pub_key)?;
                let (conn, stats) = pool.get_connection_by_slot(self.worker_id)?;
                if conn.close_reason().is_none() {
                    let peer_stats = self
                        .peer_telemetry
                        .as_ref()
                        .map(|pt| pt.get_or_create(peer_pub_key));
                    Some(ActiveConn {
                        conn,
                        stats,
                        peer_stats,
                        _pub_key: peer_pub_key,
                    })
                } else {
                    None
                }
            }
            WorkerRole::Server {
                peer_conn_registry,
                listen_ports,
            } => {
                let peer_pub_key = data_plane.router.longest_match(dst_ip)?;
                let local_port = listen_ports.get(self.worker_id).copied().unwrap_or(0);
                if local_port == 0 {
                    return None;
                }
                let registry = peer_conn_registry.read();
                let records = registry.get(&peer_pub_key)?;
                for record in records {
                    if record.stats.local_port == local_port && record.conn.close_reason().is_none()
                    {
                        let peer_stats = self
                            .peer_telemetry
                            .as_ref()
                            .map(|pt| pt.get_or_create(peer_pub_key));
                        return Some(ActiveConn {
                            conn: record.conn.clone(),
                            stats: record.stats.clone(),
                            peer_stats,
                            _pub_key: peer_pub_key,
                        });
                    }
                }
                None
            }
        }
    }

    fn get_all_active_connections(
        &self,
        data_plane: &crate::L4DataPlaneSnapshot,
    ) -> Vec<ActiveConn> {
        let mut conns = Vec::new();
        match &self.role {
            WorkerRole::Client => {
                for (&pub_key, pool) in &data_plane.client_quic_pools {
                    if let Some((conn, stats)) = pool.get_connection_by_slot(self.worker_id) {
                        if conn.close_reason().is_none() {
                            let peer_stats = self
                                .peer_telemetry
                                .as_ref()
                                .map(|pt| pt.get_or_create(pub_key));
                            conns.push(ActiveConn {
                                conn,
                                stats,
                                peer_stats,
                                _pub_key: pub_key,
                            });
                        }
                    }
                }
            }
            WorkerRole::Server {
                peer_conn_registry,
                listen_ports,
            } => {
                let local_port = listen_ports.get(self.worker_id).copied().unwrap_or(0);
                if local_port > 0 {
                    let registry = peer_conn_registry.read();
                    for (&pub_key, records) in registry.iter() {
                        for record in records {
                            if record.stats.local_port == local_port
                                && record.conn.close_reason().is_none()
                            {
                                let peer_stats = self
                                    .peer_telemetry
                                    .as_ref()
                                    .map(|pt| pt.get_or_create(pub_key));
                                conns.push(ActiveConn {
                                    conn: record.conn.clone(),
                                    stats: record.stats.clone(),
                                    peer_stats,
                                    _pub_key: pub_key,
                                });
                            }
                        }
                    }
                }
            }
        }
        conns
    }

    pub async fn run_loop(&mut self, data_plane: crate::L4DataPlane) -> Result<(), String> {
        let mut stats_timer = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut reload_timer = tokio::time::interval(std::time::Duration::from_millis(100));

        let mut local_stats = crate::telemetry::WorkerTelemetrySnapshot {
            worker_id: self.worker_id,
            ..crate::telemetry::WorkerTelemetrySnapshot::default()
        };

        let mut dp_snapshot = data_plane.load();
        let mut active_conns = self.get_all_active_connections(&dp_snapshot);
        let mut conn_cache: std::collections::HashMap<std::net::IpAddr, Option<ActiveConn>> =
            std::collections::HashMap::new();

        let rx_packets = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let rx_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut spawned_conns: std::collections::HashSet<usize> = std::collections::HashSet::new();

        // Spawn read tasks for initial connections
        for conn_info in &active_conns {
            let key = conn_info.conn.stable_id();
            if spawned_conns.insert(key) {
                let conn = conn_info.conn.clone();
                let tun_io = self.tun_io.clone();
                let conn_stats = conn_info.stats.clone();
                let peer_stats = conn_info.peer_stats.clone();
                let rx_packets = rx_packets.clone();
                let rx_bytes = rx_bytes.clone();
                tokio::spawn(async move {
                    while let Ok(bytes) = conn.read_datagram().await {
                        let n = bytes.len();
                        if let Err(e) = tun_io.write_packet(&bytes).await {
                            log::warn!("Failed to write to TUN: {}", e);
                        } else {
                            rx_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            rx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                            conn_stats
                                .rx_bytes
                                .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                            if let Some(ref p_stats) = peer_stats {
                                p_stats
                                    .rx_bytes
                                    .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        }

        let mut tun_vec = vec![0u8; 1600];

        loop {
            if active_conns.is_empty() {
                dp_snapshot = data_plane.load();
                active_conns = self.get_all_active_connections(&dp_snapshot);

                let current_keys: std::collections::HashSet<usize> =
                    active_conns.iter().map(|c| c.conn.stable_id()).collect();
                spawned_conns.retain(|key| current_keys.contains(key));

                for conn_info in &active_conns {
                    let key = conn_info.conn.stable_id();
                    if spawned_conns.insert(key) {
                        let conn = conn_info.conn.clone();
                        let tun_io = self.tun_io.clone();
                        let conn_stats = conn_info.stats.clone();
                        let peer_stats = conn_info.peer_stats.clone();
                        let rx_packets = rx_packets.clone();
                        let rx_bytes = rx_bytes.clone();
                        tokio::spawn(async move {
                            while let Ok(bytes) = conn.read_datagram().await {
                                let n = bytes.len();
                                if let Err(e) = tun_io.write_packet(&bytes).await {
                                    log::warn!("Failed to write to TUN: {}", e);
                                } else {
                                    rx_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    rx_bytes
                                        .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                                    conn_stats
                                        .rx_bytes
                                        .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                                    if let Some(ref p_stats) = peer_stats {
                                        p_stats.rx_bytes.fetch_add(
                                            n as u64,
                                            std::sync::atomic::Ordering::Relaxed,
                                        );
                                    }
                                }
                            }
                        });
                    }
                }
            }

            tokio::select! {
                read_res = self.tun_io.read(&mut tun_vec) => {
                    match read_res {
                        Ok(n) if n > 0 => {
                            local_stats.tun_rx_packets += 1;
                            local_stats.tun_rx_bytes += n as u64;

                            if let Some(dst_ip) = parse_destination_ip(&tun_vec[..n]) {

                                let active_conn = match conn_cache.get(&dst_ip) {
                                    Some(cached) => cached.as_ref(),
                                    None => {
                                        let info = self.get_active_connection(&dp_snapshot, dst_ip);
                                        conn_cache.insert(dst_ip, info);
                                        conn_cache.get(&dst_ip).unwrap().as_ref()
                                    }
                                };

                                if let Some(active_conn) = active_conn {
                                    let payload = bytes::Bytes::copy_from_slice(&tun_vec[..n]);

                                    if let Err(e) = active_conn.conn.send_datagram(payload) {
                                        log::debug!("Failed to send QUIC datagram: {}", e);
                                        conn_cache.remove(&dst_ip);
                                    } else {
                                        local_stats.l3_packets += 1;
                                        local_stats.l3_bytes += n as u64;

                                        // Update connection stats
                                        active_conn.stats.tx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);

                                        // Update peer stats
                                        if let Some(ref peer_stats) = active_conn.peer_stats {
                                            peer_stats.tx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!("TUN read error: {}", e);
                        }
                    }
                }

                _ = reload_timer.tick() => {
                    dp_snapshot = data_plane.load();
                    active_conns = self.get_all_active_connections(&dp_snapshot);
                    conn_cache.clear();

                    let current_keys: std::collections::HashSet<usize> = active_conns
                        .iter()
                        .map(|c| c.conn.stable_id())
                        .collect();
                    spawned_conns.retain(|key| current_keys.contains(key));

                    for conn_info in &active_conns {
                        let key = conn_info.conn.stable_id();
                        if spawned_conns.insert(key) {
                            let conn = conn_info.conn.clone();
                            let tun_io = self.tun_io.clone();
                            let conn_stats = conn_info.stats.clone();
                            let peer_stats = conn_info.peer_stats.clone();
                            let rx_packets = rx_packets.clone();
                            let rx_bytes = rx_bytes.clone();
                            tokio::spawn(async move {
                                while let Ok(bytes) = conn.read_datagram().await {
                                    let n = bytes.len();
                                    if let Err(e) = tun_io.write_packet(&bytes).await {
                                        log::warn!("Failed to write to TUN: {}", e);
                                    } else {
                                        rx_packets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        rx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                                        conn_stats.rx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                                        if let Some(ref p_stats) = peer_stats {
                                            p_stats.rx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                                        }
                                    }
                                }
                            });
                        }
                    }
                }

                _ = stats_timer.tick() => {
                    if let Some(ref stats) = self.worker_stats {
                        let mut publish_stats = local_stats.clone();
                        publish_stats.l3_packets += rx_packets.load(std::sync::atomic::Ordering::Relaxed);
                        publish_stats.l3_bytes += rx_bytes.load(std::sync::atomic::Ordering::Relaxed);
                        stats.publish(&publish_stats);
                    }
                }
            }
        }
    }
}

fn parse_destination_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version == 4 {
        Some(IpAddr::V4(std::net::Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )))
    } else if version == 6 {
        if packet.len() < 40 {
            return None;
        }
        let ip_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
        Some(IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_pool::{QuicConnStats, QuicPoolClient};
    use crate::routing::AllowedIPsRouter;
    use arc_swap::ArcSwap;
    use parking_lot::{Mutex, RwLock};
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::os::unix::io::IntoRawFd;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    static PORT_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(46000);

    fn unused_udp_port() -> u16 {
        loop {
            let port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
            if std::net::UdpSocket::bind(format!("127.0.0.1:{}", port)).is_ok() {
                return port;
            }
        }
    }

    #[tokio::test]
    async fn test_rtc_worker_datagram_loop() {
        let port = unused_udp_port();
        let session_cache = Arc::new(RwLock::new(HashMap::new()));
        let peer_registry = Arc::new(RwLock::new(HashMap::new()));

        let client_pub_key = [10u8; 32];
        let session_psk = [11u8; 32];
        session_cache.write().insert(client_pub_key, session_psk);

        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));
        let server = crate::quic_pool::QuicPoolServer::new(
            vec![port],
            session_cache.clone(),
            auth_nonce_cache,
        );
        let (certs, key) = crate::quic_pool::generate_self_signed_cert().unwrap();
        let cert_fingerprint = crate::quic_pool::cert_sha256(&certs).unwrap();

        let handler = Arc::new(
            move |_pub_key: [u8; 32],
                  _send: quinn::SendStream,
                  _recv: quinn::RecvStream,
                  _stat: Arc<QuicConnStats>|
                  -> crate::quic_pool::ServerFuture { Box::pin(async move {}) },
        );

        server
            .run_with_registry(certs, key, handler, peer_registry.clone())
            .await
            .unwrap();

        let server_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap();
        let client = QuicPoolClient::new(
            client_pub_key,
            session_psk,
            cert_fingerprint,
            vec![server_addr],
        );
        client.start_pool().await.unwrap();

        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
        sock1.set_nonblocking(true).unwrap();
        sock2.set_nonblocking(true).unwrap();

        let tun_io = Arc::new(AsyncTunIo::new(sock1.into_raw_fd()).unwrap());
        let pool = Arc::new(client);

        // Setup L4DataPlane snapshot
        let mut client_quic_pools = HashMap::new();
        client_quic_pools.insert(client_pub_key, pool.clone());

        let mut router = AllowedIPsRouter::new();
        router.insert("10.0.0.1/32".parse().unwrap(), client_pub_key);

        let data_plane = Arc::new(ArcSwap::new(Arc::new(crate::L4DataPlaneSnapshot {
            router,
            userspace_tcp_offload_enabled: true,
            client_quic_pools,
        })));

        // Spawn Worker
        let buffer_pool = crate::buffer_pool::BufferPool::new(1500);
        let mut worker = RtcWorker::new(
            tun_io,
            0,
            WorkerRole::Client,
            RtcWorkerConfig {
                mtu: 1400,
                buffer_pool,
            },
        );

        let data_plane_clone = data_plane.clone();
        let worker_task = tokio::spawn(async move {
            let _ = worker.run_loop(data_plane_clone).await;
        });

        // 1. Test Outbound Packet (TUN -> QUIC Datagram)
        // Build mock IPv4 TCP SYN to 10.0.0.1 with MSS=1460 (0x05B4)
        let mut test_packet = vec![0u8; 44];
        test_packet[0] = 0x45;
        test_packet[2] = 0x00;
        test_packet[3] = 44;
        test_packet[9] = 0x06; // TCP
        test_packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        test_packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        test_packet[20] = 0x30;
        test_packet[21] = 0x39; // Src Port
        test_packet[22] = 0x00;
        test_packet[23] = 0x50; // Dst Port
        test_packet[32] = 0x60; // Data offset
        test_packet[33] = 0x02; // Flags: SYN
        test_packet[40] = 2; // Kind: MSS
        test_packet[41] = 4; // Length: 4
        test_packet[42] = 0x05;
        test_packet[43] = 0xB4; // MSS Value: 1460

        let mut writer = sock2.try_clone().unwrap();
        std::io::Write::write_all(&mut writer, &test_packet).unwrap();

        // Server connection should receive the datagram
        tokio::time::sleep(Duration::from_millis(50)).await;
        let server_conn = {
            let registry = peer_registry.read();
            registry[&client_pub_key][0].conn.clone()
        };

        let received = server_conn.read_datagram().await.unwrap();
        // Assert it was received, and MSS option remained 1460 (0x05B4)
        assert_eq!(received.len(), 44);
        assert_eq!(received[42], 0x05);
        assert_eq!(received[43], 0xB4);

        // 2. Test Inbound Packet (QUIC Datagram -> TUN)
        let inbound_payload = vec![9u8; 20];
        server_conn
            .send_datagram(bytes::Bytes::copy_from_slice(&inbound_payload))
            .unwrap();

        let mut reader = tokio::net::UnixStream::from_std(sock2).unwrap();
        let mut read_buf = vec![0u8; 20];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut reader, &mut read_buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(read_buf, inbound_payload);

        // Cleanup
        worker_task.abort();
        pool.shutdown(b"test complete");
    }
}
