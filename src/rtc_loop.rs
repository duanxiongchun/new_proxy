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
    ) -> Option<(Connection, Arc<crate::quic_pool::QuicConnStats>, [u8; 32])> {
        match &self.role {
            WorkerRole::Client => {
                let peer_pub_key = data_plane.router.longest_match(dst_ip)?;
                let pool = data_plane.client_quic_pools.get(&peer_pub_key)?;
                let (conn, stats) = pool.get_connection_by_slot(self.worker_id)?;
                if conn.close_reason().is_none() {
                    Some((conn, stats, peer_pub_key))
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
                        return Some((
                            record.conn.clone(),
                            Arc::new(record.stats.clone()),
                            peer_pub_key,
                        ));
                    }
                }
                None
            }
        }
    }

    fn get_all_active_connections(
        &self,
        data_plane: &crate::L4DataPlaneSnapshot,
    ) -> Vec<(Connection, Arc<crate::quic_pool::QuicConnStats>, [u8; 32])> {
        let mut conns = Vec::new();
        match &self.role {
            WorkerRole::Client => {
                for (&pub_key, pool) in &data_plane.client_quic_pools {
                    if let Some((conn, stats)) = pool.get_connection_by_slot(self.worker_id) {
                        if conn.close_reason().is_none() {
                            conns.push((conn, stats, pub_key));
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
                                conns.push((
                                    record.conn.clone(),
                                    Arc::new(record.stats.clone()),
                                    pub_key,
                                ));
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
        let mut conn_cache: std::collections::HashMap<
            std::net::IpAddr,
            (
                quinn::Connection,
                std::sync::Arc<crate::quic_pool::QuicConnStats>,
                [u8; 32],
            ),
        > = std::collections::HashMap::new();

        let mut tun_vec = vec![0u8; 1600];

        loop {
            if active_conns.is_empty() {
                dp_snapshot = data_plane.load();
                active_conns = self.get_all_active_connections(&dp_snapshot);
            }

            tokio::select! {
                read_res = self.tun_io.read(&mut tun_vec) => {
                    match read_res {
                        Ok(n) if n > 0 => {
                            local_stats.tun_rx_packets += 1;
                            local_stats.tun_rx_bytes += n as u64;

                            let mut packet_sent = false;
                            if let Some(dst_ip) = parse_destination_ip(&tun_vec[..n]) {
                                crate::mss_clamping::clamp_tcp_mss(&mut tun_vec[..n], 1160);

                                let cached_conn = if let Some(info) = conn_cache.get(&dst_ip) {
                                    let (conn, _, _) = info;
                                    if conn.close_reason().is_none() {
                                        Some(info.clone())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                };

                                let conn_info = match cached_conn {
                                    Some(info) => Some(info),
                                    None => {
                                        if let Some((conn, stats, pub_key)) = self.get_active_connection(&dp_snapshot, dst_ip) {
                                            conn_cache.insert(dst_ip, (conn.clone(), stats.clone(), pub_key));
                                            Some((conn, stats, pub_key))
                                        } else {
                                            None
                                        }
                                    }
                                };

                                if let Some((conn, stats, pub_key)) = conn_info {
                                    tun_vec.truncate(n);
                                    let payload = bytes::Bytes::from(tun_vec);
                                    tun_vec = vec![0u8; 1600];
                                    packet_sent = true;

                                    if let Err(e) = conn.send_datagram(payload) {
                                        log::debug!("Failed to send QUIC datagram: {}", e);
                                    } else {
                                        local_stats.l3_packets += 1;
                                        local_stats.l3_bytes += n as u64;

                                        // Update connection stats
                                        let _old_tx = stats.tx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);

                                        // Update peer stats
                                        if let Some(ref peer_telemetry) = self.peer_telemetry {
                                            let peer_stats = peer_telemetry.get_or_create(pub_key);
                                            peer_stats.tx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            if !packet_sent {
                                if tun_vec.len() != 1600 {
                                    tun_vec.resize(1600, 0);
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!("TUN read error: {}", e);
                        }
                    }
                }

                read_dg = read_any_datagram(&active_conns) => {
                    if let Some((bytes, idx)) = read_dg {
                        let n = bytes.len();
                        if let Err(e) = self.tun_io.write_packet(&bytes).await {
                            log::warn!("Failed to write to TUN: {}", e);
                        } else {
                            local_stats.l3_packets += 1;
                            local_stats.l3_bytes += n as u64;

                            // Update connection stats
                            let (_, stats, pub_key) = &active_conns[idx];
                            let _old_rx = stats.rx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);

                            // Update peer stats
                            if let Some(ref peer_telemetry) = self.peer_telemetry {
                                let peer_stats = peer_telemetry.get_or_create(*pub_key);
                                peer_stats.rx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }

                _ = reload_timer.tick() => {
                    dp_snapshot = data_plane.load();
                    active_conns = self.get_all_active_connections(&dp_snapshot);
                    conn_cache.clear();
                }

                _ = stats_timer.tick() => {
                    if let Some(ref stats) = self.worker_stats {
                        stats.publish(&local_stats);
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
        let mut ip_bytes = [0u8; 4];
        ip_bytes.copy_from_slice(&packet[16..20]);
        Some(IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes)))
    } else if version == 6 {
        if packet.len() < 40 {
            return None;
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&packet[24..40]);
        Some(IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)))
    } else {
        None
    }
}

async fn read_any_datagram(
    conns: &[(Connection, Arc<crate::quic_pool::QuicConnStats>, [u8; 32])],
) -> Option<(bytes::Bytes, usize)> {
    match conns.len() {
        0 => {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            None
        }
        1 => match conns[0].0.read_datagram().await {
            Ok(bytes) => Some((bytes, 0)),
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                None
            }
        },
        2 => {
            tokio::select! {
                r0 = conns[0].0.read_datagram() => match r0 {
                    Ok(bytes) => Some((bytes, 0)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                },
                r1 = conns[1].0.read_datagram() => match r1 {
                    Ok(bytes) => Some((bytes, 1)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                }
            }
        }
        3 => {
            tokio::select! {
                r0 = conns[0].0.read_datagram() => match r0 {
                    Ok(bytes) => Some((bytes, 0)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                },
                r1 = conns[1].0.read_datagram() => match r1 {
                    Ok(bytes) => Some((bytes, 1)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                },
                r2 = conns[2].0.read_datagram() => match r2 {
                    Ok(bytes) => Some((bytes, 2)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                }
            }
        }
        4 => {
            tokio::select! {
                r0 = conns[0].0.read_datagram() => match r0 {
                    Ok(bytes) => Some((bytes, 0)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                },
                r1 = conns[1].0.read_datagram() => match r1 {
                    Ok(bytes) => Some((bytes, 1)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                },
                r2 = conns[2].0.read_datagram() => match r2 {
                    Ok(bytes) => Some((bytes, 2)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                },
                r3 = conns[3].0.read_datagram() => match r3 {
                    Ok(bytes) => Some((bytes, 3)),
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        None
                    }
                }
            }
        }
        _ => {
            let futures = conns
                .iter()
                .enumerate()
                .map(|(idx, (conn, _, _))| {
                    Box::pin(async move { (conn.read_datagram().await, idx) })
                })
                .collect::<Vec<_>>();

            let (res, _, _) = futures::future::select_all(futures).await;
            match res {
                (Ok(bytes), idx) => Some((bytes, idx)),
                (Err(_), _) => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                    None
                }
            }
        }
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

        // Setup Unix socketpair for mocking TUN
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
        // Assert it was received, and MSS option was clamped to 1160 (0x0488)
        assert_eq!(received.len(), 44);
        assert_eq!(received[42], 0x04);
        assert_eq!(received[43], 0x88);

        // 2. Test Inbound Packet (QUIC Datagram -> TUN)
        let inbound_payload = vec![9u8; 20];
        server_conn
            .send_datagram(bytes::Bytes::copy_from_slice(&inbound_payload))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut reader = sock2;
        let mut read_buf = vec![0u8; 20];
        std::io::Read::read_exact(&mut reader, &mut read_buf).unwrap();
        assert_eq!(read_buf, inbound_payload);

        // Cleanup
        worker_task.abort();
        pool.shutdown(b"test complete");
    }
}
