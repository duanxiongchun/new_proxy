use crate::tun_io::AsyncTunIo;
use std::net::IpAddr;
#[allow(unused_imports)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
#[allow(unused_imports)]
use tokio::io::Interest;
use tokio::sync::Notify;

pub struct RtcWorkerConfig {
    pub mtu: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WorkerRole {
    Client,
    Server,
}

#[allow(clippy::type_complexity)]
pub struct RtcWorker {
    pub tun_io: Arc<AsyncTunIo>,
    pub worker_id: usize,
    pub packet_buffer_size: usize,
    pub worker_stats: Option<Arc<crate::telemetry::WorkerTelemetry>>,
    pub peer_telemetry: Option<Arc<crate::telemetry::TelemetryRegistry>>,
    pub role: WorkerRole,
    pub bridge_notify: Arc<Notify>,

    pub udp_socket: tokio::net::UdpSocket,
    pub endpoint: quinn_proto::Endpoint,
    pub connections: std::collections::HashMap<
        quinn_proto::ConnectionHandle,
        crate::quic_proto_engine::WorkerConnection,
    >,
    pub pub_key_to_handle: std::collections::HashMap<[u8; 32], quinn_proto::ConnectionHandle>,
    pub session_cache:
        Option<Arc<parking_lot::RwLock<std::collections::HashMap<[u8; 32], [u8; 32]>>>>,
    pub auth_nonce_cache: Option<
        Arc<parking_lot::Mutex<std::collections::HashMap<[u8; 32], crate::control::NonceCache>>>,
    >,
    pub shared_quic_registry: Option<crate::quic_pool::PeerConnRegistry>,
    #[cfg(target_os = "linux")]
    pub udp_batch: UdpBatch,
    #[cfg(target_os = "linux")]
    pub tx_batch: UdpBatch,
    pub tx_packet_run: Vec<bytes::Bytes>,
    pub tun_rx_batch: Vec<bytes::Bytes>,
    #[cfg(target_os = "linux")]
    pub tx_packet_slices: Vec<SendSlicePtr>,
    #[cfg(target_os = "linux")]
    pub peer_transmits: std::collections::HashMap<std::net::SocketAddr, Vec<quinn_proto::Transmit>>,
    #[cfg(target_os = "linux")]
    pub active_handles: Vec<quinn_proto::ConnectionHandle>,
}

#[derive(Clone, Copy)]
pub struct SendSlicePtr(pub *const [u8]);
unsafe impl Send for SendSlicePtr {}
unsafe impl Sync for SendSlicePtr {}

unsafe impl Send for RtcWorker {}
unsafe impl Sync for RtcWorker {}

impl RtcWorker {
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn new(
        tun_io: Arc<AsyncTunIo>,
        worker_id: usize,
        role: WorkerRole,
        config: RtcWorkerConfig,
        udp_socket: tokio::net::UdpSocket,
        endpoint: quinn_proto::Endpoint,
        session_cache: Option<
            Arc<parking_lot::RwLock<std::collections::HashMap<[u8; 32], [u8; 32]>>>,
        >,
        auth_nonce_cache: Option<
            Arc<
                parking_lot::Mutex<std::collections::HashMap<[u8; 32], crate::control::NonceCache>>,
            >,
        >,
        shared_quic_registry: Option<crate::quic_pool::PeerConnRegistry>,
    ) -> Self {
        let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(config.mtu);
        Self {
            tun_io,
            worker_id,
            packet_buffer_size,
            worker_stats: None,
            peer_telemetry: None,
            role,
            bridge_notify: Arc::new(Notify::new()),
            udp_socket,
            endpoint,
            connections: std::collections::HashMap::new(),
            pub_key_to_handle: std::collections::HashMap::new(),
            session_cache,
            auth_nonce_cache,
            shared_quic_registry,
            #[cfg(target_os = "linux")]
            udp_batch: UdpBatch::new(),
            #[cfg(target_os = "linux")]
            tx_batch: UdpBatch::new(),
            tx_packet_run: Vec::with_capacity(64),
            tun_rx_batch: Vec::with_capacity(128),
            #[cfg(target_os = "linux")]
            tx_packet_slices: Vec::with_capacity(128),
            #[cfg(target_os = "linux")]
            peer_transmits: std::collections::HashMap::with_capacity(8),
            #[cfg(target_os = "linux")]
            active_handles: Vec::with_capacity(8),
        }
    }

    pub fn set_worker_stats(&mut self, stats: Arc<crate::telemetry::WorkerTelemetry>) {
        self.worker_stats = Some(stats);
    }

    pub fn set_peer_telemetry(&mut self, telemetry: Arc<crate::telemetry::TelemetryRegistry>) {
        self.peer_telemetry = Some(telemetry);
    }

    #[cfg(not(target_os = "linux"))]
    async fn send_transmit(&mut self, transmit: quinn_proto::Transmit) {
        let contents = &transmit.contents;
        let dest = transmit.destination;
        if let Some(seg_size) = transmit.segment_size {
            for chunk in contents.chunks(seg_size) {
                match self.udp_socket.try_send_to(chunk, dest) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if let Err(e) = self.udp_socket.send_to(chunk, dest).await {
                            log::warn!("Failed to send UDP transmit packet: {}", e);
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to send UDP transmit packet: {}", e);
                    }
                }
            }
        } else {
            match self.udp_socket.try_send_to(contents, dest) {
                Ok(_) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Err(e) = self.udp_socket.send_to(contents, dest).await {
                        log::warn!("Failed to send UDP transmit packet: {}", e);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to send UDP transmit packet: {}", e);
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn process_endpoint_transmits(&mut self) {
        let now = std::time::Instant::now();
        // 1. Poll endpoint-level transmits
        while let Some(transmit) = self.endpoint.poll_transmit() {
            self.send_transmit(transmit).await;
        }
        // 2. Poll connection-level transmits from all active connections
        let mut transmits = Vec::new();
        for conn in self.connections.values_mut() {
            while let Some(transmit) = conn.connection.poll_transmit(now, 1024) {
                transmits.push(transmit);
            }
        }
        for transmit in transmits {
            self.send_transmit(transmit).await;
        }
    }

    async fn drive_connection(
        &mut self,
        handle: quinn_proto::ConnectionHandle,
        dp_snapshot: &crate::L4DataPlaneSnapshot,
        _now: std::time::Instant,
        local_stats: &mut crate::telemetry::WorkerTelemetrySnapshot,
    ) {
        let mut connection_lost = false;
        let mut datagrams = Vec::new();
        let mut events = Vec::new();

        if let Some(conn) = self.connections.get_mut(&handle) {
            while let Some(event) = conn.connection.poll() {
                match event {
                    quinn_proto::Event::DatagramReceived => {
                        while let Some(bytes) = conn.connection.datagrams().recv() {
                            datagrams.push(bytes);
                        }
                    }
                    other => {
                        events.push(other);
                    }
                }
            }
        }

        for bytes in datagrams {
            self.handle_inbound_datagram(handle, bytes, dp_snapshot, local_stats)
                .await;
        }

        for event in events {
            match event {
                quinn_proto::Event::Connected => {
                    log::info!("Connection {:?} connected", handle);
                    if self.role == WorkerRole::Client {
                        self.send_client_auth(handle, dp_snapshot).await;
                    }
                }
                quinn_proto::Event::ConnectionLost { reason } => {
                    log::warn!("Connection {:?} lost: {:?}", handle, reason);
                    connection_lost = true;
                }
                _ => {}
            }
        }

        if connection_lost {
            if let Some(conn) = self.connections.remove(&handle) {
                if let Some(pub_key) = conn.peer_public_key {
                    self.pub_key_to_handle.remove(&pub_key);
                }
            }
            return;
        }

        if let Some(conn) = self.connections.get_mut(&handle) {
            while let Some(endpoint_event) = conn.connection.poll_endpoint_events() {
                if let Some(conn_event) = self.endpoint.handle_event(handle, endpoint_event) {
                    conn.connection.handle_event(conn_event);
                }
            }
        }
    }

    async fn send_client_auth(
        &mut self,
        handle: quinn_proto::ConnectionHandle,
        dp_snapshot: &crate::L4DataPlaneSnapshot,
    ) {
        let mut found_info = None;
        if let Some(conn) = self.connections.get(&handle) {
            let server_ip = conn.connection.remote_address().ip();
            for pool in dp_snapshot.client_quic_pools.values() {
                if pool.endpoints().iter().any(|addr| addr.ip() == server_ip) {
                    found_info = Some((pool.client_public_key(), pool.session_psk()));
                    break;
                }
            }
        }

        if let Some((client_pub_key, session_psk)) = found_info {
            let nonce = rand::random::<[u8; 16]>();
            let auth_payload = crate::quic_proto_engine::generate_auth_payload(
                [0u8; 32],
                client_pub_key,
                session_psk,
                nonce,
            );
            if let Some(conn) = self.connections.get_mut(&handle) {
                if let Err(e) = conn
                    .connection
                    .datagrams()
                    .send(bytes::Bytes::from(auth_payload))
                {
                    log::warn!("Failed to send client auth datagram: {:?}", e);
                }
            }
        }
    }

    async fn handle_inbound_datagram(
        &mut self,
        handle: quinn_proto::ConnectionHandle,
        bytes: bytes::Bytes,
        dp_snapshot: &crate::L4DataPlaneSnapshot,
        local_stats: &mut crate::telemetry::WorkerTelemetrySnapshot,
    ) {
        if bytes.is_empty() {
            return;
        }
        let header = bytes[0];
        match header {
            0x01 => {
                if self.role == WorkerRole::Server {
                    let signed_packet = match serde_json::from_slice::<
                        crate::quic_proto_engine::SignedPacket,
                    >(&bytes[1..])
                    {
                        Ok(sp) => sp,
                        Err(e) => {
                            log::warn!("Failed to parse SignedPacket: {:?}", e);
                            self.abort_connection(handle, b"Invalid SignedPacket format")
                                .await;
                            return;
                        }
                    };
                    if signed_packet.payload.len() != 48 {
                        log::warn!("Invalid SignedPacket payload len");
                        self.abort_connection(handle, b"Invalid payload length")
                            .await;
                        return;
                    }
                    let nonce: [u8; 16] = signed_packet.payload[0..16].try_into().unwrap();
                    let client_pub_key: [u8; 32] =
                        signed_packet.payload[16..48].try_into().unwrap();

                    let session_psk = if let Some(ref cache) = self.session_cache {
                        cache.read().get(&client_pub_key).copied()
                    } else {
                        None
                    };
                    let session_psk = match session_psk {
                        Some(psk) => psk,
                        None => {
                            log::warn!("No session PSK found for client key");
                            self.abort_connection(handle, b"No session PSK found").await;
                            return;
                        }
                    };

                    let nonce_valid = if let Some(ref cache) = self.auth_nonce_cache {
                        let mut cache_guard = cache.lock();
                        let nonce_cache = cache_guard
                            .entry(client_pub_key)
                            .or_insert_with(|| crate::control::NonceCache::new(4096));
                        nonce_cache.insert(nonce)
                    } else {
                        false
                    };
                    if !nonce_valid {
                        log::warn!("Replayed or invalid auth nonce");
                        self.abort_connection(handle, b"Replay protection triggered")
                            .await;
                        return;
                    }

                    if !crate::quic_proto_engine::verify_auth_payload(&bytes, &session_psk, &nonce)
                    {
                        log::warn!("verify_auth_payload signature verification failed");
                        self.abort_connection(handle, b"Signature verification failed")
                            .await;
                        return;
                    }

                    if let Some(conn) = self.connections.get_mut(&handle) {
                        conn.authenticated = true;
                        conn.peer_public_key = Some(client_pub_key);
                    }

                    self.pub_key_to_handle.insert(client_pub_key, handle);

                    let ok_payload = vec![0x01, b'O', b'K'];
                    if let Some(conn) = self.connections.get_mut(&handle) {
                        let _ = conn
                            .connection
                            .datagrams()
                            .send(bytes::Bytes::from(ok_payload));
                    }
                } else {
                    if &bytes[1..] == b"OK" {
                        if let Some(conn) = self.connections.get_mut(&handle) {
                            conn.authenticated = true;
                        }

                        let mut found_pub_key = None;
                        if let Some(conn) = self.connections.get(&handle) {
                            let server_ip = conn.connection.remote_address().ip();
                            for (pub_key, pool) in &dp_snapshot.client_quic_pools {
                                if pool.endpoints().iter().any(|addr| addr.ip() == server_ip) {
                                    found_pub_key = Some(*pub_key);
                                    break;
                                }
                            }
                        }
                        if let Some(pub_key) = found_pub_key {
                            if let Some(conn) = self.connections.get_mut(&handle) {
                                conn.peer_public_key = Some(pub_key);
                            }
                            self.pub_key_to_handle.insert(pub_key, handle);
                        }
                    }
                }
            }
            0x02 => {
                let authenticated = self
                    .connections
                    .get(&handle)
                    .map(|c| c.authenticated)
                    .unwrap_or(false);
                if authenticated {
                    let mut write_res = self.tun_io.try_write_packet(&bytes[1..]);
                    if let Err(ref e) = write_res {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            write_res = self.tun_io.write_packet(&bytes[1..]).await;
                        }
                    }
                    if let Err(e) = write_res {
                        log::warn!("Failed to write data packet to TUN: {:?}", e);
                    } else if let Some(conn) = self.connections.get(&handle) {
                        let payload_len = (bytes.len() - 1) as u64;
                        conn.rx_bytes.add(payload_len);
                        local_stats.l3_packets += 1;
                        local_stats.l3_bytes += payload_len;

                        if let Some(ref peer_telemetry) = self.peer_telemetry {
                            if let Some(pub_key) = conn.peer_public_key {
                                let peer_stats = peer_telemetry.get_or_create(pub_key);
                                peer_stats.rx_bytes.add(payload_len);
                            }
                        }
                    }
                } else {
                    log::debug!("Discarding data packet from unauthenticated connection");
                }
            }
            _ => {
                log::debug!("Unknown datagram header: {}", header);
            }
        }
    }

    async fn abort_connection(&mut self, handle: quinn_proto::ConnectionHandle, reason: &[u8]) {
        if let Some(mut conn) = self.connections.remove(&handle) {
            if let Some(pub_key) = conn.peer_public_key {
                self.pub_key_to_handle.remove(&pub_key);
            }
            let now = std::time::Instant::now();
            let error_code = quinn_proto::VarInt::from(0u32);
            let reason_bytes = bytes::Bytes::copy_from_slice(reason);
            conn.connection.close(now, error_code, reason_bytes);
            while let Some(endpoint_event) = conn.connection.poll_endpoint_events() {
                let _ = self.endpoint.handle_event(handle, endpoint_event);
            }
        }
        self.process_endpoint_transmits().await;
    }

    fn find_handle_for_ip(
        &self,
        dst_ip: std::net::IpAddr,
        dp_snapshot: &crate::L4DataPlaneSnapshot,
    ) -> Option<quinn_proto::ConnectionHandle> {
        if let Some(pub_key) = dp_snapshot.router.longest_match(dst_ip) {
            if let Some(&handle) = self.pub_key_to_handle.get(&pub_key) {
                return Some(handle);
            }
        }
        None
    }

    async fn send_batch_to_connection(
        &mut self,
        handle: quinn_proto::ConnectionHandle,
        packets: &[bytes::Bytes],
        local_stats: &mut crate::telemetry::WorkerTelemetrySnapshot,
        now: std::time::Instant,
        dp_snapshot: &crate::L4DataPlaneSnapshot,
    ) {
        if packets.is_empty() {
            return;
        }
        let mut sent = false;
        if let Some(conn) = self.connections.get_mut(&handle) {
            if conn.authenticated {
                for packet in packets {
                    let packet_len = (packet.len() - 1) as u64;
                    if let Err(e) = conn.connection.datagrams().send(packet.clone()) {
                        log::warn!("Failed to send datagram: {:?}", e);
                    } else {
                        conn.tx_bytes.add(packet_len);
                        local_stats.l3_packets += 1;
                        local_stats.l3_bytes += packet_len;

                        if let Some(ref peer_telemetry) = self.peer_telemetry {
                            if let Some(pub_key) = conn.peer_public_key {
                                let peer_stats = peer_telemetry.get_or_create(pub_key);
                                peer_stats.tx_bytes.add(packet_len);
                            }
                        }
                        sent = true;
                    }
                }
            }
        }
        if sent {
            self.drive_connection(handle, dp_snapshot, now, local_stats)
                .await;
        }
    }

    #[allow(dead_code)]
    async fn handle_tun_packet(
        &mut self,
        packet: bytes::Bytes,
        dp_snapshot: &crate::L4DataPlaneSnapshot,
        now: std::time::Instant,
        local_stats: &mut crate::telemetry::WorkerTelemetrySnapshot,
    ) {
        if let Some(dst_ip) = parse_destination_ip(&packet[1..]) {
            if let Some(handle) = self.find_handle_for_ip(dst_ip, dp_snapshot) {
                let mut sent = false;
                if let Some(conn) = self.connections.get_mut(&handle) {
                    if conn.authenticated {
                        if let Err(e) = conn.connection.datagrams().send(packet.clone()) {
                            log::debug!("Failed to send datagram: {:?}", e);
                        } else {
                            let packet_len = (packet.len() - 1) as u64;
                            conn.tx_bytes.add(packet_len);
                            local_stats.l3_packets += 1;
                            local_stats.l3_bytes += packet_len;

                            if let Some(ref peer_telemetry) = self.peer_telemetry {
                                if let Some(pub_key) = conn.peer_public_key {
                                    let peer_stats = peer_telemetry.get_or_create(pub_key);
                                    peer_stats.tx_bytes.add(packet_len);
                                }
                            }
                            sent = true;
                        }
                    }
                }
                if sent {
                    self.drive_connection(handle, dp_snapshot, now, local_stats)
                        .await;
                }
            }
        }
    }

    async fn check_and_connect_clients(&mut self, dp_snapshot: &crate::L4DataPlaneSnapshot) {
        for (&pub_key, pool) in &dp_snapshot.client_quic_pools {
            let endpoints = pool.endpoints();
            if endpoints.is_empty() {
                continue;
            }
            let server_addr = match endpoints.get(self.worker_id) {
                Some(&addr) => addr,
                None => {
                    log::warn!(
                        "Worker {} has no corresponding endpoint in pool (total endpoints {})",
                        self.worker_id,
                        endpoints.len()
                    );
                    continue;
                }
            };
            let already_connected = self
                .connections
                .values()
                .any(|conn| conn.connection.remote_address() == server_addr);
            if !already_connected {
                let client_config =
                    build_client_proto_config(pool.server_cert_sha256(), self.packet_buffer_size);
                match self
                    .endpoint
                    .connect(client_config, server_addr, "localhost")
                {
                    Ok((handle, conn)) => {
                        let worker_conn = crate::quic_proto_engine::WorkerConnection {
                            connection: conn,
                            authenticated: false,
                            tx_bytes: Arc::new(crate::telemetry::CellU64::new(0)),
                            rx_bytes: Arc::new(crate::telemetry::CellU64::new(0)),
                            peer_public_key: Some(pub_key),
                        };
                        self.connections.insert(handle, worker_conn);
                    }
                    Err(e) => {
                        log::error!("Failed to connect to {}: {:?}", server_addr, e);
                    }
                }
            }
        }
    }

    pub async fn run_loop(&mut self, data_plane: crate::L4DataPlane) -> Result<(), String> {
        let mut stats_timer = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut reload_timer = tokio::time::interval(std::time::Duration::from_secs(1));

        let mut local_stats = crate::telemetry::WorkerTelemetrySnapshot {
            worker_id: self.worker_id,
            ..crate::telemetry::WorkerTelemetrySnapshot::default()
        };

        let mut dp_snapshot = data_plane.load();

        if self.role == WorkerRole::Client {
            self.check_and_connect_clients(&dp_snapshot).await;
            self.process_endpoint_transmits().await;
        }

        let mut tun_buf = bytes::BytesMut::with_capacity(256 * 1024);
        #[cfg(target_os = "linux")]
        let recv_packet_size = 1600;
        #[cfg(target_os = "linux")]
        let mut udp_recv_buf = bytes::BytesMut::with_capacity(UDP_BATCH_SIZE * recv_packet_size);
        #[cfg(not(target_os = "linux"))]
        let mut udp_buf = bytes::BytesMut::with_capacity(256 * 1024);

        let sleep = tokio::time::sleep(std::time::Duration::from_secs(3600));
        tokio::pin!(sleep);

        let mut consecutive_polls = 0;

        loop {
            // Reset and prepare tun_buf
            tun_buf.truncate(0);
            if tun_buf.capacity() < 65536 {
                tun_buf.reserve(256 * 1024);
            }
            // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
            // for read/recv_from. The uninitialized bytes are never read before they are
            // overwritten by the OS kernel during the IO system call.
            unsafe {
                let cap = tun_buf.capacity();
                tun_buf.set_len(cap);
            }

            #[cfg(not(target_os = "linux"))]
            {
                // Reset and prepare udp_buf
                udp_buf.truncate(0);
                if udp_buf.capacity() < 65536 {
                    udp_buf.reserve(256 * 1024);
                }
                // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                // for read/recv_from. The uninitialized bytes are never read before they are
                // overwritten by the OS kernel during the IO system call.
                unsafe {
                    let cap = udp_buf.capacity();
                    udp_buf.set_len(cap);
                }
            }

            let mut processed = false;
            if consecutive_polls < 1024 {
                let now = std::time::Instant::now();
                #[cfg(target_os = "linux")]
                {
                    // A. Try reading from TUN non-blockingly
                    let tun_res = self.tun_io.try_read(&mut tun_buf[1..65536]);

                    match tun_res {
                        Ok(Some(n)) if n > 0 => {
                            processed = true;
                            local_stats.tun_rx_packets += 1;
                            local_stats.tun_rx_bytes += n as u64;
                            tun_buf[0] = 0x02;
                            unsafe {
                                tun_buf.set_len(1 + n);
                            }
                            let first_frame = tun_buf.split_to(1 + n).freeze();
                            self.tun_rx_batch.clear();
                            self.tun_rx_batch.push(first_frame);

                            for _ in 0..127 {
                                if tun_buf.capacity() < 65536 {
                                    tun_buf.reserve(256 * 1024);
                                }
                                unsafe {
                                    let cap = tun_buf.capacity();
                                    tun_buf.set_len(cap);
                                }
                                match self.tun_io.try_read(&mut tun_buf[1..65536]) {
                                    Ok(Some(n_next)) if n_next > 0 => {
                                        local_stats.tun_rx_packets += 1;
                                        local_stats.tun_rx_bytes += n_next as u64;
                                        tun_buf[0] = 0x02;
                                        unsafe {
                                            tun_buf.set_len(1 + n_next);
                                        }
                                        let frame = tun_buf.split_to(1 + n_next).freeze();
                                        self.tun_rx_batch.push(frame);
                                    }
                                    _ => {
                                        break;
                                    }
                                }
                            }
                            tun_buf.truncate(0);

                            let mut batch = std::mem::take(&mut self.tun_rx_batch);

                            self.tx_packet_run.clear();
                            let mut current_handle: Option<quinn_proto::ConnectionHandle> = None;

                            for packet in &batch {
                                if let Some(dst_ip) = parse_destination_ip(&packet[1..]) {
                                    if let Some(handle) =
                                        self.find_handle_for_ip(dst_ip, &dp_snapshot)
                                    {
                                        if let Some(curr) = current_handle {
                                            if curr == handle {
                                                self.tx_packet_run.push(packet.clone());
                                            } else {
                                                let mut packets =
                                                    std::mem::take(&mut self.tx_packet_run);
                                                self.send_batch_to_connection(
                                                    curr,
                                                    &packets,
                                                    &mut local_stats,
                                                    now,
                                                    &dp_snapshot,
                                                )
                                                .await;
                                                packets.clear();
                                                self.tx_packet_run = packets;
                                                current_handle = Some(handle);
                                                self.tx_packet_run.push(packet.clone());
                                            }
                                        } else {
                                            current_handle = Some(handle);
                                            self.tx_packet_run.push(packet.clone());
                                        }
                                    }
                                }
                            }
                            if let Some(curr) = current_handle {
                                let mut packets = std::mem::take(&mut self.tx_packet_run);
                                self.send_batch_to_connection(
                                    curr,
                                    &packets,
                                    &mut local_stats,
                                    now,
                                    &dp_snapshot,
                                )
                                .await;
                                packets.clear();
                                self.tx_packet_run = packets;
                            }
                            self.tx_packet_run.clear();

                            batch.clear();
                            self.tun_rx_batch = batch;
                        }
                        _ => {}
                    }

                    // B. Try reading from UDP non-blockingly
                    let fd = self.udp_socket.as_raw_fd();
                    let udp_batch = &mut self.udp_batch;

                    let res = self.udp_socket.try_io(Interest::READABLE, || {
                        let mut batch_buf = std::mem::take(&mut udp_recv_buf);
                        batch_buf.truncate(0);
                        if batch_buf.capacity() < UDP_BATCH_SIZE * recv_packet_size {
                            batch_buf.reserve(UDP_BATCH_SIZE * recv_packet_size);
                        }
                        unsafe {
                            batch_buf.set_len(UDP_BATCH_SIZE * recv_packet_size);
                        }
                        for i in 0..UDP_BATCH_SIZE {
                            udp_batch.iovs[i].iov_base = unsafe {
                                batch_buf.as_mut_ptr().add(i * recv_packet_size)
                                    as *mut libc::c_void
                            };
                            udp_batch.iovs[i].iov_len = recv_packet_size as libc::size_t;

                            udp_batch.mmsgs[i].msg_hdr.msg_name = &mut udp_batch.addrs[i]
                                as *mut libc::sockaddr_storage
                                as *mut libc::c_void;
                            udp_batch.mmsgs[i].msg_hdr.msg_namelen =
                                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                            udp_batch.mmsgs[i].msg_hdr.msg_iov =
                                &mut udp_batch.iovs[i] as *mut libc::iovec;
                            udp_batch.mmsgs[i].msg_hdr.msg_iovlen = 1;
                            udp_batch.mmsgs[i].msg_hdr.msg_control = std::ptr::null_mut();
                            udp_batch.mmsgs[i].msg_hdr.msg_controllen = 0;
                            udp_batch.mmsgs[i].msg_hdr.msg_flags = 0;
                            udp_batch.mmsgs[i].msg_len = 0;
                        }

                        let count = unsafe {
                            libc::recvmmsg(
                                fd,
                                udp_batch.mmsgs.as_mut_ptr(),
                                UDP_BATCH_SIZE as libc::c_uint,
                                libc::MSG_DONTWAIT,
                                std::ptr::null_mut(),
                            )
                        };

                        if count < 0 {
                            let err = std::io::Error::last_os_error();
                            udp_recv_buf = batch_buf;
                            return Err(err);
                        }
                        Ok((count as usize, batch_buf))
                    });

                    match res {
                        Ok((count, batch_buf)) if count > 0 => {
                            processed = true;
                            let mut remaining = batch_buf;
                            self.active_handles.clear();
                            for i in 0..count {
                                let len = self.udp_batch.mmsgs[i].msg_len as usize;
                                let mut packet_chunk = remaining.split_to(recv_packet_size);
                                if len > 0 {
                                    packet_chunk.truncate(len);
                                    let namelen = self.udp_batch.mmsgs[i].msg_hdr.msg_namelen;
                                    if let Some(remote_addr) =
                                        sockaddr_to_socket_addr(&self.udp_batch.addrs[i], namelen)
                                    {
                                        let handle_res = self.endpoint.handle(
                                            now,
                                            remote_addr,
                                            None,
                                            None,
                                            packet_chunk,
                                        );
                                        if let Some((handle, datagram_event)) = handle_res {
                                            match datagram_event {
                                                quinn_proto::DatagramEvent::NewConnection(conn) => {
                                                    let worker_conn = crate::quic_proto_engine::WorkerConnection {
                                                        connection: conn,
                                                        authenticated: false,
                                                        tx_bytes: Arc::new(crate::telemetry::CellU64::new(0)),
                                                        rx_bytes: Arc::new(crate::telemetry::CellU64::new(0)),
                                                        peer_public_key: None,
                                                    };
                                                    self.connections.insert(handle, worker_conn);
                                                }
                                                quinn_proto::DatagramEvent::ConnectionEvent(
                                                    conn_event,
                                                ) => {
                                                    if let Some(conn) =
                                                        self.connections.get_mut(&handle)
                                                    {
                                                        conn.connection.handle_event(conn_event);
                                                    }
                                                }
                                            }
                                            if !self.active_handles.contains(&handle) {
                                                self.active_handles.push(handle);
                                            }
                                        }
                                    } else {
                                        log::warn!(
                                            "sockaddr_to_socket_addr failed: namelen={}",
                                            namelen
                                        );
                                    }
                                }
                            }
                            for handle in std::mem::take(&mut self.active_handles) {
                                self.drive_connection(handle, &dp_snapshot, now, &mut local_stats)
                                    .await;
                            }
                            udp_recv_buf = remaining;
                        }
                        Ok((_, batch_buf)) => {
                            udp_recv_buf = batch_buf;
                        }
                        _ => {}
                    }
                    if processed {
                        self.process_endpoint_transmits().await;
                    }
                }

                #[cfg(not(target_os = "linux"))]
                {
                    // A. Try reading from TUN non-blockingly
                    match self.tun_io.try_read(&mut tun_buf[1..65536]) {
                        Ok(Some(n)) if n > 0 => {
                            processed = true;
                            local_stats.tun_rx_packets += 1;
                            local_stats.tun_rx_bytes += n as u64;
                            tun_buf[0] = 0x02;
                            unsafe {
                                tun_buf.set_len(1 + n);
                            }
                            let frame = tun_buf.split_to(1 + n).freeze();
                            self.handle_tun_packet(frame, &dp_snapshot, now, &mut local_stats)
                                .await;

                            for _ in 0..63 {
                                if tun_buf.capacity() < 65536 {
                                    tun_buf.reserve(256 * 1024);
                                }
                                unsafe {
                                    let cap = tun_buf.capacity();
                                    tun_buf.set_len(cap);
                                }
                                match self.tun_io.try_read(&mut tun_buf[1..65536]) {
                                    Ok(Some(n_next)) if n_next > 0 => {
                                        local_stats.tun_rx_packets += 1;
                                        local_stats.tun_rx_bytes += n_next as u64;
                                        tun_buf[0] = 0x02;
                                        unsafe {
                                            tun_buf.set_len(1 + n_next);
                                        }
                                        let frame = tun_buf.split_to(1 + n_next).freeze();
                                        self.handle_tun_packet(
                                            frame,
                                            &dp_snapshot,
                                            now,
                                            &mut local_stats,
                                        )
                                        .await;
                                    }
                                    _ => {
                                        break;
                                    }
                                }
                            }
                            tun_buf.truncate(0);
                            self.process_endpoint_transmits().await;
                        }
                        _ => {}
                    }

                    // B. Try reading from UDP non-blockingly
                    match self.udp_socket.try_recv_from(&mut udp_buf) {
                        Ok((n, remote_addr)) if n > 0 => {
                            processed = true;
                            unsafe {
                                udp_buf.set_len(n);
                            }
                            let data = udp_buf.split_to(n);
                            self.handle_udp_packet(
                                data,
                                remote_addr,
                                &dp_snapshot,
                                now,
                                &mut local_stats,
                            )
                            .await;

                            for _ in 0..63 {
                                if udp_buf.capacity() < 65536 {
                                    udp_buf.reserve(256 * 1024);
                                }
                                unsafe {
                                    let cap = udp_buf.capacity();
                                    udp_buf.set_len(cap);
                                }
                                match self.udp_socket.try_recv_from(&mut udp_buf) {
                                    Ok((n_next, remote_addr)) if n_next > 0 => {
                                        unsafe {
                                            udp_buf.set_len(n_next);
                                        }
                                        let data = udp_buf.split_to(n_next);
                                        self.handle_udp_packet(
                                            data,
                                            remote_addr,
                                            &dp_snapshot,
                                            now,
                                            &mut local_stats,
                                        )
                                        .await;
                                    }
                                    _ => {
                                        udp_buf.truncate(0);
                                        break;
                                    }
                                }
                            }
                            self.process_endpoint_transmits().await;
                        }
                        _ => {
                            udp_buf.truncate(0);
                        }
                    }
                }
            }

            if processed {
                consecutive_polls += 1;
                continue;
            } else {
                consecutive_polls = 0;
            }

            let mut next_timeout = None;
            for conn in self.connections.values_mut() {
                if let Some(timeout) = conn.connection.poll_timeout() {
                    next_timeout =
                        Some(next_timeout.map_or(timeout, |t| std::cmp::min(t, timeout)));
                }
            }

            if let Some(timeout) = next_timeout {
                sleep
                    .as_mut()
                    .reset(tokio::time::Instant::from_std(timeout));
            } else {
                sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + std::time::Duration::from_secs(3600));
            }

            macro_rules! run_select {
                ($binding:pat = $fut:expr => $body:block) => {
                    tokio::select! {
                        _ = &mut sleep => {
                            let now = std::time::Instant::now();
                            for conn in self.connections.values_mut() {
                                conn.connection.handle_timeout(now);
                            }
                            let handles: Vec<_> = self.connections.keys().copied().collect();
                            for handle in handles {
                                self.drive_connection(handle, &dp_snapshot, now, &mut local_stats).await;
                            }
                            self.process_endpoint_transmits().await;
                        }

                        read_res = self.tun_io.read(&mut tun_buf[1..65536]) => {
                            match read_res {
                                Ok(0) => {
                                    tun_buf.truncate(0);
                                    return Err("TUN interface EOF".to_string());
                                }
                                Ok(n) => {
                                    #[cfg(target_os = "linux")]
                                    {
                                        let now = std::time::Instant::now();
                                        self.tun_rx_batch.clear();

                                        local_stats.tun_rx_packets += 1;
                                        local_stats.tun_rx_bytes += n as u64;
                                        tun_buf[0] = 0x02;
                                        // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                        // for read/recv_from. The uninitialized bytes are never read before they are
                                        // overwritten by the OS kernel during the IO system call.
                                        unsafe {
                                            tun_buf.set_len(1 + n);
                                        }
                                        let first_frame = tun_buf.split_to(1 + n).freeze();
                                        self.tun_rx_batch.push(first_frame);

                                        for _ in 0..127 {
                                            if tun_buf.capacity() < 65536 {
                                                tun_buf.reserve(256 * 1024);
                                            }
                                            // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                            // for read/recv_from. The uninitialized bytes are never read before they are
                                            // overwritten by the OS kernel during the IO system call.
                                            unsafe {
                                                let cap = tun_buf.capacity();
                                                tun_buf.set_len(cap);
                                            }
                                            match self.tun_io.try_read(&mut tun_buf[1..65536]) {
                                                Ok(Some(n_next)) if n_next > 0 => {
                                                    local_stats.tun_rx_packets += 1;
                                                    local_stats.tun_rx_bytes += n_next as u64;
                                                    tun_buf[0] = 0x02;
                                                    // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                                    // for read/recv_from. The uninitialized bytes are never read before they are
                                                    // overwritten by the OS kernel during the IO system call.
                                                    unsafe {
                                                        tun_buf.set_len(1 + n_next);
                                                    }
                                                    let frame = tun_buf.split_to(1 + n_next).freeze();
                                                    self.tun_rx_batch.push(frame);
                                                }
                                                _ => {
                                                    break;
                                                }
                                            }
                                        }
                                        tun_buf.truncate(0);

                                        let mut batch = std::mem::take(&mut self.tun_rx_batch);

                                         self.tx_packet_run.clear();
                                         let mut current_handle: Option<quinn_proto::ConnectionHandle> = None;

                                         for packet in &batch {
                                             if let Some(dst_ip) = parse_destination_ip(&packet[1..]) {
                                                 if let Some(handle) = self.find_handle_for_ip(dst_ip, &dp_snapshot) {
                                                     if let Some(curr) = current_handle {
                                                         if curr == handle {
                                                             self.tx_packet_run.push(packet.clone());
                                                         } else {
                                                             let mut packets = std::mem::take(&mut self.tx_packet_run);
                                                             self.send_batch_to_connection(curr, &packets, &mut local_stats, now, &dp_snapshot).await;
                                                             packets.clear();
                                                             self.tx_packet_run = packets;
                                                             current_handle = Some(handle);
                                                             self.tx_packet_run.push(packet.clone());
                                                         }
                                                     } else {
                                                         current_handle = Some(handle);
                                                         self.tx_packet_run.push(packet.clone());
                                                     }
                                                 }
                                             }
                                         }
                                         if let Some(curr) = current_handle {
                                             let mut packets = std::mem::take(&mut self.tx_packet_run);
                                             self.send_batch_to_connection(curr, &packets, &mut local_stats, now, &dp_snapshot).await;
                                             packets.clear();
                                             self.tx_packet_run = packets;
                                         }
                                         self.tx_packet_run.clear();

                                         batch.clear();
                                         self.tun_rx_batch = batch;

                                        self.process_endpoint_transmits().await;
                                    }

                                    #[cfg(not(target_os = "linux"))]
                                    {
                                        let now = std::time::Instant::now();
                                        local_stats.tun_rx_packets += 1;
                                        local_stats.tun_rx_bytes += n as u64;
                                        tun_buf[0] = 0x02;
                                        // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                        // for read/recv_from. The uninitialized bytes are never read before they are
                                        // overwritten by the OS kernel during the IO system call.
                                        unsafe {
                                            tun_buf.set_len(1 + n);
                                        }
                                        let frame = tun_buf.split_to(1 + n).freeze();
                                        self.handle_tun_packet(frame, &dp_snapshot, now, &mut local_stats).await;

                                        for _ in 0..63 {
                                            if tun_buf.capacity() < 65536 {
                                                tun_buf.reserve(256 * 1024);
                                            }
                                            // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                            // for read/recv_from. The uninitialized bytes are never read before they are
                                            // overwritten by the OS kernel during the IO system call.
                                            unsafe {
                                                let cap = tun_buf.capacity();
                                                tun_buf.set_len(cap);
                                            }
                                            match self.tun_io.try_read(&mut tun_buf[1..65536]) {
                                                Ok(Some(n)) if n > 0 => {
                                                    local_stats.tun_rx_packets += 1;
                                                    local_stats.tun_rx_bytes += n as u64;
                                                    tun_buf[0] = 0x02;
                                                    // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                                    // for read/recv_from. The uninitialized bytes are never read before they are
                                                    // overwritten by the OS kernel during the IO system call.
                                                    unsafe {
                                                        tun_buf.set_len(1 + n);
                                                    }
                                                    let frame = tun_buf.split_to(1 + n).freeze();
                                                    self.handle_tun_packet(frame, &dp_snapshot, now, &mut local_stats).await;
                                                }
                                                _ => {
                                                    break;
                                                }
                                            }
                                        }
                                        tun_buf.truncate(0);
                                        self.process_endpoint_transmits().await;
                                    }
                                }
                                Err(e) => {
                                    tun_buf.truncate(0);
                                    log::warn!("TUN read error: {:?}", e);
                                }
                            }
                        }

                        $binding = $fut => $body

                        _ = reload_timer.tick() => {
                            dp_snapshot = data_plane.load();
                            if self.role == WorkerRole::Client {
                                self.check_and_connect_clients(&dp_snapshot).await;
                                self.process_endpoint_transmits().await;
                                let handles_to_abort: Vec<quinn_proto::ConnectionHandle> = self.connections.iter()
                                    .filter(|(_, conn)| {
                                        if let Some(pub_key) = conn.peer_public_key {
                                            !dp_snapshot.client_quic_pools.contains_key(&pub_key)
                                        } else {
                                            false
                                        }
                                    })
                                    .map(|(handle, _)| *handle)
                                    .collect();
                                for handle in handles_to_abort {
                                    log::warn!("Closing client connection for removed peer");
                                    self.abort_connection(handle, b"Peer removed").await;
                                }
                            }
                            if self.role == WorkerRole::Server {
                                let handles_to_abort = if let Some(ref session_cache) = self.session_cache {
                                    let cache_guard = session_cache.read();
                                    self.connections.iter()
                                        .filter(|(_, conn)| {
                                            if let Some(pub_key) = conn.peer_public_key {
                                                !cache_guard.contains_key(&pub_key)
                                            } else {
                                                false
                                            }
                                        })
                                        .map(|(handle, _)| *handle)
                                        .collect::<Vec<_>>()
                                } else {
                                    Vec::new()
                                };
                                for handle in handles_to_abort {
                                    log::warn!("Closing connection for removed or rotated peer");
                                    self.abort_connection(handle, b"Peer removed or session rotated").await;
                                }
                            }
                        }

                        _ = stats_timer.tick() => {
                            if let Some(ref stats) = self.worker_stats {
                                let mut publish_stats = local_stats.clone();
                                let mut total_tx = 0;
                                let mut total_rx = 0;
                                for conn in self.connections.values() {
                                    total_tx += conn.tx_bytes.load();
                                    total_rx += conn.rx_bytes.load();
                                }
                                publish_stats.l3_bytes = total_tx + total_rx;
                                stats.publish(&publish_stats);
                            }
                            if let Some(ref registry) = self.shared_quic_registry {
                                let mut reg_guard = registry.write();
                                let local_port = self.udp_socket.local_addr().ok().map(|a| a.port()).unwrap_or(0);
                                for conns in reg_guard.values_mut() {
                                    conns.retain(|snap| snap.local_port != local_port);
                                }
                                for conn in self.connections.values() {
                                    if conn.authenticated {
                                        if let Some(pub_key) = conn.peer_public_key {
                                            let remote_address = conn.connection.remote_address().to_string();
                                            let active_streams = 0;
                                            let snap = crate::quic_pool::QuicConnSnapshot {
                                                remote_addr: remote_address,
                                                local_port,
                                                rx_bytes: conn.rx_bytes.load(),
                                                tx_bytes: conn.tx_bytes.load(),
                                                active_streams,
                                            };
                                            reg_guard.entry(pub_key).or_default().push(snap);
                                        }
                                    }
                                }
                            }
                        }
                    }
                };
            }

            #[cfg(target_os = "linux")]
            run_select! {
                _ = self.udp_socket.readable() => {
                    let fd = self.udp_socket.as_raw_fd();
                    let udp_batch = &mut self.udp_batch;

                    let res = self.udp_socket.try_io(Interest::READABLE, || {
                        let mut batch_buf = std::mem::take(&mut udp_recv_buf);
                        batch_buf.truncate(0);
                        if batch_buf.capacity() < UDP_BATCH_SIZE * recv_packet_size {
                            batch_buf.reserve(UDP_BATCH_SIZE * recv_packet_size);
                        }
                        // SAFETY: The flat buffer is set to capacity to allow slicing it for recv.
                        // The uninitialized bytes are never read before they are written by the OS kernel.
                        unsafe { batch_buf.set_len(UDP_BATCH_SIZE * recv_packet_size); }
                        for i in 0..UDP_BATCH_SIZE {
                            let offset = i * recv_packet_size;
                            udp_batch.iovs[i].iov_base = unsafe { batch_buf.as_mut_ptr().add(offset) as *mut libc::c_void };
                            udp_batch.iovs[i].iov_len = recv_packet_size as libc::size_t;

                            udp_batch.mmsgs[i].msg_hdr.msg_name = &mut udp_batch.addrs[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
                            udp_batch.mmsgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                            udp_batch.mmsgs[i].msg_hdr.msg_iov = &mut udp_batch.iovs[i] as *mut libc::iovec;
                            udp_batch.mmsgs[i].msg_hdr.msg_iovlen = 1;
                            udp_batch.mmsgs[i].msg_hdr.msg_control = std::ptr::null_mut();
                            udp_batch.mmsgs[i].msg_hdr.msg_controllen = 0;
                            udp_batch.mmsgs[i].msg_hdr.msg_flags = 0;
                            udp_batch.mmsgs[i].msg_len = 0;
                        }

                        let count = unsafe {
                            libc::recvmmsg(
                                fd,
                                udp_batch.mmsgs.as_mut_ptr(),
                                UDP_BATCH_SIZE as libc::c_uint,
                                libc::MSG_DONTWAIT,
                                std::ptr::null_mut(),
                            )
                        };

                        if count < 0 {
                            let err = std::io::Error::last_os_error();
                            udp_recv_buf = batch_buf;
                            return Err(err);
                        }
                        Ok((count as usize, batch_buf))
                    });

                    match res {
                        Ok((count, batch_buf)) if count > 0 => {
                            let now = std::time::Instant::now();
                            let mut remaining = batch_buf;
                            self.active_handles.clear();
                            for i in 0..count {
                                let len = self.udp_batch.mmsgs[i].msg_len as usize;
                                let mut packet_chunk = remaining.split_to(recv_packet_size);
                                if len > 0 {
                                    packet_chunk.truncate(len);
                                    let namelen = self.udp_batch.mmsgs[i].msg_hdr.msg_namelen;
                                    if let Some(remote_addr) = sockaddr_to_socket_addr(&self.udp_batch.addrs[i], namelen) {
                                        let handle_res = self.endpoint.handle(now, remote_addr, None, None, packet_chunk);
                                        if let Some((handle, datagram_event)) = handle_res {
                                            match datagram_event {
                                                quinn_proto::DatagramEvent::NewConnection(conn) => {
                                                    let worker_conn = crate::quic_proto_engine::WorkerConnection {
                                                        connection: conn,
                                                        authenticated: false,
                                                        tx_bytes: Arc::new(crate::telemetry::CellU64::new(0)),
                                                        rx_bytes: Arc::new(crate::telemetry::CellU64::new(0)),
                                                        peer_public_key: None,
                                                    };
                                                    self.connections.insert(handle, worker_conn);
                                                }
                                                quinn_proto::DatagramEvent::ConnectionEvent(conn_event) => {
                                                    if let Some(conn) = self.connections.get_mut(&handle) {
                                                        conn.connection.handle_event(conn_event);
                                                    }
                                                }
                                            }
                                            if !self.active_handles.contains(&handle) {
                                                self.active_handles.push(handle);
                                            }
                                        }
                                    } else {
                                        log::warn!("sockaddr_to_socket_addr failed: namelen={}", namelen);
                                    }
                                }
                            }
                            for handle in std::mem::take(&mut self.active_handles) {
                                self.drive_connection(handle, &dp_snapshot, now, &mut local_stats).await;
                            }
                            self.process_endpoint_transmits().await;
                            udp_recv_buf = remaining;
                        }
                        Ok((_, batch_buf)) => {
                            udp_recv_buf = batch_buf;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            log::warn!("UDP recvmmsg error: {:?}", e);
                        }
                    }
                }
            }

            #[cfg(not(target_os = "linux"))]
            run_select! {
                read_res = self.udp_socket.recv_from(&mut udp_buf) => {
                    match read_res {
                        Ok((n, remote_addr)) if n > 0 => {
                            let now = std::time::Instant::now();
                            // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                            // for read/recv_from. The uninitialized bytes are never read before they are
                            // overwritten by the OS kernel during the IO system call.
                            unsafe {
                                udp_buf.set_len(n);
                            }
                            let data = udp_buf.split_to(n);
                            self.handle_udp_packet(data, remote_addr, &dp_snapshot, now, &mut local_stats).await;

                            for _ in 0..63 {
                                if udp_buf.capacity() < 65536 {
                                    udp_buf.reserve(256 * 1024);
                                }
                                // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                // for read/recv_from. The uninitialized bytes are never read before they are
                                // overwritten by the OS kernel during the IO system call.
                                unsafe {
                                    let cap = udp_buf.capacity();
                                    udp_buf.set_len(cap);
                                }
                                match self.udp_socket.try_recv_from(&mut udp_buf) {
                                    Ok((n, remote_addr)) if n > 0 => {
                                        // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
                                        // for read/recv_from. The uninitialized bytes are never read before they are
                                        // overwritten by the OS kernel during the IO system call.
                                        unsafe {
                                            udp_buf.set_len(n);
                                        }
                                        let data = udp_buf.split_to(n);
                                        self.handle_udp_packet(data, remote_addr, &dp_snapshot, now, &mut local_stats).await;
                                    }
                                    _ => {
                                        udp_buf.truncate(0);
                                        break;
                                    }
                                }
                            }
                            self.process_endpoint_transmits().await;
                        }
                        _ => {
                            udp_buf.truncate(0);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl RtcWorker {
    async fn send_transmits_for_peer(
        &mut self,
        dest: std::net::SocketAddr,
        transmits: &[quinn_proto::Transmit],
    ) {
        if transmits.is_empty() {
            return;
        }

        self.tx_packet_slices.clear();
        for transmit in transmits {
            if let Some(seg_size) = transmit.segment_size {
                for chunk in transmit.contents.chunks(seg_size) {
                    self.tx_packet_slices
                        .push(SendSlicePtr(chunk as *const [u8]));
                }
            } else {
                self.tx_packet_slices
                    .push(SendSlicePtr(&transmit.contents[..] as *const [u8]));
            }
        }

        let fd = self.udp_socket.as_raw_fd();
        let tx_batch = &mut self.tx_batch;
        // We chunk packets into sizes of UDP_BATCH_SIZE
        for chunk in self.tx_packet_slices.chunks(UDP_BATCH_SIZE) {
            let count = chunk.len();
            for (i, pkt_ptr) in chunk.iter().enumerate() {
                // SAFETY: pkt_ptr is a valid raw pointer to a slice whose lifetime is valid
                // for the duration of this function call.
                let pkt = unsafe { &*pkt_ptr.0 };
                tx_batch.iovs[i].iov_base = pkt.as_ptr() as *mut libc::c_void;
                tx_batch.iovs[i].iov_len = pkt.len() as libc::size_t;

                socket_addr_to_sockaddr(dest, &mut tx_batch.addrs[i]);
                tx_batch.mmsgs[i].msg_hdr.msg_name =
                    &mut tx_batch.addrs[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
                tx_batch.mmsgs[i].msg_hdr.msg_namelen = if dest.is_ipv4() {
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                } else {
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                };
                tx_batch.mmsgs[i].msg_hdr.msg_iov = &mut tx_batch.iovs[i] as *mut libc::iovec;
                tx_batch.mmsgs[i].msg_hdr.msg_iovlen = 1;
                tx_batch.mmsgs[i].msg_hdr.msg_control = std::ptr::null_mut();
                tx_batch.mmsgs[i].msg_hdr.msg_controllen = 0;
                tx_batch.mmsgs[i].msg_hdr.msg_flags = 0;
                tx_batch.mmsgs[i].msg_len = 0;
            }

            let res = {
                let tx_ptr = tx_batch.mmsgs.as_mut_ptr();
                self.udp_socket.try_io(Interest::WRITABLE, || {
                    let sent = unsafe {
                        libc::sendmmsg(fd, tx_ptr, count as libc::c_uint, libc::MSG_DONTWAIT)
                    };
                    if sent < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(sent as usize)
                })
            };

            match res {
                Ok(sent) => {
                    if sent < count {
                        // Fallback for unsent packets in the batch
                        // Copy unsent slices to owned Send bytes to avoid non-Send pointers crossing await.
                        let mut fallback_packets = Vec::with_capacity(count - sent);
                        for pkt_ptr in &chunk[sent..] {
                            let pkt = unsafe { &*pkt_ptr.0 };
                            fallback_packets.push(bytes::Bytes::copy_from_slice(pkt));
                        }
                        for pkt in fallback_packets {
                            if let Err(e) = self.udp_socket.send_to(&pkt, dest).await {
                                log::warn!("Failed to send UDP transmit fallback packet: {}", e);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Fallback asynchronously by copying slices to Send bytes to avoid non-Send pointers crossing await.
                    let mut fallback_packets = Vec::with_capacity(count);
                    for pkt_ptr in chunk {
                        let pkt = unsafe { &*pkt_ptr.0 };
                        fallback_packets.push(bytes::Bytes::copy_from_slice(pkt));
                    }
                    for pkt in fallback_packets {
                        if let Err(e) = self.udp_socket.send_to(&pkt, dest).await {
                            log::warn!("Failed to send UDP transmit fallback packet: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to sendmmsg: {:?}", e);
                }
            }
        }
    }

    async fn process_endpoint_transmits(&mut self) {
        let now = std::time::Instant::now();
        // Group transmits by destination SocketAddr using preallocated HashMap
        let mut peer_transmits = std::mem::take(&mut self.peer_transmits);
        peer_transmits.clear();

        // 1. Poll endpoint-level transmits
        while let Some(transmit) = self.endpoint.poll_transmit() {
            peer_transmits
                .entry(transmit.destination)
                .or_default()
                .push(transmit);
        }

        // 2. Poll connection-level transmits
        for conn in self.connections.values_mut() {
            while let Some(transmit) = conn.connection.poll_transmit(now, 1024) {
                peer_transmits
                    .entry(transmit.destination)
                    .or_default()
                    .push(transmit);
            }
        }

        // 3. Batch send per peer
        for (dest, transmits) in &peer_transmits {
            self.send_transmits_for_peer(*dest, transmits).await;
        }

        // 4. Restore the preallocated HashMap to self
        self.peer_transmits = peer_transmits;
    }
}

/// Calculate the minimum QUIC initial_mtu required to carry a full-size TUN packet
/// as a QUIC datagram. The QUIC packet must contain:
///   - 1 byte: flags/header
///   - up to 20 bytes: connection ID
///   - 4 bytes: worst-case packet number
///   - 16 bytes: AEAD tag (AES-256-GCM)
///   - ~3 bytes: datagram frame header (type + length varint)
///   - the payload (packet_buffer_size bytes)
///
/// We add 100 bytes of headroom to be safe.
pub fn quic_initial_mtu_for_packet_buffer(packet_buffer_size: usize) -> u16 {
    // Prevent IP fragmentation by capping the initial MTU to fit within 1500-byte physical MTU.
    // Specifically, for 1420 TUN MTU, the packet buffer size is 1420 + 256 = 1676.
    // The maximum datagram size we actually send is 1421 bytes.
    // With ~35-45 bytes QUIC/UDP/IP overhead, this fits perfectly in a 1450-byte QUIC MTU
    // without causing IP fragmentation (which would occur if QUIC MTU > 1472).
    if packet_buffer_size >= 256 {
        let tun_mtu = packet_buffer_size - 256;
        let required = tun_mtu + 45;
        if tun_mtu <= 1420 {
            (required as u16).clamp(1200, 1470)
        } else {
            (required as u16).max(1200)
        }
    } else {
        (packet_buffer_size as u16 + 100).max(1200)
    }
}

fn build_client_proto_config(
    server_cert_sha256: [u8; 32],
    packet_buffer_size: usize,
) -> quinn_proto::ClientConfig {
    let mut rustls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(crate::quic_pool::PinnedCertVerifier {
            expected_sha256: server_cert_sha256,
        }))
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"new_proxy_mux".to_vec()];

    let quic_mtu = quic_initial_mtu_for_packet_buffer(packet_buffer_size);
    let mut client_config = quinn_proto::ClientConfig::new(Arc::new(rustls_config));
    let mut transport = quinn_proto::TransportConfig::default();
    transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.stream_receive_window(quinn_proto::VarInt::from(8 * 1024 * 1024u32));
    transport.receive_window(quinn_proto::VarInt::from(16 * 1024 * 1024u32));
    transport.send_window(16 * 1024 * 1024);
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.initial_mtu(quic_mtu);
    transport.min_mtu(quic_mtu);
    client_config.transport_config(Arc::new(transport));
    client_config
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

#[cfg(target_os = "linux")]
pub const UDP_BATCH_SIZE: usize = 128;

#[cfg(target_os = "linux")]
pub struct UdpBatch {
    pub mmsgs: [libc::mmsghdr; UDP_BATCH_SIZE],
    pub iovs: [libc::iovec; UDP_BATCH_SIZE],
    pub addrs: [libc::sockaddr_storage; UDP_BATCH_SIZE],
}

#[cfg(target_os = "linux")]
impl UdpBatch {
    pub fn new() -> Self {
        // SAFETY: All components are POD structures. Zero-initializing them is safe.
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(target_os = "linux")]
impl Default for UdpBatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
unsafe impl Send for UdpBatch {}
#[cfg(target_os = "linux")]
unsafe impl Sync for UdpBatch {}

pub fn sockaddr_to_socket_addr(
    addr: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<std::net::SocketAddr> {
    let sockaddr = unsafe { socket2::SockAddr::new(*addr, len) };
    sockaddr.as_socket()
}

pub fn socket_addr_to_sockaddr(
    addr: std::net::SocketAddr,
    dest: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    let sockaddr = socket2::SockAddr::from(addr);
    let len = sockaddr.len();
    unsafe {
        std::ptr::copy_nonoverlapping(
            sockaddr.as_ptr() as *const u8,
            dest as *mut libc::sockaddr_storage as *mut u8,
            len as usize,
        );
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_pool::QuicPoolClient;
    use crate::routing::AllowedIPsRouter;
    use arc_swap::ArcSwap;
    use parking_lot::{Mutex, RwLock};
    use std::collections::HashMap;
    use std::os::unix::io::IntoRawFd;
    use std::time::Duration;

    #[tokio::test]
    async fn test_rtc_worker_datagram_loop() {
        let session_cache = Arc::new(RwLock::new(HashMap::new()));
        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));

        let client_pub_key = [10u8; 32];
        let session_psk = [11u8; 32];
        session_cache.write().insert(client_pub_key, session_psk);

        // Bind UDP sockets
        let server_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();

        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Server TLS & Quinn-Proto Endpoint Setup
        let (certs, key) = crate::quic_pool::generate_self_signed_cert().unwrap();
        let mut rustls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key.clone())
            .unwrap();
        rustls_config.alpn_protocols = vec![b"new_proxy_mux".to_vec()];
        let mut server_proto_config =
            quinn_proto::ServerConfig::with_crypto(Arc::new(rustls_config));
        let mut transport = quinn_proto::TransportConfig::default();
        transport.mtu_discovery_config(None);
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
        transport.stream_receive_window(quinn_proto::VarInt::from(8 * 1024 * 1024u32));
        transport.receive_window(quinn_proto::VarInt::from(16 * 1024 * 1024u32));
        transport.send_window(16 * 1024 * 1024);
        transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
        transport.datagram_send_buffer_size(8 * 1024 * 1024);
        server_proto_config.transport_config(Arc::new(transport));

        let server_endpoint = quinn_proto::Endpoint::new(
            Arc::new(quinn_proto::EndpointConfig::default()),
            Some(Arc::new(server_proto_config)),
            false,
        );

        // Client Quinn-Proto Endpoint Setup
        let client_endpoint = quinn_proto::Endpoint::new(
            Arc::new(quinn_proto::EndpointConfig::default()),
            None,
            false,
        );

        let (client_sock_tun, client_sock_user) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let (server_sock_tun, server_sock_user) = std::os::unix::net::UnixDatagram::pair().unwrap();
        client_sock_tun.set_nonblocking(true).unwrap();
        client_sock_user.set_nonblocking(true).unwrap();
        server_sock_tun.set_nonblocking(true).unwrap();
        server_sock_user.set_nonblocking(true).unwrap();

        let client_tun_io = Arc::new(AsyncTunIo::new(client_sock_tun.into_raw_fd()).unwrap());
        let server_tun_io = Arc::new(AsyncTunIo::new(server_sock_tun.into_raw_fd()).unwrap());

        let mut client_worker = RtcWorker::new(
            client_tun_io,
            0,
            WorkerRole::Client,
            RtcWorkerConfig { mtu: 1400 },
            client_sock,
            client_endpoint,
            None,
            None,
            None,
        );

        let mut server_worker = RtcWorker::new(
            server_tun_io,
            0,
            WorkerRole::Server,
            RtcWorkerConfig { mtu: 1400 },
            server_sock,
            server_endpoint,
            Some(session_cache.clone()),
            Some(auth_nonce_cache.clone()),
            None,
        );

        let cert_fingerprint = crate::quic_pool::cert_sha256(&certs).unwrap();
        let pool = Arc::new(QuicPoolClient::new(
            client_pub_key,
            session_psk,
            cert_fingerprint,
            vec![server_addr],
        ));

        let mut client_pools = HashMap::new();
        client_pools.insert(client_pub_key, pool.clone());

        let mut client_router = AllowedIPsRouter::new();
        client_router.insert("10.0.0.1/32".parse().unwrap(), client_pub_key);

        let mut server_router = AllowedIPsRouter::new();
        server_router.insert("10.0.0.2/32".parse().unwrap(), client_pub_key);

        let client_data_plane = Arc::new(ArcSwap::new(Arc::new(crate::L4DataPlaneSnapshot {
            router: client_router,
            userspace_tcp_offload_enabled: true,
            client_quic_pools: client_pools,
        })));

        let server_data_plane = Arc::new(ArcSwap::new(Arc::new(crate::L4DataPlaneSnapshot {
            router: server_router,
            userspace_tcp_offload_enabled: true,
            client_quic_pools: HashMap::new(),
        })));

        let server_task = tokio::spawn(async move {
            let _ = server_worker.run_loop(server_data_plane).await;
        });

        let client_task = tokio::spawn(async move {
            let _ = client_worker.run_loop(client_data_plane).await;
        });

        // Give some time for handshake and authentication
        tokio::time::sleep(Duration::from_millis(500)).await;

        // 1. Test Outbound Packet (Client TUN -> Server TUN)
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

        let writer = client_sock_user.try_clone().unwrap();
        for _ in 0..64 {
            writer.send(&test_packet).unwrap();
        }

        let writer2 = server_sock_user.try_clone().unwrap();
        let reader = tokio::net::UnixDatagram::from_std(server_sock_user).unwrap();
        let mut read_buf = vec![0u8; 1500];
        let mut recved_count = 0;
        for _ in 0..64 {
            let res =
                tokio::time::timeout(Duration::from_secs(5), reader.recv(&mut read_buf)).await;
            if let Ok(Ok(n)) = res {
                assert_eq!(n, 44);
                assert_eq!(&read_buf[12..16], &[10, 0, 0, 2]);
                assert_eq!(&read_buf[16..20], &[10, 0, 0, 1]);
                recved_count += 1;
            } else {
                break;
            }
        }
        assert_eq!(recved_count, 64);

        // 2. Test Inbound Packet (Server TUN -> Client TUN)
        let mut inbound_packet = vec![0u8; 44];
        inbound_packet[0] = 0x45;
        inbound_packet[2] = 0x00;
        inbound_packet[3] = 44;
        inbound_packet[9] = 0x06; // TCP
        inbound_packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        inbound_packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        inbound_packet[20] = 0x00;
        inbound_packet[21] = 0x50; // Src Port
        inbound_packet[22] = 0x30;
        inbound_packet[23] = 0x39; // Dst Port
        inbound_packet[32] = 0x60; // Data offset
        inbound_packet[33] = 0x12; // Flags: SYN-ACK

        writer2.send(&inbound_packet).unwrap();

        let reader2 = tokio::net::UnixDatagram::from_std(client_sock_user).unwrap();
        let mut read_buf2 = vec![0u8; 1500];
        let n2 = tokio::time::timeout(Duration::from_secs(5), reader2.recv(&mut read_buf2))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(n2, 44);
        assert_eq!(read_buf2[12..16], [10, 0, 0, 1]);
        assert_eq!(read_buf2[16..20], [10, 0, 0, 2]);

        // Cleanup
        server_task.abort();
        client_task.abort();
    }

    #[test]
    fn test_sockaddr_conversion_roundtrip() {
        use super::*;
        let ipv4_addr: std::net::SocketAddr = "1.2.3.4:51820".parse().unwrap();
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = socket_addr_to_sockaddr(ipv4_addr, &mut storage);
        assert!(len > 0);
        let back = sockaddr_to_socket_addr(&storage, len).unwrap();
        assert_eq!(back, ipv4_addr);

        let ipv6_addr: std::net::SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        let mut storage6: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len6 = socket_addr_to_sockaddr(ipv6_addr, &mut storage6);
        assert!(len6 > 0);
        let back6 = sockaddr_to_socket_addr(&storage6, len6).unwrap();
        assert_eq!(back6, ipv6_addr);
    }
}
