use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig};
use rand::Rng;
use rustls::client::ServerCertVerified;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_AUTH_PACKET_LEN: usize = 2048;
const MAX_INCOMING_QUIC_CONNECTIONS: usize = 4096;

fn bind_server_endpoint(server_config: ServerConfig, port: u16) -> Result<Endpoint, String> {
    let runtime =
        quinn::default_runtime().ok_or_else(|| "No async runtime found for QUIC".to_string())?;
    let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
    let v6_result = (|| -> Result<Endpoint, String> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| format!("create IPv6 UDP socket failed: {}", e))?;
        socket
            .set_only_v6(false)
            .map_err(|e| format!("disable IPV6_V6ONLY failed: {}", e))?;
        socket
            .bind(&v6_addr.into())
            .map_err(|e| format!("bind [::]:{} failed: {}", port, e))?;
        let udp_socket: std::net::UdpSocket = socket.into();
        Endpoint::new(
            EndpointConfig::default(),
            Some(server_config.clone()),
            udp_socket,
            runtime.clone(),
        )
        .map_err(|e| format!("create dual-stack QUIC endpoint failed: {}", e))
    })();

    match v6_result {
        Ok(endpoint) => {
            log::info!(
                "QUIC listener bound on [::]:{} with IPV6_V6ONLY=false",
                port
            );
            Ok(endpoint)
        }
        Err(v6_err) => {
            let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            Endpoint::server(server_config, v4_addr).map_err(|v4_err| {
                format!(
                    "Failed to start QUIC listener on UDP port {}: IPv6 dual-stack bind failed: {}; IPv4 bind failed: {}",
                    port, v6_err, v4_err
                )
            })
        }
    }
}

pub type StreamHandler =
    Arc<dyn Fn([u8; 32], quinn::SendStream, quinn::RecvStream, Arc<QuicConnStats>) + Send + Sync>;

// 1. QUIC 隧道内应用层 PSK 认证报文
#[derive(Serialize, Deserialize, Debug)]
pub struct QuicAuthPacket {
    pub client_public_key: [u8; 32],
    pub nonce: [u8; 16],
    pub mac: [u8; 32],
}

// 单条 QUIC 物理连接的实时流量统计
#[derive(Clone)]
pub struct QuicConnStats {
    pub remote_addr: SocketAddr,
    pub local_port: u16,
    pub rx_bytes: Arc<AtomicU64>,
    pub tx_bytes: Arc<AtomicU64>,
    pub active_streams: Arc<AtomicU64>,
}

impl QuicConnStats {
    pub fn new(remote_addr: SocketAddr, local_port: u16) -> Self {
        Self {
            remote_addr,
            local_port,
            rx_bytes: Arc::new(AtomicU64::new(0)),
            tx_bytes: Arc::new(AtomicU64::new(0)),
            active_streams: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 快照：生成可序列化的统计视图
    pub fn snapshot(&self) -> QuicConnSnapshot {
        QuicConnSnapshot {
            remote_addr: self.remote_addr.to_string(),
            local_port: self.local_port,
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
        }
    }
}

/// 可序列化的单连接统计快照（用于 UDS 传输）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicConnSnapshot {
    pub remote_addr: String,
    pub local_port: u16,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active_streams: u64,
}

// 自定义 Dummy 证书验证器以支持 TLS 零证书配置
struct DummyVerifier;
impl rustls::client::ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

// 生成动态自签名证书 (用于服务端 QUIC 极速初始化)
pub fn generate_self_signed_cert() -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), String>
{
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| format!("Failed to generate cert: {}", e))?;
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert_der = rustls::Certificate(cert.serialize_der().unwrap());
    Ok((vec![cert_der], key))
}

// 2. 客户端 QUIC 物理连接池
pub struct QuicPoolClient {
    client_public_key: [u8; 32],
    session_psk: [u8; 32],
    endpoints: Vec<SocketAddr>,
    slots: Arc<Mutex<Vec<PoolSlot>>>,
    rr_index: Arc<Mutex<usize>>,
    endpoint: Arc<Mutex<Option<Endpoint>>>,
}

#[derive(Clone)]
struct PoolSlot {
    endpoint: SocketAddr,
    conn: Connection,
    stats: QuicConnStats,
}

impl QuicPoolClient {
    pub fn new(
        client_public_key: [u8; 32],
        session_psk: [u8; 32],
        endpoints: Vec<SocketAddr>,
    ) -> Self {
        Self {
            client_public_key,
            session_psk,
            endpoints,
            slots: Arc::new(Mutex::new(Vec::new())),
            rr_index: Arc::new(Mutex::new(0)),
            endpoint: Arc::new(Mutex::new(None)),
        }
    }

    // 启动物理连接池，在后台并发拉起多路 QUIC 链接
    pub async fn start_pool(&self) -> Result<(), String> {
        if self.endpoints.is_empty() {
            return Err("Empty endpoints pool".to_string());
        }

        // 配置 0 证书验证的客户端配置
        let mut rustls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(DummyVerifier))
            .with_no_client_auth();

        // 开启 ALPN
        rustls_config.alpn_protocols = vec![b"new_proxy_mux".to_vec()];

        let mut client_config = ClientConfig::new(Arc::new(rustls_config));
        // 配置连接保活与传输超时
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        transport.stream_receive_window(quinn::VarInt::from(8 * 1024 * 1024u32));
        transport.receive_window(quinn::VarInt::from(16 * 1024 * 1024u32));
        transport.send_window(16 * 1024 * 1024);
        client_config.transport_config(Arc::new(transport));

        // 绑定本地客户端 UDP 端口
        let bind_addr = if self.endpoints[0].is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let mut endpoint = Endpoint::client(bind_addr.parse().unwrap())
            .map_err(|e| format!("Failed to create client endpoint: {}", e))?;
        endpoint.set_default_client_config(client_config);
        *self.endpoint.lock().unwrap() = Some(endpoint.clone());

        let mut join_set = tokio::task::JoinSet::new();

        // 并发连向推上来的公网 UDP 端口池
        for &target_addr in &self.endpoints {
            log::info!(
                "Establishing physical QUIC connection pool link to {}",
                target_addr
            );
            let endpoint_clone = endpoint.clone();
            let client_public_key = self.client_public_key;
            let session_psk = self.session_psk;
            join_set.spawn(async move {
                Self::connect_authenticated_with(
                    endpoint_clone,
                    target_addr,
                    client_public_key,
                    session_psk,
                )
                .await
            });
        }

        let mut slots = Vec::new();
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(slot)) => slots.push(slot),
                Ok(Err(e)) => log::warn!("{}", e),
                Err(e) => log::warn!("QUIC connection worker failed: {}", e),
            }
        }

        if slots.is_empty() {
            return Err(
                "Failed to establish any healthy physical QUIC connection links".to_string(),
            );
        }

        log::info!(
            "Successfully initialized QUIC connection pool with {} active links",
            slots.len()
        );
        *self.slots.lock().unwrap() = slots;
        Ok(())
    }

    // 执行应用层 HMAC-PSK 强认证
    async fn authenticate_connection_with(
        client_public_key: [u8; 32],
        session_psk: [u8; 32],
        conn: &Connection,
    ) -> Result<(), String> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open auth stream: {}", e))?;

        let mut nonce = [0u8; 16];
        rand::thread_rng().fill(&mut nonce);

        // 用协商的 session_psk 签名
        let mac = crate::control::calculate_mac(&session_psk, &nonce);
        let auth_packet = QuicAuthPacket {
            client_public_key,
            nonce,
            mac,
        };

        let bytes = serde_json::to_vec(&auth_packet).unwrap();
        // 写入认证报文并关闭发送端
        if bytes.len() > u16::MAX as usize {
            return Err("Auth packet too large".to_string());
        }
        send.write_u16(bytes.len() as u16)
            .await
            .map_err(|e| format!("Auth length write error: {}", e))?;
        send.write_all(&bytes)
            .await
            .map_err(|e| format!("Auth write error: {}", e))?;
        send.shutdown().await.unwrap();

        // 等待服务端响应 "OK"
        let mut resp = [0u8; 2];
        timeout(AUTH_TIMEOUT, recv.read_exact(&mut resp))
            .await
            .map_err(|_| "Auth response timeout".to_string())?
            .map_err(|e| format!("Auth read error: {}", e))?;

        if &resp == b"OK" {
            Ok(())
        } else {
            Err("Server rejected PSK authentication".to_string())
        }
    }

    async fn connect_authenticated_with(
        endpoint: Endpoint,
        target_addr: SocketAddr,
        client_public_key: [u8; 32],
        session_psk: [u8; 32],
    ) -> Result<PoolSlot, String> {
        let connecting = endpoint
            .connect(target_addr, "localhost")
            .map_err(|e| format!("QUIC connect initiation failed to {}: {}", target_addr, e))?;
        let conn = timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| format!("QUIC connection timed out to {}", target_addr))?
            .map_err(|e| format!("QUIC connection failed to {}: {}", target_addr, e))?;

        match timeout(
            AUTH_TIMEOUT,
            Self::authenticate_connection_with(client_public_key, session_psk, &conn),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                conn.close(0u32.into(), b"Auth failed");
                return Err(format!(
                    "PSK Authentication failed on link {}: {}",
                    target_addr, e
                ));
            }
            Err(_) => {
                conn.close(0u32.into(), b"Auth timeout");
                return Err(format!(
                    "PSK Authentication timed out on link {}",
                    target_addr
                ));
            }
        }

        Ok(PoolSlot {
            endpoint: target_addr,
            stats: QuicConnStats::new(conn.remote_address(), target_addr.port()),
            conn,
        })
    }

    // 从活跃的平行物理池中轮询获取一个健康的流，同时返回对应的连接统计句柄
    pub async fn open_mux_stream(
        &self,
    ) -> Result<(quinn::SendStream, quinn::RecvStream, Arc<QuicConnStats>), String> {
        let mut attempts = 0;

        loop {
            attempts += 1;

            let (conn, conn_stat, total_conns) = {
                let slots = self.slots.lock().unwrap();
                if slots.is_empty() {
                    return Err("No active QUIC connections in pool".to_string());
                }

                let mut idx = self.rr_index.lock().unwrap();
                let i = *idx % slots.len();
                let selected_conn = slots[i].conn.clone();
                let selected_stat = Arc::new(slots[i].stats.clone());
                let total = slots.len();
                *idx += 1;
                (selected_conn, selected_stat, total)
            };

            if attempts > total_conns {
                return Err("All physical QUIC connections in pool are dead".to_string());
            }

            // 快速本地预检：如果连接已知已关闭，直接跳过，避免 open_bi().await 产生不必要的异步等待与延迟抖动
            if conn.close_reason().is_some() {
                log::debug!(
                    "Link round-robin matched known closed connection, skipping instantly."
                );
                continue;
            }

            match timeout(OPEN_STREAM_TIMEOUT, conn.open_bi()).await {
                Ok(Ok((send, recv))) => {
                    return Ok((send, recv, conn_stat));
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to open stream, link might be dead: {}", e);
                    continue;
                }
                Err(_) => {
                    log::warn!("Timed out opening mux stream on a QUIC link; trying another link");
                    continue;
                }
            }
        }
    }

    // 启动后台连接探针与动态自愈重连任务
    pub fn start_health_checker(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;

                let (endpoints, endpoint_opt) = {
                    let ep = self.endpoint.lock().unwrap();
                    (self.endpoints.clone(), ep.clone())
                };

                let endpoint = match endpoint_opt {
                    Some(ep) => ep,
                    None => continue,
                };

                let active_slots = self.slots.lock().unwrap().clone();

                let mut reconnects = tokio::task::JoinSet::new();

                for (i, slot) in active_slots.iter().enumerate() {
                    let need_reconnect = slot.conn.close_reason().is_some();

                    if need_reconnect {
                        log::info!(
                            "Connection index {} to {} is dead. Reconnecting...",
                            i,
                            slot.endpoint
                        );

                        let endpoint_clone = endpoint.clone();
                        let target_addr = slot.endpoint;
                        let client_public_key = self.client_public_key;
                        let session_psk = self.session_psk;
                        reconnects.spawn(async move {
                            (
                                Some(i),
                                target_addr,
                                Self::connect_authenticated_with(
                                    endpoint_clone,
                                    target_addr,
                                    client_public_key,
                                    session_psk,
                                )
                                .await,
                            )
                        });
                    }
                }

                let missing_endpoints = {
                    let slots = self.slots.lock().unwrap();
                    endpoints
                        .iter()
                        .copied()
                        .filter(|endpoint_addr| {
                            !slots.iter().any(|slot| slot.endpoint == *endpoint_addr)
                        })
                        .collect::<Vec<_>>()
                };

                for target_addr in missing_endpoints {
                    log::info!(
                        "Connection to {} is missing from pool. Connecting...",
                        target_addr
                    );
                    let endpoint_clone = endpoint.clone();
                    let client_public_key = self.client_public_key;
                    let session_psk = self.session_psk;
                    reconnects.spawn(async move {
                        (
                            None,
                            target_addr,
                            Self::connect_authenticated_with(
                                endpoint_clone,
                                target_addr,
                                client_public_key,
                                session_psk,
                            )
                            .await,
                        )
                    });
                }

                while let Some(result) = reconnects.join_next().await {
                    let (slot_index, target_addr, reconnect_result) = match result {
                        Ok(result) => result,
                        Err(e) => {
                            log::warn!("QUIC recovery worker failed: {}", e);
                            continue;
                        }
                    };

                    match reconnect_result {
                        Ok(new_slot) => {
                            let mut slots = self.slots.lock().unwrap();
                            if let Some(i) = slot_index {
                                if i < slots.len() && slots[i].endpoint == target_addr {
                                    slots[i] = new_slot;
                                    log::info!(
                                        "Successfully re-established dead connection to {}",
                                        target_addr
                                    );
                                }
                            } else if !slots.iter().any(|slot| slot.endpoint == target_addr) {
                                slots.push(new_slot);
                                log::info!(
                                    "Successfully added recovered connection to {}",
                                    target_addr
                                );
                            }
                        }
                        Err(e) => {
                            log::warn!("{}", e);
                        }
                    }
                }
            }
        });
    }
}

// 3. 服务端 QUIC 接收端与验证服务
// 每个已认证的对端连接 → 聚合统计（按 client_pub_key）
pub type PeerConnRegistry = Arc<Mutex<HashMap<[u8; 32], Vec<QuicConnRecord>>>>;

#[derive(Clone)]
pub struct QuicConnRecord {
    pub stats: QuicConnStats,
    conn: Connection,
}

impl QuicConnRecord {
    pub fn snapshot(&self) -> QuicConnSnapshot {
        self.stats.snapshot()
    }

    pub fn close(&self, reason: &'static [u8]) {
        self.conn.close(0u32.into(), reason);
    }
}

pub struct QuicPoolServer {
    listen_ports: Vec<u16>,
    session_cache: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
    auth_nonce_cache: Arc<Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
}

impl QuicPoolServer {
    pub fn new(
        listen_ports: Vec<u16>,
        session_cache: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
        auth_nonce_cache: Arc<Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
    ) -> Self {
        Self {
            listen_ports,
            session_cache,
            auth_nonce_cache,
        }
    }

    // 启动服务端 QUIC 引擎（使用外部传入的 registry，用于与 UDS 层共享统计数据）
    pub async fn run_with_registry(
        self,
        handler: StreamHandler,
        external_registry: PeerConnRegistry,
    ) -> Result<(), String> {
        let (certs, key) = generate_self_signed_cert()?;

        let mut rustls_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("Failed to create server TLS config: {}", e))?;

        rustls_config.alpn_protocols = vec![b"new_proxy_mux".to_vec()];

        let mut server_config = ServerConfig::with_crypto(Arc::new(rustls_config));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        transport.stream_receive_window(quinn::VarInt::from(8 * 1024 * 1024u32));
        transport.receive_window(quinn::VarInt::from(16 * 1024 * 1024u32));
        transport.send_window(16 * 1024 * 1024);
        server_config.transport_config(Arc::new(transport));

        let mut listeners = Vec::new();
        for port in self.listen_ports {
            let endpoint = bind_server_endpoint(server_config.clone(), port)?;
            listeners.push((port, endpoint));
        }

        let connection_limit = Arc::new(tokio::sync::Semaphore::new(MAX_INCOMING_QUIC_CONNECTIONS));

        // 为端口池中的每个物理 UDP 端口拉起一个异步接收 Endpoint
        for (port, endpoint) in listeners {
            let session_cache_clone = self.session_cache.clone();
            let auth_nonce_cache_clone = self.auth_nonce_cache.clone();
            let handler_clone = handler.clone();
            // 使用外部传入的 registry（与 UDS stats 层共享同一个 Arc）
            let peer_conn_registry = external_registry.clone();
            let connection_limit = connection_limit.clone();

            tokio::spawn(async move {
                log::info!("QUIC Pool Listener running on UDP port {}", port);

                while let Some(connecting) = endpoint.accept().await {
                    let permit = match connection_limit.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log::warn!("QUIC incoming connection limit reached on port {}; dropping connection", port);
                            continue;
                        }
                    };
                    let session_cache = session_cache_clone.clone();
                    let auth_nonce_cache = auth_nonce_cache_clone.clone();
                    let handler = handler_clone.clone();
                    let peer_conn_registry = peer_conn_registry.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        let conn = match timeout(CONNECT_TIMEOUT, connecting).await {
                            Ok(Ok(c)) => c,
                            Ok(Err(e)) => {
                                log::warn!("QUIC incoming connection handshake failed: {}", e);
                                return;
                            }
                            Err(_) => {
                                log::warn!("QUIC incoming connection handshake timed out");
                                return;
                            }
                        };

                        let remote_addr = conn.remote_address();
                        log::info!("New incoming QUIC connection from {}", remote_addr);

                        // 1. 等待第一条流，执行 PSK 强认证
                        let (mut send, mut recv) =
                            match timeout(AUTH_TIMEOUT, conn.accept_bi()).await {
                                Ok(Ok(stream)) => stream,
                                Ok(Err(_)) => {
                                    conn.close(0u32.into(), b"No auth stream");
                                    return;
                                }
                                Err(_) => {
                                    conn.close(0u32.into(), b"Auth stream timeout");
                                    return;
                                }
                            };

                        let auth_len = match timeout(AUTH_TIMEOUT, recv.read_u16()).await {
                            Ok(Ok(len)) => len as usize,
                            Ok(Err(_)) => {
                                conn.close(0u32.into(), b"Auth read failed");
                                return;
                            }
                            Err(_) => {
                                conn.close(0u32.into(), b"Auth read timeout");
                                return;
                            }
                        };
                        if auth_len == 0 || auth_len > MAX_AUTH_PACKET_LEN {
                            conn.close(0u32.into(), b"Invalid auth packet length");
                            return;
                        }

                        let mut buf = vec![0u8; auth_len];
                        match timeout(AUTH_TIMEOUT, recv.read_exact(&mut buf)).await {
                            Ok(Ok(_)) => {}
                            Ok(Err(_)) => {
                                conn.close(0u32.into(), b"Auth read failed");
                                return;
                            }
                            Err(_) => {
                                conn.close(0u32.into(), b"Auth read timeout");
                                return;
                            }
                        };

                        let auth_packet: QuicAuthPacket = match serde_json::from_slice(&buf) {
                            Ok(p) => p,
                            Err(_) => {
                                conn.close(0u32.into(), b"Invalid auth packet");
                                return;
                            }
                        };

                        // 查找临时协商的 PSK 缓存
                        let authenticated = {
                            let cache = session_cache.lock().unwrap();
                            if let Some(psk) = cache.get(&auth_packet.client_public_key) {
                                crate::control::verify_mac(
                                    psk,
                                    &auth_packet.nonce,
                                    &auth_packet.mac,
                                )
                            } else {
                                false
                            }
                        };

                        if !authenticated {
                            log::warn!(
                                "PSK Authentication FAILED for QUIC connection from {}",
                                remote_addr
                            );
                            conn.close(0u32.into(), b"Auth failed");
                            return;
                        }

                        {
                            let mut cache = auth_nonce_cache.lock().unwrap();
                            let peer_cache = cache
                                .entry(auth_packet.client_public_key)
                                .or_insert_with(|| crate::control::NonceCache::new(4096));
                            if !peer_cache.insert(auth_packet.nonce) {
                                log::warn!("Replayed QUIC auth nonce from {}", remote_addr);
                                conn.close(0u32.into(), b"Auth replay");
                                return;
                            }
                        }

                        // 验证成功，回复 OK
                        log::info!(
                            "PSK Authentication SUCCESSFUL for peer: {:?}",
                            auth_packet.client_public_key
                        );
                        if send.write_all(b"OK").await.is_err() {
                            return;
                        }
                        let _ = send.shutdown().await;

                        // 2. 为这条物理连接创建统计句柄，注册到 peer_conn_registry
                        let client_pub_key = auth_packet.client_public_key;
                        let conn_stat = Arc::new(QuicConnStats::new(remote_addr, port));
                        {
                            let mut registry = peer_conn_registry.lock().unwrap();
                            registry
                                .entry(client_pub_key)
                                .or_default()
                                .push(QuicConnRecord {
                                    stats: (*conn_stat).clone(),
                                    conn: conn.clone(),
                                });
                        }

                        let _guard = TelemetryRegistryGuard {
                            registry: peer_conn_registry.clone(),
                            client_pub_key,
                            remote_addr,
                        };

                        // 3. 进入多路复用流接收循环
                        while let Ok((send_mux, recv_mux)) = conn.accept_bi().await {
                            let still_authorized = {
                                let cache = session_cache.lock().unwrap();
                                cache.contains_key(&client_pub_key)
                            };
                            if !still_authorized {
                                log::warn!(
                                    "Closing QUIC connection from removed peer {:?}",
                                    client_pub_key
                                );
                                conn.close(0u32.into(), b"Peer removed");
                                break;
                            }
                            let handler = handler.clone();
                            let stat_clone = conn_stat.clone();
                            tokio::spawn(async move {
                                handler(client_pub_key, send_mux, recv_mux, stat_clone);
                            });
                        }
                        log::info!("QUIC connection from {} closed", remote_addr);
                    });
                }
            });
        }

        Ok(())
    }
}

struct TelemetryRegistryGuard {
    registry: PeerConnRegistry,
    client_pub_key: [u8; 32],
    remote_addr: SocketAddr,
}

impl Drop for TelemetryRegistryGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(conns) = registry.get_mut(&self.client_pub_key) {
                conns.retain(|record| record.stats.remote_addr != self.remote_addr);
                if conns.is_empty() {
                    registry.remove(&self.client_pub_key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn test_quic_pool_client_server_integration() {
        // 1. 获取一个闲置的本地 UDP 端口
        let port = {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };

        // 2. 初始化服务端
        let session_cache = Arc::new(Mutex::new(HashMap::new()));
        let peer_registry = Arc::new(Mutex::new(HashMap::new()));

        let client_pub_key = [7u8; 32];
        let session_psk = [9u8; 32];
        session_cache
            .lock()
            .unwrap()
            .insert(client_pub_key, session_psk);

        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));
        let server = QuicPoolServer::new(vec![port], session_cache.clone(), auth_nonce_cache);

        // 3. 服务端流处理逻辑 (Echo 服务)
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
        let handler = Arc::new(
            move |_pub_key: [u8; 32],
                  mut send: quinn::SendStream,
                  mut recv: quinn::RecvStream,
                  stat: Arc<QuicConnStats>| {
                let tx = tx.clone();
                tokio::spawn(async move {
                    // 模拟接收数据并增加 rx 计数
                    let mut buf = vec![0u8; 1024];
                    if let Ok(Some(n)) = recv.read(&mut buf).await {
                        buf.truncate(n);
                        stat.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        // 回写数据并增加 tx 计数
                        if send.write_all(&buf).await.is_ok() {
                            stat.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        let _ = send.finish().await;
                        let _ = tx.send(buf).await;
                    }
                });
            },
        );

        server
            .run_with_registry(handler, peer_registry.clone())
            .await
            .unwrap();

        // 4. 初始化客户端并连接
        let server_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap();
        let client = QuicPoolClient::new(client_pub_key, session_psk, vec![server_addr]);
        client.start_pool().await.unwrap();

        // 5. 验证 open_mux_stream 并进行双向数据交互
        let (mut send, mut recv, conn_stat) = client.open_mux_stream().await.unwrap();
        assert_eq!(conn_stat.remote_addr, server_addr);
        send.write_all(b"Hello QUIC Mux Pool!").await.unwrap();
        send.finish().await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = recv.read(&mut resp).await.unwrap().unwrap();
        resp.truncate(n);
        assert_eq!(&resp, b"Hello QUIC Mux Pool!");

        // 6. 等待并验证服务端接收通道也接到了相同内容
        let server_received = rx.recv().await.unwrap();
        assert_eq!(&server_received, b"Hello QUIC Mux Pool!");

        // 7. 验证流量统计与快照
        {
            let registry = peer_registry.lock().unwrap();
            assert!(registry.contains_key(&client_pub_key));
            let stats = &registry[&client_pub_key];
            assert_eq!(stats.len(), 1);
            assert_eq!(stats[0].stats.local_port, port);

            let snapshot = stats[0].snapshot();
            assert_eq!(snapshot.local_port, port);
            assert!(snapshot.rx_bytes > 0);
            assert!(snapshot.tx_bytes > 0);
        }

        // 8. 启动健康检查探针以实现代码覆盖 (验证不会崩溃即可)
        let client_arc = Arc::new(client);
        client_arc.clone().start_health_checker();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 9. 关闭客户端连接，验证 Registry 自动清理
        if let Some(slot) = client_arc.slots.lock().unwrap().first() {
            slot.conn.close(0u32.into(), b"Test shutdown");
        }

        // 给清理机制一些时间
        tokio::time::sleep(Duration::from_millis(150)).await;

        {
            let registry = peer_registry.lock().unwrap();
            assert!(registry.is_empty() || !registry.contains_key(&client_pub_key));
        }
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let res = generate_self_signed_cert();
        assert!(res.is_ok());
        let (certs, key) = res.unwrap();
        assert!(!certs.is_empty());
        assert!(!key.0.is_empty());
    }
}
