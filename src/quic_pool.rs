use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig};
use rand::Rng;
use rustls::client::ServerCertVerified;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;

const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(2);
const QUIC_RECOVERY_COOLDOWN: Duration = Duration::from_secs(10);
const CONTROL_REFRESH_INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const CONTROL_REFRESH_MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_AUTH_PACKET_LEN: usize = 2048;
const MAX_INCOMING_QUIC_CONNECTIONS: usize = 4096;
static NEXT_QUIC_CONN_RECORD_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolState {
    Active,
    Fallback,
    Recovering { recovery_start: std::time::Instant },
}

#[derive(Clone)]
struct PoolRuntimeConfig {
    session_psk: [u8; 32],
    server_cert_sha256: [u8; 32],
    endpoints: Vec<SocketAddr>,
}

#[derive(Clone)]
struct ControlRefreshConfig {
    private_key: [u8; 32],
    server_public_key: [u8; 32],
    control_endpoint: SocketAddr,
    fallback_endpoint: SocketAddr,
}

struct ControlRefreshBackoff {
    next_allowed: Option<Instant>,
    current_delay: Duration,
}

impl Default for ControlRefreshBackoff {
    fn default() -> Self {
        Self {
            next_allowed: None,
            current_delay: CONTROL_REFRESH_INITIAL_BACKOFF,
        }
    }
}

#[derive(Clone, Copy)]
struct QuicPoolClientTiming {
    connect_timeout: Duration,
    health_check_interval: Duration,
}

impl Default for QuicPoolClientTiming {
    fn default() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            health_check_interval: Duration::from_secs(5),
        }
    }
}

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
        crate::socket_mark::set_outer_mark(&udp_socket)?;
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
            let v4_result = (|| -> Result<Endpoint, String> {
                let socket = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .map_err(|e| format!("create IPv4 UDP socket failed: {}", e))?;
                socket
                    .bind(&v4_addr.into())
                    .map_err(|e| format!("bind 0.0.0.0:{} failed: {}", port, e))?;
                crate::socket_mark::set_socket2_outer_mark(&socket)?;
                let udp_socket: std::net::UdpSocket = socket.into();
                Endpoint::new(
                    EndpointConfig::default(),
                    Some(server_config),
                    udp_socket,
                    runtime,
                )
                .map_err(|e| format!("create IPv4 QUIC endpoint failed: {}", e))
            })();
            v4_result.map_err(|v4_err| {
                format!(
                    "Failed to start QUIC listener on UDP port {}: IPv6 dual-stack bind failed: {}; IPv4 bind failed: {}",
                    port, v6_err, v4_err
                )
            })
        }
    }
}

pub type ServerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub type StreamHandler = Arc<
    dyn Fn([u8; 32], quinn::SendStream, quinn::RecvStream, Arc<QuicConnStats>) -> ServerFuture
        + Send
        + Sync,
>;

const SERVER_FUTURES_POLL_BUDGET: usize = 128;

#[derive(Clone, Copy)]
struct ReadyKey {
    index: usize,
    generation: u64,
}

struct ReadyWake {
    key: ReadyKey,
    queued: Arc<AtomicBool>,
    queue: Arc<parking_lot::Mutex<VecDeque<ReadyKey>>>,
    waiter: Arc<parking_lot::Mutex<Option<Waker>>>,
}

impl Wake for ReadyWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            self.queue.lock().push_back(self.key);
        }
        if let Some(waiter) = self.waiter.lock().as_ref() {
            waiter.wake_by_ref();
        }
    }
}

struct ServerTask {
    future: ServerFuture,
    queued: Arc<AtomicBool>,
    generation: u64,
}

struct ServerFutures {
    tasks: Vec<Option<ServerTask>>,
    free: Vec<usize>,
    ready: Arc<parking_lot::Mutex<VecDeque<ReadyKey>>>,
    waiter: Arc<parking_lot::Mutex<Option<Waker>>>,
    live: usize,
    next_generation: u64,
}

impl ServerFutures {
    fn new() -> Self {
        Self {
            tasks: Vec::new(),
            free: Vec::new(),
            ready: Arc::new(parking_lot::Mutex::new(VecDeque::new())),
            waiter: Arc::new(parking_lot::Mutex::new(None)),
            live: 0,
            next_generation: 1,
        }
    }

    fn is_empty(&self) -> bool {
        self.live == 0
    }

    fn push(&mut self, future: ServerFuture) {
        let index = self.free.pop().unwrap_or_else(|| {
            self.tasks.push(None);
            self.tasks.len() - 1
        });
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        let queued = Arc::new(AtomicBool::new(true));
        self.tasks[index] = Some(ServerTask {
            future,
            queued: queued.clone(),
            generation,
        });
        self.ready.lock().push_back(ReadyKey { index, generation });
        self.live += 1;
    }

    fn poll_ready(&mut self) -> impl Future<Output = ()> + '_ {
        std::future::poll_fn(move |cx| {
            let mut progressed = false;
            *self.waiter.lock() = Some(cx.waker().clone());
            let ready_count = self.ready.lock().len().min(SERVER_FUTURES_POLL_BUDGET);
            for _ in 0..ready_count {
                let Some(key) = self.ready.lock().pop_front() else {
                    break;
                };
                let Some(Some(task)) = self.tasks.get_mut(key.index) else {
                    continue;
                };
                if task.generation != key.generation {
                    continue;
                };
                task.queued.store(false, Ordering::Release);
                let waker = std::task::Waker::from(Arc::new(ReadyWake {
                    key,
                    queued: task.queued.clone(),
                    queue: self.ready.clone(),
                    waiter: self.waiter.clone(),
                }));
                let mut cx = Context::from_waker(&waker);
                match task.future.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => {
                        self.tasks[key.index] = None;
                        self.free.push(key.index);
                        self.live -= 1;
                    }
                    Poll::Pending => {}
                }
                progressed = true;
            }

            if progressed {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
    }
}

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

// 控制面通过已认证 HMAC 响应下发 QUIC 证书指纹；数据面只接受该证书。
struct PinnedCertVerifier {
    expected_sha256: [u8; 32],
}

impl rustls::client::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = Sha256::digest(&end_entity.0);
        if digest.as_slice() == self.expected_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "pinned QUIC certificate fingerprint mismatch".to_string(),
            ))
        }
    }
}

// 生成动态自签名证书 (用于服务端 QUIC 极速初始化)
pub fn generate_self_signed_cert() -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), String>
{
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| format!("Failed to generate cert: {}", e))?;
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    let cert_der = rustls::Certificate(
        cert.serialize_der()
            .map_err(|e| format!("Failed to serialize cert: {}", e))?,
    );
    Ok((vec![cert_der], key))
}

pub fn cert_sha256(certs: &[rustls::Certificate]) -> Result<[u8; 32], String> {
    let cert = certs
        .first()
        .ok_or_else(|| "QUIC certificate chain is empty".to_string())?;
    let digest = Sha256::digest(&cert.0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

// 2. 客户端 QUIC 物理连接池
pub struct QuicPoolClient {
    client_public_key: [u8; 32],
    runtime_config: Arc<RwLock<PoolRuntimeConfig>>,
    refresh_config: Option<ControlRefreshConfig>,
    slots: Arc<ArcSwap<Vec<PoolSlot>>>,
    rr_index: Arc<AtomicUsize>,
    endpoint: Arc<Mutex<Option<Endpoint>>>,
    shutdown: Arc<AtomicBool>,
    pool_state: Arc<RwLock<PoolState>>,
    control_refresh_backoff: Arc<Mutex<ControlRefreshBackoff>>,
    timing: Arc<RwLock<QuicPoolClientTiming>>,
    data_port_count: usize,
}

#[derive(Clone)]
struct PoolSlot {
    endpoint: SocketAddr,
    conn: Connection,
    stats: Arc<QuicConnStats>,
}

impl QuicPoolClient {
    #[allow(dead_code)]
    pub fn new(
        client_public_key: [u8; 32],
        session_psk: [u8; 32],
        server_cert_sha256: [u8; 32],
        endpoints: Vec<SocketAddr>,
    ) -> Self {
        Self::new_internal(
            client_public_key,
            session_psk,
            server_cert_sha256,
            endpoints,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_refresh(
        client_public_key: [u8; 32],
        session_psk: [u8; 32],
        server_cert_sha256: [u8; 32],
        endpoints: Vec<SocketAddr>,
        private_key: [u8; 32],
        server_public_key: [u8; 32],
        control_endpoint: SocketAddr,
        fallback_endpoint: SocketAddr,
    ) -> Self {
        Self::new_internal(
            client_public_key,
            session_psk,
            server_cert_sha256,
            endpoints,
            Some(ControlRefreshConfig {
                private_key,
                server_public_key,
                control_endpoint,
                fallback_endpoint,
            }),
        )
    }

    fn new_internal(
        client_public_key: [u8; 32],
        session_psk: [u8; 32],
        server_cert_sha256: [u8; 32],
        endpoints: Vec<SocketAddr>,
        refresh_config: Option<ControlRefreshConfig>,
    ) -> Self {
        let data_port_count = endpoints.len();
        Self {
            client_public_key,
            runtime_config: Arc::new(RwLock::new(PoolRuntimeConfig {
                session_psk,
                server_cert_sha256,
                endpoints,
            })),
            refresh_config,
            slots: Arc::new(ArcSwap::from_pointee(Vec::new())),
            rr_index: Arc::new(AtomicUsize::new(0)),
            endpoint: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
            pool_state: Arc::new(RwLock::new(PoolState::Active)),
            control_refresh_backoff: Arc::new(Mutex::new(ControlRefreshBackoff::default())),
            timing: Arc::new(RwLock::new(QuicPoolClientTiming::default())),
            data_port_count,
        }
    }

    #[cfg(test)]
    fn set_test_timing(&self, connect_timeout: Duration, health_check_interval: Duration) {
        *self.timing.write() = QuicPoolClientTiming {
            connect_timeout,
            health_check_interval,
        };
    }

    pub fn get_state(&self) -> PoolState {
        *self.pool_state.read()
    }

    pub fn endpoint_count(&self) -> usize {
        self.data_port_count
    }

    pub fn connection_snapshots(&self) -> Vec<QuicConnSnapshot> {
        self.slots
            .load()
            .iter()
            .filter(|slot| slot.conn.close_reason().is_none())
            .map(|slot| slot.stats.snapshot())
            .collect()
    }

    pub fn enter_fallback(&self, reason: &str) {
        let mut state = self.pool_state.write();
        if !matches!(*state, PoolState::Fallback) {
            log::warn!("Entering QUIC fallback state: {}", reason);
            *state = PoolState::Fallback;
        }
    }

    pub fn shutdown(&self, reason: &'static [u8]) {
        self.shutdown.store(true, Ordering::Relaxed);
        {
            let slots = self.slots.load();
            for slot in slots.iter() {
                slot.conn.close(0u32.into(), reason);
            }
        }
        if let Some(endpoint) = self.endpoint.lock().as_ref() {
            endpoint.close(0u32.into(), reason);
        }
    }

    fn should_refresh_control_after_failure(error: &str) -> bool {
        error.contains("PSK Authentication failed")
            || error.contains("PSK Authentication timed out")
            || error.contains("QUIC connection timed out")
            || error.contains("QUIC connection failed")
            || error.contains("pinned QUIC certificate fingerprint mismatch")
            || error.contains("Server rejected PSK authentication")
    }

    fn control_refresh_allowed_now(&self) -> bool {
        self.control_refresh_backoff
            .lock()
            .next_allowed
            .map(|next_allowed| Instant::now() >= next_allowed)
            .unwrap_or(true)
    }

    fn record_control_refresh_success(&self) {
        *self.control_refresh_backoff.lock() = ControlRefreshBackoff::default();
    }

    fn record_control_refresh_failure(&self) -> Duration {
        let mut backoff = self.control_refresh_backoff.lock();
        let delay = backoff.current_delay;
        backoff.next_allowed = Some(Instant::now() + delay);
        backoff.current_delay = (delay * 2).min(CONTROL_REFRESH_MAX_BACKOFF);
        delay
    }

    // 启动物理连接池，在后台并发拉起多路 QUIC 链接
    pub async fn start_pool(&self) -> Result<(), String> {
        let runtime_config = self.runtime_config.read().clone();
        if runtime_config.endpoints.is_empty() {
            return Err("Empty endpoints pool".to_string());
        }

        let endpoint = Self::create_client_endpoint(&runtime_config)?;
        *self.endpoint.lock() = Some(endpoint.clone());

        let slots = self
            .connect_all_endpoints(&endpoint, &runtime_config)
            .await?;

        log::info!(
            "Successfully initialized QUIC connection pool with {} active links",
            slots.len()
        );
        self.slots.store(Arc::new(slots));
        Ok(())
    }

    fn build_client_config(server_cert_sha256: [u8; 32]) -> ClientConfig {
        let mut rustls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier {
                expected_sha256: server_cert_sha256,
            }))
            .with_no_client_auth();
        rustls_config.alpn_protocols = vec![b"new_proxy_mux".to_vec()];

        let mut client_config = ClientConfig::new(Arc::new(rustls_config));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        transport.stream_receive_window(quinn::VarInt::from(8 * 1024 * 1024u32));
        transport.receive_window(quinn::VarInt::from(16 * 1024 * 1024u32));
        transport.send_window(16 * 1024 * 1024);
        client_config.transport_config(Arc::new(transport));
        client_config
    }

    fn create_client_endpoint(runtime_config: &PoolRuntimeConfig) -> Result<Endpoint, String> {
        if runtime_config.endpoints.is_empty() {
            return Err("Empty endpoints pool".to_string());
        }
        let client_config = Self::build_client_config(runtime_config.server_cert_sha256);
        let bind_addr = if runtime_config.endpoints[0].is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let runtime = quinn::default_runtime()
            .ok_or_else(|| "No async runtime found for QUIC".to_string())?;
        let udp_socket = std::net::UdpSocket::bind(bind_addr)
            .map_err(|e| format!("Failed to bind QUIC client UDP socket: {}", e))?;
        crate::socket_mark::set_outer_mark(&udp_socket)?;
        let mut endpoint = Endpoint::new(EndpointConfig::default(), None, udp_socket, runtime)
            .map_err(|e| format!("Failed to create client endpoint: {}", e))?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }

    async fn connect_all_endpoints(
        &self,
        endpoint: &Endpoint,
        runtime_config: &PoolRuntimeConfig,
    ) -> Result<Vec<PoolSlot>, String> {
        let mut join_set = tokio::task::JoinSet::new();

        for &target_addr in &runtime_config.endpoints {
            log::info!(
                "Establishing physical QUIC connection pool link to {}",
                target_addr
            );
            let endpoint_clone = endpoint.clone();
            let client_public_key = self.client_public_key;
            let session_psk = runtime_config.session_psk;
            let connect_timeout = self.timing.read().connect_timeout;
            join_set.spawn(async move {
                Self::connect_authenticated_with(
                    endpoint_clone,
                    target_addr,
                    client_public_key,
                    session_psk,
                    connect_timeout,
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

        Ok(slots)
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
        send.shutdown()
            .await
            .map_err(|e| format!("Auth shutdown error: {}", e))?;

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
        connect_timeout: Duration,
    ) -> Result<PoolSlot, String> {
        let connecting = endpoint
            .connect(target_addr, "localhost")
            .map_err(|e| format!("QUIC connect initiation failed to {}: {}", target_addr, e))?;
        let conn = timeout(connect_timeout, connecting)
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
            stats: Arc::new(QuicConnStats::new(
                conn.remote_address(),
                target_addr.port(),
            )),
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
                let slots = self.slots.load();
                if slots.is_empty() {
                    return Err("No active QUIC connections in pool".to_string());
                }

                let idx = self.rr_index.fetch_add(1, Ordering::Relaxed);
                let i = idx % slots.len();
                let selected_conn = slots[i].conn.clone();
                let selected_stat = slots[i].stats.clone();
                let total = slots.len();
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
                    conn.close(0u32.into(), b"open stream failed");
                    continue;
                }
                Err(_) => {
                    log::warn!("Timed out opening mux stream on a QUIC link; trying another link");
                    conn.close(0u32.into(), b"open stream timeout");
                    continue;
                }
            }
        }
    }

    // 启动后台连接探针与动态自愈重连任务
    pub fn start_health_checker(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                let health_check_interval = self.timing.read().health_check_interval;
                tokio::time::sleep(health_check_interval).await;
                if self.shutdown.load(Ordering::Relaxed) {
                    break;
                }

                let pool_state = { *self.pool_state.read() };

                let runtime_config = self.runtime_config.read().clone();
                let (endpoints, session_psk, endpoint_opt) = {
                    let ep = self.endpoint.lock();
                    (
                        runtime_config.endpoints.clone(),
                        runtime_config.session_psk,
                        ep.clone(),
                    )
                };
                let connect_timeout = self.timing.read().connect_timeout;

                let endpoint = match endpoint_opt {
                    Some(ep) => ep,
                    None => continue,
                };

                let active_slots = self.slots.load_full();

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
                        reconnects.spawn(async move {
                            (
                                Some(i),
                                target_addr,
                                Self::connect_authenticated_with(
                                    endpoint_clone,
                                    target_addr,
                                    client_public_key,
                                    session_psk,
                                    connect_timeout,
                                )
                                .await,
                            )
                        });
                    }
                }

                let missing_endpoints = {
                    let slots = self.slots.load();
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
                    reconnects.spawn(async move {
                        (
                            None,
                            target_addr,
                            Self::connect_authenticated_with(
                                endpoint_clone,
                                target_addr,
                                client_public_key,
                                session_psk,
                                connect_timeout,
                            )
                            .await,
                        )
                    });
                }

                let mut refresh_worthy_failures = 0usize;
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
                            let mut slots = self.slots.load_full().as_ref().clone();
                            if let Some(i) = slot_index {
                                if i < slots.len() && slots[i].endpoint == target_addr {
                                    slots[i] = new_slot;
                                    log::info!(
                                        "Successfully re-established dead connection to {}",
                                        target_addr
                                    );
                                    self.slots.store(Arc::new(slots));
                                }
                            } else if !slots.iter().any(|slot| slot.endpoint == target_addr) {
                                slots.push(new_slot);
                                log::info!(
                                    "Successfully added recovered connection to {}",
                                    target_addr
                                );
                                self.slots.store(Arc::new(slots));
                            }
                        }
                        Err(e) => {
                            if Self::should_refresh_control_after_failure(&e) {
                                refresh_worthy_failures += 1;
                            }
                            log::warn!("{}", e);
                        }
                    }
                }

                if refresh_worthy_failures > 0 {
                    if self.control_refresh_allowed_now() {
                        match self.refresh_control_config().await {
                            Ok(()) => self.record_control_refresh_success(),
                            Err(e) => {
                                let delay = self.record_control_refresh_failure();
                                log::warn!(
                                    "Failed to refresh QUIC session after auth failures: {}; backing off for {:?}",
                                    e,
                                    delay
                                );
                            }
                        }
                    } else {
                        log::debug!("Skipping QUIC control refresh while backoff is active");
                    }
                }

                let has_live_connection = {
                    let slots = self.slots.load();
                    slots.iter().any(|slot| slot.conn.close_reason().is_none())
                };

                let mut new_pool_state = pool_state;
                match pool_state {
                    PoolState::Active | PoolState::Recovering { .. } => {
                        if !has_live_connection {
                            log::warn!("QUIC pool is completely down; entering Fallback state");
                            new_pool_state = PoolState::Fallback;
                        } else if let PoolState::Recovering { recovery_start } = pool_state {
                            if std::time::Instant::now().duration_since(recovery_start)
                                >= QUIC_RECOVERY_COOLDOWN
                            {
                                log::info!(
                                    "QUIC pool cooldown period expired; entering Active state."
                                );
                                new_pool_state = PoolState::Active;
                            }
                        }
                    }
                    PoolState::Fallback => {
                        if has_live_connection {
                            log::info!("QUIC pool has recovered. Entering Recovery (cooldown) period before switching back to QUIC.");
                            new_pool_state = PoolState::Recovering {
                                recovery_start: std::time::Instant::now(),
                            };
                        }
                    }
                }

                if new_pool_state != pool_state {
                    *self.pool_state.write() = new_pool_state;
                }
            }
        });
    }

    async fn refresh_control_config(&self) -> Result<(), String> {
        let Some(refresh) = self.refresh_config.clone() else {
            return Err("control refresh is not configured for this pool".to_string());
        };

        log::info!(
            "Refreshing QUIC control session for peer {}",
            crate::app_config::encode_base64_32(&refresh.server_public_key)
        );
        let control_client = crate::control::ControlClient::new(
            refresh.private_key,
            refresh.server_public_key,
            refresh.control_endpoint,
        );
        let (control_response, _control_socket) = control_client.negotiate_config().await?;
        let quic_endpoint_ip = crate::app_config::select_quic_endpoint_ip(
            &control_response,
            refresh.fallback_endpoint,
        )?;
        let endpoints = control_response
            .port_pool
            .iter()
            .map(|&port| SocketAddr::new(quic_endpoint_ip, port))
            .collect::<Vec<_>>();
        if endpoints.len() != self.data_port_count {
            return Err(format!(
                "refreshed QUIC data port count mismatch: existing pool uses {}, control plane returned {}; restart the client to change worker topology",
                self.data_port_count,
                endpoints.len()
            ));
        }
        let runtime_config = PoolRuntimeConfig {
            session_psk: control_response.session_psk,
            server_cert_sha256: control_response.quic_cert_sha256,
            endpoints,
        };

        let endpoint = Self::create_client_endpoint(&runtime_config)?;
        let slots = self
            .connect_all_endpoints(&endpoint, &runtime_config)
            .await?;

        if let Some(old_endpoint) = self.endpoint.lock().replace(endpoint) {
            old_endpoint.close(0u32.into(), b"QUIC session refreshed");
        }
        let old_slots = self.slots.swap(Arc::new(Vec::new()));
        for slot in old_slots.iter() {
            slot.conn.close(0u32.into(), b"QUIC session refreshed");
        }
        *self.runtime_config.write() = runtime_config;
        self.slots.store(Arc::new(slots));
        Ok(())
    }
}

// 3. 服务端 QUIC 接收端与验证服务
// 每个已认证的对端连接 → 聚合统计（按 client_pub_key）
pub type PeerConnRegistry = Arc<Mutex<HashMap<[u8; 32], Vec<QuicConnRecord>>>>;

#[derive(Clone)]
pub struct QuicConnRecord {
    id: u64,
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
    session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    auth_nonce_cache: Arc<Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
}

impl QuicPoolServer {
    pub fn new(
        listen_ports: Vec<u16>,
        session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        auth_nonce_cache: Arc<Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
    ) -> Self {
        Self {
            listen_ports,
            session_cache,
            auth_nonce_cache,
        }
    }

    async fn drive_quic_listener(
        port: u16,
        endpoint: Endpoint,
        session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        auth_nonce_cache: Arc<Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
        handler: StreamHandler,
        peer_conn_registry: PeerConnRegistry,
        connection_limit: Arc<tokio::sync::Semaphore>,
    ) {
        let mut connections = ServerFutures::new();
        log::info!("QUIC Pool Listener running on UDP port {}", port);

        loop {
            tokio::select! {
                connecting = endpoint.accept() => {
                    let Some(connecting) = connecting else {
                        break;
                    };
                    let permit = match connection_limit.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log::warn!("QUIC incoming connection limit reached on port {}; dropping connection", port);
                            continue;
                        }
                    };
                    connections.push(Box::pin(Self::drive_quic_connection(
                        port,
                        connecting,
                        permit,
                        session_cache.clone(),
                        auth_nonce_cache.clone(),
                        handler.clone(),
                        peer_conn_registry.clone(),
                    )) as ServerFuture);
                }

                _ = connections.poll_ready(), if !connections.is_empty() => {}
            }
        }
    }

    async fn drive_quic_connection(
        port: u16,
        connecting: quinn::Connecting,
        permit: OwnedSemaphorePermit,
        session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        auth_nonce_cache: Arc<Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
        handler: StreamHandler,
        peer_conn_registry: PeerConnRegistry,
    ) {
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

        let (mut send, mut recv) = match timeout(AUTH_TIMEOUT, conn.accept_bi()).await {
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

        let authenticated_psk = {
            let cache = session_cache.read();
            if let Some(psk) = cache.get(&auth_packet.client_public_key) {
                if crate::control::verify_mac(psk, &auth_packet.nonce, &auth_packet.mac) {
                    Some(*psk)
                } else {
                    None
                }
            } else {
                None
            }
        };

        let connection_psk = match authenticated_psk {
            Some(psk) => psk,
            None => {
                log::warn!(
                    "PSK Authentication FAILED for QUIC connection from {}",
                    remote_addr
                );
                conn.close(0u32.into(), b"Auth failed");
                return;
            }
        };

        {
            let mut cache = auth_nonce_cache.lock();
            let peer_cache = cache
                .entry(auth_packet.client_public_key)
                .or_insert_with(|| crate::control::NonceCache::new(4096));
            if !peer_cache.insert(auth_packet.nonce) {
                log::warn!("Replayed QUIC auth nonce from {}", remote_addr);
                conn.close(0u32.into(), b"Auth replay");
                return;
            }
        }

        log::info!(
            "PSK Authentication SUCCESSFUL for peer: {:?}",
            auth_packet.client_public_key
        );
        if send.write_all(b"OK").await.is_err() {
            return;
        }
        let _ = send.shutdown().await;

        let client_pub_key = auth_packet.client_public_key;
        let record_id = NEXT_QUIC_CONN_RECORD_ID.fetch_add(1, Ordering::Relaxed);
        let conn_stat = Arc::new(QuicConnStats::new(remote_addr, port));
        {
            let mut registry = peer_conn_registry.lock();
            registry
                .entry(client_pub_key)
                .or_default()
                .push(QuicConnRecord {
                    id: record_id,
                    stats: (*conn_stat).clone(),
                    conn: conn.clone(),
                });
        }

        let _guard = TelemetryRegistryGuard {
            registry: peer_conn_registry.clone(),
            client_pub_key,
            record_id,
        };

        let mut streams = ServerFutures::new();
        loop {
            tokio::select! {
                stream = conn.accept_bi() => {
                    let Ok((send_mux, recv_mux)) = stream else {
                        break;
                    };
                    let still_authorized = {
                        let cache = session_cache.read();
                        cache
                            .get(&client_pub_key)
                            .map(|psk| *psk == connection_psk)
                            .unwrap_or(false)
                    };
                    if !still_authorized {
                        log::warn!(
                            "Closing QUIC connection from removed or rotated peer {:?}",
                            client_pub_key
                        );
                        conn.close(0u32.into(), b"Peer removed or session rotated");
                        break;
                    }
                    streams.push(handler(
                        client_pub_key,
                        send_mux,
                        recv_mux,
                        conn_stat.clone(),
                    ));
                }

                _ = streams.poll_ready(), if !streams.is_empty() => {}
            }
        }
        log::info!("QUIC connection from {} closed", remote_addr);
    }

    // 启动服务端 QUIC 引擎（使用外部传入的 registry，用于与 UDS 层共享统计数据）
    pub async fn run_with_registry(
        self,
        certs: Vec<rustls::Certificate>,
        key: rustls::PrivateKey,
        handler: StreamHandler,
        external_registry: PeerConnRegistry,
    ) -> Result<(), String> {
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
            let session_cache = self.session_cache.clone();
            let auth_nonce_cache = self.auth_nonce_cache.clone();
            let handler = handler.clone();
            let peer_conn_registry = external_registry.clone();
            let connection_limit = connection_limit.clone();
            tokio::spawn(async move {
                Self::drive_quic_listener(
                    port,
                    endpoint,
                    session_cache,
                    auth_nonce_cache,
                    handler,
                    peer_conn_registry,
                    connection_limit,
                )
                .await;
            });
        }

        Ok(())
    }
}

struct TelemetryRegistryGuard {
    registry: PeerConnRegistry,
    client_pub_key: [u8; 32],
    record_id: u64,
}

impl Drop for TelemetryRegistryGuard {
    fn drop(&mut self) {
        let mut registry = self.registry.lock();
        if let Some(conns) = registry.get_mut(&self.client_pub_key) {
            conns.retain(|record| record.id != self.record_id);
            if conns.is_empty() {
                registry.remove(&self.client_pub_key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::Ordering;
    use std::task::Waker;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn unused_udp_port() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    }

    struct CountingPendingFuture {
        polls: Arc<AtomicUsize>,
        waker: Arc<parking_lot::Mutex<Option<Waker>>>,
    }

    impl Future for CountingPendingFuture {
        type Output = ();

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            *self.waker.lock() = Some(cx.waker().clone());
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn server_futures_only_repolls_woken_futures() {
        let polls_a = Arc::new(AtomicUsize::new(0));
        let polls_b = Arc::new(AtomicUsize::new(0));
        let waker_a = Arc::new(parking_lot::Mutex::new(None));
        let waker_b = Arc::new(parking_lot::Mutex::new(None));
        let mut futures = ServerFutures::new();

        futures.push(Box::pin(CountingPendingFuture {
            polls: polls_a.clone(),
            waker: waker_a.clone(),
        }));
        futures.push(Box::pin(CountingPendingFuture {
            polls: polls_b.clone(),
            waker: waker_b,
        }));

        futures.poll_ready().await;
        assert_eq!(polls_a.load(Ordering::Relaxed), 1);
        assert_eq!(polls_b.load(Ordering::Relaxed), 1);

        waker_a.lock().as_ref().unwrap().wake_by_ref();
        futures.poll_ready().await;
        assert_eq!(polls_a.load(Ordering::Relaxed), 2);
        assert_eq!(polls_b.load(Ordering::Relaxed), 1);
    }

    struct SelfWakingPendingFuture {
        polls: Arc<AtomicUsize>,
    }

    impl Future for SelfWakingPendingFuture {
        type Output = ();

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn server_futures_defers_self_wake_until_next_poll_ready_round() {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut futures = ServerFutures::new();

        futures.push(Box::pin(SelfWakingPendingFuture {
            polls: polls.clone(),
        }));

        tokio::time::timeout(Duration::from_secs(1), futures.poll_ready())
            .await
            .unwrap();
        assert_eq!(polls.load(Ordering::Relaxed), 1);

        tokio::time::timeout(Duration::from_secs(1), futures.poll_ready())
            .await
            .unwrap();
        assert_eq!(polls.load(Ordering::Relaxed), 2);
    }

    struct ReadyFuture;

    impl Future for ReadyFuture {
        type Output = ();

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Ready(())
        }
    }

    #[tokio::test]
    async fn server_futures_reuses_completed_slots() {
        let mut futures = ServerFutures::new();

        for _ in 0..1024 {
            futures.push(Box::pin(ReadyFuture));
            futures.poll_ready().await;
            assert!(futures.is_empty());
        }

        assert_eq!(futures.tasks.len(), 1);
        assert_eq!(futures.free.len(), 1);
    }

    #[tokio::test]
    async fn server_futures_limits_each_poll_ready_round() {
        let mut futures = ServerFutures::new();
        let mut poll_counts = Vec::new();

        for _ in 0..(SERVER_FUTURES_POLL_BUDGET + 5) {
            let polls = Arc::new(AtomicUsize::new(0));
            poll_counts.push(polls.clone());
            futures.push(Box::pin(CountingPendingFuture {
                polls,
                waker: Arc::new(parking_lot::Mutex::new(None)),
            }));
        }

        futures.poll_ready().await;
        let first_round_polls: usize = poll_counts
            .iter()
            .map(|polls| polls.load(Ordering::Relaxed))
            .sum();
        assert_eq!(first_round_polls, SERVER_FUTURES_POLL_BUDGET);

        futures.poll_ready().await;
        let second_round_polls: usize = poll_counts
            .iter()
            .map(|polls| polls.load(Ordering::Relaxed))
            .sum();
        assert_eq!(second_round_polls, SERVER_FUTURES_POLL_BUDGET + 5);
    }

    struct CaptureAndCompleteFuture {
        waker: Arc<parking_lot::Mutex<Option<Waker>>>,
    }

    impl Future for CaptureAndCompleteFuture {
        type Output = ();

        fn poll(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            *self.waker.lock() = Some(cx.waker().clone());
            std::task::Poll::Ready(())
        }
    }

    #[tokio::test]
    async fn server_futures_ignores_stale_wake_after_slot_reuse() {
        let stale_waker = Arc::new(parking_lot::Mutex::new(None));
        let new_future_polls = Arc::new(AtomicUsize::new(0));
        let mut futures = ServerFutures::new();

        futures.push(Box::pin(CaptureAndCompleteFuture {
            waker: stale_waker.clone(),
        }));
        futures.poll_ready().await;

        futures.push(Box::pin(CountingPendingFuture {
            polls: new_future_polls.clone(),
            waker: Arc::new(parking_lot::Mutex::new(None)),
        }));
        futures.poll_ready().await;
        assert_eq!(new_future_polls.load(Ordering::Relaxed), 1);

        stale_waker.lock().as_ref().unwrap().wake_by_ref();
        let result = tokio::time::timeout(Duration::from_millis(50), futures.poll_ready()).await;
        assert!(result.is_err());
        assert_eq!(new_future_polls.load(Ordering::Relaxed), 1);
    }

    async fn start_echo_quic_server(
        port: u16,
        session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    ) -> (
        [u8; 32],
        PeerConnRegistry,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        let peer_registry = Arc::new(Mutex::new(HashMap::new()));
        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));
        let server = QuicPoolServer::new(vec![port], session_cache, auth_nonce_cache);
        let (certs, key) = generate_self_signed_cert().unwrap();
        let cert_fingerprint = cert_sha256(&certs).unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10);

        let handler = Arc::new(
            move |_pub_key: [u8; 32],
                  mut send: quinn::SendStream,
                  mut recv: quinn::RecvStream,
                  stat: Arc<QuicConnStats>|
                  -> ServerFuture {
                let tx = tx.clone();
                Box::pin(async move {
                    let mut buf = vec![0u8; 1024];
                    if let Ok(Some(n)) = recv.read(&mut buf).await {
                        buf.truncate(n);
                        stat.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        if send.write_all(&buf).await.is_ok() {
                            stat.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        let _ = send.finish().await;
                        let _ = tx.send(buf).await;
                    }
                })
            },
        );

        server
            .run_with_registry(certs, key, handler, peer_registry.clone())
            .await
            .unwrap();

        (cert_fingerprint, peer_registry, rx)
    }

    #[tokio::test]
    async fn test_quic_pool_rejects_empty_endpoint_pool() {
        let client = QuicPoolClient::new([1u8; 32], [2u8; 32], [3u8; 32], Vec::new());

        assert_eq!(
            client.start_pool().await.unwrap_err(),
            "Empty endpoints pool"
        );
    }

    #[tokio::test]
    async fn test_quic_pool_client_server_integration() {
        // 1. 获取一个闲置的本地 UDP 端口
        let port = unused_udp_port();

        // 2. 初始化服务端
        let session_cache = Arc::new(RwLock::new(HashMap::new()));
        let peer_registry = Arc::new(Mutex::new(HashMap::new()));

        let client_pub_key = [7u8; 32];
        let session_psk = [9u8; 32];
        session_cache.write().insert(client_pub_key, session_psk);

        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));
        let server = QuicPoolServer::new(vec![port], session_cache.clone(), auth_nonce_cache);
        let (certs, key) = generate_self_signed_cert().unwrap();
        let cert_fingerprint = cert_sha256(&certs).unwrap();

        // 3. 服务端流处理逻辑 (Echo 服务)
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
        let handler = Arc::new(
            move |_pub_key: [u8; 32],
                  mut send: quinn::SendStream,
                  mut recv: quinn::RecvStream,
                  stat: Arc<QuicConnStats>|
                  -> ServerFuture {
                let tx = tx.clone();
                Box::pin(async move {
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
                })
            },
        );

        server
            .run_with_registry(certs, key, handler, peer_registry.clone())
            .await
            .unwrap();

        // 4. 初始化客户端并连接
        let server_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap();
        let bad_client =
            QuicPoolClient::new(client_pub_key, session_psk, [0u8; 32], vec![server_addr]);
        assert!(bad_client.start_pool().await.is_err());

        let client = QuicPoolClient::new(
            client_pub_key,
            session_psk,
            cert_fingerprint,
            vec![server_addr],
        );
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
            let registry = peer_registry.lock();
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
        if let Some(slot) = client_arc.slots.load().first() {
            slot.conn.close(0u32.into(), b"Test shutdown");
        }

        // 给清理机制一些时间
        tokio::time::sleep(Duration::from_millis(150)).await;

        {
            let registry = peer_registry.lock();
            assert!(registry.is_empty() || !registry.contains_key(&client_pub_key));
        }
    }

    #[tokio::test]
    async fn test_health_checker_refreshes_control_config_after_server_restart() {
        let old_port = unused_udp_port();
        let new_port = unused_udp_port();
        let control_port = unused_udp_port();

        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_pub = PublicKey::from(&client_secret).to_bytes();
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_pub = PublicKey::from(&server_secret).to_bytes();
        let server_shared = server_secret
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes();

        let old_psk = [9u8; 32];
        let old_session_cache = Arc::new(RwLock::new(HashMap::new()));
        old_session_cache.write().insert(client_pub, old_psk);
        let (old_cert_fingerprint, _old_registry, _old_rx) =
            start_echo_quic_server(old_port, old_session_cache.clone()).await;

        let new_session_cache = Arc::new(RwLock::new(HashMap::new()));
        let (new_cert_fingerprint, _new_registry, mut new_rx) =
            start_echo_quic_server(new_port, new_session_cache.clone()).await;

        let peer_secrets = Arc::new(RwLock::new(HashMap::new()));
        peer_secrets.write().insert(client_pub, server_shared);
        let control_server = crate::control::ControlServer::new(
            control_port,
            peer_secrets,
            vec![new_port],
            None,
            None,
            new_cert_fingerprint,
            new_session_cache.clone(),
        );
        let control_task = control_server.start().await.unwrap();

        let old_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), old_port);
        let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), new_port);
        let control_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), control_port);
        let client = Arc::new(QuicPoolClient::new_with_refresh(
            client_pub,
            old_psk,
            old_cert_fingerprint,
            vec![old_addr],
            client_secret.to_bytes(),
            server_pub,
            control_addr,
            control_addr,
        ));
        client.set_test_timing(Duration::from_millis(500), Duration::from_millis(50));
        client.start_pool().await.unwrap();

        old_session_cache.write().insert(client_pub, [8u8; 32]);
        {
            let slots = client.slots.load();
            for slot in slots.iter() {
                slot.conn.close(0u32.into(), b"simulated server restart");
            }
        }

        client.clone().start_health_checker();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let refreshed =
                client.runtime_config.read().endpoints == vec![new_addr]
                    && client.slots.load().iter().any(|slot| {
                        slot.endpoint == new_addr && slot.conn.close_reason().is_none()
                    });
            if refreshed {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "health checker did not refresh control config and reconnect to restarted server"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(new_session_cache.read().contains_key(&client_pub));
        let (mut send, mut recv, conn_stat) = client.open_mux_stream().await.unwrap();
        assert_eq!(conn_stat.local_port, new_port);
        send.write_all(b"after restart").await.unwrap();
        send.finish().await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = recv.read(&mut resp).await.unwrap().unwrap();
        resp.truncate(n);
        assert_eq!(&resp, b"after restart");
        assert_eq!(new_rx.recv().await.unwrap(), b"after restart");

        client.shutdown(b"test complete");
        control_task.abort();
    }

    #[tokio::test]
    async fn test_health_checker_refreshes_control_config_after_dead_data_port() {
        let old_port = unused_udp_port();
        let dead_port = unused_udp_port();
        let new_port = unused_udp_port();
        let control_port = unused_udp_port();

        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_pub = PublicKey::from(&client_secret).to_bytes();
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_pub = PublicKey::from(&server_secret).to_bytes();
        let server_shared = server_secret
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes();

        let old_psk = [9u8; 32];
        let old_session_cache = Arc::new(RwLock::new(HashMap::new()));
        old_session_cache.write().insert(client_pub, old_psk);
        let (old_cert_fingerprint, _old_registry, _old_rx) =
            start_echo_quic_server(old_port, old_session_cache.clone()).await;

        let new_session_cache = Arc::new(RwLock::new(HashMap::new()));
        let (new_cert_fingerprint, _new_registry, mut new_rx) =
            start_echo_quic_server(new_port, new_session_cache.clone()).await;

        let peer_secrets = Arc::new(RwLock::new(HashMap::new()));
        peer_secrets.write().insert(client_pub, server_shared);
        let control_server = crate::control::ControlServer::new(
            control_port,
            peer_secrets,
            vec![new_port],
            None,
            None,
            new_cert_fingerprint,
            new_session_cache.clone(),
        );
        let control_task = control_server.start().await.unwrap();

        let old_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), old_port);
        let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dead_port);
        let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), new_port);
        let control_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), control_port);
        let client = Arc::new(QuicPoolClient::new_with_refresh(
            client_pub,
            old_psk,
            old_cert_fingerprint,
            vec![old_addr],
            client_secret.to_bytes(),
            server_pub,
            control_addr,
            control_addr,
        ));
        client.set_test_timing(Duration::from_millis(500), Duration::from_millis(50));
        client.start_pool().await.unwrap();

        {
            let mut config = client.runtime_config.write();
            config.endpoints = vec![dead_addr];
        }
        {
            let old_slots = client.slots.load();
            let old_conn = old_slots[0].conn.clone();
            old_conn.close(0u32.into(), b"simulate dead data port");
            client.slots.store(Arc::new(vec![PoolSlot {
                endpoint: dead_addr,
                stats: Arc::new(QuicConnStats::new(dead_addr, dead_port)),
                conn: old_conn,
            }]));
        }

        client.clone().start_health_checker();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let refreshed =
                client.runtime_config.read().endpoints == vec![new_addr]
                    && client.slots.load().iter().any(|slot| {
                        slot.endpoint == new_addr && slot.conn.close_reason().is_none()
                    });
            if refreshed {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "health checker did not refresh control config after dead QUIC data port"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let (mut send, mut recv, conn_stat) = client.open_mux_stream().await.unwrap();
        assert_eq!(conn_stat.local_port, new_port);
        send.write_all(b"after dead data port").await.unwrap();
        send.finish().await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = recv.read(&mut resp).await.unwrap().unwrap();
        resp.truncate(n);
        assert_eq!(&resp, b"after dead data port");
        assert_eq!(new_rx.recv().await.unwrap(), b"after dead data port");

        client.shutdown(b"test complete");
        control_task.abort();
    }

    #[tokio::test]
    async fn test_health_checker_refreshes_control_config_after_partial_data_port_failure() {
        let old_port = unused_udp_port();
        let dead_port = unused_udp_port();
        let new_port = unused_udp_port();
        let control_port = unused_udp_port();

        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_pub = PublicKey::from(&client_secret).to_bytes();
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_pub = PublicKey::from(&server_secret).to_bytes();
        let server_shared = server_secret
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes();

        let old_psk = [10u8; 32];
        let old_session_cache = Arc::new(RwLock::new(HashMap::new()));
        old_session_cache.write().insert(client_pub, old_psk);
        let (old_cert_fingerprint, _old_registry, _old_rx) =
            start_echo_quic_server(old_port, old_session_cache.clone()).await;

        let new_session_cache = Arc::new(RwLock::new(HashMap::new()));
        let (new_cert_fingerprint, _new_registry, mut new_rx) =
            start_echo_quic_server(new_port, new_session_cache.clone()).await;

        let peer_secrets = Arc::new(RwLock::new(HashMap::new()));
        peer_secrets.write().insert(client_pub, server_shared);
        let control_server = crate::control::ControlServer::new(
            control_port,
            peer_secrets,
            vec![new_port],
            None,
            None,
            new_cert_fingerprint,
            new_session_cache.clone(),
        );
        let control_task = control_server.start().await.unwrap();

        let old_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), old_port);
        let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dead_port);
        let new_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), new_port);
        let control_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), control_port);
        let client = Arc::new(QuicPoolClient::new_with_refresh(
            client_pub,
            old_psk,
            old_cert_fingerprint,
            vec![old_addr],
            client_secret.to_bytes(),
            server_pub,
            control_addr,
            control_addr,
        ));
        client.set_test_timing(Duration::from_millis(500), Duration::from_millis(50));
        client.start_pool().await.unwrap();

        {
            let mut config = client.runtime_config.write();
            config.endpoints = vec![old_addr, dead_addr];
        }

        client.clone().start_health_checker();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let refreshed =
                client.runtime_config.read().endpoints == vec![new_addr]
                    && client.slots.load().iter().any(|slot| {
                        slot.endpoint == new_addr && slot.conn.close_reason().is_none()
                    });
            if refreshed {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "health checker did not refresh control config after partial QUIC data port failure"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let (mut send, mut recv, conn_stat) = client.open_mux_stream().await.unwrap();
        assert_eq!(conn_stat.local_port, new_port);
        send.write_all(b"after partial data port failure")
            .await
            .unwrap();
        send.finish().await.unwrap();

        let mut resp = vec![0u8; 1024];
        let n = recv.read(&mut resp).await.unwrap().unwrap();
        resp.truncate(n);
        assert_eq!(&resp, b"after partial data port failure");
        assert_eq!(
            new_rx.recv().await.unwrap(),
            b"after partial data port failure"
        );

        client.shutdown(b"test complete");
        control_task.abort();
    }

    #[test]
    fn control_refresh_covers_auth_certificate_and_full_endpoint_failures() {
        assert!(QuicPoolClient::should_refresh_control_after_failure(
            "PSK Authentication failed on link 127.0.0.1:40001: Auth read error"
        ));
        assert!(QuicPoolClient::should_refresh_control_after_failure(
            "QUIC connection failed to 127.0.0.1:40001: the cryptographic handshake failed: error 40: unexpected error: pinned QUIC certificate fingerprint mismatch"
        ));
        assert!(QuicPoolClient::should_refresh_control_after_failure(
            "QUIC connection timed out to 127.0.0.1:40001"
        ));
        assert!(QuicPoolClient::should_refresh_control_after_failure(
            "QUIC connection failed to 127.0.0.1:40001: transport error"
        ));
        assert!(!QuicPoolClient::should_refresh_control_after_failure(
            "No active QUIC connections in pool"
        ));
    }

    #[test]
    fn control_refresh_backoff_blocks_immediate_retry_and_resets_on_success() {
        let client = QuicPoolClient::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            vec!["127.0.0.1:40001".parse().unwrap()],
        );

        assert!(client.control_refresh_allowed_now());
        assert_eq!(
            client.record_control_refresh_failure(),
            CONTROL_REFRESH_INITIAL_BACKOFF
        );
        assert!(!client.control_refresh_allowed_now());
        client.record_control_refresh_success();
        assert!(client.control_refresh_allowed_now());
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
