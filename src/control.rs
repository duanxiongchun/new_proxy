use hmac::{Hmac, Mac};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;
const MAX_CONTROL_WORKERS: usize = 1024;

// 1. 控制面协商协议数据结构
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ControlRequest {
    pub client_nonce: [u8; 16],
    pub client_public_key: [u8; 32],
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ControlResponse {
    pub server_nonce: [u8; 16],
    pub session_psk: [u8; 32],
    pub port_pool: Vec<u16>,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub quic_cert_sha256: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ControlResponseWire {
    pub client_nonce: [u8; 16],
    pub server_nonce: [u8; 16],
    pub port_pool: Vec<u16>,
    pub public_ipv4: Option<String>,
    pub public_ipv6: Option<String>,
    pub quic_cert_sha256: [u8; 32],
}

// 封装带 HMAC 签名的 UDP 数据包
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedPacket {
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

// 计算 HMAC-SHA256 签名
pub fn calculate_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

// 验证 HMAC-SHA256 签名
pub fn verify_mac(key: &[u8; 32], data: &[u8], expected_mac: &[u8; 32]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.verify_slice(expected_mac).is_ok()
}

pub fn derive_session_psk(
    shared_secret: &[u8; 32],
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"new_proxy control session psk v1");
    hasher.update(shared_secret);
    hasher.update(client_nonce);
    hasher.update(server_nonce);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// 2. 客户端控制面协商引擎
pub struct ControlClient {
    client_private_key: [u8; 32],
    server_public_key: [u8; 32],
    server_control_endpoint: SocketAddr,
}

impl ControlClient {
    pub fn new(
        client_private_key: [u8; 32],
        server_public_key: [u8; 32],
        server_control_endpoint: SocketAddr,
    ) -> Self {
        Self {
            client_private_key,
            server_public_key,
            server_control_endpoint,
        }
    }

    // 执行对等 ECDH 认证与配置拉取
    pub async fn negotiate_config(&self) -> Result<(ControlResponse, UdpSocket), String> {
        // 1. 本地计算共享密钥 (X25519 ECDH)
        let client_secret = StaticSecret::from(self.client_private_key);
        let server_pub = PublicKey::from(self.server_public_key);
        let shared_secret = client_secret.diffie_hellman(&server_pub).to_bytes();

        // 2. 绑定本地 UDP 套接字 (根据对端 Endpoint IP 协议簇绑定，以在不同内核默认值下完美解决 IPV6_V6ONLY 限制)
        let socket = if self.server_control_endpoint.is_ipv6() {
            UdpSocket::bind("[::]:0")
                .await
                .map_err(|e| format!("Failed to bind local IPv6 UDP socket: {}", e))?
        } else {
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Failed to bind local IPv4 UDP socket: {}", e))?
        };

        let client_pub_derived = PublicKey::from(&client_secret).to_bytes();

        // 3. UDP 发送并重试循环 (最多重试 4 次)。每次重试都生成新 nonce，
        // 避免“响应丢包后重发同 nonce 被服务端 replay cache 拒绝”。
        let mut attempts = 0;
        let mut buf = [0u8; 2048];

        loop {
            attempts += 1;
            if attempts > 4 {
                return Err(
                    "Failed to negotiate with server: Control connection timeout".to_string(),
                );
            }

            log::info!(
                "Sending control negotiation packet (Attempt {}/4) to {}",
                attempts,
                self.server_control_endpoint
            );
            let mut client_nonce = [0u8; 16];
            rand::thread_rng().fill(&mut client_nonce);
            let req = ControlRequest {
                client_nonce,
                client_public_key: client_pub_derived,
            };
            let payload =
                serde_json::to_vec(&req).map_err(|e| format!("Serialization error: {}", e))?;
            let mac = calculate_mac(&shared_secret, &payload);
            let signed_packet = SignedPacket { payload, mac };
            let packet_bytes = serde_json::to_vec(&signed_packet)
                .map_err(|e| format!("Serialization error: {}", e))?;

            if let Err(e) = socket
                .send_to(&packet_bytes, self.server_control_endpoint)
                .await
            {
                log::warn!("Failed to send UDP packet: {}, retrying...", e);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }

            match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await
            {
                Ok(Ok((len, src_addr))) => {
                    if src_addr != self.server_control_endpoint {
                        continue; // 过滤非服务端的恶意报文
                    }

                    let signed_resp: SignedPacket = match serde_json::from_slice(&buf[..len]) {
                        Ok(p) => p,
                        Err(_) => continue,
                    };

                    // 验证服务端 MAC 签名
                    if !verify_mac(&shared_secret, &signed_resp.payload, &signed_resp.mac) {
                        log::warn!("Received response packet with bad HMAC signature!");
                        continue;
                    }

                    // 反序列化配置
                    let wire: ControlResponseWire = serde_json::from_slice(&signed_resp.payload)
                        .map_err(|e| format!("Failed to parse response: {}", e))?;
                    if wire.client_nonce != client_nonce {
                        log::warn!("Received stale control response for a previous nonce");
                        continue;
                    }
                    let resp = ControlResponse {
                        session_psk: derive_session_psk(
                            &shared_secret,
                            &client_nonce,
                            &wire.server_nonce,
                        ),
                        server_nonce: wire.server_nonce,
                        port_pool: wire.port_pool,
                        public_ipv4: wire.public_ipv4,
                        public_ipv6: wire.public_ipv6,
                        quic_cert_sha256: wire.quic_cert_sha256,
                    };

                    log::info!("Successfully negotiated PSK and received QUIC pool configuration!");
                    return Ok((resp, socket));
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to receive UDP control response: {}, retrying...", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }
}

pub struct NonceCache {
    seen: std::collections::HashSet<[u8; 16]>,
    queue: std::collections::VecDeque<[u8; 16]>,
    capacity: usize,
}

impl NonceCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            queue: std::collections::VecDeque::new(),
            capacity,
        }
    }

    pub fn insert(&mut self, nonce: [u8; 16]) -> bool {
        if self.seen.contains(&nonce) {
            return false;
        }
        if self.queue.len() >= self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.queue.push_back(nonce);
        self.seen.insert(nonce);
        true
    }
}

use std::time::Instant;

struct IpRateLimiter {
    history: Mutex<HashMap<IpAddr, (Instant, f64)>>,
}

impl IpRateLimiter {
    fn new() -> Self {
        Self {
            history: Mutex::new(HashMap::new()),
        }
    }

    fn check_limit(&self, ip: IpAddr) -> bool {
        let mut history = self.history.lock();
        if history.len() > 10000 {
            let now = Instant::now();
            history.retain(|_, (last_seen, _)| now.duration_since(*last_seen).as_secs() < 60);
        }
        let now = Instant::now();
        let (last_seen, tokens) = history.entry(ip).or_insert((now, 10.0));
        let elapsed = now.duration_since(*last_seen).as_secs_f64();
        *last_seen = now;
        *tokens = (*tokens + elapsed * 5.0).min(10.0);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// 3. 服务端控制面协商服务
pub struct ControlServer {
    listen_port: u16,
    pub peer_secrets: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>, // {Client_PublicKey -> Derived_Shared_Secret}
    quic_ports: Vec<u16>,
    public_ipv4: Option<String>,
    public_ipv6: Option<String>,
    quic_cert_sha256: [u8; 32],
    session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>, // {Client_PublicKey -> Session_PSK}
    nonce_cache: Arc<Mutex<NonceCache>>,
    rate_limiter: Arc<IpRateLimiter>,
}

impl ControlServer {
    pub fn new(
        listen_port: u16,
        peer_secrets: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        quic_ports: Vec<u16>,
        public_ipv4: Option<String>,
        public_ipv6: Option<String>,
        quic_cert_sha256: [u8; 32],
        session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    ) -> Self {
        Self {
            listen_port,
            peer_secrets,
            quic_ports,
            public_ipv4,
            public_ipv6,
            quic_cert_sha256,
            session_cache,
            nonce_cache: Arc::new(Mutex::new(NonceCache::new(4096))),
            rate_limiter: Arc::new(IpRateLimiter::new()),
        }
    }

    async fn bind_socket(listen_port: u16) -> Result<UdpSocket, String> {
        let socket = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(sock) => {
                let _ = sock.set_only_v6(false);
                let _ = sock.set_reuse_address(true);
                let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), listen_port);
                if sock.bind(&bind_addr.into()).is_ok() {
                    let std_sock: StdUdpSocket = sock.into();
                    std_sock
                        .set_nonblocking(true)
                        .map_err(|e| format!("Failed to set nonblocking: {}", e))?;
                    UdpSocket::from_std(std_sock)
                        .map_err(|e| format!("Failed to convert to Tokio UdpSocket: {}", e))?
                } else {
                    UdpSocket::bind(format!("0.0.0.0:{}", listen_port))
                        .await
                        .map_err(|e| format!("Server failed to bind control UDP port: {}", e))?
                }
            }
            Err(_) => UdpSocket::bind(format!("0.0.0.0:{}", listen_port))
                .await
                .map_err(|e| format!("Server failed to bind control UDP port: {}", e))?,
        };
        Ok(socket)
    }

    pub async fn start(self) -> Result<tokio::task::JoinHandle<()>, String> {
        let socket = Arc::new(Self::bind_socket(self.listen_port).await?);
        Ok(tokio::spawn(async move {
            if let Err(e) = self.run_loop(socket).await {
                log::error!("Control plane server error: {}", e);
            }
        }))
    }

    // 运行服务端 UDP 监听循环
    #[allow(dead_code)]
    pub async fn run(self) -> Result<(), String> {
        let socket = Arc::new(Self::bind_socket(self.listen_port).await?);
        self.run_loop(socket).await
    }

    async fn run_loop(self, socket: Arc<UdpSocket>) -> Result<(), String> {
        let worker_limit = Arc::new(Semaphore::new(MAX_CONTROL_WORKERS));
        log::info!(
            "Userspace Control Server listening on UDP port {}",
            self.listen_port
        );

        loop {
            let mut buf = [0u8; 2048];
            let (len, client_addr) = match socket.recv_from(&mut buf).await {
                Ok((len, src_addr)) => (len, src_addr),
                Err(e) => {
                    log::warn!("Receive error: {}", e);
                    continue;
                }
            };

            if len == 0 || buf[0] != b'{' || buf[len - 1] != b'}' {
                log::debug!(
                    "Fast discard obviously invalid control packet from {}, len={}",
                    client_addr,
                    len
                );
                continue;
            }

            if !self.rate_limiter.check_limit(client_addr.ip()) {
                log::debug!(
                    "Rate limit exceeded for control packet from {}; dropping.",
                    client_addr
                );
                continue;
            }

            let socket_clone = socket.clone();
            let peer_secrets_clone = self.peer_secrets.clone();
            let session_cache_clone = self.session_cache.clone();
            let nonce_cache_clone = self.nonce_cache.clone();
            let ports_clone = self.quic_ports.clone();
            let v4_clone = self.public_ipv4.clone();
            let v6_clone = self.public_ipv6.clone();
            let quic_cert_sha256 = self.quic_cert_sha256;
            let permit = match worker_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    log::warn!(
                        "Control plane worker limit reached; dropping packet from {}",
                        client_addr
                    );
                    continue;
                }
            };

            tokio::spawn(async move {
                let _permit = permit;
                let signed_packet: SignedPacket = match serde_json::from_slice(&buf[..len]) {
                    Ok(p) => p,
                    Err(_) => return,
                };

                let req: ControlRequest = match serde_json::from_slice(&signed_packet.payload) {
                    Ok(r) => r,
                    Err(_) => return,
                };

                // 1. 查找客户端共享密钥
                let shared_secret = {
                    let guard = peer_secrets_clone.read();
                    guard.get(&req.client_public_key).cloned()
                };
                let shared_secret = match shared_secret {
                    Some(secret) => secret,
                    None => {
                        log::warn!(
                            "Received connection request from unconfigured peer: {:?}",
                            req.client_public_key
                        );
                        return;
                    }
                };

                // 2. 校验 HMAC 签名
                if !verify_mac(&shared_secret, &signed_packet.payload, &signed_packet.mac) {
                    log::warn!("Authentication failed for peer: Bad HMAC signature!");
                    return;
                }

                // 3. 已认证后再记录 nonce，避免未认证流量污染 replay cache。
                {
                    let mut cache = nonce_cache_clone.lock();
                    if !cache.insert(req.client_nonce) {
                        log::warn!(
                            "Replayed ControlRequest detected from peer: {:?}, dropping request.",
                            req.client_public_key
                        );
                        return;
                    }
                }

                // 4. 生成 Session_PSK 与 Response
                let mut server_nonce = [0u8; 16];
                rand::thread_rng().fill(&mut server_nonce);
                let session_psk =
                    derive_session_psk(&shared_secret, &req.client_nonce, &server_nonce);

                // 更新用户态会话缓存
                {
                    let mut cache = session_cache_clone.write();
                    cache.insert(req.client_public_key, session_psk);
                }

                let resp = ControlResponseWire {
                    client_nonce: req.client_nonce,
                    server_nonce,
                    port_pool: ports_clone,
                    public_ipv4: v4_clone,
                    public_ipv6: v6_clone,
                    quic_cert_sha256,
                };

                let resp_payload = serde_json::to_vec(&resp).unwrap();
                let resp_mac = calculate_mac(&shared_secret, &resp_payload);

                let signed_resp = SignedPacket {
                    payload: resp_payload,
                    mac: resp_mac,
                };
                let resp_bytes = serde_json::to_vec(&signed_resp).unwrap();

                // 4. 回复配置
                if let Err(e) = socket_clone.send_to(&resp_bytes, client_addr).await {
                    log::warn!("Failed to send control response to {}: {}", client_addr, e);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_roundtrip() {
        let key = [42u8; 32];
        let payload = b"Hello, Secure Control Plane!";
        let mac = calculate_mac(&key, payload);
        assert!(verify_mac(&key, payload, &mac));

        // Test invalid payload
        assert!(!verify_mac(&key, b"Hello, Secure Control Plane? ", &mac));

        // Test invalid key
        let mut bad_key = key;
        bad_key[0] = 0;
        assert!(!verify_mac(&bad_key, payload, &mac));
    }

    #[tokio::test]
    async fn test_control_negotiation_full() {
        use std::net::{IpAddr, Ipv4Addr};

        // 1. 生成客户端与服务端的 Noise 密钥对
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_pub = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_pub = PublicKey::from(&server_secret);

        // 2. 预计算 Diffie-Hellman 共享密钥
        let server_shared = server_secret.diffie_hellman(&client_pub).to_bytes();

        let peer_secrets = Arc::new(RwLock::new(HashMap::new()));
        peer_secrets
            .write()
            .insert(client_pub.to_bytes(), server_shared);

        let session_cache = Arc::new(RwLock::new(HashMap::new()));

        // 3. 在随机的可用 UDP 端口上拉起 ControlServer
        let server_port = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };

        let server = ControlServer::new(
            server_port,
            peer_secrets.clone(),
            vec![40001, 40002],
            Some("1.2.3.4".to_string()),
            None,
            [3u8; 32],
            session_cache.clone(),
        );

        let server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // 给服务端绑定的时间
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 4. 客户端发起协商请求
        let control_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
        let client = ControlClient::new(
            client_secret.to_bytes(),
            server_pub.to_bytes(),
            control_addr,
        );

        let (resp, _client_socket) = client.negotiate_config().await.unwrap();

        // 5. 校验协商配置结果是否匹配
        assert_eq!(resp.port_pool, vec![40001, 40002]);
        assert_eq!(resp.public_ipv4, Some("1.2.3.4".to_string()));
        assert_eq!(resp.quic_cert_sha256, [3u8; 32]);
        assert!(resp.session_psk != [0u8; 32]);

        // 验证服务端 session cache 里成功缓存了该 session_psk
        let cache = session_cache.read();
        assert_eq!(cache.get(&client_pub.to_bytes()), Some(&resp.session_psk));

        server_task.abort();
    }

    #[tokio::test]
    async fn test_control_server_rejects_bad_hmac_and_replay() {
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let client_pub = PublicKey::from(&client_secret);
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let shared_secret = server_secret.diffie_hellman(&client_pub).to_bytes();

        let peer_secrets = Arc::new(RwLock::new(HashMap::new()));
        peer_secrets
            .write()
            .insert(client_pub.to_bytes(), shared_secret);
        let session_cache = Arc::new(RwLock::new(HashMap::new()));

        let server_port = {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        };
        let server = ControlServer::new(
            server_port,
            peer_secrets,
            vec![40001],
            None,
            None,
            [9u8; 32],
            session_cache.clone(),
        );
        let server_task = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = SocketAddr::new(IpAddr::V4("127.0.0.1".parse().unwrap()), server_port);
        let req = ControlRequest {
            client_nonce: [7u8; 16],
            client_public_key: client_pub.to_bytes(),
        };
        let payload = serde_json::to_vec(&req).unwrap();
        let bad_packet = SignedPacket {
            payload: payload.clone(),
            mac: [0u8; 32],
        };
        socket
            .send_to(&serde_json::to_vec(&bad_packet).unwrap(), server_addr)
            .await
            .unwrap();
        let mut buf = [0u8; 2048];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf))
                .await
                .is_err(),
            "bad HMAC request must not receive a response"
        );
        assert!(session_cache.read().is_empty());

        let good_packet = SignedPacket {
            mac: calculate_mac(&shared_secret, &payload),
            payload,
        };
        let good_bytes = serde_json::to_vec(&good_packet).unwrap();
        socket.send_to(&good_bytes, server_addr).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(serde_json::from_slice::<SignedPacket>(&buf[..len]).is_ok());
        assert!(session_cache.read().contains_key(&client_pub.to_bytes()));

        socket.send_to(&good_bytes, server_addr).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf))
                .await
                .is_err(),
            "replayed nonce must not receive a second response"
        );

        server_task.abort();
    }

    #[tokio::test]
    async fn test_control_client_rejects_stale_nonce_response() {
        let client_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let server_pub = PublicKey::from(&server_secret);
        let shared_secret = client_secret.diffie_hellman(&server_pub).to_bytes();

        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, client_addr)) = server_socket.recv_from(&mut buf).await {
                let signed_req: SignedPacket = serde_json::from_slice(&buf[..len]).unwrap();
                assert!(verify_mac(
                    &shared_secret,
                    &signed_req.payload,
                    &signed_req.mac
                ));
                let wire = ControlResponseWire {
                    client_nonce: [0u8; 16],
                    server_nonce: [1u8; 16],
                    port_pool: vec![40001],
                    public_ipv4: None,
                    public_ipv6: None,
                    quic_cert_sha256: [2u8; 32],
                };
                let payload = serde_json::to_vec(&wire).unwrap();
                let resp = SignedPacket {
                    mac: calculate_mac(&shared_secret, &payload),
                    payload,
                };
                let _ = server_socket
                    .send_to(&serde_json::to_vec(&resp).unwrap(), client_addr)
                    .await;
            }
        });

        let client =
            ControlClient::new(client_secret.to_bytes(), server_pub.to_bytes(), server_addr);
        let err = client.negotiate_config().await.unwrap_err();
        assert!(err.contains("timeout"));
        responder.abort();
    }
}
