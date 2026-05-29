mod config;
mod routing;
mod control;
mod quic_pool;
mod relay;
mod tproxy;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use serde::{Serialize, Deserialize};
use x25519_dalek::{PublicKey, StaticSecret};

use config::{GatewayConfig, decode_base64_32};
use routing::AllowedIPsRouter;
use control::{ControlServer, ControlClient};
use quic_pool::{QuicPoolServer, QuicPoolClient, QuicConnSnapshot};
use relay::PeerL4Stats;

// 统一的 L3/L4 遥测聚合数据结构 (用于 CLI 输出与 UDS JSON 传递)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnifiedTelemetry {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    // L3 内核 WireGuard 统计
    pub l3_rx_bytes: u64,
    pub l3_tx_bytes: u64,
    pub last_handshake: u64,
    // L4 用户态 QUIC 聚合统计
    pub l4_rx_bytes: u64,
    pub l4_tx_bytes: u64,
    pub active_streams: u64,
    // 每条物理 QUIC 连接的独立统计（无代理时为空）
    pub quic_connections: Vec<QuicConnSnapshot>,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct WgPeerStats {
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: u64,
}

// Unix Domain Socket API 请求指令结构 (支持 CLI 动态管理)
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum CommandInput {
    Stats,
    Dump,
    AddPeer {
        public_key: String,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
        proxy_port: Option<u16>,
    },
    RemovePeer {
        public_key: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse {
    pub status: String,
    pub message: Option<String>,
}

// 动态网关共享运行时状态 (支持 AllowedIPs 路由基数树热重载)
pub struct GatewayState {
    pub config: GatewayConfig,
    pub router: AllowedIPsRouter<[u8; 32]>,
}

// 用户态 L4 (QUIC) 遥测注册中心
const TELEMETRY_SHARDS: usize = 64;

pub struct TelemetryRegistry {
    stats: Vec<Mutex<HashMap<[u8; 32], Arc<PeerL4Stats>>>>,
}

impl TelemetryRegistry {
    pub fn new() -> Self {
        let mut stats = Vec::with_capacity(TELEMETRY_SHARDS);
        for _ in 0..TELEMETRY_SHARDS {
            stats.push(Mutex::new(HashMap::new()));
        }
        Self {
            stats,
        }
    }

    pub fn get_or_create(&self, pub_key: [u8; 32]) -> Arc<PeerL4Stats> {
        let mut map = self.stats[self.shard_index(&pub_key)].lock().unwrap();
        map.entry(pub_key).or_insert_with(|| Arc::new(PeerL4Stats::default())).clone()
    }

    pub fn snapshot(&self) -> HashMap<[u8; 32], Arc<PeerL4Stats>> {
        let mut snapshot = HashMap::new();
        for shard in &self.stats {
            let map = shard.lock().unwrap();
            snapshot.extend(map.iter().map(|(k, v)| (*k, v.clone())));
        }
        snapshot
    }

    fn shard_index(&self, pub_key: &[u8; 32]) -> usize {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&pub_key[..8]);
        (u64::from_le_bytes(bytes) as usize) % self.stats.len()
    }
}

// 极其高效轻量内置的 Base64 编码器
pub fn encode_base64_32(bytes: &[u8; 32]) -> String {
    let mut out = String::new();
    let mut temp = 0u32;
    let mut bits = 0;
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    for &b in bytes {
        temp = (temp << 8) | b as u32;
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(chars[((temp >> bits) & 0x3F) as usize] as char);
        }
    }
    if bits > 0 {
        temp <<= 6 - bits;
        out.push(chars[(temp & 0x3F) as usize] as char);
    }
    while out.len() % 4 != 0 {
        out.push('=');
    }
    out
}

fn set_tcp_keepalive(socket: &tokio::net::TcpStream) -> std::io::Result<()> {
    let socket_ref = socket2::SockRef::from(socket);
    let mut keepalive = socket2::TcpKeepalive::new();
    keepalive = keepalive.with_time(Duration::from_secs(60));
    keepalive = keepalive.with_interval(Duration::from_secs(10));
    socket_ref.set_tcp_keepalive(&keepalive)?;
    Ok(())
}

// 目标地址代理协议头部编解码辅助函数
pub async fn write_target_addr<W: AsyncWrite + Unpin>(w: &mut W, addr: SocketAddr) -> std::io::Result<()> {
    match addr.ip() {
        IpAddr::V4(ipv4) => {
            w.write_all(&[0]).await?;
            w.write_all(&ipv4.octets()).await?;
        }
        IpAddr::V6(ipv6) => {
            w.write_all(&[1]).await?;
            w.write_all(&ipv6.octets()).await?;
        }
    }
    w.write_u16(addr.port()).await?;
    Ok(())
}

pub async fn read_target_addr<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<SocketAddr> {
    let addr_type = r.read_u8().await?;
    let ip = match addr_type {
        0 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        1 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid address type")),
    };
    let port = r.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

// 通过内核 WireGuard 命令行工具按需拉取 L3 流量统计
pub async fn get_wg_dump_stats(interface: &str) -> Result<HashMap<[u8; 32], WgPeerStats>, String> {
    let interface = interface.to_string();
    tokio::task::spawn_blocking(move || get_wg_dump_stats_blocking(&interface))
        .await
        .map_err(|e| format!("Failed to join wg dump worker: {}", e))?
}

fn get_wg_dump_stats_blocking(interface: &str) -> Result<HashMap<[u8; 32], WgPeerStats>, String> {
    let output = match std::process::Command::new("wg")
        .args(["show", interface, "dump"])
        .output() {
            Ok(out) => out,
            Err(_) => return Ok(HashMap::new()), // 优雅降级：若系统未安装 wg CLI，则返回空指标
        };
    
    if !output.status.success() {
        return Ok(HashMap::new());
    }
    
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let mut stats = HashMap::new();
    
    for line in stdout_str.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 8 {
            let peer_pub_b64 = parts[0];
            let endpoint = if parts[2] == "(none)" || parts[2].is_empty() {
                None
            } else {
                Some(parts[2].to_string())
            };
            let allowed_ips = if parts[3] == "(none)" || parts[3].is_empty() {
                Vec::new()
            } else {
                parts[3].split(',').map(|s| s.trim().to_string()).collect()
            };
            let latest_handshake: u64 = parts[4].parse().unwrap_or(0);
            let rx_bytes: u64 = parts[5].parse().unwrap_or(0);
            let tx_bytes: u64 = parts[6].parse().unwrap_or(0);
            
            if let Ok(pub_key) = decode_base64_32(peer_pub_b64) {
                stats.insert(pub_key, WgPeerStats {
                    allowed_ips,
                    endpoint,
                    rx_bytes,
                    tx_bytes,
                    last_handshake: latest_handshake,
                });
            }
        }
    }
    Ok(stats)
}

async fn run_tproxy_accept_loop(
    listener: TcpListener,
    quic_pool: Arc<QuicPoolClient>,
    state: Arc<std::sync::RwLock<GatewayState>>,
    telemetry: Arc<TelemetryRegistry>,
) {
    while let Ok((tcp_socket, src_addr)) = listener.accept().await {
        let quic_pool = quic_pool.clone();
        let state = state.clone();
        let telemetry = telemetry.clone();
        tokio::spawn(async move {
            handle_tproxy_connection(tcp_socket, src_addr, quic_pool, state, telemetry).await;
        });
    }
}

async fn handle_tproxy_connection(
    tcp_socket: TcpStream,
    src_addr: SocketAddr,
    quic_pool: Arc<QuicPoolClient>,
    state: Arc<std::sync::RwLock<GatewayState>>,
    telemetry: Arc<TelemetryRegistry>,
) {
    if let Err(e) = set_tcp_keepalive(&tcp_socket) {
        log::warn!("Failed to set TCP Keep-Alive on TPROXY socket: {}", e);
    }

    let original_dst = match tcp_socket.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            log::warn!("Failed to retrieve original destination for intercepted connection: {}", e);
            return;
        }
    };

    let matched = {
        let st = state.read().unwrap();
        st.router.longest_match(original_dst.ip()).is_some()
    };

    if matched {
        log::info!("Intercepted TCP stream from {} -> {}, matched AllowedIPs. Offloading to QUIC.", src_addr, original_dst);

        let (mut quic_send, mut quic_recv, conn_stat) = match quic_pool.open_mux_stream().await {
            Ok(stream) => stream,
            Err(e) => {
                log::warn!("Failed to open parallel multiplexed QUIC stream: {}", e);
                return;
            }
        };

        if write_target_addr(&mut quic_send, original_dst).await.is_err() {
            return;
        }

        let mut status = [0u8; 1];
        match timeout(Duration::from_secs(5), quic_recv.read_exact(&mut status)).await {
            Ok(Ok(_)) if status[0] == 1 => {}
            Ok(Ok(_)) => {
                log::warn!("Server side rejected proxy endpoint {}", original_dst);
                return;
            }
            Ok(Err(e)) => {
                log::warn!("Failed to read server proxy status for {}: {}", original_dst, e);
                return;
            }
            Err(_) => {
                log::warn!("Timed out waiting for server proxy status for {}", original_dst);
                return;
            }
        }

        let server_pub_key = {
            let st = state.read().unwrap();
            st.config.peers.first().map(|p| p.public_key)
        };

        let stats = if let Some(pub_key) = server_pub_key {
            telemetry.get_or_create(pub_key)
        } else {
            Arc::new(PeerL4Stats::default())
        };

        relay::relay_connections_with_conn_stat(
            tcp_socket,
            quic_send,
            quic_recv,
            stats,
            conn_stat,
        ).await;
    } else {
        log::debug!("Intercepted connection to {} does not match AllowedIPs. Dropped.", original_dst);
    }
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to listen for SIGINT");
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to listen for SIGTERM");
    tokio::select! {
        _ = sigint.recv() => {
            log::info!("Received SIGINT, shutting down...");
        }
        _ = sigterm.recv() => {
            log::info!("Received SIGTERM, shutting down...");
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl_c");
    log::info!("Received CTRL+C, shutting down...");
}

fn run_command_silently(cmd: &str) {
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output();
}

fn run_script(script: &str) {
    log::info!("Executing script: {}", script);
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output();
    match output {
        Ok(out) => {
            if !out.status.success() {
                log::warn!("Script exited with error: {:?}", out.status);
                log::warn!("Script stdout: {}", String::from_utf8_lossy(&out.stdout));
                log::warn!("Script stderr: {}", String::from_utf8_lossy(&out.stderr));
            } else {
                log::info!("Script completed successfully.");
            }
        }
        Err(e) => {
            log::error!("Failed to execute script '{}': {}", script, e);
        }
    }
}

fn setup_routes_and_iptables(config: &GatewayConfig, config_path: &str) {
    if let Some(ref t) = config.interface.table {
        if t.to_lowercase() == "off" {
            log::info!("Table is off. Skipping automatic routing and iptables setup.");
            return;
        }
    }

    // Determine interface name from config path, defaulting to "tun0"
    let interface_name = std::path::Path::new(config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("tun0")
        .to_string();

    log::info!("Setting up automatic routing and iptables for interface: {}", interface_name);

    // 1. Add addresses to the tun interface
    for addr in &config.interface.addresses {
        let cmd = format!("ip addr add {} dev {}", addr, interface_name);
        run_command_silently(&cmd);
    }
    
    // Set interface UP
    run_command_silently(&format!("ip link set {} up", interface_name));

    // 2. Add routes for AllowedIPs of all peers
    for peer in &config.peers {
        for allowed_ip in &peer.allowed_ips {
            let cmd = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                format!("ip route add {} dev {}", allowed_ip, interface_name)
            } else {
                format!("ip -6 route add {} dev {}", allowed_ip, interface_name)
            };
            run_command_silently(&cmd);
        }
    }

    // 3. Configure TPROXY iptables rules if TProxyPort is set
    if let Some(tproxy_port) = config.interface.tproxy_port {
        log::info!("Setting up TPROXY iptables rules on port {}", tproxy_port);

        // IPv4 policy routing & local route
        run_command_silently("ip rule add fwmark 1 lookup 100");
        run_command_silently("ip route add local 0.0.0.0/0 dev lo table 100");

        // IPv6 policy routing & local route
        run_command_silently("ip -6 rule add fwmark 1 lookup 100");
        run_command_silently("ip -6 route add local ::/0 dev lo table 100");

        // Add PREROUTING rules for each AllowedIP
        for peer in &config.peers {
            for allowed_ip in &peer.allowed_ips {
                if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                    let cmd = format!(
                        "iptables -t mangle -A PREROUTING -p tcp -d {} -j TPROXY --on-port {} --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1",
                        allowed_ip,
                        tproxy_port
                    );
                    run_command_silently(&cmd);
                } else {
                    let cmd = format!(
                        "ip6tables -t mangle -A PREROUTING -p tcp -d {} -j TPROXY --on-port {} --on-ip :: --tproxy-mark 0x1/0x1",
                        allowed_ip,
                        tproxy_port
                    );
                    run_command_silently(&cmd);
                }
            }
        }
    }
}

fn cleanup_routes_and_iptables(config: &GatewayConfig, config_path: &str) {
    if let Some(ref t) = config.interface.table {
        if t.to_lowercase() == "off" {
            return;
        }
    }

    let interface_name = std::path::Path::new(config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("tun0")
        .to_string();

    log::info!("Cleaning up automatic routing and iptables for interface: {}", interface_name);

    // 1. Remove TPROXY iptables rules if TProxyPort is set
    if let Some(tproxy_port) = config.interface.tproxy_port {
        log::info!("Tearing down TPROXY iptables rules on port {}", tproxy_port);

        for peer in &config.peers {
            for allowed_ip in &peer.allowed_ips {
                if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                    let cmd = format!(
                        "iptables -t mangle -D PREROUTING -p tcp -d {} -j TPROXY --on-port {} --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1",
                        allowed_ip,
                        tproxy_port
                    );
                    run_command_silently(&cmd);
                } else {
                    let cmd = format!(
                        "ip6tables -t mangle -D PREROUTING -p tcp -d {} -j TPROXY --on-port {} --on-ip :: --tproxy-mark 0x1/0x1",
                        allowed_ip,
                        tproxy_port
                    );
                    run_command_silently(&cmd);
                }
            }
        }

        // Clean up policy routing & local routes
        run_command_silently("ip rule del fwmark 1 lookup 100");
        run_command_silently("ip route del local 0.0.0.0/0 dev lo table 100");
        run_command_silently("ip -6 rule del fwmark 1 lookup 100");
        run_command_silently("ip -6 route del local ::/0 dev lo table 100");
    }
}

async fn sync_kernel_and_proxy_state(
    interface_name: &str,
    state: &Arc<std::sync::RwLock<GatewayState>>,
    peer_secrets: &Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
    server_secret: &StaticSecret,
    l3_stats: &HashMap<[u8; 32], WgPeerStats>,
) -> HashMap<[u8; 32], String> {
    let mut sources = HashMap::new();
    let mut peers_to_sync_to_kernel = Vec::new();
    let mut peers_to_sync_to_proxy = Vec::new();

    // 1. Identify sources and find peers missing in kernel
    {
        let st = state.read().unwrap();
        for peer in &st.config.peers {
            if l3_stats.contains_key(&peer.public_key) {
                sources.insert(peer.public_key, "both".to_string());
            } else {
                sources.insert(peer.public_key, "proxy".to_string());
                peers_to_sync_to_kernel.push(peer.clone());
            }
        }
    }

    // 2. Identify peers missing in proxy config
    for (&pub_key, wg_stats) in l3_stats {
        if !sources.contains_key(&pub_key) {
            sources.insert(pub_key, "kernel".to_string());
            peers_to_sync_to_proxy.push((pub_key, wg_stats.clone()));
        }
    }

    // 3. Perform synchronization to kernel (wg CLI)
    for peer in peers_to_sync_to_kernel {
        let pub_key_b64 = encode_base64_32(&peer.public_key);
        let allowed_ips_str = peer.allowed_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(",");
        let mut args = vec![
            "set".to_string(),
            interface_name.to_string(),
            "peer".to_string(),
            pub_key_b64,
            "allowed-ips".to_string(),
            allowed_ips_str,
        ];
        if let Some(endpoint) = peer.endpoint {
            args.push("endpoint".to_string());
            args.push(endpoint.to_string());
        }
        let _ = std::process::Command::new("wg")
            .args(&args)
            .output();
    }

    // 4. Perform synchronization to proxy (GatewayState peers & Trie router & peer_secrets)
    for (pub_key, wg_stats) in peers_to_sync_to_proxy {
        // Generates and caches the DH shared secret
        let peer_pub = PublicKey::from(pub_key);
        let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
        peer_secrets.lock().unwrap().insert(pub_key, shared_secret);

        let mut parsed_allowed_ips = Vec::new();
        for ip_str in &wg_stats.allowed_ips {
            if let Ok(ipnet) = std::str::FromStr::from_str(ip_str) {
                parsed_allowed_ips.push(ipnet);
            }
        }
        let parsed_endpoint = wg_stats.endpoint.as_ref().and_then(|s| std::str::FromStr::from_str(s).ok());

        {
            let mut st = state.write().unwrap();
            st.config.peers.retain(|p| p.public_key != pub_key);
            st.config.peers.push(config::PeerConfig {
                public_key: pub_key,
                allowed_ips: parsed_allowed_ips,
                endpoint: parsed_endpoint,
                proxy_port: Some(51821),
            });
            // Hot-rebuild allowed IPs Trie router
            let mut new_router = AllowedIPsRouter::new();
            for p in &st.config.peers {
                for &allowed_ip in &p.allowed_ips {
                    new_router.insert(allowed_ip, p.public_key);
                }
            }
            st.router = new_router;
        }
    }

    sources
}


#[tokio::main]
async fn main() {
    // 初始化日志系统
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    
    // CLI 遥测展示
    if args.len() > 1 && args[1] == "stats" {
        if let Err(e) = run_cli_stats().await {
            eprintln!("Error query stats: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let mut config_path = "proxy.conf".to_string();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-config" && i + 1 < args.len() {
            config_path = args[i + 1].clone();
            i += 2;
        } else {
            i += 1;
        }
    }

    log::info!("Loading hybrid secure proxy gateway configuration: {}", config_path);
    let config = match GatewayConfig::load_from_file(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to parse config {}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    let interface_name = std::path::Path::new(&config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("tun0")
        .to_string();

    // 执行 PreScript 脚本
    if let Some(ref pre_script) = config.interface.pre_script {
        run_script(pre_script);
    }

    // 自动配置路由与 iptables
    setup_routes_and_iptables(&config, &config_path);

    // 共享遥测注册中心与运行时共享状态初始化
    let telemetry_registry = Arc::new(TelemetryRegistry::new());
    
    let mut initial_router = AllowedIPsRouter::new();
    for peer in &config.peers {
        for &allowed_ip in &peer.allowed_ips {
            initial_router.insert(allowed_ip, peer.public_key);
        }
    }
    
    let gateway_state = Arc::new(std::sync::RwLock::new(GatewayState {
        config: config.clone(),
        router: initial_router,
    }));

    // 初始化控制面 Peer Secrets 动态共享哈希表
    let peer_secrets = Arc::new(Mutex::new(HashMap::new()));
    let server_secret = StaticSecret::from(config.interface.private_key);
    {
        let mut secrets_guard = peer_secrets.lock().unwrap();
        for peer in &config.peers {
            let peer_pub = PublicKey::from(peer.public_key);
            let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
            secrets_guard.insert(peer.public_key, shared_secret);
        }
    }

    // 智能自适应识别网关运行模式 (Server vs. Client)
    let is_server = config.interface.listen_control_port.is_some() || !config.quic_pool.listen_ports.is_empty();

    // 运行在后台的 Unix Domain Socket API 服务器，处理动态命令与 stats 遥测
    // 采用分立设计：服务端监听默认路径以供 CLI 直接查询，客户端监听独立路径，防止启动时相互覆盖套接字文件
    let uds_path = if is_server {
        "/tmp/new_proxy_api.sock"
    } else {
        "/tmp/new_proxy_api_client.sock"
    };
    let _ = std::fs::remove_file(uds_path);
    let uds_listener = match tokio::net::UnixListener::bind(uds_path) {
        Ok(l) => Some(l),
        Err(e) => {
            log::warn!("Failed to bind API UDS socket: {}. Telemetry query CLI will be disabled.", e);
            None
        }
    };

    // 共享的 QUIC peer 连接注册表：
    // - server 模式下由 QuicPoolServer.run_with_registry 填充
    // - client 模式下不使用，始终为空
    let shared_quic_registry: quic_pool::PeerConnRegistry = Arc::new(Mutex::new(std::collections::HashMap::new()));

    if let Some(uds) = uds_listener {
        let telemetry_clone = telemetry_registry.clone();
        let state_clone = gateway_state.clone();
        let peer_secrets_clone = peer_secrets.clone();
        let server_secret_clone = server_secret.clone();
        let shared_quic_registry_uds = shared_quic_registry.clone();
        let interface_name_clone = interface_name.clone();
        
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = uds.accept().await {
                let telemetry = telemetry_clone.clone();
                let state = state_clone.clone();
                let peer_secrets = peer_secrets_clone.clone();
                let server_secret = server_secret_clone.clone();
                let shared_quic_registry = shared_quic_registry_uds.clone();
                let interface_name = interface_name_clone.clone();
                
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut temp = [0u8; 1024];
                    const MAX_UDS_PAYLOAD: usize = 65536; // 64KB
                    const UDS_READ_TIMEOUT: Duration = Duration::from_secs(2);

                    let read_result = timeout(UDS_READ_TIMEOUT, async {
                        loop {
                            match stream.read(&mut temp).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    buf.extend_from_slice(&temp[..n]);
                                    if buf.len() > MAX_UDS_PAYLOAD {
                                        return Err("Payload too large");
                                    }
                                    if let Ok(_) = serde_json::from_slice::<serde_json::Value>(&buf) {
                                        break;
                                    }
                                }
                                Err(_) => return Err("Read error"),
                            }
                        }
                        Ok(())
                    }).await;

                    if read_result.is_err() || read_result.unwrap().is_err() {
                        return;
                    }

                    let cmd: CommandInput = match serde_json::from_slice(&buf) {
                        Ok(c) => c,
                        Err(e) => {
                            let resp = ApiResponse { status: "Error".to_string(), message: Some(format!("Invalid request JSON: {}", e)) };
                            let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                            return;
                        }
                    };

                    match cmd {
                        CommandInput::Stats => {
                            let l3_stats = get_wg_dump_stats(&interface_name).await.unwrap_or_default();
                            let sources = sync_kernel_and_proxy_state(
                                &interface_name,
                                &state,
                                &peer_secrets,
                                &server_secret,
                                &l3_stats,
                            ).await;
                            let aggregated = {
                                let mut aggregated = Vec::new();
                                let mut seen = HashSet::new();
                                let peers = {
                                    let st = state.read().unwrap();
                                    st.config.peers.clone()
                                };
                                let registry_map = telemetry.snapshot();
                                // 从共享的 QUIC 连接注册表获取每连接统计
                                let quic_registry = shared_quic_registry.lock().unwrap();
                                
                                for peer in peers {
                                    let pub_key = peer.public_key;
                                    let pub_key_b64 = encode_base64_32(&pub_key);
                                    
                                    let wg_stats = l3_stats.get(&pub_key);
                                    let l3_rx = wg_stats.map(|s| s.rx_bytes).unwrap_or(0);
                                    let l3_tx = wg_stats.map(|s| s.tx_bytes).unwrap_or(0);
                                    let handshake = wg_stats.map(|s| s.last_handshake).unwrap_or(0);
                                    
                                    // 从聚合注册表获取 L4 总量
                                    let (l4_rx, l4_tx, active_streams) = if let Some(stats) = registry_map.get(&pub_key) {
                                        (
                                            stats.rx_bytes.load(Ordering::Relaxed),
                                            stats.tx_bytes.load(Ordering::Relaxed),
                                            stats.active_streams.load(Ordering::Relaxed),
                                        )
                                    } else {
                                        (0, 0, 0)
                                    };
                                    
                                    // 从 peer_conn_registry 获取每条物理 QUIC 连接的快照
                                    let quic_connections = quic_registry
                                        .get(&pub_key)
                                        .map(|conns| conns.iter().map(|c| c.snapshot()).collect())
                                        .unwrap_or_default();
                                    
                                    let endpoint = peer.endpoint
                                        .map(|a| a.to_string())
                                        .or_else(|| wg_stats.and_then(|s| s.endpoint.clone()));
                                    let allowed_ips = if peer.allowed_ips.is_empty() {
                                        wg_stats.map(|s| s.allowed_ips.clone()).unwrap_or_default()
                                    } else {
                                        peer.allowed_ips.iter().map(|ip| ip.to_string()).collect()
                                    };
                                    
                                    let source = sources
                                        .get(&pub_key)
                                        .cloned()
                                        .unwrap_or_else(|| "both".to_string());
                                    
                                    aggregated.push(UnifiedTelemetry {
                                        public_key: pub_key_b64,
                                        allowed_ips,
                                        endpoint,
                                        l3_rx_bytes: l3_rx,
                                        l3_tx_bytes: l3_tx,
                                        last_handshake: handshake,
                                        l4_rx_bytes: l4_rx,
                                        l4_tx_bytes: l4_tx,
                                        active_streams,
                                        quic_connections,
                                        source,
                                    });
                                    seen.insert(pub_key);
                                }

                                // 标准 WireGuard 客户端可能只存在于内核 wg dump 中，没有 QUIC 代理运行态。
                                for (pub_key, wg_stats) in &l3_stats {
                                    if seen.contains(pub_key) {
                                        continue;
                                    }

                                    let (l4_rx, l4_tx, active_streams) = if let Some(stats) = registry_map.get(pub_key) {
                                        (
                                            stats.rx_bytes.load(Ordering::Relaxed),
                                            stats.tx_bytes.load(Ordering::Relaxed),
                                            stats.active_streams.load(Ordering::Relaxed),
                                        )
                                    } else {
                                        (0, 0, 0)
                                    };
                                    let quic_connections = quic_registry
                                        .get(pub_key)
                                        .map(|conns| conns.iter().map(|c| c.snapshot()).collect())
                                        .unwrap_or_default();

                                    let source = sources
                                        .get(pub_key)
                                        .cloned()
                                        .unwrap_or_else(|| "kernel".to_string());

                                    aggregated.push(UnifiedTelemetry {
                                        public_key: encode_base64_32(pub_key),
                                        allowed_ips: wg_stats.allowed_ips.clone(),
                                        endpoint: wg_stats.endpoint.clone(),
                                        l3_rx_bytes: wg_stats.rx_bytes,
                                        l3_tx_bytes: wg_stats.tx_bytes,
                                        last_handshake: wg_stats.last_handshake,
                                        l4_rx_bytes: l4_rx,
                                        l4_tx_bytes: l4_tx,
                                        active_streams,
                                        quic_connections,
                                        source,
                                    });
                                    seen.insert(*pub_key);
                                }

                                // 极端情况下 QUIC registry 里存在已认证连接，但该 peer 不在配置或 wg dump 中，也要展示。
                                for pub_key in quic_registry.keys() {
                                    if seen.contains(pub_key) {
                                        continue;
                                    }

                                    let (l4_rx, l4_tx, active_streams) = if let Some(stats) = registry_map.get(pub_key) {
                                        (
                                            stats.rx_bytes.load(Ordering::Relaxed),
                                            stats.tx_bytes.load(Ordering::Relaxed),
                                            stats.active_streams.load(Ordering::Relaxed),
                                        )
                                    } else {
                                        (0, 0, 0)
                                    };
                                    let quic_connections = quic_registry
                                        .get(pub_key)
                                        .map(|conns| conns.iter().map(|c| c.snapshot()).collect())
                                        .unwrap_or_default();

                                    let source = sources
                                        .get(pub_key)
                                        .cloned()
                                        .unwrap_or_else(|| "proxy".to_string());

                                    aggregated.push(UnifiedTelemetry {
                                        public_key: encode_base64_32(pub_key),
                                        allowed_ips: Vec::new(),
                                        endpoint: None,
                                        l3_rx_bytes: 0,
                                        l3_tx_bytes: 0,
                                        last_handshake: 0,
                                        l4_rx_bytes: l4_rx,
                                        l4_tx_bytes: l4_tx,
                                        active_streams,
                                        quic_connections,
                                        source,
                                    });
                                }
                                aggregated
                            };
                            let _ = stream.write_all(&serde_json::to_vec(&aggregated).unwrap()).await;
                        }
                        CommandInput::Dump => {
                            let l3_stats = get_wg_dump_stats(&interface_name).await.unwrap_or_default();
                            let response = {
                                let telemetry = telemetry.snapshot();
                                let quic_registry = shared_quic_registry.lock().unwrap();
                                let mut keys = HashSet::new();
                                keys.extend(l3_stats.keys().copied());
                                keys.extend(telemetry.keys().copied());
                                keys.extend(quic_registry.keys().copied());

                                let mut lines = Vec::new();
                                for key in keys {
                                    let wg = l3_stats.get(&key);
                                    let l4 = telemetry.get(&key);
                                    let l4_rx = l4.map(|s| s.rx_bytes.load(Ordering::Relaxed)).unwrap_or(0);
                                    let l4_tx = l4.map(|s| s.tx_bytes.load(Ordering::Relaxed)).unwrap_or(0);
                                    let active_streams = l4.map(|s| s.active_streams.load(Ordering::Relaxed)).unwrap_or(0);
                                    let quic_connections = quic_registry.get(&key).map(|c| c.len()).unwrap_or(0);
                                    lines.push(format!(
                                        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                                        encode_base64_32(&key),
                                        wg.and_then(|s| s.endpoint.clone()).unwrap_or_else(|| "(none)".to_string()),
                                        wg.map(|s| s.allowed_ips.join(",")).filter(|s| !s.is_empty()).unwrap_or_else(|| "(none)".to_string()),
                                        wg.map(|s| s.last_handshake).unwrap_or(0),
                                        wg.map(|s| s.rx_bytes).unwrap_or(0),
                                        wg.map(|s| s.tx_bytes).unwrap_or(0),
                                        l4_rx + l4_tx,
                                        format!("{}:{}", quic_connections, active_streams),
                                    ));
                                }
                                lines.sort();
                                lines.join("\n")
                            };
                            let _ = stream.write_all(response.as_bytes()).await;
                        }
                        CommandInput::AddPeer { public_key, allowed_ips, endpoint, proxy_port } => {
                            let parsed_pub_key = match decode_base64_32(&public_key) {
                                Ok(k) => k,
                                Err(e) => {
                                    let resp = ApiResponse { status: "Error".to_string(), message: Some(format!("Invalid public key: {}", e)) };
                                    let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                                    return;
                                }
                            };
                            
                            let mut parsed_allowed_ips = Vec::new();
                            for ip_str in allowed_ips {
                                match std::str::FromStr::from_str(&ip_str) {
                                    Ok(ipnet) => parsed_allowed_ips.push(ipnet),
                                    Err(e) => {
                                        let resp = ApiResponse { status: "Error".to_string(), message: Some(format!("Invalid allowed IP: {}", e)) };
                                        let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                                        return;
                                    }
                                }
                            }
                            
                            let parsed_endpoint = match endpoint {
                                Some(ep_str) => match std::str::FromStr::from_str(&ep_str) {
                                    Ok(addr) => Some(addr),
                                    Err(e) => {
                                        let resp = ApiResponse { status: "Error".to_string(), message: Some(format!("Invalid endpoint: {}", e)) };
                                        let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                                        return;
                                    }
                                }
                                None => None,
                            };

                            // 1. 动态生成并缓存 Diffie-Hellman 共享密钥
                            let peer_pub = PublicKey::from(parsed_pub_key);
                            let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
                            peer_secrets.lock().unwrap().insert(parsed_pub_key, shared_secret);

                            // 2. 动态更新 AllowedIPs 路由树与 peers 配置
                            {
                                let mut st = state.write().unwrap();
                                st.config.peers.retain(|p| p.public_key != parsed_pub_key);
                                st.config.peers.push(config::PeerConfig {
                                    public_key: parsed_pub_key,
                                    allowed_ips: parsed_allowed_ips,
                                    endpoint: parsed_endpoint,
                                    proxy_port,
                                });
                                // 热重构 Trie
                                let mut new_router = AllowedIPsRouter::new();
                                for p in &st.config.peers {
                                    for &allowed_ip in &p.allowed_ips {
                                        new_router.insert(allowed_ip, p.public_key);
                                    }
                                }
                                st.router = new_router;
                            }

                            let resp = ApiResponse { status: "Ok".to_string(), message: None };
                            let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                        }
                        CommandInput::RemovePeer { public_key } => {
                            let parsed_pub_key = match decode_base64_32(&public_key) {
                                Ok(k) => k,
                                Err(e) => {
                                    let resp = ApiResponse { status: "Error".to_string(), message: Some(format!("Invalid public key: {}", e)) };
                                    let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                                    return;
                                }
                            };

                            // 1. 动态移除 Shared Secret
                            peer_secrets.lock().unwrap().remove(&parsed_pub_key);

                            // 2. 动态移除 AllowedIPs 路由
                            {
                                let mut st = state.write().unwrap();
                                st.config.peers.retain(|p| p.public_key != parsed_pub_key);
                                // 热重构 Trie
                                let mut new_router = AllowedIPsRouter::new();
                                for p in &st.config.peers {
                                    for &allowed_ip in &p.allowed_ips {
                                        new_router.insert(allowed_ip, p.public_key);
                                    }
                                }
                                st.router = new_router;
                            }

                            let resp = ApiResponse { status: "Ok".to_string(), message: None };
                            let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                        }
                    }
                });
            }
        });
    }

    if is_server {
        log::info!("------------------------------------------------------");
        log::info!("         STARTING GATEWAY IN [ SERVER MODE ]         ");
        log::info!("------------------------------------------------------");

        let listen_control_port = config.interface.listen_control_port.expect("Missing ListenControlPort for Server mode");
        let session_cache = Arc::new(Mutex::new(HashMap::new()));

        // 启动用户态独立公网控制通道协商服务器 (传递动态 peer_secrets 哈希表)
        let control_server = ControlServer::new(
            listen_control_port,
            peer_secrets.clone(),
            config.quic_pool.listen_ports.clone(),
            config.quic_pool.public_ipv4.clone(),
            config.quic_pool.public_ipv6.clone(),
            session_cache.clone(),
        );

        tokio::spawn(async move {
            if let Err(e) = control_server.run().await {
                log::error!("Control plane server error: {}", e);
            }
        });

        // 启动用户态多路复用平行 QUIC 物理池接收服务器
        let quic_server = QuicPoolServer::new(
            config.quic_pool.listen_ports.clone(),
            session_cache.clone(),
        );
        // 删除多余的锁操作（shared_quic_registry 与 server 内部 registry 已通过 run_with_registry 共享）
        let telemetry_for_handler = telemetry_registry.clone();
        let shared_reg_for_server = shared_quic_registry.clone();
        let quic_run_task = tokio::spawn(async move {
            let handler = Arc::new(move |client_pub: [u8; 32], mut send_mux: quinn::SendStream, mut recv_mux: quinn::RecvStream, conn_stat: Arc<quic_pool::QuicConnStats>| {
                let stats = telemetry_for_handler.get_or_create(client_pub);
                tokio::spawn(async move {
                    let target_addr = match timeout(Duration::from_secs(5), read_target_addr(&mut recv_mux)).await {
                        Ok(Ok(addr)) => addr,
                        Ok(Err(e)) => {
                            log::debug!("Failed to read target proxy address header: {}", e);
                            return;
                        }
                        Err(_) => {
                            log::debug!("Timed out reading target proxy address header");
                            return;
                        }
                    };
                    
                    log::info!("Establishing userspace TCP proxy bridge to target destination: {}", target_addr);
                    match tokio::net::TcpStream::connect(target_addr).await {
                        Ok(tcp_socket) => {
                            if let Err(e) = set_tcp_keepalive(&tcp_socket) {
                                log::warn!("Failed to set TCP Keep-Alive on target TCP stream: {}", e);
                            }
                            if send_mux.write_all(&[1]).await.is_ok() {
                                relay::relay_connections_with_conn_stat(
                                    tcp_socket, send_mux, recv_mux, stats, conn_stat
                                ).await;
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to establish TCP connection to target {}: {}", target_addr, e);
                            let _ = send_mux.write_all(&[0]).await;
                        }
                    }
                });
            });

            if let Err(e) = quic_server.run_with_registry(handler, shared_reg_for_server).await {
                log::error!("QUIC Pool Server error: {}", e);
            }
        });

        let _ = quic_run_task.await;
        wait_for_shutdown().await;

    } else {
        log::info!("------------------------------------------------------");
        log::info!("         STARTING GATEWAY IN [ CLIENT MODE ]         ");
        log::info!("------------------------------------------------------");

        if config.peers.is_empty() {
            eprintln!("Error: Client config must have at least one Peer!");
            std::process::exit(1);
        }

        let peer = &config.peers[0];
        let endpoint = peer.endpoint.expect("Error: Endpoint required for Client mode");
        let proxy_port = peer.proxy_port.expect("Error: ProxyPort required for Client mode");

        let control_addr = SocketAddr::new(endpoint.ip(), proxy_port);
        let control_client = ControlClient::new(
            config.interface.private_key,
            peer.public_key,
            control_addr,
        );

        log::info!("Initiating userspace ECDH + HMAC-SHA256 control handshake to {}", control_addr);
        let (control_response, _control_socket) = match control_client.negotiate_config().await {
            Ok(res) => res,
            Err(e) => {
                log::error!("Control Negotiation FAILED: {}", e);
                std::process::exit(1);
            }
        };

        let mut quic_endpoints = Vec::new();
        for &port in &control_response.port_pool {
            quic_endpoints.push(SocketAddr::new(endpoint.ip(), port));
        }

        let client_pub_derived = PublicKey::from(&StaticSecret::from(config.interface.private_key)).to_bytes();
        let quic_pool_client = Arc::new(QuicPoolClient::new(
            client_pub_derived,
            control_response.session_psk,
            quic_endpoints,
        ));

        if let Err(e) = quic_pool_client.start_pool().await {
            log::error!("Failed to establish physical parallel QUIC connection pool: {}", e);
            std::process::exit(1);
        }

        quic_pool_client.clone().start_health_checker();

        let tproxy_port = config.interface.tproxy_port.expect("Error: TProxyPort required for Client mode");
        let tproxy_v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tproxy_port);
        let tproxy_v4_listener = match tproxy::create_tproxy_listener(tproxy_v4_addr) {
            Ok(l) => l,
            Err(e) => {
                log::error!("IPv4 TPROXY Listener bind FAILED: {}", e);
                std::process::exit(1);
            }
        };
        let tproxy_v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), tproxy_port);
        let tproxy_v6_listener = match tproxy::create_tproxy_listener(tproxy_v6_addr) {
            Ok(l) => Some(l),
            Err(e) => {
                log::warn!("IPv6 TPROXY Listener bind FAILED: {}. IPv4 interception remains active.", e);
                None
            }
        };

        log::info!("------------------------------------------------------");
        log::info!("  TPROXY TCP transparent intercept running on port {} ", tproxy_port);
        log::info!("  All TCP streams routed to AllowedIPs will offload to ");
        log::info!("  Parallel Userspace QUIC Connection Pool bypass L3 !  ");
        log::info!("------------------------------------------------------");

        if let Some(listener) = tproxy_v6_listener {
            tokio::spawn(run_tproxy_accept_loop(
                listener,
                quic_pool_client.clone(),
                gateway_state.clone(),
                telemetry_registry.clone(),
            ));
        }

        tokio::select! {
            _ = run_tproxy_accept_loop(
                tproxy_v4_listener,
                quic_pool_client.clone(),
                gateway_state.clone(),
                telemetry_registry.clone(),
            ) => {}
            _ = wait_for_shutdown() => {}
        }
    }

    // 自动清理路由与 iptables
    cleanup_routes_and_iptables(&config, &config_path);

    // 执行 PostScript 脚本
    if let Some(ref post_script) = config.interface.post_script {
        run_script(post_script);
    }
}

// CLI 遥测查看实用工具实现
async fn run_cli_stats() -> Result<(), String> {
    let mut stream = tokio::net::UnixStream::connect("/tmp/new_proxy_api.sock").await
        .map_err(|e| format!("Cannot connect to gateway API socket. Gateway not running? Error: {}", e))?;
    
    // 发起 Stats 命令 JSON
    let cmd = CommandInput::Stats;
    let json_bytes = serde_json::to_vec(&cmd).unwrap();
    let _ = stream.write_all(&json_bytes).await;
    let _ = stream.shutdown().await;
    
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await
        .map_err(|e| format!("Failed to read stats from socket: {}", e))?;
    
    let stats: Vec<UnifiedTelemetry> = serde_json::from_slice(&buf)
        .map_err(|e| format!("Failed to parse JSON stats: {}", e))?;
    
    println!("\n+-------------------------------------------------------------------------------------------------------------------------------------------+");
    println!("|                                             HYBRID SECURE PROXY GATEWAY TELEMETRY                                                         |");
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");
    println!("| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |", "Peer Public Key", "Source", "L3 Transfer (RX/TX)", "L4 Transfer (RX/TX)", "Handshake (ago)", "Active Strm");
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for s in stats {
        let l3_str = format!("{}/{}", format_bytes(s.l3_rx_bytes), format_bytes(s.l3_tx_bytes));
        let l4_str = format!("{}/{}", format_bytes(s.l4_rx_bytes), format_bytes(s.l4_tx_bytes));
        let handshake_str = if s.last_handshake == 0 {
            "never".to_string()
        } else if now > s.last_handshake {
            format!("{}s", now - s.last_handshake)
        } else {
            "0s".to_string()
        };
        
        println!(
            "| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |",
            s.public_key,
            s.source,
            l3_str,
            l4_str,
            handshake_str,
            s.active_streams
        );
    }
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_base64_encode() {
        let bytes = [0x55u8; 32];
        let encoded = encode_base64_32(&bytes);
        let decoded = decode_base64_32(&encoded).unwrap();
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn test_telemetry_registry() {
        let registry = TelemetryRegistry::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let stats1 = registry.get_or_create(key1);
        let _stats2 = registry.get_or_create(key2);

        stats1.rx_bytes.store(100, Ordering::Relaxed);
        stats1.tx_bytes.store(200, Ordering::Relaxed);
        stats1.active_streams.store(3, Ordering::Relaxed);

        let snap = registry.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[&key1].rx_bytes.load(Ordering::Relaxed), 100);
        assert_eq!(snap[&key1].tx_bytes.load(Ordering::Relaxed), 200);
        assert_eq!(snap[&key1].active_streams.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_target_addr_codec_ipv4() {
        let addr = "1.2.3.4:12345".parse::<SocketAddr>().unwrap();
        let mut buf = Vec::new();
        write_target_addr(&mut buf, addr).await.unwrap();

        let mut reader = Cursor::new(buf);
        let decoded_addr = read_target_addr(&mut reader).await.unwrap();
        assert_eq!(addr, decoded_addr);
    }

    #[tokio::test]
    async fn test_target_addr_codec_ipv6() {
        let addr = "[2001:db8::1]:12345".parse::<SocketAddr>().unwrap();
        let mut buf = Vec::new();
        write_target_addr(&mut buf, addr).await.unwrap();

        let mut reader = Cursor::new(buf);
        let decoded_addr = read_target_addr(&mut reader).await.unwrap();
        assert_eq!(addr, decoded_addr);
    }

    #[test]
    fn test_format_bytes_main() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[tokio::test]
    async fn test_get_wg_dump_stats() {
        let res = get_wg_dump_stats("nonexistent_interface").await;
        assert!(res.is_ok());
        let map = res.unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_encode_base64_padding() {
        let key = [0u8; 32];
        let encoded = encode_base64_32(&key);
        assert_eq!(encoded.len(), 44);
        assert!(encoded.ends_with("="));
    }

    #[tokio::test]
    async fn test_main_uds_api_server() {
        use tokio::net::UnixListener;
        use std::fs;

        let test_uds_path = "/tmp/test_main_api.sock";
        let _ = fs::remove_file(test_uds_path);

        let listener = UnixListener::bind(test_uds_path).unwrap();

        // 1. 准备 GatewayState 和 TelemetryRegistry 等
        let config = GatewayConfig {
            interface: config::InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec![],
                listen_port: Some(0),
                listen_control_port: Some(51820),
                tproxy_port: Some(8080),
                mtu: 1420,
                table: None,
                pre_script: None,
                post_script: None,
            },
            peers: vec![config::PeerConfig {
                public_key: [2u8; 32],
                allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
                endpoint: Some("1.2.3.4:51820".parse().unwrap()),
                proxy_port: Some(40001),
            }],
            quic_pool: config::QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![],
            },
        };

        let telemetry_registry = Arc::new(TelemetryRegistry::new());
        let initial_router = AllowedIPsRouter::new();
        let gateway_state = Arc::new(std::sync::RwLock::new(GatewayState {
            config: config.clone(),
            router: initial_router,
        }));
        let peer_secrets = Arc::new(Mutex::new(HashMap::new()));
        let server_secret = StaticSecret::from(config.interface.private_key);
        let shared_quic_registry: quic_pool::PeerConnRegistry = Arc::new(Mutex::new(HashMap::new()));

        // 2. 启动 UDS API 模拟服务端
        let _telemetry_clone = telemetry_registry.clone();
        let _state_clone = gateway_state.clone();
        let peer_secrets_clone = peer_secrets.clone();
        let server_secret_clone = server_secret.clone();
        let _shared_quic_registry_uds = shared_quic_registry.clone();

        let server_handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut temp = [0u8; 1024];
                while let Ok(n) = stream.read(&mut temp).await {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&temp[..n]);
                    if serde_json::from_slice::<serde_json::Value>(&buf).is_ok() {
                        break;
                    }
                }

                let cmd: CommandInput = serde_json::from_slice(&buf).unwrap();
                match cmd {
                    CommandInput::Stats => {
                        let response = vec![UnifiedTelemetry {
                            public_key: encode_base64_32(&[2u8; 32]),
                            allowed_ips: vec!["10.0.0.2/32".to_string()],
                            endpoint: Some("1.2.3.4:51820".to_string()),
                            l3_rx_bytes: 50,
                            l3_tx_bytes: 60,
                            last_handshake: 0,
                            l4_rx_bytes: 70,
                            l4_tx_bytes: 80,
                            active_streams: 0,
                            quic_connections: vec![],
                            source: "both".to_string(),
                        }];
                        let _ = stream.write_all(&serde_json::to_vec(&response).unwrap()).await;
                    }
                    CommandInput::Dump => {
                        let response = "mock_dump_line\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    CommandInput::AddPeer { public_key, allowed_ips: _, endpoint: _, proxy_port: _ } => {
                        let parsed_pub_key = decode_base64_32(&public_key).unwrap();
                        let peer_pub = PublicKey::from(parsed_pub_key);
                        let shared_secret = server_secret_clone.diffie_hellman(&peer_pub).to_bytes();
                        peer_secrets_clone.lock().unwrap().insert(parsed_pub_key, shared_secret);

                        let resp = ApiResponse { status: "ok".to_string(), message: None };
                        let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                    }
                    CommandInput::RemovePeer { public_key } => {
                        let _ = decode_base64_32(&public_key).unwrap();
                        let resp = ApiResponse { status: "ok".to_string(), message: None };
                        let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                    }
                }
            }
        });

        // 给服务端启动的时间
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. 客户端发送 Stats 请求
        {
            let mut stream = tokio::net::UnixStream::connect(test_uds_path).await.unwrap();
            let cmd = CommandInput::Stats;
            let json_bytes = serde_json::to_vec(&cmd).unwrap();
            stream.write_all(&json_bytes).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            let stats: Vec<UnifiedTelemetry> = serde_json::from_slice(&resp).unwrap();
            assert_eq!(stats.len(), 1);
            assert_eq!(stats[0].public_key, encode_base64_32(&[2u8; 32]));
        }

        let _ = server_handle.await;
        let _ = fs::remove_file(test_uds_path);
    }

    #[tokio::test]
    async fn test_main_uds_add_remove_peer() {
        use tokio::net::UnixListener;
        use std::fs;

        let test_uds_path = "/tmp/test_main_api_add_remove.sock";
        let _ = fs::remove_file(test_uds_path);

        let listener = UnixListener::bind(test_uds_path).unwrap();

        let private_key = [1u8; 32];
        let server_secret = StaticSecret::from(private_key);
        let peer_secrets = Arc::new(Mutex::new(HashMap::new()));

        let server_handle = tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = Vec::new();
                    let mut temp = [0u8; 1024];
                    while let Ok(n) = stream.read(&mut temp).await {
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&temp[..n]);
                        if serde_json::from_slice::<serde_json::Value>(&buf).is_ok() {
                            break;
                        }
                    }

                    let cmd: CommandInput = serde_json::from_slice(&buf).unwrap();
                    match cmd {
                        CommandInput::AddPeer { public_key, allowed_ips: _, endpoint: _, proxy_port: _ } => {
                            let parsed_pub_key = decode_base64_32(&public_key).unwrap();
                            let peer_pub = PublicKey::from(parsed_pub_key);
                            let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
                            peer_secrets.lock().unwrap().insert(parsed_pub_key, shared_secret);

                            let resp = ApiResponse { status: "ok".to_string(), message: None };
                            let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                        }
                        CommandInput::RemovePeer { public_key } => {
                            let parsed_pub_key = decode_base64_32(&public_key).unwrap();
                            peer_secrets.lock().unwrap().remove(&parsed_pub_key);

                            let resp = ApiResponse { status: "ok".to_string(), message: None };
                            let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                        }
                        _ => {}
                    }
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // AddPeer
        {
            let mut stream = tokio::net::UnixStream::connect(test_uds_path).await.unwrap();
            let cmd = CommandInput::AddPeer {
                public_key: encode_base64_32(&[3u8; 32]),
                allowed_ips: vec!["10.0.0.3/32".to_string()],
                endpoint: None,
                proxy_port: None,
            };
            let json_bytes = serde_json::to_vec(&cmd).unwrap();
            stream.write_all(&json_bytes).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            let api_resp: ApiResponse = serde_json::from_slice(&resp).unwrap();
            assert_eq!(api_resp.status, "ok");
        }

        // RemovePeer
        {
            let mut stream = tokio::net::UnixStream::connect(test_uds_path).await.unwrap();
            let cmd = CommandInput::RemovePeer {
                public_key: encode_base64_32(&[3u8; 32]),
            };
            let json_bytes = serde_json::to_vec(&cmd).unwrap();
            stream.write_all(&json_bytes).await.unwrap();
            stream.shutdown().await.unwrap();

            let mut resp = Vec::new();
            stream.read_to_end(&mut resp).await.unwrap();
            let api_resp: ApiResponse = serde_json::from_slice(&resp).unwrap();
            assert_eq!(api_resp.status, "ok");
        }

        let _ = server_handle.await;
        let _ = fs::remove_file(test_uds_path);
    }

    #[tokio::test]
    async fn test_peer_synchronization() {
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let peer_secrets = Arc::new(Mutex::new(HashMap::new()));
        
        let config = GatewayConfig {
            interface: config::InterfaceConfig {
                private_key: server_secret.to_bytes(),
                addresses: vec![],
                listen_port: Some(51820),
                listen_control_port: None,
                tproxy_port: None,
                mtu: 1420,
                table: None,
                pre_script: None,
                post_script: None,
            },
            peers: vec![
                config::PeerConfig {
                    public_key: [1u8; 32],
                    allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
                    endpoint: Some("127.0.0.1:12345".parse().unwrap()),
                    proxy_port: None,
                },
                config::PeerConfig {
                    public_key: [2u8; 32],
                    allowed_ips: vec!["10.0.2.0/24".parse().unwrap()],
                    endpoint: Some("127.0.0.1:12346".parse().unwrap()),
                    proxy_port: None,
                }
            ],
            quic_pool: config::QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![],
            },
        };
        
        let initial_router = AllowedIPsRouter::new();
        let gateway_state = Arc::new(std::sync::RwLock::new(GatewayState {
            config,
            router: initial_router,
        }));
        
        let mut l3_stats = HashMap::new();
        l3_stats.insert([1u8; 32], WgPeerStats {
            allowed_ips: vec!["10.0.1.0/24".to_string()],
            endpoint: Some("127.0.0.1:12345".to_string()),
            rx_bytes: 100,
            tx_bytes: 200,
            last_handshake: 0,
        });
        l3_stats.insert([3u8; 32], WgPeerStats {
            allowed_ips: vec!["10.0.3.0/24".to_string()],
            endpoint: Some("127.0.0.1:12347".to_string()),
            rx_bytes: 300,
            tx_bytes: 400,
            last_handshake: 0,
        });
        
        let sources = sync_kernel_and_proxy_state(
            "tun_test_sync",
            &gateway_state,
            &peer_secrets,
            &server_secret,
            &l3_stats,
        ).await;
        
        assert_eq!(sources.get(&[1u8; 32]).unwrap(), "both");
        assert_eq!(sources.get(&[2u8; 32]).unwrap(), "proxy");
        assert_eq!(sources.get(&[3u8; 32]).unwrap(), "kernel");
        
        let st = gateway_state.read().unwrap();
        let peer3 = st.config.peers.iter().find(|p| p.public_key == [3u8; 32]);
        assert!(peer3.is_some(), "Peer [3u8; 32] should be synced to proxy config");
        let peer3_config = peer3.unwrap();
        assert_eq!(peer3_config.allowed_ips[0], "10.0.3.0/24".parse::<ipnet::IpNet>().unwrap());
        
        let lookup_res = st.router.longest_match(std::net::IpAddr::V4("10.0.3.5".parse().unwrap()));
        assert_eq!(lookup_res, Some([3u8; 32]), "Router should be able to resolve IP to [3u8; 32]");
        
        let secrets = peer_secrets.lock().unwrap();
        assert!(secrets.contains_key(&[3u8; 32]), "Peer [3u8; 32] secret should be computed");
    }
}
