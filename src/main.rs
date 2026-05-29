mod config;
mod control;
mod quic_pool;
mod relay;
mod routing;
mod tproxy;
mod wireguard;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

use config::{decode_base64_32, GatewayConfig};
use control::{ControlClient, ControlServer};
use quic_pool::{
    cert_sha256, generate_self_signed_cert, QuicConnSnapshot, QuicPoolClient, QuicPoolServer,
};
use relay::PeerL4Stats;
use routing::AllowedIPsRouter;
use wireguard::{get_wg_dump_stats, remove_peer_from_kernel, sync_peer_to_kernel, WgPeerStats};

type PeerQuicPools = Arc<std::sync::RwLock<HashMap<[u8; 32], Arc<QuicPoolClient>>>>;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeMode {
    Server,
    Client,
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
        Self { stats }
    }

    pub fn get_or_create(&self, pub_key: [u8; 32]) -> Arc<PeerL4Stats> {
        let mut map = self.stats[self.shard_index(&pub_key)].lock().unwrap();
        map.entry(pub_key)
            .or_insert_with(|| Arc::new(PeerL4Stats::default()))
            .clone()
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

impl Default for TelemetryRegistry {
    fn default() -> Self {
        Self::new()
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
    while !out.len().is_multiple_of(4) {
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
pub async fn write_target_addr<W: AsyncWrite + Unpin>(
    w: &mut W,
    addr: SocketAddr,
) -> std::io::Result<()> {
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
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid address type",
            ))
        }
    };
    let port = r.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

async fn run_tproxy_accept_loop(
    listener: TcpListener,
    quic_pools: PeerQuicPools,
    state: Arc<std::sync::RwLock<GatewayState>>,
    telemetry: Arc<TelemetryRegistry>,
    connection_limit: Arc<tokio::sync::Semaphore>,
) {
    while let Ok((tcp_socket, src_addr)) = listener.accept().await {
        let permit = match connection_limit.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                log::warn!("TPROXY connection limit reached; dropping {}", src_addr);
                continue;
            }
        };
        let quic_pools = quic_pools.clone();
        let state = state.clone();
        let telemetry = telemetry.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_tproxy_connection(tcp_socket, src_addr, quic_pools, state, telemetry).await;
        });
    }
}

async fn handle_tproxy_connection(
    tcp_socket: TcpStream,
    src_addr: SocketAddr,
    quic_pools: PeerQuicPools,
    state: Arc<std::sync::RwLock<GatewayState>>,
    telemetry: Arc<TelemetryRegistry>,
) {
    if let Err(e) = set_tcp_keepalive(&tcp_socket) {
        log::warn!("Failed to set TCP Keep-Alive on TPROXY socket: {}", e);
    }

    let original_dst = match tcp_socket.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            log::warn!(
                "Failed to retrieve original destination for intercepted connection: {}",
                e
            );
            return;
        }
    };

    let matched_peer = {
        let st = state.read().unwrap();
        st.router.longest_match(original_dst.ip())
    };

    if let Some(peer_pub_key) = matched_peer {
        let quic_pool = {
            let pools = quic_pools.read().unwrap();
            pools.get(&peer_pub_key).cloned()
        };
        let Some(quic_pool) = quic_pool else {
            log::warn!(
                "AllowedIPs matched peer {}, but no QUIC pool exists; dropping {} -> {}",
                encode_base64_32(&peer_pub_key),
                src_addr,
                original_dst
            );
            return;
        };

        log::info!(
            "Intercepted TCP stream from {} -> {}, matched AllowedIPs. Offloading to QUIC.",
            src_addr,
            original_dst
        );

        let (mut quic_send, mut quic_recv, conn_stat) = match quic_pool.open_mux_stream().await {
            Ok(stream) => stream,
            Err(e) => {
                log::warn!("Failed to open parallel multiplexed QUIC stream: {}", e);
                return;
            }
        };

        if write_target_addr(&mut quic_send, original_dst)
            .await
            .is_err()
        {
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
                log::warn!(
                    "Failed to read server proxy status for {}: {}",
                    original_dst,
                    e
                );
                return;
            }
            Err(_) => {
                log::warn!(
                    "Timed out waiting for server proxy status for {}",
                    original_dst
                );
                return;
            }
        }

        let stats = telemetry.get_or_create(peer_pub_key);

        relay::relay_connections_with_conn_stat(tcp_socket, quic_send, quic_recv, stats, conn_stat)
            .await;
    } else {
        log::debug!(
            "Intercepted connection to {} does not match AllowedIPs. Dropped.",
            original_dst
        );
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
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl_c");
    log::info!("Received CTRL+C, shutting down...");
}

const MAX_TPROXY_CONNECTIONS: usize = 4096;
const MAX_QUIC_STREAM_HANDLERS: usize = 8192;
const MAX_UDS_CLIENTS: usize = 1024;

fn interface_name_from_config_path(config_path: &str) -> Result<String, String> {
    let name = std::path::Path::new(config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("tun0")
        .to_string();
    validate_interface_name(&name)?;
    Ok(name)
}

fn validate_interface_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 15 {
        return Err(format!(
            "Invalid interface name '{}': Linux interface names must be 1..=15 bytes",
            name
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
    {
        return Err(format!(
            "Invalid interface name '{}': allowed characters are [A-Za-z0-9_.:-]",
            name
        ));
    }
    Ok(())
}

fn api_socket_path(interface_name: &str) -> String {
    format!("/run/new_proxy/{}.sock", interface_name)
}

fn determine_runtime_mode(config: &GatewayConfig) -> Result<RuntimeMode, String> {
    let server_mode =
        config.interface.listen_control_port.is_some() || !config.quic_pool.listen_ports.is_empty();
    if server_mode {
        if config.interface.listen_control_port.is_none() {
            return Err(
                "Invalid server config: ListenControlPort is required when QUICPool.ListenPorts is set"
                    .to_string(),
            );
        }
        if config.quic_pool.listen_ports.is_empty() {
            return Err(
                "Invalid server config: QUICPool.ListenPorts must contain at least one port"
                    .to_string(),
            );
        }
        return Ok(RuntimeMode::Server);
    }

    if config.peers.is_empty() {
        return Err("Invalid client config: at least one [Peer] is required".to_string());
    }
    let mut proxy_peer_count = 0;
    for peer in &config.peers {
        match (peer.endpoint, peer.proxy_port) {
            (Some(_), Some(_)) => proxy_peer_count += 1,
            (None, None) => {}
            _ => {
                return Err(format!(
                    "Invalid client config: peer {} must define both Endpoint and ProxyPort for QUIC offload, or neither for WireGuard-only mode",
                    encode_base64_32(&peer.public_key)
                ));
            }
        }
    }
    if proxy_peer_count > 0 && config.interface.tproxy_port.is_none() {
        return Err("Invalid client config: TProxyPort is required when any peer defines Endpoint/ProxyPort".to_string());
    }
    Ok(RuntimeMode::Client)
}

fn validate_gateway_config(config: &GatewayConfig) -> Result<RuntimeMode, String> {
    if let Some(table) = config.interface.table.as_deref() {
        if !table.eq_ignore_ascii_case("auto") && !table.eq_ignore_ascii_case("off") {
            return Err(format!(
                "Invalid Table value '{}': expected auto or off",
                table
            ));
        }
    }
    let mut seen_quic_ports = HashSet::new();
    for port in &config.quic_pool.listen_ports {
        if !seen_quic_ports.insert(*port) {
            return Err(format!("Duplicate QUICPool ListenPorts entry: {}", port));
        }
    }
    for peer in &config.peers {
        if peer.allowed_ips.is_empty() {
            return Err(format!(
                "Peer {} has no AllowedIPs",
                encode_base64_32(&peer.public_key)
            ));
        }
    }
    determine_runtime_mode(config)
}

fn peer_has_l4_proxy(peer: &config::PeerConfig) -> bool {
    peer.endpoint.is_some() && peer.proxy_port.is_some()
}

fn rebuild_l4_router(peers: &[config::PeerConfig]) -> AllowedIPsRouter<[u8; 32]> {
    let mut router = AllowedIPsRouter::new();
    for peer in peers.iter().filter(|peer| peer_has_l4_proxy(peer)) {
        for &allowed_ip in &peer.allowed_ips {
            router.insert(allowed_ip, peer.public_key);
        }
    }
    router
}

fn telemetry_sources(
    peers: &[config::PeerConfig],
    l3_stats: &HashMap<[u8; 32], WgPeerStats>,
) -> HashMap<[u8; 32], String> {
    let mut sources = HashMap::new();
    for peer in peers {
        if l3_stats.contains_key(&peer.public_key) {
            sources.insert(peer.public_key, "both".to_string());
        } else {
            sources.insert(peer.public_key, "proxy".to_string());
        }
    }
    for pub_key in l3_stats.keys() {
        sources
            .entry(*pub_key)
            .or_insert_with(|| "kernel".to_string());
    }
    sources
}

fn select_quic_endpoint_ip(
    control_response: &control::ControlResponse,
    fallback_endpoint: SocketAddr,
) -> Result<IpAddr, String> {
    if fallback_endpoint.is_ipv6() {
        if let Some(public_ipv6) = &control_response.public_ipv6 {
            return public_ipv6
                .parse::<Ipv6Addr>()
                .map(IpAddr::V6)
                .map_err(|e| format!("Invalid server PublicIPv6 '{}': {}", public_ipv6, e));
        }
    } else if let Some(public_ipv4) = &control_response.public_ipv4 {
        return public_ipv4
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|e| format!("Invalid server PublicIPv4 '{}': {}", public_ipv4, e));
    }
    Ok(fallback_endpoint.ip())
}

async fn build_peer_quic_pool(
    private_key: [u8; 32],
    peer: &config::PeerConfig,
) -> Result<Arc<QuicPoolClient>, String> {
    let endpoint = peer
        .endpoint
        .ok_or_else(|| "proxy peer is missing Endpoint".to_string())?;
    let proxy_port = peer
        .proxy_port
        .ok_or_else(|| "proxy peer is missing ProxyPort".to_string())?;
    let control_addr = SocketAddr::new(endpoint.ip(), proxy_port);
    let control_client = ControlClient::new(private_key, peer.public_key, control_addr);

    log::info!(
        "Initiating userspace ECDH + HMAC-SHA256 control handshake for peer {} to {}",
        encode_base64_32(&peer.public_key),
        control_addr
    );
    let (control_response, _control_socket) = control_client.negotiate_config().await?;
    let quic_endpoint_ip = select_quic_endpoint_ip(&control_response, endpoint)?;
    let quic_endpoints = control_response
        .port_pool
        .iter()
        .map(|&port| SocketAddr::new(quic_endpoint_ip, port))
        .collect::<Vec<_>>();
    let client_pub_derived = PublicKey::from(&StaticSecret::from(private_key)).to_bytes();
    let quic_pool_client = Arc::new(QuicPoolClient::new(
        client_pub_derived,
        control_response.session_psk,
        control_response.quic_cert_sha256,
        quic_endpoints,
    ));
    quic_pool_client.start_pool().await?;
    quic_pool_client.clone().start_health_checker();
    Ok(quic_pool_client)
}

fn instance_routing_ids(interface_name: &str) -> (u32, u32) {
    let mut hash = 0x811c9dc5u32;
    for byte in interface_name.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    let fwmark = 0x1000_0000 | (hash & 0x00ff_ffff);
    let table = 10_000 + (hash % 50_000);
    (fwmark, table)
}

fn run_command_checked(program: &str, args: &[String]) -> Result<(), String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute '{} {}': {}", program, args.join(" "), e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "command '{} {}' failed with status {:?}: {}",
            program,
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_command_best_effort(program: &str, args: &[String]) {
    if let Err(e) = run_command_checked(program, args) {
        log::debug!("{}", e);
    }
}

async fn run_blocking_command<F>(op: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String> + Send + 'static,
{
    tokio::task::spawn_blocking(op)
        .await
        .map_err(|e| format!("blocking command worker failed: {}", e))?
}

struct UdsRequest {
    command: CommandInput,
    framed: bool,
}

async fn read_uds_command(stream: &mut tokio::net::UnixStream) -> Result<UdsRequest, String> {
    const MAX_UDS_PAYLOAD: usize = 65536;
    const UDS_READ_TIMEOUT: Duration = Duration::from_secs(2);

    let first = timeout(UDS_READ_TIMEOUT, stream.read_u8())
        .await
        .map_err(|_| "UDS request read timeout".to_string())?
        .map_err(|e| format!("UDS request read error: {}", e))?;

    let mut buf = Vec::new();
    let framed = first != b'{';
    if !framed {
        buf.push(first);
        let mut temp = [0u8; 1024];
        timeout(UDS_READ_TIMEOUT, async {
            loop {
                match stream.read(&mut temp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&temp[..n]);
                        if buf.len() > MAX_UDS_PAYLOAD {
                            return Err("UDS request payload too large".to_string());
                        }
                    }
                    Err(e) => return Err(format!("UDS request read error: {}", e)),
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| "UDS request read timeout".to_string())??;
    } else {
        let mut len_bytes = [0u8; 4];
        len_bytes[0] = first;
        timeout(UDS_READ_TIMEOUT, stream.read_exact(&mut len_bytes[1..]))
            .await
            .map_err(|_| "UDS request length read timeout".to_string())?
            .map_err(|e| format!("UDS request length read error: {}", e))?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_UDS_PAYLOAD {
            return Err(format!("Invalid UDS request payload length: {}", len));
        }
        buf.resize(len, 0);
        timeout(UDS_READ_TIMEOUT, stream.read_exact(&mut buf))
            .await
            .map_err(|_| "UDS request payload read timeout".to_string())?
            .map_err(|e| format!("UDS request payload read error: {}", e))?;
    }

    serde_json::from_slice(&buf)
        .map(|command| UdsRequest { command, framed })
        .map_err(|e| format!("Invalid request JSON: {}", e))
}

async fn write_uds_json<T: Serialize>(
    stream: &mut tokio::net::UnixStream,
    value: &T,
    framed: bool,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    write_uds_payload(stream, &payload, framed).await
}

async fn write_uds_payload(
    stream: &mut tokio::net::UnixStream,
    payload: &[u8],
    framed: bool,
) -> std::io::Result<()> {
    if framed {
        stream.write_u32(payload.len() as u32).await?;
    }
    stream.write_all(payload).await
}

fn ensure_iptables_rule(tool: &str, rule: &[String]) -> Result<(), String> {
    let mut check_args = vec!["-t".to_string(), "mangle".to_string(), "-C".to_string()];
    check_args.extend(rule.iter().cloned());
    if run_command_checked(tool, &check_args).is_ok() {
        return Ok(());
    }
    let mut add_args = vec!["-t".to_string(), "mangle".to_string(), "-A".to_string()];
    add_args.extend(rule.iter().cloned());
    run_command_checked(tool, &add_args)
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

fn cleanup_runtime(config: &GatewayConfig, interface_name: &str) {
    cleanup_routes_and_iptables(config, interface_name);
    if let Some(ref post_script) = config.interface.post_script {
        run_script(post_script);
    }
}

fn setup_routes_and_iptables(config: &GatewayConfig, interface_name: &str) -> Result<(), String> {
    if let Some(ref t) = config.interface.table {
        if t.to_lowercase() == "off" {
            log::info!("Table is off. Skipping automatic routing and iptables setup.");
            return Ok(());
        }
    }

    log::info!(
        "Setting up automatic routing and iptables for interface: {}",
        interface_name
    );

    // 1. Add addresses to the tun interface
    for addr in &config.interface.addresses {
        run_command_checked(
            "ip",
            &[
                "addr".to_string(),
                "replace".to_string(),
                addr.to_string(),
                "dev".to_string(),
                interface_name.to_string(),
            ],
        )?;
    }

    // Set interface UP and configure the parsed MTU to prevent PMTU fragmentation issues
    run_command_checked(
        "ip",
        &[
            "link".to_string(),
            "set".to_string(),
            interface_name.to_string(),
            "up".to_string(),
            "mtu".to_string(),
            config.interface.mtu.to_string(),
        ],
    )?;

    // 2. Add routes for AllowedIPs of all peers
    for peer in &config.peers {
        setup_peer_routes_and_tproxy(peer, config.interface.tproxy_port, interface_name)?;
    }

    // 3. Configure TPROXY iptables rules if TProxyPort is set
    if let Some(tproxy_port) = config.interface.tproxy_port {
        log::info!("Setting up TPROXY iptables rules on port {}", tproxy_port);
        let (fwmark, route_table) = instance_routing_ids(interface_name);
        let mark_spec = format!("{:#x}/0xffffffff", fwmark);

        // IPv4 policy routing & local route
        run_command_best_effort(
            "ip",
            &[
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_checked(
            "ip",
            &[
                "rule".to_string(),
                "add".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        )?;
        run_command_checked(
            "ip",
            &[
                "route".to_string(),
                "replace".to_string(),
                "local".to_string(),
                "0.0.0.0/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        )?;

        // IPv6 policy routing & local route
        run_command_best_effort(
            "ip",
            &[
                "-6".to_string(),
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_checked(
            "ip",
            &[
                "-6".to_string(),
                "rule".to_string(),
                "add".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        )?;
        run_command_checked(
            "ip",
            &[
                "-6".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "local".to_string(),
                "::/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        )?;

        let _ = mark_spec;
    }
    Ok(())
}

fn setup_peer_routes_and_tproxy(
    peer: &config::PeerConfig,
    tproxy_port: Option<u16>,
    interface_name: &str,
) -> Result<(), String> {
    let (fwmark, _) = instance_routing_ids(interface_name);
    let mark_spec = format!("{:#x}/0xffffffff", fwmark);

    for allowed_ip in &peer.allowed_ips {
        if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
            run_command_checked(
                "ip",
                &[
                    "route".to_string(),
                    "replace".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )?;
        } else {
            run_command_checked(
                "ip",
                &[
                    "-6".to_string(),
                    "route".to_string(),
                    "replace".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )?;
        }
        if let Some(port) = tproxy_port.filter(|_| peer_has_l4_proxy(peer)) {
            ensure_tproxy_rule(*allowed_ip, port, &mark_spec)?;
            let _ = ensure_mss_clamp_rule(*allowed_ip);
        }
    }
    Ok(())
}

fn ensure_mss_clamp_rule(allowed_ip: ipnet::IpNet) -> Result<(), String> {
    let tool = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        "iptables"
    } else {
        "ip6tables"
    };
    let rule = vec![
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--tcp-flags".to_string(),
        "SYN,RST".to_string(),
        "SYN".to_string(),
        "-d".to_string(),
        allowed_ip.to_string(),
        "-j".to_string(),
        "TCPMSS".to_string(),
        "--clamp-mss-to-pmtud".to_string(),
    ];
    ensure_iptables_rule(tool, &rule).map_err(|e| {
        log::warn!(
            "Failed to set TCPMSS clamping rule (might be unsupported in this environment): {}",
            e
        );
        e
    })
}

fn ensure_tproxy_rule(
    allowed_ip: ipnet::IpNet,
    tproxy_port: u16,
    mark_spec: &str,
) -> Result<(), String> {
    let (tool, on_ip) = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        ("iptables", "0.0.0.0")
    } else {
        ("ip6tables", "::")
    };
    let rule = vec![
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-d".to_string(),
        allowed_ip.to_string(),
        "-j".to_string(),
        "TPROXY".to_string(),
        "--on-port".to_string(),
        tproxy_port.to_string(),
        "--on-ip".to_string(),
        on_ip.to_string(),
        "--tproxy-mark".to_string(),
        mark_spec.to_string(),
    ];
    ensure_iptables_rule(tool, &rule)
}

fn cleanup_routes_and_iptables(config: &GatewayConfig, interface_name: &str) {
    if let Some(ref t) = config.interface.table {
        if t.to_lowercase() == "off" {
            return;
        }
    }

    log::info!(
        "Cleaning up automatic routing and iptables for interface: {}",
        interface_name
    );

    // 1. Remove TPROXY iptables rules if TProxyPort is set
    if let Some(tproxy_port) = config.interface.tproxy_port {
        log::info!("Tearing down TPROXY iptables rules on port {}", tproxy_port);
        let (fwmark, route_table) = instance_routing_ids(interface_name);
        let mark_spec = format!("{:#x}/0xffffffff", fwmark);

        for peer in &config.peers {
            for allowed_ip in &peer.allowed_ips {
                cleanup_tproxy_rule(*allowed_ip, tproxy_port, &mark_spec);
                cleanup_mss_clamp_rule(*allowed_ip);
            }
        }

        // Clean up policy routing & local routes
        run_command_best_effort(
            "ip",
            &[
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_best_effort(
            "ip",
            &[
                "route".to_string(),
                "del".to_string(),
                "local".to_string(),
                "0.0.0.0/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_best_effort(
            "ip",
            &[
                "-6".to_string(),
                "rule".to_string(),
                "del".to_string(),
                "fwmark".to_string(),
                format!("{:#x}", fwmark),
                "lookup".to_string(),
                route_table.to_string(),
            ],
        );
        run_command_best_effort(
            "ip",
            &[
                "-6".to_string(),
                "route".to_string(),
                "del".to_string(),
                "local".to_string(),
                "::/0".to_string(),
                "dev".to_string(),
                "lo".to_string(),
                "table".to_string(),
                route_table.to_string(),
            ],
        );
    }

    // 2. Remove routes and addresses injected during setup.
    for peer in &config.peers {
        for allowed_ip in &peer.allowed_ips {
            if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                run_command_best_effort(
                    "ip",
                    &[
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                    ],
                );
            } else {
                run_command_best_effort(
                    "ip",
                    &[
                        "-6".to_string(),
                        "route".to_string(),
                        "del".to_string(),
                        allowed_ip.to_string(),
                        "dev".to_string(),
                        interface_name.to_string(),
                    ],
                );
            }
        }
    }

    for addr in &config.interface.addresses {
        run_command_best_effort(
            "ip",
            &[
                "addr".to_string(),
                "del".to_string(),
                addr.to_string(),
                "dev".to_string(),
                interface_name.to_string(),
            ],
        );
    }
}

fn cleanup_tproxy_rule(allowed_ip: ipnet::IpNet, tproxy_port: u16, mark_spec: &str) {
    let (tool, on_ip) = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        ("iptables", "0.0.0.0")
    } else {
        ("ip6tables", "::")
    };
    let args = vec![
        "-t".to_string(),
        "mangle".to_string(),
        "-D".to_string(),
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-d".to_string(),
        allowed_ip.to_string(),
        "-j".to_string(),
        "TPROXY".to_string(),
        "--on-port".to_string(),
        tproxy_port.to_string(),
        "--on-ip".to_string(),
        on_ip.to_string(),
        "--tproxy-mark".to_string(),
        mark_spec.to_string(),
    ];
    run_command_best_effort(tool, &args);
}

fn cleanup_mss_clamp_rule(allowed_ip: ipnet::IpNet) {
    let tool = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
        "iptables"
    } else {
        "ip6tables"
    };
    let args = vec![
        "-t".to_string(),
        "mangle".to_string(),
        "-D".to_string(),
        "PREROUTING".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "--tcp-flags".to_string(),
        "SYN,RST".to_string(),
        "SYN".to_string(),
        "-d".to_string(),
        allowed_ip.to_string(),
        "-j".to_string(),
        "TCPMSS".to_string(),
        "--clamp-mss-to-pmtud".to_string(),
    ];
    run_command_best_effort(tool, &args);
}

fn cleanup_peer_routes_and_tproxy(
    peer: &config::PeerConfig,
    tproxy_port: Option<u16>,
    interface_name: &str,
) -> Result<(), String> {
    let (fwmark, _) = instance_routing_ids(interface_name);
    let mark_spec = format!("{:#x}/0xffffffff", fwmark);
    let mut errors = Vec::new();
    for allowed_ip in &peer.allowed_ips {
        if let Some(port) = tproxy_port.filter(|_| peer_has_l4_proxy(peer)) {
            let (tool, on_ip) = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                ("iptables", "0.0.0.0")
            } else {
                ("ip6tables", "::")
            };
            let tproxy_args = vec![
                "-t".to_string(),
                "mangle".to_string(),
                "-D".to_string(),
                "PREROUTING".to_string(),
                "-p".to_string(),
                "tcp".to_string(),
                "-d".to_string(),
                allowed_ip.to_string(),
                "-j".to_string(),
                "TPROXY".to_string(),
                "--on-port".to_string(),
                port.to_string(),
                "--on-ip".to_string(),
                on_ip.to_string(),
                "--tproxy-mark".to_string(),
                mark_spec.clone(),
            ];
            if let Err(e) = run_command_checked(tool, &tproxy_args) {
                errors.push(e);
            }

            let mss_tool = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
                "iptables"
            } else {
                "ip6tables"
            };
            let mss_args = vec![
                "-t".to_string(),
                "mangle".to_string(),
                "-D".to_string(),
                "PREROUTING".to_string(),
                "-p".to_string(),
                "tcp".to_string(),
                "--tcp-flags".to_string(),
                "SYN,RST".to_string(),
                "SYN".to_string(),
                "-d".to_string(),
                allowed_ip.to_string(),
                "-j".to_string(),
                "TCPMSS".to_string(),
                "--clamp-mss-to-pmtud".to_string(),
            ];
            if let Err(e) = run_command_checked(mss_tool, &mss_args) {
                errors.push(e);
            }
        }
        let route_result = if matches!(allowed_ip, ipnet::IpNet::V4(_)) {
            run_command_checked(
                "ip",
                &[
                    "route".to_string(),
                    "del".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )
        } else {
            run_command_checked(
                "ip",
                &[
                    "-6".to_string(),
                    "route".to_string(),
                    "del".to_string(),
                    allowed_ip.to_string(),
                    "dev".to_string(),
                    interface_name.to_string(),
                ],
            )
        };
        if let Err(e) = route_result {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
async fn sync_kernel_and_proxy_state(
    interface_name: &str,
    state: &Arc<std::sync::RwLock<GatewayState>>,
    peer_secrets: &Arc<std::sync::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
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
        if let std::collections::hash_map::Entry::Vacant(entry) = sources.entry(pub_key) {
            entry.insert("kernel".to_string());
            peers_to_sync_to_proxy.push((pub_key, wg_stats.clone()));
        }
    }

    // 3. Perform synchronization to kernel (wg CLI)
    for peer in peers_to_sync_to_kernel {
        let interface_name = interface_name.to_string();
        let _ = run_blocking_command(move || {
            sync_peer_to_kernel(&interface_name, &peer)?;
            Ok(())
        })
        .await;
    }

    // 4. Perform synchronization to proxy (GatewayState peers & Trie router & peer_secrets)
    for (pub_key, wg_stats) in peers_to_sync_to_proxy {
        // Generates and caches the DH shared secret
        let peer_pub = PublicKey::from(pub_key);
        let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
        peer_secrets.write().unwrap().insert(pub_key, shared_secret);

        let mut parsed_allowed_ips = Vec::new();
        for ip_str in &wg_stats.allowed_ips {
            if let Ok(ipnet) = std::str::FromStr::from_str(ip_str) {
                parsed_allowed_ips.push(ipnet);
            }
        }
        let parsed_endpoint = wg_stats
            .endpoint
            .as_ref()
            .and_then(|s| std::str::FromStr::from_str(s).ok());

        {
            let mut st = state.write().unwrap();
            st.config.peers.retain(|p| p.public_key != pub_key);
            st.config.peers.push(config::PeerConfig {
                public_key: pub_key,
                allowed_ips: parsed_allowed_ips,
                endpoint: parsed_endpoint,
                proxy_port: None,
            });
            st.router = rebuild_l4_router(&st.config.peers);
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

    log::info!(
        "Loading hybrid secure proxy gateway configuration: {}",
        config_path
    );
    let config = match GatewayConfig::load_from_file(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to parse config {}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    let interface_name = match interface_name_from_config_path(&config_path) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    let runtime_mode = match validate_gateway_config(&config) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    // 执行 PreScript 脚本
    if let Some(ref pre_script) = config.interface.pre_script {
        run_script(pre_script);
    }

    // 自动配置路由与 iptables
    if let Err(e) = setup_routes_and_iptables(&config, &interface_name) {
        eprintln!("Failed to setup routes and firewall rules: {}", e);
        cleanup_runtime(&config, &interface_name);
        std::process::exit(1);
    }

    // 共享遥测注册中心与运行时共享状态初始化
    let telemetry_registry = Arc::new(TelemetryRegistry::new());

    let initial_router = rebuild_l4_router(&config.peers);

    let gateway_state = Arc::new(std::sync::RwLock::new(GatewayState {
        config: config.clone(),
        router: initial_router,
    }));

    // 初始化控制面 Peer Secrets 动态共享哈希表
    let peer_secrets = Arc::new(std::sync::RwLock::new(HashMap::new()));
    let server_secret = StaticSecret::from(config.interface.private_key);
    {
        let mut secrets_guard = peer_secrets.write().unwrap();
        for peer in &config.peers {
            let peer_pub = PublicKey::from(peer.public_key);
            let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
            secrets_guard.insert(peer.public_key, shared_secret);
        }
    }

    // 初始化会话与 Nonce 动态共享缓存（用于 UDS 动态清理）
    let session_cache = Arc::new(Mutex::new(HashMap::new()));
    let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));

    // 运行在后台的 Unix Domain Socket API 服务器，处理动态命令与 stats 遥测
    let uds_path = api_socket_path(&interface_name);
    let uds_listener = match std::fs::create_dir_all("/run/new_proxy") {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    "/run/new_proxy",
                    std::fs::Permissions::from_mode(0o700),
                );
            }
            let _ = std::fs::remove_file(&uds_path);
            match tokio::net::UnixListener::bind(&uds_path) {
                Ok(l) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Err(e) = std::fs::set_permissions(
                            &uds_path,
                            std::fs::Permissions::from_mode(0o600),
                        ) {
                            log::warn!(
                                "Failed to restrict API UDS socket permissions on {}: {}",
                                uds_path,
                                e
                            );
                        }
                    }
                    Some(l)
                }
                Err(e) => {
                    log::warn!(
                        "Failed to bind API UDS socket: {}. Telemetry query CLI will be disabled.",
                        e
                    );
                    None
                }
            }
        }
        Err(e) => {
            log::warn!(
                "Failed to create /run/new_proxy: {}. Telemetry query CLI will be disabled.",
                e
            );
            None
        }
    };

    // 共享的 QUIC peer 连接注册表：
    // - server 模式下由 QuicPoolServer.run_with_registry 填充
    // - client 模式下不使用，始终为空
    let shared_quic_registry: quic_pool::PeerConnRegistry =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let client_quic_pools: PeerQuicPools = Arc::new(std::sync::RwLock::new(HashMap::new()));

    if let Some(uds) = uds_listener {
        let telemetry_clone = telemetry_registry.clone();
        let state_clone = gateway_state.clone();
        let peer_secrets_clone = peer_secrets.clone();
        let server_secret_clone = server_secret.clone();
        let shared_quic_registry_uds = shared_quic_registry.clone();
        let interface_name_clone = interface_name.clone();
        let session_cache_clone = session_cache.clone();
        let auth_nonce_cache_clone = auth_nonce_cache.clone();
        let client_quic_pools_clone = client_quic_pools.clone();
        let client_private_key = config.interface.private_key;
        let uds_runtime_mode = runtime_mode;

        tokio::spawn(async move {
            let uds_client_limit = Arc::new(tokio::sync::Semaphore::new(MAX_UDS_CLIENTS));
            while let Ok((mut stream, _)) = uds.accept().await {
                let permit = match uds_client_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let resp = ApiResponse {
                            status: "Error".to_string(),
                            message: Some("UDS client limit reached".to_string()),
                        };
                        let _ = write_uds_json(&mut stream, &resp, false).await;
                        continue;
                    }
                };

                let telemetry = telemetry_clone.clone();
                let state = state_clone.clone();
                let peer_secrets = peer_secrets_clone.clone();
                let server_secret = server_secret_clone.clone();
                let shared_quic_registry = shared_quic_registry_uds.clone();
                let interface_name = interface_name_clone.clone();
                let session_cache = session_cache_clone.clone();
                let auth_nonce_cache = auth_nonce_cache_clone.clone();
                let client_quic_pools = client_quic_pools_clone.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    let request = match read_uds_command(&mut stream).await {
                        Ok(request) => request,
                        Err(e) => {
                            let resp = ApiResponse {
                                status: "Error".to_string(),
                                message: Some(e),
                            };
                            let _ = write_uds_json(&mut stream, &resp, false).await;
                            return;
                        }
                    };
                    let framed_response = request.framed;
                    let cmd = request.command;

                    match cmd {
                        CommandInput::Stats => {
                            let l3_stats =
                                get_wg_dump_stats(&interface_name).await.unwrap_or_default();
                            let aggregated = {
                                let mut aggregated = Vec::new();
                                let mut seen = HashSet::new();
                                let peers = {
                                    let st = state.read().unwrap();
                                    st.config.peers.clone()
                                };
                                let sources = telemetry_sources(&peers, &l3_stats);
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
                                    let (l4_rx, l4_tx, active_streams) =
                                        if let Some(stats) = registry_map.get(&pub_key) {
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

                                    let endpoint = peer
                                        .endpoint
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

                                // 标准 WireGuard 客户端可能只存在于内核 WireGuard 状态中，没有 QUIC 代理运行态。
                                for (pub_key, wg_stats) in &l3_stats {
                                    if seen.contains(pub_key) {
                                        continue;
                                    }

                                    let (l4_rx, l4_tx, active_streams) =
                                        if let Some(stats) = registry_map.get(pub_key) {
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

                                // 极端情况下 QUIC registry 里存在已认证连接，但该 peer 不在配置或内核状态中，也要展示。
                                for pub_key in quic_registry.keys() {
                                    if seen.contains(pub_key) {
                                        continue;
                                    }

                                    let (l4_rx, l4_tx, active_streams) =
                                        if let Some(stats) = registry_map.get(pub_key) {
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
                            let _ = write_uds_json(&mut stream, &aggregated, framed_response).await;
                        }
                        CommandInput::Dump => {
                            let l3_stats =
                                get_wg_dump_stats(&interface_name).await.unwrap_or_default();
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
                                    let l4_rx =
                                        l4.map(|s| s.rx_bytes.load(Ordering::Relaxed)).unwrap_or(0);
                                    let l4_tx =
                                        l4.map(|s| s.tx_bytes.load(Ordering::Relaxed)).unwrap_or(0);
                                    let active_streams = l4
                                        .map(|s| s.active_streams.load(Ordering::Relaxed))
                                        .unwrap_or(0);
                                    let quic_connections =
                                        quic_registry.get(&key).map(|c| c.len()).unwrap_or(0);
                                    lines.push(format!(
                                        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}:{}",
                                        encode_base64_32(&key),
                                        wg.and_then(|s| s.endpoint.clone())
                                            .unwrap_or_else(|| "(none)".to_string()),
                                        wg.map(|s| s.allowed_ips.join(","))
                                            .filter(|s| !s.is_empty())
                                            .unwrap_or_else(|| "(none)".to_string()),
                                        wg.map(|s| s.last_handshake).unwrap_or(0),
                                        wg.map(|s| s.rx_bytes).unwrap_or(0),
                                        wg.map(|s| s.tx_bytes).unwrap_or(0),
                                        l4_rx + l4_tx,
                                        quic_connections,
                                        active_streams,
                                    ));
                                }
                                lines.sort();
                                lines.join("\n")
                            };
                            let _ = write_uds_payload(
                                &mut stream,
                                response.as_bytes(),
                                framed_response,
                            )
                            .await;
                        }
                        CommandInput::AddPeer {
                            public_key,
                            allowed_ips,
                            endpoint,
                            proxy_port,
                        } => {
                            let parsed_pub_key = match decode_base64_32(&public_key) {
                                Ok(k) => k,
                                Err(e) => {
                                    let resp = ApiResponse {
                                        status: "Error".to_string(),
                                        message: Some(format!("Invalid public key: {}", e)),
                                    };
                                    let _ =
                                        write_uds_json(&mut stream, &resp, framed_response).await;
                                    return;
                                }
                            };

                            let mut parsed_allowed_ips = Vec::new();
                            for ip_str in allowed_ips {
                                match std::str::FromStr::from_str(&ip_str) {
                                    Ok(ipnet) => parsed_allowed_ips.push(ipnet),
                                    Err(e) => {
                                        let resp = ApiResponse {
                                            status: "Error".to_string(),
                                            message: Some(format!("Invalid allowed IP: {}", e)),
                                        };
                                        let _ = write_uds_json(&mut stream, &resp, framed_response)
                                            .await;
                                        return;
                                    }
                                }
                            }
                            if parsed_allowed_ips.is_empty() {
                                let resp = ApiResponse {
                                    status: "Error".to_string(),
                                    message: Some("AllowedIPs must not be empty".to_string()),
                                };
                                let _ = write_uds_json(&mut stream, &resp, framed_response).await;
                                return;
                            }

                            let parsed_endpoint = match endpoint {
                                Some(ep_str) => match std::str::FromStr::from_str(&ep_str) {
                                    Ok(addr) => Some(addr),
                                    Err(e) => {
                                        let resp = ApiResponse {
                                            status: "Error".to_string(),
                                            message: Some(format!("Invalid endpoint: {}", e)),
                                        };
                                        let _ = write_uds_json(&mut stream, &resp, framed_response)
                                            .await;
                                        return;
                                    }
                                },
                                None => None,
                            };

                            let new_peer = config::PeerConfig {
                                public_key: parsed_pub_key,
                                allowed_ips: parsed_allowed_ips,
                                endpoint: parsed_endpoint,
                                proxy_port,
                            };

                            let (table_off, tproxy_port, old_peer) = {
                                let st = state.read().unwrap();
                                (
                                    st.config
                                        .interface
                                        .table
                                        .as_deref()
                                        .map(|t| t.eq_ignore_ascii_case("off"))
                                        .unwrap_or(false),
                                    st.config.interface.tproxy_port,
                                    st.config
                                        .peers
                                        .iter()
                                        .find(|p| p.public_key == parsed_pub_key)
                                        .cloned(),
                                )
                            };
                            if uds_runtime_mode == RuntimeMode::Client {
                                match (new_peer.endpoint, new_peer.proxy_port) {
                                    (Some(_), Some(_)) => {}
                                    (None, None) => {}
                                    _ => {
                                        let resp = ApiResponse {
                                            status: "Error".to_string(),
                                            message: Some(
                                                "Endpoint and ProxyPort must be provided together for client QUIC offload"
                                                    .to_string(),
                                            ),
                                        };
                                        let _ = write_uds_json(&mut stream, &resp, framed_response)
                                            .await;
                                        return;
                                    }
                                }
                                if peer_has_l4_proxy(&new_peer) && tproxy_port.is_none() {
                                    let resp = ApiResponse {
                                        status: "Error".to_string(),
                                        message: Some(
                                            "TProxyPort is required before adding a QUIC proxy peer"
                                                .to_string(),
                                        ),
                                    };
                                    let _ =
                                        write_uds_json(&mut stream, &resp, framed_response).await;
                                    return;
                                }
                            }

                            let prepared_client_pool = if uds_runtime_mode == RuntimeMode::Client
                                && peer_has_l4_proxy(&new_peer)
                            {
                                match build_peer_quic_pool(client_private_key, &new_peer).await {
                                    Ok(pool) => Some(pool),
                                    Err(e) => {
                                        let resp = ApiResponse {
                                            status: "Error".to_string(),
                                            message: Some(format!(
                                                "Failed to establish QUIC pool for peer: {}",
                                                e
                                            )),
                                        };
                                        let _ = write_uds_json(&mut stream, &resp, framed_response)
                                            .await;
                                        return;
                                    }
                                }
                            } else {
                                None
                            };
                            if !table_off {
                                if let Some(peer) = old_peer.clone() {
                                    let interface_name = interface_name.clone();
                                    let _ = run_blocking_command(move || {
                                        let _ = cleanup_peer_routes_and_tproxy(
                                            &peer,
                                            tproxy_port,
                                            &interface_name,
                                        );
                                        Ok(())
                                    })
                                    .await;
                                }
                            }
                            if !table_off {
                                let new_peer_for_routes = new_peer.clone();
                                let interface_name_for_routes = interface_name.clone();
                                let setup_result = run_blocking_command(move || {
                                    setup_peer_routes_and_tproxy(
                                        &new_peer_for_routes,
                                        tproxy_port,
                                        &interface_name_for_routes,
                                    )
                                })
                                .await;
                                if let Err(e) = setup_result {
                                    if let Some(pool) = prepared_client_pool.as_ref() {
                                        pool.shutdown(b"Peer route setup failed");
                                    }
                                    let new_peer_for_cleanup = new_peer.clone();
                                    let interface_name_for_cleanup = interface_name.clone();
                                    let _ = run_blocking_command(move || {
                                        let _ = cleanup_peer_routes_and_tproxy(
                                            &new_peer_for_cleanup,
                                            tproxy_port,
                                            &interface_name_for_cleanup,
                                        );
                                        Ok(())
                                    })
                                    .await;
                                    if let Some(peer) = old_peer.clone() {
                                        let interface_name = interface_name.clone();
                                        let _ = run_blocking_command(move || {
                                            setup_peer_routes_and_tproxy(
                                                &peer,
                                                tproxy_port,
                                                &interface_name,
                                            )
                                        })
                                        .await;
                                    }
                                    let resp = ApiResponse {
                                        status: "Error".to_string(),
                                        message: Some(format!(
                                            "Failed to sync peer routes/tproxy: {}",
                                            e
                                        )),
                                    };
                                    let _ =
                                        write_uds_json(&mut stream, &resp, framed_response).await;
                                    return;
                                }
                            }
                            let interface_name_for_kernel = interface_name.clone();
                            let new_peer_for_kernel = new_peer.clone();
                            if let Err(e) = run_blocking_command(move || {
                                sync_peer_to_kernel(
                                    &interface_name_for_kernel,
                                    &new_peer_for_kernel,
                                )
                            })
                            .await
                            {
                                if let Some(pool) = prepared_client_pool.as_ref() {
                                    pool.shutdown(b"Peer kernel sync failed");
                                }
                                if !table_off {
                                    let new_peer_for_cleanup = new_peer.clone();
                                    let interface_name_for_cleanup = interface_name.clone();
                                    let _ = run_blocking_command(move || {
                                        let _ = cleanup_peer_routes_and_tproxy(
                                            &new_peer_for_cleanup,
                                            tproxy_port,
                                            &interface_name_for_cleanup,
                                        );
                                        Ok(())
                                    })
                                    .await;
                                    if let Some(peer) = old_peer.clone() {
                                        let interface_name = interface_name.clone();
                                        let _ = run_blocking_command(move || {
                                            setup_peer_routes_and_tproxy(
                                                &peer,
                                                tproxy_port,
                                                &interface_name,
                                            )
                                        })
                                        .await;
                                    }
                                }
                                let resp = ApiResponse {
                                    status: "Error".to_string(),
                                    message: Some(format!("Failed to sync peer to kernel: {}", e)),
                                };
                                let _ = write_uds_json(&mut stream, &resp, framed_response).await;
                                return;
                            }

                            // 1. 动态生成并缓存 Diffie-Hellman 共享密钥
                            let peer_pub = PublicKey::from(parsed_pub_key);
                            let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
                            peer_secrets
                                .write()
                                .unwrap()
                                .insert(parsed_pub_key, shared_secret);

                            // 2. 动态更新 AllowedIPs 路由树与 peers 配置
                            {
                                let mut st = state.write().unwrap();
                                st.config.peers.retain(|p| p.public_key != parsed_pub_key);
                                st.config.peers.push(new_peer);
                                st.router = rebuild_l4_router(&st.config.peers);
                            }
                            if uds_runtime_mode == RuntimeMode::Client {
                                let old_pool = {
                                    let mut pools = client_quic_pools.write().unwrap();
                                    if let Some(pool) = prepared_client_pool {
                                        pools.insert(parsed_pub_key, pool)
                                    } else {
                                        pools.remove(&parsed_pub_key)
                                    }
                                };
                                if let Some(pool) = old_pool {
                                    pool.shutdown(b"Peer replaced");
                                }
                            }

                            let resp = ApiResponse {
                                status: "Ok".to_string(),
                                message: None,
                            };
                            let _ = write_uds_json(&mut stream, &resp, framed_response).await;
                        }
                        CommandInput::RemovePeer { public_key } => {
                            let parsed_pub_key = match decode_base64_32(&public_key) {
                                Ok(k) => k,
                                Err(e) => {
                                    let resp = ApiResponse {
                                        status: "Error".to_string(),
                                        message: Some(format!("Invalid public key: {}", e)),
                                    };
                                    let _ =
                                        write_uds_json(&mut stream, &resp, framed_response).await;
                                    return;
                                }
                            };

                            let (removed_peer, table_off, tproxy_port) = {
                                let st = state.read().unwrap();
                                (
                                    st.config
                                        .peers
                                        .iter()
                                        .find(|p| p.public_key == parsed_pub_key)
                                        .cloned(),
                                    st.config
                                        .interface
                                        .table
                                        .as_deref()
                                        .map(|t| t.eq_ignore_ascii_case("off"))
                                        .unwrap_or(false),
                                    st.config.interface.tproxy_port,
                                )
                            };

                            peer_secrets.write().unwrap().remove(&parsed_pub_key);
                            session_cache.lock().unwrap().remove(&parsed_pub_key);
                            auth_nonce_cache.lock().unwrap().remove(&parsed_pub_key);
                            if uds_runtime_mode == RuntimeMode::Client {
                                if let Some(pool) =
                                    client_quic_pools.write().unwrap().remove(&parsed_pub_key)
                                {
                                    pool.shutdown(b"Peer removed");
                                }
                            }
                            if let Some(conns) =
                                shared_quic_registry.lock().unwrap().remove(&parsed_pub_key)
                            {
                                for conn in conns {
                                    conn.close(b"Peer removed");
                                }
                            }

                            {
                                let mut st = state.write().unwrap();
                                st.config.peers.retain(|p| p.public_key != parsed_pub_key);
                                st.router = rebuild_l4_router(&st.config.peers);
                            }

                            let mut remove_errors = Vec::new();
                            if let Some(peer) = &removed_peer {
                                if !table_off {
                                    let peer = peer.clone();
                                    let interface_name_for_cleanup = interface_name.clone();
                                    if let Err(e) = run_blocking_command(move || {
                                        cleanup_peer_routes_and_tproxy(
                                            &peer,
                                            tproxy_port,
                                            &interface_name_for_cleanup,
                                        )
                                    })
                                    .await
                                    {
                                        remove_errors
                                            .push(format!("failed to clean routes/tproxy: {}", e));
                                    }
                                }
                            }
                            let interface_name_for_kernel = interface_name.clone();
                            if let Err(e) = run_blocking_command(move || {
                                remove_peer_from_kernel(&interface_name_for_kernel, parsed_pub_key)
                            })
                            .await
                            {
                                remove_errors.push(format!("failed to remove kernel peer: {}", e));
                            }

                            let resp = ApiResponse {
                                status: "Ok".to_string(),
                                message: if remove_errors.is_empty() {
                                    None
                                } else {
                                    Some(format!(
                                        "Peer removed; cleanup warnings: {}",
                                        remove_errors.join("; ")
                                    ))
                                },
                            };
                            let _ = write_uds_json(&mut stream, &resp, framed_response).await;
                        }
                    }
                });
            }
        });
    }

    if runtime_mode == RuntimeMode::Server {
        log::info!("------------------------------------------------------");
        log::info!("         STARTING GATEWAY IN [ SERVER MODE ]         ");
        log::info!("------------------------------------------------------");

        let Some(listen_control_port) = config.interface.listen_control_port else {
            log::error!("Server config validation failed to enforce ListenControlPort");
            let cleanup_config = gateway_state.read().unwrap().config.clone();
            cleanup_runtime(&cleanup_config, &interface_name);
            std::process::exit(1);
        };

        let (quic_certs, quic_key) = match generate_self_signed_cert() {
            Ok(cert) => cert,
            Err(e) => {
                log::error!("Failed to generate QUIC certificate: {}", e);
                let cleanup_config = gateway_state.read().unwrap().config.clone();
                cleanup_runtime(&cleanup_config, &interface_name);
                std::process::exit(1);
            }
        };
        let quic_cert_sha256 = match cert_sha256(&quic_certs) {
            Ok(fingerprint) => fingerprint,
            Err(e) => {
                log::error!("Failed to fingerprint QUIC certificate: {}", e);
                let cleanup_config = gateway_state.read().unwrap().config.clone();
                cleanup_runtime(&cleanup_config, &interface_name);
                std::process::exit(1);
            }
        };

        // 启动用户态独立公网控制通道协商服务器 (传递动态 peer_secrets 哈希表)
        let control_server = ControlServer::new(
            listen_control_port,
            peer_secrets.clone(),
            config.quic_pool.listen_ports.clone(),
            config.quic_pool.public_ipv4.clone(),
            config.quic_pool.public_ipv6.clone(),
            quic_cert_sha256,
            session_cache.clone(),
        );

        let control_task = match control_server.start().await {
            Ok(handle) => handle,
            Err(e) => {
                log::error!("Control plane server failed to start: {}", e);
                let cleanup_config = gateway_state.read().unwrap().config.clone();
                cleanup_runtime(&cleanup_config, &interface_name);
                std::process::exit(1);
            }
        };

        // 启动用户态多路复用平行 QUIC 物理池接收服务器
        let quic_server = QuicPoolServer::new(
            config.quic_pool.listen_ports.clone(),
            session_cache.clone(),
            auth_nonce_cache.clone(),
        );
        // 删除多余的锁操作（shared_quic_registry 与 server 内部 registry 已通过 run_with_registry 共享）
        let telemetry_for_handler = telemetry_registry.clone();
        let shared_reg_for_server = shared_quic_registry.clone();
        let stream_handler_limit = Arc::new(tokio::sync::Semaphore::new(MAX_QUIC_STREAM_HANDLERS));
        let handler = Arc::new(
            move |client_pub: [u8; 32],
                  mut send_mux: quinn::SendStream,
                  mut recv_mux: quinn::RecvStream,
                  conn_stat: Arc<quic_pool::QuicConnStats>| {
                let permit = match stream_handler_limit.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!(
                            "QUIC stream handler limit reached; rejecting stream for peer {:?}",
                            client_pub
                        );
                        return;
                    }
                };
                let stats = telemetry_for_handler.get_or_create(client_pub);
                tokio::spawn(async move {
                    let _permit = permit;
                    let target_addr = match timeout(
                        Duration::from_secs(5),
                        read_target_addr(&mut recv_mux),
                    )
                    .await
                    {
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

                    log::info!(
                        "Establishing userspace TCP proxy bridge to target destination: {}",
                        target_addr
                    );
                    match timeout(
                        Duration::from_secs(5),
                        tokio::net::TcpStream::connect(target_addr),
                    )
                    .await
                    {
                        Ok(Ok(tcp_socket)) => {
                            if let Err(e) = set_tcp_keepalive(&tcp_socket) {
                                log::warn!(
                                    "Failed to set TCP Keep-Alive on target TCP stream: {}",
                                    e
                                );
                            }
                            if send_mux.write_all(&[1]).await.is_ok() {
                                relay::relay_connections_with_conn_stat(
                                    tcp_socket, send_mux, recv_mux, stats, conn_stat,
                                )
                                .await;
                            }
                        }
                        Ok(Err(e)) => {
                            log::warn!(
                                "Failed to establish TCP connection to target {}: {}",
                                target_addr,
                                e
                            );
                            let _ = send_mux.write_all(&[0]).await;
                        }
                        Err(_) => {
                            log::warn!("Timed out connecting to target {}", target_addr);
                            let _ = send_mux.write_all(&[0]).await;
                        }
                    }
                });
            },
        );

        if let Err(e) = quic_server
            .run_with_registry(quic_certs, quic_key, handler, shared_reg_for_server)
            .await
        {
            log::error!("QUIC Pool Server error: {}", e);
            control_task.abort();
            let cleanup_config = gateway_state.read().unwrap().config.clone();
            cleanup_runtime(&cleanup_config, &interface_name);
            std::process::exit(1);
        }

        wait_for_shutdown().await;
        control_task.abort();
    } else {
        log::info!("------------------------------------------------------");
        log::info!("         STARTING GATEWAY IN [ CLIENT MODE ]         ");
        log::info!("------------------------------------------------------");

        let proxy_peers = config
            .peers
            .iter()
            .filter(|peer| peer_has_l4_proxy(peer))
            .cloned()
            .collect::<Vec<_>>();
        if proxy_peers.is_empty() {
            log::warn!("No QUIC proxy peers configured; TPROXY offload remains inactive.");
        }

        for peer in &proxy_peers {
            match build_peer_quic_pool(config.interface.private_key, peer).await {
                Ok(pool) => {
                    client_quic_pools
                        .write()
                        .unwrap()
                        .insert(peer.public_key, pool);
                }
                Err(e) => {
                    log::error!(
                        "Failed to establish QUIC pool for peer {}: {}",
                        encode_base64_32(&peer.public_key),
                        e
                    );
                    let cleanup_config = gateway_state.read().unwrap().config.clone();
                    cleanup_runtime(&cleanup_config, &interface_name);
                    std::process::exit(1);
                }
            }
        }

        if proxy_peers.is_empty() && config.interface.tproxy_port.is_none() {
            wait_for_shutdown().await;
        } else {
            let tproxy_port = match config.interface.tproxy_port {
                Some(port) => port,
                None => {
                    log::error!("Error: TProxyPort required for Client mode");
                    let cleanup_config = gateway_state.read().unwrap().config.clone();
                    cleanup_runtime(&cleanup_config, &interface_name);
                    std::process::exit(1);
                }
            };
            let tproxy_v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), tproxy_port);
            let tproxy_v4_listener = match tproxy::create_tproxy_listener(tproxy_v4_addr) {
                Ok(l) => l,
                Err(e) => {
                    log::error!("IPv4 TPROXY Listener bind FAILED: {}", e);
                    let cleanup_config = gateway_state.read().unwrap().config.clone();
                    cleanup_runtime(&cleanup_config, &interface_name);
                    std::process::exit(1);
                }
            };
            let tproxy_v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), tproxy_port);
            let tproxy_v6_listener = match tproxy::create_tproxy_listener(tproxy_v6_addr) {
                Ok(l) => Some(l),
                Err(e) => {
                    log::warn!(
                        "IPv6 TPROXY Listener bind FAILED: {}. IPv4 interception remains active.",
                        e
                    );
                    None
                }
            };

            log::info!("------------------------------------------------------");
            log::info!(
                "  TPROXY TCP transparent intercept running on port {} ",
                tproxy_port
            );
            log::info!("  All TCP streams routed to AllowedIPs will offload to ");
            log::info!("  Parallel Userspace QUIC Connection Pool bypass L3 !  ");
            log::info!("------------------------------------------------------");

            let tproxy_connection_limit =
                Arc::new(tokio::sync::Semaphore::new(MAX_TPROXY_CONNECTIONS));
            if let Some(listener) = tproxy_v6_listener {
                tokio::spawn(run_tproxy_accept_loop(
                    listener,
                    client_quic_pools.clone(),
                    gateway_state.clone(),
                    telemetry_registry.clone(),
                    tproxy_connection_limit.clone(),
                ));
            }

            tokio::select! {
                _ = run_tproxy_accept_loop(
                    tproxy_v4_listener,
                    client_quic_pools.clone(),
                    gateway_state.clone(),
                    telemetry_registry.clone(),
                    tproxy_connection_limit.clone(),
                ) => {}
                _ = wait_for_shutdown() => {}
            }
        }
    }

    // 自动清理路由与 iptables
    let cleanup_config = gateway_state.read().unwrap().config.clone();
    cleanup_runtime(&cleanup_config, &interface_name);
}

// CLI 遥测查看实用工具实现
async fn run_cli_stats() -> Result<(), String> {
    let socket_path =
        std::env::var("NEW_PROXY_API_SOCKET").unwrap_or_else(|_| api_socket_path("tun0"));
    let mut stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .map_err(|e| {
            format!(
                "Cannot connect to gateway API socket. Gateway not running? Error: {}",
                e
            )
        })?;

    // 发起 Stats 命令 JSON
    let cmd = CommandInput::Stats;
    let json_bytes = serde_json::to_vec(&cmd).unwrap();
    stream
        .write_u32(json_bytes.len() as u32)
        .await
        .map_err(|e| format!("Failed to write stats request length: {}", e))?;
    stream
        .write_all(&json_bytes)
        .await
        .map_err(|e| format!("Failed to write stats request: {}", e))?;
    let _ = stream.shutdown().await;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("Failed to read stats from socket: {}", e))?;

    let body = if buf.len() >= 4 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len == buf.len().saturating_sub(4) {
            &buf[4..]
        } else {
            &buf[..]
        }
    } else {
        &buf[..]
    };

    let stats: Vec<UnifiedTelemetry> =
        serde_json::from_slice(body).map_err(|e| format!("Failed to parse JSON stats: {}", e))?;

    println!("\n+-------------------------------------------------------------------------------------------------------------------------------------------+");
    println!("|                                             HYBRID SECURE PROXY GATEWAY TELEMETRY                                                         |");
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");
    println!(
        "| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |",
        "Peer Public Key",
        "Source",
        "L3 Transfer (RX/TX)",
        "L4 Transfer (RX/TX)",
        "Handshake (ago)",
        "Active Strm"
    );
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for s in stats {
        let l3_str = format!(
            "{}/{}",
            format_bytes(s.l3_rx_bytes),
            format_bytes(s.l3_tx_bytes)
        );
        let l4_str = format!(
            "{}/{}",
            format_bytes(s.l4_rx_bytes),
            format_bytes(s.l4_tx_bytes)
        );
        let handshake_str = if s.last_handshake == 0 {
            "never".to_string()
        } else if now > s.last_handshake {
            format!("{}s", now - s.last_handshake)
        } else {
            "0s".to_string()
        };

        println!(
            "| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |",
            s.public_key, s.source, l3_str, l4_str, handshake_str, s.active_streams
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

    #[test]
    fn test_l4_router_only_contains_proxy_peers() {
        let proxy_peer = config::PeerConfig {
            public_key: [1u8; 32],
            allowed_ips: vec!["10.10.0.0/16".parse().unwrap()],
            endpoint: Some("127.0.0.1:51820".parse().unwrap()),
            proxy_port: Some(51821),
        };
        let wg_only_peer = config::PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: vec!["10.20.0.0/16".parse().unwrap()],
            endpoint: None,
            proxy_port: None,
        };

        let router = rebuild_l4_router(&[proxy_peer, wg_only_peer]);

        assert_eq!(
            router.longest_match("10.10.1.1".parse().unwrap()),
            Some([1u8; 32])
        );
        assert_eq!(router.longest_match("10.20.1.1".parse().unwrap()), None);
    }

    #[test]
    fn test_client_mode_peer_proxy_fields_must_be_paired() {
        let mut config = GatewayConfig {
            interface: config::InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.2/24".parse().unwrap()],
                listen_port: None,
                listen_control_port: None,
                tproxy_port: Some(1080),
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
            },
            peers: vec![config::PeerConfig {
                public_key: [2u8; 32],
                allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
                endpoint: Some("127.0.0.1:51820".parse().unwrap()),
                proxy_port: Some(51821),
            }],
            quic_pool: config::QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![],
            },
        };

        assert_eq!(determine_runtime_mode(&config), Ok(RuntimeMode::Client));
        config.interface.tproxy_port = None;
        assert!(determine_runtime_mode(&config)
            .unwrap_err()
            .contains("TProxyPort is required"));
        config.interface.tproxy_port = Some(1080);
        config.peers[0].proxy_port = None;
        assert!(determine_runtime_mode(&config)
            .unwrap_err()
            .contains("must define both Endpoint and ProxyPort"));
        config.peers[0].endpoint = None;
        assert_eq!(determine_runtime_mode(&config), Ok(RuntimeMode::Client));
    }

    #[test]
    fn test_select_quic_endpoint_ip_rejects_invalid_advertised_public_ips() {
        let fallback_v4 = "10.0.2.2:51820".parse::<SocketAddr>().unwrap();
        let fallback_v6 = "[fd00:2::2]:51820".parse::<SocketAddr>().unwrap();

        let mut resp = control::ControlResponse {
            session_psk: [1u8; 32],
            server_nonce: [4u8; 16],
            port_pool: vec![40001],
            public_ipv4: Some("not-an-ipv4".to_string()),
            public_ipv6: None,
            quic_cert_sha256: [2u8; 32],
        };
        assert!(select_quic_endpoint_ip(&resp, fallback_v4)
            .unwrap_err()
            .contains("Invalid server PublicIPv4"));

        resp.public_ipv4 = None;
        resp.public_ipv6 = Some("not-an-ipv6".to_string());
        assert!(select_quic_endpoint_ip(&resp, fallback_v6)
            .unwrap_err()
            .contains("Invalid server PublicIPv6"));

        resp.public_ipv6 = None;
        assert_eq!(
            select_quic_endpoint_ip(&resp, fallback_v6).unwrap(),
            fallback_v6.ip()
        );
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

    #[tokio::test]
    async fn test_uds_raw_request_gets_raw_response() {
        use std::fs;
        use tokio::net::UnixListener;

        let test_uds_path = "/tmp/test_uds_raw_compat.sock";
        let _ = fs::remove_file(test_uds_path);
        let listener = UnixListener::bind(test_uds_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_uds_command(&mut stream).await.unwrap();
            assert!(!request.framed);
            match request.command {
                CommandInput::Stats => {}
                _ => panic!("unexpected command"),
            }
            let resp = ApiResponse {
                status: "Ok".to_string(),
                message: None,
            };
            write_uds_json(&mut stream, &resp, request.framed)
                .await
                .unwrap();
        });

        let mut client = tokio::net::UnixStream::connect(test_uds_path)
            .await
            .unwrap();
        let cmd = serde_json::to_vec(&CommandInput::Stats).unwrap();
        client.write_all(&cmd).await.unwrap();
        client.shutdown().await.unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp.first(), Some(&b'{'));
        let api_resp: ApiResponse = serde_json::from_slice(&resp).unwrap();
        assert_eq!(api_resp.status, "Ok");

        server.await.unwrap();
        let _ = fs::remove_file(test_uds_path);
    }

    #[tokio::test]
    async fn test_uds_framed_request_gets_framed_response() {
        use std::fs;
        use tokio::net::UnixListener;

        let test_uds_path = "/tmp/test_uds_framed_compat.sock";
        let _ = fs::remove_file(test_uds_path);
        let listener = UnixListener::bind(test_uds_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_uds_command(&mut stream).await.unwrap();
            assert!(request.framed);
            match request.command {
                CommandInput::Stats => {}
                _ => panic!("unexpected command"),
            }
            let resp = ApiResponse {
                status: "Ok".to_string(),
                message: Some("framed".to_string()),
            };
            write_uds_json(&mut stream, &resp, request.framed)
                .await
                .unwrap();
        });

        let mut client = tokio::net::UnixStream::connect(test_uds_path)
            .await
            .unwrap();
        let cmd = serde_json::to_vec(&CommandInput::Stats).unwrap();
        client.write_u32(cmd.len() as u32).await.unwrap();
        client.write_all(&cmd).await.unwrap();
        client.shutdown().await.unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let len = u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
        assert_eq!(len, resp.len() - 4);
        let api_resp: ApiResponse = serde_json::from_slice(&resp[4..]).unwrap();
        assert_eq!(api_resp.status, "Ok");
        assert_eq!(api_resp.message.as_deref(), Some("framed"));

        server.await.unwrap();
        let _ = fs::remove_file(test_uds_path);
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
        use std::fs;
        use tokio::net::UnixListener;

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
        let peer_secrets = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let server_secret = StaticSecret::from(config.interface.private_key);
        let shared_quic_registry: quic_pool::PeerConnRegistry =
            Arc::new(Mutex::new(HashMap::new()));

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
                        let _ = stream
                            .write_all(&serde_json::to_vec(&response).unwrap())
                            .await;
                    }
                    CommandInput::Dump => {
                        let response = "mock_dump_line\n";
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    CommandInput::AddPeer {
                        public_key,
                        allowed_ips: _,
                        endpoint: _,
                        proxy_port: _,
                    } => {
                        let parsed_pub_key = decode_base64_32(&public_key).unwrap();
                        let peer_pub = PublicKey::from(parsed_pub_key);
                        let shared_secret =
                            server_secret_clone.diffie_hellman(&peer_pub).to_bytes();
                        peer_secrets_clone
                            .write()
                            .unwrap()
                            .insert(parsed_pub_key, shared_secret);

                        let resp = ApiResponse {
                            status: "ok".to_string(),
                            message: None,
                        };
                        let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                    }
                    CommandInput::RemovePeer { public_key } => {
                        let _ = decode_base64_32(&public_key).unwrap();
                        let resp = ApiResponse {
                            status: "ok".to_string(),
                            message: None,
                        };
                        let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                    }
                }
            }
        });

        // 给服务端启动的时间
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 3. 客户端发送 Stats 请求
        {
            let mut stream = tokio::net::UnixStream::connect(test_uds_path)
                .await
                .unwrap();
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
        use std::fs;
        use tokio::net::UnixListener;

        let test_uds_path = "/tmp/test_main_api_add_remove.sock";
        let _ = fs::remove_file(test_uds_path);

        let listener = UnixListener::bind(test_uds_path).unwrap();

        let private_key = [1u8; 32];
        let server_secret = StaticSecret::from(private_key);
        let peer_secrets = Arc::new(std::sync::RwLock::new(HashMap::new()));

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
                        CommandInput::AddPeer {
                            public_key,
                            allowed_ips: _,
                            endpoint: _,
                            proxy_port: _,
                        } => {
                            let parsed_pub_key = decode_base64_32(&public_key).unwrap();
                            let peer_pub = PublicKey::from(parsed_pub_key);
                            let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
                            peer_secrets
                                .write()
                                .unwrap()
                                .insert(parsed_pub_key, shared_secret);

                            let resp = ApiResponse {
                                status: "ok".to_string(),
                                message: None,
                            };
                            let _ = stream.write_all(&serde_json::to_vec(&resp).unwrap()).await;
                        }
                        CommandInput::RemovePeer { public_key } => {
                            let parsed_pub_key = decode_base64_32(&public_key).unwrap();
                            peer_secrets.write().unwrap().remove(&parsed_pub_key);

                            let resp = ApiResponse {
                                status: "ok".to_string(),
                                message: None,
                            };
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
            let mut stream = tokio::net::UnixStream::connect(test_uds_path)
                .await
                .unwrap();
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
            let mut stream = tokio::net::UnixStream::connect(test_uds_path)
                .await
                .unwrap();
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
        let peer_secrets = Arc::new(std::sync::RwLock::new(HashMap::new()));

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
                },
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
        l3_stats.insert(
            [1u8; 32],
            WgPeerStats {
                allowed_ips: vec!["10.0.1.0/24".to_string()],
                endpoint: Some("127.0.0.1:12345".to_string()),
                rx_bytes: 100,
                tx_bytes: 200,
                last_handshake: 0,
            },
        );
        l3_stats.insert(
            [3u8; 32],
            WgPeerStats {
                allowed_ips: vec!["10.0.3.0/24".to_string()],
                endpoint: Some("127.0.0.1:12347".to_string()),
                rx_bytes: 300,
                tx_bytes: 400,
                last_handshake: 0,
            },
        );

        let sources = sync_kernel_and_proxy_state(
            "tun_test_sync",
            &gateway_state,
            &peer_secrets,
            &server_secret,
            &l3_stats,
        )
        .await;

        assert_eq!(sources.get(&[1u8; 32]).unwrap(), "both");
        assert_eq!(sources.get(&[2u8; 32]).unwrap(), "proxy");
        assert_eq!(sources.get(&[3u8; 32]).unwrap(), "kernel");

        let st = gateway_state.read().unwrap();
        let peer3 = st.config.peers.iter().find(|p| p.public_key == [3u8; 32]);
        assert!(
            peer3.is_some(),
            "Peer [3u8; 32] should be synced to proxy config"
        );
        let peer3_config = peer3.unwrap();
        assert_eq!(
            peer3_config.allowed_ips[0],
            "10.0.3.0/24".parse::<ipnet::IpNet>().unwrap()
        );

        let lookup_res = st
            .router
            .longest_match(std::net::IpAddr::V4("10.0.3.5".parse().unwrap()));
        assert_eq!(
            lookup_res, None,
            "Kernel-synced peers are WireGuard-only unless they explicitly define ProxyPort"
        );

        let secrets = peer_secrets.read().unwrap();
        assert!(
            secrets.contains_key(&[3u8; 32]),
            "Peer [3u8; 32] secret should be computed"
        );
    }

    #[test]
    fn test_dynamic_peer_removal_caches_cleanup() {
        let peer_secrets = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let session_cache = Arc::new(Mutex::new(HashMap::new()));
        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));

        let pub_key = [5u8; 32];
        let secret = [10u8; 32];
        let session_psk = [15u8; 32];

        // 1. Populate caches
        peer_secrets.write().unwrap().insert(pub_key, secret);
        session_cache.lock().unwrap().insert(pub_key, session_psk);
        auth_nonce_cache
            .lock()
            .unwrap()
            .insert(pub_key, crate::control::NonceCache::new(10));

        // Verify populated
        assert!(peer_secrets.read().unwrap().contains_key(&pub_key));
        assert!(session_cache.lock().unwrap().contains_key(&pub_key));
        assert!(auth_nonce_cache.lock().unwrap().contains_key(&pub_key));

        // 2. Perform dynamic peer removal (mirroring CommandInput::RemovePeer block)
        peer_secrets.write().unwrap().remove(&pub_key);
        session_cache.lock().unwrap().remove(&pub_key);
        auth_nonce_cache.lock().unwrap().remove(&pub_key);

        // 3. Verify completely cleared
        assert!(!peer_secrets.read().unwrap().contains_key(&pub_key));
        assert!(!session_cache.lock().unwrap().contains_key(&pub_key));
        assert!(!auth_nonce_cache.lock().unwrap().contains_key(&pub_key));
    }
}
