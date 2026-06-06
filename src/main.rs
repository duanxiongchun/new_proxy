mod api;
mod app_config;
mod client_proxy;
mod config;
mod control;
mod proxy_proto;
mod quic_pool;
mod relay;
mod routing;
pub mod rtc_loop;
mod runtime;
mod server_proxy;
mod socket_mark;
mod stats_cli;
mod tcp_util;
mod telemetry;
pub mod tun_device;
pub mod tun_io;
mod uds_server;
pub mod userspace_tcp;
pub mod userspace_wg;
mod wireguard;
pub mod virtual_tunnel;


use client_proxy::build_peer_quic_pool;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

pub use app_config::encode_base64_32;
use app_config::{
    interface_name_from_config_path, peer_has_l4_proxy, rebuild_l4_router, validate_gateway_config,
    RuntimeMode,
};
use config::GatewayConfig;
use control::ControlServer;
use quic_pool::{
    cert_sha256, generate_self_signed_cert, PoolState, QuicPoolClient, QuicPoolServer,
};
use routing::AllowedIPsRouter;
use runtime::{cleanup_runtime, run_script, setup_routes};
#[cfg(not(tarpaulin))]
use server_proxy::build_stream_handler;
use stats_cli::run_cli_stats;
use telemetry::TelemetryRegistry;

type PeerQuicPools = Arc<parking_lot::RwLock<HashMap<[u8; 32], Arc<QuicPoolClient>>>>;

// 动态网关共享运行时状态 (支持 AllowedIPs 路由基数树热重载)
pub struct GatewayState {
    pub config: GatewayConfig,
    pub router: AllowedIPsRouter<[u8; 32]>,
    pub userspace_tcp_offload_enabled: bool,
}

const USERSPACE_TCP_FAILOVER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Debug, Clone, Eq, PartialEq)]
struct StartupArgs {
    config_path: String,
    num_threads: usize,
    stats: bool,
}

fn parse_startup_args(args: &[String]) -> StartupArgs {
    let mut parsed = StartupArgs {
        config_path: "proxy.conf".to_string(),
        num_threads: 1,
        stats: false,
    };

    if args.len() > 1 && args[1] == "stats" {
        parsed.stats = true;
        return parsed;
    }

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-config" && i + 1 < args.len() {
            parsed.config_path = args[i + 1].clone();
            i += 2;
        } else if args[i] == "--threads" && i + 1 < args.len() {
            if let Ok(threads) = args[i + 1].parse::<usize>() {
                parsed.num_threads = threads.max(1);
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    parsed
}

fn should_enable_userspace_tcp_for_pool_states(
    expected_proxy_peer_count: usize,
    states: &[PoolState],
) -> bool {
    expected_proxy_peer_count > 0
        && states.len() == expected_proxy_peer_count
        && states
            .iter()
            .all(|state| matches!(state, PoolState::Active))
}

#[cfg(not(tarpaulin))]
fn start_userspace_tcp_failover_manager(
    state: Arc<parking_lot::RwLock<GatewayState>>,
    pools: PeerQuicPools,
    client_private_key: [u8; 32],
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(USERSPACE_TCP_FAILOVER_POLL_INTERVAL).await;

            let (current_enabled, proxy_peers) = {
                let st = state.read();
                (
                    st.userspace_tcp_offload_enabled,
                    st.config
                        .peers
                        .iter()
                        .filter(|peer| peer_has_l4_proxy(peer))
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            };
            if proxy_peers.is_empty() {
                continue;
            }

            let missing_peers = {
                let pools_guard = pools.read();
                proxy_peers
                    .iter()
                    .filter(|peer| !pools_guard.contains_key(&peer.public_key))
                    .cloned()
                    .collect::<Vec<_>>()
            };

            for peer in missing_peers {
                log::info!(
                    "Attempting to establish missing QUIC pool for peer {}",
                    encode_base64_32(&peer.public_key)
                );
                match build_peer_quic_pool(client_private_key, &peer).await {
                    Ok(pool) => {
                        let still_configured = {
                            let st = state.read();
                            st.config.peers.iter().any(|configured| {
                                configured.public_key == peer.public_key
                                    && peer_has_l4_proxy(configured)
                            })
                        };
                        if !still_configured {
                            pool.shutdown(b"Peer removed before pool recovery completed");
                            continue;
                        }
                        let mut pools_guard = pools.write();
                        match pools_guard.entry(peer.public_key) {
                            std::collections::hash_map::Entry::Vacant(entry) => {
                                entry.insert(pool);
                                log::info!(
                                    "Recovered missing QUIC pool for peer {}",
                                    encode_base64_32(&peer.public_key)
                                );
                            }
                            std::collections::hash_map::Entry::Occupied(_) => {
                                pool.shutdown(b"Peer pool already recovered");
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to recover missing QUIC pool for peer {}: {}",
                            encode_base64_32(&peer.public_key),
                            e
                        );
                    }
                }
            }

            let pool_states = {
                let pools = pools.read();
                pools
                    .values()
                    .map(|pool| pool.get_state())
                    .collect::<Vec<_>>()
            };
            let desired_enabled =
                should_enable_userspace_tcp_for_pool_states(proxy_peers.len(), &pool_states);
            if desired_enabled == current_enabled {
                continue;
            }

            state.write().userspace_tcp_offload_enabled = desired_enabled;
            if desired_enabled {
                log::info!("QUIC pools recovered after cooldown; userspace offload active");
            } else {
                log::warn!("At least one QUIC pool is in fallback/recovering; userspace offload disabled, using userspace WireGuard L3 fallback");
            }
        }
    })
}

fn effective_client_tun_queues(requested: usize) -> usize {
    requested.max(1)
}

fn build_initial_gateway_state(config: GatewayConfig) -> GatewayState {
    let router = rebuild_l4_router(&config.peers);
    GatewayState {
        config,
        router,
        userspace_tcp_offload_enabled: true,
    }
}

fn derive_peer_secrets(config: &GatewayConfig) -> HashMap<[u8; 32], [u8; 32]> {
    let server_secret = StaticSecret::from(config.interface.private_key);
    config
        .peers
        .iter()
        .map(|peer| {
            let peer_pub = PublicKey::from(peer.public_key);
            (
                peer.public_key,
                server_secret.diffie_hellman(&peer_pub).to_bytes(),
            )
        })
        .collect()
}

fn proxy_peers(config: &GatewayConfig) -> Vec<config::PeerConfig> {
    config
        .peers
        .iter()
        .filter(|peer| peer_has_l4_proxy(peer))
        .cloned()
        .collect()
}

fn smoltcp_ip_cidrs(config: &GatewayConfig) -> Result<Vec<smoltcp::wire::IpCidr>, String> {
    config
        .interface
        .addresses
        .iter()
        .map(|addr| {
            addr.to_string()
                .parse::<smoltcp::wire::IpCidr>()
                .map_err(|e| format!("Invalid smoltcp interface address {}: {:?}", addr, e))
        })
        .collect()
}

fn local_stack_ips(config: &GatewayConfig) -> (Option<IpAddr>, Option<IpAddr>) {
    let local_ipv4 = config
        .interface
        .addresses
        .iter()
        .find_map(|addr| match addr {
            ipnet::IpNet::V4(net) => Some(IpAddr::V4(net.addr())),
            _ => None,
        });
    let local_ipv6 = config
        .interface
        .addresses
        .iter()
        .find_map(|addr| match addr {
            ipnet::IpNet::V6(net) => Some(IpAddr::V6(net.addr())),
            _ => None,
        });
    (local_ipv4, local_ipv6)
}

#[cfg(all(unix, not(tarpaulin)))]
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

#[cfg(all(not(unix), not(tarpaulin)))]
async fn wait_for_shutdown() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl_c");
    log::info!("Received CTRL+C, shutting down...");
}

const MAX_QUIC_STREAM_HANDLERS: usize = 8192;
const MAX_CLIENT_USERSPACE_TCP_BRIDGES: usize = 1024;

fn needs_ipv6_l3_socket(config: &GatewayConfig) -> bool {
    config
        .peers
        .iter()
        .any(|peer| peer.endpoint.map(|addr| addr.is_ipv6()).unwrap_or(false))
        || config
            .interface
            .addresses
            .iter()
            .any(|addr| matches!(addr, ipnet::IpNet::V6(_)))
}

#[cfg(not(tarpaulin))]
fn bind_l3_udp_socket(port: u16, require_ipv6: bool) -> Result<std::net::UdpSocket, String> {
    if require_ipv6 {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(|e| format!("failed to create IPv6 UDP socket: {}", e))?;
        socket
            .set_only_v6(false)
            .map_err(|e| format!("failed to enable dual-stack UDP socket: {}", e))?;
        socket
            .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())
            .map_err(|e| {
                format!(
                    "failed to bind dual-stack UDP socket on port {}: {}",
                    port, e
                )
            })?;
        socket_mark::set_socket2_outer_mark(&socket)?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("failed to set UDP socket nonblocking: {}", e))?;
        Ok(socket.into())
    } else {
        let socket = std::net::UdpSocket::bind(("0.0.0.0", port))
            .map_err(|e| format!("failed to bind IPv4 UDP socket on port {}: {}", port, e))?;
        socket_mark::set_outer_mark(&socket)?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("failed to set UDP socket nonblocking: {}", e))?;
        Ok(socket)
    }
}

#[tokio::main]
#[cfg(not(tarpaulin))]
async fn main() {
    // 初始化日志系统
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let startup_args = parse_startup_args(&args);

    // CLI 遥测展示
    if startup_args.stats {
        if let Err(e) = run_cli_stats().await {
            eprintln!("Error query stats: {}", e);
            std::process::exit(1);
        }
        return;
    }

    log::info!(
        "Loading hybrid secure proxy gateway configuration: {}",
        startup_args.config_path
    );
    let config = match GatewayConfig::load_from_file(&startup_args.config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to parse config {}: {}", startup_args.config_path, e);
            std::process::exit(1);
        }
    };

    let interface_name = match interface_name_from_config_path(&startup_args.config_path) {
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
        if let Err(e) = run_script(pre_script) {
            eprintln!("PreScript failed: {}", e);
            std::process::exit(1);
        }
    }

    // 共享遥测注册中心与运行时共享状态初始化
    let telemetry_registry = Arc::new(TelemetryRegistry::new());
    let worker_telemetry_registry = Arc::new(telemetry::WorkerTelemetryRegistry::new());

    let gateway_state = Arc::new(parking_lot::RwLock::new(build_initial_gateway_state(
        config.clone(),
    )));

    // 初始化控制面 Peer Secrets 动态共享哈希表
    let peer_secrets = Arc::new(parking_lot::RwLock::new(derive_peer_secrets(&config)));
    let server_secret = StaticSecret::from(config.interface.private_key);

    // 初始化会话与 Nonce 动态共享缓存（用于 UDS 动态清理）
    let session_cache = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let auth_nonce_cache = Arc::new(parking_lot::Mutex::new(HashMap::new()));

    // 共享的 QUIC peer 连接注册表：
    // - server 模式下由 QuicPoolServer.run_with_registry 填充
    // - client 模式下不使用，始终为空
    let shared_quic_registry: quic_pool::PeerConnRegistry =
        Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
    let client_quic_pools: PeerQuicPools = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let peer_mutation_lock = Arc::new(tokio::sync::Mutex::new(()));
    let l3_registry =
        match userspace_wg::UserspaceWgRegistry::new(config.interface.private_key, &config.peers) {
            Ok(registry) => registry,
            Err(e) => {
                eprintln!("Failed to initialize userspace WireGuard registry: {}", e);
                std::process::exit(1);
            }
        };

    if let Some(listener) = uds_server::bind_listener(&interface_name) {
        uds_server::start(
            listener,
            uds_server::UdsServerContext {
                telemetry: telemetry_registry.clone(),
                worker_telemetry: worker_telemetry_registry.clone(),
                state: gateway_state.clone(),
                peer_secrets: peer_secrets.clone(),
                server_secret: server_secret.clone(),
                shared_quic_registry: shared_quic_registry.clone(),
                interface_name: interface_name.clone(),
                session_cache: session_cache.clone(),
                auth_nonce_cache: auth_nonce_cache.clone(),
                client_quic_pools: client_quic_pools.clone(),
                client_private_key: config.interface.private_key,
                runtime_mode,
                peer_mutation_lock: peer_mutation_lock.clone(),
                l3_registry: l3_registry.clone(),
            },
        );
    }

    if runtime_mode == RuntimeMode::Server {
        log::info!("------------------------------------------------------");
        log::info!("         STARTING GATEWAY IN [ SERVER MODE ]         ");
        log::info!("------------------------------------------------------");

        let listen_port = match config.interface.listen_port {
            Some(port) => port,
            None => {
                log::error!("Server userspace WireGuard L3 requires Interface.ListenPort");
                cleanup_runtime(&config, &interface_name);
                std::process::exit(1);
            }
        };

        let tun_fds = match tun_device::open_tun(&interface_name, startup_args.num_threads) {
            Ok(fds) => fds,
            Err(e) => {
                log::error!("Failed to open server TUN device: {}", e);
                cleanup_runtime(&config, &interface_name);
                std::process::exit(1);
            }
        };

        if let Err(e) = setup_routes(&config, &interface_name) {
            eprintln!("Failed to setup userspace routes: {}", e);
            cleanup_runtime(&config, &interface_name);
            std::process::exit(1);
        }

        let server_udp = match bind_l3_udp_socket(listen_port, needs_ipv6_l3_socket(&config)) {
            Ok(socket) => socket,
            Err(e) => {
                log::error!(
                    "Failed to bind userspace WireGuard UDP port {}: {}",
                    listen_port,
                    e
                );
                cleanup_runtime(&config, &interface_name);
                std::process::exit(1);
            }
        };
        let server_udp_raw = Arc::new(tokio::net::UdpSocket::from_std(server_udp).unwrap());
        let server_udp = crate::virtual_tunnel::TunnelSocket::Single(server_udp_raw);
        let mut l3_tasks = Vec::new();
        for fd in tun_fds {
            let tun_io = Arc::new(match tun_io::AsyncTunIo::new(fd) {
                Ok(io) => io,
                Err(e) => {
                    log::error!("Failed to wrap server TUN FD in AsyncTunIo: {}", e);
                    cleanup_runtime(&config, &interface_name);
                    std::process::exit(1);
                }
            });
            let task = tokio::spawn(userspace_wg::run_userspace_wg_loop(
                tun_io,
                server_udp.clone(),
                l3_registry.clone(),
            ));
            l3_tasks.push(task);
        }
        let l3_timer_task = tokio::spawn(userspace_wg::run_userspace_wg_timer_loop(
            server_udp.clone(),
            l3_registry.clone(),
        ));

        let Some(listen_control_port) = config.interface.listen_control_port else {
            log::error!("Server config validation failed to enforce ListenControlPort");
            let cleanup_config = gateway_state.read().config.clone();
            cleanup_runtime(&cleanup_config, &interface_name);
            std::process::exit(1);
        };

        let (quic_certs, quic_key) = match generate_self_signed_cert() {
            Ok(cert) => cert,
            Err(e) => {
                log::error!("Failed to generate QUIC certificate: {}", e);
                let cleanup_config = gateway_state.read().config.clone();
                cleanup_runtime(&cleanup_config, &interface_name);
                std::process::exit(1);
            }
        };
        let quic_cert_sha256 = match cert_sha256(&quic_certs) {
            Ok(fingerprint) => fingerprint,
            Err(e) => {
                log::error!("Failed to fingerprint QUIC certificate: {}", e);
                let cleanup_config = gateway_state.read().config.clone();
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
                let cleanup_config = gateway_state.read().config.clone();
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
        let shared_reg_for_server = shared_quic_registry.clone();
        let stream_handler_limit = Arc::new(tokio::sync::Semaphore::new(MAX_QUIC_STREAM_HANDLERS));
        let handler = build_stream_handler(telemetry_registry.clone(), stream_handler_limit);

        if let Err(e) = quic_server
            .run_with_registry(quic_certs, quic_key, handler, shared_reg_for_server)
            .await
        {
            log::error!("QUIC Pool Server error: {}", e);
            control_task.abort();
            let cleanup_config = gateway_state.read().config.clone();
            cleanup_runtime(&cleanup_config, &interface_name);
            std::process::exit(1);
        }

        wait_for_shutdown().await;
        control_task.abort();
        l3_timer_task.abort();
        for task in l3_tasks {
            task.abort();
        }
    } else {
        log::info!("------------------------------------------------------");
        log::info!("         STARTING GATEWAY IN [ CLIENT MODE ]         ");
        log::info!("------------------------------------------------------");

        let proxy_peers = proxy_peers(&config);
        if proxy_peers.is_empty() {
            log::warn!("No QUIC proxy peers configured; userspace TCP offload remains inactive.");
        }

        let mut initial_pool_failures = 0usize;
        for peer in &proxy_peers {
            match build_peer_quic_pool(config.interface.private_key, peer).await {
                Ok(pool) => {
                    client_quic_pools.write().insert(peer.public_key, pool);
                }
                Err(e) => {
                    initial_pool_failures += 1;
                    log::warn!(
                        "Failed to establish initial QUIC pool for peer {}; starting in WireGuard L3 fallback and retrying in background: {}",
                        encode_base64_32(&peer.public_key),
                        e
                    );
                }
            }
        }
        if initial_pool_failures > 0 {
            gateway_state.write().userspace_tcp_offload_enabled = false;
            log::warn!(
                "Disabled userspace TCP offload because {} initial QUIC pool(s) failed; traffic will use userspace WireGuard L3 until QUIC recovers",
                initial_pool_failures
            );
        }
        let userspace_tcp_failover_task = start_userspace_tcp_failover_manager(
            gateway_state.clone(),
            client_quic_pools.clone(),
            config.interface.private_key,
        );

        let effective_num_threads = effective_client_tun_queues(startup_args.num_threads);

        log::info!(
            "Opening userspace multiqueue TUN device: {} with {} queues",
            interface_name,
            effective_num_threads
        );
        let tun_fds = match tun_device::open_tun(&interface_name, effective_num_threads) {
            Ok(fds) => fds,
            Err(e) => {
                log::error!("Failed to open TUN device: {}", e);
                let cleanup_config = gateway_state.read().config.clone();
                cleanup_runtime(&cleanup_config, &interface_name);
                std::process::exit(1);
            }
        };

        if let Err(e) = setup_routes(&config, &interface_name) {
            log::error!("Failed to setup userspace routes: {}", e);
            for fd in tun_fds {
                unsafe {
                    libc::close(fd);
                }
            }
            let cleanup_config = gateway_state.read().config.clone();
            cleanup_runtime(&cleanup_config, &interface_name);
            std::process::exit(1);
        }

        // Set up active connection handler
        let gateway_state_clone = gateway_state.clone();
        let client_quic_pools_clone = client_quic_pools.clone();
        let telemetry_for_client_bridge = telemetry_registry.clone();
        let client_bridge_limit = Arc::new(tokio::sync::Semaphore::new(
            MAX_CLIENT_USERSPACE_TCP_BRIDGES,
        ));
        let client_bridge_limit_for_handler = client_bridge_limit.clone();
        let active_conn_handler = Arc::new(
            move |original_dest: SocketAddr, tx_receiver, rx_sender, worker_notify| {
                let peer_pub_key = {
                    let st = gateway_state_clone.read();
                    st.router.longest_match(original_dest.ip())
                };
                if let Some(peer_pub_key) = peer_pub_key {
                    let permit = match client_bridge_limit_for_handler.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            log::warn!(
                                "Client userspace TCP bridge limit reached; dropping {}",
                                original_dest
                            );
                            return;
                        }
                    };
                    let quic_pool = {
                        let pools = client_quic_pools_clone.read();
                        pools.get(&peer_pub_key).cloned()
                    };
                    if let Some(quic_pool) = quic_pool {
                        let stats = telemetry_for_client_bridge.get_or_create(peer_pub_key);
                        tokio::spawn(async move {
                            let _permit = permit;
                            crate::client_proxy::bridge_userspace_stream_to_quic(
                                original_dest,
                                quic_pool,
                                stats,
                                tx_receiver,
                                rx_sender,
                                worker_notify,
                            )
                            .await;
                        });
                    }
                }
            },
        );

        let client_udp = {
            let mut sockets = Vec::new();
            for i in 0..2 {
                match bind_l3_udp_socket(0, needs_ipv6_l3_socket(&config)) {
                    Ok(socket) => sockets.push(tokio::net::UdpSocket::from_std(socket).unwrap()),
                    Err(e) => {
                        log::error!(
                            "Failed to bind client userspace WireGuard UDP socket {}: {}",
                            i,
                            e
                        );
                        let cleanup_config = gateway_state.read().config.clone();
                        cleanup_runtime(&cleanup_config, &interface_name);
                        std::process::exit(1);
                    }
                }
            }
            let virtual_sock = crate::virtual_tunnel::VirtualTunnelSocket::new(sockets);
            crate::virtual_tunnel::TunnelSocket::Virtual(virtual_sock)
        };
        let l3_timer_task = tokio::spawn(userspace_wg::run_userspace_wg_timer_loop(
            client_udp.clone(),
            l3_registry.clone(),
        ));

        let smoltcp_ip_cidrs = match smoltcp_ip_cidrs(&config) {
            Ok(addrs) => addrs,
            Err(e) => {
                log::error!("{}", e);
                let cleanup_config = gateway_state.read().config.clone();
                cleanup_runtime(&cleanup_config, &interface_name);
                std::process::exit(1);
            }
        };
        let (local_ipv4, local_ipv6) = local_stack_ips(&config);

        let mut worker_tasks = Vec::new();
        for (worker_id, fd) in tun_fds.into_iter().enumerate() {
            let tun_io = Arc::new(match tun_io::AsyncTunIo::new(fd) {
                Ok(io) => io,
                Err(e) => {
                    log::error!("Failed to wrap TUN FD in AsyncTunIo: {}", e);
                    std::process::exit(1);
                }
            });

            let tcp_stack = match userspace_tcp::UserspaceTcpStack::new(
                smoltcp_ip_cidrs.clone(),
                config.interface.mtu as usize,
            ) {
                Ok(stack) => stack,
                Err(e) => {
                    log::error!("Failed to initialize userspace TCP stack: {}", e);
                    std::process::exit(1);
                }
            };

            let mut worker = rtc_loop::RtcWorker::new(
                tun_io,
                client_udp.clone(),
                l3_registry.clone(),
                tcp_stack,
                local_ipv4,
                local_ipv6,
                config.interface.mtu as usize,
            );
            worker.active_conn_handler = Some(active_conn_handler.clone());
            worker.set_worker_stats(worker_telemetry_registry.get_or_create(worker_id));

            let gateway_state_for_worker = gateway_state.clone();
            let client_quic_pools_for_worker = client_quic_pools.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = worker
                    .run_loop(gateway_state_for_worker, client_quic_pools_for_worker)
                    .await
                {
                    log::error!("RtcWorker loop failed: {}", e);
                }
            });
            worker_tasks.push(handle);
        }

        log::info!("------------------------------------------------------");
        log::info!("  Userspace multiqueue TUN transparent proxy running  ");
        log::info!("  All L3 and L4 traffic processed in userspace.       ");
        log::info!("------------------------------------------------------");

        wait_for_shutdown().await;
        for t in worker_tasks {
            t.abort();
        }
        l3_timer_task.abort();
        userspace_tcp_failover_task.abort();
    }

    // 自动清理 userspace TUN 路由
    let cleanup_config = gateway_state.read().config.clone();
    cleanup_runtime(&cleanup_config, &interface_name);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceConfig, PeerConfig, QUICPoolConfig};

    fn peer(public_key: [u8; 32], endpoint: Option<&str>, proxy_port: Option<u16>) -> PeerConfig {
        PeerConfig {
            public_key,
            allowed_ips: vec!["10.10.0.0/16".parse().unwrap()],
            endpoint: endpoint.map(|addr| addr.parse().unwrap()),
            proxy_port,
        }
    }

    fn config_with_peers(peers: Vec<PeerConfig>) -> GatewayConfig {
        GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec![
                    "10.0.0.2/24".parse().unwrap(),
                    "fd00::2/64".parse().unwrap(),
                ],
                listen_port: None,
                listen_control_port: None,
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
            },
            peers,
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: Vec::new(),
            },
        }
    }

    #[test]
    fn test_userspace_tcp_failover_policy_requires_all_pools_active() {
        assert!(!should_enable_userspace_tcp_for_pool_states(1, &[]));
        assert!(!should_enable_userspace_tcp_for_pool_states(
            2,
            &[PoolState::Active]
        ));
        assert!(should_enable_userspace_tcp_for_pool_states(
            1,
            &[PoolState::Active]
        ));
        assert!(!should_enable_userspace_tcp_for_pool_states(
            2,
            &[PoolState::Active, PoolState::Fallback,]
        ));
        assert!(!should_enable_userspace_tcp_for_pool_states(
            1,
            &[PoolState::Recovering {
                recovery_start: std::time::Instant::now(),
            },]
        ));
    }

    #[test]
    fn client_tun_queues_follow_requested_thread_count() {
        assert_eq!(effective_client_tun_queues(4), 4);
        assert_eq!(effective_client_tun_queues(1), 1);
        assert_eq!(effective_client_tun_queues(0), 1);
    }

    #[test]
    fn parse_startup_args_defaults_and_overrides() {
        assert_eq!(
            parse_startup_args(&["new_proxy".to_string()]),
            StartupArgs {
                config_path: "proxy.conf".to_string(),
                num_threads: 1,
                stats: false,
            }
        );
        assert_eq!(
            parse_startup_args(&[
                "new_proxy".to_string(),
                "-config".to_string(),
                "conf/client.conf".to_string(),
                "--threads".to_string(),
                "4".to_string(),
            ]),
            StartupArgs {
                config_path: "conf/client.conf".to_string(),
                num_threads: 4,
                stats: false,
            }
        );
        assert_eq!(
            parse_startup_args(&[
                "new_proxy".to_string(),
                "--threads".to_string(),
                "bad".to_string(),
            ])
            .num_threads,
            1
        );
        assert_eq!(
            parse_startup_args(&[
                "new_proxy".to_string(),
                "--threads".to_string(),
                "0".to_string(),
            ])
            .num_threads,
            1
        );
    }

    #[test]
    fn parse_startup_args_stats_short_circuits_gateway_args() {
        assert_eq!(
            parse_startup_args(&[
                "new_proxy".to_string(),
                "stats".to_string(),
                "-config".to_string(),
                "ignored.conf".to_string(),
            ]),
            StartupArgs {
                config_path: "proxy.conf".to_string(),
                num_threads: 1,
                stats: true,
            }
        );
    }

    #[test]
    fn build_initial_gateway_state_only_routes_l4_proxy_peers() {
        let l4_peer = peer([2u8; 32], Some("127.0.0.1:51820"), Some(4433));
        let wg_only_peer = peer([3u8; 32], None, None);
        let config = config_with_peers(vec![l4_peer.clone(), wg_only_peer]);

        let state = build_initial_gateway_state(config);

        assert!(state.userspace_tcp_offload_enabled);
        assert_eq!(
            state.router.longest_match("10.10.1.2".parse().unwrap()),
            Some(l4_peer.public_key)
        );
    }

    #[test]
    fn derive_peer_secrets_matches_x25519_shared_secret() {
        let server_secret = StaticSecret::from([1u8; 32]);
        let peer_secret = StaticSecret::from([2u8; 32]);
        let peer_public = PublicKey::from(&peer_secret).to_bytes();
        let config = config_with_peers(vec![peer(peer_public, None, None)]);

        let secrets = derive_peer_secrets(&config);

        assert_eq!(
            secrets[&peer_public],
            server_secret
                .diffie_hellman(&PublicKey::from(peer_public))
                .to_bytes()
        );
    }

    #[test]
    fn proxy_peers_filters_wireguard_only_peers() {
        let l4_peer = peer([2u8; 32], Some("127.0.0.1:51820"), Some(4433));
        let config = config_with_peers(vec![l4_peer.clone(), peer([3u8; 32], None, None)]);

        assert_eq!(proxy_peers(&config).len(), 1);
        assert_eq!(proxy_peers(&config)[0].public_key, l4_peer.public_key);
    }

    #[test]
    fn smoltcp_ip_cidrs_and_local_stack_ips_follow_interface_addresses() {
        let config = config_with_peers(Vec::new());

        let cidrs = smoltcp_ip_cidrs(&config).unwrap();
        let (local_ipv4, local_ipv6) = local_stack_ips(&config);

        assert_eq!(cidrs.len(), 2);
        assert_eq!(local_ipv4, Some("10.0.0.2".parse().unwrap()));
        assert_eq!(local_ipv6, Some("fd00::2".parse().unwrap()));
    }

    #[test]
    fn needs_ipv6_l3_socket_when_interface_or_peer_uses_ipv6() {
        let mut config = config_with_peers(Vec::new());
        assert!(needs_ipv6_l3_socket(&config));

        config.interface.addresses = vec!["10.0.0.2/24".parse().unwrap()];
        assert!(!needs_ipv6_l3_socket(&config));

        config.peers = vec![peer([2u8; 32], Some("[::1]:51820"), Some(4433))];
        assert!(needs_ipv6_l3_socket(&config));
    }
}
