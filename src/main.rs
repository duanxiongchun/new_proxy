mod api;
mod app_config;
mod client_proxy;
mod config;
mod control;
mod proxy_proto;
mod quic_pool;
mod relay;
mod routing;
mod runtime;
mod server_proxy;
mod stats_cli;
mod tcp_util;
mod telemetry;
mod tproxy;
mod uds_server;
mod wireguard;
pub mod tun_device;
pub mod tun_io;
pub mod userspace_wg;
pub mod userspace_tcp;
pub mod rtc_loop;






use client_proxy::{build_peer_quic_pool, run_tproxy_accept_loop};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
#[cfg(test)]
use runtime::run_blocking_command;
use runtime::{
    cleanup_proxy_tproxy_rules, cleanup_runtime, run_script, setup_proxy_tproxy_rules,
    setup_routes_and_iptables,
};
use server_proxy::build_stream_handler;
use stats_cli::run_cli_stats;
use telemetry::TelemetryRegistry;
#[cfg(test)]
use wireguard::sync_peer_to_wireguard;

type PeerQuicPools = Arc<parking_lot::RwLock<HashMap<[u8; 32], Arc<QuicPoolClient>>>>;

// 动态网关共享运行时状态 (支持 AllowedIPs 路由基数树热重载)
pub struct GatewayState {
    pub config: GatewayConfig,
    pub router: AllowedIPsRouter<[u8; 32]>,
    pub tproxy_offload_enabled: bool,
}

const TPROXY_FAILOVER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

fn should_enable_tproxy_for_pool_states(
    expected_proxy_peer_count: usize,
    states: &[PoolState],
) -> bool {
    expected_proxy_peer_count > 0
        && states.len() == expected_proxy_peer_count
        && states
            .iter()
            .all(|state| matches!(state, PoolState::Active))
}

fn start_tproxy_failover_manager(
    state: Arc<parking_lot::RwLock<GatewayState>>,
    pools: PeerQuicPools,
    interface_name: String,
    client_private_key: [u8; 32],
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TPROXY_FAILOVER_POLL_INTERVAL).await;

            let (current_enabled, proxy_peers) = {
                let st = state.read();
                (
                    st.tproxy_offload_enabled,
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
                should_enable_tproxy_for_pool_states(proxy_peers.len(), &pool_states);
            if desired_enabled == current_enabled {
                continue;
            }

            state.write().tproxy_offload_enabled = desired_enabled;
            if desired_enabled {
                log::info!("QUIC pools recovered after cooldown; userspace offload active");
            } else {
                log::warn!("At least one QUIC pool is in fallback/recovering; userspace offload disabled, using userspace WireGuard L3 fallback");
            }
        }
    })
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

#[cfg(test)]
async fn sync_wireguard_and_proxy_state(
    interface_name: &str,
    state: &Arc<parking_lot::RwLock<GatewayState>>,
    peer_secrets: &Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    server_secret: &StaticSecret,
    l3_stats: &HashMap<[u8; 32], wireguard::WgPeerStats>,
) -> HashMap<[u8; 32], String> {
    let mut sources = HashMap::new();
    let mut peers_to_sync_to_wireguard = Vec::new();
    let mut peers_to_sync_to_proxy = Vec::new();

    // 1. Identify sources and find peers missing in WireGuard
    {
        let st = state.read();
        for peer in &st.config.peers {
            if l3_stats.contains_key(&peer.public_key) {
                sources.insert(peer.public_key, "both".to_string());
            } else {
                sources.insert(peer.public_key, "proxy".to_string());
                peers_to_sync_to_wireguard.push(peer.clone());
            }
        }
    }

    // 2. Identify peers missing in proxy config
    for (&pub_key, wg_stats) in l3_stats {
        if let std::collections::hash_map::Entry::Vacant(entry) = sources.entry(pub_key) {
            entry.insert("wireguard".to_string());
            peers_to_sync_to_proxy.push((pub_key, wg_stats.clone()));
        }
    }

    // 3. Perform synchronization to WireGuard.
    for peer in peers_to_sync_to_wireguard {
        let interface_name = interface_name.to_string();
        let _ = run_blocking_command(move || {
            sync_peer_to_wireguard(&interface_name, &peer)?;
            Ok(())
        })
        .await;
    }

    // 4. Perform synchronization to proxy (GatewayState peers & Trie router & peer_secrets)
    for (pub_key, wg_stats) in peers_to_sync_to_proxy {
        // Generates and caches the DH shared secret
        let peer_pub = PublicKey::from(pub_key);
        let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
        peer_secrets.write().insert(pub_key, shared_secret);

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
            let mut st = state.write();
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
    let mut num_threads = 1usize;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-config" && i + 1 < args.len() {
            config_path = args[i + 1].clone();
            i += 2;
        } else if args[i] == "--threads" && i + 1 < args.len() {
            if let Ok(t) = args[i + 1].parse::<usize>() {
                num_threads = t;
            }
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

    // 将配置文件中所有静态声明的对等体 (Peers) 下发同步到 WireGuard 设备
    for peer in &config.peers {
        if let Err(e) = wireguard::sync_peer_to_wireguard(&interface_name, peer) {
            log::error!(
                "Failed to sync peer {} to WireGuard on boot: {}",
                encode_base64_32(&peer.public_key),
                e
            );
            cleanup_runtime(&config, &interface_name);
            std::process::exit(1);
        } else {
            log::info!(
                "Successfully synced peer {} to WireGuard on startup",
                encode_base64_32(&peer.public_key)
            );
        }
    }

    // 共享遥测注册中心与运行时共享状态初始化
    let telemetry_registry = Arc::new(TelemetryRegistry::new());

    let initial_router = rebuild_l4_router(&config.peers);

    let gateway_state = Arc::new(parking_lot::RwLock::new(GatewayState {
        config: config.clone(),
        router: initial_router,
        tproxy_offload_enabled: true,
    }));

    // 初始化控制面 Peer Secrets 动态共享哈希表
    let peer_secrets = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let server_secret = StaticSecret::from(config.interface.private_key);
    {
        let mut secrets_guard = peer_secrets.write();
        for peer in &config.peers {
            let peer_pub = PublicKey::from(peer.public_key);
            let shared_secret = server_secret.diffie_hellman(&peer_pub).to_bytes();
            secrets_guard.insert(peer.public_key, shared_secret);
        }
    }

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

    if let Some(listener) = uds_server::bind_listener(&interface_name) {
        uds_server::start(
            listener,
            uds_server::UdsServerContext {
                telemetry: telemetry_registry.clone(),
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
            },
        );
    }

    if runtime_mode == RuntimeMode::Server {
        log::info!("------------------------------------------------------");
        log::info!("         STARTING GATEWAY IN [ SERVER MODE ]         ");
        log::info!("------------------------------------------------------");

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
        if initial_pool_failures > 0
            && !config
                .interface
                .table
                .as_deref()
                .map(|table| table.eq_ignore_ascii_case("off"))
                .unwrap_or(false)
        {
            cleanup_proxy_tproxy_rules(&config, &interface_name);
            gateway_state.write().tproxy_offload_enabled = false;
            log::warn!(
                "Removed proxy TPROXY rules because {} initial QUIC pool(s) failed; traffic will use WireGuard L3 until QUIC recovers",
                initial_pool_failures
            );
        }
        let tproxy_failover_task = start_tproxy_failover_manager(
            gateway_state.clone(),
            client_quic_pools.clone(),
            interface_name.clone(),
            config.interface.private_key,
        );

        if proxy_peers.is_empty() {
            wait_for_shutdown().await;
        } else {
            log::info!("Opening userspace multiqueue TUN device: {} with {} queues", interface_name, num_threads);
            let tun_fds = match tun_device::open_tun(&interface_name, num_threads) {
                Ok(fds) => fds,
                Err(e) => {
                    log::error!("Failed to open TUN device: {}", e);
                    let cleanup_config = gateway_state.read().config.clone();
                    cleanup_runtime(&cleanup_config, &interface_name);
                    std::process::exit(1);
                }
            };

            let peer = config.peers.iter().find(|p| p.endpoint.is_some()).expect("Client requires at least one peer with an endpoint");
            let server_endpoint = peer.endpoint.unwrap();

            // Set up active connection handler
            let gateway_state_clone = gateway_state.clone();
            let client_quic_pools_clone = client_quic_pools.clone();
            let active_conn_handler = Arc::new(move |original_dest: SocketAddr, tx_receiver, rx_sender| {
                let peer_pub_key = {
                    let st = gateway_state_clone.read();
                    st.router.longest_match(original_dest.ip())
                };
                if let Some(peer_pub_key) = peer_pub_key {
                    let quic_pool = {
                        let pools = client_quic_pools_clone.read();
                        pools.get(&peer_pub_key).cloned()
                    };
                    if let Some(quic_pool) = quic_pool {
                        tokio::spawn(async move {
                            crate::client_proxy::bridge_userspace_stream_to_quic(
                                original_dest,
                                quic_pool,
                                tx_receiver,
                                rx_sender,
                            ).await;
                        });
                    }
                }
            });

            let mut worker_tasks = Vec::new();
            for fd in tun_fds {
                let tun_io = Arc::new(match tun_io::AsyncTunIo::new(fd) {
                    Ok(io) => io,
                    Err(e) => {
                        log::error!("Failed to wrap TUN FD in AsyncTunIo: {}", e);
                        std::process::exit(1);
                    }
                });

                let udp_socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
                udp_socket.set_nonblocking(true).unwrap();
                let tokio_udp = Arc::new(tokio::net::UdpSocket::from_std(udp_socket).unwrap());

                let private_key = boringtun::x25519::StaticSecret::from(config.interface.private_key);
                let public_key = boringtun::x25519::PublicKey::from(peer.public_key);
                let wg = userspace_wg::UserspaceWg::new(private_key, public_key).unwrap();

                let ip_cidr_str = config.interface.addresses.first().map(|addr| addr.to_string()).unwrap_or_else(|| "10.0.0.2/24".to_string());
                let ip_cidr = std::str::FromStr::from_str(&ip_cidr_str).unwrap();
                let tcp_stack = userspace_tcp::UserspaceTcpStack::new(ip_cidr).unwrap();

                let mut worker = rtc_loop::RtcWorker::new(
                    tun_io,
                    tokio_udp,
                    server_endpoint,
                    wg,
                    tcp_stack,
                );
                worker.active_conn_handler = Some(active_conn_handler.clone());

                let gateway_state_for_worker = gateway_state.clone();
                let client_quic_pools_for_worker = client_quic_pools.clone();

                let handle = tokio::spawn(async move {
                    if let Err(e) = worker.run_loop(gateway_state_for_worker, client_quic_pools_for_worker).await {
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
        }
        tproxy_failover_task.abort();
    }

    // 自动清理路由与 iptables
    let cleanup_config = gateway_state.read().config.clone();
    cleanup_runtime(&cleanup_config, &interface_name);
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireguard::WgPeerStats;

    #[test]
    fn test_tproxy_failover_policy_requires_all_pools_active() {
        assert!(!should_enable_tproxy_for_pool_states(1, &[]));
        assert!(!should_enable_tproxy_for_pool_states(
            2,
            &[PoolState::Active]
        ));
        assert!(should_enable_tproxy_for_pool_states(
            1,
            &[PoolState::Active]
        ));
        assert!(!should_enable_tproxy_for_pool_states(
            2,
            &[PoolState::Active, PoolState::Fallback,]
        ));
        assert!(!should_enable_tproxy_for_pool_states(
            1,
            &[PoolState::Recovering {
                recovery_start: std::time::Instant::now(),
            },]
        ));
    }

    #[tokio::test]
    async fn test_peer_synchronization() {
        let server_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let peer_secrets = Arc::new(parking_lot::RwLock::new(HashMap::new()));

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
        let gateway_state = Arc::new(parking_lot::RwLock::new(GatewayState {
            config,
            router: initial_router,
            tproxy_offload_enabled: true,
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

        let sources = sync_wireguard_and_proxy_state(
            "tun_test_sync",
            &gateway_state,
            &peer_secrets,
            &server_secret,
            &l3_stats,
        )
        .await;

        assert_eq!(sources.get(&[1u8; 32]).unwrap(), "both");
        assert_eq!(sources.get(&[2u8; 32]).unwrap(), "proxy");
        assert_eq!(sources.get(&[3u8; 32]).unwrap(), "wireguard");

        let st = gateway_state.read();
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
            "WireGuard-synced peers are WireGuard-only unless they explicitly define ProxyPort"
        );

        let secrets = peer_secrets.read();
        assert!(
            secrets.contains_key(&[3u8; 32]),
            "Peer [3u8; 32] secret should be computed"
        );
    }
}
