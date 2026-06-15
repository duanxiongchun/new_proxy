mod api;
mod app_config;
mod client;
mod config;
mod control;
pub mod datapath;
mod quic_pool;
pub mod quic_proto_engine;
mod routing;
pub mod rtc_loop;
mod runtime;
mod socket_mark;
mod stats_cli;
mod telemetry;
pub mod tun_datapath;
pub mod tun_device;
pub mod tun_io;
pub mod xdp_datapath;
use datapath::Datapath;
use tun_datapath::TunDatapath;
use xdp_datapath::XdpDatapath;
mod uds_server;

use arc_swap::ArcSwap;
use client::{build_peer_quic_pool, negotiate_peer_quic_data_port_count};
use std::collections::HashMap;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

pub use app_config::encode_base64_32;
use app_config::{
    interface_name_from_config_path, peer_has_l4_proxy, rebuild_l4_router, validate_gateway_config,
    RuntimeMode,
};
use config::GatewayConfig;
use quic_pool::{PoolState, QuicPoolClient};
use routing::AllowedIPsRouter;
use runtime::{cleanup_runtime, run_script};
use stats_cli::run_cli_stats;
use telemetry::{TelemetryRegistry, UserspaceWgRegistry};

pub(crate) type PeerQuicPools = Arc<parking_lot::RwLock<HashMap<[u8; 32], Arc<QuicPoolClient>>>>;
pub(crate) type L4DataPlane = Arc<ArcSwap<L4DataPlaneSnapshot>>;
pub(crate) type ClientQuicDataPortBaseline = Arc<parking_lot::Mutex<usize>>;

// 动态网关共享运行时状态 (支持 AllowedIPs 路由基数树热重载)
pub struct GatewayState {
    pub config: GatewayConfig,
    pub router: AllowedIPsRouter<[u8; 32]>,
    pub userspace_tcp_offload_enabled: bool,
}

pub struct L4DataPlaneSnapshot {
    pub router: AllowedIPsRouter<[u8; 32]>,
    pub userspace_tcp_offload_enabled: bool,
    pub client_quic_pools: HashMap<[u8; 32], Arc<QuicPoolClient>>,
}

const USERSPACE_TCP_FAILOVER_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

fn build_l4_data_plane_snapshot(
    state: &GatewayState,
    pools: &HashMap<[u8; 32], Arc<QuicPoolClient>>,
) -> L4DataPlaneSnapshot {
    L4DataPlaneSnapshot {
        router: state.router.clone(),
        userspace_tcp_offload_enabled: state.userspace_tcp_offload_enabled,
        client_quic_pools: pools.clone(),
    }
}

pub(crate) fn current_l4_data_plane_snapshot(
    state: &Arc<parking_lot::RwLock<GatewayState>>,
    pools: &PeerQuicPools,
) -> L4DataPlaneSnapshot {
    let state = state.read();
    let pools = pools.read();
    build_l4_data_plane_snapshot(&state, &pools)
}

pub fn publish_l4_data_plane_snapshot(
    data_plane: &L4DataPlane,
    state: &Arc<parking_lot::RwLock<GatewayState>>,
    pools: &PeerQuicPools,
) {
    data_plane.store(Arc::new(current_l4_data_plane_snapshot(state, pools)));
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct StartupArgs {
    config_path: String,
    stats: bool,
}

fn parse_startup_args(args: &[String]) -> StartupArgs {
    let mut parsed = StartupArgs {
        config_path: "proxy.conf".to_string(),
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
        } else {
            i += 1;
        }
    }

    parsed
}

pub(crate) fn should_enable_userspace_tcp_for_pool_states(
    expected_proxy_peer_count: usize,
    states: &[PoolState],
) -> bool {
    expected_proxy_peer_count > 0
        && states.len() == expected_proxy_peer_count
        && states
            .iter()
            .all(|state| matches!(state, PoolState::Active))
}

pub(crate) fn start_userspace_tcp_failover_manager(
    state: Arc<parking_lot::RwLock<GatewayState>>,
    pools: PeerQuicPools,
    data_plane: L4DataPlane,
    client_private_key: [u8; 32],
    client_quic_data_port_baseline: ClientQuicDataPortBaseline,
    peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(USERSPACE_TCP_FAILOVER_POLL_INTERVAL).await;

            let proxy_peers = {
                let st = state.read();
                st.config
                    .peers
                    .iter()
                    .filter(|peer| peer_has_l4_proxy(peer))
                    .cloned()
                    .collect::<Vec<_>>()
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
                        let _mutation_guard = peer_mutation_lock.lock().await;
                        let endpoint_count = pool.endpoint_count();
                        if let Err(e) = validate_client_quic_data_port_count(&pools, endpoint_count)
                        {
                            pool.shutdown(b"QUIC data port count mismatch");
                            log::warn!(
                                "Rejected recovered QUIC pool for peer {}: {}",
                                encode_base64_32(&peer.public_key),
                                e
                            );
                            continue;
                        }
                        if let Err(e) = validate_client_quic_data_port_count_matches_baseline(
                            endpoint_count,
                            *client_quic_data_port_baseline.lock(),
                        ) {
                            pool.shutdown(b"QUIC data port count does not match baseline");
                            log::warn!(
                                "Rejected recovered QUIC pool for peer {}: {}",
                                encode_base64_32(&peer.public_key),
                                e
                            );
                            continue;
                        }
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
                                record_client_quic_data_port_baseline_if_unset(
                                    &client_quic_data_port_baseline,
                                    endpoint_count,
                                );
                                drop(pools_guard);
                                publish_l4_data_plane_snapshot(&data_plane, &state, &pools);
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

            let _mutation_guard = peer_mutation_lock.lock().await;
            let (current_enabled, proxy_peer_count) = {
                let st = state.read();
                (
                    st.userspace_tcp_offload_enabled,
                    st.config
                        .peers
                        .iter()
                        .filter(|peer| peer_has_l4_proxy(peer))
                        .count(),
                )
            };
            if proxy_peer_count == 0 {
                continue;
            }
            let pool_states = {
                let pools = pools.read();
                pools
                    .values()
                    .map(|pool| pool.get_state())
                    .collect::<Vec<_>>()
            };
            let desired_enabled =
                should_enable_userspace_tcp_for_pool_states(proxy_peer_count, &pool_states);
            if desired_enabled == current_enabled {
                continue;
            }

            state.write().userspace_tcp_offload_enabled = desired_enabled;
            publish_l4_data_plane_snapshot(&data_plane, &state, &pools);
            if desired_enabled {
                log::info!("QUIC pools recovered after cooldown; userspace offload active");
            } else {
                log::warn!("At least one QUIC pool is in fallback/recovering; userspace offload disabled, using userspace WireGuard L3 fallback");
            }
        }
    })
}

pub(crate) fn effective_server_tun_queues(listen_ports: &[u16]) -> usize {
    listen_ports.len().max(1)
}

pub(crate) fn effective_client_tun_queues(quic_data_port_count: usize) -> usize {
    quic_data_port_count.max(1)
}

pub(crate) fn client_quic_data_port_count(
    pools: &PeerQuicPools,
    startup_expected_count: Option<usize>,
) -> Option<usize> {
    pools
        .read()
        .values()
        .map(|pool| pool.endpoint_count())
        .find(|count| *count > 0)
        .or(startup_expected_count)
}

pub(crate) fn record_startup_quic_data_port_count(
    expected_count: &mut Option<usize>,
    candidate_count: usize,
) -> Result<(), String> {
    if candidate_count == 0 {
        return Ok(());
    }
    match *expected_count {
        Some(existing_count) if existing_count != candidate_count => Err(format!(
            "QUIC data port count mismatch during startup: previous peers use {}, this peer uses {}",
            existing_count, candidate_count
        )),
        Some(_) => Ok(()),
        None => {
            *expected_count = Some(candidate_count);
            Ok(())
        }
    }
}

pub(crate) fn validate_client_quic_data_port_count(
    pools: &PeerQuicPools,
    candidate_count: usize,
) -> Result<(), String> {
    let Some(existing_count) = pools
        .read()
        .values()
        .map(|pool| pool.endpoint_count())
        .find(|count| *count > 0)
    else {
        return Ok(());
    };

    if candidate_count == existing_count {
        Ok(())
    } else {
        Err(format!(
            "QUIC data port count mismatch: existing peers use {}, new peer uses {}",
            existing_count, candidate_count
        ))
    }
}

pub(crate) fn validate_client_quic_data_port_count_matches_baseline(
    candidate_count: usize,
    baseline_count: usize,
) -> Result<(), String> {
    if baseline_count == 0 || candidate_count == baseline_count {
        Ok(())
    } else {
        Err(format!(
            "QUIC data port count mismatch: established baseline uses {}, peer uses {}; restart the client with a consistent proxy peer set to change worker topology",
            baseline_count, candidate_count
        ))
    }
}

pub fn record_client_quic_data_port_baseline_if_unset(
    client_quic_data_port_baseline: &parking_lot::Mutex<usize>,
    candidate_count: usize,
) {
    if candidate_count > 0 {
        let mut baseline = client_quic_data_port_baseline.lock();
        if *baseline == 0 {
            *baseline = candidate_count;
        }
    }
}

pub(crate) fn record_initial_client_quic_data_port_baseline(
    client_quic_data_port_baseline: &parking_lot::Mutex<usize>,
    quic_data_port_count: Option<usize>,
) {
    if let Some(count) = quic_data_port_count.filter(|count| *count > 0) {
        *client_quic_data_port_baseline.lock() = count;
    }
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

pub(crate) fn proxy_peers(config: &GatewayConfig) -> Vec<config::PeerConfig> {
    config
        .peers
        .iter()
        .filter(|peer| peer_has_l4_proxy(peer))
        .cloned()
        .collect()
}

#[cfg(unix)]
pub(crate) async fn wait_for_shutdown() {
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
pub(crate) async fn wait_for_shutdown() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl_c");
    log::info!("Received CTRL+C, shutting down...");
}

#[cfg(not(tarpaulin))]
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let startup_args = parse_startup_args(&args);

    if startup_args.stats {
        let runtime = build_tokio_runtime();
        if let Err(e) = runtime.block_on(run_cli_stats()) {
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

    let client_quic_data_port_count = match runtime_mode {
        RuntimeMode::Client => match preflight_client_quic_data_port_count(&config) {
            Ok(count) => count,
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        },
        RuntimeMode::Server => None,
    };
    let runtime = build_tokio_runtime();
    runtime.block_on(run_gateway(
        config,
        interface_name,
        runtime_mode,
        client_quic_data_port_count,
    ));
}

#[cfg(not(tarpaulin))]
fn build_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime")
}

#[cfg(not(tarpaulin))]
fn preflight_client_quic_data_port_count(config: &GatewayConfig) -> Result<Option<usize>, String> {
    let proxy_peers = proxy_peers(config);
    if proxy_peers.is_empty() {
        return Ok(None);
    }

    let runtime = build_tokio_runtime();
    let preflight_count = runtime.block_on(async {
        let mut expected_count = None;
        for peer in &proxy_peers {
            match negotiate_peer_quic_data_port_count(config.interface.private_key, peer).await {
                Ok(data_port_count) => {
                    record_startup_quic_data_port_count(&mut expected_count, data_port_count)?;
                }
                Err(e) => {
                    if let Some(data_port_count) = e.data_port_count() {
                        record_startup_quic_data_port_count(&mut expected_count, data_port_count)?;
                    }
                    log::warn!(
                        "Failed to preflight QUIC data port count for peer {}; using fallback topology if no other peer reports a count: {}",
                        encode_base64_32(&peer.public_key),
                        e
                    );
                }
            }
        }
        Ok::<Option<usize>, String>(expected_count)
    })?;

    match preflight_count {
        Some(count) if count > 0 => Ok(Some(count)),
        Some(_) | None => {
            log::warn!(
                "No QUIC proxy peer reported a data port count during startup preflight; fixing client topology to one queue until restart"
            );
            Ok(Some(1))
        }
    }
}

#[allow(dead_code)]
fn runtime_worker_threads(
    config: &GatewayConfig,
    runtime_mode: RuntimeMode,
    client_quic_data_port_count: Option<usize>,
) -> usize {
    match runtime_mode {
        RuntimeMode::Server => effective_server_tun_queues(&config.quic_pool.listen_ports),
        RuntimeMode::Client => client_quic_data_port_count.unwrap_or(1).max(1),
    }
}

#[cfg(not(tarpaulin))]
async fn run_gateway(
    config: GatewayConfig,
    interface_name: String,
    runtime_mode: RuntimeMode,
    fixed_client_quic_data_port_count: Option<usize>,
) {
    // 执行 PreScript 脚本
    if let Some(ref pre_script) = config.interface.pre_script {
        if let Err(e) = run_script(pre_script) {
            eprintln!("PreScript failed: {}", e);
            std::process::exit(1);
        }
    }

    let tun_queue_count = match runtime_mode {
        RuntimeMode::Server => effective_server_tun_queues(&config.quic_pool.listen_ports),
        RuntimeMode::Client => {
            effective_client_tun_queues(fixed_client_quic_data_port_count.unwrap_or(0))
        }
    };
    let mut peer_telemetries = Vec::new();
    for _ in 0..tun_queue_count {
        peer_telemetries.push(Arc::new(TelemetryRegistry::new()));
    }
    let worker_telemetry_registry = Arc::new(telemetry::WorkerTelemetryRegistry::new());
    let virtual_tunnel_telemetry = Arc::new(telemetry::VirtualTunnelTelemetry::default());

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
        Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    let client_quic_pools: PeerQuicPools = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    let l4_data_plane: L4DataPlane = Arc::new(ArcSwap::from_pointee(
        current_l4_data_plane_snapshot(&gateway_state, &client_quic_pools),
    ));
    let client_quic_data_port_baseline: ClientQuicDataPortBaseline =
        Arc::new(parking_lot::Mutex::new(0));
    let peer_mutation_lock = Arc::new(tokio::sync::Mutex::new(()));
    let exit_notify = Arc::new(tokio::sync::Notify::new());
    let l3_registry = match UserspaceWgRegistry::new(config.interface.private_key, &config.peers) {
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
                peer_telemetries: peer_telemetries.clone(),
                worker_telemetry: worker_telemetry_registry.clone(),
                state: gateway_state.clone(),
                peer_secrets: peer_secrets.clone(),
                server_secret: server_secret.clone(),
                shared_quic_registry: shared_quic_registry.clone(),
                interface_name: interface_name.clone(),
                session_cache: session_cache.clone(),
                auth_nonce_cache: auth_nonce_cache.clone(),
                client_quic_pools: client_quic_pools.clone(),
                l4_data_plane: l4_data_plane.clone(),
                client_private_key: config.interface.private_key,
                runtime_mode,
                peer_mutation_lock: peer_mutation_lock.clone(),
                l3_registry: l3_registry.clone(),
                virtual_tunnel_telemetry: virtual_tunnel_telemetry.clone(),
                client_quic_data_port_baseline: client_quic_data_port_baseline.clone(),
            },
        );
    }

    let datapath: Arc<dyn Datapath> = if config.interface.mode == "af_xdp" {
        Arc::new(
            XdpDatapath::new(
                config.clone(),
                interface_name.clone(),
                runtime_mode,
                fixed_client_quic_data_port_count,
                peer_telemetries,
                worker_telemetry_registry,
                gateway_state.clone(),
                peer_secrets,
                session_cache,
                auth_nonce_cache,
                shared_quic_registry,
                client_quic_pools,
                client_quic_data_port_baseline,
                peer_mutation_lock,
            )
            .expect("failed to construct XdpDatapath"),
        )
    } else {
        Arc::new(
            TunDatapath::new(
                config.clone(),
                interface_name.clone(),
                runtime_mode,
                fixed_client_quic_data_port_count,
                peer_telemetries,
                worker_telemetry_registry,
                gateway_state.clone(),
                peer_secrets,
                session_cache,
                auth_nonce_cache,
                shared_quic_registry,
                client_quic_pools,
                client_quic_data_port_baseline,
                peer_mutation_lock,
            )
            .expect("failed to construct TunDatapath"),
        )
    };

    let run_res = datapath.run_loop(l4_data_plane, exit_notify).await;

    // 自动清理 userspace TUN 路由
    let cleanup_config = gateway_state.read().config.clone();
    cleanup_runtime(&cleanup_config, &interface_name);

    if let Err(e) = run_res {
        log::error!("Datapath run_loop failed: {:?}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceConfig, PeerConfig, PeerType, QUICPoolConfig, XdpConfig};

    fn peer(public_key: [u8; 32], endpoint: Option<&str>, proxy_port: Option<u16>) -> PeerConfig {
        PeerConfig {
            public_key,
            allowed_ips: vec!["10.10.0.0/16".parse().unwrap()],
            endpoint: endpoint.map(|addr| addr.parse().unwrap()),
            proxy_port,
            r#type: PeerType::Quic,
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
                wg_listen_port: None,
                listen_control_port: None,
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
                mode: "tun".to_string(),
            },
            peers,
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: Vec::new(),
            },
            xdp: XdpConfig::default(),
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
    fn server_tun_queues_follow_quic_listen_port_count() {
        assert_eq!(effective_server_tun_queues(&[40001, 40002]), 2);
        assert_eq!(effective_server_tun_queues(&[40001]), 1);
        assert_eq!(effective_server_tun_queues(&[]), 1);
    }

    #[test]
    fn client_tun_queues_follow_negotiated_quic_data_ports() {
        assert_eq!(effective_client_tun_queues(2), 2);
        assert_eq!(effective_client_tun_queues(4), 4);
        assert_eq!(effective_client_tun_queues(0), 1);
    }

    #[test]
    fn runtime_worker_threads_follow_fixed_data_plane_width() {
        let mut server = config_with_peers(Vec::new());
        server.quic_pool.listen_ports = vec![40001, 40002, 40003];
        assert_eq!(
            runtime_worker_threads(&server, RuntimeMode::Server, None),
            3
        );

        let client = config_with_peers(vec![
            peer([2u8; 32], Some("127.0.0.1:51820"), Some(40000)),
            peer([3u8; 32], Some("127.0.0.1:51821"), Some(40000)),
        ]);
        assert_eq!(
            runtime_worker_threads(&client, RuntimeMode::Client, Some(4)),
            4
        );
        assert_eq!(
            runtime_worker_threads(&client, RuntimeMode::Client, None),
            1
        );
    }

    #[test]
    fn gateway_entrypoint_uses_explicit_bounded_runtime() {
        let main_source = include_str!("main.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();

        assert!(!main_source.contains("#[tokio::main]"));
        assert!(main_source.contains("tokio::runtime::Builder::new_current_thread()"));
    }

    #[test]
    fn startup_failed_pool_data_port_count_drives_client_tun_worker_count() {
        let pools: PeerQuicPools = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        assert_eq!(client_quic_data_port_count(&pools, Some(4)), Some(4));
    }

    #[test]
    fn missing_startup_peer_leaves_client_quic_data_port_count_unset() {
        let pools: PeerQuicPools = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        assert_eq!(client_quic_data_port_count(&pools, None), None);
    }

    #[test]
    fn startup_data_port_count_rejects_inconsistent_failed_peers() {
        let mut expected = None;
        record_startup_quic_data_port_count(&mut expected, 2).unwrap();
        assert_eq!(expected, Some(2));
        let err = record_startup_quic_data_port_count(&mut expected, 4).unwrap_err();
        assert!(err.contains("previous peers use 2"));
        assert!(err.contains("this peer uses 4"));
    }

    #[test]
    fn client_quic_data_port_count_must_match_existing_proxy_peers() {
        let pools: PeerQuicPools = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        assert!(validate_client_quic_data_port_count(&pools, 2).is_ok());

        pools.write().insert(
            [2u8; 32],
            Arc::new(QuicPoolClient::new(
                [1u8; 32],
                [2u8; 32],
                [3u8; 32],
                vec![
                    "127.0.0.1:40001".parse().unwrap(),
                    "127.0.0.1:40002".parse().unwrap(),
                ],
            )),
        );

        assert!(validate_client_quic_data_port_count(&pools, 2).is_ok());
        let err = validate_client_quic_data_port_count(&pools, 3).unwrap_err();
        assert!(err.contains("existing peers use 2"));
        assert!(err.contains("new peer uses 3"));
    }

    #[test]
    fn client_quic_data_port_count_must_match_established_baseline() {
        assert!(validate_client_quic_data_port_count_matches_baseline(2, 2).is_ok());
        assert!(validate_client_quic_data_port_count_matches_baseline(2, 0).is_ok());
        let err = validate_client_quic_data_port_count_matches_baseline(4, 1).unwrap_err();
        assert!(err.contains("established baseline uses 1"));
        assert!(err.contains("peer uses 4"));
        assert!(err.contains("restart"));
    }

    #[test]
    fn first_dynamic_peer_records_client_quic_data_port_baseline() {
        let baseline = parking_lot::Mutex::new(0);
        record_client_quic_data_port_baseline_if_unset(&baseline, 2);
        assert_eq!(*baseline.lock(), 2);
        record_client_quic_data_port_baseline_if_unset(&baseline, 4);
        assert_eq!(*baseline.lock(), 2);
    }

    #[test]
    fn missing_startup_peer_does_not_lock_client_quic_data_port_baseline() {
        let baseline = parking_lot::Mutex::new(0);
        record_initial_client_quic_data_port_baseline(&baseline, None);
        assert_eq!(*baseline.lock(), 0);

        record_initial_client_quic_data_port_baseline(&baseline, Some(2));
        assert_eq!(*baseline.lock(), 2);
    }

    #[test]
    fn parse_startup_args_defaults_and_overrides() {
        assert_eq!(
            parse_startup_args(&["new_proxy".to_string()]),
            StartupArgs {
                config_path: "proxy.conf".to_string(),
                stats: false,
            }
        );
        assert_eq!(
            parse_startup_args(&[
                "new_proxy".to_string(),
                "-config".to_string(),
                "conf/client.conf".to_string(),
            ]),
            StartupArgs {
                config_path: "conf/client.conf".to_string(),
                stats: false,
            }
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
                stats: true,
            }
        );
    }

    #[test]
    fn build_initial_gateway_state_routes_all_peers() {
        let mut l4_peer = peer([2u8; 32], Some("127.0.0.1:51820"), Some(4433));
        l4_peer.allowed_ips = vec!["10.10.1.0/24".parse().unwrap()];
        let mut wg_only_peer = peer([3u8; 32], None, None);
        wg_only_peer.allowed_ips = vec!["10.10.2.0/24".parse().unwrap()];
        let config = config_with_peers(vec![l4_peer.clone(), wg_only_peer.clone()]);

        let state = build_initial_gateway_state(config);

        assert_eq!(
            state.router.longest_match("10.10.1.2".parse().unwrap()),
            Some(l4_peer.public_key)
        );
        assert_eq!(
            state.router.longest_match("10.10.2.2".parse().unwrap()),
            Some(wg_only_peer.public_key)
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
    fn proxy_peers_filters_peers_without_outbound_endpoints() {
        let l4_peer = peer([2u8; 32], Some("127.0.0.1:51820"), Some(4433));
        let config = config_with_peers(vec![l4_peer.clone(), peer([3u8; 32], None, None)]);

        assert_eq!(proxy_peers(&config).len(), 1);
        assert_eq!(proxy_peers(&config)[0].public_key, l4_peer.public_key);
    }
}
