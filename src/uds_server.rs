use crate::api::{read_uds_command, write_uds_json, write_uds_payload, ApiResponse, CommandInput};
use crate::app_config::{
    api_socket_path, encode_base64_32, peer_has_l4_proxy, rebuild_l4_router, telemetry_sources,
    RuntimeMode,
};
use crate::client_proxy::build_peer_quic_pool;
use crate::config::{self, decode_base64_32};
use crate::control::NonceCache;
use crate::quic_pool;
use crate::runtime::{cleanup_peer_routes, run_blocking_command, setup_peer_routes};
use crate::telemetry::{TelemetryRegistry, UnifiedTelemetry, WorkerTelemetryRegistry};
use crate::userspace_wg::UserspaceWgRegistry;
use crate::virtual_tunnel::VirtualTunnelTelemetry;
use crate::{GatewayState, PeerQuicPools};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UnixListener;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_UDS_CLIENTS: usize = 1024;

#[derive(Clone)]
pub struct UdsServerContext {
    pub telemetry: Arc<TelemetryRegistry>,
    pub worker_telemetry: Arc<WorkerTelemetryRegistry>,
    pub state: Arc<RwLock<GatewayState>>,
    pub peer_secrets: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    pub server_secret: StaticSecret,
    pub shared_quic_registry: quic_pool::PeerConnRegistry,
    pub interface_name: String,
    pub session_cache: Arc<RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    pub auth_nonce_cache: Arc<Mutex<HashMap<[u8; 32], NonceCache>>>,
    pub client_quic_pools: PeerQuicPools,
    pub client_private_key: [u8; 32],
    pub runtime_mode: RuntimeMode,
    pub peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    pub l3_registry: UserspaceWgRegistry,
    pub virtual_tunnel_telemetry: Arc<VirtualTunnelTelemetry>,
}

pub fn bind_listener(interface_name: &str) -> Option<UnixListener> {
    let uds_path = api_socket_path(interface_name);
    match std::fs::create_dir_all("/run/new_proxy") {
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
            match UnixListener::bind(&uds_path) {
                Ok(listener) => {
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
                    Some(listener)
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
    }
}

pub fn start(listener: UnixListener, context: UdsServerContext) {
    tokio::spawn(async move {
        let uds_client_limit = Arc::new(tokio::sync::Semaphore::new(MAX_UDS_CLIENTS));
        while let Ok((mut stream, _)) = listener.accept().await {
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

            let context = context.clone();
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

                match request.command {
                    CommandInput::Stats => {
                        handle_stats(&context, &mut stream, framed_response).await
                    }
                    CommandInput::Dump => handle_dump(&context, &mut stream, framed_response).await,
                    CommandInput::AddPeer {
                        public_key,
                        allowed_ips,
                        endpoint,
                        proxy_port,
                    } => {
                        handle_add_peer(
                            &context,
                            &mut stream,
                            framed_response,
                            public_key,
                            allowed_ips,
                            endpoint,
                            proxy_port,
                        )
                        .await
                    }
                    CommandInput::RemovePeer { public_key } => {
                        handle_remove_peer(&context, &mut stream, framed_response, public_key).await
                    }
                }
            });
        }
    });
}

fn quic_connection_snapshots(
    quic_registry: &HashMap<[u8; 32], Vec<quic_pool::QuicConnRecord>>,
    client_quic_pools: &PeerQuicPools,
    pub_key: &[u8; 32],
) -> Vec<quic_pool::QuicConnSnapshot> {
    let server_side = quic_registry
        .get(pub_key)
        .map(|conns| conns.iter().map(|conn| conn.snapshot()).collect::<Vec<_>>())
        .unwrap_or_default();
    if !server_side.is_empty() {
        return server_side;
    }

    client_quic_pools
        .read()
        .get(pub_key)
        .map(|pool| pool.connection_snapshots())
        .unwrap_or_default()
}

async fn handle_stats(
    context: &UdsServerContext,
    stream: &mut tokio::net::UnixStream,
    framed_response: bool,
) {
    let l3_stats = context.l3_registry.snapshot();
    let aggregated = {
        let mut aggregated = Vec::new();
        let mut seen = HashSet::new();
        let peers = {
            let st = context.state.read();
            st.config.peers.clone()
        };
        let sources = telemetry_sources(&peers, &l3_stats);
        let registry_map = context.telemetry.snapshot();
        let quic_registry = context.shared_quic_registry.lock();

        for peer in peers {
            let pub_key = peer.public_key;
            let wg_stats = l3_stats.get(&pub_key);
            let (l4_rx, l4_tx, active_streams) = registry_map
                .get(&pub_key)
                .map(|stats| {
                    (
                        stats.rx_bytes.load(Ordering::Relaxed),
                        stats.tx_bytes.load(Ordering::Relaxed),
                        stats.active_streams.load(Ordering::Relaxed),
                    )
                })
                .unwrap_or((0, 0, 0));
            let quic_connections =
                quic_connection_snapshots(&quic_registry, &context.client_quic_pools, &pub_key);
            let endpoint = peer
                .endpoint
                .map(|addr| addr.to_string())
                .or_else(|| wg_stats.and_then(|stats| stats.endpoint.clone()));
            let allowed_ips = if peer.allowed_ips.is_empty() {
                wg_stats
                    .map(|stats| stats.allowed_ips.clone())
                    .unwrap_or_default()
            } else {
                peer.allowed_ips.iter().map(|ip| ip.to_string()).collect()
            };
            let source = sources
                .get(&pub_key)
                .cloned()
                .unwrap_or_else(|| "both".to_string());

            aggregated.push(UnifiedTelemetry {
                public_key: encode_base64_32(&pub_key),
                allowed_ips,
                endpoint,
                l3_rx_bytes: wg_stats.map(|stats| stats.rx_bytes).unwrap_or(0),
                l3_tx_bytes: wg_stats.map(|stats| stats.tx_bytes).unwrap_or(0),
                l3_unknown_handshake_drops: wg_stats
                    .map(|stats| stats.unknown_handshake_drops)
                    .unwrap_or(0),
                last_handshake: wg_stats.map(|stats| stats.last_handshake).unwrap_or(0),
                l4_rx_bytes: l4_rx,
                l4_tx_bytes: l4_tx,
                active_streams,
                quic_connections,
                source,
            });
            seen.insert(pub_key);
        }

        for (pub_key, wg_stats) in &l3_stats {
            if seen.contains(pub_key) {
                continue;
            }
            let (l4_rx, l4_tx, active_streams) = registry_map
                .get(pub_key)
                .map(|stats| {
                    (
                        stats.rx_bytes.load(Ordering::Relaxed),
                        stats.tx_bytes.load(Ordering::Relaxed),
                        stats.active_streams.load(Ordering::Relaxed),
                    )
                })
                .unwrap_or((0, 0, 0));
            let quic_connections =
                quic_connection_snapshots(&quic_registry, &context.client_quic_pools, pub_key);
            let source = sources
                .get(pub_key)
                .cloned()
                .unwrap_or_else(|| "wireguard".to_string());

            aggregated.push(UnifiedTelemetry {
                public_key: encode_base64_32(pub_key),
                allowed_ips: wg_stats.allowed_ips.clone(),
                endpoint: wg_stats.endpoint.clone(),
                l3_rx_bytes: wg_stats.rx_bytes,
                l3_tx_bytes: wg_stats.tx_bytes,
                l3_unknown_handshake_drops: wg_stats.unknown_handshake_drops,
                last_handshake: wg_stats.last_handshake,
                l4_rx_bytes: l4_rx,
                l4_tx_bytes: l4_tx,
                active_streams,
                quic_connections,
                source,
            });
            seen.insert(*pub_key);
        }

        for pub_key in quic_registry.keys() {
            if seen.contains(pub_key) {
                continue;
            }
            let (l4_rx, l4_tx, active_streams) = registry_map
                .get(pub_key)
                .map(|stats| {
                    (
                        stats.rx_bytes.load(Ordering::Relaxed),
                        stats.tx_bytes.load(Ordering::Relaxed),
                        stats.active_streams.load(Ordering::Relaxed),
                    )
                })
                .unwrap_or((0, 0, 0));
            let quic_connections =
                quic_connection_snapshots(&quic_registry, &context.client_quic_pools, pub_key);
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
                l3_unknown_handshake_drops: 0,
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

    let _ = write_uds_json(stream, &aggregated, framed_response).await;
}

async fn handle_dump(
    context: &UdsServerContext,
    stream: &mut tokio::net::UnixStream,
    framed_response: bool,
) {
    let l3_stats = context.l3_registry.snapshot();
    let response = {
        let telemetry = context.telemetry.snapshot();
        let quic_registry = context.shared_quic_registry.lock();
        let peers = {
            let state = context.state.read();
            state.config.peers.clone()
        };
        let peer_map = peers
            .iter()
            .map(|peer| (peer.public_key, peer))
            .collect::<HashMap<_, _>>();
        let mut keys = HashSet::new();
        keys.extend(peers.iter().map(|peer| peer.public_key));
        keys.extend(l3_stats.keys().copied());
        keys.extend(telemetry.keys().copied());
        keys.extend(quic_registry.keys().copied());
        keys.extend(context.client_quic_pools.read().keys().copied());

        let mut lines = Vec::new();
        for worker in context.worker_telemetry.snapshot() {
            lines.push(format!(
                "worker:{}\ttun_rx={}:{}\ttcp_offload={}:{}\tl3={}:{}\tnew_flows={}\tcurrent_flows={}",
                worker.worker_id,
                worker.tun_rx_packets,
                worker.tun_rx_bytes,
                worker.tcp_offload_packets,
                worker.tcp_offload_bytes,
                worker.l3_packets,
                worker.l3_bytes,
                worker.new_tcp_flows,
                worker.current_tcp_flows,
            ));
        }
        let virtual_tunnel = context.virtual_tunnel_telemetry.snapshot();
        lines.push(format!(
            "virtual_tunnel\tqueue={}:{}\tdrops={}:{}",
            virtual_tunnel.queued_packets,
            virtual_tunnel.queued_bytes,
            virtual_tunnel.dropped_packets,
            virtual_tunnel.dropped_bytes,
        ));
        for key in keys {
            let configured = peer_map.get(&key).copied();
            let wg = l3_stats.get(&key);
            let l4 = telemetry.get(&key);
            let l4_rx = l4
                .map(|stats| stats.rx_bytes.load(Ordering::Relaxed))
                .unwrap_or(0);
            let l4_tx = l4
                .map(|stats| stats.tx_bytes.load(Ordering::Relaxed))
                .unwrap_or(0);
            let active_streams = l4
                .map(|stats| stats.active_streams.load(Ordering::Relaxed))
                .unwrap_or(0);
            let quic_connections =
                quic_connection_snapshots(&quic_registry, &context.client_quic_pools, &key).len();
            let endpoint = configured
                .and_then(|peer| peer.endpoint.map(|addr| addr.to_string()))
                .or_else(|| wg.and_then(|stats| stats.endpoint.clone()))
                .unwrap_or_else(|| "(none)".to_string());
            let allowed_ips = configured
                .map(|peer| {
                    peer.allowed_ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .filter(|allowed_ips| !allowed_ips.is_empty())
                .or_else(|| {
                    wg.map(|stats| stats.allowed_ips.join(","))
                        .filter(|allowed_ips| !allowed_ips.is_empty())
                })
                .unwrap_or_else(|| "(none)".to_string());
            lines.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}:{}\tunknown_wg_drops={}",
                encode_base64_32(&key),
                endpoint,
                allowed_ips,
                wg.map(|stats| stats.last_handshake).unwrap_or(0),
                wg.map(|stats| stats.rx_bytes).unwrap_or(0),
                wg.map(|stats| stats.tx_bytes).unwrap_or(0),
                l4_rx + l4_tx,
                quic_connections,
                active_streams,
                wg.map(|stats| stats.unknown_handshake_drops).unwrap_or(0),
            ));
        }
        lines.sort();
        lines.join("\n")
    };
    let _ = write_uds_payload(stream, response.as_bytes(), framed_response).await;
}

async fn handle_add_peer(
    context: &UdsServerContext,
    stream: &mut tokio::net::UnixStream,
    framed_response: bool,
    public_key: String,
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
    proxy_port: Option<u16>,
) {
    let parsed_pub_key = match decode_base64_32(&public_key) {
        Ok(key) => key,
        Err(e) => {
            write_error(
                stream,
                framed_response,
                format!("Invalid public key: {}", e),
            )
            .await;
            return;
        }
    };

    let mut parsed_allowed_ips = Vec::new();
    for ip_str in allowed_ips {
        match std::str::FromStr::from_str(&ip_str) {
            Ok(ipnet) => parsed_allowed_ips.push(ipnet),
            Err(e) => {
                write_error(
                    stream,
                    framed_response,
                    format!("Invalid allowed IP: {}", e),
                )
                .await;
                return;
            }
        }
    }
    if parsed_allowed_ips.is_empty() {
        write_error(
            stream,
            framed_response,
            "AllowedIPs must not be empty".to_string(),
        )
        .await;
        return;
    }

    let parsed_endpoint = match endpoint {
        Some(endpoint) => match std::str::FromStr::from_str(&endpoint) {
            Ok(addr) => Some(addr),
            Err(e) => {
                write_error(stream, framed_response, format!("Invalid endpoint: {}", e)).await;
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

    if context.runtime_mode == RuntimeMode::Client {
        match (new_peer.endpoint, new_peer.proxy_port) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => {
                write_error(
                    stream,
                    framed_response,
                    "Endpoint and ProxyPort must be provided together for client QUIC offload"
                        .to_string(),
                )
                .await;
                return;
            }
        }
    }

    let precheck_conflict = {
        let state = context.state.read();
        find_allowed_ip_conflict(&state.config.peers, &new_peer)
    };
    if let Some(conflict) = precheck_conflict {
        write_error(stream, framed_response, conflict).await;
        return;
    }

    let prepared_client_pool = if context.runtime_mode == RuntimeMode::Client
        && peer_has_l4_proxy(&new_peer)
    {
        match build_peer_quic_pool(context.client_private_key, &new_peer).await {
            Ok(pool) => Some(pool),
            Err(e) => {
                log::warn!(
                        "Failed to establish QUIC pool for dynamically added peer {}; adding peer in WireGuard L3 fallback mode and retrying in background: {}",
                        encode_base64_32(&parsed_pub_key),
                        e
                    );
                None
            }
        }
    } else {
        None
    };
    let quic_pool_unavailable = context.runtime_mode == RuntimeMode::Client
        && peer_has_l4_proxy(&new_peer)
        && prepared_client_pool.is_none();

    let _mutation_guard = context.peer_mutation_lock.lock().await;

    let (table_off, old_peer, conflict) = {
        let state = context.state.read();
        let conflict = find_allowed_ip_conflict(&state.config.peers, &new_peer);
        (
            state
                .config
                .interface
                .table
                .as_deref()
                .map(|table| table.eq_ignore_ascii_case("off"))
                .unwrap_or(false),
            state
                .config
                .peers
                .iter()
                .find(|peer| peer.public_key == parsed_pub_key)
                .cloned(),
            conflict,
        )
    };
    if let Some(conflict) = conflict {
        if let Some(pool) = prepared_client_pool.as_ref() {
            pool.shutdown(b"Peer add conflict");
        }
        write_error(stream, framed_response, conflict).await;
        return;
    }

    if !table_off {
        if let Some(peer) = old_peer.clone() {
            if let Err(e) = cleanup_peer_routes_for_context(context, peer).await {
                if let Some(pool) = prepared_client_pool.as_ref() {
                    pool.shutdown(b"Peer route cleanup failed");
                }
                write_error(
                    stream,
                    framed_response,
                    format!("Failed to clean old peer routes: {}", e),
                )
                .await;
                return;
            }
        }
    }

    if !table_off {
        let setup_result = setup_peer_routes_for_context(context, new_peer.clone()).await;
        if let Err(e) = setup_result {
            if let Some(pool) = prepared_client_pool.as_ref() {
                pool.shutdown(b"Peer route setup failed");
            }
            let rollback_error = rollback_peer_routes(context, &new_peer, old_peer.clone()).await;
            let message = match rollback_error {
                Ok(()) => format!("Failed to sync peer routes: {}", e),
                Err(rollback) => format!(
                    "Failed to sync peer routes: {}; rollback failed: {}",
                    e, rollback
                ),
            };
            write_error(stream, framed_response, message).await;
            return;
        }
    }

    if let Err(e) = context.l3_registry.add_or_replace_peer(new_peer.clone()) {
        if let Some(pool) = prepared_client_pool.as_ref() {
            pool.shutdown(b"Peer userspace WireGuard update failed");
        }
        if !table_off {
            let rollback_error = rollback_peer_routes(context, &new_peer, old_peer.clone()).await;
            let message = match rollback_error {
                Ok(()) => format!("Failed to update userspace WireGuard peer: {}", e),
                Err(rollback) => format!(
                    "Failed to update userspace WireGuard peer: {}; route rollback failed: {}",
                    e, rollback
                ),
            };
            write_error(stream, framed_response, message).await;
            return;
        }
        write_error(
            stream,
            framed_response,
            format!("Failed to update userspace WireGuard peer: {}", e),
        )
        .await;
        return;
    }

    let peer_pub = PublicKey::from(parsed_pub_key);
    let shared_secret = context.server_secret.diffie_hellman(&peer_pub).to_bytes();
    context
        .peer_secrets
        .write()
        .insert(parsed_pub_key, shared_secret);

    {
        let mut state = context.state.write();
        state
            .config
            .peers
            .retain(|peer| peer.public_key != parsed_pub_key);
        state.config.peers.push(new_peer);
        state.router = rebuild_l4_router(&state.config.peers);
        if quic_pool_unavailable {
            state.userspace_tcp_offload_enabled = false;
        }
    }

    if context.runtime_mode == RuntimeMode::Client {
        let old_pool = {
            let mut pools = context.client_quic_pools.write();
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

    let message = if quic_pool_unavailable {
        Some(
            "Peer added; QUIC pool is unavailable, using WireGuard L3 fallback until recovery"
                .to_string(),
        )
    } else {
        None
    };
    write_ok(stream, framed_response, message).await;
}

async fn handle_remove_peer(
    context: &UdsServerContext,
    stream: &mut tokio::net::UnixStream,
    framed_response: bool,
    public_key: String,
) {
    let parsed_pub_key = match decode_base64_32(&public_key) {
        Ok(key) => key,
        Err(e) => {
            write_error(
                stream,
                framed_response,
                format!("Invalid public key: {}", e),
            )
            .await;
            return;
        }
    };

    let _mutation_guard = context.peer_mutation_lock.lock().await;

    let (removed_peer, table_off) = {
        let state = context.state.read();
        (
            state
                .config
                .peers
                .iter()
                .find(|peer| peer.public_key == parsed_pub_key)
                .cloned(),
            state
                .config
                .interface
                .table
                .as_deref()
                .map(|table| table.eq_ignore_ascii_case("off"))
                .unwrap_or(false),
        )
    };

    if let Some(peer) = &removed_peer {
        if !table_off {
            if let Err(e) = cleanup_peer_routes_for_context(context, peer.clone()).await {
                write_error(
                    stream,
                    framed_response,
                    format!("Failed to clean peer routes: {}", e),
                )
                .await;
                return;
            }
        }
    }
    context.l3_registry.remove_peer(&parsed_pub_key);

    context.peer_secrets.write().remove(&parsed_pub_key);
    context.session_cache.write().remove(&parsed_pub_key);
    context.auth_nonce_cache.lock().remove(&parsed_pub_key);
    context.telemetry.remove(&parsed_pub_key);

    if context.runtime_mode == RuntimeMode::Client {
        if let Some(pool) = context.client_quic_pools.write().remove(&parsed_pub_key) {
            pool.shutdown(b"Peer removed");
        }
    }
    if let Some(conns) = context.shared_quic_registry.lock().remove(&parsed_pub_key) {
        for conn in conns {
            conn.close(b"Peer removed");
        }
    }

    {
        let mut state = context.state.write();
        state
            .config
            .peers
            .retain(|peer| peer.public_key != parsed_pub_key);
        state.router = rebuild_l4_router(&state.config.peers);
    }

    write_ok(stream, framed_response, None).await;
}

fn find_allowed_ip_conflict(
    peers: &[config::PeerConfig],
    new_peer: &config::PeerConfig,
) -> Option<String> {
    for (i, allowed_ip) in new_peer.allowed_ips.iter().enumerate() {
        if new_peer.allowed_ips[..i].contains(allowed_ip) {
            return Some(format!(
                "Duplicate AllowedIPs entry {} in AddPeer request",
                allowed_ip
            ));
        }
    }

    for peer in peers {
        if peer.public_key == new_peer.public_key {
            continue;
        }
        for existing_ip in &peer.allowed_ips {
            for new_ip in &new_peer.allowed_ips {
                if ipnets_overlap(*existing_ip, *new_ip) {
                    return Some(format!(
                        "Overlapping AllowedIPs entries {} and {} used by peers {} and {}",
                        existing_ip,
                        new_ip,
                        encode_base64_32(&peer.public_key),
                        encode_base64_32(&new_peer.public_key)
                    ));
                }
            }
        }
    }
    None
}

fn ipnets_overlap(a: ipnet::IpNet, b: ipnet::IpNet) -> bool {
    match (a, b) {
        (ipnet::IpNet::V4(a), ipnet::IpNet::V4(b)) => {
            a.contains(&b.network()) || b.contains(&a.network())
        }
        (ipnet::IpNet::V6(a), ipnet::IpNet::V6(b)) => {
            a.contains(&b.network()) || b.contains(&a.network())
        }
        _ => false,
    }
}

async fn setup_peer_routes_for_context(
    context: &UdsServerContext,
    peer: config::PeerConfig,
) -> Result<(), String> {
    let interface_name = context.interface_name.clone();
    run_blocking_command(move || setup_peer_routes(&peer, &interface_name)).await
}

async fn cleanup_peer_routes_for_context(
    context: &UdsServerContext,
    peer: config::PeerConfig,
) -> Result<(), String> {
    let interface_name = context.interface_name.clone();
    run_blocking_command(move || cleanup_peer_routes(&peer, &interface_name)).await
}

async fn rollback_peer_routes(
    context: &UdsServerContext,
    new_peer: &config::PeerConfig,
    old_peer: Option<config::PeerConfig>,
) -> Result<(), String> {
    let mut errors = Vec::new();

    if let Err(e) = cleanup_peer_routes_for_context(context, new_peer.clone()).await {
        errors.push(format!("failed to clean new peer routes: {}", e));
    }
    if let Some(peer) = old_peer {
        if let Err(e) = setup_peer_routes_for_context(context, peer).await {
            errors.push(format!("failed to restore old peer routes: {}", e));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn write_ok(
    stream: &mut tokio::net::UnixStream,
    framed_response: bool,
    message: Option<String>,
) {
    let resp = ApiResponse {
        status: "Ok".to_string(),
        message,
    };
    let _ = write_uds_json(stream, &resp, framed_response).await;
}

async fn write_error(stream: &mut tokio::net::UnixStream, framed_response: bool, message: String) {
    let resp = ApiResponse {
        status: "Error".to_string(),
        message: Some(message),
    };
    let _ = write_uds_json(stream, &resp, framed_response).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GatewayConfig, InterfaceConfig, PeerConfig, QUICPoolConfig};
    use crate::routing::AllowedIPsRouter;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_context() -> UdsServerContext {
        let config = GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec![],
                listen_port: Some(0),
                listen_control_port: Some(51820),
                mtu: 1420,
                table: None,
                pre_script: None,
                post_script: None,
            },
            peers: vec![PeerConfig {
                public_key: [2u8; 32],
                allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
                endpoint: Some("1.2.3.4:51820".parse().unwrap()),
                proxy_port: Some(40001),
            }],
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![],
            },
        };
        let telemetry = Arc::new(TelemetryRegistry::new());
        let worker_telemetry = Arc::new(WorkerTelemetryRegistry::new());
        let stats = telemetry.get_or_create([2u8; 32]);
        stats.rx_bytes.store(70, Ordering::Relaxed);
        stats.tx_bytes.store(80, Ordering::Relaxed);

        let l3_registry =
            UserspaceWgRegistry::new(config.interface.private_key, &config.peers).unwrap();

        UdsServerContext {
            telemetry,
            worker_telemetry,
            state: Arc::new(RwLock::new(GatewayState {
                config,
                router: AllowedIPsRouter::new(),
                userspace_tcp_offload_enabled: true,
            })),
            peer_secrets: Arc::new(RwLock::new(HashMap::new())),
            server_secret: StaticSecret::from([1u8; 32]),
            shared_quic_registry: Arc::new(Mutex::new(HashMap::new())),
            interface_name: "nonexistent_interface".to_string(),
            session_cache: Arc::new(RwLock::new(HashMap::new())),
            auth_nonce_cache: Arc::new(Mutex::new(HashMap::new())),
            client_quic_pools: Arc::new(RwLock::new(HashMap::new())),
            client_private_key: [1u8; 32],
            runtime_mode: RuntimeMode::Server,
            peer_mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            l3_registry,
            virtual_tunnel_telemetry: Arc::new(VirtualTunnelTelemetry::default()),
        }
    }

    async fn send_raw_command<T: serde::de::DeserializeOwned>(
        path: &str,
        command: &CommandInput,
    ) -> T {
        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        let payload = serde_json::to_vec(command).unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        serde_json::from_slice(&response).unwrap()
    }

    async fn send_framed_command<T: serde::de::DeserializeOwned>(
        path: &str,
        command: &CommandInput,
    ) -> T {
        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        let payload = serde_json::to_vec(command).unwrap();
        stream.write_u32(payload.len() as u32).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        let len = stream.read_u32().await.unwrap() as usize;
        let mut response = vec![0u8; len];
        stream.read_exact(&mut response).await.unwrap();
        serde_json::from_slice(&response).unwrap()
    }

    #[tokio::test]
    async fn test_uds_server_stats_uses_context_state_and_telemetry() {
        let path = "/tmp/test_real_uds_stats.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        start(listener, test_context());

        let stats: Vec<UnifiedTelemetry> = send_raw_command(path, &CommandInput::Stats).await;
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].public_key, encode_base64_32(&[2u8; 32]));
        assert_eq!(stats[0].allowed_ips, vec!["10.0.0.2/32"]);
        assert_eq!(stats[0].endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(stats[0].l4_rx_bytes, 70);
        assert_eq!(stats[0].l4_tx_bytes, 80);
        assert_eq!(stats[0].l3_unknown_handshake_drops, 0);
        assert_eq!(stats[0].source, "both");

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_server_dump_returns_tabular_runtime_snapshot() {
        let path = "/tmp/test_real_uds_dump.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let context = test_context();
        context
            .worker_telemetry
            .get_or_create(1)
            .tun_rx_packets
            .store(42, Ordering::Relaxed);
        {
            let mut state = context.state.write();
            state.config.peers.push(PeerConfig {
                public_key: [9u8; 32],
                allowed_ips: vec!["10.0.9.0/24".parse().unwrap()],
                endpoint: None,
                proxy_port: None,
            });
        }
        start(listener, context);

        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        let payload = serde_json::to_vec(&CommandInput::Dump).unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let dump = String::from_utf8(response).unwrap();
        assert!(dump.contains(&encode_base64_32(&[2u8; 32])));
        assert!(dump.contains(&encode_base64_32(&[9u8; 32])));
        assert!(dump.contains("10.0.9.0/24"));
        assert!(dump.contains("150"));
        assert!(dump.contains("worker:1"));
        assert!(dump.contains("tun_rx=42:0"));
        assert!(dump.contains("virtual_tunnel\tqueue=0:0\tdrops=0:0"));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_server_invalid_request_returns_error() {
        let path = "/tmp/test_real_uds_invalid.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        start(listener, test_context());

        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        stream.write_all(b"{not valid json").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response: ApiResponse = serde_json::from_slice(&response).unwrap();
        assert_eq!(response.status, "Error");
        assert!(response
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("Invalid request JSON"));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_add_peer_updates_runtime_state_and_registries() {
        let path = "/tmp/test_real_uds_add_peer.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let context = test_context();
        context.state.write().config.interface.table = Some("off".to_string());
        let context_for_assert = context.clone();
        start(listener, context);

        let new_key = [8u8; 32];
        let response: ApiResponse = send_framed_command(
            path,
            &CommandInput::AddPeer {
                public_key: encode_base64_32(&new_key),
                allowed_ips: vec!["10.8.0.0/24".to_string()],
                endpoint: None,
                proxy_port: None,
            },
        )
        .await;

        assert_eq!(response.status, "Ok");
        let state = context_for_assert.state.read();
        assert!(state
            .config
            .peers
            .iter()
            .any(|peer| peer.public_key == new_key));
        assert!(context_for_assert
            .peer_secrets
            .read()
            .contains_key(&new_key));
        assert!(context_for_assert
            .l3_registry
            .snapshot()
            .contains_key(&new_key));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_add_peer_replaces_existing_peer() {
        let path = "/tmp/test_real_uds_replace_peer.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let context = test_context();
        context.state.write().config.interface.table = Some("off".to_string());
        let context_for_assert = context.clone();
        start(listener, context);

        let response: ApiResponse = send_raw_command(
            path,
            &CommandInput::AddPeer {
                public_key: encode_base64_32(&[2u8; 32]),
                allowed_ips: vec!["10.2.0.0/24".to_string()],
                endpoint: Some("5.6.7.8:51820".to_string()),
                proxy_port: Some(40002),
            },
        )
        .await;

        assert_eq!(response.status, "Ok");
        let state = context_for_assert.state.read();
        let replaced = state
            .config
            .peers
            .iter()
            .filter(|peer| peer.public_key == [2u8; 32])
            .collect::<Vec<_>>();
        assert_eq!(replaced.len(), 1);
        assert_eq!(
            replaced[0].allowed_ips,
            vec!["10.2.0.0/24".parse().unwrap()]
        );
        assert_eq!(
            replaced[0].endpoint.map(|addr| addr.to_string()).as_deref(),
            Some("5.6.7.8:51820")
        );

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_remove_peer_clears_runtime_state_and_registries() {
        let path = "/tmp/test_real_uds_remove_peer.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let context = test_context();
        context.state.write().config.interface.table = Some("off".to_string());
        context.peer_secrets.write().insert([2u8; 32], [3u8; 32]);
        context.session_cache.write().insert([2u8; 32], [4u8; 32]);
        context
            .auth_nonce_cache
            .lock()
            .insert([2u8; 32], NonceCache::new(4));
        let context_for_assert = context.clone();
        start(listener, context);

        let response: ApiResponse = send_raw_command(
            path,
            &CommandInput::RemovePeer {
                public_key: encode_base64_32(&[2u8; 32]),
            },
        )
        .await;

        assert_eq!(response.status, "Ok");
        assert!(!context_for_assert
            .state
            .read()
            .config
            .peers
            .iter()
            .any(|peer| peer.public_key == [2u8; 32]));
        assert!(!context_for_assert
            .l3_registry
            .snapshot()
            .contains_key(&[2u8; 32]));
        assert!(!context_for_assert
            .peer_secrets
            .read()
            .contains_key(&[2u8; 32]));
        assert!(!context_for_assert
            .session_cache
            .read()
            .contains_key(&[2u8; 32]));
        assert!(!context_for_assert
            .auth_nonce_cache
            .lock()
            .contains_key(&[2u8; 32]));
        assert!(!context_for_assert
            .telemetry
            .snapshot()
            .contains_key(&[2u8; 32]));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_client_add_peer_requires_endpoint_and_proxy_port_together() {
        let path = "/tmp/test_real_uds_add_peer_client_pair.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let mut context = test_context();
        context.runtime_mode = RuntimeMode::Client;
        context.state.write().config.interface.table = Some("off".to_string());
        start(listener, context);

        let response: ApiResponse = send_raw_command(
            path,
            &CommandInput::AddPeer {
                public_key: encode_base64_32(&[8u8; 32]),
                allowed_ips: vec!["10.8.0.0/24".to_string()],
                endpoint: Some("1.2.3.4:51820".to_string()),
                proxy_port: None,
            },
        )
        .await;

        assert_eq!(response.status, "Error");
        assert!(response
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("Endpoint and ProxyPort"));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_client_add_peer_keeps_peer_when_quic_pool_is_unavailable() {
        let path = "/tmp/test_real_uds_add_peer_client_fallback.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let mut context = test_context();
        context.runtime_mode = RuntimeMode::Client;
        context.state.write().config.interface.table = Some("off".to_string());
        let context_for_assert = context.clone();
        start(listener, context);

        let new_key = [8u8; 32];
        let response: ApiResponse = send_raw_command(
            path,
            &CommandInput::AddPeer {
                public_key: encode_base64_32(&new_key),
                allowed_ips: vec!["10.8.0.0/24".to_string()],
                endpoint: Some("127.0.0.1:9".to_string()),
                proxy_port: Some(9),
            },
        )
        .await;

        assert_eq!(response.status, "Ok");
        assert!(response
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("WireGuard L3 fallback"));
        let state = context_for_assert.state.read();
        assert!(!state.userspace_tcp_offload_enabled);
        assert!(state
            .config
            .peers
            .iter()
            .any(|peer| peer.public_key == new_key && peer.proxy_port == Some(9)));
        drop(state);
        assert!(context_for_assert
            .l3_registry
            .snapshot()
            .contains_key(&new_key));
        assert!(!context_for_assert
            .client_quic_pools
            .read()
            .contains_key(&new_key));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_client_add_peer_rejects_conflict_before_quic_pool_setup() {
        let path = "/tmp/test_real_uds_add_peer_client_conflict.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        let mut context = test_context();
        context.runtime_mode = RuntimeMode::Client;
        context.state.write().config.interface.table = Some("off".to_string());
        let context_for_assert = context.clone();
        start(listener, context);

        let response: ApiResponse = send_raw_command(
            path,
            &CommandInput::AddPeer {
                public_key: encode_base64_32(&[8u8; 32]),
                allowed_ips: vec!["10.0.0.2/32".to_string()],
                endpoint: Some("127.0.0.1:9".to_string()),
                proxy_port: Some(9),
            },
        )
        .await;

        assert_eq!(response.status, "Error");
        assert!(response
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("Overlapping AllowedIPs"));
        assert!(!context_for_assert
            .client_quic_pools
            .read()
            .contains_key(&[8u8; 32]));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_remove_peer_caches_are_cleared_together() {
        let peer_secrets = Arc::new(RwLock::new(HashMap::new()));
        let session_cache = Arc::new(RwLock::new(HashMap::new()));
        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));
        let telemetry = crate::telemetry::TelemetryRegistry::new();

        let pub_key = [5u8; 32];
        peer_secrets.write().insert(pub_key, [10u8; 32]);
        session_cache.write().insert(pub_key, [15u8; 32]);
        auth_nonce_cache
            .lock()
            .insert(pub_key, crate::control::NonceCache::new(10));
        let stats = telemetry.get_or_create(pub_key);
        stats
            .rx_bytes
            .store(500, std::sync::atomic::Ordering::Relaxed);

        peer_secrets.write().remove(&pub_key);
        session_cache.write().remove(&pub_key);
        auth_nonce_cache.lock().remove(&pub_key);
        telemetry.remove(&pub_key);

        assert!(!peer_secrets.read().contains_key(&pub_key));
        assert!(!session_cache.read().contains_key(&pub_key));
        assert!(!auth_nonce_cache.lock().contains_key(&pub_key));
        assert!(!telemetry.snapshot().contains_key(&pub_key));
    }

    #[test]
    fn test_add_peer_rejects_duplicate_and_overlapping_allowed_ips() {
        let existing_peer = PeerConfig {
            public_key: [2u8; 32],
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            endpoint: None,
            proxy_port: None,
        };
        let mut new_peer = PeerConfig {
            public_key: [3u8; 32],
            allowed_ips: vec!["10.0.0.128/25".parse().unwrap()],
            endpoint: None,
            proxy_port: None,
        };

        assert!(
            find_allowed_ip_conflict(std::slice::from_ref(&existing_peer), &new_peer)
                .unwrap()
                .contains("Overlapping AllowedIPs")
        );

        new_peer.allowed_ips = vec![
            "10.1.0.0/24".parse().unwrap(),
            "10.1.0.0/24".parse().unwrap(),
        ];
        assert!(
            find_allowed_ip_conflict(std::slice::from_ref(&existing_peer), &new_peer)
                .unwrap()
                .contains("Duplicate AllowedIPs")
        );

        new_peer.public_key = existing_peer.public_key;
        new_peer.allowed_ips = vec!["10.0.0.128/25".parse().unwrap()];
        assert!(find_allowed_ip_conflict(&[existing_peer], &new_peer).is_none());
    }
}
