use crate::api::{read_uds_command, write_uds_json, write_uds_payload, ApiResponse, CommandInput};
use crate::app_config::{
    api_socket_path, encode_base64_32, peer_has_l4_proxy, rebuild_l4_router, telemetry_sources,
    RuntimeMode,
};
use crate::client_proxy::build_peer_quic_pool;
use crate::config::{self, decode_base64_32};
use crate::control::NonceCache;
use crate::quic_pool;
use crate::runtime::{
    cleanup_peer_routes_and_tproxy, run_blocking_command, setup_peer_routes_and_tproxy,
};
use crate::telemetry::{TelemetryRegistry, UnifiedTelemetry};
use crate::wireguard::{get_wg_dump_stats, remove_peer_from_kernel, sync_peer_to_kernel};
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

async fn handle_stats(
    context: &UdsServerContext,
    stream: &mut tokio::net::UnixStream,
    framed_response: bool,
) {
    let l3_stats = get_wg_dump_stats(&context.interface_name)
        .await
        .unwrap_or_default();
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
            let quic_connections = quic_registry
                .get(&pub_key)
                .map(|conns| conns.iter().map(|conn| conn.snapshot()).collect())
                .unwrap_or_default();
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
            let quic_connections = quic_registry
                .get(pub_key)
                .map(|conns| conns.iter().map(|conn| conn.snapshot()).collect())
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
            let quic_connections = quic_registry
                .get(pub_key)
                .map(|conns| conns.iter().map(|conn| conn.snapshot()).collect())
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

    let _ = write_uds_json(stream, &aggregated, framed_response).await;
}

async fn handle_dump(
    context: &UdsServerContext,
    stream: &mut tokio::net::UnixStream,
    framed_response: bool,
) {
    let l3_stats = get_wg_dump_stats(&context.interface_name)
        .await
        .unwrap_or_default();
    let response = {
        let telemetry = context.telemetry.snapshot();
        let quic_registry = context.shared_quic_registry.lock();
        let mut keys = HashSet::new();
        keys.extend(l3_stats.keys().copied());
        keys.extend(telemetry.keys().copied());
        keys.extend(quic_registry.keys().copied());

        let mut lines = Vec::new();
        for key in keys {
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
            let quic_connections = quic_registry
                .get(&key)
                .map(|conns| conns.len())
                .unwrap_or(0);
            lines.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}:{}",
                encode_base64_32(&key),
                wg.and_then(|stats| stats.endpoint.clone())
                    .unwrap_or_else(|| "(none)".to_string()),
                wg.map(|stats| stats.allowed_ips.join(","))
                    .filter(|allowed_ips| !allowed_ips.is_empty())
                    .unwrap_or_else(|| "(none)".to_string()),
                wg.map(|stats| stats.last_handshake).unwrap_or(0),
                wg.map(|stats| stats.rx_bytes).unwrap_or(0),
                wg.map(|stats| stats.tx_bytes).unwrap_or(0),
                l4_rx + l4_tx,
                quic_connections,
                active_streams,
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

    let _mutation_guard = context.peer_mutation_lock.lock().await;

    let (table_off, tproxy_port, old_peer, conflict) = {
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
            state.config.interface.tproxy_port,
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
        write_error(stream, framed_response, conflict).await;
        return;
    }

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
        if peer_has_l4_proxy(&new_peer) && tproxy_port.is_none() {
            write_error(
                stream,
                framed_response,
                "TProxyPort is required before adding a QUIC proxy peer".to_string(),
            )
            .await;
            return;
        }
    }

    let prepared_client_pool =
        if context.runtime_mode == RuntimeMode::Client && peer_has_l4_proxy(&new_peer) {
            match build_peer_quic_pool(context.client_private_key, &new_peer).await {
                Ok(pool) => Some(pool),
                Err(e) => {
                    write_error(
                        stream,
                        framed_response,
                        format!("Failed to establish QUIC pool for peer: {}", e),
                    )
                    .await;
                    return;
                }
            }
        } else {
            None
        };

    if !table_off {
        if let Some(peer) = old_peer.clone() {
            if let Err(e) = cleanup_peer_routes(context, peer, tproxy_port).await {
                if let Some(pool) = prepared_client_pool.as_ref() {
                    pool.shutdown(b"Peer route cleanup failed");
                }
                write_error(
                    stream,
                    framed_response,
                    format!("Failed to clean old peer routes/tproxy: {}", e),
                )
                .await;
                return;
            }
        }
    }

    if !table_off {
        let setup_result = setup_peer_routes(context, new_peer.clone(), tproxy_port).await;
        if let Err(e) = setup_result {
            if let Some(pool) = prepared_client_pool.as_ref() {
                pool.shutdown(b"Peer route setup failed");
            }
            let rollback_error =
                rollback_peer_routes(context, &new_peer, old_peer.clone(), tproxy_port).await;
            let message = match rollback_error {
                Ok(()) => format!("Failed to sync peer routes/tproxy: {}", e),
                Err(rollback) => format!(
                    "Failed to sync peer routes/tproxy: {}; rollback failed: {}",
                    e, rollback
                ),
            };
            write_error(stream, framed_response, message).await;
            return;
        }
    }

    let interface_name = context.interface_name.clone();
    let new_peer_for_kernel = new_peer.clone();
    if let Err(e) =
        run_blocking_command(move || sync_peer_to_kernel(&interface_name, &new_peer_for_kernel))
            .await
    {
        if let Some(pool) = prepared_client_pool.as_ref() {
            pool.shutdown(b"Peer kernel sync failed");
        }
        if !table_off {
            let rollback_error =
                rollback_peer_routes(context, &new_peer, old_peer.clone(), tproxy_port).await;
            let message = match rollback_error {
                Ok(()) => format!("Failed to sync peer to kernel: {}", e),
                Err(rollback) => format!(
                    "Failed to sync peer to kernel: {}; route rollback failed: {}",
                    e, rollback
                ),
            };
            write_error(stream, framed_response, message).await;
            return;
        }
        write_error(
            stream,
            framed_response,
            format!("Failed to sync peer to kernel: {}", e),
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

    write_ok(stream, framed_response, None).await;
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

    let (removed_peer, table_off, tproxy_port) = {
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
            state.config.interface.tproxy_port,
        )
    };

    let mut routes_cleaned = false;
    if let Some(peer) = &removed_peer {
        if !table_off {
            if let Err(e) = cleanup_peer_routes(context, peer.clone(), tproxy_port).await {
                write_error(
                    stream,
                    framed_response,
                    format!("Failed to clean peer routes/tproxy: {}", e),
                )
                .await;
                return;
            }
            routes_cleaned = true;
        }
    }
    let interface_name = context.interface_name.clone();
    if let Err(e) =
        run_blocking_command(move || remove_peer_from_kernel(&interface_name, parsed_pub_key)).await
    {
        let restore_error = if routes_cleaned {
            match removed_peer.clone() {
                Some(peer) => setup_peer_routes(context, peer, tproxy_port).await.err(),
                None => None,
            }
        } else {
            None
        };
        let message = match restore_error {
            Some(restore) => format!(
                "Failed to remove kernel peer: {}; failed to restore peer routes/tproxy: {}",
                e, restore
            ),
            None => format!("Failed to remove kernel peer: {}", e),
        };
        write_error(stream, framed_response, message).await;
        return;
    }

    context.peer_secrets.write().remove(&parsed_pub_key);
    context.session_cache.write().remove(&parsed_pub_key);
    context.auth_nonce_cache.lock().remove(&parsed_pub_key);

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

async fn setup_peer_routes(
    context: &UdsServerContext,
    peer: config::PeerConfig,
    tproxy_port: Option<u16>,
) -> Result<(), String> {
    let interface_name = context.interface_name.clone();
    run_blocking_command(move || setup_peer_routes_and_tproxy(&peer, tproxy_port, &interface_name))
        .await
}

async fn cleanup_peer_routes(
    context: &UdsServerContext,
    peer: config::PeerConfig,
    tproxy_port: Option<u16>,
) -> Result<(), String> {
    let interface_name = context.interface_name.clone();
    run_blocking_command(move || {
        cleanup_peer_routes_and_tproxy(&peer, tproxy_port, &interface_name)
    })
    .await
}

async fn rollback_peer_routes(
    context: &UdsServerContext,
    new_peer: &config::PeerConfig,
    old_peer: Option<config::PeerConfig>,
    tproxy_port: Option<u16>,
) -> Result<(), String> {
    let mut errors = Vec::new();

    if let Err(e) = cleanup_peer_routes(context, new_peer.clone(), tproxy_port).await {
        errors.push(format!("failed to clean new peer routes/tproxy: {}", e));
    }
    if let Some(peer) = old_peer {
        if let Err(e) = setup_peer_routes(context, peer, tproxy_port).await {
            errors.push(format!("failed to restore old peer routes/tproxy: {}", e));
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
                tproxy_port: Some(8080),
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
        let stats = telemetry.get_or_create([2u8; 32]);
        stats.rx_bytes.store(70, Ordering::Relaxed);
        stats.tx_bytes.store(80, Ordering::Relaxed);

        UdsServerContext {
            telemetry,
            state: Arc::new(RwLock::new(GatewayState {
                config,
                router: AllowedIPsRouter::new(),
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
        assert_eq!(stats[0].source, "proxy");

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_uds_server_dump_returns_tabular_runtime_snapshot() {
        let path = "/tmp/test_real_uds_dump.sock";
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        start(listener, test_context());

        let mut stream = tokio::net::UnixStream::connect(path).await.unwrap();
        let payload = serde_json::to_vec(&CommandInput::Dump).unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let dump = String::from_utf8(response).unwrap();
        assert!(dump.contains(&encode_base64_32(&[2u8; 32])));
        assert!(dump.contains("150"));

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

    #[test]
    fn test_remove_peer_caches_are_cleared_together() {
        let peer_secrets = Arc::new(RwLock::new(HashMap::new()));
        let session_cache = Arc::new(RwLock::new(HashMap::new()));
        let auth_nonce_cache = Arc::new(Mutex::new(HashMap::new()));

        let pub_key = [5u8; 32];
        peer_secrets.write().insert(pub_key, [10u8; 32]);
        session_cache.write().insert(pub_key, [15u8; 32]);
        auth_nonce_cache
            .lock()
            .insert(pub_key, crate::control::NonceCache::new(10));

        peer_secrets.write().remove(&pub_key);
        session_cache.write().remove(&pub_key);
        auth_nonce_cache.lock().remove(&pub_key);

        assert!(!peer_secrets.read().contains_key(&pub_key));
        assert!(!session_cache.read().contains_key(&pub_key));
        assert!(!auth_nonce_cache.lock().contains_key(&pub_key));
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
            find_allowed_ip_conflict(&[existing_peer.clone()], &new_peer)
                .unwrap()
                .contains("Overlapping AllowedIPs")
        );

        new_peer.allowed_ips = vec![
            "10.1.0.0/24".parse().unwrap(),
            "10.1.0.0/24".parse().unwrap(),
        ];
        assert!(
            find_allowed_ip_conflict(&[existing_peer.clone()], &new_peer)
                .unwrap()
                .contains("Duplicate AllowedIPs")
        );

        new_peer.public_key = existing_peer.public_key;
        new_peer.allowed_ips = vec!["10.0.0.128/25".parse().unwrap()];
        assert!(find_allowed_ip_conflict(&[existing_peer], &new_peer).is_none());
    }
}
