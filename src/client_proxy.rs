use crate::app_config::select_quic_endpoint_ip;
use crate::config;
use crate::control::ControlClient;
use crate::proxy_proto::write_target_addr;
use crate::quic_pool::QuicPoolClient;
use crate::tcp_util::set_tcp_keepalive;
use crate::telemetry::TelemetryRegistry;
use crate::{encode_base64_32, relay, GatewayState, PeerQuicPools};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn build_peer_quic_pool(
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
    let quic_pool_client = Arc::new(QuicPoolClient::new_with_refresh(
        client_pub_derived,
        control_response.session_psk,
        control_response.quic_cert_sha256,
        quic_endpoints,
        private_key,
        peer.public_key,
        control_addr,
        endpoint,
    ));
    quic_pool_client.start_pool().await?;
    quic_pool_client.clone().start_health_checker();
    Ok(quic_pool_client)
}

pub async fn run_tproxy_accept_loop(
    listener: TcpListener,
    quic_pools: PeerQuicPools,
    state: Arc<parking_lot::RwLock<GatewayState>>,
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
    state: Arc<parking_lot::RwLock<GatewayState>>,
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
        let st = state.read();
        st.router.longest_match(original_dst.ip())
    };

    if let Some(peer_pub_key) = matched_peer {
        let quic_pool = {
            let pools = quic_pools.read();
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
