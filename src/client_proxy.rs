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
    interface_name: &str,
    _tproxy_port: Option<u16>,
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
        interface_name.to_string(),
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

        let is_pool_active = quic_pool.is_active();

        let quic_stream_res = if !is_pool_active {
            Err("QUIC pool is unhealthy".to_string())
        } else {
            quic_pool.open_mux_stream().await
        };

        match quic_stream_res {
            Ok((mut quic_send, mut quic_recv, conn_stat)) => {
                log::info!(
                    "Intercepted TCP stream from {} -> {}, matched AllowedIPs. Offloading to QUIC.",
                    src_addr,
                    original_dst
                );

                if write_target_addr(&mut quic_send, original_dst)
                    .await
                    .is_ok()
                {
                    let mut status = [0u8; 1];
                    match timeout(Duration::from_secs(5), quic_recv.read_exact(&mut status)).await {
                        Ok(Ok(_)) if status[0] == 1 => {
                            let stats = telemetry.get_or_create(peer_pub_key);
                            relay::relay_connections_with_conn_stat(
                                tcp_socket,
                                quic_send,
                                quic_recv,
                                stats,
                                conn_stat,
                            )
                            .await;
                            return;
                        }
                        Ok(Ok(_)) => {
                            log::warn!("Server side rejected proxy endpoint {}", original_dst);
                        }
                        Ok(Err(e)) => {
                            log::warn!(
                                "Failed to read server proxy status for {}: {}",
                                original_dst,
                                e
                            );
                        }
                        Err(_) => {
                            log::warn!(
                                "Timed out waiting for server proxy status for {}",
                                original_dst
                            );
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "QUIC pool unhealthy or failed to open stream: {}. Falling back to WireGuard (L3) tunnel.",
                    e
                );
            }
        }

        // --- WIREGUARD FALLBACK PATH ---
        log::info!(
            "QUIC pool unavailable; falling back connection {} -> {} to WireGuard L3 relay",
            src_addr,
            original_dst
        );

        let local_bind_ip = {
            let st = state.read();
            st.config.interface.addresses.iter()
                .find(|ipnet| matches!(ipnet, ipnet::IpNet::V4(_)) == original_dst.is_ipv4())
                .map(|ipnet| ipnet.addr())
        };

        let outbound_socket = if original_dst.is_ipv6() {
            tokio::net::TcpSocket::new_v6()
        } else {
            tokio::net::TcpSocket::new_v4()
        };

        let outbound_stream = match outbound_socket {
            Ok(socket) => {
                if let Some(ip) = local_bind_ip {
                    let _ = socket.bind(SocketAddr::new(ip, 0));
                }

                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::io::AsRawFd;
                    let fd = socket.as_raw_fd();
                    if let Ok(iface_cstring) = std::ffi::CString::new(quic_pool.interface_name()) {
                        let iface_bytes = iface_cstring.as_bytes_with_nul();
                        let ret = unsafe {
                            libc::setsockopt(
                                fd,
                                libc::SOL_SOCKET,
                                libc::SO_BINDTODEVICE,
                                iface_bytes.as_ptr() as *const libc::c_void,
                                iface_bytes.len() as libc::socklen_t,
                            )
                        };
                        if ret != 0 {
                            log::warn!(
                                "WireGuard fallback: failed to set SO_BINDTODEVICE on interface {}: {}",
                                quic_pool.interface_name(),
                                std::io::Error::last_os_error()
                            );
                        }
                    }
                }

                match timeout(Duration::from_secs(5), socket.connect(original_dst)).await {
                    Ok(Ok(stream)) => Some(stream),
                    Ok(Err(err)) => {
                        log::error!("WireGuard fallback: connection to {} failed: {}", original_dst, err);
                        None
                    }
                    Err(_) => {
                        log::error!("WireGuard fallback: connection to {} timed out", original_dst);
                        None
                    }
                }
            }
            Err(err) => {
                log::error!("WireGuard fallback: failed to create TCP socket: {}", err);
                None
            }
        };

        if let Some(outbound_stream) = outbound_stream {
            relay::relay_fallback_connections(tcp_socket, outbound_stream).await;
        }
    } else {
        log::debug!(
            "Intercepted connection to {} does not match AllowedIPs. Dropped.",
            original_dst
        );
    }
}
