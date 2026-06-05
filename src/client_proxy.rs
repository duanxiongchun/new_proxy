use crate::app_config::select_quic_endpoint_ip;
use crate::config;
use crate::control::ControlClient;
use crate::encode_base64_32;
use crate::proxy_proto::write_target_addr;
use crate::quic_pool::{PoolState, QuicPoolClient};
use crate::relay::PeerL4Stats;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::timeout;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(not(tarpaulin))]
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

#[cfg(tarpaulin)]
pub async fn build_peer_quic_pool(
    _private_key: [u8; 32],
    _peer: &config::PeerConfig,
) -> Result<Arc<QuicPoolClient>, String> {
    Err("QUIC pool creation is excluded from unit coverage".to_string())
}

#[cfg(not(tarpaulin))]
pub async fn bridge_userspace_stream_to_quic(
    target_addr: SocketAddr,
    quic_pool: Arc<QuicPoolClient>,
    stats: Arc<PeerL4Stats>,
    mut tx_receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    rx_sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    worker_notify: Arc<Notify>,
) {
    let pool_state = quic_pool.get_state();
    if !matches!(pool_state, PoolState::Active) {
        log::warn!(
            "QUIC pool is not active, dropping userspace stream to {}",
            target_addr
        );
        return;
    }

    match quic_pool.open_mux_stream().await {
        Ok((mut quic_send, mut quic_recv, conn_stat)) => {
            if write_target_addr(&mut quic_send, target_addr).await.is_ok() {
                let mut status = [0u8; 1];
                match timeout(Duration::from_secs(5), quic_recv.read_exact(&mut status)).await {
                    Ok(Ok(_)) if status[0] == 1 => {
                        stats.active_streams.fetch_add(1, Ordering::Relaxed);
                        conn_stat.active_streams.fetch_add(1, Ordering::Relaxed);
                        let _active_guard = UserspaceBridgeActiveStreamGuard {
                            stats: stats.clone(),
                            conn_stat: conn_stat.clone(),
                        };
                        // Bridge data
                        let send_stats = stats.clone();
                        let send_conn_stat = conn_stat.clone();
                        let send_loop = async move {
                            while let Some(data) = tx_receiver.recv().await {
                                let len = data.len();
                                if quic_send.write_all(&data).await.is_err() {
                                    break;
                                }
                                send_stats.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                                send_conn_stat
                                    .tx_bytes
                                    .fetch_add(len as u64, Ordering::Relaxed);
                            }
                            let _ = quic_send.finish().await;
                        };
                        let recv_stats = stats.clone();
                        let recv_conn_stat = conn_stat.clone();
                        let recv_loop = async move {
                            let mut buf = vec![0u8; 1500];
                            while let Ok(n) = quic_recv.read(&mut buf).await {
                                if let Some(bytes) = n {
                                    if bytes > 0 {
                                        recv_stats
                                            .rx_bytes
                                            .fetch_add(bytes as u64, Ordering::Relaxed);
                                        recv_conn_stat
                                            .rx_bytes
                                            .fetch_add(bytes as u64, Ordering::Relaxed);
                                        if rx_sender.send(buf[..bytes].to_vec()).await.is_err() {
                                            break;
                                        }
                                        worker_notify.notify_one();
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            worker_notify.notify_one();
                        };
                        let mut send_task = tokio::spawn(send_loop);
                        let mut recv_task = tokio::spawn(recv_loop);
                        tokio::select! {
                            res = &mut recv_task => {
                                if let Err(e) = res {
                                    log::debug!("userspace QUIC receive bridge task failed: {}", e);
                                }
                                send_task.abort();
                                let _ = send_task.await;
                            }
                            res = &mut send_task => {
                                if let Err(e) = res {
                                    log::debug!("userspace QUIC send bridge task failed: {}", e);
                                }
                                tokio::select! {
                                    res2 = &mut recv_task => {
                                        if let Err(e) = res2 {
                                            log::debug!("userspace QUIC receive bridge task failed: {}", e);
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                                        recv_task.abort();
                                        let _ = recv_task.await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(Ok(_)) => {
                        log::warn!("Server rejected userspace target {}", target_addr);
                    }
                    Ok(Err(e)) => {
                        log::warn!(
                            "Failed to read userspace target proxy status for {}: {}",
                            target_addr,
                            e
                        );
                        quic_pool.enter_fallback("failed to read userspace stream proxy status");
                    }
                    Err(_) => {
                        log::warn!(
                            "Timed out waiting for userspace target proxy status for {}",
                            target_addr
                        );
                        quic_pool.enter_fallback("failed to complete userspace stream proxy setup");
                    }
                }
            } else {
                quic_pool.enter_fallback("failed to write userspace stream target address");
            }
        }
        Err(e) => {
            log::warn!("Failed to open stream for userspace bridge: {}", e);
            quic_pool.enter_fallback("failed to open userspace QUIC mux stream");
        }
    }
}

struct UserspaceBridgeActiveStreamGuard {
    stats: Arc<PeerL4Stats>,
    conn_stat: Arc<crate::quic_pool::QuicConnStats>,
}

impl Drop for UserspaceBridgeActiveStreamGuard {
    fn drop(&mut self) {
        self.stats.active_streams.fetch_sub(1, Ordering::Relaxed);
        self.conn_stat
            .active_streams
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(tarpaulin)]
pub async fn bridge_userspace_stream_to_quic(
    _target_addr: SocketAddr,
    _quic_pool: Arc<QuicPoolClient>,
    _stats: Arc<PeerL4Stats>,
    _tx_receiver: tokio::sync::mpsc::Receiver<Vec<u8>>,
    _rx_sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    _worker_notify: Arc<Notify>,
) {
}
