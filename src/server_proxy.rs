use crate::proxy_proto::{ProxyProtocol, ProxyTargetHeader};
use crate::quic_pool::{QuicConnStats, StreamHandler};
use crate::relay;
use crate::tcp_util::set_tcp_keepalive;
use crate::telemetry::TelemetryRegistry;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

#[cfg(not(tarpaulin))]
pub fn build_stream_handler(
    telemetry: Arc<TelemetryRegistry>,
    stream_handler_limit: Arc<tokio::sync::Semaphore>,
) -> StreamHandler {
    Arc::new(
        move |client_pub: [u8; 32],
              mut send_mux: quinn::SendStream,
              mut recv_mux: quinn::RecvStream,
              conn_stat: Arc<QuicConnStats>|
              -> crate::quic_pool::ServerFuture {
            let permit = match stream_handler_limit.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    log::warn!(
                        "QUIC stream handler limit reached; rejecting stream for peer {:?}",
                        client_pub
                    );
                    return Box::pin(async move {
                        let _ = send_mux.write_all(&[0]).await;
                        let _ = send_mux.shutdown().await;
                    });
                }
            };
            let stats = telemetry.get_or_create(client_pub);
            Box::pin(async move {
                let _permit = permit;
                let header =
                    match timeout(Duration::from_secs(5), ProxyTargetHeader::read_from(&mut recv_mux)).await {
                        Ok(Ok(h)) => h,
                        Ok(Err(e)) => {
                            log::debug!("Failed to read target proxy address header: {}", e);
                            return;
                        }
                        Err(_) => {
                            log::debug!("Timed out reading target proxy address header");
                            return;
                        }
                    };

                let target_addr = std::net::SocketAddr::new(header.dst_ip, header.dst_port);

                match header.protocol {
                    ProxyProtocol::Tcp => {
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
                                    log::warn!("Failed to set TCP Keep-Alive on target TCP stream: {}", e);
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
                    }
                    ProxyProtocol::Udp => {
                        log::info!(
                            "Establishing userspace UDP proxy bridge to target destination: {}",
                            target_addr
                        );
                        let bind_addr = match header.dst_ip {
                            std::net::IpAddr::V4(_) => "0.0.0.0:0",
                            std::net::IpAddr::V6(_) => "[::]:0",
                        };
                        match tokio::net::UdpSocket::bind(bind_addr).await {
                            Ok(udp_socket) => {
                                if let Err(e) = udp_socket.connect(target_addr).await {
                                    log::warn!("Failed to connect UDP socket to {}: {}", target_addr, e);
                                    let _ = send_mux.write_all(&[0]).await;
                                    return;
                                }
                                if send_mux.write_all(&[1]).await.is_ok() {
                                    let mut r = recv_mux;
                                    let mut w = send_mux;
                                    if let Err(e) = relay::relay_stream_to_udp(
                                        &mut r,
                                        &mut w,
                                        &udp_socket,
                                        stats,
                                        Some(conn_stat),
                                    )
                                    .await {
                                        log::debug!("UDP relay error: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("Failed to bind UDP socket: {}", e);
                                let _ = send_mux.write_all(&[0]).await;
                            }
                        }
                    }
                }
            })
        },
    )
}
