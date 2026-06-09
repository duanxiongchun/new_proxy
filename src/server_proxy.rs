use crate::proxy_proto::read_target_addr;
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
                let target_addr =
                    match timeout(Duration::from_secs(5), read_target_addr(&mut recv_mux)).await {
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
            })
        },
    )
}
