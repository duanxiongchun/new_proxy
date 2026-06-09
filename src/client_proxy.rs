use crate::app_config::select_quic_endpoint_ip;
use crate::config;
use crate::control::ControlClient;
use crate::encode_base64_32;
use crate::quic_pool::QuicPoolClient;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{error::Error, fmt};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Clone)]
pub struct BuildPeerQuicPoolError {
    message: String,
    data_port_count: Option<usize>,
}

impl BuildPeerQuicPoolError {
    fn new(message: impl Into<String>, data_port_count: Option<usize>) -> Self {
        Self {
            message: message.into(),
            data_port_count,
        }
    }

    pub fn data_port_count(&self) -> Option<usize> {
        self.data_port_count
    }
}

impl fmt::Display for BuildPeerQuicPoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for BuildPeerQuicPoolError {}

#[cfg(not(tarpaulin))]
pub async fn negotiate_peer_quic_data_port_count(
    private_key: [u8; 32],
    peer: &config::PeerConfig,
) -> Result<usize, BuildPeerQuicPoolError> {
    let endpoint = peer
        .endpoint
        .ok_or_else(|| BuildPeerQuicPoolError::new("proxy peer is missing Endpoint", None))?;
    let proxy_port = peer
        .proxy_port
        .ok_or_else(|| BuildPeerQuicPoolError::new("proxy peer is missing ProxyPort", None))?;
    let control_addr = SocketAddr::new(endpoint.ip(), proxy_port);
    let control_client = ControlClient::new(private_key, peer.public_key, control_addr);

    log::info!(
        "Preflighting QUIC data port count for peer {} to {}",
        encode_base64_32(&peer.public_key),
        control_addr
    );
    let (control_response, _control_socket) = control_client
        .negotiate_config()
        .await
        .map_err(|e| BuildPeerQuicPoolError::new(e, None))?;
    Ok(control_response.port_pool.len())
}

#[cfg(tarpaulin)]
pub async fn negotiate_peer_quic_data_port_count(
    _private_key: [u8; 32],
    _peer: &config::PeerConfig,
) -> Result<usize, BuildPeerQuicPoolError> {
    Err(BuildPeerQuicPoolError::new(
        "QUIC data port preflight is excluded from unit coverage",
        None,
    ))
}

#[cfg(not(tarpaulin))]
pub async fn build_peer_quic_pool(
    private_key: [u8; 32],
    peer: &config::PeerConfig,
) -> Result<Arc<QuicPoolClient>, BuildPeerQuicPoolError> {
    let endpoint = peer
        .endpoint
        .ok_or_else(|| BuildPeerQuicPoolError::new("proxy peer is missing Endpoint", None))?;
    let proxy_port = peer
        .proxy_port
        .ok_or_else(|| BuildPeerQuicPoolError::new("proxy peer is missing ProxyPort", None))?;
    let control_addr = SocketAddr::new(endpoint.ip(), proxy_port);
    let control_client = ControlClient::new(private_key, peer.public_key, control_addr);

    log::info!(
        "Initiating userspace ECDH + HMAC-SHA256 control handshake for peer {} to {}",
        encode_base64_32(&peer.public_key),
        control_addr
    );
    let (control_response, _control_socket) = control_client
        .negotiate_config()
        .await
        .map_err(|e| BuildPeerQuicPoolError::new(e, None))?;
    let data_port_count = Some(control_response.port_pool.len());
    let quic_endpoint_ip = select_quic_endpoint_ip(&control_response, endpoint)
        .map_err(|e| BuildPeerQuicPoolError::new(e, data_port_count))?;
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
    quic_pool_client
        .start_pool()
        .await
        .map_err(|e| BuildPeerQuicPoolError::new(e, data_port_count))?;
    quic_pool_client.clone().start_health_checker();
    Ok(quic_pool_client)
}

#[cfg(tarpaulin)]
pub async fn build_peer_quic_pool(
    _private_key: [u8; 32],
    _peer: &config::PeerConfig,
) -> Result<Arc<QuicPoolClient>, BuildPeerQuicPoolError> {
    Err(BuildPeerQuicPoolError::new(
        "QUIC pool creation is excluded from unit coverage",
        None,
    ))
}
