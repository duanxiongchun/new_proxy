#[derive(Debug, Clone, Default)]
pub struct WgPeerStats {
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: u64,
    pub unknown_handshake_drops: u64,
}
