use crate::config;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct WgPeerStats {
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_handshake: u64,
    pub unknown_handshake_drops: u64,
}

#[derive(Clone)]
pub struct UserspaceWgRegistry {
    peers: Arc<parking_lot::RwLock<HashMap<[u8; 32], config::PeerConfig>>>,
}

impl UserspaceWgRegistry {
    pub fn new(_private_key: [u8; 32], peers: &[config::PeerConfig]) -> Result<Self, String> {
        let mut map = HashMap::new();
        for peer in peers {
            map.insert(peer.public_key, peer.clone());
        }
        Ok(Self {
            peers: Arc::new(parking_lot::RwLock::new(map)),
        })
    }

    pub fn snapshot(&self) -> HashMap<[u8; 32], WgPeerStats> {
        let peers = self.peers.read();
        let mut map = HashMap::new();
        for (&pub_key, peer) in peers.iter() {
            map.insert(pub_key, WgPeerStats {
                allowed_ips: peer.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
                endpoint: peer.endpoint.map(|ep| ep.to_string()),
                rx_bytes: 0,
                tx_bytes: 0,
                last_handshake: 0,
                unknown_handshake_drops: 0,
            });
        }
        map
    }

    pub fn add_or_replace_peer(&self, peer: config::PeerConfig) -> Result<(), String> {
        let mut peers = self.peers.write();
        peers.insert(peer.public_key, peer);
        Ok(())
    }

    pub fn remove_peer(&self, pub_key: &[u8; 32]) {
        let mut peers = self.peers.write();
        peers.remove(pub_key);
    }
}
