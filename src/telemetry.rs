use crate::quic_pool::QuicConnSnapshot;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// 非原子型 U64 计数器包装类，通过 UnsafeCell 绕过 Rust 的内部可变性检查，
// 从而在多线程环境的单线程独占写入（Worker 线程）场景中完全消除 LOCK 前缀指令的原子开销。
#[derive(Debug)]
pub struct CellU64(core::cell::UnsafeCell<u64>);

impl CellU64 {
    #[inline(always)]
    pub fn new(val: u64) -> Self {
        Self(core::cell::UnsafeCell::new(val))
    }

    #[inline(always)]
    pub fn add(&self, val: u64) {
        unsafe {
            *self.0.get() += val;
        }
    }

    #[inline(always)]
    pub fn load(&self) -> u64 {
        unsafe { *self.0.get() }
    }

    #[inline(always)]
    pub fn store(&self, val: u64) {
        unsafe {
            *self.0.get() = val;
        }
    }
}

unsafe impl Send for CellU64 {}
unsafe impl Sync for CellU64 {}

impl Default for CellU64 {
    #[inline(always)]
    fn default() -> Self {
        Self::new(0)
    }
}

// 用户态 L4 (QUIC) 统计指标（聚合到 peer 级别）
pub struct PeerL4Stats {
    pub tx_bytes: Arc<CellU64>,
    pub rx_bytes: Arc<CellU64>,
    pub active_streams: CellU64,
}

impl Default for PeerL4Stats {
    fn default() -> Self {
        Self {
            tx_bytes: Arc::new(CellU64::new(0)),
            rx_bytes: Arc::new(CellU64::new(0)),
            active_streams: CellU64::new(0),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnifiedTelemetry {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub l3_rx_bytes: u64,
    pub l3_tx_bytes: u64,
    #[serde(default)]
    pub l3_unknown_handshake_drops: u64,
    pub last_handshake: u64,
    pub l4_rx_bytes: u64,
    pub l4_tx_bytes: u64,
    pub active_streams: u64,
    pub quic_connections: Vec<QuicConnSnapshot>,
    pub source: String,
}

const TELEMETRY_SHARDS: usize = 64;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct WorkerTelemetrySnapshot {
    pub worker_id: usize,
    pub tun_rx_packets: u64,
    pub tun_rx_bytes: u64,
    pub tcp_offload_packets: u64,
    pub tcp_offload_bytes: u64,
    pub l3_packets: u64,
    pub l3_bytes: u64,
    pub new_tcp_flows: u64,
    pub current_tcp_flows: u64,
}

pub struct WorkerTelemetry {
    worker_id: usize,
    snapshot: Mutex<WorkerTelemetrySnapshot>,
}

impl WorkerTelemetry {
    fn new(worker_id: usize) -> Self {
        Self {
            worker_id,
            snapshot: Mutex::new(WorkerTelemetrySnapshot {
                worker_id,
                ..WorkerTelemetrySnapshot::default()
            }),
        }
    }

    pub fn worker_id(&self) -> usize {
        self.worker_id
    }

    pub fn publish(&self, snapshot: &WorkerTelemetrySnapshot) {
        *self.snapshot.lock() = snapshot.clone();
    }

    pub fn snapshot(&self) -> WorkerTelemetrySnapshot {
        self.snapshot.lock().clone()
    }
}

#[derive(Default)]
pub struct WorkerTelemetryRegistry {
    workers: Mutex<HashMap<usize, Arc<WorkerTelemetry>>>,
}

impl WorkerTelemetryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&self, worker_id: usize) -> Arc<WorkerTelemetry> {
        let mut workers = self.workers.lock();
        workers
            .entry(worker_id)
            .or_insert_with(|| Arc::new(WorkerTelemetry::new(worker_id)))
            .clone()
    }

    pub fn snapshot(&self) -> Vec<WorkerTelemetrySnapshot> {
        let mut snapshot = self
            .workers
            .lock()
            .values()
            .map(|worker| worker.snapshot())
            .collect::<Vec<_>>();
        snapshot.sort_by_key(|worker| worker.worker_id);
        snapshot
    }
}

pub struct TelemetryRegistry {
    stats: Vec<Mutex<HashMap<[u8; 32], Arc<PeerL4Stats>>>>,
}

impl TelemetryRegistry {
    pub fn new() -> Self {
        let mut stats = Vec::with_capacity(TELEMETRY_SHARDS);
        for _ in 0..TELEMETRY_SHARDS {
            stats.push(Mutex::new(HashMap::new()));
        }
        Self { stats }
    }

    pub fn get_or_create(&self, pub_key: [u8; 32]) -> Arc<PeerL4Stats> {
        let mut map = self.stats[self.shard_index(&pub_key)].lock();
        map.entry(pub_key)
            .or_insert_with(|| Arc::new(PeerL4Stats::default()))
            .clone()
    }

    pub fn snapshot(&self) -> HashMap<[u8; 32], Arc<PeerL4Stats>> {
        let mut snapshot = HashMap::new();
        for shard in &self.stats {
            let map = shard.lock();
            snapshot.extend(map.iter().map(|(k, v)| (*k, v.clone())));
        }
        snapshot
    }

    pub fn remove(&self, pub_key: &[u8; 32]) {
        let mut map = self.stats[self.shard_index(pub_key)].lock();
        map.remove(pub_key);
    }

    fn shard_index(&self, pub_key: &[u8; 32]) -> usize {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&pub_key[..8]);
        (u64::from_le_bytes(bytes) as usize) % self.stats.len()
    }
}

impl Default for TelemetryRegistry {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct VirtualTunnelTelemetrySnapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub control_packets: u64,
    pub recv_errors: u64,
}

#[derive(Default)]
pub struct VirtualTunnelTelemetry {
    pub rx_packets: CellU64,
    pub rx_bytes: CellU64,
    pub control_packets: CellU64,
    pub recv_errors: CellU64,
}

impl VirtualTunnelTelemetry {
    pub fn snapshot(&self) -> VirtualTunnelTelemetrySnapshot {
        VirtualTunnelTelemetrySnapshot {
            rx_packets: self.rx_packets.load(),
            rx_bytes: self.rx_bytes.load(),
            control_packets: self.control_packets.load(),
            recv_errors: self.recv_errors.load(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_registry_get_or_create_and_snapshot() {
        let registry = TelemetryRegistry::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let stats1 = registry.get_or_create(key1);
        let stats1_again = registry.get_or_create(key1);
        let _stats2 = registry.get_or_create(key2);

        assert!(Arc::ptr_eq(&stats1, &stats1_again));
        stats1.rx_bytes.store(100);
        stats1.tx_bytes.store(200);
        stats1.active_streams.store(3);

        let snap = registry.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[&key1].rx_bytes.load(), 100);
        assert_eq!(snap[&key1].tx_bytes.load(), 200);
        assert_eq!(snap[&key1].active_streams.load(), 3);
    }

    #[test]
    fn test_telemetry_registry_remove() {
        let registry = TelemetryRegistry::new();
        let key = [9u8; 32];
        let stats = registry.get_or_create(key);
        stats.rx_bytes.store(500);

        registry.remove(&key);
        let snap = registry.snapshot();
        assert!(!snap.contains_key(&key));
    }

    #[test]
    fn worker_telemetry_registry_snapshots_in_worker_order() {
        let registry = WorkerTelemetryRegistry::new();
        let worker2 = registry.get_or_create(2);
        worker2.publish(&WorkerTelemetrySnapshot {
            worker_id: 2,
            tun_rx_packets: 20,
            ..WorkerTelemetrySnapshot::default()
        });
        let worker1 = registry.get_or_create(1);
        worker1.publish(&WorkerTelemetrySnapshot {
            worker_id: 1,
            tcp_offload_bytes: 100,
            ..WorkerTelemetrySnapshot::default()
        });

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].worker_id, 1);
        assert_eq!(snapshot[0].tcp_offload_bytes, 100);
        assert_eq!(snapshot[1].worker_id, 2);
        assert_eq!(snapshot[1].tun_rx_packets, 20);
    }
}

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
    peers: Arc<parking_lot::RwLock<HashMap<[u8; 32], crate::config::PeerConfig>>>,
}

impl UserspaceWgRegistry {
    pub fn new(
        _private_key: [u8; 32],
        peers: &[crate::config::PeerConfig],
    ) -> Result<Self, String> {
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
            map.insert(
                pub_key,
                WgPeerStats {
                    allowed_ips: peer.allowed_ips.iter().map(|ip| ip.to_string()).collect(),
                    endpoint: peer.endpoint.map(|ep| ep.to_string()),
                    rx_bytes: 0,
                    tx_bytes: 0,
                    last_handshake: 0,
                    unknown_handshake_drops: 0,
                },
            );
        }
        map
    }

    pub fn add_or_replace_peer(&self, peer: crate::config::PeerConfig) -> Result<(), String> {
        let mut peers = self.peers.write();
        peers.insert(peer.public_key, peer);
        Ok(())
    }

    pub fn remove_peer(&self, pub_key: &[u8; 32]) {
        let mut peers = self.peers.write();
        peers.remove(pub_key);
    }
}
