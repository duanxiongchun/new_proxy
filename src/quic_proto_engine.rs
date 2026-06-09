use quinn_proto::Connection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPacket {
    pub payload: Vec<u8>,
    pub mac: [u8; 32],
}

pub struct WorkerConnection {
    pub connection: Connection,
    pub authenticated: bool,
    pub tx_bytes: Arc<std::sync::atomic::AtomicU64>,
    pub rx_bytes: Arc<std::sync::atomic::AtomicU64>,
}
