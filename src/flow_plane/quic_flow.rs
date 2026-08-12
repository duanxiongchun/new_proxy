use crate::flow_plane::QuicFlowId;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DcidOwner {
    pub flow_worker_id: usize,
    pub quic_flow_id: QuicFlowId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicFlow {
    id: QuicFlowId,
    flow_worker_id: usize,
    tunnel_queue_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QuicFlowError {
    #[error("DCID must not be empty")]
    EmptyDcid,
    #[error("worker count must be greater than zero")]
    ZeroWorkers,
    #[error("tunnel queue count must be greater than zero")]
    ZeroTunnelQueues,
    #[error("DCID is already owned by {0:?}")]
    DuplicateDcid(DcidOwner),
}

impl QuicFlow {
    pub fn new(
        id: QuicFlowId,
        flow_worker_id: usize,
        initial_dcid: &[u8],
        tunnel_queue_count: u32,
    ) -> Result<Self, QuicFlowError> {
        if initial_dcid.is_empty() {
            return Err(QuicFlowError::EmptyDcid);
        }
        if tunnel_queue_count == 0 {
            return Err(QuicFlowError::ZeroTunnelQueues);
        }
        Ok(Self {
            id,
            flow_worker_id,
            tunnel_queue_id: (fnv1a(initial_dcid) % u64::from(tunnel_queue_count)) as u32,
        })
    }

    pub const fn id(&self) -> QuicFlowId {
        self.id
    }

    pub const fn flow_worker_id(&self) -> usize {
        self.flow_worker_id
    }

    pub const fn tunnel_queue_id(&self) -> u32 {
        self.tunnel_queue_id
    }
}

pub fn bootstrap_owner(dcid: &[u8], worker_count: usize) -> Result<usize, QuicFlowError> {
    if dcid.is_empty() {
        return Err(QuicFlowError::EmptyDcid);
    }
    if worker_count == 0 {
        return Err(QuicFlowError::ZeroWorkers);
    }
    Ok((fnv1a(dcid) % worker_count as u64) as usize)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    bytes.iter().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

#[derive(Debug, Default)]
pub struct ActiveDcidIndex {
    by_dcid: HashMap<Vec<u8>, DcidOwner>,
    by_flow: HashMap<QuicFlowId, HashSet<Vec<u8>>>,
}

impl ActiveDcidIndex {
    pub fn publish(&mut self, dcid: &[u8], owner: DcidOwner) -> Result<(), QuicFlowError> {
        if dcid.is_empty() {
            return Err(QuicFlowError::EmptyDcid);
        }
        if let Some(existing) = self.by_dcid.get(dcid) {
            return if *existing == owner {
                Ok(())
            } else {
                Err(QuicFlowError::DuplicateDcid(*existing))
            };
        }
        let dcid = dcid.to_vec();
        self.by_dcid.insert(dcid.clone(), owner);
        self.by_flow
            .entry(owner.quic_flow_id)
            .or_default()
            .insert(dcid);
        Ok(())
    }

    pub fn resolve(&self, dcid: &[u8]) -> Option<DcidOwner> {
        self.by_dcid.get(dcid).copied()
    }

    pub fn retire(&mut self, dcid: &[u8]) -> Option<DcidOwner> {
        let owner = self.by_dcid.remove(dcid)?;
        if let Some(dcids) = self.by_flow.get_mut(&owner.quic_flow_id) {
            dcids.remove(dcid);
            if dcids.is_empty() {
                self.by_flow.remove(&owner.quic_flow_id);
            }
        }
        Some(owner)
    }

    pub fn close_flow(&mut self, quic_flow_id: QuicFlowId) -> usize {
        let Some(dcids) = self.by_flow.remove(&quic_flow_id) else {
            return 0;
        };
        let removed = dcids.len();
        for dcid in dcids {
            self.by_dcid.remove(&dcid);
        }
        removed
    }

    pub fn len(&self) -> usize {
        self.by_dcid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_dcid.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_plane::SessionTable;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn v1_unit_quic_flow_keeps_stable_tunnel_queue_across_dcid_rotation() {
        let flow = QuicFlow::new(QuicFlowId(7), 2, b"initial-dcid", 4).unwrap();
        let queue = flow.tunnel_queue_id();
        let mut index = ActiveDcidIndex::default();
        let owner = DcidOwner {
            flow_worker_id: flow.flow_worker_id(),
            quic_flow_id: flow.id(),
        };

        index.publish(b"initial-dcid", owner).unwrap();
        index.publish(b"rotated-dcid", owner).unwrap();
        index.retire(b"initial-dcid");

        assert_eq!(flow.tunnel_queue_id(), queue);
        assert_eq!(index.resolve(b"rotated-dcid"), Some(owner));
    }

    #[test]
    fn v1_unit_quic_flow_bootstrap_is_deterministic_and_validated() {
        let first = bootstrap_owner(b"unknown-dcid", 4).unwrap();
        let second = bootstrap_owner(b"unknown-dcid", 4).unwrap();

        assert_eq!(first, second);
        assert!(first < 4);
        assert_eq!(bootstrap_owner(b"", 4), Err(QuicFlowError::EmptyDcid));
        assert_eq!(bootstrap_owner(b"dcid", 0), Err(QuicFlowError::ZeroWorkers));
        assert_eq!(
            QuicFlow::new(QuicFlowId(1), 0, b"dcid", 0),
            Err(QuicFlowError::ZeroTunnelQueues)
        );
    }

    #[test]
    fn v1_unit_quic_flow_bootstrap_does_not_create_business_session() {
        let table =
            SessionTable::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001).unwrap();

        let _owner = bootstrap_owner(b"bootstrap-dcid", 2).unwrap();

        assert!(table.is_empty());
        assert_eq!(table.nat_len(), 0);
    }

    #[test]
    fn v1_unit_dcid_publish_retire_and_close_are_complete() {
        let mut index = ActiveDcidIndex::default();
        let first = DcidOwner {
            flow_worker_id: 1,
            quic_flow_id: QuicFlowId(7),
        };
        let conflicting = DcidOwner {
            flow_worker_id: 2,
            quic_flow_id: QuicFlowId(8),
        };

        index.publish(b"a", first).unwrap();
        index.publish(b"b", first).unwrap();
        assert_eq!(
            index.publish(b"a", conflicting),
            Err(QuicFlowError::DuplicateDcid(first))
        );
        assert_eq!(index.retire(b"a"), Some(first));
        assert_eq!(index.resolve(b"a"), None);
        assert_eq!(index.close_flow(QuicFlowId(7)), 1);
        assert!(index.is_empty());
    }
}
