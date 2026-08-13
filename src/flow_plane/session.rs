use crate::flow_plane::{
    FlowKey, IoOwnerKey, NatBinding, NatError, NatTable, QuicFlowId, SessionId, SessionLocator,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionKey {
    pub original: FlowKey,
    pub intercept_ifindex: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: SessionId,
    pub original: FlowKey,
    pub nat: NatBinding,
    pub flow_worker_id: usize,
    pub intercept_io: IoOwnerKey,
    pub quic_flow_id: QuicFlowId,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionError {
    #[error("flow state belongs to worker {expected}, not worker {actual}")]
    WrongOwner { expected: usize, actual: usize },
    #[error("session {0:?} does not exist")]
    UnknownSession(SessionId),
    #[error(transparent)]
    Nat(#[from] NatError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterceptIoUpdate {
    Unchanged,
    Corrected,
    Mismatch,
}

#[derive(Debug)]
pub struct SessionTable {
    owner_worker_id: usize,
    next_session_id: u64,
    by_key: HashMap<SessionKey, SessionId>,
    sessions: HashMap<SessionId, Session>,
    nat: NatTable,
}

impl SessionTable {
    pub fn new(
        owner_worker_id: usize,
        snat_ip: IpAddr,
        ports: RangeInclusive<u16>,
    ) -> Result<Self, SessionError> {
        let (snat_ipv4, snat_ipv6) = match snat_ip {
            IpAddr::V4(address) => (Some(address), None),
            IpAddr::V6(address) => (None, Some(address)),
        };
        Self::new_dual(owner_worker_id, snat_ipv4, snat_ipv6, ports)
    }

    pub fn new_dual(
        owner_worker_id: usize,
        snat_ipv4: Option<Ipv4Addr>,
        snat_ipv6: Option<Ipv6Addr>,
        ports: RangeInclusive<u16>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            owner_worker_id,
            next_session_id: 1,
            by_key: HashMap::new(),
            sessions: HashMap::new(),
            nat: NatTable::new_dual(snat_ipv4, snat_ipv6, ports)?,
        })
    }

    pub fn get_or_create(
        &mut self,
        caller_worker_id: usize,
        original: FlowKey,
        intercept_io: IoOwnerKey,
        quic_flow_id: QuicFlowId,
    ) -> Result<SessionId, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let key = SessionKey {
            original: original.clone(),
            intercept_ifindex: intercept_io.ifindex,
        };
        if let Some(session_id) = self.by_key.get(&key) {
            return Ok(*session_id);
        }

        let session_id = SessionId(self.next_session_id);
        let locator = SessionLocator {
            flow_worker_id: self.owner_worker_id,
            session_id,
        };
        let nat = self
            .nat
            .allocate(session_id, original.clone(), locator)?
            .clone();
        let session = Session {
            id: session_id,
            original,
            nat,
            flow_worker_id: self.owner_worker_id,
            intercept_io,
            quic_flow_id,
        };

        self.by_key.insert(key, session_id);
        self.sessions.insert(session_id, session);
        self.next_session_id = self.next_session_id.wrapping_add(1);
        Ok(session_id)
    }

    pub fn get(&self, session_id: SessionId) -> Option<&Session> {
        self.sessions.get(&session_id)
    }

    pub fn correct_intercept_io(
        &mut self,
        caller_worker_id: usize,
        session_id: SessionId,
        observed: IoOwnerKey,
    ) -> Result<InterceptIoUpdate, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionError::UnknownSession(session_id))?;
        if session.intercept_io == observed {
            return Ok(InterceptIoUpdate::Unchanged);
        }
        if session.intercept_io.ifindex == observed.ifindex && session.intercept_io.queue_id == 0 {
            session.intercept_io = observed;
            return Ok(InterceptIoUpdate::Corrected);
        }
        Ok(InterceptIoUpdate::Mismatch)
    }

    pub fn lookup_reverse(&self, return_flow: &FlowKey) -> Option<SessionId> {
        self.nat
            .lookup_reverse(return_flow)
            .filter(|locator| locator.flow_worker_id == self.owner_worker_id)
            .filter(|locator| self.sessions.contains_key(&locator.session_id))
            .map(|locator| locator.session_id)
    }

    pub fn allocate_ephemeral_nat(
        &mut self,
        caller_worker_id: usize,
        token: SessionId,
        original: FlowKey,
    ) -> Result<NatBinding, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let locator = SessionLocator {
            flow_worker_id: self.owner_worker_id,
            session_id: token,
        };
        Ok(self.nat.allocate(token, original, locator)?.clone())
    }

    pub fn release_ephemeral_nat(
        &mut self,
        caller_worker_id: usize,
        token: SessionId,
    ) -> Result<NatBinding, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        Ok(self.nat.remove(token)?)
    }

    pub fn remove(
        &mut self,
        caller_worker_id: usize,
        session_id: SessionId,
    ) -> Result<Session, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let session = self
            .sessions
            .get(&session_id)
            .cloned()
            .ok_or(SessionError::UnknownSession(session_id))?;
        self.nat.remove(session_id)?;
        self.sessions.remove(&session_id);
        self.by_key.remove(&SessionKey {
            original: session.original.clone(),
            intercept_ifindex: session.intercept_io.ifindex,
        });
        Ok(session)
    }

    pub fn remove_by_quic_flow(
        &mut self,
        caller_worker_id: usize,
        quic_flow_id: QuicFlowId,
    ) -> Result<usize, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let session_ids = self
            .sessions
            .values()
            .filter(|session| session.quic_flow_id == quic_flow_id)
            .map(|session| session.id)
            .collect::<Vec<_>>();
        for session_id in &session_ids {
            self.remove(caller_worker_id, *session_id)?;
        }
        Ok(session_ids.len())
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn nat_len(&self) -> usize {
        self.nat.len()
    }

    pub fn reverse_nat_len(&self) -> usize {
        self.nat.reverse_len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SessionId, &Session)> {
        self.sessions.iter()
    }

    fn ensure_owner(&self, caller_worker_id: usize) -> Result<(), SessionError> {
        if caller_worker_id != self.owner_worker_id {
            return Err(SessionError::WrongOwner {
                expected: self.owner_worker_id,
                actual: caller_worker_id,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_plane::{FlowKey, QuicFlowId, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn flow(source_port: u16) -> FlowKey {
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            source_port,
            destination_port: 443,
            protocol: TransportProtocol::Tcp,
        }
    }

    fn table() -> SessionTable {
        SessionTable::new(2, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40002).unwrap()
    }

    #[test]
    fn v1_unit_session_duplicate_packets_reuse_one_session() {
        let mut table = table();
        let ingress = IoOwnerKey::new(10, 3);

        let first = table
            .get_or_create(2, flow(10001), ingress, QuicFlowId(7))
            .unwrap();
        let duplicate = table
            .get_or_create(2, flow(10001), ingress, QuicFlowId(7))
            .unwrap();

        assert_eq!(first, duplicate);
        assert_eq!(table.len(), 1);
        assert_eq!(table.nat_len(), 1);
    }

    #[test]
    fn v1_unit_session_distinguishes_same_flow_on_different_interfaces() {
        let mut table = table();

        let first = table
            .get_or_create(2, flow(10001), IoOwnerKey::new(10, 0), QuicFlowId(7))
            .unwrap();
        let second = table
            .get_or_create(2, flow(10001), IoOwnerKey::new(11, 0), QuicFlowId(7))
            .unwrap();

        assert_ne!(first, second);
        assert_ne!(
            table.get(first).unwrap().nat.translated,
            table.get(second).unwrap().nat.translated
        );
    }

    #[test]
    fn v1_unit_session_rejects_mutation_by_the_wrong_worker() {
        let mut table = table();

        assert_eq!(
            table.get_or_create(1, flow(10001), IoOwnerKey::new(10, 0), QuicFlowId(7)),
            Err(SessionError::WrongOwner {
                expected: 2,
                actual: 1,
            })
        );
        assert!(table.is_empty());
    }

    #[test]
    fn v1_unit_session_remove_cleans_forward_reverse_and_port_state() {
        let mut table = table();
        let first = table
            .get_or_create(2, flow(10001), IoOwnerKey::new(10, 0), QuicFlowId(7))
            .unwrap();
        let return_flow = table.get(first).unwrap().nat.translated.reverse();

        assert_eq!(table.lookup_reverse(&return_flow), Some(first));
        table.remove(2, first).unwrap();

        assert!(table.get(first).is_none());
        assert_eq!(table.lookup_reverse(&return_flow), None);
        assert_eq!(table.nat_len(), 0);
        assert_eq!(table.reverse_nat_len(), 0);

        let second = table
            .get_or_create(2, flow(10002), IoOwnerKey::new(10, 0), QuicFlowId(7))
            .unwrap();
        assert_eq!(table.get(second).unwrap().nat.translated.source_port, 40000);
    }

    #[test]
    fn v1_unit_session_reverse_miss_never_creates_state() {
        let table = table();

        assert_eq!(table.lookup_reverse(&flow(65000)), None);
        assert!(table.is_empty());
        assert_eq!(table.nat_len(), 0);
    }

    #[test]
    fn v1_unit_session_reclaims_only_the_closed_quic_flow() {
        let mut table = table();
        let first = table
            .get_or_create(2, flow(10001), IoOwnerKey::new(10, 0), QuicFlowId(7))
            .unwrap();
        let second = table
            .get_or_create(2, flow(10002), IoOwnerKey::new(10, 1), QuicFlowId(7))
            .unwrap();
        let retained = table
            .get_or_create(2, flow(10003), IoOwnerKey::new(10, 2), QuicFlowId(8))
            .unwrap();
        let first_return = table.get(first).unwrap().nat.translated.reverse();
        let second_return = table.get(second).unwrap().nat.translated.reverse();

        let removed = table.remove_by_quic_flow(2, QuicFlowId(7)).unwrap();

        assert_eq!(removed, 2);
        assert!(table.get(first).is_none());
        assert!(table.get(second).is_none());
        assert!(table.get(retained).is_some());
        assert_eq!(table.lookup_reverse(&first_return), None);
        assert_eq!(table.lookup_reverse(&second_return), None);
        assert_eq!(table.nat_len(), 1);
        assert_eq!(table.reverse_nat_len(), 1);
    }
}
