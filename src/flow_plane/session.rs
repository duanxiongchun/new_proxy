use crate::flow_plane::{
    FlowKey, IoOwnerKey, NatBinding, NatError, NatTable, QuicFlowId, SessionId, SessionLocator,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_RST_TIMEOUT: Duration = Duration::from_secs(2);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const ICMP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpSessionState {
    Established,
    FinSeenForward,
    FinSeenReverse,
    Closing,
    Reset,
}

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
    pub expires_at: Instant,
    pub tcp_state: Option<TcpSessionState>,
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
    deadlines: BTreeMap<Instant, HashSet<SessionId>>,
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
            deadlines: BTreeMap::new(),
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
        self.get_or_create_at(
            caller_worker_id,
            original,
            intercept_io,
            quic_flow_id,
            Instant::now(),
        )
    }

    pub fn get_or_create_at(
        &mut self,
        caller_worker_id: usize,
        original: FlowKey,
        intercept_io: IoOwnerKey,
        quic_flow_id: QuicFlowId,
        now: Instant,
    ) -> Result<SessionId, SessionError> {
        self.get_or_create_with_flags_at(
            caller_worker_id,
            original,
            intercept_io,
            quic_flow_id,
            None,
            false,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn get_or_create_with_flags_at(
        &mut self,
        caller_worker_id: usize,
        original: FlowKey,
        intercept_io: IoOwnerKey,
        quic_flow_id: QuicFlowId,
        flags: Option<u8>,
        is_reverse: bool,
        now: Instant,
    ) -> Result<SessionId, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let key = SessionKey {
            original: original.clone(),
            intercept_ifindex: intercept_io.ifindex,
        };
        if let Some(session_id) = self.by_key.get(&key).copied() {
            self.touch_tcp(caller_worker_id, session_id, flags, is_reverse, now)?;
            return Ok(session_id);
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

        let (tcp_state, timeout) = if original.protocol == crate::flow_plane::TransportProtocol::Tcp
        {
            let state = TcpSessionState::Established;
            let timeout = if let Some(flags) = flags {
                if flags & 0x04 != 0 {
                    TCP_RST_TIMEOUT
                } else if flags & 0x01 != 0 {
                    TCP_CLOSING_TIMEOUT
                } else {
                    TCP_IDLE_TIMEOUT
                }
            } else {
                TCP_IDLE_TIMEOUT
            };
            (Some(state), timeout)
        } else {
            (None, protocol_idle_timeout(original.protocol))
        };

        let expires_at = now + timeout;
        let session = Session {
            id: session_id,
            original,
            nat,
            flow_worker_id: self.owner_worker_id,
            intercept_io,
            quic_flow_id,
            expires_at,
            tcp_state,
        };

        self.by_key.insert(key, session_id);
        self.sessions.insert(session_id, session);
        self.deadlines
            .entry(expires_at)
            .or_default()
            .insert(session_id);
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
        self.lookup_reverse_locator(return_flow)
            .map(|locator| locator.session_id)
    }

    pub fn lookup_reverse_locator(&self, return_flow: &FlowKey) -> Option<SessionLocator> {
        self.nat
            .lookup_reverse(return_flow)
            .filter(|locator| locator.flow_worker_id == self.owner_worker_id)
            .filter(|locator| self.sessions.contains_key(&locator.session_id))
    }

    pub fn touch(
        &mut self,
        caller_worker_id: usize,
        session_id: SessionId,
        now: Instant,
    ) -> Result<(), SessionError> {
        self.touch_tcp(caller_worker_id, session_id, None, false, now)
    }

    pub fn touch_tcp(
        &mut self,
        caller_worker_id: usize,
        session_id: SessionId,
        flags: Option<u8>,
        is_reverse: bool,
        now: Instant,
    ) -> Result<(), SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionError::UnknownSession(session_id))?;
        let previous_deadline = session.expires_at;

        let timeout = if session.original.protocol == crate::flow_plane::TransportProtocol::Tcp {
            if let Some(flags) = flags {
                if flags & 0x04 != 0 {
                    session.tcp_state = Some(TcpSessionState::Reset);
                    TCP_RST_TIMEOUT
                } else if flags & 0x01 != 0 {
                    let next_state = match session.tcp_state {
                        Some(TcpSessionState::FinSeenReverse) if !is_reverse => {
                            TcpSessionState::Closing
                        }
                        Some(TcpSessionState::FinSeenForward) if is_reverse => {
                            TcpSessionState::Closing
                        }
                        Some(TcpSessionState::Closing) => TcpSessionState::Closing,
                        Some(TcpSessionState::Reset) => TcpSessionState::Reset,
                        _ => {
                            if is_reverse {
                                TcpSessionState::FinSeenReverse
                            } else {
                                TcpSessionState::FinSeenForward
                            }
                        }
                    };
                    session.tcp_state = Some(next_state);
                    if matches!(
                        next_state,
                        TcpSessionState::Closing | TcpSessionState::Reset
                    ) {
                        TCP_CLOSING_TIMEOUT
                    } else {
                        TCP_IDLE_TIMEOUT
                    }
                } else {
                    match session.tcp_state {
                        Some(TcpSessionState::Closing) => TCP_CLOSING_TIMEOUT,
                        Some(TcpSessionState::Reset) => TCP_RST_TIMEOUT,
                        _ => TCP_IDLE_TIMEOUT,
                    }
                }
            } else {
                match session.tcp_state {
                    Some(TcpSessionState::Closing) => TCP_CLOSING_TIMEOUT,
                    Some(TcpSessionState::Reset) => TCP_RST_TIMEOUT,
                    _ => TCP_IDLE_TIMEOUT,
                }
            }
        } else {
            protocol_idle_timeout(session.original.protocol)
        };

        session.expires_at = now + timeout;
        remove_deadline(&mut self.deadlines, previous_deadline, session_id);
        self.deadlines
            .entry(session.expires_at)
            .or_default()
            .insert(session_id);
        Ok(())
    }

    pub fn expire_idle(
        &mut self,
        caller_worker_id: usize,
        now: Instant,
    ) -> Result<Vec<Session>, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let mut expired = Vec::new();
        while self
            .deadlines
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let (_, session_ids) = self
                .deadlines
                .pop_first()
                .expect("checked earliest session deadline");
            expired.extend(session_ids);
        }
        let expired = expired
            .into_iter()
            .filter(|session_id| {
                self.sessions
                    .get(session_id)
                    .is_some_and(|session| session.expires_at <= now)
            })
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .map(|session_id| self.remove(caller_worker_id, session_id))
            .collect()
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
        remove_deadline(&mut self.deadlines, session.expires_at, session_id);
        self.by_key.remove(&SessionKey {
            original: session.original.clone(),
            intercept_ifindex: session.intercept_io.ifindex,
        });
        Ok(session)
    }

    pub fn rebind_quic_flow(
        &mut self,
        caller_worker_id: usize,
        old_quic_flow_id: QuicFlowId,
        new_quic_flow_id: QuicFlowId,
    ) -> Result<usize, SessionError> {
        self.ensure_owner(caller_worker_id)?;
        let mut count = 0;
        for session in self.sessions.values_mut() {
            if session.quic_flow_id == old_quic_flow_id {
                session.quic_flow_id = new_quic_flow_id;
                count += 1;
            }
        }
        Ok(count)
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

const fn protocol_idle_timeout(protocol: crate::flow_plane::TransportProtocol) -> Duration {
    match protocol {
        crate::flow_plane::TransportProtocol::Tcp => TCP_IDLE_TIMEOUT,
        crate::flow_plane::TransportProtocol::Udp => UDP_IDLE_TIMEOUT,
        crate::flow_plane::TransportProtocol::Icmp
        | crate::flow_plane::TransportProtocol::Icmpv6 => ICMP_IDLE_TIMEOUT,
    }
}

fn remove_deadline(
    deadlines: &mut BTreeMap<Instant, HashSet<SessionId>>,
    deadline: Instant,
    session_id: SessionId,
) {
    let remove_bucket = deadlines.get_mut(&deadline).is_some_and(|session_ids| {
        session_ids.remove(&session_id);
        session_ids.is_empty()
    });
    if remove_bucket {
        deadlines.remove(&deadline);
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
    fn v1_unit_session_idle_deadlines_refresh_and_release_nat_state() {
        let mut table = table();
        let ingress = IoOwnerKey::new(10, 3);
        let now = Instant::now();
        let first = table
            .get_or_create_at(2, flow(10001), ingress, QuicFlowId(7), now)
            .unwrap();
        let second = table
            .get_or_create_at(2, flow(10002), ingress, QuicFlowId(7), now)
            .unwrap();

        table
            .touch(2, second, now + Duration::from_secs(299))
            .unwrap();
        let expired = table
            .expire_idle(2, now + Duration::from_secs(300))
            .unwrap();

        assert_eq!(
            expired.iter().map(|session| session.id).collect::<Vec<_>>(),
            vec![first]
        );
        assert!(table.get(first).is_none());
        assert!(table.get(second).is_some());
        assert_eq!(table.nat_len(), 1);
        assert_eq!(table.reverse_nat_len(), 1);

        let expired = table
            .expire_idle(2, now + Duration::from_secs(599))
            .unwrap();
        assert_eq!(
            expired.iter().map(|session| session.id).collect::<Vec<_>>(),
            vec![second]
        );
        assert!(table.is_empty());
        assert_eq!(table.nat_len(), 0);
        assert_eq!(table.reverse_nat_len(), 0);
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
    fn v1_unit_session_remove_cleans_state_and_quarantines_reverse_tuple() {
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
        assert_eq!(table.get(second).unwrap().nat.translated.source_port, 40001);
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

    #[test]
    fn v1_unit_session_tcp_rst_and_closing_accelerate_expiry() {
        let mut table = table();
        let ingress = IoOwnerKey::new(10, 3);
        let now = Instant::now();
        let session_id = table
            .get_or_create_at(2, flow(10001), ingress, QuicFlowId(7), now)
            .unwrap();

        assert_eq!(
            table.get(session_id).unwrap().tcp_state,
            Some(TcpSessionState::Established)
        );

        // Forward FIN -> FinSeenForward (still idle timeout)
        table
            .touch_tcp(2, session_id, Some(0x01), false, now)
            .unwrap();
        assert_eq!(
            table.get(session_id).unwrap().tcp_state,
            Some(TcpSessionState::FinSeenForward)
        );
        assert_eq!(
            table.get(session_id).unwrap().expires_at,
            now + TCP_IDLE_TIMEOUT
        );

        // Reverse FIN -> Closing (5s timeout)
        table
            .touch_tcp(2, session_id, Some(0x01), true, now)
            .unwrap();
        assert_eq!(
            table.get(session_id).unwrap().tcp_state,
            Some(TcpSessionState::Closing)
        );
        assert_eq!(
            table.get(session_id).unwrap().expires_at,
            now + TCP_CLOSING_TIMEOUT
        );

        // RST -> Reset (2s timeout)
        let rst_now = now + Duration::from_secs(1);
        table
            .touch_tcp(2, session_id, Some(0x04), false, rst_now)
            .unwrap();
        assert_eq!(
            table.get(session_id).unwrap().tcp_state,
            Some(TcpSessionState::Reset)
        );
        assert_eq!(
            table.get(session_id).unwrap().expires_at,
            rst_now + TCP_RST_TIMEOUT
        );
    }
}
