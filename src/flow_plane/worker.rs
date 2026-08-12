use crate::flow_plane::{
    parse_flow_key, rewrite_packet, FlowKey, InterceptIoUpdate, IoOwnerKey, QuicFlowId, Session,
    SessionError, SessionId, SessionTable, TransportProtocol,
};
use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowMessage {
    InterceptIngress {
        io_owner: IoOwnerKey,
        packet: Bytes,
    },
    TunnelIngress {
        io_owner: IoOwnerKey,
        dcid: Bytes,
        remote: SocketAddr,
        local_ip: IpAddr,
        packet: Bytes,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IoTransmit {
    pub target: IoOwnerKey,
    pub packet: Bytes,
    pub outer: Option<OuterRoute>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterRoute {
    pub source_ip: Option<IpAddr>,
    pub source_port: u16,
    pub destination: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    Accepted,
    DroppedFull,
    DroppedDisconnected,
    InvalidWorker,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchStats {
    pub channel_full_drops: u64,
    pub channel_disconnected_drops: u64,
    pub invalid_worker_drops: u64,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FlowChannelError {
    #[error("flow worker count must be greater than zero")]
    ZeroWorkers,
    #[error("flow channel capacity must be greater than zero")]
    ZeroCapacity,
}

#[derive(Debug, Default)]
struct DispatchCounters {
    channel_full_drops: AtomicU64,
    channel_disconnected_drops: AtomicU64,
    invalid_worker_drops: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct FlowDispatcher {
    senders: Arc<[SyncSender<FlowMessage>]>,
    counters: Arc<DispatchCounters>,
}

impl FlowDispatcher {
    pub fn dispatch_to(&self, worker_id: usize, message: FlowMessage) -> DispatchOutcome {
        let Some(sender) = self.senders.get(worker_id) else {
            self.counters
                .invalid_worker_drops
                .fetch_add(1, Ordering::Relaxed);
            return DispatchOutcome::InvalidWorker;
        };
        match sender.try_send(message) {
            Ok(()) => DispatchOutcome::Accepted,
            Err(TrySendError::Full(_)) => {
                self.counters
                    .channel_full_drops
                    .fetch_add(1, Ordering::Relaxed);
                DispatchOutcome::DroppedFull
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters
                    .channel_disconnected_drops
                    .fetch_add(1, Ordering::Relaxed);
                DispatchOutcome::DroppedDisconnected
            }
        }
    }

    pub fn stats(&self) -> DispatchStats {
        DispatchStats {
            channel_full_drops: self.counters.channel_full_drops.load(Ordering::Relaxed),
            channel_disconnected_drops: self
                .counters
                .channel_disconnected_drops
                .load(Ordering::Relaxed),
            invalid_worker_drops: self.counters.invalid_worker_drops.load(Ordering::Relaxed),
        }
    }
}

pub fn bounded_flow_channels(
    worker_count: usize,
    capacity: usize,
) -> Result<(FlowDispatcher, Vec<Receiver<FlowMessage>>), FlowChannelError> {
    if worker_count == 0 {
        return Err(FlowChannelError::ZeroWorkers);
    }
    if capacity == 0 {
        return Err(FlowChannelError::ZeroCapacity);
    }
    let mut senders = Vec::with_capacity(worker_count);
    let mut receivers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        senders.push(sender);
        receivers.push(receiver);
    }
    Ok((
        FlowDispatcher {
            senders: senders.into(),
            counters: Arc::new(DispatchCounters::default()),
        },
        receivers,
    ))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlowWorkerStats {
    pub queue_mismatch_drops: u64,
    pub unknown_dcid_drops: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandledIntercept {
    pub session_id: SessionId,
    pub transmit: IoTransmit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandledReverse {
    pub session_id: SessionId,
    pub quic_flow_id: QuicFlowId,
    pub local_target: IoOwnerKey,
    pub packet: Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum FlowWorkerError {
    #[error(transparent)]
    Packet(#[from] crate::flow_plane::PacketError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

#[derive(Debug)]
pub struct FlowWorkerState {
    worker_id: usize,
    sessions: SessionTable,
    stats: FlowWorkerStats,
}

impl FlowWorkerState {
    pub fn new(
        worker_id: usize,
        snat_ip: IpAddr,
        ports: RangeInclusive<u16>,
    ) -> Result<Self, SessionError> {
        let (snat_ipv4, snat_ipv6) = match snat_ip {
            IpAddr::V4(address) => (Some(address), None),
            IpAddr::V6(address) => (None, Some(address)),
        };
        Self::new_dual(worker_id, snat_ipv4, snat_ipv6, ports)
    }

    pub fn new_dual(
        worker_id: usize,
        snat_ipv4: Option<Ipv4Addr>,
        snat_ipv6: Option<Ipv6Addr>,
        ports: RangeInclusive<u16>,
    ) -> Result<Self, SessionError> {
        Ok(Self {
            worker_id,
            sessions: SessionTable::new_dual(worker_id, snat_ipv4, snat_ipv6, ports)?,
            stats: FlowWorkerStats::default(),
        })
    }

    pub fn handle_intercept(
        &mut self,
        io_owner: IoOwnerKey,
        packet: Bytes,
        quic_flow_id: QuicFlowId,
        tunnel_target: IoOwnerKey,
    ) -> Result<HandledIntercept, FlowWorkerError> {
        let flow = parse_flow_key(&packet)?;
        let session_id =
            self.sessions
                .get_or_create(self.worker_id, flow, io_owner, quic_flow_id)?;
        let translated = self
            .sessions
            .get(session_id)
            .expect("newly created session exists")
            .nat
            .translated
            .clone();
        let mut packet = packet.to_vec();
        rewrite_packet(&mut packet, &translated)?;
        Ok(HandledIntercept {
            session_id,
            transmit: IoTransmit {
                target: tunnel_target,
                packet: Bytes::from(packet),
                outer: None,
            },
        })
    }

    pub fn handle_reverse(&self, packet: Bytes) -> Result<Option<HandledReverse>, FlowWorkerError> {
        let return_flow = parse_flow_key(&packet)?;
        let Some(session_id) = self.sessions.lookup_reverse(&return_flow) else {
            return Ok(None);
        };
        let session = self
            .sessions
            .get(session_id)
            .expect("reverse NAT index points to an existing session");
        let mut restored = packet.to_vec();
        let restored_flow = match session.original.protocol {
            TransportProtocol::Tcp | TransportProtocol::Udp => session.original.reverse(),
            TransportProtocol::Icmp | TransportProtocol::Icmpv6 => FlowKey {
                source: session.original.destination,
                destination: session.original.source,
                source_port: session.original.source_port,
                destination_port: return_flow.destination_port,
                protocol: session.original.protocol,
            },
        };
        rewrite_packet(&mut restored, &restored_flow)?;
        Ok(Some(HandledReverse {
            session_id,
            quic_flow_id: session.quic_flow_id,
            local_target: session.intercept_io,
            packet: Bytes::from(restored),
        }))
    }

    pub fn session(&self, session_id: SessionId) -> Option<&Session> {
        self.sessions.get(session_id)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter().map(|(_, session)| session)
    }

    pub fn remove_by_quic_flow(
        &mut self,
        quic_flow_id: QuicFlowId,
    ) -> Result<Vec<Session>, SessionError> {
        let sessions = self
            .sessions
            .iter()
            .filter(|(_, session)| session.quic_flow_id == quic_flow_id)
            .map(|(_, session)| session.clone())
            .collect::<Vec<_>>();
        self.sessions
            .remove_by_quic_flow(self.worker_id, quic_flow_id)?;
        Ok(sessions)
    }

    pub fn remove_session(&mut self, session_id: SessionId) -> Result<Session, SessionError> {
        self.sessions.remove(self.worker_id, session_id)
    }

    pub fn local_return_target(&self, session_id: SessionId) -> Option<IoOwnerKey> {
        self.sessions
            .get(session_id)
            .map(|session| session.intercept_io)
    }

    pub fn correct_server_return_io(
        &mut self,
        session_id: SessionId,
        observed: IoOwnerKey,
    ) -> bool {
        match self
            .sessions
            .correct_intercept_io(self.worker_id, session_id, observed)
        {
            Ok(InterceptIoUpdate::Unchanged | InterceptIoUpdate::Corrected) => true,
            Ok(InterceptIoUpdate::Mismatch) | Err(_) => {
                self.stats.queue_mismatch_drops += 1;
                false
            }
        }
    }

    pub fn lookup_reverse(&self, flow: &FlowKey) -> Option<SessionId> {
        self.sessions.lookup_reverse(flow)
    }

    pub const fn stats(&self) -> FlowWorkerStats {
        self.stats
    }
}
