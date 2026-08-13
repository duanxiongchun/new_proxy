use crate::flow_plane::{
    clamp_edns_udp_payload, classify_query, ip_packet_is_fragmented, parse_flow_key,
    response_matches_query, rewrite_packet, transaction_key, udp_payload, udp_payload_mut,
    DnsRoute, DnsTransactionKey, FlowKey, InterceptIoUpdate, IoOwnerKey, NatBinding, NatError,
    QuicFlow, QuicFlowId, Session, SessionError, SessionId, SessionTable, TransportProtocol,
    DNS_PAYLOAD_MAX,
};
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    pub dns_query_local: u64,
    pub dns_query_remote: u64,
    pub dns_response_local: u64,
    pub dns_response_remote: u64,
    pub dns_servfail: u64,
    pub dns_capacity_exhausted: u64,
    pub dns_nat_exhausted: u64,
    pub dns_malformed_local_fallback: u64,
    pub dns_spoofed_response_drop: u64,
    pub dns_late_response_drop: u64,
    pub dns_edns_clamped: u64,
    pub dns_timeout: u64,
    pub dns_transactions_active: u64,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsFlowConfig {
    pub listen: SocketAddr,
    pub local_resolver: SocketAddr,
    pub remote_resolver: SocketAddr,
    pub remote_domains: Vec<String>,
    pub transaction_capacity: usize,
    pub timeout: Duration,
    pub remote_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandledDnsQuery {
    Local {
        transmit: IoTransmit,
        binding: NatBinding,
        transaction_id: SessionId,
    },
    Remote {
        packet: Bytes,
        binding: NatBinding,
        transaction_id: SessionId,
    },
    Servfail(IoTransmit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandledDnsResponse {
    pub local_target: IoOwnerKey,
    pub packet: Bytes,
    pub binding: NatBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredDnsTransaction {
    pub transmit: IoTransmit,
    pub binding: NatBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnsFlowTransaction {
    token: SessionId,
    client: SocketAddr,
    dns_vip: SocketAddr,
    binding: crate::flow_plane::NatBinding,
    local_target: IoOwnerKey,
    remote: bool,
    created_at: Instant,
    original_packet: Bytes,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsFlowTransactionKey {
    io_owner: IoOwnerKey,
    dns: DnsTransactionKey,
}

const DNS_COMPLETED_REVERSE_CAPACITY: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DnsFlowError {
    #[error("packet is not a DNS VIP UDP query")]
    NotDnsQuery,
    #[error("DNS transaction capacity is exhausted")]
    CapacityExhausted,
}

#[derive(Debug, thiserror::Error)]
pub enum FlowWorkerError {
    #[error(transparent)]
    Packet(#[from] crate::flow_plane::PacketError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Dns(#[from] DnsFlowError),
    #[error("QUIC flow belongs to worker {expected}, not worker {actual}")]
    WrongQuicFlowOwner { expected: usize, actual: usize },
}

#[derive(Debug)]
pub struct FlowWorkerState {
    worker_id: usize,
    sessions: SessionTable,
    next_dns_token: u64,
    dns_by_key: HashMap<DnsFlowTransactionKey, DnsFlowTransaction>,
    dns_by_reverse: HashMap<FlowKey, DnsFlowTransactionKey>,
    dns_completed_reverse: HashMap<FlowKey, u64>,
    dns_completed_order: BTreeMap<u64, FlowKey>,
    next_dns_completed_sequence: u64,
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
            next_dns_token: 1,
            dns_by_key: HashMap::new(),
            dns_by_reverse: HashMap::new(),
            dns_completed_reverse: HashMap::new(),
            dns_completed_order: BTreeMap::new(),
            next_dns_completed_sequence: 1,
            stats: FlowWorkerStats::default(),
        })
    }

    pub fn handle_intercept(
        &mut self,
        io_owner: IoOwnerKey,
        packet: Bytes,
        quic_flow: &QuicFlow,
        tunnel_target: IoOwnerKey,
    ) -> Result<HandledIntercept, FlowWorkerError> {
        if quic_flow.flow_worker_id() != self.worker_id {
            return Err(FlowWorkerError::WrongQuicFlowOwner {
                expected: self.worker_id,
                actual: quic_flow.flow_worker_id(),
            });
        }
        let flow = parse_flow_key(&packet)?;
        let session_id =
            self.sessions
                .get_or_create(self.worker_id, flow, io_owner, quic_flow.id())?;
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

    pub fn handle_server_inner(
        &mut self,
        default_intercept: IoOwnerKey,
        packet: Bytes,
        quic_flow: &QuicFlow,
    ) -> Result<HandledIntercept, FlowWorkerError> {
        if quic_flow.flow_worker_id() != self.worker_id {
            return Err(FlowWorkerError::WrongQuicFlowOwner {
                expected: self.worker_id,
                actual: quic_flow.flow_worker_id(),
            });
        }
        let flow = parse_flow_key(&packet)?;
        let session_id =
            self.sessions
                .get_or_create(self.worker_id, flow, default_intercept, quic_flow.id())?;
        let session = self
            .sessions
            .get(session_id)
            .expect("newly created session exists");
        let mut packet = packet.to_vec();
        rewrite_packet(&mut packet, &session.nat.translated)?;
        Ok(HandledIntercept {
            session_id,
            transmit: IoTransmit {
                target: session.intercept_io,
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

    pub fn handle_dns_query(
        &mut self,
        io_owner: IoOwnerKey,
        packet: Bytes,
        config: &DnsFlowConfig,
    ) -> Result<HandledDnsQuery, FlowWorkerError> {
        self.handle_dns_query_at(io_owner, packet, config, Instant::now())
    }

    pub fn handle_dns_query_at(
        &mut self,
        io_owner: IoOwnerKey,
        packet: Bytes,
        config: &DnsFlowConfig,
        now: Instant,
    ) -> Result<HandledDnsQuery, FlowWorkerError> {
        let flow = parse_flow_key(&packet)?;
        if flow.protocol != TransportProtocol::Udp
            || flow.destination != config.listen.ip()
            || flow.destination_port != config.listen.port()
        {
            return Err(DnsFlowError::NotDnsQuery.into());
        }
        let mut packet = packet;
        if ip_packet_is_fragmented(&packet)? {
            self.stats.dns_servfail += 1;
            return Ok(HandledDnsQuery::Servfail(dns_servfail_transmit(
                io_owner, packet, &flow, config,
            )?));
        }
        let payload = udp_payload(&packet)?;
        if payload.len() > DNS_PAYLOAD_MAX {
            self.stats.dns_servfail += 1;
            return Ok(HandledDnsQuery::Servfail(dns_servfail_transmit(
                io_owner, packet, &flow, config,
            )?));
        }
        if edns_clamp_packet(&mut packet)? {
            self.stats.dns_edns_clamped += 1;
        }
        let payload = udp_payload(&packet)?;
        let client = SocketAddr::new(flow.source, flow.source_port);
        let key = DnsFlowTransactionKey {
            io_owner,
            dns: transaction_key(client, payload),
        };
        if let Some(transaction) = self.dns_by_key.get(&key).cloned() {
            return self.rewrite_dns_query(packet, &transaction);
        }

        let route = classify_query(payload, &config.remote_domains);
        let (resolver, remote) = match route {
            DnsRoute::Remote(_) => (config.remote_resolver, true),
            DnsRoute::Local(_) => (config.local_resolver, false),
            DnsRoute::LocalFallback => {
                self.stats.dns_malformed_local_fallback += 1;
                (config.local_resolver, false)
            }
        };
        if remote && !config.remote_available {
            self.stats.dns_servfail += 1;
            return Ok(HandledDnsQuery::Servfail(dns_servfail_transmit(
                io_owner, packet, &flow, config,
            )?));
        }
        if self.dns_by_key.len() >= config.transaction_capacity {
            self.stats.dns_capacity_exhausted += 1;
            self.stats.dns_servfail += 1;
            return Ok(HandledDnsQuery::Servfail(dns_servfail_transmit(
                io_owner, packet, &flow, config,
            )?));
        }
        let token = self.next_dns_session_token();
        let selected_flow = FlowKey {
            source: flow.source,
            destination: resolver.ip(),
            source_port: flow.source_port,
            destination_port: resolver.port(),
            protocol: TransportProtocol::Udp,
        };
        let binding =
            match self
                .sessions
                .allocate_ephemeral_nat(self.worker_id, token, selected_flow)
            {
                Ok(binding) => binding,
                Err(SessionError::Nat(NatError::PortRangeExhausted)) => {
                    self.stats.dns_nat_exhausted += 1;
                    self.stats.dns_servfail += 1;
                    return Ok(HandledDnsQuery::Servfail(dns_servfail_transmit(
                        io_owner, packet, &flow, config,
                    )?));
                }
                Err(error) => return Err(error.into()),
            };
        let reverse_key = binding.translated.reverse();
        let transaction = DnsFlowTransaction {
            token,
            client,
            dns_vip: config.listen,
            binding,
            local_target: io_owner,
            remote,
            created_at: now,
            original_packet: packet.clone(),
        };
        self.forget_completed_dns_reverse(&reverse_key);
        self.dns_by_reverse.insert(reverse_key, key.clone());
        self.dns_by_key.insert(key, transaction.clone());
        self.stats.dns_transactions_active = self.dns_by_key.len() as u64;
        if remote {
            self.stats.dns_query_remote += 1;
        } else {
            self.stats.dns_query_local += 1;
        }
        self.rewrite_dns_query(packet, &transaction)
    }

    pub fn handle_dns_response(
        &mut self,
        packet: Bytes,
    ) -> Result<Option<HandledDnsResponse>, FlowWorkerError> {
        let flow = parse_flow_key(&packet)?;
        let Some(key) = self.dns_by_reverse.get(&flow).cloned() else {
            if self.dns_completed_reverse.contains_key(&flow) {
                self.stats.dns_late_response_drop += 1;
            } else {
                self.stats.dns_spoofed_response_drop += 1;
            }
            return Ok(None);
        };
        let Some(transaction) = self.dns_by_key.get(&key).cloned() else {
            self.stats.dns_spoofed_response_drop += 1;
            return Ok(None);
        };
        if ip_packet_is_fragmented(&packet)? {
            self.stats.dns_spoofed_response_drop += 1;
            return Ok(None);
        }
        let payload = udp_payload(&packet)?;
        if response_matches_query(udp_payload(&transaction.original_packet)?, payload).is_err() {
            self.stats.dns_spoofed_response_drop += 1;
            return Ok(None);
        }
        let transaction = self
            .remove_dns_transaction(&key)?
            .expect("transaction exists after validation");
        self.remember_completed_dns_reverse(flow);
        self.stats.dns_transactions_active = self.dns_by_key.len() as u64;
        if payload.len() > DNS_PAYLOAD_MAX {
            let original_flow = parse_flow_key(&transaction.original_packet)?;
            self.stats.dns_servfail += 1;
            return Ok(Some(HandledDnsResponse {
                local_target: transaction.local_target,
                packet: dns_servfail_transmit_to_listen(
                    transaction.local_target,
                    transaction.original_packet,
                    &original_flow,
                    transaction.dns_vip,
                )?
                .packet,
                binding: transaction.binding,
            }));
        }
        if transaction.remote {
            self.stats.dns_response_remote += 1;
        } else {
            self.stats.dns_response_local += 1;
        }
        let mut packet = packet.to_vec();
        rewrite_packet(
            &mut packet,
            &FlowKey {
                source: transaction.dns_vip.ip(),
                destination: transaction.client.ip(),
                source_port: transaction.dns_vip.port(),
                destination_port: transaction.client.port(),
                protocol: TransportProtocol::Udp,
            },
        )?;
        Ok(Some(HandledDnsResponse {
            local_target: transaction.local_target,
            packet: Bytes::from(packet),
            binding: transaction.binding,
        }))
    }

    pub fn expire_dns_transactions(
        &mut self,
        now: Instant,
        config: &DnsFlowConfig,
    ) -> Result<Vec<ExpiredDnsTransaction>, FlowWorkerError> {
        let expired = self
            .dns_by_key
            .iter()
            .filter(|(_, transaction)| now.duration_since(transaction.created_at) >= config.timeout)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut transmits = Vec::with_capacity(expired.len());
        for key in expired {
            let Some(transaction) = self.dns_by_key.remove(&key) else {
                continue;
            };
            self.dns_by_reverse
                .remove(&transaction.binding.translated.reverse());
            self.sessions
                .release_ephemeral_nat(self.worker_id, transaction.token)?;
            let flow = parse_flow_key(&transaction.original_packet)?;
            let transmit = dns_servfail_transmit(
                transaction.local_target,
                transaction.original_packet,
                &flow,
                config,
            )?;
            transmits.push(ExpiredDnsTransaction {
                transmit,
                binding: transaction.binding,
            });
            self.stats.dns_timeout += 1;
            self.stats.dns_servfail += 1;
        }
        self.stats.dns_transactions_active = self.dns_by_key.len() as u64;
        Ok(transmits)
    }

    pub fn abort_dns_transaction(
        &mut self,
        binding: &NatBinding,
        config: &DnsFlowConfig,
    ) -> Result<Option<ExpiredDnsTransaction>, FlowWorkerError> {
        let reverse = binding.translated.reverse();
        let Some(key) = self.dns_by_reverse.get(&reverse).cloned() else {
            return Ok(None);
        };
        let transaction = self
            .remove_dns_transaction(&key)?
            .expect("reverse DNS index points to an existing transaction");
        self.stats.dns_servfail += 1;
        Ok(Some(self.servfail_for_transaction(transaction, config)?))
    }

    pub fn abort_remote_dns_transactions(
        &mut self,
        config: &DnsFlowConfig,
    ) -> Result<Vec<ExpiredDnsTransaction>, FlowWorkerError> {
        let keys = self
            .dns_by_key
            .iter()
            .filter(|(_, transaction)| transaction.remote)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut aborted = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(transaction) = self.remove_dns_transaction(&key)? else {
                continue;
            };
            aborted.push(self.servfail_for_transaction(transaction, config)?);
            self.stats.dns_servfail += 1;
        }
        Ok(aborted)
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

    pub fn remove_dns_transactions(&mut self) -> Result<Vec<NatBinding>, SessionError> {
        let transactions = self
            .dns_by_key
            .drain()
            .map(|(_, transaction)| transaction)
            .collect::<Vec<_>>();
        self.dns_by_reverse.clear();
        self.dns_completed_reverse.clear();
        self.dns_completed_order.clear();
        let mut bindings = Vec::with_capacity(transactions.len());
        for transaction in transactions {
            self.sessions
                .release_ephemeral_nat(self.worker_id, transaction.token)?;
            bindings.push(transaction.binding);
        }
        self.stats.dns_transactions_active = 0;
        Ok(bindings)
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

    pub fn has_dns_reverse(&self, flow: &FlowKey) -> bool {
        self.dns_by_reverse.contains_key(flow)
    }

    pub const fn stats(&self) -> FlowWorkerStats {
        self.stats
    }

    fn rewrite_dns_query(
        &self,
        packet: Bytes,
        transaction: &DnsFlowTransaction,
    ) -> Result<HandledDnsQuery, FlowWorkerError> {
        let mut packet = packet.to_vec();
        rewrite_packet(&mut packet, &transaction.binding.translated)?;
        let packet = Bytes::from(packet);
        if transaction.remote {
            Ok(HandledDnsQuery::Remote {
                packet,
                binding: transaction.binding.clone(),
                transaction_id: transaction.token,
            })
        } else {
            Ok(HandledDnsQuery::Local {
                transmit: IoTransmit {
                    target: transaction.local_target,
                    packet,
                    outer: None,
                },
                binding: transaction.binding.clone(),
                transaction_id: transaction.token,
            })
        }
    }

    fn next_dns_session_token(&mut self) -> SessionId {
        let token = SessionId((1u64 << 63) | self.next_dns_token);
        self.next_dns_token = self.next_dns_token.wrapping_add(1).max(1);
        token
    }

    fn remove_dns_transaction(
        &mut self,
        key: &DnsFlowTransactionKey,
    ) -> Result<Option<DnsFlowTransaction>, SessionError> {
        let Some(transaction) = self.dns_by_key.remove(key) else {
            return Ok(None);
        };
        self.dns_by_reverse
            .remove(&transaction.binding.translated.reverse());
        self.sessions
            .release_ephemeral_nat(self.worker_id, transaction.token)?;
        self.stats.dns_transactions_active = self.dns_by_key.len() as u64;
        Ok(Some(transaction))
    }

    fn servfail_for_transaction(
        &self,
        transaction: DnsFlowTransaction,
        config: &DnsFlowConfig,
    ) -> Result<ExpiredDnsTransaction, FlowWorkerError> {
        let flow = parse_flow_key(&transaction.original_packet)?;
        Ok(ExpiredDnsTransaction {
            transmit: dns_servfail_transmit(
                transaction.local_target,
                transaction.original_packet,
                &flow,
                config,
            )?,
            binding: transaction.binding,
        })
    }

    fn remember_completed_dns_reverse(&mut self, flow: FlowKey) {
        let sequence = self.next_dns_completed_sequence;
        self.next_dns_completed_sequence = self.next_dns_completed_sequence.wrapping_add(1).max(1);
        if let Some(previous) = self.dns_completed_reverse.insert(flow.clone(), sequence) {
            self.dns_completed_order.remove(&previous);
        }
        self.dns_completed_order.insert(sequence, flow);
        while self.dns_completed_reverse.len() > DNS_COMPLETED_REVERSE_CAPACITY {
            if let Some((sequence, expired)) = self.dns_completed_order.pop_first() {
                if self.dns_completed_reverse.get(&expired) == Some(&sequence) {
                    self.dns_completed_reverse.remove(&expired);
                }
            }
        }
    }

    fn forget_completed_dns_reverse(&mut self, flow: &FlowKey) {
        if let Some(sequence) = self.dns_completed_reverse.remove(flow) {
            self.dns_completed_order.remove(&sequence);
        }
    }
}

fn edns_clamp_packet(packet: &mut Bytes) -> Result<bool, crate::flow_plane::PacketError> {
    let flow = parse_flow_key(packet)?;
    let mut buffer = packet.to_vec();
    let clamped = {
        let payload = udp_payload_mut(&mut buffer)?;
        clamp_edns_udp_payload(payload).unwrap_or(false)
    };
    if clamped {
        rewrite_packet(&mut buffer, &flow)?;
        *packet = Bytes::from(buffer);
    }
    Ok(clamped)
}

fn dns_servfail_transmit(
    target: IoOwnerKey,
    packet: Bytes,
    flow: &FlowKey,
    config: &DnsFlowConfig,
) -> Result<IoTransmit, crate::flow_plane::PacketError> {
    dns_servfail_transmit_to_listen(target, packet, flow, config.listen)
}

fn dns_servfail_transmit_to_listen(
    target: IoOwnerKey,
    packet: Bytes,
    flow: &FlowKey,
    listen: SocketAddr,
) -> Result<IoTransmit, crate::flow_plane::PacketError> {
    let mut packet = packet.to_vec();
    {
        let payload = udp_payload_mut(&mut packet)?;
        if payload.len() >= 12 {
            let mut flags = u16::from_be_bytes([payload[2], payload[3]]);
            flags |= 0x8000;
            flags = (flags & !0x000f) | 0x0002;
            payload[2..4].copy_from_slice(&flags.to_be_bytes());
            payload[6..12].fill(0);
        }
    }
    rewrite_packet(
        &mut packet,
        &FlowKey {
            source: listen.ip(),
            destination: flow.source,
            source_port: listen.port(),
            destination_port: flow.source_port,
            protocol: TransportProtocol::Udp,
        },
    )?;
    Ok(IoTransmit {
        target,
        packet: Bytes::from(packet),
        outer: None,
    })
}
