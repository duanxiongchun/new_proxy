use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, ConnectionId, ConnectionIdGenerator, DatagramEvent,
    Dir, Endpoint, EndpointConfig, Event, ReadError, ServerConfig, StreamEvent, StreamId, Transmit,
    TransportConfig, VarInt, WriteError,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

const AUTH_REQUEST: u8 = 1;
const AUTH_RESPONSE: u8 = 2;
const AUTH_CONFIRM: u8 = 3;
const AUTH_COMPLETE: u8 = 4;
const AUTH_FRAME_LEN: usize = 65;
const AUTH_PROTOCOL: &[u8] = b"new-proxy-auth-v2";
const AUTH_EXPORTER_LABEL: &[u8] = b"EXPORTER-new-proxy-v1-auth";
const EMPTY_NONCE: [u8; 16] = [0; 16];
const INNER_PACKET: u8 = 16;
const INNER_FRAGMENT: u8 = 17;
const ALPN: &[u8] = b"new-proxy-v1";
const INNER_FRAGMENT_HEADER_LEN: usize = 13;
const MAX_INNER_PACKET_LEN: usize = u16::MAX as usize;
const MAX_REASSEMBLY_BYTES: usize = 1024 * 1024;
const MAX_REASSEMBLY_ENTRIES: usize = 4096;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
const AUTH_STREAM_WINDOW: u32 = 4096;
const MAX_TRACKED_DCIDS: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicRole {
    Client,
    Server,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicEngineEvent {
    Transmit(OuterTransmit),
    Authenticated,
    InnerPacket(Bytes),
    DcidStaged(Bytes),
    DcidPublished(Bytes),
    DcidRetired(Bytes),
    Replaced(Vec<Bytes>),
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OuterTransmit {
    pub destination: SocketAddr,
    pub source_ip: Option<IpAddr>,
    pub contents: Bytes,
    pub segment_size: Option<usize>,
}

impl From<Transmit> for OuterTransmit {
    fn from(transmit: Transmit) -> Self {
        Self {
            destination: transmit.destination,
            source_ip: transmit.src_ip,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuicEngineError {
    #[error("DCID length must be in 1..=20")]
    InvalidDcidLength,
    #[error("client endpoint is missing a remote address")]
    MissingRemote,
    #[error("client endpoint is missing a TLS configuration")]
    MissingClientConfig,
    #[error("failed to start QUIC connection: {0}")]
    Connect(String),
    #[error("QUIC connection is not established")]
    NotConnected,
    #[error("QUIC connection is not authenticated")]
    NotAuthenticated,
    #[error("inner packet is empty")]
    EmptyInnerPacket,
    #[error("inner packet exceeds the current QUIC datagram limit")]
    DatagramTooLarge,
}

pub struct QuicEngine {
    role: QuicRole,
    endpoint: Endpoint,
    connection: Option<ManagedConnection>,
    candidate: Option<ManagedConnection>,
    client_reconnect: Option<ClientReconnect>,
    shared_key: [u8; 32],
    dcid_len: usize,
    generated_dcids: Arc<Mutex<VecDeque<Bytes>>>,
    published_dcids: HashSet<Bytes>,
    candidate_promotion_pending: bool,
    next_inner_packet_id: u64,
    reassembly: HashMap<u64, InnerReassembly>,
    reassembly_bytes: usize,
    events: VecDeque<QuicEngineEvent>,
}

struct ManagedConnection {
    handle: ConnectionHandle,
    connection: Connection,
    auth: AuthState,
    dcids: HashSet<Bytes>,
    auth_deadline: Instant,
    endpoint_registered: bool,
    dcid_limit_exceeded: bool,
    retired_dcid_frames: u64,
}

#[derive(Default)]
struct AuthState {
    client_nonce: Option<[u8; 16]>,
    server_nonce: Option<[u8; 16]>,
    stream: Option<StreamId>,
    receive: BytesMut,
    transmit: VecDeque<Bytes>,
    transmit_offset: usize,
    authenticate_after_flush: bool,
    authenticated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthFlushOutcome {
    Complete,
    Blocked,
    Failed,
}

#[derive(Default)]
struct ConnectionDrive {
    endpoint_events: Vec<(ConnectionHandle, quinn_proto::EndpointEvent)>,
    transmits: Vec<Transmit>,
    datagrams: Vec<Bytes>,
    authenticated_now: bool,
    lost: bool,
}

impl ManagedConnection {
    fn new(handle: ConnectionHandle, connection: Connection, now: Instant) -> Self {
        Self {
            handle,
            connection,
            auth: AuthState::default(),
            dcids: HashSet::new(),
            auth_deadline: now + AUTH_TIMEOUT,
            endpoint_registered: true,
            dcid_limit_exceeded: false,
            retired_dcid_frames: 0,
        }
    }

    fn track_dcid(&mut self, dcid: Bytes) {
        if self.dcids.contains(&dcid) {
            return;
        }
        if self.dcids.len() >= MAX_TRACKED_DCIDS {
            self.dcid_limit_exceeded = true;
            return;
        }
        self.dcids.insert(dcid);
    }
}

struct InnerReassembly {
    created_at: Instant,
    packet: Vec<u8>,
    received: Vec<bool>,
    received_count: usize,
}

#[derive(Clone)]
struct ClientReconnect {
    client_config: ClientConfig,
    remote: SocketAddr,
    server_name: String,
    worker_id: usize,
    worker_count: usize,
}

impl QuicEngine {
    pub fn client(
        client_config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
        shared_key: [u8; 32],
        dcid_len: usize,
    ) -> Result<Self, QuicEngineError> {
        Self::client_for_worker(
            client_config,
            remote,
            server_name,
            shared_key,
            dcid_len,
            0,
            1,
        )
    }

    pub fn client_for_worker(
        client_config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
        shared_key: [u8; 32],
        dcid_len: usize,
        worker_id: usize,
        worker_count: usize,
    ) -> Result<Self, QuicEngineError> {
        validate_dcid_len(dcid_len)?;
        if worker_count == 0 || worker_id >= worker_count {
            return Err(QuicEngineError::Connect(
                "invalid Flow worker ownership".to_string(),
            ));
        }
        for _ in 0..1024 {
            let generated_dcids = Arc::new(Mutex::new(VecDeque::new()));
            let mut endpoint = Endpoint::new(
                endpoint_config(dcid_len, worker_id, worker_count, generated_dcids.clone()),
                None,
                false,
            );
            let connection = endpoint
                .connect(client_config.clone(), remote, server_name)
                .map_err(|error| QuicEngineError::Connect(error.to_string()))?;
            let (handle, connection) = connection;
            let now = Instant::now();
            let mut engine = Self {
                role: QuicRole::Client,
                endpoint,
                connection: Some(ManagedConnection::new(handle, connection, now)),
                candidate: None,
                client_reconnect: Some(ClientReconnect {
                    client_config: client_config.clone(),
                    remote,
                    server_name: server_name.to_string(),
                    worker_id,
                    worker_count,
                }),
                shared_key,
                dcid_len,
                generated_dcids,
                published_dcids: HashSet::new(),
                candidate_promotion_pending: false,
                next_inner_packet_id: 0,
                reassembly: HashMap::new(),
                reassembly_bytes: 0,
                events: VecDeque::new(),
            };
            engine.stage_generated_dcids(handle);
            engine.drive(now);
            let owner_matches = engine.events.iter().find_map(|event| {
                let QuicEngineEvent::Transmit(transmit) = event else {
                    return None;
                };
                let dcid = extract_dcid(&transmit.contents, dcid_len)?;
                crate::flow_plane::bootstrap_owner(&dcid, worker_count).ok()
            }) == Some(worker_id);
            if owner_matches {
                return Ok(engine);
            }
        }
        Err(QuicEngineError::Connect(
            "failed to generate an Initial DCID for the requested Flow worker".to_string(),
        ))
    }

    pub fn server(
        server_config: ServerConfig,
        shared_key: [u8; 32],
        dcid_len: usize,
    ) -> Result<Self, QuicEngineError> {
        Self::server_for_worker(server_config, shared_key, dcid_len, 0, 1)
    }

    pub fn server_for_worker(
        server_config: ServerConfig,
        shared_key: [u8; 32],
        dcid_len: usize,
        worker_id: usize,
        worker_count: usize,
    ) -> Result<Self, QuicEngineError> {
        validate_dcid_len(dcid_len)?;
        let generated_dcids = Arc::new(Mutex::new(VecDeque::new()));
        Ok(Self {
            role: QuicRole::Server,
            endpoint: Endpoint::new(
                endpoint_config(dcid_len, worker_id, worker_count, generated_dcids.clone()),
                Some(Arc::new(server_config)),
                false,
            ),
            connection: None,
            candidate: None,
            client_reconnect: None,
            shared_key,
            dcid_len,
            generated_dcids,
            published_dcids: HashSet::new(),
            candidate_promotion_pending: false,
            next_inner_packet_id: 0,
            reassembly: HashMap::new(),
            reassembly_bytes: 0,
            events: VecDeque::new(),
        })
    }

    pub fn handle_outer(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        local_ip: Option<IpAddr>,
        packet: Bytes,
    ) {
        let accepted_dcid = extract_dcid(&packet, self.dcid_len);
        self.discard_generated_dcids();
        let handled = self
            .endpoint
            .handle(now, remote, local_ip, None, BytesMut::from(packet));
        let generated_dcids = self.take_generated_dcids();
        let Some((handle, event)) = handled else {
            self.drive(now);
            return;
        };
        match event {
            DatagramEvent::NewConnection(connection) => {
                let incoming = ManagedConnection::new(handle, connection, now);
                if self.candidate.is_some() {
                    self.dispose_managed_connection(incoming, now, Some(b"candidate busy"));
                } else {
                    self.candidate = Some(incoming);
                }
            }
            DatagramEvent::ConnectionEvent(event) => {
                if let Some(connection) = self.connection_for_handle_mut(handle) {
                    connection.connection.handle_event(event);
                }
            }
        }
        if let Some(dcid) = accepted_dcid {
            if let Some(connection) = self.connection_for_handle_mut(handle) {
                connection.track_dcid(dcid);
            }
        }
        self.stage_dcids_for_handle(handle, generated_dcids);
        self.drive(now);
    }

    pub fn send_inner(&mut self, now: Instant, packet: Bytes) -> Result<(), QuicEngineError> {
        if packet.is_empty() {
            return Err(QuicEngineError::EmptyInnerPacket);
        }
        if !self.is_authenticated() {
            return Err(QuicEngineError::NotAuthenticated);
        }
        let max_datagram_size = self
            .connection
            .as_mut()
            .and_then(|connection| connection.connection.datagrams().max_size())
            .ok_or(QuicEngineError::NotConnected)?;
        if packet.len() < max_datagram_size {
            let mut wire = Vec::with_capacity(1 + packet.len());
            wire.push(INNER_PACKET);
            wire.extend_from_slice(&packet);
            self.send_datagram(Bytes::from(wire))
                .map_err(|_| QuicEngineError::DatagramTooLarge)?;
        } else {
            self.send_fragmented_inner(packet, max_datagram_size)?;
        }
        self.drive(now);
        Ok(())
    }

    pub fn close(&mut self, now: Instant) {
        if let Some(connection) = self.connection.take() {
            self.dispose_managed_connection(connection, now, Some(b"closed"));
        }
        if let Some(candidate) = self.candidate.take() {
            self.dispose_managed_connection(candidate, now, Some(b"closed"));
        }
        self.clear_reassembly();
        self.retire_all_dcids();
        self.events.push_back(QuicEngineEvent::Closed);
    }

    pub fn poll(&mut self, now: Instant) -> Option<QuicEngineEvent> {
        self.drive(now);
        self.events.pop_front()
    }

    pub fn is_authenticated(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.auth.authenticated)
    }

    pub fn reconnect_client(&mut self) -> Result<(), QuicEngineError> {
        let reconnect = self
            .client_reconnect
            .clone()
            .ok_or(QuicEngineError::MissingClientConfig)?;
        *self = Self::client_for_worker(
            reconnect.client_config,
            reconnect.remote,
            &reconnect.server_name,
            self.shared_key,
            self.dcid_len,
            reconnect.worker_id,
            reconnect.worker_count,
        )?;
        Ok(())
    }

    pub fn resolve_candidate_replacement(&mut self, now: Instant, publish_succeeded: bool) {
        if !self.candidate_promotion_pending {
            return;
        }
        self.candidate_promotion_pending = false;
        if publish_succeeded {
            self.commit_candidate_replacement(now);
        } else if let Some(candidate) = self.candidate.take() {
            self.retire_staged_dcids(&candidate.dcids);
            self.dispose_managed_connection(candidate, now, Some(b"DCID publication rejected"));
        }
    }

    fn drive(&mut self, now: Instant) {
        let mut transmits = Vec::new();
        let mut endpoint_events = Vec::new();
        let mut active_drive = self
            .connection
            .as_mut()
            .map(|connection| drive_connection(self.role, &self.shared_key, now, connection));
        let mut candidate_drive = self
            .candidate
            .as_mut()
            .map(|connection| drive_connection(self.role, &self.shared_key, now, connection));
        if let Some(drive) = active_drive.as_mut() {
            transmits.append(&mut drive.transmits);
            endpoint_events.append(&mut drive.endpoint_events);
        }
        if let Some(drive) = candidate_drive.as_mut() {
            transmits.append(&mut drive.transmits);
            endpoint_events.append(&mut drive.endpoint_events);
        }

        for (handle, event) in endpoint_events {
            if event.is_drained() {
                if let Some(connection) = self.connection_for_handle_mut(handle) {
                    connection.endpoint_registered = false;
                }
            }
            self.discard_generated_dcids();
            let connection_event = self.endpoint.handle_event(handle, event);
            let generated_dcids = self.take_generated_dcids();
            if let Some(connection_event) = connection_event {
                if let Some(connection) = self.connection_for_handle_mut(handle) {
                    connection.connection.handle_event(connection_event);
                }
            }
            self.stage_dcids_for_handle(handle, generated_dcids);
        }
        while let Some(transmit) = self.endpoint.poll_transmit() {
            transmits.push(transmit);
        }

        let active_authenticated_now = active_drive
            .as_ref()
            .is_some_and(|drive| drive.authenticated_now);
        let active_lost = active_drive.as_ref().is_some_and(|drive| drive.lost);
        let candidate_authenticated_now = candidate_drive
            .as_ref()
            .is_some_and(|drive| drive.authenticated_now);
        let candidate_lost = candidate_drive.as_ref().is_some_and(|drive| drive.lost);

        if active_authenticated_now {
            self.publish_active_dcids();
            self.events.push_back(QuicEngineEvent::Authenticated);
        }
        if candidate_authenticated_now {
            self.promote_candidate();
        } else if candidate_lost {
            if let Some(candidate) = self.candidate.take() {
                self.retire_staged_dcids(&candidate.dcids);
                self.dispose_managed_connection(candidate, now, None);
            }
        }
        if active_lost && !candidate_authenticated_now {
            if let Some(candidate) = self.candidate.take() {
                self.retire_staged_dcids(&candidate.dcids);
                self.dispose_managed_connection(candidate, now, Some(b"active connection lost"));
            }
            if let Some(active) = self.connection.take() {
                self.dispose_managed_connection(active, now, None);
            }
            self.clear_reassembly();
            self.retire_all_dcids();
            self.events.push_back(QuicEngineEvent::Closed);
        }

        self.prune_reassembly(now);
        let application_datagrams = if candidate_authenticated_now {
            candidate_drive
                .into_iter()
                .flat_map(|drive| drive.datagrams)
                .collect::<Vec<_>>()
        } else if !active_lost {
            active_drive
                .into_iter()
                .flat_map(|drive| drive.datagrams)
                .collect()
        } else {
            Vec::new()
        };
        for datagram in application_datagrams {
            self.handle_application_datagram(now, datagram);
        }
        for transmit in &transmits {
            log::trace!(
                "QUIC outer transmit role={:?} bytes={} segment_size={:?} prefix={:02x?}",
                self.role,
                transmit.contents.len(),
                transmit.segment_size,
                &transmit.contents[..transmit.contents.len().min(16)]
            );
        }
        self.events.extend(
            transmits
                .into_iter()
                .map(OuterTransmit::from)
                .map(QuicEngineEvent::Transmit),
        );
    }

    fn handle_application_datagram(&mut self, now: Instant, datagram: Bytes) {
        let Some((&kind, payload)) = datagram.split_first() else {
            return;
        };
        log::debug!(
            "received QUIC application datagram role={:?} kind={} payload_len={}",
            self.role,
            kind,
            payload.len()
        );
        match (self.role, kind) {
            (_, INNER_PACKET) if self.is_authenticated() && !payload.is_empty() => {
                self.events
                    .push_back(QuicEngineEvent::InnerPacket(Bytes::copy_from_slice(
                        payload,
                    )));
            }
            (_, INNER_FRAGMENT) if self.is_authenticated() => {
                self.handle_inner_fragment(now, payload);
            }
            _ => {}
        }
    }

    fn send_fragmented_inner(
        &mut self,
        packet: Bytes,
        max_datagram_size: usize,
    ) -> Result<(), QuicEngineError> {
        if packet.len() > MAX_INNER_PACKET_LEN || max_datagram_size <= INNER_FRAGMENT_HEADER_LEN {
            return Err(QuicEngineError::DatagramTooLarge);
        }
        let packet_id = self.next_inner_packet_id;
        self.next_inner_packet_id = self.next_inner_packet_id.wrapping_add(1);
        let fragment_payload_len = max_datagram_size - INNER_FRAGMENT_HEADER_LEN;
        let total_len =
            u16::try_from(packet.len()).map_err(|_| QuicEngineError::DatagramTooLarge)?;
        for offset in (0..packet.len()).step_by(fragment_payload_len) {
            let end = packet.len().min(offset + fragment_payload_len);
            let mut wire =
                Vec::with_capacity(INNER_FRAGMENT_HEADER_LEN + end.saturating_sub(offset));
            wire.push(INNER_FRAGMENT);
            wire.extend_from_slice(&packet_id.to_be_bytes());
            wire.extend_from_slice(&total_len.to_be_bytes());
            wire.extend_from_slice(&(offset as u16).to_be_bytes());
            wire.extend_from_slice(&packet[offset..end]);
            self.send_datagram(Bytes::from(wire))
                .map_err(|_| QuicEngineError::DatagramTooLarge)?;
        }
        Ok(())
    }

    fn handle_inner_fragment(&mut self, now: Instant, payload: &[u8]) {
        if payload.len() < INNER_FRAGMENT_HEADER_LEN {
            return;
        }
        let packet_id = u64::from_be_bytes(payload[..8].try_into().expect("checked packet id"));
        let total_len = usize::from(u16::from_be_bytes(
            payload[8..10].try_into().expect("checked total length"),
        ));
        let offset = usize::from(u16::from_be_bytes(
            payload[10..12].try_into().expect("checked fragment offset"),
        ));
        let fragment = &payload[12..];
        let Some(end) = offset.checked_add(fragment.len()) else {
            return;
        };
        if total_len == 0
            || total_len > MAX_INNER_PACKET_LEN
            || offset >= total_len
            || end > total_len
        {
            return;
        }

        if !self.reassembly.contains_key(&packet_id) {
            if self.reassembly.len() >= MAX_REASSEMBLY_ENTRIES
                || self.reassembly_bytes.saturating_add(total_len) > MAX_REASSEMBLY_BYTES
            {
                return;
            }
            self.reassembly.insert(
                packet_id,
                InnerReassembly {
                    created_at: now,
                    packet: vec![0; total_len],
                    received: vec![false; total_len],
                    received_count: 0,
                },
            );
            self.reassembly_bytes += total_len;
        }
        let Some(reassembly) = self.reassembly.get_mut(&packet_id) else {
            return;
        };
        if reassembly.packet.len() != total_len {
            return;
        }
        for (index, byte) in fragment.iter().copied().enumerate() {
            let position = offset + index;
            if !reassembly.received[position] {
                reassembly.received[position] = true;
                reassembly.received_count += 1;
            }
            reassembly.packet[position] = byte;
        }
        if reassembly.received_count == total_len {
            let completed = self
                .reassembly
                .remove(&packet_id)
                .expect("completed reassembly exists");
            self.reassembly_bytes -= completed.packet.len();
            self.events
                .push_back(QuicEngineEvent::InnerPacket(Bytes::from(completed.packet)));
        }
    }

    fn prune_reassembly(&mut self, now: Instant) {
        self.reassembly.retain(|_, entry| {
            now.saturating_duration_since(entry.created_at) < REASSEMBLY_TIMEOUT
        });
        self.reassembly_bytes = self
            .reassembly
            .values()
            .map(|entry| entry.packet.len())
            .sum();
    }

    fn clear_reassembly(&mut self) {
        self.reassembly.clear();
        self.reassembly_bytes = 0;
    }

    fn connection_for_handle_mut(
        &mut self,
        handle: ConnectionHandle,
    ) -> Option<&mut ManagedConnection> {
        if self
            .connection
            .as_ref()
            .is_some_and(|connection| connection.handle == handle)
        {
            return self.connection.as_mut();
        }
        self.candidate
            .as_mut()
            .filter(|connection| connection.handle == handle)
    }

    fn stage_generated_dcids(&mut self, handle: ConnectionHandle) {
        let generated = self.take_generated_dcids();
        self.stage_dcids_for_handle(handle, generated);
    }

    fn take_generated_dcids(&self) -> Vec<Bytes> {
        self.generated_dcids
            .lock()
            .expect("CID publication queue is not poisoned")
            .drain(..)
            .collect()
    }

    fn discard_generated_dcids(&self) {
        self.generated_dcids
            .lock()
            .expect("CID publication queue is not poisoned")
            .clear();
    }

    fn stage_dcids_for_handle(&mut self, handle: ConnectionHandle, generated: Vec<Bytes>) {
        let Some(connection) = self.connection_for_handle_mut(handle) else {
            return;
        };
        for dcid in &generated {
            connection.track_dcid(dcid.clone());
        }
        if connection.dcid_limit_exceeded {
            return;
        }
        let authenticated = connection.auth.authenticated;
        for dcid in generated {
            if authenticated {
                self.publish_dcid(dcid);
            } else {
                self.events.push_back(QuicEngineEvent::DcidStaged(dcid));
            }
        }
    }

    fn publish_active_dcids(&mut self) {
        let dcids = self
            .connection
            .as_ref()
            .map(|connection| connection.dcids.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for dcid in dcids {
            self.publish_dcid(dcid);
        }
    }

    fn retire_staged_dcids(&mut self, dcids: &HashSet<Bytes>) {
        for dcid in dcids {
            if !self.published_dcids.contains(dcid) {
                self.events
                    .push_back(QuicEngineEvent::DcidRetired(dcid.clone()));
            }
        }
    }

    fn promote_candidate(&mut self) {
        let Some(candidate) = self.candidate.as_ref() else {
            return;
        };
        let candidate_dcids = candidate.dcids.iter().cloned().collect::<Vec<_>>();
        if self.connection.is_some() {
            self.candidate_promotion_pending = true;
            self.events
                .push_back(QuicEngineEvent::Replaced(candidate_dcids));
        } else {
            let candidate = self.candidate.take().expect("candidate exists");
            self.connection = Some(candidate);
            for dcid in candidate_dcids {
                self.publish_dcid(dcid);
            }
            self.events.push_back(QuicEngineEvent::Authenticated);
        }
    }

    fn commit_candidate_replacement(&mut self, now: Instant) {
        let Some(candidate) = self.candidate.take() else {
            return;
        };
        let candidate_dcids = candidate.dcids.clone();
        let previous = self.connection.replace(candidate);
        if let Some(active) = previous {
            self.dispose_managed_connection(active, now, Some(b"peer restarted"));
        }
        self.clear_reassembly();
        for dcid in self
            .published_dcids
            .drain()
            .filter(|dcid| !candidate_dcids.contains(dcid))
        {
            self.events.push_back(QuicEngineEvent::DcidRetired(dcid));
        }
        self.published_dcids.extend(candidate_dcids);
        self.events.push_back(QuicEngineEvent::Authenticated);
    }

    fn dispose_managed_connection(
        &mut self,
        mut managed: ManagedConnection,
        now: Instant,
        reason: Option<&'static [u8]>,
    ) {
        if let Some(reason) = reason {
            managed
                .connection
                .close(now, VarInt::from(0u32), Bytes::from_static(reason));
        }
        while let Some(event) = managed.connection.poll_endpoint_events() {
            if event.is_drained() {
                managed.endpoint_registered = false;
            }
            self.discard_generated_dcids();
            let _ = self.endpoint.handle_event(managed.handle, event);
            self.discard_generated_dcids();
        }
        if managed.endpoint_registered {
            self.discard_generated_dcids();
            let _ = self
                .endpoint
                .handle_event(managed.handle, quinn_proto::EndpointEvent::drained());
            self.discard_generated_dcids();
        }
    }

    fn send_datagram(&mut self, datagram: Bytes) -> Result<(), ()> {
        self.connection
            .as_mut()
            .ok_or(())?
            .connection
            .datagrams()
            .send(datagram)
            .map_err(|_| ())
    }

    fn publish_dcid(&mut self, dcid: Bytes) {
        if self.published_dcids.insert(dcid.clone()) {
            self.events.push_back(QuicEngineEvent::DcidPublished(dcid));
        }
    }

    fn retire_all_dcids(&mut self) {
        for dcid in self.published_dcids.drain() {
            self.events.push_back(QuicEngineEvent::DcidRetired(dcid));
        }
    }
}

fn drive_connection(
    role: QuicRole,
    shared_key: &[u8; 32],
    now: Instant,
    managed: &mut ManagedConnection,
) -> ConnectionDrive {
    let mut drive = ConnectionDrive::default();
    let was_authenticated = managed.auth.authenticated;
    if managed.dcid_limit_exceeded {
        log::warn!("QUIC connection exceeded tracked DCID limit");
        drive.lost = true;
    }
    if !managed.auth.authenticated && now >= managed.auth_deadline {
        log::warn!("QUIC authentication timed out");
        drive.lost = true;
    }
    if managed
        .connection
        .poll_timeout()
        .is_some_and(|deadline| deadline <= now)
    {
        managed.connection.handle_timeout(now);
    }
    let mut stream_events = Vec::new();
    while let Some(event) = managed.connection.poll() {
        log::trace!("QUIC connection event role={role:?}: {event:?}");
        match event {
            Event::Connected
                if role == QuicRole::Client
                    && !start_client_authentication(shared_key, managed) =>
            {
                drive.lost = true;
            }
            Event::DatagramReceived => {
                while let Some(datagram) = managed.connection.datagrams().recv() {
                    drive.datagrams.push(datagram);
                }
            }
            Event::Stream(event) => stream_events.push(event),
            Event::ConnectionLost { reason } => {
                log::warn!("QUIC connection lost: {reason}");
                drive.lost = true;
            }
            _ => {}
        }
    }
    for event in stream_events {
        handle_stream_event(role, shared_key, managed, event, &mut drive);
    }
    if drive.lost {
        return finish_connection_drive(now, managed, drive);
    }
    match flush_auth_stream(managed) {
        AuthFlushOutcome::Complete if managed.auth.authenticate_after_flush => {
            managed.auth.authenticate_after_flush = false;
            managed.auth.authenticated = true;
            drive.authenticated_now = true;
        }
        AuthFlushOutcome::Failed => {
            managed.auth.authenticated = false;
            drive.lost = true;
        }
        AuthFlushOutcome::Complete | AuthFlushOutcome::Blocked => {}
    }
    let retired_dcid_frames = managed.connection.stats().frame_rx.retire_connection_id;
    if !was_authenticated && managed.auth.authenticated {
        managed.retired_dcid_frames = retired_dcid_frames;
    } else if managed.auth.authenticated && retired_dcid_frames > managed.retired_dcid_frames {
        managed.retired_dcid_frames = retired_dcid_frames;
        log::warn!("peer retired a QUIC DCID after authentication; closing v1 transport");
        drive.lost = true;
    } else if !managed.auth.authenticated {
        managed.retired_dcid_frames = retired_dcid_frames;
    }
    finish_connection_drive(now, managed, drive)
}

fn finish_connection_drive(
    now: Instant,
    managed: &mut ManagedConnection,
    mut drive: ConnectionDrive,
) -> ConnectionDrive {
    while let Some(event) = managed.connection.poll_endpoint_events() {
        drive.endpoint_events.push((managed.handle, event));
    }
    while let Some(transmit) = managed.connection.poll_transmit(now, 1) {
        drive.transmits.push(transmit);
    }
    drive
}

fn start_client_authentication(shared_key: &[u8; 32], managed: &mut ManagedConnection) -> bool {
    let Some(stream) = managed.connection.streams().open(Dir::Bi) else {
        log::warn!("failed to open v1 HMAC authentication stream");
        return false;
    };
    let nonce = rand::random::<[u8; 16]>();
    managed.auth.stream = Some(stream);
    managed.auth.client_nonce = Some(nonce);
    queue_auth_frame(
        shared_key,
        managed,
        AUTH_REQUEST,
        b"client",
        nonce,
        EMPTY_NONCE,
    ) != AuthFlushOutcome::Failed
}

fn handle_stream_event(
    role: QuicRole,
    shared_key: &[u8; 32],
    managed: &mut ManagedConnection,
    event: StreamEvent,
    drive: &mut ConnectionDrive,
) {
    match event {
        StreamEvent::Opened { dir: Dir::Bi } if role == QuicRole::Server => {
            let streams = {
                let mut streams = managed.connection.streams();
                std::iter::from_fn(|| streams.accept(Dir::Bi)).collect::<Vec<_>>()
            };
            for stream in streams {
                if managed.auth.stream.is_none() {
                    managed.auth.stream = Some(stream);
                    drain_auth_stream(role, shared_key, managed, drive);
                } else {
                    drive.lost = true;
                }
            }
        }
        StreamEvent::Opened { .. } => drive.lost = true,
        StreamEvent::Readable { id } if managed.auth.stream == Some(id) => {
            drain_auth_stream(role, shared_key, managed, drive);
        }
        StreamEvent::Writable { id } if managed.auth.stream == Some(id) => {
            match flush_auth_stream(managed) {
                AuthFlushOutcome::Complete if managed.auth.authenticate_after_flush => {
                    managed.auth.authenticate_after_flush = false;
                    managed.auth.authenticated = true;
                    drive.authenticated_now = true;
                }
                AuthFlushOutcome::Failed => {
                    managed.auth.authenticated = false;
                    drive.lost = true;
                }
                AuthFlushOutcome::Complete | AuthFlushOutcome::Blocked => {}
            }
        }
        StreamEvent::Readable { .. }
        | StreamEvent::Writable { .. }
        | StreamEvent::Stopped { .. } => drive.lost = true,
        StreamEvent::Finished { id } if managed.auth.stream != Some(id) => drive.lost = true,
        StreamEvent::Finished { .. } | StreamEvent::Available { .. } => {}
    }
}

fn drain_auth_stream(
    role: QuicRole,
    shared_key: &[u8; 32],
    managed: &mut ManagedConnection,
    drive: &mut ConnectionDrive,
) {
    let Some(stream) = managed.auth.stream else {
        return;
    };
    let mut received = Vec::new();
    let mut failed = false;
    {
        let mut recv = managed.connection.recv_stream(stream);
        match recv.read(true) {
            Ok(mut chunks) => {
                loop {
                    match chunks.next(usize::MAX) {
                        Ok(Some(chunk)) => received.extend_from_slice(&chunk.bytes),
                        Ok(None) | Err(ReadError::Blocked) => break,
                        Err(ReadError::Reset(_)) => {
                            failed = true;
                            break;
                        }
                    }
                }
                let _ = chunks.finalize();
            }
            Err(_) => failed = true,
        };
    }
    if failed {
        managed.auth.authenticated = false;
        drive.lost = true;
        return;
    }
    managed.auth.receive.extend_from_slice(&received);
    if managed.auth.receive.len() > AUTH_FRAME_LEN {
        drive.lost = true;
        return;
    }
    while managed.auth.receive.len() >= AUTH_FRAME_LEN {
        let frame = managed.auth.receive.split_to(AUTH_FRAME_LEN).freeze();
        handle_auth_frame(role, shared_key, managed, &frame, drive);
    }
}

fn handle_auth_frame(
    role: QuicRole,
    shared_key: &[u8; 32],
    managed: &mut ManagedConnection,
    frame: &[u8],
    drive: &mut ConnectionDrive,
) {
    let kind = frame[0];
    let client_nonce: [u8; 16] = frame[1..17].try_into().expect("fixed client nonce");
    let server_nonce: [u8; 16] = frame[17..33].try_into().expect("fixed server nonce");
    let received_mac: [u8; 32] = frame[33..].try_into().expect("fixed auth MAC");
    let Some(exporter) = auth_exporter(managed) else {
        drive.lost = true;
        return;
    };
    match (role, kind) {
        (QuicRole::Server, AUTH_REQUEST)
            if server_nonce == EMPTY_NONCE
                && constant_time_eq(
                    &received_mac,
                    &auth_mac(
                        shared_key,
                        b"client",
                        &client_nonce,
                        &server_nonce,
                        &exporter,
                    ),
                ) =>
        {
            let server_nonce = rand::random::<[u8; 16]>();
            managed.auth.client_nonce = Some(client_nonce);
            managed.auth.server_nonce = Some(server_nonce);
            if queue_auth_frame(
                shared_key,
                managed,
                AUTH_RESPONSE,
                b"server",
                client_nonce,
                server_nonce,
            ) == AuthFlushOutcome::Failed
            {
                drive.lost = true;
            }
        }
        (QuicRole::Client, AUTH_RESPONSE)
            if managed.auth.client_nonce == Some(client_nonce)
                && server_nonce != EMPTY_NONCE
                && constant_time_eq(
                    &received_mac,
                    &auth_mac(
                        shared_key,
                        b"server",
                        &client_nonce,
                        &server_nonce,
                        &exporter,
                    ),
                ) =>
        {
            managed.auth.server_nonce = Some(server_nonce);
            if queue_auth_frame(
                shared_key,
                managed,
                AUTH_CONFIRM,
                b"confirm",
                client_nonce,
                server_nonce,
            ) == AuthFlushOutcome::Failed
            {
                drive.lost = true;
            }
        }
        (QuicRole::Server, AUTH_CONFIRM)
            if managed.auth.client_nonce == Some(client_nonce)
                && managed.auth.server_nonce == Some(server_nonce)
                && constant_time_eq(
                    &received_mac,
                    &auth_mac(
                        shared_key,
                        b"confirm",
                        &client_nonce,
                        &server_nonce,
                        &exporter,
                    ),
                ) =>
        {
            match queue_auth_frame(
                shared_key,
                managed,
                AUTH_COMPLETE,
                b"complete",
                client_nonce,
                server_nonce,
            ) {
                AuthFlushOutcome::Complete => {
                    managed.auth.authenticated = true;
                    drive.authenticated_now = true;
                }
                AuthFlushOutcome::Blocked => {
                    managed.auth.authenticate_after_flush = true;
                }
                AuthFlushOutcome::Failed => drive.lost = true,
            }
        }
        (QuicRole::Client, AUTH_COMPLETE)
            if managed.auth.client_nonce == Some(client_nonce)
                && managed.auth.server_nonce == Some(server_nonce)
                && constant_time_eq(
                    &received_mac,
                    &auth_mac(
                        shared_key,
                        b"complete",
                        &client_nonce,
                        &server_nonce,
                        &exporter,
                    ),
                ) =>
        {
            managed.auth.client_nonce = Some(client_nonce);
            managed.auth.server_nonce = Some(server_nonce);
            managed.auth.authenticated = true;
            drive.authenticated_now = true;
        }
        _ => drive.lost = true,
    }
}

fn queue_auth_frame(
    shared_key: &[u8; 32],
    managed: &mut ManagedConnection,
    kind: u8,
    label: &[u8],
    client_nonce: [u8; 16],
    server_nonce: [u8; 16],
) -> AuthFlushOutcome {
    let Some(exporter) = auth_exporter(managed) else {
        return AuthFlushOutcome::Failed;
    };
    let mut frame = Vec::with_capacity(AUTH_FRAME_LEN);
    frame.push(kind);
    frame.extend_from_slice(&client_nonce);
    frame.extend_from_slice(&server_nonce);
    frame.extend_from_slice(&auth_mac(
        shared_key,
        label,
        &client_nonce,
        &server_nonce,
        &exporter,
    ));
    managed.auth.transmit.push_back(Bytes::from(frame));
    flush_auth_stream(managed)
}

fn flush_auth_stream(managed: &mut ManagedConnection) -> AuthFlushOutcome {
    let Some(stream) = managed.auth.stream else {
        return if managed.auth.transmit.is_empty() {
            AuthFlushOutcome::Complete
        } else {
            AuthFlushOutcome::Failed
        };
    };
    while let Some(frame) = managed.auth.transmit.front() {
        match managed
            .connection
            .send_stream(stream)
            .write(&frame[managed.auth.transmit_offset..])
        {
            Ok(written) => {
                managed.auth.transmit_offset += written;
                if managed.auth.transmit_offset == frame.len() {
                    managed.auth.transmit.pop_front();
                    managed.auth.transmit_offset = 0;
                }
            }
            Err(WriteError::Blocked) => return AuthFlushOutcome::Blocked,
            Err(_) => return AuthFlushOutcome::Failed,
        }
    }
    AuthFlushOutcome::Complete
}

pub fn pinned_client_config(expected_sha256: [u8; 32]) -> Result<ClientConfig, rustls::Error> {
    let mut tls = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificateVerifier { expected_sha256 }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ClientConfig::new(Arc::new(tls));
    config.transport_config(stable_transport_config());
    Ok(config)
}

pub fn server_config(
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
) -> Result<ServerConfig, rustls::Error> {
    let mut tls = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::Certificate(certificate_der)],
            rustls::PrivateKey(private_key_der),
        )?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ServerConfig::with_crypto(Arc::new(tls));
    config.use_retry(true);
    config.concurrent_connections(2);
    config.migration(false);
    config.transport_config(stable_transport_config());
    Ok(config)
}

fn stable_transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.initial_mtu(1452);
    config.min_mtu(1452);
    config.mtu_discovery_config(None);
    config.max_idle_timeout(Some(
        QUIC_IDLE_TIMEOUT
            .try_into()
            .expect("QUIC idle timeout fits QUIC varint"),
    ));
    config.keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL));
    config.max_concurrent_bidi_streams(VarInt::from(1u32));
    config.max_concurrent_uni_streams(VarInt::from(0u32));
    config.stream_receive_window(VarInt::from(AUTH_STREAM_WINDOW));
    config.receive_window(VarInt::from(AUTH_STREAM_WINDOW));
    config.datagram_receive_buffer_size(Some(1024 * 1024 * 8));
    config.datagram_send_buffer_size(1024 * 1024 * 8);
    Arc::new(config)
}

struct PinnedCertificateVerifier {
    expected_sha256: [u8; 32],
}

impl rustls::client::ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let digest = Sha256::digest(&end_entity.0);
        if constant_time_eq(digest.as_slice(), &self.expected_sha256) {
            Ok(rustls::client::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "pinned server certificate mismatch".to_string(),
            ))
        }
    }
}

fn endpoint_config(
    dcid_len: usize,
    worker_id: usize,
    worker_count: usize,
    generated_dcids: Arc<Mutex<VecDeque<Bytes>>>,
) -> Arc<EndpointConfig> {
    let mut config = EndpointConfig::default();
    config.cid_generator(move || {
        Box::new(WorkerConnectionIdGenerator {
            dcid_len,
            worker_id,
            worker_count,
            generated_dcids: generated_dcids.clone(),
        })
    });
    Arc::new(config)
}

#[derive(Clone, Debug)]
struct WorkerConnectionIdGenerator {
    dcid_len: usize,
    worker_id: usize,
    worker_count: usize,
    generated_dcids: Arc<Mutex<VecDeque<Bytes>>>,
}

impl ConnectionIdGenerator for WorkerConnectionIdGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0u8; 20];
        loop {
            rand::thread_rng().fill_bytes(&mut bytes[..self.dcid_len]);
            if crate::flow_plane::bootstrap_owner(&bytes[..self.dcid_len], self.worker_count)
                == Ok(self.worker_id)
            {
                self.generated_dcids
                    .lock()
                    .expect("CID publication queue is not poisoned")
                    .push_back(Bytes::copy_from_slice(&bytes[..self.dcid_len]));
                return ConnectionId::new(&bytes[..self.dcid_len]);
            }
        }
    }

    fn cid_len(&self) -> usize {
        self.dcid_len
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

fn validate_dcid_len(dcid_len: usize) -> Result<(), QuicEngineError> {
    if (1..=20).contains(&dcid_len) {
        Ok(())
    } else {
        Err(QuicEngineError::InvalidDcidLength)
    }
}

fn auth_exporter(managed: &ManagedConnection) -> Option<[u8; 32]> {
    let mut exporter = [0u8; 32];
    managed
        .connection
        .crypto_session()
        .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, AUTH_PROTOCOL)
        .ok()?;
    Some(exporter)
}

fn auth_mac(
    key: &[u8; 32],
    label: &[u8],
    client_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
    exporter: &[u8; 32],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(AUTH_PROTOCOL);
    mac.update(label);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.update(exporter);
    let mut output = [0u8; 32];
    output.copy_from_slice(&mac.finalize().into_bytes());
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn extract_dcid(packet: &[u8], fixed_len: usize) -> Option<Bytes> {
    let first = *packet.first()?;
    if first & 0x80 != 0 {
        let dcid_len = usize::from(*packet.get(5)?);
        if dcid_len == 0 || dcid_len > 20 {
            return None;
        }
        Some(Bytes::copy_from_slice(packet.get(6..6 + dcid_len)?))
    } else {
        Some(Bytes::copy_from_slice(packet.get(1..1 + fixed_len)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::Duration;

    fn engine_pair() -> (QuicEngine, QuicEngine, SocketAddr, SocketAddr) {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = certificate.serialize_der().unwrap();
        let private_key_der = certificate.serialize_private_key_der();
        let digest = Sha256::digest(&certificate_der);
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&digest);
        let client_addr = "127.0.0.1:40000".parse().unwrap();
        let server_addr = "127.0.0.1:4433".parse().unwrap();
        let shared_key = [7u8; 32];
        let client = QuicEngine::client(
            pinned_client_config(fingerprint).unwrap(),
            server_addr,
            "localhost",
            shared_key,
            8,
        )
        .unwrap();
        let server = QuicEngine::server(
            server_config(certificate_der, private_key_der).unwrap(),
            shared_key,
            8,
        )
        .unwrap();
        (client, server, client_addr, server_addr)
    }

    fn drive_pair(
        client: &mut QuicEngine,
        server: &mut QuicEngine,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        now: &mut Instant,
        captured: &mut Vec<Bytes>,
    ) -> Vec<QuicEngineEvent> {
        let mut pending = VecDeque::new();
        let mut observed = Vec::new();
        for _ in 0..500 {
            while let Some(event) = client.poll(*now) {
                match event {
                    QuicEngineEvent::Transmit(transmit) => {
                        captured.push(transmit.contents.clone());
                        pending.push_back((true, transmit.contents));
                    }
                    other => observed.push(other),
                }
            }
            while let Some(event) = server.poll(*now) {
                match event {
                    QuicEngineEvent::Transmit(transmit) => {
                        captured.push(transmit.contents.clone());
                        pending.push_back((false, transmit.contents));
                    }
                    other => observed.push(other),
                }
            }
            if let Some((to_server, packet)) = pending.pop_front() {
                if to_server {
                    server.handle_outer(*now, client_addr, Some(server_addr.ip()), packet);
                } else {
                    client.handle_outer(*now, server_addr, Some(client_addr.ip()), packet);
                }
            } else if client.is_authenticated() && server.is_authenticated() {
                break;
            } else {
                *now += Duration::from_millis(1);
            }
        }
        observed
    }

    fn drive_two_clients(
        first: (&mut QuicEngine, SocketAddr),
        second: (&mut QuicEngine, SocketAddr),
        server: &mut QuicEngine,
        server_addr: SocketAddr,
        now: &mut Instant,
    ) {
        let (first_client, first_addr) = first;
        let (second_client, second_addr) = second;
        for _ in 0..2000 {
            while let Some(event) = first_client.poll(*now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    server.handle_outer(
                        *now,
                        first_addr,
                        Some(server_addr.ip()),
                        transmit.contents,
                    );
                }
            }
            while let Some(event) = second_client.poll(*now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    server.handle_outer(
                        *now,
                        second_addr,
                        Some(server_addr.ip()),
                        transmit.contents,
                    );
                }
            }
            while let Some(event) = server.poll(*now) {
                let QuicEngineEvent::Transmit(transmit) = event else {
                    continue;
                };
                if transmit.destination == first_addr {
                    first_client.handle_outer(
                        *now,
                        server_addr,
                        Some(first_addr.ip()),
                        transmit.contents,
                    );
                } else if transmit.destination == second_addr {
                    second_client.handle_outer(
                        *now,
                        server_addr,
                        Some(second_addr.ip()),
                        transmit.contents,
                    );
                }
            }
            if second_client.is_authenticated() && server.is_authenticated() {
                break;
            }
            *now += Duration::from_millis(2);
        }
    }

    #[test]
    fn v1_unit_quic_engine_authenticates_and_round_trips_inner_packets() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut captured = Vec::new();
        let mut observed = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        assert!(client.is_authenticated());
        assert!(server.is_authenticated());
        assert!(client
            .connection
            .as_mut()
            .and_then(|connection| connection.connection.datagrams().max_size())
            .is_some_and(|maximum| maximum >= 1394));

        let ipv4 = Bytes::from_static(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        let mut ipv6_bytes = [0u8; 40];
        ipv6_bytes[0] = 0x60;
        ipv6_bytes[6] = 59;
        let ipv6 = Bytes::copy_from_slice(&ipv6_bytes);
        client.send_inner(now, ipv4.clone()).unwrap();
        server.send_inner(now, ipv6.clone()).unwrap();
        observed.extend(drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        ));

        assert!(observed.contains(&QuicEngineEvent::InnerPacket(ipv4.clone())));
        assert!(observed.contains(&QuicEngineEvent::InnerPacket(ipv6.clone())));
        assert!(captured
            .iter()
            .all(|outer| !outer.windows(ipv4.len()).any(|window| window == ipv4)));
        assert!(captured
            .iter()
            .all(|outer| !outer.windows(ipv6.len()).any(|window| window == ipv6)));
        assert!(observed
            .iter()
            .any(|event| matches!(event, QuicEngineEvent::DcidPublished(_))));
    }

    #[test]
    fn v1_unit_quic_engine_retransmits_hmac_authentication_after_packet_loss() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut pending = VecDeque::new();
        let mut dropped_auth_packet = false;

        for _ in 0..2000 {
            while let Some(event) = client.poll(now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    if client
                        .connection
                        .as_ref()
                        .is_some_and(|connection| connection.auth.client_nonce.is_some())
                        && !client.is_authenticated()
                        && !dropped_auth_packet
                    {
                        dropped_auth_packet = true;
                    } else {
                        pending.push_back((true, transmit.contents));
                    }
                }
            }
            while let Some(event) = server.poll(now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    pending.push_back((false, transmit.contents));
                }
            }
            if let Some((to_server, packet)) = pending.pop_front() {
                if to_server {
                    server.handle_outer(now, client_addr, Some(server_addr.ip()), packet);
                } else {
                    client.handle_outer(now, server_addr, Some(client_addr.ip()), packet);
                }
            } else {
                now += Duration::from_millis(5);
            }
            if client.is_authenticated() && server.is_authenticated() {
                break;
            }
        }

        assert!(dropped_auth_packet);
        assert!(client.is_authenticated());
        assert!(server.is_authenticated());
    }

    #[test]
    fn v1_unit_quic_engine_does_not_publish_active_dcid_before_authentication() {
        let (mut client, _, _, _) = engine_pair();
        let now = Instant::now();

        let events = std::iter::from_fn(|| client.poll(now)).collect::<Vec<_>>();

        assert!(!events
            .iter()
            .any(|event| matches!(event, QuicEngineEvent::DcidPublished(_))));
    }

    #[test]
    fn v1_unit_quic_engine_does_not_stage_dcid_without_a_managed_connection() {
        let (_, mut server, _, _) = engine_pair();
        server
            .generated_dcids
            .lock()
            .unwrap()
            .push_back(Bytes::from_static(b"orphan"));

        server.stage_generated_dcids(ConnectionHandle(usize::MAX));

        assert!(!server.events.iter().any(
            |event| matches!(event, QuicEngineEvent::DcidStaged(dcid) if dcid.as_ref() == b"orphan")
        ));
    }

    #[test]
    fn v1_unit_quic_engine_discards_cids_generated_for_stateless_initial_handling() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let now = Instant::now();
        let initial = std::iter::from_fn(|| client.poll(now))
            .find_map(|event| match event {
                QuicEngineEvent::Transmit(transmit) => Some(transmit.contents),
                _ => None,
            })
            .expect("client emits an Initial");

        server.handle_outer(now, client_addr, Some(server_addr.ip()), initial);

        assert!(server
            .generated_dcids
            .lock()
            .expect("CID publication queue is not poisoned")
            .is_empty());
        assert!(server.connection.is_none());
        assert!(server.candidate.is_none());
    }

    #[test]
    fn v1_unit_quic_engine_unauthenticated_candidate_does_not_replace_active_connection() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut captured = Vec::new();
        let _ = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        assert!(server.is_authenticated());
        while server.poll(now).is_some() {}

        let reconnect = client.client_reconnect.as_ref().unwrap().clone();
        let mut candidate = QuicEngine::client(
            reconnect.client_config,
            reconnect.remote,
            &reconnect.server_name,
            [9u8; 32],
            8,
        )
        .unwrap();
        let mut pending = VecDeque::new();
        let mut server_events = Vec::new();
        for _ in 0..1000 {
            while let Some(event) = candidate.poll(now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    pending.push_back((true, transmit.contents));
                }
            }
            while let Some(event) = server.poll(now) {
                match event {
                    QuicEngineEvent::Transmit(transmit) => {
                        pending.push_back((false, transmit.contents));
                    }
                    other => server_events.push(other),
                }
            }
            if let Some((to_server, packet)) = pending.pop_front() {
                if to_server {
                    server.handle_outer(now, client_addr, Some(server_addr.ip()), packet);
                } else {
                    candidate.handle_outer(now, server_addr, Some(client_addr.ip()), packet);
                }
            } else {
                now += Duration::from_millis(2);
            }
        }

        assert!(server.is_authenticated());
        assert!(!server_events.contains(&QuicEngineEvent::Closed));
        assert!(!server_events
            .iter()
            .any(|event| matches!(event, QuicEngineEvent::DcidPublished(_))));
    }

    #[test]
    fn v1_unit_quic_engine_wrong_key_cold_start_cannot_block_a_different_peer() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let reconnect = client.client_reconnect.as_ref().unwrap().clone();
        let attacker_addr = "127.0.0.2:41000".parse().unwrap();
        let mut attacker = QuicEngine::client(
            reconnect.client_config,
            reconnect.remote,
            &reconnect.server_name,
            [9u8; 32],
            8,
        )
        .unwrap();
        let mut now = Instant::now();

        drive_two_clients(
            (&mut attacker, attacker_addr),
            (&mut client, client_addr),
            &mut server,
            server_addr,
            &mut now,
        );

        assert!(client.is_authenticated());
        assert!(server.is_authenticated());
        assert_eq!(
            server
                .connection
                .as_ref()
                .map(|connection| connection.connection.remote_address()),
            Some(client_addr)
        );
    }

    #[test]
    fn v1_unit_quic_engine_auth_timeout_releases_candidate_and_endpoint_slot() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let reconnect = client.client_reconnect.as_ref().unwrap().clone();
        let stalled_addr = "127.0.0.2:42000".parse().unwrap();
        let mut stalled = QuicEngine::client(
            reconnect.client_config.clone(),
            reconnect.remote,
            &reconnect.server_name,
            [9u8; 32],
            8,
        )
        .unwrap();
        let mut now = Instant::now();

        for _ in 0..500 {
            while let Some(event) = stalled.poll(now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    server.handle_outer(
                        now,
                        stalled_addr,
                        Some(server_addr.ip()),
                        transmit.contents,
                    );
                }
            }
            while let Some(event) = server.poll(now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    stalled.handle_outer(
                        now,
                        server_addr,
                        Some(stalled_addr.ip()),
                        transmit.contents,
                    );
                }
            }
            if server.candidate.is_some() {
                break;
            }
            now += Duration::from_millis(2);
        }
        assert!(server.candidate.is_some());

        now += AUTH_TIMEOUT + Duration::from_millis(1);
        while server.poll(now).is_some() {}
        assert!(server.candidate.is_none());
        assert!(server.connection.is_none());

        client = QuicEngine::client(
            reconnect.client_config,
            reconnect.remote,
            &reconnect.server_name,
            [7u8; 32],
            8,
        )
        .unwrap();
        now = Instant::now();
        let mut captured = Vec::new();
        let _ = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        assert!(client.is_authenticated());
        assert!(server.is_authenticated());
    }

    #[test]
    fn v1_unit_quic_engine_authenticated_candidate_is_promoted_atomically() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut captured = Vec::new();
        let _ = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        while server.poll(now).is_some() {}

        let reconnect = client.client_reconnect.as_ref().unwrap().clone();
        let mut candidate = QuicEngine::client(
            reconnect.client_config,
            reconnect.remote,
            &reconnect.server_name,
            [7u8; 32],
            8,
        )
        .unwrap();
        let mut pending = VecDeque::new();
        let mut server_events = Vec::new();
        for _ in 0..2000 {
            while let Some(event) = candidate.poll(now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    pending.push_back((true, transmit.contents));
                }
            }
            while let Some(event) = server.poll(now) {
                match event {
                    QuicEngineEvent::Transmit(transmit) => {
                        pending.push_back((false, transmit.contents));
                    }
                    QuicEngineEvent::Replaced(dcids) => {
                        server_events.push(QuicEngineEvent::Replaced(dcids));
                        server.resolve_candidate_replacement(now, true);
                    }
                    other => server_events.push(other),
                }
            }
            if let Some((to_server, packet)) = pending.pop_front() {
                if to_server {
                    server.handle_outer(now, client_addr, Some(server_addr.ip()), packet);
                } else {
                    candidate.handle_outer(now, server_addr, Some(client_addr.ip()), packet);
                }
            } else {
                now += Duration::from_millis(2);
            }
            if candidate.is_authenticated()
                && server.is_authenticated()
                && server_events.contains(&QuicEngineEvent::Authenticated)
            {
                break;
            }
        }

        let replaced = server_events
            .iter()
            .position(|event| matches!(event, QuicEngineEvent::Replaced(_)))
            .expect("old active connection is retired");
        let published = server_events
            .iter()
            .position(
                |event| matches!(event, QuicEngineEvent::Replaced(dcids) if !dcids.is_empty()),
            )
            .expect("candidate DCID is published");
        let authenticated = server_events
            .iter()
            .position(|event| *event == QuicEngineEvent::Authenticated)
            .expect("candidate is promoted");

        assert!(server.is_authenticated());
        assert!(!server_events.contains(&QuicEngineEvent::Closed));
        assert_eq!(replaced, published);
        assert!(published < authenticated);
    }

    #[test]
    fn v1_unit_quic_engine_rejected_candidate_replacement_keeps_active_connection() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut captured = Vec::new();
        let _ = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        while server.poll(now).is_some() {}
        let active_handle = server.connection.as_ref().unwrap().handle;

        let reconnect = client.client_reconnect.as_ref().unwrap().clone();
        let candidate_addr = "127.0.0.2:43000".parse().unwrap();
        let mut candidate = QuicEngine::client(
            reconnect.client_config,
            reconnect.remote,
            &reconnect.server_name,
            [7u8; 32],
            8,
        )
        .unwrap();
        let mut pending = VecDeque::new();
        let mut rejected = false;
        let mut server_events = Vec::new();
        for _ in 0..2000 {
            while let Some(event) = candidate.poll(now) {
                if let QuicEngineEvent::Transmit(transmit) = event {
                    pending.push_back((true, transmit.contents));
                }
            }
            while let Some(event) = server.poll(now) {
                match event {
                    QuicEngineEvent::Transmit(transmit) => {
                        pending.push_back((false, transmit.contents));
                    }
                    QuicEngineEvent::Replaced(dcids) => {
                        assert!(!dcids.is_empty());
                        rejected = true;
                        server.resolve_candidate_replacement(now, false);
                    }
                    other => server_events.push(other),
                }
            }
            if rejected {
                while let Some(event) = server.poll(now) {
                    server_events.push(event);
                }
                break;
            }
            if let Some((to_server, packet)) = pending.pop_front() {
                if to_server {
                    server.handle_outer(now, candidate_addr, Some(server_addr.ip()), packet);
                } else {
                    candidate.handle_outer(now, server_addr, Some(candidate_addr.ip()), packet);
                }
            } else {
                now += Duration::from_millis(2);
            }
        }

        assert!(rejected);
        assert!(server.is_authenticated());
        assert_eq!(server.connection.as_ref().unwrap().handle, active_handle);
        assert!(server.candidate.is_none());
        assert!(!server_events.contains(&QuicEngineEvent::Closed));
        assert!(!server_events.contains(&QuicEngineEvent::Authenticated));
        assert!(server_events
            .iter()
            .any(|event| matches!(event, QuicEngineEvent::DcidRetired(_))));
    }

    #[test]
    fn v1_unit_quic_engine_keeps_authenticated_connection_alive_while_idle() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut captured = Vec::new();
        let _ = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        assert!(client.is_authenticated());
        assert!(server.is_authenticated());

        for _ in 0..30 {
            now += Duration::from_secs(1);
            let _ = drive_pair(
                &mut client,
                &mut server,
                client_addr,
                server_addr,
                &mut now,
                &mut captured,
            );
        }

        assert!(client.is_authenticated());
        assert!(server.is_authenticated());
    }

    #[test]
    fn v1_unit_quic_engine_fragments_and_reassembles_standard_mtu_inner_packet() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut captured = Vec::new();
        let mut observed = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        let inner = Bytes::from(
            (0..1500)
                .map(|offset| (offset % 251) as u8)
                .collect::<Vec<_>>(),
        );

        client.send_inner(now, inner.clone()).unwrap();
        observed.extend(drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        ));

        assert_eq!(
            observed
                .iter()
                .filter(|event| **event == QuicEngineEvent::InnerPacket(inner.clone()))
                .count(),
            1
        );
    }

    #[test]
    fn v1_unit_quic_engine_rejects_data_before_auth_and_retires_dcids_on_close() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let now = Instant::now();
        assert!(matches!(
            client.send_inner(now, Bytes::from_static(b"not-authenticated")),
            Err(QuicEngineError::NotAuthenticated)
        ));
        let mut now = now;
        let mut captured = Vec::new();
        let _ = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        client.close(now);
        let events = std::iter::from_fn(|| client.poll(now)).collect::<Vec<_>>();
        assert!(events
            .iter()
            .any(|event| matches!(event, QuicEngineEvent::DcidRetired(_))));
        assert!(events.contains(&QuicEngineEvent::Closed));
    }

    #[test]
    fn v1_unit_quic_engine_server_requires_auth_confirmation_before_inner_data() {
        let (_, mut server, _, _) = engine_pair();
        let now = Instant::now();

        server.handle_application_datagram(now, Bytes::from_static(&[INNER_PACKET, b'i', b'p']));

        assert!(!server.is_authenticated());
        assert!(std::iter::from_fn(|| server.poll(now))
            .all(|event| !matches!(event, QuicEngineEvent::InnerPacket(_))));
    }

    #[test]
    fn v1_unit_auth_mac_binds_both_nonces_and_tls_exporter() {
        let key = [7u8; 32];
        let client_nonce = [1u8; 16];
        let server_nonce = [2u8; 16];
        let other_server_nonce = [3u8; 16];
        let exporter = [4u8; 32];
        let other_exporter = [5u8; 32];

        let expected = auth_mac(&key, b"confirm", &client_nonce, &server_nonce, &exporter);
        assert_ne!(
            expected,
            auth_mac(
                &key,
                b"confirm",
                &client_nonce,
                &other_server_nonce,
                &exporter,
            )
        );
        assert_ne!(
            expected,
            auth_mac(
                &key,
                b"confirm",
                &client_nonce,
                &server_nonce,
                &other_exporter,
            )
        );
    }

    #[test]
    fn v1_unit_quic_engine_reassembly_limits_fragment_entry_count() {
        let (mut client, mut server, client_addr, server_addr) = engine_pair();
        let mut now = Instant::now();
        let mut captured = Vec::new();
        let _ = drive_pair(
            &mut client,
            &mut server,
            client_addr,
            server_addr,
            &mut now,
            &mut captured,
        );
        assert!(server.is_authenticated());

        for packet_id in 0..MAX_REASSEMBLY_ENTRIES as u64 {
            let mut fragment = vec![INNER_FRAGMENT];
            fragment.extend_from_slice(&packet_id.to_be_bytes());
            fragment.extend_from_slice(&2u16.to_be_bytes());
            fragment.extend_from_slice(&0u16.to_be_bytes());
            fragment.push(1);
            server.handle_application_datagram(now, Bytes::from(fragment));
        }

        let mut extra = vec![INNER_FRAGMENT];
        extra.extend_from_slice(&(MAX_REASSEMBLY_ENTRIES as u64).to_be_bytes());
        extra.extend_from_slice(&2u16.to_be_bytes());
        extra.extend_from_slice(&0u16.to_be_bytes());
        extra.push(1);
        server.handle_application_datagram(now, Bytes::from(extra));

        assert_eq!(server.reassembly.len(), MAX_REASSEMBLY_ENTRIES);
        assert!(!server
            .reassembly
            .contains_key(&(MAX_REASSEMBLY_ENTRIES as u64)));
    }

    #[test]
    fn v1_unit_quic_engine_generates_dcids_owned_by_the_flow_worker() {
        for worker_id in 0..4 {
            let mut generator = WorkerConnectionIdGenerator {
                dcid_len: 8,
                worker_id,
                worker_count: 4,
                generated_dcids: Arc::new(Mutex::new(VecDeque::new())),
            };
            for _ in 0..32 {
                let cid = generator.generate_cid();
                assert_eq!(
                    crate::flow_plane::bootstrap_owner(&cid, 4).unwrap(),
                    worker_id
                );
            }
        }
    }

    #[test]
    fn v1_unit_quic_engine_client_initial_maps_to_its_flow_worker() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = certificate.serialize_der().unwrap();
        let digest = Sha256::digest(&certificate_der);
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&digest);
        let remote = "127.0.0.1:4433".parse().unwrap();

        for worker_id in 0..4 {
            let mut engine = QuicEngine::client_for_worker(
                pinned_client_config(fingerprint).unwrap(),
                remote,
                "localhost",
                [7u8; 32],
                8,
                worker_id,
                4,
            )
            .unwrap();
            let initial = std::iter::from_fn(|| engine.poll(Instant::now())).find_map(|event| {
                let QuicEngineEvent::Transmit(transmit) = event else {
                    return None;
                };
                extract_dcid(&transmit.contents, 8)
            });

            assert_eq!(
                crate::flow_plane::bootstrap_owner(&initial.unwrap(), 4).unwrap(),
                worker_id
            );
        }
    }

    #[test]
    fn v1_unit_quic_engine_reconnect_keeps_worker_affinity() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let certificate_der = certificate.serialize_der().unwrap();
        let digest = Sha256::digest(&certificate_der);
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&digest);
        let mut engine = QuicEngine::client_for_worker(
            pinned_client_config(fingerprint).unwrap(),
            "127.0.0.1:4433".parse().unwrap(),
            "localhost",
            [7u8; 32],
            8,
            2,
            4,
        )
        .unwrap();
        while engine.poll(Instant::now()).is_some() {}

        engine.reconnect_client().unwrap();
        let initial = std::iter::from_fn(|| engine.poll(Instant::now())).find_map(|event| {
            let QuicEngineEvent::Transmit(transmit) = event else {
                return None;
            };
            extract_dcid(&transmit.contents, 8)
        });

        assert_eq!(
            crate::flow_plane::bootstrap_owner(&initial.unwrap(), 4).unwrap(),
            2
        );
    }
}
