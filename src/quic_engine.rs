use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, ConnectionId, ConnectionIdGenerator, DatagramEvent,
    Endpoint, EndpointConfig, Event, ServerConfig, Transmit, TransportConfig, VarInt,
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
const INNER_PACKET: u8 = 16;
const INNER_FRAGMENT: u8 = 17;
const ALPN: &[u8] = b"new-proxy-v1";
const INNER_FRAGMENT_HEADER_LEN: usize = 13;
const MAX_INNER_PACKET_LEN: usize = u16::MAX as usize;
const MAX_REASSEMBLY_BYTES: usize = 1024 * 1024;
const MAX_REASSEMBLY_ENTRIES: usize = 4096;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);

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
    DcidPublished(Bytes),
    DcidRetired(Bytes),
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
    connection: Option<(ConnectionHandle, Connection)>,
    client_reconnect: Option<ClientReconnect>,
    shared_key: [u8; 32],
    client_nonce: Option<[u8; 16]>,
    server_pending_nonce: Option<[u8; 16]>,
    authenticated: bool,
    dcid_len: usize,
    generated_dcids: Arc<Mutex<VecDeque<Bytes>>>,
    published_dcids: HashSet<Bytes>,
    next_inner_packet_id: u64,
    reassembly: HashMap<u64, InnerReassembly>,
    reassembly_bytes: usize,
    events: VecDeque<QuicEngineEvent>,
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
            let mut engine = Self {
                role: QuicRole::Client,
                endpoint,
                connection: Some(connection),
                client_reconnect: Some(ClientReconnect {
                    client_config: client_config.clone(),
                    remote,
                    server_name: server_name.to_string(),
                    worker_id,
                    worker_count,
                }),
                shared_key,
                client_nonce: None,
                server_pending_nonce: None,
                authenticated: false,
                dcid_len,
                generated_dcids,
                published_dcids: HashSet::new(),
                next_inner_packet_id: 0,
                reassembly: HashMap::new(),
                reassembly_bytes: 0,
                events: VecDeque::new(),
            };
            engine.drive(Instant::now());
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
            client_reconnect: None,
            shared_key,
            client_nonce: None,
            server_pending_nonce: None,
            authenticated: false,
            dcid_len,
            generated_dcids,
            published_dcids: HashSet::new(),
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
        let Some((handle, event)) =
            self.endpoint
                .handle(now, remote, local_ip, None, BytesMut::from(packet))
        else {
            self.drive(now);
            return;
        };
        match event {
            DatagramEvent::NewConnection(connection) => {
                let replace_same_peer = self
                    .connection
                    .as_ref()
                    .is_some_and(|(_, active)| active.remote_address() == remote);
                if self.connection.is_none() || replace_same_peer {
                    if replace_same_peer {
                        self.close_active_connection(now, b"peer restarted");
                    }
                    self.connection = Some((handle, connection));
                }
            }
            DatagramEvent::ConnectionEvent(event) => {
                if let Some((active_handle, connection)) = self.connection.as_mut() {
                    if *active_handle == handle {
                        connection.handle_event(event);
                    }
                }
            }
        }
        if let Some(dcid) = accepted_dcid {
            self.publish_dcid(dcid);
        }
        self.drive(now);
    }

    pub fn send_inner(&mut self, now: Instant, packet: Bytes) -> Result<(), QuicEngineError> {
        if packet.is_empty() {
            return Err(QuicEngineError::EmptyInnerPacket);
        }
        if !self.authenticated {
            return Err(QuicEngineError::NotAuthenticated);
        }
        let max_datagram_size = self
            .connection
            .as_mut()
            .and_then(|(_, connection)| connection.datagrams().max_size())
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
        if let Some((_, connection)) = self.connection.as_mut() {
            connection.close(now, VarInt::from(0u32), Bytes::from_static(b"closed"));
        }
        self.authenticated = false;
        self.server_pending_nonce = None;
        self.clear_reassembly();
        self.retire_all_dcids();
        self.events.push_back(QuicEngineEvent::Closed);
        self.drive(now);
        self.connection = None;
    }

    pub fn poll(&mut self, now: Instant) -> Option<QuicEngineEvent> {
        self.drive(now);
        self.events.pop_front()
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
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

    fn drive(&mut self, now: Instant) {
        let generated = {
            let mut generated = self
                .generated_dcids
                .lock()
                .expect("CID publication queue is not poisoned");
            generated.drain(..).collect::<Vec<_>>()
        };
        for dcid in generated {
            self.publish_dcid(dcid);
        }
        let mut connection_events = Vec::new();
        let mut datagrams = Vec::new();
        let mut endpoint_events = Vec::new();
        let mut transmits = Vec::new();
        let mut connection_lost = false;
        if let Some((handle, connection)) = self.connection.as_mut() {
            if connection
                .poll_timeout()
                .is_some_and(|deadline| deadline <= now)
            {
                connection.handle_timeout(now);
            }
            while let Some(event) = connection.poll() {
                log::trace!("QUIC connection event role={:?}: {event:?}", self.role);
                match event {
                    Event::DatagramReceived => {
                        while let Some(datagram) = connection.datagrams().recv() {
                            log::trace!(
                                "drained QUIC application datagram role={:?} bytes={}",
                                self.role,
                                datagram.len()
                            );
                            datagrams.push(datagram);
                        }
                    }
                    other => connection_events.push(other),
                }
            }
            while let Some(event) = connection.poll_endpoint_events() {
                endpoint_events.push((*handle, event));
            }
            while let Some(transmit) = connection.poll_transmit(now, 1) {
                transmits.push(transmit);
            }
        }

        for event in connection_events {
            match event {
                Event::Connected if self.role == QuicRole::Client => {
                    log::debug!("client QUIC transport connected");
                    let nonce = rand::random::<[u8; 16]>();
                    self.client_nonce = Some(nonce);
                    let mut request = Vec::with_capacity(49);
                    request.push(AUTH_REQUEST);
                    request.extend_from_slice(&nonce);
                    request.extend_from_slice(&auth_mac(&self.shared_key, b"client", &nonce));
                    if self.send_datagram(Bytes::from(request)).is_err() {
                        log::warn!("failed to queue v1 HMAC authentication request");
                    } else {
                        log::debug!("queued v1 HMAC authentication request");
                    }
                }
                Event::ConnectionLost { reason } => {
                    log::warn!("QUIC connection lost: {reason}");
                    self.authenticated = false;
                    self.server_pending_nonce = None;
                    self.clear_reassembly();
                    self.retire_all_dcids();
                    self.events.push_back(QuicEngineEvent::Closed);
                    connection_lost = true;
                }
                _ => {}
            }
        }
        self.prune_reassembly(now);
        for datagram in datagrams {
            self.handle_application_datagram(now, datagram);
        }
        for (handle, event) in endpoint_events {
            if let Some(connection_event) = self.endpoint.handle_event(handle, event) {
                if let Some((active_handle, connection)) = self.connection.as_mut() {
                    if *active_handle == handle {
                        connection.handle_event(connection_event);
                    }
                }
            }
        }
        while let Some(transmit) = self.endpoint.poll_transmit() {
            transmits.push(transmit);
        }
        if let Some((_, connection)) = self.connection.as_mut() {
            while let Some(transmit) = connection.poll_transmit(now, 1) {
                transmits.push(transmit);
            }
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
        if connection_lost {
            self.connection = None;
        }
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
            (QuicRole::Server, AUTH_REQUEST) if payload.len() == 48 => {
                let nonce: [u8; 16] = payload[..16].try_into().expect("checked auth nonce");
                let received_mac: [u8; 32] = payload[16..].try_into().expect("checked auth MAC");
                if constant_time_eq(
                    &received_mac,
                    &auth_mac(&self.shared_key, b"client", &nonce),
                ) {
                    log::debug!("server accepted v1 HMAC authentication");
                    self.server_pending_nonce = Some(nonce);
                    let mut response = Vec::with_capacity(49);
                    response.push(AUTH_RESPONSE);
                    response.extend_from_slice(&nonce);
                    response.extend_from_slice(&auth_mac(&self.shared_key, b"server", &nonce));
                    if self.send_datagram(Bytes::from(response)).is_err() {
                        log::warn!("failed to queue v1 HMAC authentication response");
                    } else {
                        log::debug!("queued v1 HMAC authentication response");
                    }
                }
            }
            (QuicRole::Client, AUTH_RESPONSE) if payload.len() == 48 => {
                let nonce: [u8; 16] = payload[..16].try_into().expect("checked auth nonce");
                let received_mac: [u8; 32] = payload[16..].try_into().expect("checked auth MAC");
                if self.client_nonce == Some(nonce)
                    && constant_time_eq(
                        &received_mac,
                        &auth_mac(&self.shared_key, b"server", &nonce),
                    )
                {
                    log::debug!("client accepted v1 HMAC authentication");
                    self.authenticated = true;
                    let mut confirm = Vec::with_capacity(49);
                    confirm.push(AUTH_CONFIRM);
                    confirm.extend_from_slice(&nonce);
                    confirm.extend_from_slice(&auth_mac(&self.shared_key, b"confirm", &nonce));
                    if self.send_datagram(Bytes::from(confirm)).is_err() {
                        log::warn!("failed to queue v1 HMAC authentication confirmation");
                    } else {
                        log::debug!("queued v1 HMAC authentication confirmation");
                    }
                    self.events.push_back(QuicEngineEvent::Authenticated);
                }
            }
            (QuicRole::Server, AUTH_CONFIRM) if payload.len() == 48 => {
                let nonce: [u8; 16] = payload[..16].try_into().expect("checked auth nonce");
                let received_mac: [u8; 32] = payload[16..].try_into().expect("checked auth MAC");
                if self.server_pending_nonce == Some(nonce)
                    && constant_time_eq(
                        &received_mac,
                        &auth_mac(&self.shared_key, b"confirm", &nonce),
                    )
                {
                    log::debug!("server accepted v1 HMAC authentication confirmation");
                    self.server_pending_nonce = None;
                    self.authenticated = true;
                    self.events.push_back(QuicEngineEvent::Authenticated);
                }
            }
            (_, INNER_PACKET) if self.authenticated && !payload.is_empty() => {
                self.events
                    .push_back(QuicEngineEvent::InnerPacket(Bytes::copy_from_slice(
                        payload,
                    )));
            }
            (_, INNER_FRAGMENT) if self.authenticated => {
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

    fn close_active_connection(&mut self, now: Instant, reason: &'static [u8]) {
        let Some((handle, mut connection)) = self.connection.take() else {
            return;
        };
        connection.close(now, VarInt::from(0u32), Bytes::from_static(reason));
        while let Some(event) = connection.poll_endpoint_events() {
            let _ = self.endpoint.handle_event(handle, event);
        }
        self.authenticated = false;
        self.server_pending_nonce = None;
        self.clear_reassembly();
        self.retire_all_dcids();
        self.events.push_back(QuicEngineEvent::Closed);
    }

    fn send_datagram(&mut self, datagram: Bytes) -> Result<(), ()> {
        self.connection
            .as_mut()
            .ok_or(())?
            .1
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
    config.transport_config(stable_transport_config());
    Ok(config)
}

fn stable_transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.max_idle_timeout(Some(
        QUIC_IDLE_TIMEOUT
            .try_into()
            .expect("QUIC idle timeout fits QUIC varint"),
    ));
    config.keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL));
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

fn auth_mac(key: &[u8; 32], label: &[u8], nonce: &[u8; 16]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte key");
    mac.update(label);
    mac.update(nonce);
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
        server.server_pending_nonce = Some([9u8; 16]);

        server.handle_application_datagram(now, Bytes::from_static(&[INNER_PACKET, b'i', b'p']));

        assert!(!server.is_authenticated());
        assert!(std::iter::from_fn(|| server.poll(now))
            .all(|event| !matches!(event, QuicEngineEvent::InnerPacket(_))));
    }

    #[test]
    fn v1_unit_quic_engine_reassembly_limits_fragment_entry_count() {
        let (_, mut server, _, _) = engine_pair();
        let now = Instant::now();
        server.authenticated = true;

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
