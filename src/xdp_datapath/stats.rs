use crate::flow_plane::{DispatchStats, FlowDispatcher, FlowWorkerState, IoOwnerKey, QuicFlow};
use crate::xdp_datapath::io_worker::{DropReason, IngressOutcome};
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

#[derive(Debug, Default)]
pub struct IoStatsSlot {
    rx_frames: AtomicU64,
    tx_frames: AtomicU64,
    tx_drops: AtomicU64,
    passed_frames: AtomicU64,
    dispatched_frames: AtomicU64,
    dropped_frames: AtomicU64,
    unknown_dcid_drops: AtomicU64,
    invalid_quic_drops: AtomicU64,
    malformed_drops: AtomicU64,
    dispatch_drops: AtomicU64,
    dns_unknown_transaction_drops: AtomicU64,
    dns_fragmented_drops: AtomicU64,
}

impl IoStatsSlot {
    pub fn record_rx(&self, count: u32) {
        self.rx_frames
            .fetch_add(u64::from(count), Ordering::Relaxed);
    }

    pub fn record_tx(&self) {
        self.tx_frames.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tx_drop(&self) {
        self.tx_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ingress(&self, outcome: IngressOutcome) {
        match outcome {
            IngressOutcome::Passed => {
                self.passed_frames.fetch_add(1, Ordering::Relaxed);
            }
            IngressOutcome::Dispatched { .. } => {
                self.dispatched_frames.fetch_add(1, Ordering::Relaxed);
            }
            IngressOutcome::Dropped(reason) => {
                self.dropped_frames.fetch_add(1, Ordering::Relaxed);
                if reason == DropReason::UnknownDcid {
                    self.unknown_dcid_drops.fetch_add(1, Ordering::Relaxed);
                } else if reason == DropReason::InvalidQuic {
                    self.invalid_quic_drops.fetch_add(1, Ordering::Relaxed);
                } else if matches!(
                    reason,
                    DropReason::MalformedEthernet
                        | DropReason::MalformedIp
                        | DropReason::MalformedUdp
                        | DropReason::InvalidFlow
                ) {
                    self.malformed_drops.fetch_add(1, Ordering::Relaxed);
                } else if matches!(reason, DropReason::DispatchRejected(_)) {
                    self.dispatch_drops.fetch_add(1, Ordering::Relaxed);
                } else if reason == DropReason::UnknownDnsTransaction {
                    self.dns_unknown_transaction_drops
                        .fetch_add(1, Ordering::Relaxed);
                } else if reason == DropReason::FragmentedDns {
                    self.dns_fragmented_drops.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn snapshot(&self) -> IoCounters {
        IoCounters {
            rx_frames: self.rx_frames.load(Ordering::Relaxed),
            tx_frames: self.tx_frames.load(Ordering::Relaxed),
            tx_drops: self.tx_drops.load(Ordering::Relaxed),
            passed_frames: self.passed_frames.load(Ordering::Relaxed),
            dispatched_frames: self.dispatched_frames.load(Ordering::Relaxed),
            dropped_frames: self.dropped_frames.load(Ordering::Relaxed),
            unknown_dcid_drops: self.unknown_dcid_drops.load(Ordering::Relaxed),
            invalid_quic_drops: self.invalid_quic_drops.load(Ordering::Relaxed),
            malformed_drops: self.malformed_drops.load(Ordering::Relaxed),
            dispatch_drops: self.dispatch_drops.load(Ordering::Relaxed),
            dns_unknown_transaction_drops: self
                .dns_unknown_transaction_drops
                .load(Ordering::Relaxed),
            dns_fragmented_drops: self.dns_fragmented_drops.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct IoStatsEntry {
    pub owner: IoOwnerKey,
    pub tunnel: bool,
    pub intercept: bool,
    pub slot: std::sync::Arc<IoStatsSlot>,
}

#[derive(Debug, Default)]
pub struct FlowStatsSlot {
    snapshot: RwLock<FlowWorkerSnapshot>,
    pending_inner_drops: AtomicU64,
    quic_send_drops: AtomicU64,
    io_missing_owner_drops: AtomicU64,
    io_channel_full_drops: AtomicU64,
    io_channel_disconnected_drops: AtomicU64,
    reverse_nat_publish_drops: AtomicU64,
    dcid_publish_drops: AtomicU64,
    reconnect_failures: AtomicU64,
}

impl FlowStatsSlot {
    pub fn record_pending_inner_drop(&self) {
        self.pending_inner_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_quic_send_drop(&self) {
        self.quic_send_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_io_missing_owner_drop(&self) {
        self.io_missing_owner_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_io_channel_full_drop(&self) {
        self.io_channel_full_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_io_channel_disconnected_drop(&self) {
        self.io_channel_disconnected_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reverse_nat_publish_drop(&self) {
        self.reverse_nat_publish_drops
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dcid_publish_drop(&self) {
        self.dcid_publish_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconnect_failure(&self) {
        self.reconnect_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn publish(&self, state: &FlowWorkerState, quic_flow: &QuicFlow, authenticated: bool) {
        let sessions = state
            .sessions()
            .map(|session| SessionSnapshot {
                session_id: session.id.0,
                quic_flow_id: session.quic_flow_id.0,
                flow_worker_id: session.flow_worker_id,
                intercept_ifindex: session.intercept_io.ifindex,
                intercept_queue_id: session.intercept_io.queue_id,
                original: FlowSnapshot::from(&session.original),
                translated: FlowSnapshot::from(&session.nat.translated),
            })
            .collect::<Vec<_>>();
        let stats = state.stats();
        *self
            .snapshot
            .write()
            .expect("Flow stats slot is not poisoned") = FlowWorkerSnapshot {
            worker_id: quic_flow.flow_worker_id(),
            quic_flow_id: quic_flow.id().0,
            tunnel_queue_id: quic_flow.tunnel_queue_id(),
            authenticated,
            session_count: sessions.len(),
            nat_count: sessions.len(),
            reverse_nat_count: sessions.len(),
            queue_mismatch_drops: stats.queue_mismatch_drops,
            pending_inner_drops: self.pending_inner_drops.load(Ordering::Relaxed),
            quic_send_drops: self.quic_send_drops.load(Ordering::Relaxed),
            io_missing_owner_drops: self.io_missing_owner_drops.load(Ordering::Relaxed),
            io_channel_full_drops: self.io_channel_full_drops.load(Ordering::Relaxed),
            io_channel_disconnected_drops: self
                .io_channel_disconnected_drops
                .load(Ordering::Relaxed),
            reverse_nat_publish_drops: self.reverse_nat_publish_drops.load(Ordering::Relaxed),
            dcid_publish_drops: self.dcid_publish_drops.load(Ordering::Relaxed),
            reconnect_failures: self.reconnect_failures.load(Ordering::Relaxed),
            dns_query_local: stats.dns_query_local,
            dns_query_remote: stats.dns_query_remote,
            dns_response_local: stats.dns_response_local,
            dns_response_remote: stats.dns_response_remote,
            dns_servfail: stats.dns_servfail,
            dns_capacity_exhausted: stats.dns_capacity_exhausted,
            dns_nat_exhausted: stats.dns_nat_exhausted,
            dns_malformed_local_fallback: stats.dns_malformed_local_fallback,
            dns_spoofed_response_drop: stats.dns_spoofed_response_drop,
            dns_late_response_drop: stats.dns_late_response_drop,
            dns_edns_clamped: stats.dns_edns_clamped,
            dns_timeout: stats.dns_timeout,
            dns_transactions_active: stats.dns_transactions_active,
            sessions,
        };
    }

    fn snapshot(&self) -> FlowWorkerSnapshot {
        self.snapshot
            .read()
            .expect("Flow stats slot is not poisoned")
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn io_delivery_drop_counts(&self) -> (u64, u64, u64) {
        (
            self.io_missing_owner_drops.load(Ordering::Relaxed),
            self.io_channel_full_drops.load(Ordering::Relaxed),
            self.io_channel_disconnected_drops.load(Ordering::Relaxed),
        )
    }
}

#[derive(Serialize)]
struct RuntimeSnapshot {
    role: &'static str,
    io_owners: Vec<IoOwnerSnapshot>,
    flow_workers: Vec<FlowWorkerSnapshot>,
    active_dcid_count: usize,
    reverse_nat_count: usize,
    dispatch: DispatchStatsSnapshot,
}

#[derive(Serialize)]
struct IoOwnerSnapshot {
    ifindex: u32,
    queue_id: u32,
    tunnel: bool,
    intercept: bool,
    #[serde(flatten)]
    counters: IoCounters,
}

#[derive(Serialize)]
struct IoCounters {
    rx_frames: u64,
    tx_frames: u64,
    tx_drops: u64,
    passed_frames: u64,
    dispatched_frames: u64,
    dropped_frames: u64,
    unknown_dcid_drops: u64,
    invalid_quic_drops: u64,
    malformed_drops: u64,
    dispatch_drops: u64,
    dns_unknown_transaction_drops: u64,
    dns_fragmented_drops: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct FlowWorkerSnapshot {
    worker_id: usize,
    quic_flow_id: u64,
    tunnel_queue_id: u32,
    authenticated: bool,
    session_count: usize,
    nat_count: usize,
    reverse_nat_count: usize,
    queue_mismatch_drops: u64,
    pending_inner_drops: u64,
    quic_send_drops: u64,
    io_missing_owner_drops: u64,
    io_channel_full_drops: u64,
    io_channel_disconnected_drops: u64,
    reverse_nat_publish_drops: u64,
    dcid_publish_drops: u64,
    reconnect_failures: u64,
    dns_query_local: u64,
    dns_query_remote: u64,
    dns_response_local: u64,
    dns_response_remote: u64,
    dns_servfail: u64,
    dns_capacity_exhausted: u64,
    dns_nat_exhausted: u64,
    dns_malformed_local_fallback: u64,
    dns_spoofed_response_drop: u64,
    dns_late_response_drop: u64,
    dns_edns_clamped: u64,
    dns_timeout: u64,
    dns_transactions_active: u64,
    sessions: Vec<SessionSnapshot>,
}

#[derive(Clone, Debug, Serialize)]
struct SessionSnapshot {
    session_id: u64,
    quic_flow_id: u64,
    flow_worker_id: usize,
    intercept_ifindex: u32,
    intercept_queue_id: u32,
    original: FlowSnapshot,
    translated: FlowSnapshot,
}

#[derive(Clone, Debug, Serialize)]
struct FlowSnapshot {
    source: String,
    destination: String,
    source_port: u16,
    destination_port: u16,
    protocol: &'static str,
}

impl From<&crate::flow_plane::FlowKey> for FlowSnapshot {
    fn from(flow: &crate::flow_plane::FlowKey) -> Self {
        Self {
            source: flow.source.to_string(),
            destination: flow.destination.to_string(),
            source_port: flow.source_port,
            destination_port: flow.destination_port,
            protocol: match flow.protocol {
                crate::flow_plane::TransportProtocol::Tcp => "tcp",
                crate::flow_plane::TransportProtocol::Udp => "udp",
                crate::flow_plane::TransportProtocol::Icmp => "icmp",
                crate::flow_plane::TransportProtocol::Icmpv6 => "icmpv6",
            },
        }
    }
}

#[derive(Serialize)]
struct DispatchStatsSnapshot {
    channel_full_drops: u64,
    channel_disconnected_drops: u64,
    invalid_worker_drops: u64,
}

impl From<DispatchStats> for DispatchStatsSnapshot {
    fn from(stats: DispatchStats) -> Self {
        Self {
            channel_full_drops: stats.channel_full_drops,
            channel_disconnected_drops: stats.channel_disconnected_drops,
            invalid_worker_drops: stats.invalid_worker_drops,
        }
    }
}

pub fn write_snapshot(
    path: &Path,
    role: &'static str,
    io_entries: &[IoStatsEntry],
    flow_slots: &[std::sync::Arc<FlowStatsSlot>],
    dispatcher: &FlowDispatcher,
    active_dcid_count: usize,
    reverse_nat_count: usize,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let snapshot = RuntimeSnapshot {
        role,
        io_owners: io_entries
            .iter()
            .map(|entry| IoOwnerSnapshot {
                ifindex: entry.owner.ifindex,
                queue_id: entry.owner.queue_id,
                tunnel: entry.tunnel,
                intercept: entry.intercept,
                counters: entry.slot.snapshot(),
            })
            .collect(),
        flow_workers: flow_slots.iter().map(|slot| slot.snapshot()).collect(),
        active_dcid_count,
        reverse_nat_count,
        dispatch: dispatcher.stats().into(),
    };
    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(std::io::Error::other)?;
    let (temporary, mut output) = secure_stats_file(path)?;
    if let Err(error) = output.write_all(&bytes).and_then(|()| output.sync_all()) {
        drop(output);
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(output);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn secure_stats_file(path: &Path) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    for _ in 0..8 {
        let temporary = path.with_extension(format!(
            "tmp-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(output) => return Ok((temporary, output)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to create a unique stats temporary file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_plane::{
        bounded_flow_channels, DnsFlowConfig, FlowWorkerState, IoOwnerKey, QuicFlow, QuicFlowId,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    #[test]
    fn v1_unit_runtime_stats_serializes_owner_and_flow_state() {
        let io_slot = Arc::new(IoStatsSlot::default());
        io_slot.record_rx(2);
        io_slot.record_ingress(IngressOutcome::Dropped(DropReason::UnknownDcid));
        io_slot.record_ingress(IngressOutcome::Dropped(DropReason::UnknownDnsTransaction));
        io_slot.record_ingress(IngressOutcome::Dropped(DropReason::FragmentedDns));
        let io_entries = vec![IoStatsEntry {
            owner: IoOwnerKey::new(10, 1),
            tunnel: true,
            intercept: false,
            slot: io_slot,
        }];
        let flow_slot = Arc::new(FlowStatsSlot::default());
        flow_slot.record_pending_inner_drop();
        flow_slot.record_quic_send_drop();
        flow_slot.record_io_missing_owner_drop();
        flow_slot.record_io_channel_full_drop();
        flow_slot.record_io_channel_disconnected_drop();
        flow_slot.record_reverse_nat_publish_drop();
        flow_slot.record_dcid_publish_drop();
        flow_slot.record_reconnect_failure();
        let mut state =
            FlowWorkerState::new(0, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001)
                .unwrap();
        state
            .handle_dns_query(
                IoOwnerKey::new(10, 1),
                stats_dns_packet(53000, b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x07example\x00\x00\x01\x00\x01"),
                &DnsFlowConfig {
                    listen: "10.0.0.53:53".parse().unwrap(),
                    local_resolver: "192.0.2.53:53".parse().unwrap(),
                    remote_resolver: "1.1.1.1:53".parse().unwrap(),
                    remote_domains: vec!["google.com".to_string()],
                    transaction_capacity: 4,
                    timeout: std::time::Duration::from_secs(5),
                    remote_available: true,
                },
            )
            .unwrap();
        let flow = QuicFlow::new(QuicFlowId(7), 0, b"stats", 2).unwrap();
        flow_slot.publish(&state, &flow, false);
        let (dispatcher, _) = bounded_flow_channels(1, 1).unwrap();
        let path = std::env::temp_dir().join(format!(
            "new-proxy-v1-stats-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));

        write_snapshot(
            &path,
            "client",
            &io_entries,
            &[flow_slot],
            &dispatcher,
            3,
            0,
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        #[cfg(unix)]
        let stats_mode = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777
        };
        std::fs::remove_file(&path).unwrap();

        assert_eq!(value["role"], "client");
        assert_eq!(value["io_owners"][0]["ifindex"], 10);
        assert_eq!(value["io_owners"][0]["unknown_dcid_drops"], 1);
        assert_eq!(value["io_owners"][0]["dns_unknown_transaction_drops"], 1);
        assert_eq!(value["io_owners"][0]["dns_fragmented_drops"], 1);
        assert_eq!(value["flow_workers"][0]["quic_flow_id"], 7);
        assert_eq!(value["flow_workers"][0]["pending_inner_drops"], 1);
        assert_eq!(value["flow_workers"][0]["quic_send_drops"], 1);
        assert_eq!(value["flow_workers"][0]["io_missing_owner_drops"], 1);
        assert_eq!(value["flow_workers"][0]["io_channel_full_drops"], 1);
        assert_eq!(value["flow_workers"][0]["io_channel_disconnected_drops"], 1);
        assert_eq!(value["flow_workers"][0]["reverse_nat_publish_drops"], 1);
        assert_eq!(value["flow_workers"][0]["dcid_publish_drops"], 1);
        assert_eq!(value["flow_workers"][0]["reconnect_failures"], 1);
        assert_eq!(value["flow_workers"][0]["dns_query_local"], 1);
        assert_eq!(value["flow_workers"][0]["dns_edns_clamped"], 0);
        assert_eq!(value["flow_workers"][0]["dns_transactions_active"], 1);
        assert_eq!(value["active_dcid_count"], 3);
        #[cfg(unix)]
        assert_eq!(stats_mode, 0o600);
    }

    fn stats_dns_packet(source_port: u16, payload: &[u8]) -> bytes::Bytes {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 53]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&53u16.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        bytes::Bytes::from(packet)
    }
}
