use crate::flow_plane::{
    bounded_flow_channels, ActiveDcidIndex, DnsFlowConfig, DnsFlowError, FlowMessage,
    FlowWorkerError, FlowWorkerState, HandledDnsQuery, IoOwnerKey, IoRegistry, IoTransmit,
    NatBinding, OuterRoute, QuicFlow, QuicFlowId, ReverseNatDirectory, SessionLocator,
};
use crate::quic_engine::{
    pinned_client_config, server_config, QuicEngine, QuicEngineError, QuicEngineEvent,
};
use crate::v1_config::{
    ApplianceConfig, InterceptConfig, IpPolicy, MacAddress, Role, XdpAttachMode,
};
#[cfg(target_os = "linux")]
use crate::xdp_datapath::io_wakeup::IoWakeup;
use crate::xdp_datapath::io_worker::{
    DnsLocalResponseClassifier, InterceptPolicy, IoClassifierConfig,
    IoWorker as ClassifyingIoWorker,
};
use crate::xdp_datapath::loader::BpfLinkManager;
use crate::xdp_datapath::port_reservation::ensure_nat_ports_reserved;
use crate::xdp_datapath::stats::{
    preflight_snapshot_path, write_snapshot, FlowStatsSlot, IoStatsEntry, IoStatsSlot,
    RuntimeGauges, SnapshotMetadata,
};
#[cfg(target_os = "linux")]
use crate::xdp_datapath::xsk::{lookup_bpf_map, open_bpf_map, update_bpf_map, Xsk};
use bytes::Bytes;
use ipnet::IpNet;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const XSK_MAP_MAX_ENTRIES: u32 = 4096;
const POLICY_TUNNEL_PREFIXES: u8 = 0;
const POLICY_DIRECT_PREFIXES: u8 = 1;
const POLICY_ACTION_PASS: u8 = 0;
const POLICY_ACTION_REDIRECT: u8 = 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IoClassifiers {
    pub tunnel: bool,
    pub intercept: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceSpec {
    pub ifindex: u32,
    pub queue_count: u32,
    classifiers: IoClassifiers,
}

impl InterfaceSpec {
    pub const fn tunnel(ifindex: u32, queue_count: u32) -> Self {
        Self {
            ifindex,
            queue_count,
            classifiers: IoClassifiers {
                tunnel: true,
                intercept: false,
            },
        }
    }

    pub const fn intercept(ifindex: u32, queue_count: u32) -> Self {
        Self {
            ifindex,
            queue_count,
            classifiers: IoClassifiers {
                tunnel: false,
                intercept: true,
            },
        }
    }
}

pub trait XskFactory {
    type Xsk;
    type Error: Display;

    fn create(&mut self, owner: IoOwnerKey) -> Result<Self::Xsk, Self::Error>;
    fn start(&mut self, xsk: &mut Self::Xsk);
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeBuildError {
    #[error("interface {ifindex} has inconsistent queue counts: {first} and {second}")]
    QueueCountMismatch {
        ifindex: u32,
        first: u32,
        second: u32,
    },
    #[error("interface {0} has no RX queues")]
    ZeroQueues(u32),
    #[error(
        "interface {ifindex} has {queue_count} RX queues, exceeding XSK map capacity {capacity}"
    )]
    TooManyQueues {
        ifindex: u32,
        queue_count: u32,
        capacity: u32,
    },
    #[error("failed to create XSK for {owner:?}: {message}")]
    XskCreate { owner: IoOwnerKey, message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("v1 runtime is only supported on Linux")]
    UnsupportedPlatform,
    #[error("interface discovery failed: {0}")]
    Interface(String),
    #[error("BPF setup failed: {0}")]
    Bpf(String),
    #[error(transparent)]
    Build(#[from] RuntimeBuildError),
    #[error("flow channel setup failed: {0}")]
    FlowChannel(String),
    #[error("SNAT port range is too small for {0} Flow workers")]
    NatRangeTooSmall(usize),
    #[error("TLS material failed: {0}")]
    Tls(String),
    #[error("QUIC engine setup failed: {0}")]
    Quic(String),
    #[error("NAT port reservation failed: {0}")]
    PortReservation(String),
    #[error("worker thread panicked")]
    WorkerPanic,
    #[error("worker thread exited unexpectedly")]
    WorkerExited,
}

#[cfg(not(target_os = "linux"))]
pub fn run(_config: ApplianceConfig) -> Result<(), RuntimeError> {
    Err(RuntimeError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
pub fn run(config: ApplianceConfig) -> Result<(), RuntimeError> {
    preflight_snapshot_path(Path::new(&config.stats_path))
        .map_err(|error| RuntimeError::Interface(format!("StatsPath is not writable: {error}")))?;
    let prepared = PreparedRuntime::build(config)?;
    prepared.run()
}

pub fn worker_port_range(
    ports: RangeInclusive<u16>,
    worker_id: usize,
    worker_count: usize,
) -> Option<RangeInclusive<u16>> {
    if worker_count == 0 || worker_id >= worker_count || ports.is_empty() {
        return None;
    }
    let start = u32::from(*ports.start());
    let total = u32::from(*ports.end()) - start + 1;
    if total < worker_count as u32 {
        return None;
    }
    let base = total / worker_count as u32;
    let extra = total % worker_count as u32;
    let worker_id = worker_id as u32;
    let offset = worker_id * base + worker_id.min(extra);
    let length = base + u32::from(worker_id < extra);
    Some((start + offset) as u16..=(start + offset + length - 1) as u16)
}

#[derive(Debug)]
struct PreparedIo<Xsk> {
    classifiers: IoClassifiers,
    xsk: Xsk,
}

#[derive(Debug)]
pub struct XdpRuntime<Xsk> {
    owners: IoRegistry<PreparedIo<Xsk>>,
}

impl<Xsk> XdpRuntime<Xsk> {
    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    pub fn contains(&self, owner: IoOwnerKey) -> bool {
        self.owners.contains(owner)
    }

    pub fn classifiers(&self, owner: IoOwnerKey) -> Option<IoClassifiers> {
        self.owners.get(owner).map(|entry| entry.classifiers)
    }

    pub fn owners(&self) -> impl Iterator<Item = IoOwnerKey> + '_ {
        self.owners.iter().map(|(owner, _)| *owner)
    }

    fn into_entries(self) -> impl Iterator<Item = (IoOwnerKey, IoClassifiers, Xsk)> {
        self.owners
            .into_iter()
            .map(|(owner, prepared)| (owner, prepared.classifiers, prepared.xsk))
    }
}

pub fn build_runtime<F>(
    tunnel: InterfaceSpec,
    intercepts: Vec<InterfaceSpec>,
    factory: &mut F,
) -> Result<XdpRuntime<F::Xsk>, RuntimeBuildError>
where
    F: XskFactory,
{
    let interfaces = merge_interfaces(std::iter::once(tunnel).chain(intercepts))?;
    let mut prepared_owners = Vec::new();

    for (ifindex, (queue_count, classifiers)) in interfaces {
        for queue_id in 0..queue_count {
            let owner = IoOwnerKey::new(ifindex, queue_id);
            let xsk = factory
                .create(owner)
                .map_err(|error| RuntimeBuildError::XskCreate {
                    owner,
                    message: error.to_string(),
                })?;
            prepared_owners.push((owner, PreparedIo { classifiers, xsk }));
        }
    }

    for (_, prepared) in &mut prepared_owners {
        factory.start(&mut prepared.xsk);
    }

    let mut owners = IoRegistry::new();
    for (owner, prepared) in prepared_owners {
        owners
            .register(owner, prepared)
            .expect("merged interface queues produce unique IO owners");
    }

    Ok(XdpRuntime { owners })
}

fn merge_interfaces(
    specs: impl IntoIterator<Item = InterfaceSpec>,
) -> Result<BTreeMap<u32, (u32, IoClassifiers)>, RuntimeBuildError> {
    let mut interfaces = BTreeMap::new();
    for spec in specs {
        if spec.queue_count == 0 {
            return Err(RuntimeBuildError::ZeroQueues(spec.ifindex));
        }
        if spec.queue_count > XSK_MAP_MAX_ENTRIES {
            return Err(RuntimeBuildError::TooManyQueues {
                ifindex: spec.ifindex,
                queue_count: spec.queue_count,
                capacity: XSK_MAP_MAX_ENTRIES,
            });
        }
        match interfaces.entry(spec.ifindex) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((spec.queue_count, spec.classifiers));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let (queue_count, classifiers) = entry.get_mut();
                if *queue_count != spec.queue_count {
                    return Err(RuntimeBuildError::QueueCountMismatch {
                        ifindex: spec.ifindex,
                        first: *queue_count,
                        second: spec.queue_count,
                    });
                }
                classifiers.tunnel |= spec.classifiers.tunnel;
                classifiers.intercept |= spec.classifiers.intercept;
            }
        }
    }
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct InterfaceInfo {
    name: String,
    ifindex: u32,
    queue_count: u32,
    mac: [u8; 6],
    addresses: Vec<IpAddr>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct IoLinkConfig {
    interface: InterfaceInfo,
    tunnel_next_hop: Option<[u8; 6]>,
    intercept_next_hop: Option<[u8; 6]>,
}

#[cfg(target_os = "linux")]
struct LinuxXskFactory {
    mode: XdpAttachMode,
    maps: HashMap<u32, PathBuf>,
}

#[cfg(target_os = "linux")]
impl XskFactory for LinuxXskFactory {
    type Xsk = Xsk;
    type Error = io::Error;

    fn create(&mut self, owner: IoOwnerKey) -> Result<Self::Xsk, Self::Error> {
        let map = self.maps.get(&owner.ifindex).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("missing XSK map for ifindex {}", owner.ifindex),
            )
        })?;
        Xsk::create(owner, self.mode, map)
    }

    fn start(&mut self, _xsk: &mut Self::Xsk) {}
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct IoTxChannel {
    sender: SyncSender<IoTransmit>,
    wakeup: Arc<IoWakeup>,
}

#[cfg(target_os = "linux")]
struct IoRxChannel {
    receiver: Receiver<IoTransmit>,
    wakeup: Arc<IoWakeup>,
}

#[cfg(target_os = "linux")]
struct PreparedRuntime {
    config: ApplianceConfig,
    tunnel: InterfaceInfo,
    tunnel_local_ips: Vec<IpAddr>,
    intercepts: Vec<(InterceptConfig, InterfaceInfo)>,
    links: HashMap<u32, IoLinkConfig>,
    bpf_links: Vec<(u32, BpfLinkManager, IoClassifiers)>,
    io_runtime: XdpRuntime<Xsk>,
    flow_dispatcher: crate::flow_plane::FlowDispatcher,
    flow_receivers: Vec<Receiver<FlowMessage>>,
    io_senders: Arc<IoRegistry<IoTxChannel>>,
    io_receivers: HashMap<IoOwnerKey, IoRxChannel>,
    engines: Vec<QuicEngine>,
    active_dcids: Arc<RwLock<ActiveDcidIndex>>,
    reverse_nat: Arc<RwLock<ReverseNatDirectory>>,
    dns_intercept_ifindex: Option<u32>,
}

#[cfg(target_os = "linux")]
impl PreparedRuntime {
    fn build(config: ApplianceConfig) -> Result<Self, RuntimeError> {
        let tunnel = discover_interface(config.tunnel_interface.as_str())?;
        let tunnel_local_ips = resolve_tunnel_local_ips(&config, &tunnel)?;
        ensure_nat_ports_reserved(config.nat.ports.clone())
            .map_err(|error| RuntimeError::PortReservation(error.to_string()))?;
        let intercepts = config
            .intercept_interfaces
            .iter()
            .map(|intercept| {
                discover_interface(intercept.interface.as_str())
                    .map(|info| (intercept.clone(), info))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dns_intercept_ifindex =
            validate_dns_runtime_addresses(&config, &tunnel_local_ips, &intercepts)?;

        let mut unique_interfaces = BTreeMap::new();
        unique_interfaces.insert(tunnel.ifindex, tunnel.clone());
        for (_, interface) in &intercepts {
            unique_interfaces
                .entry(interface.ifindex)
                .or_insert_with(|| interface.clone());
        }

        let classifiers = merge_interfaces(
            std::iter::once(InterfaceSpec::tunnel(tunnel.ifindex, tunnel.queue_count)).chain(
                intercepts.iter().map(|(_, interface)| {
                    InterfaceSpec::intercept(interface.ifindex, interface.queue_count)
                }),
            ),
        )?;
        let local_tunnel_port = tunnel_port(&config);
        let mut bpf_links = Vec::new();
        let mut xsk_maps = HashMap::new();
        for (ifindex, interface) in &unique_interfaces {
            let link = BpfLinkManager::attach(&interface.name, config.xdp_mode)
                .map_err(|error| RuntimeError::Bpf(error.to_string()))?;
            let roles = classifiers
                .get(ifindex)
                .map(|(_, roles)| *roles)
                .expect("every interface has classifier roles");
            configure_bpf_maps(
                *ifindex,
                &link,
                &tunnel_local_ips,
                roles,
                local_tunnel_port,
                &config,
                dns_intercept_ifindex,
            )?;
            xsk_maps.insert(*ifindex, link.map_path("xsks_map"));
            bpf_links.push((*ifindex, link, roles));
        }

        let mut factory = LinuxXskFactory {
            mode: config.xdp_mode,
            maps: xsk_maps,
        };
        let io_runtime = build_runtime(
            InterfaceSpec::tunnel(tunnel.ifindex, tunnel.queue_count),
            intercepts
                .iter()
                .map(|(_, interface)| {
                    InterfaceSpec::intercept(interface.ifindex, interface.queue_count)
                })
                .collect(),
            &mut factory,
        )?;

        let (flow_dispatcher, flow_receivers) =
            bounded_flow_channels(config.flow_worker_count, config.channel_capacity)
                .map_err(|error| RuntimeError::FlowChannel(error.to_string()))?;
        let mut io_senders = IoRegistry::new();
        let mut io_receivers = HashMap::new();
        for owner in io_runtime.owners() {
            let (sender, receiver) = mpsc::sync_channel(config.channel_capacity);
            let wakeup = Arc::new(
                IoWakeup::new().map_err(|error| RuntimeError::Interface(error.to_string()))?,
            );
            io_senders
                .register(
                    owner,
                    IoTxChannel {
                        sender,
                        wakeup: wakeup.clone(),
                    },
                )
                .expect("IO runtime owners are unique");
            io_receivers.insert(owner, IoRxChannel { receiver, wakeup });
        }

        let mut links = HashMap::new();
        for interface in unique_interfaces.values() {
            links.insert(
                interface.ifindex,
                IoLinkConfig {
                    interface: interface.clone(),
                    tunnel_next_hop: (interface.ifindex == tunnel.ifindex)
                        .then(|| config.tunnel_next_hop_mac.octets()),
                    intercept_next_hop: intercepts
                        .iter()
                        .find(|(_, intercept)| intercept.ifindex == interface.ifindex)
                        .map(|(config, _)| config.next_hop_mac.octets()),
                },
            );
        }

        let engines = build_engines(&config)?;
        Ok(Self {
            config,
            tunnel,
            tunnel_local_ips,
            intercepts,
            links,
            bpf_links,
            io_runtime,
            flow_dispatcher,
            flow_receivers,
            io_senders: Arc::new(io_senders),
            io_receivers,
            engines,
            active_dcids: Arc::new(RwLock::new(ActiveDcidIndex::default())),
            reverse_nat: Arc::new(RwLock::new(ReverseNatDirectory::default())),
            dns_intercept_ifindex,
        })
    }

    fn run(mut self) -> Result<(), RuntimeError> {
        install_signal_handlers();
        EXIT_REQUESTED.store(false, Ordering::Release);
        let mut handles = Vec::new();
        let mut io_stats = Vec::new();

        for (owner, classifiers, xsk) in self.io_runtime.into_entries() {
            let channel = self
                .io_receivers
                .remove(&owner)
                .expect("every IO owner has a transmit receiver");
            let link = self
                .links
                .get(&owner.ifindex)
                .expect("every IO owner has link configuration")
                .clone();
            let dns_owner =
                classifiers.intercept && self.dns_intercept_ifindex == Some(owner.ifindex);
            let classifier = ClassifyingIoWorker::new(
                IoClassifierConfig {
                    owner,
                    tunnel: classifiers.tunnel,
                    intercept: classifiers.intercept,
                    tunnel_port: tunnel_port(&self.config),
                    tunnel_local_ips: if classifiers.tunnel {
                        self.tunnel_local_ips.clone()
                    } else {
                        Vec::new()
                    },
                    nat_return_ips: nat_return_ips(&self.config),
                    dns_listen: dns_owner
                        .then(|| self.config.dns.as_ref().map(|dns| dns.listen))
                        .flatten(),
                    dns_local_response: dns_owner
                        .then(|| dns_local_response_classifier(&self.config))
                        .flatten(),
                    dcid_len: self.config.dcid_len,
                    flow_worker_count: self.config.flow_worker_count,
                    intercept_policy: match self.config.role {
                        Role::Client => intercept_policy_from_config(&self.config.ip_policy),
                        Role::Server => {
                            InterceptPolicy::TunnelPrefixes(nat_host_prefixes(&self.config))
                        }
                    },
                },
                self.flow_dispatcher.clone(),
            );
            let active_dcids = self.active_dcids.clone();
            let reverse_nat = self.reverse_nat.clone();
            let stats = Arc::new(IoStatsSlot::default());
            io_stats.push(IoStatsEntry {
                owner,
                tunnel: classifiers.tunnel,
                intercept: classifiers.intercept,
                slot: stats.clone(),
            });
            handles.push(
                thread::Builder::new()
                    .name(format!("v1-io-{}-{}", owner.ifindex, owner.queue_id))
                    .spawn(move || {
                        io_loop(
                            xsk,
                            classifier,
                            channel,
                            active_dcids,
                            reverse_nat,
                            link,
                            stats,
                        )
                    })
                    .map_err(|error| RuntimeError::Interface(error.to_string()))?,
            );
        }

        let tunnel_queue_count = self.tunnel.queue_count;
        let tunnel_ifindex = self.tunnel.ifindex;
        let default_intercept = self
            .intercepts
            .first()
            .map(|(_, interface)| IoOwnerKey::new(interface.ifindex, 0))
            .expect("validated config contains an intercept interface");
        let local_port = tunnel_port(&self.config);
        let mut flow_stats = Vec::with_capacity(self.config.flow_worker_count);
        for (worker_id, (receiver, engine)) in self
            .flow_receivers
            .into_iter()
            .zip(self.engines)
            .enumerate()
        {
            let ports = worker_port_range(
                self.config.nat.ports.clone(),
                worker_id,
                self.config.flow_worker_count,
            )
            .ok_or(RuntimeError::NatRangeTooSmall(
                self.config.flow_worker_count,
            ))?;
            let state = FlowWorkerState::new_dual(
                worker_id,
                self.config.nat.address_v4,
                self.config.nat.address_v6,
                ports,
            )
            .map_err(|error| RuntimeError::Interface(error.to_string()))?;
            let quic_flow_id = QuicFlowId(worker_id as u64 + 1);
            let queue_seed = (worker_id as u64 + 1).to_be_bytes();
            let quic_flow = QuicFlow::new(quic_flow_id, worker_id, &queue_seed, tunnel_queue_count)
                .map_err(|error| RuntimeError::Quic(error.to_string()))?;
            let stats = Arc::new(FlowStatsSlot::default());
            flow_stats.push(stats.clone());
            let context = FlowLoopContext {
                role: self.config.role,
                worker_id,
                receiver,
                state,
                engine,
                quic_flow,
                flow_worker_count: self.config.flow_worker_count,
                tunnel_queue_count,
                tunnel_ifindex,
                default_intercept,
                local_port,
                dns_config: dns_flow_config(&self.config),
                dns_local_response: dns_local_response_classifier(&self.config),
                io_senders: self.io_senders.clone(),
                active_dcids: self.active_dcids.clone(),
                reverse_nat: self.reverse_nat.clone(),
                stats,
            };
            handles.push(
                thread::Builder::new()
                    .name(format!("v1-flow-{worker_id}"))
                    .spawn(move || flow_loop(context))
                    .map_err(|error| RuntimeError::Interface(error.to_string()))?,
            );
        }

        if let Err(error) = enable_bpf_classifiers(&self.bpf_links) {
            EXIT_REQUESTED.store(true, Ordering::Release);
            for handle in handles {
                let _ = handle.join();
            }
            return Err(error);
        }

        let stats_path = PathBuf::from(&self.config.stats_path);
        let role = match self.config.role {
            Role::Client => "client",
            Role::Server => "server",
        };
        let mut stats_metadata = SnapshotMetadata::new(role);
        let mut worker_exited = false;
        let mut xdp_parser_drops = 0;
        let mut xdp_dns_fragment_drops = 0;
        let mut stats_read_failures = 0u64;
        let mut stats_write_failures = 0u64;
        let mut last_policy_epoch = RELOAD_POLICY_EPOCH.load(Ordering::Acquire);
        while !EXIT_REQUESTED.load(Ordering::Acquire) {
            let current_policy_epoch = RELOAD_POLICY_EPOCH.load(Ordering::Acquire);
            if current_policy_epoch != last_policy_epoch {
                last_policy_epoch = current_policy_epoch;
                log::info!(
                    "SIGUSR1 received: reloading policies (epoch {})",
                    current_policy_epoch
                );
                if let Err(error) = self.config.reload_policy_from_source() {
                    log::error!("failed to reload policy configuration: {}", error);
                } else {
                    let port = tunnel_port(&self.config);
                    for (ifindex, link, roles) in &self.bpf_links {
                        if let Err(error) = configure_bpf_maps(
                            *ifindex,
                            link,
                            &self.tunnel_local_ips,
                            *roles,
                            port,
                            &self.config,
                            self.dns_intercept_ifindex,
                        ) {
                            log::error!(
                                "failed to reconfigure BPF maps for ifindex {}: {}",
                                ifindex,
                                error
                            );
                        }
                    }
                    let remote_rules = self
                        .config
                        .dns
                        .as_ref()
                        .map(|d| d.remote_domains.clone().into());
                    self.flow_dispatcher.broadcast(FlowMessage::ReloadPolicies {
                        remote_domains: remote_rules,
                    });
                    log::info!(
                        "policies successfully reloaded (epoch {})",
                        current_policy_epoch
                    );
                }
            }
            if handles.iter().any(thread::JoinHandle::is_finished) {
                worker_exited = true;
                EXIT_REQUESTED.store(true, Ordering::Release);
                break;
            }
            match read_xdp_parser_drops(&self.bpf_links) {
                Ok(drops) => xdp_parser_drops = drops,
                Err(error) => {
                    stats_read_failures = stats_read_failures.saturating_add(1);
                    log::warn!("failed to read XDP parser-drop stats: {error}");
                }
            }
            match read_xdp_dns_fragment_drops(&self.bpf_links) {
                Ok(drops) => xdp_dns_fragment_drops = drops,
                Err(error) => {
                    stats_read_failures = stats_read_failures.saturating_add(1);
                    log::warn!("failed to read XDP DNS-fragment stats: {error}");
                }
            }
            if let Err(error) = write_snapshot(
                &stats_path,
                &stats_metadata,
                &io_stats,
                &flow_stats,
                &self.flow_dispatcher,
                RuntimeGauges {
                    active_dcid_count: self
                        .active_dcids
                        .read()
                        .expect("active DCID index is not poisoned")
                        .len(),
                    reverse_nat_count: self
                        .reverse_nat
                        .read()
                        .expect("reverse NAT directory is not poisoned")
                        .len(),
                    xdp_parser_drops,
                    xdp_dns_fragment_drops,
                    stats_read_failures,
                    stats_write_failures,
                },
            ) {
                stats_write_failures = stats_write_failures.saturating_add(1);
                log::warn!("failed to write v1 stats {}: {error}", stats_path.display());
            }
            stats_metadata.advance();
            thread::sleep(Duration::from_millis(100));
        }
        let disable_result = disable_bpf_classifiers(&self.bpf_links);
        let mut worker_panicked = false;
        for handle in handles {
            if handle.join().is_err() {
                worker_panicked = true;
            }
        }
        if worker_panicked {
            return Err(RuntimeError::WorkerPanic);
        }
        if worker_exited {
            return Err(RuntimeError::WorkerExited);
        }
        disable_result?;
        if let Ok(drops) = read_xdp_parser_drops(&self.bpf_links) {
            xdp_parser_drops = drops;
        } else {
            stats_read_failures = stats_read_failures.saturating_add(1);
        }
        if let Ok(drops) = read_xdp_dns_fragment_drops(&self.bpf_links) {
            xdp_dns_fragment_drops = drops;
        } else {
            stats_read_failures = stats_read_failures.saturating_add(1);
        }
        if let Err(error) = write_snapshot(
            &stats_path,
            &stats_metadata,
            &io_stats,
            &flow_stats,
            &self.flow_dispatcher,
            RuntimeGauges {
                active_dcid_count: self
                    .active_dcids
                    .read()
                    .expect("active DCID index is not poisoned")
                    .len(),
                reverse_nat_count: self
                    .reverse_nat
                    .read()
                    .expect("reverse NAT directory is not poisoned")
                    .len(),
                xdp_parser_drops,
                xdp_dns_fragment_drops,
                stats_read_failures,
                stats_write_failures,
            },
        ) {
            log::warn!(
                "failed to write final v1 stats {}: {error}",
                stats_path.display()
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct FlowLoopContext {
    role: Role,
    worker_id: usize,
    receiver: Receiver<FlowMessage>,
    state: FlowWorkerState,
    engine: QuicEngine,
    quic_flow: QuicFlow,
    flow_worker_count: usize,
    tunnel_queue_count: u32,
    tunnel_ifindex: u32,
    default_intercept: IoOwnerKey,
    local_port: u16,
    dns_config: Option<DnsFlowConfig>,
    dns_local_response: Option<DnsLocalResponseClassifier>,
    io_senders: Arc<IoRegistry<IoTxChannel>>,
    active_dcids: Arc<RwLock<ActiveDcidIndex>>,
    reverse_nat: Arc<RwLock<ReverseNatDirectory>>,
    stats: Arc<FlowStatsSlot>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct PendingInner {
    epoch: u64,
    packets: VecDeque<Bytes>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InnerSendOutcome {
    Sent,
    Queued,
    Dropped,
}

#[cfg(target_os = "linux")]
impl PendingInner {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            packets: VecDeque::new(),
        }
    }

    fn advance(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.packets.clear();
    }

    fn push(&mut self, epoch: u64, packet: Bytes) -> bool {
        if epoch != self.epoch || self.packets.len() >= 1024 {
            return false;
        }
        self.packets.push_back(packet);
        true
    }

    fn pop_front(&mut self, epoch: u64) -> Option<Bytes> {
        (epoch == self.epoch)
            .then(|| self.packets.pop_front())
            .flatten()
    }

    fn push_front(&mut self, epoch: u64, packet: Bytes) {
        if epoch == self.epoch {
            self.packets.push_front(packet);
        }
    }
}

#[cfg(target_os = "linux")]
fn flow_loop(mut context: FlowLoopContext) {
    let mut next_stats = Instant::now();
    let mut reconnect_epoch = RECONNECT_EPOCH.load(Ordering::Acquire);
    let mut pending_inner = PendingInner::new(reconnect_epoch);
    while !EXIT_REQUESTED.load(Ordering::Acquire) {
        let requested_epoch = RECONNECT_EPOCH.load(Ordering::Acquire);
        if requested_epoch != reconnect_epoch {
            reconnect_epoch = requested_epoch;
            pending_inner.advance(reconnect_epoch);
            context.engine.close(Instant::now());
        }
        match context.receiver.recv_timeout(Duration::from_millis(2)) {
            Ok(message) => {
                handle_flow_message(&mut context, message, reconnect_epoch, &mut pending_inner);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        drain_engine(&mut context, reconnect_epoch, &mut pending_inner);
        expire_dns_transactions(&mut context);
        expire_idle_sessions(&mut context);
        if Instant::now() >= next_stats {
            context.stats.publish(
                &context.state,
                &context.quic_flow,
                context.engine.is_authenticated(),
            );
            next_stats = Instant::now() + Duration::from_millis(100);
        }
    }
    context.engine.close(Instant::now());
    drain_engine(&mut context, reconnect_epoch, &mut pending_inner);
    context.stats.publish(
        &context.state,
        &context.quic_flow,
        context.engine.is_authenticated(),
    );
}

#[cfg(target_os = "linux")]
fn expire_idle_sessions(context: &mut FlowLoopContext) {
    let Ok(expired) = context.state.expire_idle_sessions(Instant::now()) else {
        return;
    };
    if expired.is_empty() {
        return;
    }
    let mut directory = context
        .reverse_nat
        .write()
        .expect("reverse NAT directory is not poisoned");
    for session in expired {
        directory.retire(
            &session.nat,
            SessionLocator {
                flow_worker_id: context.worker_id,
                session_id: session.id,
            },
        );
    }
}

#[cfg(target_os = "linux")]
fn expire_dns_transactions(context: &mut FlowLoopContext) {
    let Some(dns_config) = context.dns_config.clone() else {
        return;
    };
    let Ok(transmits) = context
        .state
        .expire_dns_transactions(Instant::now(), &dns_config)
    else {
        return;
    };
    for expired in transmits {
        retire_dns_reverse(context, &expired.binding, expired.transaction_id);
        send_io(&context.io_senders, expired.transmit, &context.stats);
    }
}

#[cfg(target_os = "linux")]
fn handle_flow_message(
    context: &mut FlowLoopContext,
    message: FlowMessage,
    reconnect_epoch: u64,
    pending_inner: &mut PendingInner,
) {
    match message {
        FlowMessage::ReloadPolicies { remote_domains } => {
            if let (Some(dns_config), Some(remote_domains)) =
                (&mut context.dns_config, remote_domains)
            {
                dns_config.remote_domains = remote_domains;
                log::info!(
                    "flow worker {} updated remote domain rules",
                    context.worker_id
                );
            }
        }
        FlowMessage::InterceptIngress {
            io_owner,
            packet,
            expected_locator,
        } => match context.role {
            Role::Client => {
                if let Some(mut dns_config) = context.dns_config.clone() {
                    if context
                        .dns_local_response
                        .as_ref()
                        .is_some_and(|classifier| {
                            is_dns_local_resolver_candidate(&packet, classifier)
                        })
                    {
                        let dns_reverse =
                            expected_locator.is_some_and(|locator| {
                                crate::flow_plane::parse_flow_key(&packet).ok().is_some_and(
                                    |flow| context.state.dns_reverse_matches(&flow, locator),
                                )
                            });
                        if dns_reverse {
                            if let Ok(Some(restored)) = context.state.handle_dns_response(packet) {
                                retire_dns_reverse(
                                    context,
                                    &restored.binding,
                                    restored.transaction_id,
                                );
                                send_io(
                                    &context.io_senders,
                                    IoTransmit {
                                        target: restored.local_target,
                                        packet: restored.packet,
                                        outer: None,
                                    },
                                    &context.stats,
                                );
                            }
                            return;
                        }
                        if let Some(locator) = expected_locator {
                            if let Ok(Some(restored)) =
                                context.state.handle_reverse_for(packet, locator)
                            {
                                send_io(
                                    &context.io_senders,
                                    IoTransmit {
                                        target: restored.local_target,
                                        packet: restored.packet,
                                        outer: None,
                                    },
                                    &context.stats,
                                );
                            }
                            return;
                        }
                    }
                    dns_config.remote_available = context.engine.is_authenticated();
                    match context
                        .state
                        .handle_dns_query(io_owner, packet.clone(), &dns_config)
                    {
                        Ok(HandledDnsQuery::Local {
                            transmit,
                            binding,
                            transaction_id,
                        }) => {
                            if publish_dns_reverse(context, &binding, transaction_id) {
                                send_io(&context.io_senders, transmit, &context.stats);
                            } else if let Ok(Some(aborted)) =
                                context.state.abort_dns_transaction(&binding, &dns_config)
                            {
                                send_io(&context.io_senders, aborted.transmit, &context.stats);
                            }
                            return;
                        }
                        Ok(HandledDnsQuery::Servfail(transmit)) => {
                            send_io(&context.io_senders, transmit, &context.stats);
                            return;
                        }
                        Ok(HandledDnsQuery::Remote {
                            packet,
                            binding,
                            transaction_id,
                        }) => {
                            if publish_dns_reverse(context, &binding, transaction_id) {
                                send_or_queue_inner(
                                    context,
                                    packet,
                                    reconnect_epoch,
                                    pending_inner,
                                );
                            } else if let Ok(Some(aborted)) =
                                context.state.abort_dns_transaction(&binding, &dns_config)
                            {
                                send_io(&context.io_senders, aborted.transmit, &context.stats);
                            }
                            return;
                        }
                        Err(FlowWorkerError::Dns(DnsFlowError::NotDnsQuery)) => {}
                        Err(_) => return,
                    }
                }
                if !context.engine.is_authenticated() {
                    context.stats.record_pending_inner_drop();
                    return;
                }
                let tunnel_target =
                    IoOwnerKey::new(context.tunnel_ifindex, context.quic_flow.tunnel_queue_id());
                if let Ok(handled) = context.state.handle_intercept(
                    io_owner,
                    packet,
                    &context.quic_flow,
                    tunnel_target,
                ) {
                    if publish_session(context, handled.session_id)
                        && send_or_queue_inner(
                            context,
                            handled.transmit.packet,
                            reconnect_epoch,
                            pending_inner,
                        ) == InnerSendOutcome::Dropped
                    {
                        retire_session(context, handled.session_id);
                    }
                }
            }
            Role::Server => {
                let Some(locator) = expected_locator else {
                    return;
                };
                if locator.flow_worker_id != context.worker_id {
                    return;
                }
                if let Ok(Some(restored)) = context
                    .state
                    .handle_server_reverse(io_owner, packet, locator)
                {
                    send_or_queue_inner(context, restored.packet, reconnect_epoch, pending_inner);
                }
            }
        },
        FlowMessage::TunnelIngress {
            remote,
            local_ip,
            packet,
            ..
        } => {
            context
                .engine
                .handle_outer(Instant::now(), remote, Some(local_ip), packet);
        }
    }
}

#[cfg(target_os = "linux")]
fn send_or_queue_inner(
    context: &mut FlowLoopContext,
    packet: Bytes,
    reconnect_epoch: u64,
    pending_inner: &mut PendingInner,
) -> InnerSendOutcome {
    match context.engine.send_inner(Instant::now(), packet.clone()) {
        Ok(()) => InnerSendOutcome::Sent,
        Err(QuicEngineError::NotAuthenticated | QuicEngineError::NotConnected) => {
            if pending_inner.push(reconnect_epoch, packet) {
                InnerSendOutcome::Queued
            } else {
                context.stats.record_pending_inner_drop();
                InnerSendOutcome::Dropped
            }
        }
        Err(_) => {
            context.stats.record_quic_send_drop();
            InnerSendOutcome::Dropped
        }
    }
}

#[cfg(target_os = "linux")]
fn drain_engine(
    context: &mut FlowLoopContext,
    reconnect_epoch: u64,
    pending_inner: &mut PendingInner,
) {
    while let Some(event) = context.engine.poll(Instant::now()) {
        match event {
            QuicEngineEvent::Transmit(transmit) => {
                for packet in split_outer_transmit(transmit.contents, transmit.segment_size) {
                    send_io(
                        &context.io_senders,
                        IoTransmit {
                            target: IoOwnerKey::new(
                                context.tunnel_ifindex,
                                context.quic_flow.tunnel_queue_id(),
                            ),
                            packet,
                            outer: Some(OuterRoute {
                                source_ip: transmit.source_ip,
                                source_port: context.local_port,
                                destination: transmit.destination,
                            }),
                        },
                        &context.stats,
                    );
                }
            }
            QuicEngineEvent::Authenticated => {
                while let Some(packet) = pending_inner.pop_front(reconnect_epoch) {
                    if context
                        .engine
                        .send_inner(Instant::now(), packet.clone())
                        .is_err()
                    {
                        pending_inner.push_front(reconnect_epoch, packet);
                        break;
                    }
                }
            }
            QuicEngineEvent::InnerPacket(packet) => match context.role {
                Role::Server => {
                    if let Ok(handled) = context.state.handle_server_inner(
                        context.default_intercept,
                        packet,
                        &context.quic_flow,
                    ) {
                        if publish_session(context, handled.session_id) {
                            send_io(&context.io_senders, handled.transmit, &context.stats);
                        }
                    }
                }
                Role::Client => {
                    let dns_flow = crate::flow_plane::parse_flow_key(&packet)
                        .ok()
                        .filter(|flow| context.state.has_dns_reverse(flow));
                    if dns_flow.is_some() {
                        match context.state.handle_dns_response(packet.clone()) {
                            Ok(Some(restored)) => {
                                retire_dns_reverse(
                                    context,
                                    &restored.binding,
                                    restored.transaction_id,
                                );
                                send_io(
                                    &context.io_senders,
                                    IoTransmit {
                                        target: restored.local_target,
                                        packet: restored.packet,
                                        outer: None,
                                    },
                                    &context.stats,
                                );
                                continue;
                            }
                            Ok(None) => {}
                            Err(_) => continue,
                        }
                    }
                    if let Ok(Some(restored)) = context.state.handle_reverse(packet) {
                        send_io(
                            &context.io_senders,
                            IoTransmit {
                                target: restored.local_target,
                                packet: restored.packet,
                                outer: None,
                            },
                            &context.stats,
                        );
                    }
                }
            },
            QuicEngineEvent::DcidPublished(dcid) => {
                if context
                    .active_dcids
                    .write()
                    .expect("active DCID index is not poisoned")
                    .publish_for_flow(&dcid, &context.quic_flow)
                    .is_err()
                {
                    context.stats.record_dcid_publish_drop();
                    context.engine.close(Instant::now());
                }
            }
            QuicEngineEvent::DcidStaged(dcid) => {
                if context
                    .active_dcids
                    .write()
                    .expect("active DCID index is not poisoned")
                    .stage_for_flow(&dcid, &context.quic_flow)
                    .is_err()
                {
                    context.stats.record_dcid_publish_drop();
                    context.engine.close(Instant::now());
                }
            }
            QuicEngineEvent::DcidRetired(dcid) => {
                context
                    .active_dcids
                    .write()
                    .expect("active DCID index is not poisoned")
                    .retire_for_flow(&dcid, &context.quic_flow);
            }
            QuicEngineEvent::Replaced(dcids) => {
                let published = context
                    .active_dcids
                    .write()
                    .expect("active DCID index is not poisoned")
                    .publish_batch_for_flow(&dcids, &context.quic_flow)
                    .is_ok();
                context
                    .engine
                    .resolve_candidate_replacement(Instant::now(), published);
                if published {
                    pending_inner.advance(reconnect_epoch);
                } else {
                    context.stats.record_dcid_publish_drop();
                }
            }
            QuicEngineEvent::Closed => {
                pending_inner.advance(reconnect_epoch);
                let closed_flow_id = context.quic_flow.id();
                if let Some(config) = context.dns_config.as_ref() {
                    let _ = context.state.abort_remote_dns_transactions(config);
                }
                context
                    .active_dcids
                    .write()
                    .expect("active DCID index is not poisoned")
                    .close_flow(closed_flow_id);
                if !EXIT_REQUESTED.load(Ordering::Acquire) {
                    let next_flow_id =
                        QuicFlowId(closed_flow_id.0 + context.flow_worker_count as u64);
                    let queue_seed = next_flow_id.0.to_be_bytes();
                    if let Ok(quic_flow) = QuicFlow::new(
                        next_flow_id,
                        context.worker_id,
                        &queue_seed,
                        context.tunnel_queue_count,
                    ) {
                        context.quic_flow = quic_flow;
                        let _ = context.state.rebind_quic_flow(closed_flow_id, next_flow_id);
                        if context.role == Role::Client
                            && context.engine.reconnect_client().is_err()
                        {
                            context.stats.record_reconnect_failure();
                        }
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn retire_quic_flow_state(context: &mut FlowLoopContext) {
    let removed = context
        .state
        .remove_by_quic_flow(context.quic_flow.id())
        .unwrap_or_default();
    let removed_dns = context
        .dns_config
        .as_ref()
        .and_then(|config| context.state.abort_remote_dns_transactions(config).ok())
        .unwrap_or_default();
    {
        let mut directory = context
            .reverse_nat
            .write()
            .expect("reverse NAT directory is not poisoned");
        for session in removed {
            directory.retire(
                &session.nat,
                SessionLocator {
                    flow_worker_id: context.worker_id,
                    session_id: session.id,
                },
            );
        }
        for transaction in &removed_dns {
            directory.retire(
                &transaction.binding,
                SessionLocator {
                    flow_worker_id: context.worker_id,
                    session_id: transaction.transaction_id,
                },
            );
        }
    }
    for transaction in removed_dns {
        send_io(&context.io_senders, transaction.transmit, &context.stats);
    }
}

#[cfg(target_os = "linux")]
fn split_outer_transmit(contents: Bytes, segment_size: Option<usize>) -> Vec<Bytes> {
    let Some(segment_size) = segment_size.filter(|size| *size > 0 && *size < contents.len()) else {
        return vec![contents];
    };
    (0..contents.len())
        .step_by(segment_size)
        .map(|offset| contents.slice(offset..contents.len().min(offset + segment_size)))
        .collect()
}

#[cfg(target_os = "linux")]
fn publish_session(
    context: &mut FlowLoopContext,
    session_id: crate::flow_plane::SessionId,
) -> bool {
    let Some(session) = context.state.session(session_id) else {
        return false;
    };
    let binding = session.nat.clone();
    let result = context
        .reverse_nat
        .write()
        .expect("reverse NAT directory is not poisoned")
        .publish(
            &binding,
            SessionLocator {
                flow_worker_id: context.worker_id,
                session_id,
            },
        );
    if result.is_err() {
        context.stats.record_reverse_nat_publish_drop();
        let _ = context.state.remove_session(session_id);
        return false;
    }
    true
}

#[cfg(target_os = "linux")]
fn retire_session(context: &mut FlowLoopContext, session_id: crate::flow_plane::SessionId) {
    let Ok(session) = context.state.remove_session(session_id) else {
        return;
    };
    context
        .reverse_nat
        .write()
        .expect("reverse NAT directory is not poisoned")
        .retire(
            &session.nat,
            SessionLocator {
                flow_worker_id: context.worker_id,
                session_id,
            },
        );
}

#[cfg(target_os = "linux")]
fn dns_local_response_classifier(config: &ApplianceConfig) -> Option<DnsLocalResponseClassifier> {
    let dns = config.dns.as_ref()?;
    let nat_ip = match dns.local_resolver {
        SocketAddr::V4(_) => config.nat.address_v4.map(IpAddr::V4),
        SocketAddr::V6(_) => config.nat.address_v6.map(IpAddr::V6),
    }?;
    Some(DnsLocalResponseClassifier {
        resolver: dns.local_resolver,
        nat_ip,
        nat_ports: config.nat.ports.clone(),
    })
}

#[cfg(target_os = "linux")]
fn is_dns_local_resolver_candidate(
    packet: &Bytes,
    classifier: &DnsLocalResponseClassifier,
) -> bool {
    crate::flow_plane::parse_flow_key(packet).is_ok_and(|flow| {
        flow.protocol == crate::flow_plane::TransportProtocol::Udp
            && flow.source == classifier.resolver.ip()
            && flow.source_port == classifier.resolver.port()
            && flow.destination == classifier.nat_ip
            && classifier.nat_ports.contains(&flow.destination_port)
    })
}

#[cfg(target_os = "linux")]
fn publish_dns_reverse(
    context: &mut FlowLoopContext,
    binding: &NatBinding,
    transaction_id: crate::flow_plane::SessionId,
) -> bool {
    let result = context
        .reverse_nat
        .write()
        .expect("reverse NAT directory is not poisoned")
        .publish(
            binding,
            SessionLocator {
                flow_worker_id: context.worker_id,
                session_id: transaction_id,
            },
        );
    if result.is_err() {
        context.stats.record_reverse_nat_publish_drop();
        return false;
    }
    true
}

#[cfg(target_os = "linux")]
fn retire_dns_reverse(
    context: &mut FlowLoopContext,
    binding: &NatBinding,
    transaction_id: crate::flow_plane::SessionId,
) {
    context
        .reverse_nat
        .write()
        .expect("reverse NAT directory is not poisoned")
        .retire(
            binding,
            SessionLocator {
                flow_worker_id: context.worker_id,
                session_id: transaction_id,
            },
        );
}

#[cfg(target_os = "linux")]
fn send_io(senders: &IoRegistry<IoTxChannel>, transmit: IoTransmit, stats: &FlowStatsSlot) {
    let Some(channel) = senders.get(transmit.target) else {
        stats.record_io_missing_owner_drop();
        return;
    };
    match channel.sender.try_send(transmit) {
        Ok(()) => {
            if let Err(error) = channel.wakeup.notify() {
                log::warn!("failed to wake IO worker: {error}");
            }
        }
        Err(TrySendError::Full(_)) => stats.record_io_channel_full_drop(),
        Err(TrySendError::Disconnected(_)) => stats.record_io_channel_disconnected_drop(),
    }
}

#[cfg(target_os = "linux")]
fn io_loop(
    mut xsk: Xsk,
    classifier: ClassifyingIoWorker,
    channel: IoRxChannel,
    active_dcids: Arc<RwLock<ActiveDcidIndex>>,
    reverse_nat: Arc<RwLock<ReverseNatDirectory>>,
    link: IoLinkConfig,
    stats: Arc<IoStatsSlot>,
) {
    const IO_BATCH_SIZE: usize = 64;
    const FRAME_BUFFER_CAPACITY: usize = 4096;
    let mut tx_frames = (0..IO_BATCH_SIZE)
        .map(|_| Vec::with_capacity(FRAME_BUFFER_CAPACITY))
        .collect::<Vec<_>>();
    while !EXIT_REQUESTED.load(Ordering::Acquire) {
        let received = xsk.receive_with(IO_BATCH_SIZE as u32, |frame| {
            let outcome = classifier.handle_frame(
                frame,
                &active_dcids
                    .read()
                    .expect("active DCID index is not poisoned"),
                &reverse_nat
                    .read()
                    .expect("reverse NAT directory is not poisoned"),
            );
            stats.record_ingress(outcome);
        });
        stats.record_rx(received);

        let mut transmitted = false;
        loop {
            let mut tx_count = 0;
            while tx_count < IO_BATCH_SIZE {
                match channel.receiver.try_recv() {
                    Ok(transmit) => {
                        if fill_ethernet_frame(&link, &transmit, &mut tx_frames[tx_count]) {
                            tx_count += 1;
                        } else {
                            stats.record_tx_drop();
                        }
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            if tx_count == 0 {
                break;
            }
            let sent = xsk.transmit_batch(&tx_frames[..tx_count]).unwrap_or(0);
            transmitted |= sent > 0;
            for _ in 0..sent {
                stats.record_tx();
            }
            for _ in sent..tx_count {
                stats.record_tx_drop();
            }
        }
        if received == 0 && !transmitted {
            let mut descriptors = [
                libc::pollfd {
                    fd: xsk.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: channel.wakeup.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    100,
                )
            };
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
            if result > 0 && descriptors[1].revents & libc::POLLIN != 0 {
                if channel.wakeup.drain().is_err() {
                    break;
                }
                channel.wakeup.clear_pending();
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn fill_ethernet_frame(link: &IoLinkConfig, transmit: &IoTransmit, frame: &mut Vec<u8>) -> bool {
    let (next_hop, ether_type, payload_len) = match &transmit.outer {
        Some(route) => {
            let (ether_type, header_len) = match route.destination {
                SocketAddr::V4(_) => (0x0800, 28),
                SocketAddr::V6(_) => (0x86dd, 48),
            };
            (
                match link.tunnel_next_hop {
                    Some(next_hop) => next_hop,
                    None => return false,
                },
                ether_type,
                header_len + transmit.packet.len(),
            )
        }
        None => {
            let ether_type = match transmit.packet.first().map(|byte| byte >> 4) {
                Some(4) => 0x0800,
                Some(6) => 0x86dd,
                _ => return false,
            };
            (
                match link.intercept_next_hop {
                    Some(next_hop) => next_hop,
                    None => return false,
                },
                ether_type,
                transmit.packet.len(),
            )
        }
    };
    frame.clear();
    frame.resize(14 + payload_len, 0);
    frame[..6].copy_from_slice(&next_hop);
    frame[6..12].copy_from_slice(&link.interface.mac);
    frame[12..14].copy_from_slice(&u16::to_be_bytes(ether_type));
    match &transmit.outer {
        Some(route) => {
            if fill_outer_packet(&link.interface, route, &transmit.packet, &mut frame[14..])
                .is_none()
            {
                return false;
            }
        }
        None => frame[14..].copy_from_slice(&transmit.packet),
    }
    true
}

#[cfg(target_os = "linux")]
fn fill_outer_packet(
    interface: &InterfaceInfo,
    route: &OuterRoute,
    payload: &[u8],
    packet: &mut [u8],
) -> Option<()> {
    match route.destination {
        SocketAddr::V4(destination) => {
            let source = match route.source_ip {
                Some(IpAddr::V4(source)) => source,
                None => interface.ipv4?,
                Some(IpAddr::V6(_)) => return None,
            };
            fill_ipv4_udp(
                packet,
                source,
                *destination.ip(),
                route.source_port,
                destination.port(),
                payload,
            );
        }
        SocketAddr::V6(destination) => {
            let source = match route.source_ip {
                Some(IpAddr::V6(source)) => source,
                None => interface.ipv6?,
                Some(IpAddr::V4(_)) => return None,
            };
            fill_ipv6_udp(
                packet,
                source,
                *destination.ip(),
                route.source_port,
                destination.port(),
                payload,
            );
        }
    }
    Some(())
}

#[cfg(all(target_os = "linux", test))]
fn build_ipv4_udp(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    fill_ipv4_udp(
        &mut packet,
        source,
        destination,
        source_port,
        destination_port,
        payload,
    );
    packet
}

#[cfg(target_os = "linux")]
fn fill_ipv4_udp(
    packet: &mut [u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    debug_assert_eq!(packet.len(), total_len);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    let udp_checksum = transport_checksum(&packet[12..20], 17, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
}

#[cfg(all(target_os = "linux", test))]
fn build_ipv6_udp(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut packet = vec![0u8; 40 + udp_len];
    fill_ipv6_udp(
        &mut packet,
        source,
        destination,
        source_port,
        destination_port,
        payload,
    );
    packet
}

#[cfg(target_os = "linux")]
fn fill_ipv6_udp(
    packet: &mut [u8],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) {
    let udp_len = 8 + payload.len();
    debug_assert_eq!(packet.len(), 40 + udp_len);
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[48..].copy_from_slice(payload);
    let udp_len = (udp_len as u32).to_be_bytes();
    let next_header = [0, 0, 0, 17];
    let udp_checksum = checksum_parts(&[&packet[8..40], &udp_len, &next_header, &packet[40..]]);
    let udp_checksum = if udp_checksum == 0 {
        0xffff
    } else {
        udp_checksum
    };
    packet[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
}

#[cfg(target_os = "linux")]
fn transport_checksum(pseudo: &[u8], protocol: u8, transport: &[u8]) -> u16 {
    let protocol_and_len = [
        0,
        protocol,
        (transport.len() >> 8) as u8,
        transport.len() as u8,
    ];
    let checksum = checksum_parts(&[pseudo, &protocol_and_len, transport]);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

#[cfg(target_os = "linux")]
fn checksum(bytes: &[u8]) -> u16 {
    checksum_parts(&[bytes])
}

#[cfg(target_os = "linux")]
fn checksum_parts(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut high_byte = None;
    for part in parts {
        let mut offset = 0;
        if let Some(high) = high_byte.take() {
            if let Some(&low) = part.first() {
                sum += u32::from(u16::from_be_bytes([high, low]));
                offset = 1;
            } else {
                high_byte = Some(high);
                continue;
            }
        }
        let mut chunks = part[offset..].chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        high_byte = chunks.remainder().first().copied();
    }
    if let Some(high) = high_byte {
        sum += u32::from(high) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(target_os = "linux")]
fn build_engines(config: &ApplianceConfig) -> Result<Vec<QuicEngine>, RuntimeError> {
    match config.role {
        Role::Client => {
            let fingerprint = config
                .server_certificate_sha256
                .expect("validated client certificate fingerprint");
            let client_config = pinned_client_config(fingerprint)
                .map_err(|error| RuntimeError::Tls(error.to_string()))?;
            let endpoint = config.endpoint.expect("validated client endpoint");
            (0..config.flow_worker_count)
                .map(|worker_id| {
                    QuicEngine::client_for_worker(
                        client_config.clone(),
                        endpoint,
                        "new-proxy-v1",
                        config.shared_key,
                        config.dcid_len,
                        worker_id,
                        config.flow_worker_count,
                    )
                    .map_err(|error| RuntimeError::Quic(error.to_string()))
                })
                .collect()
        }
        Role::Server => {
            let certificate = std::fs::read(
                config
                    .server_certificate
                    .as_ref()
                    .expect("validated server certificate"),
            )
            .map_err(|error| RuntimeError::Tls(error.to_string()))?;
            let private_key = std::fs::read(
                config
                    .server_private_key
                    .as_ref()
                    .expect("validated server private key"),
            )
            .map_err(|error| RuntimeError::Tls(error.to_string()))?;
            let server = server_config(certificate, private_key)
                .map_err(|error| RuntimeError::Tls(error.to_string()))?;
            (0..config.flow_worker_count)
                .map(|worker_id| {
                    QuicEngine::server_for_worker(
                        server.clone(),
                        config.shared_key,
                        config.dcid_len,
                        worker_id,
                        config.flow_worker_count,
                    )
                    .map_err(|error| RuntimeError::Quic(error.to_string()))
                })
                .collect()
        }
    }
}

#[cfg(target_os = "linux")]
fn discover_interface(name: &str) -> Result<InterfaceInfo, RuntimeError> {
    let c_name = CString::new(name).map_err(|error| RuntimeError::Interface(error.to_string()))?;
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if ifindex == 0 {
        return Err(RuntimeError::Interface(
            io::Error::last_os_error().to_string(),
        ));
    }
    let queue_path = format!("/sys/class/net/{name}/queues");
    let queue_count = std::fs::read_dir(queue_path)
        .map_err(|error| RuntimeError::Interface(error.to_string()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("rx-"))
        .count() as u32;
    if queue_count == 0 {
        return Err(RuntimeBuildError::ZeroQueues(ifindex).into());
    }
    let mac_text = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
        .map_err(|error| RuntimeError::Interface(error.to_string()))?;
    let mac = MacAddress::parse(mac_text.trim())
        .map_err(|error| RuntimeError::Interface(error.to_string()))?
        .octets();
    let addresses = interface_addresses(name)?;
    let ipv4 = addresses.iter().find_map(|address| match address {
        IpAddr::V4(address) => Some(*address),
        IpAddr::V6(_) => None,
    });
    let ipv6 = addresses.iter().find_map(|address| match address {
        IpAddr::V4(_) => None,
        IpAddr::V6(address) => Some(*address),
    });
    Ok(InterfaceInfo {
        name: name.to_string(),
        ifindex,
        queue_count,
        mac,
        addresses,
        ipv4,
        ipv6,
    })
}

#[cfg(target_os = "linux")]
fn interface_addresses(name: &str) -> Result<Vec<IpAddr>, RuntimeError> {
    let mut addresses = std::ptr::null_mut::<libc::ifaddrs>();
    if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
        return Err(RuntimeError::Interface(
            io::Error::last_os_error().to_string(),
        ));
    }
    let mut found = Vec::new();
    let mut current = addresses;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null()
            && unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() == name.as_bytes()
            && !entry.ifa_addr.is_null()
        {
            let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET {
                let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                found.push(IpAddr::V4(Ipv4Addr::from(
                    address.sin_addr.s_addr.to_ne_bytes(),
                )));
            } else if family == libc::AF_INET6 {
                let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                let candidate = Ipv6Addr::from(address.sin6_addr.s6_addr);
                if !candidate.is_unicast_link_local() {
                    found.push(IpAddr::V6(candidate));
                }
            }
        }
        current = entry.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(addresses);
    }
    found.sort_unstable();
    found.dedup();
    Ok(found)
}

#[cfg(target_os = "linux")]
fn resolve_tunnel_local_ips(
    config: &ApplianceConfig,
    tunnel: &InterfaceInfo,
) -> Result<Vec<IpAddr>, RuntimeError> {
    match config.role {
        Role::Client => {
            let endpoint = config.endpoint.expect("validated client endpoint");
            let candidates = tunnel
                .addresses
                .iter()
                .copied()
                .filter(|address| address.is_ipv4() == endpoint.is_ipv4())
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                return Err(RuntimeError::Interface(format!(
                    "tunnel interface {} must have exactly one address matching Endpoint family",
                    tunnel.name
                )));
            }
            Ok(candidates)
        }
        Role::Server => {
            let listen_ip = config.listen.expect("validated server listen").ip();
            if !tunnel.addresses.contains(&listen_ip) {
                return Err(RuntimeError::Interface(format!(
                    "Tunnel.Listen address {listen_ip} does not belong to interface {}",
                    tunnel.name
                )));
            }
            Ok(vec![listen_ip])
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_dns_runtime_addresses(
    config: &ApplianceConfig,
    tunnel_local_ips: &[IpAddr],
    intercepts: &[(InterceptConfig, InterfaceInfo)],
) -> Result<Option<u32>, RuntimeError> {
    let Some(dns) = &config.dns else {
        return Ok(None);
    };
    let listen = dns.listen.ip();
    if tunnel_local_ips.contains(&listen)
        || Some(listen) == config.nat.address_v4.map(IpAddr::V4)
        || Some(listen) == config.nat.address_v6.map(IpAddr::V6)
    {
        return Err(RuntimeError::Interface(format!(
            "DNS.Listen address {listen} must be distinct from tunnel and NAT addresses"
        )));
    }
    let owners = intercepts
        .iter()
        .filter(|(_, interface)| interface.addresses.contains(&listen))
        .map(|(intercept, interface)| (intercept.interface.as_str(), interface.ifindex))
        .collect::<Vec<_>>();
    if owners.len() != 1 {
        let names = owners.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        return Err(RuntimeError::Interface(format!(
            "DNS.Listen address {listen} must belong to exactly one intercept interface, got {names:?}"
        )));
    }
    Ok(Some(owners[0].1))
}

#[cfg(target_os = "linux")]
fn configure_bpf_maps(
    ifindex: u32,
    link: &BpfLinkManager,
    tunnel_local_ips: &[IpAddr],
    roles: IoClassifiers,
    port: u16,
    config: &ApplianceConfig,
    dns_intercept_ifindex: Option<u32>,
) -> Result<(), RuntimeError> {
    update_pinned_map(&link.map_path("tunnel_port"), &0u32, &port.to_be())?;
    update_pinned_map(&link.map_path("role_flags"), &0u32, &0u8)?;
    let tunnel_ipv4 = tunnel_local_ips.iter().find_map(|address| match address {
        IpAddr::V4(address) => Some(*address),
        IpAddr::V6(_) => None,
    });
    let tunnel_ipv6 = tunnel_local_ips.iter().find_map(|address| match address {
        IpAddr::V4(_) => None,
        IpAddr::V6(address) => Some(*address),
    });
    let tunnel_ip_flags = u8::from(tunnel_ipv4.is_some()) | (u8::from(tunnel_ipv6.is_some()) << 1);
    update_pinned_map(&link.map_path("tunnel_ip_flags"), &0u32, &tunnel_ip_flags)?;
    if let Some(address) = tunnel_ipv4 {
        update_pinned_map(
            &link.map_path("tunnel_v4"),
            &0u32,
            &u32::from_ne_bytes(address.octets()),
        )?;
    }
    if let Some(address) = tunnel_ipv6 {
        update_pinned_map(
            &link.map_path("tunnel_v6"),
            &0u32,
            &TunnelV6Value {
                address: address.octets(),
            },
        )?;
    }
    let dns_owner = roles.intercept && dns_intercept_ifindex == Some(ifindex);
    let dns_listen = dns_owner
        .then(|| config.dns.as_ref().map(|dns| dns.listen.ip()))
        .flatten();
    let dns_ipv4 = match dns_listen {
        Some(IpAddr::V4(address)) => Some(address),
        _ => None,
    };
    let dns_ipv6 = match dns_listen {
        Some(IpAddr::V6(address)) => Some(address),
        _ => None,
    };
    let dns_ip_flags = u8::from(dns_ipv4.is_some()) | (u8::from(dns_ipv6.is_some()) << 1);
    update_pinned_map(&link.map_path("dns_ip_flags"), &0u32, &dns_ip_flags)?;
    if let Some(address) = dns_ipv4 {
        update_pinned_map(
            &link.map_path("dns_v4"),
            &0u32,
            &u32::from_ne_bytes(address.octets()),
        )?;
    }
    if let Some(address) = dns_ipv6 {
        update_pinned_map(
            &link.map_path("dns_v6"),
            &0u32,
            &TunnelV6Value {
                address: address.octets(),
            },
        )?;
    }
    let dns_local_resolver = dns_owner
        .then_some(config.dns.as_ref())
        .flatten()
        .map(|dns| dns.local_resolver);
    let dns_local_ipv4 = match dns_local_resolver {
        Some(SocketAddr::V4(address)) => config
            .nat
            .address_v4
            .map(|nat| (*address.ip(), nat, address.port())),
        _ => None,
    };
    let dns_local_ipv6 = match dns_local_resolver {
        Some(SocketAddr::V6(address)) => config
            .nat
            .address_v6
            .map(|nat| (*address.ip(), nat, address.port())),
        _ => None,
    };
    let dns_local_flags =
        u8::from(dns_local_ipv4.is_some()) | (u8::from(dns_local_ipv6.is_some()) << 1);
    update_pinned_map(&link.map_path("dns_local_flags"), &0u32, &dns_local_flags)?;
    if let Some((resolver, nat, port)) = dns_local_ipv4 {
        update_pinned_map(
            &link.map_path("dns_local_resolver_v4"),
            &0u32,
            &u32::from_ne_bytes(resolver.octets()),
        )?;
        update_pinned_map(
            &link.map_path("dns_nat_v4"),
            &0u32,
            &u32::from_ne_bytes(nat.octets()),
        )?;
        update_pinned_map(
            &link.map_path("dns_local_resolver_port"),
            &0u32,
            &port.to_be(),
        )?;
        update_pinned_map(
            &link.map_path("dns_nat_port_start"),
            &0u32,
            config.nat.ports.start(),
        )?;
        update_pinned_map(
            &link.map_path("dns_nat_port_end"),
            &0u32,
            config.nat.ports.end(),
        )?;
    }
    if let Some((resolver, nat, port)) = dns_local_ipv6 {
        update_pinned_map(
            &link.map_path("dns_local_resolver_v6"),
            &0u32,
            &TunnelV6Value {
                address: resolver.octets(),
            },
        )?;
        update_pinned_map(
            &link.map_path("dns_nat_v6"),
            &0u32,
            &TunnelV6Value {
                address: nat.octets(),
            },
        )?;
        update_pinned_map(
            &link.map_path("dns_local_resolver_port"),
            &0u32,
            &port.to_be(),
        )?;
        update_pinned_map(
            &link.map_path("dns_nat_port_start"),
            &0u32,
            config.nat.ports.start(),
        )?;
        update_pinned_map(
            &link.map_path("dns_nat_port_end"),
            &0u32,
            config.nat.ports.end(),
        )?;
    }
    if roles.intercept {
        let (policy_mode, prefixes, action) = match config.role {
            Role::Client => match &config.ip_policy {
                IpPolicy::TunnelPrefixes(prefixes) => (
                    POLICY_TUNNEL_PREFIXES,
                    prefixes.clone(),
                    POLICY_ACTION_REDIRECT,
                ),
                IpPolicy::DirectPrefixes(prefixes) => {
                    (POLICY_DIRECT_PREFIXES, prefixes.clone(), POLICY_ACTION_PASS)
                }
            },
            Role::Server => (
                POLICY_TUNNEL_PREFIXES,
                nat_host_prefixes(config),
                POLICY_ACTION_REDIRECT,
            ),
        };
        update_pinned_map(&link.map_path("intercept_policy_mode"), &0u32, &policy_mode)?;
        for prefix in prefixes {
            match prefix {
                IpNet::V4(network) => {
                    let key = LpmV4Key {
                        prefix_len: network.prefix_len() as u32,
                        address: u32::from_ne_bytes(network.network().octets()),
                    };
                    update_pinned_map(&link.map_path("allowed_v4"), &key, &action)?;
                }
                IpNet::V6(network) => {
                    let key = LpmV6Key {
                        prefix_len: network.prefix_len() as u32,
                        address: network.network().octets(),
                    };
                    update_pinned_map(&link.map_path("allowed_v6"), &key, &action)?;
                }
            }
        }
        for address in xdp_forced_local_ips(config, tunnel_local_ips) {
            match address {
                IpAddr::V4(address) => {
                    let key = LpmV4Key {
                        prefix_len: 32,
                        address: u32::from_ne_bytes(address.octets()),
                    };
                    update_pinned_map(&link.map_path("allowed_v4"), &key, &POLICY_ACTION_PASS)?;
                }
                IpAddr::V6(address) => {
                    let key = LpmV6Key {
                        prefix_len: 128,
                        address: address.octets(),
                    };
                    update_pinned_map(&link.map_path("allowed_v6"), &key, &POLICY_ACTION_PASS)?;
                }
            }
        }
        for address in nat_return_ips(config) {
            match address {
                IpAddr::V4(address) => {
                    let key = LpmV4Key {
                        prefix_len: 32,
                        address: u32::from_ne_bytes(address.octets()),
                    };
                    update_pinned_map(&link.map_path("allowed_v4"), &key, &POLICY_ACTION_REDIRECT)?;
                }
                IpAddr::V6(address) => {
                    let key = LpmV6Key {
                        prefix_len: 128,
                        address: address.octets(),
                    };
                    update_pinned_map(&link.map_path("allowed_v6"), &key, &POLICY_ACTION_REDIRECT)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn enable_bpf_classifiers(
    links: &[(u32, BpfLinkManager, IoClassifiers)],
) -> Result<(), RuntimeError> {
    let mut enabled = Vec::new();
    for (ifindex, link, roles) in links {
        let flags = u8::from(roles.tunnel) | (u8::from(roles.intercept) << 1);
        if let Err(error) = update_pinned_map(&link.map_path("role_flags"), &0u32, &flags) {
            for enabled_ifindex in enabled {
                if let Some((_, enabled_link, _)) = links
                    .iter()
                    .find(|(ifindex, _, _)| *ifindex == enabled_ifindex)
                {
                    let _ = update_pinned_map(&enabled_link.map_path("role_flags"), &0u32, &0u8);
                }
            }
            return Err(error);
        }
        enabled.push(*ifindex);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn disable_bpf_classifiers(
    links: &[(u32, BpfLinkManager, IoClassifiers)],
) -> Result<(), RuntimeError> {
    let mut first_error = None;
    for (_, link, _) in links {
        if let Err(error) = update_pinned_map(&link.map_path("role_flags"), &0u32, &0u8) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LpmV4Key {
    prefix_len: u32,
    address: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LpmV6Key {
    prefix_len: u32,
    address: [u8; 16],
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct TunnelV6Value {
    address: [u8; 16],
}

#[cfg(target_os = "linux")]
fn update_pinned_map<K, V>(path: &Path, key: &K, value: &V) -> Result<(), RuntimeError> {
    let fd = open_bpf_map(path).map_err(|error| RuntimeError::Bpf(error.to_string()))?;
    let result = update_bpf_map(fd, key, value);
    unsafe {
        libc::close(fd);
    }
    result.map_err(|error| RuntimeError::Bpf(error.to_string()))
}

#[cfg(target_os = "linux")]
fn read_xdp_parser_drops(links: &[(u32, BpfLinkManager, IoClassifiers)]) -> io::Result<u64> {
    read_xdp_counter(links, "parser_drops")
}

#[cfg(target_os = "linux")]
fn read_xdp_dns_fragment_drops(links: &[(u32, BpfLinkManager, IoClassifiers)]) -> io::Result<u64> {
    read_xdp_counter(links, "dns_fragment_drops")
}

#[cfg(target_os = "linux")]
fn read_xdp_counter(links: &[(u32, BpfLinkManager, IoClassifiers)], name: &str) -> io::Result<u64> {
    links.iter().try_fold(0u64, |total, (_, link, _)| {
        let fd = open_bpf_map(&link.map_path(name))?;
        let result = lookup_bpf_map::<_, u64>(fd, &0u32);
        unsafe {
            libc::close(fd);
        }
        result.map(|value| total.saturating_add(value))
    })
}

fn tunnel_port(config: &ApplianceConfig) -> u16 {
    config
        .listen
        .or(config.endpoint)
        .expect("validated tunnel address")
        .port()
}

fn intercept_policy_from_config(policy: &IpPolicy) -> InterceptPolicy {
    match policy {
        IpPolicy::TunnelPrefixes(prefixes) => InterceptPolicy::TunnelPrefixes(prefixes.clone()),
        IpPolicy::DirectPrefixes(prefixes) => InterceptPolicy::DirectPrefixes(prefixes.clone()),
    }
}

fn xdp_forced_local_ips(config: &ApplianceConfig, tunnel_local_ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut addresses = tunnel_local_ips.to_vec();
    addresses.extend(
        config
            .endpoint
            .or(config.listen)
            .map(|address| address.ip()),
    );
    if let Some(dns) = &config.dns {
        addresses.push(dns.listen.ip());
    }
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn nat_return_ips(config: &ApplianceConfig) -> Vec<IpAddr> {
    config
        .nat
        .address_v4
        .map(IpAddr::V4)
        .into_iter()
        .chain(config.nat.address_v6.map(IpAddr::V6))
        .collect()
}

fn dns_flow_config(config: &ApplianceConfig) -> Option<DnsFlowConfig> {
    config.dns.as_ref().map(|dns| DnsFlowConfig {
        listen: dns.listen,
        local_resolver: dns.local_resolver,
        remote_resolver: dns.remote_resolver,
        remote_domains: dns.remote_domains.clone().into(),
        transaction_capacity: dns.transaction_capacity,
        timeout: Duration::from_secs(dns.timeout_seconds),
        remote_available: false,
    })
}

fn nat_host_prefixes(config: &ApplianceConfig) -> Vec<IpNet> {
    config
        .nat
        .address_v4
        .map(|address| IpNet::new(IpAddr::V4(address), 32).expect("valid IPv4 host prefix"))
        .into_iter()
        .chain(
            config.nat.address_v6.map(|address| {
                IpNet::new(IpAddr::V6(address), 128).expect("valid IPv6 host prefix")
            }),
        )
        .collect()
}

#[cfg(target_os = "linux")]
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
static RECONNECT_EPOCH: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
static RELOAD_POLICY_EPOCH: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
extern "C" fn request_exit(_signal: libc::c_int) {
    EXIT_REQUESTED.store(true, Ordering::Release);
}

#[cfg(target_os = "linux")]
extern "C" fn request_reconnect(_signal: libc::c_int) {
    RECONNECT_EPOCH.fetch_add(1, Ordering::Release);
}

#[cfg(target_os = "linux")]
extern "C" fn request_reload_policy(_signal: libc::c_int) {
    RELOAD_POLICY_EPOCH.fetch_add(1, Ordering::Release);
}

#[cfg(target_os = "linux")]
fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_exit as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_exit as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGHUP,
            request_reconnect as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGUSR1,
            request_reload_policy as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_runtime, nat_return_ips, validate_dns_runtime_addresses, xdp_forced_local_ips,
        InterfaceInfo, InterfaceSpec, IoClassifiers, IoTxChannel, IoWakeup, PendingInner,
        RuntimeBuildError, XskFactory,
    };
    use crate::flow_plane::IoOwnerKey;
    use crate::v1_config::{
        ApplianceConfig, AutoReservePorts, DnsConfig, InterceptConfig, InterfaceName, IpPolicy,
        MacAddress, NatConfig, Role, XdpAttachMode,
    };
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{mpsc, Arc};

    #[derive(Debug)]
    struct FakeXsk(IoOwnerKey);

    #[derive(Default)]
    struct FakeFactory {
        created: Vec<IoOwnerKey>,
        fail_on: Option<IoOwnerKey>,
        started: Vec<IoOwnerKey>,
    }

    impl XskFactory for FakeFactory {
        type Xsk = FakeXsk;
        type Error = &'static str;

        fn create(&mut self, owner: IoOwnerKey) -> Result<Self::Xsk, Self::Error> {
            self.created.push(owner);
            if self.fail_on == Some(owner) {
                return Err("injected XSK failure");
            }
            Ok(FakeXsk(owner))
        }

        fn start(&mut self, xsk: &mut Self::Xsk) {
            self.started.push(xsk.0);
        }
    }

    fn interface(name: &str, ifindex: u32, addresses: Vec<IpAddr>) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_string(),
            ifindex,
            queue_count: 1,
            mac: [2, 0, 0, 0, 0, ifindex as u8],
            ipv4: addresses.iter().find_map(|address| match address {
                IpAddr::V4(address) => Some(*address),
                IpAddr::V6(_) => None,
            }),
            ipv6: addresses.iter().find_map(|address| match address {
                IpAddr::V4(_) => None,
                IpAddr::V6(address) => Some(*address),
            }),
            addresses,
        }
    }

    fn dns_config(listen: &str) -> ApplianceConfig {
        ApplianceConfig {
            role: Role::Client,
            tunnel_interface: InterfaceName::parse("tun0").unwrap(),
            tunnel_next_hop_mac: MacAddress::parse("02:00:00:00:00:01").unwrap(),
            intercept_interfaces: vec![InterceptConfig {
                interface: InterfaceName::parse("eth1").unwrap(),
                next_hop_mac: MacAddress::parse("02:00:00:00:00:02").unwrap(),
            }],
            endpoint: Some("192.0.2.20:4433".parse().unwrap()),
            listen: None,
            flow_worker_count: 1,
            channel_capacity: 16,
            dcid_len: 8,
            stats_path: "/tmp/new-proxy-stats.json".to_string(),
            shared_key: [1; 32],
            server_certificate: None,
            server_private_key: None,
            server_certificate_sha256: Some([2; 32]),
            nat: NatConfig {
                address_v4: Some("192.0.2.1".parse().unwrap()),
                address_v6: None,
                ports: 40000..=40010,
                auto_reserve_ports: AutoReservePorts::No,
            },
            ip_policy: IpPolicy::TunnelPrefixes(Vec::new()),
            dns: Some(DnsConfig {
                listen: listen.parse().unwrap(),
                local_resolver: "198.51.100.53:53".parse().unwrap(),
                remote_resolver: "203.0.113.53:53".parse().unwrap(),
                remote_domains: vec!["example.com".to_string()],
                transaction_capacity: 16,
                timeout_seconds: 5,
            }),
            xdp_mode: XdpAttachMode::Skb,
            config_source_path: None,
        }
    }

    #[test]
    fn v1_unit_xdp_runtime_dns_vip_must_belong_to_one_intercept_and_not_nat_or_tunnel() {
        let tunnel_ips = vec!["192.0.2.20".parse().unwrap()];
        let intercept = InterceptConfig {
            interface: InterfaceName::parse("eth1").unwrap(),
            next_hop_mac: MacAddress::parse("02:00:00:00:00:02").unwrap(),
        };
        let intercept_info = interface("eth1", 20, vec!["10.30.1.53".parse().unwrap()]);

        assert_eq!(
            validate_dns_runtime_addresses(
                &dns_config("10.30.1.53:53"),
                &tunnel_ips,
                &[(intercept.clone(), intercept_info.clone())],
            )
            .unwrap(),
            Some(20)
        );
        assert!(validate_dns_runtime_addresses(
            &dns_config("10.30.1.53:53"),
            &tunnel_ips,
            &[
                (intercept.clone(), intercept_info.clone()),
                (
                    InterceptConfig {
                        interface: InterfaceName::parse("eth2").unwrap(),
                        next_hop_mac: MacAddress::parse("02:00:00:00:00:03").unwrap(),
                    },
                    interface("eth2", 30, vec!["10.30.1.53".parse().unwrap()]),
                ),
            ],
        )
        .is_err());
        assert!(validate_dns_runtime_addresses(
            &dns_config("10.30.1.99:53"),
            &tunnel_ips,
            &[(intercept.clone(), intercept_info.clone())],
        )
        .is_err());
        assert!(validate_dns_runtime_addresses(
            &dns_config("192.0.2.1:53"),
            &tunnel_ips,
            &[(intercept.clone(), intercept_info.clone())],
        )
        .is_err());
        assert!(validate_dns_runtime_addresses(
            &dns_config("192.0.2.20:53"),
            &tunnel_ips,
            &[(intercept.clone(), intercept_info.clone())],
        )
        .is_err());

        let same_interface = interface(
            "eth0",
            10,
            vec!["192.0.2.20".parse().unwrap(), "10.30.1.53".parse().unwrap()],
        );
        let same_intercept = InterceptConfig {
            interface: InterfaceName::parse("eth0").unwrap(),
            next_hop_mac: MacAddress::parse("02:00:00:00:00:04").unwrap(),
        };
        assert_eq!(
            validate_dns_runtime_addresses(
                &dns_config("10.30.1.53:53"),
                &tunnel_ips,
                &[(same_intercept, same_interface)],
            )
            .unwrap(),
            Some(10)
        );
    }

    #[test]
    fn v1_unit_xdp_runtime_nat_hosts_are_dedicated_reverse_nat_addresses() {
        let config = dns_config("10.30.1.53:53");
        let tunnel_ips = vec!["192.0.2.30".parse().unwrap()];

        assert!(!xdp_forced_local_ips(&config, &tunnel_ips)
            .contains(&IpAddr::V4("192.0.2.1".parse().unwrap())));
        assert_eq!(
            nat_return_ips(&config),
            vec![IpAddr::V4("192.0.2.1".parse().unwrap())]
        );
    }

    #[test]
    fn v1_unit_xdp_runtime_uses_complete_owner_keys() {
        let mut factory = FakeFactory::default();
        let runtime = build_runtime(
            InterfaceSpec::tunnel(10, 2),
            vec![InterfaceSpec::intercept(20, 2)],
            &mut factory,
        )
        .unwrap();

        assert_eq!(runtime.len(), 4);
        assert!(runtime.contains(IoOwnerKey::new(10, 0)));
        assert!(runtime.contains(IoOwnerKey::new(10, 1)));
        assert!(runtime.contains(IoOwnerKey::new(20, 0)));
        assert!(runtime.contains(IoOwnerKey::new(20, 1)));
    }

    #[test]
    fn v1_unit_xdp_runtime_same_interface_has_one_owner_and_two_classifiers() {
        let mut factory = FakeFactory::default();
        let runtime = build_runtime(
            InterfaceSpec::tunnel(10, 2),
            vec![InterfaceSpec::intercept(10, 2)],
            &mut factory,
        )
        .unwrap();

        assert_eq!(runtime.len(), 2);
        for queue_id in 0..2 {
            assert_eq!(
                runtime.classifiers(IoOwnerKey::new(10, queue_id)),
                Some(IoClassifiers {
                    tunnel: true,
                    intercept: true,
                })
            );
        }
        assert_eq!(factory.created.len(), 2);
    }

    #[test]
    fn v1_unit_xdp_runtime_keeps_queue_spaces_independent() {
        let mut factory = FakeFactory::default();
        let runtime = build_runtime(
            InterfaceSpec::tunnel(10, 1),
            vec![InterfaceSpec::intercept(20, 3)],
            &mut factory,
        )
        .unwrap();

        let owners = runtime.owners().collect::<HashSet<_>>();
        assert_eq!(
            owners,
            HashSet::from([
                IoOwnerKey::new(10, 0),
                IoOwnerKey::new(20, 0),
                IoOwnerKey::new(20, 1),
                IoOwnerKey::new(20, 2),
            ])
        );
        assert!(!runtime.contains(IoOwnerKey::new(10, 1)));
    }

    #[test]
    fn v1_unit_xdp_runtime_xsk_failure_starts_no_workers() {
        let failed_owner = IoOwnerKey::new(20, 1);
        let mut factory = FakeFactory {
            fail_on: Some(failed_owner),
            ..FakeFactory::default()
        };

        let result = build_runtime(
            InterfaceSpec::tunnel(10, 2),
            vec![InterfaceSpec::intercept(20, 2)],
            &mut factory,
        );

        assert_eq!(
            result.unwrap_err(),
            RuntimeBuildError::XskCreate {
                owner: failed_owner,
                message: "injected XSK failure".to_string(),
            }
        );
        assert!(factory.started.is_empty());
    }

    #[test]
    fn v1_unit_xdp_runtime_rejects_queue_count_beyond_xsk_map_capacity() {
        let mut factory = FakeFactory::default();

        assert_eq!(
            build_runtime(
                InterfaceSpec::tunnel(10, super::XSK_MAP_MAX_ENTRIES + 1),
                vec![],
                &mut factory,
            )
            .unwrap_err(),
            RuntimeBuildError::TooManyQueues {
                ifindex: 10,
                queue_count: super::XSK_MAP_MAX_ENTRIES + 1,
                capacity: super::XSK_MAP_MAX_ENTRIES,
            }
        );
        assert!(factory.created.is_empty());
    }

    #[test]
    fn v1_unit_xdp_runtime_partitions_snat_ports_without_overlap() {
        assert_eq!(
            super::worker_port_range(40000..=40009, 0, 3),
            Some(40000..=40003)
        );
        assert_eq!(
            super::worker_port_range(40000..=40009, 1, 3),
            Some(40004..=40006)
        );
        assert_eq!(
            super::worker_port_range(40000..=40009, 2, 3),
            Some(40007..=40009)
        );
        assert_eq!(super::worker_port_range(40000..=40001, 0, 3), None);
        assert_eq!(super::worker_port_range(40000..=40009, 3, 3), None);
    }

    #[test]
    fn v1_unit_xdp_runtime_pending_inner_never_crosses_reconnect_epoch() {
        let mut pending = PendingInner::new(7);
        assert!(pending.push(7, bytes::Bytes::from_static(b"old")));

        pending.advance(8);

        assert_eq!(pending.pop_front(8), None);
        assert!(!pending.push(7, bytes::Bytes::from_static(b"stale")));
        assert!(pending.push(8, bytes::Bytes::from_static(b"new")));
        assert_eq!(
            pending.pop_front(8),
            Some(bytes::Bytes::from_static(b"new"))
        );
    }

    #[test]
    fn v1_unit_xdp_runtime_flow_to_io_drops_are_accounted() {
        let owner = IoOwnerKey::new(10, 0);
        let transmit = crate::flow_plane::IoTransmit {
            target: owner,
            packet: bytes::Bytes::from_static(b"packet"),
            outer: None,
        };
        let stats = Arc::new(crate::xdp_datapath::stats::FlowStatsSlot::default());
        let mut senders = crate::flow_plane::IoRegistry::new();

        super::send_io(&senders, transmit.clone(), &stats);

        let (full_sender, _full_receiver) = mpsc::sync_channel(1);
        full_sender.send(transmit.clone()).unwrap();
        senders
            .register(
                owner,
                IoTxChannel {
                    sender: full_sender,
                    wakeup: Arc::new(IoWakeup::new().unwrap()),
                },
            )
            .unwrap();
        super::send_io(&senders, transmit.clone(), &stats);

        let disconnected_owner = IoOwnerKey::new(11, 0);
        let (disconnected_sender, disconnected_receiver) = mpsc::sync_channel(1);
        drop(disconnected_receiver);
        senders
            .register(
                disconnected_owner,
                IoTxChannel {
                    sender: disconnected_sender,
                    wakeup: Arc::new(IoWakeup::new().unwrap()),
                },
            )
            .unwrap();
        super::send_io(
            &senders,
            crate::flow_plane::IoTransmit {
                target: disconnected_owner,
                ..transmit
            },
            &stats,
        );

        assert_eq!(stats.io_delivery_drop_counts(), (1, 1, 1));
    }

    #[test]
    fn v1_unit_xdp_runtime_successful_flow_to_io_delivery_wakes_owner() {
        let owner = IoOwnerKey::new(10, 0);
        let (sender, receiver) = mpsc::sync_channel(1);
        let wakeup = Arc::new(IoWakeup::new().unwrap());
        let mut senders = crate::flow_plane::IoRegistry::new();
        senders
            .register(
                owner,
                IoTxChannel {
                    sender,
                    wakeup: wakeup.clone(),
                },
            )
            .unwrap();

        super::send_io(
            &senders,
            crate::flow_plane::IoTransmit {
                target: owner,
                packet: bytes::Bytes::from_static(b"packet"),
                outer: None,
            },
            &crate::xdp_datapath::stats::FlowStatsSlot::default(),
        );

        assert_eq!(receiver.try_recv().unwrap().target, owner);
        let mut descriptor = libc::pollfd {
            fd: wakeup.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 0) }, 1);
        assert_ne!(descriptor.revents & libc::POLLIN, 0);
    }

    #[test]
    fn v1_unit_xdp_runtime_coalesces_flow_to_io_wakeups_while_pending() {
        let owner = IoOwnerKey::new(10, 0);
        let (sender, receiver) = mpsc::sync_channel(2);
        let wakeup = Arc::new(IoWakeup::new().unwrap());
        let mut senders = crate::flow_plane::IoRegistry::new();
        senders
            .register(
                owner,
                IoTxChannel {
                    sender,
                    wakeup: wakeup.clone(),
                },
            )
            .unwrap();
        let stats = crate::xdp_datapath::stats::FlowStatsSlot::default();
        let transmit = crate::flow_plane::IoTransmit {
            target: owner,
            packet: bytes::Bytes::from_static(b"packet"),
            outer: None,
        };

        super::send_io(&senders, transmit.clone(), &stats);
        super::send_io(&senders, transmit, &stats);

        assert_eq!(receiver.try_iter().count(), 2);
        let mut value = 0u64;
        assert_eq!(
            unsafe {
                libc::read(
                    wakeup.fd(),
                    (&mut value as *mut u64).cast(),
                    std::mem::size_of::<u64>(),
                )
            },
            std::mem::size_of::<u64>() as isize
        );
        assert_eq!(value, 1);
    }

    #[test]
    fn v1_unit_xdp_runtime_builds_checksum_safe_outer_ipv4_udp() {
        let packet = super::build_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(198, 51, 100, 20),
            40000,
            4433,
            b"odd-length",
        );

        assert_eq!(super::checksum(&packet[..20]), 0);
        let mut checksum_input = Vec::new();
        checksum_input.extend_from_slice(&packet[12..20]);
        checksum_input.extend_from_slice(&[0, 17]);
        checksum_input.extend_from_slice(&((packet.len() - 20) as u16).to_be_bytes());
        checksum_input.extend_from_slice(&packet[20..]);
        assert_eq!(super::checksum(&checksum_input), 0);
    }

    #[test]
    fn v1_unit_xdp_runtime_builds_checksum_safe_outer_ipv6_udp() {
        let packet = super::build_ipv6_udp(
            "2001:db8::10".parse::<Ipv6Addr>().unwrap(),
            "2001:db8::20".parse::<Ipv6Addr>().unwrap(),
            40000,
            4433,
            b"odd-length",
        );

        let mut checksum_input = Vec::new();
        checksum_input.extend_from_slice(&packet[8..40]);
        checksum_input.extend_from_slice(&((packet.len() - 40) as u32).to_be_bytes());
        checksum_input.extend_from_slice(&[0, 0, 0, 17]);
        checksum_input.extend_from_slice(&packet[40..]);
        assert_eq!(super::checksum(&checksum_input), 0);
    }

    #[test]
    fn v1_unit_xdp_runtime_scatter_checksum_matches_contiguous_bytes() {
        let parts = [&b"odd"[..], &b"-"[..], &b"length"[..], &b"-payload"[..]];
        let contiguous = parts.concat();

        assert_eq!(super::checksum_parts(&parts), super::checksum(&contiguous));
    }

    #[test]
    fn v1_unit_xdp_runtime_reuses_tx_frame_buffer_without_stale_bytes() {
        let link = super::IoLinkConfig {
            interface: interface("eth0", 10, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
            tunnel_next_hop: Some([2, 0, 0, 0, 0, 1]),
            intercept_next_hop: Some([2, 0, 0, 0, 0, 2]),
        };
        let owner = IoOwnerKey::new(10, 0);
        let mut frame = Vec::with_capacity(4096);
        assert!(super::fill_ethernet_frame(
            &link,
            &crate::flow_plane::IoTransmit {
                target: owner,
                packet: bytes::Bytes::from(vec![0x55; 1200]),
                outer: Some(crate::flow_plane::OuterRoute {
                    source_ip: None,
                    source_port: 40000,
                    destination: "198.51.100.20:4433".parse().unwrap(),
                }),
            },
            &mut frame,
        ));
        assert_eq!(frame.len(), 14 + 20 + 8 + 1200);

        let inner = bytes::Bytes::from_static(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1,
        ]);
        assert!(super::fill_ethernet_frame(
            &link,
            &crate::flow_plane::IoTransmit {
                target: owner,
                packet: inner.clone(),
                outer: None,
            },
            &mut frame,
        ));
        assert_eq!(frame.len(), 14 + inner.len());
        assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes());
        assert_eq!(&frame[14..], inner.as_ref());
    }

    #[test]
    fn v1_unit_xdp_runtime_splits_quic_gso_transmits_before_udp_encapsulation() {
        let contents = bytes::Bytes::from_static(b"abcdefghijkl");

        assert_eq!(
            super::split_outer_transmit(contents.clone(), Some(5)),
            vec![
                bytes::Bytes::from_static(b"abcde"),
                bytes::Bytes::from_static(b"fghij"),
                bytes::Bytes::from_static(b"kl"),
            ]
        );
        assert_eq!(
            super::split_outer_transmit(contents.clone(), None),
            vec![contents.clone()]
        );
        assert_eq!(
            super::split_outer_transmit(contents.clone(), Some(contents.len())),
            vec![contents]
        );
    }
}
