use std::sync::Arc;
use std::collections::HashMap;
use std::ffi::CString;
use arc_swap::ArcSwap;

use crate::datapath::{Datapath, DatapathError, DatapathStats};
use crate::config::GatewayConfig;
use crate::app_config::RuntimeMode;
use crate::telemetry::TelemetryRegistry;
use crate::quic_pool::{cert_sha256, generate_self_signed_cert};
use crate::control::ControlServer;
use crate::client::build_peer_quic_pool;
use crate::{PeerQuicPools, ClientQuicDataPortBaseline};

struct WorkerPanicGuard {
    exit_notify: Arc<tokio::sync::Notify>,
}

impl Drop for WorkerPanicGuard {
    fn drop(&mut self) {
        self.exit_notify.notify_one();
    }
}

#[allow(dead_code)]
pub struct XdpDatapath {
    config: GatewayConfig,
    #[allow(dead_code)]
    interface_name: String,
    runtime_mode: RuntimeMode,
    fixed_client_quic_data_port_count: Option<usize>,
    peer_telemetries: Vec<Arc<TelemetryRegistry>>,
    worker_telemetry_registry: Arc<crate::telemetry::WorkerTelemetryRegistry>,
    gateway_state: Arc<parking_lot::RwLock<crate::GatewayState>>,
    peer_secrets: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    session_cache: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    auth_nonce_cache: Arc<parking_lot::Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
    shared_quic_registry: crate::quic_pool::PeerConnRegistry,
    client_quic_pools: PeerQuicPools,
    client_quic_data_port_baseline: ClientQuicDataPortBaseline,
    peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(target_os = "linux")]
    quic_ifindex: u32,
    #[cfg(target_os = "linux")]
    intercept_ifindexes: Vec<u32>,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_xdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xdp_umem_reg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

#[cfg(target_os = "linux")]
struct UmemRegion {
    addr: *mut libc::c_void,
    size: usize,
}

#[cfg(target_os = "linux")]
unsafe impl Send for UmemRegion {}
#[cfg(target_os = "linux")]
unsafe impl Sync for UmemRegion {}

#[cfg(target_os = "linux")]
impl UmemRegion {
    fn new(size: usize) -> Result<Self, std::io::Error> {
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { addr, size })
    }
}

#[cfg(target_os = "linux")]
impl Drop for UmemRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.addr, self.size);
        }
    }
}

#[cfg(target_os = "linux")]
struct XskSetup {
    _umem: UmemRegion,
    sockets: Vec<libc::c_int>,
}

#[cfg(target_os = "linux")]
unsafe impl Send for XskSetup {}
#[cfg(target_os = "linux")]
unsafe impl Sync for XskSetup {}

#[cfg(target_os = "linux")]
fn setup_xsk_sockets(
    quic_ifindex: u32,
    intercept_ifindexes: &[u32],
    queue_count: usize,
) -> Result<XskSetup, DatapathError> {
    use std::io;

    let mut ifindexes = vec![quic_ifindex];
    for &index in intercept_ifindexes {
        if !ifindexes.contains(&index) {
            ifindexes.push(index);
        }
    }

    // Allocate 8MB page-aligned memory for UMEM
    let umem_size = 4096 * 2048;
    let umem = UmemRegion::new(umem_size)?;

    let mut sockets = Vec::new();
    let mut first_fd: Option<libc::c_int> = None;

    const AF_XDP: libc::c_int = 44;
    const SOL_XDP: libc::c_int = 283;
    const XDP_UMEM_REG: libc::c_int = 4;
    const XDP_UMEM_FILL_RING: libc::c_int = 5;
    const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
    const XDP_RX_RING: libc::c_int = 2;
    const XDP_TX_RING: libc::c_int = 3;
    const XDP_SHARED_UMEM: u16 = 1;

    for &ifindex in &ifindexes {
        for queue_id in 0..queue_count {
            let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                for &s_fd in &sockets {
                    unsafe { libc::close(s_fd); }
                }
                return Err(DatapathError::Io(err));
            }

            if first_fd.is_none() {
                // Register UMEM region on the first socket
                let umem_reg = xdp_umem_reg {
                    addr: umem.addr as u64,
                    len: umem.size as u64,
                    chunk_size: 4096,
                    headroom: 0,
                    flags: 0,
                };
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        SOL_XDP,
                        XDP_UMEM_REG,
                        &umem_reg as *const _ as *const libc::c_void,
                        std::mem::size_of::<xdp_umem_reg>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    unsafe { libc::close(fd); }
                    for &s_fd in &sockets {
                        unsafe { libc::close(s_fd); }
                    }
                    return Err(DatapathError::Io(err));
                }

                let ring_size: u32 = 2048;
                for opt in &[XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
                    let ret = unsafe {
                        libc::setsockopt(
                            fd,
                            SOL_XDP,
                            *opt,
                            &ring_size as *const _ as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        unsafe { libc::close(fd); }
                        for &s_fd in &sockets {
                            unsafe { libc::close(s_fd); }
                        }
                        return Err(DatapathError::Io(err));
                    }
                }

                let addr = sockaddr_xdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: 0,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id as u32,
                    sxdp_shared_umem_fd: 0,
                };
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    unsafe { libc::close(fd); }
                    for &s_fd in &sockets {
                        unsafe { libc::close(s_fd); }
                    }
                    return Err(DatapathError::Io(err));
                }

                first_fd = Some(fd);
            } else {
                // Secondary socket sharing UMEM
                let ring_size: u32 = 2048;
                for opt in &[XDP_RX_RING, XDP_TX_RING] {
                    let ret = unsafe {
                        libc::setsockopt(
                            fd,
                            SOL_XDP,
                            *opt,
                            &ring_size as *const _ as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        unsafe { libc::close(fd); }
                        for &s_fd in &sockets {
                            unsafe { libc::close(s_fd); }
                        }
                        return Err(DatapathError::Io(err));
                    }
                }

                let addr = sockaddr_xdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: XDP_SHARED_UMEM,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id as u32,
                    sxdp_shared_umem_fd: first_fd.unwrap() as u32,
                };
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    unsafe { libc::close(fd); }
                    for &s_fd in &sockets {
                        unsafe { libc::close(s_fd); }
                    }
                    return Err(DatapathError::Io(err));
                }
            }

            sockets.push(fd);
        }
    }

    Ok(XskSetup { _umem: umem, sockets })
}

#[cfg(target_os = "linux")]
fn run_xdp_worker_loop(
    worker_id: usize,
    sockets: Vec<libc::c_int>,
    exit_flag: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut poll_fds: Vec<libc::pollfd> = sockets
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    while !exit_flag.load(std::sync::atomic::Ordering::Relaxed) {
        for pfd in &mut poll_fds {
            pfd.revents = 0;
        }

        let ret = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                50, // 50ms timeout
            )
        };

        if ret > 0 {
            for pfd in &poll_fds {
                if pfd.revents & libc::POLLIN != 0 {
                    // Decoupled polling logic. In real setups, we read from Shared UMEM via RX Ring.
                }
            }
        } else if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                log::error!("XDP Worker {} libc::poll error: {}", worker_id, err);
                break;
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl XdpDatapath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: GatewayConfig,
        interface_name: String,
        runtime_mode: RuntimeMode,
        fixed_client_quic_data_port_count: Option<usize>,
        peer_telemetries: Vec<Arc<TelemetryRegistry>>,
        worker_telemetry_registry: Arc<crate::telemetry::WorkerTelemetryRegistry>,
        gateway_state: Arc<parking_lot::RwLock<crate::GatewayState>>,
        peer_secrets: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        session_cache: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        auth_nonce_cache: Arc<parking_lot::Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
        shared_quic_registry: crate::quic_pool::PeerConnRegistry,
        client_quic_pools: PeerQuicPools,
        client_quic_data_port_baseline: ClientQuicDataPortBaseline,
        peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Result<Self, DatapathError> {
        let quic_interface = match &config.xdp.quic_interface {
            Some(ifname) => ifname.clone(),
            None => return Err(DatapathError::Config("quic_interface must be configured for XDP mode".into())),
        };
        
        let quic_ifindex = unsafe {
            let c_ifname = CString::new(quic_interface.as_str()).map_err(|e| DatapathError::Config(e.to_string()))?;
            let index = libc::if_nametoindex(c_ifname.as_ptr());
            if index == 0 {
                return Err(DatapathError::Config(format!("quic_interface '{}' not found", quic_interface)));
            }
            index
        };

        let mut intercept_ifindexes = Vec::new();
        for ifname in &config.xdp.intercept_interfaces {
            let index = unsafe {
                let c_ifname = CString::new(ifname.as_str()).map_err(|e| DatapathError::Config(e.to_string()))?;
                let index = libc::if_nametoindex(c_ifname.as_ptr());
                if index == 0 {
                    return Err(DatapathError::Config(format!("intercept_interface '{}' not found", ifname)));
                }
                index
            };
            intercept_ifindexes.push(index);
        }

        Ok(Self {
            config,
            interface_name,
            runtime_mode,
            fixed_client_quic_data_port_count,
            peer_telemetries,
            worker_telemetry_registry,
            gateway_state,
            peer_secrets,
            session_cache,
            auth_nonce_cache,
            shared_quic_registry,
            client_quic_pools,
            client_quic_data_port_baseline,
            peer_mutation_lock,
            quic_ifindex,
            intercept_ifindexes,
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl XdpDatapath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _config: GatewayConfig,
        _interface_name: String,
        _runtime_mode: RuntimeMode,
        _fixed_client_quic_data_port_count: Option<usize>,
        _peer_telemetries: Vec<Arc<TelemetryRegistry>>,
        _worker_telemetry_registry: Arc<crate::telemetry::WorkerTelemetryRegistry>,
        _gateway_state: Arc<parking_lot::RwLock<crate::GatewayState>>,
        _peer_secrets: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        _session_cache: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        _auth_nonce_cache: Arc<parking_lot::Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
        _shared_quic_registry: crate::quic_pool::PeerConnRegistry,
        _client_quic_pools: PeerQuicPools,
        _client_quic_data_port_baseline: ClientQuicDataPortBaseline,
        _peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Result<Self, DatapathError> {
        Err(DatapathError::Config("XDP is only supported on Linux".into()))
    }
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl Datapath for XdpDatapath {
    async fn run_loop(
        self: Arc<Self>,
        dp_snapshot: Arc<ArcSwap<crate::L4DataPlaneSnapshot>>,
        exit_notify: Arc<tokio::sync::Notify>,
    ) -> Result<(), DatapathError> {
        if self.runtime_mode == RuntimeMode::Server {
            log::info!("------------------------------------------------------");
            log::info!("         STARTING GATEWAY IN [ SERVER MODE ]         ");
            log::info!("------------------------------------------------------");

            let _listen_port = match self.config.interface.listen_port {
                Some(port) => port,
                None => {
                    log::error!("Server userspace XDP requires Interface.ListenPort");
                    return Err(DatapathError::Config("Server userspace XDP requires Interface.ListenPort".into()));
                }
            };

            let queue_count = self.config.quic_pool.listen_ports.len();
            let queue_count = if queue_count == 0 { 1 } else { queue_count };

            let (quic_certs, _quic_key) = match generate_self_signed_cert() {
                Ok(cert) => cert,
                Err(e) => {
                    log::error!("Failed to generate QUIC certificate: {}", e);
                    return Err(DatapathError::Config(format!("Failed to generate QUIC certificate: {}", e)));
                }
            };
            let quic_cert_sha256 = match cert_sha256(&quic_certs) {
                Ok(fingerprint) => fingerprint,
                Err(e) => {
                    log::error!("Failed to fingerprint QUIC certificate: {}", e);
                    return Err(DatapathError::Config(format!("Failed to fingerprint QUIC certificate: {}", e)));
                }
            };

            let listen_control_port = self.config
                .interface
                .listen_control_port
                .or(self.config.interface.listen_port)
                .expect("Server config validation failed to enforce control port");

            let control_server = ControlServer::new(
                listen_control_port,
                self.peer_secrets.clone(),
                self.config.quic_pool.listen_ports.clone(),
                self.config.quic_pool.public_ipv4.clone(),
                self.config.quic_pool.public_ipv6.clone(),
                quic_cert_sha256,
                self.session_cache.clone(),
            );

            let control_task = match control_server.start().await {
                Ok(handle) => handle,
                Err(e) => {
                    log::error!("Control plane server failed to start: {}", e);
                    return Err(DatapathError::Config(format!("Control plane server failed to start: {}", e)));
                }
            };

            let setup = match setup_xsk_sockets(self.quic_ifindex, &self.intercept_ifindexes, queue_count) {
                Ok(s) => s,
                Err(e) => {
                    control_task.abort();
                    return Err(e);
                }
            };

            let exit_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut join_handles = Vec::new();

            for worker_id in 0..queue_count {
                let exit_notify_clone = exit_notify.clone();
                let exit_flag_clone = exit_flag.clone();
                let sockets_clone = setup.sockets.clone();
                
                let handle = std::thread::Builder::new()
                    .name(format!("new-proxy-server-xdp-worker-{}", worker_id))
                    .spawn(move || {
                        let _panic_guard = WorkerPanicGuard { exit_notify: exit_notify_clone };
                        run_xdp_worker_loop(worker_id, sockets_clone, exit_flag_clone);
                    })
                    .expect("Failed to spawn XDP worker thread");
                join_handles.push(handle);
            }

            tokio::select! {
                _ = crate::wait_for_shutdown() => {},
                _ = exit_notify.notified() => {
                    log::error!("A server worker thread exited prematurely; shutting down.");
                }
            }

            control_task.abort();
            exit_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            for handle in join_handles {
                let _ = handle.join();
            }
        } else {
            log::info!("------------------------------------------------------");
            log::info!("         STARTING GATEWAY IN [ CLIENT MODE ]         ");
            log::info!("------------------------------------------------------");

            let proxy_peers = crate::proxy_peers(&self.config);
            let mut initial_pool_failures = 0usize;
            let mut startup_quic_data_port_count = self.fixed_client_quic_data_port_count;

            for peer in &proxy_peers {
                match build_peer_quic_pool(self.config.interface.private_key, peer).await {
                    Ok(pool) => {
                        if let Err(e) = crate::record_startup_quic_data_port_count(
                            &mut startup_quic_data_port_count,
                            pool.endpoint_count(),
                        ) {
                            pool.shutdown(b"QUIC data port count mismatch");
                            return Err(DatapathError::Config(e));
                        }
                        if let Err(e) = crate::validate_client_quic_data_port_count(
                            &self.client_quic_pools,
                            pool.endpoint_count(),
                        ) {
                            pool.shutdown(b"QUIC data port count mismatch");
                            return Err(DatapathError::Config(e));
                        }
                        self.client_quic_pools.write().insert(peer.public_key, pool);
                    }
                    Err(e) => {
                        initial_pool_failures += 1;
                        if let Some(data_port_count) = e.data_port_count() {
                            if let Err(mismatch) = crate::record_startup_quic_data_port_count(
                                &mut startup_quic_data_port_count,
                                data_port_count,
                            ) {
                                return Err(DatapathError::Config(mismatch));
                            }
                        }
                        log::warn!(
                            "Failed to establish initial QUIC pool for peer {}; starting in WireGuard L3 fallback and retrying in background: {}",
                            crate::app_config::encode_base64_32(&peer.public_key),
                            e
                        );
                    }
                }
            }

            if initial_pool_failures > 0 {
                self.gateway_state.write().userspace_tcp_offload_enabled = false;
            }

            crate::publish_l4_data_plane_snapshot(&dp_snapshot, &self.gateway_state, &self.client_quic_pools);
            let quic_data_port_count =
                crate::client_quic_data_port_count(&self.client_quic_pools, startup_quic_data_port_count);
            let queue_count = crate::effective_client_tun_queues(quic_data_port_count.unwrap_or(0));
            crate::record_initial_client_quic_data_port_baseline(
                &self.client_quic_data_port_baseline,
                quic_data_port_count,
            );

            let queue_count = if queue_count == 0 { 1 } else { queue_count };

            let setup = setup_xsk_sockets(self.quic_ifindex, &self.intercept_ifindexes, queue_count)?;

            let userspace_tcp_failover_task = crate::start_userspace_tcp_failover_manager(
                self.gateway_state.clone(),
                self.client_quic_pools.clone(),
                dp_snapshot.clone(),
                self.config.interface.private_key,
                self.client_quic_data_port_baseline.clone(),
                self.peer_mutation_lock.clone(),
            );

            let exit_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut join_handles = Vec::new();

            for worker_id in 0..queue_count {
                let exit_notify_clone = exit_notify.clone();
                let exit_flag_clone = exit_flag.clone();
                let sockets_clone = setup.sockets.clone();
                
                let handle = std::thread::Builder::new()
                    .name(format!("new-proxy-client-xdp-worker-{}", worker_id))
                    .spawn(move || {
                        let _panic_guard = WorkerPanicGuard { exit_notify: exit_notify_clone };
                        run_xdp_worker_loop(worker_id, sockets_clone, exit_flag_clone);
                    })
                    .expect("Failed to spawn XDP worker thread");
                join_handles.push(handle);
            }

            tokio::select! {
                _ = crate::wait_for_shutdown() => {},
                _ = exit_notify.notified() => {
                    log::error!("A client worker thread exited prematurely; shutting down.");
                }
            }

            exit_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            for handle in join_handles {
                let _ = handle.join();
            }
            userspace_tcp_failover_task.abort();
        }

        Ok(())
    }

    fn get_stats(&self) -> DatapathStats {
        let snapshots = self.worker_telemetry_registry.snapshot();
        let total_rx_bytes = snapshots.iter().map(|s| s.tun_rx_bytes + s.tcp_offload_bytes + s.l3_bytes).sum();
        DatapathStats { rx_bytes: total_rx_bytes }
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait::async_trait]
impl Datapath for XdpDatapath {
    async fn run_loop(
        self: Arc<Self>,
        _dp_snapshot: Arc<ArcSwap<crate::L4DataPlaneSnapshot>>,
        _exit_notify: Arc<tokio::sync::Notify>,
    ) -> Result<(), DatapathError> {
        Err(DatapathError::Config("XDP is only supported on Linux".into()))
    }

    fn get_stats(&self) -> DatapathStats {
        DatapathStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GatewayConfig, InterfaceConfig, QUICPoolConfig, XdpConfig};
    use crate::app_config::RuntimeMode;
    use crate::telemetry::{TelemetryRegistry, WorkerTelemetryRegistry};
    use std::sync::Arc;
    use parking_lot::RwLock;

    fn dummy_config() -> GatewayConfig {
        GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.1/24".parse().unwrap()],
                listen_port: Some(40000),
                listen_control_port: Some(40001),
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
                mode: "af_xdp".to_string(),
            },
            peers: Vec::new(),
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![40002],
            },
            xdp: XdpConfig {
                quic_interface: Some("non_existent_dev_abc".to_string()),
                intercept_interfaces: vec!["lo".to_string()],
                xdp_mode: "native".to_string(),
            },
        }
    }

    #[test]
    fn test_xdp_datapath_fails_gracefully() {
        let config = dummy_config();
        let peer_telemetries = vec![Arc::new(TelemetryRegistry::new())];
        let worker_telemetry_registry = Arc::new(WorkerTelemetryRegistry::new());
        let gateway_state = Arc::new(RwLock::new(crate::GatewayState {
            config: config.clone(),
            router: crate::routing::AllowedIPsRouter::new(),
            userspace_tcp_offload_enabled: true,
        }));
        let peer_secrets = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let session_cache = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let auth_nonce_cache = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
        let shared_quic_registry = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let client_quic_pools = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let client_quic_data_port_baseline = Arc::new(parking_lot::Mutex::new(0));
        let peer_mutation_lock = Arc::new(tokio::sync::Mutex::new(()));

        let res = XdpDatapath::new(
            config,
            "non_existent_dev_abc".to_string(),
            RuntimeMode::Server,
            None,
            peer_telemetries,
            worker_telemetry_registry,
            gateway_state,
            peer_secrets,
            session_cache,
            auth_nonce_cache,
            shared_quic_registry,
            client_quic_pools,
            client_quic_data_port_baseline,
            peer_mutation_lock,
        );
        assert!(res.is_err());
    }
}
