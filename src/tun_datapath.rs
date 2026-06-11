use std::sync::Arc;
use std::collections::HashMap;
use arc_swap::ArcSwap;

use crate::datapath::{Datapath, DatapathError, DatapathStats};
use crate::config::GatewayConfig;
use crate::app_config::RuntimeMode;
use crate::telemetry::TelemetryRegistry;
use crate::quic_pool::{cert_sha256, generate_self_signed_cert};
use crate::control::ControlServer;
use crate::runtime::{cleanup_runtime, setup_routes};
use crate::client::build_peer_quic_pool;
use crate::{PeerQuicPools, ClientQuicDataPortBaseline};

struct WorkerTask {
    _thread: std::thread::JoinHandle<()>,
}

impl WorkerTask {
    fn abort(&self) {
        // No-op. Process exit terminates all background threads.
    }
}

struct WorkerPanicGuard {
    exit_notify: Arc<tokio::sync::Notify>,
}

impl Drop for WorkerPanicGuard {
    fn drop(&mut self) {
        self.exit_notify.notify_one();
    }
}

struct FdsGuard {
    fds: Vec<std::os::unix::io::RawFd>,
}

impl Drop for FdsGuard {
    fn drop(&mut self) {
        for &fd in &self.fds {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

pub(crate) fn setup_udp_socket(port: Option<u16>) -> Result<tokio::net::UdpSocket, DatapathError> {
    let bind_addr = match port {
        Some(p) => format!("0.0.0.0:{}", p).parse::<std::net::SocketAddr>().unwrap(),
        None => "0.0.0.0:0".parse::<std::net::SocketAddr>().unwrap(),
    };
    
    let std_sock = std::net::UdpSocket::bind(bind_addr)?;
    std_sock.set_nonblocking(true)?;
    let sock_ref = socket2::SockRef::from(&std_sock);
    let _ = sock_ref.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = sock_ref.set_send_buffer_size(8 * 1024 * 1024);
    
    if let Err(e) = crate::socket_mark::set_outer_mark(&std_sock) {
        return Err(DatapathError::Config(e));
    }
    
    let udp_socket = tokio::net::UdpSocket::from_std(std_sock)?;
    Ok(udp_socket)
}

pub(crate) fn setup_server_endpoint(
    quic_certs: &[rustls::Certificate],
    quic_key: &rustls::PrivateKey,
    packet_buffer_size: usize,
) -> Result<quinn_proto::Endpoint, String> {
    let mut rustls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(quic_certs.to_vec(), quic_key.clone())
        .map_err(|e| format!("Failed to build rustls ServerConfig: {}", e))?;
    rustls_config.alpn_protocols = vec![b"new_proxy_mux".to_vec()];
    let mut server_proto_config =
        quinn_proto::ServerConfig::with_crypto(Arc::new(rustls_config));
    let mut transport = quinn_proto::TransportConfig::default();
    let quic_mtu = crate::rtc_loop::quic_initial_mtu_for_packet_buffer(packet_buffer_size);
    transport
        .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport.stream_receive_window(quinn_proto::VarInt::from(8 * 1024 * 1024u32));
    transport.receive_window(quinn_proto::VarInt::from(16 * 1024 * 1024u32));
    transport.send_window(16 * 1024 * 1024);
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.initial_mtu(quic_mtu);
    transport.min_mtu(quic_mtu);
    server_proto_config.transport_config(Arc::new(transport));

    let mut endpoint_config = quinn_proto::EndpointConfig::default();
    endpoint_config.max_udp_payload_size(65527).unwrap();
    let endpoint = quinn_proto::Endpoint::new(
        Arc::new(endpoint_config),
        Some(Arc::new(server_proto_config)),
        false,
    );
    Ok(endpoint)
}

pub(crate) fn setup_client_endpoint() -> quinn_proto::Endpoint {
    let mut endpoint_config = quinn_proto::EndpointConfig::default();
    endpoint_config.max_udp_payload_size(65527).unwrap();
    quinn_proto::Endpoint::new(Arc::new(endpoint_config), None, false)
}

pub(crate) fn spawn_worker_thread(
    mut worker: crate::rtc_loop::RtcWorker,
    worker_id: usize,
    role_name: &'static str,
    l4_data_plane: Arc<ArcSwap<crate::L4DataPlaneSnapshot>>,
    exit_notify: Arc<tokio::sync::Notify>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name(format!("new-proxy-{}-worker-{}", role_name, worker_id))
        .spawn(move || {
            let _panic_guard = WorkerPanicGuard {
                exit_notify,
            };
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build worker local Tokio runtime");
            rt.block_on(async {
                if let Err(e) = worker.run_loop(l4_data_plane).await {
                    log::error!("{} RtcWorker loop failed: {}", role_name, e);
                }
            });
        })
        .expect("Failed to spawn RtcWorker thread")
}

pub struct TunDatapath {
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
}

impl TunDatapath {
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
        })
    }
}

#[async_trait::async_trait]
impl Datapath for TunDatapath {
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
                    log::error!("Server userspace WireGuard L3 requires Interface.ListenPort");
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Config("Server userspace WireGuard L3 requires Interface.ListenPort".into()));
                }
            };

            let tun_queue_count = crate::effective_server_tun_queues(&self.config.quic_pool.listen_ports);
            log::info!(
                "Server TUN queue count follows QUIC listen port count: using {}",
                tun_queue_count
            );

            let tun_fds = match crate::tun_device::open_tun(&self.interface_name, tun_queue_count) {
                Ok(fds) => fds,
                Err(e) => {
                    log::error!("Failed to open server TUN device: {}", e);
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Io(e));
                }
            };

            let mut fd_guard = FdsGuard { fds: tun_fds };

            if let Err(e) = setup_routes(&self.config, &self.interface_name) {
                eprintln!("Failed to setup userspace routes: {}", e);
                cleanup_runtime(&self.config, &self.interface_name);
                return Err(DatapathError::Config(e));
            }

            let (quic_certs, quic_key) = match generate_self_signed_cert() {
                Ok(cert) => cert,
                Err(e) => {
                    log::error!("Failed to generate QUIC certificate: {}", e);
                    let cleanup_config = self.gateway_state.read().config.clone();
                    cleanup_runtime(&cleanup_config, &self.interface_name);
                    return Err(DatapathError::Config(format!("Failed to generate QUIC certificate: {}", e)));
                }
            };
            let quic_cert_sha256 = match cert_sha256(&quic_certs) {
                Ok(fingerprint) => fingerprint,
                Err(e) => {
                    log::error!("Failed to fingerprint QUIC certificate: {}", e);
                    let cleanup_config = self.gateway_state.read().config.clone();
                    cleanup_runtime(&cleanup_config, &self.interface_name);
                    return Err(DatapathError::Config(format!("Failed to fingerprint QUIC certificate: {}", e)));
                }
            };

            let listen_control_port = self.config
                .interface
                .listen_control_port
                .or(self.config.interface.listen_port)
                .expect("Server config validation failed to enforce control port");

            // 启动用户态独立公网控制通道协商服务器 (传递动态 peer_secrets 哈希表)
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
                    let cleanup_config = self.gateway_state.read().config.clone();
                    cleanup_runtime(&cleanup_config, &self.interface_name);
                    return Err(DatapathError::Config(format!("Control plane server failed to start: {}", e)));
                }
            };

            let mut worker_preps = Vec::new();
            for (worker_id, &fd) in fd_guard.fds.clone().iter().enumerate() {
                let tun_io = Arc::new(match crate::tun_io::AsyncTunIo::new(fd) {
                    Ok(io) => {
                        fd_guard.fds[worker_id] = -1;
                        io
                    }
                    Err(e) => {
                        log::error!("Failed to wrap server TUN FD in AsyncTunIo: {}", e);
                        cleanup_runtime(&self.config, &self.interface_name);
                        control_task.abort();
                        return Err(DatapathError::Io(e));
                    }
                });

                let local_port = self.config.quic_pool.listen_ports[worker_id];
                let udp_socket = match setup_udp_socket(Some(local_port)) {
                    Ok(s) => s,
                    Err(e) => {
                        cleanup_runtime(&self.config, &self.interface_name);
                        control_task.abort();
                        return Err(e);
                    }
                };

                let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(self.config.interface.mtu);
                let endpoint = match setup_server_endpoint(&quic_certs, &quic_key, packet_buffer_size) {
                    Ok(ep) => ep,
                    Err(e) => {
                        cleanup_runtime(&self.config, &self.interface_name);
                        control_task.abort();
                        return Err(DatapathError::Config(e));
                    }
                };

                worker_preps.push((tun_io, udp_socket, endpoint));
            }

            let mut l3_tasks = Vec::new();
            for (worker_id, (tun_io, udp_socket, endpoint)) in worker_preps.into_iter().enumerate() {
                let mut worker = crate::rtc_loop::RtcWorker::new(
                    tun_io,
                    worker_id,
                    crate::rtc_loop::WorkerRole::Server,
                    crate::rtc_loop::RtcWorkerConfig {
                        mtu: self.config.interface.mtu,
                    },
                    udp_socket,
                    endpoint,
                    Some(self.session_cache.clone()),
                    Some(self.auth_nonce_cache.clone()),
                    Some(self.shared_quic_registry.clone()),
                );
                worker.set_worker_stats(self.worker_telemetry_registry.get_or_create(worker_id));
                worker.set_peer_telemetry(self.peer_telemetries[worker_id].clone());

                let thread = spawn_worker_thread(
                    worker,
                    worker_id,
                    "server",
                    dp_snapshot.clone(),
                    exit_notify.clone(),
                );
                l3_tasks.push(WorkerTask { _thread: thread });
            }

            tokio::select! {
                _ = crate::wait_for_shutdown() => {},
                _ = exit_notify.notified() => {
                    log::error!("A server worker thread exited prematurely; shutting down.");
                }
            }
            control_task.abort();
            for task in l3_tasks {
                task.abort();
            }
        } else {
            log::info!("------------------------------------------------------");
            log::info!("         STARTING GATEWAY IN [ CLIENT MODE ]         ");
            log::info!("------------------------------------------------------");

            let proxy_peers = crate::proxy_peers(&self.config);
            if proxy_peers.is_empty() {
                log::warn!("No QUIC proxy peers configured; userspace TCP offload remains inactive.");
            }

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
                            log::error!(
                                "Failed to establish initial QUIC pool for peer {}: {}",
                                crate::app_config::encode_base64_32(&peer.public_key),
                                e
                            );
                            let cleanup_config = self.gateway_state.read().config.clone();
                            cleanup_runtime(&cleanup_config, &self.interface_name);
                            return Err(DatapathError::Config(e));
                        }
                        if let Err(e) = crate::validate_client_quic_data_port_count(
                            &self.client_quic_pools,
                            pool.endpoint_count(),
                        ) {
                            pool.shutdown(b"QUIC data port count mismatch");
                            log::error!(
                                "Failed to establish initial QUIC pool for peer {}: {}",
                                crate::app_config::encode_base64_32(&peer.public_key),
                                e
                            );
                            let cleanup_config = self.gateway_state.read().config.clone();
                            cleanup_runtime(&cleanup_config, &self.interface_name);
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
                                log::error!(
                                    "Failed to establish initial QUIC pool for peer {}: {}; {}",
                                    crate::app_config::encode_base64_32(&peer.public_key),
                                    e,
                                    mismatch
                                );
                                let cleanup_config = self.gateway_state.read().config.clone();
                                cleanup_runtime(&cleanup_config, &self.interface_name);
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
                log::warn!(
                    "Disabled userspace TCP offload because {} initial QUIC pool(s) failed; traffic will use userspace WireGuard L3 until QUIC recovers",
                    initial_pool_failures
                );
            }
            crate::publish_l4_data_plane_snapshot(&dp_snapshot, &self.gateway_state, &self.client_quic_pools);
            let quic_data_port_count =
                crate::client_quic_data_port_count(&self.client_quic_pools, startup_quic_data_port_count);
            let tun_queue_count = crate::effective_client_tun_queues(quic_data_port_count.unwrap_or(0));
            crate::record_initial_client_quic_data_port_baseline(
                &self.client_quic_data_port_baseline,
                quic_data_port_count,
            );
            match quic_data_port_count {
                Some(count) => log::info!(
                    "Client TUN queue count follows negotiated QUIC data port count: data_ports {}, using {}",
                    count,
                    tun_queue_count
                ),
                None => log::info!(
                    "Client TUN queue count has no negotiated QUIC data port count yet; using {} initial queue",
                    tun_queue_count
                ),
            }

            log::info!(
                "Opening userspace multiqueue TUN device: {} with {} queues",
                self.interface_name,
                tun_queue_count
            );
            let tun_fds = match crate::tun_device::open_tun(&self.interface_name, tun_queue_count) {
                Ok(fds) => fds,
                Err(e) => {
                    log::error!("Failed to open TUN device: {}", e);
                    let cleanup_config = self.gateway_state.read().config.clone();
                    cleanup_runtime(&cleanup_config, &self.interface_name);
                    return Err(DatapathError::Io(e));
                }
            };

            let mut fd_guard = FdsGuard { fds: tun_fds };

            if let Err(e) = setup_routes(&self.config, &self.interface_name) {
                log::error!("Failed to setup userspace routes: {}", e);
                let cleanup_config = self.gateway_state.read().config.clone();
                cleanup_runtime(&cleanup_config, &self.interface_name);
                return Err(DatapathError::Config(e));
            }

            let mut worker_preps = Vec::new();
            for (worker_id, &fd) in fd_guard.fds.clone().iter().enumerate() {
                let tun_io = Arc::new(match crate::tun_io::AsyncTunIo::new(fd) {
                    Ok(io) => {
                        fd_guard.fds[worker_id] = -1;
                        io
                    }
                    Err(e) => {
                        log::error!("Failed to wrap TUN FD in AsyncTunIo: {}", e);
                        return Err(DatapathError::Io(e));
                    }
                });

                let udp_socket = match setup_udp_socket(None) {
                    Ok(s) => s,
                    Err(e) => {
                        let cleanup_config = self.gateway_state.read().config.clone();
                        cleanup_runtime(&cleanup_config, &self.interface_name);
                        return Err(e);
                    }
                };

                let endpoint = setup_client_endpoint();
                worker_preps.push((tun_io, udp_socket, endpoint));
            }

            let userspace_tcp_failover_task = crate::start_userspace_tcp_failover_manager(
                self.gateway_state.clone(),
                self.client_quic_pools.clone(),
                dp_snapshot.clone(),
                self.config.interface.private_key,
                self.client_quic_data_port_baseline.clone(),
                self.peer_mutation_lock.clone(),
            );

            let mut worker_tasks = Vec::new();
            for (worker_id, (tun_io, udp_socket, endpoint)) in worker_preps.into_iter().enumerate() {
                let mut worker = crate::rtc_loop::RtcWorker::new(
                    tun_io,
                    worker_id,
                    crate::rtc_loop::WorkerRole::Client,
                    crate::rtc_loop::RtcWorkerConfig {
                        mtu: self.config.interface.mtu,
                    },
                    udp_socket,
                    endpoint,
                    None,
                    None,
                    Some(self.shared_quic_registry.clone()),
                );
                worker.set_worker_stats(self.worker_telemetry_registry.get_or_create(worker_id));
                worker.set_peer_telemetry(self.peer_telemetries[worker_id].clone());

                let thread = spawn_worker_thread(
                    worker,
                    worker_id,
                    "client",
                    dp_snapshot.clone(),
                    exit_notify.clone(),
                );
                worker_tasks.push(WorkerTask { _thread: thread });
            }

            log::info!("------------------------------------------------------");
            log::info!("  Userspace multiqueue TUN transparent proxy running  ");
            log::info!("  All L3 and L4 traffic processed in userspace.       ");
            log::info!("------------------------------------------------------");

            tokio::select! {
                _ = crate::wait_for_shutdown() => {},
                _ = exit_notify.notified() => {
                    log::error!("A client worker thread exited prematurely; shutting down.");
                }
            }
            for t in worker_tasks {
                t.abort();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceConfig, QUICPoolConfig, XdpConfig};

    fn dummy_config() -> GatewayConfig {
        GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.2/24".parse().unwrap()],
                listen_port: None,
                listen_control_port: None,
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
                mode: "tun".to_string(),
            },
            peers: Vec::new(),
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: Vec::new(),
            },
            xdp: XdpConfig::default(),
        }
    }

    #[test]
    fn test_tun_datapath_new() {
        let config = dummy_config();
        let gateway_state = Arc::new(parking_lot::RwLock::new(crate::GatewayState {
            config: config.clone(),
            router: crate::routing::AllowedIPsRouter::new(),
            userspace_tcp_offload_enabled: true,
        }));
        
        let res = TunDatapath::new(
            config,
            "test_if".to_string(),
            RuntimeMode::Client,
            None,
            Vec::new(),
            Arc::new(crate::telemetry::WorkerTelemetryRegistry::new()),
            gateway_state,
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(parking_lot::Mutex::new(HashMap::new())),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(parking_lot::Mutex::new(0)),
            Arc::new(tokio::sync::Mutex::new(())),
        );
        assert!(res.is_ok());
    }
}
