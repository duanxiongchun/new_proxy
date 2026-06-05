use crate::tun_io::AsyncTunIo;
use crate::userspace_tcp::UserspaceTcpStack;
use crate::userspace_wg::UserspaceWg;
use boringtun::noise::TunnResult;
use smoltcp::socket::tcp;
use smoltcp::socket::AnySocket;
use smoltcp::iface::SocketHandle;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;

pub fn get_ip_protocol(packet: &[u8]) -> Option<u8> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() >= 20 {
                Some(packet[9])
            } else {
                None
            }
        }
        6 => {
            if packet.len() >= 40 {
                Some(packet[6])
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn parse_tcp_packet(packet: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, bool)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            let proto = packet[9];
            if proto != 6 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if packet.len() < ihl + 20 {
                return None;
            }
            let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
            let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
            
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            let flags = packet[ihl + 13];
            let is_syn = (flags & 0x02) != 0;
            Some((src_ip, src_port, dst_ip, dst_port, is_syn))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let proto = packet[6];
            if proto != 6 {
                return None;
            }
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&packet[8..24]);
            let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(src_bytes));
            
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&packet[24..40]);
            let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(dst_bytes));
            
            let src_port = u16::from_be_bytes([packet[40], packet[41]]);
            let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
            let flags = packet[53];
            let is_syn = (flags & 0x02) != 0;
            Some((src_ip, src_port, dst_ip, dst_port, is_syn))
        }
        _ => None,
    }
}

pub fn rewrite_destination_ip(packet: &mut [u8], new_dst: IpAddr) {
    let version = packet[0] >> 4;
    match (version, new_dst) {
        (4, IpAddr::V4(addr)) => {
            let octets = addr.octets();
            packet[16..20].copy_from_slice(&octets);
        }
        (6, IpAddr::V6(addr)) => {
            let octets = addr.octets();
            packet[24..40].copy_from_slice(&octets);
        }
        _ => {}
    }
}

pub fn rewrite_source_ip(packet: &mut [u8], new_src: IpAddr) {
    let version = packet[0] >> 4;
    match (version, new_src) {
        (4, IpAddr::V4(addr)) => {
            let octets = addr.octets();
            packet[12..16].copy_from_slice(&octets);
        }
        (6, IpAddr::V6(addr)) => {
            let octets = addr.octets();
            packet[8..24].copy_from_slice(&octets);
        }
        _ => {}
    }
}

pub struct BridgeChannels {
    pub tx_sender: mpsc::Sender<Vec<u8>>,
    pub rx_receiver: mpsc::Receiver<Vec<u8>>,
}

pub struct RtcWorker {
    pub tun_io: Arc<AsyncTunIo>,
    pub udp_socket: Arc<tokio::net::UdpSocket>,
    pub server_endpoint: SocketAddr,
    pub wg: UserspaceWg,
    pub tcp_stack: UserspaceTcpStack,
    pub bridges: HashMap<SocketHandle, BridgeChannels>,
    pub active_conn_handler: Option<Arc<dyn Fn(SocketAddr, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>) + Send + Sync>>,
    pub nat_map: HashMap<(IpAddr, u16, u16), IpAddr>,
}

impl RtcWorker {
    pub fn new(
        tun_io: Arc<AsyncTunIo>,
        udp_socket: Arc<tokio::net::UdpSocket>,
        server_endpoint: SocketAddr,
        wg: UserspaceWg,
        tcp_stack: UserspaceTcpStack,
    ) -> Self {
        Self {
            tun_io,
            udp_socket,
            server_endpoint,
            wg,
            tcp_stack,
            bridges: HashMap::new(),
            active_conn_handler: None,
            nat_map: HashMap::new(),
        }
    }

    pub async fn run_one_iteration(&mut self) -> Result<std::time::Duration, String> {
        let now = smoltcp::time::Instant::now();
        self.tcp_stack.iface.poll(now, &mut self.tcp_stack.device, &mut self.tcp_stack.sockets);

        // Flush outgoing TCP packets from smoltcp to TUN
        while let Some(mut pkt) = self.tcp_stack.device.tx_queue.pop_front() {
            if let Some((_src_ip, src_port, dst_ip, dst_port, _)) = parse_tcp_packet(&pkt) {
                let key = (dst_ip, dst_port, src_port);
                if let Some(&orig_dst_ip) = self.nat_map.get(&key) {
                    rewrite_source_ip(&mut pkt, orig_dst_ip);
                }
            }
            let _ = self.tun_io.write(&pkt).await;
        }

        // Handle active TCP bridges
        self.handle_bridges().await;

        let poll_delay = self.tcp_stack.iface.poll_delay(now, &self.tcp_stack.sockets)
            .unwrap_or(smoltcp::time::Duration::from_millis(10));
        Ok(std::time::Duration::from_millis(poll_delay.total_millis()))
    }

    pub async fn run_loop(&mut self) -> Result<(), String> {
        let mut tun_buf = vec![0u8; 65535];
        let mut udp_buf = vec![0u8; 65535];
        let mut wg_buf = vec![0u8; 65535];

        let mut timer_interval = tokio::time::interval(std::time::Duration::from_millis(100));

        loop {
            let now = smoltcp::time::Instant::now();
            self.tcp_stack.iface.poll(now, &mut self.tcp_stack.device, &mut self.tcp_stack.sockets);

            // Flush outgoing TCP packets from smoltcp to TUN, applying NAT reverse rewrite
            while let Some(mut pkt) = self.tcp_stack.device.tx_queue.pop_front() {
                if let Some((_src_ip, src_port, dst_ip, dst_port, _)) = parse_tcp_packet(&pkt) {
                    let key = (dst_ip, dst_port, src_port);
                    if let Some(&orig_dst_ip) = self.nat_map.get(&key) {
                        rewrite_source_ip(&mut pkt, orig_dst_ip);
                    }
                }
                let _ = self.tun_io.write(&pkt).await;
            }

            self.handle_bridges().await;

            let poll_delay = self.tcp_stack.iface.poll_delay(now, &self.tcp_stack.sockets)
                .unwrap_or(smoltcp::time::Duration::from_millis(10));
            let delay_duration = std::time::Duration::from_millis(poll_delay.total_millis());

            tokio::select! {
                read_res = self.tun_io.read(&mut tun_buf) => {
                    match read_res {
                        Ok(n) if n > 0 => {
                            let packet = &mut tun_buf[..n];
                            if let Some((src_ip, src_port, dst_ip, dst_port, is_syn)) = parse_tcp_packet(packet) {
                                if is_syn {
                                    let has_listening = self.tcp_stack.sockets.iter().any(|(_, s)| {
                                        if let Some(s) = tcp::Socket::downcast(s) {
                                            s.state() == tcp::State::Listen && s.local_endpoint().map(|ep| ep.port == dst_port).unwrap_or(false)
                                        } else {
                                            false
                                        }
                                    });
                                    if !has_listening {
                                        if let Ok(handle) = self.tcp_stack.create_tcp_socket(65535, 65535) {
                                            let s = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);
                                            let _ = s.listen(dst_port);
                                            log::debug!("Created userspace listening TCP socket on port {}", dst_port);
                                        }
                                    }
                                }

                                self.nat_map.insert((src_ip, src_port, dst_port), dst_ip);

                                let local_ip = if dst_ip.is_ipv4() {
                                    IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2))
                                } else {
                                    IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
                                };
                                rewrite_destination_ip(packet, local_ip);

                                self.tcp_stack.process_input_packet(packet.to_vec());
                            } else {
                                match self.wg.encapsulate(packet, &mut wg_buf) {
                                    TunnResult::WriteToNetwork(enc_pkt) => {
                                        let _ = self.udp_socket.send_to(enc_pkt, self.server_endpoint).await;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }

                udp_res = self.udp_socket.recv_from(&mut udp_buf) => {
                    match udp_res {
                        Ok((n, addr)) if addr == self.server_endpoint => {
                            let enc_packet = &udp_buf[..n];
                            let mut dec_dst = vec![0u8; 65535];
                            match self.wg.decapsulate(None, enc_packet, &mut dec_dst) {
                                TunnResult::WriteToTunnelV4(dec_pkt, _) | TunnResult::WriteToTunnelV6(dec_pkt, _) => {
                                    let _ = self.tun_io.write(dec_pkt).await;
                                }
                                TunnResult::WriteToNetwork(resp_pkt) => {
                                    let _ = self.udp_socket.send_to(resp_pkt, self.server_endpoint).await;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }

                _ = tokio::time::sleep(delay_duration) => {}

                _ = timer_interval.tick() => {
                    match self.wg.update_timers(&mut wg_buf) {
                        TunnResult::WriteToNetwork(resp_pkt) => {
                            let _ = self.udp_socket.send_to(resp_pkt, self.server_endpoint).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn handle_bridges(&mut self) {
        let mut closed_handles = Vec::new();

        // Check for new connections in smoltcp
        let mut new_connections = Vec::new();
        for (handle, socket) in self.tcp_stack.sockets.iter_mut() {
            if let Some(socket) = tcp::Socket::downcast_mut(socket) {
                if socket.is_active() && !self.bridges.contains_key(&handle) {
                    if let Some(local_endpoint) = socket.local_endpoint() {
                        let original_dest = SocketAddr::new(
                            match local_endpoint.addr {
                                smoltcp::wire::IpAddress::Ipv4(a) => std::net::IpAddr::V4(a.into()),
                                smoltcp::wire::IpAddress::Ipv6(a) => std::net::IpAddr::V6(a.into()),
                            },
                            local_endpoint.port,
                        );
                        new_connections.push((handle, original_dest));
                    }
                }
            }
        }

        for (handle, original_dest) in new_connections {
            if let Some(ref handler) = self.active_conn_handler {
                let (tx_sender, tx_receiver) = mpsc::channel(100);
                let (rx_sender, rx_receiver) = mpsc::channel(100);
                self.bridges.insert(handle, BridgeChannels { tx_sender, rx_receiver });
                let handler_clone = handler.clone();
                tokio::spawn(async move {
                    handler_clone(original_dest, tx_receiver, rx_sender);
                });
            }
        }

        // Process existing bridges
        for (&handle, bridge) in self.bridges.iter_mut() {
            let socket = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);
            
            if !socket.is_active() {
                closed_handles.push(handle);
                continue;
            }

            // 1. Read from smoltcp TCP socket -> send to QUIC task
            if socket.can_recv() {
                let mut buf = vec![0u8; 1500];
                if let Ok(n) = socket.recv_slice(&mut buf) {
                    if n > 0 {
                        buf.truncate(n);
                        let _ = bridge.tx_sender.try_send(buf);
                    }
                }
            }

            // 2. Receive from QUIC task -> write to smoltcp TCP socket
            if socket.can_send() {
                match bridge.rx_receiver.try_recv() {
                    Ok(data) => {
                        let _ = socket.send_slice(&data);
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        closed_handles.push(handle);
                    }
                    _ => {}
                }
            }
        }

        for handle in closed_handles {
            self.bridges.remove(&handle);
            let socket = self.tcp_stack.sockets.get_mut::<tcp::Socket>(handle);
            socket.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_packet_classification() {
        let ipv4_tcp_packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
            127, 0, 0, 1, 127, 0, 0, 1
        ];
        assert_eq!(get_ip_protocol(&ipv4_tcp_packet), Some(6));
    }

    #[test]
    fn test_rtc_worker_creation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let private_key = boringtun::x25519::StaticSecret::from([1u8; 32]);
            let public_key = boringtun::x25519::PublicKey::from(&private_key);
            let wg = UserspaceWg::new(private_key, public_key).unwrap();
            let ip_cidr = smoltcp::wire::IpCidr::from_str("10.0.0.2/24").unwrap();
            let tcp_stack = UserspaceTcpStack::new(ip_cidr).unwrap();
            let (sock1, _sock2) = std::os::unix::net::UnixStream::pair().unwrap();
            sock1.set_nonblocking(true).unwrap();
            let tun_io = Arc::new(AsyncTunIo::new(std::os::unix::io::AsRawFd::as_raw_fd(&sock1)).unwrap());
            let udp_socket = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
            udp_socket.set_nonblocking(true).unwrap();
            let tokio_udp = Arc::new(tokio::net::UdpSocket::from_std((*udp_socket).try_clone().unwrap()).unwrap());
            
            let mut worker = RtcWorker::new(
                tun_io,
                tokio_udp,
                "127.0.0.1:51820".parse().unwrap(),
                wg,
                tcp_stack,
            );
            let result = worker.run_one_iteration().await;
            assert!(result.is_ok());
        });
    }
}
