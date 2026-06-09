use parking_lot::RwLock;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct VirtualTunnelTelemetrySnapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub control_packets: u64,
    pub recv_errors: u64,
}

#[derive(Default)]
pub struct VirtualTunnelTelemetry {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    control_packets: AtomicU64,
    recv_errors: AtomicU64,
}

impl VirtualTunnelTelemetry {
    pub fn snapshot(&self) -> VirtualTunnelTelemetrySnapshot {
        VirtualTunnelTelemetrySnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            control_packets: self.control_packets.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
        }
    }

    fn record_rx(&self, bytes: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn record_control(&self) {
        self.control_packets.fetch_add(1, Ordering::Relaxed);
    }

    fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct PhysicalSocket {
    socket: Arc<UdpSocket>,
    last_pong: Arc<RwLock<Option<Instant>>>,
}

struct VirtualTunnelSocketInner {
    sockets: Vec<PhysicalSocket>,
    active_idx: Arc<AtomicUsize>,
    last_target: Arc<RwLock<Option<SocketAddr>>>,
    telemetry: Arc<VirtualTunnelTelemetry>,
}

#[derive(Clone)]
pub struct VirtualTunnelSocket {
    inner: Arc<VirtualTunnelSocketInner>,
}

impl VirtualTunnelSocket {
    pub fn new(sockets: Vec<UdpSocket>) -> Result<Self, String> {
        Self::new_with_telemetry(sockets, Arc::new(VirtualTunnelTelemetry::default()))
    }

    pub fn new_with_telemetry(
        sockets: Vec<UdpSocket>,
        telemetry: Arc<VirtualTunnelTelemetry>,
    ) -> Result<Self, String> {
        if sockets.is_empty() {
            return Err("VirtualTunnelSocket requires at least one physical socket".to_string());
        }
        let last_target = Arc::new(RwLock::new(None));
        let mut physical_sockets = Vec::new();

        for socket in sockets {
            let socket = Arc::new(socket);
            let last_pong = Arc::new(RwLock::new(None));
            physical_sockets.push(PhysicalSocket {
                socket: socket.clone(),
                last_pong: last_pong.clone(),
            });
        }

        let active_idx = Arc::new(AtomicUsize::new(0));

        let inner = Arc::new(VirtualTunnelSocketInner {
            sockets: physical_sockets,
            active_idx,
            last_target,
            telemetry,
        });

        Ok(Self { inner })
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let needs_write = {
            let guard = self.inner.last_target.read();
            *guard != Some(target)
        };
        if needs_write {
            *self.inner.last_target.write() = Some(target);
        }

        let active_idx = self.inner.active_idx.load(Ordering::Relaxed);
        let socket = &self.inner.sockets[active_idx].socket;
        socket.send_to(buf, target).await
    }

    pub fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        let needs_write = {
            let guard = self.inner.last_target.read();
            *guard != Some(target)
        };
        if needs_write {
            *self.inner.last_target.write() = Some(target);
        }

        let active_idx = self.inner.active_idx.load(Ordering::Relaxed);
        let socket = &self.inner.sockets[active_idx].socket;
        socket.try_send_to(buf, target)
    }

    pub async fn writable(&self) -> io::Result<()> {
        let active_idx = self.inner.active_idx.load(Ordering::Relaxed);
        self.inner.sockets[active_idx].socket.writable().await
    }

    pub fn tick_control(&self) {
        let target = *self.inner.last_target.read();
        if let Some(target_addr) = target {
            for physical in &self.inner.sockets {
                let _ = physical.socket.try_send_to(b"PING", target_addr);
            }
        }

        let now = Instant::now();
        let prev_idx = self.inner.active_idx.load(Ordering::Relaxed);
        let mut best_idx = prev_idx;
        let mut best_time = None;
        for (idx, physical) in self.inner.sockets.iter().enumerate() {
            let pong_time = *physical.last_pong.read();
            if let Some(t) = pong_time {
                if now.duration_since(t) < Duration::from_secs(5)
                    && best_time.is_none_or(|bt| t > bt)
                {
                    best_time = Some(t);
                    best_idx = idx;
                }
            }
        }

        if best_idx != prev_idx {
            log::info!(
                "Switching active virtual tunnel socket index from {} to {}",
                prev_idx,
                best_idx
            );
            self.inner.active_idx.store(best_idx, Ordering::Relaxed);
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let ready_idx = poll_fn(|cx| {
                for (idx, physical) in self.inner.sockets.iter().enumerate() {
                    match physical.socket.poll_recv_ready(cx) {
                        Poll::Ready(Ok(())) => return Poll::Ready(Ok(idx)),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {}
                    }
                }
                Poll::Pending
            })
            .await?;

            let physical = &self.inner.sockets[ready_idx];
            match physical.socket.try_recv_from(buf) {
                Ok((0, _)) => continue,
                Ok((n, addr)) => {
                    if n >= 4 && &buf[..n] == b"PONG" {
                        *physical.last_pong.write() = Some(Instant::now());
                        self.inner.telemetry.record_control();
                        continue;
                    }
                    if n >= 4 && &buf[..n] == b"PING" {
                        self.inner.telemetry.record_control();
                        let _ = physical.socket.try_send_to(b"PONG", addr);
                        continue;
                    }
                    self.inner.telemetry.record_rx(n);
                    return Ok((n, addr));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    self.inner.telemetry.record_recv_error();
                    return Err(e);
                }
            }
        }
    }

    pub fn telemetry_snapshot(&self) -> VirtualTunnelTelemetrySnapshot {
        self.inner.telemetry.snapshot()
    }
}

#[derive(Clone)]
pub enum TunnelSocket {
    Single(Arc<UdpSocket>),
    Virtual(VirtualTunnelSocket),
}

impl TunnelSocket {
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Single(s) => s.send_to(buf, target).await,
            Self::Virtual(s) => s.send_to(buf, target).await,
        }
    }

    pub fn try_send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Single(s) => s.try_send_to(buf, target),
            Self::Virtual(s) => s.try_send_to(buf, target),
        }
    }

    pub async fn writable(&self) -> io::Result<()> {
        match self {
            Self::Single(s) => s.writable().await,
            Self::Virtual(s) => s.writable().await,
        }
    }

    pub fn tick_control(&self) {
        if let Self::Virtual(s) = self {
            s.tick_control();
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Single(s) => s.recv_from(buf).await,
            Self::Virtual(s) => s.recv_from(buf).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn virtual_tunnel_socket_rejects_empty_physical_socket_set() {
        assert!(VirtualTunnelSocket::new(Vec::new()).is_err());
    }

    #[tokio::test]
    async fn virtual_tunnel_sequential_recv_uses_caller_buffer_without_queue() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let vt = VirtualTunnelSocket::new(vec![socket]).unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"one", local_addr).await.unwrap();
        sender.send_to(b"two", local_addr).await.unwrap();

        let mut first_buf = [0u8; 16];
        let (first_len, _) = vt.recv_from(&mut first_buf).await.unwrap();
        let mut second_buf = [0u8; 16];
        let (second_len, _) = vt.recv_from(&mut second_buf).await.unwrap();
        let mut received = vec![
            first_buf[..first_len].to_vec(),
            second_buf[..second_len].to_vec(),
        ];
        received.sort();
        assert_eq!(received, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[tokio::test]
    async fn virtual_tunnel_does_not_consume_business_packets_before_recv() {
        let telemetry = Arc::new(VirtualTunnelTelemetry::default());
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let vt = VirtualTunnelSocket::new_with_telemetry(vec![socket], telemetry.clone()).unwrap();

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"direct", local_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(telemetry.snapshot().rx_packets, 0);

        let mut buf = [0u8; 16];
        let (n, _) = vt.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"direct");
        assert_eq!(telemetry.snapshot().rx_packets, 1);
    }

    #[tokio::test]
    async fn virtual_tunnel_recv_reads_directly_from_multiple_physical_sockets() {
        let telemetry = Arc::new(VirtualTunnelTelemetry::default());
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr1 = s1.local_addr().unwrap();
        let addr2 = s2.local_addr().unwrap();
        let vt = VirtualTunnelSocket::new_with_telemetry(vec![s1, s2], telemetry.clone()).unwrap();

        let sender_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender_a.send_to(b"a", addr1).await.unwrap();
        sender_b.send_to(b"b", addr2).await.unwrap();

        let mut first = [0u8; 16];
        let (n_first, _) = vt.recv_from(&mut first).await.unwrap();
        let mut second = [0u8; 16];
        let (n_second, _) = vt.recv_from(&mut second).await.unwrap();
        let mut received = vec![first[..n_first].to_vec(), second[..n_second].to_vec()];
        received.sort();

        let snapshot = telemetry.snapshot();
        assert_eq!(received, vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(snapshot.rx_packets, 2);
        drop(vt);
    }

    #[tokio::test]
    async fn virtual_tunnel_keeps_active_socket_when_all_pongs_are_stale() {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let vt = VirtualTunnelSocket::new(vec![s1, s2]).unwrap();

        vt.inner.active_idx.store(1, Ordering::Relaxed);
        for physical in &vt.inner.sockets {
            *physical.last_pong.write() = Some(Instant::now() - Duration::from_secs(10));
        }

        vt.tick_control();

        assert_eq!(vt.inner.active_idx.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn virtual_tunnel_has_no_background_task_spawn() {
        let source = include_str!("virtual_tunnel.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        assert!(!source.contains("tokio::spawn"));
    }

    #[tokio::test]
    async fn virtual_tunnel_tick_control_sends_ping_and_selects_fresh_pong_socket() {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr2 = s2.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = server.local_addr().unwrap();
        let vt = VirtualTunnelSocket::new(vec![s1, s2]).unwrap();

        vt.send_to(b"seed", srv_addr).await.unwrap();
        vt.tick_control();

        let mut pings = Vec::new();
        let mut buf = [0u8; 16];
        for _ in 0..3 {
            let (n, from) =
                tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            if &buf[..n] == b"PING" {
                pings.push(from);
            }
        }
        assert_eq!(pings.len(), 2);
        assert!(pings.contains(&addr2));

        server.send_to(b"PONG", addr2).await.unwrap();
        let mut recv_buf = [0u8; 16];
        let _ = tokio::time::timeout(Duration::from_millis(100), vt.recv_from(&mut recv_buf)).await;

        vt.tick_control();
        assert_eq!(vt.inner.active_idx.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn virtual_tunnel_send_uses_active_physical_socket() {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr2 = s2.local_addr().unwrap();

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = server.local_addr().unwrap();

        let vt = VirtualTunnelSocket::new(vec![s1, s2]).unwrap();
        vt.inner.active_idx.store(1, Ordering::Relaxed);

        vt.send_to(b"first", srv_addr).await.unwrap();
        vt.send_to(b"second", srv_addr).await.unwrap();

        let mut buf = [0u8; 16];
        let (_, from_a) = server.recv_from(&mut buf).await.unwrap();
        let (_, from_b) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(from_a, local_addr2);
        assert_eq!(from_b, local_addr2);
    }
}
