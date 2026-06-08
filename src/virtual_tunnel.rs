use parking_lot::{Mutex, RwLock};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

const RECV_QUEUE_PACKET_LIMIT: usize = 512;
const RECV_QUEUE_BYTES_LIMIT: usize = 16 * 1024 * 1024;
type RecvQueue = Arc<Mutex<VecDeque<(Vec<u8>, SocketAddr)>>>;

#[derive(Clone)]
struct PhysicalSocket {
    socket: Arc<UdpSocket>,
    last_pong: Arc<RwLock<Option<Instant>>>,
}

struct VirtualTunnelSocketInner {
    sockets: Vec<PhysicalSocket>,
    active_idx: Arc<AtomicUsize>,
    last_target: Arc<RwLock<Option<SocketAddr>>>,
    recv_queue: RecvQueue,
    recv_queue_bytes: Arc<AtomicUsize>,
    recv_notify: Arc<Notify>,
    abort_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for VirtualTunnelSocketInner {
    fn drop(&mut self) {
        for handle in &self.abort_handles {
            handle.abort();
        }
    }
}

#[derive(Clone)]
pub struct VirtualTunnelSocket {
    inner: Arc<VirtualTunnelSocketInner>,
}

impl VirtualTunnelSocket {
    pub fn new(sockets: Vec<UdpSocket>) -> Result<Self, String> {
        if sockets.is_empty() {
            return Err("VirtualTunnelSocket requires at least one physical socket".to_string());
        }
        let last_target = Arc::new(RwLock::new(None));
        let mut abort_handles = Vec::new();
        let mut physical_sockets = Vec::new();
        let recv_queue = Arc::new(Mutex::new(VecDeque::new()));
        let recv_queue_bytes = Arc::new(AtomicUsize::new(0));
        let recv_notify = Arc::new(Notify::new());

        for socket in sockets {
            let socket = Arc::new(socket);
            let last_pong = Arc::new(RwLock::new(None));
            physical_sockets.push(PhysicalSocket {
                socket: socket.clone(),
                last_pong: last_pong.clone(),
            });

            let recv_queue_clone = recv_queue.clone();
            let recv_queue_bytes_clone = recv_queue_bytes.clone();
            let recv_notify_clone = recv_notify.clone();
            let socket_clone = socket.clone();
            let last_pong_clone = last_pong.clone();
            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match socket_clone.recv_from(&mut buf).await {
                        Ok((n, addr)) => {
                            if n == 0 {
                                continue;
                            }
                            let data = &buf[..n];
                            if n >= 4 && data == b"PONG" {
                                *last_pong_clone.write() = Some(Instant::now());
                                continue;
                            }
                            if n >= 4 && data == b"PING" {
                                let _ = socket_clone.send_to(b"PONG", addr).await;
                                continue;
                            }
                            let mut queue = recv_queue_clone.lock();
                            let queued_bytes = recv_queue_bytes_clone.load(Ordering::Relaxed);
                            if queued_bytes.saturating_add(n) > RECV_QUEUE_BYTES_LIMIT {
                                log::warn!(
                                    "Virtual tunnel receive queue byte limit reached; dropping packet from {}",
                                    addr
                                );
                                continue;
                            }
                            if queue.len() >= RECV_QUEUE_PACKET_LIMIT {
                                log::warn!(
                                    "Virtual tunnel receive queue packet limit reached; dropping packet from {}",
                                    addr
                                );
                                continue;
                            }
                            queue.push_back((data.to_vec(), addr));
                            recv_queue_bytes_clone.fetch_add(n, Ordering::Relaxed);
                            drop(queue);
                            recv_notify_clone.notify_one();
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            });
            abort_handles.push(handle);
        }

        let active_idx = Arc::new(AtomicUsize::new(0));
        let sockets_for_ping = physical_sockets.clone();
        let last_target_for_ping = last_target.clone();
        let active_idx_for_ping = active_idx.clone();

        // Spawn background ping task running every 1 second
        let ping_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let target = *last_target_for_ping.read();

                if let Some(target_addr) = target {
                    for p_socket in &sockets_for_ping {
                        let _ = p_socket.socket.send_to(b"PING", target_addr).await;
                    }
                }

                // Evaluate health
                let now = Instant::now();
                let mut best_idx = 0;
                let mut best_time = None;
                for (i, p_socket) in sockets_for_ping.iter().enumerate() {
                    let pong_time = *p_socket.last_pong.read();
                    if let Some(t) = pong_time {
                        if now.duration_since(t) < Duration::from_secs(5)
                            && best_time.is_none_or(|bt| t > bt)
                        {
                            best_time = Some(t);
                            best_idx = i;
                        }
                    }
                }

                // Update active index
                let prev_idx = active_idx_for_ping.load(Ordering::Relaxed);
                if best_idx != prev_idx {
                    log::info!(
                        "Switching active virtual tunnel socket index from {} to {}",
                        prev_idx,
                        best_idx
                    );
                    active_idx_for_ping.store(best_idx, Ordering::Relaxed);
                }
            }
        });
        abort_handles.push(ping_handle);

        let inner = Arc::new(VirtualTunnelSocketInner {
            sockets: physical_sockets,
            active_idx,
            last_target,
            recv_queue,
            recv_queue_bytes,
            recv_notify,
            abort_handles,
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

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            if let Some((data, addr)) = {
                let mut queue = self.inner.recv_queue.lock();
                let item = queue.pop_front();
                if let Some((data, _)) = &item {
                    self.inner
                        .recv_queue_bytes
                        .fetch_sub(data.len(), Ordering::Relaxed);
                }
                item
            } {
                if data.len() <= buf.len() {
                    buf[..data.len()].copy_from_slice(&data);
                    return Ok((data.len(), addr));
                } else {
                    return Err(io::Error::other("buffer too small"));
                }
            }
            self.inner.recv_notify.notified().await;
        }
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
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn virtual_tunnel_socket_rejects_empty_physical_socket_set() {
        assert!(VirtualTunnelSocket::new(Vec::new()).is_err());
    }

    #[tokio::test]
    async fn virtual_tunnel_recv_waiters_do_not_hold_global_async_lock() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();
        let vt = VirtualTunnelSocket::new(vec![socket]).unwrap();

        let recv_a = {
            let vt = vt.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 16];
                let (n, _) = vt.recv_from(&mut buf).await.unwrap();
                buf[..n].to_vec()
            })
        };
        let recv_b = {
            let vt = vt.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 16];
                let (n, _) = vt.recv_from(&mut buf).await.unwrap();
                buf[..n].to_vec()
            })
        };

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"one", local_addr).await.unwrap();
        sender.send_to(b"two", local_addr).await.unwrap();

        let first = tokio::time::timeout(Duration::from_secs(1), recv_a)
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(1), recv_b)
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![first, second];
        received.sort();
        assert_eq!(received, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[tokio::test]
    async fn test_virtual_tunnel_socket_failover() {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr1 = s1.local_addr().unwrap();
        let local_addr2 = s2.local_addr().unwrap();

        let server1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr1 = server1.local_addr().unwrap();
        let srv_addr2 = server2.local_addr().unwrap();

        let vt = VirtualTunnelSocket::new(vec![s1, s2]).unwrap();

        // Initially index 0 is active, sends to server1
        let n = vt.send_to(b"hello", srv_addr1).await.unwrap();
        assert_eq!(n, 5);

        let mut buf = [0u8; 100];
        let (n_recv, from_addr) = server1.recv_from(&mut buf).await.unwrap();
        assert_eq!(n_recv, 5);
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(from_addr, local_addr1);

        // Spawn mock servers to handle pings.
        // server1 ignores pings (path 1 blocked).
        // server2 responds to pings (path 2 healthy).
        let srv1_handle = tokio::spawn(async move {
            let mut buf = [0u8; 100];
            while let Ok((n, _addr)) = server1.recv_from(&mut buf).await {
                if &buf[..n] == b"PING" {
                    // Ignore ping to simulate path failure
                }
            }
        });

        let (tx2, mut rx2) = mpsc::channel(100);
        let srv2_handle = tokio::spawn(async move {
            let mut buf = [0u8; 100];
            while let Ok((n, addr)) = server2.recv_from(&mut buf).await {
                if &buf[..n] == b"PING" {
                    let _ = server2.send_to(b"PONG", addr).await;
                } else {
                    let _ = tx2.send((buf[..n].to_vec(), addr)).await;
                }
            }
        });

        // Trigger pinging target on srv_addr2
        let _ = vt.send_to(b"trigger", srv_addr2).await.unwrap();

        // Drain the trigger packet from rx2
        let (trigger_data, _) = tokio::time::timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(trigger_data, b"trigger");

        // Wait for failover detection (> 2 seconds to allow ping tick and switch)
        tokio::time::sleep(Duration::from_millis(2500)).await;

        // Verify active index switched to 1
        assert_eq!(vt.inner.active_idx.load(Ordering::Relaxed), 1);

        // Send a new message, should go via socket 2 to server 2
        let n = vt.send_to(b"world", srv_addr2).await.unwrap();
        assert_eq!(n, 5);

        // Read from mock server 2's channel
        let (data2, from_addr2) = tokio::time::timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data2, b"world");
        assert_eq!(from_addr2, local_addr2);

        srv1_handle.abort();
        srv2_handle.abort();
    }
}
