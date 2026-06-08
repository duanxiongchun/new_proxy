use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::io;

#[derive(Clone)]
struct PhysicalSocket {
    socket: Arc<UdpSocket>,
    last_pong: Arc<RwLock<Option<Instant>>>,
}

struct VirtualTunnelSocketInner {
    sockets: Vec<PhysicalSocket>,
    active_idx: Arc<AtomicUsize>,
    last_target: Arc<RwLock<Option<SocketAddr>>>,
    recv_rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
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
    pub fn new(sockets: Vec<UdpSocket>) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(10000);
        let last_target = Arc::new(RwLock::new(None));
        let mut abort_handles = Vec::new();
        let mut physical_sockets = Vec::new();

        for socket in sockets {
            let socket = Arc::new(socket);
            let last_pong = Arc::new(RwLock::new(None));
            physical_sockets.push(PhysicalSocket {
                socket: socket.clone(),
                last_pong: last_pong.clone(),
            });

            // Spawn receiver loop for this socket
            let recv_tx_clone = recv_tx.clone();
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
                            // Forward data packet
                            if recv_tx_clone.send((data.to_vec(), addr)).await.is_err() {
                                break;
                            }
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
                        if now.duration_since(t) < Duration::from_secs(5) {
                            if best_time.map_or(true, |bt| t > bt) {
                                best_time = Some(t);
                                best_idx = i;
                            }
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
            recv_rx: Mutex::new(recv_rx),
            abort_handles,
        });

        Self { inner }
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
        let mut rx = self.inner.recv_rx.lock().await;
        match rx.recv().await {
            Some((data, addr)) => {
                if data.len() <= buf.len() {
                    buf[..data.len()].copy_from_slice(&data);
                    Ok((data.len(), addr))
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "buffer too small"))
                }
            }
            None => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "channel closed")),
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

        let vt = VirtualTunnelSocket::new(vec![s1, s2]);

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
