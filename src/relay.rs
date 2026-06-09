use crate::quic_pool::QuicConnStats;
use quinn::{RecvStream, SendStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const RELAY_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_COPY_YIELD_BUDGET_BYTES: usize = 64 * 1024;

// 用户态 L4 (QUIC) 统计指标（聚合到 peer 级别）
pub struct PeerL4Stats {
    pub tx_bytes: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
    pub active_streams: AtomicU64,
}

impl Default for PeerL4Stats {
    fn default() -> Self {
        Self {
            tx_bytes: Arc::new(AtomicU64::new(0)),
            rx_bytes: Arc::new(AtomicU64::new(0)),
            active_streams: AtomicU64::new(0),
        }
    }
}

// 包装型 Reader：每次读取时同时更新多个计数器（peer 聚合 + 单物理连接）
pub struct CountingReader<R> {
    inner: R,
    counters: Vec<Arc<AtomicU64>>,
}

impl<R: AsyncRead + Unpin> CountingReader<R> {
    pub fn new(inner: R, counters: Vec<Arc<AtomicU64>>) -> Self {
        Self { inner, counters }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let prev_len = buf.filled().len();
        let pin = std::pin::Pin::new(&mut self.inner);
        match pin.poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(())) => {
                let read_bytes = buf.filled().len() - prev_len;
                if read_bytes > 0 {
                    for counter in &self.counters {
                        counter.fetch_add(read_bytes as u64, Ordering::Relaxed);
                    }
                }
                std::task::Poll::Ready(Ok(()))
            }
            res => res,
        }
    }
}

// TCP↔QUIC 双向流转发（同时更新 peer 聚合统计 + 单条物理 QUIC 连接统计）
pub async fn relay_connections_with_conn_stat(
    tcp_socket: TcpStream,
    quic_send: SendStream,
    quic_recv: RecvStream,
    stats: Arc<PeerL4Stats>,
    conn_stat: Arc<QuicConnStats>,
) {
    let (tcp_read, tcp_write) = tcp_socket.into_split();
    relay_connections_generic(
        tcp_read,
        tcp_write,
        quic_send,
        quic_recv,
        stats,
        Some(conn_stat),
    )
    .await;
}

use parking_lot::Mutex;
use std::sync::OnceLock;

static BUFFER_POOL: OnceLock<BufferPool> = OnceLock::new();

struct BufferPool {
    pool: Mutex<Vec<Box<[u8; 16 * 1024]>>>,
}

impl BufferPool {
    fn global() -> &'static BufferPool {
        BUFFER_POOL.get_or_init(|| BufferPool {
            pool: Mutex::new(Vec::with_capacity(64)),
        })
    }

    fn get() -> Box<[u8; 16 * 1024]> {
        if let Some(buf) = Self::global().pool.lock().pop() {
            buf
        } else {
            Box::new([0u8; 16 * 1024])
        }
    }

    fn put(buf: Box<[u8; 16 * 1024]>) {
        let mut p = Self::global().pool.lock();
        if p.len() < 128 {
            p.push(buf);
        }
    }
}

struct PooledBuffer(Option<Box<[u8; 16 * 1024]>>);

impl PooledBuffer {
    fn new() -> Self {
        Self(Some(BufferPool::get()))
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = [u8; 16 * 1024];
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().unwrap()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.0.take() {
            BufferPool::put(buf);
        }
    }
}

pub async fn relay_connections_generic<TR, TW, QR, QW>(
    tcp_read: TR,
    tcp_write: TW,
    quic_send: QW,
    quic_recv: QR,
    stats: Arc<PeerL4Stats>,
    conn_stat: Option<Arc<QuicConnStats>>,
) where
    TR: AsyncRead + Send + Unpin + 'static,
    TW: AsyncWrite + Send + Unpin + 'static,
    QW: AsyncWrite + Send + Unpin + 'static,
    QR: AsyncRead + Send + Unpin + 'static,
{
    struct ActiveStreamGuard {
        stats: Arc<PeerL4Stats>,
        conn_stat: Option<Arc<QuicConnStats>>,
    }

    impl Drop for ActiveStreamGuard {
        fn drop(&mut self) {
            self.stats.active_streams.fetch_sub(1, Ordering::Relaxed);
            if let Some(cs) = &self.conn_stat {
                cs.active_streams.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    // 1. 累加活跃流计数器（聚合 + 单连接）
    stats.active_streams.fetch_add(1, Ordering::Relaxed);
    if let Some(cs) = &conn_stat {
        cs.active_streams.fetch_add(1, Ordering::Relaxed);
    }
    let _active_stream_guard = ActiveStreamGuard {
        stats: stats.clone(),
        conn_stat: conn_stat.clone(),
    };

    // Keep L4 rx/tx aligned with WireGuard peer semantics:
    // rx = bytes received from the remote peer over QUIC, tx = bytes sent to it.
    let mut rx_counters = vec![stats.rx_bytes.clone()];
    let mut tx_counters = vec![stats.tx_bytes.clone()];
    if let Some(cs) = &conn_stat {
        rx_counters.push(cs.rx_bytes.clone());
        tx_counters.push(cs.tx_bytes.clone());
    }

    let counting_tcp_read = CountingReader::new(tcp_read, tx_counters);
    let counting_quic_read = CountingReader::new(quic_recv, rx_counters);

    let client_to_server = async move {
        let mut reader = counting_tcp_read;
        let mut writer = quic_send;
        if let Err(e) = relay_copy_with_idle(&mut reader, &mut writer).await {
            log::debug!("Client→Server relay error: {}", e);
        }
        let _ = writer.shutdown().await;
    };

    let server_to_client = async move {
        let mut reader = counting_quic_read;
        let mut writer = tcp_write;
        if let Err(e) = relay_copy_with_idle(&mut reader, &mut writer).await {
            log::debug!("Server→Client relay error: {}", e);
        }
        let _ = writer.shutdown().await;
    };

    // 4. 并发等待双方关闭，配合 10 秒优雅半关闭超时机制，避免连接悬挂。
    let mut c2s = Box::pin(client_to_server);
    let mut s2c = Box::pin(server_to_client);

    tokio::select! {
        _ = &mut c2s => {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    log::debug!("Server→Client relay half-close grace period expired");
                }
                _ = &mut s2c => {}
            }
        }
        _ = &mut s2c => {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    log::debug!("Client→Server relay half-close grace period expired");
                }
                _ = &mut c2s => {}
            }
        }
    }
}

async fn relay_copy_with_idle<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = PooledBuffer::new();
    let mut copied = 0u64;
    let mut copied_since_yield = 0usize;
    loop {
        let n = match tokio::time::timeout(RELAY_IDLE_TIMEOUT, reader.read(&mut buf[..])).await {
            Ok(res) => res?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "relay idle timeout",
                ));
            }
        };
        if n == 0 {
            return Ok(copied);
        }
        match tokio::time::timeout(RELAY_WRITE_TIMEOUT, writer.write_all(&buf[..n])).await {
            Ok(res) => res?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "relay write timeout",
                ));
            }
        }
        copied += n as u64;
        copied_since_yield += n;
        if copied_since_yield >= RELAY_COPY_YIELD_BUDGET_BYTES {
            copied_since_yield = 0;
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_counting_reader_multi_counter() {
        use tokio::io::AsyncReadExt;
        let data = b"hello world";
        let counter1 = Arc::new(AtomicU64::new(0));
        let counter2 = Arc::new(AtomicU64::new(0));
        let mut reader = CountingReader::new(&data[..], vec![counter1.clone(), counter2.clone()]);
        let mut buf = vec![0u8; 64];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, data.len());
        assert_eq!(counter1.load(Ordering::Relaxed), data.len() as u64);
        assert_eq!(counter2.load(Ordering::Relaxed), data.len() as u64);
    }

    #[tokio::test]
    async fn test_relay_connections_generic_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (tcp_client, mut tcp_server) = tokio::io::duplex(64);
        let (quic_client_read, mut quic_client_write) = tokio::io::duplex(64);
        let (mut quic_server_read, quic_server_write) = tokio::io::duplex(64);

        let stats = Arc::new(PeerL4Stats::default());
        let conn_stat = Arc::new(QuicConnStats::new(
            "127.0.0.1:12345".parse().unwrap(),
            40001,
        ));

        let (tcp_read, tcp_write) = tokio::io::split(tcp_client);
        let stats_clone = stats.clone();
        let conn_stat_clone = conn_stat.clone();

        let relay_task = tokio::spawn(async move {
            relay_connections_generic(
                tcp_read,
                tcp_write,
                quic_server_write,
                quic_client_read,
                stats_clone,
                Some(conn_stat_clone),
            )
            .await;
        });

        // 写入 TCP 数据
        tcp_server.write_all(b"hello tcp").await.unwrap();
        // QUIC 侧接收
        let mut buf = [0u8; 9];
        quic_server_read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello tcp");

        // 写入 QUIC 数据
        quic_client_write.write_all(b"hello quic").await.unwrap();
        // TCP 侧接收
        let mut buf2 = [0u8; 10];
        tcp_server.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello quic");

        // 触发 TCP FIN 半关闭
        tcp_server.shutdown().await.unwrap();
        // QUIC 应该读到 EOF
        let n = quic_server_read.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        // 触发 QUIC FIN 半关闭
        quic_client_write.shutdown().await.unwrap();
        // TCP 应该读到 EOF
        let n2 = tcp_server.read(&mut buf2).await.unwrap();
        assert_eq!(n2, 0);

        relay_task.await.unwrap();

        // 验证流量计数器更新正确
        assert_eq!(stats.rx_bytes.load(Ordering::Relaxed), 10);
        assert_eq!(stats.tx_bytes.load(Ordering::Relaxed), 9);
        assert_eq!(conn_stat.rx_bytes.load(Ordering::Relaxed), 10);
        assert_eq!(conn_stat.tx_bytes.load(Ordering::Relaxed), 9);
        assert_eq!(stats.active_streams.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_relay_copy_with_idle_timeout() {
        tokio::time::pause();

        let (mut client, _server) = tokio::io::duplex(64);
        let (mut writer_client, _writer_server) = tokio::io::duplex(64);

        let relay_fut = relay_copy_with_idle(&mut client, &mut writer_client);
        tokio::pin!(relay_fut);

        tokio::select! {
            _ = &mut relay_fut => {
                panic!("Should not complete immediately");
            }
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }

        tokio::time::advance(RELAY_IDLE_TIMEOUT + Duration::from_secs(1)).await;

        let res = relay_fut.await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }
}
