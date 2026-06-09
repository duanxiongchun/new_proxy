use crate::quic_pool::QuicConnStats;
use quinn::{RecvStream, SendStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
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

/// TCP/QUIC bidirectional stream relay loop with idle timeout.
///
/// **Performance Optimization Note:**
/// - Rather than allocating new timeout futures on every single read and write, we pin a single
///   `tokio::time::sleep` future to the stack and update its deadline in-place using `.reset()`.
/// - The write timeout has been removed in favor of transport-level keep-alives (TCP keep-alives
///   and QUIC max idle timeouts) to further reduce timer-wheel registration overhead on the hot path.
async fn relay_copy_with_idle<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = PooledBuffer::new();
    let mut copied = 0u64;
    let mut copied_since_yield = 0usize;

    let idle_sleep = tokio::time::sleep(RELAY_IDLE_TIMEOUT);
    tokio::pin!(idle_sleep);

    loop {
        let n = tokio::select! {
            res = reader.read(&mut buf[..]) => {
                res?
            }
            _ = &mut idle_sleep => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "relay idle timeout",
                ));
            }
        };

        if n == 0 {
            return Ok(copied);
        }

        writer.write_all(&buf[..n]).await?;

        idle_sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + RELAY_IDLE_TIMEOUT);

        copied += n as u64;
        copied_since_yield += n;
        if copied_since_yield >= RELAY_COPY_YIELD_BUDGET_BYTES {
            copied_since_yield = 0;
            tokio::task::yield_now().await;
        }
    }
}

pub async fn write_framed_packet<W: AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    if data.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "packet too large for u16 frame",
        ));
    }
    w.write_u16(data.len() as u16).await?;
    w.write_all(data).await?;
    Ok(())
}

pub async fn read_framed_packet<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> std::io::Result<Option<usize>> {
    let mut len_buf = [0u8; 2];
    let mut bytes_read = 0;
    while bytes_read < 2 {
        let n = r.read(&mut len_buf[bytes_read..2]).await?;
        if n == 0 {
            if bytes_read == 0 {
                return Ok(None);
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated framed packet length header",
                ));
            }
        }
        bytes_read += n;
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "buffer too small for framed packet",
        ));
    }
    r.read_exact(&mut buf[..len]).await?;
    Ok(Some(len))
}

pub async fn relay_stream_to_udp<R, W>(
    quic_recv: &mut R,
    quic_send: &mut W,
    udp_socket: &tokio::net::UdpSocket,
    stats: Arc<PeerL4Stats>,
    conn_stat: Option<Arc<QuicConnStats>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
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

    stats.active_streams.fetch_add(1, Ordering::Relaxed);
    if let Some(cs) = &conn_stat {
        cs.active_streams.fetch_add(1, Ordering::Relaxed);
    }
    let _active_stream_guard = ActiveStreamGuard {
        stats: stats.clone(),
        conn_stat: conn_stat.clone(),
    };

    let activity = Arc::new(AtomicBool::new(false));
    let activity_c2s = activity.clone();
    let activity_s2c = activity.clone();

    let client_to_server = async {
        let mut buf = vec![0u8; 65536];
        loop {
            match read_framed_packet(quic_recv, &mut buf).await? {
                Some(len) => {
                    udp_socket.send(&buf[..len]).await?;
                    activity_c2s.store(true, Ordering::Relaxed);
                    stats.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    if let Some(cs) = &conn_stat {
                        cs.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    }
                }
                None => break,
            }
        }
        Ok::<(), std::io::Error>(())
    };

    let server_to_client = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let len = udp_socket.recv(&mut buf).await?;
            write_framed_packet(quic_send, &buf[..len]).await?;
            activity_s2c.store(true, Ordering::Relaxed);
            stats.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
            if let Some(cs) = &conn_stat {
                cs.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };

    let timeout_duration = Duration::from_secs(30);
    let timer = async {
        loop {
            tokio::time::sleep(timeout_duration).await;
            if !activity.swap(false, Ordering::Relaxed) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "UDP stream idle timeout",
                ));
            }
        }
    };

    tokio::select! {
        res = client_to_server => res,
        res = server_to_client => res,
        res = timer => res,
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

        let (mut client, mut server) = tokio::io::duplex(64);
        let (mut writer_client, mut writer_server) = tokio::io::duplex(64);

        let relay_task =
            tokio::spawn(
                async move { relay_copy_with_idle(&mut client, &mut writer_client).await },
            );

        // 1. Verify that sending data resets the idle timeout timer
        tokio::io::AsyncWriteExt::write_all(&mut server, b"hello")
            .await
            .unwrap();

        // Advance time by half the timeout duration
        tokio::time::advance(RELAY_IDLE_TIMEOUT / 2).await;

        // Write data again to trigger a reset
        tokio::io::AsyncWriteExt::write_all(&mut server, b"world")
            .await
            .unwrap();

        // Advance time again by another half timeout duration.
        // Total elapsed time since start is now RELAY_IDLE_TIMEOUT, but because of the reset,
        // it should not time out yet.
        tokio::time::advance(RELAY_IDLE_TIMEOUT / 2).await;

        // Read data from the writer's peer to ensure data was relayed
        let mut read_buf = [0u8; 10];
        let read_len = tokio::io::AsyncReadExt::read(&mut writer_server, &mut read_buf)
            .await
            .unwrap();
        assert_eq!(&read_buf[..read_len], b"helloworld");

        // The relay task should still be active
        assert!(!relay_task.is_finished());

        // 2. Now let it time out by advancing past the idle timeout without any new data
        tokio::time::advance(RELAY_IDLE_TIMEOUT + Duration::from_secs(1)).await;

        let res = relay_task.await.unwrap();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn test_udp_stream_framing_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let test_data = b"hello udp packet";

        let write_fut = write_framed_packet(&mut client, test_data);
        let read_fut = async {
            let mut read_buf = vec![0u8; 100];
            let len = read_framed_packet(&mut server, &mut read_buf)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&read_buf[..len], test_data);
        };

        tokio::join!(write_fut, read_fut).0.unwrap();
    }

    #[tokio::test]
    async fn test_relay_stream_to_udp_success() {
        let (mut client_stream, server_stream) = tokio::io::duplex(1024);
        let target_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_udp.local_addr().unwrap();

        let relay_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        relay_udp.connect(target_addr).await.unwrap();

        let stats = Arc::new(PeerL4Stats::default());

        // Spawn relay_stream_to_udp
        let (quic_recv, quic_send) = tokio::io::split(server_stream);
        let stats_clone = stats.clone();
        let relay_task = tokio::spawn(async move {
            let mut recv = quic_recv;
            let mut send = quic_send;
            relay_stream_to_udp(&mut recv, &mut send, &relay_udp, stats_clone, None).await
        });

        // 1. Client send framed packet to stream -> UDP target should receive it
        let test_data = b"hello udp target";
        write_framed_packet(&mut client_stream, test_data)
            .await
            .unwrap();

        let mut udp_buf = vec![0u8; 100];
        let (n, src) = target_udp.recv_from(&mut udp_buf).await.unwrap();
        assert_eq!(&udp_buf[..n], test_data);

        // 2. UDP target send packet back -> client stream should read framed packet
        target_udp.send_to(b"reply from target", src).await.unwrap();

        let mut client_buf = vec![0u8; 100];
        let len = read_framed_packet(&mut client_stream, &mut client_buf)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&client_buf[..len], b"reply from target");

        // Cleanup: drop client stream to end the relay task
        drop(client_stream);
        let _ = relay_task.await.unwrap();
    }
}
