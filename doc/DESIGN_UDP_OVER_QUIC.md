# Spec: UDP-over-QUIC Stream Proxy Design

## Background
Currently, `new_proxy` routes UDP traffic (such as DNS, WebRTC, HTTP/3, and QUIC) through userspace WireGuard (L3 fallback via `boringtun`). While secure, WireGuard UDP traffic has highly recognizable handshake and data headers that are easily identified and blocked by Deep Packet Inspection (DPI) firewalls on restrictive networks.

This specification outlines the design for proxying UDP traffic through the pre-established authenticated QUIC connection pool. Because we prioritize protocol obscurity (anti-censorship), all UDP traffic is encapsulated and multiplexed over standard QUIC bidirectional streams, making all UDP connections appear as standard QUIC TCP-like stream traffic.

---

## 1. Protocol Header & Framing Design

### 1.1 Mux Header Expansion (`src/proxy_proto.rs`)
The client writes a target header immediately upon establishing a new bidirectional stream to instruct the server where to forward the flow. We extend this target header to support both TCP and UDP protocols:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Tcp = 1,
    Udp = 2,
}

pub struct ProxyTargetHeader {
    pub protocol: ProxyProtocol,
    pub dst_ip: std::net::IpAddr,
    pub dst_port: u16,
}
```

The binary format is extended:
- **Byte 0**: Protocol Version (e.g. `1`)
- **Byte 1**: Protocol Type (`1` for TCP, `2` for UDP)
- **Bytes 2..**: Target IP address representation + 2-byte Destination Port.

### 1.2 Stream Framing (Packet Boundaries)
Since QUIC streams are unstructured byte-streams, we frame UDP packet boundaries over the stream using a 2-byte big-endian length prefix:

*   **Framing format**: `[2-byte Big Endian Length][UDP Payload]`
*   Maximum UDP payload size is $65535$ bytes, which fits perfectly in 2 bytes.

Helpers for serialization/deserialization:
```rust
async fn write_framed_packet<W>(writer: &mut W, data: &[u8]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if data.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "UDP packet payload too large",
        ));
    }
    let len_bytes = (data.len() as u16).to_be_bytes();
    writer.write_all(&len_bytes).await?;
    writer.write_all(data).await?;
    Ok(())
}

async fn read_framed_packet<R>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;
    if len > buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Buffer too small for incoming framed packet",
        ));
    }
    reader.read_exact(&mut buf[..len]).await?;
    Ok(len)
}
```

---

## 2. Client-side Interception & Smoltcp UDP Integration

### 2.1 Packet Classification (`src/rtc_loop.rs`)
In `RtcWorker::run_loop`, packets read from the TUN interface are parsed. We add `parse_udp_packet` to extract IP addresses and ports for UDP traffic (IPv4 Protocol 17 / IPv6 Next Header 17):

```rust
pub fn parse_udp_packet(packet: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    match version {
        4 => {
            let proto = packet[9];
            if proto != 17 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            if packet.len() < ihl + 8 {
                return None;
            }
            let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            ));
            let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            Some((src_ip, src_port, dst_ip, dst_port))
        }
        6 => {
            if packet.len() < 48 {
                return None;
            }
            let proto = packet[6];
            if proto != 17 {
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
            Some((src_ip, src_port, dst_ip, dst_port))
        }
        _ => None,
    }
}
```

### 2.2 Smoltcp UDP Sockets
`UserspaceTcpStack` (in `src/userspace_tcp.rs`) is expanded to support creating user-level UDP sockets:

```rust
impl UserspaceTcpStack {
    pub fn create_udp_socket(
        &mut self,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
    ) -> Result<SocketHandle, String> {
        use smoltcp::socket::udp;
        let rx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 16],
            vec![0; rx_buffer_size],
        );
        let tx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 16],
            vec![0; tx_buffer_size],
        );
        let socket = udp::Socket::new(rx_buffer, tx_buffer);
        Ok(self.sockets.add(socket))
    }
}
```

### 2.3 UDP NAT Mapping
`RtcWorker` maintains a UDP NAT map tracking active UDP 5-tuples.
- **Outbound**: If a packet matches an existing flow, rewrite destination IP/Port to the associated `smoltcp` UDP socket port, and process it in the stack. If it's a new flow, allocate a local port, bind a `smoltcp` UDP socket, create a new QUIC stream, write the `ProxyTargetHeader` with `ConnectUdp`, and setup a new bridge.
- **Inbound**: When `smoltcp` UDP socket emits a payload, it is framed and written to the corresponding QUIC stream.

---

## 3. UDP-over-QUIC Stream Bridge & Relay Logic

### 3.1 Server-side UDP Mux Relay (`src/server_proxy.rs`)
Upon accepting a stream with `ConnectUdp { dst_ip, dst_port }`:
1.  **UDP Socket Binding**: Bind a physical UDP socket:
    ```rust
    let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let target_addr = SocketAddr::new(dst_ip, dst_port);
    ```
2.  **Relay Loop**:
    - **Stream to UDP Socket**: Read framed packets from the QUIC stream, parse `[2-byte length]`, and send the payload via `udp_socket.send_to(payload, target_addr).await`.
    - **UDP Socket to Stream**: Read incoming packets from `udp_socket.recv_from(...)`, frame them, and write them to the QUIC stream.

### 3.2 Idle Timeout & Teardown
Since UDP is connectionless, we use a 30-second idle timeout (`UDP_IDLE_TIMEOUT = Duration::from_secs(30)`) to clean up inactive resources:
- We instantiate a pinned `tokio::time::sleep(UDP_IDLE_TIMEOUT)` future before entering the relay loops (on both client and server).
- On any packet transfer (read/write), we reset the deadline in-place using `.reset(Instant::now() + UDP_IDLE_TIMEOUT)`.
- If the timer expires, close the QUIC stream, remove the NAT entry, and release local socket resources.
