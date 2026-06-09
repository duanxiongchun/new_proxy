# Design Specification: Pure L3 IP-over-QUIC Datagram Tunnel (No WireGuard)

## 1. Overview & Objectives

This document specifies the design for transitioning the proxy library from the hybrid L4 SOCKS/QUIC stream + L3 WireGuard fallback architecture to a **Pure L3 IP-over-QUIC Datagram Tunnel**. 

By leveraging QUIC Datagrams (unreliable, unordered frames) directly at the IP layer, we eliminate the need for userspace TCP/IP stacks (such as `smoltcp`) and remove the dependency on WireGuard (`boringtun`). This achieves low-latency, high-throughput tunneling with symmetric multi-core scaling.

### Core Goals:
* **Remove WireGuard**: Run all L3/L4 traffic (TCP, UDP, ICMP) entirely over QUIC.
* **Run-to-Completion (RTC)**: Ensure all data path worker loops are non-blocking, statically allocated, and do not dynamically spawn threads or tasks.
* **Symmetric Multi-Port Mapping**: Dynamically negotiate data ports on startup and align client-server threads 1-to-1 without cross-thread lock contention.
* **Zero Allocation**: Use thread-local buffer pools to reuse packet buffers without heap allocation churn.

---

## 2. Architecture & Data Flow

The system acts as a secure L3 Virtual Private Network (VPN) tunnel running over a multiplexed multi-link QUIC connection.

```
+---------------------------------------------------------------------------------------+
|                                  Client Namespace                                     |
|                                                                                       |
|  [App Traffic] ---> [Client TUN (MQ)]                                                 |
|                           | (Queue i)                                                 |
|                           v                                                           |
|                     [Client Worker i] <--- (Thread-Local Buffer Pool)                 |
|                           | (Symmetric flow affinity)                                 |
|                           v                                                           |
|                     [QUIC Conn i]                                                     |
+---------------------------|-----------------------------------------------------------+
                            | (UDP Port 40000+i, Datagram Frame)
                            v
+---------------------------|-----------------------------------------------------------+
|                           |                                                           |
|                     [QUIC Conn i]                                                     |
|                           |                                                           |
|                           v                                                           |
|                     [Server Worker i] <--- (Thread-Local Buffer Pool)                 |
|                           | (Queue i)                                                 |
|                           v                                                           |
|  [Target Traffic] < [Server TUN (MQ)]                                                 |
|                                                                                       |
|                                  Server Namespace                                     |
+---------------------------------------------------------------------------------------+
```

### 2.1 Packet Encapsulation & Transport
* All IP packets (IPv4/IPv6) read from the TUN interface are wrapped directly in QUIC Datagram frames.
* **Wire Format**: Since QUIC Datagrams inherently preserve packet boundaries, the frame payload is the raw IP packet itself. No length prefixing or framing header is required.

### 2.2 TCP MTU & MSS Clamping
To prevent IP packet fragmentation over the QUIC tunnel:
1. **TUN MTU**: The client TUN interface MTU is set to a safe value (e.g., `1200` bytes) based on the negotiated path MTU.
2. **MSS Clamping**: Workers inspect incoming packets from the TUN. For TCP SYN/SYN-ACK packets, they rewrite the Maximum Segment Size (MSS) option header to `1160` bytes (or lower), forcing the local and target OS TCP stacks to generate segments that fit within a single QUIC Datagram.

---

## 3. Symmetric Thread Mapping & Multi-Port Connection

To achieve high parallel throughput without thread lock contention, client worker threads map 1-to-1 to server data ports and listener threads.

### 3.1 Control-Plane Port Negotiation
1. **Control Connection**: The client initiates a connection to the server's control port.
2. **Port Query**: The client requests the data-plane configuration.
3. **Dynamic Port List**: The server returns its active list of $N$ data ports (e.g. `[40001, ..., 40001+N-1]`).
4. **Thread Baseline Setup**:
   * The client uses the port count $N$ returned by the first connected Peer to initialize its local TUN interface with $N$ queues.
   * The client spawns exactly $N$ worker threads.
   * **Symmetric Constraints**: Subsequent peers configured on the client must expose exactly $N$ data ports. If a peer configuration mismatches, the connection is rejected.

### 3.2 Thread & Queue Alignment
* **Client**: Worker thread $i$ (for $i \in [0, N-1]$) opens a dedicated client UDP socket, connects to the server's data port `40000+i`, establishes QUIC Connection $i$, and reads exclusively from Client TUN queue $i$.
* **Server**: Data-plane thread $i$ listens on UDP port `40000+i`, accepts the incoming QUIC Connection $i$ from the client, and writes/reads exclusively to/from Server TUN queue $i$.
* **Flow Affinity**: By using the Linux kernel's multiqueue TUN (`IFF_MULTI_QUEUE`), the kernel automatically performs symmetric hash routing on the 4-tuple. This guarantees that both directions of a network flow are handled by the same worker thread index $i$ on both client and server, resulting in zero cross-thread data sharing.

---

## 4. Run-to-Completion (RTC) & Zero-Allocation Memory Model

To prevent scheduling latency and runtime overhead, workers run in a strict non-blocking loop with thread-isolated resources.

### 4.1 Strict RTC Loop
* No tasks or futures are spawned dynamically (no `tokio::spawn` or heap-allocated async tasks per packet).
* Each thread runs a synchronous, non-blocking `poll` loop:
  1. Poll the assigned TUN queue for outbound IP packets. If a packet is available, read it into a pooled buffer, encapsulate it, and immediately send it using the non-blocking `send_datagram()` on the corresponding QUIC connection.
  2. Poll the QUIC connection for incoming Datagram frames. If available, decode the raw IP packet and immediately write it to the TUN queue.
  3. Yield briefly or park using `epoll` / `io_uring` triggers when idle.

### 4.2 Thread-Local Buffer Pool (Zero Fragmentation)
* **Static Pre-allocation**: Each worker thread owns an isolated, pre-allocated `BufferPool`. All buffers are fixed-size (matching the packet MTU requirements, e.g., 2048 or 16384 bytes).
* **Zero Allocation Churn**: Buffers are continuously recycled locally within the thread. During high-speed packet forwarding, the data plane makes zero calls to the global allocator (`malloc`/`free`), eliminating dynamic heap allocation latency.
* **No Memory Fragmentation**: Because all data-plane buffers are statically allocated with fixed sizes and bound to their respective thread loops, heap memory fragmentation is completely eliminated.


---

## 5. Security & Fallback

* **TLS 1.3 Encryption**: All QUIC Datagrams are encrypted and authenticated using the same QUIC AEAD context established during the connection handshake.
* **Handshake Pinned Session PSK**: Prevents unauthorized clients from initiating data connections.
* **Health Check**: Connections send periodic lightweight keep-alive pings. If a QUIC Connection $i$ goes dead, the client schedules reconnection attempts for that specific slot while other workers continue routing traffic.
