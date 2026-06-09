# UDP-over-QUIC Stream Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a UDP-over-QUIC stream proxy that intercepts UDP traffic matching AllowedIPs, encapsulates datagrams with length-prefix framing, multiplexes them over standard QUIC streams, and forwards them to target remote services, with automatic idle connection cleanup.

**Architecture:** We will extend the connection target header to support UDP and add length-prefix framing helpers. We will integrate UDP sockets into smoltcp, parse UDP headers on intercepted packets, map UDP 5-tuples to QUIC stream bridges, and implement a bidirectional Stream-to-UDP socket relay with a 30-second idle timeout.

**Tech Stack:** Rust, Tokio, Quinn, Smoltcp

---

### Task 1: Extend Mux Protocol Header for UDP

**Files:**
- Modify: `src/proxy_proto.rs`

- [ ] **Step 1: Write the failing test**
  Add unit tests inside `src/proxy_proto.rs` tests module verifying serialization and deserialization of a `ProxyTargetHeader` with protocol set to `ProxyProtocol::Udp`.

```rust
    #[test]
    fn test_udp_target_header_serialization() {
        let header = ProxyTargetHeader {
            protocol: ProxyProtocol::Udp,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 53,
        };
        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();

        let parsed = ProxyTargetHeader::read_from(&buf[..]).unwrap();
        assert_eq!(parsed.protocol, ProxyProtocol::Udp);
        assert_eq!(parsed.dst_ip, header.dst_ip);
        assert_eq!(parsed.dst_port, header.dst_port);
    }
```

- [ ] **Step 2: Run test to verify it fails**
  Run: `cargo test proxy_proto`
  Expected: Compile error (no `ProxyProtocol` type, `ProxyTargetHeader` lacks `protocol` field).

- [ ] **Step 3: Implement protocol header changes**
  Add the `ProxyProtocol` enum. Modify `ProxyTargetHeader` to include a `protocol` field. Update serialization/deserialization logic in `src/proxy_proto.rs` to encode protocol type (TCP = 1, UDP = 2) at byte 1 of the header.

- [ ] **Step 4: Run test to verify it passes**
  Run: `cargo test proxy_proto`
  Expected: PASS

- [ ] **Step 5: Commit**
  Run:
  ```bash
  git add src/proxy_proto.rs
  git commit -m "proto: extend target header to support UDP protocol encoding"
  ```

---

### Task 2: Add UDP Packet Framing Helpers

**Files:**
- Modify: `src/relay.rs`

- [ ] **Step 1: Write the failing test**
  Add unit tests verifying `write_framed_packet` and `read_framed_packet` correctly frame and recover UDP packet boundaries over a stream.

```rust
    #[tokio::test]
    async fn test_udp_stream_framing_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let test_data = b"hello udp packet";

        let write_fut = write_framed_packet(&mut client, test_data);
        let read_fut = async {
            let mut read_buf = vec![0u8; 100];
            let len = read_framed_packet(&mut server, &mut read_buf).await.unwrap();
            assert_eq!(&read_buf[..len], test_data);
        };

        tokio::join!(write_fut, read_fut).0.unwrap();
    }
```

- [ ] **Step 2: Run test to verify it fails**
  Run: `cargo test relay`
  Expected: Compile error (no `write_framed_packet` or `read_framed_packet` functions).

- [ ] **Step 3: Implement framing helpers**
  Implement `write_framed_packet` and `read_framed_packet` in `src/relay.rs`.

- [ ] **Step 4: Run test to verify it passes**
  Run: `cargo test relay`
  Expected: PASS

- [ ] **Step 5: Commit**
  Run:
  ```bash
  git add src/relay.rs
  git commit -m "perf: implement length-prefixed stream framing for UDP packets"
  ```

---

### Task 3: Extend Smoltcp Stack with UDP Socket Support

**Files:**
- Modify: `src/userspace_tcp.rs`

- [ ] **Step 1: Write the failing test**
  Add a unit test `test_smoltcp_udp_socket_creation` verifying that a UDP socket can be successfully added to the `SocketSet`.

```rust
    #[test]
    fn test_smoltcp_udp_socket_creation() {
        let ip_cidr = IpCidr::from_str("10.0.0.2/24").unwrap();
        let mut stack = UserspaceTcpStack::new(vec![ip_cidr], 1400, BufferPool::new(1656)).unwrap();
        let handle = stack.create_udp_socket(1024, 1024).unwrap();
        let socket = stack.sockets.get::<smoltcp::socket::udp::Socket>(handle);
        assert!(!socket.is_open());
    }
```

- [ ] **Step 2: Run test to verify it fails**
  Run: `cargo test userspace_tcp`
  Expected: Compile error (no `create_udp_socket` method).

- [ ] **Step 3: Implement `create_udp_socket`**
  Implement `create_udp_socket` in `UserspaceTcpStack` in `src/userspace_tcp.rs`.

- [ ] **Step 4: Run test to verify it passes**
  Run: `cargo test userspace_tcp`
  Expected: PASS

- [ ] **Step 5: Commit**
  Run:
  ```bash
  git add src/userspace_tcp.rs
  git commit -m "net: add userspace UDP socket allocation in smoltcp wrapper"
  ```

---

### Task 4: Add UDP Packet Parsing Helper

**Files:**
- Modify: `src/rtc_loop.rs`

- [ ] **Step 1: Write the failing test**
  Add unit tests `test_parse_udp_packet` verifying parsing of IPv4 and IPv6 UDP packets.

```rust
    #[test]
    fn test_parse_udp_packet_ipv4() {
        // Construct mock IPv4 UDP packet
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // Version 4, IHL 20
        pkt[9] = 17;   // UDP Protocol
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]); // Src IP
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);  // Dst IP
        pkt[20..22].copy_from_slice(&53000u16.to_be_bytes()); // Src Port
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());    // Dst Port

        let res = parse_udp_packet(&pkt).unwrap();
        assert_eq!(res.0, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(res.1, 53000);
        assert_eq!(res.2, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(res.3, 53);
    }
```

- [ ] **Step 2: Run test to verify it fails**
  Run: `cargo test rtc_loop`
  Expected: Compile error (no `parse_udp_packet` function).

- [ ] **Step 3: Implement `parse_udp_packet`**
  Add the `parse_udp_packet` function to `src/rtc_loop.rs`.

- [ ] **Step 4: Run test to verify it passes**
  Run: `cargo test rtc_loop`
  Expected: PASS

- [ ] **Step 5: Commit**
  Run:
  ```bash
  git add src/rtc_loop.rs
  git commit -m "net: add userspace UDP header parser"
  ```

---

### Task 5: Implement Server-Side UDP Mux Stream Handler & Relay

**Files:**
- Modify: `src/relay.rs`, `src/server_proxy.rs`

- [ ] **Step 1: Write the failing test**
  Add a unit test in `src/relay.rs` verifying that `relay_stream_to_udp` successfully reads framed packets from a stream and sends them to a destination UDP socket, and vice versa.

- [ ] **Step 2: Run test to verify it fails**
  Run: `cargo test relay`
  Expected: Compile error (no `relay_stream_to_udp` function).

- [ ] **Step 3: Implement `relay_stream_to_udp` and Server Dispatch**
  Implement `relay_stream_to_udp` in `src/relay.rs` with `UDP_IDLE_TIMEOUT` (30s) using stack-allocated timer reset optimization. In `src/server_proxy.rs`, update the stream dispatcher to bind a physical UDP socket and call `relay_stream_to_udp` when the target protocol is `ProxyProtocol::Udp`.

- [ ] **Step 4: Run test to verify it passes**
  Run: `cargo test relay`
  Expected: PASS

- [ ] **Step 5: Commit**
  Run:
  ```bash
  git add src/relay.rs src/server_proxy.rs
  git commit -m "net: implement server-side UDP-over-QUIC stream relay and handler"
  ```

---

### Task 6: Implement Client-Side UDP NAT & Stream Bridge

**Files:**
- Modify: `src/rtc_loop.rs`

- [ ] **Step 1: Write the failing test**
  Add a unit test in `src/rtc_loop.rs` verifying that intercepting a UDP packet allocated a NAT mapping and established a `smoltcp` socket bridge.

- [ ] **Step 2: Run test to verify it fails**
  Run: `cargo test rtc_loop`
  Expected: FAIL / Compile error.

- [ ] **Step 3: Implement Client-side UDP NAT and Bridge**
  In `src/rtc_loop.rs`, intercept UDP packets matching AllowedIPs, create smoltcp UDP sockets, assign NAT local ports, and bridge the sockets to QUIC streams using framed loops.

- [ ] **Step 4: Run test to verify it passes**
  Run: `cargo test rtc_loop`
  Expected: PASS

- [ ] **Step 5: Commit**
  Run:
  ```bash
  git add src/rtc_loop.rs
  git commit -m "net: implement client-side UDP interception, NAT mapping, and stream bridge"
  ```

---

### Task 7: E2E Acceptance Test and Verification

**Files:**
- Create: `script/acceptance/e2e_udp_over_quic.sh`
- Modify: `script/acceptance/run_acceptance.sh`

- [ ] **Step 1: Create E2E script**
  Create `script/acceptance/e2e_udp_over_quic.sh` mimicking `e2e_scenarios.sh` but executing UDP communication (e.g., DNS resolution or netcat UDP test) through the client TUN, verifying that it is proxied over QUIC stream telemetry and not routed over WireGuard.

- [ ] **Step 2: Run script to verify it fails**
  Run: `sudo bash script/acceptance/e2e_udp_over_quic.sh`
  Expected: FAIL

- [ ] **Step 3: Integrate and resolve**
  Ensure config files allow UDP offloading (or it is enabled by default). Verify all other acceptance tests still pass.

- [ ] **Step 4: Run acceptance test**
  Run: `./script/acceptance/run_acceptance.sh`
  Expected: "All acceptance tests passed successfully!"

- [ ] **Step 5: Commit**
  Run:
  ```bash
  git add script/acceptance/e2e_udp_over_quic.sh script/acceptance/run_acceptance.sh
  git commit -m "test: add E2E acceptance test for UDP-over-QUIC stream proxy"
  ```
