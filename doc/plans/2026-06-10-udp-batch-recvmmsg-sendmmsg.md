# UDP Batch RX/TX (recvmmsg and sendmmsg) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 64-packet full-pipeline batch receiving and sending using `recvmmsg` and `sendmmsg` in `new_proxy` to optimize single-thread performance.

**Architecture:** Use Linux native `recvmmsg` with `MSG_DONTWAIT` to read up to 64 UDP packets non-blockingly under Tokio's `try_io` reactor. Group outgoing transmits by Peer/ConnectionHandle, and use `sendmmsg` to transmit them in batches per peer. Integrate batch read from TUN using `try_read` in a loop.

**Tech Stack:** Rust, libc, tokio, bytes.

---

### Task 1: Add structs and helper functions

**Files:**
- Modify: `src/rtc_loop.rs:1-10` (add imports)
- Modify: `src/rtc_loop.rs:1080-1092` (add struct and helpers at the end)
- Test: `src/rtc_loop.rs:tests` (add test case)

- [ ] **Step 1: Add libc and std imports to `src/rtc_loop.rs`**
  Add raw fd, Interest, and sockaddr imports:
  ```rust
  use std::os::unix::io::AsRawFd;
  use tokio::io::Interest;
  ```

- [ ] **Step 2: Implement UdpBatch, sockaddr_to_socket_addr, and socket_addr_to_sockaddr in `src/rtc_loop.rs`**
  Append the following at the bottom of the file (before unit tests):
  ```rust
  pub const UDP_BATCH_SIZE: usize = 64;

  pub struct UdpBatch {
      pub mmsgs: [libc::mmsghdr; UDP_BATCH_SIZE],
      pub iovs: [libc::iovec; UDP_BATCH_SIZE],
      pub addrs: [libc::sockaddr_storage; UDP_BATCH_SIZE],
  }

  impl UdpBatch {
      pub fn new() -> Self {
          // SAFETY: All components are POD structures. Zero-initializing them is safe.
          unsafe { std::mem::zeroed() }
      }
  }

  pub fn sockaddr_to_socket_addr(addr: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
      match addr.ss_family as libc::c_int {
          libc::AF_INET => {
              let addr_in = unsafe { *(addr as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
              let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
              let port = u16::from_be(addr_in.sin_port);
              Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port))
          }
          libc::AF_INET6 => {
              let addr_in6 = unsafe { *(addr as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
              let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
              let port = u16::from_be(addr_in6.sin6_port);
              Some(std::net::SocketAddr::new(std::net::IpAddr::V6(ip), port))
          }
          _ => None,
      }
  }

  pub fn socket_addr_to_sockaddr(addr: std::net::SocketAddr, dest: &mut libc::sockaddr_storage) -> libc::socklen_t {
      match addr {
          std::net::SocketAddr::V4(addr_v4) => {
              let dest_in = dest as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
              unsafe {
                  (*dest_in).sin_family = libc::AF_INET as libc::sa_family_t;
                  (*dest_in).sin_port = addr_v4.port().to_be();
                  (*dest_in).sin_addr.s_addr = u32::from(*addr_v4.ip()).to_be();
              }
              std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
          }
          std::net::SocketAddr::V6(addr_v6) => {
              let dest_in6 = dest as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
              unsafe {
                  (*dest_in6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                  (*dest_in6).sin6_port = addr_v6.port().to_be();
                  (*dest_in6).sin6_addr.s6_addr = addr_v6.ip().octets();
              }
              std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
          }
      }
  }
  ```

- [ ] **Step 3: Add unit tests for address conversion in `src/rtc_loop.rs`**
  Add tests inside `mod tests`:
  ```rust
  #[test]
  fn test_sockaddr_conversion_roundtrip() {
      use super::*;
      let ipv4_addr: std::net::SocketAddr = "1.2.3.4:51820".parse().unwrap();
      let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
      let len = socket_addr_to_sockaddr(ipv4_addr, &mut storage);
      assert!(len > 0);
      let back = sockaddr_to_socket_addr(&storage).unwrap();
      assert_eq!(back, ipv4_addr);

      let ipv6_addr: std::net::SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
      let mut storage6: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
      let len6 = socket_addr_to_sockaddr(ipv6_addr, &mut storage6);
      assert!(len6 > 0);
      let back6 = sockaddr_to_socket_addr(&storage6).unwrap();
      assert_eq!(back6, ipv6_addr);
  }
  ```

- [ ] **Step 4: Run cargo test to verify**
  Run: `cargo test --lib rtc_loop`
  Expected: PASS

- [ ] **Step 5: Commit**
  ```bash
  git add src/rtc_loop.rs
  git commit -m "feat: add UdpBatch and address conversion helpers with unit tests"
  ```

---

### Task 2: Refactor RtcWorker struct definition and constructor

**Files:**
- Modify: `src/rtc_loop.rs:17-40` (update `RtcWorker` struct fields)
- Modify: `src/rtc_loop.rs:42-79` (update `RtcWorker::new`)
- Modify: `src/rtc_loop.rs:tests` (update test worker instantiation points)

- [ ] **Step 1: Add `udp_batch` field to `RtcWorker`**
  Modify `RtcWorker` struct definition:
  ```rust
  pub struct RtcWorker {
      // ... (existing fields)
      pub udp_batch: UdpBatch,
  }
  ```

- [ ] **Step 2: Initialize `udp_batch` in `RtcWorker::new`**
  Modify the `new` constructor to initialize `udp_batch`:
  ```rust
  pub fn new(
      // ... (existing params)
  ) -> Self {
      let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(config.mtu);
      Self {
          // ... (existing fields)
          udp_batch: UdpBatch::new(),
      }
  }
  ```

- [ ] **Step 3: Verify and run cargo check**
  Run: `cargo check`
  Expected: PASS

- [ ] **Step 4: Commit**
  ```bash
  git add src/rtc_loop.rs
  git commit -m "refactor: add UdpBatch initialization to RtcWorker"
  ```

---

### Task 3: Implement UDP Batch Receiving (recvmmsg)

**Files:**
- Modify: `src/rtc_loop.rs:689-736` (rewrite UDP read select branch)

- [ ] **Step 1: Replace UDP recv select branch in `run_loop`**
  Rewrite the `read_res = self.udp_socket.recv_from(...)` select branch to use non-blocking `recvmmsg`:
  ```rust
                  _ = self.udp_socket.readable() => {
                      let mut batch_buf = bytes::BytesMut::with_capacity(UDP_BATCH_SIZE * self.packet_buffer_size);
                      // SAFETY: The flat buffer is set to capacity to allow slicing it for recv.
                      // The uninitialized bytes are never read before they are written by the OS kernel.
                      unsafe { batch_buf.set_len(UDP_BATCH_SIZE * self.packet_buffer_size); }
                      let fd = self.udp_socket.as_raw_fd();
                      let packet_size = self.packet_buffer_size;

                      let res = self.udp_socket.try_io(Interest::READABLE, || {
                          for i in 0..UDP_BATCH_SIZE {
                              let offset = i * packet_size;
                              self.udp_batch.iovs[i].iov_base = unsafe { batch_buf.as_mut_ptr().add(offset) as *mut libc::c_void };
                              self.udp_batch.iovs[i].iov_len = packet_size as libc::size_t;

                              self.udp_batch.mmsgs[i].msg_hdr.msg_name = &mut self.udp_batch.addrs[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
                              self.udp_batch.mmsgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                              self.udp_batch.mmsgs[i].msg_hdr.msg_iov = &mut self.udp_batch.iovs[i] as *mut libc::iovec;
                              self.udp_batch.mmsgs[i].msg_hdr.msg_iovlen = 1;
                              self.udp_batch.mmsgs[i].msg_hdr.msg_control = std::ptr::null_mut();
                              self.udp_batch.mmsgs[i].msg_hdr.msg_controllen = 0;
                              self.udp_batch.mmsgs[i].msg_hdr.msg_flags = 0;
                              self.udp_batch.mmsgs[i].msg_len = 0;
                          }

                          let count = unsafe {
                              libc::recvmmsg(
                                  fd,
                                  self.udp_batch.mmsgs.as_mut_ptr(),
                                  UDP_BATCH_SIZE as libc::c_uint,
                                  libc::MSG_DONTWAIT,
                                  std::ptr::null_mut(),
                              )
                          };

                          if count < 0 {
                              return Err(std::io::Error::last_os_error());
                          }
                          Ok(count as usize)
                      });

                      match res {
                          Ok(count) if count > 0 => {
                              let now = std::time::Instant::now();
                              let mut remaining = batch_buf;
                              for i in 0..count {
                                  let len = self.udp_batch.mmsgs[i].msg_len as usize;
                                  let mut packet_chunk = remaining.split_to(packet_size);
                                  if len > 0 {
                                      packet_chunk.truncate(len);
                                      if let Some(remote_addr) = sockaddr_to_socket_addr(&self.udp_batch.addrs[i]) {
                                          self.handle_udp_packet(packet_chunk, remote_addr, &dp_snapshot, now, &mut local_stats).await;
                                      }
                                  }
                              }
                              self.process_endpoint_transmits().await;
                          }
                          Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                          Err(e) => {
                              log::warn!("UDP recvmmsg error: {:?}", e);
                          }
                          _ => {}
                      }
                  }
  ```

- [ ] **Step 2: Clean up unused `udp_buf` allocation**
  Remove `let mut udp_buf = bytes::BytesMut::with_capacity(256 * 1024);` and its preparation/reset logic from `run_loop` (lines ~566, ~585-597).

- [ ] **Step 3: Run cargo test to verify**
  Run: `cargo test`
  Expected: PASS

- [ ] **Step 4: Commit**
  ```bash
  git add src/rtc_loop.rs
  git commit -m "feat: implement UDP batch receiving using recvmmsg"
  ```

---

### Task 4: Implement UDP Batch Sending (sendmmsg) per Peer

**Files:**
- Modify: `src/rtc_loop.rs:89-137` (rewrite transmission functions)

- [ ] **Step 1: Implement send_transmit_batch in `src/rtc_loop.rs`**
  Modify `process_endpoint_transmits` and helper `send_transmits_for_peer` to batch transmissions using `sendmmsg` per peer destination.
  ```rust
      async fn send_transmits_for_peer(&mut self, dest: std::net::SocketAddr, transmits: &[quinn_proto::Transmit]) {
          if transmits.is_empty() {
              return;
          }

          let fd = self.udp_socket.as_raw_fd();
          let mut tx_batch = UdpBatch::new();

          // We chunk transmits into sizes of UDP_BATCH_SIZE
          for chunk in transmits.chunks(UDP_BATCH_SIZE) {
              let count = chunk.len();
              for (i, transmit) in chunk.iter().enumerate() {
                  tx_batch.iovs[i].iov_base = transmit.contents.as_ptr() as *mut libc::c_void;
                  tx_batch.iovs[i].iov_len = transmit.contents.len() as libc::size_t;

                  socket_addr_to_sockaddr(dest, &mut tx_batch.addrs[i]);
                  tx_batch.mmsgs[i].msg_hdr.msg_name = &mut tx_batch.addrs[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
                  tx_batch.mmsgs[i].msg_hdr.msg_namelen = if dest.is_ipv4() {
                      std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
                  } else {
                      std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
                  };
                  tx_batch.mmsgs[i].msg_hdr.msg_iov = &mut tx_batch.iovs[i] as *mut libc::iovec;
                  tx_batch.mmsgs[i].msg_hdr.msg_iovlen = 1;
                  tx_batch.mmsgs[i].msg_hdr.msg_control = std::ptr::null_mut();
                  tx_batch.mmsgs[i].msg_hdr.msg_controllen = 0;
                  tx_batch.mmsgs[i].msg_hdr.msg_flags = 0;
                  tx_batch.mmsgs[i].msg_len = 0;
              }

              let res = self.udp_socket.try_io(Interest::WRITABLE, || {
                  let sent = unsafe {
                      libc::sendmmsg(
                          fd,
                          tx_batch.mmsgs.as_mut_ptr(),
                          count as libc::c_uint,
                          libc::MSG_DONTWAIT,
                      )
                  };
                  if sent < 0 {
                      return Err(std::io::Error::last_os_error());
                  }
                  Ok(sent as usize)
              });

              match res {
                  Ok(sent) => {
                      if sent < count {
                          // Fallback for unsent packets in the batch
                          for transmit in &chunk[sent..] {
                              if let Err(e) = self.udp_socket.send_to(&transmit.contents, dest).await {
                                  log::warn!("Failed to send UDP transmit fallback packet: {}", e);
                              }
                          }
                      }
                  }
                  Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                      // Fallback blockingly or await writable
                      for transmit in chunk {
                          if let Err(e) = self.udp_socket.send_to(&transmit.contents, dest).await {
                              log::warn!("Failed to send UDP transmit fallback packet: {}", e);
                          }
                      }
                  }
                  Err(e) => {
                      log::warn!("Failed to sendmmsg: {:?}", e);
                  }
              }
          }
      }

      async fn process_endpoint_transmits(&mut self) {
          let now = std::time::Instant::now();
          // Group transmits by destination SocketAddr
          let mut peer_transmits: std::collections::HashMap<std::net::SocketAddr, Vec<quinn_proto::Transmit>> = std::collections::HashMap::new();

          // 1. Poll endpoint-level transmits
          while let Some(transmit) = self.endpoint.poll_transmit() {
              peer_transmits.entry(transmit.destination).or_default().push(transmit);
          }

          // 2. Poll connection-level transmits
          for conn in self.connections.values_mut() {
              while let Some(transmit) = conn.connection.poll_transmit(now, 1024) {
                  peer_transmits.entry(transmit.destination).or_default().push(transmit);
              }
          }

          // 3. Batch send per peer
          for (dest, transmits) in peer_transmits {
              self.send_transmits_for_peer(dest, &transmits).await;
          }
      }
  ```

- [ ] **Step 2: Remove old `send_transmit` method**
  Remove `send_transmit` since it's fully replaced by `send_transmits_for_peer` and batching.

- [ ] **Step 3: Run cargo test to verify**
  Run: `cargo test`
  Expected: PASS

- [ ] **Step 4: Commit**
  ```bash
  git add src/rtc_loop.rs
  git commit -m "feat: implement UDP batch sending using sendmmsg per peer"
  ```

---

### Task 5: Implement TUN Batch Reading & Peer Classification

**Files:**
- Modify: `src/rtc_loop.rs:629-687` (rewrite TUN read select branch)

- [ ] **Step 1: Replace TUN read select branch in `run_loop`**
  Rewrite the `read_res = self.tun_io.read(...)` select branch to read up to 64 packets, classify by peer, batch write to Quinn connections, and transmit:
  ```rust
                  read_res = self.tun_io.read(&mut tun_buf[1..65536]) => {
                      match read_res {
                          Ok(0) => {
                              tun_buf.truncate(0);
                              return Err("TUN interface EOF".to_string());
                          }
                          Ok(first_len) => {
                              let now = std::time::Instant::now();
                              let mut packets = Vec::with_capacity(UDP_BATCH_SIZE);
                              
                              // Capture the first packet
                              tun_buf[0] = 0x02;
                              // SAFETY: Set length to 1 + first_len to split
                              unsafe { tun_buf.set_len(1 + first_len); }
                              let frame = tun_buf.split_to(1 + first_len).freeze();
                              packets.push((first_len, frame));

                              // Try to read up to 63 more packets non-blockingly
                              for _ in 0..(UDP_BATCH_SIZE - 1) {
                                  if tun_buf.capacity() < 65536 {
                                      tun_buf.reserve(256 * 1024);
                                  }
                                  // SAFETY: Prepare buffer capacity for try_read
                                  unsafe {
                                      let cap = tun_buf.capacity();
                                      tun_buf.set_len(cap);
                                  }
                                  match self.tun_io.try_read(&mut tun_buf[1..65536]) {
                                      Ok(Some(n)) if n > 0 => {
                                          tun_buf[0] = 0x02;
                                          unsafe { tun_buf.set_len(1 + n); }
                                          let frame = tun_buf.split_to(1 + n).freeze();
                                          packets.push((n, frame));
                                      }
                                      _ => {
                                          tun_buf.truncate(0);
                                          break;
                                      }
                                  }
                              }

                              // Group packets by destination connection handle
                              let mut peer_packets: std::collections::HashMap<quinn_proto::ConnectionHandle, Vec<(usize, bytes::Bytes)>> = std::collections::HashMap::new();
                              for (n, frame) in packets {
                                  if let Some(dst_ip) = parse_destination_ip(&frame[1..]) {
                                      if let Some(handle) = self.find_handle_for_ip(dst_ip, &dp_snapshot) {
                                          peer_packets.entry(handle).or_default().push((n, frame));
                                      }
                                  }
                              }

                              // Process and batch-send per peer connection
                              for (handle, group) in peer_packets {
                                  if let Some(conn) = self.connections.get_mut(&handle) {
                                      if conn.authenticated {
                                          for (n, frame) in group {
                                              if let Err(e) = conn.connection.datagrams().send(frame) {
                                                  log::debug!("Failed to send datagram: {:?}", e);
                                              } else {
                                                  let packet_len = n as u64;
                                                  conn.tx_bytes.add(packet_len);
                                                  local_stats.l3_packets += 1;
                                                  local_stats.l3_bytes += packet_len;

                                                  if let Some(ref peer_telemetry) = self.peer_telemetry {
                                                      if let Some(pub_key) = conn.peer_public_key {
                                                          let peer_stats = peer_telemetry.get_or_create(pub_key);
                                                          peer_stats.tx_bytes.add(packet_len);
                                                      }
                                                  }
                                              }
                                          }
                                      }
                                  }
                              }

                              self.process_endpoint_transmits().await;
                          }
                          Err(e) => {
                              tun_buf.truncate(0);
                              log::warn!("TUN read error: {:?}", e);
                          }
                      }
                  }
  ```

- [ ] **Step 2: Run cargo test to verify**
  Run: `cargo test`
  Expected: PASS

- [ ] **Step 3: Commit**
  ```bash
  git add src/rtc_loop.rs
  git commit -m "feat: implement TUN batch reading and peer classification"
  ```

---

### Task 6: Final Verification & Performance Run

- [ ] **Step 1: Check compiler warnings**
  Run: `cargo clippy --all-targets -- -D warnings`
  Expected: PASS with no warnings.

- [ ] **Step 2: Run full integration tests**
  Run: `cargo test`
  Expected: PASS (93 tests).

- [ ] **Step 3: Commit**
  ```bash
  git commit --allow-empty -m "chore: UDP batch RX/TX implementation verification completed"
  ```
