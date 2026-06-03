# Deployment and Telemetry Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct CLI status misrepresentation, resolve dynamic peer telemetry memory leaks, harden WireGuard startup module-load and fallback, and persistently tune UDP buffer sizes.

**Architecture:** Refactor telemetry snapshot checking inside `cli.rs` and UDS servers, introduce `remove` to the sharded `TelemetryRegistry`, introduce `modprobe` and automatic userspace fallback in device initialization, and deploy persistent sysctl config files.

**Tech Stack:** Rust (Tokio, Quinn, generic Netlink, Unix Domain Sockets), Bash, Linux sysctl.

---

### Task 1: Fix CLI Telemetry Status Formatting

**Files:**
- Modify: `/home/duanxiongchun/new_proxy/src/cli.rs:199-233`
- Test: `/home/duanxiongchun/new_proxy/src/cli.rs`

- [ ] **Step 1: Refactor `print_wg_style` to enable test assertions**
  Refactor `print_wg_style` in `/home/duanxiongchun/new_proxy/src/cli.rs` to output to a generic writer `W: std::io::Write` via a helper `print_wg_style_to`.
  
  ```rust
  fn print_wg_style(peers: &[UnifiedTelemetry]) {
      let out = std::io::stdout();
      let mut w = std::io::BufWriter::new(out.lock());
      print_wg_style_to(&mut w, peers);
  }

  fn print_wg_style_to<W: std::io::Write>(w: &mut W, peers: &[UnifiedTelemetry]) {
      // (Rest of printing code goes here)
  }
  ```

- [ ] **Step 2: Correct QUIC active/inactive status logic inside `print_wg_style_to`**
  Modify [src/cli.rs:199-211](file:///home/duanxiongchun/new_proxy/src/cli.rs#L199-L211):
  ```rust
  if peer.quic_connections.is_empty() {
      if peer.l4_rx_bytes > 0 || peer.l4_tx_bytes > 0 {
          writeln!(w, "  quic: inactive (disconnected)").unwrap();
          writeln!(
              w,
              "  quic transfer: {} received, {} sent",
              fmt_bytes(peer.l4_rx_bytes),
              fmt_bytes(peer.l4_tx_bytes)
          )
          .unwrap();
      } else {
          writeln!(w, "  quic: inactive").unwrap();
      }
  } else {
      let conn_count = peer.quic_connections.len();
      writeln!(
          w,
          "  quic: active, {} physical connection{}, {} active stream{}",
          conn_count,
          if conn_count == 1 { "" } else { "s" },
          peer.active_streams,
          if peer.active_streams == 1 { "" } else { "s" }
      )
      .unwrap();
      writeln!(
          w,
          "  quic transfer: {} received, {} sent",
          fmt_bytes(peer.l4_rx_bytes),
          fmt_bytes(peer.l4_tx_bytes)
      )
      .unwrap();

      for (i, conn) in peer.quic_connections.iter().enumerate() {
          writeln!(w, "  quic connection {}:", i).unwrap();
          writeln!(w, "    endpoint: {}", conn.remote_addr).unwrap();
          writeln!(w, "    local port: {}", conn.local_port).unwrap();
          writeln!(
              w,
              "    transfer: {} received, {} sent",
              fmt_bytes(conn.rx_bytes),
              fmt_bytes(conn.tx_bytes)
          )
          .unwrap();
          writeln!(w, "    active streams: {}", conn.active_streams).unwrap();
      }
  }
  ```

- [ ] **Step 3: Write tests verifying the disconnected status formatting**
  Add unit tests in `/home/duanxiongchun/new_proxy/src/cli.rs` test module:
  ```rust
  #[test]
  fn test_print_wg_style_peer_disconnected_with_history() {
      let peer = UnifiedTelemetry {
          public_key: "CCCC==".to_string(),
          allowed_ips: vec!["10.0.0.3/32".to_string()],
          endpoint: None,
          l3_rx_bytes: 100,
          l3_tx_bytes: 200,
          last_handshake: 0,
          l4_rx_bytes: 3500,
          l4_tx_bytes: 231,
          active_streams: 0,
          quic_connections: vec![],
          source: "both".to_string(),
      };
      let mut buf = Vec::new();
      print_wg_style_to(&mut buf, &[peer]);
      let out = String::from_utf8(buf).unwrap();
      assert!(out.contains("quic: inactive (disconnected)"));
      assert!(out.contains("quic transfer: 3.42 KiB received, 231 B sent"));
  }
  ```

- [ ] **Step 4: Run unit tests locally**
  Run: `cargo test --bin new-proxy-cli`
  Expected: PASS

- [ ] **Step 5: Commit changes**
  Run:
  ```bash
  git add src/cli.rs
  git commit -m "cli: fix misleading active status for disconnected peers with traffic"
  ```

---

### Task 2: Implement Telemetry Cleanup in TelemetryRegistry and UDS Server

**Files:**
- Modify: `/home/duanxiongchun/new_proxy/src/telemetry.rs`
- Modify: `/home/duanxiongchun/new_proxy/src/uds_server.rs:679`

- [ ] **Step 1: Write a failing unit test in `src/telemetry.rs`**
  Add a test to the test module in `/home/duanxiongchun/new_proxy/src/telemetry.rs` showing entry deletion.
  ```rust
  #[test]
  fn test_telemetry_registry_remove() {
      let registry = TelemetryRegistry::new();
      let key = [9u8; 32];
      let stats = registry.get_or_create(key);
      stats.rx_bytes.store(500, Ordering::Relaxed);

      registry.remove(&key);
      let snap = registry.snapshot();
      assert!(!snap.contains_key(&key));
  }
  ```

- [ ] **Step 2: Run test to verify compile failure**
  Run: `cargo test --lib telemetry`
  Expected: Compile error because `remove` method does not exist on `TelemetryRegistry`.

- [ ] **Step 3: Implement `remove` in `TelemetryRegistry`**
  Add the following method to `TelemetryRegistry` implementation in `/home/duanxiongchun/new_proxy/src/telemetry.rs`:
  ```rust
  pub fn remove(&self, pub_key: &[u8; 32]) {
      let mut map = self.stats[self.shard_index(pub_key)].lock();
      map.remove(pub_key);
  }
  ```

- [ ] **Step 4: Verify telemetry unit test passes**
  Run: `cargo test --lib telemetry`
  Expected: PASS

- [ ] **Step 5: Call telemetry cleanup in `handle_remove_peer`**
  Modify `/home/duanxiongchun/new_proxy/src/uds_server.rs` in `handle_remove_peer`:
  ```rust
  context.peer_secrets.write().remove(&parsed_pub_key);
  context.session_cache.write().remove(&parsed_pub_key);
  context.auth_nonce_cache.lock().remove(&parsed_pub_key);
  context.telemetry.remove(&parsed_pub_key);
  ```

- [ ] **Step 6: Run uds_server unit tests**
  Run: `cargo test uds_server`
  Expected: PASS

- [ ] **Step 7: Commit changes**
  Run:
  ```bash
  git add src/telemetry.rs src/uds_server.rs
  git commit -m "telemetry: implement peer removal cleanup in TelemetryRegistry to prevent memory leaks"
  ```

---

### Task 3: Load Kernel Module & Implement Userspace Fallback

**Files:**
- Modify: `/home/duanxiongchun/new_proxy/src/wireguard.rs:111-124`

- [ ] **Step 1: Check configure_kernel_device implementation**
  Review `/home/duanxiongchun/new_proxy/src/wireguard.rs` `configure_kernel_device` function.
  Update it to try running `modprobe wireguard` first, check if `ip link add` fails, and check if Netlink setup fails. On any failure, log warning and delegate to userspace wireguard fallback.
  
  ```rust
  fn configure_kernel_device(
      interface_name: &str,
      private_key: &[u8; 32],
      listen_port: Option<u16>,
  ) -> Result<(), String> {
      log::info!(
          "Attempting to load wireguard kernel module via modprobe"
      );
      let _ = Command::new("modprobe").arg("wireguard").output();

      log::info!(
          "Creating WireGuard interface '{}' if it does not exist",
          interface_name
      );
      let output = Command::new("ip")
          .args(["link", "add", "dev", interface_name, "type", "wireguard"])
          .output();

      let creation_success = match output {
          Ok(out) => out.status.success(),
          Err(_) => false,
      };

      if !creation_success {
          log::warn!("Kernel WireGuard interface creation failed. Attempting userspace wireguard fallback.");
          return configure_userspace_device(interface_name, private_key, listen_port);
      }

      if let Err(e) = configure_kernel_device_key(interface_name, private_key, listen_port) {
          log::warn!("Kernel Netlink key configuration failed: {}. Falling back to userspace wireguard.", e);
          let _ = Command::new("ip")
              .args(["link", "del", "dev", interface_name])
              .output();
          return configure_userspace_device(interface_name, private_key, listen_port);
      }

      Ok(())
  }
  ```

- [ ] **Step 2: Run all Rust tests locally**
  Run: `cargo test`
  Expected: PASS

- [ ] **Step 3: Run local acceptance tests**
  Verify that the tests still pass under namespace mocks:
  Run: `sudo script/acceptance/e2e_scenarios.sh`
  Expected: PASS

- [ ] **Step 4: Commit changes**
  Run:
  ```bash
  git add src/wireguard.rs
  git commit -m "wireguard: try modprobe on device startup and fallback to userspace wireguard on failure"
  ```

---

### Task 4: Persistent Server UDP Socket Buffer Tuning

**Files:**
- Create: `/etc/sysctl.d/99-new-proxy.conf` (On the remote server)

- [ ] **Step 1: Write sysctl file to remote server**
  Run SSH command to write tuning variables:
  Run:
  ```bash
  ssh root@2604:a880:4:1d0::3a41:2000 "echo -e 'net.core.rmem_max = 2621440\nnet.core.wmem_max = 2621440' > /etc/sysctl.d/99-new-proxy.conf"
  ```

- [ ] **Step 2: Apply sysctl values**
  Run:
  ```bash
  ssh root@2604:a880:4:1d0::3a41:2000 "sysctl -p /etc/sysctl.d/99-new-proxy.conf"
  ```
  Expected:
  `net.core.rmem_max = 2621440`
  `net.core.wmem_max = 2621440`

- [ ] **Step 3: Verify parameters persistently loaded**
  Run:
  ```bash
  ssh root@2604:a880:4:1d0::3a41:2000 "sysctl net.core.rmem_max net.core.wmem_max"
  ```
  Expected:
  `net.core.rmem_max = 2621440`
  `net.core.wmem_max = 2621440`

---

### Task 5: Build and Deploy the Updated Package to the Server

**Files:**
- Create: `/target/new-proxy_5.0.0_amd64.deb`
- Deploy: `root@2604:a880:4:1d0::3a41:2000`

- [ ] **Step 1: Clean build and compile Debian package locally**
  Run:
  ```bash
  make clean
  make package
  ```
  Expected: Success output with `Debian package created successfully: target/new-proxy_5.0.0_amd64.deb`

- [ ] **Step 2: Copy package to remote server**
  Run:
  ```bash
  scp target/new-proxy_5.0.0_amd64.deb root@[2604:a880:4:1d0::3a41:2000]:/tmp/
  ```

- [ ] **Step 3: Install the package on the remote server**
  Run:
  ```bash
  ssh root@2604:a880:4:1d0::3a41:2000 "dpkg -i /tmp/new-proxy_5.0.0_amd64.deb"
  ```

- [ ] **Step 4: Restart the systemd service on the server**
  Run:
  ```bash
  ssh root@2604:a880:4:1d0::3a41:2000 "systemctl restart new_proxy@server"
  ```

- [ ] **Step 5: Verify server startup logs**
  Run:
  ```bash
  ssh root@2604:a880:4:1d0::3a41:2000 "systemctl status new_proxy@server"
  ```
  Expected: `active (running)` status and no startup crash loops.

- [ ] **Step 6: Verify telemetry status output formatting**
  Verify that idle peers are formatted correctly as disconnected.
  Run:
  ```bash
  ssh root@2604:a880:4:1d0::3a41:2000 "new-proxy-cli show"
  ```
  Expected: Disconnected peers print `quic: inactive (disconnected)` if they have historical traffic.
