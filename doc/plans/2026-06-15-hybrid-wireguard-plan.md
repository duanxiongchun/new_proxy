# Hybrid QUIC and Kernel WireGuard Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement hybrid userspace QUIC + kernel WireGuard tunnel support in `new_proxy` managed via Netlink, automatically configuring interfaces, routing, and providing CLI stats/labels.

**Architecture:** Use `defguard_wireguard_rs` to manage the kernel WireGuard interface (`<config_name>-wg`) without external tools. Automatically derive interface names based on configuration names, and set up specific host routes (`/32` or `/128`) for all peers to resolve overlapping subnet routes via LPM. Query kernel statistics via Netlink to feed UDS stats and display them in `new-proxy-cli` with correct source labels. Detect lack of native WireGuard module support in Linux and dynamically fall back to launching `wireguard-go` as a background process while retaining standard Netlink configuration flow.

**Tech Stack:** Rust, tokio, defguard_wireguard_rs, ipnet.

---

### Task 1: Add Dependencies & Update Configuration Parser

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/config.rs`

- [ ] **Step 1: Add defguard_wireguard_rs to `Cargo.toml`**
  Add `defguard_wireguard_rs = "0.10.0"` to the dependencies section:
  ```toml
  defguard_wireguard_rs = "0.10.0"
  ```
  Run `cargo check` to verify it compiles and downloads.

- [ ] **Step 2: Define PeerType enum in `src/config.rs`**
  Add the following enum above `PeerConfig`:
  ```rust
  #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
  pub enum PeerType {
      #[serde(rename = "quic")]
      Quic,
      #[serde(rename = "wireguard")]
      Wireguard,
  }
  ```

- [ ] **Step 3: Update InterfaceConfig and PeerConfig structs in `src/config.rs`**
  Add `wg_listen_port` to `InterfaceConfig` and `r#type` to `PeerConfig`:
  ```rust
  // In InterfaceConfig
  pub wg_listen_port: Option<u16>,

  // In PeerConfig
  pub r#type: PeerType,
  ```

- [ ] **Step 4: Update INI parser in `src/config.rs`**
  Modify `GatewayConfig::load_from_ini` to parse `WgListenPort` / `wg_listen_port` / `wglistenport` and `Type` / `type` / `peertype`:
  ```rust
  let wg_listen_port = interface_section
      .get("WgListenPort")
      .or_else(|| interface_section.get("wg_listen_port"))
      .or_else(|| interface_section.get("wglistenport"))
      .map(|s| s.parse::<u16>().map_err(|e| format!("Invalid WgListenPort: {}", e)))
      .transpose()?;

  let peer_type_str = section.get("Type").or_else(|| section.get("type"));
  let r#type = match peer_type_str {
      Some(s) if s.eq_ignore_ascii_case("wireguard") => PeerType::Wireguard,
      _ => PeerType::Quic,
  };
  ```

- [ ] **Step 5: Verify Cargo compilation**
  Run `cargo check` and fix any compiler issues. Commit:
  ```bash
  git add Cargo.toml src/config.rs
  git commit -m "feat: add defguard dependency and parse WgListenPort / PeerType"
  ```

---

### Task 2: Autonaming & Route Selection

**Files:**
- Modify: `src/app_config.rs`
- Modify: `src/main.rs`
- Modify: `src/runtime.rs`

- [ ] **Step 1: Add naming helper functions in `src/app_config.rs`**
  Implement:
  ```rust
  pub fn quic_interface_name(name: &str, mode: &str) -> String {
      if mode.eq_ignore_ascii_case("af_xdp") {
          format!("{}-veth", name)
      } else {
          format!("{}-tun", name)
      }
  }

  pub fn wg_interface_name(name: &str) -> String {
      format!("{}-wg", name)
  }
  ```

- [ ] **Step 2: Update runtime interfaces references**
  Update `src/main.rs` and `src/runtime.rs` to use `<interface_name>-tun`/`<interface_name>-veth` for QUIC, and `<interface_name>-wg` for WireGuard.
  Run `cargo check` to verify.

- [ ] **Step 3: Commit**
  ```bash
  git add src/app_config.rs src/main.rs src/runtime.rs
  git commit -m "feat: implement automatic interface naming convention"
  ```

---

### Task 3: Netlink-based Kernel WireGuard & wireguard-go Fallback Management

**Files:**
- Modify: `src/runtime.rs`

- [ ] **Step 1: Add Netlink setup helper with wireguard-go fallback in `src/runtime.rs`**
  Implement interface creation, IP binding, private key configuration, and peer setting using `defguard_wireguard_rs`. If native creation fails, fall back to executing `wireguard-go <wg_name>` in the background:
  ```rust
  #[cfg(target_os = "linux")]
  pub fn setup_kernel_wireguard(config: &crate::config::GatewayConfig, interface_name: &str) -> Result<(), String> {
      use defguard_wireguard_rs::{WireguardInterfaceApi, WgInterface, WgPeer, key::Key};
      let wg_name = crate::app_config::wg_interface_name(interface_name);
      let api = WireguardInterfaceApi::new()?;
      
      // Try creating native wireguard interface, if fails (missing module), fall back to wireguard-go
      if !api.interface_exists(&wg_name)? {
          if let Err(e) = api.create_interface(&wg_name) {
              log::warn!("Failed to create native kernel wireguard interface: {:?}. Falling back to wireguard-go.", e);
              // Run: wireguard-go <wg_name>
              let status = std::process::Command::new("wireguard-go")
                  .arg(&wg_name)
                  .status()
                  .map_err(|err| format!("failed to start wireguard-go: {}", err))?;
              if !status.success() {
                  return Err("wireguard-go exited with error".to_string());
              }
              // Wait briefly for the userspace TUN device to appear
              std::thread::sleep(std::time::Duration::from_millis(200));
          }
      }

      let listen_port = config.interface.wg_listen_port.unwrap_or(config.interface.listen_port.unwrap_or(51820) + 1);
      let priv_key = Key::from_bytes(&config.interface.private_key).map_err(|e| format!("{:?}", e))?;

      let mut wg_peers = Vec::new();
      for peer in &config.peers {
          if peer.r#type == crate::config::PeerType::Wireguard {
              let mut wg_peer = WgPeer::new(Key::from_bytes(&peer.public_key).map_err(|e| format!("{:?}", e))?);
              wg_peer.endpoint = peer.endpoint;
              wg_peer.allowed_ips = peer.allowed_ips.iter().map(|ip| ip.into()).collect();
              wg_peers.push(wg_peer);
          }
      }

      let interface_config = WgInterface {
          name: wg_name.clone(),
          private_key: Some(priv_key),
          listen_port: Some(listen_port),
          peers: wg_peers,
          ..Default::default()
      };
      api.configure_interface(&interface_config)?;
      
      // Bind IP address
      for addr in &config.interface.addresses {
          api.add_address(&wg_name, addr.ip(), addr.prefix_len() as u32)?;
      }
      api.set_interface_up(&wg_name)?;
      Ok(())
  }
  ```

- [ ] **Step 2: Add Netlink cleanup helper in `src/runtime.rs`**
  Implement interface deletion:
  ```rust
  #[cfg(target_os = "linux")]
  pub fn cleanup_kernel_wireguard(interface_name: &str) -> Result<(), String> {
      use defguard_wireguard_rs::WireguardInterfaceApi;
      let wg_name = crate::app_config::wg_interface_name(interface_name);
      let api = WireguardInterfaceApi::new()?;
      if api.interface_exists(&wg_name)? {
          api.delete_interface(&wg_name)?;
      }
      Ok(())
  }
  ```

- [ ] **Step 3: Integrate setup/cleanup in `setup_routes` and `cleanup_routes`**
  Call these helpers. Ensure they are gated with `#[cfg(target_os = "linux")]`.

- [ ] **Step 4: Commit**
  ```bash
  git add src/runtime.rs
  git commit -m "feat: implement native Netlink WireGuard setup with wireguard-go fallback and cleanup"
  ```

---

### Task 4: LPM Route Configuration

**Files:**
- Modify: `src/runtime.rs`

- [ ] **Step 1: Separate route commands by peer type**
  Modify `setup_peer_route_commands` and `cleanup_peer_route_commands` to direct routes of `Type = quic` peers to the QUIC device (`<config_name>-tun`/`<config_name>-veth`) and `Type = wireguard` peers to the WireGuard device (`<config_name>-wg`).

- [ ] **Step 2: Run cargo check and verify**
  Verify code compiles correctly.

- [ ] **Step 3: Commit**
  ```bash
  git add src/runtime.rs
  git commit -m "feat: configure specific host routes to split traffic by peer type"
  ```

---

### Task 5: Telemetry Stats and CLI Integration

**Files:**
- Modify: `src/uds_server.rs`
- Modify: `src/app_config.rs`

- [ ] **Step 1: Query kernel WireGuard stats in `src/uds_server.rs`**
  Modify `handle_stats` to query the kernel WireGuard interface via `defguard_wireguard_rs::WireguardInterfaceApi::get_peers` and populate the telemetry bytes and handshake times.

- [ ] **Step 2: Update peer source labels**
  Ensure QUIC peers are labeled `"proxy"`, WireGuard peers are labeled `"wireguard"`, and dual peers are labeled `"both"`.

- [ ] **Step 3: Commit**
  ```bash
  git add src/uds_server.rs src/app_config.rs
  git commit -m "feat: integrate kernel WireGuard peer statistics into telemetry stats"
  ```

---

### Task 6: E2E Hybrid WireGuard Acceptance Test

**Files:**
- Create: `script/acceptance/e2e_hybrid_wireguard.sh`

- [ ] **Step 1: Write E2E test script**
  Create a script that simulates a standard WG client namespace connecting to the `new_proxy` client's kernel WG interface (or wireguard-go fallback interface) and pinging a target server behind the QUIC tunnel.

- [ ] **Step 2: Run test and verify it passes**
  Run: `sudo bash script/acceptance/e2e_hybrid_wireguard.sh`
  Expected: PASS

- [ ] **Step 3: Commit**
  ```bash
  git add script/acceptance/e2e_hybrid_wireguard.sh
  git commit -m "test: add hybrid wireguard end-to-end acceptance test"
  ```

---

### Task 7: E2E High Availability and Reconnection Test

**Files:**
- Create: `script/acceptance/e2e_hybrid_ha_reconnect.sh`

- [ ] **Step 1: Write HA & Reconnect test script**
  Create a script that verifies:
  1. Server restart and both types of clients (QUIC/WG) auto-reconnecting.
  2. Client restart and server taking over the session cleanly.
  3. Parallel concurrent traffic handling for both clients.

- [ ] **Step 2: Run test and verify it passes**
  Run: `sudo bash script/acceptance/e2e_hybrid_ha_reconnect.sh`
  Expected: PASS

- [ ] **Step 3: Commit**
  ```bash
  git add script/acceptance/e2e_hybrid_ha_reconnect.sh
  git commit -m "test: add high availability and auto-reconnection acceptance test"
  ```
