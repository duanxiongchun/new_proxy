# Design Spec: `new_proxy` Deployment and Telemetry Optimization

This specification outlines the technical design for telemetry fixes, dynamic memory cleanup, robust kernel module loading with userspace fallback, and server UDP sysctl tuning.

---

## 1. Scope & Objectives

We aim to resolve three issues in the codebase and apply one system-level tuning on the remote host:
1. **CLI Telemetry Correction**: Fix the misleading `quic: active` status in [src/cli.rs](file:///home/duanxiongchun/new_proxy/src/cli.rs) when a client has 0 physical connections but has historical bytes.
2. **Telemetry Memory Leak Fix**: Add key deletion to [TelemetryRegistry](file:///home/duanxiongchun/new_proxy/src/telemetry.rs#L25) to prevent unbounded map growth when peers are dynamically removed.
3. **Robust WireGuard Initialization**: Run `modprobe wireguard` upon startup. If kernel link creation or Netlink key setting fails, automatically log a warning and fallback to userspace `wireguard-go`.
4. **Persistent UDP Tuning**: Deploy a custom sysctl file on the remote server to increase maximum send/receive UDP buffer size limits.

---

## 2. Technical Design

### 2.1 CLI Telemetry Formatting ([src/cli.rs](file:///home/duanxiongchun/new_proxy/src/cli.rs))

Currently, `quic: inactive` is printed only if `peer.quic_connections.is_empty() && peer.l4_rx_bytes == 0 && peer.l4_tx_bytes == 0`. 

We will modify this check to:
- If `peer.quic_connections.is_empty()` is true:
  - If `peer.l4_rx_bytes > 0 || peer.l4_tx_bytes > 0`, print:
    `  quic: inactive (disconnected)`
    followed by the historic transfer statistics:
    `  quic transfer: X received, Y sent`
  - Otherwise, print:
    `  quic: inactive`
- If `peer.quic_connections` is not empty, print:
  `  quic: active, {} physical connections, {} active streams`
  followed by cumulative transfers and detailed connection snapshots.

### 2.2 Telemetry Registry Cleanup ([src/telemetry.rs](file:///home/duanxiongchun/new_proxy/src/telemetry.rs) & [src/uds_server.rs](file:///home/duanxiongchun/new_proxy/src/uds_server.rs))

1. In [src/telemetry.rs](file:///home/duanxiongchun/new_proxy/src/telemetry.rs), we will expose a new method on `TelemetryRegistry`:
   ```rust
   pub fn remove(&self, pub_key: &[u8; 32]) {
       let mut map = self.stats[self.shard_index(pub_key)].lock();
       map.remove(pub_key);
   }
   ```
2. In [src/uds_server.rs](file:///home/duanxiongchun/new_proxy/src/uds_server.rs), inside `handle_remove_peer`, we will call:
   ```rust
   context.telemetry.remove(&parsed_pub_key);
   ```
   immediately following secret and session cache removals.

### 2.3 Robust Device Creation & Userspace Fallback ([src/wireguard.rs](file:///home/duanxiongchun/new_proxy/src/wireguard.rs))

1. We will update `configure_kernel_device` to execute `modprobe wireguard` using `Command`.
2. We will check the exit status of the `ip link add dev ... type wireguard` command.
3. If `ip link add` returns an error, OR if `configure_kernel_device_key` returns an error, we will log a warning indicating kernel WireGuard setup failed, and automatically redirect the call to `configure_userspace_device`.

```rust
fn configure_kernel_device(
    interface_name: &str,
    private_key: &[u8; 32],
    listen_port: Option<u16>,
) -> Result<(), String> {
    log::info!("Attempting to load wireguard kernel module via modprobe");
    let _ = Command::new("modprobe").arg("wireguard").output();

    log::info!("Creating WireGuard interface '{}' if it does not exist", interface_name);
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
        // Clean up the partially created device before switching to userspace
        let _ = Command::new("ip").args(["link", "del", "dev", interface_name]).output();
        return configure_userspace_device(interface_name, private_key, listen_port);
    }

    Ok(())
}
```

### 2.4 Persistent UDP Buffer Tuning (Remote Server Configuration)

We will apply the tuning directly on the remote server `2604:a880:4:1d0::3a41:2000`:
1. Create a configuration file `/etc/sysctl.d/99-new-proxy.conf`.
2. Populate it with:
   ```ini
   net.core.rmem_max = 2621440
   net.core.wmem_max = 2621440
   ```
3. Load the sysctl file persistently via:
   `sysctl -p /etc/sysctl.d/99-new-proxy.conf`

---

## 3. Verification Plan

### 3.1 Local Unit & Integration Tests
- Run `cargo test` to ensure all 50 unit tests compile and pass.
- Run dynamic peer acceptance tests:
  `sudo script/acceptance/e2e_dynamic_client_peer.sh`

### 3.2 Deployment to Remote Server
- Compile and build a new Debian package:
  `make package`
- Copy the package `/target/new-proxy_5.0.0_amd64.deb` to the remote server.
- Install the package on the remote server:
  `dpkg -i target/new-proxy_5.0.0_amd64.deb`
- Restart the systemd service to apply:
  `systemctl restart new_proxy@server`

### 3.3 Post-Deployment Verification
- Run `sysctl net.core.rmem_max` on the remote server to verify persistence.
- Inspect the systemd logs to ensure successful startup without restarts.
- Query CLI stats (`new-proxy-cli show`) to confirm formatting is correct and peer telemetry displays as `inactive (disconnected)` for idle peers.
