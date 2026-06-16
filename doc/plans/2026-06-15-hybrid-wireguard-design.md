# Hybrid QUIC and Kernel WireGuard Gateway Design Spec

This document specifies the design for adding support for Linux kernel-native WireGuard interfaces to the `new_proxy` gateway, creating a hybrid secure gateway that handles both userspace IP-over-QUIC and kernel-native WireGuard tunnels.

---

## 1. Goal

Integrate support for standard Linux kernel-native WireGuard interfaces managed entirely in Rust via Netlink (`defguard_wireguard_rs`), allowing standard WireGuard clients (e.g. mobile devices/iPads) to connect directly to the gateway, while maintaining userspace IP-over-QUIC tunnels for high-performance backends.

---

## 2. Configuration Design

### 2.1 Interface Configuration
Under `[Interface]` in the INI configuration:
* `WgListenPort` (Optional `u16`): The UDP port for the kernel-native WireGuard interface to listen on.
  * If omitted and there are `Type = wireguard` peers, it defaults to `ListenPort + 1` (where `ListenPort` is the userspace QUIC control port). If `ListenPort` is also omitted, it defaults to `51821`.

### 2.2 Peer Configuration
Under each `[Peer]` in the INI configuration:
* `Type` (Optional enum string): Specify the tunnel type for this peer.
  * `quic`: Userspace IP-over-QUIC tunnel (default).
  * `wireguard`: Kernel-native WireGuard tunnel.

### 2.3 Interface Autonaming
Virtual network interfaces are automatically named based on the configuration filename `<config_name>` (e.g. `client` from `client.conf`):
* Userspace TUN device (QUIC mode `Mode = tun`): `<config_name>-tun`
* Userspace AF_XDP device (QUIC mode `Mode = af_xdp`): `<config_name>-veth`
* Kernel WireGuard device: `<config_name>-wg`

---

## 3. Kernel WireGuard & Netlink Management

### 3.1 Crate Dependency
We will add `defguard_wireguard_rs = "0.10.0"` to `Cargo.toml`. This crate interacts with the Linux Netlink API (`RTM_NEWLINK`, `RTM_DELLINK`, Generic Netlink) to manage WireGuard interfaces without calling the external `wg` or `ip` commands.

### 3.2 Lifecycle
1. **Creation**: During startup (`setup_routes`), if there is any `Type = wireguard` peer, create the `<config_name>-wg` interface, assign its `Address` (shared with the QUIC interface), and bring the interface up.
2. **Parameters & Peers Configuration**: Call the netlink interface to set the interface's `PrivateKey`, `WgListenPort`, and configure each `Type = wireguard` peer (with public key, AllowedIPs, and endpoint).
3. **Shutdown**: During `cleanup_routes`, delete the `<config_name>-wg` interface from the kernel via Netlink.
4. **Dynamic Changes**: On dynamic UDS `AddPeer` or `RemovePeer` requests, immediately synchronize the peer updates to the kernel WireGuard interface using Netlink.

### 3.3 wireguard-go Adaptive Fallback
If the running Linux kernel lacks native WireGuard support (e.g., `CONFIG_WIREGUARD` is not set):
* **Detection**: Netlink interface creation (`create_interface`) will return a link-type-not-supported error.
* **Fallback**: When the error is caught, the gateway launches the userspace implementation by spawning `wireguard-go <config_name>-wg` as a background process.
* **Uniform Configuration**: Once the virtual TUN device is created by `wireguard-go`, the gateway configures its parameters (private key, peers, port) and retrieves telemetry via the same Netlink socket, as `wireguard-go` exposes a standard netlink interface.
* **Cleanup**: On process shutdown, deleting the link via Netlink or killing the spawned `wireguard-go` process cleans up the interface automatically.

---

## 4. LPM Routing Integration

If both `<config_name>-tun` and `<config_name>-wg` share the same subnet IP (e.g. `10.0.0.2/24`), Linux creates overlapping subnet routes.
To ensure correct traffic forwarding:
* We set up specific host routes (e.g., `/32` for IPv4 or `/128` for IPv6) for each peer pointing to their respective device:
  * For QUIC peers: `ip route replace <peer_ip>/32 dev <config_name>-tun table 1000`
  * For WireGuard peers: `ip route replace <peer_ip>/32 dev <config_name>-wg table 1000`
* Longest Prefix Match (LPM) in the Linux routing table guarantees that packets destined for specific peers are routed to the correct interface.

---

## 5. Telemetry & CLI Integration

### 5.1 Telemetry Collection
When a UDS `Stats` request is received:
1. Query the kernel WireGuard interface `<config_name>-wg` using `defguard_wireguard_rs` API to get all active peers and their statistics.
2. Retrieve the `rx_bytes`, `tx_bytes`, and `last_handshake_time` for each WireGuard peer.
3. Populate `UserspaceWgRegistry` (which will be renamed/adapted to `KernelWgRegistry` or updated in `l3_stats`) with the retrieved statistics.
4. Mark the peer's `source` in `UnifiedTelemetry` as `"wireguard"`.

### 5.2 CLI Output
`new-proxy-cli` will display the stats in WireGuard format, clearly showing:
* `source: wireguard` for kernel WireGuard peers.
* The actual data transfer (`wireguard: X received, Y sent`) and `latest handshake` timestamp retrieved from the kernel.

---

## 6. Testing Design

### 6.1 E2E Scenarios

#### 1. `e2e_hybrid_wireguard.sh` (Kernel WireGuard Access)
* **Topology**: `mobile_ns` (standard WG client, IP `10.0.0.3`) <-> `client_ns` (runs `new_proxy` client, creating `client-wg` and `client-tun`, IP `10.0.0.2`) <-> `server_ns` (runs `new_proxy` server, IP `10.0.0.1`).
* **Verification**:
  * `mobile_ns` establishes a WG handshake with `client-wg` directly.
  * Send ICMP ping from `mobile_ns` to `server_ns` (`10.0.0.1`). Packets must decrypt in `client-wg` and route via host routing to `client-tun`, which encapsulates them into QUIC Datagrams to the server.
  * Check UDS stats to verify non-zero tx/rx bytes on the WireGuard peer, and correct `source` labeling.

#### 2. `e2e_hybrid_ha_reconnect.sh` (High Availability & Reconnection)
* **Scenario A: Server Restart**:
  * Kill and restart the `new_proxy` server.
  * Check that the QUIC client's `Health Checker` detects this and auto-reconnects within 10s.
  * Check that the WireGuard client auto-reconnects seamlessly upon new traffic without manual intervention.
* **Scenario B: Client Restart**:
  * Stop and restart the `new_proxy` client (QUIC or WG).
  * Verify that the server takes over the new session cleanly, releasing the old one without routing or socket resource conflicts.
* **Scenario C: Simultaneous Connections**:
  * Concurrent `Type = quic` and `Type = wireguard` clients active. Verify no thread-safety issues, CPU locks, or routing conflicts occur.
