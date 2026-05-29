# 高性能混合多协议安全代理网关架构设计 (v5.0 - 对等密钥认证与双轨聚合遥测版)

## 1. 架构愿景与核心原则

本项目旨在实现一个“优雅、安全、极简配置、双轨解耦、自适应对抗、双模兼容”的 L3/L4 混合代理网关。
核心设计哲学：
- **绝对解耦与双模兼容 (Decoupled Dual-Mode)**：网关的数据通道与控制通道在操作系统层面完全解耦。
  - **Type B (WireGuard L3)**：通过 Linux 内核态运行，承载 UDP、ICMP 业务数据，严守 AllowedIPs 约束。
  - **Type A (QUIC L4 Mux)**：在用户态异步运行，承载 TCP 业务数据，绕过 AllowedIPs 约束，规避 TCP-over-VPN 队头阻塞。
- **对等密钥复用与 Noise_IK 认证 (0-Config Userspace Noise_IK)**：客户端与服务端完全复用已有的 WireGuard 密钥对。
  - 服务端在用户态开启一个独立的**公网 UDP 控制端口**；
  - 双方在用户态直接使用 WireGuard 的公私钥对执行标准的 **Noise_IK_25519_ChaChaPoly_BLAKE2b** 安全握手；
  - 客户端通过此加密控制连接，获取服务端动态推送的公网平行 QUIC 端口池并协商一次性 `Session_PSK`。整个过程在公网运行，不依赖内核网卡分配及内网路由，实现完全的零配置启动。
- **双轨数据聚合遥测 (Unified Telemetry Aggregation)**：
  - 网关在内存中以 **Peer 的 `PublicKey` (公钥) 作为全局唯一标识符**；
  - 网关定期通过 **Netlink 接口**（内核态）抓取 WireGuard 的 Peer 流量统计（L3 流量）；
  - 同时在 Rust 内存中实时统计该 Peer 关联的平行 QUIC 链接池读写字节（L4 流量）；
  - 以公钥为键，将内核态与用户态数据进行高内聚聚合，提供统一的可观测性视窗（Unified Telemetry）。
- **简单稳定的用户态转发 (Robust Userspace Forwarding)**：数据面全部采用成熟、健壮的用户态异步读写流（Read/Write Loop），配合严谨的背压控制。

---

## 2. 总体流量与控制面拓扑 (Topology View)

```text
                                [ 客户端与服务端双轨平行通道 ]

 +-----------------------+                                                             +-----------------------+
 |  Local Proxy (Client) |                                                             | Remote Proxy (Server) |
 +-----------------------+                                                             +-----------------------+
      |                                                                                             |
      |======= 1. Type B 隧道 (内核态 WireGuard L3 / 公网 UDP 51820) ===============================> | (AllowedIPs 生效)
      |   - 承载流量：UDP, ICMPv4/v6 业务流量                                                        |
      |                                                                                             |
      |======= 2. 独立公网控制通道 (用户态 Noise_IK 握手 / 公网 UDP 51821) ==========================> | (控制面解耦)
      |   - 密钥复用：使用 Peer 已有的 WireGuard 密钥对进行 Noise_IK 握手认证                        |
      |   - 动态推送：服务端通过此加密连接，向客户端动态推送公网 QUIC 平行池配置                        |
      |                                                                                             |
      |======= 3. Type A 隧道 (平行 QUIC 连接池 / 服务端动态推送端口) ===============================> | (AllowedIPs 避让)
          - 承载流量：TCP 业务流量
          - 安全认证：TLS 1.3 PSK 模式 (密钥与端口自适应，由 2. 动态协商)
```

---

## 3. 控制面：基于对等密钥认证与动态端口推送协议

本网关的控制面完全独立运行于公网之上，通过复用 WireGuard 静态密钥对，实现安全自引流：

### 3.1 物理公网 Noise_IK 握手与配置推送序列 (Sequence Chart)

```text
  Local Peer (Client)             Symmetric Public WAN             Remote Peer (Server)
         |                                 |                                 |
         |----- 1. 发起公网 Noise_IK 握手 -> | ==============================> | (物理端口 UDP 51821 / 基于 WG 密钥)
         |      - Client Static Key = WG Private Key                         |
         |      - Server Static Key = WG Public Key                          |
         |                                 |                                 |
         | <--- 2. 握手成功，建立安全控制流 | ===============================| (0-Config 安全控制流建立)
         |                                 |                                 |
         |      [随机生成 32 字节密钥]       |                                 |
         |      Session_PSK = Random(32)   |                                 |
         |                                 |                                 |
         |----- 3. 安全发送 Session_PSK --> | ==============================> | (发送 Session_PSK / Session_ID)
         |                                 |                                 |
         |                                 | <--- 4. 动态推送 QUIC 端口池 -----| (服务端下发双栈可用公网 UDP 端口池:
         |                                 |                                 |  e.g. 40001, 40002)
         |                                 |                                 |
         |====== 5. 在公网并行发起多路复用 QUIC 物理链接池 (TLS 1.3 PSK 握手) =======| (向推送的双栈公网端口发起连接)
         |      - Client 使用 Session_PSK 握手
         |      - Server 匹配 Session_ID 完成零证书认证 (0-RTT 极速建连)
```

---

## 4. 统一 AllowedIPs 路由与数据面分流决策

网关抛弃了传统的“TCP 代理段”独立配置，统一使用 WireGuard 规范中的 `AllowedIPs` 作为全局路由决策引擎。

```text
               [ 统一 AllowedIPs 路由决策模型 ]

                  +------------------------+
                  |  收到数据流量 (L3/L4)  |
                  +------------------------+
                               |
            +------------------+------------------+
            |                                     |
    [UDP / ICMP / ICMPv6]                    [TCP 流量]
            |                                     |
     操作系统网络栈                         TPROXY 拦截至网关用户态
            |                          (IPv4-TPROXY & IPv6-TPROXY)
   通过内核路由表寻址                               |
   直接送入 tun0 网卡                     在内存中检索目标 IP (v4/v6)
            |                            是否匹配 Peer 的 AllowedIPs
   通过 WireGuard 加密发送                         |
            |                             +------+------+
            v                             |             |
    受 AllowedIPs 控制                    [命中]        [未命中]
                                          |             |
                                    分流至该 Peer    直连公网
                                   的平行 QUIC 池    或丢弃
```

---

## 5. 数据面 Type B 实现：L3 双栈虚拟网卡与双轨 MSS 自动夹逼

Type B 负责无缝代理 L3 流量，由于封装层引入了额外的包头开销，且 IPv6 报头（40 字节）比 IPv4 报头（20 字节）大一倍，系统在拦截和路由时必须执行双轨规范：

### 6.1 L3 双栈报文捕获与加密
* **双栈网卡配置**：对 `tun0` 虚拟网卡同时配置 IPv4（10.0.0.2/24）与 IPv6（fd00::2/64）内网地址。
* **物理加密封装**：通过 `io_uring` 读入 TUN 设备的 IPv4/IPv6 IP 报文，使用 ChaCha20-Poly1305 对整个包进行高强度 AEAD 加密，直接通过物理 UDP 隧道发出。

### 6.2 双轨 MSS 自动夹逼 (Dual-Track MSS Clamping)
为了彻底防范在物理公网上因封装包超大而被分片（Fragmentation）或因 DF 标志被丢弃，控制面必须对经过网卡的 TCP 握手报文（SYN）执行差异化的 MSS 自动夹逼：

1. **IPv4 TCP 流量夹逼公式**：
   - 目标 MSS_v4 = MTU - 20 (IPv4头) - 20 (TCP头) - Noise开销 (16) - Mux开销
   - 在默认网卡 MTU=1400 时，IPv4 MSS 被自动夹逼至 1344 字节或以下。
2. **IPv6 TCP 流量夹逼公式**：
   - 目标 MSS_v6 = MTU - 40 (IPv6头) - 20 (TCP头) - Noise开销 (16) - Mux开销
   - 在默认网卡 MTU=1400 时，为了补偿 IPv6 庞大的报头开销，IPv6 MSS 必须被更严厉地夹逼至 1324 字节或以下。

---

## 6. 双轨数据聚合遥测设计 (Telemetry Aggregation)

网关提供一体化的可观测性设计，将内核态与用户态的流量指标无缝聚合：

### 6.1 遥测核心数据结构 (In-Memory Telemetry Struct)
```rust
struct PeerTelemetry {
    peer_public_key: String,       // Peer 公钥 (唯一主键)
    
    // 1. 内核态数据 (L3 WireGuard 流量 - 按需通过 Netlink 刮取)
    kernel_tx_bytes: u64,          
    kernel_rx_bytes: u64,          
    last_handshake_time: u64,      
    
    // 2. 用户态数据 (L4 QUIC 流量 - 内存中无锁 AtomicU64 累加)
    proxy_tx_bytes: u64,           
    proxy_rx_bytes: u64,           
    active_tcp_streams: usize,     
    average_quic_rtt_ms: u32,      
}
```

### 6.2 Netlink 按需拉取与零后台开销实时聚合
本系统彻底摒弃了后台定时轮询（Polling）的传统设计，采用**“按需拉取、动态聚合”**的零开销模式：
- **零后台开销运行**：在平时运行期间，网关后台不运行任何 Netlink 查询线程。用户态 L4（QUIC）统计使用极其轻量的无锁原子计数器（`AtomicU64`）在读写时就地累加，CPU 开销接近为零。
- **CLI 按需实时刮取**：仅当管理员通过管理套接字或命令行工具（如 `proxy-cli stats`）发起统计请求时，网关才会在事件循环中单次执行：
  1. 向内核发送单次 `WG_CMD_GET_DEVICE` Netlink 消息，刮取当前活跃 Peer 的 L3 流量统计；
  2. 读取内存中该 Peer 关联的 L4 原子计数器；
  3. **自适应合并**：若该 Peer 是定制双轨客户端，网关会在内存中瞬时合并 L3 与 L4 数据返回给 CLI；若该 Peer 是标准官方客户端（用户态无 QUIC 连接池），网关则直接输出该 Peer 的内核 L3 统计数据，实现天然的双模向下兼容。

### 6.3 内核与用户态对等体双向自适应互补同步 (Bidirectional Kernel <-> Userspace Auto-Sync)
由于网络管理员在配置网关时可能会同时使用两种配置管理工具（如 `new-proxy-cli` 和标准的 `wg`），从而导致内核 WireGuard 状态与网关用户态配置不一致。网关在每次执行 `show` (Stats) 遥测抓取时，会触发**双向自适应互补同步机制**：
1. **内核向用户态同步 (Kernel -> Proxy Config)**：
   - 若发现某些 Peer 仅存在于内核中（通过 `wg` 注入），但网关用户态 `GatewayState` 内存配置和 Trie 路由树中缺失该 Peer；
   - 网关会**自动将该 Peer 补全到用户态配置中**，瞬时完成 **Noise_IK 控制面协商密钥计算** 并**热重建 AllowedIPs LPM 路由基数树**，使其对应的 TCP 流量立刻能被 TPROXY 拦截后走 QUIC 卸载。
2. **用户态向内核同步 (Proxy Config -> Kernel)**：
   - 若发现某些 Peer 存在于用户态配置中（如通过 `new-proxy-cli` 动态添加），但内核 WireGuard 驱动中没有该 Peer；
   - 网关会**自动在内核中创建并绑定该 Peer**（底层自动调用 `wg set <interface> peer <pub_key> allowed-ips <ips> [endpoint]` 命令），确保该 Peer 的 L3（UDP/ICMP）双栈流量通道正常连通。
3. **前置状态源标识 (Pre-Sync Source Labels)**：
   - 为了协助网络诊断，CLI 的 `show` 输出或 UDS 遥测流对每个 Peer 附加了 `source` 状态标识（代表同步互补之前的两端分布状态）：
     - **`both`**：上一次 `show` 之前，内核态与用户态均有此 Peer，处于完全对齐状态。
     - **`kernel`**：仅内核态持有该 Peer，现已自动补充同步至用户态。
     - **`proxy`**：仅用户态（控制面）持有该 Peer，现已自动同步绑定至内核态驱动。

---

## 7. 配置文件规范示例 (Zero-Client Config)

网关使用一站式配置文件，整合了双栈 WireGuard 与平行 QUIC 连接池的配置，并支持基于路由表和自定义脚本的网卡生命周期自愈管理：

### 7.1 Interface 核心字段说明
接口名与 WireGuard/wg-quick 保持一致：来自配置文件 basename，例如 `tun0.conf` 对应接口 `tun0`，`client.conf` 对应接口 `client`。所有自动路由、`wg show <interface> dump` 与清理逻辑都使用这个接口名。

* **`Table`**（可选，支持 `Table` 或 `table`）：
  * **`auto` 或未配置 (默认值)**：网关在启动时会自动将 `Address` 绑定到 tun 设备，自动将所有 Peer 的 `AllowedIPs` 注入系统路由表（通过 `ip route`），并配置本地策略路由和 TPROXY 的 `iptables` / `ip6tables` 拦截规则。策略路由使用按接口名稳定派生的 `fwmark` 与 table，避免多实例互相覆盖。在程序退出时，会自动、无损地回滚删除所有注入的路由及防火墙规则。
  * **`off`**：网关不做任何路由和 `iptables` 的修改，完全交由用户或外部脚本接管。
* **`PreScript` / `pre_script`**（可选）：网关启动前执行的脚本。可以是一个**单行 shell 命令**（如 `sysctl -w ...`），也可以是一个**可执行脚本/bash 文件的路径**（如 `/etc/new_proxy/pre.sh` 或 `bash /path/to/script.sh`）。
* **`PostScript` / `post_script`**（可选）：程序优雅停止并清理完所有路由与 iptables 拦截规则后执行的脚本。同样支持**单行 shell 命令**或**脚本/bash 文件的路径**。

### 7.2 客户端双栈配置示例 (`client.conf`)
```ini
[Interface]
PrivateKey = client_wg_private_key_base64...
Address = 10.0.0.2/24, fd00::2/64
# 客户端本地透明代理拦截端口 (支持 IPv4 和 IPv6 监听)
TProxyPort = 1080
MTU = 1400

# 自动注入路由和代理 iptables 规则 (不写或 auto 为开启，off 为关闭)
Table = auto
# 前置启动脚本
PreScript = echo "Client gateway is starting..." && sysctl -w net.ipv4.ip_forward=1
# 后置停止脚本
PostScript = echo "Client gateway has stopped cleanly."

[Peer]
PublicKey = server_wg_public_key_base64...
# 物理对端物理地址 (可配置为 IPv4 或 IPv6 目的 Endpoint)
Endpoint = 198.51.100.1:51820
# 用户态独立公网控制端口 (网关自动提取 Endpoint 的 IP 并结合此 ProxyPort 进行安全协商)
ProxyPort = 51821
# 统一路由大脑：同时写入 IPv4 与 IPv6 目的网段，进行全局路由决策
AllowedIPs = 192.168.1.0/24, 8.8.8.8/32, 2001:db8:1::/48
```

### 7.3 服务端双栈配置示例 (`server.conf`)
```ini
[Interface]
PrivateKey = server_wg_private_key_base64...
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
# 公网独立 UDP 控制端口监听
ListenControlPort = 51821

# 自动绑定 IP 并拉起网卡 (不写或 auto 为开启，off 为关闭)
Table = auto
# 前置启动脚本
PreScript = echo "Server gateway is starting..."
# 后置停止脚本
PostScript = echo "Server gateway has stopped cleanly."

# 动态物理 QUIC 端口池配置 (支持双栈推送)
[QUICPool]
PublicIPv4 = 198.51.100.1
PublicIPv6 = 2001:db8::1
ListenPorts = 40001, 40002, 40003, 40004

[Peer]
PublicKey = client_wg_public_key_base64...
AllowedIPs = 10.0.0.2/32, fd00::2/128
```

---

## 8. 命令行工具与 API 交互协议架构 (`new-proxy-cli`)

为了向系统管理员提供类 `wg` 命令行工具的动态配置与可观测性能力，网关内建了基于 **Unix Domain Socket** 的高性能 JSON IPC 协议，并配备了独立的命令行管理工具 `new-proxy-cli`。

### 8.1 命令行工具拓扑与 API 交互流 (IPC Topology)

```text
    +--------------------------------+
    |         new-proxy-cli          |  (类似 wg 的命令行管理工具)
    +--------------------------------+
      |
      |--- 1. 发起 Unix Domain Socket 链接 -----------------+
      |    (路径: /tmp/new_proxy_api.sock)                 |
      |                                                    v
      |=== 2. 发送 JSON 格式指令 ==================> [ 代理网关守护进程 ]
      |    - Command::Stats (查看状态)               - 动态 AllowedIPs Trie
      |    - Command::AddPeer (动态添加 Peer)        - 动态 ControlServer Secrets
      |    - Command::RemovePeer (动态删除 Peer)     - L4 遥测内存注册中心
      |                                                    |
      | <== 3. 响应 JSON 并关闭连接 =========================+
```

### 8.2 动态 API 指令与 JSON 协议规范

网关在 UDS 接口上使用流式 JSON 报文进行双向无锁通信：

#### 8.2.1 获取状态与遥测 (`Command::Stats`)
* **请求格式**：
  ```json
  { "type": "Stats" }
  ```
* **响应格式** (包含内核 L3 与用户态 L4 实时聚合)：
  ```json
  [
    {
      "public_key": "client_wg_public_key_base64...",
      "allowed_ips": ["10.0.0.2/32", "fd00::2/128"],
      "l3_rx_bytes": 1048576,
      "l3_tx_bytes": 2097152,
      "last_handshake": 1716912345,
      "l4_rx_bytes": 5242880,
      "l4_tx_bytes": 9437184,
      "active_streams": 3
    }
  ]
  ```

#### 8.2.2 动态添加对端 (`Command::AddPeer`)
在网关运行期，无需重启进程即可动态注册新的对等体。网关在收到请求后，会利用服务端的 Private Key 自动为新 Peer 计算 ECDH 共享密钥并缓存至 `ControlServer`，同时热重载 `AllowedIPsRouter`：
* **请求格式**：
  ```json
  {
    "type": "AddPeer",
    "public_key": "new_client_wg_public_key_base64...",
    "allowed_ips": ["10.0.0.3/32", "fd00::3/128"],
    "endpoint": "198.51.100.2:51820",
    "proxy_port": 51821
  }
  ```
* **响应格式**：
  ```json
  { "status": "Ok" }
  ```

#### 8.2.3 动态删除对端 (`Command::RemovePeer`)
立即切断该 Peer 的所有平行 QUIC 连接，并注销其在控制面的身份验证密钥与路由条目：
* **请求格式**：
  ```json
  {
    "type": "RemovePeer",
    "public_key": "client_wg_public_key_base64..."
  }
  ```
* **响应格式**：
  ```json
  { "status": "Ok" }
  ```

### 8.3 命令行工具命令语法 (CLI Command Reference)

- **展示当前状态与实时聚合统计** (类似于 `wg show`)：
  ```bash
  new-proxy-cli show
  ```
- **导出机器可读的 tab 分隔统计** (类似于 `wg show dump`)：
  ```bash
  new-proxy-cli dump
  ```
- **动态增加 Peer**：
  ```bash
  new-proxy-cli add-peer <public_key> <allowed_ips> [endpoint] [proxy_port]
  ```
- **动态删除 Peer**：
  ```bash
  new-proxy-cli remove-peer <public_key>
  ```
