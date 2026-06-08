# new_proxy 当前架构说明

本文档描述当前代码实现，不描述规划能力。若架构设计发生变化，先更新本文档，再补对应测试。

## 1. 总体模型

`new_proxy` 是一个混合 L3/L4 网关：

- **L3 数据面**：
  - **服务端**：打开 TUN 设备并通过内建 `boringtun` 处理 WireGuard 风格 L3 加解密；配置 `Table = auto` 时会为 peer AllowedIPs 下发指向 TUN 的路由。
  - **客户端**：采用用户态协议栈。启动时程序按已建立 QUIC pool 的 data port 数量打开并持有一个或多个 TUN 队列文件描述符；若控制面已协商出 data port 数但 QUIC data 连接暂时失败，则仍按该协商数量打开队列，避免恢复时 worker 拓扑不匹配。随后程序配置该 TUN 的地址和 AllowedIPs 路由；在进程内通过 `boringtun`（用户态 WireGuard 协议库）对 UDP/ICMP 报文和 TCP fallback 报文进行加密封装，并发送至宿主机物理网卡。客户端不再同步 peer 到内核 WireGuard 设备，但创建 TUN 和配置路由仍需要相应系统权限（通常是 `CAP_NET_ADMIN` 或 root）。
- **L4 TCP 路径**：
  - **服务端**：通过物理 QUIC 连接池接收并解密来自客户端的透明流。
  - **客户端**：通过 TUN 拦截 TCP 流量，由各 TUN 队列对应的 `RtcWorker` 内部 `smoltcp` 用户态协议栈接管。建立连接后，通过在进程内桥接 `smoltcp` 套接字与对应的 QUIC 复用连接流（Quinn）进行转发，从而完全免除了内核 iptables 和 TPROXY 的防火墙规则依赖。同一 TCP flow 的状态保存在接收该 flow 的 worker 中，当前实现依赖 Linux TUN multiqueue 的 flow queue affinity。
- **控制面**：独立的 UDP 报文协议，使用 WireGuard 密钥材料派生 X25519 shared secret，并用 HMAC-SHA256 认证 JSON 请求/响应。
- **QUIC 数据面**：使用服务端自签证书，服务端在已认证控制面响应中下发证书 SHA-256 指纹，客户端只接受该指纹对应证书。
- **运行期 API**：通过 Unix Domain Socket 提供 `Stats`、`Dump`、`AddPeer`、`RemovePeer` API。

## 2. 运行模式

启动模式由配置决定：

- Server mode：`ListenControlPort` 存在，或 `[QUICPool].ListenPorts` 非空。
- Client mode：非 server mode，且至少有一个 `[Peer]`。

Server mode 要求：

- `ListenControlPort` 必须存在。
- `[QUICPool].ListenPorts` 至少一个端口。
- peer 可以只配置 `PublicKey` 和 `AllowedIPs`，用于接受控制面协商与 L3 遥测展示。

Client mode 支持：

- **用户态混合代理**：TCP 流量匹配 proxy peer 的 `AllowedIPs` 最长前缀后卸载到用户态 QUIC 连接池中；UDP/ICMP 以及 QUIC 不可用时的 TCP fallback 通过 `boringtun` 在用户态进行 WireGuard 加密封装。
- proxy peer 需要同时配置 `Endpoint` 和 `ProxyPort`。`ProxyPort` 是控制面 UDP 端口；`Endpoint` 和 `ProxyPort` 必须成对出现。
- `TProxyPort` 是旧 TPROXY 路径遗留配置，当前用户态 TUN client 不再需要它。
- 客户端 worker 数在启动时固定为已建立 QUIC pool 的 data port 数量；如果控制面协商成功但 data 连接失败，则使用协商得到的 data port 数量。多个 proxy peer 的 data port 数量必须一致，并且动态新增、后台恢复或控制面刷新得到的 data port 数必须匹配当前已启动 worker 数，不一致时拒绝该 QUIC pool 并继续走 userspace WireGuard L3 fallback。需要改变 client worker 拓扑时必须重启客户端。服务端 worker 数严格跟随 `QuicPool.ListenPorts` 数量。L4 proxy 模式下每个 worker 拥有独立的 `smoltcp`、NAT 映射和桥接通道；L3 userspace WireGuard 状态按 peer 共享，并通过内部锁串行访问。

## 3. WireGuard 后端

client/server 都使用内建的 `boringtun` 模块。程序作为库直接调用 `boringtun::noise::Tunn` 进行解密/加密，不再创建 kernel WireGuard 设备，也不再依赖 generic netlink 或外部 `wireguard-go` 进程；但 TUN 创建、接口地址和路由配置仍需要系统网络管理权限。

## 4. 控制面

控制面位于服务端 `ListenControlPort`，客户端从 peer 的 `Endpoint.ip()` 与 `ProxyPort` 拼出控制面地址。

协商流程：

1. 客户端用本地私钥和服务端公钥计算 X25519 shared secret。
2. 客户端发送 `ControlRequest`，包含客户端派生公钥和随机 `client_nonce`，外层 `SignedPacket` 用 HMAC-SHA256 保护。
3. 服务端按 peer 公钥查找预计算 shared secret，校验 HMAC 和 nonce replay cache。
4. 服务端生成 `server_nonce`，派生 `session_psk`，缓存到 `session_cache[client_public_key]`。
5. 服务端返回 QUIC 端口池、公网 IPv4/IPv6 可选地址、`client_nonce`、`server_nonce`、`quic_cert_sha256`，响应同样用 HMAC-SHA256 保护。
6. 客户端校验响应 HMAC 和 `client_nonce`，派生同一 `session_psk`。

控制面重试每次生成新的 `client_nonce`，避免响应丢包后旧 nonce 被服务端 replay cache 拒绝。

## 5. QUIC 数据面

服务端启动时生成一组自签证书和私钥：

- QUIC listener 绑定 `[QUICPool].ListenPorts`。
- 证书 SHA-256 指纹由控制面下发给客户端。
- 客户端使用 pinned certificate verifier，不再接受任意自签证书。

客户端启动每个 proxy peer 时：

1. 先完成控制面协商。
2. 从控制面响应中选择 QUIC endpoint IP（IPv6 优先使用 `PublicIPv6`，IPv4 优先使用 `PublicIPv4`，未配置时回退到 `Endpoint.ip()`）。
3. 对端口池中每个端口建立一条物理 QUIC 连接。
4. 每条连接打开认证流，发送 `QuicAuthPacket { client_public_key, nonce, mac }`。
5. 服务端用 `session_cache` 中的 `session_psk` 校验 QUIC auth HMAC。

服务端在每次接受业务 stream 前会检查该连接使用的 `session_psk` 是否仍与 `session_cache` 一致。peer 被删除或重新协商后，旧连接会被关闭。

客户端 `QuicPoolClient` 有后台健康检查：

- 已关闭连接会按原 endpoint 重连。
- 缺失 endpoint 会补建连接。
- pool 状态分为 `Active`、`Fallback`、`Recovering`。
- 重连失败后支持控制面重新协商，并替换连接池与指纹。

## 6. 用户态拦截与 RtcWorker 事件循环

在客户端模式下，程序放弃了基于 `iptables` Mangle 和 `TPROXY` 规则的流量捕获，改为完全在用户态中处理网络协议栈：

```mermaid
graph TD
    subgraph Client OS
        App[客户端应用程序] <-->| AllowedIPs 路由| Tun[Multiqueue TUN 设备]
    end

    subgraph new_proxy Client (Fixed Workers)
        subgraph Worker N
            TunQ[TUN 队列 N FD] <-->|读/写| Worker[RtcWorker Loop]
            Worker <-->|TCP (NAT)| SmolTCP[smoltcp Stack]
            Worker <-->|UDP/ICMP| UserspaceWg[Shared per-peer userspace boringtun]

            SmolTCP <-->|Channel Bridge| QuicStream[QUIC Stream]
            UserspaceWg <-->|加密包| RawUDP[物理 UDP Socket]
        end
    end

    subgraph Server Side
        Server[服务端网关]
        RawUDP <--> Server
        QuicStream <--> Server
    end
```

### 6.1 Multiqueue TUN 与多线程扩展

客户端启动时根据已建立 QUIC pool 的 data port 数开启多队列（`IFF_MULTI_QUEUE`）TUN 设备；若控制面已返回 data port 数但 data 连接失败，也使用该协商数量启动 worker；运行中不热扩容 worker。
- **出站流量**：Linux TUN multiqueue 按 flow 选择队列，单个 TCP flow 的后续包应保持队列亲和；不同 flow 可被分散到不同队列 FD。
- **L4 TCP offload 出站流量**：接收某个 TCP flow 的 `RtcWorker` 持有该 flow 的 `smoltcp` socket、NAT 映射和桥接通道。
- **固定 worker**：worker 数在启动时确定，不随连接数增长。每个 worker 绑定一个 TUN 队列 FD，拥有自己的 L4 TCP 用户态协议状态、NAT 映射和数据面 packet buffer pool；数据面热路径不使用跨 worker 的共享大池，避免全局锁竞争。
- **线程模型**：所有连接状态都由所属 `RtcWorker` 的事件循环驱动，不能按连接创建新的数据面线程或长期 task。当前实现固定 worker 数，smoltcp RX/TX 队列使用 worker 内 `PooledBuf` 流转，QUIC stream 句柄也保存在 worker 的 bridge 状态中。
- **L3 外层 UDP**：客户端 WireGuard L3 路径流量较小，当前共享单个外层 UDP socket 和共享 per-peer `boringtun::Tunn` 状态；只有 worker 0 负责该 UDP socket 的入站 receive 与 timer 包，其他 worker 只在 TCP fallback/UDP/ICMP 出站时发送。`VirtualTunnelSocket` 保留为多底层 UDP socket readiness 聚合器：它不后台预取业务包、不维护中间接收队列，调用方 `recv_from` 时直接把 ready socket 的数据读入调用方 buffer；发送使用当前 active 底层 UDP socket。该并行模型依赖 Linux TUN multiqueue 的 flow queue affinity，不声明其他平台具备相同行为。

### 6.2 Run-to-Completion (RTC) 运行完成环路

每个 `RtcWorker` 的事件循环执行路径遵循 **Run-to-Completion** 模式：包从所属 TUN queue 读入该 worker 的 `PooledBuf` 后，尽量通过所有权转移在 worker 内继续流转，避免中间 `Vec` 分配和 payload copy。必须发生的 copy 只保留在内核 syscall 边界、加解密输出边界和协议库不可避免的内部缓冲边界。
写回 TUN、发送外层 UDP 和 QUIC stream 读写均按非阻塞方式推进；当出口暂不可写时，包所有权进入所属 worker 的 pending 队列，并由 TUN/UDP writable 事件唤醒后继续 flush。只有内部 pending 字节数达到上限时才会丢弃或关闭连接，以保护 worker 内存不会无界增长。

1. **TUN 出站包**：读取 TUN 队列中的原始 L3 IP 报文。
   - **TCP 报文**：
     - 若为 SYN 握手包且未匹配当前任何套接字，则在 `smoltcp` 中动态创建并绑定一个 Listen 状态的 TCP 套接字。若 socket 创建或 listen 失败，会回滚本地 flow 状态并立即走 userspace WireGuard L3 fallback。
     - 在 `nat_map` 中记录原始目标 IP 和端口 `(client_ip, client_port, dest_port) -> original_dest_ip`。
     - 执行 **NAT 转换**：将报文目标 IP 改写为本机配置的 `smoltcp` 虚拟接口地址（来自 `[Interface].Address` 的 IPv4/IPv6 地址）。为了加快处理速度，`smoltcp` 虚拟网卡的校验和（Checksum）功能被设为忽略；写回 TUN 前会重新计算 IPv4 header checksum 和 TCP pseudo-header checksum。
     - 将同一个 `PooledBuf` 投递至本地 `smoltcp` 实例，不再把 TUN packet 复制成新的 `Vec`。
     - 处理完成后，从 `smoltcp` 提取出站 TCP 包；出站包也从该 worker 的 pool 获取 buffer，通过 `nat_map` 反向改写源 IP 并写入 TUN 队列。
     - IPv6 L4 offload 当前只解析固定 IPv6 base header 后直接承载 TCP 的报文；携带 IPv6 extension headers 的 TCP 报文不会进入 L4 offload，而是按普通 L3 报文走 userspace WireGuard fallback。
   - **UDP / ICMP 报文**：
     - 直接在当前线程中调用 `boringtun::Tunn::encapsulate` 加密，并通过本地 UDP 套接字发送给服务端。
   - **故障降级 (WireGuard Fallback)**：
     - 若目标 peer 的 QUIC 连接池不处于 `Active` 状态（发生了网络抖动或服务端重启中），出站的 TCP 报文不再投递给本地 `smoltcp`，而是自动回退到 `boringtun` 进行 L3 加密封装后发送，实现无感知 failover。
2. **物理网络入站包**：读取物理 UDP 套接字或 QUIC 数据流。
   - **QUIC 数据流**：bridge task 从 QUIC stream 读到 payload 后通过 `BridgeChannels` 送回对应 `RtcWorker`，再写入对应的 `smoltcp` 套接字缓冲区，重组后的 TCP 数据生成 ACK 或响应包写回 TUN。
   - **物理 WireGuard 加密包**：调用 `boringtun::Tunn::decapsulate` 解密，解密得到的原始 IP 数据包直接在当前线程中写入 TUN 队列。

### 6.3 管道数据桥接 (BridgeChannels)

`RtcWorker` 内部为每个活跃的 `smoltcp` 套接字维护桥接状态。当套接字成功建立连接后：
- `RtcWorker` 会通过 `nat_map` 将 smoltcp 虚拟本地地址反查为原始目标地址，动态唤醒对应的桥接任务，异步从 `smoltcp` 套接字读取 payload，并将其写入客户端连接池的 QUIC stream 中。
- 从 QUIC stream 读取的数据在工作线程中被写回 `smoltcp` 套接字的发送队列。
- 每个 worker 的 TCP flow 数、单 socket buffer、bridge pending 包数和 pending 字节数都有默认上限；达到上限的新 flow 或慢读写 bridge 会被降级或关闭，优先保护进程内存稳定性。TUN/UDP/WireGuard/QUIC bridge 的运行时 packet buffer 默认按 `MTU + 256` 派生，下限 1500、上限 65535，默认 MTU 1400 时为 1656，jumbo MTU 9000 时为 9256。默认上限可通过 `NEW_PROXY_MAX_WORKER_TCP_FLOWS`、`NEW_PROXY_TCP_SOCKET_BUFFER_BYTES`、`NEW_PROXY_BRIDGE_PENDING_LIMIT`、`NEW_PROXY_BRIDGE_PENDING_BYTES_LIMIT` 和 `NEW_PROXY_PACKET_BUFFER_BYTES` 覆盖，用于不同机器规格和压测场景调参。

QUIC bridge 不再按连接 `spawn` 长生命周期 task，而是作为 `RtcWorker` 内部 bridge 状态由同一个事件循环驱动 TUN、UDP、smoltcp socket、QUIC stream 和 timer。新连接建立 QUIC stream 时先进入 `Opening` 状态，握手 future 保存在该 bridge 中，每次 worker tick 只 poll 一次；建立完成后切到 active stream 状态，读写 QUIC 时也只做单次非阻塞 poll，不能读写时立即回到 worker 事件循环。

## 7. 路由配置

虽然绕过了 `iptables`/`TPROXY` 规则的下发，但 `new_proxy` 依然在客户端启动时做如下路由配置（`Table != off`）：

1. 配置 TUN 接口的 IP 地址（对应配置文件中 `Address` 声明）。
2. 将 TUN 接口的 MTU 设为配置值（默认 `1420`），并启用网卡（`ip link set dev <interface> up`）。
3. 针对每个 peer 声明的 `AllowedIPs`，自动添加指向该 TUN 设备的系统路由规则（`ip route replace <allowed_ip> dev <interface>`）。

为避免 full-tunnel `AllowedIPs = 0.0.0.0/0` 或 `::/0` 递归捕获 QUIC / control / userspace WireGuard 外层 UDP，程序采用 WireGuard 风格的 `SO_MARK` + policy routing：所有外层 UDP socket 自动设置固定 mark，`Table = auto` 时 peer `AllowedIPs` 被安装到专用 routing table，并添加 `lookup main suppress_prefixlength 0` 与 `not fwmark <mark> lookup <table>` 规则。这样未标记业务流量命中 full-tunnel table 进入 TUN，已标记外层流量和主表中的直连/更具体物理路由不会递归进入 TUN；动态 `AddPeer` 只需更新专用 table 中的 peer route，不再学习或缓存 endpoint host route。

## 8. 遥测与 API

UDS 路径：`/run/new_proxy/<interface>.sock`

遥测指标含义与方向：

- `rx` / `received`：从该 peer 收到的字节。
- `tx` / `sent`：发给该 peer 的字节。
- 用户态协议栈收发数据同样使用该语义：数据经 `QUIC -> smoltcp -> TUN` 计为 `rx`，经 `TUN -> smoltcp -> QUIC` 计为 `tx`。
- `dump` 输出包含 `virtual_tunnel` 行；仅启用 `VirtualTunnelSocket` 时，`rx=<packets>:<bytes>` 表示经虚拟 UDP socket 直接交给调用方的业务包，`control=<packets>` 表示 PING/PONG 健康探测控制包，`errors=<count>` 表示底层 UDP receive 错误数。当前 client WireGuard L3 使用单 UDP socket，因此该行通常为 0。

## 9. 已知架构边界

- **客户端 L3/L4 均在用户态**，消除任何系统 WireGuard 内核模块及 `iptables` / TPROXY 依赖。
- **服务端 L3 也在用户态**，不再依赖内核 WireGuard 模块；QUIC 接收池仍直接绑定宿主机 UDP 端口。
- 动态 peer 管理（`AddPeer` / `RemovePeer`）在客户端会动态调整 `RtcWorker` 拥有的 AllowedIPs 路由与套接字映射关系。
- userspace WireGuard registry 按 peer 维护共享的 `boringtun` 状态，并通过 AllowedIPs 路由选择出站 peer；入站数据优先使用 receiver index 与 endpoint 索引定位 peer，未知握手包才退回逐 peer 尝试。
- 为避免未知来源 WireGuard 握手包在多 peer 场景下触发无界 O(N) 扫描，未知 endpoint 的握手/控制类入站包会经过轻量 per-IP token bucket 限速；已建立 receiver index 或已知 endpoint 的数据包不走该限速路径。成功解开的 unknown handshake 不消耗 token，无法解开的 unknown 包才消耗 token；可通过 `NEW_PROXY_UNKNOWN_HANDSHAKE_BURST` 和 `NEW_PROXY_UNKNOWN_HANDSHAKE_REFILL_PER_SEC` 调整阈值，drop 计数会暴露在 UDS telemetry 中。
- 当前 client/server 启动路径不创建 transparent listener，也不下发 TPROXY iptables 规则。
