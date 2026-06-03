# new_proxy 当前架构说明

本文档描述当前代码实现，不描述规划能力。若架构设计发生变化，先更新本文档，再补对应测试。

## 1. 总体模型

`new_proxy` 是一个混合 L3/L4 网关：

- L3 路径依赖系统 WireGuard 接口和内核路由，遥测通过 WireGuard generic netlink 按需读取。
- TCP L4 路径由客户端 TPROXY 拦截，按目标 IP 的 `AllowedIPs` 最长前缀匹配选择 peer，再通过该 peer 的 QUIC 连接池转发到服务端。
- 控制面是独立 UDP 报文协议，使用 WireGuard 密钥材料派生 X25519 shared secret，并用 HMAC-SHA256 认证 JSON 请求/响应。
- QUIC 数据面使用服务端自签证书，服务端在已认证控制面响应中下发证书 SHA-256 指纹，客户端只接受该指纹对应证书。
- 运行期通过 Unix Domain Socket 提供 `Stats`、`Dump`、`AddPeer`、`RemovePeer` API。

当前实现没有内置 TUN 设备读写、Noise_IK 协议栈、QUIC 0-RTT、动态端口热迁移或 QUIC connection migration 编排。

## 2. 运行模式

启动模式由配置决定：

- Server mode：`ListenControlPort` 存在，或 `[QUICPool].ListenPorts` 非空。
- Client mode：非 server mode，且至少有一个 `[Peer]`。

Server mode 要求：

- `ListenControlPort` 必须存在。
- `[QUICPool].ListenPorts` 至少一个端口。
- peer 可以只配置 `PublicKey` 和 `AllowedIPs`，用于接受控制面协商与 L3 遥测展示。

Client mode 支持两类 peer：

- QUIC proxy peer：同时配置 `Endpoint` 和 `ProxyPort`，并且接口配置 `TProxyPort`。
- WireGuard-only peer：不配置 `Endpoint` 和 `ProxyPort`，不会进入 L4 路由器，也不会创建 QUIC pool。

`Endpoint` 和 `ProxyPort` 必须成对出现。只配置其中一个会被视为非法 client 配置。

## 3. 控制面

控制面位于服务端 `ListenControlPort`，客户端从 peer 的 `Endpoint.ip()` 与 `ProxyPort` 拼出控制面地址。

协商流程：

1. 客户端用本地私钥和服务端公钥计算 X25519 shared secret。
2. 客户端发送 `ControlRequest`，包含客户端派生公钥和随机 `client_nonce`，外层 `SignedPacket` 用 HMAC-SHA256 保护。
3. 服务端按 peer 公钥查找预计算 shared secret，校验 HMAC 和 nonce replay cache。
4. 服务端生成 `server_nonce`，派生 `session_psk`，缓存到 `session_cache[client_public_key]`。
5. 服务端返回 QUIC 端口池、公网 IPv4/IPv6 可选地址、`client_nonce`、`server_nonce`、`quic_cert_sha256`，响应同样用 HMAC-SHA256 保护。
6. 客户端校验响应 HMAC 和 `client_nonce`，派生同一 `session_psk`。

控制面重试每次生成新的 `client_nonce`，避免响应丢包后旧 nonce 被服务端 replay cache 拒绝。

## 4. QUIC 数据面

服务端启动时生成一组自签证书和私钥：

- QUIC listener 绑定 `[QUICPool].ListenPorts`。
- 证书 SHA-256 指纹由控制面下发给客户端。
- 客户端使用 pinned certificate verifier，不再接受任意自签证书。

客户端启动每个 proxy peer 时：

1. 先完成控制面协商。
2. 从控制面响应中选择 QUIC endpoint IP：
   - IPv6 peer endpoint 优先使用 `PublicIPv6`。
   - IPv4 peer endpoint 优先使用 `PublicIPv4`。
   - 未配置 public IP 时回退到 peer `Endpoint.ip()`。
3. 对端口池中每个端口建立一条物理 QUIC 连接。
4. 每条连接打开认证流，发送 `QuicAuthPacket { client_public_key, nonce, mac }`。
5. 服务端用 `session_cache` 中的 `session_psk` 校验 QUIC auth HMAC。

服务端在每次接受业务 stream 前会检查该连接使用的 `session_psk` 是否仍与 `session_cache` 一致。peer 被删除或重新协商后，旧连接会被关闭。

客户端 `QuicPoolClient` 有后台健康检查：

- 已关闭连接会按原 endpoint 重连。
- 缺失 endpoint 会补建连接。
- pool 状态分为 `Active`、`Fallback`、`Recovering`：
  - `Active`：新 TCP 连接被 TPROXY 劫持到用户态并走 QUIC。
  - `Fallback`：QUIC pool 不可用，新 TCP 连接不再被 TPROXY 劫持，按内核路由走 WireGuard L3。
  - `Recovering`：QUIC 物理连接已经恢复，但仍处于延迟回切窗口，新 TCP 连接继续走 WireGuard L3，避免链路抖动时频繁切换。
- 如果所有重连尝试都因 QUIC 握手、证书 pinning 或 PSK 认证失败，且该 pool 带有控制面刷新配置，客户端会重新发起控制面协商，获取新的 `session_psk`、QUIC 证书指纹和端口池，然后替换本地 QUIC endpoint 与连接池。这个路径用于服务端进程重启后自签证书和 session cache 重建的恢复。
- 刷新成功后，旧 QUIC endpoint 和旧物理连接会被显式关闭，后续新 stream 使用刷新后的连接池。
- pool 被运行期删除或替换时调用 `shutdown()`，关闭连接并停止健康检查循环。

服务端重启恢复边界：

- 已经建立在旧 QUIC 连接上的业务 stream 不迁移，失败后由上层 TCP 应用重新建连。
- 客户端恢复依赖健康检查周期、QUIC 关闭/超时或新 stream 打开失败暴露出的连接失效；恢复目标是后续新 stream 自动连回服务端。
- 控制面地址仍来自 peer 的 `Endpoint.ip()` 和 `ProxyPort`。如果服务端重启后控制面地址也变化，需要通过配置或 UDS 动态 peer 更新完成。

## 5. TPROXY 与路由

`Table = auto` 时程序自动配置：

- 接口地址和 MTU。
- 每个 peer 的 `AllowedIPs` 到接口的系统路由。
- 对 proxy peer 的 `AllowedIPs` 增加 TPROXY mangle PREROUTING 规则。
- fwmark 策略路由和 local route。
- TCPMSS clamp 规则。

`Table = off` 时程序不改系统路由和 iptables，测试脚本或外部系统需要自行配置。

L4 内存路由器只包含 proxy peer 的 `AllowedIPs`。WireGuard-only peer 不会被 TPROXY 命中后丢进 QUIC。

`Table != off` 的 client mode 还有一个全局 TPROXY failover manager：

- 正常 `Active` 时，配置中的所有 proxy peer 都保持 TPROXY 规则，新连接走 QUIC。
- 任意 proxy pool 进入 `Fallback` 或 `Recovering` 时，manager 删除当前配置里所有 proxy peer 的 TPROXY 规则和 TCPMSS clamp 规则，但保留 WireGuard route 和 peer 配置；后续新连接自然按内核路由走 WireGuard/wireguard-go L3。
- client 启动时如果某个 proxy peer 的 QUIC pool 建立失败，daemon 不退出；它会先删除 proxy TPROXY 规则进入 WireGuard L3 fallback，并由 failover manager 后台周期性重建缺失的 QUIC pool。
- 所有 proxy pool 回到 `Active` 后，manager 按当前配置全量重建所有 proxy peer 的 TPROXY 规则。
- UDS `AddPeer`/`RemovePeer` 仍负责动态 peer 的 route 与 TPROXY 生命周期；如果 AddPeer 发生在全局 fallback 期间，只添加 WireGuard route，不立即添加 TPROXY，等待恢复后统一重建。
- `Table = off` 时 daemon 不拥有 route/iptables，failover manager 不修改 TPROXY 规则；外部测试脚本或编排系统需要自行处理故障切换规则。

## 6. 遥测与 API

UDS 路径：

```text
/run/new_proxy/<interface>.sock
```

命令：

- `Stats`：返回 JSON 数组，聚合配置 peer、内核 WireGuard peer、以及 QUIC registry 中的临时 peer。
- `Dump`：返回 tab 分隔文本。
- `AddPeer`：动态添加或替换 peer。
- `RemovePeer`：动态删除 peer。

遥测来源：

- L3：通过 WireGuard generic netlink 查询内核 peer 统计。
- L4：进程内 `TelemetryRegistry` 和 server-side `PeerConnRegistry`。

`source` 字段表示本次查询前的来源关系：

- `both`：配置中存在，且内核 WireGuard 状态中也存在。
- `proxy`：只在用户态配置中存在。
- `kernel`：只在内核 WireGuard 状态中存在。

当前生产代码不会在 `Stats` 查询时自动把 kernel-only peer 持久写入用户态配置，也不会自动把 proxy-only peer 写回内核。动态写回内核只发生在 UDS `AddPeer`，删除内核 peer 只发生在 UDS `RemovePeer`。

## 7. 动态 Peer 管理

Server mode：

- `AddPeer` 会更新配置、L4 router、控制面 shared secret，并通过 WireGuard generic netlink 同步内核。
- `RemovePeer` 会移除配置、控制面缓存、session cache、auth nonce cache、server-side QUIC registry，并通过 WireGuard generic netlink 删除内核 peer。

Client mode：

- `AddPeer` 如果添加 proxy peer，会先完成控制面协商并建立 QUIC pool，再更新配置和 L4 router。
- `AddPeer` 如果添加 WireGuard-only peer，只更新配置和内核，不进入 L4 router。
- `RemovePeer` 会移除本地 QUIC pool 并 shutdown。

## 8. 已知架构边界

- 没有内置 WireGuard 数据面实现，L3 连通性依赖系统内核 WireGuard/路由环境；当前 namespace 测试通过显式 mock dump fixture 模拟内核统计。
- 没有跨 QUIC 物理连接迁移已有 stream；连接池重连只影响后续新 stream。
- 没有动态控制面端口推送更新；端口池来自 server 启动配置。
- 没有生产路径的自动 kernel/proxy 双向互补同步。
