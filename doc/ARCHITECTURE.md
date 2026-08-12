# new_proxy v1 架构

本文档描述当前实现的 AF_XDP QUIC appliance。系统只支持一组固定
`client <-> server`，不提供旧运行时兼容层。

## 1. 范围

### 已实现

- AF_XDP/XSK 是唯一数据面。
- QUIC Datagram 是唯一隧道协议。
- client/server 各自执行本地 stateful SNAT 和 reverse NAT。
- 单 client、单 server、固定 endpoint/listen。
- client 支持一个或多个 intercept interface；server 只允许一个。
- tunnel interface 与 intercept interface 可以相同。
- IPv4/IPv6 TCP、UDP、ICMP/ICMPv6。
- TLS 服务端证书 pin 与共享密钥 HMAC 双向认证。
- QUIC keepalive、标准 MTU inner packet 分片/重组。
- QUIC 重连时按 epoch 回收旧 Session、NAT、reverse NAT、DCID 和 pending packet。

### 非目标

- 多 peer、多租户、运行时动态拓扑。
- WireGuard、hybrid 或 TUN 数据面。
- 自动配置主机路由、邻居或防火墙。
- 同一个 `(ifindex, queue_id)` 上多个 XSK owner。
- 多线程共享 Fill/Completion rings。
- 依赖 NIC 可编程 RSS 才能保证正确性。

## 2. 组件

### XDP classifier

`src/xdp_datapath/xdp_filter.c` 为每个参与数据面的接口加载独立 map：

- `xsks_map`：queue 到 XSK。
- `role_flags`：接口是 tunnel、intercept 或双角色。
- `tunnel_port`：外层 QUIC UDP 目的端口。
- `allowed_v4` / `allowed_v6`：intercept 目标前缀。

目的地址为本接口 tunnel 地址且目的端口匹配的 UDP 优先进入 tunnel 分类；
同端口但目的地址为业务地址的合法 inner UDP 会回落到 intercept pipeline。

`build.rs` 在 Cargo build 时编译 XDP ELF 并将其嵌入 `new_proxy` binary。
运行时从只允许新建的私有临时文件加载 ELF，加载后立即删除，因此部署不依赖
源码目录或外置 object。

### IO worker

`src/xdp_datapath/io_worker.rs` 和 `xsk.rs` 实现 queue owner。

硬约束：

```text
1 (ifindex, queue_id) -> 1 IO worker -> 1 XSK/UMEM/ring set
```

IO worker 负责：

- 独占 RX/TX/Fill/Completion rings。
- 解析 Ethernet、IP、UDP 和最小 QUIC header。
- intercept ingress 的 AllowedIPs 检查和 flow owner 选择。
- tunnel ingress 的 DCID owner 选择。
- reverse-NAT directory 查询。
- L2 封装和最终发包。
- 记录 queue 级计数和 drop 原因。

IO worker 不创建、不修改 Session、NAT 或 QUIC connection。

### Flow worker

`src/flow_plane/worker.rs` 和 `src/xdp_datapath/runtime.rs` 实现状态 owner。

每个 Flow worker 独占：

- `SessionTable`
- `NatTable`
- `QuicEngine`
- `QuicFlow`
- 属于该 worker 的 active DCID

IO/Flow 与 Flow/IO 之间使用有界 `sync_channel`。channel 满、断开或 owner
缺失时明确丢包并记账，不会把包重投给其他 worker。

### QUIC engine

`src/quic_engine.rs` 直接驱动 `quinn-proto`：

- client 固定 server certificate SHA-256。
- QUIC transport 建立后，client/server 使用共享密钥完成 HMAC challenge。
- 认证前拒绝 inner packet。
- inner IP packet 通过 QUIC Datagram 发送；超过当前 Datagram 上限时使用有界、
  带 packet id/total length/offset 的片段，最多重组 1 MiB、5 秒后清理残片。
- transport idle timeout 为 60 秒，5 秒 keepalive 保持健康空闲连接。
- 正确处理 GSO `segment_size`，每个 QUIC UDP segment 独立封装。
- 支持 Quinn 协商的 QUIC Fixed Bit greasing。
- CID generator 产生归属指定 Flow worker 的 DCID。

## 3. Ownership 和索引

### IO owner

```text
IoOwnerKey = (ifindex, queue_id)
```

不能只用 `queue_id` 查找 owner，因为不同接口可拥有相同 queue 编号。

### Session owner

```text
SessionKey = (original FlowKey, intercept_ifindex)
```

加入 `intercept_ifindex` 是为了让 client 多入口中相同 tuple 仍拥有独立回程。
Session 保存：

- 原始 flow。
- 本节点 SNAT 后 flow。
- `flow_worker_id`。
- 原始 `intercept_ifindex/intercept_queue_id`。
- `quic_flow_id`。

Session 的创建、更新、回收只发生在所属 Flow worker。

### Reverse NAT

每个 Flow worker 持有本地可写 NAT 表；所有 IO worker 读取一个全局只读
reverse-NAT directory：

```text
translated return tuple -> (flow_worker_id, session_id)
```

发布 Session 时同时发布 reverse key；回收 Session 时同时删除。ICMP/ICMPv6
key 以 identifier 为端口语义并忽略 request/reply 的 type 变化。恢复回程时：

- 地址反转。
- identifier 恢复到原始值。
- type/code 保留实际 reply 的值。

### QUIC flow 和 DCID

`QuicFlow` 包含：

- `quic_flow_id`
- `flow_worker_id`
- 稳定的 `tunnel_queue_id`

`ActiveDcidIndex` 保存：

```text
active DCID -> (flow_worker_id, quic_flow_id)
```

active DCID 只用于 tunnel ingress 分发，不是 Session 的长期主键。

## 4. 分发规则

### Intercept ingress

1. XDP 对 client 目标地址执行 AllowedIPs LPM；server 只拦截本机 SNAT host
   address 的回包。
2. IO worker 解析内层 flow。
3. reverse-NAT 命中时直接使用记录的 Flow worker。
4. 新 flow 使用稳定 hash 选择 Flow worker。
5. Flow worker 创建或复用 Session，执行本地 SNAT。

### Tunnel ingress

1. IO worker 从 QUIC long/short header 提取 DCID。
2. active DCID 命中时直接投递到 owner。
3. 未命中时，只有 long-header Initial 可以按
   `hash(dcid) % flow_worker_count` 进入 deterministic bootstrap。
4. 其他未知 DCID 和非法 header 丢弃并记账。

Quinn 可在协商后对 long/short header 的 Fixed Bit 做 greasing；分类器不会把
合法 greased packet 当作非法 QUIC。

### Tunnel egress

每个 QUIC flow 创建时绑定稳定 `tunnel_queue_id`。连接生命周期内所有外层包
都发送到对应 `(tunnel_ifindex, tunnel_queue_id)`，不按包重新选 queue。

### Local egress

- client 回包使用原 Session 的 intercept owner。
- server 首包使用唯一 intercept 的 queue 0。
- server 收到真实本地回包后可把默认 queue 修正为实际 queue；不允许跨接口漂移。

## 5. 双层 SNAT 路径

### 正向

```text
source
  -> client intercept XSK
  -> client Session + SNAT
  -> QUIC encrypt
  -> server tunnel XSK
  -> QUIC decrypt
  -> server Session + SNAT
  -> target
```

目标看到的是 server NAT address，而不是 source 或 client NAT address。

### 回程

```text
target reply
  -> server intercept XSK
  -> server reverse NAT
  -> original QUIC flow
  -> client tunnel XSK
  -> client reverse NAT
  -> original client intercept owner
  -> source
```

TCP/UDP/ICMP 的 IP 地址和 transport checksum 都在每次改写后重算。IPv4 UDP
原始 checksum 为零时保留禁用语义；IPv6 UDP 始终生成有效 checksum。

## 6. 同接口模式

同一个 interface 同时承担 tunnel/intercept 时只创建一个 IO owner 和一个
XSK/UMEM：

```text
(ifindex, queue_id)
  |- tunnel classifier: UDP destination port + QUIC DCID
  `- intercept classifier: AllowedIPs / reverse NAT
```

只有发往本接口 tunnel 地址的 tunnel-port UDP 才优先按 QUIC 分类；业务目的
地址上的同端口 UDP 仍按 inner flow 处理，避免端口冲突误丢。

## 7. 安全边界

- TLS 提供 QUIC transport 加密。
- client 只接受配置 pin 对应的 server DER certificate。
- HMAC challenge 使用 32 字节共享密钥；两端都认证后才接受业务 Datagram。
- malformed Ethernet/IP/UDP/QUIC、非法 DCID、未知非 Initial DCID 均 fail closed。
- 配置 parser 拒绝未知字段和旧格式，避免静默启用错误路径。
- 打包配置的全零 SharedKey 是 fail-closed 占位符，必须由部署系统替换。

共享密钥和 DER 私钥由部署系统分发；JSON stats 可能包含业务 tuple，路径权限应由
部署系统限制。

## 8. 生命周期与恢复

### 启动

1. 严格解析 v1 配置。
2. 按真实接口/queue 发现 owner。
3. 为每个 ifindex 加载并 attach 独立 XDP program/maps。
4. 为每个 owner 创建独立 XSK/UMEM/rings。
5. 启动 IO workers 和 Flow workers。
6. client 发起 QUIC，完成 TLS pin 和 HMAC。

任一接口、map、XSK 或配置步骤失败都会中止启动。

### SIGHUP 重连

1. 关闭旧 QUIC connection。
2. 推进 reconnect epoch 并丢弃旧 epoch pending packet。
3. 删除该 `quic_flow_id` 的 Session、NAT 和 reverse NAT。
4. retire 旧 connection 的全部 DCID。
5. 分配新的 `quic_flow_id`。
6. client 创建新 connection 并重新认证。
7. 后续业务包创建新的 Session。

旧 Session 不迁移，避免将陈旧 NAT 与新连接混合。

### 退出

`SIGTERM`/`SIGINT` 停止 workers、关闭 connection、写最后一份 stats、detach
XDP 并删除 ifindex-scoped pins。接口地址、路由和邻居不是进程生命周期资源。
异常退出后，进程级 `(netns, ifindex)` lock 会释放；下次启动仅在 pinned program
ID 与当前 attachment 一致时 detach stale program，然后重建 pins。

## 9. Stats 契约

`StatsPath` 以临时文件加 rename 的方式原子更新，包含：

- `io_owners`：owner key、逻辑 role、RX/TX/drop 分类。
- `flow_workers`：worker、`quic_flow_id`、tunnel queue、认证状态。
- `sessions`：原始 tuple、本地 translated tuple、intercept owner。
- `active_dcid_count`、全局 `reverse_nat_count`。
- bounded channel、pending inner、QUIC send、NAT/DCID publish 和 reconnect
  failure counters。

stats 是只读观测面，不是控制面。

## 10. 当前限制

- QUIC Datagram 分片本身不提供可靠重传；端到端 TCP 自己负责可靠性，UDP/ICMP 可在
  拥塞或 ring 背压时丢失。
- 当前没有 Session idle timeout；Session 在 QUIC flow 关闭/重连时整体回收。
- L2 next-hop MAC 是配置项，没有动态 ARP/NDP resolver。
- 每个 Flow worker 当前维护一个 QUIC connection。
- 性能取决于 NIC、XDP attach mode、queue 数、CPU affinity 和内存拓扑。

这些限制是当前 v1 边界，不应通过恢复旧运行时来绕过。
