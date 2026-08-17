# new_proxy v1 架构

本文档只描述当前已实现的 AF_XDP QUIC appliance。系统只支持一组固定
`client <-> server`，不提供旧多 peer 运行时兼容层或未来配置占位。

## 1. 范围

### 已实现

- AF_XDP/XSK 是唯一数据面。
- QUIC Datagram 是唯一隧道协议。
- client/server 各自执行本地 stateful SNAT 和 reverse NAT。
- 单 client、单 server、固定 endpoint/listen。
- client 支持一个或多个 intercept interface；server 只允许一个。
- tunnel interface 与 intercept interface 可以相同。
- IPv4/IPv6 TCP、UDP、ICMP/ICMPv6 Echo Request/Reply。
- TLS 服务端证书 pin，以及绑定双方随机 nonce 和 TLS exporter 的共享密钥 HMAC
  双向认证。
- QUIC keepalive、标准 MTU inner packet 分片/重组。
- QUIC candidate 替换保持当前 `QuicFlowId`；SIGHUP 或真实 transport close 会分配
  新 `QuicFlowId`，并通过 `rebind_quic_flow` 将普通业务 Session 迁移到新 flow。
  transport 切换本身不释放其 NAT binding；TCP 是否无感继续取决于端到端重传和
  应用超时，UDP 则取决于应用自身的丢包容忍或重试。
- TCP MSS Clamping：固定 1500-byte underlay 下将 QUIC UDP payload 限制为
  1452 bytes，并按 IPv6 outer、20-byte DCID 的保守预算将 TCP MSS 限制为
  1333 bytes，避免常见 TCP 数据包触发 inner QUIC 分片。
- TCP FIN/RST 状态感知与 NAT 端口加速释放：双向 FIN-ACK 握手完成后 5 秒回收，
  收到 RST 报文 2 秒回收。
- 策略规则运行时热重载（Hot-Reloading）：通过 SIGUSR1 动态重新加载 IP 分流前缀
  与域名分流规则，内核 BPF LPM Trie 与用户态 Worker 规则原子刷新，无需重启。
- client direct-prefix 与 UDP/53 DNS 策略详见 `doc/IP_DNS_POLICY.md`。

### 非目标

- 多 peer、多租户、运行时动态拓扑。
- WireGuard、hybrid 或 TUN 数据面。
- 自动配置主机路由、邻居或防火墙。
- 同一个 `(ifindex, queue_id)` 上多个 XSK owner。
- 多线程共享 Fill/Completion rings。
- 依赖 NIC 可编程 RSS 才能保证正确性。

## 2. 组件

### 配置模型

当前 V1 使用严格 section 配置，并要求显式提供 `--config PATH`。核心 section 为：

- `[Appliance]`：role、Flow worker 数、channel 容量、DCID 长度、stats 路径和
  32-byte `SharedKey`。
- `[Tunnel]`：接口、client endpoint 或 server listen、静态 next-hop MAC，以及
  client certificate pin 或 server DER certificate/private key。
- `[Intercept*]`：一个或多个本地接口及静态 next-hop MAC；server 只允许一个。
- `[NAT]`：本节点 IPv4/IPv6 SNAT address、端口范围，以及强制为 `no` 的
  `AutoReservePorts`。
- client `[AllowedIPs]`：inline、`file:` tunnel-prefix 或 `!file:` direct-prefix。
- client 可选 `[DNS]`：UDP/53 VIP、LocalResolver、RemoteResolver 和 domain 文件。
- `[XDP]`：显式 `native` 或 `skb`。

运行时不自动修改或推导接口、路由、邻居、sysctl、NAT address 和 next-hop MAC。
未知字段、旧 section、占位 SharedKey、错误 role addressing、未预留 NAT port range
和不可加载策略文件都在 attach XDP 前失败。

### Userspace NAT Port Reservation

userspace SNAT 使用的 `(NAT address, port)` 是 appliance 的独占资源。普通 Session
NAT 和 DNS transaction 共用同一个 Flow worker 本地 allocator；因此全局 NAT port
range 必须避免被 host kernel ephemeral port allocator 或其他服务使用。

当前配置使用 `[NAT] PortStart/PortEnd` 定义 userspace NAT port range，并可设置：

```ini
[NAT]
AddressV4=192.0.2.10
AddressV6=2001:db8:1::10
PortStart=40000
PortEnd=49999
AutoReservePorts=no
```

`AutoReservePorts` 只接受精确值 `no`。启动时校验
`/proc/sys/net/ipv4/ip_local_reserved_ports` 已完整包含 NAT port range，缺失则
fail closed。部署系统必须通过 `sysctl.d`、启动前 provisioning 或等价机制预留端口；
进程本身不修改全局 netns sysctl，也不维护端口 reservation ownership record。

### XDP classifier

`src/xdp_datapath/xdp_filter.c` 为每个参与数据面的接口加载独立 map：

- `xsks_map`：queue 到 XSK。
- `role_flags`：接口是 tunnel、intercept 或双角色。
- `tunnel_port`：外层 QUIC UDP 目的端口。
- `tunnel_v4` / `tunnel_v6`：本接口可作为 tunnel 目的地址的本地 IP。
- `allowed_v4` / `allowed_v6`：intercept 目标前缀。
- `intercept_policy_mode`：正向 tunnel-prefix 或反向 direct-prefix。
- DNS VIP、LocalResolver 候选回包与 DNS NAT port range maps。

目的地址为本接口 tunnel 地址且目的端口匹配的 UDP 优先进入 tunnel 分类；
同端口但目的地址为业务地址的合法 inner UDP 会回落到 intercept pipeline。
发往本机 tunnel 地址的其他端口直接 `XDP_PASS`，不会误进入 intercept pipeline，
因此 tunnel/intercept 同接口时仍保留 SSH、监控等本机管理流量。

XDP attach 后 `role_flags=0`，classifier 保持 disabled。只有所有 XSK、IO worker 和
Flow worker 都成功启动后，runtime 才一次性写入最终 role flags；任一步失败都不会
留下一个已 redirect、但没有 userspace consumer 的半启动数据面。

client 反向 direct-prefix 模式默认只 redirect 公网目的地址。已发布 reverse-NAT
tuple 优先；tunnel endpoint、本机 tunnel/NAT address、保留地址和 DNS VIP 非
UDP/53 流量强制本地处理，防止隧道递归。DNS VIP UDP/53 与 LocalResolver 候选
回包在该规则前分类。

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

当前 hot path 使用每轮最多 64 帧的 RX/TX batch。RX descriptor 在归还 UMEM Fill
ring 前以借用 slice 解析，只在 packet 必须跨线程进入 Flow worker 时复制对应的
IP/QUIC payload；不能让借用指向已归还的 UMEM frame。Flow/IO channel 通过合并的
`eventfd` 唤醒空闲 IO worker，IO worker 同时 poll XSK fd 和 wakeup fd，避免只有
反向发送任务时等待固定轮询超时。

TX 侧复用 64 个预分配 frame buffer，并直接填入 Ethernet/IP/UDP header 和 payload；
IPv4/IPv6 UDP checksum 使用 scatter checksum，避免为了 checksum 再拼一个临时连续
buffer。`XDP_USE_NEED_WAKEUP` 启用后，只有 TX ring 明确设置
`XDP_RING_NEED_WAKEUP` 时才调用 `sendto` kick。

### Flow worker

`src/flow_plane/worker.rs` 和 `src/xdp_datapath/runtime.rs` 实现状态 owner。

每个 Flow worker 独占并修改：

- `SessionTable`
- `NatTable`
- `QuicEngine`
- `QuicFlow`
- 该 worker 产生的 connection/DCID 生命周期
- client DNS transaction、resolver reverse index 和短生命周期 NAT binding

`ActiveDcidIndex` 和 `ReverseNatDirectory` 是 runtime 级共享路由索引，不属于单个
worker 的私有状态。Flow worker 在状态创建、替换和回收时发布或退休索引项，IO
worker 只查询索引以选择 owner。

IO/Flow 与 Flow/IO 之间使用有界 `sync_channel`。channel 满、断开或 owner
缺失时明确丢包并记账，不会把包重投给其他 worker。

`FlowWorkerCount` 决定 Flow worker、`QuicEngine`、QUIC connection 和状态 shard
的数量，因此也是固定 QUIC Datagram lane 数。每条 lane 有独立 congestion control、
pacing、认证状态和 DCID 生命周期；它隔离不同五元组之间的 connection 级拥塞耦合，
但不会为每条 TCP 创建 QUIC connection 或 QUIC Stream。client/server 必须配置相同
的 lane 数；仓库示例和 E2E 默认值为 2。
IO worker 数量则来自实际 owner：每个参与接口的每个 queue 创建一个
`(ifindex, queue_id)` owner，同一接口同时承担 tunnel/intercept 时不会重复创建。
两者没有必须相等的约束。

DNS transaction 使用完整 intercept `IoOwnerKey`、client source、wire transaction ID、
规范化 Question 或完整 payload hash 选择 Flow worker，不使用普通 5-tuple hash。
Flow worker 只为可安全解析唯一 Question 的请求建立 transaction：完整报文合法时按
domain policy 分流；Question 合法但附加 section 损坏时只回退 `LocalResolver`；
Question 本身无法安全解析时立即返回 `SERVFAIL`。resolver 回包必须命中 DNS reverse
directory，并且来源、NAT tuple、wire ID 和 Question 都匹配原查询后才消费
transaction；EDNS advertised UDP payload 会 clamp 到 1232，超过 DNS payload 上限或
分片的 DNS 包 fail closed。

### QUIC engine

`src/quic_engine.rs` 直接驱动 `quinn-proto`：

- client 固定 server certificate SHA-256；server 使用配置的 DER certificate 和
  PKCS#8 private key。
- QUIC transport 建立后，client/server 在一条可靠双向 QUIC stream 上完成认证
  challenge。认证控制帧由 QUIC 重传，丢失单个外层 UDP packet 不会永久卡住认证。
  每个 connection 使用双方独立随机 nonce，HMAC transcript 绑定协议版本、角色和
  当前 TLS exporter，旧连接的认证帧不能在新 TLS session 重放。
- 认证前拒绝 inner packet。
- inner IP packet 通过 QUIC Datagram 发送；超过当前 Datagram 上限时使用有界、
  带 packet id/total length/offset 的片段；同时最多保留 4096 个 reassembly entry、
  总计 1 MiB，5 秒后清理残片。
- transport idle timeout 为 60 秒，5 秒 keepalive 保持健康空闲连接。
- 正确处理 GSO `segment_size`，每个 QUIC UDP segment 独立封装。
- 支持 Quinn 协商的 QUIC Fixed Bit greasing。
- CID generator 产生归属指定 Flow worker 的 DCID。
- 新 server connection 先进入 candidate 槽位。candidate 完成 TLS 和 HMAC 前
  不替换 active connection，也不把 DCID 发布为 active；其 DCID 只进入 staged
  路由索引以保证握手短头包仍回到同一 Flow worker。candidate 已存在时拒绝新的
  incoming connection，不允许新连接刷新当前 candidate 的 10 秒认证 deadline。
  认证完成后先发出 `Replaced(candidate DCID batch)`。runtime 全量校验并一次提交
  staged-to-active 后，engine 才关闭旧 transport、退休旧 DCID 并发出
  `Authenticated`；任一冲突都拒绝 candidate，不清理旧 transport 或业务状态。
  成功 `Replaced` 保持当前 `QuicFlowId` 和普通业务 Session/NAT，只清空旧
  `pending_inner` 与 engine fragment reassembly，并退休旧 connection/DCID。真实
  transport 断开才触发 `Closed`：runtime 关闭旧 DCID flow、从 Flow worker 本地状态
  终止未完成 remote DNS transaction、分配新 `QuicFlowId`，再将普通业务 Session
  rebind 到新 flow。
- 每个 transport 最多跟踪 32 个 DCID。当前锁定的 `quinn-proto` API 不公开
  `RETIRE_CONNECTION_ID` 对应的具体 CID；握手完成后若 peer 再退休本地 CID，
  固定拓扑 V1 会关闭整个 transport 并整体清理 owner index，避免保留 stale CID。
  达到跟踪上限同样 fail closed。

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

每个 Flow worker 持有本地可写 NAT 表；runtime 维护一个共享 reverse-NAT
directory。Flow worker 发布/退休目录项，所有 IO worker 只读查询：

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

`ActiveDcidIndex` 保存 active 和 staged 两类路由项：

```text
active DCID -> (flow_worker_id, quic_flow_id)
staged candidate DCID -> (flow_worker_id, quic_flow_id)
```

两类 DCID 都可用于 tunnel ingress 分发，但只有 active 项计入
`active_dcid_count`；DCID 不是 Session 的长期主键。
该索引由所有 Flow worker 共享写入、由所有 IO worker 共享读取；“DCID 归属某个
Flow worker”表示索引值指向该 worker，不表示每个 worker 拥有一份独立索引。

## 4. 分发规则

### Intercept ingress

1. XDP 对 client 目标地址执行 tunnel/direct prefix policy，并在前面处理 DNS、
   reverse NAT 与强制本地地址；server 只拦截本机 SNAT host address 的回包。
2. IO worker 解析内层 flow。
3. reverse-NAT 命中时直接使用记录的 Flow worker。
4. 新 flow 使用内层源/目的 IP、源/目的 port 和 protocol 的稳定 FNV-1a hash 选择
   Flow worker/QUIC Datagram lane；同一五元组在其 Session 生命周期内保持 owner。
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

只有发往本接口 tunnel 地址的 tunnel-port UDP 才优先按 QUIC 分类；发往本机
tunnel 地址的其他端口 `PASS` 给内核，业务目的地址上的同端口 UDP 仍按 inner
flow 处理，避免管理流量和端口冲突流量误分类。

## 7. 安全边界

- TLS 提供 QUIC transport 加密。
- client 只接受配置 pin 对应的 server DER certificate。
- authentication challenge 使用双方随机 nonce、当前 TLS exporter、32-byte
  `SharedKey` 和可靠 QUIC stream；server 成功写入 `complete`、client 验证
  `complete` 后才接受业务 Datagram。
- 未认证 candidate 不能替换 active connection，candidate DCID 不计入 active
  stats；candidate 失败、认证超时或 flow close 时 staged DCID 必须清理。已有
  candidate 时新的 incoming connection 直接拒绝。
- classifier 启用后，malformed Ethernet/IP/UDP/QUIC、非法 DCID、未知非 Initial
  DCID 均 fail closed；启动阶段 `role_flags=0` 时统一 `XDP_PASS`。
- 配置 parser 拒绝未知字段和旧格式，避免静默启用错误路径。
- server `Tunnel.Listen` 必须是具体单播地址，且启动时属于配置的 tunnel interface；
  wildcard `0.0.0.0`/`[::]` 直接拒绝。
- V1 只接受 code=0 的 ICMPv4 Echo 0/8 和 ICMPv6 Echo 128/129；其他 ICMP 类型
  不建立 stateful NAT Session。
- DNS VIP 必须只属于一个 client intercept，且不能与 tunnel local IP、NAT address
  或 resolver address 重复；resolver 必须使用 UDP/53。LocalResolver XDP 候选回包
  还必须匹配 resolver source、client NAT address 和配置的 NAT port range。
- 打包配置中的全零 `SharedKey` 必须 fail closed，由部署系统替换。

SharedKey、DER certificate 和 private key 由部署系统分发；JSON stats 可能包含业务
tuple，路径权限应由部署系统限制。

## 8. 生命周期与恢复

### 启动

1. 严格解析 v1 配置。
2. 按配置接口发现真实 ifindex/queue/address，并验证 server listen address 属于
   tunnel interface。
3. 为每个 ifindex 加载并 attach 独立 XDP program/maps，但保持 classifier disabled。
4. 为每个 owner 创建独立 XSK/UMEM/rings。
5. 启动 IO workers 和 Flow workers。
6. 启用全部 XDP classifier。
7. client 发起 QUIC，完成 TLS certificate pin 和 TLS-exporter-bound HMAC stream。

普通业务 Session/NAT 只在 QUIC 完成认证后创建；认证前业务包直接丢弃，不占用
Session、reverse NAT 或 SNAT port。DNS 本地 resolver 路径不依赖 QUIC，remote DNS
在未认证时返回 `SERVFAIL`。

任一接口、map、XSK 或配置步骤失败都会中止启动。XDP attach 后若 program ID
校验或 owner record 写入失败，manager 只在 attachment 仍匹配本次 program ID 时
回滚 detach，不留下无 owner 的 attachment，也不拆除外部替换程序。

### SIGHUP 重连

1. 关闭旧 QUIC connection。
2. 推进 reconnect epoch 并丢弃旧 epoch pending packet。
3. retire 旧 connection 的全部 DCID，并从共享索引关闭旧 `quic_flow_id`。
4. 从 Flow worker 本地状态终止未完成的 remote DNS transaction；本地 DNS
   transaction 不依赖 QUIC。
5. 分配新的 `quic_flow_id`，将普通业务 Session 的 flow identity rebind 到新值；
   原 Session、NAT binding 和 reverse-NAT directory 项继续有效。
6. client 创建新 connection，server 等待新 incoming connection，双方重新认证。
7. 认证完成前的新业务不创建 Session；已有 Session 的回包仍可命中 reverse NAT，
   但只有新 transport 认证后才能再次穿越隧道。

`rebind_quic_flow` 将业务 Session 生命周期与瞬态 transport identity 解耦。它不缓存
或重放重连窗口内任意数量的业务包；`pending_inner` 上限为 1024，且 reconnect epoch
变化时清空，因此“保留 Session”不等于承诺所有应用在任意重连时长下都无感。

### 退出

`SIGTERM`/`SIGINT` 停止 workers、关闭 connection、写最后一份 stats、detach
XDP 并删除 ifindex-scoped pins。接口地址、路由和邻居不是进程生命周期资源。
异常退出后，进程级 `(netns, ifindex)` lock 会释放；下次启动仅在 pinned program
ID 与当前 attachment 一致时 detach stale program，然后重建 pins。每个 attachment
另有 `/run/new_proxy/xdp-<netns_inode>-<ifindex>.owner`，记录精确 program ID 和
native/SKB attach mode；正常 Drop 也只 detach 本实例仍实际拥有的 attachment，
不会误删后来者或外部 XDP program。systemd unit 使用
`RuntimeDirectoryPreserve=yes`，显式 stop 或失败重启后都保留 owner record，直到
进程正常 detach 时自行删除。

## 9. Stats 契约

`StatsPath` 以临时文件加 rename 的方式原子更新，包含：

- `instance_id`、`pid`、进程启动时间、快照生成时间和单实例递增 `sequence`；
  读取方必须同时检查 instance identity、PID 存活、时间戳新鲜度和 sequence 前进，
  不能把遗留 JSON 当作当前进程健康证据。
- `io_owners`：owner key、逻辑 role、RX/TX/drop 分类。
- `flow_workers`：worker、`quic_flow_id`、tunnel queue、认证状态。
- `sessions`：原始 tuple、本地 translated tuple、intercept owner。
- `active_dcid_count`、全局 `reverse_nat_count`、内核 XDP 早期解析拒绝累计值
  `xdp_parser_drops`，以及 `stats_read_failures`/`stats_write_failures`。
- bounded channel、pending inner、QUIC send、普通 Session NAT exhaustion、
  NAT/DCID publish 和 reconnect failure counters。
- DNS local/remote query/response、SERVFAIL、timeout、capacity/NAT exhaustion、
  malformed/spoofed/late drop、EDNS clamp、active transaction gauge，以及 IO 级
  invalid QUIC / malformed / unknown DNS transaction / fragmented DNS /
  unknown NAT tuple drop counters。

stats 是只读观测面，不是控制面。启动前 StatsPath preflight 失败会拒绝启动；
运行期 BPF counter 读取或 JSON 写入失败只累计计数并保留数据面，不能关闭 classifier。

## 10. 性能实现与验证

### 保留的优化

以下优化已经进入当前实现，且都保持既有 ownership、fail-closed 和有界队列语义：

- Linux daemon 使用 `tikv-jemallocator` 作为全局 allocator；release profile 使用
  `opt-level=3`、LTO、单 codegen unit 和 `panic=abort`，同时保留 debug symbol 供
  `perf` 解析。
- XSK RX 在 descriptor 生命周期内借用 UMEM frame 解析，跨线程消息才复制为 owned
  `Bytes`；回归测试验证原 frame 释放后消息仍自持有。
- IO worker 以 64 帧为上限批量收发，TX frame buffer 池跨循环复用；构帧直接写最终
  buffer，checksum 可跨多个 slice 计算。
- XSK 使用 `XDP_USE_NEED_WAKEUP`，仅在 ring 请求时执行 TX kick；Flow/IO channel
  使用 coalesced `eventfd` 唤醒，空闲 IO worker poll XSK 与 channel wakeup。
- TCP MSS clamp、固定 1452-byte QUIC MTU 以及 GSO segment 拆分减少常见 1500-byte
  业务流量的 inner fragmentation 和错误的大 segment 封装。

2026-08-15 在同一台机器、相邻 12 秒 run、`veth + skb` 环境下，Linux 内置 jemalloc
相对 glibc allocator 的两组交错样本几何均值为 `1861.1` 对 `1475.2 Mbit/s`，
提升 `26.16%`，且 drops 为零。RX 借用优化的吞吐受机器波动影响，保留依据是 profile
中的 CPU/Gbit 约下降 `15.27%`，而不是挑选单次最高吞吐。TX buffer 复用与 scatter
checksum 后，构帧 children 从约 `8.75%` 降到 `2.63%`，checksum 从约 `1.24%`
降到 `0.32%`。

### 基准口径

可复现入口是 `script/perf/perf_v1.sh`。吞吐负载默认 payload 1200 bytes、
concurrency 8、每连接 `window=32`。TCP 每轮连续发送 32 个 payload 单元后读取
对应长度，UDP 每轮连续发送 32 个 datagram 后读取 32 个 response；这避免低 RTT 下
仍以单 payload stop-and-wait，把每次往返强制串行化。
性能基线、E2E 和仓库示例配置默认使用 `FlowWorkerCount=2`。这会建立两条独立 QUIC
Datagram lane，使五元组分片到两套 connection congestion control/pacing，减少单条
connection 的跨业务流耦合。`V1_FLOW_WORKER_COUNT=1` 仍用于相邻 A/B 或受限环境；
实际部署可按 CPU、queue、NUMA 和负载实测调整，但两端必须使用相同值。

当前 release Build ID 为 `4169dc84fa8a510df3a744836190985d64596c93`。它在同一
`veth + skb` 测试环境的 5 次 12 秒结果为：

```text
2326.802, 1936.908, 1453.545, 2250.854, 1907.612 Mbit/s
median = 1936.908 Mbit/s
mean   = 1975.144 Mbit/s
drops  = 0
```

2026-08-17 使用同一 Build ID、相同 payload/concurrency/window 和
`1,2,2,1,1,2` 交错顺序做固定 lane A/B，六次 12 秒结果为：

```text
FlowWorkerCount=1: 1278.567, 950.210, 961.881 Mbit/s
median = 961.881 Mbit/s
geomean = 1053.307 Mbit/s

FlowWorkerCount=2: 1833.865, 2215.874, 1033.432 Mbit/s
median = 1833.865 Mbit/s
geomean = 1613.361 Mbit/s
drops = 0
```

按几何均值，2 lane 相对 1 lane 提升 `53.17%`；按相邻配对分别提升 `43.43%`、
`133.20%` 和 `7.44%`，说明主机调度噪声很大，不能把单一百分比当作稳定硬件收益。
2 lane 几何均值达到 200 MiB/s（`1677.722 Mbit/s`）门槛的 `96.16%`，中位数越过
门槛。该结果支持将默认值从 1 改为 2，但不证明继续增加 lane 会线性扩展。

同轮 echo p50 通常约 `0.25-0.95 ms`。该环境包含 veth、generic/SKB XDP、netns、
host 调度和 Python echo 开销，且机器吞吐波动明显；这些数字只用于当前代码和相邻
A/B 的回归比较，不是物理 NIC、native XDP 或 AF_XDP zero-copy 的单核上限。当前
XSK bind 没有请求 `XDP_ZEROCOPY`，不能把 `[XDP] Mode=native` 等同于已验证
zero-copy。

最初历史 run 为 `882.638 Mbit/s`，相对当前中位数表面提升约 `119.4%`；由于两者
不是严格相邻 A/B 且机器波动大，该值只描述本轮优化收口的量级，不能作为单项优化
收益。单项决策优先使用上面的相邻 A/B 或 CPU/Gbit profile。

### 已验证拒绝的方案

以下实验已从代码删除。除非测试环境或底层机制发生变化，不应仅凭“少一次 syscall/
copy/lock”再次引入：

- Flow message batching：`sendto` 次数下降约 `54.5%`，但两组相邻样本吞吐几何
  均值下降约 `7.94%`；批处理延后 `drain_engine`，增加 QUIC 处理延迟。
- 直接在 TX UMEM 原地构帧：吞吐几何均值 `2082.020 -> 1934.778 Mbit/s`，
  `-7.07%`。当前保留临时 TX frame 到 UMEM 的一次复制。
- 为整批 RX 持有 `ActiveDcidIndex`/`ReverseNatDirectory` 读锁：写锁饥饿使吞吐
  `2201.280 -> 1291.105 Mbit/s`，`-41.35%`。
- 按包先分类、再在分支内惰性获取目录短锁：吞吐
  `2226.080 -> 2089.368 Mbit/s`，`-6.14%`，IPv6/UDP p50 同时恶化。

### 当前热点和下一次测量边界

最终 `perf` 的主要 children/self 热点包括：

- `Xsk::transmit_batch` children `23.04%`，其中 `__libc_sendto` children
  `20.79%`。
- `Xsk::receive_with` children `10.41%`，`quinn-proto` `poll_transmit`
  children `7.95%`。
- `send_io` self `8.45%`，`__memmove_avx512_unaligned_erms` self `6.59%`，
  `eventfd_write` self `1.49%`。

在本次 veth/SKB profile 中，`sendto` 下方主要是内核
`xsk_xmit -> do_xdp_generic -> veth/backlog/softirq`，不能解释成单纯的用户态
syscall 开销。下一轮优化必须先在目标物理 NIC 上确认 native XDP、copy/zero-copy
模式、queue/IRQ/CPU affinity 和 NUMA，再重新采集按线程的 cycles、cache miss、
软中断与吞吐；不能用当前 generic XDP 栈替代真实部署 profile。

## 11. 当前限制

- QUIC Datagram 分片本身不提供可靠重传；端到端 TCP 自己负责可靠性，UDP/ICMP 可在
  拥塞或 ring 背压时丢失。
- Session 按协议 idle deadline 回收：TCP 300 秒、UDP 60 秒、ICMP/ICMPv6 30 秒；
  QUIC transport close/reconnect 会 rebind 普通 Session，而不是刷新 idle deadline。
- L2 next-hop MAC 是配置项，没有动态 ARP/NDP resolver。
- 每个 Flow worker 当前维护一个 active QUIC connection；server candidate 替换期间
  可额外维护一个尚未提交的 candidate。
- 同一 lane 内的业务仍共享一套 QUIC congestion control/pacing；固定多 lane 只把
  耦合范围缩小到该 shard，并不消除所有拥塞相关队头效应。lane 数也不会突破 IO
  queue、XSK copy、内核发送路径或 NIC 的瓶颈。
- transport `Closed` 会释放 Flow worker 内部的 remote DNS transaction/NAT 状态，
  但当前事件路径没有发送返回的 `SERVFAIL`，也没有显式退休对应的共享
  reverse-NAT directory 项；candidate `Replaced` 不终止 remote DNS transaction。
  这是当前实现边界，不能从普通 Session rebind 语义推导 DNS transaction 也被迁移。
- `quinn-proto` 当前不暴露单个 peer-retired CID；固定拓扑 V1 对认证后 CID retire
  和 32 个 DCID 硬上限都采用整体关闭清理。
- `native` 是 XDP program attach mode，不代表 XSK 已请求或获得 AF_XDP zero-copy。
- 性能取决于 NIC/driver、XDP/XSK mode、queue/IRQ/CPU affinity 和 NUMA 拓扑。

这些限制是当前 v1 边界，不应通过恢复旧运行时来绕过。
