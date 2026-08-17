# IP 与 DNS 策略分流设计

本文定义 `new_proxy` V1 的目的 IP 分流和 UDP DNS 分流。设计保持现有
`1 client <-> 1 server`、AF_XDP-only、pure QUIC 和双端 userspace stateful SNAT
架构，不增加 TUN、内核 UDP socket、sidecar DNS 进程或动态控制面。

## 1. 目标和边界

### 目标

- direct prefix 内的目的 IP 本地直连，其他公网目的 IP 通过 QUIC。
- direct prefix 从文件加载，支持通过 SIGUSR1 信号进行运行时热重载，无需重启 client。
- client appliance 提供一个独立 DNS VIP，只接收发往该 VIP 的 UDP/53 查询。
- remote domain 文件命中的查询使用 server 出口访问可信远端 resolver。
- 其他查询使用 client 本地 resolver。
- DNS 只决定查询使用哪个 resolver，不改变后续业务连接的 IP 分流结果。
- DNS 决策和短生命周期状态只存在于 client；server 将远端 DNS 视为普通 UDP/53。

### 非目标

- TCP/53、DoH、DoT 和 DoQ。
- DNS cache、请求合并、预取、多 resolver、健康检查和自动故障转移。
- 根据 DNS 响应动态生成目的 IP 路由规则。
- 动态 BGP/OSPF 协议分发（目前通过 static/file 配置配合 SIGUSR1 热重载实现）。
- server 侧域名解析、DNS transaction table、DNS 专用 QUIC 消息或 DNS 专用端口段。

## 2. 配置

### Client

```ini
[AllowedIPs]
Prefixes=!file:/etc/new_proxy/direct-cidrs.txt

[DNS]
Listen=192.168.1.53:53
LocalResolver=223.5.5.5:53
RemoteResolver=1.1.1.1:53
RemoteDomainsFile=/etc/new_proxy/remote-domains.txt
TransactionCapacity=4096
TimeoutSeconds=5
```

`[DNS]` 只允许出现在 client 配置。`Listen` 必须使用独立 DNS VIP 和 UDP port 53；
VIP 必须由部署系统配置在且只配置在一个 intercept interface 上，不能与 tunnel
local IP、NAT address、`LocalResolver` 或 `RemoteResolver` address 重复。
`new_proxy` 不负责创建 VIP。

`LocalResolver` 和 `RemoteResolver` 必须与 client 已配置的 NAT address family
相容，且必须使用 UDP/53。V1 各配置一个固定 resolver，不进行自动切换。

`TransactionCapacity` 是每个 client Flow worker 的 transaction 上限。默认配置为
4096；总上限为 `FlowWorkerCount * TransactionCapacity`。

### Server

server 配置不包含 `[DNS]`。远端 DNS 查询到达 server 后复用现有普通 inner UDP、
Session、SNAT 和 reverse NAT 路径。

server 不再要求没有运行时语义的 `[AllowedIPs]`。server XDP 继续根据本机 NAT
address 的 `/32` 或 `/128` host prefix 捕获普通回包。

### IP 文件语义

`AllowedIPs.Prefixes` 支持三种互斥形式：

```ini
# 现有 inline 正向规则：命中地址进入隧道
Prefixes=203.0.113.0/24,2001:db8:2::/64

# 文件正向规则：文件内地址进入隧道
Prefixes=file:/etc/new_proxy/tunnel-cidrs.txt

# 文件反向规则：文件内地址直连，其他公网地址进入隧道
Prefixes=!file:/etc/new_proxy/direct-cidrs.txt
```

同一个值不能混用 inline CIDR、`file:` 和 `!file:`。CIDR 文件一行一个 IPv4 或
IPv6 prefix，允许空行和以 `#` 开头的注释：

```text
# IPv4
1.0.1.0/24
1.0.2.0/23

# IPv6
2400:3200::/32
```

启动时对 prefix 做网络地址规范化并去重。文件缺失、不可读、包含非法 CIDR 或去重
后超过 map capacity 时启动失败，不能静默退化为全直连或全隧道。

### 域名文件语义

`RemoteDomainsFile` 一行一个域名后缀，允许空行和 `#` 注释：

```text
google.com
youtube.com
github.com
```

加载时将域名转为小写并移除末尾的 `.`。规则按 DNS label 边界匹配：

- `google.com` 匹配 `google.com` 和 `www.google.com`。
- `google.com` 不匹配 `notgoogle.com`。
- 不支持 `*` 通配符。
- 空 label、非法域名和重复规范化规则导致启动失败。
- 文件最大 4 MiB，规范化后最多 65536 条规则；超过限制启动失败。

文件只在 client 启动时加载并编译为后缀集合；查询按 QNAME label 后缀查找，不随
规则总数线性扫描。更新后重启生效。

## 3. 目的 IP 分流

反向文件模式的逻辑是：

```text
destination in direct-cidrs.txt
    -> XDP_PASS

destination not in direct-cidrs.txt
    -> AF_XDP
    -> client SNAT
    -> QUIC
    -> server SNAT
    -> target
```

XDP 中 IPv4 和 IPv6 LPM trie 的 `max_entries` 分别为 65536，其中每个地址族为
runtime 的 tunnel、DNS 和 NAT host overlay 预留 16 项，其余 65520 项供 policy 文件使用，并继续使用
`BPF_F_NO_PREALLOC`。实际内存随加载条目增长。runtime 必须在启用 classifier 前
验证并完整写入 map；任一写入失败时启动失败。

每个 intercept classifier 还保存一个 policy mode：

```text
InlineTunnel / FileTunnel:
  default = PASS
  LPM match = REDIRECT

FileDirect:
  default = REDIRECT
  LPM match = PASS
```

LPM value 表示明确 action，而不是简单把“map 是否命中”取反。DNS VIP、tunnel
address、管理/保留地址和 NAT return tuple 在进入地理 policy 前处理，不能被默认
action 覆盖。

下列目的地址不由 direct-prefix 文件决定：

- IPv4/IPv6 loopback、link-local、multicast 和 unspecified。
- RFC1918、IPv4 CGNAT 和 IPv6 ULA。
- tunnel endpoint 和本机 tunnel 地址。
- 除 UDP/53 特例外的 DNS VIP 流量。
- 本节点 NAT address 是 appliance 专用资源：已发布 reverse tuple 才允许进入
  reverse NAT；其他发往 NAT address 的流量 fail closed，不回退内核。

除 NAT address 的 fail-closed 规则外，其余强制地址由内核本地处理，防止管理流量、
邻居流量和隧道自身递归进入 QUIC。已发布的普通 reverse-NAT tuple 和 DNS reverse
tuple 优先于 NAT address 的 fail-closed 规则。

## 4. DNS 分类和数据流

### XDP 分类

client 只特殊截获：

```text
destination = DNS.Listen IP
protocol = UDP
destination port = 53
```

client 不截获发往其他 DNS server 的 UDP/53。TCP/53、DoH、DoT 和 DoQ 继续按目的
IP 规则处理。

DNS VIP 分类优先于保留地址和 direct prefix 规则，因此即使 VIP 属于 RFC1918，
查询仍会进入 AF_XDP userspace。

为接收本地 resolver 回包，client XDP 还必须在地理规则前 redirect 以下候选包：

```text
source = LocalResolver IP
protocol = UDP
source port = 53
destination = matching client NAT address
destination port in the configured NAT port range
```

XDP 只做这个有界粗分类；IO worker 再查询 DNS reverse directory 做精确匹配。未命中
已发布 DNS reverse tuple 的候选包 fail closed 丢弃，不能交给普通 Session，也不能
回退给内核。

### 查询解析

client 只对下列查询执行域名后缀匹配：

- DNS query，标准 opcode。
- 恰好一个 Question。
- QNAME 可安全展开且不存在 compression loop。

无法安全取得唯一 Question 的 UDP/53 请求，例如多 Question、非标准 opcode、非法
QNAME 或异常 compression pointer，立即返回 `SERVFAIL`，不建立 transaction。
Question 可安全解析、但 Additional/EDNS 等后续 section 损坏时，原始 payload 只转发
给 `LocalResolver`，不会因 QNAME 命中 remote-domain 规则而走 remote resolver。

### 本地域名

```text
client host
  -> DNS VIP:53
  -> client DNS classification
  -> client DNS transaction + local SNAT
  -> LocalResolver:53
  -> client DNS reverse transaction
  -> source restored to DNS VIP:53
  -> original client host:port
```

`LocalResolver` 始终从 client intercept interface 本地访问。即使其地址不在
direct prefix 文件中，也不能进入 QUIC。

### Remote domain

```text
client host
  -> DNS VIP:53
  -> client DNS classification
  -> destination rewritten to RemoteResolver:53
  -> client DNS transaction + client SNAT
  -> existing QUIC inner UDP path
  -> server ordinary Session + server SNAT
  -> RemoteResolver:53
```

回程为：

```text
RemoteResolver
  -> server ordinary reverse NAT
  -> existing QUIC inner UDP path
  -> client DNS reverse transaction
  -> source restored to DNS VIP:53
  -> original client host:port
```

`RemoteResolver` 强制走 QUIC，即使其地址出现在 direct prefix 文件中。server 不解析
DNS payload，也不维护 DNS 专用状态。

DNS 响应地址不写入任何动态路由表。客户端随后建立的业务连接仍以目的 IP 判断：
命中 direct prefix 时直连，否则公网地址走 QUIC。

## 5. DNS transaction 和 NAT ownership

每个 client Flow worker 独占一个 `DnsTransactionTable`。DNS 状态不放入普通
`SessionTable`，但 DNS transaction 和普通 Session 使用该 Flow worker 的同一个
NAT port allocator。现有全局 NAT port range 仍按 Flow worker 无重叠分片，不增加
锁共享 allocator，也不增加 DNS 专用 port range。

可解析查询的 transaction key 为：

```text
(
  original intercept IoOwnerKey,
  client source IP,
  client source UDP port,
  DNS transaction ID,
  normalized QNAME,
  QTYPE,
  QCLASS
)
```

Question 可安全取得、但完整报文因后续 section 损坏而回退 `LocalResolver` 时，
transaction key 使用完整 payload hash：

```text
(
  original intercept IoOwnerKey,
  client source IP,
  client source UDP port,
  DNS transaction ID if present,
  stable hash of the complete DNS payload
)
```

每个 transaction 另有 Flow worker 内唯一、单调递增的 `dns_transaction_id`。该 ID
只用于内部 owner 和反向索引，不写入 DNS payload，也不通过 QUIC 发送。

IO worker 使用完整 transaction key 的稳定 hash 选择 Flow worker。payload-hash key
使用同一规则。相同查询的重传因此进入同一个 owner；remote domain 查询使用该 owner
已绑定的 QUIC flow，远端响应也回到同一个 client Flow worker。

transaction 至少保存：

```text
original client IP and UDP port
original intercept IoOwnerKey
DNS VIP
selected LocalResolver or RemoteResolver
allocated client NAT port
created_at
```

每个 Flow worker 同时维护 resolver return tuple 到 DNS transaction 的反向索引。
IO worker 读取全局只读 DNS reverse directory：

```text
(
  resolver IP,
  resolver UDP port,
  client NAT address,
  allocated NAT port
) -> (flow_worker_id, dns_transaction_id)
```

resolver 候选回包必须优先查询 DNS reverse directory，不能因为 resolver 位于
direct prefix 或私网而 `XDP_PASS` 给内核。remote resolver 回包不从物理 client intercept
ingress 到达，而是在 QUIC 解密后先查询同一个 client DNS transaction table，再
回落到普通 client reverse NAT。

相同 key 的未完成重传复用 transaction 和 NAT port。不同 client、不同 QNAME、
QTYPE 或 QCLASS 即使使用相同 DNS transaction ID，也必须拥有独立 transaction。

收到第一个来源、wire transaction ID 和 Question 均匹配原始查询的合法响应，或发生
超时后，原子删除 transaction、反向索引并释放 NAT port。重复、迟到、来源不匹配或
DNS wire 内容不匹配的响应丢弃并计数。

## 6. DNS 报文约束

- 只支持未分片 UDP/53；IPv4 `MF`/fragment offset 或 IPv6 Fragment header
  一律 fail closed，不把首片当作完整 DNS payload。
- 转发前将 EDNS advertised UDP payload 大于 1232 的值 clamp 到 1232，并重算 UDP
  checksum；没有 EDNS 的请求保持不变。
- DNS payload 最大 1232 bytes，使 IPv4/IPv6 UDP packet 都不超过 IPv6 最小 MTU
  1280；超过上限的查询返回 `SERVFAIL`。超过上限的 resolver 响应丢弃且不消费
  transaction，仍等待有效响应或 timeout；timeout 再向客户端返回 `SERVFAIL`。
- resolver 返回 `TC=1` 时原样返回客户端。
- 客户端随后发起的 TCP/53 查询不属于 DNS 域名分流 V1。
- 原始 DNS transaction ID 不改写；冲突隔离由完整 transaction key 和 NAT port
  完成。

remote DNS 不增加 DNS 专用 QUIC frame。改写后的完整 UDP/IP packet 通过现有 inner
packet Datagram 和现有有界分片/重组路径传输。

## 7. 错误处理

- `DnsTransactionTable` 达到 `TransactionCapacity`：client 向请求方返回
  `SERVFAIL`。
- 该 Flow worker 的 NAT port allocator 耗尽：返回 `SERVFAIL`。
- remote domain 查询到达时 QUIC 未认证或断开：返回 `SERVFAIL`；本地查询仍可工作。
- resolver 在 `TimeoutSeconds` 内没有响应：删除 transaction、释放 NAT port 并返回
  `SERVFAIL`；对应 reverse tuple 按 UDP 规则隔离 60 秒，不能立即复用。
- resolver 响应来源地址、source port、destination NAT tuple、原始 DNS wire
  transaction ID 或 Question 不匹配：丢弃。
- 重复和迟到响应：丢弃。
- Question 可解析、但后续 DNS section malformed：转发给 `LocalResolver`。
- Question 本身无法安全解析：立即返回 `SERVFAIL`。
- malformed IP/UDP、分片或超过 payload 上限：丢弃或按可识别原请求返回
  `SERVFAIL`，并记录明确 drop reason。

所有失败均 fail closed，不允许 remote domain 查询静默改走本地 resolver。

## 8. 分类优先级

client XDP/IO 分类顺序：

1. 发往本机 tunnel address 和 tunnel port 的外层 QUIC。
2. 发往 DNS VIP UDP/53 的客户端查询。
3. 来自 `LocalResolver:53`、发往 client NAT address 和 NAT port range 的候选回包
   redirect；IO worker 必须命中 DNS reverse directory，否则丢弃。
4. 发往本机管理、保留地址、DNS VIP 非 UDP/53 流量或 tunnel endpoint 的流量本地
   直连。
5. 正向模式命中 tunnel prefix，或反向模式未命中 direct prefix 的公网流量。
6. 其他流量 `XDP_PASS`。

QUIC 解密后的 client inner packet 不经过上述 XDP 顺序。Flow worker 先查询 DNS
transaction table；命中时恢复为 DNS VIP response，未命中时再进入普通 reverse NAT。

server 分类顺序不增加 DNS 特例：

1. 外层 QUIC。
2. 发往本机 NAT host address 的普通 reverse-NAT 回包。
3. 其他流量 `XDP_PASS`。

## 9. 可观测性

在现有 stats 输出中增加：

```text
dns_query_local
dns_query_remote
dns_response_local
dns_response_remote
dns_servfail
dns_timeout
dns_capacity_exhausted
dns_nat_exhausted
dns_malformed_local_fallback
dns_spoofed_response_drop
dns_late_response_drop
dns_edns_clamped
dns_transactions_active
dns_unknown_transaction_drops
dns_fragmented_drops
```

前 13 个计数按 Flow worker 聚合，`dns_transactions_active` 使用 gauge，其余使用
单调递增 counter。`dns_unknown_transaction_drops` 和 `dns_fragmented_drops` 是
IO owner 级 counter。日志不得输出完整 DNS payload；若记录 DNS 决策日志，只能包含
规范化 QNAME、QTYPE、选择路径和 drop reason。

## 10. 测试要求

### 配置和文件

- inline、`file:`、`!file:` 三种模式。
- 模式混用、文件缺失、不可读、坏 CIDR、去重和容量溢出。
- client `[DNS]` 完整校验，server 拒绝 `[DNS]`。
- server 不再要求 `[AllowedIPs]`。
- 域名大小写、末尾点、非法 label、重复规则、容量限制和 label 边界。

### IP 分类

- IPv4/IPv6 direct prefix 直连，其他公网地址 redirect。
- 正向 file mode 只 redirect 文件内地址。
- 私网、CGNAT、ULA、link-local、multicast、unspecified、文档/基准/协议保留地址、
  tunnel endpoint 和本节点 NAT address 不误入 QUIC。
- DNS VIP 优先于私网和 direct prefix 规则。
- `LocalResolver` 候选回包在 XDP redirect 后必须命中 DNS reverse directory。
- LPM map capacity 和两阶段 classifier enable。

### DNS parser 和 transaction

- `google.com` 匹配自身与 `www.google.com`，不匹配 `notgoogle.com`。
- compression pointer、compression loop、坏 QNAME、多 Question和非标准 opcode。
- EDNS advertised payload clamp 到 1232，checksum 保持正确。
- 相同 DNS ID 来自不同 client 时不冲突。
- 同一 client 并发 local domain 和 remote domain 查询。
- transaction key 稳定选择 Flow worker，重传不发生 owner 漂移。
- Question 可解析但后续 section malformed 时使用 payload-hash transaction key，
  不与正常查询冲突。
- 未完成重传复用 transaction。
- resolver 欺骗响应、重复响应和迟到响应丢弃。
- capacity、NAT port exhaustion 和超时生成 `SERVFAIL` 并释放 active 状态；释放的
  UDP reverse tuple 进入 60 秒隔离，避免迟到响应命中新 transaction。

### 集成和 E2E

- 本地域名经 client 本地 resolver 完整闭环。
- remote domain 经现有 client SNAT、QUIC、server SNAT 到远端 resolver 完整闭环。
- mock local/remote resolver 返回不同固定答案，证明选择路径正确。
- 目标 resolver 观察到正确的 SNAT 地址：local resolver 看到 client NAT，
  remote resolver 看到 server NAT。
- DNS 响应对 client 呈现为 DNS VIP:53。
- QUIC 未认证时 remote domain 查询 `SERVFAIL`，local domain 查询仍成功。
- server stats 和状态中不存在 DNS transaction 或 DNS 专用 QUIC message。
- DNS 响应不生成动态 IP 路由；同一响应地址仍按 direct prefix 文件决定业务连接路径。

## 11. 上线约束

- direct prefix 和 remote domain 文件必须由部署系统以原子替换方式更新，随后滚动重启
  client。
- 启动日志必须报告两类文件的规范化条目数、IPv4/IPv6 prefix 数和规则模式，但不能
  输出完整规则文件。
- 部署前必须确认 DNS VIP 已配置在 intercept 网络中，且静态 `NextHopMac` 可到达
  client host、LocalResolver 和 server 侧 RemoteResolver。
- 物理 NIC 上需验证 native XDP map capacity、内存、queue/NUMA affinity、真实 MTU
  和 UDP DNS 丢包行为。
