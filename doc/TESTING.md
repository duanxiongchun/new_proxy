# 混合多协议安全代理网关测试规格说明书 (v5.0 - 密钥认证与双轨聚合遥测版)

本测试规格说明书针对 **密钥认证与双轨聚合遥测版架构 (v5.0)** 设计。测试设计分为四个层级：**单元测试**（验证核心逻辑组件）、**端到端集成测试**（模拟网络拓扑与流量闭环）、**性能基准测试**（量化吞吐量、延迟与隔离度）以及**容灾与混沌测试**（验证背压、自适应端口热轮换、端点漫游与双轨兼容性）。

---

## 1. 单元测试 (Unit Tests)

单元测试旨在对网关底层无网络依赖的核心逻辑组件进行 **100% 分支覆盖率与边界安全校验**。我们将单元测试矩阵划分为以下五个核心高覆盖率套件：

### 1.1 AllowedIPs 统一双栈路由引擎单元测试套件 (CIDR Route Test Suite)
本套件用于确保内存 CIDR 基数树（Radix Tree / Trie）在极限查询与复杂交织网段下的匹配精准度，是网关路由安全的根基。

* **测试用例 1.1.1：标准 IPv4/IPv6 单播匹配**
  * **输入**：配置路由规则 `AllowedIPs = 192.168.1.0/24, 10.0.0.0/8, 2001:db8::/32`。
  * **验证**：检索 `192.168.1.254` -> 匹配 PeerA；检索 `10.255.255.1` -> 匹配 PeerA；检索 `2001:db8::ffff` -> 匹配 PeerA。
* **测试用例 1.1.2：最长前缀匹配优先原则 (Longest Prefix Match - LPM)（关键）**
  * **输入**：配置重叠规则：
    * **IPv4**：`PeerA.AllowedIPs = 192.168.0.0/16`，`PeerB.AllowedIPs = 192.168.1.0/24`。
    * **IPv6**：`PeerC.AllowedIPs = 2001:db8:1::/48`，`PeerD.AllowedIPs = 2001:db8:1:2::/64`。
  * **验证**：
    1. 检索目的 IPv4 `192.168.1.55`；
    2. 检索目的 IPv6 `2001:db8:1:2::beef`。
  * **预期输出**：
    1. 必须**精准返回 PeerB**（而非 PeerA）；
    2. 必须**精准返回 PeerD**（而非 PeerC）。
* **测试用例 1.1.3：全网段广播与边界值验证 (Edge Case)**
  * **输入**：配置 `AllowedIPs = 0.0.0.0/0, ::/0`。
  * **验证**：检索 `0.0.0.0`、`255.255.255.255`、`::`、`ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`，必须全部命中，且检索过程无任何算术溢出或空指针异常。
* **测试用例 1.1.4：畸变与非法 CIDR 格式解析鲁棒性**
  * **输入**：传入畸变输入：`"192.168.1.300/24"` (IP溢出)、`"2001:db8::g/32"` (非法十六进制IPv6)、`"192.168.1.0/33"` (掩码溢出)、`"2001:db8::/129"` (IPv6掩码溢出)、`""` (空字符)。
  * **预期输出**：解析器必须优雅拦截并抛出精准的 `InvalidCIDRFormat` 错误，严禁 panic 崩溃。
* **测试用例 1.1.5：超大规模高并发压力测试**
  * **输入**：导入 10,000 条互不重叠的随机网络 CIDR（混合 v4 与 v6）。使用 100 个并发线程同时发起总计 1,000,000 次匹配检索。
  * **验证**：单次检索的平均延迟必须小于等于 5us，无并发锁死、死锁或内存竞态问题。

### 1.2 内网控制面对等 Noise_IK 协议单元测试套件 (Noise_IK Auth Test Suite)
本套件对用户态独立的公网控制面进行安全性与完整性验证，确保 Noise_IK 握手在复用 WireGuard 密钥对时的防伪造和防篡改安全性。

* **测试用例 1.2.1：对等密钥 Noise_IK 握手认证测试**
  * **输入**：
    1. 客户端使用正确的客户端 WireGuard 私钥作为 Static Key 发起 Noise_IK 握手；
    2. 客户端使用伪造的、随机生成的私钥发起握手。
  * **预期输出**：
    1. 正确密钥下握手在公网 UDP 控制端口（51821）瞬时成功，协商出对称 Session Key；
    2. 伪造密钥在握手首个数据包（Ephemeral Key / Static Key 混合解密）阶段直接报错失败，服务端静默关闭，不响应任何数据。
* **测试用例 1.2.2：端口/配置推送列表 Fuzzing 测试**
  * **输入**：构造包含异常地址和端口的服务端推送报文：
    * `PublicIPv4` = `"198.51.100.300"` (非法IP)；
    * `PublicIPv6` = `"2001:db8::g"` (非法IPv6)；
    * `ListenPorts` = `[80, 22, -1, 65536, 70000, 0]`。
  * **预期输出**：客户端解析器自动过滤系统保留端口、直接拦截并抛弃非法或越界的端口及 IP，仅加载合法的公网高位双栈 UDP 端口，避免恶意端口重定向攻击。
* **测试用例 1.2.3：控制数据包防重放与篡改校验**
  * **输入**：模拟重放攻击与篡改。构造一个合法的 `Session_PSK` 协商报文，然后：
    1. 篡改报文内 `Session_ID` 的单个 bit；
    2. 复制一份相同的报文，在 5 秒后进行二次发送（重放）。
  * **预期输出**：
    1. 签名/哈希校验模块识别出 bit 级篡改，抛出 `BadMessageIntegrity` 错误并丢弃；
    2. 防重放窗口（通过时间戳/自增 SeqNum 校验）识别出重复报文，直接抛出 `ReplayPacketDetected` 错误并丢弃。

### 1.3 TCP 状态机转换与连接生命周期单元测试套件 (TCP State Machine Relay Test)
由于网关在用户态拦截并终结了 TCP，必须在用户态完美实现 TCP 的各种复杂状态转移（特别是 FIN 半关闭与 RST 重置），否则会造成极大的连接残留与内存泄露。

* **测试用例 1.3.1：TCP 半关闭状态正确传递 (TCP Half-Close / FIN Handling)（高频核心）**
  * **背景**：在很多 Web 应用中，客户端发送完请求后会调用 `shutdown(SHUT_WR)` 触发 TCP FIN（半关闭），但仍保持读通道畅通以接收响应。
  * **测试输入**：App Socket 触发 `EOF` (半关闭)。
  * **预期输出**：
    1. 网关必须**仅关闭**对应 QUIC Stream 的写入侧（发送 `FIN` 帧）；
    2. **保持**该 App Socket 的可读和写监听持续激活；
    3. 直到 QUIC Stream 读完响应并返回 `FIN` 时，才最终完全释放此 Socket 资源。
* **测试用例 1.3.2：TCP 重置信号极速响应与清理 (TCP RST / Connection Abort)**
  * **测试输入**：App Socket 突然发生物理异常，产生 `ECONNRESET` (RST) 错误。
  * **预期输出**：网关检测到 RST 后，立刻向对端 QUIC 发送 `RESET_STREAM` 帧通知业务中断，并在当前物理事件循环中**瞬时关闭**该 Stream 相关的 Pipe 文件描述符，释放所有分配 of Relay Buffer 缓存，严禁产生僵尸 FD。

### 1.4 双轨数据聚合遥测单元测试套件 (Telemetry Aggregation Test Suite)
本套件用于确保网关内存中的 Telemetry 模块能够以 `Peer_PublicKey` 作为唯一主键，自适应地在用户发起拉取请求时，按需聚合内核态 Netlink L3 流量与用户态内存中的无锁 L4 原子流量。

* **测试用例 1.4.1：按需拉取机制与实时数据合并测试**
  * **输入**：
    1. 用户通过 CLI 发起对 `Key_A` 的流量拉取请求；
    2. 触发一次性 Netlink 内核查询，Mock 得到 WireGuard 内核流量数据（PublicKey = "Key_A", Tx_Bytes = 5000, Rx_Bytes = 4000）；
    3. 从内存无锁原子变量中直接读取该 Peer 的当前并行 QUIC 流量统计（Tx_Bytes = 3000, Rx_Bytes = 2000）。
  * **验证**：调用按需遥测聚合函数 `get_aggregated_telemetry("Key_A")`。
  * **预期输出**：返回结构体必须精准瞬间合并两端指标（L3 + L4 流量数据），且验证在用户未发起拉取前，系统**没有**任何后台定时轮询任务在运行（零后台 CPU 消耗）。
* **测试用例 1.4.2：标准客户端向下兼容的单轨数据降级测试**
  * **输入**：用户通过 CLI 发起对 `Key_B` 的流量拉取请求。`Key_B` 为标准官方客户端，在用户态内存中**没有任何**对应的平行 QUIC 链接或原子计数器。
  * **验证**：调用按需遥测聚合函数 `get_aggregated_telemetry("Key_B")`。
  * **预期输出**：聚合引擎优雅降级，直接且仅输出从 Netlink 获取到的内核 L3 流量（Tx_Bytes = 2000, Rx_Bytes = 1000），返回数据结构中 L4 相关指标自动填为 0 且无任何空指针异常，证明双模遥测兼容性完备。
* **测试用例 1.4.3：Peer 离线后的内存自适应清理 (Telemetry Cleanup)**
  * **输入**：模拟有 10,000 个动态客户端接入、协商并生成了用户态流量原子结构体，随后连接全部断开并超时。
  * **验证**：在 Peer 断开且被移除后，验证网关内存中该 Peer 关联的流量原子计数器结构体是否已被安全释放，无任何残留或内存泄露。

### 1.5 双轨 MSS 自动夹逼算法单元测试套件 (Dual-Track MSS Clamping Test Suite)
本套件用于确保针对 IPv4（IP 头 20 字节）与 IPv6（IP 头 40 字节）的差异，MSS 裁剪模块能执行精准计算。

* **测试用例 1.5.1：IPv4 TCP SYN 报文裁剪校验**
  * **输入**：拦截到一个从 IPv4 源地址发往 `AllowedIPs` 子网的 TCP SYN 报文，原 MSS 字段标称为 `1460`。网卡 MTU 设置为 `1400`，Noise 封装层开销 56 字节。
  * **预期输出**：网关的 MSS 裁剪模块在内核/用户态拦截该包，将其 TCP Header 中的 MSS 强制修改为 `1344` 字节，校验和被重新计算，且报文成功流转。
* **测试用例 1.5.2：IPv6 TCP SYN 报文裁剪校验**
  * **输入**：拦截到一个从 IPv6 源地址发往 `AllowedIPs` IPv6 子网的 TCP SYN 报文，原 MSS 字段标称为 `1440`。网卡 MTU 设置为 `1400`，封装层开销 76 字节。
  * **预期输出**：网关的 MSS 裁剪模块强制将其修改为 `1324` 字节，校验和重新计算，报文成功流转，证明双轨自动夹逼机制高度精准。

### 1.6 对等体双向自适应互补同步单元测试套件 (Peer Auto-Sync Test Suite)
本套件用于确保内核态 WireGuard peer 配置与网关用户态 GatewayState 内存配置在出现不一致时，能被自动、无损地互补补充，并计算正确的预同步 source 标识。

* **测试用例 1.6.1：内核至用户态同步 (Kernel -> Proxy Sync)**
  * **输入**：配置 `GatewayState` 仅包含 PeerA，而 Mock `wg dump` 返回 PeerA (both) 和 PeerB (仅内核持有的 Peer)。
  * **验证**：调用 `sync_kernel_and_proxy_state`。
  * **预期输出**：
    1. 返回的 `sources` 映射表中：PeerA 被标记为 `"both"`，PeerB 被标记为 `"kernel"`；
    2. PeerB 被自动补充到 `GatewayState` 的 peer 配置列表中；
    3. `GatewayState` 的 AllowedIPs Trie 树完成热重建，使得查找 PeerB 对应的内网 IP 时能瞬间精准命中，证明 L4 拦截机制已对 PeerB 激活；
    4. 自动为 PeerB 协商/计算 Noise_IK 握手所需的 Diffie-Hellman 控制面共享密钥并缓存。
* **测试用例 1.6.2：用户态至内核同步 (Proxy -> Kernel Sync)**
  * **输入**：配置 `GatewayState` 包含 PeerA 和 PeerC (仅用户态配置持有的 Peer)，而 Mock `wg dump` 仅返回 PeerA。
  * **验证**：调用 `sync_kernel_and_proxy_state`。
  * **预期输出**：
    1. 返回的 `sources` 映射表中：PeerA 被标记为 `"both"`，PeerC 被标记为 `"proxy"`；
    2. 系统自动向内核驱动下发 `wg set` 配置指令，自动将 PeerC 的公钥、AllowedIPs 等信息配置绑定至系统 tun 网卡设备，确保 PeerC 对应的 L3 UDP/ICMP 双栈数据通道正常开启。

---

## 2. 端到端集成测试 (End-to-End Tests)

集成测试使用 Linux Network Namespaces (`netns`) 在单机上构建真实的分布式网络拓扑，完全模拟真实网络双栈互联。

### 2.1 测试拓扑结构

```text
  Client NS (10.0.0.2 / fd00::2)   Router NS (模拟双栈 WAN)        Server NS (10.0.0.1 / fd00::1)
 +-------------------------------+  +--------------------+  +-------------------------------+
 | - client_proxy                |  |  tc qdisc (丢包率) |  | - server_proxy                |
 | - Virtual tun0 (WG DualStack) | <|  iptables/ip6tables| <| - Virtual tun0 (WG DualStack) |
 | - App (curl/curl -6)          |  +--------------------+  | - Target Web Server (DualStack|
 +-------------------------------+                          +-------------------------------+
```

### 2.2 测试自动化脚本设计 (`e2e_test_dualstack.sh`)

```bash
#!/usr/bin/env bash
# 创建网络命名空间
ip netns add client_ns
ip netns add router_ns
ip netns add server_ns

# 建立虚拟以太网对 (veth) 连接三者，并配置 IPv4/IPv6 双栈 IP ...
# (此处省略网络接口初始化配置：Client ↔ Router ↔ Server)

# 1. 启动服务端代理
ip netns exec server_ns ./server_proxy -config server.conf &
SERVER_PID=$!
sleep 1

# 2. 启动客户端代理
ip netns exec client_ns ./client_proxy -config client.conf &
CLIENT_PID=$!
sleep 2

# 3. 验证第一阶段：WireGuard L3 通道正常连通 (ping / ping6 测试)
echo "=== 测试 Type B (UDP/ICMP) 双栈数据面 ==="
# IPv4 ICMP 测试
ip netns exec client_ns ping -c 3 10.0.0.1
if [ $? -ne 0 ]; then
    echo "✗ [FAIL] IPv4 ICMP 传输失败"
    exit 1
fi

# IPv6 ICMPv6 测试
ip netns exec client_ns ping6 -c 3 fd00::1
if [ $? -eq 0 ]; then
    echo "✓ [PASS] IPv4/IPv6 ICMP 双栈成功通过 WireGuard 隧道传输"
else
    echo "✗ [FAIL] IPv6 ICMPv6 传输失败"
    exit 1
fi

# 4. 验证第二阶段：内网安全协商与 TCP (Type A) 平行 QUIC 分流
echo "=== 测试 Type A (TCP) 平行 QUIC 双栈通道 ==="
# IPv4 curl 代理测试
ip netns exec client_ns curl --interface tun0 -4 -s -o /dev/null -w "%{http_code}" http://192.168.1.100:80
if [ $? -ne 200 ]; then
    echo "✗ [FAIL] IPv4 TCP 代理分流失败"
    exit 1
fi

# IPv6 curl 代理测试
ip netns exec client_ns curl --interface tun0 -6 -s -o /dev/null -w "%{http_code}" http://[2001:db8:1::100]:80
if [ $? -eq 200 ]; then
    echo "✓ [PASS] IPv4/IPv6 TCP 双栈流量成功绕过 AllowedIPs 并通过平行的 QUIC 隧道完成转发"
else
    echo "✗ [FAIL] IPv6 TCP 代理分流失败"
    exit 1
fi

# 清理测试环境 ...
kill $SERVER_PID $CLIENT_PID
```

---

## 3. 性能基准测试 (Performance & Benchmark)

通过科学的压测工具，量化系统的吞吐极限与多路复用下的多流隔离特性。

### 3.1 吞吐量与 CPU 消耗压测 (Throughput & CPU Profiling)
* **工具**：`iperf3` (TCP & UDP 模式)，`perf` 或 `go tool pprof`。
* **测试方法**：
  1. 在 Server NS 启动 `iperf3 -s`；
  2. 在 Client NS 运行 `iperf3 -c 10.0.0.1 -t 60`，让流量流经 Type A QUIC 物理链接池；
  3. 记录**平均带宽（Gbps）**、**每秒数据包数（PPS）**和网关进程的 **CPU 占用率**。
  4. 对比原生 WireGuard 传输 TCP 时的极限带宽，量化规避 TCP-over-VPN 后的性能提升。

### 3.2 0-RTT 首包建连延迟测试 (Time to First Byte - TTFB)
* **工具**：`wrk` 或自定义测试脚本。
* **测试方法**：
  1. 使用并发客户端频繁发起并断开 TCP 连接；
  2. 记录从 TCP 发起握手（SYN）到收到第一个字节响应的平均延迟（TTFB）；
  3. 重点评估 QUIC **0-RTT PSK Session Resumption (会话复用)** 机制下的建连耗时，验证其相比传统 TLS/TCP 握手减少的往返时延（RTT）数量。

### 3.3 弱网丢包下的多流队头阻塞消除验证 (HoL Blocking Mitigation)
* **测试目的**：用实测数据证明 UDP/QUIC 相比 TCP 物理隧道，能够彻底解决队头阻塞问题。
* **测试步骤**：
  1. 在 Router NS 挂载 `tc` 规则，模拟物理链路发生 **5% 的恶性随机丢包**：
     `ip netns exec router_ns tc qdisc add dev veth-router-client root netem loss 5%`
  2. 建立 **Stream 1**：在后台启动一个大文件下载压测，持续吃满带宽；
  3. 建立 **Stream 2**：每隔 50ms 向目标服务器发起一次高精度 ping（ICMP/TCP 实时包），记录时延与抖动（Jitter）。
  4. **对比验证指标**：
     * **TCP 物理隧道下**：Stream 2 的时延会出现频繁的、长达数百毫秒 of 断崖式飙升（因为 Stream 1 丢包阻塞了整条连接的队列）。
     * **QUIC 物理隧道下**：Stream 2 的延迟波形图应该极度平滑，时延始终保持在物理 RTT 附近，不受 Stream 1 大量丢包的影响，实证队头阻塞完美消除。

---

## 4. 容灾与混沌测试 (Chaos & Scenario Tests)

混沌测试旨在模拟最恶劣的网络封锁、重置以及突发限速，验证网关自愈自适应的能力。

### 4.1 背压熔断生存测试 (Backpressure Chaos)
* **测试目的**：验证在极端的单向限速下，网关不会发生 OOM（内存溢出）崩溃。
* **测试步骤**：
  1. 客户端向服务端发起 10GB 大文件的 TCP 传输；
  2. 突然使用 `trickle` 或内核限速，将服务端目标应用（Web Server）的写入速率限制在极低的 **50 KB/s**；
  3. 持续运行 5 分钟，监控客户端和服务端代理进程的 **内存常驻集大小 (RSS)**。
  4. **预期结果**：网关的内存曲线应始终保持平直（无任何上涨），证明背压联锁机制成功挂起了数据源端的读取，彻底杜绝了数据在用户态内存中无限积压。

### 4.2 公网 UDP 端口遭防火墙瞬间阻断测试 (DPI Port Roaming Test)
* **测试目的**：验证网关的 **自适应端口热轮换 (Zero-Touch Port Roaming)** 和物理链接**无缝倒换 (Failover)**。
* **测试步骤**：
  1. 平行 QUIC 链接池预先建立，TCP 流量（如视频播放流）正在高速传输；
  2. 模拟网络封锁：在 Router NS 中突然下发防火墙规则，阻断当前 QUIC 连接池中正在使用的某两个公网 UDP 端口：
     `ip netns exec router_ns iptables -A FORWARD -p udp --dport 40001 -j DROP`
  3. 观察系统自愈行为：
     * 服务端检测到物理端口 `40001` 失联；
     * 服务端通过完好的内网控制通道，向客户端热推送最新的 `Port Pool`（剔除 `40001`，启用新的备用端口 `40005`）；
     * 客户端接收推送后，在后台无缝向 `40005` 拉起新的 QUIC 物理通道，并将原本在 `40001` 上的活跃 TCP Stream 平滑热迁移过去。
  4. **预期结果**：整个端口阻断与平滑倒换过程中，**客户端的视频播放流无任何卡顿，底层的 App TCP 连接零断开，用户完全无感知**。

### 4.3 WireGuard 物理隧道重钥旋转测试 (Rekey / Key Rotation Test)
* **测试目的**：验证当 WireGuard 隧道因生存期到期重新握手时，密钥流的平滑过渡。
* **测试步骤**：
  1. 设定 WireGuard 强制每 3 分钟进行一次 `Rekey`（重新握手）；
  2. 观察控制面行为：当 WireGuard 重启握手成功后，客户端的控制面线程必须立刻通过内网控制端口重新协商并安全发送全新的 `Session_PSK`。
  3. **预期结果**：QUIC 平行池在不中断当前数据流的情况下，平滑热重载新的 `Session_PSK`，完成物理对称密钥的滚动旋转。

### 4.4 物理公网双栈倒换与自愈测试 (Physical WAN Dual-Stack Failover Test)
* **测试目的**：验证物理承载通道在公网物理连接（IP 端点）在 IPv4 和 IPv6 之间切换时的自愈与漫游能力。
* **测试步骤**：
  1. 物理 QUIC 通道最初建立在客户端与服务端的公网 IPv4 地址上（如 `198.51.100.1`）；
  2. 模拟客户端移动网络漫游或物理链路切换，直接通过 `ip netns` 禁用客户端的 IPv4 出口，强行使其仅保留公网 IPv6 地址（改变其源物理 IP）；
  3. 观察客户端物理 UDP 套接字是否自适应通过物理 IPv6 链路连接至服务端的公网 IPv6 地址 `2001:db8::1`，且服务端是否能在 50ms 内完成 Socket 重绑定与会话继承（Socket Roaming / Connection Migration）。
* **预期结果**：物理通道在公网 IPv4 和 IPv6 之间平滑热切换，数据链路在毫秒级内自动拉通，上层所有的逻辑 TCP Stream 无任何超时、断开或丢包，TCP 连接状态维持 `ESTABLISHED` 状态。

### 4.5 移动网络漫游与 NAT 重绑定连接迁移测试 (Connection Migration & NAT Rebinding Test)
* **测试目的**：验证当客户端的网络环境发生改变（如从 Wi-Fi 漫游到 5G 蜂窝网络，或者中间 NAT 网关重启导致其公网源 IP 和端口发生漂移）时，代理物理隧道与逻辑 TCP Streams 能够无缝漫游自愈。
* **测试步骤**：
  1. 客户端通过公网与服务端建立物理 WireGuard 隧道与平行 QUIC 连接池。TCP 逻辑流（Stream）中正在进行高负载的数据通信（如正在下载 1GB 文件）；
  2. 模拟客户端物理漫游与 IP/Port 重绑定：
     - **对于 WireGuard (Type B)**：直接修改 `client_ns` 出口路由，模拟其发送报文时，源公网四元组瞬间漂移（IP 从 `198.51.100.2` 变为 `198.51.100.200`，源端口也发生改变）；
     - **对于 QUIC (Type A)**：客户端网关不重新握手，而是直接从新的物理网络接口，使用原有的 **Connection ID (CID)** 继续向服务端发送 QUIC 数据包；
  3. 服务端在收到新报文后：
     - WireGuard 模块：在内核态解密成功后，自动且静默地将 Peer 绑定的 Endpoint 刷新为新地址；
     - QUIC 物理池模块：检测到 Connection ID 吻合，自动通过 `PATH_CHALLENGE` 帧和 `PATH_RESPONSE` 帧在 20ms 内完成路径安全校验，并将物理连接重绑定至新地址。
* **预期结果**：
  1. 服务端的 WireGuard 路由端点和平行 QUIC 通信路径无缝迁移到客户端的新 IP/Port 上；
  2. 逻辑 TCP Stream 数据传输无任何卡顿或超时，App 层面的 TCP 连接零断开，彻底实现与 WireGuard 一模一样的高级无感漫游体验。

### 4.6 标准 WireGuard 客户端向下兼容与分流回退测试 (Standard WireGuard Client Compatibility & Fallback Test)
* **测试目的**：验证当客户端为官方标准 WireGuard 客户端（没有运行定制代理网关）时，服务端网关是否能平滑向下兼容，退回“标准 VPN 路由与 NAT 模式”工作。
* **测试步骤**：
  1. 服务端网关 `server_proxy` 照常启动，其底层 WireGuard 隧道和 `ListenControlPort` (9000) 处于正常工作状态；
  2. 在客户端命名空间 `client_ns` 中，**不启动**任何 `client_proxy` 用户态程序；
  3. 客户端直接使用官方标准的 `wg-quick` 工具，利用标准的 WireGuard 配置文件拉起双栈 `tun0` 接口，并向服务端发起物理 UDP 双栈握手；
  4. 握手成功后，客户端分别进行双栈流量测试：
     - 发起 IPv4 和 IPv6 `ping` / `ping6` 时延测试；
     - 发起 TCP 双栈流量测试：调用 `curl -4 http://192.168.1.100:80` 和 `curl -6 http://[2001:db8:1::100]:80` 发送 TCP 请求。
  5. 监控服务端日志与流量路径：
     - 验证服务端控制端口（9000）保持挂起/闲置（没有收到来自该 Peer 的密钥协商）；
     - 验证服务端没有为该 Peer 创建平行 QUIC 物理连接池。
     - 监控服务端内核路由与 NAT 表，确认客户端发来的 TCP、UDP、ICMP 流量全部由服务端底层的 WireGuard 接口自动拦截、解密，并通过标准的 Linux `MASQUERADE` 路由安全分发至最终目的地。
* **预期结果**：标准客户端在不运行代理的情况下，所有双栈 TCP、UDP、ICMPv4/v6 流量均能通过标准的 WireGuard L3 隧道正常访问并返回结果，服务端实现完美的自适应双模向下兼容。

---

## 5. 1小时后台长稳与多路复用负载均衡集成测试 (1-Hour Background Stability & Mux Load Balancing Test)

本测试专门用于量化和验证代理网关在长时间并发负载下的稳定运行能力、物理连接池的资源控制特性，以及多物理 QUIC 通道下 TCP 流量轮询分流的极致均匀性。

### 5.1 测试目的
1. **可靠性校验**：验证在高并发、长周期的代理场景下，用户态 TCP-over-QUIC 的流控、分包、重组及连接维持的健壮度，检查是否有任何 Panic、FD 泄露或死锁。
2. **多通道均匀负载校验**：测试 TPROXY 劫持流量进入连接池后，4 个平行 QUIC 通道是否完全遵循 Round-Robin 机制分摊负载，流量变异系数 (CV) 必须小于 5%。
3. **内存与 CPU 稳定性**：监测 1 小时长稳运行中，代理进程的常驻内存集大小 (RSS)，证明系统无隐式内存泄漏。

### 5.2 测试步骤
1. **物理通道扩展**：
   - 动态修改服务端代理配置，使 `[QUICPool]` 下的 `ListenPorts` 包含 4 个物理 UDP 端口：`40001, 40002, 40003, 40004`。
   - 动态生成对应的 `client_stability.conf` 和 `server_stability.conf` 并放置于测试环境。
2. **多网命名空间拉起**：
   - 使用 Linux Namespace 创建并拉起 `client_ns`, `router_ns`, `server_ns` 三元网络拓扑。
   - 客户端配置 TPROXY 拦截规则，将所有流向 `10.0.0.1` 虚拟内网地址的 TCP 流量重定向至用户态代理端口 `:1080`。
3. **拉起双端代理与目标服务**：
   - 在 `server_ns` 启动 `server_proxy` 及 HTTP / UDP 测试服务。
   - 在 `client_ns` 启动 `client_proxy`，确认通过 UDP `51821` 的 Noise_IK 握手安全拉起 4 个平行的物理 QUIC 通道连接。
4. **并发拉动背景流量**：
   - **TCP 长连接**：在 `router_ns` 中启动后台 Python 压测脚本，开启 8 个并发线程，维持 8 条 TCP 长连接至 `10.0.0.1:8080`，每个连接每秒持续发送和接收 1KB 随机载荷。
   - **TCP 短连接**：在 `router_ns` 中运行循环，每 1 秒并发发起 `curl` 报文下载，频繁建立和摧毁 TCP Stream。
   - **L3 原生 UDP/ICMP**：每 5 秒发送一次 UDP 报文到 `10.0.2.2:8081`（直接走 L3 原生隧道），每 2 秒运行一次 `ping` 心跳。
5. **后台高频数据采集**：
   - 监控脚本每 30 秒执行一次检测，利用 `ps` 读取代理进程的 CPU% 与 RSS(物理内存)。
   - 使用 `new-proxy-cli dump` 获取服务端与客户端接口，解析出 4 个 QUIC 物理通道各自的 tx/rx 累加字节数据并写入 JSON。
6. **优雅拆除与数据归档**：
   - 运行 1 小时 (3600 秒) 后，自动向所有后台压测进程及代理守护进程发送 `SIGTERM` 信号。
   - 彻底删除 `client_ns`, `router_ns`, `server_ns` 以免残留网卡。
   - 分析 JSON 数据，生成包含变异系数 (CV) 和内存走势的 `stability_report.md` 归档。

### 5.3 预期结果与通过准则 (Pass Criteria)
1. **0 崩溃与 100% 成功率**：1 小时测试中，两端代理均无崩溃；短连接 `curl` 成功率达 100%；长连接无任何未知断线。
2. **流量极度平衡**：4 个 QUIC 通道的 L4 流量（tx_bytes + rx_bytes）分布完美，流量分布变异系数 (Coefficient of Variation) 满足：
   $$CV = \frac{\sigma}{\mu} < 5\%$$
3. **物理内存平直**：1 小时长稳测试后期，内存增长不超过基线的 10%，无内存持续泄漏迹象。

---

## 6. 并发多客户端 E2E 混合网络集成测试 (E2E Multi-Client Hybrid Integration Test)

为了验证服务端网关在处理大规模复杂网络拓扑下的并发性能、对等体状态隔离性，以及完美向下兼容传统客户端的混合组网能力，我们设计并编写了 **`e2e_multi_client.sh`** 并发集成测试。

### 6.1 测试拓扑结构
* **测试节点**：1 个服务端节点 (`server_ns`)，1 个核心网关路由节点 (`router_ns`)，以及 2 个并发运行的客户端节点。
* **客户端类型**：
  * **Client 1 (`client1_ns`) [定制代理客户端]**：运行 `new_proxy` 客户端守护进程，通过本地 TPROXY 强行劫持 TCP 目的流量，将其自动封装进入 **QUIC 平行物理连接池** 进行用户态分流转发。
  * **Client 2 (`client2_ns`) [标准 WireGuard 客户端]**：不启动任何用户态代理守护进程，不配置任何 TPROXY 劫持规则。所有的 TCP、UDP 和 ICMP 流量完全流经标准 L3 物理加密信道，测试服务端的向下兼容与回退承载能力。### 6.2 测试验证步骤与动态互补同步校验 (`e2e_multi_client.sh`)
1. **多网口与命名空间宣告**：拉起 4 个独立的 Linux Network Namespace，使用 3 对 veth 虚拟网口对将其连接，并建立标准的 Linux 主机静态网段寻址路由。
2. **多 Peer 不对称启动**：服务端 `server_multi.conf` 仅配置 Client 1 的 peer 公钥，**有意将 Client 2 排除在用户态配置文件之外**。
3. **并发流量发射与 TPROXY Interception**：
   * 在 Client 1 命名空间中并发发起 `curl` 业务请求。为了支持本地流量的劫持，Client 1 增加了 `iptables OUTPUT` 链 mangle MARK 规则，强行将本地生成的 TCP 流量重定向至 TPROXY，验证数据是否成功流经 QUIC 用户态连接池并产生非零 offloading 流量。
   * 在 Client 2 命名空间中并发发起 `curl` 业务请求。验证在无客户端代理的情况下，连接是否能平滑通过 L3 链路自适应回退访问成功。
4. **遥测数据动态互补同步验证**：
   * 调用 `new-proxy-cli show` 刮取并核验服务端遥测数据。
   * **预期输出**：
     - **Client 1 (Proxy)**：对应的条目中，`quic: active`，显示非零 `quic transfer` 字节（如 `775 B`），且其 `source` 状态标识为 `"both"`。
     - **Client 2 (Fallback)**：对应的条目在第一次 `show` 时自动在内核 `wg dump` 抓取发现，**在服务运行时动态补充/同步至服务端用户态 GatewayConfig 和 AllowedIPs 基数树中**；其 `source` 状态标识为 `"kernel"`，且显示正确的 L3/WireGuard 传输数据（如 `12.21 KiB`）。
     - 后续所有的 telemetry 采集和查询中，Client 2 的状态均自动持久化地对齐为 `"both"`，证明双端自适应对等体互补同步机制健壮无损。
