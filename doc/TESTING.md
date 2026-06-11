# new_proxy 测试说明与覆盖矩阵（Pure L3 IP-over-QUIC Datagram 架构）

本文档详细描述了 `new_proxy` 纯 L3 IP-over-QUIC Datagram 隧道网关架构下的测试体系。所有单元测试、端到端测试（E2E）、性能测试和稳定性测试均围绕此全新设计展开，废弃原有的 `boringtun` (WireGuard) 和 `smoltcp` (流代理) 相关测试。

---

## 1. 测试体系概览

由于系统采用无状态的 **L3 原始 IP 报文直接封装至 QUIC Datagram 传输**，测试重点从原来的“应用层流协议模拟与状态管理”转移到了**“网卡级报文吞吐、TCP MSS 夹紧（MSS Clamping）、多队列线程亲和度、零分配内存池与极致稳定性”**。

```
+-------------------------------------------------------+
|                       测试金字塔                      |
|                                                       |
|   [稳定性与压力] --> 长期高吞吐、RSS/FD 增长硬门禁     |
|   [性能与线性度] --> 1, 2, 3, 4 核心吞吐线性与零分配   |
|   [E2E 场景测试] --> 双栈透明、对称映射、连接自愈、MSS |
|   [Rust 单元测试] --> 报文改写、控制面协商、内存回收   |
+-------------------------------------------------------+
```

---

## 2. Rust 单元与集成测试

运行命令：
```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

### 2.1 单元测试分布及核心校验点

* **`src/app_config.rs` & `src/config.rs`**：
  * 校验基础配置、Base64 密钥材料解析以及 AllowedIPs 路由解析。
  * 验证非法地址、不合规端口范围的边界防御。
  * 验证 MTU 的默认加载以及如果配置值超过 `1150` 时的自动 Clamp 机制。
* **`src/control.rs`**：
  * **HMAC 双向校验**：控制面请求与响应的 HMAC-SHA256 生成与合法性判定。
  * **防重放攻击**：利用 nonce replay cache 校验 `client_nonce`。
  * **端口下发与验证**：验证服务端动态生成的 $N$ 个数据面端口列表，以及客户端对端口列表结构完整性的校验。
* **`src/quic_pool.rs`**：
  * **Datagram 协商机制**：验证 QUIC 握手期间的 Datagram 传输特性启用。
  * **多 Connection 插槽分配**：验证 $N$ 个 QUIC 物理连接槽位（`PoolSlot`）的建立、缓存与状态切换。
  * **链接断线自愈**：测试模拟其中某一个 Slot 的物理 QUIC 链接中断，健康检查后台异步触发单独 Slot 的控制面预协商和重连，不干扰其他活跃 Slot。
* **`src/rtc_loop.rs`（RtcWorker 事件循环）**：
  * **网卡多队列读写**：验证工作线程 $i$ 对 TUN 队列 $i$ 的独占非阻塞轮询。
  * **Datagram 封装与解封装**：验证从 TUN 读出 IP 数据包后，直接作为 Payload 塞入 QUIC Datagram 发送，以及反向解析 Datagram 直接写回 TUN 的正确性（IP 头部必须完全保留）。
  * **MTU 自动 Clamp 与零拷贝传输**：
    * 验证从 TUN 读取数据包到 `BytesMut` 缓冲区时正确的零拷贝封装（偏移读取及 header 打标）。
    * 验证对 `CellU64` 等非原子计数器的安全读写与聚合。
  * **线程局部 BufferPool 循环**：
    * 验证数据面转发逻辑中，所有报文缓冲区（`PooledBuf`）全部在当前工作线程的本地 BufferPool 内借用和释放。
    * **测试用例**：通过内存分配追踪，确保包转发热路径上没有发生任何全局堆内存分配（`malloc` / `free`），实现 100% 内存静态化。
* **`src/runtime.rs` & `src/main.rs`**：
  * **对称宽度校验门禁**：验证客户端启动时的协商端口数 $N$ 建立基准，若后续 Peer 配置的端口数不为 $N$，必须拒绝初始化并报错。
  * **策略路由下发**：验证 `SO_MARK` 策略路由规则的安装，确保外层 UDP 报文不会递归回环。
* **`src/uds_server.rs` & `src/stats_cli.rs`**：
  * 校验 UDS API 的 `Stats` 和 `Dump` 命令。
  * 断言导出的遥测指标（如 `sent_datagrams`、`recv_datagrams`、`dropped_packets`、`active_connections`）数值准确。

---

## 3. 端到端（E2E）验收脚本

验收测试需要在支持 Linux Network Namespace 的环境下运行，使用 `ip` 网络空间隔离并模拟真实的网络公网延迟与物理包传输。

运行所有验收测试：
```bash
sudo ./script/acceptance/run_acceptance.sh
```

### 3.1 核心 E2E 测试场景清单

#### 1. 双栈 L3 Datagram 透明转发 (`e2e_test_dualstack.sh`)
* **拓扑**：建立 `client_ns` $\leftrightarrow$ `router_ns` $\leftrightarrow$ `server_ns` 三层空间。
* **验证点**：
  * 通过客户端 TUN 网卡注入 TCP、UDP、ICMP（IPv4 及 IPv6）流量。
  * 验证所有流量直接被打包为 QUIC Datagram 发送，服务端解包后转发给目标真实服务。
  * 目标服务应能成功响应。通过 IPv6 HTTP curl 测试断言流量完美闭环。
  * 检查 UDS Stats，断言 QUIC Datagram 收发字节与包计数非零，且无 stream 开启。

#### 2. 多客户端并发隔离 (`e2e_multi_client.sh`)
* **拓扑**：两个 `client1_ns` & `client2_ns` 并发连接一个 `server_ns`。
* **验证点**：
  * 两个客户端分别建立各自独立的 QUIC 物理连接槽位，独立进行数据收发。
  * 验证服务端可为多客户端并发进行数据面流量哈希和转发。

#### 3. 动态 Peer 增删与会话自愈 (`e2e_dynamic_client_peer.sh`)
* **验证点**：
  * 运行时通过 CLI 动态添加/删除对等体。
  * 验证未配置 peer 前数据包拦截丢弃；动态 `add-peer` 之后隧道立即打通，流量恢复；`remove-peer` 之后拦截重建。
  * 验证重新添加 Peer 后，QUIC 物理池能自动触发预协商并快速恢复。

#### 4. 客户端拓扑基准防御门禁 (`e2e_client_topology_gate.sh`)
* **验证点**：
  * 客户端首个添加的对等体其 QUIC 数据端口数 $N$ 确立本地静态基准（分配 $N$ 宽度队列和线程）。
  * 动态添加新对等体时，如果其数据端口数不等于 $N$，校验机制必须拒绝添加并报错，以保护本地静态工作线程和 TUN 多队列网卡拓扑。

#### 5. 全隧道绕过与回环防御 (`e2e_full_tunnel_bypass.sh`)
* **验证点**：
  * 验证 `SO_MARK` 标记的下发和系统策略路由规则，防止在代理 `0.0.0.0/0` 全网流量时出现加密包重新注入 TUN 接口的物理回环。

#### 6. TCP MSS 夹紧有效性与零分片 (`e2e_mss_clamping.sh`)
* **验证点**：
  * 将客户端/服务端配置为 MTU = 1100（或配置大 MTU 被自动 Clamp 为 1100），并发起大流量 TCP 传输。
  * 在物理链路上抓包硬性断言：绝对不能出现 IP 层的分片包（Fragmentation），且 TCP 握手 SYN 的 MSS 字段被操作系统内核自动限制至 `1060` 安全值（即 MTU - 40 字节）。

#### 7. UDP 与 ICMP 隧道穿透 (`e2e_udp_icmp_tunnel.sh`)
* **验证点**：
  * 验证非 TCP 流量（ICMP ping、UDP DNS）直接被无状态分包至 QUIC Datagram 传输并在对端恢复，支持 ICMP ping 双向闭环。

#### 8. UDP-over-QUIC 性能极限吞吐 (`e2e_udp_over_quic.sh`)
* **验证点**：
  * 验证 UDP 数据流量在 QUIC Datagram 物理下的传输吞吐能力。

---

## 4. 性能与线性度测试

### 4.1 多核心线性度测试 (`perf_cores_scalability.sh`)
* **执行方式**：
  * 通过 `taskset` 约束客户端进程可使用的 CPU 核心数量（`1`、`2`、`3`、`4`）。
  * 相应地配置 $N$（`1..4`）个数据端口和队列进行多进程高并发压力测试。
* **线性度衡量指标**：
  * **TCP Throughput (MiB/s)**：在 CPU 资源成倍增加时，TCP 吞吐量应呈接近 **$1:1$** 的线性增长（核心效率 $\ge 95\%$）。
  * **UDP Loss Rate**：因为 UDP 走 Datagram，随着可用核心和网卡队列增加，处理能力线性提升，在发送端速率恒定的情况下，**接收丢包率必须随核心数增加呈线性下降**，直至在 3-4 核时丢包率接近 0%。

### 4.2 热路径零分配校验 (Zero Heap Allocation Check)
* **执行方式**：
  * 在测试环境中使用 `valgrind --tool=massif` 或 `heaptrack` 启动代理进程。
  * 进行 10 万个小包或高并发压力传输。
* **成功标准**：
  * **热路径硬门禁**：在连接建立成功并进入稳定转发状态后，massif 报告的分配曲线必须是一条水平线。任何由于包分发、解密、改写或写入 TUN 导致的堆分配（Heap Allocation）都被视为缺陷并阻断编译。

---

## 5. 长期稳定性测试 (`stability_stress_test.sh`)

用于验证长期高负荷运行下系统资源的稳定性和无碎片内存回收表现。

### 5.1 流量负载模型
* **持续时间**：1 小时或更长（CI 自动触发）。
* **负载混合比**：
  * **60% TCP 并发大文件下载**：持续消耗带宽，验证 MSS 夹紧在大流下的表现。
  * **30% UDP 洪水包传输**：通过 Datagram 压力通道，考验 TUN 队列的积压和丢包处理。
  * **10% 周期性 ICMP Ping**：监测抖动和底层健康状态。

### 5.2 资源增长门禁指标 (Strict Resource Thresholds)
在稳定性测试结束时，进行如下监控断言，若不满足则测试失败：
* **内存碎片与泄漏**：由于全部数据包均复用线程专属的固定大小 BufferPool，**物理内存（RSS）自 Warmup 阶段结束起，在后续运行中增长斜率必须为 0**（波动 $\le 3\%$）。严禁出现因动态内存碎片累积导致的 RSS 缓慢攀升。
* **文件描述符（FD）**：FD 数量必须保持静态恒定，不允许存在任何因临时连接销毁失败引起的 FD 泄漏。
* **CPU 稳定性**：CPU 负载与吞吐量成正比，不允许在流量平稳时出现 CPU 占用率线性抬升的情况。

---

## 6. 测试安全性与超时防卡死机制 (Safety Timeouts & Exception Cleanup)

为了防止测试用例或测试脚本在持续集成（CI）或本地运行中由于潜在的死锁、网络阻塞等原因无限期卡死（Hang），本架构设计引入了全局超时防护和自动捕获清理机制：

### 6.1 测试场景超时机制 (Timeout Wrappers)
* **E2E 脚本超时包裹**：统一验收测试脚本 [run_acceptance.sh](file:///home/duanxiongchun/new_proxy/script/acceptance/run_acceptance.sh) 在循环执行各个 E2E 场景测试时，强制使用 `timeout --kill-after=10s 300s` 包裹：
  ```bash
  timeout --kill-after=10s 300s sudo -E bash "script/acceptance/${test_name}.sh"
  ```
  如果某个测试脚本执行超过 5 分钟，`timeout` 工具将强制终止其进程并返回错误码 `124`，该错误码会被主控脚本识别并输出 `[TIMEOUT]`，同时阻断后续的发布流程。
* **Makefile 编译与测试门禁**：
  * 在 [Makefile](file:///home/duanxiongchun/new_proxy/Makefile) 的 `test` 目标中，添加 `timeout 300s cargo test`，防止本地或单元测试死锁。
  * 在 `coverage` 目标中，添加 `timeout 600s cargo tarpaulin`，防止测试覆盖率分析挂起。

### 6.2 退出与异常清理机制 (Trap Cleanup)
* **命名空间与进程残留风险**：因为 E2E 测试严重依赖 Linux Network Namespace 和路由标记，如果测试因出错或超时异常终止，残留的后台进程（如 `new_proxy` 守护进程、Python HTTP 服务）以及未释放的 `netns` 可能会导致下一次测试运行发生端口冲突或路由混乱。
* **自动 EXIT 信号捕获 (Trap EXIT)**：在核心端到端脚本（如 [e2e_multi_client.sh](file:///home/duanxiongchun/new_proxy/script/acceptance/e2e_multi_client.sh) 和 [e2e_udp_over_quic.sh](file:///home/duanxiongchun/new_proxy/script/acceptance/e2e_udp_over_quic.sh)）的头部注册：
  ```bash
  trap cleanup EXIT
  ```
  当脚本接收到退出信号（包括正常执行完毕、异常出错崩溃或因超时被 `timeout` 强制杀掉），操作系统会立即调用 `cleanup` 函数：
  1. 依次向记录的后台服务进程 PID（`SERVER_PID`, `CLIENT_PID`, `HTTP_PID` 等）发送 `SIGTERM`，并在 1 秒后发送 `SIGKILL` 强杀。
  2. 自动清理本次测试创建的所有 Network Namespaces（如 `scale_client_ns`, `scale_server_ns` 等），确保测试物理环境在任何情况下都能 100% 干净回滚。

