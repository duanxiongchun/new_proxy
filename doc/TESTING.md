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
  * **TCP MSS 夹紧（MSS Clamping）**：
    * 识别 TCP SYN 包和 SYN-ACK 包的 IP 数据包。
    * 解析并改写 TCP Option 中的 MSS 字段。
    * 重新计算 IP 校验和与 TCP 校验和。
    * **测试用例**：输入 1500 字节 MTU 配置下的 TCP SYN，断言改写后的 MSS 是否被夹紧至 `1160`（或根据 QUIC datagram 最大容量动态夹紧），并验证 checksum 重新计算后的合法性。
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

运行所有 E2E 脚本：
```bash
sudo bash script/acceptance/run_all_e2e.sh
```

### 3.1 核心 E2E 测试场景清单

#### 1. 双栈 L3 Datagram 透明转发 (`e2e_pure_l3_dualstack.sh`)
* **拓扑**：建立 `client_ns` $\leftrightarrow$ `router_ns` $\leftrightarrow$ `server_ns` 三层空间。
* **验证点**：
  * 通过客户端 TUN 网卡注入 TCP、UDP、ICMP（IPv4 及 IPv6）流量。
  * 验证所有流量直接被打包为 QUIC Datagram 发送，服务端解包后转发给目标真实服务。
  * 目标服务应能成功响应。**通过 ICMP 测试断言 Ping 能够完美双向闭环**。
  * 检查 UDS Stats，断言 QUIC Datagram 收发字节与包计数非零，且无 stream 开启。

#### 2. TCP MSS 夹紧有效性与零分片 (`e2e_mss_clamping.sh`)
* **验证点**：
  * 将客户端 TUN 的 MTU 设为 1200。
  * 在客户端空间中启动大文件传输（如通过 HTTP `curl` 下载 64 MiB 的 blob 文件）。
  * 在 `router_ns` 物理链路上使用 `tcpdump` 抓取底层传输的 UDP (QUIC) 报文。
  * **硬性断言**：
    1. 抓包中绝对不能出现任何 IP 层的分片包（Fragmentation）。
    2. 大文件能以极高的吞吐顺利传输完毕。
    3. 握手阶段的 SYN 包 MSS 选项值已被强行修改为符合 QUIC 承载上限的安全值。

#### 3. 对称多队列与流亲和度测试 (`e2e_multi_port_symmetric.sh`)
* **验证点**：
  * 配置服务端开启 4 个数据面端口，客户端自动协商并拉起 4 个 Worker 线程和 4 个网卡队列。
  * 发起 32 个并发不同的 TCP/UDP 连接流量。
  * **硬性断言**：
    1. 验证 4 个 Worker 线程的 telemetry 指标。
    2. 依赖内核的 `IFF_MULTI_QUEUE` 哈希，所有流被大体均匀地分配到 4 个队列上。
    3. 数据流在其双向链路上始终绑定在同一个工作线程 ID $i$ 上（对称亲和度验证）。

#### 4. 链路故障自愈与 Slot 隔离 (`e2e_reconnection_robustness.sh`)
* **验证点**：
  * 在 4 端口并发流量传输过程中，人为利用 `iptables` 阻断其中第 2 个物理数据端口（`40002`）的 UDP 通信。
  * **硬性断言**：
    1. 只有分配在该 Slot 上的流量触发重连或 fallback 丢包。
    2. 运行在其他 3 个端口（`40001`、`40003`、`40004`）上的业务流量完全不受任何影响，吞吐量保持平稳（Slot 级强隔离）。
    3. 撤销阻断后，健康检查自动通过控制面重协商，自动恢复该 Slot 的 QUIC 连接。

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
