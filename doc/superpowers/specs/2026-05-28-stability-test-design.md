# 1小时后台长稳与多路复用负载均衡测试设计规格说明书

- **设计日期**：2026-05-28
- **测试状态**：已批准 (Approved)
- **目标组件**：物理 QUIC 连接池、TPROXY 拦截、用户态并发转发、双轨聚合遥测接口

---

## 1. 业务目标与验证准则

### 1.1 核心诉求
验证混合代理网关在长达 1 小时的背景高负载并发环境下运行的稳定性，检验用户态 TCP-over-QUIC 协议栈在高频连接切换下的可靠度与内存泄露特征。
同时验证 TPROXY 拦截流量进入客户端连接池后，TCP Stream 在**多路物理 QUIC 隧道**中是否能够按预期执行 Round-Robin（轮询）策略，实现各通道流量的完全均匀分布。

### 1.2 成功校验标准 (Success Criteria)
1. **进程存活与零崩溃**：在 1 小时的测试周期内，`client_proxy` 和 `server_proxy` 进程无任何 Panic、零意外退出、零 Crash。
2. **流量零丢包**：所有的长连接 TCP 发送的数据包必须 100% 被目标服务器成功接收并回复，短连接 `curl` 响应成功率必须达 100%。
3. **负载均衡变异系数 CV < 5%**：
   - 客户端与服务端配置有 4 个物理 QUIC 通道（监听端口：40001, 40002, 40003, 40004）。
   - 计算 4 个 QUIC 物理通道各自消耗的 L4 总流量（发送字节 + 接收字节之和）。
   - 4 个通道流量占比的变异系数（标准差 / 平均值）必须小于 5%（证明流量极其均匀地分布在多个物理 QUIC 连接中）。
4. **内存无泄露 (RSS Stability)**：两端代理进程的物理内存占用 (RSS) 应在测试拉动前 5 分钟内达到稳定水平，随后保持平直，1 小时结束时的内存占用相比第 5 分钟时的增长幅度不超过 10%（严禁发生 OOM 或持续性内存泄漏）。

---

## 2. 拓扑与环境配置

测试使用单机 Linux Network Namespaces (`netns`) 机制构建真实的分布式物理网络模型，并配置 4 个 QUIC 端口池。

```text
       [Client NS]                           [Router NS]                          [Server NS]
 (Address: 10.0.1.2/24)                                             (Address: 10.0.2.2/24)
+-----------------------+               +-------------------+               +-------------------------------+
| - client_proxy        |               | - ip_forward = 1  |               | - server_proxy                |
| - TPROXY (Port 1080)  | <──────────── | - 策略路由跳转    | <──────────── | - python http.server (8080)   |
| - 4 x QUIC Clients    |               +-------------------+               | - nc UDP listener (8081)      |
+-----------------------+                                                   +-------------------------------+
      │                                                                           ▲
      └─────── 4 x 平行物理 QUIC 链接 (UDP: 40001, 40002, 40003, 40004) ───────────┘
```

### 2.1 端口与策略拦截配置
1. **服务端动态推送**：`server_stability.conf` 配置 `ListenPorts = 40001, 40002, 40003, 40004`。
2. **控制面交互**：客户端启动后，通过 UDP `51821` 物理控制端口执行 X25519 + HMAC-SHA256 控制面协商，安全拉取这 4 个端口的清单，并建立 4 个平行的 QUIC 隧道物理连接。
3. **TPROXY 拦截**：在 `client_ns` 中下发 `iptables -t mangle` 拦截目的地址为 `10.0.0.1` (AllowedIP) 的所有 TCP 请求，转发至 `127.0.0.1:1080` (TProxy) 导入 QUIC 连接池分配。

---

## 3. 流量生成设计 (Stability Traffic Generator)

为了提供连续、真实的负载，流量生成采用多轨混合模式：

### 3.1 8 线程高频 TCP 长连接 (Stability Long Connection)
* **工具**：`stability_long_tcp.py` (基于标准 Python `socket` 与 `threading` 编写，无第三方包依赖)。
* **配置**：
  - 启动 8 个背景工作线程。
  - 每个线程分别与 `10.0.0.1:8080` 建立 TCP Socket（直连会被 TPROXY 重定向并走 QUIC 多路复用）。
  - 每个连接在建立后保持打开，每秒向服务端写入 `1024 字节` 随机字节串，并读取服务端的 HTTP 响应。
  - 遇到断线时自动执行重连并记录重连次数。
  - 运行时间：3600 秒。

### 3.2 高频 TCP 短连接 (Frequent Short Connection)
* **工具**：Bash 循环器。
* **配置**：
  - 每隔 1 秒，在后台非阻塞拉起一次 `curl -s -o /dev/null http://10.0.0.1:8080/`。
  - 该行为频繁生成生命周期极短的 TCP 握手与释放，用以压力测试 QUIC Stream 分配模块的分配效率和回收机制。

### 3.3 物理直连 L3 UDP/ICMP 背景流量
* **UDP**：每 5 秒在 `client_ns` 发送一次 UDP 报文到 `10.0.2.2:8081`（未被 AllowedIPs 覆盖的网段，走原生 WireGuard L3 加密封装通道）。
* **ICMP**：每 2 秒运行一次 `ping -c 1 10.0.2.2` 以保持隧道持续有心跳并记录包延迟。

---

## 4. 实时遥测与数据收集

在测试进行期间，由 `stability_stress_test.sh` 内置的 `monitor_once` 采样逻辑实现周期性数据采集（默认每 30 秒一次，可通过环境变量调整）：

### 4.1 核心采集参数
1. **进程状态**：检查进程是否存在，捕获 Crash 发生时的日志后缀。
2. **资源占用**：
   - 客户端 CPU (%)、内存 RSS (MiB)
   - 服务端 CPU (%)、内存 RSS (MiB)
3. **分层物理遥测**：
   - 使用 `new-proxy-cli dump` 提取服务端与客户端接口统计。
   - 解析出 4 个 QUIC 物理通道各自对应的 `local_port` (`40001` - `40004`)、`rx_bytes`、`tx_bytes` 及 `active_streams`。
4. **归档路径**：采集到的时间序列数据以 JSON Lines 格式追加记录到 artifact 目录的 `stability_metrics.jsonl` 中。

---

## 5. 自动化数据分析与报告

在 1 小时倒计时完结、清理测试 Namespace 后，分析脚本将汇总数据并输出 `stability_report.md` Markdown 报告，自动保存至 Artifact 目录下。报告结构如下：

### 5.1 资源消耗趋势折线（文本图表或数值快照）
* 报告首、中、末阶段的 CPU / RSS 指标，分析曲线斜率以给出泄露评估。

### 5.2 多物理通道均衡评估
* **连接流量明细**：
  - QUIC Conn 0 (Local Port: 40001): Tx=A Bytes, Rx=B Bytes, Total=C Bytes, Share=P0%
  - QUIC Conn 1 (Local Port: 40002): Tx=D Bytes, Rx=E Bytes, Total=F Bytes, Share=P1%
  - QUIC Conn 2 (Local Port: 40003): Tx=G Bytes, Rx=H Bytes, Total=I Bytes, Share=P2%
  - QUIC Conn 3 (Local Port: 40004): Tx=J Bytes, Rx=K Bytes, Total=L Bytes, Share=P3%
* **均匀性指标**：
  - 均值 $\mu$ = $\text{Mean}(C, F, I, L)$
  - 标准差 $\sigma$ = $\text{StDev}(C, F, I, L)$
  - 变异系数 $CV = \sigma / \mu \times 100\%$ (预期低于 5%)。
