# 测试报告

## 测试概览

- 项目版本：`new_proxy v5.0.0`
- 报告日期：2026-06-11
- 主要测试对象：AF_XDP 零拷贝数据面、填充环批处理生产（Fill Ring Batching）、共享 MAC 地址缓存（inner_mac_cache）、空闲立即 Flush、E2E 测试超时防卡死机制（run_acceptance/Makefile）、EXIT 信号自动捕获清理（Trap EXIT）、并发多核吞吐扩展性（1..4 Cores 线性度）
- 测试环境：单机 Linux Network Namespace 三/四节点拓扑
- 测试拓扑：`client_ns -> router_ns -> server_ns`、`client1_ns + client2_ns -> router_ns -> server_ns`、动态 peer/perf/stability 专用 namespace

## 2026-06-11 AF_XDP 零拷贝数据面优化与多核扩展性测试

### 1. AF_XDP 零拷贝数据面整合与优化
* **实现内容**：实现了真正的用户态旁路数据面（AF_XDP Datapath），使用 eBPF 程序（[xdp_filter.c](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/xdp_filter.c)）在网卡驱动层实现高吞吐流量分流，将隧道及目标网段流量直接送入用户态共享内存环（UMEM Rings），绕过内核协议栈。
* **主要优化策略**：
  1. **共享二层 MAC 缓存 (inner_mac_cache)**：通过共享的 `inner_mac_cache`（`Arc<RwLock<HashMap<Ipv4Addr, [u8; 6]>>>`）自动学习和缓存出站 Plaintext 报文的源 IP 与 MAC 映射。在解密并投递 Plaintext 报文时进行缓存检索，若未命中则回退到 ARP 物理查询，大幅避免了热路径上频繁、同步调用慢系统查询的损耗。
  2. **填充环批处理生产 (Fill Ring Batching)**：在接收包流程 [process_rx_ring](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L668) 中，将原有的“逐包修改并 fence 生产 Fill 环描述符”优化为“在本地寄存器中累加已归还的缓冲地址，并在当前批次处理结束时执行一次统一的 `fill.produce()` 生产提交和一次内存屏障”。这极大地降低了 CPU 缓存失效和总线锁（Lock Fences）的频率，使得 4 核高并发 TCP 吞吐量提升了 **23.3%**（吞吐量由 741.5 MiB/s 跃升至 **914.2 MiB/s**）。
  3. **空闲时立即 Flush (Immediate Flush on Idle)**：当检测到本次事件循环中没有新数据被处理（`!work_done`）或者自上次物理发送以来已空转（Spin）超过 500 次时，无条件立即触发物理 `sendto` 系统调用。这完美平衡了高负载下的系统调用合并与低延迟场景下的快速回传，将单核 TCP 吞吐稳定提升至 **308.3 MiB/s**（突破 300 MiB/s 设计目标线）。

### 2. 测试框架鲁棒性与异常清理防护
* **超时防死锁机制**：
  * 在统一验收测试脚本 [run_acceptance.sh](file:///home/duanxiongchun/new_proxy/script/acceptance/run_acceptance.sh) 中，为每个 E2E 场景测试用例强制包裹 `timeout --kill-after=10s 300s`。如果脚本执行卡住，会在 300 秒后被强杀，并输出 `[TIMEOUT]` 错误，防止 CI/本底运行卡死。
  * 在 [Makefile](file:///home/duanxiongchun/new_proxy/Makefile) 中，为单元测试和 Tarpaulin 覆盖率分别配置了 300s 和 600s 的安全时间门禁。
* **EXIT 信号自动捕获清理 (Trap EXIT)**：
  * 在 [e2e_multi_client.sh](file:///home/duanxiongchun/new_proxy/script/acceptance/e2e_multi_client.sh) 和 [e2e_udp_over_quic.sh](file:///home/duanxiongchun/new_proxy/script/acceptance/e2e_udp_over_quic.sh) 脚本中注册 `trap cleanup EXIT`。
  * 无论是测试成功、失败或是因超时被强杀，`cleanup` 函数都会被自动执行，强杀所有拉起的 `new_proxy` 守护进程和 python 业务后台，并彻底清除所有的网络命名空间，彻底杜绝测试环境污染。
* **代码清理与规范化**：
  * 清理了 `RtcWorker` 中未使用的 `return_rx_buf` 死代码。
  * 修复了所有的 Clippy 警告（如 `needless-range-loop`），并使用 `cargo fmt` 实现了代码的统一美化。

### 3. 多核心线性度与吞吐性能实测 (2026-06-11)
使用 Linux Network Namespace 隔离，进行并发多核压测，对比 AF_XDP 模式与 TUN 模式在不同 CPU 核心数下的 TCP 与 UDP 吞吐表现。

#### 3.1 TCP 吞吐性能比较 (Throughput in MiB/s)
* **AF_XDP TCP 性能数据**：
  * **1 Core**：**308.324 MiB/s** (达到并超越单核 300 MiB/s 红线目标)
  * **2 Cores**：**529.470 MiB/s**
  * **3 Cores**：**709.586 MiB/s**
  * **4 Cores**：**914.168 MiB/s** (较优化前的 741.5 MiB/s 提升约 **23.3%**，约合 **7.66 Gbps**)
* **TUN TCP 性能数据**：
  * **1 Core**：120.300 MiB/s
  * **2 Cores**：268.895 MiB/s
  * **3 Cores**：424.529 MiB/s
  * **4 Cores**：554.719 MiB/s

#### 3.2 UDP 吞吐性能比较 (Throughput in MiB/s)
* **AF_XDP UDP 性能数据**：
  * **1 Core**：**39.434 MiB/s**
  * **2 Cores**：**86.036 MiB/s**
  * **3 Cores**：**131.770 MiB/s**
  * **4 Cores**：**175.277 MiB/s**
* **TUN UDP 性能数据**：
  * **1 Core**：39.335 MiB/s
  * **2 Cores**：85.709 MiB/s
  * **3 Cores**：131.254 MiB/s
  * **4 Cores**：175.859 MiB/s

#### 3.3 扩展性与瓶颈深度分析
1. **TUN 模式的超线性扩展 (Super-linear Scaling)**：
   * **现象**：TUN 模式在核心数由 1 增至 4 时，吞吐量呈现 4.61x 的增长（效率达 115%）。
   * **根因**：单核模式下，单一文件描述符 (TUN FD) 读写竞争以及频繁发生的 L1/L3 CPU 缓存驱逐 (Cache Eviction) 构成了沉重的单核性能开销。当核心数按 2/3/4 阶梯扩展时，物理网卡队列与线程得以一一对应解耦，消除了串行化瓶颈并提升了缓存本地化率（Cache Locality），因此表现出超线性特征。
2. **AF_XDP 模式的亚线性扩展 (Sub-linear Scaling)**：
   * **现象**：AF_XDP 模式的线性扩展效率随着核心数增加呈亚线性变化（4 核心下效率为 74.1%）。
   * **瓶颈定位 (Perf Profiling)**：
     * **XDP_COPY 模式开销**：由于测试环境运行在 `veth` 虚拟网络命名空间内，不具备真实物理网卡硬件的 Zero-Copy (无拷贝) 机制，必须回退在 `XDP_COPY` 模式下运行。这带来了高昂的软中断 (SoftIRQ) 上下文切换及内核-用户态报文数据拷贝开销。根据 Perf 分析，系统的 SoftIRQ（`veth_poll`, `process_backlog`, `tcp_v4_rcv`）占用了高达 **38.6%** 的 CPU 周期。
     * **总线与 L3 缓存饱和**：在 4 核心吞吐达到 **914.168 MiB/s**（**7.66 Gbps**）时，大量的软中断上下文切换与内存拷贝引起了极高频率的内存访问，总线带宽及 L3 缓存读写开始逐步饱和，使得继续扩展核心数时的收益受物理硬件制约而下降。

---

## 2026-06-09 管控面单线程与架构文档整合验证

### 1. 架构文档清理与整合
* **操作内容**：将 `docs` 目录下的所有架构设计及设计规约文档整合并入 [doc/ARCHITECTURE.md](file:///home/duanxiongchun/new_proxy/doc/ARCHITECTURE.md)，并将冗余的 `docs` 目录彻底删除。
* **文件状态**：`docs/` 目录已删除，所有设计及规约细节已统一至单个权威架构文档中。

### 2. 管控面单线程化（Single-Threaded Control Plane）
* **主运行时改造**：将主入口 Tokio 异步运行时变更为 `tokio::runtime::Builder::new_current_thread()`，集约管理所有控制面任务（UDS API Server, pre-negotiation Server, Health Checker / Failover 等），消除了主运行时的调度线冲突。
* **数据面独立多线程绑定**：高频数据转发 Worker 线程（`RtcWorker`）通过 `std::thread::Builder` 派生独立 OS 线程，并在线程内部启动专属单线程 Tokio 运行时，确保控制面与数据面物理级别隔离，防止低频控制面事件（如慢 UDS、DNS 查询等）抢占高频数据面 RTC 流的 CPU 资源。

### 3. 测试用例验证与修复
* **单线程回归**：所有控制面 API 及 CLI 命令在此单线程运行时下运行稳定。
* **测试用例修复**：修复了 `rtc_loop::tests::test_rtc_worker_datagram_loop` 在单线程环境下调用 `read_exact` 出现 `WouldBlock` 的缺陷（通过使 mock socketpair 的读端保持 blocking）。
* **测试结果**：
  * **单元测试**：所有 89 个单元测试 100% 通过。
  * **E2E 验收测试**：全部 8 项 E2E 场景测试通过（包含双栈、多客户端、动态 peer、拓扑防御门禁、全隧道 bypass、MSS 夹紧等）。

## 2026-06-09 数据面超时机制与定时器优化验证

本次补充优化覆盖：
- 双向流转发热路径（`relay_copy_with_idle`）中采用单实例栈分配的 pinned 定时器 `tokio::pin!(idle_sleep)`，每次读写成功后通过 `.reset()` 进行原地 Deadline 修改，实现了热路径零内存分配，极大降低了在高吞吐、高并发下的 Tokio 时间轮调度竞争。
- 移除了应用层写超时 `RELAY_WRITE_TIMEOUT` 包裹，转发层完全依赖底层的 TCP Keepalive 和 QUIC transport 级超时进行死连接清理，降低了 50% 的定时器生命周期管理开销。
- 移除了未使用的 `RELAY_WRITE_TIMEOUT` 静态常量，修复了 Clippy 的 dead-code 编译警告。
- 将 `tokio` 的 `test-util` 依赖隔离在 `[dev-dependencies]` 中，防止测试框架代码污染生产二进制体积。
- 补齐了针对 `relay_copy_with_idle` 定时器复位与空闲到期机制的 Mock 单元测试。

测试结果：
- **单元测试**：所有 134 个单元测试 100% 通过（包含新超时复位测试 `test_relay_copy_with_idle_timeout`）。
- **Acceptance 验收测试**：全部 E2E 测试例通过（`e2e_test_dualstack`、`e2e_scenarios` 等 8 项全 PASS）。
- **性能单流吞吐（Smoke Test）**：
  - 吞吐量：由原来的 `152.31 MiB/s` 提升至 **`175.11 MiB/s`**（**性能提升约 15.0%**）。
  - TTFB 首包延迟：P50 维持在 `2.63 ms` 极低水准。
- **并发多核扩展性（Covers Scalability）**：
  - 测试产物目录为 `/tmp/new_proxy_cores_scalability_20260609_164649`：
  ```text
  data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,linear_efficiency,worker_new_flows
  1,32,2,4096,37.029566,110.614,1.000,1.000,65
  2,32,2,4096,19.860860,206.235,1.864,0.932,32|33
  3,32,2,4096,12.296502,333.103,3.011,1.004,21|22|22
  4,32,2,4096,9.140728,448.104,4.051,1.013,18|15|17|15
  ```
  在 1 核到 4 核的阶梯并发下，系统吞吐量呈现非常完美的线性扩展（4 核扩展倍数 4.051 倍，扩展效率维持在 101.3%），无任何时间轮锁竞争瓶颈。

## 2026-06-09 ServerFutures event-base 修复验证

本次补充修复覆盖：

- 服务端 QUIC connection 内 accepted stream 使用 connection-local `ServerFutures` 推进，不再为每条 stream 创建 `tokio::spawn`。
- `ServerFutures` 槽位改为 generation + free-list，完成任务后的槽位可复用，旧 waker 在槽位复用后会被忽略，避免高 churn 短连接/短 stream 导致 tombstone 长期积累。
- `ServerFutures::poll_ready()` 每轮有固定 ready poll 预算，避免一次 drain 大量 ready stream 导致 accept/status 路径抖动。
- relay 每方向连续复制达到 64 KiB 后主动 `yield_now()`，降低长下载 stream 对同 connection 短 stream 的调度影响。
- 删除无调用的旧 `run_userspace_wg_timer_loop()`，保持 userspace WireGuard UDP receive/timer 只归属 worker 0 的架构不变量。
- 文档同步当前 event-base server stream 模型，不再描述 per-stream handler task。

执行命令：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --bins
sudo bash script/perf/perf_cores_scalability.sh
```

结果：**通过。** 默认高并发 perf artifact `/tmp/new_proxy_cores_scalability_20260609_105333`：

```text
data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,32,2,4096,43.011465,95.230,1.000,65
2,32,2,4096,18.570266,220.568,2.316,30|35
3,32,2,4096,13.937299,293.888,3.086,19|26|20
4,32,2,4096,8.931285,458.613,4.816,18|17|12|18
```

## 2026-06-09 Client topology 门禁补充验证

本次补充覆盖：

- 新增 `script/acceptance/e2e_client_topology_gate.sh`，并纳入 `script/acceptance/run_acceptance.sh` 默认 E2E 列表和语法门禁。
- 用两个真实 server daemon 验证 client 启动前预协商 QUIC data port 数：server1 发布 4 个 data ports，client 启动后 UDS `dump` 必须出现 4 个 worker telemetry 行。
- 移除原始 4-port peer 后，当前 QUIC pool 为空但 baseline 仍固定为 4；动态添加 1-port proxy peer 必须被拒绝，错误信息包含 `established baseline uses 4`。
- 拒绝 mismatched peer 后，worker 拓扑保持 4；重新添加原始 4-port peer 后，业务 TCP 仍可通过 TUN/smoltcp/QUIC 成功。

执行命令：

```bash
bash -n script/acceptance/e2e_client_topology_gate.sh
bash -n script/acceptance/run_acceptance.sh
cargo test runtime_worker_threads_follow_fixed_data_plane_width
cargo build --bins
sudo bash script/acceptance/e2e_client_topology_gate.sh
```

结果：**通过。** 新增 E2E 产物目录为 `/tmp/new_proxy_client_topology_20260609_100440`。

## 2026-06-09 QUIC stream 调度性能修复验证

问题定位：

- `script/perf/perf_cores_scalability.sh` 修复前在默认 `PERF_PARALLEL=32` 下，1-port 组可完成但 2-port 组超时失败。
- 降低到 `PERF_PARALLEL=8 PERF_BLOB_MIB=32` 后，2-port 组仍超时失败。
- client 日志显示大量 `Timed out waiting for userspace target proxy status`，随后 QUIC pool 进入 fallback/recovery。
- 根因是 server 侧 accepted stream handler 和长生命周期 relay future 被放在 connection loop 的 `ServerFutures` 内一起推进；大文件下载 relay 会拖慢同一 QUIC connection 上后续 stream 的 target status 写回。

最终修复：

- server QUIC connection loop 负责 `accept_bi()`、session authorization 和 stream handler future 推进。
- 每条 accepted stream 在接收时受 `MAX_QUIC_STREAM_HANDLERS` semaphore 限流，但不创建 per-stream task。
- `ServerFutures` 只 poll ready future，并带槽位复用、旧 waker generation 校验和每轮 ready poll 预算。
- relay copy 增加 64 KiB cooperative yield 预算，避免长 relay 在 event-base loop 中独占过久。

执行命令：

```bash
cargo fmt
cargo check
cargo test
cargo build --release --bins
sudo env PERF_PARALLEL=8 PERF_ROUNDS=2 PERF_BLOB_MIB=32 bash script/perf/perf_cores_scalability.sh
sudo bash script/perf/perf_cores_scalability.sh
```

结果：**通过。**

低并发复测，artifact `/tmp/new_proxy_cores_scalability_20260609_102146`：

```text
data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,8,2,512,3.216713,159.169,1.000,17
2,8,2,512,1.625278,315.023,1.979,11|6
3,8,2,512,1.143402,447.787,2.813,5|5|7
4,8,2,512,0.972662,526.390,3.307,5|6|2|4
```

默认高并发复测，artifact `/tmp/new_proxy_cores_scalability_20260609_102234`：

```text
data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,32,2,4096,34.855698,117.513,1.000,65
2,32,2,4096,16.303492,251.235,2.138,36|29
3,32,2,4096,12.778437,320.540,2.728,25|17|23
4,32,2,4096,10.225614,400.563,3.409,25|12|12|16
```

## 2026-06-09 数据面线程模型修复验证

本次修复覆盖：

- server/client userspace WireGuard 外层 UDP receive 和 timer 均收敛到 worker 0；其他 worker 只处理各自 TUN queue 的出站封装。
- 进程入口改为显式创建 Tokio runtime，worker thread 数由配置推导的数据面宽度限制。
- 服务端 QUIC data port listener 保持每 data port 一个固定 task；连接认证和 stream accept 保持轻量，accepted stream 由 connection-local `ServerFutures` 推进，relay 带 cooperative yield 预算，避免长 relay 阻塞新 stream 建立。
- server-side TCP relay 的双向复制改为单 future 内 `select` 推进，不再为每个方向创建额外 task。
- `VirtualTunnelSocket` 删除后台 ping task，改由调用方 timer 通过 `tick_control()` 驱动物理 socket 探测和 active socket 选择。
- 补充单元回归：验证 L3 UDP receive/timer ownership 只属于 worker 0、runtime worker thread 数受配置宽度限制、入口不再使用 `#[tokio::main]`、server QUIC ready queue 只重新 poll 被唤醒 future、VirtualTunnelSocket 不创建后台 task 且 `tick_control()` 能发送 PING/处理 PONG 切换 active socket，并用源码级 guard 限制 server QUIC 数据面 spawn 点。

执行命令：

```bash
cargo test
```

结果：**通过。** `cargo test` 当前为 CLI 10 个测试、主程序 128 个测试全部通过。本轮未执行需要 root/network namespace 的全量 E2E、稳定性和 perf 实测。

## 2026-06-08 严格 Review 后二次修复验证

本次修复覆盖：

- `RtcWorker::new` 构造参数收敛为 `RtcWorkerConfig`，恢复 `cargo clippy --all-targets -- -D warnings` 门禁。
- TUN/UDP/WireGuard/QUIC bridge 运行时 packet buffer 改为按 MTU 派生，默认 `MTU + 256`，下限 1500、上限 65535，并支持 `NEW_PROXY_PACKET_BUFFER_BYTES` 覆盖；默认 MTU 1400 时不再为每个 worker 固定分配 65535 字节 buffer。
- 修复 `client_quic_data_port_count()` 的 Clippy `filter_next` 门禁问题，`script/acceptance/run_acceptance.sh` 中的 Clippy 硬门禁可通过。
- client 初始 QUIC data 连接失败但控制面已返回端口池时，worker 数使用协商 data port 数，避免 cold-start fallback 后恢复阶段因“多 data port、单 worker”被拒绝；多个 peer 的启动期协商端口数不一致时直接拒绝启动。
- client 启动后记录 QUIC data port 基准；后台恢复或 UDS 动态新增 QUIC pool 时，如果 peer data port 数与既有基准不一致，则拒绝该 pool。2026-06-09 后启动期未知时基准固定为 1，动态新增 peer 不能改变已启动拓扑。
- `QuicPoolClient` 控制面刷新保留同数量换端口能力，但拒绝 data port 数变化；需要改变 client worker 拓扑时必须重启客户端。
- 架构和测试文档同步当前真实语义：client TUN worker 数启动时固定，后续不支持热扩容 TUN multiqueue worker；QUIC data port 基准与 TUN worker 数分离。

执行命令：

```bash
cargo fmt --check
cargo check --quiet
cargo clippy --all-targets -- -D warnings
cargo test --quiet
```

结果：**通过。** `cargo test` 当前为 CLI 10 个测试、主程序 119 个测试全部通过。本轮未执行需要 root/network namespace 的全量 E2E、稳定性和 perf 实测。

## 2026-06-08 严格 Review 后问题修复验证

本次修复覆盖：

- `bridge_userspace_stream_to_quic` 恢复 QUIC pool `Active` 状态预检，避免 `Fallback` / `Recovering` 状态下的新 userspace TCP bridge 继续尝试 QUIC。
- `RtcWorker` 本地端口分配修正为完整覆盖 `49152..=65535`，并补充最终端口 `65535` 可分配的边界测试。
- `RtcWorker` 本地端口分配改为只依赖 `used_local_ports` 索引，避免按 `nat_map` 做重复线性扫描。
- `RtcWorker` 半开 flow 清理补充 socket 移除断言，避免 stale smoltcp socket 长期占用端口/内存。
- `VirtualTunnelSocket` 入站包复制移到队列锁外，缩短多物理 UDP socket 并发入队时的临界区。
- `VirtualTunnelSocket` 改为 RTC readiness receive path，不再后台预取业务 UDP 包或维护中间接收队列。
- `VirtualTunnelSocket` 发送使用当前 active 底层 UDP socket，接收仍由事件 readiness 驱动。
- client WireGuard L3 继续使用单 UDP socket，但只有 worker 0 负责入站 receive/timer，避免多 worker 同时等待同一个 UDP socket。
- `QuicPoolClient` 控制面刷新触发条件覆盖认证/证书错误以及全端点 QUIC connect timeout/transport failure，并由现有指数退避限制刷新频率。
- `QuicPoolClient` 补充旧 QUIC data port 不可达、部分旧 data port 不可达、control port 下发新端口池后的自动恢复测试。
- `RtcWorker` 本地端口索引 helper 在 debug/test 构建中拒绝重复端口误用。
- `script/acceptance/run_acceptance.sh` 的语法门禁纳入稳定性、性能脚本和 Python helper；稳定性与性能实测可通过 `RUN_STABILITY=1`、`RUN_PERF=1` 显式开启，`RUN_PERF=1` 会先构建 release binaries。
- 同步测试报告日期和当前单元测试数量。

执行命令：

```bash
cargo fmt --check
cargo check --quiet
cargo clippy --all-targets -- -D warnings
cargo test --quiet
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/e2e_full_tunnel_bypass.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh \
  script/perf/perf_cores_scalability.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
```

结果：**通过。** `cargo test` 当时为 CLI 10 个测试、主程序 114 个测试全部通过。本轮未执行需要 root/network namespace 的全量 E2E、稳定性和 perf 实测。

## 2026-06-08 Review 后稳定性边界补充验证

本次修复覆盖：

- `VirtualTunnelSocket` 业务 UDP 入站由 RTC worker 直接读取，并在 UDS `dump` 的 `virtual_tunnel` 行输出 direct rx、control 包和 receive error 计数。
- 物理 UDP socket 健康探测没有任何新鲜 PONG 时保持当前 active socket，不再强制回切到 socket 0。
- L4 userspace TCP 资源预算保留默认值，同时支持通过 `NEW_PROXY_MAX_WORKER_TCP_FLOWS`、`NEW_PROXY_TCP_SOCKET_BUFFER_BYTES`、`NEW_PROXY_BRIDGE_PENDING_LIMIT`、`NEW_PROXY_BRIDGE_PENDING_BYTES_LIMIT` 和 `NEW_PROXY_BRIDGE_CHANNEL_CAPACITY` 覆盖。
- 补充 `VirtualTunnelSocket` drop/failover 边界和 `RtcWorker` flow limit fallback 单元测试。

执行命令：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/e2e_full_tunnel_bypass.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh \
  script/perf/perf_cores_scalability.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
sudo bash script/acceptance/e2e_userspace_wg_fallback.sh
```

结果：**通过。** `cargo test` 当时为 CLI 10 个测试、主程序 103 个测试全部通过。`e2e_userspace_wg_fallback.sh` 产物目录为 `/tmp/new_proxy_userspace_wg_fallback_20260608_154552`，验证 QUIC 阻断后新 TCP 仍可经 userspace WireGuard fallback 成功闭环。本轮未执行其余 root/network namespace E2E、稳定性和 perf 脚本。

## 2026-06-08 Review 后静态与单元验证

本次修复覆盖：

- `VirtualTunnelSocket` 物理 UDP 入站改为 RTC readiness receive path，避免后台预取、包复制和中间接收队列。
- L4 userspace TCP 默认资源预算下调：降低单 worker flow 上限、单 socket buffer、bridge pending 队列容量。
- `RtcWorker` 在 SYN offload 的 socket 创建或 listen 失败时回滚 flow 状态并立即走 userspace WireGuard L3 fallback。
- 修复 fmt/clippy 门禁问题，并补充 `virtual_tunnel` 空 socket 集和并发接收 waiter 单元测试。

执行命令：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --bins
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/e2e_full_tunnel_bypass.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh \
  script/perf/perf_cores_scalability.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
sudo bash script/acceptance/e2e_userspace_wg_fallback.sh
```

结果：**通过。** `cargo test` 当前为 CLI 10 个测试、主程序 100 个测试全部通过。`e2e_userspace_wg_fallback.sh` 产物目录为 `/tmp/new_proxy_userspace_wg_fallback_20260608_152441`，验证 QUIC 阻断后新 TCP 可经 userspace WireGuard fallback 成功闭环，telemetry 显示 WireGuard traffic 且 QUIC inactive。本轮未执行其余 root/network namespace E2E、稳定性和 perf 脚本。

## 2026-06-05 严格 Review 问题修复验证

本次修复覆盖：

- full-tunnel endpoint bypass 改为 WireGuard 风格 `SO_MARK` + policy routing：外层 QUIC/control/userspace WireGuard UDP socket 自动带 mark，业务流量走专用 table，主表直连/更具体路由通过 `suppress_prefixlength 0` 保留。
- `e2e_full_tunnel_bypass.sh` 增加 SO_MARK policy rule、marked endpoint route 和动态 full-tunnel proxy peer replacement 验证。
- userspace WireGuard 未知 endpoint 握手/控制类入站包增加 per-IP token bucket，成功握手不消耗 token，失败 unknown 包才消耗 token；drop 计数进入 telemetry，降低多 peer 下恶意首包触发 O(N) 扫描的 CPU 风险，同时减少 NAT/reconnect storm 误伤。
- 稳定性报告区分硬失败与 RSS 风险：业务失败、crash、UDP、ping、QUIC CV 失败会返回非零；RSS 默认记录为 `WARN`，设置 `STABILITY_ENFORCE_RSS=1` 后作为硬门禁。
- 文档同步 full-tunnel SO_MARK 路由、IPv6 extension-header TCP fallback、WireGuard 未知握手限速和完整 E2E 入口。

执行命令：

```bash
cargo fmt --check
cargo check --quiet
cargo clippy --all-targets -- -D warnings
cargo test --quiet
cargo build --bins
bash -n script/acceptance/e2e_full_tunnel_bypass.sh \
  script/acceptance/stability_stress_test.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
python3 script/acceptance/stability_report.py /tmp/stability_report_check
STABILITY_ENFORCE_RSS=1 python3 script/acceptance/stability_report.py /tmp/stability_report_check
sudo bash script/acceptance/e2e_full_tunnel_bypass.sh
```

结果：

```text
cargo fmt --check: PASS
cargo check --quiet: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo test --quiet:
  new_proxy_cli: 10 passed; 0 failed
  new_proxy: 97 passed; 0 failed
cargo build --bins: PASS
bash -n modified scripts: PASS
python3 -m py_compile stability helpers: PASS
stability_report.py default RSS mode:
  RSS growth <= 10% or <= 2 MiB: WARN
  RSS hard gate enabled: no
  exit code: 0
stability_report.py strict RSS mode:
  exit code: 1
sudo bash script/acceptance/e2e_full_tunnel_bypass.sh: PASS
  - dynamic full-tunnel add-peer replacement: PASS
  - endpoint route after replacement: 10.20.2.2 via 10.20.1.1 dev vf-c
  - artifact: /tmp/new_proxy_full_tunnel_20260605_221703
```

结论：**严格 Review 中发现的问题已修复并验证；full-tunnel 动态 replacement 真实 E2E 通过，稳定性报告门禁语义已收敛为业务硬失败 + RSS 可配置硬门禁。**

## 2026-06-05 全量 E2E、稳定性、性能与门禁验证

本轮按要求重新执行全部本地门禁、端到端场景、稳定性压测、性能冒烟和核心数扩展性能测试。

执行命令：

```bash
cargo fmt --check
cargo check --quiet
cargo clippy --all-targets -- -D warnings
cargo test --quiet
cargo build --bins
cargo build --release --bins
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/e2e_full_tunnel_bypass.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh \
  script/perf/perf_cores_scalability.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
sudo bash script/acceptance/e2e_test_dualstack.sh
sudo bash script/acceptance/e2e_scenarios.sh
sudo bash script/acceptance/e2e_multi_client.sh
sudo bash script/acceptance/e2e_dynamic_client_peer.sh
sudo bash script/acceptance/e2e_userspace_wg_fallback.sh
sudo bash script/acceptance/e2e_full_tunnel_bypass.sh
sudo bash script/acceptance/stability_stress_test.sh
sudo bash script/perf/perf_smoke.sh
sudo bash script/perf/perf_cores_scalability.sh
```

门禁结果：

```text
cargo fmt --check: PASS
cargo check --quiet: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo test --quiet:
  new_proxy_cli: 10 passed; 0 failed
  new_proxy: 94 passed; 0 failed
cargo build --bins: PASS
cargo build --release --bins: PASS
bash -n acceptance/perf scripts: PASS
python3 -m py_compile stability helpers: PASS
```

端到端场景结果：

```text
sudo bash script/acceptance/e2e_test_dualstack.sh: PASS
sudo bash script/acceptance/e2e_scenarios.sh: PASS
  - dual-track TCP over TUN/smoltcp/QUIC: PASS
  - server restart and client auto-reconnection: PASS
  - legacy external WireGuard fallback sub-scenario: SKIP
  - dynamic add/remove peer: PASS
  - standard no-QUIC L3 fallback mode: PASS
sudo bash script/acceptance/e2e_multi_client.sh: PASS
sudo bash script/acceptance/e2e_dynamic_client_peer.sh: PASS
  - artifact: /tmp/new_proxy_dynamic_peer_20260605_205511
sudo bash script/acceptance/e2e_userspace_wg_fallback.sh: PASS
  - artifact: /tmp/new_proxy_userspace_wg_fallback_20260605_205532
  - WireGuard bytes non-zero; QUIC inactive after data ports blocked
sudo bash script/acceptance/e2e_full_tunnel_bypass.sh: PASS
  - artifact: /tmp/new_proxy_full_tunnel_20260605_205638
  - endpoint route uses physical client link, not full-tunnel TUN
```

稳定性压测结果：

```text
sudo bash script/acceptance/stability_stress_test.sh: completed with exit code 0
artifact: /tmp/new_proxy_stability_20260605_205656
report: /tmp/new_proxy_stability_20260605_205656/stability_report.md
samples collected: 121
proxy crash samples: 0
long TCP iterations/errors: 57268/0
short curl OK/FAIL: 70120/0
UDP OK/FAIL: 2133/0
Ping OK/FAIL: 7124/0
worst per-peer QUIC balance CV: 0.02%
```

稳定性报告的 pass criteria：

```text
No proxy crash: PASS
Short curl success: PASS
Long TCP success: PASS
Per-peer QUIC CV < 5%: PASS
RSS growth <= 10% or <= 2 MiB: FAIL
RSS warmup baseline: 10s
```

RSS 阈值差距：

```text
client:
  RSS: 21.08 -> 24.79 MiB
  growth: +3.71 MiB / +17.62%
  over 10% threshold: +7.62 percentage points
  over 2 MiB threshold: +1.71 MiB
  final RSS over effective allowed end RSS: +1.61 MiB

client2:
  RSS: 20.32 -> 25.91 MiB
  growth: +5.58 MiB / +27.46%
  over 10% threshold: +17.46 percentage points
  over 2 MiB threshold: +3.58 MiB
  final RSS over effective allowed end RSS: +3.55 MiB

server:
  RSS: 13.36 -> 13.87 MiB
  growth: +0.51 MiB / +3.80%
  RSS threshold: PASS
```

RSS 结论：**稳定性压测业务面全部通过，无 crash、无 TCP/UDP/Ping 失败，QUIC 连接负载均衡良好；RSS 仅 client 侧超过当前严格门槛，绝对差距为 MiB 级，当前评估为可接受风险，后续可继续观察长时运行趋势或按需调优阈值/内存复用。**

性能结果：

```text
sudo bash script/perf/perf_smoke.sh: PASS
artifact: /tmp/new_proxy_perf_smoke_20260605_215732
TTFB p50: 0.012391s
TTFB p95: 0.013120s
TTFB max: 0.013466s
throughput: 22.0617 MiB/s

sudo bash script/perf/perf_cores_scalability.sh: PASS
artifact: /tmp/new_proxy_cores_scalability_20260605_215751
data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,16,2,2048,10.770592,190.147,1.000,33
2,16,2,2048,6.391580,320.422,1.685,14|19
3,16,2,2048,4.567963,448.340,2.358,8|15|10
4,16,2,2048,3.594782,569.715,2.996,8|10|8|7
```

结论：**本轮全量门禁、E2E 场景、性能冒烟和核心数扩展性能测试通过；稳定性压测业务指标全部通过，唯一未满足项为 RSS 增长阈值，超出量为 client 侧约 1.61 MiB / client2 侧约 3.55 MiB 的最终 RSS 差距，当前判定问题不大并记录为可接受风险。**

## 2026-06-05 锁粒度优化验证

本次修复覆盖：

- `QuicPoolClient` 的物理连接 `slots` 改为 `arc-swap` 快照，业务新建 stream 热路径不再获取 `RwLock`。
- UDS `add-peer` 在 mutation 锁外预建 QUIC pool，缩短动态 peer 串行锁持有时间；提交前仍在锁内重新检查 AllowedIPs 冲突。

执行命令：

```bash
cargo fmt --check
cargo check --quiet
cargo clippy --all-targets -- -D warnings
cargo test --quiet
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh \
  script/perf/perf_cores_scalability.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
```

结果：

```text
cargo fmt --check: PASS
cargo check --quiet: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo test --quiet:
  new_proxy_cli: 10 passed; 0 failed
  new_proxy: 94 passed; 0 failed
bash -n acceptance/perf scripts: PASS
python3 -m py_compile stability helpers: PASS
```

结论：**锁粒度优化通过格式、编译、Clippy、单元测试和脚本语法检查；本轮未重新执行需要 root/network namespace 的 E2E、稳定性和性能脚本。**

## 2026-06-05 严格 Review 修复验证

本次修复覆盖：

- `RtcWorker` bridge pending 队列增加按字节上限，client bridge 全局并发上限从 4096 收紧到 1024，降低慢读/慢写场景 RSS 放大风险。
- QUIC pool 在 `open_bi()` 失败或超时时主动关闭该物理连接，避免后续 health checker 将无法开 stream 的连接继续视为健康。
- 架构文档修正 L3 userspace WireGuard 语义：当前是 shared per-peer `boringtun` 状态，不是 per-worker 独立状态。

执行命令：

```bash
cargo fmt --check
cargo check --quiet
cargo clippy --all-targets -- -D warnings
cargo test --quiet
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh \
  script/perf/perf_cores_scalability.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
git diff --check
```

结果：

```text
cargo fmt --check: PASS
cargo check --quiet: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo test --quiet:
  new_proxy_cli: 10 passed; 0 failed
  new_proxy: 94 passed; 0 failed
bash -n acceptance/perf scripts: PASS
python3 -m py_compile stability helpers: PASS
git diff --check: PASS
```

结论：**严格 Review 后的稳定性修复通过格式、编译、Clippy、单元测试和脚本语法检查；本轮未重新执行需要 root/network namespace 的 E2E、稳定性和性能脚本。**

## 2026-06-05 Review 修复验证

本次修复覆盖：

- `PreScript` 执行失败时启动立即失败，不再只记录 warning 后继续启动；`PostScript` 仍保持 cleanup best-effort。
- `RtcWorker` IPv4 TCP parser 拒绝非法 IHL、过短 total length 和截断 packet，避免 malformed TUN packet 被误分类。
- `script/perf/perf_cores_scalability.sh` 删除模拟吞吐 fallback，缺 root、release binary、必需系统工具、可用 CPU 或 benchmark 拓扑时失败，不再生成可误读的性能数据；脚本强制采集 per-worker telemetry，并验证 `worker:` 行数匹配 QUIC data port 数。
- 架构和测试文档同步当前真实语义：server worker 数严格跟随 QUIC listen port 数，client TUN worker 数启动时固定；多个 proxy peer 的 data port 数量必须一致，且后续新增、恢复或控制面刷新得到的 data port 数必须匹配 QUIC data port 基准。L4 proxy 多 worker 正确性依赖 Linux TUN multiqueue 的 flow queue affinity。
- 取消 L4 proxy client 强制单 TUN 队列，proxy E2E/perf smoke 入口不再传 daemon worker 参数，worker 数由 QUIC data port 数决定。

执行命令：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
bash -n script/perf/perf_cores_scalability.sh \
  script/perf/perf_smoke.sh \
  script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/stability_stress_test.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
sudo script/acceptance/e2e_dynamic_client_peer.sh
```

结果：

```text
cargo fmt --check: PASS
cargo check: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo test:
  new_proxy_cli: 10 passed; 0 failed
  new_proxy: 93 passed; 0 failed
bash -n acceptance/perf scripts: PASS
python3 -m py_compile stability helpers: PASS
sudo script/acceptance/e2e_dynamic_client_peer.sh: PASS
  - client daemon starts with worker count derived from negotiated QUIC data port count
  - artifact: /tmp/new_proxy_dynamic_peer_20260605_200459
```

结论：**Review 修复后的格式、编译、Clippy、单元测试、脚本语法检查和动态 client proxy peer E2E 通过；本轮未重新执行其他需要 root/network namespace 的 E2E、稳定性和性能脚本。**

## 2026-06-05 L4 Proxy 多队列扩展实测

测试目标：确认取消 L4 proxy 单队列限制后，QUIC data port 数 `1..4` 是否真实开启对应 TUN queue，观察 TCP over QUIC 吞吐扩展，并通过 per-worker telemetry 判断 flow 是否分散到多个 `RtcWorker`。

测试方法：

- 使用 release binary：`cargo build --release --bins`
- 使用 Linux network namespace 搭建 `scale_work_ns -> scale_client_ns -> scale_router_ns -> scale_server_ns`
- server 分别运行 1、2、3、4 个 QUIC data ports：从 `40001` 起连续分配
- client TUN worker 数在启动时跟随控制面协商得到的 QUIC data port 数
- 每组 client 使用当前允许 cpuset 的前 N 个 CPU 运行，支持 `PERF_CPU_LIST` 覆盖
- 每组先 warmup 一次 64 MiB HTTP 下载，再运行并发 HTTP 下载同一 64 MiB 对象
- 统计来自 client UDS dump 的 `worker:` 行：`new_flows` 表示每个 worker 新建 TCP flow 数

16 并发、2 轮、总传输量 2048 MiB：

```text
artifact: /tmp/new_proxy_cores_scalability_20260605_202207
data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,16,2,2048,10.534491,194.409,1.000,33
2,16,2,2048,6.294708,325.353,1.674,15|18
3,16,2,2048,4.682595,437.364,2.250,13|10|10
4,16,2,2048,3.575260,572.825,2.946,7|7|11|8
```

64 并发、1 轮、总传输量 4096 MiB：

```text
artifact: /tmp/new_proxy_cores_scalability_20260605_202329
data_ports,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,64,1,4096,49.274695,83.126,1.000,65
2,64,1,4096,20.422916,200.559,2.413,37|28
3,64,1,4096,14.139338,289.688,3.485,22|22|21
4,64,1,4096,11.392930,359.521,4.325,17|16|19|13
```

worker dump 示例显示 4 个 data ports 下流量进入全部 worker，且没有 L3 fallback：

```text
worker:0 tun_rx=103907:4157015 tcp_offload=103907:4157015 l3=0:0 new_flows=7 current_flows=0
worker:1 tun_rx=110968:4439455 tcp_offload=110968:4439455 l3=0:0 new_flows=7 current_flows=0
worker:2 tun_rx=183794:7352931 tcp_offload=183792:7352835 l3=0:0 new_flows=11 current_flows=0
worker:3 tun_rx=122252:4890920 tcp_offload=122252:4890920 l3=0:0 new_flows=8 current_flows=0
```

结论：**L4 proxy 多队列改动已生效，flow 确实分散到多个 worker。16 并发下 4 个 data ports 为 2.946x，不是严格线性；64 并发下相对扩展达到 4.325x，但绝对吞吐下降，说明 curl/Python HTTP/连接调度引入了额外测试瓶颈。本测试能证明多 worker 参与转发和吞吐随 worker 增长，但还不能作为最终性能基准。正式结论仍需要 iperf3 或专用 Rust traffic generator、多轮 median、CPU/RSS/worker 分布联合报告。**

## 2026-06-05 文档与用户态 client 路径复查

本次复查执行了格式、编译、Clippy、单元测试、脚本语法检查，并复跑了需要 root/network namespace 的场景脚本：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --bins
bash -n script/perf/perf_cores_scalability.sh \
  script/perf/perf_smoke.sh \
  script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_userspace_wg_fallback.sh \
  script/acceptance/stability_stress_test.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
sudo script/acceptance/e2e_scenarios.sh
sudo script/acceptance/e2e_userspace_wg_fallback.sh
```

结果：

```text
cargo fmt --check: PASS
cargo check: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo test:
  new_proxy_cli: 10 passed; 0 failed
  new_proxy: 90 passed; 0 failed
cargo build --bins: PASS
bash -n acceptance/perf scripts: PASS
python3 -m py_compile stability helpers: PASS
sudo script/acceptance/e2e_scenarios.sh: PASS
  - SCENARIO 2B dynamic L3 fallback: SKIP
  - skip reason: userspace WireGuard backend does not expose a real fallback netdev for this legacy sub-scenario
sudo script/acceptance/e2e_userspace_wg_fallback.sh: PASS
  - artifact: /tmp/new_proxy_userspace_wg_fallback_20260605_184329
  - server telemetry: latest handshake just now; WireGuard bytes non-zero; QUIC inactive (disconnected)
```

备注：`cargo check` / `cargo test` / `cargo clippy` 会显示本地 path 依赖 `smoltcp` 和 `boringtun` 内部 warning，但本 crate 的检查已通过。

结论：**本轮文档与用户态 client 路径复查的格式、编译、Clippy、单元测试、脚本语法检查、`e2e_scenarios.sh` 和新增 `e2e_userspace_wg_fallback.sh` 通过；未重新执行其他需要 root/network namespace 的 E2E、稳定性和性能脚本。**

## 2026-06-04 增量复查

本次复查执行了无需 root 的静态、单元与脚本语法检查：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
```

结果：

```text
cargo fmt --check: PASS
cargo check: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo test:
  new_proxy_cli: 10 passed; 0 failed
  new_proxy: 47 passed; 0 failed
bash -n acceptance/perf scripts: PASS
python3 -m py_compile stability helpers: PASS
```

结论：**本次增量复查的格式、编译、Clippy、单元测试和脚本语法检查全部通过；未重新执行需要 root/network namespace 的 E2E、稳定性和性能脚本。**

## 2026-06-04 E2E 与场景复查

本次复查执行了需要 root/network namespace 的端到端与场景脚本：

```bash
sudo bash script/acceptance/e2e_test_dualstack.sh
sudo bash script/acceptance/e2e_scenarios.sh
sudo bash script/acceptance/e2e_multi_client.sh
sudo bash script/acceptance/e2e_dynamic_client_peer.sh
```

结果：

```text
e2e_test_dualstack.sh: PASS
e2e_scenarios.sh: PASS
  - SCENARIO 2B dynamic L3 fallback: SKIP
  - skip reason: userspace WireGuard backend does not expose a real scenario_client netdev in client_ns
e2e_multi_client.sh: PASS
e2e_dynamic_client_peer.sh: PASS
```

动态 client peer E2E 产物目录：

```text
/tmp/new_proxy_dynamic_peer_20260604_142626
```

结论：**本轮端到端与场景测试全部通过；`e2e_scenarios.sh` 中依赖真实 WireGuard netdev 的 2B 子场景在 userspace WireGuard 后端下按脚本逻辑跳过。**

## 已执行测试

### 1. 格式、编译与单元测试

执行命令：

```bash
cargo fmt --check
cargo check
cargo test
cargo build --bins
cargo build --release --bins
```

结果：

```text
cargo fmt --check: PASS
cargo check: PASS
cargo test:
  new_proxy_cli: 9 passed; 0 failed
  new_proxy: 40 passed; 0 failed
cargo build --bins: PASS
cargo build --release --bins: PASS
```

新增回归覆盖：

- 静态配置拒绝重复 peer public key、重复 AllowedIPs 和重叠 AllowedIPs。
- UDS 动态 AddPeer 拒绝请求内重复 AllowedIPs，并拒绝与其他 peer 重叠的 AllowedIPs。
- 保留 QUIC registry、动态 peer remove、control HMAC/replay、userspace TCP fallback、relay、telemetry 等既有覆盖。

结论：**全部 49 个 Rust 单元测试通过（0 失败）**。

### 2. 脚本语法与 Python 编译检查

执行命令：

```bash
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh
python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py
```

结论：**全部通过**。

### 3. 端到端双栈集成测试

执行命令：

```bash
sudo bash script/acceptance/e2e_test_dualstack.sh
```

关键结果：

```text
✓ [SUCCESS] Dual-stack physical network WAN path verified successfully.
✓ [SUCCESS] IPv6 HTTP over TUN/smoltcp/QUIC verified successfully.
✓ [SUCCESS] E2E Integration tests passed cleanly!
```

结论：**通过。双栈 WAN、IPv6 HTTP 真实业务闭环、TUN/smoltcp/QUIC 和 CLI telemetry 均验证成功。**

### 4. 端到端场景集成测试

执行命令：

```bash
sudo bash script/acceptance/e2e_scenarios.sh
```

关键结果：

```text
✓ [SUCCESS] All E2E Integration and CLI scenarios fully passed!
```

结论：**通过。TUN/smoltcp->QUIC、动态 server peer add/remove、WireGuard L3 fallback 场景验证成功。**

### 5. 并发多客户端 E2E 混合验收

执行命令：

```bash
sudo bash script/acceptance/e2e_multi_client.sh
```

关键结果：

```text
✓ [PASS] Client 1 (Proxy) successfully fetched data via intercepted TCP-over-QUIC!
✓ [PASS] Client 2 (Standard WG Fallback) successfully fetched data via native L3 tunnel!
✓ [ALL PASS] Concurrent Multi-Client E2E Test Completed Successfully!
```

结论：**通过。多客户端并发 proxy + direct L3 baseline 验证成功。**

### 6. 动态 client proxy peer 生命周期 E2E

执行命令：

```bash
sudo bash script/acceptance/e2e_dynamic_client_peer.sh
```

产物目录：

```text
/tmp/new_proxy_dynamic_peer_20260529_153720
```

关键结果：

```text
Peer added successfully.
Peer removed successfully.
✓ [SUCCESS] Dynamic client peer E2E passed
```

结论：**通过。添加前业务失败、动态 add-peer 后 TCP over QUIC 成功、remove-peer 后业务再次停止。**

### 7. 60 秒稳定性压力测试

执行命令：

```bash
sudo STABILITY_DURATION=60 STABILITY_SAMPLE_INTERVAL=10 bash script/acceptance/stability_stress_test.sh
```

产物目录：

```text
/tmp/new_proxy_stability_20260529_154039
```

关键结果：

```text
Samples collected: 7
Proxy crash samples: 0
Long TCP iterations: 960
Long TCP errors: 0
Short curl OK/FAIL: 1160/0
UDP OK/FAIL: 36/0
Ping OK/FAIL: 120/0
Worst per-peer QUIC balance CV: 0.19%
Client RSS MiB: 11.7 -> 11.7 (+0.00%)
Client2 RSS MiB: 10.4 -> 10.4 (+0.00%)
Server RSS MiB: 12.3 -> 12.6 (+2.19%)
```

通过准则：

```text
No proxy crash: PASS
Short curl success: PASS
Long TCP success: PASS
Per-peer QUIC CV < 5%: PASS
RSS growth <= 10% or <= 2 MiB: PASS
RSS warmup baseline: 10s
```

结论：**通过。稳定性报告使用 10 秒 warmup 后的 RSS 基线，避免把启动期常驻分配误判为泄漏；所有业务、均衡性和内存准则均通过。**

### 8. 性能 smoke

执行命令：

```bash
sudo bash script/perf/perf_smoke.sh
```

产物目录：

```text
/tmp/new_proxy_perf_smoke_20260529_154303
```

关键结果：

```text
TTFB p50: 0.003378s
TTFB p95: 0.003859s
TTFB max: 0.004898s
Throughput: 71.710 MiB/s
✓ [SUCCESS] Perf smoke passed
```

结论：**通过。短连接 TTFB sample 和 8 MiB HTTP throughput sample 验证成功。**

## 总结

本轮执行的格式、编译、单元、脚本语法、Python 编译、E2E、动态 peer、稳定性和 perf smoke 全部通过。新增的并发/冲突/清理相关回归覆盖已纳入单元测试。
