# 测试报告

## 测试概览

- 项目版本：`new_proxy v5.0.0`
- 报告日期：2026-05-29
- 主要测试对象：双轨代理网关、TPROXY TCP 分流、4 路 QUIC 物理连接池、聚合遥测、长稳压测脚本
- 测试环境：单机 Linux Network Namespace 三节点拓扑
- 测试拓扑：`client_ns -> router_ns -> server_ns`

## 已执行测试

### 1. 编译检查

执行命令：

```bash
cargo check
```

结果：

```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.08s
```

结论：通过。

### 2. 脚本语法检查

执行命令：

```bash
bash -n script/acceptance/e2e_scenarios.sh
bash -n script/acceptance/e2e_test_dualstack.sh
bash -n script/acceptance/stability_stress_test.sh
```

结论：通过。

### 3. 30 秒稳定性 Smoke Test

执行命令：

```bash
sudo STABILITY_DURATION=30 STABILITY_SAMPLE_INTERVAL=5 script/acceptance/stability_stress_test.sh
```

产物目录：

```text
/tmp/new_proxy_stability_20260528_203536
```

关键结果：

```text
Samples collected: 7
Proxy crash samples: 0
Long TCP iterations: 240
Long TCP errors: 0
Short curl OK/FAIL: 116/0
UDP OK/FAIL: 6/0
Ping OK/FAIL: 15/0
QUIC balance CV: 0.38%
Client RSS MiB: 11.4 -> 11.4 (+0.00%)
Server RSS MiB: 10.3 -> 10.3 (+0.19%)
```

结论：通过。基础链路、TPROXY 拦截、QUIC 分流、遥测采样和报告生成均正常。

### 4. 1 小时长稳与多路复用负载均衡测试

执行命令：

```bash
sudo script/acceptance/stability_stress_test.sh
```

产物目录：

```text
/tmp/new_proxy_stability_20260528_203810
```

关键结果：

```text
Samples collected: 121
Proxy crash samples: 0
Long TCP iterations: 28776
Long TCP errors: 0
Short curl OK/FAIL: 14124/0
UDP OK/FAIL: 717/0
Ping OK/FAIL: 1793/0
QUIC balance CV: 0.00%
Client RSS MiB: 12.9 -> 13.1 (+1.97%)
Server RSS MiB: 9.7 -> 10.7 (+10.38%)
```

4 路 QUIC 物理连接流量分布：

```text
Port 40001: tx=7638620 rx=12191368 total=19829988 share=25.00% active_streams=0
Port 40002: tx=7638543 rx=12190002 total=19828545 share=25.00% active_streams=0
Port 40003: tx=7638543 rx=12190002 total=19828545 share=25.00% active_streams=0
Port 40004: tx=7638543 rx=12190002 total=19828545 share=25.00% active_streams=0
```

通过准则：

```text
No proxy crash: PASS
Short curl success: PASS
Long TCP success: PASS
QUIC CV < 5%: PASS
RSS growth <= 10%: FAIL
```

结论：

- 进程稳定性通过：1 小时内客户端和服务端代理均无崩溃。
- 流量可靠性通过：长连接、短连接、UDP、ICMP 均无失败记录。
- 负载均衡通过：4 路 QUIC 物理连接流量份额均为 25.00%，CV 为 0.00%。
- 内存稳定性存在边界问题：服务端 RSS 增长 10.38%，比测试准则 `<= 10%` 高 0.38%，该项判定失败。

### 5. 并发多客户端及对等体双向自适应互补同步测试

网关对并发多客户端拓扑与双向自适应互补同步功能执行了端到端闭环验证。执行命令：

```bash
sudo script/acceptance/e2e_multi_client.sh
```

关键输出：
* **Client 1 (Proxy) [定制代理客户端]** 流量被 TPROXY 成功拦截，产生了非零 L4/QUIC Telemetry 数据：
  * `quic transfer`: `775 B received, 77 B sent`
  * `source` 标识: `"both"`（在配置与内核中均存在，正常建立 2 条物理 QUIC 连接）
* **Client 2 (WG Fallback) [标准 WireGuard 客户端]** 采用不对称配置方式（有意将其排除在 `server_multi.conf` 配置文件外），成功通过内核 `wg` 接口在服务运行时被动态捕获发现，**自动同步/补全至网关用户态 GatewayConfig 配置列表并热重建 AllowedIPs LPM 路由基数树**，完成了对等 Noise_IK 握手密钥的实时计算：
  * `wireguard transfer`: `12.21 KiB received, 8.20 KiB sent`
  * `source` 标识: 在第一次遥测查询时准确输出为 `"kernel"` 代表其前置状态，随后自适应持久化对齐为 `"both"`。
* **1 小时并发多客户端长稳压测**：更新了 `stability_stress_test.sh` 脚本，并发压测 Client 1（QUIC 卸载 TCP 连接）与 Client 2（标准 L3 隧道原生 fallback 连接），在 1 小时的连续重载下，自适应双向互补同步机制在首个采样秒便瞬时完成了不对称对等体的补全，随后稳定保持在对齐状态，未发生任何崩溃或性能抖动。

结论：完全通过。混合多对等体下的业务状态隔离完备，动态状态自愈和自适应对齐功能运行稳定。

## 当前风险与后续建议

1. 服务端 RSS 增长接近阈值，建议增加更长周期的 4 小时 or 24 小时压测，确认该增长是一次性稳定增长还是持续泄漏。
2. 建议补充服务端内存采样细分，例如 jemalloc heap profile、`/proc/<pid>/smaps_rollup`、tokio task 数量和 QUIC registry 长度。
3. 建议将 CI 中的 smoke test 时长固定为 30 秒，将 1 小时长稳作为夜间或手动 acceptance 测试执行。
