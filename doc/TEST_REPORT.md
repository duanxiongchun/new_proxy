# 测试报告

## 测试概览

- 项目版本：`new_proxy v5.0.0`
- 报告日期：2026-06-05
- 主要测试对象：配置冲突校验、UDS API/server、TUN/smoltcp TCP 分流、QUIC 物理连接池、控制面 HMAC/nonce、防重放、动态 peer 并发/冲突防护、聚合遥测、稳定性与 perf smoke
- 测试环境：单机 Linux Network Namespace 三/四节点拓扑
- 测试拓扑：`client_ns -> router_ns -> server_ns`、`client1_ns + client2_ns -> router_ns -> server_ns`、动态 peer/perf/stability 专用 namespace

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
- `script/perf/perf_cores_scalability.sh` 删除模拟吞吐 fallback，缺 root、release binary、必需系统工具、可用 CPU 或 benchmark 拓扑时失败，不再生成可误读的性能数据；脚本强制采集 per-worker telemetry，并验证 `worker:` 行数匹配 `--threads`。
- 架构和测试文档同步当前真实语义：client 按 `--threads` 使用多队列；L4 proxy 多 worker 正确性依赖 Linux TUN multiqueue 的 flow queue affinity。
- 取消 L4 proxy client 强制单 TUN 队列，已有 proxy E2E/perf smoke 入口改为使用 `--threads 4` 启动 client。

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
  - client daemon uses --threads 4
  - artifact: /tmp/new_proxy_dynamic_peer_20260605_200459
```

结论：**Review 修复后的格式、编译、Clippy、单元测试、脚本语法检查和 `--threads 4` 动态 client proxy peer E2E 通过；本轮未重新执行其他需要 root/network namespace 的 E2E、稳定性和性能脚本。**

## 2026-06-05 L4 Proxy 多队列扩展实测

测试目标：确认取消 L4 proxy 单队列限制后，`--threads 1..4` 是否真实开启对应 TUN queue，观察 TCP over QUIC 吞吐扩展，并通过 per-worker telemetry 判断 flow 是否分散到多个 `RtcWorker`。

测试方法：

- 使用 release binary：`cargo build --release --bins`
- 使用 Linux network namespace 搭建 `scale_work_ns -> scale_client_ns -> scale_router_ns -> scale_server_ns`
- server 运行 4 个 QUIC data ports：`40001..40004`
- client 分别以 `--threads 1`、`--threads 2`、`--threads 3`、`--threads 4` 启动
- 每组 client 使用当前允许 cpuset 的前 N 个 CPU 运行，支持 `PERF_CPU_LIST` 覆盖，`--threads=N`
- 每组先 warmup 一次 64 MiB HTTP 下载，再运行并发 HTTP 下载同一 64 MiB 对象
- 统计来自 client UDS dump 的 `worker:` 行：`new_flows` 表示每个 worker 新建 TCP flow 数

16 并发、2 轮、总传输量 2048 MiB：

```text
artifact: /tmp/new_proxy_cores_scalability_20260605_202207
threads,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,16,2,2048,10.534491,194.409,1.000,33
2,16,2,2048,6.294708,325.353,1.674,15|18
3,16,2,2048,4.682595,437.364,2.250,13|10|10
4,16,2,2048,3.575260,572.825,2.946,7|7|11|8
```

64 并发、1 轮、总传输量 4096 MiB：

```text
artifact: /tmp/new_proxy_cores_scalability_20260605_202329
threads,parallel,rounds,total_mib,seconds,mib_per_s,relative_to_1,worker_new_flows
1,64,1,4096,49.274695,83.126,1.000,65
2,64,1,4096,20.422916,200.559,2.413,37|28
3,64,1,4096,14.139338,289.688,3.485,22|22|21
4,64,1,4096,11.392930,359.521,4.325,17|16|19|13
```

worker dump 示例显示 4 threads 下流量进入全部 worker，且没有 L3 fallback：

```text
worker:0 tun_rx=103907:4157015 tcp_offload=103907:4157015 l3=0:0 new_flows=7 current_flows=0
worker:1 tun_rx=110968:4439455 tcp_offload=110968:4439455 l3=0:0 new_flows=7 current_flows=0
worker:2 tun_rx=183794:7352931 tcp_offload=183792:7352835 l3=0:0 new_flows=11 current_flows=0
worker:3 tun_rx=122252:4890920 tcp_offload=122252:4890920 l3=0:0 new_flows=8 current_flows=0
```

结论：**L4 proxy 多队列改动已生效，flow 确实分散到多个 worker。16 并发下 4 threads 为 2.946x，不是严格线性；64 并发下相对扩展达到 4.325x，但绝对吞吐下降，说明 curl/Python HTTP/连接调度引入了额外测试瓶颈。本测试能证明多 worker 参与转发和吞吐随 worker 增长，但还不能作为最终性能基准。正式结论仍需要 iperf3 或专用 Rust traffic generator、多轮 median、CPU/RSS/worker 分布联合报告。**

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
