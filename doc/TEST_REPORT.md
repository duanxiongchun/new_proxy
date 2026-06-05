# 测试报告

## 测试概览

- 项目版本：`new_proxy v5.0.0`
- 报告日期：2026-06-05
- 主要测试对象：配置冲突校验、UDS API/server、TUN/smoltcp TCP 分流、QUIC 物理连接池、控制面 HMAC/nonce、防重放、动态 peer 并发/冲突防护、聚合遥测、稳定性与 perf smoke
- 测试环境：单机 Linux Network Namespace 三/四节点拓扑
- 测试拓扑：`client_ns -> router_ns -> server_ns`、`client1_ns + client2_ns -> router_ns -> server_ns`、动态 peer/perf/stability 专用 namespace

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
