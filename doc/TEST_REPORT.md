# 测试报告

## 测试概览

- 项目版本：`new_proxy v5.0.0`
- 报告日期：2026-05-29
- 主要测试对象：双轨代理网关、TPROXY TCP 分流、QUIC 物理连接池、控制面 HMAC/nonce、防重放、动态 peer、聚合遥测、稳定性与 perf smoke
- 测试环境：单机 Linux Network Namespace 三/四节点拓扑
- 测试拓扑：`client_ns -> router_ns -> server_ns`、`client1_ns + client2_ns -> router_ns -> server_ns`、动态 peer/perf 专用 work namespace

## 已执行测试

### 1. 格式、编译与单元测试

执行命令：

```bash
cargo fmt --check
cargo check
cargo test
cargo build
```

结果：

```text
cargo fmt --check: PASS
cargo check: PASS
cargo test:
  new_proxy_cli: 6 passed; 0 failed
  new_proxy: 35 passed; 0 failed
cargo build: PASS
```

结论：**全部 41 个 Rust 单元测试通过（0 失败）**。

### 2. 脚本语法与 Python 编译检查

执行命令：

```bash
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh
python3 -m py_compile script/acceptance/stability_report.py
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
✓ [SUCCESS] IPv6 HTTP over TPROXY/QUIC verified successfully.
✓ [SUCCESS] E2E Integration tests passed cleanly!
```

结论：**通过。双栈 WAN、IPv6 HTTP 真实业务闭环、TPROXY/QUIC 和 CLI telemetry 均验证成功。**

### 4. 端到端场景集成测试

执行命令：

```bash
sudo bash script/acceptance/e2e_scenarios.sh
```

关键结果：

```text
✓ [SUCCESS] All E2E Integration and CLI scenarios fully passed!
```

结论：**通过。TPROXY->QUIC、动态 server peer add/remove、WireGuard L3 fallback 场景验证成功。**

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

结论：**通过。多客户端并发 proxy + WireGuard-only fallback 验证成功。**

### 6. 动态 client proxy peer 生命周期 E2E

执行命令：

```bash
sudo bash script/acceptance/e2e_dynamic_client_peer.sh
```

产物目录：

```text
/tmp/new_proxy_dynamic_peer_20260529_140140
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
/tmp/new_proxy_stability_20260529_140424
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
Client RSS MiB: 10.9 -> 12.0 (+9.82%)
Client2 RSS MiB: 11.4 -> 13.1 (+15.25%)
Server RSS MiB: 14.4 -> 16.1 (+11.71%)
```

通过准则：

```text
No proxy crash: PASS
Short curl success: PASS
Long TCP success: PASS
Per-peer QUIC CV < 5%: PASS
RSS growth <= 10% or <= 2 MiB: PASS
```

结论：**通过。稳定性报告脚本按 per-peer QUIC CV 计算均衡性，并用百分比或小绝对 RSS 增长阈值避免低基线误判。**

### 8. 性能 smoke

执行命令：

```bash
sudo bash script/perf/perf_smoke.sh
```

产物目录：

```text
/tmp/new_proxy_perf_smoke_20260529_140620
```

关键结果：

```text
TTFB p50: 0.003113s
TTFB p95: 0.003582s
TTFB max: 0.004860s
Throughput: 73.394 MiB/s
✓ [SUCCESS] Perf smoke passed
```

结论：**通过。短连接 TTFB sample 和 8 MiB HTTP throughput sample 验证成功。**

## 总结

本轮执行的格式、编译、单元、脚本语法、E2E、稳定性和 perf smoke 全部通过。
