# new_proxy 测试说明与缺口清单

本文档按当前代码和脚本维护测试现状。已实现测试列入覆盖矩阵；未实现能力放在 backlog。

## 1. 当前测试入口

### Rust 静态与单元测试

```bash
cargo fmt --check
cargo check
cargo test
```

当前单元测试分布：

- `src/api.rs`：UDS API command/response 类型和 raw/framed 兼容读写。
- `src/app_config.rs`：runtime mode/config validation、interface/socket path、L4 router rebuild、telemetry source 合并、base64 helper。
- `src/client_proxy.rs`：client-side TPROXY accept loop、AllowedIPs 匹配、QUIC mux stream 打开、client QUIC pool 构建与 TCP relay。
- `src/cli.rs`：CLI 输出格式、UDS 命令编码、CLI 错误返回。
- `src/config.rs`：配置解析、base64 key 解析、非法地址。
- `src/control.rs`：HMAC roundtrip、控制面协商、错误 HMAC、请求重放、stale `client_nonce` 响应拒绝。
- `src/main.rs`：mock peer sync 跨模块状态同步。
- `src/proxy_proto.rs`：QUIC mux 目标地址头部 IPv4/IPv6 编解码。
- `src/runtime.rs`：路由、policy routing、TPROXY、MSS clamp、pre/post script runtime setup/cleanup。
- `src/server_proxy.rs`：server-side QUIC mux stream 目标 TCP connect、状态回写和 relay。
- `src/stats_cli.rs`：`new_proxy stats` 内置 telemetry table 输出、byte formatter。
- `src/tcp_util.rs`：TCP keepalive socket option helper。
- `src/telemetry.rs`：统一 telemetry DTO 和 sharded L4 telemetry registry。
- `src/quic_pool.rs`：自签证书生成、QUIC client/server 集成、证书 pinning 失败路径、空 endpoint pool 拒绝、服务端重启后控制面刷新与 QUIC pool 自动恢复、QUIC pool fallback/recovering/active 状态。
- `src/main.rs`：TPROXY failover policy，确认任意 pool 处于 fallback/recovering 时不恢复 TPROXY，所有 pool active 后才允许回切。
- `src/relay.rs`：双向 relay、计数 reader。
- `src/routing.rs`：AllowedIPs longest-prefix matching。
- `src/tproxy.rs`：IPv4/IPv6 transparent listener 创建。
- `src/uds_server.rs`：真实 UDS server 的 `Stats`、`Dump`、非法请求响应和 remove-peer 缓存清理。
- `src/wireguard.rs`：WireGuard generic netlink 查询/同步、mock dump fixture 解析、缺失 interface 空结果、sockaddr roundtrip。

### Acceptance / E2E 脚本

这些脚本需要 root、Linux network namespace、`iproute2`、`iptables`/`ip6tables`、`curl`、`python3`。

```bash
sudo bash script/acceptance/e2e_test_dualstack.sh
sudo bash script/acceptance/e2e_scenarios.sh
sudo bash script/acceptance/e2e_multi_client.sh
sudo bash script/acceptance/e2e_dynamic_client_peer.sh
sudo STABILITY_DURATION=60 STABILITY_SAMPLE_INTERVAL=10 bash script/acceptance/stability_stress_test.sh
sudo bash script/perf/perf_smoke.sh
```

语法检查：

```bash
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/stability_stress_test.sh \
  script/perf/perf_smoke.sh
python3 -m py_compile script/acceptance/stability_report.py
```

## 2. 当前覆盖情况

| 层级 | 已覆盖 | 主要缺口 |
| --- | --- | --- |
| 单元测试 | 配置解析、HMAC 控制面、控制面 stale nonce/重放/坏 HMAC、非法 public IP、空 QUIC pool、QUIC pinning、relay、router、UDS 协议兼容、真实 UDS server stats/dump/error、telemetry registry、TPROXY fallback 回切策略 | `setup_peer_routes_and_tproxy()`/`cleanup_peer_routes_and_tproxy()` 的命令级断言仍主要依赖 E2E |
| E2E | 双栈 WAN、IPv6 HTTP over TPROXY/QUIC、TPROXY->QUIC、服务端重启后客户端自动重连、动态 server peer add/remove、多客户端 proxy+WireGuard-only fallback、动态 client proxy peer add/remove 生命周期、server 主动访问 client 后端时回程不被 TPROXY 拦截 | 服务端 session rotation/peer removal 的长流关闭与恢复还没有独立 E2E |
| 稳定性 | 多 client、两条独立 proxy peer、WireGuard-only fallback、长/短 TCP、UDP、ping、warmup 后 RSS、per-peer QUIC CV | 还没有 1 小时 CI 固化结果；没有 FD 数、CPU 斜率、失败日志自动摘要 |
| 性能 | `script/perf/perf_smoke.sh` 覆盖 TTFB sample 和 8 MiB throughput sample | 缺正式吞吐、延迟、CPU、连接建立耗时基准和并发阶梯压测 |
| 弱网/混沌 | 无正式脚本 | 缺丢包、端口阻断、服务端重启、session rotation、控制面丢包场景 |
| 安全负向 | 控制面坏 HMAC/重放/stale nonce、QUIC 证书 pinning、空 endpoint pool | 缺恶意响应、错误端口池、超大 UDS payload、未授权 peer 的 E2E |

## 3. 已补的重点测试

### 3.1 动态 client proxy peer 生命周期

`script/acceptance/e2e_dynamic_client_peer.sh` 覆盖：

1. client 以 WireGuard-only 配置启动，但保留 `TProxyPort`。
2. 添加前 workload namespace 访问目标 TCP 失败。
3. 调用 client UDS `add-peer <server_pub> <allowed_ips> <endpoint> <proxy_port>`。
4. 验证 client 创建 QUIC pool，workload TCP 被 TPROXY 后成功走 QUIC。
5. server namespace 绑定 `10.0.0.1` 源地址主动访问 client 后端 workload 服务，验证 SYN-ACK 回程穿过 client gateway 时不会命中 TPROXY 规则。
6. 调用 client UDS `remove-peer`。
7. 验证后续 TCP 不再进入 QUIC。

### 3.2 控制面负向与重试

Rust 单元测试覆盖：

- 控制面响应 `client_nonce` 不匹配必须被拒绝。
- 重放相同 `ControlRequest` 无响应。
- 错误 HMAC 控制请求无响应。
- 非法 `PublicIPv4`/`PublicIPv6` 导致 client 明确失败。
- 空 QUIC endpoint pool 导致 pool 构建失败。

### 3.3 TPROXY 与 WireGuard-only 边界

当前覆盖：

- `rebuild_l4_router()` 只纳入同时配置 `Endpoint` 和 `ProxyPort` 的 peer。
- 同一 client 配置中同时存在 proxy peer 和 WireGuard-only peer。
- 访问 proxy peer `AllowedIPs` 走 QUIC。
- 访问 WireGuard-only peer `AllowedIPs` 不走 QUIC。
- client gateway 的 TPROXY 规则只匹配客户端侧主动发起的初始 SYN；server 主动访问 client 后端时，回程 SYN-ACK 不进入代理。

### 3.4 UDS server 模块拆分

Rust 单元测试覆盖：

- UDS raw JSON request 与 framed request 的兼容读写。
- 非法 framed payload length 被拒绝。
- 独立 `uds_server` 启动后可基于 `UdsServerContext` 返回 `Stats` 聚合 telemetry。
- 独立 `uds_server` 启动后可返回 `Dump` 文本快照。
- 非法 JSON request 返回 `ApiResponse { status: "Error" }`。
- remove-peer 相关 peer secrets、session cache、nonce cache 同步清理。

### 3.5 IPv6 真实业务闭环

`script/acceptance/e2e_test_dualstack.sh` 覆盖：

- IPv6 HTTP server 监听。
- IPv6 `AllowedIPs` 命中 client namespace TPROXY。
- router namespace 使用 `curl -g http://[fd00::1]:8080/` 发起真实 TCP。
- server telemetry 中出现 QUIC L4 字节。

### 3.6 服务端重启后的客户端自动恢复

`script/acceptance/e2e_scenarios.sh` 覆盖 namespace 级真实进程恢复：

1. client/server daemon 先完成 TPROXY -> QUIC 业务流量。
2. 测试 kill server daemon 并重新启动 server daemon，触发新自签证书和新 session cache。
3. 等待 client health checker 自愈。
4. 从 router namespace 发起新 TCP 请求，验证业务恢复。
5. 通过 server UDS stats 检查 `quic: active`。

`src/quic_pool.rs::test_health_checker_refreshes_control_config_after_server_restart` 额外覆盖 pool 层控制面刷新细节：

1. 客户端先使用旧 `session_psk`、旧 QUIC 证书指纹和旧端口建立连接。
2. 测试模拟服务端重启后旧 session 失效，并关闭旧物理连接。
3. 健康检查按旧配置重连失败后重新走控制面协商。
4. 客户端获得新的 `session_psk`、QUIC 证书指纹和端口池，替换本地 runtime config 与连接池。
5. 新业务 stream 在新 QUIC 服务端上成功 echo。

### 3.7 QUIC 故障后的 WireGuard fallback 与延迟回切

当前代码路径：

1. QUIC stream 打开失败、目标地址写入失败、或 server proxy 状态读取失败时，client 将对应 pool 标记为 `Fallback`。
2. `Table != off` 的 client mode TPROXY failover manager 观察所有 proxy pool 状态。
3. 任意 pool 为 `Fallback` 或 `Recovering` 时，manager 删除当前配置中所有 proxy peer 的 TPROXY/TCPMSS 规则，保留 WireGuard route。
4. 后续新 TCP 连接不再进入用户态 TPROXY，自然走 WireGuard/wireguard-go L3。
5. 启动时缺失 QUIC pool 不再导致 client 退出；manager 周期性重建缺失 pool。
6. QUIC 连接恢复后先进入 `Recovering` cooldown，cooldown 结束并回到 `Active` 后，manager 按当前配置重建所有 proxy peer 的 TPROXY 规则。

`Table = off` 不由 daemon 管理 iptables；这类拓扑只验证 QUIC 重连、动态 peer 生命周期和手工规则路径，不验证自动删除/恢复 TPROXY。

Rust 单元测试覆盖：

- `src/main.rs::test_tproxy_failover_policy_requires_all_pools_active`：确认只有所有 pool 都是 `Active` 时才允许恢复 TPROXY；`Fallback` 和 `Recovering` 都保持 WireGuard fallback。

## 4. Backlog

- 服务端 session rotation / peer removal E2E：建立长 TCP 流，server `remove-peer`，验证旧 QUIC 连接关闭、新 stream 失败，重新 `add-peer` 后新 TCP 成功。
- 弱网脚本：对单个 QUIC UDP port 下发 `DROP`，验证新 stream 继续使用其他健康 port；控制面 UDP 丢第一包后重试新 nonce 成功。
- 性能脚本：正式 throughput、TTFB、CPU/RSS、连接建立耗时、并发 1k/4k/8k 阶梯压测。
- 稳定性脚本：1 小时 nightly/profile、FD 数、CPU 累计时间、失败日志自动打包、机器可读 pass/fail 总结。
- 安全负向：恶意响应、错误端口池、超大 UDS payload、未授权 peer 的 E2E。

## 5. 文档同步规则

以后改架构时至少同步：

- `doc/ARCHITECTURE.md`：只写当前代码真实行为。
- `doc/TESTING.md`：更新覆盖矩阵和缺口。
- `doc/TEST_REPORT.md`：只记录已经执行过的命令、日期、环境和结果。
- README：只保留用户安装、配置和运行需要知道的信息。
