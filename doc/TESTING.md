# new_proxy 测试说明与缺口清单

本文档按当前代码和脚本维护测试现状。已实现测试列入覆盖矩阵；未实现能力放在 backlog。

## 1. 当前测试入口

### Rust 静态与单元测试

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

当前单元测试分布：

- `src/api.rs`：UDS API command/response 类型和 raw/framed 兼容读写。
- `src/app_config.rs`：runtime mode/config validation、interface/socket path、L4 router rebuild、telemetry source 合并、base64 helper。
- `src/client_proxy.rs`：client QUIC pool 构建与 userspace stream bridge；主要由 `main`、`uds_server` 和 `quic_pool` 测试间接覆盖。
- `src/cli.rs`：CLI 输出格式、UDS 命令编码、CLI 错误返回。
- `src/config.rs`：配置解析、base64 key 解析、非法地址。
- `src/control.rs`：HMAC roundtrip、控制面协商、错误 HMAC、请求重放、stale `client_nonce` 响应拒绝。
- `src/main.rs`：mock peer sync 跨模块状态同步。
- `src/proxy_proto.rs`：QUIC mux 目标地址头部 IPv4/IPv6 编解码。
- `src/rtc_loop.rs`：RTC packet classification、IPv6 短 TCP 包拒绝、`RtcWorker` 创建、smoltcp 出站包回写 TUN、IPv4/IPv6 NAT checksum 重算、bridge pending 队列字节上限、QUIC bridge 原始目标地址反查、QUIC bridge 使用 worker-local `Notify` waker 唤醒 RTC loop、QUIC 不可用时 TCP fallback 到 userspace WireGuard。
- `src/runtime.rs`：TUN 地址、peer 路由、endpoint bypass route、pre/post script runtime setup/cleanup。
- `src/server_proxy.rs`：server-side QUIC mux stream 目标 TCP connect、状态回写和 relay。
- `src/stats_cli.rs`：`new_proxy stats` 内置 telemetry table 输出、byte formatter。
- `src/tcp_util.rs`：TCP keepalive socket option helper。
- `src/telemetry.rs`：统一 telemetry DTO 和 sharded L4 telemetry registry。
- `src/tun_device.rs`：Linux TUN 打开、单队列/多队列权限失败边界。
- `src/tun_io.rs`：基于 `AsyncFd` 的 TUN 异步读写。
- `src/userspace_tcp.rs`：smoltcp 用户态 TCP/IP 栈创建、socket buffer 与 socket handle 生命周期。
- `src/userspace_wg.rs`：boringtun tunnel 状态初始化。
- `src/virtual_tunnel.rs`：空物理 socket 集拒绝、RTC receive path 不预取业务包、调用方 buffer 直接接收、双物理 UDP socket 直接 readiness 接收、发送使用当前 active socket、不创建后台 task，并验证 `tick_control()` 发送 PING/处理 PONG 后切换 active socket。
- `src/quic_pool.rs`：自签证书生成、QUIC client/server 集成、证书 pinning 失败路径、空 endpoint pool 拒绝、服务端重启后控制面刷新与 QUIC pool 自动恢复、旧 QUIC data port 不可达后的控制面刷新恢复、控制面刷新拒绝 data port 数变化、QUIC pool fallback/recovering/active 状态、控制面刷新触发条件和退避；server-side data port listener 使用 ready queue 推进 connection/stream future，并验证只重新 poll 被唤醒 future、self-wake 延迟到下一轮、完成任务槽位复用、旧 waker 不会误唤醒复用后的槽位、每轮 ready poll 有预算上限。
- `src/main.rs`：userspace TCP failover policy，确认任意 pool 处于 fallback/recovering 时不恢复 TCP offload，所有 pool active 后才允许回切；client 启动主 runtime 前预协商 QUIC data port 数，TUN worker、Tokio runtime worker 和 QUIC data port baseline 使用同一个固定宽度；多个 proxy peer 的启动期协商端口数不一致时拒绝启动，启动期无法获知端口数时固定为单队列 baseline，后续动态新增或后台恢复不能改变拓扑；WireGuard UDP receive/timer 只归属 worker 0；服务端 QUIC 数据面只允许 client health checker 和固定 listener task，业务 stream 由 event-driven `ServerFutures` 推进；入口不使用 `#[tokio::main]` 默认 runtime。
- `src/relay.rs`：双向 relay、计数 reader；双向 relay 在单个 future 内推进，不为两个方向创建额外 task；并针对 `relay_copy_with_idle` 原地复位与超时到期设计了高精度的虚拟时钟单元测试。
- `src/routing.rs`：AllowedIPs longest-prefix matching。
- `src/uds_server.rs`：真实 UDS server 的 `Stats`、`Dump`、非法请求响应和 remove-peer 缓存清理。
- `src/wireguard.rs`：当前仅保留 `WgPeerStats` DTO，内核 WireGuard generic netlink 路径已移除。

### Acceptance / E2E 脚本

这些脚本需要 root、Linux network namespace、`iproute2`、`iptables`/`ip6tables`、`curl`、`python3`。

```bash
sudo bash script/acceptance/e2e_test_dualstack.sh
sudo bash script/acceptance/e2e_scenarios.sh
sudo bash script/acceptance/e2e_multi_client.sh
sudo bash script/acceptance/e2e_dynamic_client_peer.sh
sudo bash script/acceptance/e2e_client_topology_gate.sh
sudo bash script/acceptance/e2e_userspace_wg_fallback.sh
sudo bash script/acceptance/e2e_full_tunnel_bypass.sh
sudo STABILITY_DURATION=60 STABILITY_SAMPLE_INTERVAL=10 bash script/acceptance/stability_stress_test.sh
cargo build --release --bins
sudo bash script/perf/perf_smoke.sh
sudo bash script/perf/perf_cores_scalability.sh
```

语法检查：

```bash
bash -n script/acceptance/e2e_test_dualstack.sh \
  script/acceptance/e2e_scenarios.sh \
  script/acceptance/e2e_multi_client.sh \
  script/acceptance/e2e_dynamic_client_peer.sh \
  script/acceptance/e2e_client_topology_gate.sh \
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

## 2. 当前覆盖情况

| 层级 | 已覆盖 | 主要缺口 |
| --- | --- | --- |
| 单元测试 | 配置解析、HMAC 控制面、控制面 stale nonce/重放/坏 HMAC、非法 public IP、空 QUIC pool、QUIC pinning、relay、router、UDS 协议兼容、真实 UDS server stats/dump/error、telemetry registry、userspace TCP fallback 回切策略、TUN opener/AsyncFd I/O、boringtun/smoltcp wrapper、RtcWorker 创建、包分类、IPv6 短包边界、IPv4/IPv6 NAT checksum 重算、bridge pending 队列字节上限、VirtualTunnel drop/failover 边界、worker flow limit fallback 判断、`relay_copy_with_idle` 零分配原地 Deadline 复位与超时到期机制 | QUIC pool 状态切换到 boringtun fallback 的更多包级断言仍需加强 |
| E2E | 双栈 WAN、IPv6 HTTP over TUN/smoltcp/QUIC、TUN/smoltcp->QUIC、QUIC 被阻断时新 TCP 经 userspace WireGuard fallback、服务端重启后客户端自动重连、动态 server peer add/remove、多客户端 proxy + direct L3 baseline、动态 client proxy peer add/remove 生命周期、client 启动前 data-port 预协商驱动 4 worker 拓扑、移除所有 pool 后仍拒绝 1-port 动态 peer 改变固定 baseline、full-tunnel endpoint bypass 与动态 full-tunnel peer replacement、server 主动访问 client 后端的物理路径保持可达 | UDP/ICMP 经 userspace boringtun 的 namespace 闭环、服务端 session rotation/peer removal 的长流关闭与恢复还没有独立 E2E |
| 稳定性 | 多 client、两条独立 proxy peer、direct L3 baseline、长/短 TCP、UDP、ping、warmup 后 RSS、per-peer QUIC CV；crash、短/长 TCP、UDP、ping、QUIC CV 为硬门禁，RSS 默认 WARN、`STABILITY_ENFORCE_RSS=1` 时为硬门禁 | 还没有 1 小时 CI 固化结果；没有 FD 数、CPU 斜率、失败日志自动摘要；还缺高 stream churn 后 `ServerFutures` RSS/FD 斜率门禁 |
| 性能 | `script/perf/perf_smoke.sh` 覆盖 TTFB sample 和 8 MiB throughput sample；`script/perf/perf_cores_scalability.sh` 自建 namespace 拓扑，按 QUIC data port 数 `1..4` 同步重启 server/client，并用 `taskset` 约束 client CPU，默认 32 并发输出吞吐与 per-worker flow 分布 | 缺正式吞吐、延迟、CPU、连接建立耗时基准和并发阶梯压测；当前 cores scalability 使用 curl/Python HTTP，不能替代 iperf3 或专用 traffic generator；还缺长下载与短请求混跑的 p95/p99 TTFB 门禁；L3 userspace WireGuard 仍是 per-peer shared state，需单独评估 UDP/ICMP/fallback 扩展性 |
| 弱网/混沌 | 无正式脚本 | 缺丢包、端口阻断、服务端重启、session rotation、控制面丢包场景 |
| 安全负向 | 控制面坏 HMAC/重放/stale nonce、QUIC 证书 pinning、空 endpoint pool | 缺恶意响应、错误端口池、超大 UDS payload、未授权 peer 的 E2E |

## 3. 已补的重点测试

### 3.1 动态 client proxy peer 生命周期

`script/acceptance/e2e_dynamic_client_peer.sh` 覆盖：

1. client 以非 proxy `AllowedIPs` 配置启动。
2. 添加前 workload namespace 访问目标 TCP 失败。
3. 调用 client UDS `add-peer <server_pub> <allowed_ips> <endpoint> <proxy_port>`。
4. 验证 client 创建 QUIC pool，workload TCP 经 TUN/smoltcp 成功走 QUIC。
5. server namespace 通过物理路由主动访问 client 后端 workload 服务，验证非代理物理路径仍可达。
6. 调用 client UDS `remove-peer`。
7. 验证后续 TCP 不再进入 QUIC。

### 3.2 Client data-plane topology 门禁

`script/acceptance/e2e_client_topology_gate.sh` 覆盖：

1. 两个 server daemon 同时运行：server1 发布 4 个 QUIC data ports，server2 只发布 1 个 QUIC data port。
2. client 只配置 server1 proxy peer 启动，必须在主 runtime 前预协商出 4-port 宽度。
3. 通过 client UDS `dump` 验证 worker telemetry 行数为 4，并检查启动日志记录 `data_ports 4, using 4`。
4. 验证原始 4-port peer 业务 TCP 可通过 TUN/smoltcp/QUIC 成功。
5. 移除原始 peer，使当前 QUIC pool 为空但固定 baseline 仍为 4。
6. 动态添加 server2 这个 1-port proxy peer，必须被拒绝，错误信息包含 `established baseline uses 4`。
7. 验证拒绝不会改变 worker 拓扑，再重新添加原始 4-port peer 并验证业务恢复。

### 3.3 控制面负向与重试

Rust 单元测试覆盖：

- 控制面响应 `client_nonce` 不匹配必须被拒绝。
- 重放相同 `ControlRequest` 无响应。
- 错误 HMAC 控制请求无响应。
- 非法 `PublicIPv4`/`PublicIPv6` 导致 client 明确失败。
- 空 QUIC endpoint pool 导致 pool 构建失败。

### 3.4 Userspace TCP 与 WireGuard-only 边界

当前覆盖：

- `rebuild_l4_router()` 只纳入同时配置 `Endpoint` 和 `ProxyPort` 的 peer。
- 同一 client 配置中同时存在 proxy peer 和 WireGuard-only peer。
- 访问 proxy peer `AllowedIPs` 走 QUIC。
- 访问 WireGuard-only peer `AllowedIPs` 不走 QUIC。
- client gateway 不再依赖 TPROXY 规则；server 主动访问 client 后端的物理路径不会被 userspace TCP offload 误接管。

### 3.5 UDS server 模块拆分

Rust 单元测试覆盖：

- UDS raw JSON request 与 framed request 的兼容读写。
- 非法 framed payload length 被拒绝。
- 独立 `uds_server` 启动后可基于 `UdsServerContext` 返回 `Stats` 聚合 telemetry。
- 独立 `uds_server` 启动后可返回 `Dump` 文本快照。
- 非法 JSON request 返回 `ApiResponse { status: "Error" }`。
- remove-peer 相关 peer secrets、session cache、nonce cache 同步清理。

### 3.6 IPv6 真实业务闭环

`script/acceptance/e2e_test_dualstack.sh` 覆盖：

- IPv6 HTTP server 监听。
- IPv6 `AllowedIPs` 命中 client namespace TUN route。
- router namespace 使用 `curl -g http://[fd00::1]:8080/` 发起真实 TCP。
- server telemetry 中出现 QUIC L4 字节。

### 3.7 Userspace WireGuard TCP fallback 闭环

`script/acceptance/e2e_userspace_wg_fallback.sh` 覆盖：

1. server/client 两端均 `Table = auto`，由 new_proxy 创建并配置各自 TUN。
2. server HTTP 服务绑定在 server TUN 地址 `10.40.0.1`。
3. server namespace 丢弃 QUIC data ports `40001,40002`，但保留控制面 UDP `51821` 和 userspace WireGuard UDP `51820`。
4. client 初始 QUIC pool 失败后禁用 userspace TCP offload。
5. client 发起新 TCP 到 `10.40.0.1:8080`，经 TUN -> boringtun -> server TUN 成功闭环。
6. server telemetry 显示 WireGuard 字节非零且 QUIC inactive。

### 3.8 服务端重启后的客户端自动恢复

`script/acceptance/e2e_scenarios.sh` 覆盖 namespace 级真实进程恢复：

1. client/server daemon 先完成 TUN/smoltcp -> QUIC 业务流量。
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

### 3.9 QUIC 故障后的 userspace WireGuard fallback 与延迟回切

当前代码路径：

1. QUIC stream 打开失败时，client 将对应 pool 标记为 `Fallback`。
2. client failover manager 观察所有 proxy pool 状态。
3. 任意 pool 为 `Fallback` 或 `Recovering` 时，manager 将 `userspace_tcp_offload_enabled` 置为 false。
4. 后续从 TUN 读到的新 TCP 包不再投递给本地 `smoltcp`，而是通过 `boringtun` 走用户态 WireGuard L3 fallback。
5. 启动时缺失 QUIC pool 不再导致 client 退出；manager 周期性重建缺失 pool。
6. QUIC 连接恢复后先进入 `Recovering` cooldown，cooldown 结束并回到 `Active` 后，manager 重新启用 userspace TCP offload。

当前 client 启动路径不再下发 TPROXY iptables 规则；`runtime.rs` 只负责 TUN 地址、peer 路由和 endpoint bypass route。

Rust 单元测试覆盖：

- `src/main.rs::test_userspace_tcp_failover_policy_requires_all_pools_active`：确认只有所有 pool 都是 `Active` 时才允许恢复 userspace TCP offload；`Fallback` 和 `Recovering` 都保持 WireGuard fallback。

### 3.10 稳定性与负载均衡测试设计

`script/acceptance/stability_stress_test.sh` 是长稳测试入口，目标覆盖物理 QUIC 连接池、TUN/smoltcp 用户态并发转发和双轨聚合遥测。

核心成功标准：

- 测试期间 client/server daemon 无 panic、无意外退出、无 crash。
- 长连接 TCP 与短连接 `curl` 业务请求应持续成功。
- 多物理 QUIC 连接的流量分布应接近均匀；稳定性报告按各连接总流量计算变异系数 CV。
- warmup 后 RSS 不应持续线性增长，避免 OOM 或明显泄漏。

流量模型：

- 多线程长 TCP：后台线程持续建立到目标 HTTP 服务的 TCP 连接并发送数据，断线后自动重连。
- 高频短 TCP：周期性发起 `curl` 短连接，压测 QUIC stream 分配和回收。
- 背景 UDP/ICMP：通过非 proxy 路径保持 L3 活跃，辅助观察 WireGuard 与 QUIC 分层遥测。

采样与报告：

- 脚本周期性采集 daemon 存活、CPU、RSS、UDS/CLI dump、QUIC connection 本地端口、rx/tx bytes 和 active streams。
- 采样数据写入 artifact 目录的 JSON Lines 文件。
- `stability_report.py` 汇总资源趋势、流量成功率和 QUIC 物理连接分布。

### 3.11 部署验证

部署包验证分三层：

- 构建层：`make package` 生成本机架构包；交叉包使用 `ARCH=<deb_arch> CARGO_TARGET=<rust_target>`，并用 `file`/`dpkg-deb -f` 确认二进制架构和 Debian `Architecture` 匹配。
- 安装层：远端 `dpkg -i` 后确认 `dpkg -s new-proxy` 为 `install ok installed`，二进制和 systemd unit 属主为 `root:root`。
- 运行层：`systemctl restart new_proxy@<instance>` 后检查服务为 `active (running)`，再通过 `new-proxy-cli --interface <instance> show` 验证 UDS 可连接、peer source/handshake/QUIC 状态符合预期。

客户端隧道自举机器部署必须使用本机 rollback 机制：

1. 在客户端本地把当前安装内容打成 rollback deb。
2. 安装新 deb 前启动 watchdog。
3. 新包安装并重启服务后，在限定时间内确认 systemd active、UDS CLI 可查询、peer 非 `latest handshake: Never`。
4. 若健康确认未写入，watchdog 自动 `dpkg -i` rollback deb 并重启原服务。

### 3.12 用户态客户端协议栈测试

用户态客户端改动的测试用例统一维护在本节，不再散落到临时实施计划文档。

已实现的单元级覆盖：

- `src/tun_device.rs::test_open_tun_device`：验证 TUN opener 能返回 FD；在无权限环境下接受 `Permission denied` / `Operation not permitted`，避免普通开发环境误报。
- `src/tun_io.rs::test_async_tun_io`：用 Unix socketpair 模拟 FD，验证 `AsyncTunIo` 的异步读写路径。
- `src/userspace_wg.rs::test_boringtun_state`：验证 boringtun `Tunn` 状态可以由本地私钥和 peer 公钥初始化。
- `src/userspace_tcp.rs::test_smoltcp_stack_creation`：验证 smoltcp interface、socket set 和 TCP socket handle 创建。
- `src/rtc_loop.rs::test_packet_classification`：验证 IPv4 TCP 报文协议号识别。
- `src/rtc_loop.rs::parse_ipv6_tcp_rejects_short_header_without_panicking`：验证 IPv6 TCP 短包不会越界 panic。
- `src/rtc_loop.rs::rewrites_repair_ipv4_tcp_checksums` / `rewrites_repair_ipv6_tcp_checksums`：验证 NAT 改写后校验和会被重算。
- `src/rtc_loop.rs::bridge_pending_queues_are_capped_by_bytes`：验证 bridge 慢读/慢写 pending 队列存在字节上限。
- `src/rtc_loop.rs::new_syn_falls_back_when_worker_flow_limit_is_reached`：验证 worker TCP flow 数达到上限时，新 SYN 会被判定为 fallback，而已有 flow 不受影响。
- `src/rtc_loop.rs::allocate_local_port_can_use_final_ephemeral_port`：验证 userspace TCP 本地端口分配覆盖完整 ephemeral 范围。
- `src/rtc_loop.rs::cleanup_stale_flows_removes_half_open_socket_for_local_port`：验证 stale flow 清理会移除半开 smoltcp socket 并释放本地端口索引。
- `src/rtc_loop.rs::insert_flow_port_rejects_duplicate_port_in_debug_builds`：验证本地端口索引 helper 在 debug/test 构建中拒绝重复端口误用。
- `src/rtc_loop.rs::test_rtc_worker_creation`：验证 `RtcWorker` 组合 `AsyncTunIo`、UDP socket、boringtun 和 smoltcp 后可执行一次 poll/flush 迭代。
- `src/virtual_tunnel.rs::virtual_tunnel_socket_rejects_empty_physical_socket_set`：验证虚拟 UDP socket 不接受空物理 socket 集。
- `src/virtual_tunnel.rs::virtual_tunnel_sequential_recv_uses_caller_buffer_without_queue`：验证 RTC receive path 直接使用调用方 buffer 连续收包，不经过中间接收队列。
- `src/virtual_tunnel.rs::virtual_tunnel_does_not_consume_business_packets_before_recv`：验证虚拟 UDP socket 不用后台任务预取业务包，只有 RTC worker 调用 `recv_from` 时才收包。
- `src/virtual_tunnel.rs::virtual_tunnel_recv_reads_directly_from_multiple_physical_sockets`：验证多个物理 UDP socket 任一 ready 时都能直接读入调用方 buffer。
- `src/virtual_tunnel.rs::virtual_tunnel_keeps_active_socket_when_all_pongs_are_stale`：验证所有物理路径健康探测都过期时不会强制回切到 socket 0。
- `src/virtual_tunnel.rs::virtual_tunnel_send_uses_active_physical_socket`：验证发送使用当前 active 底层 UDP socket。

### 3.13 数据面超时机制与定时器优化单元测试

`src/relay.rs::test_relay_copy_with_idle_timeout` 覆盖：

1. **虚拟时钟 Mock 测试**：通过 `tokio::time::pause()` 暂停真实时间，使用 `tokio::time::advance()` 精确前进虚拟时间，排除外部墙上时钟抖动引起的 flaky test。
2. **连接活跃度复位（Reset）验证**：建立两端 duplex 流并在 `tokio::spawn` 异步任务中启动 `relay_copy_with_idle`。先向流写入数据，前进一半超时时间（`RELAY_IDLE_TIMEOUT / 2`），再次写入数据触发原地 `.reset()`。接着再前进另一半超时时间，验证虽然累计时间达到了 `RELAY_IDLE_TIMEOUT`，但由于原地复位，流没有超时且数据被正确转发。
3. **空闲到期超时（TimedOut）验证**：流停止数据传输后，将虚拟时钟一次性推移超过 `RELAY_IDLE_TIMEOUT`，验证 `relay_copy_with_idle` 准确返回 `std::io::ErrorKind::TimedOut` 错误。

需要补齐的回归用例：

- `RtcWorker` TCP 路由选择：目标 IP 命中 `L4DataPlaneSnapshot.router` 且 QUIC pool 为 `Active` 时进入 smoltcp；未命中、pool 缺失、`Fallback` 或 `Recovering` 时进入 boringtun L3。
- 桥接通道：smoltcp socket payload 经 `BridgeChannels` 发往 QUIC handler，QUIC 返回 payload 能写回 smoltcp socket；通道断开时 socket abort 并清理 bridge；QUIC readiness 必须通过 worker-local notify 唤醒 RTC loop，避免只能靠 timer tick 推进。
- WireGuard timer/UDP 入站：`update_timers()` 产生网络包时写入物理 UDP socket；`decapsulate()` 返回 tunnel 包时写回 TUN；server/client 多 worker 下只有 worker 0 负责外层 UDP receive 和 timer。
- 多队列启动：server 队列数严格跟随 `QuicPool.ListenPorts` 数量；client 队列数在启动主 runtime 前固定，启动期已知 QUIC data port 数时使用该数量，启动期未知时固定为 1 个 worker。多个 proxy peer 的 data port 数量必须一致；之后动态新增、后台恢复或控制面刷新得到的 data port 数必须匹配固定 baseline，不一致时拒绝该 QUIC pool 并继续走 userspace WireGuard L3 fallback。client WireGuard L3 路径仍共享单个外层 UDP socket，且只有 worker 0 负责入站 receive/timer。L4 proxy client 下必须验证多并发 TCP flow 能在多 worker 下正常完成；失败时清理 runtime。
- 多 peer userspace WireGuard：每个 proxy peer 拥有共享的 per-peer `boringtun` 状态和 UDP endpoint，并按 `AllowedIPs` 选择 L3 fallback 目标；需要覆盖多 worker 并发 fallback 时不会死锁或明显退化。
- E2E：补齐 UDP/ICMP 经 TUN -> boringtun -> server TUN 闭环。
- 性能：`script/perf/perf_cores_scalability.sh` 在具备 root、release binary、`ip`、`python3`、`curl`、`taskset`、`awk` 和可用 CPU cpuset 的环境下运行真实 HTTP 吞吐；工具、CPU 或拓扑缺失时必须失败，不能生成模拟性能数据。脚本还必须强制采集 per-worker telemetry，并验证 `worker:` 行数匹配 QUIC data port 数。

## 4. Backlog

- 服务端 session rotation / peer removal E2E：建立长 TCP 流，server `remove-peer`，验证旧 QUIC 连接关闭、新 stream 失败，重新 `add-peer` 后新 TCP 成功。
- 弱网脚本：对单个 QUIC UDP port 下发 `DROP`，验证新 stream 继续使用其他健康 port；控制面 UDP 丢第一包后重试新 nonce 成功。
- 性能脚本：正式 throughput、TTFB、CPU/RSS、连接建立耗时、并发 1k/4k/8k 阶梯压测，并将 `perf_cores_scalability.sh` 的 curl/Python HTTP 负载替换为 iperf3 或专用 Rust traffic generator。
- L3 扩展性：为 UDP/ICMP 和 TCP fallback 增加独立多队列压测，评估当前 shared per-peer `boringtun` 锁竞争；若成为瓶颈，再设计 per-worker WireGuard state。
- 稳定性脚本：1 小时 nightly/profile、FD 数、CPU 累计时间、失败日志自动打包、机器可读 pass/fail 总结。
- 安全负向：恶意响应、错误端口池、超大 UDS payload、未授权 peer 的 E2E。
- **UDP-over-QUIC Stream 代理规划测试**：
  - **单元测试**：验证 `parse_udp_packet` 头部提取与解析正确性；验证 smoltcp UDP 接口分配和 socket state 正常获取；验证大包分拆与粘包的 2 字节大端长度前缀在 Stream 上的解析可靠性；验证在 `UDP_IDLE_TIMEOUT` (30秒) 周期内无数据活动时，两端的 Pinned Sleep 定时器能准确超时并释放 socket / NAT 表资源。
  - **E2E 验收测试**：建立命名空间测试拓扑，通过 TUN 匹配 AllowedIPs 拦截 UDP 流量（如 DNS），验证其正确转换为 QUIC stream 并完成端到端通信。通过物理网卡流量捕获校验链路上没有出现明文的 WireGuard UDP（端口 51820）包。


## 5. 文档同步规则

以后改架构时至少同步：

- `doc/ARCHITECTURE.md`：只写当前代码真实行为。
- `doc/TESTING.md`：更新覆盖矩阵和缺口。
- `doc/TEST_REPORT.md`：只记录已经执行过的命令、日期、环境和结果。
- README：只保留用户安装、配置和运行需要知道的信息。
