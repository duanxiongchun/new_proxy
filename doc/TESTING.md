# new_proxy v1 测试与覆盖映射

本文档只描述当前 AF_XDP QUIC appliance 的测试资产。旧 TUN、WireGuard、
hybrid、动态 peer 和 multi-client runtime 测试已从门禁及仓库中删除。

## 1. 门禁入口

唯一入口是：

```bash
./script/acceptance/run_acceptance.sh
```

默认门禁不需要 root，执行：

1. 所有 v1 shell 的 `bash -n`。
2. Python traffic helper 的语法编译。
3. `cargo fmt --check`。
4. 全部现存 target 的 offline Cargo check。
5. 全部现存 target 的 Clippy `-D warnings`。
6. 全部 library 单元测试。
7. `tests/v1_flow_integration.rs`。

完整 root E2E：

```bash
RUN_V1_E2E=1 ./script/acceptance/run_acceptance.sh
```

该模式额外构建内嵌 XDP ELF 的 release binary，并顺序执行七个隔离 netns 场景。
可选长稳和性能基线也由同一入口启用：

```bash
RUN_V1_SOAK=1 V1_SOAK_CYCLES=10 \
  ./script/acceptance/run_acceptance.sh

RUN_V1_PERF=1 V1_PERF_ITERATIONS=100 \
  ./script/acceptance/run_acceptance.sh
```

`RUN_V1_E2E`、`RUN_V1_SOAK` 和 `RUN_V1_PERF` 都需要 root 或可用的无密码
`sudo`，并依赖 Linux netns、XDP、AF_XDP、BPF mount、`bpftool`、`iproute2`、
`ethtool`、`openssl` 与 `python3`。

## 2. 架构约束映射

| 架构约束 | 实现位置 | 自动验证 |
|---|---|---|
| IO owner 使用完整 `(ifindex, queue_id)` | `IoOwnerKey`, `IoRegistry`, `build_runtime` | `v1_unit_io_registry_*`, `v1_unit_xdp_runtime_uses_complete_owner_keys`, `v1_integration_equal_queue_ids_on_different_interfaces_have_distinct_owners` |
| 一个 owner 只有一套 XSK/UMEM/rings | `Xsk`, `build_runtime` | `v1_unit_io_registry_rejects_duplicate_owner`, `v1_unit_xdp_runtime_xsk_failure_starts_no_workers`, same-interface E2E |
| IO worker 不拥有 Session/NAT | `IoWorker::handle_frame`, `FlowDispatcher` | `v1_unit_io_worker_*`, `v1_integration_bounded_dispatch_never_changes_the_selected_owner` |
| Flow worker 独占 Session/NAT | `FlowWorkerState`, `SessionTable`, `NatTable` | `v1_unit_session_rejects_mutation_by_the_wrong_worker`, `v1_integration_session_owner_and_local_return_io_stay_stable` |
| bounded channel 满时不改投 owner | `FlowDispatcher::dispatch_to` | `v1_integration_bounded_dispatch_never_changes_the_selected_owner` |
| Session key 包含入口 ifindex | `SessionKey` | `v1_unit_session_distinguishes_same_flow_on_different_interfaces`, multi-intercept E2E |
| client/server 分别执行本地 SNAT | `FlowWorkerState::handle_intercept`, runtime tunnel handling | NAT/session unit tests，client-to-target E2E 的 target peer 与双端 stats 断言 |
| reverse NAT 原子发布与回收 | `ReverseNatDirectory`, `SessionTable::remove*` | `v1_unit_nat_*`, `v1_unit_session_remove_cleans_forward_reverse_and_port_state`, recovery E2E |
| ICMP key 忽略 request/reply type 变化 | `ReverseNatKey`, `FlowWorkerState::handle_reverse` | `v1_unit_nat_icmp_reply_uses_identifier_not_changed_message_type`, `v1_integration_icmp_reverse_nat_restores_identifier_and_keeps_reply_type` |
| QUIC flow 稳定绑定 tunnel queue | `QuicFlow` | `v1_unit_quic_flow_keeps_stable_tunnel_queue_across_dcid_rotation`, queue-space integration tests |
| tunnel ingress 按 active DCID owner 分发 | `ActiveDcidIndex`, `IoWorker::handle_frame` | DCID lifecycle tests，`v1_unit_io_worker_reverse_nat_uses_session_owner_before_flow_hash` |
| 未知 DCID 只能进入合法 Initial bootstrap | `bootstrap_owner`, QUIC parser | `v1_unit_quic_flow_bootstrap_*`, `v1_unit_io_worker_only_long_initial_bootstraps_unknown_dcid` |
| QUIC Fixed Bit greasing 合法 | QUIC header classifier | `v1_unit_io_worker_accepts_greased_{long,short}_header_for_active_dcid` |
| TLS pin 与 HMAC 双向认证 | `QuicEngine`, pinned rustls config | `v1_unit_quic_engine_authenticates_and_round_trips_inner_packets`, `v1_unit_quic_engine_rejects_data_before_auth_and_retires_dcids_on_close`, 所有 E2E |
| 空闲连接与标准 MTU | QUIC transport config，Datagram fragmentation/reassembly | `v1_unit_quic_engine_keeps_authenticated_connection_alive_while_idle`, `v1_unit_quic_engine_fragments_and_reassembles_standard_mtu_inner_packet`, reliability E2E |
| GSO segment 独立封装 | `OuterTransmit`, runtime outer encapsulation | `v1_unit_xdp_runtime_splits_quic_gso_transmits_before_udp_encapsulation` |
| 同接口仅一个 owner、外层分类优先 | runtime owner assembly，XDP/IO classifier | `v1_unit_xdp_runtime_same_interface_has_one_owner_and_two_classifiers`, `v1_unit_io_worker_same_interface_prioritizes_outer_quic`, same-interface E2E |
| 同接口业务 UDP 与 tunnel port 冲突不误分类 | local tunnel address + port classifier | `v1_unit_io_worker_same_interface_tunnel_port_to_remote_ip_is_intercepted`, same-interface E2E |
| server queue 只被真实回包纠正一次 | `SessionTable::correct_intercept_io` | `v1_integration_server_default_queue_is_corrected_once`, server-return E2E |
| 重连更换 flow identity 并清状态 | runtime SIGHUP path，`remove_by_quic_flow` | reconnect/session tests，recovery E2E，bounded soak |
| stats 原子暴露 owner/flow/session 状态 | `stats::write_snapshot` | `v1_unit_runtime_stats_serializes_owner_and_flow_state`，全部 E2E stats 断言 |
| SIGKILL 后安全恢复 | netns/ifindex lock，pinned program ID 校验 | reliability E2E |

## 3. Rust 测试覆盖

### 配置

`src/v1_config.rs` 直接测试 `conf/client.conf` 和 `conf/server.conf`，并覆盖：

- 单 client/server schema。
- client 多 intercept、server 单 intercept。
- tunnel/intercept 同接口。
- worker/DCID/channel 数量、NAT 范围和 role addressing。
- 旧 section、旧字段和未知字段 fail closed。

### Packet、NAT 与 Session

`src/flow_plane/packet.rs` 覆盖 IPv4/IPv6 TCP、UDP、ICMP/ICMPv6 的解析、地址和
端口/identifier 改写以及 checksum。IPv4 UDP 原始零 checksum 会保留禁用语义。

`src/flow_plane/nat.rs` 和 `session.rs` 覆盖：

- 双栈 SNAT tuple 唯一分配、耗尽、释放复用。
- address family 不匹配不产生半状态。
- reverse key 发布、命中和回收。
- 重复包复用 Session。
- worker ownership 拒绝越权修改。
- 按 `quic_flow_id` 精确回收。

### QUIC 与分发

`src/flow_plane/quic_flow.rs`、`src/quic_engine.rs` 和
`src/xdp_datapath/io_worker.rs` 覆盖：

- deterministic Initial bootstrap。
- active DCID 发布、轮换、退休、close。
- flow-worker affinity 与稳定 tunnel queue。
- TLS certificate pin、HMAC、认证前拒绝业务包。
- long/short header 与 Quinn Fixed Bit greasing。
- AllowedIPs 命中 redirect，未命中 pass。
- reverse-NAT owner 优先于普通 flow hash。

### Runtime 装配

`src/xdp_datapath/runtime.rs` 覆盖：

- 完整 owner key 和同接口双角色装配。
- intercept/tunnel queue 空间独立。
- 任意 XSK 创建失败时不启动部分 workers。
- 多 Flow worker NAT port range 无重叠。
- IPv4/IPv6 外层 UDP checksum。
- QUIC GSO split 后逐 segment 封装。

`tests/v1_flow_integration.rs` 在纯内存边界上验证 owner、bounded dispatch、
Session/NAT、ICMP 回程、server queue correction 和同接口 queue 语义。

## 4. Root E2E

七个脚本共用 `script/acceptance/v1/lib.sh`。每个场景创建隔离 netns、veth、
独立 BPF mount、临时证书和严格 v1 配置，启动真实 release daemon 和 XSK。

| 脚本 | 证明内容 |
|---|---|
| `e2e_v1_client_to_target.sh` | IPv4/IPv6 TCP、UDP、ICMP 闭环；target 只看到 server SNAT；双端 Session/NAT/DCID 存在 |
| `e2e_v1_server_return.sh` | target 回包进入 server reverse NAT，并通过原 QUIC flow 返回 |
| `e2e_v1_client_return.sh` | client reverse NAT 后从原 intercept owner 回投 |
| `e2e_v1_same_interface.sh` | tunnel/intercept 同接口只创建一个双角色 IO owner，无递归封装 |
| `e2e_v1_multi_intercept.sh` | 两个 client intercept 都建独立 Session，回程保留原 ifindex |
| `e2e_v1_recovery.sh` | SIGHUP 后 `quic_flow_id` 改变、旧 Session/NAT 清零、重新认证并恢复业务 |
| `e2e_v1_reliability.sh` | 1472-byte payload、12 秒双栈 TCP idle、2 workers、client SIGKILL 后 stale XDP 恢复 |

E2E 同时断言业务结果和 JSON stats，不只以“ping 通”作为成功标准。

## 5. Soak 与性能

`script/acceptance/v1/soak_v1.sh` 每轮运行完整双栈协议矩阵并强制重连。每轮重连后
必须满足：

- 双端重新认证。
- Session、NAT、reverse NAT 全部为零。
- active DCID 已重新建立。
- 最终 FD 数无漂移。
- IO owner 数无漂移。
- RSS 增长不超过 `V1_SOAK_RSS_GROWTH_KB`，默认 32 MiB。

`script/perf/perf_v1.sh` 是可复现性优先的功能性能基线，报告 v4/v6 TCP/UDP
echo 的 p50/p99 延迟、总耗时以及每个 IO queue 的 RX/TX/drop。它不内置硬件无关
的吞吐阈值，也不声称 veth `skb` 结果代表物理 NIC `native` XDP 性能。

## 6. 明确未覆盖

下列内容不属于当前 v1 自动门禁，不能从现有测试结果推导：

- 具体物理 NIC/驱动的 native XDP、zero-copy 能力和线速吞吐。
- 多队列 RSS、CPU/NUMA affinity 的性能扩展曲线。
- IP 层分片、IPv6 extension header、PMTU discovery 和超过 65535 bytes 的 inner packet。
- 动态 ARP/NDP；当前 next-hop MAC 由配置提供。
- Session idle timeout；当前只在 QUIC flow close/reconnect 时整体回收。
- supervisor 的具体重启时延；SIGKILL 后立即手工重启已进入 E2E。
- 长时间公网丢包、乱序、NAT rebinding 与恶意流量压力。
- 多 peer、多 server intercept、TUN、WireGuard、hybrid 或动态控制面；这些是非目标，
  不是待恢复的兼容测试。

物理上线前应在目标 NIC、queue 数、CPU/NUMA 绑定和真实 MTU 上单独执行 soak、
故障注入与容量测试，并保存该环境的基线。
