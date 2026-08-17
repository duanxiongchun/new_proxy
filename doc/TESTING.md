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

默认命令通过只表示非特权阶段通过；完整发布门禁必须设置 `RUN_V1_E2E=1` 并让十三个
root/netns 场景全部通过。

完整 root E2E：

```bash
RUN_V1_E2E=1 ./script/acceptance/run_acceptance.sh
```

该模式额外构建内嵌 XDP ELF 的 release binary，并顺序执行十三个隔离 netns 场景。
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
| NAT 容量耗尽只拒绝新流，不破坏已有流 | `NatTable`, `session_nat_exhausted` | `v1_integration_nat_exhaustion_rejects_new_flow_and_preserves_existing_flow`, nat-capacity E2E |
| bounded channel 满时不改投 owner | `FlowDispatcher::dispatch_to` | `v1_integration_bounded_dispatch_never_changes_the_selected_owner` |
| 五元组稳定映射到固定 QUIC Datagram lane | `stable_flow_owner`, per-worker `QuicEngine` | `v1_unit_io_worker_five_tuple_stably_distributes_across_lanes`, `v1_unit_quic_engine_{generates_dcids_owned_by_the_flow_worker,client_initial_maps_to_its_flow_worker,reconnect_keeps_worker_affinity}`，默认 2-worker E2E |
| Session key 包含入口 ifindex | `SessionKey` | `v1_unit_session_distinguishes_same_flow_on_different_interfaces`, multi-intercept E2E |
| client/server 分别执行本地 SNAT | `FlowWorkerState::handle_intercept`, runtime tunnel handling | NAT/session unit tests，client-to-target E2E 的 target peer 与双端 stats 断言 |
| reverse NAT 原子发布与回收 | `ReverseNatDirectory`, `SessionTable::remove*` | `v1_unit_nat_*`, `v1_unit_session_remove_cleans_state_and_quarantines_reverse_tuple`, recovery E2E |
| ICMP key 忽略 request/reply type 变化 | `ReverseNatKey`, `FlowWorkerState::handle_reverse` | `v1_unit_nat_icmp_reply_uses_identifier_not_changed_message_type`, `v1_integration_icmp_reverse_nat_restores_identifier_and_keeps_reply_type` |
| QUIC flow 稳定绑定 tunnel queue | `QuicFlow` | `v1_unit_quic_flow_keeps_stable_tunnel_queue_across_dcid_rotation`, queue-space integration tests |
| tunnel ingress 按 active DCID owner 分发 | `ActiveDcidIndex`, `IoWorker::handle_frame` | DCID lifecycle tests，`v1_unit_io_worker_reverse_nat_uses_session_owner_before_flow_hash` |
| 未知 DCID 只能进入合法 Initial bootstrap | `bootstrap_owner`, QUIC parser | `v1_unit_quic_flow_bootstrap_*`, `v1_unit_io_worker_only_long_initial_bootstraps_unknown_dcid` |
| QUIC Fixed Bit greasing 合法 | QUIC header classifier | `v1_unit_io_worker_accepts_greased_{long,short}_header_for_active_dcid` |
| TLS pin 与可靠 HMAC 双向认证 | `QuicEngine`, pinned rustls config，双向 auth stream | `v1_unit_quic_engine_authenticates_and_round_trips_inner_packets`, `v1_unit_quic_engine_retransmits_hmac_authentication_after_packet_loss`, `v1_unit_quic_engine_rejects_data_before_auth_and_retires_dcids_on_close`, 所有 E2E |
| candidate 认证前不替换 active、不发布 active DCID，busy 时拒绝新 candidate | `QuicEngine` active/candidate 槽位，10 秒 deadline，staged DCID index | `v1_unit_quic_engine_does_not_publish_active_dcid_before_authentication`, `v1_unit_quic_engine_unauthenticated_candidate_does_not_replace_active_connection`, `v1_unit_quic_engine_auth_timeout_releases_candidate_and_endpoint_slot`, `v1_unit_quic_engine_authenticated_candidate_is_promoted_atomically`, `v1_unit_staged_dcid_routes_without_counting_as_active`, `v1_unit_close_flow_removes_staged_candidate_dcids_without_active_dcids` |
| 空闲连接与标准 MTU | QUIC transport config，Datagram fragmentation/reassembly | `v1_unit_quic_engine_keeps_authenticated_connection_alive_while_idle`, `v1_unit_quic_engine_fragments_and_reassembles_standard_mtu_inner_packet`, reliability E2E |
| GSO segment 独立封装 | `OuterTransmit`, runtime outer encapsulation | `v1_unit_xdp_runtime_splits_quic_gso_transmits_before_udp_encapsulation` |
| 同接口仅一个 owner、外层分类优先 | runtime owner assembly，XDP/IO classifier | `v1_unit_xdp_runtime_same_interface_has_one_owner_and_two_classifiers`, `v1_unit_io_worker_same_interface_prioritizes_outer_quic`, same-interface E2E |
| 同接口本机管理流量与 tunnel-port 业务流量不误分类 | local tunnel address + exact port classifier | `v1_unit_io_worker_same_interface_local_non_tunnel_traffic_passes`, `v1_unit_io_worker_same_interface_tunnel_port_to_remote_ip_is_intercepted`, same-interface E2E |
| server queue 只被真实回包纠正一次，后续正向包使用纠正 queue | `SessionTable::correct_intercept_io`, `FlowWorkerState::handle_server_inner` | `v1_integration_server_default_queue_is_corrected_once`, server-return E2E |
| 重连更换 flow identity 并 rebind 普通 Session/NAT | runtime `Closed` path，`rebind_quic_flow` | `v1_integration_quic_rebind_flow_preserves_active_tcp_sessions`，recovery E2E，bounded soak |
| stats 原子暴露 owner/flow/session 状态 | `stats::write_snapshot` | `v1_unit_runtime_stats_serializes_owner_and_flow_state`，全部 E2E stats 断言 |
| userspace NAT port range 系统 reserve | `port_reservation`, `NAT.AutoReservePorts=no` | `v1_unit_port_reservation_*`, `v1_unit_config_requires_pre_reserved_nat_ports` |
| XDP 在 workers ready 前保持 disabled | runtime two-phase classifier enable | `v1_unit_xdp_runtime_xsk_failure_starts_no_workers`, 全部 root E2E |
| SIGKILL 后只清理自己留下的 XDP attachment | netns/ifindex lock，owner record，精确 program ID/mode 校验 | `v1_unit_bpf_owner_record_round_trips_program_and_attach_mode`, `v1_unit_bpf_owner_record_rejects_malformed_content`, reliability E2E |
| server Listen 具体且属于 tunnel interface | strict config，runtime interface discovery | `v1_unit_config_rejects_wildcard_server_listen`, 所有 server root E2E |
| V1 ICMP 只支持 Echo Request/Reply | packet parser | `v1_unit_parse_flow_key_rejects_non_echo_icmp`, ICMP unit/integration tests |
| DNS VIP 独占且属于唯一 intercept | strict config，runtime interface discovery | `v1_unit_xdp_runtime_dns_vip_must_belong_to_one_intercept_and_not_nat_or_tunnel` |
| DNS 查询按完整 transaction key 选择 owner | `IoWorker::handle_frame`, `transaction_key` | DNS IO/flow integration tests |
| DNS resolver 响应必须匹配原查询 wire ID 与 Question | `response_matches_query`, `FlowWorkerState::handle_dns_response` | `v1_unit_dns_response_must_match_original_id_and_question`, `v1_integration_dns_wrong_wire_id_does_not_consume_transaction` |
| DNS EDNS/MTU 上限 fail closed | `DNS_PAYLOAD_MAX`, EDNS clamp, packet rewrite | `v1_unit_dns_edns_clamp_updates_advertised_payload_size`, `v1_integration_dns_edns_is_clamped_and_oversized_query_servfails`, `v1_integration_dns_ipv6_edns_clamp_keeps_udp_checksum_valid`, `v1_integration_dns_malformed_oversized_response_is_rejected_without_consuming_state` |

## 3. Rust 测试覆盖

### 配置

`src/v1_config.rs` 直接测试 `conf/client.conf` 和 `conf/server.conf`，并覆盖：

- 单 client/server schema。
- client 多 intercept、server 单 intercept。
- tunnel/intercept 同接口。
- 示例 client/server 默认且一致的 2 lane、worker/DCID/channel 数量、NAT 范围和
  role addressing。
- server wildcard Listen 拒绝；真实启动时 Listen 必须属于 tunnel interface。
- `AllowedIPs.Prefixes` inline、`file:`、`!file:` 三种模式；server 拒绝无运行时语义的
  `[AllowedIPs]`。
- client `[DNS]` 字段、resolver address family、remote domain 文件规范化和重复拒绝；
  server 拒绝 `[DNS]`。
- 旧 section、旧字段和未知字段 fail closed。

### Packet、NAT 与 Session

`src/flow_plane/packet.rs` 覆盖 IPv4/IPv6 TCP、UDP、ICMP/ICMPv6 的解析、地址和
端口/identifier 改写以及 checksum。ICMP 只接受 Echo Request/Reply 且 code=0；
IPv4 UDP 原始零 checksum 会保留禁用语义。

`src/flow_plane/nat.rs` 和 `session.rs` 覆盖：

- 双栈 SNAT tuple 唯一分配、耗尽，以及 TCP/UDP/ICMP 分别 120/60/30 秒的
  reverse-tuple reuse quarantine。
- address family 不匹配不产生半状态。
- reverse key 发布、命中和回收。
- 重复包复用 Session。
- worker ownership 拒绝越权修改。
- 按 `quic_flow_id` 精确回收。

### QUIC 与分发

`src/flow_plane/quic_flow.rs`、`src/quic_engine.rs` 和
`src/xdp_datapath/io_worker.rs` 覆盖：

- deterministic Initial bootstrap。
- staged/active DCID 发布、提升、轮换、退休、close。
- 五元组稳定映射并覆盖两条 lane、flow-worker/DCID affinity 与稳定 tunnel queue。
- 每个 Flow worker 独立建立一个 QUIC connection；认证控制使用可靠 stream，业务
  packet 使用 QUIC Datagram。
- TLS certificate pin、可靠双向 HMAC stream、认证首包丢失重传、认证前拒绝业务包。
- 未认证 candidate 不替换 active；认证 candidate 以
  `DcidRetired -> Replaced(candidate DCID batch) -> Authenticated` 顺序提升；DCID
  batch 全量校验后一次提交，`Replaced` 不关闭当前 flow，也不触发 reconnect。
- candidate 槽位 busy 时拒绝新 incoming，不允许刷新现有 candidate 的认证 deadline；
  每 connection 最多跟踪 32 个 DCID，超限 fail closed 并整体清理。
- long/short header 与 Quinn Fixed Bit greasing。
- AllowedIPs 命中 redirect，未命中 pass。
- direct-prefix policy 命中 pass，未命中的公网地址 redirect，私网/保留地址不被默认
  redirect。
- reverse-NAT owner 优先于普通 flow hash。
- direct-prefix 默认 redirect 前强制排除 tunnel endpoint、本机 tunnel/NAT address
  与 DNS VIP 非 UDP/53；已发布 reverse tuple 保持最高优先级。
- DNS VIP 分片包 fail closed；IPv6 Hop-by-Hop/Routing/Destination Options/AH 后的
  UDP/Fragment header 按真实 transport offset 分类。LocalResolver 候选回包必须先
  命中 DNS reverse directory。

### DNS 策略纯逻辑

`src/flow_plane/dns.rs` 覆盖：

- 标准 DNS query、单 Question、QNAME 规范化和 label 边界后缀匹配。
- 非标准 opcode、多 Question、坏 compression pointer/loop 等无法安全取得唯一
  Question 的请求立即 `SERVFAIL`；Question 合法但后续 section malformed 时 local
  fallback。
- remote/local domain 分类。
- transaction key 隔离、重传复用、reverse tuple lookup。
- EDNS advertised UDP payload clamp 到 1232，超限 DNS payload 返回 `SERVFAIL`。
- resolver 响应 wire ID 和 Question 必须匹配原始查询，错误响应不消费 transaction。
- transaction capacity 和 NAT port exhaustion。
- FlowWorker DNS stats：local/remote query、local/remote response、SERVFAIL、
  capacity/NAT exhaustion、timeout、malformed fallback、spoofed/late response drop 和
  EDNS clamp、active transaction gauge。
- DNS capacity 与 NAT port exhaustion 返回 `SERVFAIL`，response tuple 恢复为 DNS VIP。
- QUIC 未认证时 remote domain 查询返回 `SERVFAIL`，不排队等待认证。
- DNS transaction timeout 返回 `SERVFAIL`、释放 active 状态，并让 UDP reverse
  tuple 进入 60 秒 quarantine；隔离期内单端口范围的新 query 返回 `SERVFAIL`。
- runtime transport close/candidate replacement 会释放未完成 remote DNS transaction
  的 NAT port 和 reverse directory；本地 DNS transaction 不因 QUIC 状态变化被清理。

### Runtime 装配

`src/xdp_datapath/runtime.rs` 覆盖：

- 完整 owner key 和同接口双角色装配。
- intercept/tunnel queue 空间独立。
- 任意 XSK 创建失败时不启动部分 workers。
- XDP classifier 在全部 workers ready 前保持 disabled。
- 多 Flow worker NAT port range 无重叠。
- `AutoReservePorts` 只接受 `no`，并在 XDP attach 前校验
  `ip_local_reserved_ports` 完整包含 NAT range。
- IPv4/IPv6 外层 UDP checksum。
- QUIC GSO split 后逐 segment 封装。
- DNS VIP 必须只属于一个 intercept，且不能复用 tunnel local IP 或 NAT address。
- LocalResolver XDP 粗分类限制 resolver source、client NAT address 和已配置 NAT
  port range。

`tests/v1_flow_integration.rs` 在纯内存边界上验证 owner、bounded dispatch、
Session/NAT、ICMP 回程、server queue correction 后续包目标、同接口 queue 语义，
以及 DNS local/remote resolver 分流、重传复用 NAT port、DNS VIP response 恢复、
EDNS clamp、超限 query/response `SERVFAIL`、错误 wire ID 不消费 transaction、
分片 resolver response 不消费 transaction、malformed-section fallback payload-hash key、IPv6
本地 DNS 闭环和 DNS cleanup 释放 NAT/reverse 状态。

## 4. Root E2E

十三个脚本共用 `script/acceptance/v1/lib.sh`。每个场景创建隔离 netns、veth、
独立 BPF mount、临时证书和严格 v1 配置，启动真实 release daemon 和 XSK。

| 脚本 | 证明内容 |
|---|---|
| `e2e_v1_client_to_target.sh` | IPv4/IPv6 TCP、UDP、ICMP 闭环；target 的 TCP/UDP peer 精确等于 server SNAT，ICMP 抓包源地址也是 server SNAT；双端 Session/NAT/DCID 存在 |
| `e2e_v1_auth_rejection.sh` | wrong-key client/server 冷启动后等待完整认证超时窗口，双端均不能认证、发布 active DCID、建立 Session/NAT/reverse NAT 或转发业务；恢复正确配置后业务恢复 |
| `e2e_v1_dns_policy.sh` | DNS VIP UDP/53 本地/远端域名分流；实际使用 remote DNS answer 发起 TCP/UDP；local resolver 看到 client SNAT，remote resolver 看到 server SNAT；响应 source 恢复为 DNS VIP；remote resolver timeout 返回 SERVFAIL |
| `e2e_v1_dns_policy_v6.sh` | IPv6 DNS VIP UDP/53 本地/远端域名分流；断言 IPv6 resolver peer、响应 source、rcode、wire ID 和 Question 匹配 |
| `e2e_v1_ip_policy.sh` | `!file:` IPv4/IPv6 direct-prefix 命中经内核直连且不建 Session；未命中公网地址经 QUIC 和双端 SNAT |
| `e2e_v1_server_return.sh` | target 回包进入 server reverse NAT，并通过原 QUIC flow 返回 |
| `e2e_v1_client_return.sh` | client reverse NAT 后从原 intercept owner 回投 |
| `e2e_v1_same_interface.sh` | tunnel/intercept 同接口只创建一个双角色 IO owner，无递归封装 |
| `e2e_v1_multi_intercept.sh` | 两个 client intercept 都建独立 Session，回程保留原 ifindex |
| `e2e_v1_malformed_ingress.sh` | 真实 AF_PACKET 注入 userspace truncated TCP、unknown NAT tuple、XDP 截断 IPv4/错误 IPv4 length/截断 IPv6 extension/错误 tunnel UDP length，以及合法 UDP 封装的 invalid QUIC；分别断言 `malformed_drops`、`unknown_nat_tuple_drops`、`xdp_parser_drops`、`invalid_quic_drops` 增长，daemon 存活且合法矩阵恢复 |
| `e2e_v1_nat_capacity.sh` | 默认 2 lanes 各分配一个 client NAT port；两个稳定映射到同一 lane 的 UDP 五元组证明该 lane 端口耗尽时拒绝新流、`session_nat_exhausted` 增长且已有 flow 仍持续回包 |
| `e2e_v1_recovery.sh` | 默认两条 lane 在 SIGHUP 后分别推进 `quic_flow_id`、重新认证并恢复普通业务；Session/NAT rebind 身份保持由集成测试覆盖 |
| `e2e_v1_reliability.sh` | 1472-byte payload、12 秒双栈 TCP idle、默认 2 lanes、SIGKILL stale stats/owner 恢复；随后 SIGTERM 正常 detach，再挂载 foreign XDP 并证明启动失败不会替换它 |

E2E 同时断言业务结果和 JSON stats，不只以“ping 通”作为成功标准。成功业务矩阵
还要求动作前后 IO/Flow/dispatcher 异常与 drop counter 无新增。

## 5. Soak 与性能

`script/acceptance/v1/soak_v1.sh` 每轮运行完整双栈协议矩阵并强制重连。每轮重连后
必须满足：

- 固定时长双栈 TCP/UDP 并发 echo 在负载期间持续成功，且异常/drop counter 无新增。
- 双端所有 lane 重新认证。
- 每个存活 Session 的 `quic_flow_id` 等于所属 worker 的新 flow identity，普通
  Session/NAT/reverse NAT 不因 transport 重连被错误清空。
- 每条 lane 的 active DCID 已重新建立。
- 最终 FD 数无漂移。
- 负载期间 FD 峰值不超过并发预算。
- IO owner 数无漂移。
- 最终 RSS 增长不超过 `V1_SOAK_RSS_GROWTH_KB`，默认 32 MiB；采样峰值增长不超过
  `V1_SOAK_RSS_PEAK_GROWTH_KB`，默认 64 MiB。

`script/perf/perf_v1.sh` 是可复现性优先的功能性能基线，报告 v4/v6 TCP/UDP
echo 的 nearest-rank p50/p99 延迟、固定时长窗口化并发吞吐、总耗时以及每个 IO
queue 的 RX/TX/drop。吞吐负载默认使用
`V1_PERF_LOAD_CONCURRENCY=8`、`V1_PERF_LOAD_WINDOW=32` 和
`V1_PERF_LOAD_PAYLOAD_SIZE=1200`；窗口化发送避免 stop-and-wait 把单次 RTT
直接变成吞吐上限。默认要求各路径 p99 不超过 `V1_PERF_MAX_P99_MS=250`、吞吐不低于
`V1_PERF_MIN_MBIT_PER_SECOND=0.1`，且异常/drop counter 无新增；目标环境应收紧
这两个可配置预算。veth `skb` 仍包含虚拟链路、SKB copy、netns 调度和 Python echo
开销，结果不代表物理 NIC `native`/zero-copy XDP 的单核上限。
该脚本默认继承 `V1_FLOW_WORKER_COUNT=2`；做 lane A/B 时必须只改变这个变量并使用
相邻、相同时长和相同 payload/concurrency/window 的多次样本。

## 6. IP/DNS 策略分流新增覆盖

`doc/IP_DNS_POLICY.md` 描述的 direct prefix 文件、反向分流和 UDP DNS VIP 是新增
功能范围。配置解析、userspace IP policy、XDP policy mode、DNS parser/transaction、
FlowWorker DNS packet rewrite、runtime query/response 路径和 root netns 下本地/远端
resolver 闭环已有覆盖；下列清单作为当前覆盖映射，未列入当前测试资产的项目不能从
现有结果推导。

### 配置、文件和严格校验

- `AllowedIPs.Prefixes` 的 inline、`file:`、`!file:` 三种互斥模式。
- 混用模式、文件缺失、不可读、非法 CIDR 和 LPM capacity 溢出均启动失败；重复
  CIDR 规范化后去重。
- client `[DNS]` 的 `Listen`、`LocalResolver`、`RemoteResolver`、
  `RemoteDomainsFile`、`TransactionCapacity` 和 `TimeoutSeconds` 完整校验。
- server 拒绝 `[DNS]`，且不再要求没有运行时语义的 `[AllowedIPs]`。
- remote domain 文件的大小写规范化、末尾点、非法 label、重复规则、4 MiB/65536
  容量限制和 label 边界后缀索引。

### IP 分类和 XDP 顺序

- IPv4/IPv6 direct prefix 命中直连，未命中的公网地址进入 QUIC。
- 正向 file mode 只 redirect 文件内 tunnel prefix，其他地址 `XDP_PASS`。
- 私网、CGNAT、ULA、link-local、multicast、unspecified、文档/基准/协议保留地址、
  tunnel endpoint、本机 tunnel address 和本节点 NAT address 不被默认 redirect。
- DNS VIP UDP/53 优先于私网/direct prefix 规则；DNS VIP 非 UDP/53 本地处理。
- `LocalResolver:53` 候选回包先 redirect 到 userspace，再由 DNS reverse directory
  精确命中；未命中必须 fail closed。
- DNS VIP 分片查询在 XDP/IO worker fail closed，不进入普通流量路径；IPv6 extension
  header 后的 UDP/Fragment header 使用真实 transport offset 分类。
- LPM map capacity 扩大、完整 map 写入和两阶段 classifier enable 失败回滚；attach
  后 program ID/owner record 失败也按精确 program ID 回滚。

### DNS parser、transaction 和错误路径

- `google.com` 匹配自身与 `www.google.com`，不匹配 `notgoogle.com`。
- 标准 query、单 Question、QNAME compression、compression loop、坏 QNAME、
  多 Question 和非标准 opcode。
- EDNS advertised UDP payload clamp 到 1232，并验证 IP/UDP checksum 正确。
- 超过 1232 bytes 的 DNS query 返回 `SERVFAIL`；超限或分片 resolver response
  丢弃且不消费 transaction，后续有效 response 或 timeout 仍可完成原 transaction。
- 相同 DNS ID 来自不同 client、不同 QNAME/QTYPE/QCLASS 时 transaction 不冲突。
- transaction key 稳定选择 Flow worker；未完成重传复用 transaction 和 NAT port。
- 唯一 Question 可解析但后续 section malformed 的 UDP/53 查询走 LocalResolver
  fallback，并使用 payload-hash key。
- DNS `QR=1`、多 Question、非标准 opcode 或无法安全解析 Question 的请求立即
  `SERVFAIL`。
- capacity exhaustion、NAT port exhaustion、resolver timeout、QUIC 未认证 remote 查询
  都返回 `SERVFAIL`，并释放 transaction、reverse index 和 NAT port。
- resolver source/destination tuple、wire ID、Question 不匹配，或重复响应和迟到响应，
  均丢弃并计数。

### 集成、E2E 和可观测性

- root E2E 中 mock local/remote resolver 返回不同固定答案，证明 domain 选择路径
  正确；remote resolver 返回实际 target 地址后继续发起业务连接，证明 DNS response
  不会改变静态 IP policy。
- root E2E 覆盖 IPv4/IPv6 本地域名经 client 本地 resolver 闭环；remote domain 经
  client SNAT、QUIC、server SNAT 到 remote resolver 闭环。
- root E2E 断言 local resolver 观察到 client NAT，remote resolver 观察到 server NAT。
- root E2E 断言 DNS 响应返回给客户端时 source 恢复为 DNS VIP:53。
- root E2E 覆盖 remote resolver timeout，并断言客户端收到 `SERVFAIL`。
- QUIC 未认证时 remote domain 查询 `SERVFAIL`，local domain 查询仍可成功。
- DNS response 不生成动态 IP 路由；后续业务连接仍按目的 IP direct prefix 决策。
- server stats 和状态中不得出现 DNS transaction 或 DNS 专用 QUIC message。
- stats 至少断言 local/remote query、local/remote response、`SERVFAIL`、timeout、
  active transaction gauge。capacity/NAT exhaustion、malformed fallback、
  spoofed/late drop、EDNS clamp、unknown DNS transaction drop 和 fragmented DNS drop
  由 Rust 单元/集成测试断言，不从当前 root E2E 推导。

## 7. 明确未覆盖

下列内容不属于当前 v1 自动门禁，不能从现有测试结果推导：

- 具体物理 NIC/驱动的 native XDP、zero-copy 能力和线速吞吐。
- 多队列 RSS、CPU/NUMA affinity 的性能扩展曲线。
- 非 DNS IP 层分片、IPv6 ESP/未知 extension header、PMTU discovery 和超过 65535
  bytes 的 inner packet。
- 动态 ARP/NDP；当前 next-hop MAC 由配置提供。
- 持续攻击流量、持续公网故障和目标 NIC 满带宽长稳仍需在部署环境单独验证；仓库
  已覆盖单次 malformed/unknown-NAT 注入和 NAT 容量耗尽，bounded soak 只提供固定
  时长并发负载、资源峰值和状态回收门禁。
- supervisor 的具体重启时延；SIGKILL 后立即手工重启、SIGTERM detach 和 foreign
  XDP ownership 保护已进入 E2E。
- 长时间公网丢包、乱序、NAT rebinding 与恶意流量压力。
- 多 peer、多 server intercept、TUN、WireGuard、hybrid 或动态控制面；这些是非目标，
  不是待恢复的兼容测试。

物理上线前应在目标 NIC、queue 数、CPU/NUMA 绑定和真实 MTU 上单独执行 soak、
故障注入与容量测试，并保存该环境的基线。
