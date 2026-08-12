# AF_XDP QUIC Appliance v1 硬切重构设计

## 1. 状态

- 日期：2026-08-11
- 状态：已批准，进入实施
- 输入规格：
  - `doc/ARCHITECTURE.md`
  - `doc/TESTING.md`
- 决策：不兼容旧 TUN、WireGuard、hybrid、动态 peer、多 client 测试和运行路径。

## 2. 背景

当前 `Mode = af_xdp` 并不是目标架构中的“AF_XDP I/O + QUIC 加密 Flow plane”。它同时运行两套数据路径：

1. AF_XDP worker 直接把 inner IPv4 包包装为外层 UDP，属于明文旁路。
2. 旧 TUN worker 通过 `quinn-proto` 完成真正的 QUIC 加密传输。

现有 acceptance 主要验证 TUN、动态 peer、WireGuard/hybrid 和多 client 行为，与 v1 目标架构不一致。继续维持这些兼容要求会迫使新旧数据面长期并存，使 Session ownership、NAT、queue ownership 和恢复语义无法收敛。

本次重构采用硬切：先替换测试门禁，再按照新门禁逐步实现目标架构，最终删除旧实现。

## 3. 目标

重构完成后，仓库只保留以下主路径：

- 单 `client <-> server`
- 固定拓扑
- `AF_XDP` 主数据面
- QUIC 加密内层 IPv4/IPv6 流量
- `IO worker` 独占 `(ifindex, queue_id)` 对应 XSK rings
- `Flow worker` 独占 Session、双层 SNAT、reverse NAT 和 QUIC flow
- 已注册 tunnel ingress 通过 `active_dcid -> flow_worker_id` 分发
- 未知 `DCID` 只能进入确定性 bootstrap 或被丢弃
- 本地出口通过 Session 保存的 `(intercept_ifindex, intercept_queue_id)` 恢复

## 4. 非目标

以下能力直接退出实现和门禁，不保留兼容层：

- TUN 主数据面
- WireGuard peer 和 hybrid gateway
- 动态 peer 增删
- 多 client peer、多租户
- 旧的端口数等于 worker 数的固定 TUN/QUIC 映射
- AF_XDP 明文 inner-IP-over-UDP 封装
- 同 queue 多 XSK 共享 `Fill/Completion`
- 为旧配置字段提供兼容解析

## 5. 方案选择

### 5.1 采用方案：测试先行硬替换

先删除旧 acceptance gate，建立 v1 测试目录和统一 runner。随后按测试失败顺序实现 Flow plane、QUIC ownership、AF_XDP I/O 和 E2E。

优点：

- 测试目标与架构文档立即一致。
- 不需要维护两套互相矛盾的正确性定义。
- 每个实现增量都有明确的失败测试和完成条件。
- 旧代码删除边界清晰。

代价：

- 重构过程中本地工作树在单个 TDD 循环内会短暂处于 RED 状态，但可共享提交和远端分支不得保留 RED 状态。
- 旧部署配置和旧 acceptance 不再可用。
- 第一个可运行的 v1 E2E 到来前，只能依靠单元和集成测试验证。

### 5.2 未采用：兼容式双路径迁移

保留旧 TUN/hybrid gate，在旁路新增 v1 Flow plane，待新路径完成后再切换。

未采用原因：用户明确不要求旧兼容；双路径会继续放大 `src/xdp_datapath/worker.rs` 和运行时装配复杂度。

### 5.3 未采用：一次性整体重写

一次删除旧路径并直接实现完整 v1。

未采用原因：缺少可定位失败的中间检查点，AF_XDP、QUIC、NAT 和 E2E 任一问题都会阻塞整体调试。

## 6. 目标模块边界

### 6.1 配置与启动

配置只描述一个固定 client/server appliance：

- role：`client` 或 `server`
- `tunnel_interface`
- 一个或多个 client `intercept_interface`
- server 只允许一个 `intercept_interface`
- `flow_worker_count`
- 固定非零 `dcid_len`
- client 的 server endpoint
- server 的监听地址
- client/server 各自的 SNAT 地址和端口范围
- `AllowedIPs`
- XDP attach mode

启动前完成全部配置校验。非法拓扑、重复 interface、零 queue、零长度 `DCID`、无效 SNAT 范围必须直接失败。

### 6.2 IO plane

新增明确的 `IoOwnerKey`：

```rust
pub struct IoOwnerKey {
    pub ifindex: u32,
    pub queue_id: u32,
}
```

`IoRegistry` 保存所有参与数据面的 `(ifindex, queue_id)`，每个键只能注册一个 `IO worker`。`queue_id` 不得脱离 `ifindex` 单独查找。

每个 `IO worker`：

- 独占一个 XSK 的 RX/TX/Fill/Completion rings
- 解析必要的 L2/L3/L4 或 QUIC header
- 向 Flow plane 投递消息
- 接收 Flow plane 的发送请求并补齐 L2
- 不创建、不修改 Session 或 NAT 状态

同一物理 interface 同时承担 tunnel/intercept 角色时，仍只有一个 `(ifindex, queue_id)` owner；owner 根据报文类型分发到不同逻辑 pipeline，不能创建第二个同 queue XSK。

### 6.3 Flow plane

新增独立、无 AF_XDP 系统调用依赖的 Flow plane 模块，核心类型包括：

- `FlowKey`：IPv4/IPv6 五元组
- `SessionId`
- `Session`
- `QuicFlowId`
- `QuicFlow`
- `NatBinding`
- `ReverseNatKey`
- `FlowWorkerState`
- `FlowMessage`
- `IoTransmit`

`FlowWorkerState` 是所属 Session、NAT 和 QUIC flow 的唯一可变 owner。跨 worker 只允许传递不可变报文数据和稳定 ID，不共享可写 Session。

### 6.4 Session 与双层 NAT

client 和 server 分别维护本地 Session，不共享 Session 对象。

每个 Session 至少保存：

- 原始五元组
- 本节点 SNAT 后五元组
- `flow_worker_id`
- `intercept_ifindex`
- `intercept_queue_id`
- `quic_flow_id`

NAT 必须保证：

- 一个原始流只创建一个绑定
- SNAT tuple 在本节点内唯一
- reverse NAT 唯一返回 `(flow_worker_id, session_id)`
- Session 删除时正向和反向索引原子清理
- 未命中 reverse NAT 不创建 Session
- 连接重建时，绑定旧 `quic_flow_id` 的 Session 和 NAT 一起回收

第一版使用确定性的顺序端口分配器和显式释放，不引入复杂并发分配器。

### 6.5 QUIC flow 与 DCID

QUIC engine 使用现有 `quinn-proto` 能力，但从 TUN worker 中拆出，归属 Flow worker。

规则：

- `QuicFlow` 创建时分配稳定 `quic_flow_id`
- 创建时绑定稳定 `tunnel_queue_id`
- 后续 DCID 轮换不得改变 `tunnel_queue_id`
- 一个 `QuicFlow` 的全部活动 DCID 指向同一个 Flow worker
- active DCID 索引只负责解密前分发，不是 Session 主键
- 合法未知 DCID 的 bootstrap owner 为 `hash(dcid) % flow_worker_count`
- bootstrap 只创建 QUIC ownership，不创建业务 Session
- 非法未知 DCID 丢弃并计数
- 连接重建创建新的 `quic_flow_id`，不迁移旧 Session

固定 `dcid_len` 用于 short-header 报文解析。

### 6.6 运行时消息

IO plane 向 Flow plane：

```rust
pub enum FlowMessage {
    InterceptIngress {
        io_owner: IoOwnerKey,
        packet: bytes::Bytes,
    },
    TunnelIngress {
        io_owner: IoOwnerKey,
        dcid: bytes::Bytes,
        packet: bytes::Bytes,
    },
}
```

Flow plane 向 IO plane：

```rust
pub struct IoTransmit {
    pub target: IoOwnerKey,
    pub packet: bytes::Bytes,
}
```

第一版统一使用有界 `std::sync::mpsc::sync_channel`。通道满时必须丢弃并计数，不允许无限内存增长。

## 7. 测试门禁硬替换

### 7.1 删除旧门禁

从统一 gate 删除并最终删除以下脚本：

- `e2e_test_dualstack.sh`
- `e2e_multi_client.sh`
- `e2e_dynamic_client_peer.sh`
- `e2e_client_topology_gate.sh`
- `e2e_full_tunnel_bypass.sh`
- `e2e_mss_clamping.sh`
- `e2e_udp_icmp_tunnel.sh`
- `e2e_udp_over_quic.sh`
- `e2e_hybrid_wireguard.sh`
- `e2e_hybrid_ha_reconnect.sh`
- 旧 TUN/WireGuard 性能脚本和稳定性脚本

与旧路径专用的 Python helper 一并删除；通用流量生成器只有在新 v1 E2E 使用时才保留。

### 7.2 新统一门禁

`script/acceptance/run_acceptance.sh` 改为以下顺序：

1. `cargo fmt --check`
2. 全部现存 target 的 offline `cargo check`
3. 全部现存 target 的 Clippy `-D warnings`
4. 全部 v1 library 单元测试
5. v1 集成测试
6. v1 E2E
7. 可选 soak/perf

runner 不再引用 legacy、TUN、WireGuard、动态 peer 或 multi-client 脚本。
由于旧 modules、binary 和 test targets 已全部删除，`--all-targets` 只覆盖 v1，
不会重新启用旧 test harness。

### 7.3 单元测试

优先建立以下 RED 测试：

- 配置拒绝多 peer、WireGuard、TUN 和 server 多 intercept interface
- `IoRegistry` 使用完整 `(ifindex, queue_id)` 且拒绝重复 owner
- 五元组解析覆盖 IPv4/IPv6 TCP/UDP/ICMP
- Session 只能由一个 Flow worker 创建
- client/server SNAT tuple 唯一
- reverse NAT 唯一命中
- Session 回收同步清理正反索引
- 重复/乱序包不重复建 Session
- QUIC flow 的 queue 绑定不随 DCID 轮换漂移
- active DCID 发布、退休和连接关闭清理
- 未知 DCID bootstrap 稳定且不创建业务 Session
- QUIC flow 重建回收旧 Session/NAT
- server 默认 queue 被真实回包纠正后不再回退

### 7.4 集成测试

不依赖真实 XSK 的进程内集成测试：

- 多个 IO owner 向多个 Flow worker 投递
- 同 Session 后续包稳定命中 owner
- Flow worker 生成唯一 `IoTransmit.target`
- client 多 intercept interface 回投正确
- tunnel/intercept queue 数不同不混用 queue 空间
- 同 interface 的 tunnel/intercept 分类不形成环路
- channel 背压不会改变 ownership

### 7.5 v1 E2E

新脚本只覆盖：

- `e2e_v1_client_to_target.sh`
- `e2e_v1_server_return.sh`
- `e2e_v1_client_return.sh`
- `e2e_v1_same_interface.sh`
- `e2e_v1_multi_intercept.sh`
- `e2e_v1_recovery.sh`

协议矩阵至少包含 IPv4/IPv6 的 TCP、UDP、ICMP。每个 E2E 同时断言：

- 业务结果
- 抓包结果
- Session/NAT/worker/DCID 运行时统计

仅“业务能通”不算通过。

## 8. 实施顺序

### 阶段 1：替换门禁和建立 RED 测试

- 删除旧 acceptance 列表
- 建立 v1 runner 和测试文件
- 先实现纯类型/纯函数测试夹具
- 运行聚焦测试并确认失败原因是目标能力缺失

### 阶段 2：实现纯 Flow plane

- 五元组与 packet parser
- IO owner registry
- Session table
- 双层 NAT 和 reverse NAT
- QUIC flow/DCID ownership
- queue correction

该阶段不触碰真实 AF_XDP ring，可在普通 `cargo test` 环境完成。

### 阶段 3：接入现有 `quinn-proto`

- 从 `rtc_loop.rs` 提取可复用 QUIC engine
- 删除 TUN read/write 依赖
- 让 Flow worker 直接接收 inner packet 并产生外层 QUIC packet
- 完成 DCID bootstrap 和 active index

### 阶段 4：重写 AF_XDP worker 装配

- 拆分当前 3000 行 `worker.rs`
- 一个 `(ifindex, queue_id)` 只创建一个 XSK owner
- IO worker 通过消息与 Flow worker 通信
- 删除明文 `wrap_plaintext_to_quic_slice` / `unwrap_quic_to_plaintext_slice`
- 删除 AF_XDP 路径中的 TUN worker 启动

### 阶段 5：删除 legacy 实现

- 删除 TUN datapath、WireGuard/hybrid、动态 peer 和旧控制 API
- 删除旧配置字段和运行时状态
- 删除不再使用的依赖、脚本和测试
- 更新 README 和示例配置

### 阶段 6：E2E、恢复、长稳和性能

- 建立新 netns 拓扑
- 跑通四条核心路径
- 验证 queue/interface 边界
- 验证连接重建和状态清理
- 增加 soak/perf，但不在正确性 gate 变绿前优化

## 9. 增量提交规则

- 每个任务遵循 RED -> GREEN -> REFACTOR。
- RED 只在本地聚焦测试中保留；每个可共享提交必须恢复该任务相关门禁为 GREEN。
- 不把当前工作树中已有的 `src/quic_pool.rs`、`src/routing.rs`、`src/runtime.rs`、`src/xdp_datapath/worker.rs` 改动误删或覆盖。
- 旧文件删除与新实现分阶段提交，确保每个提交可以独立审查。
- 不为已经明确删除的旧能力添加兼容层或 feature flag。

## 10. 完成标准

重构完成必须同时满足：

- 旧 acceptance 和旧运行路径已删除。
- `Mode = af_xdp` 不再存在明文 inner-IP-over-UDP 路径。
- AF_XDP 主路径不创建 TUN 设备。
- 所有 XSK owner 使用完整 `(ifindex, queue_id)`。
- Session/NAT 只由 Flow worker 修改。
- tunnel ingress、DCID 生命周期和 bootstrap 符合架构文档。
- client/server 双层 SNAT 和 reverse NAT 测试通过。
- 六个 v1 E2E 全部通过。
- `fmt/check/clippy/test/build` 全部通过。
- soak 不出现 Session、NAT、DCID、XSK 或 ring 资源泄漏。
