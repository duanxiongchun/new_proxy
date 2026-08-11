# new_proxy 测试说明与覆盖矩阵（AF_XDP QUIC Appliance v1）

本文档对应 [ARCHITECTURE.md](/data00/home/duanxiongchun/new_proxy/doc/ARCHITECTURE.md) 中定义的 v1 主架构，而不是旧的 TUN 主路径、WireGuard 混合模式或“明文 inner IP 直接包装到外层 UDP”的过渡实现。

## 文档状态

* **定位**：v1 目标测试设计与覆盖矩阵，不是当前仓库所有测试资产的逐项现状清单。
* **当前实现状态**：仓库中的默认测试入口仍混合包含 legacy、transitional 和部分 v1 相关路径。
* **阅读方式**：本文档中的条目如果尚未有对应测试实现，应理解为待补齐的目标 gate，而不是已经由当前 `cargo test` 或默认 acceptance 自动证明成立。

当前测试目标只有一件事：定义下面这套主设计在功能、边界和长期稳定性上最终需要被怎样验证。

* `AF_XDP` 是主数据面
* `IO worker` 只拥有 `(ifindex, queue_id)` 与 XSK ring
* `Flow worker` 是唯一 Session owner
* client/server 都在各自节点上维护本地 Session、本地 SNAT、本地 reverse NAT
* `tunnel ingress` 通过 `DCID` 把报文送到正确 `Flow worker`
* 本地明文回投必须根据 Session 记录的 `(intercept_ifindex, intercept_queue_id)` 走正确出口

---

## 1. 测试原则

### 1.1 测什么
v1 的测试不是先追求“跑得快”，而是先验证下面几个硬约束没有被破坏：

* `IO worker` 不能创建 Session
* `Flow worker` 必须独占 Session 与 NAT 状态
* `intercept_queue_id` 与 `tunnel_queue_id` 不能混用
* 客户端发往隧道前必须先经过 `AllowedIPs`
* 服务端首次向本地网络发包时允许使用默认出口队列，后续必须能被真实回包纠正
* 同一个 Session 后续包必须稳定命中同一个 `Flow worker`

### 1.2 不测什么
以下内容不属于 v1 测试主线，文档中不再继续保留对应验收项：

* WireGuard 混合网关
* TUN 主数据面
* 同 queue 多 XSK 共享 `Fill/Completion`
* 多 peer / 多 server `intercept_interface`
* 依赖 NIC RSS 可编程能力的复杂 fan-out

### 1.3 当前测试资产与本文档的关系

当前仓库中的测试资产需要按三类理解：

* **当前有效基础 gate**：`cargo fmt --check`、`cargo check`、`cargo clippy --all-targets -- -D warnings`、`cargo test`
* **过渡期综合回归**：当前 `script/acceptance/run_acceptance.sh` 仍覆盖 legacy、transitional 与部分 v1 相关场景，它不是本文档定义的纯 v1 gate
* **本文档目标 gate**：只有当 worker ownership、Session/NAT、隧道分发和四条核心路径的验证真正落地后，才能把对应条目标记为已实现

### 1.4 测试分层

```
+------------------------------------------------------+
|                    测试金字塔                        |
|                                                      |
|  Soak / Perf    -> 长稳、资源不泄漏、队列绑定不漂移   |
|  E2E            -> 四条核心路径、双层 SNAT、回程恢复  |
|  Integration    -> worker 边界、索引一致性、配置装配  |
|  Unit           -> AllowedIPs、hash、SNAT、Session    |
+------------------------------------------------------+
```

---

## 2. 需要覆盖的关键状态

测试设计必须围绕以下状态对象展开，而不是只看“包有没有通”：

* **Session**
  * 原始五元组
  * 本节点 SNAT 后五元组
  * `flow_worker_id`
  * `intercept_ifindex`
  * `intercept_queue_id`
  * `quic_flow_id`
* **QUIC flow**
  * 所属 `flow_worker_id`
  * 稳定的 `tunnel_queue_id`
  * 一组可用于 tunnel ingress 分发的活动 `DCID`
* **派生索引**
  * `active_dcid -> flow_worker_id`
  * reverse NAT 只读索引 `snat_tuple -> (flow_worker_id, session_ref)`

在本文档中，`tunnel ingress` 的外层分发键统一定义为 `DCID`。
如果后续架构决定更换该分发键，应先同步修改 [ARCHITECTURE.md](/data00/home/duanxiongchun/new_proxy/doc/ARCHITECTURE.md)，而不是在本文件中保留泛化表述。

---

## 3. Rust 单元与集成测试

基础命令：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

这些命令是当前最基础的质量门禁，但它们本身并不等价于本文档后续章节描述的完整 v1 覆盖度。

### 3.1 配置与装配测试

配置测试的目标是把错误挡在进程启动前。

应至少覆盖：

* `tunnel_interface` 与 `intercept_interface` 的配置解析
* 客户端多个 `intercept_interface` 的合法性校验
* 服务端 v1 只允许一个 `intercept_interface`
* `tunnel_interface == intercept_interface` 时允许启动，但必须进入“双逻辑 pipeline”模式
* 每个 interface 的真实队列数读取与 worker 数量装配
* `IO worker` 按所有参与数据面的 `(ifindex, queue_id)` 集合创建，每个键必须唯一对应一个 owner
* `queue_id` 查找必须使用 `(ifindex, queue_id)`，不能只用 `queue_id`
* 无法创建某个 XSK 时，启动必须失败或明确降级，不能静默缺 worker

### 3.2 XDP / AF_XDP 单元测试

这部分验证“包是否被送进正确 XSK”，而不是验证完整业务功能。

应至少覆盖：

* `AllowedIPs` 命中时才会把客户端 `intercept ingress` redirect 到 XSK
* 未命中 `AllowedIPs` 时严格 `XDP_PASS`
* 外层 QUIC/UDP 包与本地明文业务包在同一 interface 上能够被正确区分
* `1 (ifindex, queue_id) -> 1 IO worker` 的 ownership 不被打破
* 不允许同 queue 多 XSK 共享 `Fill/Completion` 的配置进入运行态
* `tunnel IO worker` 只做轻量头部解析与投递，不参与解密与 Session 创建
* 固定且非零的 `DCID` 长度配置可以正确解析 QUIC long-header 与 short-header 报文
* 外层报文格式异常时能够被安全丢弃并记账，例如过短 UDP 负载、无法按固定长度提取 `DCID`、零长度 `DCID`
* `RX` ring / `TX` ring / `Fill` ring / `Completion` ring 出现背压或耗尽时，不会破坏 ownership，也不会把包误投给其他 worker
* 邻居解析与 L2 补全成功时可以正常发包，解析失败或缓存失效时会按预期重试、丢弃或记账，而不是静默卡死

### 3.3 Session 与 NAT 单元测试

这是 v1 最关键的一组测试。

应至少覆盖：

* 新建 Session 时只允许在 `Flow worker` 内完成
* Session 保存原始五元组和本节点 SNAT 后五元组
* 客户端侧 SNAT 能为不同原始五元组分配无冲突的外层本地 tuple
* 服务端侧 SNAT 能为不同隧道内会话分配无冲突的本地业务出口 tuple
* reverse NAT 可以从 SNAT 后 tuple 唯一命中 `(flow_worker_id, session_ref)`
* Session 回收时，正向 NAT 与 reverse NAT 索引必须一并删除
* 重复包、乱序包命中已有 Session 时，不能重复建 Session
* 不同 `Flow worker` 之间不能同时持有同一 Session
* Session 超时、主动关闭或异常回收后，不会遗留脏的 NAT / reverse NAT / `quic_flow_id` 绑定
* reverse NAT 未命中时，不会错误创建新 Session，也不会把包投递给错误的 `Flow worker`

### 3.4 QUIC flow 与隧道分发测试

应至少覆盖：

* `Flow worker` 可以创建多个 `QUIC flow`
* 每个 `QUIC flow` 在创建时绑定一个稳定 `tunnel_queue_id`
* 同一个 `QUIC flow` 的后续发包不能因为后续 `DCID` 变化而漂移到其他 queue
* `tunnel ingress` 必须通过 `DCID` 命中 `flow_worker_id`
* `quic_flow_id` 是 Session 的稳定连接绑定，而不是把 `DCID` 当作长期主键
* 活动 `DCID` 轮换时，新的 `DCID` 加入分发表，旧的 `DCID` 被删除后不再命中原 worker
* 同一个 `QUIC flow` 的全部活动 `DCID` 始终映射到同一个 `Flow worker`
* 连接重建时创建新的 `quic_flow_id`，绑定旧 `quic_flow_id` 的 Session 与本地 NAT 状态被完整回收，不发生隐式迁移
* 合法的新连接首包使用 `hash(dcid) % flow_worker_count` 稳定命中唯一 bootstrap owner，并在创建 `QUIC flow` 后发布 active DCID 映射
* 不能识别为合法 bootstrap 的未知 `DCID` 报文会被丢弃并记账，不会随机投递或创建业务 Session

### 3.5 worker 边界与消息传递测试

这部分验证“谁负责什么”没有被写乱。

应至少覆盖：

* `intercept IO worker` 收包后只提取五元组、记录 `ifindex/queue_id`、投递给 `Flow worker`
* `Flow worker` 收到首包后创建 Session 并写入入口 `intercept_ifindex/intercept_queue_id`
* `Flow worker` 发往本地网络时能解析到唯一 `(intercept_ifindex, intercept_queue_id)` 对应的 `IO worker`
* `Flow worker` 发往隧道时能解析到唯一 `(tunnel_ifindex, tunnel_queue_id)` 对应的 `IO worker`
* 任何跨线程投递都不改变 Session owner
* `IO worker` 崩溃或重建时，不能导致 Session ownership 漂移

### 3.6 DCID 生命周期集成测试

围绕架构中已经确定的 bootstrap 和索引生命周期，应至少覆盖：

* 相同未知 `DCID` 的合法新连接首包重复到达时，始终命中同一个 bootstrap owner
* bootstrap 只创建 `QUIC flow` 和 active DCID 映射，不创建业务 Session
* 新 `DCID` 发布映射后才能承担普通 tunnel ingress 分发
* 退休 `DCID` 删除后不再命中原 owner，连接关闭时该 flow 的全部 DCID 映射被删除
* `DCID` 轮换过程中，新旧活动映射只能指向同一个 owner

---

## 4. 四条核心 E2E 路径

E2E 测试必须直接覆盖架构文档中的四个核心过程。

### 4.1 Client 发包 -> Server 收包 -> Server 发往目标网络

建议场景名：`e2e_client_to_server_to_target`

验证点：

* 业务包从 client `intercept_interface` 进入后，先经过 `AllowedIPs`
* 命中流量被送入 client `intercept IO worker`
* 首包按原始五元组 hash 落到唯一 `Flow worker`
* client `Flow worker` 创建 Session 并完成客户端侧 SNAT
* 包通过某个 `QUIC flow` 加密后，从其绑定的 `tunnel_queue_id` 发出
* server `tunnel IO worker` 通过 `DCID` 把包送到正确 `Flow worker`
* server `Flow worker` 解密、建 Session、执行服务端侧 SNAT
* server 首次向本地业务网络发包时，从默认 `(intercept_ifindex, queue_id=0)` 发出

### 4.2 Server 收到目标网络回包 -> 回隧道

建议场景名：`e2e_server_return_to_tunnel`

验证点：

* 目标网络回包从 server 唯一 `intercept_interface` 进入
* `intercept IO worker` 通过 reverse NAT 只读索引命中 `flow_worker_id` 和 `session_ref`
* 本次真实收到回包的 `intercept_ifindex/intercept_queue_id` 会被回填到 Session
* 之后同 Session 再向本地业务网络发包时，不再继续使用默认 queue
* 回包根据 Session 中的 `quic_flow_id` 返回原 `QUIC flow`
* 返回隧道时仍然落在该 `QUIC flow` 绑定的稳定 `tunnel_queue_id`

### 4.3 Client 收到隧道回包 -> 回投本地网络

建议场景名：`e2e_client_tunnel_to_local`

验证点：

* client `tunnel IO worker` 可通过 `DCID` 把包送到正确 `Flow worker`
* client `Flow worker` 能根据客户端本地 Session 执行 reverse NAT
* 回包直接发回首包记录的 `intercept_ifindex/intercept_queue_id`
* 如果客户端存在多个 `intercept_interface`，回包必须回到正确 interface，而不是随机落口

### 4.4 同接口模式

建议场景名：`e2e_same_tunnel_and_intercept_interface`

验证点：

* `tunnel_interface == intercept_interface` 时，外层 QUIC/UDP 与本地明文流量仍能正确区分
* 同一块网卡上的 tunnel pipeline 与 intercept pipeline 不会相互误判
* 不会把外层包再次当作明文业务包送入隧道形成环路

### 4.5 协议矩阵 E2E

建议场景名：`e2e_protocol_matrix`

验证点：

* IPv4 TCP 在四条核心路径上闭环正确
* IPv4 UDP 在四条核心路径上闭环正确
* IPv4 ICMP 在四条核心路径上闭环正确
* IPv6 TCP 在四条核心路径上闭环正确
* IPv6 UDP 在四条核心路径上闭环正确
* IPv6 ICMP 在四条核心路径上闭环正确
* 不同协议共存时，不能因为只按某一种协议特征建 Session 而互相污染
* 分片包、超 MTU 包或不支持的报文类型如果不在 v1 支持范围内，行为必须明确为拒绝、旁路或丢弃，并且可以观测

---

## 5. 关键边界场景

### 5.1 客户端多个 intercept_interface

验证点：

* 不同入口 interface 上的新流会被记录各自的 `intercept_ifindex`
* 同一目标地址从不同入口 interface 进入时，回包仍按各自 Session 回到原入口
* 不能只按五元组忽略入口 interface，否则会把回包发错口

### 5.2 `intercept_interface` 与 `tunnel_interface` 队列数不同

验证点：

* `intercept_queue_id` 与 `tunnel_queue_id` 分别按各自 interface 的真实队列数计算
* `Flow worker` 发往隧道时只看 `tunnel_queue_id`
* `Flow worker` 发往本地网络时只看 `intercept_ifindex/intercept_queue_id`
* 任何实现如果复用了错误的 queue 空间，测试必须能把它打出来

### 5.3 默认服务端出口队列回填

验证点：

* 首次 server 向本地网络发包时，允许默认从 queue `0` 发出
* 一旦真实回包从其他 queue 进入，Session 中的 `intercept_queue_id` 必须被更新
* 更新后后续本地业务出口必须跟随真实 queue，而不是一直停在默认值

### 5.4 多流并发与无冲突 SNAT

验证点：

* 单个 client appliance 内多个并发新流命中不同 `Flow worker` 时，SNAT 分配不能冲突
* 同一 client 高频建连/断连后，SNAT tuple 释放与复用必须正确
* 多个 `QUIC flow` 并行存在时，`quic_flow_id -> tunnel_queue_id` 绑定必须保持稳定

### 5.5 乱序、重复与重传

验证点：

* 重复首包不能创建重复 Session
* 已有 Session 的乱序包不能错误刷新到其他 `Flow worker`
* 某个 `QUIC flow` 短暂抖动但连接对象未重建时，不应导致回包路径丢失
* 连接对象重建后，旧 Session 与本地 NAT 状态被回收，后续流量通过新 Session 恢复

---

## 6. 场景测试

场景测试和 E2E 不完全相同。
E2E 更关注“从入口到出口整条路径是否成立”，场景测试更关注“异常、恢复、退化和策略边界是否成立”。

### 6.1 策略场景

建议至少覆盖：

* `AllowedIPs` 未命中时，流量不会进入隧道，而是继续本地协议栈路径
* 服务端收到不属于任何已知 Session 的回包时，不会错误 reverse NAT
* 未知 `DCID` 的外层隧道包到来时，行为符合 bootstrap 或丢弃规则
* 配置非法的 interface、queue 数或 worker 装配关系时，进程启动失败并给出明确错误

### 6.2 恢复场景

建议至少覆盖：

* 单个 `QUIC flow` 断开并重建后，旧 Session 与 NAT 状态被回收，新流量使用新的 `quic_flow_id` 建立 Session，且不影响其他 `QUIC flow` 和无关 Session
* `DCID` 轮换后，旧包和新包都不会被分发到错误 worker
* 单个 `IO worker` 短时背压或发包失败后，恢复后路径仍一致，Session 不漂移
* 服务端首次默认 queue 发包后，真实回包纠正 queue 的过程只发生一次或按设计有限次发生，不会来回抖动

### 6.3 退化与负载场景

建议至少覆盖：

* 某个 queue 明显热于其他 queue 时，系统仍保持正确性，热点只影响性能不影响路由正确性
* 某个 `Flow worker` 上 Session 激增时，不会把其他 worker 的 Session 误迁移过来
* `RX/TX` 背压下的丢包、重试、记账和告警行为符合设计
* 邻居解析失败、目标网络短时不可达时，失败只影响对应流，不影响整机 worker ownership

---

## 7. 观测与断言

仅靠抓包不足以证明架构正确。至少需要以下可观测项：

* 每个 `IO worker` 的 `(ifindex, queue_id)`、收发包数、丢包数
* 每个 `Flow worker` 的 Session 数、创建数、回收数
* 客户端 SNAT 表项数、服务端 SNAT 表项数、reverse NAT 命中/未命中计数
* 每个 `QUIC flow` 的 `quic_flow_id`、所属 worker、`tunnel_queue_id`
* tunnel ingress 的 `DCID` 命中次数、未知 `DCID` 次数
* “默认 server 出口 queue 被真实回包回填”的次数

E2E 断言建议至少同时看三类证据：

* 抓包结果
* 运行时统计
* Session / NAT dump

如果只看“业务能通”，很容易把错误 queue、错误 worker 或错误 reverse NAT 漏掉。

---

## 8. 性能与长稳测试

### 8.1 性能测试重点

性能测试必须围绕 v1 架构的真实瓶颈，而不是旧的 TUN 指标。

应至少覆盖：

* 单 queue / 单 `IO worker` / 单 `Flow worker` 的基础吞吐
* 多 queue 下 `IO worker` 扩展性
* 多 `Flow worker` 下 Session hash 分布是否均匀
* `tunnel_queue_id` 稳定绑定后是否造成明显热点
* 不同 interface 队列数不一致时的吞吐退化情况
* `tunnel_interface == intercept_interface` 时的额外分类开销
* 小包、中包、大包混合流量下的吞吐与 CPU 成本
* TCP、UDP、ICMP 三类流量的混跑退化情况
* p50 / p99 延迟与抖动，而不仅仅是总吞吐
* 各 queue 的包数、字节数和 drop 分布是否明显失衡
* 如果实现支持多种 XDP 运行模式，还应分别测对应模式下的吞吐和 CPU 占用

### 8.2 长稳测试重点

长稳测试比峰值吞吐更重要，应至少验证：

* Session 数反复涨落后，内存不会持续爬升
* SNAT / reverse NAT 索引不会泄漏
* `QUIC flow` 重连或轮换后，旧 `DCID` 不会残留在 tunnel ingress 索引里
* `IO worker` 的 ring 统计长期稳定，不出现持续性的 fill/completion 异常
* `Flow worker` 的 owner 分布不会随时间漂移成明显热点
* XSK、XDP map、邻居缓存和运行时统计对象不会在反复启停后泄漏
* 长时间跑压后，默认 queue 回填、`DCID` 轮换和 Session 回收仍然保持一致，不出现状态错乱

---

## 9. 测试执行建议

### 9.1 基础门禁

每次提交至少应通过：

```bash
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

### 9.2 E2E 执行环境

建议使用 Linux Network Namespace 组织最小拓扑：

* `client_ns`
* `transit_ns`
* `server_ns`
* `target_ns`

并在需要时额外创建第二个 `client intercept_interface` 命名空间，用于验证多入口回投。

### 9.3 超时与清理

所有 E2E / soak 脚本都应统一具备：

* `timeout --kill-after=10s ...`
* `trap cleanup EXIT`
* 自动清理后台进程
* 自动清理 netns、veth、XDP/XSK 挂载状态

否则一次失败测试很容易污染下一次运行结果。

---

## 10. 目标架构实现检查单

当代码逐步重构到新架构时，测试应按如下优先级落地：

1. 先补齐 Session / NAT / worker ownership 的单元测试。
2. 再补齐四条核心 E2E 路径。
3. 再补齐不同 interface / 不同 queue 数 / 同接口模式的边界测试。
4. 最后再做性能和长稳门禁。

如果这四层顺序反过来，通常会出现“压测能跑，但架构状态边界全是错的”。

## 11. 本文档维护规则

为了避免再次出现“目标态”和“现状”混写，后续维护应遵守以下规则：

* 新增目标测试要求时，若仓库尚未落地对应测试，应明确写成待实现约束或 TODO。
* 当默认 acceptance 仍覆盖 legacy 或 transitional 路径时，不得把它表述成纯 v1 验收通过。
* 历史测试结果应放在独立的变更记录、发布记录或提交说明中，不再回流到本文件充当当前覆盖证明。

