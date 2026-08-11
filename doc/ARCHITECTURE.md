# new_proxy 架构说明（AF_XDP QUIC Appliance）

本文档描述 `new_proxy` 的 **v1 目标架构**。本版文档只保留当前主线需要的设计：单 `client <-> server`、纯 QUIC 隧道、`AF_XDP` 主数据面、双层 SNAT、固定拓扑 appliance。

历史上的混合隧道、WireGuard、TUN 主路径、批处理微优化和旧的明文 AF_XDP 路径都不再作为主架构描述对象。它们可能仍存在于代码或旧分支里，但不再定义本项目接下来的主设计方向。

## 文档状态

* **定位**：目标架构文档，不是当前实现逐项对齐完成的验收证明。
* **当前实现状态**：仓库仍处于从旧主线向该 v1 目标架构收敛的过渡期。
* **阅读方式**：如果本文档与当前默认测试脚本、历史实现路径或运行时行为不一致，应优先理解为“实现尚未完全收敛到本文档目标”，而不是本文档自动证明现状已经满足这些约束。

---

## 1. 目标与边界

### 1.1 目标
`new_proxy` 的 v1 目标是一个面向固定部署环境的高性能隧道 appliance：

* 单 `client <-> server`
* 外层协议为 QUIC
* 内层承载普通 IPv4/IPv6 业务流量
* `AF_XDP` 作为主数据面
* 优先保证长期稳定、路径清晰、状态可恢复，而不是先追求最复杂的并行模型

### 1.2 非目标
以下内容不再作为 v1 架构主线：

* 混合 WireGuard/QUIC 共存
* 多 peer / 多租户 / 动态 peer 增删
* 同一个 queue 上多 XSK 并发共享 `Fill/Completion`
* 依赖 NIC 可控 RSS 才能保证正确性的设计
* 把历史性能优化细节当作主架构的一部分

### 1.3 当前实现状态
当前代码中的 `Mode = af_xdp` 仍包含“明文 inner IP 直接包装到外层 UDP”的过渡实现。本文档描述的是**重构后的目标架构**：内层数据必须进入真正的 QUIC 加密路径，外层接收分发通过 `DCID` 命中对应 `Flow worker`。

### 1.4 当前与目标的主要差距
当前仓库与本文档之间至少还有以下差距需要明确区分：

* 默认测试和运行入口仍覆盖 TUN、动态 peer、hybrid/legacy 路径，不能直接视为本文档定义的 v1 gate。
* `Mode = af_xdp` 的现有实现仍包含过渡期的数据路径，不应被表述为已经完全符合“AF_XDP 主数据面 + QUIC 加密内层转发”的最终目标。
* `DCID -> Flow worker`、`quic_flow_id`、双层 SNAT、reverse NAT 回填等约束是后续实现必须满足的目标，不应仅因为旧路径测试通过就被视为已验证完成。

---

## 2. 核心概念

### 2.1 接口角色
* **`tunnel_interface`**：承载外层 QUIC/UDP 隧道包的接口。
* **`intercept_interface`**：承载需要进入隧道或从隧道返回本地网络的明文业务流量的接口。

客户端可以有多个 `intercept_interface`。
这里的“多个”只表示同一个 client 节点上的多个本地明文入口，不表示多个 client peer。
服务端 v1 假定只有一个 `intercept_interface`。
`tunnel_interface` 和 `intercept_interface` 可以相同；如果相同，也仍然视为两条逻辑 pipeline，而不是一条混杂路径。

### 2.2 worker 角色
* **`IO worker`**：
  * owner 粒度是 `(ifindex, queue_id)`
  * 独占对应 XSK 的 `RX/TX/Fill/Completion`
  * 只负责收发、轻量分类、邻居/L2 补全、最终发包
  * 不创建、不维护 Session
* **`Flow worker`**：
  * owner 粒度是 flow / session
  * 负责 Session、双层 SNAT、QUIC 连接池、加密解密、路径选择
  * 是唯一的 Session owner

### 2.3 关键状态
* **Session（节点本地状态）**
  * `Session` 不是跨 `client/server` 共享的对象，而是某个节点本地 `Flow worker` 拥有的状态单元。
  * 每个节点只保存自己需要恢复和继续转发该流量所必需的字段。
  * 对客户端来说，`intercept_ifindex/intercept_queue_id` 表示首包进入隧道时记录下来的本地明文入口，也就是后续回投时应恢复的本地出口。
  * 典型字段包括：
    * 原始五元组
    * 本节点执行 SNAT 后的五元组
    * `flow_worker_id`
    * 本节点相关的 `intercept_ifindex`
    * 本节点相关的 `intercept_queue_id`
    * `quic_flow_id`
* **QUIC flow**
  * 归属某个 `Flow worker`
  * 拥有一个或多个活跃 `DCID`
  * 拥有稳定的 `tunnel_queue_id`
  * 对应一个 QUIC 连接或连接槽位
  * v1 中连接重建会创建新的 `quic_flow_id`；绑定旧 `quic_flow_id` 的 Session 不做隐式迁移，而是连同本地 NAT 状态一起回收，后续流量重新建 Session
* **Active DCID 索引**
  * `active_dcid -> flow_worker_id`
  * 用于已建立连接的 `tunnel ingress` 不解密分发
  * 不作为 Session 的长期主键
  * 索引由对应 `QUIC flow` 所属的 `Flow worker` 维护；新增 `DCID` 先发布映射，退休 `DCID` 在 QUIC 生命周期确认后删除，连接关闭时删除该 flow 的全部映射

---

## 3. 总体架构

系统被拆成两层：

1. **IO plane**
   处理网卡和 XSK 生命周期。

2. **Flow plane**
   处理状态、地址改写和 QUIC。

这样拆分的原因很直接：

* 把 `Fill/Completion` ownership 保持在 queue owner 手里
* 避免同一个 queue 上多线程共享 ring 的复杂性
* 让 `Session` 和 NAT 状态只由 `Flow worker` 持有
* 让接口数、队列数和 flow 并行度可以解耦

设计规则：

* 任意 `(ifindex, queue_id)` 只有一个 `IO worker`
* 任意 Session 只有一个 `Flow worker`
* `IO worker` 可以把包投递给任意 `Flow worker`
* 对于每一次具体发包动作，`Flow worker` 都必须解析到一个唯一的目标 `IO worker`

---

## 4. 路径选择规则

### 4.1 入口分发
* **`intercept ingress`**：按内层五元组计算 hash，命中 `Flow worker`
* **已建立连接的 `tunnel ingress`**：按 `DCID` 命中 `active_dcid -> flow_worker_id`
* **未知 `DCID`**：
  * 只有能够被识别为新建 QUIC 连接 bootstrap 的合法报文才允许继续处理
  * bootstrap owner 按 `hash(dcid) % flow_worker_count` 唯一确定；该 `Flow worker` 创建 `QUIC flow` 后发布对应的 active DCID 映射
  * 其他未知 `DCID` 报文必须丢弃并记账，不能随机投递或创建 Session

### 4.2 出口分发
* **客户端发往隧道**：由 `QUIC flow` 决定，`QUIC flow` 在创建时绑定一个稳定的 `tunnel_queue_id`
* **服务端发往隧道**：由 Session 绑定的原始 `QUIC flow` 决定，因此仍然落到该 `QUIC flow` 对应的 `tunnel_queue_id`
* **本地业务出口**：由 Session 中记录的 `(intercept_ifindex, intercept_queue_id)` 决定

### 4.3 关键约束
* 发送方向不是“每个包临时 hash 选 queue”，而是“每个 `QUIC flow` 绑定稳定 queue”
* v1 在单个节点内使用固定且非零的 `DCID` 长度，使 `IO worker` 能够在不解密 QUIC short-header 报文的前提下稳定提取分发键
* `DCID` 只承担外层收包分发键的职责；Session 的长期连接绑定通过 `quic_flow_id` 完成
* 同一个 `QUIC flow` 的全部活动 `DCID` 必须映射到同一个 `Flow worker`
* bootstrap 只负责建立 `DCID -> Flow worker` ownership，不得创建业务 Session
* `queue_id` 只在某个 interface 内有意义，所以所有 IO owner 查找都必须用 `(ifindex, queue_id)`

---

## 5. 四个核心过程

### 5.1 Client 发包

1. 业务包到达某个 `client intercept_interface`
2. XDP 在该接口先做 `AllowedIPs` 判断
3. 未命中直接 `XDP_PASS`；命中才 redirect 到对应 `(ifindex, queue_id)` 的 XSK
4. `intercept IO worker` 收包，只做三件事：
   * 提取原始内层五元组
   * 计算 `flow_hash`
   * 把报文连同 `ingress_ifindex` 和 `ingress_queue_id` 投递给命中的 `Flow worker`
5. `Flow worker` 创建或命中 Session，并记录：
   * 原始五元组
   * `flow_worker_id`
   * `intercept_ifindex`
   * `intercept_queue_id`
6. `Flow worker` 做客户端侧 SNAT，并把 SNAT 后五元组写回 Session
7. `Flow worker` 选择一个 `QUIC flow`
8. `QUIC flow` 在创建时绑定一个稳定的 `tunnel_queue_id`。v1 实现可以使用创建该 `QUIC flow` 时可见的活跃 `DCID` 计算：
   * `hash(dcid) % tunnel_queue_count`
   但该绑定一旦建立，后续应由 `QUIC flow` 自身持有，而不是随着后续 `DCID` 变化而重新漂移。
9. `Flow worker` 完成加密和外层 QUIC 封装
10. `Flow worker` 把包投递给拥有 `(tunnel_ifindex, tunnel_queue_id)` 的 `tunnel IO worker`
11. `tunnel IO worker` 补齐外层邻居/L2 信息并最终发包

### 5.2 Server 收包并转发到目标网络

1. 外层 QUIC 包到达 `server tunnel_interface`
2. 对应 `tunnel IO worker` 收包
3. `tunnel IO worker` 只解析 QUIC 头部并提取 `DCID`
4. 已注册 `DCID` 通过 `active_dcid -> flow_worker_id` 命中 owner；合法的新 QUIC 连接首包按 4.1 的 bootstrap 规则确定 owner
5. `Flow worker` 解密得到内层报文
6. `Flow worker` 创建或命中服务端 Session，并记录：
   * SNAT 前五元组
   * `flow_worker_id`
   * `quic_flow_id`
7. 对于首次进入服务端的新连接，由于此时还不知道真实回包会落在哪个入口队列：
   * `intercept_ifindex` 先设为唯一服务端 `intercept_interface`
   * `intercept_queue_id` 先使用默认出口队列；v1 默认取 `0`
8. `Flow worker` 做服务端侧 SNAT，并把 SNAT 后五元组写回 Session
9. `Flow worker` 把改写后的明文业务包投递给拥有 `(intercept_ifindex, intercept_queue_id)` 的 `intercept IO worker`
10. `intercept IO worker` 最终从服务端唯一的 `intercept_interface` 发出

### 5.3 Server 收到目标网络回包并回隧道

1. 目标网络回包从服务端唯一的 `intercept_interface` 进入
2. 对应 `intercept IO worker` 收包
3. `intercept IO worker` 根据服务端侧 reverse NAT 只读索引命中对应的 `flow_worker_id` 和 `session_ref`
4. `intercept IO worker` 将本次真实收到回包的：
   * `intercept_ifindex`
   * `intercept_queue_id`
   连同报文一起投递给对应 `Flow worker`
5. `Flow worker` 依据 `session_ref` 命中本地 Session，并把真实的 `intercept_ifindex/intercept_queue_id` 回填到 Session 中，覆盖首次发出时使用的默认值
   * v1 规则是：Session 一旦被真实回包纠正到非默认 queue，后续本地业务出口应固定使用该纠正后的 queue，而不是继续回退到默认值或在不同 queue 之间来回漂移
6. `Flow worker` 根据服务端 SNAT 状态把回包恢复为客户端隧道内地址
7. `Flow worker` 根据 Session 中保存的 `quic_flow_id` 命中原始 `QUIC flow`
8. `Flow worker` 通过该 `QUIC flow` 对回包进行加密和外层封装
9. `QUIC flow` 自带稳定的 `tunnel_queue_id`
10. `Flow worker` 把包投递给对应 `tunnel IO worker`
11. `tunnel IO worker` 从 `server tunnel_interface` 发出回包

### 5.4 Client 收包并投递回本地网络

1. 回包到达 `client tunnel_interface`
2. 对应 `tunnel IO worker` 收包
3. `tunnel IO worker` 解析 `DCID`
4. 通过 `dcid -> flow_worker_id` 命中对应 `Flow worker`
5. `Flow worker` 解密
6. `Flow worker` 根据客户端 Session 和客户端 reverse NAT 状态，把报文恢复为原始内层目标
7. 由于客户端在首次发包时已经记录了：
   * `intercept_ifindex`
   * `intercept_queue_id`
   所以这里不需要重新选择出口
8. `Flow worker` 直接把报文投递给拥有该 `(ifindex, queue_id)` 的 `intercept IO worker`
9. `intercept IO worker` 从原始 `intercept_interface` 发回本地网络

---

## 6. Session 设计

Session 是整个系统的核心状态单元，必须只由 `Flow worker` 拥有。

### 6.1 Session 必须保存的字段
* `flow_worker_id`
* 原始五元组
* 本节点 SNAT 后五元组
* `quic_flow_id`
* 本节点相关的 `intercept_ifindex`
* 本节点相关的 `intercept_queue_id`

### 6.2 为什么这样设计
* 节点回包时，需要知道原始本地出口 `(ifindex, queue_id)`
* 节点收到后续流量时，需要知道该把数据交回哪个 `Flow worker`
* `active_dcid -> flow_worker_id` 让 `tunnel ingress` 在解密前就能命中 owner
* `quic_flow_id` 让 Session 可以稳定绑定到某个连接对象，而不受 CID 变化影响
* 双层 SNAT 让客户端和服务端都能在各自节点上做稳定的 reverse NAT 恢复

---

## 7. 接口与队列模型

### 7.1 队列数可以不同
`intercept_interface` 和 `tunnel_interface` 的队列数允许不同。
因此：

* `intercept_queue_id` 和 `tunnel_queue_id` 绝不能混用
* `tunnel_queue_id` 必须根据 `tunnel_interface` 的真实队列数单独计算
* 本地回包必须依赖 Session 中记录的 `(intercept_ifindex, intercept_queue_id)`

### 7.2 当两个接口相同
当 `tunnel_interface == intercept_interface` 时，仍然按照两条逻辑 pipeline 处理：

* 一条是 `tunnel ingress/egress`
* 一条是 `intercept ingress/egress`

即使落在同一个 `ifindex` 上，也必须在 XDP 和用户态头部解析中区分“外层 QUIC 包”和“本地明文业务包”。

### 7.3 为什么不做同 queue 多 XSK 共享
v1 明确不采用“同一个 queue 上多个 XSK 共享 `Fill/Completion`”的方案。原因是：

* ownership 复杂
* `Fill/Completion` 共享容易出错
* 对长期稳定不友好
* 会把 ring 生命周期和 Session 生命周期耦合起来

v1 的规则是：

* `1 (ifindex, queue_id) -> 1 IO worker`

---

## 8. 目标设计的简化结论

本文档定义的目标架构可以压缩成一句话：

`AllowedIPs/XDP 负责把需要入隧道的流量引到 XSK，IO worker 负责 queue 级收发，Flow worker 负责 Session、双层 SNAT 和 QUIC，tunnel ingress 按 DCID 命中 owner，local egress 按 Session 中记录的 (ifindex, queue_id) 恢复。`

如果后续需要继续扩展，优先级应当是：

1. 先补齐 client 收包/回投的实现
2. 再补齐服务端 reverse NAT 和 Session 回填
3. 最后再考虑更激进的并行或同 queue fan-out 优化

不要在 v1 把复杂度提前放到：

* 多 peer
* 多 server intercept interface
* 同 queue 多 XSK
* 运行时动态拓扑变更

---

## 9. 对未来实现的直接约束

为了让代码与架构一致，后续实现应满足以下硬约束：

* `IO worker` 不得创建 Session
* `Flow worker` 是唯一 Session owner
* 已注册 `DCID` 的 `tunnel ingress` 必须通过 `active_dcid -> flow_worker_id` 命中 owner
* 未知 `DCID` 只能进入确定性的 QUIC bootstrap 路径或被丢弃，不能进入普通业务分发
* `client outbound` 必须先过 `AllowedIPs`
* `QUIC flow` 必须拥有稳定的 `tunnel_queue_id`
* 所有 IO owner 查找必须使用 `(ifindex, queue_id)` 作为完整键

这几条如果被破坏，整个路径的一致性就会被打散。

