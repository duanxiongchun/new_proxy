# new_proxy 架构说明（Pure L3 IP-over-QUIC Datagram 架构）

本文档描述 `new_proxy` 的全新纯 L3 IP-over-QUIC Datagram 数据面架构。所有数据包（TCP、UDP、ICMP）均通过无状态、无延迟的 QUIC Datagram 进行传输，并依托多队列网卡实现对称多核并行处理。

---

## 1. 总体模型

`new_proxy` 是一个纯粹的 **L3 IP-over-QUIC 隧道网关**，完全运行在用户态，通过 QUIC 协议栈提供安全加密的 VPN 功能：

* **纯 L3 隧道数据面**：
  * **客户端**：创建多队列 TUN 网卡，截获所有发往 Peer `AllowedIPs` 的 IP 数据包（IPv4/IPv6）。代理不解析应用层协议，直接将 IP 报文封装进 QUIC Datagram 帧中发送。
  * **服务端**：同样建立多队列 TUN 网卡。接收到 QUIC Datagram 后，解出原始 IP 数据包，直接写入服务端的 TUN 网卡，由系统内核完成最终的路由和转发。回程流量通过相同路径镜像传回。
  * **去 WireGuard / smoltcp 化**：新架构完全移除了原有的用户态 WireGuard 协议栈（`boringtun`）和用户态 TCP/IP 协议栈（`smoltcp`），极大地简化了数据路径，并消除了流代理机制下的队头阻塞（Head-of-Line Blocking）和 TCP-over-TCP 拥塞冲突。
* **控制面**：独立的 UDP 报文协议，使用协商好的私钥/公钥材料派生 X25519 共享密钥，并用 HMAC-SHA256 对 JSON 格式的配置交换进行签名和认证。
* **运行期 API**：通过 Unix Domain Socket 提供运行时 `Stats`、`Dump`、`AddPeer` 和 `RemovePeer` 等 API 支持。

---

## 2. 物理拓扑与运行配置

### 2.1 控制面预协商与线程基准建立
* 客户端启动时，首先通过服务端的管控端口（Control Port）发起预协商。
* 协商交互中，客户端获取服务端配置的**数据面端口列表**（共 $N$ 个端口，例如 `[40001, ..., 40001+N-1]`）。
* **首个 Peer 基准**：客户端以第一个成功建立连接的 Peer 返回的端口数量 $N$ 作为本地静态基准：
  1. 在本地初始化拥有 $N$ 个通道队列的多队列 TUN 设备（Multiqueue TUN）。
  2. 显式创建并绑定 $N$ 个独立的工作线程（Workers）。
  3. 后续添加的所有 Peer 其数据面端口数必须等于 $N$，否则将被拒绝，以保证本地静态工作线程和网卡队列拓扑的对等一致。

### 2.2 线程与物理通道的一一对称映射
* **客户端工作线程 $i$**（$i \in [0, N-1]$）：绑定独立的客户端 UDP socket，直接建立并拥有指向服务端数据端口 `40000+i` 的 **QUIC 连接 $i$**，并独占读写客户端 **TUN 队列 $i$**。
* **服务端监听线程 $i$**：监听 UDP 端口 `40000+i`，接受来自客户端的 **QUIC 连接 $i$**，并独占读写服务端 **TUN 队列 $i$**。

---

## 3. 数据流调度与内核对称哈希

借助于 Linux 内核多队列网卡（`IFF_MULTI_QUEUE`）的对称流哈希（Symmetric Flow Hashing），`new_proxy` 实现了零锁竞争的高效数据转发：

```
客户端业务包 ---> [Client TUN MQ] 
                     | (内核对称 Hash 选队列 i)
                     v
             [工作线程 i (RTC Loop)]
                     | (无锁读取，封装)
                     v
             [QUIC 连接 i (Datagram)]
                     | (公网传输至对应端口 40000+i)
                     v
             [监听线程 i (RTC Loop)]
                     | (无锁接收，解密)
                     v
客户端回程包 <--- [Server TUN MQ] <--- 目标网络回包
```

* **流队列亲和性**：一个网络连接流（例如 `ClientIP:54321 -> TargetIP:80`）的数据包会被内核固定路由至客户端 TUN 队列 $i$。
* **回程对称匹配**：当远端目标服务回包时（`TargetIP:80 -> ClientIP:54321`），服务端内核对称地将其路由至服务端 TUN 队列 $i$，并通过对应的 QUIC 连接 $i$ 传回。
* **零竞争（Zero-Contention）**：每个工作线程或监听线程在数据面上只处理自己专属的网卡队列和 QUIC 连接，**线程之间不存在任何全局锁、哈希表或共享状态的同步**，实现多核性能的完全线性扩展。

---

## 4. MTU 与 TCP MSS 夹紧（MSS Clamping）

为防止大尺寸的 IP 数据包在通过底层的 QUIC 隧道（运行在 UDP 上）时发生 **IP 层的分片（Fragmentation）** 从而导致性能大幅劣化，系统采取以下策略：

1. **TUN 物理 MTU 限制**：将客户端 TUN 网卡的 MTU 强制限制在较安全的值（例如 `1200` 字节，可根据 QUIC 的最大 datagram 大小动态调整）。
2. **TCP MSS 夹紧**：工作线程在从 TUN 网卡读取 IP 数据包时，会对其中的 TCP 握手包（SYN / SYN-ACK）进行即时解析。如果包中含有 TCP MSS 选项，工作线程会强行改写该字段值，将其限制在 `1160` 字节以下。
3. **效果**：客户端与目标服务器的操作系统内核在握手阶段即协商出较小的 TCP Segment 大小，生成的所有 TCP 包天然契合单个 QUIC Datagram 报文的大小，彻底消除了 IP 拆包与组包的 CPU 开销。

---

## 5. Run-to-Completion (RTC) 事件循环

`new_proxy` 的数据面设计遵循严苛的 **Run-to-Completion (RTC)** 模型，旨在消除任何非必要的 CPU 上下文切换与延迟调度抖动：

### 5.1 静态线程与零动态任务创建
* 所有的工作线程在启动时即一次性 spawn 完毕，运行期绝对不会为单个数据包或新流量动态创建新的异步任务（禁用数据面上的 `tokio::spawn`）。
* 每个线程运行一个紧凑的非阻塞同步 `poll` 事件循环：
  * **出站**：非阻塞 Polling 本地 TUN 队列 $\rightarrow$ 读出报文 $\rightarrow$ 塞入 `send_datagram()` 发送。
  * **入站**：非阻塞 Polling QUIC 连接 $\rightarrow$ 读出 Datagram $\rightarrow$ 解密还原为原始 IP 包 $\rightarrow$ 直接写入 TUN 队列。
  * 若无数据可读写，线程通过 `epoll` 挂起（Park）等待事件唤醒，不占用额外 CPU 周期。

### 5.2 线程局部内存池与零碎片（Zero Fragmentation）
* **固定大小内存块**：每个工作线程都拥有一个完全隔离的 `BufferPool`，内存池中仅包含固定大小的包缓冲区（例如 2048 或 16384 字节，匹配 MTU 基准）。
* **本地无锁循环**：所有数据包缓冲区仅在所属线程内部进行借用和归还，没有跨线程竞争，避免了全局内存分配器（`malloc` / `free`）的并发锁瓶颈。
* **零碎片保证**：数据面所有包内存都在启动时静态分配，不随时间动态扩张，彻底杜绝了长期运行下可能会出现的堆内存碎片（Heap Fragmentation）问题。

---

## 6. 路由与策略配置

在 `Table != off` 的配置下，`new_proxy` 客户端在启动和运行中会自动执行以下系统路由操作：
1. 配置本地 TUN 接口的 IP 地址（对应 `Address` 声明）。
2. 配置 TUN 网卡接口的 MTU 值为协商的 MTU（默认 `1200` 字节左右），并将网卡状态置为 UP。
3. 针对 peer 配置的 `AllowedIPs` 规则，将系统路由指向该 TUN 网卡设备。

为了规避全网代理（如 `0.0.0.0/0`）下外层 UDP 加密数据包再次递归进入 TUN 网卡的死循环，系统使用 `SO_MARK` 标记：所有外层加密 UDP 套接字发出的流量都会被打上特定的 fwmark 标签，配合系统的策略路由规则（`not fwmark <mark> lookup <table>`），保证加密包直接走宿主机的真实物理路由。

---

## 7. 安全与生存状态管理

* **TLS 1.3 通道加密**：所有的 QUIC Datagram 均通过 QUIC 的安全握手上下文进行加密与认证（基于 TLS 1.3 派生出的 AEAD 对称密钥）。
* **握手会话缓存验证**：客户端在连接时发送经 `session_psk` 签名的认证包，服务端验证通过后方允许 Datagram 传输。
* **单 Slot 局部重连与保活**：连接池自带后台健康检测。如果其中第 $i$ 个数据面物理 QUIC 连接由于网络抖动中断，只有该 Slot 对应的 Worker 线程会触发控制面预协商和链路重连，其他活跃 Worker 线程的数据转发不受任何干扰，最大程度保障了高吞吐连接的稳定性。
