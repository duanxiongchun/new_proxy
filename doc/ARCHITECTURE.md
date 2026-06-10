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

## 4. MTU 与 操作系统自动 MSS 夹紧（MSS Clamping）

为防止大尺寸的 IP 数据包在通过底层的 QUIC 隧道（运行在 UDP 上）时发生 **IP 层的分片（Fragmentation）** 从而导致性能大幅劣化，系统采取以下策略：

1. **TUN 物理 MTU 限制与自动 Clamp**：系统默认采用更小、更安全的 `1100` 字节作为 TUN 设备 MTU。如果在配置文件中指定了大于 `1150` 字节的 MTU，代理在加载配置时会自动将其 Clamp（夹紧）为 `1100` 字节。这可安全确保内层 IP 报文外加外层 UDP/QUIC 报头和 AEAD 加密 Tag（16 字节）后，整个物理 UDP 报文不会超过标准的 `1500` 字节以太网 Path MTU，防止包过大被网络静默丢弃。
2. **操作系统自动 MSS 夹紧**：系统完全移除了用户态解析并篡改 TCP SYN 报文的复杂逻辑，消除了繁琐的包重组与重新计算校验和的 CPU 开销。由于 TUN 设备的 MTU 已经被强制限制为 `1100` 字节，操作系统内核的 TCP 协议栈在进行 TCP 三次握手协商时，会自动将最大分段大小（MSS）限制为 `1060` 字节（IPv4，MTU - 40 字节报头）或 `1040` 字节（IPv6，MTU - 60 字节报头）。
3. **效果**：客户端与目标服务器在握手阶段天然协商出较小的 TCP Segment 大小，生成的 TCP 报文完全无需用户态额外处理即可直接装入单个 QUIC Datagram 中传输，零分片、零额外包重写开销。

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

### 5.3 零拷贝（Zero-Copy）数据通道
为了实现极致的吞吐性能并消除数据面上的内存拷贝和堆内存分配，出站 TUN 读包路径设计为纯粹的零拷贝流程：
* **前置布局与头部留空**：在 `RtcWorker::run_loop` 中，本地 `tun_buf` 使用 `bytes::BytesMut` 分配。在每次调用 `tun_io.read()` 时，直接读取到缓冲区偏移位置 `&mut tun_buf[1..]`。
* **就地打标与冻结**：读出 `n` 字节后，直接在缓冲区第 0 字节位置写入协议包头 `0x02`（`tun_buf[0] = 0x02`），然后通过 `tun_buf.split_to(1 + n).freeze()` 将当前数据段切出并转换为只读的 `bytes::Bytes`。
* **零拷贝发送**：切出的 `Bytes` 缓冲段直接克隆并传入 `conn.connection.datagrams().send(frame)` 中发送，整个传输流只涉及底层缓冲区的引用计数递增，完全避免了为添加协议头而进行 `Vec` 动态分配和包数据内存拷贝。

### 5.4 非原子线程隔离遥测（Non-Atomic Telemetry）
在超高包率下，多核并发使用原子操作（如 `fetch_add`）会因为 CPU 总线锁（`LOCK` 指令前缀）导致严重的跨核 Cache Line 冲突与指令流水线阻塞。系统对此进行了彻底的无锁化重构：
* **非原子计数器 CellU64**：设计了利用 `UnsafeCell<u64>` 实现的非原子计数器，将 `PeerL4Stats`、`QuicConnStats` 和 `VirtualTunnelTelemetry` 中所有的热路径计数器替换为 `CellU64`。
* **线程写隔离**：每一个 `RtcWorker` 线程只独占并写入属于自己的 `peer_telemetry`（即 `peer_telemetries[worker_id]`），消除了任何多线程写入同一内存单元的竞争。
* **读时聚合（Sum-on-Read）**：在通过 UDS 控制通道查询遥测数据时，UDS 服务端线程会遍历所有的线程本地 Registry 并对其非原子计数器调用 `.load()` 进行求和累加。该设计实现了“写时单线程独占无锁，读时延时求和聚合”，在完全保证数据面极速转发的同时，消除了原子操作的硬件开销。

---

## 6. 管控面单线程与控制面/数据面隔离

为了避免低频的管控任务（如配置查询、心跳检测、故障倒换、API 调用等）干扰高频数据面（RTC 转发环路）的吞吐量与极低延迟要求，`new_proxy` 在主入口中采用了严格的控制面/数据面物理线程隔离设计：

### 6.1 单线程主运行时（Single-Threaded Control Plane）
* **主 Runtime 设计**：进程主入口抛弃了传统的 `new_multi_thread()` 多线程 Tokio 运行时，使用 `tokio::runtime::Builder::new_current_thread()` 显式创建单线程异步运行时。
* **集约化管控面任务**：在该单线程 Runtime 中，集约推进所有的异步控制面逻辑：
  * **UDS API 服务器**：用于响应管理 CLI 提起的查询、配置下发和 peer 增删命令。
  * **控制面预协商通道**：基于非加密 UDP 传输的 pre-negotiation 服务。
  * **健康检查与故障恢复（Health Checker）**：定时扫描数据面 QUIC socket 健康状态，触发失效 Slot 局部重连。
  * **路由及进程自愈**：响应底层接口变化及网卡配置刷新。
* **低调度开销**：控制面全部任务都在一个 OS 线程（主线程）中顺序、协作式推进，不存在任何跨核心调度切换与锁竞争。

### 6.2 数据面专用工作线程 (Dedicated Data Workers)
* **OS 线程独立绑定**：每个 RTC 转发 Worker 都在主 Runtime 之外，通过 `std::thread::Builder` 显式创建并派生独立的 OS 物理线程（命名为 `new-proxy-client-worker-i` 或 `new-proxy-server-worker-i`）。
* **专用 Local Runtime**：每个 Worker 线程均在内部创建一个专属的单线程 Local Tokio Runtime。这确保了每个数据通道（网卡多队列接口 $i$ + 物理 QUIC 连接 $i$）拥有其完全专有的事件循环调度上下文。
* **物理级隔离**：这实现了控制面和数据面转发流量在物理 CPU 核心上的完美隔离：控制面任务卡顿（如 DNS 解析延迟或 UDS 慢查询）绝不会干扰或剥夺数据面 Worker 的 CPU 调度执行权，最大程度保证了高吞吐下转发速率的近线性度。

---

## 7. 路由与策略配置

在 `Table != off` 的配置下，`new_proxy` 客户端在启动和运行中会自动执行以下系统路由操作：
1. 配置本地 TUN 接口的 IP 地址（对应 `Address` 声明）。
2. 配置 TUN 网卡接口的 MTU 值为协商的 MTU（默认 `1200` 字节左右），并将网卡状态置为 UP。
3. 针对 peer 配置的 `AllowedIPs` 规则，将系统路由指向该 TUN 网卡设备。

为了规避全网代理（如 `0.0.0.0/0`）下外层 UDP 加密数据包再次递归进入 TUN 网卡的死循环，系统使用 `SO_MARK` 标记：所有外层加密 UDP 套接字发出的流量都会被打上特定的 fwmark 标签，配合系统的策略路由规则（`not fwmark <mark> lookup <table>`），保证加密包直接走宿主机的真实物理路由。

---

## 8. 安全与生存状态管理

* **TLS 1.3 通道加密**：所有的 QUIC Datagram 均通过 QUIC 的安全握手上下文进行加密与认证（基于 TLS 1.3 派生出的 AEAD 对称密钥）。
* **握手会话缓存验证**：客户端在连接时发送经 `session_psk` 签名的认证包，服务端验证通过后方允许 Datagram 传输。
* **单 Slot 局部重连与保活**：连接池自带后台健康检测。如果其中第 $i$ 个数据面物理 QUIC 连接由于网络抖动中断，只有该 Slot 对应的 Worker 线程会触发控制面预协商和链路重连，其他活跃 Worker 线程的数据转发不受任何干扰，最大程度保障了高吞吐连接的稳定性。

---

## 9. 纯 L3 IP-over-QUIC Datagram 隧道设计规约细节

### 8.1 概述与设计目标
本节定义了代理库从“混合 L4 SOCKS/QUIC 流 + L3 WireGuard 降级回退”架构转向**纯 L3 IP-over-QUIC Datagram 隧道**的设计细节。
通过直接在 IP 层使用 QUIC Datagrams（无连接状态、无序的不可靠数据帧），完全移除了用户态 TCP/IP 协议栈（如 `smoltcp`）并摆脱了对 WireGuard（`boringtun`）的依赖。从而实现了具有对称多核扩展能力的低延迟、高吞吐量隧道。

* **移除 WireGuard**：所有的 L3/L4 流量（TCP、UDP、ICMP）均完全在 QUIC 物理通道上运行。
* **Run-to-Completion (RTC)**：确保所有数据面工作循环均为非阻塞、静态分配，并且绝对不动态创建线程或任务。
* **对称多端口映射**：启动时动态协商数据端口，并使客户端与服务端的线程 1对1 对齐，避免跨线程锁竞争。
* **零堆内存分配**：采用线程隔离的缓冲区池，在数据转发热路径上复用数据包缓冲区，避免垃圾回收和堆内存分配带来的抖动。

### 8.2 报文封装与传输规约
* 所有从 TUN 接口读取的 IP 报文（IPv4/IPv6）都通过零拷贝封装后传输。
* **封装格式**：因为 QUIC Datagram 本身保留了数据包边界，帧载荷（Payload）采用前缀多路复用格式：第一字节为协议类型标记（数据包为 `0x02`），后续为原始 IP 报文，总格式为 `[0x02] + [IP Header] + [Payload]`。
* **MSS 夹紧**：完全依靠将本地 TUN 设备 MTU 设置/Clamp 为 `1100` 字节来使操作系统内核自动在 TCP 握手阶段将 MSS 协商并限制在安全范围内（IPv4 限制为 1060 字节，IPv6 限制为 1040 字节），去除了任何用户态改包与校验和重新计算逻辑。

### 8.3 对称线程映射与控制面端口协商流程
1. **控制通道建立**：客户端首先发起与服务端控制端口（Control Port）的 UDP 连接。
2. **协商查询**：客户端发出查询请求。
3. **下发端口列表**：服务端验证通过后，返回活跃的数据端口列表（共 $N$ 个，例如 `[40001, ..., 40001+N-1]`）。
4. **客户端对称基准建立**：
   * 客户端以获取的 $N$ 个端口在本地拉起拥有 $N$ 个队列通道的多队列 TUN 网卡。
   * 开启恰好 $N$ 个工作线程，每个线程绑定一个对应的本地 UDP Socket 和服务端端口 `40000+i` 的 QUIC 连接。
   * 随后的 Peer 必须符合相同的 $N$ 个端口配置约束，否则予以拒绝。

### 9.4 安全与自愈机制
* **TLS 1.3 安全通道**：所有的 Datagram 数据均由 TLS 1.3 派生的 QUIC AEAD 加密上下文进行就地加密和完整性校验。
* **PSK 握手绑定**：数据面连接必须携带由 `session_psk` 签名 of 认证包，由服务端进行 nonce 防重放校验。
* **Slot 断线重连自愈**：客户端后台健康检查（Health Checker）循环检测各物理 Slot 状态。若 Slot $i$ 的连接中断，会单独触发该 Slot 的控制面预协商和链路重连，期间其他 $N-1$ 个 Slot 依然在高速转发数据，避免全链路抖动。

---

## 10. 全链路批处理 (Full-Pipeline Batch Processing)

为了在单核心上支持数万甚至数十万 PPS 的高吞吐转发，`new_proxy` 引入了全链路批处理架构，将数据面热路径上的系统调用、路由检索、数据加解密和传输操作完全合并为最多 64 个数据包的批次进行处理。

```
UDP 批接收 (recvmmsg) ---> 解复用与批量解密 (Quinn poll) ---> TUN 批写入 (try_write_packet)
                                                                       
TUN 批接收 (read + try_read) ---> 批量路由与加密 (Quinn send) ---> UDP 批发送 (sendmmsg)
```

### 10.1 UDP -> TUN 数据路径批处理
1. **系统调用批量化（Batch Receive）**：当 UDP 套接字可读时，使用 `recvmmsg` 系统调用配合 `MSG_DONTWAIT` 非阻塞标志，单次系统调用读取最多 64 个加密 UDP 报文到预分配的扁平缓冲区中，极大减少系统调用和上下文切换开销。
2. **解复用与批量解密（Batch Decrypt）**：遍历接收到的批次，将报文批量输入 Quinn `Endpoint`。Quinn 批量驱动连接状态机，并行解密报文。随后，遍历有事件的连接，从中批量拉取已解密的原始 IP 报文。
3. **批量写入 TUN（Batch Write）**：将解密出的数据包批量收集到临时向量中，然后通过非阻塞的 `try_write_packet` 循环快速写入 TUN 设备队列。如果 TUN 队列暂满，则优雅退化为异步等待写入，避免阻塞整个批次。

### 10.2 TUN -> UDP 数据路径批处理
1. **TUN 批量读取（Batch Read）**：在事件循环中，首先通过异步 `read` 等待并读取第一个 TUN 报文。随后，通过非阻塞的 `try_read` 循环，将 TUN 驱动队列中当前所有立即可用的报文（最多 63 个）全部读取出来，组成一个最大 64 报文的批次。
2. **按 Peer 批量分类与加密（Batch Routing & Peer Classification）**：对批次中的每一个报文，在无锁哈希表中检索其目的 Connection Handle。将属于相同 Peer/ConnectionHandle 的报文进行聚合归类（可通过对批次数据按 ConnectionHandle 进行就地排序实现，以确保零动态分配）。随后，按 Peer 轮流调用连接的 Datagram 发送队列 `send()` 批量写入该 Peer 的所有报文，批量触发 Quinn 内部的 AEAD 加密流程。
3. **UDP 批量发送（Batch Send）**：轮询所有连接并收集最多 64 个待发送的加密 UDP 报文（`Transmit`），最后使用 Linux 原生的 `sendmmsg` 系统调用在单次内核态切换中将所有报文批量发送出去。
