# new_proxy 架构说明（混合隧道架构）

本文档描述 `new_proxy` 的全新混合网关架构。系统支持在保持原有的纯 L3 IP-over-QUIC Datagram 用户态高性能数据面的同时，通过 Rust Netlink 接口在 Linux 内核中创建并管控原生内核态 WireGuard 网卡，构建支持多协议隧道的一体化安全网关。

---

## 1. 总体模型

`new_proxy` 是一个**混合型 L3 隧道网关**，集成了用户态 IP-over-QUIC 隧道与内核态 WireGuard 隧道：

* **混合隧道数据面**：
  * **用户态 IP-over-QUIC 隧道**：创建多队列 TUN/veth 网卡，将发往 QUIC 对等体（`Type = quic`）的 IP 报文（IPv4/IPv6）无状态、零额外协议栈包装地封装进 QUIC Datagram 帧中进行高速传输。
  * **内核态 WireGuard 隧道**：针对移动端（如手机、iPad 等）以及常规 WireGuard 对等体（`Type = wireguard`），主进程直接在 Linux 内核中拉起 WireGuard 接口，通过原生 Netlink 协议管理网卡、私钥与 Peer，让流量直接通过 Linux 内核 WireGuard 驱动进行加解密。
* **物理网卡自动命名与约定**：网卡接口名称无需用户在配置中手动指定，系统自动根据配置文件名 `<config_name>`（如 `client`）生成：
  * TUN 模式 (`Mode = tun`) 用户态网卡：`<config_name>-tun`
  * AF_XDP 模式 (`Mode = af_xdp`) 用户态网卡：`<config_name>-veth`
  * 内核 WireGuard 网卡：`<config_name>-wg`
* **最长前缀匹配（LPM）混合路由**：若用户态网卡与内核 WireGuard 网卡配置了相同的 IP 地址（例如 `10.0.0.2/24`），虽然会有冲突的网段路由，但系统在路由表中下发的 Peer 允许网段（`AllowedIPs`）是更具体的 `/32`（或 `/128`）主机路由。根据 Linux 内核的最长前缀匹配原则，去往不同 Peer 的数据包会精准流向各自对应的物理/虚拟网卡，实现无冲突的并行流转。
* **控制面**：独立的 UDP 报文协议，使用协商好的私钥/公钥材料派生 X25519 共享密钥，并用 HMAC-SHA256 对 JSON 格式的配置交换进行签名和认证。
* **运行期 API 与遥测收集**：通过 Unix Domain Socket 提供运行时 `Stats`、`Dump` 和 Peer 增删 API 支持。针对内核 WireGuard 的 Peer，主进程通过 Netlink 获取其实时传输量（Bytes rx/tx）和握手时间，合并呈现到遥测信息中。

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
   * 客户端以获取 of $N$ 个端口在本地拉起拥有 $N$ 个队列通道的多队列 TUN 网卡。
   * 开启恰好 $N$ 个工作线程，每个线程绑定一个对应的本地 UDP Socket 和服务端端口 `40000+i` 的 QUIC 连接。
   * 随后的 Peer 必须符合相同的 $N$ 个端口配置约束，否则予以拒绝。

### 8.4 安全与自愈机制
* **TLS 1.3 安全通道**：所有的 Datagram 数据均由 TLS 1.3 派生的 QUIC AEAD 加密上下文进行就地加密和完整性校验。
* **PSK 握手绑定**：数据面连接必须携带由 `session_psk` 签名 of 认证包，由服务端进行 nonce 防重放校验。
* **Slot 断线重连自愈**：客户端后台健康检查（Health Checker）循环检测各物理 Slot 状态。若 Slot $i$ 的连接中断，会单独触发该 Slot 的控制面预协商 and 链路重连，期间其他 $N-1$ 个 Slot 依然在高速转发数据，避免全链路抖动。

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
2. **按 Peer 批量分类与加密（Batch Routing & Peer Classification）**：对批次中的每一个报文，在无锁哈希表中检索其目的 Connection Handle 并归类到对应的 Peer。将属于相同 Peer 的报文聚合后，轮流调用对应 Peer 的 Datagram 发送队列 `send()` 批量写入该 Peer 的所有报文，触发 Quinn 内部的 AEAD 加密。
3. **UDP 批量发送（Batch Send）**：对每个 Peer 独立收集其生成的所有待发送加密 UDP 报文（`Transmit`），并针对每个 Peer 分别使用 Linux 原生的 `sendmmsg` 系统调用将属于该 Peer 的报文批量发送出去。

---

## 11. AF_XDP 高性能零拷贝数据面 (AF_XDP High-Performance Zero-Copy Datapath)

除了传统的 TUN 虚拟网卡后端，`new_proxy` 引入了基于原生 Linux AF_XDP (Address Family XDP) 的高性能零拷贝数据面。该设计专为高吞吐物理/虚拟网卡打造，完全绕过了内核 TCP/IP 协议栈，实现了用户态旁路数据面：

```
       [ 物理 / 虚拟网卡 (NIC) ]
                   │
                   ▼ (加载 eBPF XDP 过滤程序)
         [ XDP_REDIRECT 重定向 ]
                   │
         ┌─────────┴─────────┐
         ▼ (XSK RX 环)       ▼ (XDP_PASS 默认放行)
    [ 拦截并读入 UMEM ]     [ 宿主机/其它应用流量 ]
         │
         ▼
   [ RtcWorker (用户态) ] ── (共享 MAC 地址缓存查询/学习)
         │
         ▼ (QUIC 加密封装)
    [ XSK TX 环发送 ] ── (批量生产 Fill 环 / 空闲立即 Flush)
                   │
                   ▼
             [ 物理网卡发送 ]
```

### 11.1 eBPF 驱动过滤与重定向 (eBPF Filter)
* **eBPF 过滤程序源码 (`src/xdp_datapath/xdp_filter.c`)**：
  eBPF 过滤程序在网卡物理驱动层对以太网帧进行解析和判断，将符合条件的数据包通过 `XSKMAP` 重定向至用户态套接字，其它报文一律放行：
  ```c
  #include <linux/bpf.h>
  #include <linux/if_ether.h>
  #include <linux/ip.h>
  #include <linux/udp.h>
  #include <bpf/bpf_helpers.h>

  struct {
      __uint(type, BPF_MAP_TYPE_XSKMAP);
      __uint(max_entries, 64);
      __type(key, __u32);
      __type(value, __u32);
  } xsks_map SEC(".maps");

  SEC("xdp")
  int xdp_filter_prog(struct xdp_md *ctx) {
      void *data_end = (void *)(long)ctx->data_end;
      void *data = (void *)(long)ctx->data;

      struct ethhdr *eth = data;
      if (eth + 1 > data_end)
          return XDP_PASS;

      if (eth->h_proto == __constant_htons(ETH_P_IP)) {
          struct iphdr *ip = (void *)(eth + 1);
          if (ip + 1 > data_end)
              return XDP_PASS;

          // 1. 重定向 QUIC 加密 UDP 数据包（匹配端口 51820 或 40001）
          if (ip->protocol == IPPROTO_UDP) {
              struct udphdr *udp = (void *)(ip + 1);
              if (udp + 1 > data_end)
                  return XDP_PASS;

              if (udp->dest == __constant_htons(51820) || udp->dest == __constant_htons(40001)) {
                  return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
              }
          }

          // 2. 重定向内部明文业务数据包（匹配 10.0.0.0/8 目标网段）
          __u32 dest_ip = __constant_ntohl(ip->daddr);
          if ((dest_ip & 0xFF000000) == 0x0A000000) {
              return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
          }
      }
      return XDP_PASS;
  }
  char _license[] SEC("license") = "GPL";
  ```

* **Loader 挂载与 enrollment 机制 (`src/xdp_datapath/loader.rs`)**：
  在程序启动初始化时，`BpfLinkManager` 负责进行底层网络拓扑与 eBPF 的装载：
  1. **ARP 禁用与静态邻居映射**：
     * 执行 `ip link set dev <interface> arp off` 关闭接口的自动 ARP 响应。
     * 执行 `ip neighbor add <peer_ip> lladdr <peer_mac> dev <interface>` 强制写入静态 IP 与 MAC 邻居映射，避免三层握手前因为缺少物理 MAC 导致包被默默丢弃。
  2. **过滤程序加载**：
     * 创建特定目录 `/sys/fs/bpf/new_proxy_<ifname>/` 并挂载 BPF 文件系统。
     * 调用 `bpftool prog loadall src/xdp_datapath/xdp_filter.o /sys/fs/bpf/new_proxy_<ifname>/ pinmaps /sys/fs/bpf/new_proxy_<ifname>/maps/` 将 eBPF 程序和 MAP 实例化并 Pin 在系统目录中。
     * 调用 `bpftool net attach xdpgeneric pinned /sys/fs/bpf/new_proxy_<ifname>/xdp_filter dev <ifname>` 将过滤程序绑定至对应网卡。
  3. **XSK 套接字注册映射**：
     * 打开 Pin 好的 `xsks_map` 文件描述符：`libc::open("/sys/fs/bpf/new_proxy_<ifname>/maps/xsks_map", libc::O_RDWR)`。
     * 调用 `bpf` 系统调用的 `BPF_MAP_UPDATE_ELEM` 指令，将当前工作线程关联的 AF_XDP socket 文件描述符绑定至对应网卡 `queue_id` 的 Key 位置。

### 11.2 用户态共享环（UMEM & Rings）与无锁内存屏障
* **Rust 共享环结构定义 (`XskRing`)**：
  AF_XDP 在用户态完全旁路内核系统调用，依靠四个共享的内存映射环（Rx / Tx / Fill / Completion）与内核网卡驱动直接进行数据交互：
  ```rust
  struct XskRing {
      producer: *mut u32,
      consumer: *mut u32,
      desc: *mut u8,
      mask: u32,
      size: u32,
  }
  ```
* **无锁索引同步与内存屏障控制**：
  为确保用户态与网卡驱动在超高包率下并发读写环时不发生 CPU 乱序执行或编译器重排：
  * **写环操作 (Producer Ring: Fill / Tx)**：
    1. 使用 `Acquire` 内存屏障读取 `consumer` 索引，确定当前环中内核驱动已处理并释放的空闲槽位数。
    2. 将可用的 UMEM 物理缓冲区地址或 `xdp_desc` 描述符写入 `producer` 索引所在位置。
    3. 更新 `producer` 物理索引，并执行 `Release` 内存屏障，确保缓冲区写入操作在更新 producer 索引之前全部刷入主存。
    4. 执行 `libc::sendto` 唤醒内核收发包。
  * **读环操作 (Consumer Ring: Rx / Completion)**：
    1. 执行 `Acquire` 内存屏障读取物理 `producer` 索引，确保读入的最新的网卡接收包描述符是完全有效的。
    2. 依次读取描述符中记录的 UMEM 缓冲区偏移与报文长度。
    3. 将处理完毕的槽位记录在 `consumer` 中，最终执行 `Release` 内存屏障更新 consumer 索引，通知网卡驱动当前缓冲区页可被回收重新利用。

### 11.3 共享 MAC 地址缓存 (Shared MAC Cache)
* **多核共享的 MAC 映射**：为了让各个并发绑定的工作线程（Workers）快速识别和封装二层以太网头部，设计了共享的二层缓存 `inner_mac_cache`，采用 `Arc<RwLock<HashMap<Ipv4Addr, [u8; 6]>>>` 结构。
* **写时自动学习**：当工作线程从本地拦截套接字（Intercept XSK）读取到出站 Plaintext 报文时，自动提取源 IP 与源 MAC，写入缓存中进行热学习。
* **读时无锁/慢查询回退**：当解密完成的 Plaintext 报文准备发送给本地接口时，工作线程优先读取缓存获取目的 MAC。若缓存未命中，则回退执行底层的 ARP 表查询或接口 MAC 检测，并将结果写回缓存，彻底避免了在转发热路径上频繁、同步调用慢系统查询的性能损耗。

### 11.4 填充环批处理生产 (Fill Ring Batching)
* **批量退还缓冲区**：在接收数据包时，Rx 环的缓冲区页必须归还给 Fill 环供内核重新接收包。
* **减少内存屏障开销**：优化前的设计会逐包修改 Fill 环的 Producer 索引并进行 volatile 写入。优化后，`process_rx_ring` 在循环中仅在本地寄存器中累加已归还的缓冲地址，在处理完当前批次的所有报文（最多 64 包）后，**仅进行一次统一的 `fill.produce()` 生产提交和一次内存屏障**。这极大地降低了 CPU 缓存失效和总线锁（Lock Fences）的频率，在 32 MiB/2轮 统一压测下，使 4 核高并发 TCP 吞吐量成功突破 **969.97 MiB/s** (约合 **8.13 Gbps**)。

### 11.5 空闲时立即刷新 (Immediate Flush on Idle)
* **批处理与低延迟的权衡**：由于系统采用了最大 64 包的批处理发送设计，如果在低吞吐（如 TCP 握手阶段、Ping）或者流量突发空闲时，强行等待填满 64 包才调用 `sendto` 发送，会导致往返时延（RTT）上升并阻碍 TCP 窗口扩展，使吞吐量下降。
* **空闲即刻 Flush**：通过精细化调整工作线程的主循环，当检测到本次事件循环中没有新数据被处理（`!work_done`）或者自上次物理发送以来已空转（Spin）超过 500 次时，**无条件立即触发物理 `sendto` 系统调用进行 Flush**。这既保证了高负载下的系统调用批量化合并，又保证了空闲与低频状态下的超低 RTT 时延，单核 TCP 吞吐量成功突破 **333.04 MiB/s**（超过 330 MiB/s 的设计红线，在 64 MiB/4轮 压测下能稳定达到 **341 - 347 MiB/s**）。

### 11.6 用户态 Ring 指针本地缓存与按需回收 (Rings Pointer Caching)
* **消除冗余内存读取**：XSK 套接字的四个环中，消费指针和生产指针的大部分更新仅由用户态 Worker 线程独自负责。我们将这些指针缓存在 Worker 寄存器中，在循环体中避免了每一次空转带来的 `read_volatile` 指针读取，使得无包空转时的内存屏障与读取次数降低了 50%。
* **按需回收完成队列**：只在本地空闲 TX 块计数低于 64 时触发完成队列（Completion Ring）的批量回收，极大减少了在高吞吐下针对完成环生产者索引的 volatile 读频次。

### 11.7 外层 IPv4 校验和常数运算优化 (Fast Checksum Precomputation)
* **消除累加循环**：优化前，每个从 Plaintext 到 QUIC Encrypted 的报文都需要动态遍历 20 字节的外层 IP 头部计算 IPv4 校验和。由于该头部除 `total_len` 外，所有的源 IP/MAC、目的 IP/MAC、协议号等均为连接生存期内的常数，我们将常数部分在连接建立时或本地提取预计算，计算新校验和时仅通过一次常数相加与位折叠操作得到最终校验和，完全清空了发送热路径上的头部遍历开销。

### 11.8 用户态 Ring 描述符 Non-Volatile 读写优化 (Volatile Operations Bypass)
* **避免过度 Volatile 强制**：在 lock-free UMEM 环中，内核与用户态对环槽数据描述符（地址、长度）的并发读写是单向且互斥的（受 `producer`/`consumer` 控制索引以及内存 Fence 保护）。原版代码对数据槽（`read_rx_desc`、`write_tx_desc`、`write_fill_addr`、`read_comp_addr`）使用了 `read_volatile` / `write_volatile`，这强行指示编译器不得对其进行任何寄存器缓存或指令重排优化。
* **寄存器与向量化释放**：在 [worker.rs](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs) 中，我们将其重构为 Rust 标准指针读写（`std::ptr::read`/`std::ptr::write`），仅对控制面同步变量保留 volatile 限制。这一改动释放了 LLVM 编译器的指令重排及向量化分析空间，使得在包读写循环中能以最优的寄存器布局运行，单核性能显著提升。

### 11.9 热路径微观性能优化 (Micro-Optimizations on Hot-Path)
* **32-Bit Word IP 地址解析**：在 [parse_ip_src_dst](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L953) 中，原版通过 4 字节切片逐字节提取源 IP 和目的 IP，引发了多次不必要的内存寻址。我们将其重构为单次 32 位字宽加载（32-bit Word Load），一次性获取完整的 IPv4 地址。
* **L2 协议头提前校验**：在以太网头部解析 `EthernetHeader::parse`（[worker.rs](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L219)）中，将 `ether_type` 校验提前。如若不是业务所需的以太网协议（例如非 `ETH_P_IP`），直接返回 `None` 退出，完全避免了源/目的 MAC 地址的无效内存拷贝（12 字节拷贝与对齐开销），实现了针对海量无关以太网广播帧的快速过滤。
* **TX 回收向量预分配**：在物理完成队列（Completion Ring）的缓冲区回收逻辑 [reclaim_tx_buffers](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L651) 中，在将地址推入 `free_tx_chunks` 向量之前，根据当前批次的可归还数量 `cnt` 显式调用 `.reserve(cnt)`。这完全消除了 Rust 向量在热路径上由于元素追加导致的动态扩容、重新分配以及冗余的内存拷贝。
* **退出标志检测摊销 (Amortized Exit Check)**：`exit_flag` 属于原子布尔值（`AtomicBool`），原版在工作线程 `while` 循环头每次都执行原子读取。在多核绑定的环境下，高频的原子变量读取会通过 MESI 协议在 CPU 核心之间产生频繁的总线缓存行嗅探与一致性同步开销。我们引入了一个简单的计数器，将原子读取分摊（Amortize）到每 1024 次循环执行一次，在确保及时响应退出信号的同时，完全消除了该热路径开销。

### 11.10 用户态以太网帧解析与封装细节 (Userspace L2 Packet Framing)
* **明文拦截与隧道加密路径 (出站)**：
  1. 工作线程轮询 Intercept XSK 的 RX 环，从中拉取由 eBPF 重定向的 Plaintext 二层以太网帧。
  2. 解析二层 Ether Header（14字节），剥离以太网头，暴露出原始 IP 数据报。
  3. 将原始 IP 包提交给底层连接绑定的 Quinn 加密套接字，输出密文 QUIC Datagram。
  4. 从 TX UMEM 块分配一个空闲的 Buffer Chunk（4096字节）。
  5. 重新组配物理网口发送的二层密文以太网帧：
     * `[0..14] 字节`：填充物理外层以太网头（本地物理 MAC、网关 MAC，协议 `0x0800`）。
     * `[14..34] 字节`：填充外层 IPv4 报头（本地外层 IP、Peer 物理 IP）。
     * `[34..42] 字节`：填充外层 UDP 报头（物理端口及长度）。
     * `[42..] 字节`：装入加密的 QUIC Datagram 报文载荷。
  6. 将拼装好的密文描述符提交至 QUIC Tunnel XSK 的 TX 环中物理发送。
* **物理隧道接收与明文投递路径 (入站)**：
  1. 轮询 QUIC Tunnel XSK 的 RX 环，拉取从物理网卡收到的密文以太网帧。
  2. 剥离外层的 Ethernet、IP 及 UDP 报头，将解密后的 Plaintext IP 数据报输入。
  3. 解密得到明文 IP 包。
  4. 从 TX UMEM 块分配一个空闲的 Buffer Chunk。
  5. 组配投递给本地宿主应用的明文以太网帧：
     * `[0..6] 字节`：填充目的 MAC（从 `inner_mac_cache` 缓存获取，未命中则回退执行本地 ARP 查询）。
     * `[6..12] 字节`：填充源本地 MAC。
     * `[12..14] 字节`：协议字填充 `0x0800`。
     * `[14..] 字节`：装入原始明文 IP 包。
  6. 将明文以太网帧提交至 Intercept XSK 的 TX 环，网卡接收后通过内核送达宿主应用。

---

## 12. 内核态 WireGuard 管理与 Netlink 集成

为了不依赖外部的 `wg` 命令行工具实现环境的安全沙盒化，`new_proxy` 引入了基于 Netlink 通信协议的原生 WireGuard 管理逻辑。

### 12.1 网卡生命周期与 Netlink 驱动
* **网卡创建与销毁**：使用 Netlink (`RTM_NEWLINK`) 接口向 Linux 内核发送请求，动态创建类型为 `wireguard` 的虚拟网口 `<config_name>-wg`。在进程优雅退出或通过 UDS 触发销毁时，向内核发送 `RTM_DELLINK` 请求安全销毁该网卡。
* **wireguard-go 自动降级适配**：如果运行环境的 Linux 内核未开启/编译原生 `wireguard` 模块，程序在创建原生网卡失败后将**自动降级**，在后台拉起 `wireguard-go <config_name>-wg` 用户态守护进程以创建该虚拟设备。
* **物理地址与状态配置**：通过 Netlink 绑定配置的 `Address` 到该网口，并发送 UP 指令将网卡置为活跃状态，设置对应 MTU。无论是内核原生网卡还是由 `wireguard-go` 创建的设备，程序后期的 Netlink 配置管理与遥测读取机制完全一致。

### 12.2 网卡参数与对等体（Peer）配置
* 主进程通过 Generic Netlink 的 `wireguard` 协议族发送参数更新包：
  * **接口级配置**：安全地将 `PrivateKey` 以及 `WgListenPort` 刷入内核 WireGuard 驱动。
  * **Peer 动态更新**：遍历所有 `Type = wireguard` 的 Peer，通过 Netlink 的 `WGDEVICE_A_PEERS` 属性序列化写入每个 Peer 的 `PublicKey`、`AllowedIPs` 以及 `Endpoint` 等信息。
  * **动态热插拔**：当通过 UDS API 动态执行 `AddPeer` / `RemovePeer` 时，除修改内存配置外，会立即触发 Netlink 的增量/删除事务同步至内核，实现零延迟网络热插拔。

### 12.3 零锁实时遥测收集
* 运行期主进程在处理 UDS `Stats` 查询时，会通过 Netlink 向内核发送 Dump 请求。
* 从内核返回的二进制序列化载荷中读取每个 Peer 的：
  * `rx_bytes`（累计接收字节数）
  * `tx_bytes`（累计发送字节数）
  * `last_handshake_time`（最近握手时间戳）
* 采集到的数据会被缓存并合并注入到遥测组件的 `l3_stats` 结构中，使 `new-proxy-cli` 能够提供与用户态 QUIC 同样的实时性能指标监控。

