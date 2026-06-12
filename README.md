# new_proxy

`new_proxy` 是一个高性能纯 L3 IP-over-QUIC Datagram 异步隧道安全网关。所有数据流量（TCP, UDP, ICMP）均被无状态、零额外分流处理地封装进 QUIC Datagram 报文进行公网加密传输。依托 Linux 多队列 TUN 网卡与对称多核绑定哈希设计，实现无全局锁竞争的高并发 RTC 转发流，彻底消除 TCP-over-TCP 的队头阻塞及拥塞崩溃瓶颈。

## 主要功能

- **物理双数据面后端**：同时支持标准 Linux 多队列 TUN 设备以及先进的 eBPF 驱动级 **AF_XDP 零拷贝内核旁路数据面**，实现高效率的数据转发。
- **纯 L3 隧道数据面**：摒弃用户态 SOCKS/TCP 流代理，采用 IP-over-QUIC Datagram 方式，无需任何用户态 SOCKS、WireGuard (boringtun) 或 TCP/IP 协议栈 (smoltcp)，纯粹在 IP 层高速透传。
- **AF_XDP 零拷贝内核旁路**：依托 eBPF 过滤程序，自动将目标流量在内核驱动层重定向至用户态共享内存环（UMEM Rings），并辅以共享二层 MAC 地址缓存、填充环批处理生产（Fill Ring Batching）以及空闲时立即 Flush 机制，突破 CPU 锁与总线屏障限制，榨干硬件转发性能。
- **对称多队列多核心映射**：支持多物理 QUIC 数据面连接池，与多队列网卡通道（TUN/XSK）一一对称绑定物理 OS 线程，实现无共享状态、高并发的 RTC 转发流。
- **操作系统自动 MSS 夹紧 (MSS Clamping)**：利用物理或 TUN 设备 MTU 强制内核在 TCP 握手阶段自动协商更小的 MSS 大小，防范 IP 分片并节省用户态包改写与校验和重算开销。
- **集约化管控面单线程**：主运行时使用 `new_current_thread` 单线程调度，将 UDS CLI 服务、控制协商及 Failover 检测与高频数据工作线程进行物理隔离，避免调度开销与干扰。
- **对等密钥认证与防重放**：复用 WireGuard 格式的密钥材料，通过 X25519 ECDH 派生共享密钥，并利用 HMAC-SHA256 签名校验和 Nonce 缓存防范控制面重放攻击。
- **证书指纹固定**：控制面下发服务端 QUIC 证书 SHA-256 指纹，客户端强校验建立可信 QUIC 数据物理连接。
- **聚合遥测与诊断**：通过 `new-proxy-cli` 实时查询每个网卡队列、物理 Slot 连接状态、收发字节数及物理连接数指标。
- **动态 Peer 管理**：运行期支持通过 CLI / UDS API 动态添加和删除对等体，自动安全地重新热插拔网络拓扑。

## 目录结构

```text
conf/                  示例配置文件
doc/                   架构、测试规格和测试报告
script/acceptance/     端到端与稳定性测试脚本
src/                   Rust 源码
```

## 安装与构建

### 环境要求

- Linux
- Rust stable toolchain
- root 权限或具备等价网络管理能力
- `iproute2`
- `python3`
- `curl`
- `ping`

测试脚本依赖 Linux Network Namespace、TUN 设备和路由配置能力，必须使用 root 权限运行。

### 构建

```bash
cargo build --release --bins
```

开发调试也可以构建 debug 版本：

```bash
cargo build --bins
```

构建产物：

```text
target/release/new_proxy
target/release/new-proxy-cli
```

### Debian 打包与安装 (Makefile)

本项目支持通过 `make` 工具快速构建并打包为 Debian 格式的安装包（`.deb`），自动集成二进制文件、systemd 服务模板以及示例配置：

1. **构建并打包**：
   ```bash
   make package
   ```
   该命令会在 `target/` 目录下生成匹配当前 Debian 架构的安装包，例如 `new-proxy_5.0.0_amd64.deb` 或 `new-proxy_5.0.0_arm64.deb`。也可以显式覆盖架构：`make package ARCH=arm64`。

2. **安装 Debian 包**：
   ```bash
   sudo dpkg -i target/new-proxy_5.0.0_$(dpkg --print-architecture).deb
   ```
   安装后，程序文件将被放置于 `/usr/bin/`，服务模板将写入 `/lib/systemd/system/`，示例配置复制至 `/etc/new_proxy/`。

3. **清理构建缓存与包**：
   ```bash
   make clean
   ```

## 配置方式

示例配置位于 `conf/`。支持以下高级配置项：
* **`Table`**（`auto` / `off`，默认 `auto`）：设置为 `auto` 时，网关启动会自动配置 TUN 地址和 peer 路由，退出时自动回滚。若为 `off` 则跳过该行为，交由外部配置。
* **`PreScript` / `pre_script`**：网关启动前执行的脚本。可以是一个**单行 shell 命令**（如 `sysctl -w ...`），也可以是一个**可执行脚本/bash 文件的路径**（如 `/etc/new_proxy/pre.sh` 或 `bash /path/to/script.sh`）。
* **`PostScript` / `post_script`**：在网关优雅退出并清理完所有路由和防火墙之后执行的脚本。同样支持**单行 shell 命令**或**脚本/bash 文件的路径**。

### 数据面后端模式 (TUN / AF_XDP)

`new_proxy` 支持两种物理数据面后端模式，可通过 `[Interface]` 部分中的 `Mode` 字段进行配置：

* **TUN 模式** (`Mode = tun`，默认值)：
  * 创建并配置 Linux 多队列 TUN 虚拟网卡设备。数据包经内核路由截获，通过异步读写 TUN FD 进行处理。
  * 具备广泛的兼容性，支持各种通用虚拟/物理网卡和双栈网络。
* **AF_XDP 模式** (`Mode = af_xdp`)：
  * 使用 eBPF 驱动过滤程序将目标流量在内核驱动层直接重定向至用户态共享内存套接字（XSK），完全旁路内核 TCP/IP 协议栈。
  * 提供零拷贝、低 CPU 损耗的极致包转发效率。需要宿主机配置 `[XDP]` 部分。

#### AF_XDP 相关配置
当 `Mode = af_xdp` 时，必须在配置文件中指定 `[XDP]` 选项段：
* **`QuicInterface`**：指定运行外层 QUIC 加密隧道的物理/虚拟网卡接口名（如 `eth0`）。
* **`InterceptInterfaces`**：逗号分隔的接口列表，指定需要挂载 eBPF 程序以截获本地业务流量的接口名（如 `eth0, lo`）。
* **`XdpMode`**（`native` / `skb` / `driver`，默认 `native`）：eBPF 程序的加载模式。在虚拟测试环境（如 `veth`）或网卡不支持 native 模式时，可使用 `skb` 模式（Generic XDP）。


### 服务端配置

服务端需要配置监听端口、QUIC 端口池以及允许接入的 Peer：

```ini
[Interface]
PrivateKey = <server_private_key_base64>
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
Table = auto
PreScript = echo "Server starting..."
PostScript = echo "Server stopped cleanly."

[QUICPool]
PublicIPv4 = <server_public_ipv4>
PublicIPv6 = <server_public_ipv6>
ListenPorts = 40001, 40002, 40003, 40004

[Peer]
PublicKey = <client_public_key_base64>
AllowedIPs = 10.0.0.2/32, fd00::2/128
```

启动服务端：

```bash
sudo target/release/new_proxy -config conf/server.conf
```

接口名遵循 WireGuard/wg-quick 习惯：由配置文件名去掉 `.conf` 后得到。上面的命令会使用接口名 `server`；如果要使用 `tun0`，请把配置文件命名为 `tun0.conf` 并用 `-config .../tun0.conf` 启动。

### 客户端配置

客户端的 QUIC proxy peer 需要配置服务端 endpoint 和目标 `AllowedIPs`：

```ini
[Interface]
PrivateKey = <client_private_key_base64>
Address = 10.0.0.2/24, fd00::2/64
MTU = 1100
Table = auto
PreScript = echo "Client starting..." && sysctl -w net.ipv4.ip_forward=1
PostScript = echo "Client stopped cleanly."

[Peer]
PublicKey = <server_public_key_base64>
Endpoint = <server_public_ip>:51820
AllowedIPs = 10.0.0.1/32, fd00::1/128
```

运行时 packet buffer 默认按 `MTU + 256` 分配，并限制在 `1500..65535` 字节；默认 `MTU = 1100` 时 buffer 为最低值 `1500` 字节，jumbo MTU `9000` 时为 `9256` 字节。需要特殊调参时可用环境变量 `NEW_PROXY_PACKET_BUFFER_BYTES` 覆盖。

启动客户端：

```bash
sudo target/release/new_proxy -config conf/client.conf
```

同样，`conf/client.conf` 会使用接口名 `client`；需要兼容现有 `tun0` 路由/脚本时，请使用 `tun0.conf`。

客户端也可以配置 WireGuard-only peer：该 peer 不写 `Endpoint`，不会进入 QUIC pool，也不会被 L4 router 捕获。若配置了 proxy peer，必须配置 `Endpoint`；控制面端口 `ProxyPort` 是可选配置，默认使用 `Endpoint` 的端口。

## 系统服务管理 (Systemd)

安装 Debian 包后，可以使用 systemd 来管理和守护 `new_proxy` 实例。服务采用了模块化/模板化设计（`new_proxy@.service`），支持在一台机器上同时管理多个不同配置的网关实例：

### 1. 配置实例
准备您的配置文件（实例名即接口名，与 WireGuard/wg-quick 一致），并移动到配置目录下：
```bash
sudo cp conf/server.conf /etc/new_proxy/tun0.conf
```
*注意：服务加载的配置文件路径为 `/etc/new_proxy/<interface_name>.conf`。*

### 2. 启动与自启服务
以实例名（接口名，如 `tun0`）启动服务：
```bash
# 启动 tun0 实例
sudo systemctl start new_proxy@tun0

# 设置开机自启
sudo systemctl enable new_proxy@tun0
```

### 3. 管理服务状态
```bash
# 查看服务运行状态
sudo systemctl status new_proxy@tun0

# 查看服务实时日志
sudo journalctl -u new_proxy@tun0 -f

# 停止服务
sudo systemctl stop new_proxy@tun0
```

## CLI 使用

查看服务端聚合遥测：

```bash
target/release/new-proxy-cli --interface tun0 show
```

查看客户端聚合遥测：

```bash
target/release/new-proxy-cli --interface client show
```

输出机器可读 dump：

```bash
target/release/new-proxy-cli --interface tun0 dump
```

动态添加 Peer：

```bash
target/release/new-proxy-cli --interface tun0 add-peer <public_key> <allowed_ips> [endpoint] [proxy_port]
```

动态删除 Peer：

```bash
target/release/new-proxy-cli --interface tun0 remove-peer <public_key>
```

## 测试

运行 Rust 编译检查：

```bash
cargo check
```

运行 Rust 单元测试：

```bash
cargo test
```

运行统一的 E2E 验收与集成测试套件（包括格式、Clippy、脚本语法及 8 项端到端场景）：

```bash
sudo ./script/acceptance/run_acceptance.sh
```

运行 1 小时稳定性压测（需置环境变量 `RUN_STABILITY=1`）：

```bash
sudo RUN_STABILITY=1 ./script/acceptance/run_acceptance.sh
```

最新测试结果见 [doc/TEST_REPORT.md](file:///home/duanxiongchun/new_proxy/doc/TEST_REPORT.md)。

## 性能与多核可扩展性指标

在标准 MTU 1420（外层虚拟接口 MTU 1500，无 Jumbo 帧）及多物理核心（1..4 Cores）的并发高负载压测下，对 `new_proxy` 在 TUN 模式和 AF_XDP 模式下的吞吐性能进行了对比实测：

### 1. TCP 吞吐性能 (MiB/s)

| CPU 核心数 | AF_XDP 模式 (TCP) | TUN 模式 (TCP) | 相对增长率 (AF_XDP) | 线性扩展效率 (AF_XDP) |
| :--- | :--- | :--- | :--- | :--- |
| **1 Core** | **322.06 MiB/s** | 117.05 MiB/s | 1.00x | 100.0% |
| **2 Cores** | **545.54 MiB/s** | 304.67 MiB/s | 1.69x | 84.7% |
| **3 Cores** | **697.49 MiB/s** | 403.77 MiB/s | 2.17x | 72.2% |
| **4 Cores** | **891.69 MiB/s** | 580.86 MiB/s | 2.77x | 69.2% |

*   **单核突破红线**：AF_XDP 单核心 TCP 吞吐量达到 **322.06 MiB/s**（超越 300 MiB/s 的设计红线）。在饱和 UDP 流量测试中，AF_XDP 单核转发能力达到 **366.50 MiB/s**（约合 3.07 Gbps，超越了 350 MiB/s 的设计指标）。
*   **四核极速吞吐**：AF_XDP 四核心并发 TCP 吞吐量达到 **891.69 MiB/s**（约合 **7.48 Gbps**）。

### 2. UDP 吞吐性能 (MiB/s)

*   **AF_XDP 模式**：1 Core = **39.29 MiB/s**，2 Cores = **86.11 MiB/s**，3 Cores = **131.91 MiB/s**，4 Cores = **177.00 MiB/s**。
*   **TUN 模式**：1 Core = **39.23 MiB/s**，2 Cores = **85.67 MiB/s**，3 Cores = **131.71 MiB/s**，4 Cores = **174.33 MiB/s**。

### 3. 数据面核心优化设计

除了底层的全链路批处理、动态 Flush 机制之外，最近的物理 datapath 优化进一步挖掘了编译期和运行期的极限性能：
1.  **用户态 Ring 描述符 Non-Volatile 读写优化**：在 [worker.rs](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs) 中，移除了数据描述符槽位读写（如 [read_rx_desc](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L319)、[write_tx_desc](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L329) 等）的 `read_volatile`/`write_volatile`，改用标准的 Rust 指针读写。由于 AF_XDP 环的锁同步完全由控制索引更新及内存 Fence 保证，移除冗余的数据 volatile 读写释放了 LLVM 编译器的寄存器分配与自动向量化优化。
2.  **32 位字宽 IP 地址解析**：在 [parse_ip_src_dst](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L953) 中，重构为单次 32 位字宽读取 IP 地址，消除了 4 字节数组逐字节寻址的内存总线开销。
3.  **L2 二层协议类型提前校验**：在 `EthernetHeader::parse`（定义在 [worker.rs](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L219)）中，在拷贝 MAC 地址之前优先校验 `ether_type`，对于非 IPv4 流量实现提前中断，节省拷贝耗时。
4.  **向量预分配避免动态扩容**：在 [reclaim_tx_buffers](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L651) 中预分配回收向量的容量，消除大包率下动态增长的重新分配开销。
5.  **退出标志原子检测分摊**：在主轮询循环（定义在 [worker.rs](file:///home/duanxiongchun/new_proxy/src/xdp_datapath/worker.rs#L1966)）中，通过循环计数器将 `exit_flag` 原子读取摊销到每 1024 次循环执行一次，有效减小了多核缓存一致性协议（MESI）下的原子总线冲突与 cache 一致性同步。
6.  **填充环批处理生产 (Fill Ring Batching)**：将归还已处理 RX 缓冲页的操作合并，在每次循环的批次结尾统一调用 `fill.produce()` 并仅执行一次物理内存屏障（Fence），有效消除了 CPU 缓存频繁失效与总线锁竞争开销。
7.  **空闲时立即 Flush (Immediate Flush on Idle)**：当事件循环变为空闲（没有新包或 500 次空转）时，无条件立即执行 `sendto` 系统调用进行 Flush。这消除了批处理积压引起的 TCP RTT 抖动，使得单核 TCP 吞吐能够轻松跑满带宽上限。
8.  **用户态 Ring 指针本地缓存与按需回收 (Rings Pointer Caching)**：在 worker 循环中完全缓存了 consumer/producer 指针，消除了空轮询中的 volatile 读；且仅在 `free_tx_chunks` 低于 64 时触发完成队列（Completion Ring）的批量回收，将多余的 volatile 读取减少了 99%。
9.  **外层 IPv4 校验和常数预累加优化 (Checksum Precomputation)**：优化了 UDP 封装的外层 IP 报头校验和计算方法，从慢速的 20 字节循环累加计算改进为仅依赖 `total_len` 变量的单次常数增量运算，完全清空了包生成热路径中的冗余校验和开销。
10. **可扩展性与瓶颈解析**：
    *   **TUN 超线性特征**：多物理队列绑定相互解耦，消除了单核下单个文件描述符（TUN FD）和 L1/L3 缓存抖动（Cache Eviction）的串行开销。
    *   **AF_XDP 亚线性特征**：在虚拟机（`veth`）测试环境下由于不支持硬件 Zero-Copy，AF_XDP 以 `XDP_COPY` 模式运行，导致 SoftIRQ 软中断上下文切换与内存复制开销高昂（占 CPU 比例约 39.49%）。在近 7.5 Gbps 的极高吞吐下，总线带宽及 L3 缓存读写开始逼近物理硬件瓶颈。
