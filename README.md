# new_proxy

`new_proxy` 是一个高性能纯 L3 IP-over-QUIC Datagram 异步隧道安全网关。所有数据流量（TCP, UDP, ICMP）均被无状态、零额外分流处理地封装进 QUIC Datagram 报文进行公网加密传输。依托 Linux 多队列 TUN 网卡与对称多核绑定哈希设计，实现无全局锁竞争的高并发 RTC 转发流，彻底消除 TCP-over-TCP 的队头阻塞及拥塞崩溃瓶颈。

## 主要功能

- **纯 L3 隧道数据面**：摒弃用户态 SOCKS/TCP 流代理，采用 IP-over-QUIC Datagram 方式，无需任何用户态 SOCKS、WireGuard (boringtun) 或 TCP/IP 协议栈 (smoltcp)，纯粹在 IP 层高速透传。
- **对称多队列多核心映射**：支持多物理 QUIC 数据面连接池，与多队列 TUN 设备队列一一对称绑定绑定物理 OS 线程，实现无共享状态、近线性的多核并发转发性能。
- **TCP MSS 夹紧 (MSS Clamping)**：就地拦截并重写握手报文的 TCP MSS 选项，防范 IP 分片（Fragmentation），提高传输效能。
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

### 纯 L3 IP-over-QUIC 数据面后端

当前版本已移除了 `boringtun` (WireGuard) 和 `smoltcp`，改用纯 L3 IP-over-QUIC Datagram 异步转发。程序仍需要创建多队列 TUN 设备并配置路由，因此通常需要 root 权限或 `CAP_NET_ADMIN` 能力。

### 服务端配置

服务端需要配置监听端口、控制面端口、QUIC 端口池以及允许接入的 Peer：

```ini
[Interface]
PrivateKey = <server_private_key_base64>
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
ListenControlPort = 51821
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

客户端的 QUIC proxy peer 需要配置服务端 endpoint、控制面端口和目标 `AllowedIPs`：

```ini
[Interface]
PrivateKey = <client_private_key_base64>
Address = 10.0.0.2/24, fd00::2/64
MTU = 1400
Table = auto
PreScript = echo "Client starting..." && sysctl -w net.ipv4.ip_forward=1
PostScript = echo "Client stopped cleanly."

[Peer]
PublicKey = <server_public_key_base64>
Endpoint = <server_public_ip>:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32, fd00::1/128
```

运行时 packet buffer 默认按 `MTU + 256` 分配，并限制在 `1500..65535` 字节；默认 `MTU = 1400` 时 buffer 为 `1656` 字节，jumbo MTU `9000` 时为 `9256` 字节。需要特殊调参时可用环境变量 `NEW_PROXY_PACKET_BUFFER_BYTES` 覆盖。

启动客户端：

```bash
sudo target/release/new_proxy -config conf/client.conf
```

同样，`conf/client.conf` 会使用接口名 `client`；需要兼容现有 `tun0` 路由/脚本时，请使用 `tun0.conf`。

客户端也可以配置 WireGuard-only peer：该 peer 不写 `Endpoint` 和 `ProxyPort`，不会进入 QUIC pool，也不会被 L4 router 捕获。若配置了 proxy peer，`Endpoint` 和 `ProxyPort` 必须同时存在。

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

最新测试结果见 `doc/TEST_REPORT.md`。
