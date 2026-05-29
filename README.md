# new_proxy

`new_proxy` 是一个高性能混合多协议安全代理网关。它将系统 WireGuard L3 通道和用户态 QUIC L4 多路复用通道组合起来：UDP、ICMP 等三层流量走内核态 L3 通道，TCP 流量通过 TPROXY 拦截后走用户态 QUIC 连接池，从而规避 TCP-over-VPN 的队头阻塞问题。

## 主要功能

- **双轨数据面**：L3 WireGuard 风格通道承载 UDP/ICMP，L4 QUIC 多路复用通道承载 TCP。
- **TPROXY 透明拦截**：客户端按 `AllowedIPs` 判断 TCP 目的地址，命中后透明导入 QUIC 池。
- **多物理 QUIC 连接池**：服务端可配置多个 UDP 端口，客户端自动建立并轮询分流。
- **对等密钥认证**：复用 WireGuard 密钥材料，通过 X25519 shared secret 和 HMAC-SHA256 进行用户态控制面协商。
- **证书指纹固定**：控制面下发服务端 QUIC 证书 SHA-256 指纹，客户端只接受该指纹对应证书。
- **多 Peer 客户端**：客户端可同时配置多个 QUIC proxy peer，也可混合 WireGuard-only peer。
- **来源诊断**：遥测输出提供 `"both"`, `"kernel"`, `"proxy"` source 标识，用于判断 peer 在用户态配置和内核 WireGuard 状态中的分布关系。
- **聚合遥测**：通过 `new-proxy-cli` 查看 L3/L4 合并统计、QUIC 物理连接统计和活跃流数量，并直接输出 `source` 同步溯源字段。
- **动态 Peer 管理**：运行期支持通过 CLI 添加和删除 Peer。

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
- `iptables`
- `python3`
- `curl`
- `ping`

测试脚本依赖 Linux Network Namespace 和 TPROXY，必须使用 root 权限运行。

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
   该命令会在 `target/` 目录下生成 `new-proxy_5.0.0_amd64.deb` 安装包。

2. **安装 Debian 包**：
   ```bash
   sudo dpkg -i target/new-proxy_5.0.0_amd64.deb
   ```
   安装后，程序文件将被放置于 `/usr/bin/`，服务模板将写入 `/lib/systemd/system/`，示例配置复制至 `/etc/new_proxy/`。

3. **清理构建缓存与包**：
   ```bash
   make clean
   ```

## 配置方式

示例配置位于 `conf/`。支持以下高级配置项：
* **`Table`**（`auto` / `off`，默认 `auto`）：设置为 `auto` 时，网关启动会自动配置路由表和 `iptables` 代理规则，退出时自动回滚。若为 `off` 则跳过该行为，交由外部配置。
* **`PreScript` / `pre_script`**：网关启动前执行的脚本。可以是一个**单行 shell 命令**（如 `sysctl -w ...`），也可以是一个**可执行脚本/bash 文件的路径**（如 `/etc/new_proxy/pre.sh` 或 `bash /path/to/script.sh`）。
* **`PostScript` / `post_script`**：在网关优雅退出并清理完所有路由和防火墙之后执行的脚本。同样支持**单行 shell 命令**或**脚本/bash 文件的路径**。

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

客户端的 QUIC proxy peer 需要配置本地 TPROXY 端口、服务端 endpoint、控制面端口和目标 `AllowedIPs`：

```ini
[Interface]
PrivateKey = <client_private_key_base64>
Address = 10.0.0.2/24, fd00::2/64
TProxyPort = 1080
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

启动客户端：

```bash
sudo target/release/new_proxy -config conf/client.conf
```

同样，`conf/client.conf` 会使用接口名 `client`；需要兼容现有 `tun0` 路由/脚本时，请使用 `tun0.conf`。

客户端也可以配置 WireGuard-only peer：该 peer 不写 `Endpoint` 和 `ProxyPort`，不会进入 QUIC pool，也不会被 L4 router 捕获。若配置了 proxy peer，`Endpoint` 和 `ProxyPort` 必须同时存在。

### TPROXY 路由规则

客户端需要把命中 `AllowedIPs` 的 TCP 流量导入本地 TPROXY 端口。示例：

```bash
sudo ip rule add fwmark <derived_mark> lookup <derived_table>
sudo ip route add local 0.0.0.0/0 dev lo table <derived_table>
sudo iptables -t mangle -A PREROUTING \
  -p tcp -d 10.0.0.1 \
  -j TPROXY --on-port 1080 --on-ip 0.0.0.0 --tproxy-mark <derived_mark>/0xffffffff
```

`Table = auto` 时程序会按接口名稳定派生 mark/table 并自动配置这些规则；手工配置时应按业务网段替换 `10.0.0.1`，并确保 mark/table 与实例一致。

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

运行双栈端到端测试：

```bash
sudo script/acceptance/e2e_test_dualstack.sh
```

运行多场景 E2E 测试：

```bash
sudo script/acceptance/e2e_scenarios.sh
```

运行多客户端并发 L3 回退 E2E 测试：

```bash
sudo script/acceptance/e2e_multi_client.sh
```

运行 1 小时稳定性压测：

```bash
sudo script/acceptance/stability_stress_test.sh
```

缩短稳定性压测时间用于 smoke test：

```bash
sudo STABILITY_DURATION=30 STABILITY_SAMPLE_INTERVAL=5 script/acceptance/stability_stress_test.sh
```

最新测试结果见 `doc/TEST_REPORT.md`。
