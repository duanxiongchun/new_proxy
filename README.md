# new_proxy

`new_proxy` 是一个高性能混合多协议安全代理网关。它将 WireGuard 风格的 L3 通道和用户态 QUIC L4 多路复用通道组合起来：UDP、ICMP 等三层流量走内核态 L3 通道，TCP 流量通过 TPROXY 拦截后走用户态 QUIC 连接池，从而规避 TCP-over-VPN 的队头阻塞问题。

## 主要功能

- **双轨数据面**：L3 WireGuard 风格通道承载 UDP/ICMP，L4 QUIC 多路复用通道承载 TCP。
- **TPROXY 透明拦截**：客户端按 `AllowedIPs` 判断 TCP 目的地址，命中后透明导入 QUIC 池。
- **多物理 QUIC 连接池**：服务端可配置多个 UDP 端口，客户端自动建立并轮询分流。
- **对等密钥认证**：复用 WireGuard 密钥材料进行用户态控制面协商。
- **聚合遥测**：通过 `new-proxy-cli` 查看 L3/L4 合并统计、QUIC 物理连接统计和活跃流数量。
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

## 配置方式

示例配置位于 `conf/`。

### 服务端配置

服务端需要配置监听端口、控制面端口、QUIC 端口池以及允许接入的 Peer：

```ini
[Interface]
PrivateKey = <server_private_key_base64>
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
ListenControlPort = 51821

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

### 客户端配置

客户端需要配置本地 TPROXY 端口、服务端 endpoint、控制面端口和目标 `AllowedIPs`：

```ini
[Interface]
PrivateKey = <client_private_key_base64>
Address = 10.0.0.2/24, fd00::2/64
TProxyPort = 1080
MTU = 1400

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

### TPROXY 路由规则

客户端需要把命中 `AllowedIPs` 的 TCP 流量导入本地 TPROXY 端口。示例：

```bash
sudo ip rule add fwmark 1 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100
sudo iptables -t mangle -A PREROUTING \
  -p tcp -d 10.0.0.1 \
  -j TPROXY --on-port 1080 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1
```

实际部署时应按业务网段替换 `10.0.0.1`。

## CLI 使用

查看服务端聚合遥测：

```bash
target/release/new-proxy-cli show
```

查看客户端聚合遥测：

```bash
target/release/new-proxy-cli --client show
```

输出机器可读 dump：

```bash
target/release/new-proxy-cli dump
```

动态添加 Peer：

```bash
target/release/new-proxy-cli add-peer <public_key> <allowed_ips> [endpoint] [proxy_port]
```

动态删除 Peer：

```bash
target/release/new-proxy-cli remove-peer <public_key>
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

运行 1 小时稳定性压测：

```bash
sudo script/acceptance/stability_stress_test.sh
```

缩短稳定性压测时间用于 smoke test：

```bash
sudo STABILITY_DURATION=30 STABILITY_SAMPLE_INTERVAL=5 script/acceptance/stability_stress_test.sh
```

最新测试结果见 `doc/TEST_REPORT.md`。
