# new_proxy

`new_proxy` v5 是固定拓扑的 AF_XDP QUIC L3 appliance。当前只支持一组
`client <-> server`，由用户态 Flow worker 完成双层 stateful SNAT，并通过
QUIC Datagram 加密传输 IPv4/IPv6 TCP、UDP、ICMP 流量。

项目已硬切到 v1：不提供旧运行时兼容层、动态 peer 管理或第二种数据面。

## 支持范围

- 单 client、单 server、固定 endpoint/listen 地址。
- AF_XDP/XSK 收发；每个 `(ifindex, queue_id)` 只有一个 IO owner。
- client 可配置多个本地 intercept interface；server 只能配置一个。
- tunnel interface 与 intercept interface 可以是同一接口。
- 每个 Flow worker 独占自己的 Session、NAT、reverse-NAT 和 QUIC 状态。
- client/server 分别执行本地 stateful SNAT。
- IPv4/IPv6 TCP、UDP、ICMP/ICMPv6。
- TLS 服务端证书 SHA-256 pin 和共享密钥 HMAC 双向认证。
- QUIC Datagram 内有界分片/重组，支持标准 1500-byte inner packet。
- QUIC keepalive 保持健康空闲长连接；断线后清理旧 Session/NAT/DCID 并重连。
- 以 `0600` 原子写入的只读 JSON stats 文件。

不支持：

- 多 peer、多租户或运行时动态拓扑。
- WireGuard、hybrid 或 TUN 数据面。
- 配置兼容、控制面 socket 或独立管理 CLI。
- 自动修改主机路由、邻居或防火墙。

## 架构

```text
local network
    |
intercept NIC / XSK
    |
IO worker -- bounded channel --> Flow worker
                                  |- Session owner
                                  |- local SNAT / reverse NAT
                                  |- QUIC + TLS pin + HMAC
    |                             |
tunnel NIC / XSK <----------------+
    |
encrypted QUIC/UDP
```

- IO worker 独占一个 XSK 的 RX/TX/Fill/Completion rings，只做轻量分类和收发。
- Flow worker 是唯一可创建、修改和回收 Session/NAT/QUIC 状态的线程。
- intercept ingress 按内层 flow 稳定选择 Flow worker。
- tunnel ingress 先按 active DCID 定位 Flow worker；只有合法 Initial 可以走
  deterministic bootstrap。
- 每个 QUIC flow 绑定稳定 tunnel queue；本地回投使用 Session 记录的
  `(intercept_ifindex, intercept_queue_id)`。

详细约束见 `doc/ARCHITECTURE.md`，覆盖映射见 `doc/TESTING.md`。

## 环境要求

- Linux，内核支持 XDP 和 AF_XDP。
- root 或等价的 BPF、XDP、AF_XDP 权限。
- Rust stable、Clang/LLVM。
- `bpftool`、`iproute2`、`ethtool`、`openssl`、`python3`。
- 物理部署必须预先配置接口地址、路由和静态/稳定邻居；配置中的
  `NextHopMac` 由运行时直接用于 L2 发包。

`[XDP] Mode=native` 用于支持 native XDP 的 NIC；veth 测试环境使用
`Mode=skb`。

## 构建

```bash
cargo build --release --bin new_proxy
```

唯一运行产物是：

```text
target/release/new_proxy
```

Cargo build script 会编译并嵌入 XDP ELF；部署时不需要源码目录或独立
`xdp_filter.o`。

构建 Debian 包：

```bash
make package
```

包内包含 binary、`new_proxy@.service`、client/server 示例配置、direct prefix
和 remote domain 示例文件。
`/etc/new_proxy/client.conf` 和 `server.conf` 作为 conffile 安装，升级不会静默覆盖。

## 配置

完整示例：

- `conf/client.conf`
- `conf/server.conf`

关键字段：

| Section | Field | 含义 |
|---|---|---|
| `Appliance` | `Role` | `client` 或 `server` |
| `Appliance` | `FlowWorkerCount` | Flow worker 数量，必须大于 0 |
| `Appliance` | `ChannelCapacity` | IO/Flow bounded channel 容量 |
| `Appliance` | `DcidLength` | 固定 DCID 长度，范围 `8..=20` |
| `Appliance` | `StatsPath` | 原子更新的只读 JSON stats 路径 |
| `Appliance` | `SharedKey` | 32 字节 HMAC key 的 64 位十六进制文本 |
| `Tunnel` | `Interface` | 外层 QUIC 接口 |
| `Tunnel` | `Endpoint` | client 连接的 server 地址 |
| `Tunnel` | `Listen` | server 监听地址 |
| `Tunnel` | `NextHopMac` | 外层报文下一跳 MAC |
| `Tunnel` | `ServerCertificateSha256` | client 使用的 DER 证书 SHA-256 pin |
| `Tunnel` | `ServerCertificate` | server DER 证书路径 |
| `Tunnel` | `ServerPrivateKey` | server PKCS#8 DER 私钥路径 |
| `Intercept*` | `Interface` | 本地明文接口 |
| `Intercept*` | `NextHopMac` | 本地网络下一跳 MAC |
| `NAT` | `AddressV4/AddressV6` | 本节点 SNAT 地址，至少配置一个 |
| `NAT` | `PortStart/PortEnd` | 本节点 SNAT 端口范围 |
| `AllowedIPs` | `Prefixes` | client 的 inline/file tunnel prefix 或 `!file:` direct prefix |
| `DNS` | `Listen` | client intercept 网络中的独立 UDP/53 VIP，且不能等于 NAT/tunnel/resolver address |
| `DNS` | `LocalResolver` | 未命中 remote domain 时使用的 client 本地 UDP/53 resolver |
| `DNS` | `RemoteResolver` | 命中 remote domain 时通过 server 访问的 UDP/53 resolver |
| `DNS` | `RemoteDomainsFile` | remote domain 后缀文件 |
| `XDP` | `Mode` | `native` 或 `skb` |

配置 parser 是严格的。未知 section/field、旧字段、server `[AllowedIPs]`/`[DNS]`、
server 多 intercept、重复接口、空 client AllowedIPs、无效 NAT 范围和错误 role
addressing 都会在启动前失败。
示例配置中的全零 `SharedKey` 是不可启动的占位符，部署前必须替换为两端一致的
随机 32-byte key；证书路径、pin、接口、地址和 MAC 也必须按现场修改。

## 运行

先确保 stats 目录存在，并准备接口、地址、邻居与路由：

```bash
sudo install -d -m 0700 /run/new_proxy
sudo target/release/new_proxy --config /etc/new_proxy/server.conf
sudo target/release/new_proxy --config /etc/new_proxy/client.conf
```

systemd 示例：

```bash
sudo cp conf/server.conf /etc/new_proxy/server.conf
sudo systemctl enable --now new_proxy@server
sudo journalctl -u new_proxy@server -f
```

`SIGHUP` 请求 QUIC 重连。重连会回收旧连接绑定的 Session、NAT 和 DCID；
后续业务包重新建 Session。`SIGTERM`/`SIGINT` 执行有界关闭并 detach XDP。
若进程被 `SIGKILL`，下一实例会在确认 pinned program 属于本项目后清理 stale
attachment；不会无条件拆除其他 XDP program。

## Stats

读取配置中的 `StatsPath` 即可获得：

- 每个 IO owner 的 ifindex、queue、role、RX/TX/drop 计数。
- 每个 Flow worker 的 `quic_flow_id`、tunnel queue、认证状态。
- Session 原始 tuple、本地 SNAT tuple 和原始 intercept owner。
- active DCID、reverse NAT、IO/Flow channel、QUIC send、pending queue、NAT/DCID
  发布和重连失败计数。

该文件是只读观测契约，不提供运行时修改接口。

## 测试

默认非特权门禁：

```bash
./script/acceptance/run_acceptance.sh
```

完整 root E2E（构建包含 XDP ELF 的 release binary 后顺序运行九个隔离场景）：

```bash
RUN_V1_E2E=1 ./script/acceptance/run_acceptance.sh
```

九个场景覆盖：

1. client 到 target 的双栈 TCP/UDP/ICMP 闭环。
2. IPv4 DNS VIP 的 local/remote resolver 分流、双端 SNAT、超时 `SERVFAIL` 与状态释放。
3. IPv6 DNS VIP 的 local/remote resolver 分流、响应 rcode、wire ID 和 Question 匹配。
4. server reverse NAT 与回隧道。
5. client reverse NAT 与本地回投。
6. tunnel/intercept 同接口。
7. client 多 intercept 回到原接口。
8. SIGHUP 重连后的状态回收与新 flow identity。
9. 1500-byte inner packet、12 秒双栈空闲 TCP、2 Flow workers 和 SIGKILL 恢复。

可选的有界长稳和性能基线：

```bash
RUN_V1_SOAK=1 V1_SOAK_CYCLES=10 ./script/acceptance/run_acceptance.sh
RUN_V1_PERF=1 V1_PERF_ITERATIONS=100 ./script/acceptance/run_acceptance.sh
```

性能结果依赖 NIC、XDP mode、queue 数和 CPU 拓扑；仓库不内置不可复现的历史数字。

## 回滚

部署失败时停止对应实例即可：

```bash
sudo systemctl stop new_proxy@client new_proxy@server
```

进程退出会 detach 自己加载的 XDP program 并删除 ifindex-scoped BPF pins。
接口地址、路由和邻居由部署系统管理，`new_proxy` 不会替用户回滚这些外部配置。
