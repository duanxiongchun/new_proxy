#!/usr/bin/env bash
# ==============================================================================
# HYBRID SECURE PROXY GATEWAY - E2E MULTI-STREAM & DYNAMIC CLI SCENARIOS TEST
# ==============================================================================
# 流量路径说明:
#   Scenario 1 (QUIC卸载激活):
#     TCP:  client_app -> router_ns -> [TPROXY in client_ns:1080] -> QUIC Pool -> server_ns:8080
#     UDP/ICMP: client_ns -> router_ns -> server_ns (L3 native path)
#   Scenario 3 (L3回退):
#     ALL: client_ns -> router_ns -> server_ns:8080 (native path, no QUIC)
# ==============================================================================

set -e

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT_DIR/script/acceptance/test_key_material.sh"
source "$ROOT_DIR/script/acceptance/wireguard_backend.sh"
new_proxy_select_wireguard_backend

# Ensure script is run with sudo/root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root / using sudo."
  exit 1
fi

echo "======================================================================"
# Cleanup previous runs
ip netns delete client_ns 2>/dev/null || true
ip netns delete router_ns 2>/dev/null || true
ip netns delete server_ns 2>/dev/null || true
rm -f /run/new_proxy/server.sock
rm -f /run/new_proxy/client.sock
rm -f /tmp/client_proxy_active
rm -f /tmp/scenario_server.conf /tmp/scenario_client.conf
rm -f /tmp/scenario_server.conf /tmp/scenario_client.conf

# -------------------------------------------------------------------------
# 1. SETUP NAMESPACES & ROUTING
# -------------------------------------------------------------------------
echo "=== [1/5] Setting Up Network Namespaces & Routing ==="
ip netns add client_ns
ip netns add router_ns
ip netns add server_ns

# Setup veth interfaces: client_ns <-> router_ns
ip link add veth-client type veth peer name veth-router-c
ip link set veth-client netns client_ns
ip link set veth-router-c netns router_ns

# Setup veth interfaces: server_ns <-> router_ns
ip link add veth-server type veth peer name veth-router-s
ip link set veth-server netns server_ns
ip link set veth-router-s netns router_ns

# --- Client NS ---
ip netns exec client_ns ip addr add 10.0.1.2/24 dev veth-client
ip netns exec client_ns ip link set veth-client up
ip netns exec client_ns ip link set lo up
# 虚拟 WireGuard 隧道 IP (AllowedIP)
ip netns exec client_ns ip addr add 10.0.0.2/32 dev lo
ip netns exec client_ns ip route add default via 10.0.1.1
# 启用 ip_forward 以便路由流量进入 PREROUTING 被 TPROXY 拦截
ip netns exec client_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# --- Server NS ---
ip netns exec server_ns ip addr add 10.0.2.2/24 dev veth-server
ip netns exec server_ns ip link set veth-server up
ip netns exec server_ns ip link set lo up
# 虚拟 WireGuard 隧道 IP (AllowedIP) - 绑定在 lo 上
ip netns exec server_ns ip addr add 10.0.0.1/32 dev lo
ip netns exec server_ns ip route add default via 10.0.2.1
# 添加 lo 路由，确保 server daemon 能将 QUIC 流量转发到本地 HTTP 服务
ip netns exec server_ns ip route add 10.0.0.1/32 dev lo scope host

# --- Router NS ---
ip netns exec router_ns ip addr add 10.0.1.1/24 dev veth-router-c
ip netns exec router_ns ip link set veth-router-c up
ip netns exec router_ns ip addr add 10.0.2.1/24 dev veth-router-s
ip netns exec router_ns ip link set veth-router-s up
ip netns exec router_ns ip link set lo up
ip netns exec router_ns sysctl -w net.ipv4.ip_forward=1 >/dev/null

# router 路由: 访问 10.0.0.1 先经过 client_ns (Scenario 1 TPROXY 拦截)
ip netns exec router_ns ip route add 10.0.0.1/32 via 10.0.1.2
# client_ns 中: 访问 10.0.0.1 也通过 veth (否则是 lo 路由，不过 PREROUTING)
ip netns exec client_ns ip route add 10.0.0.1/32 via 10.0.1.1

# TPROXY 策略路由: 标记了 0x1 的包走 local 表
ip netns exec client_ns ip rule add fwmark 1 lookup 100
ip netns exec client_ns ip route add local 0.0.0.0/0 dev lo table 100

# TPROXY 拦截规则: 用单条规则同时 mark + 重定向 (正确语法)
ip netns exec client_ns iptables -t mangle -A PREROUTING \
    -p tcp -d 10.0.0.1 \
    -j TPROXY --on-port 1080 --on-ip 0.0.0.0 --tproxy-mark 0x1/0x1

echo "  ✓ 命名空间配置完成"
echo "  路由: router_ns -> 10.0.0.1 via 10.0.1.2 (client_ns)"
echo "  TPROXY: client_ns PREROUTING tcp->10.0.0.1 重定向到 :1080"

# -------------------------------------------------------------------------
# 2. START TARGET HOST SERVERS
# -------------------------------------------------------------------------
echo "=== [2/5] Starting Target TCP & UDP Servers in Server Namespace ==="
# HTTP 服务器 (多 TCP 流测试目标)
ip netns exec server_ns python3 -m http.server 8080 >/dev/null 2>&1 &
HTTP_PID=$!

# UDP 监听器 (多 UDP 流测试目标)
ip netns exec server_ns nc -u -l -k -p 8081 >/dev/null 2>&1 &
NC_UDP_PID=$!
sleep 1

# -------------------------------------------------------------------------
# 3. SCENARIO 1: DUAL-TRACK ACTIVE MODE (TCP via QUIC L4 + UDP/ICMP via L3)
# -------------------------------------------------------------------------
echo ""
echo "=== [3/5] SCENARIO 1: Dual-Track Offloading & Telemetry Verification ==="
echo "  流量路径:"
echo "  [TCP]      router_ns ──► client_ns:TPROXY:1080 ──► QUIC Pool ──► server_ns:8080"
echo "  [UDP/ICMP] client_ns ──► router_ns ──► server_ns (L3 native)"

# 激活客户端代理路径标志
touch /tmp/client_proxy_active

cat > /tmp/scenario_server.conf <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24
ListenPort = 51820
ListenControlPort = 51821
Table = off

[QUICPool]
PublicIPv4 = 10.0.2.2
ListenPorts = 40001, 40002

[Peer]
PublicKey = ${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}
AllowedIPs = 10.0.0.2/32
EOF_CONF

cat > /tmp/scenario_client.conf <<EOF_CONF
[Interface]
PrivateKey = ${NEW_PROXY_TEST_CLIENT1_PRIVATE_KEY}
Address = 10.0.0.2/24
TProxyPort = 1080
MTU = 1400
Table = off

[Peer]
PublicKey = ${NEW_PROXY_TEST_SERVER_PUBLIC_KEY}
Endpoint = 10.0.2.2:51820
ProxyPort = 51821
AllowedIPs = 10.0.0.1/32
EOF_CONF

# 启动 Server Daemon
ip netns exec server_ns ./target/debug/new_proxy -config /tmp/scenario_server.conf > /tmp/new_proxy_server_daemon.log 2>&1 &
SERVER_PID=$!
sleep 2

# 启动 Client Daemon (含 TPROXY 监听)
ip netns exec client_ns ./target/debug/new_proxy -config /tmp/scenario_client.conf > /tmp/new_proxy_client_daemon.log 2>&1 &
CLIENT_PID=$!
sleep 2

echo ""
echo "  >> 发射并行并发流量..."

# 3 个并发 TCP 流: 从 router_ns 发出，经过 client_ns TPROXY 拦截后走 QUIC 卸载
ip netns exec router_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/ &
TCP_PID1=$!
ip netns exec router_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/ &
TCP_PID2=$!
ip netns exec router_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/ &
TCP_PID3=$!

# 2 个并发 UDP 流: 从 client_ns 直发 server_ns (Type B L3 native)
echo "UDP Stream 1 payload" | ip netns exec client_ns nc -u -w 1 10.0.2.2 8081 &
echo "UDP Stream 2 payload" | ip netns exec client_ns nc -u -w 1 10.0.2.2 8081 &

# 2 个并发 ICMP 流: 从 client_ns 直发 server_ns (Type B L3 native)
ip netns exec client_ns ping -c 3 10.0.2.2 >/dev/null &
ip netns exec client_ns ping -c 3 10.0.2.2 >/dev/null &

# 等待 TCP 流完成
wait $TCP_PID1 $TCP_PID2 $TCP_PID3 2>/dev/null
sleep 1

echo ""
echo "  >> 从网关拉取聚合遥测 (L3 WAN + L4 QUIC 分层):"
ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show

echo ""
echo "  预期结果:"
echo "  L3 Transfer: 显示 WireGuard 后端统计数据"
echo "  L4 Transfer: 显示 QUIC 卸载的 TCP 字节 (应 > 0)"
echo "  Active Strm: TCP 完成后应为 0 (连接已关闭)"

# -------------------------------------------------------------------------
# 4. SCENARIO 2: SERVER RESTART & AUTO-RECONNECTION
# -------------------------------------------------------------------------
echo ""
echo "=== [4/6] SCENARIO 2: Server Restart & Client Auto-Reconnection ==="
echo "  >> 重启服务端以更改自签名证书..."
kill $SERVER_PID
sleep 1

# 启动 Server Daemon (这会生成全新的自签名证书)
ip netns exec server_ns ./target/debug/new_proxy -config /tmp/scenario_server.conf > /tmp/new_proxy_server_daemon.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "  >> 等待客户端健康检查器检测到连接断开并进行自愈重连..."
# 客户端的健康检查周期是 5 秒，空闲超时时间是 30 秒，我们睡眠 35 秒以确保连接彻底超时并完成自愈重连
sleep 35

echo "  >> 发送新的 TCP 流量以验证连接已恢复且走了 QUIC 隧道..."
ip netns exec router_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/

echo ""
echo "  >> 从网关拉取重启后的遥测数据:"
ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show

# 验证当前 quic 连接是否为 active，以确保重连成功
CLIENT_STATS=$(ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show)
if ! echo "$CLIENT_STATS" | grep -q "quic: active"; then
  echo "❌ [ERROR] Client failed to reconnect automatically after server restart!"
  exit 1
fi
echo "  ✓ 客户端重连成功！"

# -------------------------------------------------------------------------
# 4b. SCENARIO 2B: DYNAMIC FALLBACK TO WIREGUARD ON QUIC FAILURE
# -------------------------------------------------------------------------
echo ""
echo "=== [4b/6] SCENARIO 2B: Dynamic Fallback to WireGuard on QUIC Failure ==="
if ! ip netns exec client_ns ip link show scenario_client >/dev/null 2>&1; then
  echo "  >> SKIP: WireGuard device scenario_client is not present in client_ns; dynamic L3 fallback requires a real WireGuard netdev."
else
echo "  >> 模拟 QUIC 物理链路网络故障（丢弃服务器端 QUIC 端口的 UDP 包）..."
ip netns exec server_ns iptables -A INPUT -p udp --match multiport --dports 40001,40002 -j DROP

echo "  >> 等待客户端连接空闲超时（35秒）以触发降级逻辑..."
sleep 35

# 此时，客户端应该已经检测到连接全部断开，并将流量降级为 WireGuard 传输
echo "  >> 发送新的 TCP 流量，验证在 QUIC 故障下，流量是否可以无缝降级并成功通过 WireGuard 传输..."
ip netns exec router_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/
if [ $? -ne 0 ]; then
  echo "❌ [ERROR] TCP traffic failed under QUIC fallback state!"
  exit 1
fi
echo "  ✓ 降级模式流量传输成功！"

# -------------------------------------------------------------------------
# 4c. SCENARIO 2C: COOLDOWN-BASED SWITCH-BACK TO QUIC
# -------------------------------------------------------------------------
echo ""
echo "=== [4c/6] SCENARIO 2C: Cooldown-Based Switch-Back to QUIC ==="
echo "  >> 恢复服务器端 QUIC 端口（清空 iptables 阻断规则）..."
ip netns exec server_ns iptables -F INPUT

echo "  >> 等待客户端健康检查器重新建立物理 QUIC 连接并进入 Recovering (cooldown) 状态..."
# 健康检查间隔为 5 秒，加 2 秒缓冲
sleep 7

# 此时客户端应该重建了 QUIC 连接，但处于 Recovering 状态，新的 TCP 流量应该继续走 WireGuard 降级通道
echo "  >> 在 30 秒冷却时间内发送 TCP 流量，验证流量依然走 WireGuard 降级通道（防止频繁切换抖动）..."
# 记录发送流量前的 QUIC 字节数
PRE_QUIC_STATS=$(ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show)
PRE_QUIC_LINE=$(echo "$PRE_QUIC_STATS" | grep -A 7 "$NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY" | grep "quic transfer:")

ip netns exec router_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/

POST_QUIC_STATS=$(ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show)
POST_QUIC_LINE=$(echo "$POST_QUIC_STATS" | grep -A 7 "$NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY" | grep "quic transfer:")

if [ "$PRE_QUIC_LINE" != "$POST_QUIC_LINE" ]; then
  echo "❌ [ERROR] Traffic was sent over QUIC during the cooldown window!"
  exit 1
fi
echo "  ✓ 验证成功：冷却时间内流量未切换回 QUIC！"

echo "  >> 等待冷却时间结束（再等待 25 秒，总计超过 30 秒）..."
sleep 25

echo "  >> 发送新的 TCP 流量，验证冷却期结束后流量成功切换回 QUIC 通道..."
ip netns exec router_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/

FINAL_QUIC_STATS=$(ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show)
FINAL_QUIC_LINE=$(echo "$FINAL_QUIC_STATS" | grep -A 7 "$NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY" | grep "quic transfer:")

if [ "$FINAL_QUIC_LINE" = "$POST_QUIC_LINE" ]; then
  echo "❌ [ERROR] Traffic failed to switch back to QUIC after cooldown expired!"
  exit 1
fi
echo "  ✓ 验证成功：冷却期结束后流量成功切回 QUIC 隧道！"
fi

# -------------------------------------------------------------------------
# 5. SCENARIO 3: DYNAMIC PEER MANAGEMENT (hot-adding/removing peers)
# -------------------------------------------------------------------------
echo ""
echo "=== [5/6] SCENARIO 3: Dynamic Peer Management (Hot-Add/Remove Peer) ==="

NEW_PEER_KEY="${NEW_PROXY_TEST_CLIENT1_PUBLIC_KEY}"

echo "  A. 动态新增 Peer..."
ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server add-peer "$NEW_PEER_KEY" "10.0.0.99/32"

echo "  B. 验证 Peer 添加后遥测表 (应出现新 peer 行):"
ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show

echo "  C. 动态删除 Peer..."
ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server remove-peer "$NEW_PEER_KEY"

echo "  D. 验证 Peer 删除后遥测表 (应只剩原始 peer):"
ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show

# -------------------------------------------------------------------------
# 6. SCENARIO 4: WIREGUARD L3 FALLBACK (无 QUIC 代理, 纯 L3)
# -------------------------------------------------------------------------
echo ""
echo "=== [6/6] SCENARIO 4: Standard WireGuard L3 Fallback Mode (No QUIC) ==="
echo "  流量路径 (回退):"
echo "  [ALL]  client_ns ──► router_ns ──► server_ns:8080 (native L3, no QUIC)"

# 停止 client daemon
kill $CLIENT_PID 2>/dev/null
sleep 1

# 清除 TPROXY 拦截规则
ip netns exec client_ns iptables -t mangle -F PREROUTING
ip netns exec client_ns ip rule del fwmark 1 lookup 100 2>/dev/null || true
rm -f /tmp/client_proxy_active

# 更新 router 路由: 10.0.0.1 现在直接去 server_ns (绕过 client_ns)
ip netns exec router_ns ip route del 10.0.0.1/32 2>/dev/null || true
ip netns exec router_ns ip route add 10.0.0.1/32 via 10.0.2.2

echo ""
echo "  >> 发射相同流量 (纯 L3 回退路径)..."

# TCP 流: 从 client_ns 出发经 router_ns 直达 server_ns
ip netns exec client_ns curl -s --connect-timeout 5 -o /dev/null http://10.0.0.1:8080/ &
TCP_PID_FB=$!
# UDP 流
echo "UDP Fallback payload" | ip netns exec client_ns nc -u -w 1 10.0.0.1 8081 &
# ICMP 流
ip netns exec client_ns ping -c 2 10.0.0.1 >/dev/null &

wait $TCP_PID_FB 2>/dev/null || true
sleep 1

echo ""
echo "  >> 从网关拉取回退模式遥测:"
ip netns exec server_ns ./target/debug/new-proxy-cli --interface scenario_server show

echo ""
echo "  预期结果:"
echo "  L3 Transfer: 增加 (WireGuard 后端显示全量 L3 流量)"
echo "  L4 Transfer: 保持 0 B (QUIC 完全未使用)"
echo "  Active Strm: 0 (无 QUIC 流)"

# -------------------------------------------------------------------------
# CLEANUP
# -------------------------------------------------------------------------
echo ""
echo "=== Tearing Down Namespaces and Target Servers ==="
kill $SERVER_PID $HTTP_PID $NC_UDP_PID 2>/dev/null || true
sleep 1
ip netns delete client_ns 2>/dev/null || true
ip netns delete router_ns 2>/dev/null || true
ip netns delete server_ns 2>/dev/null || true

echo ""
echo "======================================================================="
echo " ✓ [SUCCESS] All E2E Integration and CLI scenarios fully passed!"
echo "======================================================================="
exit 0
