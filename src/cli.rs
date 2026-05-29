use std::io::Write;
use std::os::unix::net::UnixStream;
use std::io::{Read, BufWriter};
use serde::{Serialize, Deserialize};

// 每条物理 QUIC 连接的统计快照（与 quic_pool::QuicConnSnapshot 字段完全对齐）
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuicConnSnapshot {
    pub remote_addr: String,
    pub local_port: u16,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub active_streams: u64,
}

// CLI 的本地副本，与 main.rs 中的 UnifiedTelemetry 保持字段对齐
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnifiedTelemetry {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub l3_rx_bytes: u64,
    pub l3_tx_bytes: u64,
    pub last_handshake: u64,
    pub l4_rx_bytes: u64,
    pub l4_tx_bytes: u64,
    pub active_streams: u64,
    pub quic_connections: Vec<QuicConnSnapshot>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum CommandInput {
    Stats,
    Dump,
    AddPeer { public_key: String, allowed_ips: Vec<String>, endpoint: Option<String>, proxy_port: Option<u16> },
    RemovePeer { public_key: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse {
    pub status: String,
    pub message: Option<String>,
}

const DEFAULT_SERVER_UDS_PATH: &str = "/tmp/new_proxy_api.sock";
const DEFAULT_CLIENT_UDS_PATH: &str = "/tmp/new_proxy_api_client.sock";

fn connect_uds(path: &str) -> Result<UnixStream, String> {
    UnixStream::connect(path)
        .map_err(|e| format!("Cannot connect to daemon socket ({}): {}\n  → Is the gateway daemon running?", path, e))
}

fn send_command(path: &str, cmd: &CommandInput) -> Result<String, String> {
    let mut stream = connect_uds(path)?;
    let payload = serde_json::to_vec(cmd).unwrap();
    stream.write_all(&payload).map_err(|e| format!("Write error: {}", e))?;
    drop(stream.try_clone().ok()); // trigger EOF on server side
    let mut buf = String::new();
    stream.read_to_string(&mut buf).map_err(|e| format!("Read error: {}", e))?;
    Ok(buf)
}

/// 将字节数格式化为人类可读形式（与 wg show 一致）
fn fmt_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes == 0 {
        "0 B".to_string()
    } else if bytes < KIB {
        format!("{} B", bytes)
    } else if bytes < MIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else if bytes < GIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    }
}

/// 将 Unix 时间戳差值格式化为"X minutes, Y seconds ago"
fn fmt_handshake_ago(ts: u64) -> String {
    if ts == 0 {
        return "Never".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now <= ts {
        return "just now".to_string();
    }
    let secs = now - ts;
    if secs < 60 {
        format!("{} second{} ago", secs, if secs == 1 { "" } else { "s" })
    } else if secs < 3600 {
        let m = secs / 60; let s = secs % 60;
        if s == 0 {
            format!("{} minute{} ago", m, if m == 1 { "" } else { "s" })
        } else {
            format!("{} minute{}, {} second{} ago", m, if m == 1 { "" } else { "s" }, s, if s == 1 { "" } else { "s" })
        }
    } else {
        let h = secs / 3600; let m = (secs % 3600) / 60;
        format!("{} hour{}, {} minute{} ago", h, if h == 1 { "" } else { "s" }, m, if m == 1 { "" } else { "s" })
    }
}

/// WireGuard 风格的 show 展示（每个 peer 独立块，缩进文本）
fn print_wg_style(peers: &[UnifiedTelemetry]) {
    let out = std::io::stdout();
    let mut w = BufWriter::new(out.lock());

    writeln!(w, "interface: new-proxy").unwrap();
    writeln!(w, "  mode: hybrid secure gateway (WireGuard L3 + QUIC L4 offload)").unwrap();
    writeln!(w, "  peers: {}", peers.len()).unwrap();
    writeln!(w).unwrap();

    if peers.is_empty() {
        writeln!(w, "  (no peers configured)").unwrap();
        return;
    }

    for peer in peers {
        writeln!(w, "peer: {}", peer.public_key).unwrap();

        if let Some(ep) = &peer.endpoint {
            writeln!(w, "  endpoint: {}", ep).unwrap();
        }

        if !peer.allowed_ips.is_empty() {
            writeln!(w, "  allowed ips: {}", peer.allowed_ips.join(", ")).unwrap();
        } else {
            writeln!(w, "  allowed ips: (none)").unwrap();
        }

        writeln!(w, "  latest handshake: {}", fmt_handshake_ago(peer.last_handshake)).unwrap();

        let total_rx = peer.l3_rx_bytes.saturating_add(peer.l4_rx_bytes);
        let total_tx = peer.l3_tx_bytes.saturating_add(peer.l4_tx_bytes);
        writeln!(w, "  transfer: {} received, {} sent",
            fmt_bytes(total_rx), fmt_bytes(total_tx)).unwrap();
        writeln!(w, "  wireguard: {} received, {} sent",
            fmt_bytes(peer.l3_rx_bytes), fmt_bytes(peer.l3_tx_bytes)).unwrap();

        if peer.quic_connections.is_empty() && peer.l4_rx_bytes == 0 && peer.l4_tx_bytes == 0 {
            writeln!(w, "  quic: inactive").unwrap();
        } else {
            let conn_count = peer.quic_connections.len();
            writeln!(w, "  quic: active, {} physical connection{}, {} active stream{}",
                conn_count,
                if conn_count == 1 { "" } else { "s" },
                peer.active_streams,
                if peer.active_streams == 1 { "" } else { "s" }).unwrap();
            writeln!(w, "  quic transfer: {} received, {} sent",
                fmt_bytes(peer.l4_rx_bytes), fmt_bytes(peer.l4_tx_bytes)).unwrap();

            for (i, conn) in peer.quic_connections.iter().enumerate() {
                writeln!(w, "  quic connection {}:", i).unwrap();
                writeln!(w, "    endpoint: {}", conn.remote_addr).unwrap();
                writeln!(w, "    local port: {}", conn.local_port).unwrap();
                writeln!(w, "    transfer: {} received, {} sent",
                    fmt_bytes(conn.rx_bytes), fmt_bytes(conn.tx_bytes)).unwrap();
                writeln!(w, "    active streams: {}", conn.active_streams).unwrap();
            }
        }

        writeln!(w).unwrap();
    }
}

pub fn run_cli_stats(socket_path: &str) {
    match send_command(socket_path, &CommandInput::Stats) {
        Ok(json) => {
            match serde_json::from_str::<Vec<UnifiedTelemetry>>(&json) {
                Ok(peers) => print_wg_style(&peers),
                Err(e) => eprintln!("Failed to parse gateway response: {}\nRaw: {}", e, json),
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

pub fn run_cli_dump(socket_path: &str) {
    match send_command(socket_path, &CommandInput::Dump) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error: {}", e),
    }
}

pub fn run_cli_add_peer(socket_path: &str, public_key: String, allowed_ips: Vec<String>, endpoint: Option<String>, proxy_port: Option<u16>) {
    let cmd = CommandInput::AddPeer { public_key, allowed_ips, endpoint, proxy_port };
    match send_command(socket_path, &cmd) {
        Ok(json) => {
            match serde_json::from_str::<ApiResponse>(&json) {
                Ok(resp) => {
                    if resp.status.eq_ignore_ascii_case("ok") {
                        println!("Peer added successfully.");
                    } else {
                        eprintln!("Failed to add peer: {}", resp.message.unwrap_or_default());
                    }
                }
                Err(_) => println!("{}", json),
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

pub fn run_cli_remove_peer(socket_path: &str, public_key: String) {
    let cmd = CommandInput::RemovePeer { public_key };
    match send_command(socket_path, &cmd) {
        Ok(json) => {
            match serde_json::from_str::<ApiResponse>(&json) {
                Ok(resp) => {
                    if resp.status.eq_ignore_ascii_case("ok") {
                        println!("Peer removed successfully.");
                    } else {
                        eprintln!("Failed to remove peer: {}", resp.message.unwrap_or_default());
                    }
                }
                Err(_) => println!("{}", json),
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  new-proxy-cli [--client | --socket <path>] show");
    eprintln!("  new-proxy-cli [--client | --socket <path>] dump");
    eprintln!("  new-proxy-cli [--client | --socket <path>] add-peer <public_key> <allowed_ips> [endpoint] [proxy_port]");
    eprintln!("  new-proxy-cli [--client | --socket <path>] remove-peer <public_key>");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut socket_path = DEFAULT_SERVER_UDS_PATH.to_string();
    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "--client" => {
                socket_path = DEFAULT_CLIENT_UDS_PATH.to_string();
                idx += 1;
            }
            "--socket" => {
                if idx + 1 >= args.len() {
                    print_usage();
                    std::process::exit(2);
                }
                socket_path = args[idx + 1].clone();
                idx += 2;
            }
            _ => break,
        }
    }

    if idx >= args.len() {
        print_usage();
        std::process::exit(2);
    }

    match args[idx].as_str() {
        "show" | "stats" => run_cli_stats(&socket_path),
        "dump" => run_cli_dump(&socket_path),
        "add-peer" => {
            if args.len() < idx + 3 {
                print_usage();
                std::process::exit(2);
            }
            let allowed_ips = args[idx + 2]
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect();
            let endpoint = args.get(idx + 3).cloned();
            let proxy_port = args.get(idx + 4).and_then(|s| s.parse::<u16>().ok());
            run_cli_add_peer(&socket_path, args[idx + 1].clone(), allowed_ips, endpoint, proxy_port);
        }
        "remove-peer" => {
            if args.len() != idx + 2 {
                print_usage();
                std::process::exit(2);
            }
            run_cli_remove_peer(&socket_path, args[idx + 1].clone());
        }
        _ => {
            print_usage();
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_bytes() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1024), "1.00 KiB");
        assert_eq!(fmt_bytes(1536), "1.50 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(fmt_bytes(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn test_fmt_handshake_never() {
        assert_eq!(fmt_handshake_ago(0), "Never");
    }

    #[test]
    fn test_print_wg_style_no_peers() {
        // 不崩溃即可
        print_wg_style(&[]);
    }

    #[test]
    fn test_print_wg_style_peer_no_quic() {
        let peer = UnifiedTelemetry {
            public_key: "AAAA==".to_string(),
            allowed_ips: vec!["10.0.0.2/32".to_string()],
            endpoint: Some("1.2.3.4:51820".to_string()),
            l3_rx_bytes: 1024,
            l3_tx_bytes: 256,
            last_handshake: 0,
            l4_rx_bytes: 0,
            l4_tx_bytes: 0,
            active_streams: 0,
            quic_connections: vec![],
        };
        print_wg_style(&[peer]); // 应打印 L3-only 行
    }

    #[test]
    fn test_print_wg_style_peer_with_quic() {
        let conn = QuicConnSnapshot {
            remote_addr: "10.0.1.1:44363".to_string(),
            local_port: 40001,
            rx_bytes: 3500,
            tx_bytes: 231,
            active_streams: 0,
        };
        let peer = UnifiedTelemetry {
            public_key: "BBBB==".to_string(),
            allowed_ips: vec!["10.0.0.2/32".to_string()],
            endpoint: None,
            l3_rx_bytes: 3480,
            l3_tx_bytes: 256,
            last_handshake: 0,
            l4_rx_bytes: 3500,
            l4_tx_bytes: 231,
            active_streams: 0,
            quic_connections: vec![conn],
        };
        print_wg_style(&[peer]);
    }

    #[test]
    fn test_cli_uds_commands() {
        use std::os::unix::net::UnixListener;
        use std::io::{Read, Write};
        use std::thread;

        let uds_path = "/tmp/test_uds_cli.sock";
        let _ = std::fs::remove_file(uds_path);

        let listener = UnixListener::bind(uds_path).unwrap();

        // 启动一个 mock 的后台 UDS 服务端，使用标准线程，专门接收和响应 CLI 指令
        let handle = thread::spawn(move || {
            for _ in 0..4 {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf) {
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        
                        if req_str.contains("Stats") {
                            let mock_telemetry = vec![UnifiedTelemetry {
                                public_key: "09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=".to_string(),
                                allowed_ips: vec!["10.0.0.2/32".to_string()],
                                endpoint: Some("1.2.3.4:51820".to_string()),
                                l3_rx_bytes: 100,
                                l3_tx_bytes: 200,
                                last_handshake: 0,
                                l4_rx_bytes: 300,
                                l4_tx_bytes: 400,
                                active_streams: 0,
                                quic_connections: vec![],
                            }];
                            let resp = serde_json::to_vec(&mock_telemetry).unwrap();
                            let _ = stream.write_all(&resp);
                        } else if req_str.contains("Dump") {
                            let _ = stream.write_all(b"mock_dump_line\n");
                        } else if req_str.contains("AddPeer") || req_str.contains("RemovePeer") {
                            let api_resp = ApiResponse {
                                status: "ok".to_string(),
                                message: None,
                            };
                            let resp = serde_json::to_vec(&api_resp).unwrap();
                            let _ = stream.write_all(&resp);
                        }
                    }
                }
            }
        });

        // 给服务端绑定启动的时间
        thread::sleep(std::time::Duration::from_millis(100));

        // 验证 run_cli_stats
        run_cli_stats(uds_path);

        // 验证 run_cli_dump
        run_cli_dump(uds_path);

        // 验证 run_cli_add_peer
        run_cli_add_peer(
            uds_path,
            "09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=".to_string(),
            vec!["10.0.0.99/32".to_string()],
            None,
            None,
        );

        // 验证 run_cli_remove_peer
        run_cli_remove_peer(
            uds_path,
            "09oeT4J/+NVN39aRL+CNd+N4J8t0vvW2Wc2DLAE5XS4=".to_string(),
        );

        let _ = handle.join();
        let _ = std::fs::remove_file(uds_path);
    }
}
