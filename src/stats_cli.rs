use crate::api::CommandInput;
use crate::app_config::api_socket_path;
use crate::telemetry::UnifiedTelemetry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn run_cli_stats() -> Result<(), String> {
    let socket_path =
        std::env::var("NEW_PROXY_API_SOCKET").unwrap_or_else(|_| api_socket_path("tun0"));
    let mut stream = tokio::net::UnixStream::connect(&socket_path)
        .await
        .map_err(|e| {
            format!(
                "Cannot connect to gateway API socket. Gateway not running? Error: {}",
                e
            )
        })?;

    let cmd = CommandInput::Stats;
    let json_bytes = serde_json::to_vec(&cmd).unwrap();
    stream
        .write_u32(json_bytes.len() as u32)
        .await
        .map_err(|e| format!("Failed to write stats request length: {}", e))?;
    stream
        .write_all(&json_bytes)
        .await
        .map_err(|e| format!("Failed to write stats request: {}", e))?;
    let _ = stream.shutdown().await;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("Failed to read stats from socket: {}", e))?;

    let stats = parse_stats_payload(&buf)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    print!("{}", format_stats_table(&stats, now));
    Ok(())
}

fn parse_stats_payload(buf: &[u8]) -> Result<Vec<UnifiedTelemetry>, String> {
    let body = if buf.len() >= 4 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len == buf.len().saturating_sub(4) {
            &buf[4..]
        } else {
            buf
        }
    } else {
        buf
    };

    serde_json::from_slice(body).map_err(|e| format!("Failed to parse JSON stats: {}", e))
}

fn format_stats_table(stats: &[UnifiedTelemetry], now: u64) -> String {
    let mut out = String::new();
    out.push_str("\n+-------------------------------------------------------------------------------------------------------------------------------------------+\n");
    out.push_str("|                                             HYBRID SECURE PROXY GATEWAY TELEMETRY                                                         |\n");
    out.push_str("+-------------------------------------------------------------------------------------------------------------------------------------------+\n");
    out.push_str(&format!(
        "| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |\n",
        "Peer Public Key",
        "Source",
        "L3 Transfer (RX/TX)",
        "L4 Transfer (RX/TX)",
        "Handshake (ago)",
        "Active Strm"
    ));
    out.push_str("+-------------------------------------------------------------------------------------------------------------------------------------------+\n");

    for s in stats {
        let l3_str = format!(
            "{}/{}",
            format_bytes(s.l3_rx_bytes),
            format_bytes(s.l3_tx_bytes)
        );
        let l4_str = format!(
            "{}/{}",
            format_bytes(s.l4_rx_bytes),
            format_bytes(s.l4_tx_bytes)
        );
        let handshake_str = if s.last_handshake == 0 {
            "never".to_string()
        } else if now > s.last_handshake {
            format!("{}s", now - s.last_handshake)
        } else {
            "0s".to_string()
        };

        out.push_str(&format!(
            "| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |\n",
            s.public_key, s.source, l3_str, l4_str, handshake_str, s.active_streams
        ));
    }
    out.push_str("+-------------------------------------------------------------------------------------------------------------------------------------------+\n");
    out
}

pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn telemetry(last_handshake: u64) -> UnifiedTelemetry {
        UnifiedTelemetry {
            public_key: "peer-key".to_string(),
            allowed_ips: vec!["10.0.0.2/32".to_string()],
            endpoint: Some("1.2.3.4:51820".to_string()),
            l3_rx_bytes: 1024,
            l3_tx_bytes: 2048,
            l3_unknown_handshake_drops: 0,
            last_handshake,
            l4_rx_bytes: 3 * 1024 * 1024,
            l4_tx_bytes: 4 * 1024 * 1024,
            active_streams: 2,
            quic_connections: Vec::new(),
            source: "both".to_string(),
        }
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn parse_stats_payload_accepts_raw_and_framed_json() {
        let payload = serde_json::to_vec(&vec![telemetry(0)]).unwrap();
        assert_eq!(parse_stats_payload(&payload).unwrap().len(), 1);

        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(&payload);
        assert_eq!(parse_stats_payload(&framed).unwrap().len(), 1);
    }

    #[test]
    fn parse_stats_payload_falls_back_to_raw_when_length_prefix_does_not_match() {
        let payload = serde_json::to_vec(&vec![telemetry(0)]).unwrap();
        let parsed = parse_stats_payload(&payload).unwrap();
        assert_eq!(parsed[0].public_key, "peer-key");
    }

    #[test]
    fn format_stats_table_renders_never_past_and_future_handshakes() {
        let table = format_stats_table(&[telemetry(0), telemetry(90), telemetry(120)], 100);

        assert!(table.contains("peer-key"));
        assert!(table.contains("1.00 KB/2.00 KB"));
        assert!(table.contains("3.00 MB/4.00 MB"));
        assert!(table.contains("never"));
        assert!(table.contains("10s"));
        assert!(table.contains("0s"));
    }
}
