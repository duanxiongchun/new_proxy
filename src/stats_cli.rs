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

    let body = if buf.len() >= 4 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len == buf.len().saturating_sub(4) {
            &buf[4..]
        } else {
            &buf[..]
        }
    } else {
        &buf[..]
    };

    let stats: Vec<UnifiedTelemetry> =
        serde_json::from_slice(body).map_err(|e| format!("Failed to parse JSON stats: {}", e))?;

    println!("\n+-------------------------------------------------------------------------------------------------------------------------------------------+");
    println!("|                                             HYBRID SECURE PROXY GATEWAY TELEMETRY                                                         |");
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");
    println!(
        "| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |",
        "Peer Public Key",
        "Source",
        "L3 Transfer (RX/TX)",
        "L4 Transfer (RX/TX)",
        "Handshake (ago)",
        "Active Strm"
    );
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

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

        println!(
            "| {:<44} | {:<8} | {:<20} | {:<20} | {:<20} | {:<12} |",
            s.public_key, s.source, l3_str, l4_str, handshake_str, s.active_streams
        );
    }
    println!("+-------------------------------------------------------------------------------------------------------------------------------------------+");
    Ok(())
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

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }
}
