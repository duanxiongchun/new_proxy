use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum CommandInput {
    Stats,
    Dump,
    AddPeer {
        public_key: String,
        allowed_ips: Vec<String>,
        endpoint: Option<String>,
        proxy_port: Option<u16>,
    },
    RemovePeer {
        public_key: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse {
    pub status: String,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct UdsRequest {
    pub command: CommandInput,
    pub framed: bool,
}

pub async fn read_uds_command(stream: &mut tokio::net::UnixStream) -> Result<UdsRequest, String> {
    const MAX_UDS_PAYLOAD: usize = 65536;
    const UDS_READ_TIMEOUT: Duration = Duration::from_secs(2);

    let first = timeout(UDS_READ_TIMEOUT, stream.read_u8())
        .await
        .map_err(|_| "UDS request read timeout".to_string())?
        .map_err(|e| format!("UDS request read error: {}", e))?;

    let mut buf = Vec::new();
    let framed = first != b'{';
    if !framed {
        buf.push(first);
        let mut temp = [0u8; 1024];
        timeout(UDS_READ_TIMEOUT, async {
            loop {
                match stream.read(&mut temp).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&temp[..n]);
                        if buf.len() > MAX_UDS_PAYLOAD {
                            return Err("UDS request payload too large".to_string());
                        }
                    }
                    Err(e) => return Err(format!("UDS request read error: {}", e)),
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| "UDS request read timeout".to_string())??;
    } else {
        let mut len_bytes = [0u8; 4];
        len_bytes[0] = first;
        timeout(UDS_READ_TIMEOUT, stream.read_exact(&mut len_bytes[1..]))
            .await
            .map_err(|_| "UDS request length read timeout".to_string())?
            .map_err(|e| format!("UDS request length read error: {}", e))?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len == 0 || len > MAX_UDS_PAYLOAD {
            return Err(format!("Invalid UDS request payload length: {}", len));
        }
        buf.resize(len, 0);
        timeout(UDS_READ_TIMEOUT, stream.read_exact(&mut buf))
            .await
            .map_err(|_| "UDS request payload read timeout".to_string())?
            .map_err(|e| format!("UDS request payload read error: {}", e))?;
    }

    serde_json::from_slice(&buf)
        .map(|command| UdsRequest { command, framed })
        .map_err(|e| format!("Invalid request JSON: {}", e))
}

pub async fn write_uds_json<T: Serialize>(
    stream: &mut tokio::net::UnixStream,
    value: &T,
    framed: bool,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    write_uds_payload(stream, &payload, framed).await
}

pub async fn write_uds_payload(
    stream: &mut tokio::net::UnixStream,
    payload: &[u8],
    framed: bool,
) -> std::io::Result<()> {
    if framed {
        stream.write_u32(payload.len() as u32).await?;
    }
    stream.write_all(payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn test_uds_raw_request_gets_raw_response() {
        let test_uds_path = "/tmp/test_uds_raw_compat.sock";
        let _ = fs::remove_file(test_uds_path);
        let listener = UnixListener::bind(test_uds_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_uds_command(&mut stream).await.unwrap();
            assert!(!request.framed);
            match request.command {
                CommandInput::Stats => {}
                _ => panic!("unexpected command"),
            }
            let resp = ApiResponse {
                status: "Ok".to_string(),
                message: None,
            };
            write_uds_json(&mut stream, &resp, request.framed)
                .await
                .unwrap();
        });

        let mut client = tokio::net::UnixStream::connect(test_uds_path)
            .await
            .unwrap();
        let cmd = serde_json::to_vec(&CommandInput::Stats).unwrap();
        client.write_all(&cmd).await.unwrap();
        client.shutdown().await.unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp.first(), Some(&b'{'));
        let api_resp: ApiResponse = serde_json::from_slice(&resp).unwrap();
        assert_eq!(api_resp.status, "Ok");

        server.await.unwrap();
        let _ = fs::remove_file(test_uds_path);
    }

    #[tokio::test]
    async fn test_uds_framed_request_gets_framed_response() {
        let test_uds_path = "/tmp/test_uds_framed_compat.sock";
        let _ = fs::remove_file(test_uds_path);
        let listener = UnixListener::bind(test_uds_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_uds_command(&mut stream).await.unwrap();
            assert!(request.framed);
            match request.command {
                CommandInput::Stats => {}
                _ => panic!("unexpected command"),
            }
            let resp = ApiResponse {
                status: "Ok".to_string(),
                message: Some("framed".to_string()),
            };
            write_uds_json(&mut stream, &resp, request.framed)
                .await
                .unwrap();
        });

        let mut client = tokio::net::UnixStream::connect(test_uds_path)
            .await
            .unwrap();
        let cmd = serde_json::to_vec(&CommandInput::Stats).unwrap();
        client.write_u32(cmd.len() as u32).await.unwrap();
        client.write_all(&cmd).await.unwrap();
        client.shutdown().await.unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let len = u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
        assert_eq!(len, resp.len() - 4);
        let api_resp: ApiResponse = serde_json::from_slice(&resp[4..]).unwrap();
        assert_eq!(api_resp.status, "Ok");
        assert_eq!(api_resp.message.as_deref(), Some("framed"));

        server.await.unwrap();
        let _ = fs::remove_file(test_uds_path);
    }

    #[tokio::test]
    async fn test_uds_rejects_invalid_framed_length() {
        let test_uds_path = "/tmp/test_uds_bad_len.sock";
        let _ = fs::remove_file(test_uds_path);
        let listener = UnixListener::bind(test_uds_path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let err = read_uds_command(&mut stream).await.unwrap_err();
            assert!(err.contains("Invalid UDS request payload length"));
        });

        let mut client = tokio::net::UnixStream::connect(test_uds_path)
            .await
            .unwrap();
        client.write_u32(0).await.unwrap();
        client.shutdown().await.unwrap();

        server.await.unwrap();
        let _ = fs::remove_file(test_uds_path);
    }
}
