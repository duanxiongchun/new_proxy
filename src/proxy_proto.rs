use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn write_target_addr<W: AsyncWrite + Unpin>(
    w: &mut W,
    addr: SocketAddr,
) -> std::io::Result<()> {
    match addr.ip() {
        IpAddr::V4(ipv4) => {
            w.write_all(&[0]).await?;
            w.write_all(&ipv4.octets()).await?;
        }
        IpAddr::V6(ipv6) => {
            w.write_all(&[1]).await?;
            w.write_all(&ipv6.octets()).await?;
        }
    }
    w.write_u16(addr.port()).await?;
    Ok(())
}

pub async fn read_target_addr<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<SocketAddr> {
    let addr_type = r.read_u8().await?;
    let ip = match addr_type {
        0 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        1 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid address type",
            ))
        }
    };
    let port = r.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_target_addr_codec_ipv4() {
        let addr = "1.2.3.4:12345".parse::<SocketAddr>().unwrap();
        let mut buf = Vec::new();
        write_target_addr(&mut buf, addr).await.unwrap();

        let mut reader = Cursor::new(buf);
        let decoded_addr = read_target_addr(&mut reader).await.unwrap();
        assert_eq!(addr, decoded_addr);
    }

    #[tokio::test]
    async fn test_target_addr_codec_ipv6() {
        let addr = "[2001:db8::1]:12345".parse::<SocketAddr>().unwrap();
        let mut buf = Vec::new();
        write_target_addr(&mut buf, addr).await.unwrap();

        let mut reader = Cursor::new(buf);
        let decoded_addr = read_target_addr(&mut reader).await.unwrap();
        assert_eq!(addr, decoded_addr);
    }

    #[tokio::test]
    async fn read_target_addr_rejects_unknown_address_type() {
        let mut reader = Cursor::new(vec![9, 0, 0]);
        let err = read_target_addr(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_target_addr_rejects_truncated_ipv6_address() {
        let mut reader = Cursor::new(vec![1, 0, 1, 2, 3]);
        let err = read_target_addr(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
