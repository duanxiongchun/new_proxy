use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Tcp = 1,
    Udp = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyTargetHeader {
    pub protocol: ProxyProtocol,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl ProxyTargetHeader {
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_u8(1).await?; // version
        w.write_u8(self.protocol as u8).await?; // protocol type
        match self.dst_ip {
            IpAddr::V4(ipv4) => {
                w.write_u8(0).await?; // address family
                w.write_all(&ipv4.octets()).await?;
            }
            IpAddr::V6(ipv6) => {
                w.write_u8(1).await?; // address family
                w.write_all(&ipv6.octets()).await?;
            }
        }
        w.write_u16(self.dst_port).await?;
        Ok(())
    }

    pub async fn read_from<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Self> {
        let version = r.read_u8().await?;
        if version != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported proxy protocol version",
            ));
        }
        let protocol = match r.read_u8().await? {
            1 => ProxyProtocol::Tcp,
            2 => ProxyProtocol::Udp,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid protocol type",
                ))
            }
        };
        let addr_type = r.read_u8().await?;
        let dst_ip = match addr_type {
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
        let dst_port = r.read_u16().await?;
        Ok(Self {
            protocol,
            dst_ip,
            dst_port,
        })
    }
}

pub async fn write_target_addr<W: AsyncWrite + Unpin>(
    w: &mut W,
    addr: SocketAddr,
) -> std::io::Result<()> {
    let header = ProxyTargetHeader {
        protocol: ProxyProtocol::Tcp,
        dst_ip: addr.ip(),
        dst_port: addr.port(),
    };
    header.write_to(w).await
}

#[allow(dead_code)]
pub async fn read_target_addr<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<SocketAddr> {
    let header = ProxyTargetHeader::read_from(r).await?;
    Ok(SocketAddr::new(header.dst_ip, header.dst_port))
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
        let mut reader = Cursor::new(vec![1, 1, 1, 2, 3]);
        let err = read_target_addr(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn test_udp_target_header_serialization() {
        let header = ProxyTargetHeader {
            protocol: ProxyProtocol::Udp,
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            dst_port: 53,
        };
        let mut buf = Vec::new();
        header.write_to(&mut buf).await.unwrap();

        let mut reader = Cursor::new(buf);
        let parsed = ProxyTargetHeader::read_from(&mut reader).await.unwrap();
        assert_eq!(parsed.protocol, ProxyProtocol::Udp);
        assert_eq!(parsed.dst_ip, header.dst_ip);
        assert_eq!(parsed.dst_port, header.dst_port);
    }
}
