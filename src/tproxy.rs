use std::net::{TcpListener as StdTcpListener, SocketAddr};
use tokio::net::TcpListener as TokioTcpListener;
use socket2::{Socket, Domain, Type, Protocol};

#[cfg(target_os = "linux")]
use libc;

// 创建支持 TPROXY (IP_TRANSPARENT) 的透明代理套接字监听器
// 采用自适应优雅降级设计：当检测到无 CAP_NET_ADMIN 权限或非 Linux 系统时，降级为普通 TCP 监听器
pub fn create_tproxy_listener(addr: SocketAddr) -> Result<TokioTcpListener, String> {
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| format!("Failed to create socket: {}", e))?;

    socket.set_reuse_address(true)
        .map_err(|e| format!("Failed to set SO_REUSEADDR: {}", e))?;

    #[cfg(target_os = "linux")]
    {
        // 尝试通过 raw setsockopt 设置 IP_TRANSPARENT / IPV6_TRANSPARENT
        let (level, optname) = if addr.is_ipv6() {
            (libc::SOL_IPV6, libc::IPV6_TRANSPARENT)
        } else {
            (libc::SOL_IP, libc::IP_TRANSPARENT)
        };
        unsafe {
            let optval: libc::c_int = 1;
            let ret = libc::setsockopt(
                std::os::unix::io::AsRawFd::as_raw_fd(&socket),
                level,
                optname,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
            if ret == 0 {
                log::info!("Successfully set IP_TRANSPARENT/IPV6_TRANSPARENT socket option for TPROXY on {}", addr);
            } else {
                let err = std::io::Error::last_os_error();
                log::warn!("Failed to set IP_TRANSPARENT/IPV6_TRANSPARENT socket option for TPROXY on {}: {}. Falling back to standard listener.", addr, err);
            }
        }
    }

    // IPv4/IPv6 使用独立监听器；IPv6 listener 设为 v6-only，避免占用 IPv4 端口。
    if addr.is_ipv6() {
        if let Err(e) = socket.set_only_v6(true) {
            log::warn!("Failed to set IPV6_V6ONLY = true: {}", e);
        }
    }

    // 绑定物理端口与开启 TCP 监听
    socket.bind(&addr.into())
        .map_err(|e| format!("Failed to bind TPROXY socket to {}: {}", addr, e))?;

    socket.listen(1024)
        .map_err(|e| format!("Failed to listen on TPROXY socket: {}", e))?;

    let std_listener: StdTcpListener = socket.into();
    std_listener.set_nonblocking(true)
        .map_err(|e| format!("Failed to set non-blocking on std TCP listener: {}", e))?;

    TokioTcpListener::from_std(std_listener)
        .map_err(|e| format!("Failed to convert to Tokio TcpListener: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_tproxy_listener_ipv4() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let res = create_tproxy_listener(addr);
        assert!(res.is_ok());
        let listener = res.unwrap();
        assert!(listener.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_create_tproxy_listener_ipv6() {
        let addr = "[::1]:0".parse().unwrap();
        let res = create_tproxy_listener(addr);
        assert!(res.is_ok());
        let listener = res.unwrap();
        assert!(listener.local_addr().is_ok());
    }
}
