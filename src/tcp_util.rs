use std::time::Duration;

pub fn set_tcp_keepalive(socket: &tokio::net::TcpStream) -> std::io::Result<()> {
    let socket_ref = socket2::SockRef::from(socket);
    let mut keepalive = socket2::TcpKeepalive::new();
    keepalive = keepalive.with_time(Duration::from_secs(60));
    keepalive = keepalive.with_interval(Duration::from_secs(10));
    socket_ref.set_tcp_keepalive(&keepalive)?;
    Ok(())
}
