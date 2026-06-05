use std::time::Duration;

pub fn set_tcp_keepalive(socket: &tokio::net::TcpStream) -> std::io::Result<()> {
    let socket_ref = socket2::SockRef::from(socket);
    let mut keepalive = socket2::TcpKeepalive::new();
    keepalive = keepalive.with_time(Duration::from_secs(60));
    keepalive = keepalive.with_interval(Duration::from_secs(10));
    socket_ref.set_tcp_keepalive(&keepalive)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_tcp_keepalive_accepts_connected_tcp_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move { listener.accept().await.unwrap().0 });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server = accept_task.await.unwrap();

        set_tcp_keepalive(&client).unwrap();
        set_tcp_keepalive(&server).unwrap();
    }
}
