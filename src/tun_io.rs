use std::io;
use std::os::unix::io::RawFd;
use tokio::io::unix::AsyncFd;

pub struct AsyncTunIo {
    fd: AsyncFd<RawFd>,
}

impl AsyncTunIo {
    pub fn new(fd: RawFd) -> io::Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(fd)?,
        })
    }

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = *self.fd.get_ref();
            match unsafe {
                libc::read(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            } {
                r if r >= 0 => {
                    guard.retain_ready();
                    return Ok(r as usize);
                }
                _ => {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Err(err);
                }
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            let fd = *self.fd.get_ref();
            match unsafe {
                libc::write(
                    fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                )
            } {
                r if r >= 0 => {
                    guard.retain_ready();
                    return Ok(r as usize);
                }
                _ => {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Err(err);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_async_tun_io() {
        use std::os::unix::io::AsRawFd;
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
        sock1.set_nonblocking(true).unwrap();
        sock2.set_nonblocking(true).unwrap();

        let fd1 = sock1.as_raw_fd();
        let tun_io = AsyncTunIo::new(fd1).unwrap();

        let packet = vec![1, 2, 3, 4];
        let mut writer = sock2.try_clone().unwrap();
        std::io::Write::write_all(&mut writer, &packet).unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tun_io.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &packet[..]);
        
        // Let's also verify write
        tun_io.write(&packet).await.unwrap();
        let mut reader = sock2;
        let mut read_buf = vec![0u8; 4];
        std::io::Read::read_exact(&mut reader, &mut read_buf).unwrap();
        assert_eq!(read_buf, packet);
    }
}
