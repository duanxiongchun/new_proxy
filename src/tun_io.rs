use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;

pub struct AsyncTunIo {
    fd: AsyncFd<OwnedFd>,
}

impl AsyncTunIo {
    pub fn new(fd: RawFd) -> io::Result<Self> {
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd: AsyncFd::new(owned_fd)?,
        })
    }

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } {
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

    pub fn try_read(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.fd.try_io(tokio::io::Interest::READABLE, |_ready| {
            let fd = self.fd.get_ref().as_raw_fd();
            match unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } {
                r if r >= 0 => Ok(r as usize),
                _ => Err(io::Error::last_os_error()),
            }
        }) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            let fd = self.fd.get_ref().as_raw_fd();
            match unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) } {
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

    pub async fn writable(&self) -> io::Result<()> {
        let _guard = self.fd.writable().await?;
        Ok(())
    }

    pub async fn write_packet(&self, buf: &[u8]) -> io::Result<()> {
        let written = self.write(buf).await?;
        if written == buf.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short packet write: wrote {} of {} bytes",
                    written,
                    buf.len()
                ),
            ))
        }
    }

    pub fn try_write_packet(&self, buf: &[u8]) -> io::Result<()> {
        let fd = self.fd.get_ref().as_raw_fd();
        match unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) } {
            r if r >= 0 && r as usize == buf.len() => Ok(()),
            r if r >= 0 => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short packet write: wrote {} of {} bytes", r, buf.len()),
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_async_tun_io() {
        use std::os::unix::io::IntoRawFd;
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair().unwrap();
        sock1.set_nonblocking(true).unwrap();
        sock2.set_nonblocking(true).unwrap();

        let fd1 = sock1.try_clone().unwrap().into_raw_fd();
        let tun_io = AsyncTunIo::new(fd1).unwrap();

        let packet = vec![1, 2, 3, 4];
        let mut writer = sock2.try_clone().unwrap();
        std::io::Write::write_all(&mut writer, &packet).unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tun_io.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &packet[..]);

        // Let's also verify write
        tun_io.write_packet(&packet).await.unwrap();
        let mut reader = sock2;
        let mut read_buf = vec![0u8; 4];
        std::io::Read::read_exact(&mut reader, &mut read_buf).unwrap();
        assert_eq!(read_buf, packet);
    }
}
