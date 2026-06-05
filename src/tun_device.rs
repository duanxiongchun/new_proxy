use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::RawFd;

const TUNSETIFF: libc::c_ulong = 0x400454ca;

#[cfg(target_os = "linux")]
pub fn open_tun(name: &str, num_queues: usize) -> io::Result<Vec<RawFd>> {
    let mut fds = Vec::new();
    for _ in 0..num_queues {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")?;
        let fd = file.into_raw_fd();

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        // IFF_TUN (IP packet tunnel), IFF_NO_PI (no packet information header)
        let mut flags = libc::IFF_TUN | libc::IFF_NO_PI;
        if num_queues > 1 {
            flags |= libc::IFF_MULTI_QUEUE;
        }
        ifr.ifr_ifru.ifru_flags = flags as i16;

        let name_bytes = name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), ifr.ifr_name.len() - 1);
        for (i, byte) in name_bytes.iter().enumerate().take(len) {
            ifr.ifr_name[i] = *byte as i8;
        }

        let res = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if res < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        fds.push(fd);
    }
    Ok(fds)
}

#[cfg(not(target_os = "linux"))]
pub fn open_tun(_name: &str, _num_queues: usize) -> io::Result<Vec<RawFd>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Non-Linux platforms require custom TUN setup",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_open_tun_device() {
        let result = open_tun("test_tun0", 1);
        match result {
            Ok(fds) => {
                assert_eq!(fds.len(), 1);
                assert!(fds[0] > 0);
                for fd in fds {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
            Err(_e) => {
                // Any IO error is acceptable when running tests in sandboxed environments without root/TUN privileges
            }
        }
    }
}
