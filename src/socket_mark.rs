#[cfg(all(target_os = "linux", not(test), not(tarpaulin)))]
use std::os::fd::AsRawFd;

pub const OUTER_SOCKET_MARK: u32 = 0x6e70;
pub const ROUTING_TABLE: u32 = 0x6e70;
pub const MAIN_SUPPRESS_RULE_PRIORITY: u32 = 9999;
pub const ROUTING_RULE_PRIORITY: u32 = 10000;

#[cfg(all(target_os = "linux", not(test), not(tarpaulin)))]
pub fn set_outer_mark(socket: &std::net::UdpSocket) -> Result<(), String> {
    set_fd_mark(socket.as_raw_fd(), OUTER_SOCKET_MARK)
}

#[cfg(all(target_os = "linux", not(test), not(tarpaulin)))]
pub fn set_socket2_outer_mark(socket: &socket2::Socket) -> Result<(), String> {
    set_fd_mark(socket.as_raw_fd(), OUTER_SOCKET_MARK)
}

#[cfg(all(target_os = "linux", not(test), not(tarpaulin)))]
fn set_fd_mark(fd: std::os::fd::RawFd, mark: u32) -> Result<(), String> {
    let value = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to set SO_MARK {} on outer UDP socket: {}",
            mark,
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(any(not(target_os = "linux"), test, tarpaulin))]
pub fn set_outer_mark(_socket: &std::net::UdpSocket) -> Result<(), String> {
    Ok(())
}

#[cfg(any(not(target_os = "linux"), test, tarpaulin))]
pub fn set_socket2_outer_mark(_socket: &socket2::Socket) -> Result<(), String> {
    Ok(())
}
