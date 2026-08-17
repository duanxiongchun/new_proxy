use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub struct IoWakeup {
    fd: RawFd,
    pending: AtomicBool,
}

impl IoWakeup {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self {
                fd,
                pending: AtomicBool::new(false),
            })
        }
    }

    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn notify(&self) -> io::Result<bool> {
        if self.pending.swap(true, Ordering::AcqRel) {
            return Ok(false);
        }
        let value = 1u64.to_ne_bytes();
        let written = unsafe { libc::write(self.fd, value.as_ptr().cast(), value.len()) };
        if written == value.len() as isize {
            Ok(true)
        } else if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                self.pending.store(false, Ordering::Release);
                Err(error)
            }
        } else {
            self.pending.store(false, Ordering::Release);
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short eventfd write",
            ))
        }
    }

    pub fn clear_pending(&self) {
        self.pending.store(false, Ordering::Release);
    }

    pub fn drain(&self) -> io::Result<()> {
        let mut value = 0u64;
        let read = unsafe {
            libc::read(
                self.fd,
                (&mut value as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if read == std::mem::size_of::<u64>() as isize {
            Ok(())
        } else if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                Ok(())
            } else {
                Err(error)
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short eventfd read",
            ))
        }
    }
}

impl Drop for IoWakeup {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn readable(fd: RawFd) -> bool {
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        assert!(result >= 0, "poll failed: {}", io::Error::last_os_error());
        result == 1 && descriptor.revents & libc::POLLIN != 0
    }

    #[test]
    fn v1_unit_io_wakeup_becomes_readable_until_drained() {
        let wakeup = IoWakeup::new().unwrap();
        assert!(!readable(wakeup.fd()));

        assert!(wakeup.notify().unwrap());
        assert!(readable(wakeup.fd()));

        wakeup.drain().unwrap();
        assert!(!readable(wakeup.fd()));
    }

    #[test]
    fn v1_unit_io_wakeup_coalesces_multiple_signals() {
        let wakeup = IoWakeup::new().unwrap();

        assert!(wakeup.notify().unwrap());
        assert!(!wakeup.notify().unwrap());
        wakeup.drain().unwrap();

        assert!(!readable(wakeup.fd()));
        assert!(!wakeup.notify().unwrap());
        wakeup.clear_pending();
        assert!(wakeup.notify().unwrap());
    }
}
