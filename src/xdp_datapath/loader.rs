use std::io;

#[cfg(target_os = "linux")]
pub struct BpfLinkManager {
    #[allow(dead_code)]
    ifindex: u32,
}

#[cfg(not(target_os = "linux"))]
pub struct BpfLinkManager;

impl BpfLinkManager {
    #[cfg(target_os = "linux")]
    pub fn new(interface: &str) -> Result<Self, io::Error> {
        use std::ffi::CString;
        let c_interface = CString::new(interface)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { ifindex })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new(_interface: &str) -> Result<Self, io::Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "BpfLinkManager is only supported on Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_fail_on_invalid_dev() {
        let manager = BpfLinkManager::new("invalid_interface_nonexistent");
        assert!(manager.is_err());
    }
}
