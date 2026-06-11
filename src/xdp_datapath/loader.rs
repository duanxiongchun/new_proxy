use std::io;

#[cfg(target_os = "linux")]
pub struct BpfLinkManager {
    #[allow(dead_code)]
    ifindex: u32,
    interface: String,
}

#[cfg(not(target_os = "linux"))]
pub struct BpfLinkManager;

#[cfg(target_os = "linux")]
impl BpfLinkManager {
    pub fn new(interface: &str) -> Result<Self, io::Error> {
        use std::ffi::CString;
        use std::process::Command;

        let c_interface = CString::new(interface)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }

        // Create BPF directories
        let status = Command::new("mkdir")
            .args(&["-p", &format!("/sys/fs/bpf/new_proxy_{}/maps", interface)])
            .status()?;
        if !status.success() {
            log::warn!("Failed to create BPF maps directory for interface {}", interface);
        }

        let manager = Self {
            ifindex,
            interface: interface.to_string(),
        };

        let cmds = manager.build_load_commands();
        for cmd in cmds {
            let status = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .status()?;
            if !status.success() {
                log::warn!("Command failed: {}", cmd);
            }
        }

        Ok(manager)
    }

    pub fn build_load_commands(&self) -> Vec<String> {
        vec![
            format!(
                "bpftool prog loadall src/xdp_datapath/xdp_filter.o /sys/fs/bpf/new_proxy_{}/ pinmaps /sys/fs/bpf/new_proxy_{}/maps/",
                self.interface, self.interface
            ),
            format!(
                "bpftool net attach xdpgeneric pinned /sys/fs/bpf/new_proxy_{}/xdp_filter dev {}",
                self.interface, self.interface
            ),
        ]
    }
}

#[cfg(not(target_os = "linux"))]
impl BpfLinkManager {
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

    #[test]
    #[cfg(target_os = "linux")]
    fn test_bpf_load_commands() {
        let manager = BpfLinkManager::new("lo").unwrap();
        let cmds = manager.build_load_commands();
        assert!(cmds[0].contains("bpftool prog loadall"));
        assert!(cmds[1].contains("bpftool net attach"));
    }
}
