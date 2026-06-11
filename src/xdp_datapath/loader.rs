use std::io;

#[cfg(target_os = "linux")]
pub struct BpfLinkManager {
    #[allow(dead_code)]
    ifindex: u32,
    interface: String,
    mode: String,
}

#[cfg(not(target_os = "linux"))]
pub struct BpfLinkManager;

#[cfg(target_os = "linux")]
impl BpfLinkManager {
    pub fn new(interface: &str, mode: &str) -> Result<Self, io::Error> {
        use std::ffi::CString;
        use std::process::Command;

        let c_interface =
            CString::new(interface).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }

        // Create BPF directories
        #[cfg(not(test))]
        {
            let status = Command::new("mkdir")
                .args(["-p", &format!("/sys/fs/bpf/new_proxy_{}/maps", interface)])
                .status()?;
            if !status.success() {
                log::warn!(
                    "Failed to create BPF maps directory for interface {}",
                    interface
                );
            }
        }

        let manager = Self {
            ifindex,
            interface: interface.to_string(),
            mode: mode.to_string(),
        };

        let cmds = manager.build_load_commands();
        #[cfg(not(test))]
        for cmd in cmds {
            let status = Command::new("sh").arg("-c").arg(&cmd).status()?;
            if !status.success() {
                log::warn!("Command failed: {}", cmd);
            }
        }

        Ok(manager)
    }

    pub fn build_load_commands(&self) -> Vec<String> {
        let attach_type = if self.mode == "native" {
            "xdp"
        } else {
            "xdpgeneric"
        };
        vec![
            format!(
                "bpftool prog loadall src/xdp_datapath/xdp_filter.o /sys/fs/bpf/new_proxy_{}/ pinmaps /sys/fs/bpf/new_proxy_{}/maps/",
                self.interface, self.interface
            ),
            format!(
                "bpftool net attach {} pinned /sys/fs/bpf/new_proxy_{}/xdp_filter_prog dev {}",
                attach_type, self.interface, self.interface
            ),
        ]
    }
}

#[cfg(target_os = "linux")]
impl Drop for BpfLinkManager {
    fn drop(&mut self) {
        #[cfg(not(test))]
        {
            use std::process::Command;
            let attach_type = if self.mode == "native" {
                "xdp"
            } else {
                "xdpgeneric"
            };

            // Detach XDP program from interface
            let status = Command::new("bpftool")
                .args(["net", "detach", attach_type, "dev", &self.interface])
                .status();
            match status {
                Ok(s) if s.success() => {
                    log::info!(
                        "Successfully detached XDP program from interface {}",
                        self.interface
                    );
                }
                other => {
                    log::warn!(
                        "Failed to detach XDP program from interface {}: {:?}",
                        self.interface,
                        other
                    );
                }
            }

            // Remove pinned BPF directory
            let path = format!("/sys/fs/bpf/new_proxy_{}", self.interface);
            let status = Command::new("rm").args(["-rf", &path]).status();
            match status {
                Ok(s) if s.success() => {
                    log::info!("Successfully removed pinned BPF directory {}", path);
                }
                other => {
                    log::warn!(
                        "Failed to remove pinned BPF directory {}: {:?}",
                        path,
                        other
                    );
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl BpfLinkManager {
    pub fn new(_interface: &str, _mode: &str) -> Result<Self, io::Error> {
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
        let manager = BpfLinkManager::new("invalid_interface_nonexistent", "native");
        assert!(manager.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_bpf_load_commands() {
        let manager = BpfLinkManager::new("lo", "native").unwrap();
        let cmds = manager.build_load_commands();
        assert!(cmds[0].contains("bpftool prog loadall"));
        assert!(cmds[1].contains("bpftool net attach"));
    }
}
