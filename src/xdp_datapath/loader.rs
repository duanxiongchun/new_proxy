use crate::v1_config::XdpAttachMode;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "linux")]
const XDP_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xdp_filter.o"));

#[cfg(all(target_os = "linux", not(test)))]
fn write_embedded_xdp_object(ifindex: u32) -> io::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    for _ in 0..8 {
        let path = std::env::temp_dir().join(format!(
            "new_proxy_xdp_filter_{}_{}_{:016x}.o",
            std::process::id(),
            ifindex,
            rand::random::<u64>()
        ));
        let mut object = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(object) => object,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        if let Err(error) = object.write_all(XDP_OBJECT) {
            drop(object);
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        return Ok(path);
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create a unique temporary XDP object",
    ))
}

#[cfg(target_os = "linux")]
#[cfg_attr(test, allow(dead_code))]
pub struct BpfLinkManager {
    interface: String,
    mode: XdpAttachMode,
    pin_dir: PathBuf,
    _lock: File,
    attached: bool,
}

#[cfg(not(target_os = "linux"))]
pub struct BpfLinkManager;

#[cfg(target_os = "linux")]
impl BpfLinkManager {
    pub fn attach(interface: &str, mode: XdpAttachMode) -> Result<Self, io::Error> {
        use std::ffi::CString;

        let c_interface =
            CString::new(interface).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ifindex = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
        if ifindex == 0 {
            return Err(io::Error::last_os_error());
        }

        let pin_dir = PathBuf::from(format!("/sys/fs/bpf/new_proxy_{ifindex}"));
        let lock = claim_interface_lock(ifindex)?;
        let manager = Self {
            interface: interface.to_string(),
            mode,
            pin_dir,
            _lock: lock,
            attached: false,
        };

        #[cfg(not(test))]
        {
            let mut manager = manager;
            let object_path = write_embedded_xdp_object(ifindex)?;
            if manager.pin_dir.exists() {
                if let Err(error) = manager.cleanup_stale_attachment() {
                    let _ = std::fs::remove_file(&object_path);
                    return Err(error);
                }
            }
            if let Err(error) = std::fs::create_dir(&manager.pin_dir) {
                let _ = std::fs::remove_file(&object_path);
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "failed to claim BPF pin directory for interface {interface} at {}: {error}",
                        manager.pin_dir.display()
                    ),
                ));
            }
            if let Err(error) = std::fs::create_dir(manager.pin_dir.join("maps")) {
                let _ = std::fs::remove_file(&object_path);
                let _ = std::fs::remove_dir_all(&manager.pin_dir);
                return Err(error);
            }
            let load_result = manager.run(
                Command::new("bpftool")
                    .args(["prog", "loadall"])
                    .arg(&object_path)
                    .arg(&manager.pin_dir)
                    .arg("pinmaps")
                    .arg(manager.pin_dir.join("maps")),
                "load XDP program",
            );
            let remove_result = std::fs::remove_file(&object_path);
            if let Err(error) = load_result {
                let _ = std::fs::remove_dir_all(&manager.pin_dir);
                return Err(error);
            }
            if let Err(error) = remove_result {
                let _ = std::fs::remove_dir_all(&manager.pin_dir);
                return Err(error);
            }
            if let Err(error) = manager.detach_matching_stale_attachment() {
                let _ = std::fs::remove_dir_all(&manager.pin_dir);
                return Err(error);
            }
            if let Err(error) = manager.run(
                Command::new("bpftool")
                    .args(["net", "attach", manager.attach_type(), "pinned"])
                    .arg(manager.pin_dir.join("xdp_filter_prog"))
                    .args(["dev", interface]),
                "attach XDP program",
            ) {
                let _ = std::fs::remove_dir_all(&manager.pin_dir);
                return Err(error);
            }
            manager.attached = true;
            Ok(manager)
        }

        #[cfg(test)]
        Ok(manager)
    }

    pub fn map_path(&self, name: &str) -> PathBuf {
        self.pin_dir.join("maps").join(name)
    }

    #[cfg_attr(test, allow(dead_code))]
    fn attach_type(&self) -> &'static str {
        match self.mode {
            XdpAttachMode::Native => "xdp",
            XdpAttachMode::Skb => "xdpgeneric",
        }
    }

    #[cfg_attr(test, allow(dead_code))]
    fn run(&self, command: &mut Command, action: &str) -> io::Result<()> {
        let output = command.output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "{action} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    #[cfg(not(test))]
    fn cleanup_stale_attachment(&self) -> io::Result<()> {
        let pinned_program = self.pin_dir.join("xdp_filter_prog");
        if pinned_program.exists() {
            let pinned_id = bpftool_program_id(
                Command::new("bpftool")
                    .args(["-j", "prog", "show", "pinned"])
                    .arg(&pinned_program),
            )?;
            let attached = Command::new("bpftool")
                .args(["-j", "net", "show", "dev", &self.interface])
                .output()?;
            if !attached.status.success() {
                return Err(io::Error::other(format!(
                    "query XDP attachment failed: {}",
                    String::from_utf8_lossy(&attached.stderr).trim()
                )));
            }
            let attached: serde_json::Value =
                serde_json::from_slice(&attached.stdout).map_err(io::Error::other)?;
            if json_contains_program_id(&attached, pinned_id) {
                self.run(
                    Command::new("bpftool").args([
                        "net",
                        "detach",
                        self.attach_type(),
                        "dev",
                        &self.interface,
                    ]),
                    "detach stale XDP program",
                )?;
            }
        }
        std::fs::remove_dir_all(&self.pin_dir)
    }

    #[cfg(not(test))]
    fn detach_matching_stale_attachment(&self) -> io::Result<()> {
        let Some(attached_id) = self.attached_program_id()? else {
            return Ok(());
        };
        let loaded_tag = bpftool_program_tag(
            Command::new("bpftool")
                .args(["-j", "prog", "show", "pinned"])
                .arg(self.pin_dir.join("xdp_filter_prog")),
        )?;
        let attached_tag = bpftool_program_tag(
            Command::new("bpftool")
                .args(["-j", "prog", "show", "id"])
                .arg(attached_id.to_string()),
        )?;
        if attached_tag != loaded_tag {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "interface {} has a non-new_proxy XDP program attached",
                    self.interface
                ),
            ));
        }
        self.run(
            Command::new("bpftool").args([
                "net",
                "detach",
                self.attach_type(),
                "dev",
                &self.interface,
            ]),
            "detach stale XDP program",
        )
    }

    #[cfg(not(test))]
    fn attached_program_id(&self) -> io::Result<Option<u64>> {
        let output = Command::new("bpftool")
            .args(["-j", "net", "show", "dev", &self.interface])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "query XDP attachment failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
        Ok(find_xdp_program_id(&value))
    }
}

#[cfg(target_os = "linux")]
fn claim_interface_lock(ifindex: u32) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let netns = std::fs::metadata("/proc/self/ns/net")?;
    use std::os::unix::fs::MetadataExt;
    let netns_inode = netns.ino();
    #[cfg(not(test))]
    let path = {
        use std::os::unix::fs::DirBuilderExt;
        let directory = PathBuf::from("/run/new_proxy");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        directory.join(format!("xdp-{netns_inode}-{ifindex}.lock"))
    };
    #[cfg(test)]
    let path = std::env::temp_dir().join(format!(
        "new_proxy-xdp-test-{}-{netns_inode}-{ifindex}.lock",
        std::process::id(),
    ));
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("interface {ifindex} is already owned by another new_proxy process: {error}"),
        ));
    }
    Ok(lock)
}

#[cfg(all(target_os = "linux", not(test)))]
fn bpftool_program_id(command: &mut Command) -> io::Result<u64> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "query pinned XDP program failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
    value
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| io::Error::other("pinned XDP program has no numeric id"))
}

#[cfg(all(target_os = "linux", not(test)))]
fn bpftool_program_tag(command: &mut Command) -> io::Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "query XDP program tag failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
    value
        .get("tag")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| io::Error::other("XDP program has no tag"))
}

#[cfg(all(target_os = "linux", not(test)))]
fn json_contains_program_id(value: &serde_json::Value, expected: u64) -> bool {
    match value {
        serde_json::Value::Object(fields) => {
            fields.get("id").and_then(serde_json::Value::as_u64) == Some(expected)
                || fields
                    .values()
                    .any(|value| json_contains_program_id(value, expected))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_contains_program_id(value, expected)),
        _ => false,
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn find_xdp_program_id(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Object(fields) => fields
            .get("xdp")
            .and_then(find_program_id)
            .or_else(|| fields.values().find_map(find_xdp_program_id)),
        serde_json::Value::Array(values) => values.iter().find_map(find_xdp_program_id),
        _ => None,
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn find_program_id(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Object(fields) => fields
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .or_else(|| fields.values().find_map(find_program_id)),
        serde_json::Value::Array(values) => values.iter().find_map(find_program_id),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
impl Drop for BpfLinkManager {
    fn drop(&mut self) {
        #[cfg(not(test))]
        {
            if !self.attached {
                return;
            }
            use std::process::Command;
            let status = Command::new("bpftool")
                .args(["net", "detach", self.attach_type(), "dev", &self.interface])
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

            if let Err(error) = std::fs::remove_dir_all(&self.pin_dir) {
                log::warn!("failed to remove {}: {error}", self.pin_dir.display());
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl BpfLinkManager {
    pub fn attach(_interface: &str, _mode: XdpAttachMode) -> Result<Self, io::Error> {
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
    fn v1_unit_bpf_loader_fails_on_invalid_interface() {
        let manager =
            BpfLinkManager::attach("invalid_interface_nonexistent", XdpAttachMode::Native);
        assert!(manager.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn v1_unit_bpf_embedded_object_is_elf() {
        assert_eq!(&XDP_OBJECT[..4], b"\x7fELF");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn v1_unit_bpf_loader_uses_ifindex_scoped_maps() {
        let manager = BpfLinkManager::attach("lo", XdpAttachMode::Native).unwrap();
        assert!(manager.map_path("xsks_map").ends_with("maps/xsks_map"));
    }
}
