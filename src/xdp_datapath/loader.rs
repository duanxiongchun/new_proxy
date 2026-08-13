use crate::v1_config::XdpAttachMode;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "linux")]
const XDP_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/xdp_filter.o"));

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnerRecord {
    program_id: u64,
    mode: XdpAttachMode,
}

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
    owner_path: PathBuf,
    _lock: File,
    owned_program_id: Option<u64>,
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
        let owner_path = interface_owner_path(ifindex)?;
        let lock = claim_interface_lock(ifindex)?;
        let manager = Self {
            interface: interface.to_string(),
            mode,
            pin_dir,
            owner_path,
            _lock: lock,
            owned_program_id: None,
        };

        #[cfg(not(test))]
        {
            let mut manager = manager;
            let object_path = write_embedded_xdp_object(ifindex)?;
            if let Err(error) = manager.detach_owned_stale_attachment() {
                let _ = std::fs::remove_file(&object_path);
                return Err(error);
            }
            let attached = match manager.attached_program_id() {
                Ok(attached) => attached,
                Err(error) => {
                    let _ = std::fs::remove_file(&object_path);
                    return Err(error);
                }
            };
            if let Some(attached) = attached {
                let _ = std::fs::remove_file(&object_path);
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "interface {} has unowned XDP program {attached} attached",
                        manager.interface
                    ),
                ));
            }
            if manager.pin_dir.exists() {
                std::fs::remove_dir_all(&manager.pin_dir)?;
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
            let program_id = bpftool_program_id(
                Command::new("bpftool")
                    .args(["-j", "prog", "show", "pinned"])
                    .arg(manager.pin_dir.join("xdp_filter_prog")),
            )?;
            if let Ok(Some(attached)) = manager.attached_program_id() {
                let _ = std::fs::remove_dir_all(&manager.pin_dir);
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "interface {} has unowned XDP program {attached} attached",
                        manager.interface
                    ),
                ));
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
            manager.owned_program_id = Some(program_id);
            if manager.attached_program_id()? != Some(program_id) {
                return Err(io::Error::other(format!(
                    "interface {} attachment does not match loaded program {program_id}",
                    manager.interface
                )));
            }
            write_owner_record(
                &manager.owner_path,
                OwnerRecord {
                    program_id,
                    mode: manager.mode,
                },
            )?;
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
        attach_type(self.mode)
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
    fn detach_owned_stale_attachment(&self) -> io::Result<()> {
        let Some(owner) = read_owner_record(&self.owner_path)? else {
            return Ok(());
        };
        let attached_id = self.attached_program_id()?;
        if attached_id.is_some_and(|attached| attached != owner.program_id) {
            let _ = std::fs::remove_file(&self.owner_path);
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "interface {} attachment no longer matches owned program {}",
                    self.interface, owner.program_id
                ),
            ));
        }
        if attached_id == Some(owner.program_id) {
            self.run(
                Command::new("bpftool").args([
                    "net",
                    "detach",
                    attach_type(owner.mode),
                    "dev",
                    &self.interface,
                ]),
                "detach stale XDP program",
            )?;
        }
        remove_owner_record(&self.owner_path)
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
fn attach_type(mode: XdpAttachMode) -> &'static str {
    match mode {
        XdpAttachMode::Native => "xdp",
        XdpAttachMode::Skb => "xdpgeneric",
    }
}

#[cfg(target_os = "linux")]
fn netns_inode() -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata("/proc/self/ns/net")?.ino())
}

#[cfg(target_os = "linux")]
fn interface_owner_path(ifindex: u32) -> io::Result<PathBuf> {
    let netns_inode = netns_inode()?;
    #[cfg(not(test))]
    {
        use std::os::unix::fs::DirBuilderExt;
        let directory = PathBuf::from("/run/new_proxy");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        Ok(directory.join(format!("xdp-{netns_inode}-{ifindex}.owner")))
    }
    #[cfg(test)]
    Ok(std::env::temp_dir().join(format!(
        "new_proxy-xdp-test-{}-{netns_inode}-{ifindex}.owner",
        std::process::id(),
    )))
}

#[cfg(target_os = "linux")]
fn write_owner_record(path: &std::path::Path, owner: OwnerRecord) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let temporary = path.with_extension(format!("owner.{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let mode = match owner.mode {
        XdpAttachMode::Native => "native",
        XdpAttachMode::Skb => "skb",
    };
    if let Err(error) = writeln!(file, "{} {mode}", owner.program_id) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    drop(file);
    if let Err(error) = std::fs::rename(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_owner_record(path: &std::path::Path) -> io::Result<Option<OwnerRecord>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut fields = text.split_whitespace();
    let program_id = fields
        .next()
        .ok_or_else(|| io::Error::other("XDP owner record is missing program id"))?
        .parse::<u64>()
        .map_err(|_| io::Error::other("XDP owner record has invalid program id"))?;
    let mode = match fields.next() {
        Some("native") => XdpAttachMode::Native,
        Some("skb") => XdpAttachMode::Skb,
        _ => return Err(io::Error::other("XDP owner record has invalid mode")),
    };
    if fields.next().is_some() {
        return Err(io::Error::other("XDP owner record has extra fields"));
    }
    Ok(Some(OwnerRecord { program_id, mode }))
}

#[cfg(target_os = "linux")]
fn remove_owner_record(path: &std::path::Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn claim_interface_lock(ifindex: u32) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let netns_inode = netns_inode()?;
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
            if let Some(owned_program_id) = self.owned_program_id {
                match self.attached_program_id() {
                    Ok(Some(attached_program_id)) if attached_program_id == owned_program_id => {
                        let status = Command::new("bpftool")
                            .args(["net", "detach", self.attach_type(), "dev", &self.interface])
                            .status();
                        match status {
                            Ok(status) if status.success() => {
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
                    }
                    Ok(Some(attached_program_id)) => {
                        log::warn!(
                            "leaving replacement XDP program {attached_program_id} attached to {}; owned program was {owned_program_id}",
                            self.interface
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        log::warn!(
                            "failed to verify XDP ownership on {} during shutdown: {error}",
                            self.interface
                        );
                    }
                }
                if let Err(error) = remove_owner_record(&self.owner_path) {
                    log::warn!(
                        "failed to remove owner record {}: {error}",
                        self.owner_path.display()
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

    #[test]
    #[cfg(target_os = "linux")]
    fn v1_unit_bpf_owner_record_round_trips_program_and_attach_mode() {
        let path = std::env::temp_dir().join(format!(
            "new_proxy-owner-record-{}-{}.owner",
            std::process::id(),
            rand::random::<u64>()
        ));
        let owner = OwnerRecord {
            program_id: 42,
            mode: XdpAttachMode::Skb,
        };

        write_owner_record(&path, owner).unwrap();
        assert_eq!(read_owner_record(&path).unwrap(), Some(owner));
        remove_owner_record(&path).unwrap();
        assert_eq!(read_owner_record(&path).unwrap(), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn v1_unit_bpf_owner_record_rejects_malformed_content() {
        let path = std::env::temp_dir().join(format!(
            "new_proxy-owner-record-invalid-{}-{}.owner",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, "not-an-id native\n").unwrap();

        assert!(read_owner_record(&path).is_err());
        remove_owner_record(&path).unwrap();
    }
}
