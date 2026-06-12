#![allow(
    clippy::too_many_arguments,
    clippy::unnecessary_unwrap,
    clippy::collapsible_if
)]
#[cfg(target_os = "linux")]
use super::loader::BpfLinkManager;
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::sync::Arc;

use crate::app_config::RuntimeMode;
#[cfg(target_os = "linux")]
use crate::client::build_peer_quic_pool;
use crate::config::GatewayConfig;
#[cfg(target_os = "linux")]
use crate::control::ControlServer;
use crate::datapath::{Datapath, DatapathError, DatapathStats};
#[cfg(target_os = "linux")]
use crate::quic_pool::{cert_sha256, generate_self_signed_cert};
#[cfg(target_os = "linux")]
use crate::runtime::{cleanup_runtime, setup_routes};
use crate::telemetry::TelemetryRegistry;
#[cfg(target_os = "linux")]
use crate::tun_datapath::{
    setup_client_endpoint, setup_server_endpoint, setup_udp_socket, spawn_worker_thread,
};
use crate::{ClientQuicDataPortBaseline, PeerQuicPools};

#[cfg(target_os = "linux")]
struct FdsGuard {
    fds: Vec<std::os::unix::io::RawFd>,
}

#[cfg(target_os = "linux")]
impl Drop for FdsGuard {
    fn drop(&mut self) {
        for &fd in &self.fds {
            if fd >= 0 {
                // SAFETY: The FDs stored in the vector are valid and non-negative.
                // When FDs are handed over or managed, they are reset to -1 in the vector.
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct WorkerPanicGuard {
    exit_notify: Arc<tokio::sync::Notify>,
}

#[cfg(target_os = "linux")]
impl Drop for WorkerPanicGuard {
    fn drop(&mut self) {
        self.exit_notify.notify_one();
    }
}

#[allow(dead_code)]
pub struct XdpDatapath {
    config: GatewayConfig,
    #[allow(dead_code)]
    interface_name: String,
    runtime_mode: RuntimeMode,
    fixed_client_quic_data_port_count: Option<usize>,
    peer_telemetries: Vec<Arc<TelemetryRegistry>>,
    worker_telemetry_registry: Arc<crate::telemetry::WorkerTelemetryRegistry>,
    gateway_state: Arc<parking_lot::RwLock<crate::GatewayState>>,
    peer_secrets: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    session_cache: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
    auth_nonce_cache: Arc<parking_lot::Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
    shared_quic_registry: crate::quic_pool::PeerConnRegistry,
    client_quic_pools: PeerQuicPools,
    client_quic_data_port_baseline: ClientQuicDataPortBaseline,
    peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(target_os = "linux")]
    quic_ifindex: u32,
    #[cfg(target_os = "linux")]
    intercept_ifindexes: Vec<u32>,
    #[cfg(target_os = "linux")]
    _bpf_managers: Vec<BpfLinkManager>,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_xdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xdp_umem_reg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

#[cfg(target_os = "linux")]
struct UmemRegion {
    addr: *mut libc::c_void,
    size: usize,
}

#[cfg(target_os = "linux")]
unsafe impl Send for UmemRegion {}
#[cfg(target_os = "linux")]
unsafe impl Sync for UmemRegion {}

#[cfg(target_os = "linux")]
impl UmemRegion {
    fn new(size: usize) -> Result<Self, std::io::Error> {
        // SAFETY: mmap is called with MAP_ANONYMOUS | MAP_PRIVATE to allocate a private,
        // zero-initialized, anonymous memory block of the requested size.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { addr, size })
    }
}

#[cfg(target_os = "linux")]
impl Drop for UmemRegion {
    fn drop(&mut self) {
        // SAFETY: munmap is called on a valid anonymous memory block allocated by mmap in `new`.
        unsafe {
            libc::munmap(self.addr, self.size);
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct XskSocketSetup {
    fd: libc::c_int,
    ifindex: u32,
    umem_addr: SendPtr,
    rx: XskRing,
    tx: XskRing,
    fill: XskRing,
    comp: XskRing,
}

#[cfg(target_os = "linux")]
struct XskSetup {
    #[allow(dead_code)]
    umems: Vec<UmemRegion>,
    quic_sockets: Vec<XskSocketSetup>,
    intercept_sockets: Vec<XskSocketSetup>,
}

#[cfg(target_os = "linux")]
impl Drop for XskSetup {
    fn drop(&mut self) {
        for s in &self.quic_sockets {
            if s.fd >= 0 {
                // SAFETY: close valid socket FD.
                unsafe {
                    libc::close(s.fd);
                }
            }
        }
        for s in &self.intercept_sockets {
            if s.fd >= 0 {
                // SAFETY: close valid socket FD.
                unsafe {
                    libc::close(s.fd);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe impl Send for XskSetup {}
#[cfg(target_os = "linux")]
unsafe impl Sync for XskSetup {}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct SendPtr(pub *mut libc::c_void);

#[cfg(target_os = "linux")]
unsafe impl Send for SendPtr {}
#[cfg(target_os = "linux")]
unsafe impl Sync for SendPtr {}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for SendPtr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:p}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub fn parse(packet: &[u8]) -> Option<(Self, &[u8])> {
        if packet.len() < 14 {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&packet[0..6]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&packet[6..12]);
        let ether_type = u16::from_be_bytes([packet[12], packet[13]]);
        Some((
            Self {
                dst_mac,
                src_mac,
                ether_type,
            },
            &packet[14..],
        ))
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Option<usize> {
        if buffer.len() < 14 {
            return None;
        }
        buffer[0..6].copy_from_slice(&self.dst_mac);
        buffer[6..12].copy_from_slice(&self.src_mac);
        let be_type = self.ether_type.to_be_bytes();
        buffer[12] = be_type[0];
        buffer[13] = be_type[1];
        Some(14)
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct xdp_desc {
    addr: u64,
    len: u32,
    options: u32,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct XskRing {
    pub producer: *mut u32,
    pub consumer: *mut u32,
    pub desc: *mut u8,
    pub mask: u32,
    pub size: u32,
}

#[cfg(target_os = "linux")]
unsafe impl Send for XskRing {}
#[cfg(target_os = "linux")]
unsafe impl Sync for XskRing {}

#[cfg(target_os = "linux")]
impl XskRing {
    /// # Safety
    ///
    /// The caller must ensure that the producer and consumer pointers are valid and aligned.
    pub unsafe fn free_slots(&self) -> u32 {
        let prod = std::ptr::read_volatile(self.producer);
        let cons = std::ptr::read_volatile(self.consumer);
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        self.size - (prod.wrapping_sub(cons))
    }

    /// # Safety
    ///
    /// The caller must ensure that the desc pointer is valid, aligned, and points to a buffer
    /// of at least size `(idx & mask) + 1` elements.
    pub unsafe fn write_fill_addr(&mut self, idx: u32, addr: u64) {
        let offset_ptr = (self.desc as *mut u64).offset((idx & self.mask) as isize);
        std::ptr::write_volatile(offset_ptr, addr);
    }

    /// # Safety
    ///
    /// The caller must ensure that the producer pointer is valid and aligned.
    pub unsafe fn produce(&mut self, cnt: u32) {
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        let prod = std::ptr::read_volatile(self.producer);
        std::ptr::write_volatile(self.producer, prod.wrapping_add(cnt));
    }

    /// # Safety
    ///
    /// The caller must ensure that the desc pointer is valid, aligned, and points to a buffer
    /// of at least size `(idx & mask) + 1` elements of type `xdp_desc`.
    pub unsafe fn read_rx_desc(&self, idx: u32) -> (u64, u32) {
        let desc_ptr = (self.desc as *const xdp_desc).offset((idx & self.mask) as isize);
        let desc = std::ptr::read_volatile(desc_ptr);
        (desc.addr, desc.len)
    }

    /// # Safety
    ///
    /// The caller must ensure that the desc pointer is valid, aligned, and points to a buffer
    /// of at least size `(idx & mask) + 1` elements of type `xdp_desc`.
    pub unsafe fn write_tx_desc(&mut self, idx: u32, addr: u64, len: u32) {
        let desc_ptr = (self.desc as *mut xdp_desc).offset((idx & self.mask) as isize);
        let desc = xdp_desc {
            addr,
            len,
            options: 0,
        };
        std::ptr::write_volatile(desc_ptr, desc);
    }

    /// # Safety
    ///
    /// The caller must ensure that the consumer pointer is valid and aligned.
    pub unsafe fn consume(&mut self, cnt: u32) {
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        let cons = std::ptr::read_volatile(self.consumer);
        std::ptr::write_volatile(self.consumer, cons.wrapping_add(cnt));
    }

    /// # Safety
    ///
    /// The caller must ensure that the desc pointer is valid, aligned, and points to a buffer
    /// of at least size `(idx & mask) + 1` elements of type `u64`.
    pub unsafe fn read_comp_addr(&self, idx: u32) -> u64 {
        let addr_ptr = (self.desc as *const u64).offset((idx & self.mask) as isize);
        std::ptr::read_volatile(addr_ptr)
    }
}

#[cfg(target_os = "linux")]
fn get_interface_queue_count(ifindex: u32) -> usize {
    let mut buf = [0u8; 32];
    // SAFETY: libc::if_indextoname is called with an output buffer `buf` of 32 bytes,
    // which is larger than IFNAMSIZ (16 bytes). On success, name_ptr returns a pointer
    // to a valid null-terminated string contained inside `buf`.
    let name_ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
    if name_ptr.is_null() {
        return 1;
    }
    // SAFETY: name_ptr is non-null and points to the valid null-terminated string inside `buf`.
    let ifname = unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_string_lossy();
    let path = format!("/sys/class/net/{}/queues", ifname);
    if let Ok(entries) = std::fs::read_dir(path) {
        let count = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
            .count();
        if count > 0 {
            return count;
        }
    }
    1
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct bpf_attr_update_elem {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct bpf_attr_obj_get {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[cfg(target_os = "linux")]
fn register_xsk_in_map(
    map_fd: libc::c_int,
    queue_id: u32,
    xsk_fd: libc::c_int,
) -> Result<(), std::io::Error> {
    let key = queue_id;
    let value = xsk_fd as u32;

    let attr = bpf_attr_update_elem {
        map_fd: map_fd as u32,
        _pad: 0,
        key: &key as *const u32 as u64,
        value: &value as *const u32 as u64,
        flags: 0, // BPF_ANY
    };

    // SAFETY: The synchronous bpf syscall takes a valid pointer to the `bpf_attr_update_elem`
    // and its internal pointers (key and value) which are guaranteed to live for the scope of the call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            2, // BPF_MAP_UPDATE_ELEM
            &attr as *const bpf_attr_update_elem as *const libc::c_void,
            std::mem::size_of::<bpf_attr_update_elem>() as libc::size_t,
        )
    };

    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn bpf_obj_get(pathname: &str) -> Result<libc::c_int, std::io::Error> {
    let c_path = CString::new(pathname)?;
    let attr = bpf_attr_obj_get {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    // SAFETY: The synchronous bpf syscall takes a valid pointer to the `bpf_attr_obj_get`
    // and the path string pointer which are guaranteed to live for the scope of the call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            7, // BPF_OBJ_GET
            &attr as *const bpf_attr_obj_get as *const libc::c_void,
            std::mem::size_of::<bpf_attr_obj_get>() as libc::size_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret as libc::c_int)
    }
}

#[cfg(target_os = "linux")]
unsafe fn populate_local_ips_map(map_path: &str) -> Result<(), std::io::Error> {
    let map_fd = bpf_obj_get(map_path)?;
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if libc::getifaddrs(&mut addrs) != 0 {
        libc::close(map_fd);
        return Err(std::io::Error::last_os_error());
    }
    let mut curr = addrs;
    while !curr.is_null() {
        if !(*curr).ifa_addr.is_null() && (*(*curr).ifa_addr).sa_family == libc::AF_INET as u16 {
            let sin = (*curr).ifa_addr as *const libc::sockaddr_in;
            let ip_bytes = (*sin).sin_addr.s_addr;
            let value = 1u8;
            let attr = bpf_attr_update_elem {
                map_fd: map_fd as u32,
                _pad: 0,
                key: &ip_bytes as *const u32 as u64,
                value: &value as *const u8 as u64,
                flags: 0, // BPF_ANY
            };
            libc::syscall(
                libc::SYS_bpf,
                2, // BPF_MAP_UPDATE_ELEM
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<bpf_attr_update_elem>() as libc::size_t,
            );
        }
        curr = (*curr).ifa_next;
    }
    libc::freeifaddrs(addrs);
    libc::close(map_fd);
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct xdp_ring_offset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct xdp_mmap_offsets {
    rx: xdp_ring_offset,
    tx: xdp_ring_offset,
    fr: xdp_ring_offset,
    cr: xdp_ring_offset,
}

/// # Safety
///
/// The caller must ensure that `fd` is a valid, open AF_XDP socket file descriptor,
/// and that the `offsets` structure contains correct field offsets retrieved from the kernel.
#[cfg(target_os = "linux")]
unsafe fn mmap_ring(
    fd: libc::c_int,
    offsets: &xdp_ring_offset,
    pgoff: u64,
    ring_size: u32,
    is_desc_u64: bool,
) -> Result<XskRing, std::io::Error> {
    let desc_sz = if is_desc_u64 {
        std::mem::size_of::<u64>()
    } else {
        std::mem::size_of::<xdp_desc>()
    };

    let ring_map_sz = (offsets.desc as usize) + (ring_size as usize) * desc_sz;

    // SAFETY: mmap is called with MAP_SHARED and MAP_POPULATE to map kernel rings into userspace.
    let ptr = libc::mmap(
        std::ptr::null_mut(),
        ring_map_sz,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED | libc::MAP_POPULATE,
        fd,
        pgoff as libc::off_t,
    );
    if ptr == libc::MAP_FAILED {
        let err = std::io::Error::last_os_error();
        log::error!(
            "mmap_ring failed for fd {}, pgoff 0x{:x}, size {}, error: {}",
            fd,
            pgoff,
            ring_map_sz,
            err
        );
        return Err(err);
    }

    Ok(XskRing {
        producer: (ptr as usize + offsets.producer as usize) as *mut u32,
        consumer: (ptr as usize + offsets.consumer as usize) as *mut u32,
        desc: (ptr as usize + offsets.desc as usize) as *mut u8,
        mask: ring_size - 1,
        size: ring_size,
    })
}

#[cfg(target_os = "linux")]
const SOL_XDP: libc::c_int = 283;
#[cfg(target_os = "linux")]
const XDP_MMAP_OFFSETS: libc::c_int = 1;
#[cfg(target_os = "linux")]
const XDP_PGOFF_RX_RING: u64 = 0;
#[cfg(target_os = "linux")]
const XDP_PGOFF_TX_RING: u64 = 0x80000000;
#[cfg(target_os = "linux")]
const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
#[cfg(target_os = "linux")]
const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

#[cfg(target_os = "linux")]
fn mmap_socket_rings(
    fd: libc::c_int,
) -> Result<(XskRing, XskRing, XskRing, XskRing), std::io::Error> {
    let mut offsets = unsafe {
        // SAFETY: Zeroing is safe for POD layout struct containing u64 fields.
        std::mem::zeroed::<xdp_mmap_offsets>()
    };
    let mut optlen = std::mem::size_of::<xdp_mmap_offsets>() as libc::socklen_t;
    // SAFETY: getsockopt fetches XSK ring offsets from the Linux kernel.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut offsets as *mut _ as *mut libc::c_void,
            &mut optlen,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    log::info!(
        "mmap_socket_rings: fd {}, rx.desc={}, tx.desc={}, fr.desc={}, cr.desc={}",
        fd,
        offsets.rx.desc,
        offsets.tx.desc,
        offsets.fr.desc,
        offsets.cr.desc
    );

    let ring_size: u32 = 2048;

    let rx = unsafe { mmap_ring(fd, &offsets.rx, XDP_PGOFF_RX_RING, ring_size, false)? };
    let tx = unsafe { mmap_ring(fd, &offsets.tx, XDP_PGOFF_TX_RING, ring_size, false)? };
    let fill = unsafe { mmap_ring(fd, &offsets.fr, XDP_UMEM_PGOFF_FILL_RING, ring_size, true)? };
    let comp = unsafe {
        mmap_ring(
            fd,
            &offsets.cr,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            ring_size,
            true,
        )?
    };

    Ok((rx, tx, fill, comp))
}

/// # Safety
///
/// The caller must ensure that the `fill` ring is backed by valid, mapped memory-mapped pointers.
#[cfg(target_os = "linux")]
unsafe fn populate_fill_ring(fill: &mut XskRing, start_chunk: u32, num_chunks: u32) {
    let free = fill.free_slots();
    let cnt = std::cmp::min(free, num_chunks);
    for i in 0..cnt {
        let addr = ((start_chunk + i) as u64) * 4096;
        fill.write_fill_addr((*fill.producer).wrapping_add(i), addr);
    }
    if cnt > 0 {
        fill.produce(cnt);
    }
}

/// # Safety
///
/// The caller must ensure that the `comp` ring is backed by valid, mapped memory-mapped pointers.
#[cfg(target_os = "linux")]
unsafe fn reclaim_tx_buffers(
    comp: &mut XskRing,
    comp_cons: &mut u32,
    free_tx_chunks: &mut Vec<u64>,
) {
    let prod = std::ptr::read_volatile(comp.producer);
    let cons = *comp_cons;
    let cnt = prod.wrapping_sub(cons);
    if cnt > 0 {
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        for i in 0..cnt {
            let idx = cons.wrapping_add(i);
            let addr = comp.read_comp_addr(idx);
            free_tx_chunks.push(addr);
        }
        *comp_cons = cons.wrapping_add(cnt);
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        std::ptr::write_volatile(comp.consumer, *comp_cons);
    }
}

/// # Safety
///
/// The caller must ensure that `rx`, `fill`, `tx`, and `comp` rings are backed by valid, mapped
/// memory-mapped pointers, and that `rx_umem_base` and `tx_umem_base` point to valid UMEM areas.
#[cfg(target_os = "linux")]
unsafe fn process_rx_ring(
    rx: &mut XskRing,
    rx_cons: &mut u32,
    fill: &mut XskRing,
    fill_prod: &mut u32,
    rx_umem_base: *mut libc::c_void,
    mut process_packet: impl FnMut(&[u8], &mut [u8]) -> Option<usize>,
    tx: &mut XskRing,
    tx_prod: &mut u32,
    comp: &mut XskRing,
    comp_cons: &mut u32,
    free_tx_chunks: &mut Vec<u64>,
    tx_umem_base: *mut libc::c_void,
) -> u32 {
    let prod = std::ptr::read_volatile(rx.producer);
    let cons = *rx_cons;
    let cnt = prod.wrapping_sub(cons);
    let mut tx_produced = 0;
    if cnt > 0 {
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        // Reclaim completed TX buffers only when our free pool is running low.
        if free_tx_chunks.len() < 64 {
            reclaim_tx_buffers(comp, comp_cons, free_tx_chunks);
        }

        let fill_cons = std::ptr::read_volatile(fill.consumer);
        let fill_prod_idx = *fill_prod;
        let fill_free = fill.size - (fill_prod_idx.wrapping_sub(fill_cons));

        let mut fill_produced = 0;

        for i in 0..cnt {
            let idx = cons.wrapping_add(i);
            let (addr, len) = rx.read_rx_desc(idx);

            // Bounds check UMEM read address
            debug_assert!(
                addr + len as u64 <= 4096 * 4096,
                "RX UMEM access out of bounds"
            );

            // SAFETY: rx_umem_base + addr points to a valid mapped packet buffer.
            let pkt_ptr = (rx_umem_base as usize + addr as usize) as *const u8;
            let pkt_slice = std::slice::from_raw_parts(pkt_ptr, len as usize);

            if free_tx_chunks.is_empty() {
                reclaim_tx_buffers(comp, comp_cons, free_tx_chunks);
            }

            if let Some(tx_addr) = free_tx_chunks.pop() {
                // Bounds check UMEM write address
                debug_assert!(
                    tx_addr + 4096 <= 4096 * 4096,
                    "TX UMEM access out of bounds"
                );

                // SAFETY: tx_umem_base + tx_addr points to a valid mapped packet buffer.
                let tx_ptr = (tx_umem_base as usize + tx_addr as usize) as *mut u8;
                let out_slice = std::slice::from_raw_parts_mut(tx_ptr, 4096);

                if let Some(written_len) = process_packet(pkt_slice, out_slice) {
                    let tx_idx = tx_prod.wrapping_add(tx_produced);
                    tx.write_tx_desc(tx_idx, tx_addr, written_len as u32);
                    tx_produced += 1;
                } else {
                    free_tx_chunks.push(tx_addr);
                }
            }

            // Batch returned RX buffers to fill ring
            if fill_produced < fill_free {
                fill.write_fill_addr(fill_prod_idx.wrapping_add(fill_produced), addr);
                fill_produced += 1;
            }
        }

        *rx_cons = cons.wrapping_add(cnt);
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        std::ptr::write_volatile(rx.consumer, *rx_cons);

        if tx_produced > 0 {
            *tx_prod = tx_prod.wrapping_add(tx_produced);
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            std::ptr::write_volatile(tx.producer, *tx_prod);
        }
        if fill_produced > 0 {
            *fill_prod = fill_prod.wrapping_add(fill_produced);
            std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
            std::ptr::write_volatile(fill.producer, *fill_prod);
        }
    }
    tx_produced
}

#[derive(Debug, Clone)]
pub struct OuterPacketInfo {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: std::net::Ipv4Addr,
    pub dst_ip: std::net::Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct XdpRouteState {
    local_outer_mac: [u8; 6],
    peer_outer_mac: Option<[u8; 6]>,
    local_outer_ip: std::net::Ipv4Addr,
    peer_outer_ip: Option<std::net::Ipv4Addr>,
    local_outer_port: u16,
    peer_outer_port: u16,
    inner_mac_cache: Arc<RwLock<HashMap<std::net::Ipv4Addr, [u8; 6]>>>,
    intercept_local_macs: HashMap<u32, [u8; 6]>, // ifindex -> local MAC
    last_resolve_attempts: HashMap<std::net::Ipv4Addr, std::time::Instant>,
    local_mac_cache: HashMap<std::net::Ipv4Addr, [u8; 6]>,
}

#[cfg(target_os = "linux")]
fn get_gateway_ip(ifname: &str) -> Option<std::net::Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        if parts[0] == ifname {
            let gw_hex = parts[2];
            if gw_hex != "00000000" {
                if let Ok(gw_val) = u32::from_str_radix(gw_hex, 16) {
                    let bytes = gw_val.to_ne_bytes();
                    return Some(std::net::Ipv4Addr::new(
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ));
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_mac_from_arp(ip: std::net::Ipv4Addr, ifname: &str) -> Option<[u8; 6]> {
    let content = std::fs::read_to_string("/proc/net/arp").ok()?;
    let ip_str = ip.to_string();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        if parts[0] == ip_str && parts[5] == ifname {
            let mac_str = parts[3];
            let mut mac = [0u8; 6];
            let mut i = 0;
            for byte_str in mac_str.split(':') {
                if i >= 6 {
                    break;
                }
                mac[i] = u8::from_str_radix(byte_str, 16).ok()?;
                i += 1;
            }
            if i == 6 {
                return Some(mac);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn resolve_mac(ifname: &str, dest_ip: std::net::Ipv4Addr) -> Option<[u8; 6]> {
    if let Some(mac) = get_mac_from_arp(dest_ip, ifname) {
        return Some(mac);
    }
    if let Some(gw_ip) = get_gateway_ip(ifname) {
        if let Some(mac) = get_mac_from_arp(gw_ip, ifname) {
            return Some(mac);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn get_interface_mac(ifname: &str) -> Option<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", ifname);
    let content = std::fs::read_to_string(path).ok()?;
    let content = content.trim();
    let mut mac = [0u8; 6];
    let mut i = 0;
    for byte_str in content.split(':') {
        if i >= 6 {
            break;
        }
        mac[i] = u8::from_str_radix(byte_str, 16).ok()?;
        i += 1;
    }
    if i == 6 {
        Some(mac)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn get_interface_mac_by_ip(target_ip: std::net::Ipv4Addr) -> Option<[u8; 6]> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return None;
    }
    let mut curr = addrs;
    let mut name = None;
    while !curr.is_null() {
        unsafe {
            if !(*curr).ifa_addr.is_null() && (*(*curr).ifa_addr).sa_family == libc::AF_INET as u16
            {
                let sin = (*curr).ifa_addr as *const libc::sockaddr_in;
                let ip_bytes = (*sin).sin_addr.s_addr.to_ne_bytes();
                let ip =
                    std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                if ip == target_ip {
                    name = Some(
                        std::ffi::CStr::from_ptr((*curr).ifa_name)
                            .to_string_lossy()
                            .into_owned(),
                    );
                    break;
                }
            }
            curr = (*curr).ifa_next;
        }
    }
    unsafe {
        libc::freeifaddrs(addrs);
    }
    if let Some(ifname) = name {
        get_interface_mac(&ifname)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn get_interface_ip(ifname: &str) -> Option<std::net::Ipv4Addr> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return None;
    }
    let mut curr = addrs;
    let mut ip = None;
    while !curr.is_null() {
        unsafe {
            let name = std::ffi::CStr::from_ptr((*curr).ifa_name).to_string_lossy();
            if name == ifname && !(*curr).ifa_addr.is_null() {
                if (*(*curr).ifa_addr).sa_family == libc::AF_INET as u16 {
                    let sin = (*curr).ifa_addr as *const libc::sockaddr_in;
                    let ip_bytes = (*sin).sin_addr.s_addr.to_ne_bytes();
                    ip = Some(std::net::Ipv4Addr::new(
                        ip_bytes[0],
                        ip_bytes[1],
                        ip_bytes[2],
                        ip_bytes[3],
                    ));
                    break;
                }
            }
            curr = (*curr).ifa_next;
        }
    }
    unsafe {
        libc::freeifaddrs(addrs);
    }
    ip
}

fn parse_ip_src_dst(packet: &[u8]) -> Option<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version == 4 {
        let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        Some((src, dst))
    } else {
        None
    }
}

pub fn wrap_plaintext_to_quic_slice(
    plaintext_ip: &[u8],
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    dst_ip: std::net::Ipv4Addr,
    src_ip: std::net::Ipv4Addr,
    dst_port: u16,
    src_port: u16,
    out_buf: &mut [u8],
) -> Option<usize> {
    let required_len = 14 + 20 + 8 + plaintext_ip.len();
    if out_buf.len() < required_len {
        return None;
    }

    // Ethernet header
    out_buf[0..6].copy_from_slice(&dst_mac);
    out_buf[6..12].copy_from_slice(&src_mac);
    out_buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IP header
    out_buf[14] = 0x45;
    out_buf[15] = 0;
    let total_len = (20 + 8 + plaintext_ip.len()) as u16;
    out_buf[16..18].copy_from_slice(&total_len.to_be_bytes());
    out_buf[18..20].copy_from_slice(&0u16.to_be_bytes());
    out_buf[20..22].copy_from_slice(&0u16.to_be_bytes());
    out_buf[22] = 64;
    out_buf[23] = 17; // UDP

    // Fast checksum calculation using precomputed constant fields
    let s_oct = src_ip.octets();
    let d_oct = dst_ip.octets();
    let src_high = u16::from_be_bytes([s_oct[0], s_oct[1]]) as u32;
    let src_low = u16::from_be_bytes([s_oct[2], s_oct[3]]) as u32;
    let dst_high = u16::from_be_bytes([d_oct[0], d_oct[1]]) as u32;
    let dst_low = u16::from_be_bytes([d_oct[2], d_oct[3]]) as u32;

    let mut sum =
        0x4500u32 + 0x4011u32 + src_high + src_low + dst_high + dst_low + total_len as u32;
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let checksum = !sum as u16;

    out_buf[24..26].copy_from_slice(&checksum.to_be_bytes());
    out_buf[26..30].copy_from_slice(&s_oct);
    out_buf[30..34].copy_from_slice(&d_oct);

    // UDP header
    out_buf[34..36].copy_from_slice(&src_port.to_be_bytes());
    out_buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + plaintext_ip.len()) as u16;
    out_buf[38..40].copy_from_slice(&udp_len.to_be_bytes());
    out_buf[40..42].copy_from_slice(&0u16.to_be_bytes()); // Checksum (0 = disabled/ignored)

    // Payload
    out_buf[42..required_len].copy_from_slice(plaintext_ip);

    Some(required_len)
}

pub fn unwrap_quic_to_plaintext_slice(quic_packet: &[u8]) -> Option<(OuterPacketInfo, &[u8])> {
    if quic_packet.len() < 42 {
        return None;
    }

    let mut src_mac = [0u8; 6];
    let mut dst_mac = [0u8; 6];
    dst_mac.copy_from_slice(&quic_packet[0..6]);
    src_mac.copy_from_slice(&quic_packet[6..12]);
    let ether_type = u16::from_be_bytes([quic_packet[12], quic_packet[13]]);
    if ether_type != 0x0800 {
        return None;
    }

    let ip_hdr = &quic_packet[14..34];
    let ihl = ip_hdr[0] & 0x0F;
    let ip_len = (ihl * 4) as usize;
    if ip_len < 20 || quic_packet.len() < 14 + ip_len + 8 {
        return None;
    }

    let src_ip_bytes = [ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]];
    let dst_ip_bytes = [ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]];
    let src_ip = std::net::Ipv4Addr::from(src_ip_bytes);
    let dst_ip = std::net::Ipv4Addr::from(dst_ip_bytes);

    let udp_hdr = &quic_packet[14 + ip_len..14 + ip_len + 8];
    let src_port = u16::from_be_bytes([udp_hdr[0], udp_hdr[1]]);
    let dst_port = u16::from_be_bytes([udp_hdr[2], udp_hdr[3]]);

    let info = OuterPacketInfo {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    };

    let plaintext_ip = &quic_packet[14 + ip_len + 8..];
    Some((info, plaintext_ip))
}

#[cfg(target_os = "linux")]
fn setup_xsk_sockets(
    quic_ifindex: u32,
    intercept_ifindexes: &[u32],
    queue_count: usize,
    xdp_mode: &str,
) -> Result<XskSetup, DatapathError> {
    use std::io;

    let mut quic_sockets = Vec::new();
    let mut intercept_sockets = Vec::new();
    let mut umems = Vec::new();

    const AF_XDP: libc::c_int = 44;
    const SOL_XDP: libc::c_int = 283;
    const XDP_UMEM_REG: libc::c_int = 4;
    const XDP_UMEM_FILL_RING: libc::c_int = 5;
    const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
    const XDP_RX_RING: libc::c_int = 2;
    const XDP_TX_RING: libc::c_int = 3;
    const XDP_SHARED_UMEM: u16 = 1;
    const XDP_COPY: u16 = 2;

    let (bind_flags, shared_flags) = if xdp_mode == "native" {
        (0u16, XDP_SHARED_UMEM)
    } else {
        (XDP_COPY, XDP_SHARED_UMEM | XDP_COPY)
    };

    let cleanup = |quic: &[XskSocketSetup], intercept: &[XskSocketSetup]| {
        for s in quic {
            if s.fd >= 0 {
                // SAFETY: closing socket FD.
                unsafe {
                    libc::close(s.fd);
                }
            }
        }
        for s in intercept {
            if s.fd >= 0 {
                // SAFETY: closing socket FD.
                unsafe {
                    libc::close(s.fd);
                }
            }
        }
    };

    // 1. Process quic_ifindex
    {
        let ifindex = quic_ifindex;
        let hw_queues = get_interface_queue_count(ifindex);
        let q_count = queue_count.min(hw_queues);
        if q_count > 0 {
            let mut buf = [0u8; 32];
            // SAFETY: libc::if_indextoname writes to `buf` (size 32 > IFNAMSIZ).
            let name_ptr =
                unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
            if name_ptr.is_null() {
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!(
                    "Failed to get interface name for index {}",
                    ifindex
                )));
            }
            // SAFETY: name_ptr is valid and null-terminated inside `buf`.
            let ifname = unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_string_lossy();
            let local_ips_path = format!("/sys/fs/bpf/new_proxy_{}/maps/local_ips", ifname);
            if let Err(e) = unsafe { populate_local_ips_map(&local_ips_path) } {
                log::warn!(
                    "Failed to populate local_ips map at {}: {}",
                    local_ips_path,
                    e
                );
            }
            let map_path = format!("/sys/fs/bpf/new_proxy_{}/maps/xsks_map", ifname);

            let map_fd = match bpf_obj_get(&map_path) {
                Ok(fd) => fd,
                Err(e) => {
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "Failed to open pinned map at {}: {}",
                        map_path, e
                    )));
                }
            };

            let umem_size = 4096 * 4096;
            let umem = match UmemRegion::new(umem_size) {
                Ok(u) => u,
                Err(e) => {
                    // SAFETY: closing map FD.
                    unsafe {
                        libc::close(map_fd);
                    }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "Failed to allocate UMEM mmap for ifindex {}: {}",
                        ifindex, e
                    )));
                }
            };

            let mut first_fd_for_iface: Option<libc::c_int> = None;

            for queue_id in 0..q_count {
                // SAFETY: socket call with standard constants.
                let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
                if fd < 0 {
                    let err = io::Error::last_os_error();
                    // SAFETY: closing map FD.
                    unsafe {
                        libc::close(map_fd);
                    }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "socket(AF_XDP) failed: {}",
                        err
                    )));
                }

                if first_fd_for_iface.is_none() {
                    let umem_reg = xdp_umem_reg {
                        addr: umem.addr as u64,
                        len: umem.size as u64,
                        chunk_size: 4096,
                        headroom: 0,
                        flags: 0,
                    };
                    // SAFETY: setsockopt configures UMEM mapping on the first socket FD of the interface.
                    let ret = unsafe {
                        libc::setsockopt(
                            fd,
                            SOL_XDP,
                            XDP_UMEM_REG,
                            &umem_reg as *const _ as *const libc::c_void,
                            std::mem::size_of::<xdp_umem_reg>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "setsockopt(XDP_UMEM_REG) failed: {}",
                            err
                        )));
                    }

                    let ring_size: u32 = 2048;
                    for opt in &[
                        XDP_UMEM_FILL_RING,
                        XDP_UMEM_COMPLETION_RING,
                        XDP_RX_RING,
                        XDP_TX_RING,
                    ] {
                        // SAFETY: setsockopt configures ring sizes on the first socket FD of the interface.
                        let ret = unsafe {
                            libc::setsockopt(
                                fd,
                                SOL_XDP,
                                *opt,
                                &ring_size as *const _ as *const libc::c_void,
                                std::mem::size_of::<u32>() as libc::socklen_t,
                            )
                        };
                        if ret < 0 {
                            let err = io::Error::last_os_error();
                            // SAFETY: cleaning up FDs.
                            unsafe {
                                libc::close(fd);
                            }
                            unsafe {
                                libc::close(map_fd);
                            }
                            cleanup(&quic_sockets, &intercept_sockets);
                            return Err(DatapathError::Config(format!(
                                "setsockopt(opt={}) failed: {}",
                                opt, err
                            )));
                        }
                    }

                    // Map socket rings BEFORE bind to prevent EBUSY
                    let (rx, tx, fill, comp) = match mmap_socket_rings(fd) {
                        Ok(r) => r,
                        Err(e) => {
                            // SAFETY: cleaning up FDs.
                            unsafe {
                                libc::close(fd);
                            }
                            unsafe {
                                libc::close(map_fd);
                            }
                            cleanup(&quic_sockets, &intercept_sockets);
                            return Err(DatapathError::Config(format!(
                                "mmap_socket_rings failed: {}",
                                e
                            )));
                        }
                    };

                    let addr = sockaddr_xdp {
                        sxdp_family: AF_XDP as u16,
                        sxdp_flags: bind_flags,
                        sxdp_ifindex: ifindex,
                        sxdp_queue_id: queue_id as u32,
                        sxdp_shared_umem_fd: 0,
                    };
                    // SAFETY: bind binds the XSK raw socket.
                    let ret = unsafe {
                        libc::bind(
                            fd,
                            &addr as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "bind(ifindex={}, queue_id={}) failed: {}",
                            ifindex, queue_id, err
                        )));
                    }

                    first_fd_for_iface = Some(fd);

                    if let Err(e) = register_xsk_in_map(map_fd, queue_id as u32, fd) {
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "Failed to register XSK socket FD {} in BPF map: {}",
                            fd, e
                        )));
                    }

                    quic_sockets.push(XskSocketSetup {
                        fd,
                        ifindex,
                        umem_addr: SendPtr(umem.addr),
                        rx,
                        tx,
                        fill,
                        comp,
                    });
                } else {
                    let ring_size: u32 = 2048;
                    for opt in &[
                        XDP_UMEM_FILL_RING,
                        XDP_UMEM_COMPLETION_RING,
                        XDP_RX_RING,
                        XDP_TX_RING,
                    ] {
                        // SAFETY: setsockopt configures ring sizes on secondary socket.
                        let ret = unsafe {
                            libc::setsockopt(
                                fd,
                                SOL_XDP,
                                *opt,
                                &ring_size as *const _ as *const libc::c_void,
                                std::mem::size_of::<u32>() as libc::socklen_t,
                            )
                        };
                        if ret < 0 {
                            let err = io::Error::last_os_error();
                            // SAFETY: cleaning up FDs.
                            unsafe {
                                libc::close(fd);
                            }
                            unsafe {
                                libc::close(map_fd);
                            }
                            cleanup(&quic_sockets, &intercept_sockets);
                            return Err(DatapathError::Config(format!(
                                "setsockopt(secondary opt={}) failed: {}",
                                opt, err
                            )));
                        }
                    }

                    // Map all socket rings BEFORE bind to prevent EBUSY
                    let (rx, tx, fill, comp) = match mmap_socket_rings(fd) {
                        Ok(r) => r,
                        Err(e) => {
                            // SAFETY: cleaning up FDs.
                            unsafe {
                                libc::close(fd);
                            }
                            unsafe {
                                libc::close(map_fd);
                            }
                            cleanup(&quic_sockets, &intercept_sockets);
                            return Err(DatapathError::Config(format!(
                                "mmap_socket_rings failed: {}",
                                e
                            )));
                        }
                    };

                    let addr = sockaddr_xdp {
                        sxdp_family: AF_XDP as u16,
                        sxdp_flags: shared_flags,
                        sxdp_ifindex: ifindex,
                        sxdp_queue_id: queue_id as u32,
                        sxdp_shared_umem_fd: first_fd_for_iface
                            .expect("first_fd_for_iface is missing")
                            as u32,
                    };
                    // SAFETY: bind binds secondary XSK raw socket.
                    let ret = unsafe {
                        libc::bind(
                            fd,
                            &addr as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "bind(secondary ifindex={}, queue_id={}) failed: {}",
                            ifindex, queue_id, err
                        )));
                    }

                    if let Err(e) = register_xsk_in_map(map_fd, queue_id as u32, fd) {
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "Failed to register XSK socket FD {} in BPF map: {}",
                            fd, e
                        )));
                    }

                    quic_sockets.push(XskSocketSetup {
                        fd,
                        ifindex,
                        umem_addr: SendPtr(umem.addr),
                        rx,
                        tx,
                        fill,
                        comp,
                    });
                }
            }
            // SAFETY: close map FD.
            unsafe {
                libc::close(map_fd);
            }
            umems.push(umem);
        }
    }

    // 2. Process intercept_ifindexes
    for &ifindex in intercept_ifindexes {
        let hw_queues = get_interface_queue_count(ifindex);
        let q_count = queue_count.min(hw_queues);
        if q_count == 0 {
            continue;
        }

        let mut buf = [0u8; 32];
        // SAFETY: libc::if_indextoname writes to `buf`.
        let name_ptr =
            unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
        if name_ptr.is_null() {
            cleanup(&quic_sockets, &intercept_sockets);
            return Err(DatapathError::Config(format!(
                "Failed to get interface name for index {}",
                ifindex
            )));
        }
        // SAFETY: name_ptr is null-terminated inside `buf`.
        let ifname = unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_string_lossy();
        let local_ips_path = format!("/sys/fs/bpf/new_proxy_{}/maps/local_ips", ifname);
        if let Err(e) = unsafe { populate_local_ips_map(&local_ips_path) } {
            log::warn!(
                "Failed to populate local_ips map at {}: {}",
                local_ips_path,
                e
            );
        }
        let map_path = format!("/sys/fs/bpf/new_proxy_{}/maps/xsks_map", ifname);

        let map_fd = match bpf_obj_get(&map_path) {
            Ok(fd) => fd,
            Err(e) => {
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!(
                    "Failed to open pinned map at {}: {}",
                    map_path, e
                )));
            }
        };

        let umem_size = 4096 * 4096;
        let umem = match UmemRegion::new(umem_size) {
            Ok(u) => u,
            Err(e) => {
                // SAFETY: close map FD.
                unsafe {
                    libc::close(map_fd);
                }
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!(
                    "Failed to allocate UMEM mmap for ifindex {}: {}",
                    ifindex, e
                )));
            }
        };

        let mut first_fd_for_iface: Option<libc::c_int> = None;

        for queue_id in 0..q_count {
            // SAFETY: socket call with standard constants.
            let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                // SAFETY: close map FD.
                unsafe {
                    libc::close(map_fd);
                }
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!(
                    "socket(AF_XDP) failed: {}",
                    err
                )));
            }

            if first_fd_for_iface.is_none() {
                let umem_reg = xdp_umem_reg {
                    addr: umem.addr as u64,
                    len: umem.size as u64,
                    chunk_size: 4096,
                    headroom: 0,
                    flags: 0,
                };
                // SAFETY: setsockopt configures UMEM.
                let ret = unsafe {
                    libc::setsockopt(
                        fd,
                        SOL_XDP,
                        XDP_UMEM_REG,
                        &umem_reg as *const _ as *const libc::c_void,
                        std::mem::size_of::<xdp_umem_reg>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    // SAFETY: cleaning up FDs.
                    unsafe {
                        libc::close(fd);
                    }
                    unsafe {
                        libc::close(map_fd);
                    }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "setsockopt(XDP_UMEM_REG) failed: {}",
                        err
                    )));
                }

                let ring_size: u32 = 2048;
                for opt in &[
                    XDP_UMEM_FILL_RING,
                    XDP_UMEM_COMPLETION_RING,
                    XDP_RX_RING,
                    XDP_TX_RING,
                ] {
                    // SAFETY: setsockopt configures rings.
                    let ret = unsafe {
                        libc::setsockopt(
                            fd,
                            SOL_XDP,
                            *opt,
                            &ring_size as *const _ as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "setsockopt(opt={}) failed: {}",
                            opt, err
                        )));
                    }
                }

                // Map rings BEFORE bind
                let (rx, tx, fill, comp) = match mmap_socket_rings(fd) {
                    Ok(r) => r,
                    Err(e) => {
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "mmap_socket_rings failed: {}",
                            e
                        )));
                    }
                };

                let addr = sockaddr_xdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: bind_flags,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id as u32,
                    sxdp_shared_umem_fd: 0,
                };
                // SAFETY: bind binds socket.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    // SAFETY: cleaning up FDs.
                    unsafe {
                        libc::close(fd);
                    }
                    unsafe {
                        libc::close(map_fd);
                    }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "bind(ifindex={}, queue_id={}) failed: {}",
                        ifindex, queue_id, err
                    )));
                }

                first_fd_for_iface = Some(fd);

                if let Err(e) = register_xsk_in_map(map_fd, queue_id as u32, fd) {
                    // SAFETY: cleaning up FDs.
                    unsafe {
                        libc::close(fd);
                    }
                    unsafe {
                        libc::close(map_fd);
                    }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "Failed to register XSK socket FD {} in BPF map: {}",
                        fd, e
                    )));
                }

                intercept_sockets.push(XskSocketSetup {
                    fd,
                    ifindex,
                    umem_addr: SendPtr(umem.addr),
                    rx,
                    tx,
                    fill,
                    comp,
                });
            } else {
                let ring_size: u32 = 2048;
                for opt in &[
                    XDP_UMEM_FILL_RING,
                    XDP_UMEM_COMPLETION_RING,
                    XDP_RX_RING,
                    XDP_TX_RING,
                ] {
                    // SAFETY: setsockopt configures ring sizes on secondary socket.
                    let ret = unsafe {
                        libc::setsockopt(
                            fd,
                            SOL_XDP,
                            *opt,
                            &ring_size as *const _ as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "setsockopt(secondary opt={}) failed: {}",
                            opt, err
                        )));
                    }
                }

                // Map all socket rings BEFORE bind to prevent EBUSY
                let (rx, tx, fill, comp) = match mmap_socket_rings(fd) {
                    Ok(r) => r,
                    Err(e) => {
                        // SAFETY: cleaning up FDs.
                        unsafe {
                            libc::close(fd);
                        }
                        unsafe {
                            libc::close(map_fd);
                        }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!(
                            "mmap_socket_rings failed: {}",
                            e
                        )));
                    }
                };

                let addr = sockaddr_xdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: shared_flags,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id as u32,
                    sxdp_shared_umem_fd: first_fd_for_iface.expect("first_fd_for_iface is missing")
                        as u32,
                };
                // SAFETY: bind binds secondary socket.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    // SAFETY: cleaning up FDs.
                    unsafe {
                        libc::close(fd);
                    }
                    unsafe {
                        libc::close(map_fd);
                    }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "bind(secondary ifindex={}, queue_id={}) failed: {}",
                        ifindex, queue_id, err
                    )));
                }

                if let Err(e) = register_xsk_in_map(map_fd, queue_id as u32, fd) {
                    // SAFETY: cleaning up FDs.
                    unsafe {
                        libc::close(fd);
                    }
                    unsafe {
                        libc::close(map_fd);
                    }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!(
                        "Failed to register XSK socket FD {} in BPF map: {}",
                        fd, e
                    )));
                }

                intercept_sockets.push(XskSocketSetup {
                    fd,
                    ifindex,
                    umem_addr: SendPtr(umem.addr),
                    rx,
                    tx,
                    fill,
                    comp,
                });
            }
        }
        // SAFETY: close map FD.
        unsafe {
            libc::close(map_fd);
        }
        umems.push(umem);
    }

    Ok(XskSetup {
        umems,
        quic_sockets,
        intercept_sockets,
    })
}

#[cfg(target_os = "linux")]
fn mac_to_u64(mac: [u8; 6]) -> u64 {
    let mut val = 0u64;
    for (i, &byte) in mac.iter().enumerate() {
        val |= (byte as u64) << (i * 8);
    }
    val
}

#[cfg(target_os = "linux")]
fn u64_to_mac(val: u64) -> [u8; 6] {
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = ((val >> (i * 8)) & 0xFF) as u8;
    }
    mac
}

#[cfg(target_os = "linux")]
fn run_xdp_worker_loop(
    worker_id: usize,
    queue_count: usize,
    quic: XskSocketSetup,
    intercept: XskSocketSetup,
    exit_flag: Arc<std::sync::atomic::AtomicBool>,
    quic_ifname: String,
    _is_server: bool,
    peer_endpoint_ip: Option<std::net::Ipv4Addr>,
    shared_peer_mac: Arc<std::sync::atomic::AtomicU64>,
    shared_peer_ip: Arc<std::sync::atomic::AtomicU32>,
    shared_inner_mac_cache: Arc<RwLock<HashMap<std::net::Ipv4Addr, [u8; 6]>>>,
) {
    let quic_umem_addr = quic.umem_addr.0;
    let intercept_umem_addr = intercept.umem_addr.0;
    let mut quic_rx = quic.rx;
    let mut quic_tx = quic.tx;
    let mut quic_fill = quic.fill;
    let mut quic_comp = quic.comp;
    let mut intercept_rx = intercept.rx;
    let mut intercept_tx = intercept.tx;
    let mut intercept_fill = intercept.fill;
    let mut intercept_comp = intercept.comp;
    let quic_fd = quic.fd;
    let intercept_fd = intercept.fd;

    // Resolve initial routing state
    let local_outer_ip =
        get_interface_ip(&quic_ifname).unwrap_or_else(|| std::net::Ipv4Addr::new(127, 0, 0, 1));
    let local_outer_mac =
        get_interface_mac(&quic_ifname).unwrap_or([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);

    let peer_outer_ip = peer_endpoint_ip;
    let peer_outer_mac = if let Some(ip) = peer_endpoint_ip {
        resolve_mac(&quic_ifname, ip)
    } else {
        None
    };

    // Resolve the intercept interface name and its own MAC from ifindex
    let intercept_ifname = {
        let mut buf = [0u8; 32];
        // SAFETY: libc::if_indextoname writes to `buf` (size 32 > IFNAMSIZ).
        let name_ptr = unsafe {
            libc::if_indextoname(intercept.ifindex, buf.as_mut_ptr() as *mut libc::c_char)
        };
        if !name_ptr.is_null() {
            // SAFETY: name_ptr points to valid null-terminated string in `buf`.
            unsafe { std::ffi::CStr::from_ptr(name_ptr) }
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        }
    };
    let mut intercept_local_macs = HashMap::new();
    if !intercept_ifname.is_empty() {
        if let Some(mac) = get_interface_mac(&intercept_ifname) {
            log::info!("XDP [Worker {}]: Resolved intercept interface {} (ifindex {}) MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                worker_id, intercept_ifname, intercept.ifindex,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            intercept_local_macs.insert(intercept.ifindex, mac);
        }
    }

    let mut route_state = XdpRouteState {
        local_outer_mac,
        peer_outer_mac,
        local_outer_ip,
        peer_outer_ip,
        local_outer_port: 40001 + worker_id as u16, // default port matching BPF filter
        peer_outer_port: 40001 + worker_id as u16,  // default port matching BPF filter
        inner_mac_cache: shared_inner_mac_cache,
        intercept_local_macs,
        last_resolve_attempts: HashMap::new(),
        local_mac_cache: HashMap::new(),
    };

    let chunks_per_worker = 4096 / queue_count;
    let worker_chunk_start = worker_id * chunks_per_worker;
    let rx_fill_start = worker_chunk_start;
    let rx_fill_count = chunks_per_worker / 2;
    let tx_free_start = worker_chunk_start + rx_fill_count;
    let tx_free_count = chunks_per_worker / 2;

    unsafe {
        populate_fill_ring(&mut quic_fill, rx_fill_start as u32, rx_fill_count as u32);
        populate_fill_ring(
            &mut intercept_fill,
            rx_fill_start as u32,
            rx_fill_count as u32,
        );
    }

    let mut quic_free_tx_chunks: Vec<u64> = (tx_free_start..tx_free_start + tx_free_count)
        .map(|i| (i as u64) * 4096)
        .collect();
    let mut intercept_free_tx_chunks: Vec<u64> = (tx_free_start..tx_free_start + tx_free_count)
        .map(|i| (i as u64) * 4096)
        .collect();

    let mut poll_fds = [
        libc::pollfd {
            fd: quic_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: intercept_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let mut consecutive_empty = 0;
    let mut quic_pending_tx = 0;
    let mut intercept_pending_tx = 0;
    let mut quic_spins_since_tx = 0;
    let mut intercept_spins_since_tx = 0;

    let mut quic_rx_cons = unsafe { std::ptr::read_volatile(quic_rx.consumer) };
    let mut quic_tx_prod = unsafe { std::ptr::read_volatile(quic_tx.producer) };
    let mut quic_fill_prod = unsafe { std::ptr::read_volatile(quic_fill.producer) };
    let mut quic_comp_cons = unsafe { std::ptr::read_volatile(quic_comp.consumer) };

    let mut intercept_rx_cons = unsafe { std::ptr::read_volatile(intercept_rx.consumer) };
    let mut intercept_tx_prod = unsafe { std::ptr::read_volatile(intercept_tx.producer) };
    let mut intercept_fill_prod = unsafe { std::ptr::read_volatile(intercept_fill.producer) };
    let mut intercept_comp_cons = unsafe { std::ptr::read_volatile(intercept_comp.consumer) };

    while !exit_flag.load(std::sync::atomic::Ordering::Relaxed) {
        let mut work_done = false;

        unsafe {
            // Process Intercept RX (plaintext packets from app) -> Strip L2, Wrap to QUIC -> Transmit on QUIC TX
            let int_prod = std::ptr::read_volatile(intercept_rx.producer);
            let int_rx_len = int_prod.wrapping_sub(intercept_rx_cons);
            if int_rx_len > 0 {
                // Sync peer IP/MAC from shared state if ours is None
                if route_state.peer_outer_ip.is_none() {
                    let ip_val = shared_peer_ip.load(std::sync::atomic::Ordering::Relaxed);
                    if ip_val != 0 {
                        route_state.peer_outer_ip = Some(std::net::Ipv4Addr::from(ip_val));
                    }
                }
                if route_state.peer_outer_ip.is_some() && route_state.peer_outer_mac.is_none() {
                    let mac_val = shared_peer_mac.load(std::sync::atomic::Ordering::Relaxed);
                    if mac_val != 0 {
                        route_state.peer_outer_mac = Some(u64_to_mac(mac_val));
                    } else if let Some(ip) = route_state.peer_outer_ip {
                        if let Some(mac) = resolve_mac(&quic_ifname, ip) {
                            route_state.peer_outer_mac = Some(mac);
                            shared_peer_mac
                                .store(mac_to_u64(mac), std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }

                let tx_produced = process_rx_ring(
                    &mut intercept_rx,
                    &mut intercept_rx_cons,
                    &mut intercept_fill,
                    &mut intercept_fill_prod,
                    intercept_umem_addr,
                    |pkt_data, out_slice| {
                        // Strip Ethernet header
                        if let Some((eth_header, ip_payload)) = EthernetHeader::parse(pkt_data) {
                            if eth_header.ether_type == 0x0800 {
                                // Learn inner source IP -> MAC mapping
                                if let Some((src_ip, dst_ip)) = parse_ip_src_dst(ip_payload) {
                                    log::debug!(
                                        "XDP [Worker {}]: Intercept RX packet from {} to {}",
                                        worker_id,
                                        src_ip,
                                        dst_ip
                                    );
                                    let needs_local_update =
                                        match route_state.local_mac_cache.get(&src_ip) {
                                            Some(&mac) => mac != eth_header.src_mac,
                                            None => true,
                                        };
                                    if needs_local_update {
                                        route_state
                                            .local_mac_cache
                                            .insert(src_ip, eth_header.src_mac);
                                        let needs_shared_update = {
                                            let cache = route_state.inner_mac_cache.read();
                                            match cache.get(&src_ip) {
                                                Some(&mac) => mac != eth_header.src_mac,
                                                None => true,
                                            }
                                        };
                                        if needs_shared_update {
                                            route_state
                                                .inner_mac_cache
                                                .write()
                                                .insert(src_ip, eth_header.src_mac);
                                        }
                                    }
                                    route_state
                                        .intercept_local_macs
                                        .insert(intercept.ifindex, eth_header.dst_mac);
                                }

                                // Wrap plaintext to QUIC UDP
                                if let Some(peer_outer_ip) = route_state.peer_outer_ip {
                                    if let Some(peer_outer_mac) = route_state.peer_outer_mac {
                                        let res = wrap_plaintext_to_quic_slice(
                                            ip_payload,
                                            peer_outer_mac,
                                            route_state.local_outer_mac,
                                            peer_outer_ip,
                                            route_state.local_outer_ip,
                                            route_state.peer_outer_port,
                                            route_state.local_outer_port,
                                            out_slice,
                                        );
                                        if let Some(written_len) = res {
                                            log::debug!("XDP [Worker {}]: Wrapped and sent packet of len {} (outer src {} to dst {}, outer src mac {:?} to dst mac {:?})",
                                                worker_id, written_len, route_state.local_outer_ip, peer_outer_ip, route_state.local_outer_mac, peer_outer_mac);
                                        }
                                        res
                                    } else {
                                        log::warn!("XDP [Worker {}]: Cannot wrap packet: peer_outer_mac is None", worker_id);
                                        None
                                    }
                                } else {
                                    log::warn!("XDP [Worker {}]: Cannot wrap packet: peer_outer_ip is None", worker_id);
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    },
                    &mut quic_tx,
                    &mut quic_tx_prod,
                    &mut quic_comp,
                    &mut quic_comp_cons,
                    &mut quic_free_tx_chunks,
                    quic_umem_addr,
                );
                quic_pending_tx += tx_produced;
                if tx_produced > 0 {
                    quic_spins_since_tx = 0;
                } else {
                    quic_spins_since_tx += 1;
                }
                work_done = true;
            } else if quic_pending_tx > 0 {
                quic_spins_since_tx += 1;
            }

            // Process QUIC RX (encrypted QUIC packets from NIC) -> Unwrap / Decrypt -> Prepend L2 -> Transmit on Intercept TX
            let quic_prod = std::ptr::read_volatile(quic_rx.producer);
            let quic_rx_len = quic_prod.wrapping_sub(quic_rx_cons);
            if quic_rx_len > 0 {
                let tx_produced = process_rx_ring(
                    &mut quic_rx,
                    &mut quic_rx_cons,
                    &mut quic_fill,
                    &mut quic_fill_prod,
                    quic_umem_addr,
                    |pkt_data, out_slice| {
                        log::debug!(
                            "XDP [Worker {}]: Received QUIC RX packet of len {}",
                            worker_id,
                            pkt_data.len()
                        );
                        if let Some((info, plaintext_ip)) = unwrap_quic_to_plaintext_slice(pkt_data)
                        {
                            log::debug!("XDP [Worker {}]: Unwrapped outer src {} to dst {}, outer src mac {:?} to dst mac {:?}",
                                worker_id, info.src_ip, info.dst_ip, info.src_mac, info.dst_mac);
                            // Learn/Update peer outer state
                            route_state.peer_outer_mac = Some(info.src_mac);
                            route_state.local_outer_mac = info.dst_mac;
                            route_state.peer_outer_ip = Some(info.src_ip);
                            route_state.local_outer_ip = info.dst_ip;
                            route_state.peer_outer_port = info.src_port;
                            route_state.local_outer_port = info.dst_port;

                            // Update shared state
                            shared_peer_ip.store(
                                u32::from(info.src_ip),
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            shared_peer_mac.store(
                                mac_to_u64(info.src_mac),
                                std::sync::atomic::Ordering::Relaxed,
                            );

                            // Parse destination IP to route to correct local client MAC
                            if let Some((src_ip, inner_dst_ip)) = parse_ip_src_dst(plaintext_ip) {
                                let src_mac = route_state
                                    .intercept_local_macs
                                    .get(&intercept.ifindex)
                                    .cloned()
                                    .unwrap_or([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
                                // Look up the destination IP in thread-local cache, fallback to shared cache, then ARP
                                let dst_mac = route_state
                                    .local_mac_cache
                                    .get(&inner_dst_ip)
                                    .cloned()
                                    .or_else(|| {
                                        let shared_mac = route_state
                                            .inner_mac_cache
                                            .read()
                                            .get(&inner_dst_ip)
                                            .cloned();
                                        if let Some(mac) = shared_mac {
                                            route_state.local_mac_cache.insert(inner_dst_ip, mac);
                                        }
                                        shared_mac
                                    });
                                let dst_mac = match dst_mac {
                                    Some(mac) => mac,
                                    None => {
                                        let mut attempt_allowed = true;
                                        if let Some(&last_time) =
                                            route_state.last_resolve_attempts.get(&inner_dst_ip)
                                        {
                                            if std::time::Instant::now().duration_since(last_time)
                                                < std::time::Duration::from_secs(1)
                                            {
                                                attempt_allowed = false;
                                            }
                                        }
                                        if attempt_allowed {
                                            route_state
                                                .last_resolve_attempts
                                                .insert(inner_dst_ip, std::time::Instant::now());
                                            let resolved =
                                                resolve_mac(&intercept_ifname, inner_dst_ip)
                                                    .or_else(|| {
                                                        get_interface_mac_by_ip(inner_dst_ip)
                                                    });
                                            if let Some(mac) = resolved {
                                                route_state
                                                    .local_mac_cache
                                                    .insert(inner_dst_ip, mac);
                                                route_state
                                                    .inner_mac_cache
                                                    .write()
                                                    .insert(inner_dst_ip, mac);
                                                mac
                                            } else {
                                                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
                                            }
                                        } else {
                                            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
                                        }
                                    }
                                };

                                log::debug!("XDP [Worker {}]: Sending plaintext inner from {} to {} (dest MAC {:?}, local MAC {:?}) on intercept interface",
                                    worker_id, src_ip, inner_dst_ip, dst_mac, src_mac);

                                if out_slice.len() >= 14 + plaintext_ip.len() {
                                    out_slice[0..6].copy_from_slice(&dst_mac);
                                    out_slice[6..12].copy_from_slice(&src_mac);
                                    out_slice[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
                                    out_slice[14..14 + plaintext_ip.len()]
                                        .copy_from_slice(plaintext_ip);
                                    Some(14 + plaintext_ip.len())
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    },
                    &mut intercept_tx,
                    &mut intercept_tx_prod,
                    &mut intercept_comp,
                    &mut intercept_comp_cons,
                    &mut intercept_free_tx_chunks,
                    intercept_umem_addr,
                );
                intercept_pending_tx += tx_produced;
                if tx_produced > 0 {
                    intercept_spins_since_tx = 0;
                } else {
                    intercept_spins_since_tx += 1;
                }
                work_done = true;
            } else if intercept_pending_tx > 0 {
                intercept_spins_since_tx += 1;
            }

            // Flush pending TX packets if we've accumulated enough or if we spun enough/went idle
            if quic_pending_tx >= 256
                || (quic_pending_tx > 0 && (quic_spins_since_tx >= 500 || !work_done))
            {
                libc::sendto(
                    quic_fd,
                    std::ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null(),
                    0,
                );
                quic_pending_tx = 0;
                quic_spins_since_tx = 0;
            }
            if intercept_pending_tx >= 256
                || (intercept_pending_tx > 0 && (intercept_spins_since_tx >= 500 || !work_done))
            {
                libc::sendto(
                    intercept_fd,
                    std::ptr::null(),
                    0,
                    libc::MSG_DONTWAIT,
                    std::ptr::null(),
                    0,
                );
                intercept_pending_tx = 0;
                intercept_spins_since_tx = 0;
            }
        }

        if work_done {
            consecutive_empty = 0;
        } else {
            consecutive_empty += 1;
            if consecutive_empty > 10_000 {
                // Flush any remaining pending packets before going to sleep!
                if quic_pending_tx > 0 {
                    unsafe {
                        libc::sendto(
                            quic_fd,
                            std::ptr::null(),
                            0,
                            libc::MSG_DONTWAIT,
                            std::ptr::null(),
                            0,
                        );
                    }
                    quic_pending_tx = 0;
                    quic_spins_since_tx = 0;
                }
                if intercept_pending_tx > 0 {
                    unsafe {
                        libc::sendto(
                            intercept_fd,
                            std::ptr::null(),
                            0,
                            libc::MSG_DONTWAIT,
                            std::ptr::null(),
                            0,
                        );
                    }
                    intercept_pending_tx = 0;
                    intercept_spins_since_tx = 0;
                }

                // Completely idle: fall back to libc::poll to sleep
                for pfd in &mut poll_fds {
                    pfd.revents = 0;
                }
                let ret = unsafe {
                    libc::poll(
                        poll_fds.as_mut_ptr(),
                        poll_fds.len() as libc::nfds_t,
                        5, // 5ms timeout
                    )
                };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::Interrupted {
                        log::error!("XDP Worker {} libc::poll error: {}", worker_id, err);
                        break;
                    }
                }
                consecutive_empty = 0;
            } else if consecutive_empty > 1_000 {
                // Intermediate pause: cooperatively yield the CPU every 100 spins
                if consecutive_empty % 100 == 0 {
                    std::thread::yield_now();
                } else {
                    std::hint::spin_loop();
                }
            } else {
                // Active burst pause: pure low-latency spin
                std::hint::spin_loop();
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl XdpDatapath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: GatewayConfig,
        interface_name: String,
        runtime_mode: RuntimeMode,
        fixed_client_quic_data_port_count: Option<usize>,
        peer_telemetries: Vec<Arc<TelemetryRegistry>>,
        worker_telemetry_registry: Arc<crate::telemetry::WorkerTelemetryRegistry>,
        gateway_state: Arc<parking_lot::RwLock<crate::GatewayState>>,
        peer_secrets: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        session_cache: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        auth_nonce_cache: Arc<parking_lot::Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
        shared_quic_registry: crate::quic_pool::PeerConnRegistry,
        client_quic_pools: PeerQuicPools,
        client_quic_data_port_baseline: ClientQuicDataPortBaseline,
        peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Result<Self, DatapathError> {
        let quic_interface = match &config.xdp.quic_interface {
            Some(ifname) => ifname.clone(),
            None => {
                return Err(DatapathError::Config(
                    "quic_interface must be configured for XDP mode".into(),
                ))
            }
        };

        let quic_ifindex = unsafe {
            let c_ifname = CString::new(quic_interface.as_str())
                .map_err(|e| DatapathError::Config(e.to_string()))?;
            let index = libc::if_nametoindex(c_ifname.as_ptr());
            if index == 0 {
                return Err(DatapathError::Config(format!(
                    "quic_interface '{}' not found",
                    quic_interface
                )));
            }
            index
        };

        let intercept_names = if config.xdp.intercept_interfaces.is_empty() {
            vec![interface_name.clone()]
        } else {
            config.xdp.intercept_interfaces.clone()
        };

        let mut intercept_ifindexes = Vec::new();
        for ifname in &intercept_names {
            let index = unsafe {
                let c_ifname = CString::new(ifname.as_str())
                    .map_err(|e| DatapathError::Config(e.to_string()))?;
                let index = libc::if_nametoindex(c_ifname.as_ptr());
                if index == 0 {
                    return Err(DatapathError::Config(format!(
                        "intercept_interface '{}' not found",
                        ifname
                    )));
                }
                index
            };
            intercept_ifindexes.push(index);
        }

        let mut bpf_managers = Vec::new();
        let manager = super::loader::BpfLinkManager::new(&quic_interface, &config.xdp.xdp_mode)
            .map_err(|e| {
                DatapathError::Config(format!("Failed to load BPF for {}: {}", quic_interface, e))
            })?;
        bpf_managers.push(manager);

        for ifname in &intercept_names {
            if ifname == &quic_interface {
                continue;
            }
            let manager = super::loader::BpfLinkManager::new(ifname, &config.xdp.xdp_mode)
                .map_err(|e| {
                    DatapathError::Config(format!("Failed to load BPF for {}: {}", ifname, e))
                })?;
            bpf_managers.push(manager);
        }

        Ok(Self {
            config,
            interface_name,
            runtime_mode,
            fixed_client_quic_data_port_count,
            peer_telemetries,
            worker_telemetry_registry,
            gateway_state,
            peer_secrets,
            session_cache,
            auth_nonce_cache,
            shared_quic_registry,
            client_quic_pools,
            client_quic_data_port_baseline,
            peer_mutation_lock,
            quic_ifindex,
            intercept_ifindexes,
            _bpf_managers: bpf_managers,
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl XdpDatapath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _config: GatewayConfig,
        _interface_name: String,
        _runtime_mode: RuntimeMode,
        _fixed_client_quic_data_port_count: Option<usize>,
        _peer_telemetries: Vec<Arc<TelemetryRegistry>>,
        _worker_telemetry_registry: Arc<crate::telemetry::WorkerTelemetryRegistry>,
        _gateway_state: Arc<parking_lot::RwLock<crate::GatewayState>>,
        _peer_secrets: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        _session_cache: Arc<parking_lot::RwLock<HashMap<[u8; 32], [u8; 32]>>>,
        _auth_nonce_cache: Arc<parking_lot::Mutex<HashMap<[u8; 32], crate::control::NonceCache>>>,
        _shared_quic_registry: crate::quic_pool::PeerConnRegistry,
        _client_quic_pools: PeerQuicPools,
        _client_quic_data_port_baseline: ClientQuicDataPortBaseline,
        _peer_mutation_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Result<Self, DatapathError> {
        Err(DatapathError::Config(
            "XDP is only supported on Linux".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl Datapath for XdpDatapath {
    async fn run_loop(
        self: Arc<Self>,
        dp_snapshot: Arc<ArcSwap<crate::L4DataPlaneSnapshot>>,
        exit_notify: Arc<tokio::sync::Notify>,
    ) -> Result<(), DatapathError> {
        if self.runtime_mode == RuntimeMode::Server {
            log::info!("------------------------------------------------------");
            log::info!("         STARTING GATEWAY IN [ SERVER MODE ]         ");
            log::info!("------------------------------------------------------");

            let _listen_port = match self.config.interface.listen_port {
                Some(port) => port,
                None => {
                    log::error!("Server userspace XDP requires Interface.ListenPort");
                    return Err(DatapathError::Config(
                        "Server userspace XDP requires Interface.ListenPort".into(),
                    ));
                }
            };

            let queue_count = self.config.quic_pool.listen_ports.len();
            let queue_count = if queue_count == 0 { 1 } else { queue_count };

            // Open TUN device for the server plaintext L3 datapath
            let tun_fds = match crate::tun_device::open_tun(&self.interface_name, queue_count) {
                Ok(fds) => fds,
                Err(e) => {
                    log::error!("Failed to open server TUN device: {}", e);
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Io(e));
                }
            };

            let mut fd_guard = FdsGuard { fds: tun_fds };

            if let Err(e) = setup_routes(&self.config, &self.interface_name) {
                log::error!("Failed to setup userspace routes: {}", e);
                cleanup_runtime(&self.config, &self.interface_name);
                return Err(DatapathError::Config(e));
            }

            let (quic_certs, quic_key) = match generate_self_signed_cert() {
                Ok(cert) => cert,
                Err(e) => {
                    log::error!("Failed to generate QUIC certificate: {}", e);
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Config(format!(
                        "Failed to generate QUIC certificate: {}",
                        e
                    )));
                }
            };
            let quic_cert_sha256 = match cert_sha256(&quic_certs) {
                Ok(fingerprint) => fingerprint,
                Err(e) => {
                    log::error!("Failed to fingerprint QUIC certificate: {}", e);
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Config(format!(
                        "Failed to fingerprint QUIC certificate: {}",
                        e
                    )));
                }
            };

            let listen_control_port = self
                .config
                .interface
                .listen_control_port
                .or(self.config.interface.listen_port)
                .expect("Server config validation failed to enforce control port");

            let control_server = ControlServer::new(
                listen_control_port,
                self.peer_secrets.clone(),
                self.config.quic_pool.listen_ports.clone(),
                self.config.quic_pool.public_ipv4.clone(),
                self.config.quic_pool.public_ipv6.clone(),
                quic_cert_sha256,
                self.session_cache.clone(),
            );

            let control_task = match control_server.start().await {
                Ok(handle) => handle,
                Err(e) => {
                    log::error!("Control plane server failed to start: {}", e);
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Config(format!(
                        "Control plane server failed to start: {}",
                        e
                    )));
                }
            };

            let setup = match setup_xsk_sockets(
                self.quic_ifindex,
                &self.intercept_ifindexes,
                queue_count,
                &self.config.xdp.xdp_mode,
            ) {
                Ok(s) => s,
                Err(e) => {
                    cleanup_runtime(&self.config, &self.interface_name);
                    control_task.abort();
                    return Err(e);
                }
            };

            log::info!(
                "run_loop: server setup quic_sockets={:?}, intercept_sockets={:?}",
                setup.quic_sockets,
                setup.intercept_sockets
            );

            let mut worker_preps = Vec::new();
            for worker_id in 0..fd_guard.fds.len() {
                let fd = fd_guard.fds[worker_id];
                let tun_io = Arc::new(match crate::tun_io::AsyncTunIo::new(fd) {
                    Ok(io) => {
                        fd_guard.fds[worker_id] = -1;
                        io
                    }
                    Err(e) => {
                        log::error!("Failed to wrap server TUN FD in AsyncTunIo: {}", e);
                        cleanup_runtime(&self.config, &self.interface_name);
                        control_task.abort();
                        return Err(DatapathError::Io(e));
                    }
                });

                let local_port = self.config.quic_pool.listen_ports[worker_id];
                let udp_socket = match setup_udp_socket(Some(local_port)) {
                    Ok(s) => s,
                    Err(e) => {
                        cleanup_runtime(&self.config, &self.interface_name);
                        control_task.abort();
                        return Err(e);
                    }
                };

                let packet_buffer_size =
                    crate::config::packet_buffer_size_for_mtu(self.config.interface.mtu);
                let endpoint =
                    match setup_server_endpoint(&quic_certs, &quic_key, packet_buffer_size) {
                        Ok(ep) => ep,
                        Err(e) => {
                            cleanup_runtime(&self.config, &self.interface_name);
                            control_task.abort();
                            return Err(DatapathError::Config(e));
                        }
                    };

                worker_preps.push((tun_io, udp_socket, endpoint));
            }

            let exit_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut join_handles = Vec::new();

            let shared_peer_mac = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let shared_peer_ip = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let shared_inner_mac_cache = Arc::new(RwLock::new(HashMap::new()));

            for worker_id in 0..queue_count {
                let exit_notify_clone = exit_notify.clone();
                let exit_flag_clone = exit_flag.clone();
                let quic_setup = setup.quic_sockets[worker_id % setup.quic_sockets.len()].clone();
                let intercept_setup =
                    setup.intercept_sockets[worker_id % setup.intercept_sockets.len()].clone();
                let quic_ifname = self.config.xdp.quic_interface.clone().unwrap_or_default();
                let shared_mac_clone = shared_peer_mac.clone();
                let shared_ip_clone = shared_peer_ip.clone();
                let shared_inner_mac_cache_clone = shared_inner_mac_cache.clone();

                let handle = std::thread::Builder::new()
                    .name(format!("new-proxy-server-xdp-worker-{}", worker_id))
                    .spawn(move || {
                        let _panic_guard = WorkerPanicGuard {
                            exit_notify: exit_notify_clone,
                        };
                        run_xdp_worker_loop(
                            worker_id,
                            queue_count,
                            quic_setup,
                            intercept_setup,
                            exit_flag_clone,
                            quic_ifname,
                            true,
                            None,
                            shared_mac_clone,
                            shared_ip_clone,
                            shared_inner_mac_cache_clone,
                        );
                    })
                    .expect("Failed to spawn XDP worker thread");
                join_handles.push(handle);
            }

            let mut l3_tasks = Vec::new();
            for (worker_id, (tun_io, udp_socket, endpoint)) in worker_preps.into_iter().enumerate()
            {
                let mut worker = crate::rtc_loop::RtcWorker::new(
                    tun_io,
                    worker_id,
                    crate::rtc_loop::WorkerRole::Server,
                    crate::rtc_loop::RtcWorkerConfig {
                        mtu: self.config.interface.mtu,
                    },
                    udp_socket,
                    endpoint,
                    Some(self.session_cache.clone()),
                    Some(self.auth_nonce_cache.clone()),
                    Some(self.shared_quic_registry.clone()),
                );
                worker.set_worker_stats(self.worker_telemetry_registry.get_or_create(worker_id));
                worker.set_peer_telemetry(self.peer_telemetries[worker_id].clone());

                let thread = spawn_worker_thread(
                    worker,
                    worker_id,
                    "server",
                    dp_snapshot.clone(),
                    exit_notify.clone(),
                );
                l3_tasks.push(thread);
            }

            tokio::select! {
                _ = crate::wait_for_shutdown() => {},
                _ = exit_notify.notified() => {
                    log::error!("A server worker thread exited prematurely; shutting down.");
                }
            }

            control_task.abort();
            exit_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            for handle in join_handles {
                let _ = handle.join();
            }
            cleanup_runtime(&self.config, &self.interface_name);
        } else {
            log::info!("------------------------------------------------------");
            log::info!("         STARTING GATEWAY IN [ CLIENT MODE ]         ");
            log::info!("------------------------------------------------------");

            let proxy_peers = crate::proxy_peers(&self.config);
            let mut initial_pool_failures = 0usize;
            let mut startup_quic_data_port_count = self.fixed_client_quic_data_port_count;

            for peer in &proxy_peers {
                match build_peer_quic_pool(self.config.interface.private_key, peer).await {
                    Ok(pool) => {
                        if let Err(e) = crate::record_startup_quic_data_port_count(
                            &mut startup_quic_data_port_count,
                            pool.endpoint_count(),
                        ) {
                            pool.shutdown(b"QUIC data port count mismatch");
                            return Err(DatapathError::Config(e));
                        }
                        if let Err(e) = crate::validate_client_quic_data_port_count(
                            &self.client_quic_pools,
                            pool.endpoint_count(),
                        ) {
                            pool.shutdown(b"QUIC data port count mismatch");
                            return Err(DatapathError::Config(e));
                        }
                        self.client_quic_pools.write().insert(peer.public_key, pool);
                    }
                    Err(e) => {
                        initial_pool_failures += 1;
                        if let Some(data_port_count) = e.data_port_count() {
                            if let Err(mismatch) = crate::record_startup_quic_data_port_count(
                                &mut startup_quic_data_port_count,
                                data_port_count,
                            ) {
                                return Err(DatapathError::Config(mismatch));
                            }
                        }
                        log::warn!(
                            "Failed to establish initial QUIC pool for peer {}; starting in WireGuard L3 fallback and retrying in background: {}",
                            crate::app_config::encode_base64_32(&peer.public_key),
                            e
                        );
                    }
                }
            }

            if initial_pool_failures > 0 {
                self.gateway_state.write().userspace_tcp_offload_enabled = false;
            }

            crate::publish_l4_data_plane_snapshot(
                &dp_snapshot,
                &self.gateway_state,
                &self.client_quic_pools,
            );
            let quic_data_port_count = crate::client_quic_data_port_count(
                &self.client_quic_pools,
                startup_quic_data_port_count,
            );
            let queue_count = crate::effective_client_tun_queues(quic_data_port_count.unwrap_or(0));
            crate::record_initial_client_quic_data_port_baseline(
                &self.client_quic_data_port_baseline,
                quic_data_port_count,
            );

            let queue_count = if queue_count == 0 { 1 } else { queue_count };

            // Open TUN device for the client L3 datapath
            let tun_fds = match crate::tun_device::open_tun(&self.interface_name, queue_count) {
                Ok(fds) => fds,
                Err(e) => {
                    log::error!("Failed to open TUN device: {}", e);
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Io(e));
                }
            };
            let mut fd_guard = FdsGuard { fds: tun_fds };

            if let Err(e) = setup_routes(&self.config, &self.interface_name) {
                log::error!("Failed to setup userspace routes: {}", e);
                cleanup_runtime(&self.config, &self.interface_name);
                return Err(DatapathError::Config(e));
            }

            let setup = setup_xsk_sockets(
                self.quic_ifindex,
                &self.intercept_ifindexes,
                queue_count,
                &self.config.xdp.xdp_mode,
            )?;

            log::info!(
                "run_loop: client setup quic_sockets={:?}, intercept_sockets={:?}",
                setup.quic_sockets,
                setup.intercept_sockets
            );

            let mut worker_preps = Vec::new();
            for worker_id in 0..fd_guard.fds.len() {
                let fd = fd_guard.fds[worker_id];
                let tun_io = Arc::new(match crate::tun_io::AsyncTunIo::new(fd) {
                    Ok(io) => {
                        fd_guard.fds[worker_id] = -1;
                        io
                    }
                    Err(e) => {
                        log::error!("Failed to wrap TUN FD in AsyncTunIo: {}", e);
                        cleanup_runtime(&self.config, &self.interface_name);
                        return Err(DatapathError::Io(e));
                    }
                });

                let udp_socket = match setup_udp_socket(None) {
                    Ok(s) => s,
                    Err(e) => {
                        cleanup_runtime(&self.config, &self.interface_name);
                        return Err(e);
                    }
                };

                let endpoint = setup_client_endpoint();
                worker_preps.push((tun_io, udp_socket, endpoint));
            }

            let userspace_tcp_failover_task = crate::start_userspace_tcp_failover_manager(
                self.gateway_state.clone(),
                self.client_quic_pools.clone(),
                dp_snapshot.clone(),
                self.config.interface.private_key,
                self.client_quic_data_port_baseline.clone(),
                self.peer_mutation_lock.clone(),
            );

            let exit_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut join_handles = Vec::new();

            let peer_endpoint_ip = proxy_peers
                .first()
                .and_then(|p| p.endpoint.as_ref().map(|ep| ep.ip()))
                .and_then(|ip| match ip {
                    std::net::IpAddr::V4(ipv4) => Some(ipv4),
                    _ => None,
                });

            let shared_peer_mac = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let shared_peer_ip = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let shared_inner_mac_cache = Arc::new(RwLock::new(HashMap::new()));

            let quic_ifname = self.config.xdp.quic_interface.clone().unwrap_or_default();
            if let Some(ip) = peer_endpoint_ip {
                shared_peer_ip.store(u32::from(ip), std::sync::atomic::Ordering::Relaxed);
                if let Some(mac) = resolve_mac(&quic_ifname, ip) {
                    shared_peer_mac.store(mac_to_u64(mac), std::sync::atomic::Ordering::Relaxed);
                }
            }

            for worker_id in 0..queue_count {
                let exit_notify_clone = exit_notify.clone();
                let exit_flag_clone = exit_flag.clone();
                let quic_setup = setup.quic_sockets[worker_id % setup.quic_sockets.len()].clone();
                let intercept_setup =
                    setup.intercept_sockets[worker_id % setup.intercept_sockets.len()].clone();
                let quic_ifname = self.config.xdp.quic_interface.clone().unwrap_or_default();
                let peer_ip = peer_endpoint_ip;
                let shared_mac_clone = shared_peer_mac.clone();
                let shared_ip_clone = shared_peer_ip.clone();
                let shared_inner_mac_cache_clone = shared_inner_mac_cache.clone();

                let handle = std::thread::Builder::new()
                    .name(format!("new-proxy-client-xdp-worker-{}", worker_id))
                    .spawn(move || {
                        let _panic_guard = WorkerPanicGuard {
                            exit_notify: exit_notify_clone,
                        };
                        run_xdp_worker_loop(
                            worker_id,
                            queue_count,
                            quic_setup,
                            intercept_setup,
                            exit_flag_clone,
                            quic_ifname,
                            false,
                            peer_ip,
                            shared_mac_clone,
                            shared_ip_clone,
                            shared_inner_mac_cache_clone,
                        );
                    })
                    .expect("Failed to spawn XDP worker thread");
                join_handles.push(handle);
            }

            let mut worker_tasks = Vec::new();
            for (worker_id, (tun_io, udp_socket, endpoint)) in worker_preps.into_iter().enumerate()
            {
                let mut worker = crate::rtc_loop::RtcWorker::new(
                    tun_io,
                    worker_id,
                    crate::rtc_loop::WorkerRole::Client,
                    crate::rtc_loop::RtcWorkerConfig {
                        mtu: self.config.interface.mtu,
                    },
                    udp_socket,
                    endpoint,
                    None,
                    None,
                    Some(self.shared_quic_registry.clone()),
                );
                worker.set_worker_stats(self.worker_telemetry_registry.get_or_create(worker_id));
                worker.set_peer_telemetry(self.peer_telemetries[worker_id].clone());

                let thread = spawn_worker_thread(
                    worker,
                    worker_id,
                    "client",
                    dp_snapshot.clone(),
                    exit_notify.clone(),
                );
                worker_tasks.push(thread);
            }

            tokio::select! {
                _ = crate::wait_for_shutdown() => {},
                _ = exit_notify.notified() => {
                    log::error!("A client worker thread exited prematurely; shutting down.");
                }
            }

            exit_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            for handle in join_handles {
                let _ = handle.join();
            }
            userspace_tcp_failover_task.abort();
            cleanup_runtime(&self.config, &self.interface_name);
        }

        Ok(())
    }

    fn get_stats(&self) -> DatapathStats {
        let snapshots = self.worker_telemetry_registry.snapshot();
        let total_rx_bytes = snapshots
            .iter()
            .map(|s| s.tun_rx_bytes + s.tcp_offload_bytes + s.l3_bytes)
            .sum();
        DatapathStats {
            rx_bytes: total_rx_bytes,
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[async_trait::async_trait]
impl Datapath for XdpDatapath {
    async fn run_loop(
        self: Arc<Self>,
        _dp_snapshot: Arc<ArcSwap<crate::L4DataPlaneSnapshot>>,
        _exit_notify: Arc<tokio::sync::Notify>,
    ) -> Result<(), DatapathError> {
        Err(DatapathError::Config(
            "XDP is only supported on Linux".into(),
        ))
    }

    fn get_stats(&self) -> DatapathStats {
        DatapathStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_config::RuntimeMode;
    use crate::config::{GatewayConfig, InterfaceConfig, QUICPoolConfig, XdpConfig};
    use crate::telemetry::{TelemetryRegistry, WorkerTelemetryRegistry};
    use parking_lot::RwLock;
    use std::sync::Arc;

    fn dummy_config() -> GatewayConfig {
        GatewayConfig {
            interface: InterfaceConfig {
                private_key: [1u8; 32],
                addresses: vec!["10.0.0.1/24".parse().unwrap()],
                listen_port: Some(40000),
                listen_control_port: Some(40001),
                mtu: 1400,
                table: None,
                pre_script: None,
                post_script: None,
                mode: "af_xdp".to_string(),
            },
            peers: Vec::new(),
            quic_pool: QUICPoolConfig {
                public_ipv4: None,
                public_ipv6: None,
                listen_ports: vec![40002],
            },
            xdp: XdpConfig {
                quic_interface: Some("non_existent_dev_abc".to_string()),
                intercept_interfaces: vec!["lo".to_string()],
                xdp_mode: "native".to_string(),
            },
        }
    }

    #[test]
    fn test_xdp_datapath_fails_gracefully() {
        let config = dummy_config();
        let peer_telemetries = vec![Arc::new(TelemetryRegistry::new())];
        let worker_telemetry_registry = Arc::new(WorkerTelemetryRegistry::new());
        let gateway_state = Arc::new(RwLock::new(crate::GatewayState {
            config: config.clone(),
            router: crate::routing::AllowedIPsRouter::new(),
            userspace_tcp_offload_enabled: true,
        }));
        let peer_secrets = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let session_cache = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let auth_nonce_cache = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
        let shared_quic_registry = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let client_quic_pools = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let client_quic_data_port_baseline = Arc::new(parking_lot::Mutex::new(0));
        let peer_mutation_lock = Arc::new(tokio::sync::Mutex::new(()));

        let res = XdpDatapath::new(
            config,
            "non_existent_dev_abc".to_string(),
            RuntimeMode::Server,
            None,
            peer_telemetries,
            worker_telemetry_registry,
            gateway_state,
            peer_secrets,
            session_cache,
            auth_nonce_cache,
            shared_quic_registry,
            client_quic_pools,
            client_quic_data_port_baseline,
            peer_mutation_lock,
        );
        assert!(res.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_ring_produce_consume() {
        let mut producer = 0u32;
        let mut consumer = 0u32;
        let mut descs = vec![0u64; 16];

        let mut ring = XskRing {
            producer: &mut producer as *mut u32,
            consumer: &mut consumer as *mut u32,
            desc: descs.as_mut_ptr() as *mut u8,
            mask: 15,
            size: 16,
        };

        unsafe {
            assert_eq!(ring.free_slots(), 16);
            ring.write_fill_addr(0, 0x1000);
            ring.write_fill_addr(1, 0x2000);
            ring.produce(2);
            assert_eq!(ring.free_slots(), 14);
            assert_eq!(*ring.producer, 2);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_bpf_map_registration_fail_on_invalid_fd() {
        let res = register_xsk_in_map(-1, 0, -1);
        assert!(res.is_err());
    }

    #[test]
    fn test_ethernet_header_processing() {
        let mut packet = vec![0u8; 100];
        packet[0..6].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        packet[6..12].copy_from_slice(&[0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
        packet[12..14].copy_from_slice(&[0x08, 0x00]);
        packet[14..18].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let parsed = EthernetHeader::parse(&packet).unwrap();
        assert_eq!(parsed.0.dst_mac, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(parsed.0.src_mac, [0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
        assert_eq!(parsed.0.ether_type, 0x0800);
        assert_eq!(&parsed.1[0..4], &[0xaa, 0xbb, 0xcc, 0xdd]);

        let mut out_buf = vec![0u8; 14];
        let bytes_written = parsed.0.serialize(&mut out_buf).unwrap();
        assert_eq!(bytes_written, 14);
        assert_eq!(&out_buf[0..14], &packet[0..14]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_resolve_mac() {
        // Test basic gateway lookup on loopback (should be None or parsed)
        let gw = get_gateway_ip("lo");
        println!("lo gateway: {:?}", gw);

        // Test resolving loopback IP
        let mac = resolve_mac("lo", std::net::Ipv4Addr::new(127, 0, 0, 1));
        println!("lo 127.0.0.1 MAC: {:?}", mac);

        // Test resolving uwg-c gateway
        if let Some(gw_uwg) = get_gateway_ip("uwg-c") {
            println!("uwg-c gateway: {:?}", gw_uwg);
            let mac_uwg = resolve_mac("uwg-c", std::net::Ipv4Addr::new(10, 0, 2, 2));
            println!("uwg-c 10.0.2.2 MAC: {:?}", mac_uwg);
        } else {
            println!("uwg-c gateway not found");
        }

        // Test resolving vs-c gateway
        if let Some(gw_vs) = get_gateway_ip("vs-c") {
            println!("vs-c gateway: {:?}", gw_vs);
            let mac_vs = resolve_mac("vs-c", std::net::Ipv4Addr::new(10, 0, 2, 2));
            println!("vs-c 10.0.2.2 MAC: {:?}", mac_vs);
        } else {
            println!("vs-c gateway not found");
        }
    }
}
