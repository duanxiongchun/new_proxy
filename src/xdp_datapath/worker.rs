use std::sync::Arc;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use arc_swap::ArcSwap;

use crate::datapath::{Datapath, DatapathError, DatapathStats};
use crate::config::GatewayConfig;
use crate::app_config::RuntimeMode;
use crate::telemetry::TelemetryRegistry;
#[cfg(target_os = "linux")]
use crate::quic_pool::{cert_sha256, generate_self_signed_cert};
#[cfg(target_os = "linux")]
use crate::control::ControlServer;
#[cfg(target_os = "linux")]
use crate::client::build_peer_quic_pool;
use crate::{PeerQuicPools, ClientQuicDataPortBaseline};
#[cfg(target_os = "linux")]
use crate::runtime::{cleanup_runtime, setup_routes};
#[cfg(target_os = "linux")]
use crate::tun_datapath::{setup_udp_socket, setup_server_endpoint, setup_client_endpoint, spawn_worker_thread};

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
struct XskSetup {
    #[allow(dead_code)]
    umems: Vec<UmemRegion>,
    quic_sockets: Vec<(libc::c_int, SendPtr)>,
    intercept_sockets: Vec<(libc::c_int, SendPtr)>,
}

#[cfg(target_os = "linux")]
impl Drop for XskSetup {
    fn drop(&mut self) {
        for &(fd, _) in &self.quic_sockets {
            if fd >= 0 {
                // SAFETY: close valid socket FD.
                unsafe {
                    libc::close(fd);
                }
            }
        }
        for &(fd, _) in &self.intercept_sockets {
            if fd >= 0 {
                // SAFETY: close valid socket FD.
                unsafe {
                    libc::close(fd);
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
        let desc = xdp_desc { addr, len, options: 0 };
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
fn register_xsk_in_map(map_fd: libc::c_int, queue_id: u32, xsk_fd: libc::c_int) -> Result<(), std::io::Error> {
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
        return Err(std::io::Error::last_os_error());
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
fn mmap_socket_rings(fd: libc::c_int) -> Result<(XskRing, XskRing, XskRing, XskRing), std::io::Error> {
    const SOL_XDP: libc::c_int = 283;
    const XDP_MMAP_OFFSETS: libc::c_int = 1;
    const XDP_PGOFF_RX_RING: u64 = 0;
    const XDP_PGOFF_TX_RING: u64 = 0x80000000;
    const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
    const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

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

    let ring_size: u32 = 2048;

    let rx = unsafe { mmap_ring(fd, &offsets.rx, XDP_PGOFF_RX_RING, ring_size, false)? };
    let tx = unsafe { mmap_ring(fd, &offsets.tx, XDP_PGOFF_TX_RING, ring_size, false)? };
    let fill = unsafe { mmap_ring(fd, &offsets.fr, XDP_UMEM_PGOFF_FILL_RING, ring_size, true)? };
    let comp = unsafe { mmap_ring(fd, &offsets.cr, XDP_UMEM_PGOFF_COMPLETION_RING, ring_size, true)? };

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
/// The caller must ensure that the `fill` ring is backed by valid, mapped memory-mapped pointers.
#[cfg(target_os = "linux")]
unsafe fn return_rx_buf(fill: &mut XskRing, addr: u64) {
    if fill.free_slots() > 0 {
        let prod = *fill.producer;
        fill.write_fill_addr(prod, addr);
        fill.produce(1);
    }
}

/// # Safety
///
/// The caller must ensure that the `comp` ring is backed by valid, mapped memory-mapped pointers.
#[cfg(target_os = "linux")]
unsafe fn reclaim_tx_buffers(comp: &mut XskRing, free_tx_chunks: &mut Vec<u64>) {
    let prod = std::ptr::read_volatile(comp.producer);
    let cons = std::ptr::read_volatile(comp.consumer);
    let cnt = prod.wrapping_sub(cons);
    if cnt > 0 {
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        for i in 0..cnt {
            let idx = cons.wrapping_add(i);
            let addr = comp.read_comp_addr(idx);
            free_tx_chunks.push(addr);
        }
        comp.consume(cnt);
    }
}

/// # Safety
///
/// The caller must ensure that `rx`, `fill`, `tx`, and `comp` rings are backed by valid, mapped
/// memory-mapped pointers, and that `rx_umem_base` and `tx_umem_base` point to valid UMEM areas.
#[cfg(target_os = "linux")]
unsafe fn process_rx_ring(
    rx: &mut XskRing,
    fill: &mut XskRing,
    rx_umem_base: *mut libc::c_void,
    mut process_packet: impl FnMut(&[u8]) -> Option<Vec<u8>>,
    tx: &mut XskRing,
    comp: &mut XskRing,
    free_tx_chunks: &mut Vec<u64>,
    tx_umem_base: *mut libc::c_void,
    tx_fd: libc::c_int,
) {
    let prod = std::ptr::read_volatile(rx.producer);
    let cons = std::ptr::read_volatile(rx.consumer);
    let cnt = prod.wrapping_sub(cons);
    if cnt > 0 {
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        let mut tx_produced = 0;
        for i in 0..cnt {
            let idx = cons.wrapping_add(i);
            let (addr, len) = rx.read_rx_desc(idx);
            
            // Bounds check UMEM read address
            assert!(addr + len as u64 <= 4096 * 2048, "RX UMEM access out of bounds");
            
            // SAFETY: rx_umem_base + addr points to a valid mapped packet buffer.
            let pkt_ptr = (rx_umem_base as usize + addr as usize) as *const u8;
            let pkt_slice = std::slice::from_raw_parts(pkt_ptr, len as usize);
            
            if let Some(out_pkt) = process_packet(pkt_slice) {
                if free_tx_chunks.is_empty() {
                    reclaim_tx_buffers(comp, free_tx_chunks);
                }
                
                if let Some(tx_addr) = free_tx_chunks.pop() {
                    // Bounds check UMEM write address
                    assert!(tx_addr + out_pkt.len() as u64 <= 4096 * 2048, "TX UMEM access out of bounds");
                    
                    // SAFETY: tx_umem_base + tx_addr points to a valid mapped packet buffer.
                    let tx_ptr = (tx_umem_base as usize + tx_addr as usize) as *mut u8;
                    std::ptr::copy_nonoverlapping(out_pkt.as_ptr(), tx_ptr, out_pkt.len());
                    
                    let tx_idx = (*tx.producer).wrapping_add(tx_produced);
                    tx.write_tx_desc(tx_idx, tx_addr, out_pkt.len() as u32);
                    tx_produced += 1;
                }
            }
            
            return_rx_buf(fill, addr);
        }
        
        rx.consume(cnt);
        if tx_produced > 0 {
            tx.produce(tx_produced);
            // SAFETY: sendto triggers kernel processing of TX rings.
            libc::sendto(tx_fd, std::ptr::null(), 0, libc::MSG_DONTWAIT, std::ptr::null(), 0);
        }
    }
}

pub fn wrap_plaintext_to_quic(plaintext_ip: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(14 + 20 + 8 + plaintext_ip.len());
    
    let eth = EthernetHeader {
        dst_mac: [0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e],
        src_mac: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        ether_type: 0x0800,
    };
    let mut eth_buf = [0u8; 14];
    eth.serialize(&mut eth_buf).expect("Eth serialization failed");
    pkt.extend_from_slice(&eth_buf);

    let mut ip_hdr = [0u8; 20];
    ip_hdr[0] = 0x45;
    ip_hdr[8] = 64;
    ip_hdr[9] = 17;
    ip_hdr[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip_hdr[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let total_len = (20 + 8 + plaintext_ip.len()) as u16;
    ip_hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&ip_hdr);

    let mut udp_hdr = [0u8; 8];
    udp_hdr[0..2].copy_from_slice(&40001u16.to_be_bytes());
    udp_hdr[2..4].copy_from_slice(&40002u16.to_be_bytes());
    let udp_len = (8 + plaintext_ip.len()) as u16;
    udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&udp_hdr);

    pkt.extend_from_slice(plaintext_ip);
    pkt
}

pub fn unwrap_quic_to_plaintext(quic_packet: &[u8]) -> Option<Vec<u8>> {
    if quic_packet.len() < 42 {
        return None;
    }
    let plaintext_ip = &quic_packet[42..];
    
    let mut pkt = Vec::with_capacity(14 + plaintext_ip.len());
    let eth = EthernetHeader {
        dst_mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        src_mac: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        ether_type: 0x0800,
    };
    let mut eth_buf = [0u8; 14];
    eth.serialize(&mut eth_buf).expect("Eth serialization failed");
    pkt.extend_from_slice(&eth_buf);
    pkt.extend_from_slice(plaintext_ip);
    
    Some(pkt)
}

#[cfg(target_os = "linux")]
fn setup_xsk_sockets(
    quic_ifindex: u32,
    intercept_ifindexes: &[u32],
    _queue_count: usize,
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

    let cleanup = |quic: &[(libc::c_int, SendPtr)], intercept: &[(libc::c_int, SendPtr)]| {
        for &(s_fd, _) in quic {
            if s_fd >= 0 {
                // SAFETY: closing a valid open socket FD.
                unsafe { libc::close(s_fd); }
            }
        }
        for &(s_fd, _) in intercept {
            if s_fd >= 0 {
                // SAFETY: closing a valid open socket FD.
                unsafe { libc::close(s_fd); }
            }
        }
    };

    // 1. Process quic_ifindex
    {
        let ifindex = quic_ifindex;
        let q_count = get_interface_queue_count(ifindex);
        if q_count > 0 {
            let mut buf = [0u8; 32];
            // SAFETY: libc::if_indextoname is called with an output buffer `buf` of 32 bytes,
            // which is larger than IFNAMSIZ (16 bytes). On success, name_ptr returns a pointer
            // to a valid null-terminated string contained inside `buf`.
            let name_ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
            if name_ptr.is_null() {
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!("Failed to get interface name for index {}", ifindex)));
            }
            // SAFETY: name_ptr is non-null and points to the valid null-terminated string inside `buf`.
            let ifname = unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_string_lossy();
            let map_path = format!("/sys/fs/bpf/new_proxy_{}/maps/xsks_map", ifname);

            let map_fd = match bpf_obj_get(&map_path) {
                Ok(fd) => fd,
                Err(e) => {
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!("Failed to open pinned map at {}: {}", map_path, e)));
                }
            };

            let umem_size = 4096 * 2048;
            let umem = match UmemRegion::new(umem_size) {
                Ok(u) => u,
                Err(e) => {
                    // SAFETY: close map FD.
                    unsafe { libc::close(map_fd); }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!("Failed to allocate UMEM mmap for ifindex {}: {}", ifindex, e)));
                }
            };
            let mut first_fd_for_iface: Option<libc::c_int> = None;

            for queue_id in 0..q_count {
                // SAFETY: socket call with standard constants.
                let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
                if fd < 0 {
                    let err = io::Error::last_os_error();
                    // SAFETY: close map FD.
                    unsafe { libc::close(map_fd); }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!("socket(AF_XDP) failed: {}", err)));
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
                        // SAFETY: clean up local and map FDs.
                        unsafe { libc::close(fd); }
                        unsafe { libc::close(map_fd); }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!("setsockopt(XDP_UMEM_REG) failed: {}", err)));
                    }

                    let ring_size: u32 = 2048;
                    for opt in &[XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
                        // SAFETY: setsockopt configures ring sizes for the first socket FD of the interface.
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
                            // SAFETY: clean up local and map FDs.
                            unsafe { libc::close(fd); }
                            unsafe { libc::close(map_fd); }
                            cleanup(&quic_sockets, &intercept_sockets);
                            return Err(DatapathError::Config(format!("setsockopt(opt={}) failed: {}", opt, err)));
                        }
                    }

                    let addr = sockaddr_xdp {
                        sxdp_family: AF_XDP as u16,
                        sxdp_flags: XDP_COPY,
                        sxdp_ifindex: ifindex,
                        sxdp_queue_id: queue_id as u32,
                        sxdp_shared_umem_fd: 0,
                    };
                    // SAFETY: bind binds the XSK raw socket to the interface index and queue ID.
                    let ret = unsafe {
                        libc::bind(
                            fd,
                            &addr as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        // SAFETY: clean up local and map FDs.
                        unsafe { libc::close(fd); }
                        unsafe { libc::close(map_fd); }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!("bind(ifindex={}, queue_id={}) failed: {}", ifindex, queue_id, err)));
                    }

                    first_fd_for_iface = Some(fd);
                } else {
                    let ring_size: u32 = 2048;
                    for opt in &[XDP_RX_RING, XDP_TX_RING] {
                        // SAFETY: setsockopt configures secondary socket ring sizes.
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
                            // SAFETY: clean up local and map FDs.
                            unsafe { libc::close(fd); }
                            unsafe { libc::close(map_fd); }
                            cleanup(&quic_sockets, &intercept_sockets);
                            return Err(DatapathError::Config(format!("setsockopt(secondary opt={}) failed: {}", opt, err)));
                        }
                    }

                    let addr = sockaddr_xdp {
                        sxdp_family: AF_XDP as u16,
                        sxdp_flags: XDP_SHARED_UMEM | XDP_COPY,
                        sxdp_ifindex: ifindex,
                        sxdp_queue_id: queue_id as u32,
                        sxdp_shared_umem_fd: first_fd_for_iface.expect("first_fd_for_iface is missing") as u32,
                    };
                    // SAFETY: bind binds secondary XSK raw socket sharing UMEM with the primary socket.
                    let ret = unsafe {
                        libc::bind(
                            fd,
                            &addr as *const _ as *const libc::sockaddr,
                            std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                        )
                    };
                    if ret < 0 {
                        let err = io::Error::last_os_error();
                        // SAFETY: clean up local and map FDs.
                        unsafe { libc::close(fd); }
                        unsafe { libc::close(map_fd); }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!("bind(secondary ifindex={}, queue_id={}) failed: {}", ifindex, queue_id, err)));
                    }
                }

                if let Err(e) = register_xsk_in_map(map_fd, queue_id as u32, fd) {
                    // SAFETY: close FD.
                    unsafe { libc::close(fd); }
                    // SAFETY: close map FD.
                    unsafe { libc::close(map_fd); }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!("Failed to register XSK socket FD {} in BPF map: {}", fd, e)));
                }

                quic_sockets.push((fd, SendPtr(umem.addr)));
            }
            // SAFETY: close map FD.
            unsafe { libc::close(map_fd); }
            umems.push(umem);
        }
    }

    // 2. Process intercept_ifindexes
    for &ifindex in intercept_ifindexes {
        let q_count = get_interface_queue_count(ifindex);
        if q_count == 0 {
            continue;
        }

        let mut buf = [0u8; 32];
        // SAFETY: libc::if_indextoname is called with an output buffer `buf` of 32 bytes,
        // which is larger than IFNAMSIZ (16 bytes). On success, name_ptr returns a pointer
        // to a valid null-terminated string contained inside `buf`.
        let name_ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
        if name_ptr.is_null() {
            cleanup(&quic_sockets, &intercept_sockets);
            return Err(DatapathError::Config(format!("Failed to get interface name for index {}", ifindex)));
        }
        // SAFETY: name_ptr is non-null and points to the valid null-terminated string inside `buf`.
        let ifname = unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_string_lossy();
        let map_path = format!("/sys/fs/bpf/new_proxy_{}/maps/xsks_map", ifname);

        let map_fd = match bpf_obj_get(&map_path) {
            Ok(fd) => fd,
            Err(e) => {
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!("Failed to open pinned map at {}: {}", map_path, e)));
            }
        };

        let umem_size = 4096 * 2048;
        let umem = match UmemRegion::new(umem_size) {
            Ok(u) => u,
            Err(e) => {
                // SAFETY: close map FD.
                unsafe { libc::close(map_fd); }
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!("Failed to allocate UMEM mmap for ifindex {}: {}", ifindex, e)));
            }
        };
        let mut first_fd_for_iface: Option<libc::c_int> = None;

        for queue_id in 0..q_count {
            // SAFETY: socket call with standard constants.
            let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                // SAFETY: close map FD.
                unsafe { libc::close(map_fd); }
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!("socket(AF_XDP) failed: {}", err)));
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
                    // SAFETY: clean up local and map FDs.
                    unsafe { libc::close(fd); }
                    unsafe { libc::close(map_fd); }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!("setsockopt(XDP_UMEM_REG) failed: {}", err)));
                }

                let ring_size: u32 = 2048;
                for opt in &[XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING, XDP_TX_RING] {
                    // SAFETY: setsockopt configures ring sizes for the first socket FD of the interface.
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
                        // SAFETY: clean up local and map FDs.
                        unsafe { libc::close(fd); }
                        unsafe { libc::close(map_fd); }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!("setsockopt(opt={}) failed: {}", opt, err)));
                    }
                }

                let addr = sockaddr_xdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: XDP_COPY,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id as u32,
                    sxdp_shared_umem_fd: 0,
                };
                // SAFETY: bind binds the XSK raw socket to the interface index and queue ID.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    // SAFETY: clean up local and map FDs.
                    unsafe { libc::close(fd); }
                    unsafe { libc::close(map_fd); }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!("bind(ifindex={}, queue_id={}) failed: {}", ifindex, queue_id, err)));
                }

                first_fd_for_iface = Some(fd);
            } else {
                let ring_size: u32 = 2048;
                for opt in &[XDP_RX_RING, XDP_TX_RING] {
                    // SAFETY: setsockopt configures secondary socket ring sizes.
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
                        // SAFETY: clean up local and map FDs.
                        unsafe { libc::close(fd); }
                        unsafe { libc::close(map_fd); }
                        cleanup(&quic_sockets, &intercept_sockets);
                        return Err(DatapathError::Config(format!("setsockopt(secondary opt={}) failed: {}", opt, err)));
                    }
                }

                let addr = sockaddr_xdp {
                    sxdp_family: AF_XDP as u16,
                    sxdp_flags: XDP_SHARED_UMEM | XDP_COPY,
                    sxdp_ifindex: ifindex,
                    sxdp_queue_id: queue_id as u32,
                    sxdp_shared_umem_fd: first_fd_for_iface.expect("first_fd_for_iface is missing") as u32,
                };
                // SAFETY: bind binds secondary XSK raw socket sharing UMEM with the primary socket.
                let ret = unsafe {
                    libc::bind(
                        fd,
                        &addr as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<sockaddr_xdp>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    // SAFETY: clean up local and map FDs.
                    unsafe { libc::close(fd); }
                    unsafe { libc::close(map_fd); }
                    cleanup(&quic_sockets, &intercept_sockets);
                    return Err(DatapathError::Config(format!("bind(secondary ifindex={}, queue_id={}) failed: {}", ifindex, queue_id, err)));
                }
            }

            if let Err(e) = register_xsk_in_map(map_fd, queue_id as u32, fd) {
                // SAFETY: close FD.
                unsafe { libc::close(fd); }
                // SAFETY: close map FD.
                unsafe { libc::close(map_fd); }
                cleanup(&quic_sockets, &intercept_sockets);
                return Err(DatapathError::Config(format!("Failed to register XSK socket FD {} in BPF map: {}", fd, e)));
            }

            intercept_sockets.push((fd, SendPtr(umem.addr)));
        }
        // SAFETY: close map FD.
        unsafe { libc::close(map_fd); }
        umems.push(umem);
    }

    Ok(XskSetup { umems, quic_sockets, intercept_sockets })
}

#[cfg(target_os = "linux")]
fn run_xdp_worker_loop(
    worker_id: usize,
    quic_fd: libc::c_int,
    quic_umem_addr: SendPtr,
    intercept_fd: libc::c_int,
    intercept_umem_addr: SendPtr,
    exit_flag: Arc<std::sync::atomic::AtomicBool>,
) {
    let quic_umem_addr = quic_umem_addr.0;
    let intercept_umem_addr = intercept_umem_addr.0;
    let (mut quic_rx, mut quic_tx, mut quic_fill, mut quic_comp) = match mmap_socket_rings(quic_fd) {
        Ok(r) => r,
        Err(e) => {
            log::error!("XDP Worker {} failed to mmap QUIC socket rings: {}", worker_id, e);
            return;
        }
    };

    let (mut intercept_rx, mut intercept_tx, mut intercept_fill, mut intercept_comp) = match mmap_socket_rings(intercept_fd) {
        Ok(r) => r,
        Err(e) => {
            log::error!("XDP Worker {} failed to mmap Intercept socket rings: {}", worker_id, e);
            return;
        }
    };

    // Populate Fill rings
    unsafe {
        populate_fill_ring(&mut quic_fill, 0, 1024);
        populate_fill_ring(&mut intercept_fill, 0, 1024);
    }

    let mut quic_free_tx_chunks: Vec<u64> = (1024..2048).map(|i| (i as u64) * 4096).collect();
    let mut intercept_free_tx_chunks: Vec<u64> = (1024..2048).map(|i| (i as u64) * 4096).collect();

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

    while !exit_flag.load(std::sync::atomic::Ordering::Relaxed) {
        for pfd in &mut poll_fds {
            pfd.revents = 0;
        }

        let ret = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                50, // 50ms timeout
            )
        };

        if ret > 0 {
            unsafe {
                // Process Intercept RX (plaintext packets from app) -> Strip L2, Wrap to QUIC -> Transmit on QUIC TX
                process_rx_ring(
                    &mut intercept_rx,
                    &mut intercept_fill,
                    intercept_umem_addr,
                    |pkt_data| {
                        // Strip Ethernet header
                        if let Some((eth_header, ip_payload)) = EthernetHeader::parse(pkt_data) {
                            if eth_header.ether_type == 0x0800 {
                                // Strip L2 and wrap to QUIC UDP
                                Some(wrap_plaintext_to_quic(ip_payload))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    },
                    &mut quic_tx,
                    &mut quic_comp,
                    &mut quic_free_tx_chunks,
                    quic_umem_addr,
                    quic_fd,
                );

                // Process QUIC RX (encrypted QUIC packets from NIC) -> Unwrap / Decrypt -> Prepend L2 -> Transmit on Intercept TX
                process_rx_ring(
                    &mut quic_rx,
                    &mut quic_fill,
                    quic_umem_addr,
                    |pkt_data| {
                        // Strip UDP/QUIC headers and prepend new Ethernet header
                        unwrap_quic_to_plaintext(pkt_data)
                    },
                    &mut intercept_tx,
                    &mut intercept_comp,
                    &mut intercept_free_tx_chunks,
                    intercept_umem_addr,
                    intercept_fd,
                );
            }
        } else if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                log::error!("XDP Worker {} libc::poll error: {}", worker_id, err);
                break;
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
            None => return Err(DatapathError::Config("quic_interface must be configured for XDP mode".into())),
        };
        
        let quic_ifindex = unsafe {
            let c_ifname = CString::new(quic_interface.as_str()).map_err(|e| DatapathError::Config(e.to_string()))?;
            let index = libc::if_nametoindex(c_ifname.as_ptr());
            if index == 0 {
                return Err(DatapathError::Config(format!("quic_interface '{}' not found", quic_interface)));
            }
            index
        };

        let mut intercept_ifindexes = Vec::new();
        for ifname in &config.xdp.intercept_interfaces {
            let index = unsafe {
                let c_ifname = CString::new(ifname.as_str()).map_err(|e| DatapathError::Config(e.to_string()))?;
                let index = libc::if_nametoindex(c_ifname.as_ptr());
                if index == 0 {
                    return Err(DatapathError::Config(format!("intercept_interface '{}' not found", ifname)));
                }
                index
            };
            intercept_ifindexes.push(index);
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
        Err(DatapathError::Config("XDP is only supported on Linux".into()))
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
                    return Err(DatapathError::Config("Server userspace XDP requires Interface.ListenPort".into()));
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
                    return Err(DatapathError::Config(format!("Failed to generate QUIC certificate: {}", e)));
                }
            };
            let quic_cert_sha256 = match cert_sha256(&quic_certs) {
                Ok(fingerprint) => fingerprint,
                Err(e) => {
                    log::error!("Failed to fingerprint QUIC certificate: {}", e);
                    cleanup_runtime(&self.config, &self.interface_name);
                    return Err(DatapathError::Config(format!("Failed to fingerprint QUIC certificate: {}", e)));
                }
            };

            let listen_control_port = self.config
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
                    return Err(DatapathError::Config(format!("Control plane server failed to start: {}", e)));
                }
            };

            let setup = match setup_xsk_sockets(self.quic_ifindex, &self.intercept_ifindexes, queue_count) {
                Ok(s) => s,
                Err(e) => {
                    cleanup_runtime(&self.config, &self.interface_name);
                    control_task.abort();
                    return Err(e);
                }
            };

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

                let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(self.config.interface.mtu);
                let endpoint = match setup_server_endpoint(&quic_certs, &quic_key, packet_buffer_size) {
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

            for worker_id in 0..queue_count {
                let exit_notify_clone = exit_notify.clone();
                let exit_flag_clone = exit_flag.clone();
                let (quic_fd, quic_umem_addr) = setup.quic_sockets[worker_id % setup.quic_sockets.len()];
                let (intercept_fd, intercept_umem_addr) = setup.intercept_sockets[worker_id % setup.intercept_sockets.len()];
                
                let handle = std::thread::Builder::new()
                    .name(format!("new-proxy-server-xdp-worker-{}", worker_id))
                    .spawn(move || {
                        let _panic_guard = WorkerPanicGuard { exit_notify: exit_notify_clone };
                        run_xdp_worker_loop(
                            worker_id,
                            quic_fd,
                            quic_umem_addr,
                            intercept_fd,
                            intercept_umem_addr,
                            exit_flag_clone,
                        );
                    })
                    .expect("Failed to spawn XDP worker thread");
                join_handles.push(handle);
            }

            let mut l3_tasks = Vec::new();
            for (worker_id, (tun_io, udp_socket, endpoint)) in worker_preps.into_iter().enumerate() {
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
            for handle in l3_tasks {
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

            crate::publish_l4_data_plane_snapshot(&dp_snapshot, &self.gateway_state, &self.client_quic_pools);
            let quic_data_port_count =
                crate::client_quic_data_port_count(&self.client_quic_pools, startup_quic_data_port_count);
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

            let setup = setup_xsk_sockets(self.quic_ifindex, &self.intercept_ifindexes, queue_count)?;

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

            for worker_id in 0..queue_count {
                let exit_notify_clone = exit_notify.clone();
                let exit_flag_clone = exit_flag.clone();
                let (quic_fd, quic_umem_addr) = setup.quic_sockets[worker_id % setup.quic_sockets.len()];
                let (intercept_fd, intercept_umem_addr) = setup.intercept_sockets[worker_id % setup.intercept_sockets.len()];
                
                let handle = std::thread::Builder::new()
                    .name(format!("new-proxy-client-xdp-worker-{}", worker_id))
                    .spawn(move || {
                        let _panic_guard = WorkerPanicGuard { exit_notify: exit_notify_clone };
                        run_xdp_worker_loop(
                            worker_id,
                            quic_fd,
                            quic_umem_addr,
                            intercept_fd,
                            intercept_umem_addr,
                            exit_flag_clone,
                        );
                    })
                    .expect("Failed to spawn XDP worker thread");
                join_handles.push(handle);
            }

            let mut worker_tasks = Vec::new();
            for (worker_id, (tun_io, udp_socket, endpoint)) in worker_preps.into_iter().enumerate() {
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
            for handle in worker_tasks {
                let _ = handle.join();
            }
            userspace_tcp_failover_task.abort();
            cleanup_runtime(&self.config, &self.interface_name);
        }

        Ok(())
    }

    fn get_stats(&self) -> DatapathStats {
        let snapshots = self.worker_telemetry_registry.snapshot();
        let total_rx_bytes = snapshots.iter().map(|s| s.tun_rx_bytes + s.tcp_offload_bytes + s.l3_bytes).sum();
        DatapathStats { rx_bytes: total_rx_bytes }
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
        Err(DatapathError::Config("XDP is only supported on Linux".into()))
    }

    fn get_stats(&self) -> DatapathStats {
        DatapathStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GatewayConfig, InterfaceConfig, QUICPoolConfig, XdpConfig};
    use crate::app_config::RuntimeMode;
    use crate::telemetry::{TelemetryRegistry, WorkerTelemetryRegistry};
    use std::sync::Arc;
    use parking_lot::RwLock;

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
}

