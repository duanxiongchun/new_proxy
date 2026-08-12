use crate::flow_plane::IoOwnerKey;
use crate::v1_config::XdpAttachMode;
use std::collections::VecDeque;
use std::io;
use std::os::fd::RawFd;
use std::path::Path;

const AF_XDP: libc::c_int = 44;
const SOL_XDP: libc::c_int = 283;
const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_RX_RING: libc::c_int = 2;
const XDP_TX_RING: libc::c_int = 3;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
const XDP_COPY: u16 = 2;
const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_PGOFF_TX_RING: libc::off_t = 0x80000000;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x180000000;
const RING_SIZE: u32 = 1024;
const CHUNK_SIZE: usize = 4096;
const CHUNK_COUNT: usize = 2048;
const RX_CHUNKS: usize = 1024;

#[repr(C)]
struct SockaddrXdp {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MmapOffsets {
    rx: RingOffset,
    tx: RingOffset,
    fill: RingOffset,
    completion: RingOffset,
}

struct Umem {
    pointer: *mut u8,
    length: usize,
}

unsafe impl Send for Umem {}

impl Umem {
    fn allocate() -> io::Result<Self> {
        let length = CHUNK_SIZE * CHUNK_COUNT;
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pointer: pointer.cast(),
            length,
        })
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer.cast(), self.length);
        }
    }
}

struct Ring {
    mapping: *mut libc::c_void,
    mapping_len: usize,
    producer: *mut u32,
    consumer: *mut u32,
    descriptors: *mut u8,
    mask: u32,
}

unsafe impl Send for Ring {}

impl Ring {
    unsafe fn map(
        fd: RawFd,
        offset: RingOffset,
        page_offset: libc::off_t,
        descriptor_size: usize,
    ) -> io::Result<Self> {
        let mapping_len = offset.desc as usize + RING_SIZE as usize * descriptor_size;
        let mapping = libc::mmap(
            std::ptr::null_mut(),
            mapping_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            page_offset,
        );
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            mapping,
            mapping_len,
            producer: mapping.byte_add(offset.producer as usize).cast(),
            consumer: mapping.byte_add(offset.consumer as usize).cast(),
            descriptors: mapping.byte_add(offset.desc as usize).cast(),
            mask: RING_SIZE - 1,
        })
    }

    unsafe fn producer(&self) -> u32 {
        std::ptr::read_volatile(self.producer)
    }

    unsafe fn consumer(&self) -> u32 {
        std::ptr::read_volatile(self.consumer)
    }
}

impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.mapping, self.mapping_len);
        }
    }
}

pub struct Xsk {
    owner: IoOwnerKey,
    fd: RawFd,
    umem: Umem,
    rx: Ring,
    tx: Ring,
    fill: Ring,
    completion: Ring,
    rx_consumer: u32,
    fill_producer: u32,
    tx_producer: u32,
    completion_consumer: u32,
    free_tx: VecDeque<u64>,
}

unsafe impl Send for Xsk {}

impl Xsk {
    pub fn create(owner: IoOwnerKey, mode: XdpAttachMode, xsks_map: &Path) -> io::Result<Self> {
        let umem = Umem::allocate()?;
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = Self::configure(owner, mode, xsks_map, fd, umem);
        if result.is_err() {
            unsafe {
                libc::close(fd);
            }
        }
        result
    }

    fn configure(
        owner: IoOwnerKey,
        mode: XdpAttachMode,
        xsks_map: &Path,
        fd: RawFd,
        umem: Umem,
    ) -> io::Result<Self> {
        let registration = XdpUmemReg {
            addr: umem.pointer as u64,
            len: umem.length as u64,
            chunk_size: CHUNK_SIZE as u32,
            headroom: 0,
            flags: 0,
        };
        set_socket_option(fd, XDP_UMEM_REG, &registration)?;
        for option in [
            XDP_UMEM_FILL_RING,
            XDP_UMEM_COMPLETION_RING,
            XDP_RX_RING,
            XDP_TX_RING,
        ] {
            set_socket_option(fd, option, &RING_SIZE)?;
        }

        let mut offsets = MmapOffsets::default();
        let mut length = std::mem::size_of::<MmapOffsets>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                (&mut offsets as *mut MmapOffsets).cast(),
                &mut length,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let rx = unsafe {
            Ring::map(
                fd,
                offsets.rx,
                XDP_PGOFF_RX_RING,
                std::mem::size_of::<XdpDesc>(),
            )?
        };
        let tx = unsafe {
            Ring::map(
                fd,
                offsets.tx,
                XDP_PGOFF_TX_RING,
                std::mem::size_of::<XdpDesc>(),
            )?
        };
        let fill = unsafe {
            Ring::map(
                fd,
                offsets.fill,
                XDP_UMEM_PGOFF_FILL_RING,
                std::mem::size_of::<u64>(),
            )?
        };
        let completion = unsafe {
            Ring::map(
                fd,
                offsets.completion,
                XDP_UMEM_PGOFF_COMPLETION_RING,
                std::mem::size_of::<u64>(),
            )?
        };

        let address = SockaddrXdp {
            family: AF_XDP as u16,
            flags: match mode {
                XdpAttachMode::Native => 0,
                XdpAttachMode::Skb => XDP_COPY,
            },
            ifindex: owner.ifindex,
            queue_id: owner.queue_id,
            shared_umem_fd: 0,
        };
        let result = unsafe {
            libc::bind(
                fd,
                (&address as *const SockaddrXdp).cast(),
                std::mem::size_of::<SockaddrXdp>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        update_xsk_map(xsks_map, owner.queue_id, fd)?;

        let mut xsk = Self {
            owner,
            fd,
            umem,
            rx,
            tx,
            fill,
            completion,
            rx_consumer: 0,
            fill_producer: 0,
            tx_producer: 0,
            completion_consumer: 0,
            free_tx: (RX_CHUNKS..CHUNK_COUNT)
                .map(|chunk| (chunk * CHUNK_SIZE) as u64)
                .collect(),
        };
        xsk.seed_fill_ring();
        Ok(xsk)
    }

    pub const fn owner(&self) -> IoOwnerKey {
        self.owner
    }

    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn receive(&mut self, output: &mut Vec<Vec<u8>>, budget: u32) -> u32 {
        let producer = unsafe { self.rx.producer() };
        let count = producer.wrapping_sub(self.rx_consumer).min(budget);
        if count == 0 {
            return 0;
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        for offset in 0..count {
            let index = self.rx_consumer.wrapping_add(offset) & self.rx.mask;
            let descriptor = unsafe {
                std::ptr::read((self.rx.descriptors as *const XdpDesc).add(index as usize))
            };
            if descriptor.addr as usize + descriptor.len as usize <= self.umem.length {
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        self.umem.pointer.add(descriptor.addr as usize),
                        descriptor.len as usize,
                    )
                };
                output.push(bytes.to_vec());
            }
            self.push_fill(descriptor.addr);
        }
        self.rx_consumer = self.rx_consumer.wrapping_add(count);
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        unsafe {
            std::ptr::write_volatile(self.rx.consumer, self.rx_consumer);
            std::ptr::write_volatile(self.fill.producer, self.fill_producer);
        }
        count
    }

    pub fn transmit(&mut self, frame: &[u8]) -> io::Result<bool> {
        if frame.len() > CHUNK_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame exceeds AF_XDP chunk size",
            ));
        }
        self.reclaim_completions();
        let Some(address) = self.free_tx.pop_front() else {
            return Ok(false);
        };
        let producer = unsafe { self.tx.producer() };
        let consumer = unsafe { self.tx.consumer() };
        if producer.wrapping_sub(consumer) >= RING_SIZE {
            self.free_tx.push_front(address);
            return Ok(false);
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                self.umem.pointer.add(address as usize),
                frame.len(),
            );
            let index = self.tx_producer & self.tx.mask;
            std::ptr::write(
                (self.tx.descriptors as *mut XdpDesc).add(index as usize),
                XdpDesc {
                    addr: address,
                    len: frame.len() as u32,
                    options: 0,
                },
            );
        }
        self.tx_producer = self.tx_producer.wrapping_add(1);
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        let kick_result = unsafe {
            std::ptr::write_volatile(self.tx.producer, self.tx_producer);
            libc::sendto(
                self.fd,
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if kick_result < 0 {
            let error = io::Error::last_os_error();
            if !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(error);
            }
        }
        Ok(true)
    }

    fn seed_fill_ring(&mut self) {
        for chunk in 0..RX_CHUNKS {
            self.push_fill((chunk * CHUNK_SIZE) as u64);
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        unsafe {
            std::ptr::write_volatile(self.fill.producer, self.fill_producer);
        }
    }

    fn push_fill(&mut self, address: u64) {
        let index = self.fill_producer & self.fill.mask;
        unsafe {
            std::ptr::write(
                (self.fill.descriptors as *mut u64).add(index as usize),
                address,
            );
        }
        self.fill_producer = self.fill_producer.wrapping_add(1);
    }

    fn reclaim_completions(&mut self) {
        let producer = unsafe { self.completion.producer() };
        let count = producer.wrapping_sub(self.completion_consumer);
        if count == 0 {
            return;
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
        for offset in 0..count {
            let index = self.completion_consumer.wrapping_add(offset) & self.completion.mask;
            let address = unsafe {
                std::ptr::read((self.completion.descriptors as *const u64).add(index as usize))
            };
            self.free_tx.push_back(address);
        }
        self.completion_consumer = self.completion_consumer.wrapping_add(count);
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        unsafe {
            std::ptr::write_volatile(self.completion.consumer, self.completion_consumer);
        }
    }
}

impl Drop for Xsk {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

fn set_socket_option<T>(fd: RawFd, option: libc::c_int, value: &T) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            option,
            (value as *const T).cast(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[repr(C)]
struct BpfObjectGet {
    pathname: u64,
    fd: u32,
    file_flags: u32,
}

#[repr(C)]
struct BpfUpdate {
    map_fd: u32,
    padding: u32,
    key: u64,
    value: u64,
    flags: u64,
}

pub fn open_bpf_map(path: &Path) -> io::Result<RawFd> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let attribute = BpfObjectGet {
        pathname: path.as_ptr() as u64,
        fd: 0,
        file_flags: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            7,
            &attribute,
            std::mem::size_of::<BpfObjectGet>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as RawFd)
    }
}

pub fn update_bpf_map<K, V>(fd: RawFd, key: &K, value: &V) -> io::Result<()> {
    let attribute = BpfUpdate {
        map_fd: fd as u32,
        padding: 0,
        key: key as *const K as u64,
        value: value as *const V as u64,
        flags: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            2,
            &attribute,
            std::mem::size_of::<BpfUpdate>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn update_xsk_map(path: &Path, queue_id: u32, xsk_fd: RawFd) -> io::Result<()> {
    let map_fd = open_bpf_map(path)?;
    let result = update_bpf_map(map_fd, &queue_id, &(xsk_fd as u32));
    unsafe {
        libc::close(map_fd);
    }
    result
}
