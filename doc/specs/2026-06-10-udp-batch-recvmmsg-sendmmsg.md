# Design Spec: UDP Batch Processing (recvmmsg and sendmmsg)

This document specifies the design for optimizing the UDP packet processing hotpath by batching socket reads and writes using the Linux native `recvmmsg` and `sendmmsg` system calls.

## 1. Problem Statement & Goals

* **Problem**: The single-thread performance is limited by the overhead of executing a system call (`recv_from` / `send_to`) for every single packet. With 70k+ PPS, this leads to ~140k UDP system calls per second, consuming more than 75% of CPU time in kernel transitions.
* **Goal**: Reduce system call frequency by processing packets in batches (up to 64 packets per syscall) without introducing packet buffering delays or dynamic memory allocations.

## 2. Detailed Architecture & Design

### 2.1 Configuration
A constant is defined to specify the batch size:
```rust
const UDP_BATCH_SIZE: usize = 64;
```

### 2.2 Data Structures
To interface with `recvmmsg` and `sendmmsg` without heap allocations, we introduce a batch struct:
```rust
pub struct UdpBatch {
    mmsgs: [libc::mmsghdr; UDP_BATCH_SIZE],
    iovs: [libc::iovec; UDP_BATCH_SIZE],
    addrs: [libc::sockaddr_storage; UDP_BATCH_SIZE],
}

impl UdpBatch {
    pub fn new() -> Self {
        // SAFETY: All fields are POD types (mmsghdr, iovec, sockaddr_storage).
        // Zero-initializing them is safe and correct.
        unsafe { std::mem::zeroed() }
    }
}
```

We also implement a helper to parse `libc::sockaddr_storage` into `std::net::SocketAddr`:
```rust
fn sockaddr_to_socket_addr(addr: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr_in = unsafe { *(addr as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
            let port = u16::from_be(addr_in.sin_port);
            Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let addr_in6 = unsafe { *(addr as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
            let port = u16::from_be(addr_in6.sin6_port);
            Some(std::net::SocketAddr::new(std::net::IpAddr::V6(ip), port))
        }
        _ => None,
    }
}
```

### 2.3 Non-blocking Batch Receiving (`recvmmsg`)
When the socket becomes readable, we invoke `recvmmsg` with `MSG_DONTWAIT`. This guarantees the system call returns immediately with whatever packets are currently available in the kernel receive queue (up to 64), preventing any blocking/waiting delays.

* **Buffer Strategy**: A single flat `BytesMut` buffer is allocated once per loop iteration (or reused). Its size is `UDP_BATCH_SIZE * packet_buffer_size`.
* **Slicing**: The buffer is sliced into individual packet chunks using `split_to()`, which is a zero-copy operation.

```rust
_ = self.udp_socket.readable() => {
    let mut batch_buf = bytes::BytesMut::with_capacity(UDP_BATCH_SIZE * self.packet_buffer_size);
    unsafe { batch_buf.set_len(UDP_BATCH_SIZE * self.packet_buffer_size); }
    let fd = self.udp_socket.as_raw_fd();
    let packet_size = self.packet_buffer_size;
    
    let res = self.udp_socket.try_io(Interest::READABLE, || {
        // Set up iovecs and message headers pointing to batch_buf chunks
        for i in 0..UDP_BATCH_SIZE {
            let offset = i * packet_size;
            self.udp_batch.iovs[i].iov_base = unsafe { batch_buf.as_mut_ptr().add(offset) as *mut libc::c_void };
            self.udp_batch.iovs[i].iov_len = packet_size as libc::size_t;

            self.udp_batch.mmsgs[i].msg_hdr.msg_name = &mut self.udp_batch.addrs[i] as *mut libc::sockaddr_storage as *mut libc::c_void;
            self.udp_batch.mmsgs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            self.udp_batch.mmsgs[i].msg_hdr.msg_iov = &mut self.udp_batch.iovs[i] as *mut libc::iovec;
            self.udp_batch.mmsgs[i].msg_hdr.msg_iovlen = 1;
            self.udp_batch.mmsgs[i].msg_hdr.msg_control = std::ptr::null_mut();
            self.udp_batch.mmsgs[i].msg_hdr.msg_controllen = 0;
            self.udp_batch.mmsgs[i].msg_hdr.msg_flags = 0;
            self.udp_batch.mmsgs[i].msg_len = 0;
        }

        let count = unsafe {
            libc::recvmmsg(
                fd,
                self.udp_batch.mmsgs.as_mut_ptr(),
                UDP_BATCH_SIZE as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if count < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(count as usize)
    });

    match res {
        Ok(count) if count > 0 => {
            let now = std::time::Instant::now();
            let mut remaining = batch_buf;
            for i in 0..count {
                let len = self.udp_batch.mmsgs[i].msg_len as usize;
                let mut packet_chunk = remaining.split_to(packet_size);
                if len > 0 {
                    packet_chunk.truncate(len);
                    if let Some(remote_addr) = sockaddr_to_socket_addr(&self.udp_batch.addrs[i]) {
                        self.handle_udp_packet(packet_chunk, remote_addr, &dp_snapshot, now, &mut local_stats).await;
                    }
                }
            }
            self.process_endpoint_transmits().await;
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(e) => {
            log::warn!("UDP recvmmsg error: {:?}", e);
        }
        _ => {}
    }
}
```

### 2.4 Batch Sending (`sendmmsg`)
In `process_endpoint_transmits`, instead of sending transmits one-by-one, we collect up to 64 transmits and send them in a single batch using `sendmmsg`.

```rust
struct TxBatch {
    mmsgs: [libc::mmsghdr; UDP_BATCH_SIZE],
    iovs: [libc::iovec; UDP_BATCH_SIZE],
    addrs: [libc::sockaddr_storage; UDP_BATCH_SIZE],
}
```

* Destination addresses are converted to `libc::sockaddr_storage` and stored in `addrs`.
* Payload pointers are assigned to `iovs`.
* We perform `sendmmsg` using `try_io` to transmit the batch non-blockingly.

## 3. Testing & Verification

* **Unit Tests**: Add tests to verify IP address conversion correctness.
* **Integration Tests**: Verify end-to-end packet transmission through the event loop under heavy load.
* **Performance Validation**: Run the core scalability test script to compare single-thread throughput.
