use crate::buffer_pool::{BufferPool, PooledBuf};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use std::collections::VecDeque;

pub struct DummyPhyDevice {
    pub rx_queue: VecDeque<PooledBuf>,
    pub tx_queue: VecDeque<PooledBuf>,
    pub mtu: usize,
    pub buffer_pool: BufferPool,
}

impl Device for DummyPhyDevice {
    type RxToken<'a> = DummyRxToken;
    type TxToken<'a> = DummyTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(|packet| {
            (
                DummyRxToken { packet },
                DummyTxToken {
                    queue: &mut self.tx_queue,
                    pool: self.buffer_pool.clone(),
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(DummyTxToken {
            queue: &mut self.tx_queue,
            pool: self.buffer_pool.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
        caps
    }
}

pub struct DummyRxToken {
    packet: PooledBuf,
}

impl RxToken for DummyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.as_slice())
    }
}

pub struct DummyTxToken<'a> {
    queue: &'a mut VecDeque<PooledBuf>,
    pool: BufferPool,
}

impl<'a> TxToken for DummyTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self.pool.get();
        let result = f(&mut buffer.as_mut_capacity()[..len]);
        buffer.set_len(len);
        self.queue.push_back(buffer);
        result
    }
}

pub struct UserspaceTcpStack {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    pub device: DummyPhyDevice,
}

impl UserspaceTcpStack {
    pub fn new(ip_cidrs: Vec<IpCidr>, mtu: usize, buffer_pool: BufferPool) -> Result<Self, String> {
        if ip_cidrs.is_empty() {
            return Err("smoltcp stack requires at least one interface address".to_string());
        }
        let mut device = DummyPhyDevice {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
            buffer_pool,
        };
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::now());
        let mut push_error = None;
        iface.update_ip_addrs(|addrs| {
            addrs.clear();
            for ip_cidr in ip_cidrs {
                if addrs.push(ip_cidr).is_err() {
                    push_error = Some("too many interface addresses for smoltcp stack".to_string());
                    break;
                }
            }
        });
        if let Some(error) = push_error {
            return Err(error);
        }

        let sockets = SocketSet::new(vec![]);
        Ok(Self {
            iface,
            sockets,
            device,
        })
    }

    pub fn create_tcp_socket(
        &mut self,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
    ) -> Result<SocketHandle, String> {
        let rx_buffer = tcp::SocketBuffer::new(vec![0; rx_buffer_size]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; tx_buffer_size]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        Ok(self.sockets.add(socket))
    }

    pub fn get_socket_state(&self, handle: SocketHandle) -> Result<(), String> {
        let _socket = self.sockets.get::<tcp::Socket>(handle);
        Ok(())
    }

    pub fn process_input_packet(&mut self, packet: PooledBuf) {
        self.device.rx_queue.push_back(packet);
        let timestamp = Instant::now();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_smoltcp_stack_creation() {
        let ip_cidr = IpCidr::from_str("10.0.0.2/24").unwrap();
        let mut stack = UserspaceTcpStack::new(vec![ip_cidr], 1400, BufferPool::new(1656)).unwrap();
        let handle = stack.create_tcp_socket(1024, 1024).unwrap();
        assert!(stack.get_socket_state(handle).is_ok());
        assert_eq!(stack.device.capabilities().max_transmission_unit, 1400);
    }

    #[test]
    fn test_smoltcp_stack_requires_configured_addresses() {
        assert!(UserspaceTcpStack::new(Vec::new(), 1400, BufferPool::new(1656)).is_err());
    }
}
