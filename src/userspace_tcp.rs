use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use std::collections::VecDeque;

pub struct DummyPhyDevice {
    pub rx_queue: VecDeque<Vec<u8>>,
    pub tx_queue: VecDeque<Vec<u8>>,
}

impl Device for DummyPhyDevice {
    type RxToken<'a> = DummyRxToken;
    type TxToken<'a> = DummyTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(|packet| {
            (
                DummyRxToken { packet },
                DummyTxToken { queue: &mut self.tx_queue },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(DummyTxToken { queue: &mut self.tx_queue })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

pub struct DummyRxToken {
    packet: Vec<u8>,
}

impl RxToken for DummyRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct DummyTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for DummyTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
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
    pub fn new(ip_cidr: IpCidr) -> Result<Self, String> {
        let mut device = DummyPhyDevice {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        };
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs.push(ip_cidr).unwrap();
        });

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

    pub fn process_input_packet(&mut self, packet: Vec<u8>) {
        self.device.rx_queue.push_back(packet);
        let timestamp = Instant::now();
        self.iface.poll(timestamp, &mut self.device, &mut self.sockets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_smoltcp_stack_creation() {
        let ip_cidr = IpCidr::from_str("10.0.0.2/24").unwrap();
        let mut stack = UserspaceTcpStack::new(ip_cidr).unwrap();
        let handle = stack.create_tcp_socket(1024, 1024).unwrap();
        assert!(stack.get_socket_state(handle).is_ok());
    }
}
