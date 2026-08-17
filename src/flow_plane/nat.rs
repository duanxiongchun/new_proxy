use crate::flow_plane::{FlowKey, SessionId, TransportProtocol};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

const TCP_REUSE_QUARANTINE: Duration = Duration::from_secs(120);
const UDP_REUSE_QUARANTINE: Duration = Duration::from_secs(60);
const ICMP_REUSE_QUARANTINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLocator {
    pub flow_worker_id: usize,
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReverseNatKey(pub FlowKey);

impl From<FlowKey> for ReverseNatKey {
    fn from(flow: FlowKey) -> Self {
        Self::from_return_flow(flow)
    }
}

impl ReverseNatKey {
    pub fn from_translated_flow(flow: &FlowKey) -> Self {
        match flow.protocol {
            TransportProtocol::Tcp | TransportProtocol::Udp => Self(flow.reverse()),
            TransportProtocol::Icmp | TransportProtocol::Icmpv6 => Self(FlowKey {
                source: flow.destination,
                destination: flow.source,
                source_port: flow.source_port,
                destination_port: 0,
                protocol: flow.protocol,
            }),
        }
    }

    fn from_return_flow(mut flow: FlowKey) -> Self {
        if matches!(
            flow.protocol,
            TransportProtocol::Icmp | TransportProtocol::Icmpv6
        ) {
            flow.destination_port = 0;
        }
        Self(flow)
    }
}

#[derive(Debug, Default)]
pub struct ReverseNatDirectory {
    entries: HashMap<ReverseNatKey, SessionLocator>,
}

impl ReverseNatDirectory {
    pub fn publish(
        &mut self,
        binding: &NatBinding,
        locator: SessionLocator,
    ) -> Result<(), NatError> {
        let key = ReverseNatKey::from_translated_flow(&binding.translated);
        match self.entries.get(&key) {
            Some(existing) if *existing == locator => Ok(()),
            Some(_) => Err(NatError::DuplicateReverseKey(key)),
            None => {
                self.entries.insert(key, locator);
                Ok(())
            }
        }
    }

    pub fn lookup(&self, return_flow: &FlowKey) -> Option<SessionLocator> {
        self.entries
            .get(&ReverseNatKey::from_return_flow(return_flow.clone()))
            .copied()
    }

    pub fn retire(
        &mut self,
        binding: &NatBinding,
        expected: SessionLocator,
    ) -> Option<SessionLocator> {
        let key = ReverseNatKey::from_translated_flow(&binding.translated);
        if self.entries.get(&key) != Some(&expected) {
            return None;
        }
        self.entries.remove(&key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NatBinding {
    pub original: FlowKey,
    pub translated: FlowKey,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NatError {
    #[error("SNAT port range is invalid")]
    InvalidPortRange,
    #[error("SNAT address family does not match the original flow")]
    AddressFamilyMismatch,
    #[error("SNAT port range is exhausted")]
    PortRangeExhausted,
    #[error("session {0:?} already has a NAT binding")]
    DuplicateSession(SessionId),
    #[error("reverse NAT key already exists")]
    DuplicateReverseKey(ReverseNatKey),
    #[error("session {0:?} has no NAT binding")]
    UnknownSession(SessionId),
}

#[derive(Debug)]
pub struct NatTable {
    snat_ipv4: Option<Ipv4Addr>,
    snat_ipv6: Option<Ipv6Addr>,
    available_ports: BTreeSet<u16>,
    forward: HashMap<SessionId, NatBinding>,
    reverse: HashMap<ReverseNatKey, SessionLocator>,
    quarantined: HashMap<ReverseNatKey, Instant>,
}

impl NatTable {
    pub fn new(snat_ip: IpAddr, ports: RangeInclusive<u16>) -> Result<Self, NatError> {
        let (snat_ipv4, snat_ipv6) = match snat_ip {
            IpAddr::V4(address) => (Some(address), None),
            IpAddr::V6(address) => (None, Some(address)),
        };
        Self::new_dual(snat_ipv4, snat_ipv6, ports)
    }

    pub fn new_dual(
        snat_ipv4: Option<Ipv4Addr>,
        snat_ipv6: Option<Ipv6Addr>,
        ports: RangeInclusive<u16>,
    ) -> Result<Self, NatError> {
        if ports.is_empty() {
            return Err(NatError::InvalidPortRange);
        }
        Ok(Self {
            snat_ipv4,
            snat_ipv6,
            available_ports: ports.collect(),
            forward: HashMap::new(),
            reverse: HashMap::new(),
            quarantined: HashMap::new(),
        })
    }

    pub fn allocate(
        &mut self,
        session_id: SessionId,
        original: FlowKey,
        locator: SessionLocator,
    ) -> Result<&NatBinding, NatError> {
        self.allocate_at(session_id, original, locator, Instant::now())
    }

    fn allocate_at(
        &mut self,
        session_id: SessionId,
        original: FlowKey,
        locator: SessionLocator,
        now: Instant,
    ) -> Result<&NatBinding, NatError> {
        if self.forward.contains_key(&session_id) {
            return Err(NatError::DuplicateSession(session_id));
        }
        let snat_ip = match original.source {
            IpAddr::V4(_) => self.snat_ipv4.map(IpAddr::V4),
            IpAddr::V6(_) => self.snat_ipv6.map(IpAddr::V6),
        }
        .ok_or(NatError::AddressFamilyMismatch)?;

        self.quarantined.retain(|_, expires_at| *expires_at > now);
        let (port, translated, reverse_key) = self
            .available_ports
            .iter()
            .copied()
            .find_map(|port| {
                let mut translated = original.clone();
                translated.source = snat_ip;
                translated.source_port = port;
                let reverse_key = ReverseNatKey::from_translated_flow(&translated);
                (!self.reverse.contains_key(&reverse_key)
                    && !self.quarantined.contains_key(&reverse_key))
                .then_some((port, translated, reverse_key))
            })
            .ok_or(NatError::PortRangeExhausted)?;

        self.available_ports.remove(&port);
        self.reverse.insert(reverse_key, locator);
        self.forward.insert(
            session_id,
            NatBinding {
                original,
                translated,
            },
        );
        Ok(self
            .forward
            .get(&session_id)
            .expect("binding was inserted for this session"))
    }

    pub fn get(&self, session_id: SessionId) -> Option<&NatBinding> {
        self.forward.get(&session_id)
    }

    pub fn lookup_reverse(&self, return_flow: &FlowKey) -> Option<SessionLocator> {
        self.reverse
            .get(&ReverseNatKey::from_return_flow(return_flow.clone()))
            .copied()
    }

    pub fn remove(&mut self, session_id: SessionId) -> Result<NatBinding, NatError> {
        self.remove_at(session_id, Instant::now())
    }

    fn remove_at(&mut self, session_id: SessionId, now: Instant) -> Result<NatBinding, NatError> {
        let binding = self
            .forward
            .remove(&session_id)
            .ok_or(NatError::UnknownSession(session_id))?;
        let reverse_key = ReverseNatKey::from_translated_flow(&binding.translated);
        self.reverse.remove(&reverse_key);
        self.quarantined.insert(
            reverse_key,
            now + reuse_quarantine(binding.translated.protocol),
        );
        self.available_ports.insert(binding.translated.source_port);
        Ok(binding)
    }

    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }

    pub fn reverse_len(&self) -> usize {
        self.reverse.len()
    }
}

const fn reuse_quarantine(protocol: TransportProtocol) -> Duration {
    match protocol {
        TransportProtocol::Tcp => TCP_REUSE_QUARANTINE,
        TransportProtocol::Udp => UDP_REUSE_QUARANTINE,
        TransportProtocol::Icmp | TransportProtocol::Icmpv6 => ICMP_REUSE_QUARANTINE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_plane::{FlowKey, SessionId, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn flow(source_port: u16) -> FlowKey {
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            source_port,
            destination_port: 443,
            protocol: TransportProtocol::Tcp,
        }
    }

    fn icmp_flow(identifier: u16, message_type: u8) -> FlowKey {
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            source_port: identifier,
            destination_port: u16::from(message_type) << 8,
            protocol: TransportProtocol::Icmp,
        }
    }

    fn ipv6_flow(source_port: u16) -> FlowKey {
        FlowKey {
            source: "2001:db8:1::2".parse().unwrap(),
            destination: "2001:db8:2::10".parse().unwrap(),
            source_port,
            destination_port: 443,
            protocol: TransportProtocol::Tcp,
        }
    }

    fn locator(session_id: u64) -> SessionLocator {
        SessionLocator {
            flow_worker_id: 2,
            session_id: SessionId(session_id),
        }
    }

    #[test]
    fn v1_unit_nat_allocates_unique_tuples_and_reverse_indexes() {
        let mut table =
            NatTable::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001).unwrap();

        let first = table
            .allocate(SessionId(1), flow(10001), locator(1))
            .unwrap()
            .clone();
        let second = table
            .allocate(SessionId(2), flow(10002), locator(2))
            .unwrap()
            .clone();

        assert_eq!(first.translated.source_port, 40000);
        assert_eq!(second.translated.source_port, 40001);
        assert_ne!(first.translated, second.translated);
        assert_eq!(
            table.lookup_reverse(&first.translated.reverse()),
            Some(locator(1))
        );
        assert_eq!(
            table.lookup_reverse(&second.translated.reverse()),
            Some(locator(2))
        );
    }

    #[test]
    fn v1_unit_nat_quarantines_released_reverse_tuple_before_reuse() {
        let mut table =
            NatTable::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001).unwrap();
        let now = Instant::now();
        table
            .allocate_at(SessionId(1), flow(10001), locator(1), now)
            .unwrap();
        table
            .allocate_at(SessionId(2), flow(10002), locator(2), now)
            .unwrap();

        assert_eq!(
            table.allocate_at(SessionId(3), flow(10003), locator(3), now),
            Err(NatError::PortRangeExhausted)
        );

        table.remove_at(SessionId(1), now).unwrap();
        assert_eq!(
            table.allocate_at(SessionId(3), flow(10003), locator(3), now),
            Err(NatError::PortRangeExhausted)
        );
        let reused_at = now + TCP_REUSE_QUARANTINE;
        let reused = table
            .allocate_at(SessionId(3), flow(10003), locator(3), reused_at)
            .unwrap();
        assert_eq!(reused.translated.source_port, 40000);
    }

    #[test]
    fn v1_unit_reverse_directory_retire_is_locator_compare_and_swap() {
        let mut directory = ReverseNatDirectory::default();
        let binding = NatBinding {
            original: flow(10001),
            translated: FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source_port: 40000,
                ..flow(10001)
            },
        };
        directory.publish(&binding, locator(1)).unwrap();

        assert_eq!(directory.retire(&binding, locator(2)), None);
        assert_eq!(
            directory.lookup(&binding.translated.reverse()),
            Some(locator(1))
        );
        assert_eq!(directory.retire(&binding, locator(1)), Some(locator(1)));
    }

    #[test]
    fn v1_unit_nat_rejects_duplicate_session_without_mutating_indexes() {
        let mut table =
            NatTable::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001).unwrap();
        table
            .allocate(SessionId(1), flow(10001), locator(1))
            .unwrap();

        assert_eq!(
            table.allocate(SessionId(1), flow(10002), locator(1)),
            Err(NatError::DuplicateSession(SessionId(1)))
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.reverse_len(), 1);
    }

    #[test]
    fn v1_unit_nat_icmp_reply_uses_identifier_not_changed_message_type() {
        let mut table =
            NatTable::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 40000..=40001).unwrap();
        let translated = table
            .allocate(SessionId(1), icmp_flow(77, 8), locator(1))
            .unwrap()
            .translated
            .clone();
        let reply = FlowKey {
            source: translated.destination,
            destination: translated.source,
            source_port: translated.source_port,
            destination_port: 0,
            protocol: TransportProtocol::Icmp,
        };

        assert_eq!(table.lookup_reverse(&reply), Some(locator(1)));
    }

    #[test]
    fn v1_unit_nat_supports_ipv6_snat_and_reverse_lookup() {
        let snat_ip = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let mut table = NatTable::new(IpAddr::V6(snat_ip), 40000..=40001).unwrap();

        let binding = table
            .allocate(SessionId(1), ipv6_flow(10001), locator(1))
            .unwrap()
            .clone();

        assert_eq!(binding.translated.source, IpAddr::V6(snat_ip));
        assert_eq!(
            table.lookup_reverse(&binding.translated.reverse()),
            Some(locator(1))
        );
    }

    #[test]
    fn v1_unit_nat_rejects_address_family_mismatch_without_state() {
        let mut table = NatTable::new(
            IpAddr::V6("2001:db8:ffff::1".parse().unwrap()),
            40000..=40001,
        )
        .unwrap();

        assert_eq!(
            table.allocate(SessionId(1), flow(10001), locator(1)),
            Err(NatError::AddressFamilyMismatch)
        );
        assert!(table.is_empty());
        assert_eq!(table.reverse_len(), 0);
    }
}
