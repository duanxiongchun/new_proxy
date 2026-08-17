use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;

pub const DNS_PAYLOAD_MAX: usize = 1232;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsRoute {
    Local(DnsQuestion),
    Remote(DnsQuestion),
    LocalFallback,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DnsTransactionKey {
    Question {
        client: SocketAddr,
        id: u16,
        qname: String,
        qtype: u16,
        qclass: u16,
    },
    Opaque {
        client: SocketAddr,
        id: Option<u16>,
        payload_hash: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DnsReverseKey {
    pub resolver: SocketAddr,
    pub nat_ip: IpAddr,
    pub nat_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsTransaction {
    pub id: u64,
    pub key: DnsTransactionKey,
    pub client: SocketAddr,
    pub resolver: SocketAddr,
    pub nat_ip: IpAddr,
    pub nat_port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DnsError {
    #[error("DNS payload is truncated")]
    Truncated,
    #[error("DNS query must use standard opcode")]
    NonStandardOpcode,
    #[error("DNS query must contain exactly one question")]
    QuestionCount,
    #[error("DNS name is malformed")]
    MalformedName,
    #[error("DNS transaction capacity is exhausted")]
    CapacityExhausted,
    #[error("DNS NAT port range is exhausted")]
    NatPortExhausted,
    #[error("DNS NAT port range is invalid")]
    InvalidPortRange,
    #[error("DNS response does not match the original query")]
    ResponseMismatch,
    #[error("DNS payload is not a query")]
    NotQuery,
}

#[derive(Debug)]
pub struct DnsTransactionTable {
    capacity: usize,
    nat_ip: IpAddr,
    available_ports: BTreeSet<u16>,
    next_id: u64,
    by_key: HashMap<DnsTransactionKey, DnsTransaction>,
    by_id: HashMap<u64, DnsTransactionKey>,
    reverse: HashMap<DnsReverseKey, u64>,
}

impl DnsTransactionTable {
    pub fn new(
        capacity: usize,
        nat_ip: IpAddr,
        ports: RangeInclusive<u16>,
    ) -> Result<Self, DnsError> {
        if ports.is_empty() {
            return Err(DnsError::InvalidPortRange);
        }
        Ok(Self {
            capacity,
            nat_ip,
            available_ports: ports.collect(),
            next_id: 1,
            by_key: HashMap::new(),
            by_id: HashMap::new(),
            reverse: HashMap::new(),
        })
    }

    pub fn get_or_create(
        &mut self,
        key: DnsTransactionKey,
        client: SocketAddr,
        resolver: SocketAddr,
    ) -> Result<&DnsTransaction, DnsError> {
        if self.by_key.contains_key(&key) {
            return Ok(self.by_key.get(&key).expect("checked transaction exists"));
        }
        if self.by_key.len() >= self.capacity {
            return Err(DnsError::CapacityExhausted);
        }
        let nat_port = self
            .available_ports
            .first()
            .copied()
            .ok_or(DnsError::NatPortExhausted)?;
        self.available_ports.remove(&nat_port);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let transaction = DnsTransaction {
            id,
            key: key.clone(),
            client,
            resolver,
            nat_ip: self.nat_ip,
            nat_port,
        };
        let reverse = DnsReverseKey {
            resolver,
            nat_ip: self.nat_ip,
            nat_port,
        };
        self.by_id.insert(id, key.clone());
        self.reverse.insert(reverse, id);
        self.by_key.insert(key.clone(), transaction);
        Ok(self
            .by_key
            .get(&key)
            .expect("transaction was inserted for this key"))
    }

    pub fn lookup_reverse(&self, key: &DnsReverseKey) -> Option<&DnsTransaction> {
        self.reverse
            .get(key)
            .and_then(|id| self.by_id.get(id))
            .and_then(|key| self.by_key.get(key))
    }

    pub fn complete(&mut self, id: u64) -> Option<DnsTransaction> {
        let key = self.by_id.remove(&id)?;
        let transaction = self.by_key.remove(&key)?;
        self.reverse.remove(&DnsReverseKey {
            resolver: transaction.resolver,
            nat_ip: transaction.nat_ip,
            nat_port: transaction.nat_port,
        });
        self.available_ports.insert(transaction.nat_port);
        Some(transaction)
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemoteDomainRules {
    suffixes: Arc<HashSet<String>>,
}

impl RemoteDomainRules {
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        Self {
            suffixes: Arc::new(domains.into_iter().collect()),
        }
    }

    pub fn matches(&self, qname: &str) -> bool {
        self.suffixes.contains(qname)
            || qname
                .match_indices('.')
                .any(|(offset, _)| self.suffixes.contains(&qname[offset + 1..]))
    }

    pub fn len(&self) -> usize {
        self.suffixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty()
    }
}

impl From<Vec<String>> for RemoteDomainRules {
    fn from(domains: Vec<String>) -> Self {
        Self::new(domains)
    }
}

pub fn classify_query(payload: &[u8], remote_domains: &RemoteDomainRules) -> DnsRoute {
    match validate_query(payload) {
        Ok(question) if remote_domains.matches(&question.qname) => DnsRoute::Remote(question),
        Ok(question) => DnsRoute::Local(question),
        Err(_) => DnsRoute::LocalFallback,
    }
}

pub fn transaction_key(client: SocketAddr, payload: &[u8]) -> DnsTransactionKey {
    match validate_query(payload) {
        Ok(question) => DnsTransactionKey::Question {
            client,
            id: dns_id(payload).expect("parse_question requires DNS header"),
            qname: question.qname,
            qtype: question.qtype,
            qclass: question.qclass,
        },
        Err(_) => DnsTransactionKey::Opaque {
            client,
            id: dns_id(payload),
            payload_hash: fnv1a(payload),
        },
    }
}

pub fn response_matches_query(query: &[u8], response: &[u8]) -> Result<(), DnsError> {
    let query_id = dns_id(query).ok_or(DnsError::Truncated)?;
    let response_id = dns_id(response).ok_or(DnsError::Truncated)?;
    if response_id != query_id {
        return Err(DnsError::ResponseMismatch);
    }
    let header = response.get(..12).ok_or(DnsError::Truncated)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 {
        return Err(DnsError::ResponseMismatch);
    }
    let query_question = parse_question(query).map_err(|_| DnsError::ResponseMismatch)?;
    let response_question =
        validate_message(response, true).map_err(|_| DnsError::ResponseMismatch)?;
    if response_question != query_question {
        return Err(DnsError::ResponseMismatch);
    }
    Ok(())
}

pub fn clamp_edns_udp_payload(payload: &mut [u8]) -> Result<bool, DnsError> {
    let header = payload.get(..12).ok_or(DnsError::Truncated)?;
    let qdcount = u16::from_be_bytes([header[4], header[5]]);
    let ancount = u16::from_be_bytes([header[6], header[7]]);
    let nscount = u16::from_be_bytes([header[8], header[9]]);
    let arcount = u16::from_be_bytes([header[10], header[11]]);
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_name(payload, offset)?;
        offset = offset.checked_add(4).ok_or(DnsError::Truncated)?;
        if offset > payload.len() {
            return Err(DnsError::Truncated);
        }
    }
    for _ in 0..ancount.saturating_add(nscount) {
        offset = skip_resource_record(payload, offset)?;
    }
    let mut clamped = false;
    for _ in 0..arcount {
        offset = skip_name(payload, offset)?;
        let rr = payload
            .get_mut(offset..offset + 10)
            .ok_or(DnsError::Truncated)?;
        let rr_type = u16::from_be_bytes([rr[0], rr[1]]);
        let rdlength = u16::from_be_bytes([rr[8], rr[9]]);
        if rr_type == 41 {
            let advertised = u16::from_be_bytes([rr[2], rr[3]]);
            if advertised > DNS_PAYLOAD_MAX as u16 {
                rr[2..4].copy_from_slice(&(DNS_PAYLOAD_MAX as u16).to_be_bytes());
                clamped = true;
            }
        }
        offset = offset
            .checked_add(10)
            .and_then(|offset| offset.checked_add(usize::from(rdlength)))
            .ok_or(DnsError::Truncated)?;
        if offset > payload.len() {
            return Err(DnsError::Truncated);
        }
    }
    if offset != payload.len() {
        return Err(DnsError::Truncated);
    }
    Ok(clamped)
}

pub fn parse_question(payload: &[u8]) -> Result<DnsQuestion, DnsError> {
    let header = payload.get(..12).ok_or(DnsError::Truncated)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if flags & 0x8000 != 0 {
        return Err(DnsError::NotQuery);
    }
    if flags & 0x7800 != 0 {
        return Err(DnsError::NonStandardOpcode);
    }
    parse_question_fields(payload)
}

fn validate_query(payload: &[u8]) -> Result<DnsQuestion, DnsError> {
    validate_message(payload, false)
}

fn validate_message(payload: &[u8], response: bool) -> Result<DnsQuestion, DnsError> {
    let header = payload.get(..12).ok_or(DnsError::Truncated)?;
    let flags = u16::from_be_bytes([header[2], header[3]]);
    if (flags & 0x8000 != 0) != response {
        return Err(if response {
            DnsError::ResponseMismatch
        } else {
            DnsError::NotQuery
        });
    }
    if flags & 0x7800 != 0 {
        return Err(DnsError::NonStandardOpcode);
    }
    let question = parse_question_fields(payload)?;
    let ancount = u16::from_be_bytes([header[6], header[7]]);
    let nscount = u16::from_be_bytes([header[8], header[9]]);
    let arcount = u16::from_be_bytes([header[10], header[11]]);
    let mut offset = skip_name(payload, 12)?
        .checked_add(4)
        .ok_or(DnsError::Truncated)?;
    for _ in 0..ancount.saturating_add(nscount).saturating_add(arcount) {
        offset = skip_resource_record(payload, offset)?;
    }
    if offset != payload.len() {
        return Err(DnsError::Truncated);
    }
    Ok(question)
}

fn parse_question_fields(payload: &[u8]) -> Result<DnsQuestion, DnsError> {
    let header = payload.get(..12).ok_or(DnsError::Truncated)?;
    let qdcount = u16::from_be_bytes([header[4], header[5]]);
    if qdcount != 1 {
        return Err(DnsError::QuestionCount);
    }
    let (qname, offset) = parse_name(payload, 12)?;
    let fields = payload.get(offset..offset + 4).ok_or(DnsError::Truncated)?;
    Ok(DnsQuestion {
        qname,
        qtype: u16::from_be_bytes([fields[0], fields[1]]),
        qclass: u16::from_be_bytes([fields[2], fields[3]]),
    })
}

fn skip_resource_record(payload: &[u8], offset: usize) -> Result<usize, DnsError> {
    let offset = skip_name(payload, offset)?;
    let rr = payload
        .get(offset..offset + 10)
        .ok_or(DnsError::Truncated)?;
    let rdlength = u16::from_be_bytes([rr[8], rr[9]]);
    offset
        .checked_add(10)
        .and_then(|offset| offset.checked_add(usize::from(rdlength)))
        .filter(|offset| *offset <= payload.len())
        .ok_or(DnsError::Truncated)
}

fn skip_name(payload: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    let start = offset;
    for _ in 0..128 {
        let length = *payload.get(offset).ok_or(DnsError::Truncated)?;
        if length & 0xc0 == 0xc0 {
            validate_name_pointer(payload, offset, start)?;
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::MalformedName);
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(usize::from(length))
            .filter(|offset| *offset <= payload.len())
            .ok_or(DnsError::Truncated)?;
    }
    Err(DnsError::MalformedName)
}

fn validate_name_pointer(
    payload: &[u8],
    offset: usize,
    owner_start: usize,
) -> Result<(), DnsError> {
    let next = *payload.get(offset + 1).ok_or(DnsError::Truncated)?;
    let first = payload[offset];
    let pointer = (usize::from(first & 0x3f) << 8) | usize::from(next);
    if pointer >= owner_start {
        return Err(DnsError::MalformedName);
    }
    parse_name(payload, pointer).map(|_| ())
}

pub fn domain_matches(rule: &str, qname: &str) -> bool {
    qname == rule
        || qname
            .strip_suffix(rule)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn parse_name(payload: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut next_offset = None;
    let mut seen = HashSet::new();
    for _ in 0..128 {
        if !seen.insert(offset) {
            return Err(DnsError::MalformedName);
        }
        let length = *payload.get(offset).ok_or(DnsError::Truncated)?;
        if length & 0xc0 == 0xc0 {
            let next = *payload.get(offset + 1).ok_or(DnsError::Truncated)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(next);
            if pointer >= payload.len() {
                return Err(DnsError::MalformedName);
            }
            next_offset.get_or_insert(offset + 2);
            offset = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::MalformedName);
        }
        offset += 1;
        if length == 0 {
            let end = next_offset.unwrap_or(offset);
            if labels.is_empty() {
                return Err(DnsError::MalformedName);
            }
            return Ok((labels.join("."), end));
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(DnsError::MalformedName);
        }
        let label = payload
            .get(offset..offset + length)
            .ok_or(DnsError::Truncated)?;
        let label = normalize_label(label)?;
        labels.push(label);
        offset += length;
    }
    Err(DnsError::MalformedName)
}

fn normalize_label(label: &[u8]) -> Result<String, DnsError> {
    if label.is_empty()
        || label.starts_with(b"-")
        || label.ends_with(b"-")
        || !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(DnsError::MalformedName);
    }
    let text = std::str::from_utf8(label).map_err(|_| DnsError::MalformedName)?;
    Ok(text.to_ascii_lowercase())
}

fn dns_id(payload: &[u8]) -> Option<u16> {
    let header = payload.get(..2)?;
    Some(u16::from_be_bytes([header[0], header[1]]))
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());
        for label in qname.trim_end_matches('.').split('.') {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label.as_bytes());
        }
        payload.push(0);
        payload.extend_from_slice(&qtype.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload
    }

    fn response_for(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] |= 0x80;
        response
    }

    #[test]
    fn v1_unit_dns_parser_normalizes_single_question_and_matches_suffix() {
        let question = parse_question(&query(7, "WWW.Google.COM.", 1)).unwrap();

        assert_eq!(question.qname, "www.google.com");
        assert_eq!(question.qtype, 1);
        assert_eq!(question.qclass, 1);
        assert!(domain_matches("google.com", "google.com"));
        assert!(domain_matches("google.com", "www.google.com"));
        assert!(!domain_matches("google.com", "notgoogle.com"));
    }

    #[test]
    fn v1_unit_dns_parser_rejects_bad_opcode_count_and_compression_loop() {
        let mut opcode = query(1, "example.com", 1);
        opcode[2] = 0x08;
        assert_eq!(parse_question(&opcode), Err(DnsError::NonStandardOpcode));

        let mut response_like = query(1, "example.com", 1);
        response_like[2] = 0x80;
        assert_eq!(parse_question(&response_like), Err(DnsError::NotQuery));

        let mut multi = query(1, "example.com", 1);
        multi[5] = 2;
        assert_eq!(parse_question(&multi), Err(DnsError::QuestionCount));

        let mut looped = vec![0u8; 16];
        looped[5] = 1;
        looped[12] = 0xc0;
        looped[13] = 12;
        assert_eq!(parse_question(&looped), Err(DnsError::MalformedName));
    }

    #[test]
    fn v1_unit_dns_validation_rejects_invalid_resource_record_pointer() {
        let query = query(1, "example.com", 1);
        let mut response = response_for(&query);
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0xff]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());

        assert_eq!(
            validate_message(&response, true),
            Err(DnsError::MalformedName)
        );
    }

    #[test]
    fn v1_unit_dns_classification_uses_remote_suffix_or_local_fallback() {
        let rules = RemoteDomainRules::new(["google.com".to_string(), "github.com".to_string()]);

        assert!(matches!(
            classify_query(&query(1, "www.google.com", 1), &rules),
            DnsRoute::Remote(question) if question.qname == "www.google.com"
        ));
        assert!(matches!(
            classify_query(&query(1, "local.example", 1), &rules),
            DnsRoute::Local(question) if question.qname == "local.example"
        ));
        assert_eq!(classify_query(&[0, 1, 2], &rules), DnsRoute::LocalFallback);
    }

    #[test]
    fn v1_unit_remote_domain_rules_match_only_label_suffixes() {
        let rules =
            RemoteDomainRules::new(["example.com".to_string(), "deep.service.test".to_string()]);

        assert!(rules.matches("example.com"));
        assert!(rules.matches("www.example.com"));
        assert!(rules.matches("a.b.deep.service.test"));
        assert!(!rules.matches("notexample.com"));
        assert!(!rules.matches("service.test"));
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn v1_unit_dns_edns_clamp_updates_advertised_payload_size() {
        let mut payload = query(3, "example.com", 1);
        payload[11] = 1;
        payload.push(0);
        payload.extend_from_slice(&41u16.to_be_bytes());
        payload.extend_from_slice(&4096u16.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes());

        assert_eq!(clamp_edns_udp_payload(&mut payload), Ok(true));

        let opt_offset = payload.len() - 11;
        assert_eq!(
            u16::from_be_bytes([payload[opt_offset + 3], payload[opt_offset + 4]]),
            DNS_PAYLOAD_MAX as u16
        );
        assert_eq!(clamp_edns_udp_payload(&mut payload), Ok(false));
    }

    #[test]
    fn v1_unit_dns_response_must_match_original_id_and_question() {
        let query = query(4, "example.com", 1);
        assert_eq!(
            response_matches_query(&query, &response_for(&query)),
            Ok(())
        );

        let mut wrong_id = response_for(&query);
        wrong_id[1] = 5;
        assert_eq!(
            response_matches_query(&query, &wrong_id),
            Err(DnsError::ResponseMismatch)
        );

        let mut wrong_question = response_for(&query);
        let label_start = 13;
        wrong_question[label_start] = b'X';
        assert_eq!(
            response_matches_query(&query, &wrong_question),
            Err(DnsError::ResponseMismatch)
        );
    }

    #[test]
    fn v1_unit_dns_transaction_reuses_retransmit_and_indexes_reverse_tuple() {
        let client = "192.0.2.10:53000".parse().unwrap();
        let resolver = "1.1.1.1:53".parse().unwrap();
        let key = transaction_key(client, &query(9, "google.com", 1));
        let mut table =
            DnsTransactionTable::new(4, "192.0.2.1".parse().unwrap(), 40000..=40001).unwrap();

        let first = table
            .get_or_create(key.clone(), client, resolver)
            .unwrap()
            .clone();
        let repeated = table.get_or_create(key, client, resolver).unwrap().clone();

        assert_eq!(first.id, repeated.id);
        assert_eq!(first.nat_port, 40000);
        assert_eq!(
            table.lookup_reverse(&DnsReverseKey {
                resolver,
                nat_ip: first.nat_ip,
                nat_port: first.nat_port,
            }),
            Some(&first)
        );
        assert_eq!(table.complete(first.id), Some(first));
        assert!(table.is_empty());
    }

    #[test]
    fn v1_unit_dns_transaction_enforces_capacity_and_port_exhaustion() {
        let resolver = "1.1.1.1:53".parse().unwrap();
        let mut capacity =
            DnsTransactionTable::new(1, "192.0.2.1".parse().unwrap(), 40000..=40001).unwrap();
        let first_client = "192.0.2.10:53000".parse().unwrap();
        let second_client = "192.0.2.11:53000".parse().unwrap();
        capacity
            .get_or_create(
                transaction_key(first_client, &query(1, "a.example", 1)),
                first_client,
                resolver,
            )
            .unwrap();
        assert_eq!(
            capacity.get_or_create(
                transaction_key(second_client, &query(2, "b.example", 1)),
                second_client,
                resolver,
            ),
            Err(DnsError::CapacityExhausted)
        );

        let mut ports =
            DnsTransactionTable::new(2, "192.0.2.1".parse().unwrap(), 40000..=40000).unwrap();
        ports
            .get_or_create(
                transaction_key(first_client, &query(1, "a.example", 1)),
                first_client,
                resolver,
            )
            .unwrap();
        assert_eq!(
            ports.get_or_create(
                transaction_key(second_client, &query(2, "b.example", 1)),
                second_client,
                resolver,
            ),
            Err(DnsError::NatPortExhausted)
        );
    }
}
