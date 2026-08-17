pub mod dns;
pub mod io_registry;
pub mod nat;
pub mod packet;
pub mod quic_flow;
pub mod session;
pub mod worker;

pub use dns::{
    clamp_edns_udp_payload, classify_query, domain_matches, parse_question as parse_dns_question,
    response_matches_query, transaction_key, DnsError, DnsQuestion, DnsReverseKey, DnsRoute,
    DnsTransaction, DnsTransactionKey, DnsTransactionTable, RemoteDomainRules, DNS_PAYLOAD_MAX,
};
pub use io_registry::{IoOwnerKey, IoRegistry, RegistryError};
pub use nat::{NatBinding, NatError, NatTable, ReverseNatDirectory, ReverseNatKey, SessionLocator};
pub use packet::{
    clamp_tcp_mss, ensure_udp_payload_len, ip_packet_is_fragmented, parse_flow_key,
    parse_tcp_flags, prepare_forwarded_packet, rewrite_packet, udp_payload, udp_payload_mut,
    FlowKey, PacketError, TransportProtocol, TCP_MAX_SAFE_MSS,
};
pub use quic_flow::{bootstrap_owner, ActiveDcidIndex, DcidOwner, QuicFlow, QuicFlowError};
pub use session::{
    InterceptIoUpdate, Session, SessionError, SessionKey, SessionTable, TcpSessionState,
};
pub use worker::{
    bounded_flow_channels, DispatchOutcome, DispatchStats, DnsFlowConfig, DnsFlowError,
    ExpiredDnsTransaction, FlowChannelError, FlowDispatcher, FlowMessage, FlowWorkerError,
    FlowWorkerState, FlowWorkerStats, HandledDnsQuery, HandledDnsResponse, HandledIntercept,
    HandledReverse, IoTransmit, OuterRoute,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuicFlowId(pub u64);
