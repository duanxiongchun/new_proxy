pub mod io_registry;
pub mod nat;
pub mod packet;
pub mod quic_flow;
pub mod session;
pub mod worker;

pub use io_registry::{IoOwnerKey, IoRegistry, RegistryError};
pub use nat::{NatBinding, NatError, NatTable, ReverseNatDirectory, ReverseNatKey, SessionLocator};
pub use packet::{parse_flow_key, rewrite_packet, FlowKey, PacketError, TransportProtocol};
pub use quic_flow::{bootstrap_owner, ActiveDcidIndex, DcidOwner, QuicFlow, QuicFlowError};
pub use session::{InterceptIoUpdate, Session, SessionError, SessionKey, SessionTable};
pub use worker::{
    bounded_flow_channels, DispatchOutcome, DispatchStats, FlowChannelError, FlowDispatcher,
    FlowMessage, FlowWorkerError, FlowWorkerState, FlowWorkerStats, HandledIntercept,
    HandledReverse, IoTransmit, OuterRoute,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SessionId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuicFlowId(pub u64);
