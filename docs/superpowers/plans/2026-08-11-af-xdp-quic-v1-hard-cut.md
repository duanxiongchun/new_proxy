# AF_XDP QUIC Appliance v1 Hard-Cut Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the legacy TUN/hybrid datapath and its tests with a single-client/server AF_XDP datapath whose Flow workers exclusively own QUIC, Session, dual-SNAT, reverse-NAT, and DCID lifecycle state.

**Architecture:** Build and verify a pure, platform-independent Flow plane before connecting it to `quinn-proto` and AF_XDP. Each `(ifindex, queue_id)` has one IO owner, each Session has one Flow owner, established tunnel ingress is dispatched by active DCID, and all IO/Flow communication uses bounded channels. Legacy runtime and tests are removed only after the replacement path is wired and green.

**Tech Stack:** Rust 2021, Cargo, `bytes`, `ipnet`, `quinn-proto` 0.10, Linux AF_XDP/XDP, Bash, Linux network namespaces.

## Global Constraints

- The only supported topology is one fixed `client <-> server`; no multi-peer, multi-tenant, dynamic-peer, WireGuard, hybrid, or TUN compatibility remains.
- AF_XDP is the only main datapath and inner IPv4/IPv6 packets must be encrypted by QUIC; plaintext inner-IP-over-UDP is forbidden.
- Every IO owner key is the complete non-ambiguous pair `(ifindex, queue_id)`.
- A Flow worker is the exclusive mutable owner of its Session, NAT binding, reverse-NAT binding, QUIC flow, and active DCID lifecycle.
- `dcid_len` is fixed, non-zero, and validated before runtime startup.
- Unknown DCIDs use deterministic `hash(dcid) % flow_worker_count` only for legal QUIC bootstrap packets; all other unknown DCIDs are dropped and counted.
- QUIC reconnect creates a new `quic_flow_id`; Sessions and NAT bound to the old connection are reclaimed and never implicitly migrated.
- Initial IO/Flow queues use bounded `std::sync::mpsc::sync_channel`; full queues drop and increment counters.
- Existing uncommitted edits in `src/quic_pool.rs`, `src/routing.rs`, `src/runtime.rs`, and `src/xdp_datapath/worker.rs` must be preserved and merged, never reverted.
- Every shared commit is green and ends exactly once with `Co-authored-by: TRAE CLI <noreply@bytedance.com>`.

---

## File Map

- `src/v1_config.rs`: Parse and validate only the fixed v1 appliance configuration.
- `src/flow_plane/mod.rs`: Public Flow-plane contracts and module exports.
- `src/flow_plane/io_registry.rs`: Unique `(ifindex, queue_id)` ownership registry.
- `src/flow_plane/packet.rs`: IPv4/IPv6 TCP/UDP/ICMP flow-key parsing and checksum-safe NAT rewriting.
- `src/flow_plane/nat.rs`: Deterministic port allocation plus forward and reverse NAT indexes.
- `src/flow_plane/quic_flow.rs`: `QuicFlowId`, stable tunnel queue binding, active DCID index, and bootstrap selection.
- `src/flow_plane/session.rs`: Session lifecycle and atomic coupling to NAT and QUIC flow.
- `src/flow_plane/worker.rs`: Bounded Flow messages, ingress handling, dispatch, and statistics.
- `src/quic_engine.rs`: TUN-independent `quinn-proto` connection driver consumed by Flow workers.
- `src/xdp_datapath/io_worker.rs`: One XSK owner for one `IoOwnerKey`, packet classification, and bounded messaging.
- `src/xdp_datapath/runtime.rs`: Build IO/Flow workers and own their shutdown lifecycle.
- `src/xdp_datapath/worker.rs`: Transitional source; reduced and then removed after logic is moved to focused modules.
- `src/main.rs`: Load only v1 config and launch only the AF_XDP v1 runtime.
- `tests/v1_flow_integration.rs`: In-process IO/Flow ownership and backpressure tests.
- `script/acceptance/run_acceptance.sh`: Unified v1-only quality gate.
- `script/acceptance/v1/lib.sh`: Netns, process, capture, stats, timeout, and cleanup helpers.
- `script/acceptance/v1/e2e_v1_*.sh`: Six v1-only E2E scenarios.
- `conf/proxy.conf`: Replace legacy example with explicit client/server v1 examples.
- `README.md`: Describe only the supported v1 runtime and commands.

### Task 1: Hard-Cut the Unified Gate

**Files:**
- Modify: `script/acceptance/run_acceptance.sh`
- Delete: `script/acceptance/e2e_client_topology_gate.sh`
- Delete: `script/acceptance/e2e_dynamic_client_peer.sh`
- Delete: `script/acceptance/e2e_full_tunnel_bypass.sh`
- Delete: `script/acceptance/e2e_hybrid_ha_reconnect.sh`
- Delete: `script/acceptance/e2e_hybrid_wireguard.sh`
- Delete: `script/acceptance/e2e_mss_clamping.sh`
- Delete: `script/acceptance/e2e_multi_client.sh`
- Delete: `script/acceptance/e2e_test_dualstack.sh`
- Delete: `script/acceptance/e2e_udp_icmp_tunnel.sh`
- Delete: `script/acceptance/e2e_udp_over_quic.sh`
- Delete: `script/acceptance/stability_long_tcp.py`
- Delete: `script/acceptance/stability_report.py`
- Delete: `script/acceptance/stability_server.py`
- Delete: `script/acceptance/stability_stress_test.sh`
- Delete: `script/perf/perf_compare_hybrid.sh`
- Delete: `script/perf/perf_cores_scalability.sh`
- Delete: `script/perf/perf_smoke.sh`

**Interfaces:**
- Consumes: Rust tests prefixed `v1_unit_` and `v1_integration_`; executable scripts matching `script/acceptance/v1/e2e_v1_*.sh`.
- Produces: One fail-fast v1 gate. During Tasks 1-9, privileged E2E is explicitly enabled with `RUN_V1_E2E=1`; Task 10 makes E2E mandatory in pre-push after all six scripts exist.

- [ ] **Step 1: Replace the legacy script manifest with v1 gate phases**

```bash
run "Rust formatting" cargo fmt --check
run "Cargo check" cargo check
run "Clippy" cargo clippy --all-targets -- -D warnings
run "v1 unit tests" cargo test --lib v1_unit_
run "v1 integration tests" cargo test --test v1_flow_integration
run "all Rust tests" cargo test
run "binary build" cargo build --bins
```

When `RUN_V1_E2E=1`, require exactly the six named `script/acceptance/v1/e2e_v1_*.sh` scripts, pass each through `bash -n`, and execute each under `timeout --kill-after=10s 300s sudo -E`. Reject a missing script instead of treating an empty glob as success.

- [ ] **Step 2: Delete legacy acceptance, stability, and TUN/hybrid performance scripts**

Use an explicit patch deletion for each listed file. Keep `test_key_material.sh` and `verify_pcap.py` only if the v1 helper imports them; otherwise delete them in Task 8.

- [ ] **Step 3: Verify the runner has no legacy references**

Run: `rg -n 'tun|wireguard|hybrid|multi_client|dynamic_client|legacy' script/acceptance/run_acceptance.sh`

Expected: no matches.

- [ ] **Step 4: Verify shell syntax without running privileged E2E**

Run: `bash script/acceptance/run_acceptance.sh`

Expected: static checks, focused tests, full tests, and binary build pass; the runner explicitly reports privileged v1 E2E deferred until `RUN_V1_E2E=1`.

- [ ] **Step 5: Commit the gate replacement**

```bash
git add script/acceptance script/perf
git commit -m "test: replace legacy acceptance gate with v1 gate

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 2: Establish IO Ownership and Packet Parsing

**Files:**
- Create: `src/flow_plane/mod.rs`
- Create: `src/flow_plane/io_registry.rs`
- Create: `src/flow_plane/packet.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: raw inner IP packet bytes and discovered Linux interface queue pairs.
- Produces: `IoOwnerKey { ifindex: u32, queue_id: u32 }`, `IoRegistry<T>`, `FlowKey`, `TransportProtocol`, and `parse_flow_key(&[u8]) -> Result<FlowKey, PacketError>`.

- [ ] **Step 1: Write RED ownership tests**

```rust
#[test]
fn v1_unit_io_registry_keys_by_ifindex_and_queue() {
    let mut registry = IoRegistry::new();
    registry.register(IoOwnerKey::new(2, 0), "intercept").unwrap();
    registry.register(IoOwnerKey::new(3, 0), "tunnel").unwrap();
    assert_eq!(registry.get(IoOwnerKey::new(2, 0)), Some(&"intercept"));
    assert_eq!(registry.get(IoOwnerKey::new(3, 0)), Some(&"tunnel"));
}

#[test]
fn v1_unit_io_registry_rejects_duplicate_owner() {
    let mut registry = IoRegistry::new();
    registry.register(IoOwnerKey::new(2, 0), "first").unwrap();
    assert_eq!(
        registry.register(IoOwnerKey::new(2, 0), "second"),
        Err(RegistryError::DuplicateOwner(IoOwnerKey::new(2, 0)))
    );
}
```

- [ ] **Step 2: Run RED ownership tests**

Run: `cargo test v1_unit_io_registry -- --nocapture`

Expected: FAIL because `flow_plane::io_registry` does not exist.

- [ ] **Step 3: Implement `IoOwnerKey` and `IoRegistry<T>`**

Use a private `HashMap<IoOwnerKey, T>`, reject duplicate registration, expose `get`, `contains`, `len`, and `iter`, and do not expose lookup by `queue_id` alone.

- [ ] **Step 4: Write RED IPv4/IPv6 flow-key tests**

Create fixed packet fixtures in the test module for IPv4/IPv6 TCP, UDP, ICMP echo, and ICMPv6 echo. Assert address, protocol, and port/identifier normalization; assert truncated packets and unsupported extension chains return `PacketError` without panic.

- [ ] **Step 5: Run RED packet tests**

Run: `cargo test v1_unit_parse_flow_key -- --nocapture`

Expected: FAIL because `parse_flow_key` is missing.

- [ ] **Step 6: Implement minimal safe parser**

Define:

```rust
pub enum TransportProtocol { Tcp, Udp, Icmp, Icmpv6 }
pub struct FlowKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: TransportProtocol,
}
pub fn parse_flow_key(packet: &[u8]) -> Result<FlowKey, PacketError>;
```

Use checked slicing and checked IPv6 extension-header offsets. Normalize ICMP echo identifier into `source_port` and type/code into `destination_port`.

- [ ] **Step 7: Verify the slice**

Run: `cargo test v1_unit_io_registry v1_unit_parse_flow_key`

Expected: all focused tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/main.rs src/flow_plane
git commit -m "feat: add v1 IO ownership and flow parsing

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 3: Implement Deterministic NAT and Session Ownership

**Files:**
- Create: `src/flow_plane/nat.rs`
- Create: `src/flow_plane/session.rs`
- Modify: `src/flow_plane/mod.rs`

**Interfaces:**
- Consumes: `FlowKey`, `IoOwnerKey`, `flow_worker_id`, `QuicFlowId`, configured SNAT IP and inclusive port range.
- Produces: `SessionId(u64)`, `NatBinding`, `ReverseNatKey`, `Session`, and `SessionTable`.

- [ ] **Step 1: Write RED NAT uniqueness and exhaustion tests**

Test sequential allocation over `40000..=40001`, uniqueness for two distinct Flow keys, deterministic reuse after explicit release, and `NatError::PortRangeExhausted` for the third concurrent binding.

- [ ] **Step 2: Run RED NAT tests**

Run: `cargo test v1_unit_nat_ -- --nocapture`

Expected: FAIL because `NatTable` does not exist.

- [ ] **Step 3: Implement NAT indexes**

Define:

```rust
pub struct NatTable {
    forward: HashMap<FlowKey, NatBinding>,
    reverse: HashMap<ReverseNatKey, SessionLocator>,
    allocator: PortAllocator,
}

pub struct SessionLocator {
    pub flow_worker_id: usize,
    pub session_id: SessionId,
}
```

`insert` must publish forward and reverse indexes together or leave both unchanged. `remove` must remove both before releasing the port.

- [ ] **Step 4: Write RED Session lifecycle tests**

Assert duplicate and out-of-order packets return the same `SessionId`; an owner mismatch returns `SessionError::WrongOwner`; removal clears forward Session, forward NAT, reverse NAT, and port allocation; reverse miss never creates a Session.

- [ ] **Step 5: Run RED Session tests**

Run: `cargo test v1_unit_session_ -- --nocapture`

Expected: FAIL because `SessionTable` does not exist.

- [ ] **Step 6: Implement `SessionTable` atomic lifecycle**

Expose `get_or_create`, `lookup_reverse`, `remove`, `remove_by_quic_flow`, and immutable iteration. Keep all mutating methods on `&mut self` so a table cannot be shared as a concurrent mutable owner.

- [ ] **Step 7: Verify NAT and Session behavior**

Run: `cargo test v1_unit_nat_ v1_unit_session_`

Expected: all focused tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/flow_plane
git commit -m "feat: add v1 NAT and session ownership

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 4: Implement QUIC Flow and DCID Lifecycle

**Files:**
- Create: `src/flow_plane/quic_flow.rs`
- Modify: `src/flow_plane/session.rs`
- Modify: `src/flow_plane/mod.rs`

**Interfaces:**
- Consumes: fixed `dcid_len`, Flow worker count, tunnel queue count, active DCIDs, and connection lifecycle events.
- Produces: `QuicFlowId(u64)`, `QuicFlow`, `ActiveDcidIndex`, `bootstrap_owner(dcid, worker_count)`, and Session reclamation by old `QuicFlowId`.

- [ ] **Step 1: Write RED stable queue and bootstrap tests**

Assert a `QuicFlow` computes its queue once, adding/replacing DCIDs never changes that queue, equal unknown DCIDs always choose the same bootstrap owner, zero workers and empty DCID return explicit errors, and bootstrap does not mutate `SessionTable`.

- [ ] **Step 2: Run RED QUIC ownership tests**

Run: `cargo test v1_unit_quic_flow_ -- --nocapture`

Expected: FAIL because `quic_flow` does not exist.

- [ ] **Step 3: Implement stable QUIC flow identity**

Use deterministic FNV-1a over DCID bytes rather than `DefaultHasher`, whose algorithm is not a stable protocol contract. Bind `tunnel_queue_id = hash(initial_dcid) % tunnel_queue_count` only in `QuicFlow::new`.

- [ ] **Step 4: Write RED DCID publish/retire/close tests**

Assert all active DCIDs for one flow resolve to one owner, duplicate publication to another flow is rejected, retired DCID no longer resolves, and close removes every DCID for that flow.

- [ ] **Step 5: Implement `ActiveDcidIndex`**

Maintain both `dcid -> (worker_id, quic_flow_id)` and `quic_flow_id -> HashSet<dcid>` so close is complete and bounded by the flow's CID count.

- [ ] **Step 6: Write and satisfy reconnect reclamation test**

Create two Sessions bound to an old flow and one to another flow. Call `remove_by_quic_flow(old)`, assert only the two old Sessions and their NAT indexes are removed, then create a new flow with a different ID.

- [ ] **Step 7: Verify**

Run: `cargo test v1_unit_quic_flow_ v1_unit_dcid_ v1_unit_session_reclaims_`

Expected: all focused tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/flow_plane
git commit -m "feat: add v1 QUIC flow and DCID ownership

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 5: Build the Pure Flow Worker and Integration Harness

**Files:**
- Create: `src/flow_plane/worker.rs`
- Create: `tests/v1_flow_integration.rs`
- Create: `src/lib.rs`
- Modify: `src/main.rs`
- Modify: `src/flow_plane/mod.rs`

**Interfaces:**
- Consumes: `FlowMessage`, bounded channel receivers, IO registry, Session/NAT/DCID state.
- Produces: `IoTransmit`, `FlowWorkerState::handle`, deterministic `FlowDispatcher`, and drop/ownership counters.

- [ ] **Step 1: Expose v1 modules from a library target**

Move only reusable v1 modules behind `src/lib.rs`; update `main.rs` to import them from `new_proxy` rather than compiling duplicate module copies.

- [ ] **Step 2: Write RED integration tests**

Define and use:

```rust
pub enum FlowMessage {
    InterceptIngress { io_owner: IoOwnerKey, packet: Bytes },
    TunnelIngress { io_owner: IoOwnerKey, dcid: Bytes, packet: Bytes },
}

pub struct IoTransmit {
    pub target: IoOwnerKey,
    pub packet: Bytes,
}
```

Test multiple IO owners dispatching to multiple Flow workers, stable Session owner for repeated packets, correct client return interface, separate tunnel/intercept queue spaces, same-interface classification without a loop, and full-channel drop without ownership change.

- [ ] **Step 3: Run RED integration tests**

Run: `cargo test --test v1_flow_integration -- --nocapture`

Expected: FAIL because `FlowWorkerState` and `FlowDispatcher` are missing.

- [ ] **Step 4: Implement bounded dispatch and worker handling**

`try_send` must return `DispatchOutcome::DroppedFull` and increment `channel_full_drops`; it must never retry on another Flow worker. Tunnel ingress with an unknown illegal DCID increments `unknown_dcid_drops`.

- [ ] **Step 5: Implement server queue correction**

Allow a server Session initialized with `(server_intercept_ifindex, 0)` to accept the first real reverse-path owner. Once corrected to a non-default queue, a packet observed on another queue increments `queue_mismatch_drops` and does not rewrite the Session again.

- [ ] **Step 6: Verify pure Flow plane**

Run: `cargo test v1_unit_`

Run: `cargo test --test v1_flow_integration`

Expected: all focused v1 tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/lib.rs src/main.rs src/flow_plane tests/v1_flow_integration.rs
git commit -m "feat: add v1 Flow worker message plane

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 6: Replace Legacy Configuration

**Files:**
- Create: `src/v1_config.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`
- Modify: `conf/proxy.conf`
- Delete after callers migrate: `src/config.rs`
- Delete after callers migrate: `src/app_config.rs`

**Interfaces:**
- Consumes: INI sections `[Appliance]`, `[Tunnel]`, one or more `[Intercept]`, `[NAT]`, `[AllowedIPs]`, and `[XDP]`.
- Produces: validated `ApplianceConfig`, `Role::{Client, Server}`, `InterfaceName`, `NatConfig`, and `XdpAttachMode`.

- [ ] **Step 1: Write RED hard-cut config tests**

Assert valid single client and server parse; server with two intercept interfaces is rejected; client with multiple intercept interfaces is accepted; `dcid_len=0`, `flow_worker_count=0`, empty interface, duplicate interface role declaration, invalid/reversed SNAT range, missing endpoint/listen address, `[Peer]`, `Mode=tun`, and any WireGuard key are rejected with field-specific errors.

- [ ] **Step 2: Run RED config tests**

Run: `cargo test v1_unit_config_ -- --nocapture`

Expected: FAIL because `ApplianceConfig` is missing.

- [ ] **Step 3: Implement strict parser and validation**

Do not silently ignore unknown legacy sections or fields. Return `ConfigError::UnsupportedLegacyField` for known legacy names and `ConfigError::UnknownField` for other unknown input.

- [ ] **Step 4: Replace startup config dependency**

Make `main` load and validate `ApplianceConfig` before any device, XDP, socket, namespace, or thread side effect.

- [ ] **Step 5: Replace the example config**

Provide separate, complete `conf/client.conf` and `conf/server.conf`; remove the ambiguous legacy `conf/proxy.conf`.

- [ ] **Step 6: Verify**

Run: `cargo test v1_unit_config_`

Run: `cargo check`

Expected: focused tests and compilation pass.

- [ ] **Step 7: Commit**

```bash
git add src/v1_config.rs src/lib.rs src/main.rs conf
git commit -m "refactor: hard-cut configuration to v1 appliance

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 7: Extract TUN-Independent QUIC Engine

**Files:**
- Create: `src/quic_engine.rs`
- Modify: `src/lib.rs`
- Modify: `src/rtc_loop.rs`
- Modify: `src/quic_proto_engine.rs`
- Test: `src/quic_engine.rs`

**Interfaces:**
- Consumes: UDP/QUIC packet bytes, current `Instant`, inner IP datagrams, TLS/auth config, and QUIC endpoint events.
- Produces: `QuicEngineEvent::{Transmit, InnerPacket, DcidPublished, DcidRetired, Closed}`, `QuicEngine::handle_outer`, `send_inner`, and `poll`.

- [ ] **Step 1: Write RED in-memory QUIC engine tests**

Drive client and server engines by exchanging `Transmit` events in memory. Assert authentication completes, one IPv4 and one IPv6 inner datagram round-trip encrypted, active DCID events publish before data ingress use, and close emits complete retirement.

- [ ] **Step 2: Run RED engine tests**

Run: `cargo test v1_unit_quic_engine_ -- --nocapture`

Expected: FAIL because `QuicEngine` does not exist.

- [ ] **Step 3: Extract protocol logic without TUN or sockets**

Move connection state-machine logic from `rtc_loop.rs` behind byte/event methods. No method in `quic_engine.rs` may accept a TUN fd, XSK ring, UDP socket, or `IoOwnerKey`.

- [ ] **Step 4: Connect engine events to Flow worker**

Flow worker publishes/retires DCIDs, wraps outer `Transmit` in `IoTransmit` targeting the flow's stable tunnel queue, and routes decrypted `InnerPacket` through Session/NAT handling.

- [ ] **Step 5: Verify encryption boundary**

Run the in-memory test and assert the outer packet capture does not contain the complete inner packet byte sequence.

- [ ] **Step 6: Verify**

Run: `cargo test v1_unit_quic_engine_ v1_integration_`

Run: `cargo clippy --all-targets -- -D warnings`

Expected: tests and clippy pass.

- [ ] **Step 7: Commit**

```bash
git add src/quic_engine.rs src/quic_proto_engine.rs src/rtc_loop.rs src/flow_plane src/lib.rs
git commit -m "refactor: detach QUIC engine from TUN IO

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 8: Rebuild AF_XDP Runtime Around IO Owners

**Files:**
- Create: `src/xdp_datapath/io_worker.rs`
- Create: `src/xdp_datapath/runtime.rs`
- Modify: `src/xdp_datapath/mod.rs`
- Modify: `src/xdp_datapath/loader.rs`
- Modify: `src/xdp_datapath/xdp_filter.c`
- Modify: `src/xdp_datapath/worker.rs`
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: validated appliance config, discovered queue counts, BPF/XSK resources, Flow channels, and `IoTransmit`.
- Produces: exactly one `IoWorker` per `IoOwnerKey`, classified `FlowMessage`, outer QUIC and inner local TX, and per-owner ring/drop counters.

- [ ] **Step 1: Write RED assembly tests using fake XSK factories**

Assert unique owners across different interfaces with equal queue IDs, same-interface tunnel/intercept uses one owner with two classifiers, queue-count mismatch does not cross-index queue spaces, and any XSK creation failure aborts the whole runtime without a partial registry.

- [ ] **Step 2: Run RED assembly tests**

Run: `cargo test v1_unit_xdp_runtime_ -- --nocapture`

Expected: FAIL because the owner-based runtime is missing.

- [ ] **Step 3: Move ring loop into `IoWorker`**

Preserve the existing exit checks around `poll`. Each worker owns one RX, TX, Fill, and Completion ring. It may parse/classify and repair L2, but may not import or mutate `SessionTable`, `NatTable`, or `QuicFlow`.

- [ ] **Step 4: Wire bounded IO/Flow channels**

Build all registries and channels before starting threads. If construction fails, drop all prepared XSK/BPF resources and start no workers.

- [ ] **Step 5: Remove plaintext and TUN startup**

Delete `wrap_plaintext_to_quic_slice`, `unwrap_quic_to_plaintext_slice`, plaintext outer-UDP forwarding, and every AF_XDP call that starts old TUN/QUIC workers.

- [ ] **Step 6: Verify source boundaries**

Run: `rg -n 'wrap_plaintext|unwrap_quic|TunDatapath|tun_device|tun_io' src/xdp_datapath src/main.rs`

Expected: no runtime-path matches.

- [ ] **Step 7: Verify**

Run: `cargo test v1_unit_xdp_runtime_`

Run: `cargo test`

Run: `cargo build --bins`

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/xdp_datapath src/main.rs
git commit -m "refactor: make AF_XDP IO owners drive v1 Flow workers

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 9: Remove the Legacy Runtime and Dependencies

**Files:**
- Delete: `src/tun_datapath.rs`
- Delete: `src/tun_device.rs`
- Delete: `src/tun_io.rs`
- Delete: `src/client.rs`
- Delete: `src/quic_pool.rs`
- Delete: `src/runtime.rs`
- Delete: legacy dynamic-peer portions of `src/api.rs`, `src/control.rs`, `src/uds_server.rs`, and `src/telemetry.rs`
- Modify: `src/main.rs`
- Modify: `src/lib.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: the complete v1 path from Tasks 2-8.
- Produces: one supported runtime with no legacy feature flag or compatibility parser.

- [ ] **Step 1: Identify all legacy references**

Run: `rg -n 'TunDatapath|Wireguard|wireguard|PeerConfig|dynamic peer|QuicPoolClient|L4DataPlaneSnapshot' src Cargo.toml`

Expected: a finite deletion list; classify every match as v1-required authentication code or legacy runtime code.

- [ ] **Step 2: Delete legacy modules and imports**

Keep only cryptographic functions genuinely consumed by `quic_engine`; move those functions into a focused authentication module before deleting their old container file.

- [ ] **Step 3: Remove unused dependencies**

Remove `defguard_wireguard_rs`, `arc-swap`, and other dependencies only after `cargo tree -i <crate>` confirms no v1 caller remains.

- [ ] **Step 4: Delete old tests instead of adapting them**

Remove tests for TUN, WireGuard, hybrid, dynamic peers, multi-peer pools, and legacy APIs. Do not rename them into v1 tests unless they assert a v1 requirement.

- [ ] **Step 5: Verify hard-cut source state**

Run: `rg -n 'tun|wireguard|hybrid|dynamic.peer|multi.peer|plaintext' src Cargo.toml`

Expected: no implementation matches; comments that explain forbidden behavior are allowed only in tests.

- [ ] **Step 6: Verify**

Run: `cargo fmt --check`

Run: `cargo check`

Run: `cargo clippy --all-targets -- -D warnings`

Run: `cargo test`

Run: `cargo build --bins`

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src Cargo.toml Cargo.lock
git commit -m "refactor: remove legacy tunnel and hybrid runtime

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 10: Add Six v1 E2E Scenarios and Runtime Assertions

**Files:**
- Create: `script/acceptance/v1/lib.sh`
- Create: `script/acceptance/v1/e2e_v1_client_to_target.sh`
- Create: `script/acceptance/v1/e2e_v1_server_return.sh`
- Create: `script/acceptance/v1/e2e_v1_client_return.sh`
- Create: `script/acceptance/v1/e2e_v1_same_interface.sh`
- Create: `script/acceptance/v1/e2e_v1_multi_intercept.sh`
- Create: `script/acceptance/v1/e2e_v1_recovery.sh`
- Modify: `script/acceptance/run_acceptance.sh`
- Modify: runtime stats API used by `new-proxy-cli`

**Interfaces:**
- Consumes: built binaries, root, AF_XDP-capable Linux, network namespaces, veth queue configuration, packet capture, and JSON runtime stats.
- Produces: six deterministic E2Es asserting business traffic, packet capture, and Session/NAT/worker/DCID state.

- [ ] **Step 1: Build common isolated topology helper**

Create `client_ns`, `transit_ns`, `server_ns`, and `target_ns`; add a second client-intercept namespace only for the multi-intercept scenario. Every resource name includes `$$`, and `trap cleanup EXIT INT TERM` removes processes, XDP links, veths, captures, and namespaces.

- [ ] **Step 2: Add protocol matrix helpers**

For IPv4 and IPv6, exercise TCP with a bounded echo transfer, UDP with request/response payload equality, and ICMP/ICMPv6 echo. Every command has an explicit timeout.

- [ ] **Step 3: Add runtime assertion helper**

Query JSON stats and assert IO owner pairs, Session owner and count, unique client/server NAT and reverse-NAT entries, `quic_flow_id`, stable tunnel queue, active DCID count, unknown DCID drops, and server queue-correction count.

- [ ] **Step 4: Implement the six scripts**

Each script invokes shared setup but owns its scenario assertions. `e2e_v1_recovery.sh` records old `quic_flow_id`, forces reconnect, asserts old Session/NAT/DCIDs reach zero, then verifies new traffic uses a distinct ID.

- [ ] **Step 5: Run syntax checks**

Run: `for script in script/acceptance/v1/*.sh; do bash -n "$script"; done`

Expected: all scripts pass.

- [ ] **Step 6: Run each privileged scenario**

Run each script individually under `timeout --kill-after=10s 300s sudo -E bash ...`; after every run, assert `ip netns list` and `ip link show` contain no test-specific names.

- [ ] **Step 7: Run unified gate**

Run: `bash script/acceptance/run_acceptance.sh`

Expected: all static, unit, integration, build, and six v1 E2E phases pass.

- [ ] **Step 8: Commit**

```bash
git add script/acceptance src
git commit -m "test: add AF_XDP QUIC v1 end-to-end gate

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```

### Task 11: Documentation, Soak, and Final Verification

**Files:**
- Modify: `README.md`
- Modify: `doc/ARCHITECTURE.md`
- Modify: `doc/TESTING.md`
- Modify: `docs/superpowers/specs/2026-08-11-af-xdp-quic-v1-hard-cut-design.md`
- Create: `script/acceptance/v1/soak_v1.sh`
- Create: `script/perf/perf_v1.sh`

**Interfaces:**
- Consumes: implemented v1 CLI/config/stats and all green gates.
- Produces: current user documentation, optional leak soak, v1-only performance baseline, and final evidence.

- [ ] **Step 1: Rewrite user-facing documentation to current state**

Remove old TUN/hybrid/WireGuard configuration and performance claims. Document both v1 roles, interfaces, queue ownership, NAT ranges, required kernel capabilities, startup, stats, E2E, and rollback.

- [ ] **Step 2: Add bounded soak**

Repeatedly create/close traffic and force QUIC reconnect. Sample RSS, Session, NAT, reverse-NAT, DCID, XSK, fill, and completion counts; fail if state does not return to the configured idle baseline after the grace interval.

- [ ] **Step 3: Add v1 performance runner**

Measure TCP/UDP throughput, p50/p99 latency, packet sizes, queue distribution, and CPU for one and multiple IO/Flow workers. Keep it behind `RUN_V1_PERF=1`, outside correctness by default.

- [ ] **Step 4: Self-review against architecture and testing matrices**

For every hard constraint in `doc/ARCHITECTURE.md` and every target test in `doc/TESTING.md`, record the implementing type/function and test/script. Fix any uncovered item before declaring completion.

- [ ] **Step 5: Run final verification**

Run: `cargo fmt --check`

Run: `cargo check`

Run: `cargo clippy --all-targets -- -D warnings`

Run: `cargo test`

Run: `cargo build --bins`

Run: `bash script/acceptance/run_acceptance.sh`

Run: `RUN_V1_SOAK=1 bash script/acceptance/run_acceptance.sh`

Expected: every command passes and soak reports no retained Session, NAT, DCID, XSK, or ring resources.

- [ ] **Step 6: Review the final diff and commit**

```bash
git diff --check
git status --short
git add README.md doc docs/superpowers script
git commit -m "docs: finalize AF_XDP QUIC appliance v1

Co-authored-by: TRAE CLI <noreply@bytedance.com>"
```
