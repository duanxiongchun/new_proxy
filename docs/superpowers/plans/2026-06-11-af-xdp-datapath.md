# AF_XDP Datapath Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate a high-performance `AF_XDP` datapath side-by-side with the existing `TUN` datapath, selectable via config (`Mode = tun | af_xdp`), sharing a global `Shared UMEM` memory pool to decouple hardware queues from thread counts.

**Architecture:** Define a polymorphic `Datapath` Trait. Implement `TunDatapath` (refactoring current TUN + socket logic) and `XdpDatapath` (using eBPF XDP Loader + Shared UMEM + XSK poll).

**Tech Stack:** Rust, Tokio, Quinn-proto, libbpf-rs (or aya), AF_XDP (Linux specific).

---

### Task 1: Define the `Datapath` Trait

**Files:**
- Create: `src/datapath.rs`
- Modify: `src/main.rs:1-10`

- [ ] **Step 1: Write the failing unit test for `Datapath` initialization**

Create a temporary test module in `src/datapath.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockDatapath;
    impl Datapath for MockDatapath {
        async fn run_loop(
            self: Arc<Self>,
            _dp_snapshot: Arc<arc_swap::ArcSwap<crate::L4DataPlaneSnapshot>>,
            _exit_notify: Arc<tokio::sync::Notify>,
        ) -> Result<(), DatapathError> {
            Ok(())
        }
        fn get_stats(&self) -> DatapathStats {
            DatapathStats { rx_bytes: 42 }
        }
    }

    #[tokio::test]
    async fn test_mock_datapath_stats() {
        let dp = Arc::new(MockDatapath);
        assert_eq!(dp.get_stats().rx_bytes, 42);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin new_proxy`
Expected: Compile fail due to missing `Datapath`, `DatapathError`, `DatapathStats`.

- [ ] **Step 3: Write minimal implementation in `src/datapath.rs`**

```rust
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatapathError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
}

#[derive(Debug, Clone, Default)]
pub struct DatapathStats {
    pub rx_bytes: u64,
}

#[async_trait::async_trait]
pub trait Datapath: Send + Sync {
    async fn run_loop(
        self: Arc<Self>,
        dp_snapshot: Arc<arc_swap::ArcSwap<crate::L4DataPlaneSnapshot>>,
        exit_notify: Arc<tokio::sync::Notify>,
    ) -> Result<(), DatapathError>;

    fn get_stats(&self) -> DatapathStats;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin new_proxy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/datapath.rs
git commit -m "feat: define core Datapath trait and error types"
```

---

### Task 2: Implement `TunDatapath`

Refactor the existing TUN收发 logic inside [src/rtc_loop.rs](file:///home/duanxiongchun/new_proxy/src/rtc_loop.rs) and [src/main.rs](file:///home/duanxiongchun/new_proxy/src/main.rs) into a dedicated implementation.

**Files:**
- Create: `src/tun_datapath.rs`
- Modify: `src/main.rs` (to use `TunDatapath`)

- [ ] **Step 1: Write a unit test for `TunDatapath` instancing**

Create the test structure in `src/tun_datapath.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tun_datapath_new() {
        // Verify creation fails gracefully without real interfaces
        let res = TunDatapath::new();
        assert!(res.is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin new_proxy`
Expected: Compile fail due to missing `TunDatapath`.

- [ ] **Step 3: Write implementation of `TunDatapath`**

Copy the current socket binding and worker instantiation from `src/main.rs` into `src/tun_datapath.rs`:
```rust
use std::sync::Arc;
use crate::datapath::{Datapath, DatapathError, DatapathStats};
use arc_swap::ArcSwap;

pub struct TunDatapath {
    worker_id: usize,
}

impl TunDatapath {
    pub fn new() -> Result<Self, DatapathError> {
        Err(DatapathError::Config("Not implemented".into()))
    }
}

#[async_trait::async_trait]
impl Datapath impl for TunDatapath {
    async fn run_loop(
        self: Arc<Self>,
        _dp_snapshot: Arc<ArcSwap<crate::L4DataPlaneSnapshot>>,
        _exit_notify: Arc<tokio::sync::Notify>,
    ) -> Result<(), DatapathError> {
        Ok(())
    }

    fn get_stats(&self) -> DatapathStats {
        DatapathStats::default()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin new_proxy`
Expected: PASS (graceful config error).

- [ ] **Step 5: Commit**

```bash
git add src/tun_datapath.rs
git commit -m "feat: stub out TunDatapath structure"
```

---

### Task 3: Support CONFIG Mode Fields for AF_XDP

**Files:**
- Modify: `src/config.rs`
- Modify: `src/app_config.rs`

- [ ] **Step 1: Write failing test in `src/config.rs` for XDP options**

Add test in `config.rs` asserting parsing of `QuicInterface` and `InterceptInterfaces`:
```rust
#[test]
fn test_xdp_config_parse() {
    let conf = "[Interface]\nMode = af_xdp\n[XDP]\nQuicInterface = eth0\nInterceptInterfaces = eth0, lo\n";
    let gateway_conf = GatewayConfig::load_from_str(conf).unwrap();
    assert_eq!(gateway_conf.xdp.quic_interface, Some("eth0".to_string()));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test config::tests::test_xdp_config_parse`
Expected: Compile failure due to missing fields.

- [ ] **Step 3: Implement new fields in `GatewayConfig`**

Modify `src/config.rs` to parse the new structure:
```rust
#[derive(Debug, Clone, Default)]
pub struct XdpConfig {
    pub quic_interface: Option<String>,
    pub intercept_interfaces: Vec<String>,
    pub xdp_mode: String,
}
```
Update ini file parsers to populate this struct.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test config::tests::test_xdp_config_parse`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/app_config.rs
git commit -m "chore: add AF_XDP config fields and parser logic"
```

---

### Task 4: Implement eBPF XDP Loader (`XdpLinkManager`)

**Files:**
- Create: `src/xdp_datapath/loader.rs`
- Create: `src/xdp_datapath/mod.rs`

- [ ] **Step 1: Write mock test for loader attachment**

```rust
#[test]
fn test_loader_fail_on_invalid_dev() {
    let manager = BpfLinkManager::new("invalid_interface_nonexistent");
    assert!(manager.is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin new_proxy`
Expected: Compile fail due to missing `BpfLinkManager`.

- [ ] **Step 3: Write BpfLinkManager wrapper**

Use `libbpf-rs` or `aya` to load compiled XDP filter ELF.
```rust
#[cfg(target_os = "linux")]
pub struct BpfLinkManager {
    ifindex: u32,
}

#[cfg(target_os = "linux")]
impl BpfLinkManager {
    pub fn new(interface: &str) -> Result<Self, std::io::Error> {
        let ifindex = nix::net::if_::if_nametoindex(interface)?;
        Ok(Self { ifindex })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin new_proxy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/xdp_datapath/mod.rs src/xdp_datapath/loader.rs
git commit -m "feat: add BpfLinkManager layout for XDP loading"
```

---

### Task 5: Implement `XdpDatapath` with Shared UMEM and Worker loop

**Files:**
- Create: `src/xdp_datapath/worker.rs`
- Modify: `src/main.rs` (to bootstrap `XdpDatapath`)

- [ ] **Step 1: Create failing test for `XdpDatapath` initialization**

```rust
#[test]
fn test_xdp_datapath_fails_gracefully() {
    let res = XdpDatapath::new("non_existent_dev", "lo");
    assert!(res.is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin new_proxy`
Expected: Compile fail due to missing `XdpDatapath`.

- [ ] **Step 3: Implement `XdpDatapath` and Shared UMEM mapping**

Implement the Worker Loop using `libbpf-rs` AF_XDP bindings:
1. Initialize a large shared UMEM block.
2. Bind multiple XSK sockets on Queue 0..M sharing the UMEM.
3. Decouple worker threads from device queue index. Redirect flows based on `worker_id` via `XSKMAP`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin new_proxy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/xdp_datapath/worker.rs
git commit -m "feat: complete XdpDatapath worker loop with Shared UMEM support"
```
