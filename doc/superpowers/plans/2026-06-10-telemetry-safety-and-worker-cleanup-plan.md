# Telemetry Safety and Worker Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean up the codebase by fixing telemetry concurrent access Undefined Behavior, removing the unused `BufferPool` parameter in worker setups, and documenting `unsafe` blocks.

**Architecture:** Use relaxed memory-ordered `AtomicU64` load and store for a data-race-free and lock-free thread-sharded metrics model. Clean up worker config structs and add clear safety justifications for raw pointer length manipulation.

**Tech Stack:** Rust, `std::sync::atomic::AtomicU64`.

---

### Task 1: Telemetry Safety Refactoring

**Files:**
- Modify: `src/telemetry.rs:7-47`
- Test: Run existing telemetry unit tests.

- [ ] **Step 1: Replace CellU64 UnsafeCell with AtomicU64**
  Modify [src/telemetry.rs](file:///home/duanxiongchun/new_proxy/src/telemetry.rs) to use `AtomicU64` and `Ordering::Relaxed` for operations:
  ```rust
  use std::sync::atomic::{AtomicU64, Ordering};

  #[derive(Debug)]
  pub struct CellU64(AtomicU64);

  impl CellU64 {
      #[inline(always)]
      pub fn new(val: u64) -> Self {
          Self(AtomicU64::new(val))
      }

      #[inline(always)]
      pub fn add(&self, val: u64) {
          let current = self.0.load(Ordering::Relaxed);
          self.0.store(current + val, Ordering::Relaxed);
      }

      #[inline(always)]
      pub fn load(&self) -> u64 {
          self.0.load(Ordering::Relaxed)
      }

      #[inline(always)]
      pub fn store(&self, val: u64) {
          self.0.store(val, Ordering::Relaxed);
      }
  }

  impl Default for CellU64 {
      #[inline(always)]
      fn default() -> Self {
          Self::new(0)
      }
  }
  ```
  Remove manual `Send` and `Sync` implementations:
  ```rust
  // Delete: unsafe impl Send for CellU64 {}
  // Delete: unsafe impl Sync for CellU64 {}
  ```

- [ ] **Step 2: Run cargo check to verify code compiles**
  Run: `cargo check`
  Expected: PASS with no compile errors in `src/telemetry.rs`.

- [ ] **Step 3: Run existing unit tests**
  Run: `cargo test --lib telemetry`
  Expected: PASS

- [ ] **Step 4: Commit**
  Run:
  ```bash
  git add src/telemetry.rs
  git commit -m "refactor: use AtomicU64 for CellU64 telemetry to avoid UB data races"
  ```

---

### Task 2: Worker Configuration Clean-up

**Files:**
- Modify: `src/rtc_loop.rs:7-10`, `src/rtc_loop.rs:22`, `src/rtc_loop.rs:68`, `src/rtc_loop.rs:940-965`
- Modify: `src/main.rs:720-730`, `src/main.rs:990-1000`

- [ ] **Step 1: Modify RtcWorkerConfig and RtcWorker in src/rtc_loop.rs**
  Remove `buffer_pool` field from `RtcWorkerConfig`:
  ```rust
  pub struct RtcWorkerConfig {
      pub mtu: usize,
  }
  ```
  Remove `buffer_pool` field from `RtcWorker`:
  ```rust
  pub struct RtcWorker {
      pub tun_io: Arc<AsyncTunIo>,
      pub worker_id: usize,
      pub packet_buffer_size: usize,
      // ... (other fields, delete buffer_pool field)
  ```
  Remove `buffer_pool` from `RtcWorker::new` constructor:
  ```rust
  pub fn new(
      tun_io: Arc<AsyncTunIo>,
      worker_id: usize,
      role: WorkerRole,
      config: RtcWorkerConfig,
      // ...
  ) -> Self {
      let packet_buffer_size = crate::config::packet_buffer_size_for_mtu(config.mtu as u16);
      Self {
          tun_io,
          worker_id,
          packet_buffer_size,
          // ... (remove buffer_pool field assignment)
      }
  }
  ```
  Also update unit tests inside `src/rtc_loop.rs` where workers are constructed (lines ~943 and ~958):
  ```rust
  // Modify configuration constructor calls to omit buffer_pool:
  config: RtcWorkerConfig {
      mtu: 1500,
  }
  ```

- [ ] **Step 2: Modify src/main.rs worker config instantiation**
  Remove creation and pass-through of `worker_buffer_pool`:
  Modify client worker configuration (~721):
  ```rust
  let worker_config = rtc_loop::RtcWorkerConfig {
      mtu: config.mtu as usize,
  };
  ```
  Modify server worker configuration (~991):
  ```rust
  let worker_config = rtc_loop::RtcWorkerConfig {
      mtu: config.mtu as usize,
  };
  ```

- [ ] **Step 3: Run cargo test to verify**
  Run: `cargo test`
  Expected: PASS (all 94 tests)

- [ ] **Step 4: Commit**
  Run:
  ```bash
  git add src/rtc_loop.rs src/main.rs
  git commit -m "refactor: remove unused BufferPool parameter from RtcWorker configuration"
  ```

---

### Task 3: Unsafe Documentation

**Files:**
- Modify: `src/rtc_loop.rs` (unsafe blocks ~583, ~593, ~640, ~650, ~659, ~684, ~694, ~700)

- [ ] **Step 1: Add SAFETY comments to all unsafe set_len calls in rtc_loop.rs**
  Identify each instance where `tun_buf.set_len(cap)` or similar is called inside `src/rtc_loop.rs`, and prepend the following comment:
  ```rust
  // SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
  // for read/recv_from. The uninitialized bytes are never read before they are
  // overwritten by the OS kernel during the IO system call.
  unsafe {
      // ...
  }
  ```

- [ ] **Step 2: Verify code style and compiler warnings**
  Run: `cargo clippy --all-targets -- -D warnings`
  Expected: PASS with no warnings or errors.

- [ ] **Step 3: Commit**
  Run:
  ```bash
  git add src/rtc_loop.rs
  git commit -m "docs: add SAFETY comments to unsafe buffer length manipulation"
  ```

---

### Task 4: E2E and Formatting Check

- [ ] **Step 1: Check formatting**
  Run: `cargo fmt --check`
  Expected: PASS

- [ ] **Step 2: Run E2E tests**
  Run: `sudo ./script/acceptance/run_acceptance.sh`
  Expected: PASS

- [ ] **Step 3: Push commits**
  Run: `git push origin perf-quinn-proto-event-loop && git push github perf-quinn-proto-event-loop`
  Expected: PASS
