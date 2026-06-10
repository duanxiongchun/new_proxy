# Telemetry Safety, Worker Cleanup, and Unsafe Documentation Design

This design document outlines the safety and performance optimizations to be applied to the `new_proxy` codebase. It addresses potential Undefined Behavior (UB) in concurrent telemetry access, cleans up unused `BufferPool` worker parameters, and documents the safety invariants of existing `unsafe` blocks in `src/rtc_loop.rs`.

---

## 1. Objectives

1. **Eliminate Telemetry UB**: Replace `UnsafeCell`-based `CellU64` with `std::sync::atomic::AtomicU64`. Use `Ordering::Relaxed` for all operations to guarantee UB-free concurrency without introducing memory bus locks (`LOCK` prefix instructions) on x86_64.
2. **Clean Up Unused Code**: Remove the unused `BufferPool` references from `RtcWorkerConfig`, `RtcWorker`, and initialization code.
3. **Document Unsafe Blocks**: Add formal `// SAFETY:` justifications for all `unsafe` operations inside `src/rtc_loop.rs`.

---

## 2. Detailed Changes

### 2.1 Telemetry Safety (`src/telemetry.rs`)

Modify `CellU64` to wrap `AtomicU64`:
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
        // Since write access is single-thread exclusive per counter,
        // load and store with Relaxed ordering avoids the LOCK prefix
        // while safely eliminating data race UB.
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
```
*Note: Because `AtomicU64` is naturally thread-safe, we can remove the manual `unsafe impl Send` and `unsafe impl Sync` for `CellU64`.*

### 2.2 Worker Config Clean-up

#### In `src/rtc_loop.rs`
* Remove `buffer_pool` field from `RtcWorkerConfig` and `RtcWorker`.
* Update constructor and tests.

#### In `src/main.rs`
* Remove `worker_buffer_pool` allocation and pass-through to workers.
* `buffer_pool.rs` itself remains intact for testing or other non-hotpath utilities.

### 2.3 Unsafe Blocks Documentation (`src/rtc_loop.rs`)

Add safety comments to the `set_len` calls in the worker run loop:
```rust
// SAFETY: The length of the buffer is set to capacity to allow slicing the buffer
// for read and recv_from operations. The uninitialized bytes are never read
// before they are overwritten by the OS kernel during the IO system call.
unsafe {
    let cap = tun_buf.capacity();
    tun_buf.set_len(cap);
}
```

---

## 3. Verification Plan

1. **Unit Tests**: Run `cargo test` to ensure all 94/94 unit tests continue to pass.
2. **Clippy & Format**: Run `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` to ensure code style compliance.
3. **E2E Acceptance**: Run `sudo ./script/acceptance/run_acceptance.sh` to verify full tunnel functionality, throughput, and stability.
