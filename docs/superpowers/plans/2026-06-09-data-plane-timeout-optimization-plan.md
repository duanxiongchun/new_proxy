# Data Plane Timeout Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Optimize the performance of the data plane connection relay path (`relay_copy_with_idle` in `src/relay.rs`) by removing the write timeout and replacing the read timeout with a pinned sleep timer that resets in-place.

**Architecture:** We will use `tokio::pin!` to pin a single `tokio::time::sleep` future on the stack. In the main loop of `relay_copy_with_idle`, `tokio::select!` will poll the read future and the sleep timer. On successful read, the timer is reset in-place using `.reset(Instant::now() + RELAY_IDLE_TIMEOUT)`. The write timeout is completely removed.

**Tech Stack:** Rust, Tokio

---

### Task 1: Add Unit Test for `relay_copy_with_idle` Timeout

**Files:**
- Modify: `src/relay.rs:359` (At the end of the `tests` module)

- [ ] **Step 1: Write the failing test**
  Add the following test at the end of the `tests` module in `src/relay.rs`:

```rust
    #[tokio::test]
    async fn test_relay_copy_with_idle_timeout() {
        tokio::time::pause();

        let (mut client, _server) = tokio::io::duplex(64);
        let (mut writer_client, _writer_server) = tokio::io::duplex(64);

        let relay_fut = relay_copy_with_idle(&mut client, &mut writer_client);
        tokio::pin!(relay_fut);

        tokio::select! {
            _ = &mut relay_fut => {
                panic!("Should not complete immediately");
            }
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }

        tokio::time::advance(RELAY_IDLE_TIMEOUT + Duration::from_secs(1)).await;

        let res = relay_fut.await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }
```

- [ ] **Step 2: Run test to verify it fails**
  Run: `cargo test relay::tests::test_relay_copy_with_idle_timeout`
  Expected: Compile failure if `RELAY_IDLE_TIMEOUT` is not in scope in the tests module, or PASS if it already passes (wait, the old timeout mechanism also implements timeout, so this test should pass even with the old implementation). Let's verify that it compiles and passes/fails appropriately.

- [ ] **Step 3: Commit the test**
  Run:
  ```bash
  git add src/relay.rs
  git commit -m "test: add unit test for relay copy idle timeout"
  ```

---

### Task 2: Implement Optimization in `relay_copy_with_idle`

**Files:**
- Modify: `src/relay.rs:237-274`

- [ ] **Step 1: Replace implementation of `relay_copy_with_idle`**
  Modify the `relay_copy_with_idle` function to match the following implementation:

```rust
async fn relay_copy_with_idle<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = PooledBuffer::new();
    let mut copied = 0u64;
    let mut copied_since_yield = 0usize;

    let idle_sleep = tokio::time::sleep(RELAY_IDLE_TIMEOUT);
    tokio::pin!(idle_sleep);

    loop {
        let n = tokio::select! {
            res = reader.read(&mut buf[..]) => {
                res?
            }
            _ = &mut idle_sleep => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "relay idle timeout",
                ));
            }
        };

        if n == 0 {
            return Ok(copied);
        }

        writer.write_all(&buf[..n]).await?;

        idle_sleep.as_mut().reset(tokio::time::Instant::now() + RELAY_IDLE_TIMEOUT);

        copied += n as u64;
        copied_since_yield += n;
        if copied_since_yield >= RELAY_COPY_YIELD_BUDGET_BYTES {
            copied_since_yield = 0;
            tokio::task::yield_now().await;
        }
    }
}
```

- [ ] **Step 2: Run all unit tests to verify correctness**
  Run: `cargo test`
  Expected: PASS (134 tests passed)

- [ ] **Step 3: Format the code**
  Run: `cargo fmt`

- [ ] **Step 4: Commit the implementation**
  Run:
  ```bash
  git add src/relay.rs
  git commit -m "perf: optimize relay data plane by removing write timeouts and pinning idle sleep timer"
  ```

---

### Task 3: Run E2E Acceptance Tests

**Files:**
- None (Verification task)

- [ ] **Step 1: Run full acceptance suite**
  Run: `./script/acceptance/run_acceptance.sh`
  Expected: "All acceptance tests passed successfully!"

---

### Task 4: Run Performance Scaling Verification

**Files:**
- None (Verification task)

- [ ] **Step 1: Run single-stream smoke perf test**
  Run: `sudo ./script/perf/perf_smoke.sh`
  Expected: SUCCESS. Review throughput metrics.

- [ ] **Step 2: Run multi-core scalability perf test**
  Run: `sudo ./script/perf/perf_cores_scalability.sh`
  Expected: SUCCESS. Compare throughput metrics at 1, 2, 3, and 4 cores with baseline.
