# Spec: Data Plane Timeout Optimization

## Background
The `new_proxy` data plane connection relaying loop (`relay_copy_with_idle` in `src/relay.rs`) is invoked frequently under high traffic loads. In its original implementation, for every 16KB data block transferred, it constructed two `tokio::time::timeout` futures (one for read, one for write). Creating these futures results in continuous heap allocations and timer-wheel registration/deregistration overhead within Tokio, creating a CPU bottleneck at high throughput.

## Design Changes
1. **Remove Write Timeout**:
   - Remove the `RELAY_WRITE_TIMEOUT` wrapper from `writer.write_all(&buf[..n])`.
   - Rely on transport-level TCP keep-alives and QUIC idle timeouts to detect and terminate dead connections.
2. **Optimize Read Timeout**:
   - Instantiate a single `tokio::time::sleep(RELAY_IDLE_TIMEOUT)` future before entering the relay loop.
   - Pin the sleep future to the stack using `tokio::pin!`.
   - Concurrently poll the read operation and the sleep future using `tokio::select!`.
   - On a successful read, reset the deadline of the pinned sleep future in-place using `.reset(Instant::now() + RELAY_IDLE_TIMEOUT)`. This avoids allocating new future objects and optimizes timer wheel updates.

## Detailed Control Flow
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

## Verification Plan
1. **Compilation**: Run `cargo check` and `cargo test` to verify syntax and passing of all unit/integration tests.
2. **Acceptance Tests**: Run `./script/acceptance/run_acceptance.sh` to ensure E2E behavior is unchanged.
3. **Performance Baseline Comparison**:
   - Run `sudo ./script/perf/perf_smoke.sh` and compare TTFB and single-stream throughput.
   - Run `sudo ./script/perf/perf_cores_scalability.sh` and compare multi-core scaling efficiency.
