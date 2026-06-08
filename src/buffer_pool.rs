use parking_lot::Mutex;
use std::sync::Arc;

const DEFAULT_POOL_CACHE_LIMIT: usize = 1024;
const POOL_CACHE_LIMIT_ENV: &str = "NEW_PROXY_PACKET_BUFFER_POOL_CACHE";

#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

struct BufferPoolInner {
    buffers: Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
    cache_limit: usize,
}

pub struct PooledBuf {
    data: Option<Vec<u8>>,
    start: usize,
    len: usize,
    pool: Arc<BufferPoolInner>,
}

impl BufferPool {
    pub fn new(buffer_size: usize) -> Self {
        let cache_limit = std::env::var(POOL_CACHE_LIMIT_ENV)
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_POOL_CACHE_LIMIT);
        Self {
            inner: Arc::new(BufferPoolInner {
                buffers: Mutex::new(Vec::with_capacity(cache_limit.min(1024))),
                buffer_size,
                cache_limit,
            }),
        }
    }

    pub fn get(&self) -> PooledBuf {
        let data = self
            .inner
            .buffers
            .lock()
            .pop()
            .unwrap_or_else(|| vec![0u8; self.inner.buffer_size]);
        PooledBuf {
            data: Some(data),
            start: 0,
            len: 0,
            pool: self.inner.clone(),
        }
    }

    pub fn copy_from_slice(&self, src: &[u8]) -> Option<PooledBuf> {
        let mut buf = self.get();
        if src.len() > buf.capacity() {
            return None;
        }
        buf.as_mut_capacity()[..src.len()].copy_from_slice(src);
        buf.set_len(src.len());
        Some(buf)
    }
}

impl PooledBuf {
    pub fn capacity(&self) -> usize {
        self.data.as_ref().map(|data| data.len()).unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        let data = self.data.as_ref().expect("pooled buffer present");
        &data[self.start..self.start + self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let data = self.data.as_mut().expect("pooled buffer present");
        &mut data[self.start..self.start + self.len]
    }

    pub fn as_mut_capacity(&mut self) -> &mut [u8] {
        self.start = 0;
        self.len = 0;
        self.data
            .as_mut()
            .expect("pooled buffer present")
            .as_mut_slice()
    }

    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.capacity(),
            "pooled buffer length exceeds capacity"
        );
        self.start = 0;
        self.len = len;
    }

    pub fn consume_front(&mut self, consumed: usize) {
        let consumed = consumed.min(self.len);
        self.start += consumed;
        self.len -= consumed;
        if self.len == 0 {
            self.start = 0;
        }
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        let Some(mut data) = self.data.take() else {
            return;
        };
        if data.len() != self.pool.buffer_size {
            data.resize(self.pool.buffer_size, 0);
        }
        let mut buffers = self.pool.buffers.lock();
        if buffers.len() < self.pool.cache_limit {
            buffers.push(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_buffer_round_trips_and_consumes_without_copying_tail() {
        let pool = BufferPool::new(16);
        let mut buf = pool.copy_from_slice(b"abcdef").unwrap();
        assert_eq!(buf.as_slice(), b"abcdef");
        buf.consume_front(2);
        assert_eq!(buf.as_slice(), b"cdef");
        buf.consume_front(4);
        assert!(buf.is_empty());
    }
}
