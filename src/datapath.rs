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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockDatapath;
    #[async_trait::async_trait]
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
