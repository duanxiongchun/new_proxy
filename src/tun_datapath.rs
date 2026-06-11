use std::sync::Arc;
use crate::datapath::{Datapath, DatapathError, DatapathStats};
use arc_swap::ArcSwap;

pub struct TunDatapath {
    _worker_id: usize,
}

impl TunDatapath {
    pub fn new() -> Result<Self, DatapathError> {
        Err(DatapathError::Config("Not implemented".into()))
    }
}

#[async_trait::async_trait]
impl Datapath for TunDatapath {
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
