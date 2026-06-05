use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::IpAddr;

pub struct UserspaceWg {
    tunn: Tunn,
}

impl UserspaceWg {
    pub fn new(
        private_key: StaticSecret,
        peer_public_key: PublicKey,
    ) -> Result<Self, String> {
        let tunn = Tunn::new(
            private_key,
            peer_public_key,
            None,
            None,
            1,
            None,
        );
        Ok(Self { tunn })
    }

    pub fn decapsulate<'a>(
        &mut self,
        src_ip: Option<IpAddr>,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.tunn.decapsulate(src_ip, src, dst)
    }

    pub fn encapsulate<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.tunn.encapsulate(src, dst)
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.update_timers(dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boringtun_state() {
        let private_key = StaticSecret::from([1u8; 32]);
        let public_key = PublicKey::from(&private_key);
        let tunn = UserspaceWg::new(private_key, public_key);
        assert!(tunn.is_ok());
    }
}
