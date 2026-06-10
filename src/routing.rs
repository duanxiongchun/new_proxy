use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone, Default)]
struct TrieNode<V> {
    value: Option<V>,
    children: [Option<Box<TrieNode<V>>>; 2],
}

impl<V> TrieNode<V> {
    fn new() -> Self {
        Self {
            value: None,
            children: [None, None],
        }
    }

    fn find_ips(&self, val: &V, path: u32, depth: u8, results: &mut Vec<IpAddr>)
    where
        V: PartialEq,
    {
        if let Some(ref v) = self.value {
            if v == val {
                let ip_val = if depth == 0 { 0 } else { path << (32 - depth) };
                let ip = std::net::Ipv4Addr::from(ip_val);
                results.push(IpAddr::V4(ip));
            }
        }
        for bit in 0..2 {
            if let Some(ref child) = self.children[bit] {
                child.find_ips(val, (path << 1) | (bit as u32), depth + 1, results);
            }
        }
    }

    fn find_ips_v6(&self, val: &V, path: [u8; 16], depth: u8, results: &mut Vec<IpAddr>)
    where
        V: PartialEq,
    {
        if let Some(ref v) = self.value {
            if v == val {
                results.push(IpAddr::V6(std::net::Ipv6Addr::from(path)));
            }
        }
        for bit in 0..2 {
            if let Some(ref child) = self.children[bit] {
                let mut next_path = path;
                let byte_idx = (depth / 8) as usize;
                let bit_idx = 7 - (depth % 8);
                if bit == 1 {
                    next_path[byte_idx] |= 1 << bit_idx;
                } else {
                    next_path[byte_idx] &= !(1 << bit_idx);
                }
                child.find_ips_v6(val, next_path, depth + 1, results);
            }
        }
    }
}

#[derive(Clone)]
pub struct AllowedIPsRouter<V> {
    v4_root: TrieNode<V>,
    v6_root: TrieNode<V>,
}

impl<V: Clone> AllowedIPsRouter<V> {
    pub fn new() -> Self {
        Self {
            v4_root: TrieNode::new(),
            v6_root: TrieNode::new(),
        }
    }

    // 插入一个 CIDR 子网段路由
    pub fn insert(&mut self, net: IpNet, value: V) {
        match net {
            IpNet::V4(net_v4) => {
                let ip = net_v4.network();
                let prefix_len = net_v4.prefix_len();
                let bits = u32::from(ip);
                let mut current = &mut self.v4_root;

                for i in 0..prefix_len {
                    let bit = ((bits >> (31 - i)) & 1) as usize;
                    if current.children[bit].is_none() {
                        current.children[bit] = Some(Box::new(TrieNode::new()));
                    }
                    current = current.children[bit].as_mut().unwrap();
                }
                current.value = Some(value);
            }
            IpNet::V6(net_v6) => {
                let ip = net_v6.network();
                let prefix_len = net_v6.prefix_len();
                let bits = ip.octets();
                let mut current = &mut self.v6_root;

                for i in 0..prefix_len {
                    let byte_idx = (i / 8) as usize;
                    let bit_idx = 7 - (i % 8);
                    let bit = ((bits[byte_idx] >> bit_idx) & 1) as usize;
                    if current.children[bit].is_none() {
                        current.children[bit] = Some(Box::new(TrieNode::new()));
                    }
                    current = current.children[bit].as_mut().unwrap();
                }
                current.value = Some(value);
            }
        }
    }

    // 最长前缀匹配 (LPM) 精准检索
    pub fn longest_match(&self, ip: IpAddr) -> Option<V> {
        match ip {
            IpAddr::V4(ip_v4) => {
                let bits = u32::from(ip_v4);
                let mut current = &self.v4_root;
                let mut best_match = &current.value;

                for i in 0..32 {
                    let bit = ((bits >> (31 - i)) & 1) as usize;
                    if let Some(ref next) = current.children[bit] {
                        current = next;
                        if current.value.is_some() {
                            best_match = &current.value;
                        }
                    } else {
                        break;
                    }
                }
                best_match.clone()
            }
            IpAddr::V6(ip_v6) => {
                let bits = ip_v6.octets();
                let mut current = &self.v6_root;
                let mut best_match = &current.value;

                for i in 0..128 {
                    let byte_idx = (i / 8) as usize;
                    let bit_idx = 7 - (i % 8);
                    let bit = ((bits[byte_idx] >> bit_idx) & 1) as usize;
                    if let Some(ref next) = current.children[bit] {
                        current = next;
                        if current.value.is_some() {
                            best_match = &current.value;
                        }
                    } else {
                        break;
                    }
                }
                best_match.clone()
            }
        }
    }

    pub fn find_ips_for_value(&self, val: &V) -> Vec<IpAddr>
    where
        V: PartialEq,
    {
        let mut results = Vec::new();
        self.v4_root.find_ips(val, 0, 0, &mut results);
        self.v6_root.find_ips_v6(val, [0u8; 16], 0, &mut results);
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_trie_routing() {
        let mut router = AllowedIPsRouter::new();
        router.insert(IpNet::from_str("192.168.1.0/24").unwrap(), "PeerA");
        router.insert(IpNet::from_str("192.168.0.0/16").unwrap(), "PeerB");
        router.insert(IpNet::from_str("8.8.8.8/32").unwrap(), "PeerC");
        router.insert(IpNet::from_str("2001:db8::/32").unwrap(), "PeerD");

        // 1. LPM 验证：同时命中的情况下，必须返回掩码更长、更精准的 PeerA (L32 优先于 L16)
        assert_eq!(
            router.longest_match(IpAddr::from_str("192.168.1.55").unwrap()),
            Some("PeerA")
        );
        assert_eq!(
            router.longest_match(IpAddr::from_str("192.168.2.1").unwrap()),
            Some("PeerB")
        );

        // 2. 精确主机匹配
        assert_eq!(
            router.longest_match(IpAddr::from_str("8.8.8.8").unwrap()),
            Some("PeerC")
        );
        assert_eq!(
            router.longest_match(IpAddr::from_str("8.8.8.9").unwrap()),
            None
        );

        // 3. IPv6 匹配
        assert_eq!(
            router.longest_match(IpAddr::from_str("2001:db8::ffff").unwrap()),
            Some("PeerD")
        );
        assert_eq!(
            router.longest_match(IpAddr::from_str("2001:db9::1").unwrap()),
            None
        );
    }

    #[test]
    fn default_routes_match_when_no_more_specific_route_exists() {
        let mut router = AllowedIPsRouter::new();
        router.insert(IpNet::from_str("0.0.0.0/0").unwrap(), "PeerV4Default");
        router.insert(IpNet::from_str("::/0").unwrap(), "PeerV6Default");
        router.insert(IpNet::from_str("10.0.0.0/8").unwrap(), "PeerV4Private");

        assert_eq!(
            router.longest_match(IpAddr::from_str("8.8.8.8").unwrap()),
            Some("PeerV4Default")
        );
        assert_eq!(
            router.longest_match(IpAddr::from_str("10.1.2.3").unwrap()),
            Some("PeerV4Private")
        );
        assert_eq!(
            router.longest_match(IpAddr::from_str("2001:db8::1").unwrap()),
            Some("PeerV6Default")
        );
    }

    #[test]
    fn inserting_same_prefix_replaces_previous_value() {
        let mut router = AllowedIPsRouter::new();
        router.insert(IpNet::from_str("192.0.2.0/24").unwrap(), "old");
        router.insert(IpNet::from_str("192.0.2.0/24").unwrap(), "new");

        assert_eq!(
            router.longest_match(IpAddr::from_str("192.0.2.42").unwrap()),
            Some("new")
        );
    }
}
