#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} tunnel_port SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} role_flags SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} parser_drops SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dns_fragment_drops SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} intercept_policy_mode SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} tunnel_ip_flags SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} dns_ip_flags SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} tunnel_v4 SEC(".maps") __attribute__((unused));

struct tunnel_v6_value {
    __u8 address[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_v6_value);
} tunnel_v6 SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dns_v4 SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_v6_value);
} dns_v6 SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} dns_local_flags SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} dns_local_resolver_port SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} dns_nat_port_start SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} dns_nat_port_end SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dns_local_resolver_v4 SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} dns_nat_v4 SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_v6_value);
} dns_local_resolver_v6 SEC(".maps") __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_v6_value);
} dns_nat_v6 SEC(".maps") __attribute__((unused));

struct lpm_v4_key {
    __u32 prefix_len;
    __u32 address;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
} allowed_v4 SEC(".maps") __attribute__((unused));

struct lpm_v6_key {
    __u32 prefix_len;
    __u8 address[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
} allowed_v6 SEC(".maps") __attribute__((unused));

#define POLICY_TUNNEL_PREFIXES 0
#define POLICY_DIRECT_PREFIXES 1
#define POLICY_ACTION_PASS 0
#define POLICY_ACTION_REDIRECT 1

static __always_inline int redirect_queue(struct xdp_md *ctx) {
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_DROP);
}

static __always_inline int parser_drop(__u32 zero) {
    __u64 *drops = bpf_map_lookup_elem(&parser_drops, &zero);
    if (drops)
        __sync_fetch_and_add(drops, 1);
    return XDP_DROP;
}

static __always_inline int dns_fragment_drop(__u32 zero) {
    __u64 *drops = bpf_map_lookup_elem(&dns_fragment_drops, &zero);
    if (drops)
        __sync_fetch_and_add(drops, 1);
    return XDP_DROP;
}

static __always_inline int is_tunnel_v4(struct iphdr *ip, __u32 zero) {
    __u8 *flags = bpf_map_lookup_elem(&tunnel_ip_flags, &zero);
    if (!flags || !(*flags & 1))
        return 0;
    __u32 *configured = bpf_map_lookup_elem(&tunnel_v4, &zero);
    return configured && ip->daddr == *configured;
}

static __always_inline int is_tunnel_v6(struct ipv6hdr *ip6, __u32 zero) {
    __u8 *flags = bpf_map_lookup_elem(&tunnel_ip_flags, &zero);
    if (!flags || !(*flags & 2))
        return 0;
    struct tunnel_v6_value *configured = bpf_map_lookup_elem(&tunnel_v6, &zero);
    if (!configured)
        return 0;
    for (int i = 0; i < 16; i++) {
        if (ip6->daddr.s6_addr[i] != configured->address[i])
            return 0;
    }
    return 1;
}

static __always_inline int is_dns_v4(struct iphdr *ip, __u32 zero) {
    __u8 *flags = bpf_map_lookup_elem(&dns_ip_flags, &zero);
    if (!flags || !(*flags & 1))
        return 0;
    __u32 *configured = bpf_map_lookup_elem(&dns_v4, &zero);
    return configured && ip->daddr == *configured;
}

static __always_inline int is_dns_v6(struct ipv6hdr *ip6, __u32 zero) {
    __u8 *flags = bpf_map_lookup_elem(&dns_ip_flags, &zero);
    if (!flags || !(*flags & 2))
        return 0;
    struct tunnel_v6_value *configured = bpf_map_lookup_elem(&dns_v6, &zero);
    if (!configured)
        return 0;
    for (int i = 0; i < 16; i++) {
        if (ip6->daddr.s6_addr[i] != configured->address[i])
            return 0;
    }
    return 1;
}

static __always_inline int is_dns_local_response_v4(struct iphdr *ip, __u32 zero) {
    __u8 *flags = bpf_map_lookup_elem(&dns_local_flags, &zero);
    if (!flags || !(*flags & 1))
        return 0;
    __u32 *resolver = bpf_map_lookup_elem(&dns_local_resolver_v4, &zero);
    __u32 *nat = bpf_map_lookup_elem(&dns_nat_v4, &zero);
    return resolver && nat && ip->saddr == *resolver && ip->daddr == *nat;
}

static __always_inline int is_dns_local_response_v6(struct ipv6hdr *ip6, __u32 zero) {
    __u8 *flags = bpf_map_lookup_elem(&dns_local_flags, &zero);
    if (!flags || !(*flags & 2))
        return 0;
    struct tunnel_v6_value *resolver = bpf_map_lookup_elem(&dns_local_resolver_v6, &zero);
    struct tunnel_v6_value *nat = bpf_map_lookup_elem(&dns_nat_v6, &zero);
    if (!resolver || !nat)
        return 0;
    for (int i = 0; i < 16; i++) {
        if (ip6->saddr.s6_addr[i] != resolver->address[i])
            return 0;
        if (ip6->daddr.s6_addr[i] != nat->address[i])
            return 0;
    }
    return 1;
}

static __always_inline int is_public_v4(__be32 address) {
    __u32 host = bpf_ntohl(address);
    __u8 a = host >> 24;
    __u8 b = host >> 16;
    __u8 c = host >> 8;
    if (a == 0 || a == 10 || a == 127 || a >= 224)
        return 0;
    if (a == 100 && b >= 64 && b <= 127)
        return 0;
    if (a == 169 && b == 254)
        return 0;
    if (a == 172 && b >= 16 && b <= 31)
        return 0;
    if (a == 192 && b == 168)
        return 0;
    if (a == 192 && b == 0 && (c == 0 || c == 2))
        return 0;
    if (a == 192 && b == 31 && c == 196)
        return 0;
    if (a == 192 && b == 52 && c == 193)
        return 0;
    if (a == 192 && b == 88 && c == 99)
        return 0;
    if (a == 192 && b == 175 && c == 48)
        return 0;
    if (a == 198 && (b == 18 || b == 19))
        return 0;
    if (a == 198 && b == 51 && c == 100)
        return 0;
    if (a == 203 && b == 0 && c == 113)
        return 0;
    if (host == 0xffffffff)
        return 0;
    return 1;
}

static __always_inline int is_unspecified_v6(struct ipv6hdr *ip6) {
    for (int i = 0; i < 16; i++) {
        if (ip6->daddr.s6_addr[i] != 0)
            return 0;
    }
    return 1;
}

static __always_inline int is_loopback_v6(struct ipv6hdr *ip6) {
    for (int i = 0; i < 15; i++) {
        if (ip6->daddr.s6_addr[i] != 0)
            return 0;
    }
    return ip6->daddr.s6_addr[15] == 1;
}

static __always_inline int is_public_v6(struct ipv6hdr *ip6) {
    __u8 first = ip6->daddr.s6_addr[0];
    __u8 second = ip6->daddr.s6_addr[1];
    if (is_unspecified_v6(ip6) || is_loopback_v6(ip6))
        return 0;
    if (first == 0xff)
        return 0;
    if (first == 0xfe && (second & 0xc0) == 0x80)
        return 0;
    if (first == 0xfe && (second & 0xc0) == 0xc0)
        return 0;
    if ((first & 0xfe) == 0xfc)
        return 0;
    int mapped_v4 = 1;
    for (int i = 0; i < 10; i++) {
        if (ip6->daddr.s6_addr[i] != 0)
            mapped_v4 = 0;
    }
    if (mapped_v4 && ip6->daddr.s6_addr[10] == 0xff &&
        ip6->daddr.s6_addr[11] == 0xff)
        return 0;
    if (first == 0x01 && second == 0x00) {
        int discard = 1;
        for (int i = 2; i < 8; i++) {
            if (ip6->daddr.s6_addr[i] != 0)
                discard = 0;
        }
        if (discard)
            return 0;
    }
    if (first == 0x20 && second == 0x01 &&
        ip6->daddr.s6_addr[2] == 0x0d && ip6->daddr.s6_addr[3] == 0xb8)
        return 0;
    if (first == 0x20 && second == 0x01 &&
        ip6->daddr.s6_addr[2] == 0x00 && ip6->daddr.s6_addr[3] == 0x02 &&
        ip6->daddr.s6_addr[4] == 0 && ip6->daddr.s6_addr[5] == 0)
        return 0;
    return 1;
}

static __always_inline int intercept_action_v4(
    struct xdp_md *ctx,
    struct iphdr *ip,
    __u32 zero,
    int fragmented
) {
    struct lpm_v4_key key = {
        .prefix_len = 32,
        .address = ip->daddr,
    };
    __u8 *action = bpf_map_lookup_elem(&allowed_v4, &key);
    if (action) {
        if (*action == POLICY_ACTION_REDIRECT) {
            if (fragmented)
                return XDP_DROP;
            return redirect_queue(ctx);
        }
        return XDP_PASS;
    }
    __u8 *mode = bpf_map_lookup_elem(&intercept_policy_mode, &zero);
    if (mode && *mode == POLICY_DIRECT_PREFIXES && is_public_v4(ip->daddr)) {
        if (fragmented)
            return XDP_DROP;
        return redirect_queue(ctx);
    }
    return XDP_PASS;
}

static __always_inline int intercept_action_v6(
    struct xdp_md *ctx,
    struct ipv6hdr *ip6,
    __u32 zero,
    int fragmented
) {
    struct lpm_v6_key key = { .prefix_len = 128 };
    __builtin_memcpy(key.address, &ip6->daddr, sizeof(key.address));
    __u8 *action = bpf_map_lookup_elem(&allowed_v6, &key);
    if (action) {
        if (*action == POLICY_ACTION_REDIRECT) {
            if (fragmented)
                return XDP_DROP;
            return redirect_queue(ctx);
        }
        return XDP_PASS;
    }
    __u8 *mode = bpf_map_lookup_elem(&intercept_policy_mode, &zero);
    if (mode && *mode == POLICY_DIRECT_PREFIXES && is_public_v6(ip6)) {
        if (fragmented)
            return XDP_DROP;
        return redirect_queue(ctx);
    }
    return XDP_PASS;
}

static __always_inline int ipv6_transport_header(
    void **cursor,
    void *data_end,
    __u8 *nexthdr,
    int *fragmented,
    __u32 *remaining_payload
) {
    void *offset = *cursor;
#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (*nexthdr == IPPROTO_HOPOPTS || *nexthdr == IPPROTO_ROUTING ||
            *nexthdr == IPPROTO_DSTOPTS) {
            __u8 *header = offset;
            if ((void *)(header + 2) > data_end)
                return 0;
            *nexthdr = header[0];
            __u32 header_len = (__u32)(header[1] + 1) * 8;
            if (header_len > *remaining_payload)
                return 0;
            offset += header_len;
            if (offset > data_end)
                return 0;
            *remaining_payload -= header_len;
        } else if (*nexthdr == IPPROTO_FRAGMENT) {
            __u8 *header = offset;
            if (*remaining_payload < 8 || (void *)(header + 8) > data_end)
                return 0;
            __u16 fragment = ((__u16)header[2] << 8) | header[3];
            if (fragment & 0xfff8)
                *fragmented = 2;
            else if (fragment & 1)
                *fragmented = 1;
            *nexthdr = header[0];
            offset += 8;
            *remaining_payload -= 8;
        } else if (*nexthdr == IPPROTO_AH) {
            __u8 *header = offset;
            if ((void *)(header + 2) > data_end)
                return 0;
            *nexthdr = header[0];
            __u32 header_len = (__u32)(header[1] + 2) * 4;
            if (header_len > *remaining_payload)
                return 0;
            offset += header_len;
            if (offset > data_end)
                return 0;
            *remaining_payload -= header_len;
        } else {
            *cursor = offset;
            return 1;
        }
    }
    return 0;
}

SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 zero = 0;
    __u8 *roles = bpf_map_lookup_elem(&role_flags, &zero);
    if (!roles || !*roles)
        return XDP_PASS;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return parser_drop(zero);

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return parser_drop(zero);

        __u32 ip_len = ip->ihl * 4;
        if (ip->version != 4 || ip_len < sizeof(struct iphdr))
            return parser_drop(zero);

        void *ip_end = (void *)ip + ip_len;
        if (ip_end > data_end)
            return parser_drop(zero);
        __u16 total_len = bpf_ntohs(ip->tot_len);
        __u64 captured_ip_len = data_end - (void *)ip;
        if (total_len < ip_len || total_len > captured_ip_len)
            return parser_drop(zero);
        int fragmented = (ip->frag_off & bpf_htons(0x3fff)) != 0;
        int non_initial_fragment = (ip->frag_off & bpf_htons(0x1fff)) != 0;

        if ((*roles & 1) && ip->protocol == IPPROTO_UDP && is_tunnel_v4(ip, zero)) {
            struct udphdr *udp = (void *)ip_end;
            if ((void *)(udp + 1) > data_end)
                return parser_drop(zero);
            __u16 udp_len = bpf_ntohs(udp->len);
            if (udp_len < sizeof(struct udphdr) || udp_len > total_len - ip_len)
                return parser_drop(zero);

            __u16 *configured = bpf_map_lookup_elem(&tunnel_port, &zero);
            if (configured && udp->dest == *configured)
                return redirect_queue(ctx);
        }
        if ((*roles & 2) && is_dns_v4(ip, zero)) {
            if (ip->protocol != IPPROTO_UDP)
                return XDP_PASS;
            if (non_initial_fragment)
                return dns_fragment_drop(zero);
            struct udphdr *udp = (void *)ip_end;
            if ((void *)(udp + 1) > data_end)
                return parser_drop(zero);
            __u16 udp_len = bpf_ntohs(udp->len);
            if (udp_len < sizeof(struct udphdr) || udp_len > total_len - ip_len)
                return parser_drop(zero);
            if (udp->dest == bpf_htons(53)) {
                if (fragmented)
                    return dns_fragment_drop(zero);
                return redirect_queue(ctx);
            }
            return XDP_PASS;
        }
        if ((*roles & 2) && ip->protocol == IPPROTO_UDP && is_dns_local_response_v4(ip, zero)) {
            if (ip->frag_off & bpf_htons(0x3fff))
                return dns_fragment_drop(zero);
            struct udphdr *udp = (void *)ip_end;
            if ((void *)(udp + 1) > data_end)
                return parser_drop(zero);
            __u16 udp_len = bpf_ntohs(udp->len);
            if (udp_len < sizeof(struct udphdr) || udp_len > total_len - ip_len)
                return parser_drop(zero);
            __u16 *configured = bpf_map_lookup_elem(&dns_local_resolver_port, &zero);
            __u16 *start = bpf_map_lookup_elem(&dns_nat_port_start, &zero);
            __u16 *end = bpf_map_lookup_elem(&dns_nat_port_end, &zero);
            __u16 destination = bpf_ntohs(udp->dest);
            if (configured && start && end && udp->source == *configured &&
                destination >= *start && destination <= *end)
                return redirect_queue(ctx);
        }
        if ((*roles & 1) && is_tunnel_v4(ip, zero))
            return XDP_PASS;

        if (*roles & 2)
            return intercept_action_v4(ctx, ip, zero, fragmented);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return parser_drop(zero);
        if (ip6->version != 6)
            return parser_drop(zero);
        __u32 payload_len = bpf_ntohs(ip6->payload_len) & 0xffff;
        __u64 captured_payload_len = data_end - (void *)(ip6 + 1);
        if (payload_len > captured_payload_len)
            return parser_drop(zero);

        __u8 protocol = ip6->nexthdr;
        void *transport = (void *)(ip6 + 1);
        int fragmented = 0;
        __u32 remaining_payload = payload_len;
        if (!ipv6_transport_header(
                &transport,
                data_end,
                &protocol,
                &fragmented,
                &remaining_payload
            ))
            return parser_drop(zero);

        if ((*roles & 1) && protocol == IPPROTO_UDP && is_tunnel_v6(ip6, zero)) {
            if (fragmented)
                return XDP_DROP;
            struct udphdr *udp = transport;
            if ((void *)(udp + 1) > data_end)
                return parser_drop(zero);
            __u16 udp_len = bpf_ntohs(udp->len);
            if (udp_len < sizeof(struct udphdr) || udp_len > remaining_payload)
                return parser_drop(zero);
            __u16 *configured = bpf_map_lookup_elem(&tunnel_port, &zero);
            if (configured && udp->dest == *configured)
                return redirect_queue(ctx);
        }
        if ((*roles & 2) && is_dns_v6(ip6, zero)) {
            if (protocol != IPPROTO_UDP)
                return XDP_PASS;
            if (fragmented == 2)
                return dns_fragment_drop(zero);
            struct udphdr *udp = transport;
            if ((void *)(udp + 1) > data_end)
                return parser_drop(zero);
            __u16 udp_len = bpf_ntohs(udp->len);
            if (udp_len < sizeof(struct udphdr) || udp_len > remaining_payload)
                return parser_drop(zero);
            if (udp->dest == bpf_htons(53)) {
                if (fragmented)
                    return dns_fragment_drop(zero);
                return redirect_queue(ctx);
            }
            return XDP_PASS;
        }
        if ((*roles & 2) && is_dns_local_response_v6(ip6, zero)) {
            if (fragmented)
                return dns_fragment_drop(zero);
            if (protocol == IPPROTO_UDP) {
                struct udphdr *udp = transport;
                if ((void *)(udp + 1) > data_end)
                    return parser_drop(zero);
                __u16 udp_len = bpf_ntohs(udp->len);
                if (udp_len < sizeof(struct udphdr) || udp_len > remaining_payload)
                    return parser_drop(zero);
                __u16 *configured = bpf_map_lookup_elem(&dns_local_resolver_port, &zero);
                __u16 *start = bpf_map_lookup_elem(&dns_nat_port_start, &zero);
                __u16 *end = bpf_map_lookup_elem(&dns_nat_port_end, &zero);
                __u16 destination = bpf_ntohs(udp->dest);
                if (configured && start && end && udp->source == *configured &&
                    destination >= *start && destination <= *end)
                    return redirect_queue(ctx);
            }
        }
        if ((*roles & 1) && is_tunnel_v6(ip6, zero))
            return XDP_PASS;

        if (*roles & 2)
            return intercept_action_v6(ctx, ip6, zero, fragmented);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
