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
    __type(value, __u8);
} tunnel_ip_flags SEC(".maps") __attribute__((unused));

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

struct lpm_v4_key {
    __u32 prefix_len;
    __u32 address;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
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
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
} allowed_v6 SEC(".maps") __attribute__((unused));

static __always_inline int redirect_queue(struct xdp_md *ctx) {
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
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

SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    __u32 zero = 0;
    __u8 *roles = bpf_map_lookup_elem(&role_flags, &zero);
    if (!roles)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u32 ip_len = ip->ihl * 4;
        if (ip_len < sizeof(struct iphdr))
            return XDP_PASS;

        void *ip_end = (void *)ip + ip_len;
        if (ip_end > data_end)
            return XDP_PASS;

        if ((*roles & 1) && ip->protocol == IPPROTO_UDP && is_tunnel_v4(ip, zero)) {
            struct udphdr *udp = (void *)ip_end;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;

            __u16 *configured = bpf_map_lookup_elem(&tunnel_port, &zero);
            if (configured && udp->dest == *configured)
                return redirect_queue(ctx);
        }

        struct lpm_v4_key key = {
            .prefix_len = 32,
            .address = ip->daddr,
        };
        if ((*roles & 2) && bpf_map_lookup_elem(&allowed_v4, &key))
            return redirect_queue(ctx);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        if ((*roles & 1) && ip6->nexthdr == IPPROTO_UDP && is_tunnel_v6(ip6, zero)) {
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
            __u16 *configured = bpf_map_lookup_elem(&tunnel_port, &zero);
            if (configured && udp->dest == *configured)
                return redirect_queue(ctx);
        }

        struct lpm_v6_key key = { .prefix_len = 128 };
        __builtin_memcpy(key.address, &ip6->daddr, sizeof(key.address));
        if ((*roles & 2) && bpf_map_lookup_elem(&allowed_v6, &key))
            return redirect_queue(ctx);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
