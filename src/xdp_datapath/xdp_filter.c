#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps") __attribute__((unused));

SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
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

        // 1. Redirect QUIC UDP packets on port 51820 or 40001
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip_end;
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;

            if (udp->dest == bpf_htons(51820) || udp->dest == bpf_htons(40001)) {
                return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
            }
        }

        // 2. Redirect client plaintext IPs (10.0.0.0/8 subnet)
        __u32 dest_ip = ip->daddr;
        if ((dest_ip & bpf_htonl(0xFF000000)) == bpf_htonl(0x0A000000)) {
            return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
