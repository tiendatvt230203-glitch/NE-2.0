#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP_VAL 0x0806
#define ETH_P_8021Q_VAL 0x8100
#define PATH_MTU 1500
#define ETH_FRAME_MAX (14 + PATH_MTU)
#define ETH_VLAN_FRAME_MAX (18 + PATH_MTU)

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len;
    struct ethhdr *eth = data;

    pkt_len = (__u32)((long)data_end - (long)data);
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q_VAL)) {
        if (pkt_len > ETH_VLAN_FRAME_MAX)
            return XDP_DROP;
    } else if (pkt_len > ETH_FRAME_MAX) {
        return XDP_DROP;
    }

    if (eth->h_proto == bpf_htons(ETH_P_ARP_VAL)) {
        goto redirect;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        goto redirect;
    }

    return XDP_PASS;

redirect:
    ;
    __u32 qid = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
