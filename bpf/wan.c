#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} wan_xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u16);
} wan_config_map SEC(".maps");

#define IPPROTO_ICMP_VAL 1
#define IPPROTO_TCP_VAL 6
#define IPPROTO_UDP_VAL 17
#define IPPROTO_OSPF_VAL 89
#define ETH_P_NE_ARP_ENC 0x1048
#define ETH_P_NE_UDP_ENC 0x104B
#define ETH_P_CFM        0x8902

SEC("xdp.frags")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;

    /* CFM failover — luôn vào kernel stack cho AF_PACKET raw socket. */
    if (proto == __constant_htons(ETH_P_CFM))
        return XDP_PASS;

    if (proto == __constant_htons(ETH_P_ARP)) {
        goto redirect;
    }

    if (proto == __constant_htons(ETH_P_NE_ARP_ENC)) {
        goto redirect;
    }

    if (proto == __constant_htons(ETH_P_NE_UDP_ENC)) {
        goto redirect;
    }

    if (proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_ICMP_VAL || ip->protocol == IPPROTO_TCP_VAL ||
            ip->protocol == IPPROTO_UDP_VAL || ip->protocol == IPPROTO_OSPF_VAL) {
            goto redirect;
        }

        return XDP_PASS;
    }

    int key0 = 0;
    __u16 *fake4 = bpf_map_lookup_elem(&wan_config_map, &key0);
    if (fake4 && *fake4 != 0 && proto == bpf_htons(*fake4))
        goto redirect;

    int key1 = 1;
    __u16 *fake_udp = bpf_map_lookup_elem(&wan_config_map, &key1);
    if (fake_udp && *fake_udp != 0 && proto == bpf_htons(*fake_udp))
        goto redirect;

    return XDP_PASS;

redirect:
    ;
    __u32 qid = ctx->rx_queue_index;
    return bpf_redirect_map(&wan_xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
