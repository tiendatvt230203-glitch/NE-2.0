#include <linux/bpf.h>
#include <linux/if_ether.h>
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

#define ETH_P_NE_ARP_ENC 0x1048
#define ETH_P_NE_UDP_ENC 0x104B
#define ETH_P_8021Q_VAL  0x8100
#define PATH_MTU         1500
#define ETH_FRAME_MAX    (14 + PATH_MTU)
#define ETH_VLAN_FRAME_MAX (18 + PATH_MTU)
/* A plaintext 1500-byte IP packet grows on the encrypted WAN wire. */
#define NE_L2_WIRE_OVERHEAD 41
#define ETH_ENCRYPTED_FRAME_MAX (ETH_FRAME_MAX + NE_L2_WIRE_OVERHEAD)
#define ETH_VLAN_ENCRYPTED_FRAME_MAX (ETH_VLAN_FRAME_MAX + NE_L2_WIRE_OVERHEAD)

static __always_inline int xdp_wan_redirect_common(struct xdp_md *ctx,
                                                    int phase1_mtu_guard)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;
    __u16 wire_proto = proto;
    int key0 = 0;
    __u16 *fake4 = bpf_map_lookup_elem(&wan_config_map, &key0);
    if (proto == bpf_htons(ETH_P_8021Q_VAL)) {
        __u16 *inner_proto = data + 16;

        if ((void *)(inner_proto + 1) > data_end)
            return XDP_PASS;
        wire_proto = *inner_proto;
    }
    int encrypted_l2 =
        wire_proto == bpf_htons(ETH_P_NE_ARP_ENC) ||
        wire_proto == bpf_htons(ETH_P_NE_UDP_ENC) ||
        (fake4 && *fake4 != 0 && wire_proto == bpf_htons(*fake4));

    if (phase1_mtu_guard) {
        __u32 pkt_len = (__u32)((long)data_end - (long)data);

        if (proto == bpf_htons(ETH_P_8021Q_VAL)) {
            if (pkt_len > (encrypted_l2 ? ETH_VLAN_ENCRYPTED_FRAME_MAX
                                        : ETH_VLAN_FRAME_MAX))
                return XDP_DROP;
        } else if (pkt_len > (encrypted_l2 ? ETH_ENCRYPTED_FRAME_MAX
                                           : ETH_FRAME_MAX)) {
            return XDP_DROP;
        }
    }

    /* Capture every WAN frame. Userspace accepts only authenticated encrypted
     * markers, so plaintext or unknown EtherTypes cannot leak through a bridge. */
    __u32 qid = ctx->rx_queue_index;
    return bpf_redirect_map(&wan_xsks_map, qid, 0);
}

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    return xdp_wan_redirect_common(ctx, 0);
}

SEC("xdp.frags")
int xdp_wan_redirect_prog_frags(struct xdp_md *ctx)
{
    /* Keep phase-1 behavior bounded to MTU 1500 until WAN jumbo ownership
     * and crypto processing are implemented. */
    return xdp_wan_redirect_common(ctx, 1);
}

char _license[] SEC("license") = "GPL";
