#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_ENCRYPTED_UDP 0x104B

/* Older bundled headers do not declare this XDP multi-buffer helper. */
static __u64 (*xdp_get_buff_len)(struct xdp_md *ctx) = (void *)188;

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} wan_xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} wan_config_map SEC(".maps");

static __always_inline int wan_redirect(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    __u16 ether_type;
    __u32 l2_len = 14;
    __u32 key = 0;
    __u16 *encrypted_et;
    int encrypted;

    if ((void *)(eth + 1) > (void *)data_end)
        return XDP_PASS;
    ether_type = eth->h_proto;
    if (ether_type == bpf_htons(ETH_P_8021Q) ||
        ether_type == bpf_htons(ETH_P_8021AD))
        return XDP_PASS;
    encrypted_et = bpf_map_lookup_elem(&wan_config_map, &key);
    encrypted = ether_type == bpf_htons(ETH_P_ENCRYPTED_UDP) ||
                (encrypted_et && *encrypted_et != 0 &&
                 ether_type == bpf_htons(*encrypted_et));
    /* Plain ARP and all other WAN traffic belong to the kernel bridge. */
    if (!encrypted)
        return XDP_PASS;
    if ((__u32)xdp_get_buff_len(ctx) > l2_len + 9000)
        return XDP_DROP;
    return bpf_redirect_map(&wan_xsks_map, ctx->rx_queue_index, 0);
}

SEC("xdp.frags")
int xdp_wan_redirect_prog_frags(struct xdp_md *ctx)
{
    return wan_redirect(ctx);
}

char _license[] SEC("license") = "GPL";
