#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Older bundled headers do not declare this XDP multi-buffer helper. */
static __u64 (*xdp_get_buff_len)(struct xdp_md *ctx) = (void *)188;

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline int lan_redirect(struct xdp_md *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    __u8 *ip;
    __u16 ether_type;
    __u16 ip_len;
    __u8 protocol;
    __u32 packet_len;

    if ((void *)(eth + 1) > (void *)data_end)
        return XDP_PASS;
    ether_type = eth->h_proto;
    ip = data + 14;
    /* VLAN, ARP and non-IPv4 packets stay in the kernel path. */
    if (ether_type != bpf_htons(ETH_P_IP) || ip + 20 > data_end)
        return XDP_PASS;
    protocol = ip[9];
    if (protocol != 1 && protocol != 6 && protocol != 17 && protocol != 89)
        return XDP_PASS;
    ip_len = ((__u16)ip[2] << 8) | ip[3];
    packet_len = (__u32)xdp_get_buff_len(ctx);
    if (ip_len < 20 || ip_len > 9000 ||
        packet_len < (__u32)(ip - data) + ip_len ||
        packet_len > (__u32)(ip - data) + 9000)
        return XDP_DROP;
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
}

SEC("xdp.frags")
int xdp_redirect_prog_frags(struct xdp_md *ctx)
{
    return lan_redirect(ctx);
}

char _license[] SEC("license") = "GPL";
