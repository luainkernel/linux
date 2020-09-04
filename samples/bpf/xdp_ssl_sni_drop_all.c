#define KBUILD_MODNAME "foo"

#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/bpf.h>
#include <net/ip.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") rx_cnt = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 1,
};

SEC("sslparser")
int handle_ingress(struct xdp_md *ctx)
{
	u32 key_rx = 0;
	long *cnt;

	cnt = bpf_map_lookup_elem(&rx_cnt, &key_rx);
	if (!cnt)
		return XDP_PASS;

	(*cnt)++;

	return XDP_DROP;
}
char _license[] SEC("license") = "GPL";
