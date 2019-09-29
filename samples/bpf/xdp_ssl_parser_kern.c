#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include "bpf_helpers.h"

static int tcp(struct xdp_md *ctx, void *data, uint64_t tp_off, void *data_end, __u32 dst_ip)
{
	char funcname[] = "checksni";
	struct tcphdr *tcp = data + tp_off;
	int data_ref;
	int veridict;

	if (tcp + 1 > data_end)
		return XDP_PASS;

	if (tcp->dest == htons(443)) {
		bpf_set_lua_state(ctx);
		data_ref = bpf_lua_data_newref(ctx, tp_off + tcp->doff * 4);
		if (data_ref < 0)
			return XDP_PASS;

		bpf_lua_pushskb(ctx);
		bpf_lua_pcall(ctx, funcname, 2, 1);
		veridict = bpf_lua_toboolean(ctx, -1);
		bpf_lua_pop(ctx, -1);

		bpf_lua_data_unref(ctx, data_ref);
		if (veridict)
			return XDP_TX;

	}

	return XDP_PASS;
}

static int parse_ipv4(struct xdp_md *ctx, void *data, uint64_t nh_off, void *data_end)
{
	struct iphdr *iph;
	uint64_t ihl_len;

	iph = data + nh_off;
	if (iph + 1 > data_end)
		return 0;

	ihl_len = iph->ihl * 4;

	if (iph->protocol == IPPROTO_TCP)
		return tcp(ctx, data, nh_off + ihl_len, data_end, iph->daddr);

	return XDP_PASS;
}

SEC("sslparser")
int xdp_parse_sni(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	u16 h_proto;
	uint64_t nh_off = 0;
	struct ethhdr *eth = data;
	int rc = XDP_PASS;

	if(eth + 1 > data_end)
		return rc;

	h_proto = eth->h_proto;
	nh_off += sizeof(struct ethhdr);
	if (h_proto != htons(ETH_P_IP))
			return rc;

	return parse_ipv4(ctx, data, nh_off, data_end);
}

char _license[] SEC("license") = "GPL";
