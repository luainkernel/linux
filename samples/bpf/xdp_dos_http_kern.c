#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include "bpf_helpers.h"
#define RATEMAX 1000
#define NANOSEC_IN_SEC 1000000000

struct per_ip_data {
	u64 start_time;
	int pkt_count;
};

struct bpf_map_def SEC("maps") ip_data = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct per_ip_data),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") blacklist = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(bool),
	.max_entries = 100,
};

static int tcp(struct xdp_md *ctx, void *data, uint64_t tp_off, void *data_end, __u32 src_ip)
{
	char funcname[] = "checkuseragent";
	struct tcphdr *tcp = data + tp_off;
	int data_ref;
	int veridict;
	int *pkt_count;
	int key_time = 0;
	int key_pkt = 1;
	u64 current_time;
	bool dummy = true;
	u64 *start_time;
	u64 time_elapsed;
	struct per_ip_data *per_ip_data;
	struct per_ip_data start_data = {};

	if (tcp + 1 > data_end)
		return XDP_PASS;

	if (tcp->dest != htons(80))
		return XDP_PASS;

	current_time = bpf_ktime_get_ns() / NANOSEC_IN_SEC;

	per_ip_data = bpf_map_lookup_elem(&ip_data, &src_ip);
	if (!per_ip_data) {
		start_data.pkt_count = 0;
		start_data.start_time = current_time;
		bpf_map_update_elem(&ip_data, &src_ip, &start_data, BPF_ANY);
		return XDP_PASS;
	}

	time_elapsed = current_time - per_ip_data->start_time;
	if (time_elapsed == 0) {
		per_ip_data->pkt_count++;
		bpf_map_update_elem(&ip_data, &src_ip, per_ip_data, BPF_ANY);
		return XDP_PASS;
	}
	if (time_elapsed > 0) {
		if (per_ip_data->pkt_count / time_elapsed < RATEMAX) {
			per_ip_data->pkt_count++;
			bpf_map_update_elem(&ip_data, &src_ip, per_ip_data, BPF_ANY);
			return XDP_PASS;
		}
	}

	bpf_set_lua_state(ctx);
	data_ref = bpf_lua_data_newref(ctx, tp_off + tcp->doff * 4);
	if (data_ref < 0) {
		return XDP_PASS;
	}

	bpf_lua_pushskb(ctx);
	bpf_lua_pcall(ctx, funcname, 2, 1);
	veridict = bpf_lua_toboolean(ctx, -1);
	bpf_lua_pop(ctx, -1);
	bpf_lua_data_unref(ctx, data_ref);

	bpf_map_update_elem(&blacklist, &src_ip, &dummy, BPF_ANY);
	if (veridict)
		return XDP_TX;

	return XDP_PASS;
}

static int parse_ipv4(struct xdp_md *ctx, void *data, uint64_t nh_off, void *data_end)
{
	struct iphdr *iph;
	uint64_t ihl_len;
	int key_ip = 2;

	iph = data + nh_off;
	if (iph + 1 > data_end)
		return 0;

	if (bpf_map_lookup_elem(&blacklist, &iph->saddr))
			return XDP_DROP;

	ihl_len = iph->ihl * 4;

	if (iph->protocol == IPPROTO_TCP)
		return tcp(ctx, data, nh_off + ihl_len, data_end, iph->saddr);

	return XDP_PASS;
}

SEC("sslparser")
int xdp_parse_http(struct xdp_md *ctx)
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
