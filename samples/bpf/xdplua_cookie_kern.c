/*
 * Copyright (C) 2020 ring-0 Ltda
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <asm/byteorder.h>
#include <bpf/bpf_helpers.h>

#define HTTPDSTPORT     80

static int parse_tcp(struct xdp_md *ctx, void *data, uint64_t tp_off,
		void *data_end, __be32 saddr) {

	struct tcphdr *tcp = data + tp_off;
	char cookiefunc[] = "checkcookie";
	int data_ref;

	if (tcp + 1 > data_end)
		return XDP_PASS;

	if (tcp->dest == htons(HTTPDSTPORT)) {
		bool verdict;
		data_ref = bpf_lua_dataref(ctx, tp_off + tcp->doff * 4);
		if (data_ref < 0)
			return XDP_PASS;

		bpf_lua_pushinteger(ctx, saddr);

		bpf_lua_pcall(ctx, cookiefunc, 2, 1);

		verdict = bpf_lua_toboolean(ctx, -1);

		return verdict ? XDP_PASS : XDP_DROP;
	}

	return XDP_PASS;
}

static inline u64 parse_ipv4(struct xdp_md *ctx, void *data, u64 nh_off, void *data_end, __be32 *saddr)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return -1;

	nh_off += iph->ihl * 4;

	*saddr = iph->saddr;

	return nh_off;
}

SEC("xdplua_cookie")
int xdp_lua_cookie_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int rc = XDP_PASS;
	struct ethhdr *eth = data;
	u16 h_proto;
	u64 nh_off;
	u64 ip_off;
	u_int8_t protonum;
	int verdict;
	__be32 saddr;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP))
		return rc;

	ip_off = parse_ipv4(ctx, data, nh_off, data_end, &saddr);
	if (ip_off == -1)
		return rc;

	return parse_tcp(ctx, data, ip_off, data_end, saddr);
}

char _license[] SEC("license") = "GPL";
