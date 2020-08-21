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
#include <linux/icmp.h>
#include <linux/inet.h>

SEC("matheus")
int xdplua_matheus(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int rc = XDP_PASS;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	char myfunc[] = "icmp";
	u16 h_proto;
	u16 port;
	u32 srcip;
	u64 nh_off;
	u64 ip_off;
	u16 seq;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;
	if (h_proto != htons(ETH_P_IP))
		return rc;

	ip = data + nh_off;
	if (ip + 1 > data_end)
		return -1;
	
	tcp = data + nh_off + ip->ihl;
	if (tcp + 1 > data_end)
		return -1;

	if (ip->protocol == IPPROTO_TCP) {
		bpf_lua_pushinteger(ctx, ip->saddr);
		bpf_lua_pushinteger(ctx, ntohs(tcp->source));
		bpf_lua_pcall(ctx, myfunc, 2, 0);
	}
	return rc;
}

char _license[] SEC("license") = "GPL";
