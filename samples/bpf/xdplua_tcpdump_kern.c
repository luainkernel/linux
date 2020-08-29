/*
 * Copyright (C) 2020 Matheus Rodrigues <matheussr61@gmail.com>
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

SEC("tcpdump")
int tcp_dump_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	int response = XDP_PASS;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct tcphdr *tcp;
	u64 nh_off;
	char myfunc[] = "tcpdump";

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return response;

	ip = data + nh_off;
	if (ip + 1 > data_end)
		return response;

	if (ip->protocol == IPPROTO_TCP) {
		tcp = data + nh_off + ip->ihl * 4;
		if (tcp + 1 > data_end)
			return response;

		bpf_lua_pushinteger(ctx, ip->saddr);
		bpf_lua_pushinteger(ctx, ntohs(tcp->source));
		bpf_lua_pushinteger(ctx, ip->daddr);
		bpf_lua_pushinteger(ctx, ntohs(tcp->dest));
		bpf_lua_pcall(ctx, myfunc, 4, 0);
	}

	return response;
}

char _license[] SEC("license") = "GPL";
