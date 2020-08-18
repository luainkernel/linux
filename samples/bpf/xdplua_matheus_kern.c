/*
 * Copyright (C) 2019-2020 Victor Nogueira <victor.nogueira@ring-0.io>
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
#include <bpf/bpf_helpers.h>


SEC("xdp_lua_matheus")
int xdp_lua_matheus_prog(struct xdp_md *ctx)
{
	char functionname[] = "icmp";

	bpf_lua_pcall(ctx, functionname, 0, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
