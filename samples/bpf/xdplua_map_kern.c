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

struct bpf_map_def SEC("maps") lua_test_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.key_size	= sizeof(int),
	.value_size	= sizeof(int),
	.max_entries	= 20,
};

SEC("xdp_lua_test_map")
int xdp_lua_test_map_prog(struct xdp_md *ctx)
{
	char lookupname[] = "lookup";
	char updatename[] = "update";

	bpf_lua_setstate(ctx);
	bpf_lua_pushmap(ctx, &lua_test_map);
	bpf_lua_pcall(ctx, updatename, 1, 0);

	bpf_lua_pushmap(ctx, &lua_test_map);
	bpf_lua_pcall(ctx, lookupname, 1, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
