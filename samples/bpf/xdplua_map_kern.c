/*
 * Copyright (C) 2019-2021 Victor Nogueira <victor.nogueira@ring-0.io>
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
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") rx_cnt = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size	= sizeof(int),
	.value_size	= sizeof(int),
	.max_entries	= 1,
};

SEC("xdp_lua_rx_cnt")
int xdp_lua_rx_cnt_prog(struct xdp_md *ctx)
{
	char updatename[] = "update";

	bpf_lua_pushmap(&rx_cnt);
	bpf_lua_pcall(updatename, 1, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
