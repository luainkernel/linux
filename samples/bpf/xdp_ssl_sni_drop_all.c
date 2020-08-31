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
#include "bpf_endian.h"

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
