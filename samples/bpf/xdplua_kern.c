#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") test_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.key_size	= sizeof(int),
	.value_size	= sizeof(int),
	.max_entries	= 20,
};

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	char lookupname[] = "lookup";
	char updatename[] = "update";

	bpf_set_lua_state(ctx);
	bpf_lua_pushmap(ctx, &test_map);
	bpf_lua_pcall(ctx, updatename, 1, 0);

	bpf_lua_pushmap(ctx, &test_map);
	bpf_lua_pcall(ctx, lookupname, 1, 0);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
