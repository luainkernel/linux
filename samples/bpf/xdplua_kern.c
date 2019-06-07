#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	char funcname[] = "test2";

	return bpf_lua_run(ctx, funcname);
}

char _license[] SEC("license") = "GPL";
