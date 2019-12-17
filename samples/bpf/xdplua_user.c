#include <linux/if_link.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include "bpf/libbpf.h"
#include "libbpf.h"

#include "bpf_util.h"

static int ifindex = 0;

static void usage(const char *prog) {
	fprintf(stderr, "usage: %s [OPTS]\n"
		"\nOPTS:\n"
		"    -d    detach program\n"
		"    -s    lua script path\n"
		"    -p    eBPF program path\n"
		"    -i    iface\n"
		"    -m    monitor\n",
		prog);
}

static char *extract_lua_prog(const char *path)
{
	FILE *f;
	long prog_size;
	char *lua_prog;

	f = fopen(path, "r");
	if (f == NULL) {
		perror("unable to xopen lua file");
		return NULL;
	}

	fseek(f, 0 , SEEK_END);
	prog_size = ftell(f);
	rewind(f);

	lua_prog = (char *) malloc(prog_size + 1);
	memset(lua_prog, 0, prog_size + 1);
	if (fread(lua_prog, 1, prog_size, f) < 0) {
		perror("unable to read lua file");
		return NULL;
	}

	lua_prog[prog_size] = '\0';
	fclose(f);
	return lua_prog;
}

static int do_attach_ebpf(int idx, int fd, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, fd, XDP_FLAGS_SKB_MODE);
	if (err < 0)
		fprintf(stderr, "ERROR: failed to attach program to %s\n", name);

	return err;
}

static int do_attach_lua(const char *name, char *lua_prog)
{
	int err;

	err = bpf_set_link_xdp_lua_prog(lua_prog);
	if (err < 0)
		fprintf(stderr, "ERROR: failed to attach lua script to %s\n", name);

	return err;
}

static int do_detach(int idx, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, -1, XDP_FLAGS_SKB_MODE);
	if (err < 0)
		fprintf(stderr, "ERROR: failed to detach program from %s\n", name);

	return err;
}

static void poll(int map_fd, int interval) {
	long cnt;
	unsigned int key = 0;

	while(1) {
		bpf_map_lookup_elem(map_fd, &key, &cnt);
		printf("pkt count: %lu\n", cnt);
		sleep(interval);
	}
}

int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char lua_filename[256];
	char filename[256];
	struct bpf_object *obj;
	int opt, prog_fd;
	int rx_cnt_map_fd;
	int detach = 0, attach_lua = 0, attach_ebpf = 0, monitor = 0;
	char *lua_prog = NULL;
	const char *optstr = "s:p:i:dm";
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};

	memset(lua_filename, 0, 256);
	memset(filename, 0, 256);
	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
			case 's':
				snprintf(lua_filename, sizeof(lua_filename),
						"%s", optarg);
				attach_lua = 1;
				break;
			case 'p':
				snprintf(filename, sizeof(filename),
						"%s", optarg);
				attach_ebpf = 1;
				break;
			case 'd':
				detach = 1;
				break;
			case 'i':
				ifindex = if_nametoindex(optarg);
				break;
			case 'm':
				monitor = 1;
				break;
			default:
				usage(basename(argv[0]));
				return 1;
		}
	}

	if (attach_ebpf || detach) {
		if (!ifindex) {
			printf("ERROR: invalid interface name");
			return 1;
		}
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("ERROR: setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	if (detach) {
		if (do_detach(ifindex, lua_filename) < 0)
			return 1;

		return 0;
	}

	if (attach_ebpf) {
		prog_load_attr.file = filename;

		if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
			return 1;

		if (!prog_fd) {
			printf("ERROR: failed to load_bpf_file\n");
			return 1;
		}

		if (do_attach_ebpf(ifindex, prog_fd, lua_filename) < 0)
			return 1;

	}

	if (attach_lua) {
		lua_prog = extract_lua_prog(lua_filename);
		if (!lua_prog)
			return 1;

		if (do_attach_lua(lua_filename, lua_prog) < 0) {
			free(lua_prog);
			return 1;
		}

		free(lua_prog);
	}

	if (monitor) {
		rx_cnt_map_fd = bpf_object__find_map_fd_by_name(obj, "rx_cnt");

		poll(rx_cnt_map_fd, 1);
	}
	return 0;
}
