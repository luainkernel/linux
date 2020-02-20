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
#include <linux/if_link.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf/libbpf.h"
#include "bpf/bpf.h"

#include "bpf_util.h"

#define MAXFILENAMELEN 256

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

static char *extract_script(const char *path)
{
	FILE *f;
	long script_len;
	size_t read;
	char *script = NULL;

	f = fopen(path, "r");
	if (f == NULL) {
		perror("unable to open lua file");
		return NULL;
	}

	if (fseek(f, 0 , SEEK_END) < 0) {
		perror("unable to reach end of script file");
		goto out;
	}
	script_len = ftell(f);
	if (script_len < 0) {
		perror("error while attempting to get script length");
		goto out;
	}
	rewind(f);

	script = (char *) malloc(script_len + 1);
	if (!script) {
		perror("failed to alloc lua script");
		goto out;
	}
	memset(script, 0, script_len + 1);
	read = fread(script, 1, script_len, f);
	if (read != script_len) {
		perror("unable to read lua file");
		free(script);
		script = NULL;
		goto out;
	}

out:
	fclose(f);
	return script;
}

static int do_attach_ebpf(int idx, int fd, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, fd, XDP_FLAGS_SKB_MODE);
	if (err < 0)
		fprintf(stderr, "ERROR: failed to attach program to %s\n", name);

	return err;
}

static int do_attach_lua(const char *script)
{
	int err;

	err = bpf_set_link_xdp_lua_script(script);
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
	char lua_filename[MAXFILENAMELEN];
	char filename[MAXFILENAMELEN];
	char script[XDP_LUA_MAX_SCRIPT_LEN];
	char ifname[IFNAMSIZ];
	struct bpf_object *obj;
	int opt, prog_fd;
	int rx_cnt_map_fd;
	int ifindex = 0;
	int detach = 0, attach_lua_file = 0, attach_ebpf = 0, monitor = 0,
		attach_lua_script = 0, interval = 1, duration = 1;

	const char *optstr = "f:p:i:dms:I:D:";
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct bpf_map *map;

	memset(lua_filename, 0, MAXFILENAMELEN);
	memset(filename, 0, MAXFILENAMELEN);
	memset(script, 0, XDP_LUA_MAX_SCRIPT_LEN);
	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
			case 'f':
				snprintf(lua_filename, sizeof(lua_filename), "%s", optarg);
				attach_lua_file = 1;
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
				snprintf(ifname, sizeof(ifname), "%s", optarg);
				ifindex = if_nametoindex(optarg);
				break;
			case 'm':
				monitor = 1;
				break;
			case 's':
				snprintf(script, sizeof(script), "%s", optarg);
				attach_lua_script = 1;
				break;
			case 'I':
				interval = atoi(optarg);
				break;
			case 'D':
				duration = atoi(optarg);
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
		if (do_detach(ifindex, ifname) < 0)
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

		if (do_attach_ebpf(ifindex, prog_fd, ifname) < 0)
			return 1;

	}

	if (attach_lua_file) {
		char *extracted_script = extract_script(lua_filename);
		if (!extracted_script)
			return 1;

		if (do_attach_lua(extracted_script) < 0) {
			free(extracted_script);
			return 1;
		}

		free(extracted_script);
	}

	if (attach_lua_script)
		if (do_attach_lua(script) < 0)
			return 1;

	if (monitor) {
		map = bpf_object__find_map_by_name(obj, "rx_cnt");
		rx_cnt_map_fd = bpf_map__fd(map);

		poll(rx_cnt_map_fd, interval, duration);

		if (ifindex && attach_ebpf) {
			if (do_detach(ifindex, ifname) < 0)
				return 1;
		}
	}
	return 0;
}
