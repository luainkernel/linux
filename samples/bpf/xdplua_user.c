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

static int try_strncpy(char *dest, const char *src, size_t n, const char *fmt) {
	int srclen = strnlen(src, n);

	if (srclen == n) {
		int err = ENAMETOOLONG;
		fprintf(stderr, fmt, strerror(err));
		return -err;
	}

	strncpy(dest, src, n);
	return srclen;
}

static char *extract_script(const char *path, size_t *script_len)
{
	FILE *f;
	size_t read;
	char *script;

	f = fopen(path, "r");
	if (f == NULL) {
		perror("unable to open lua file");
		return NULL;
	}

	if (fseek(f, 0 , SEEK_END) < 0 || (*script_len = (size_t) ftell(f)) < 0)
	{
		perror("error while attempting to get file length");
		goto close;
	}
	rewind(f);

	if (*script_len > XDP_LUA_MAX_SCRIPT_LEN) {
		fprintf(stderr, "lua file can't have more than %d bytes.\n%s\n",
			XDP_LUA_MAX_SCRIPT_LEN, strerror(E2BIG);
	}

	script = (char *) malloc(sizeof(char) * (*script_len));
	if (!script) {
		perror("failed to alloc lua script");
		goto close;
	}

	read = fread(script, sizeof(char), *script_len, f);
	if (read != *script_len) {
		fprintf(stderr, "unable to read file %s\n", path);
		free(script);
		goto close;
	}

	return script;
close:
	fclose(f);
	return NULL;
}

static int do_attach_ebpf(int idx, int fd, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, fd, XDP_FLAGS_SKB_MODE);
	if (err < 0)
		fprintf(stderr, "ERROR: failed to attach program to %s\n", name);

	return err;
}

static int do_attach_lua(const char *script, size_t script_len)
{
	int err;

	err = bpf_set_link_xdp_lua_script(script, script_len);
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

#define strncpy_err(fmt, err) fprintf(stderr, fmt, strerr(-err))

int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char lua_filename[MAXFILENAMELEN];
	char filename[MAXFILENAMELEN];
	char script[XDP_LUA_MAX_SCRIPT_LEN];
	size_t script_len = 0;
	char ifname[IFNAMSIZ];
	struct bpf_object *obj;
	int opt, prog_fd;
	int rx_cnt_map_fd;
	int ifindex = 0;
	int detach = 0, attach_lua_file = 0, attach_ebpf = 0, monitor = 0,
		attach_lua_script = 0, interval = 1, duration = 1;
	int err = 0;

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
				err = try_strncpy(lua_filename, optarg,
							MAXFILENAMELEN, "Invalid lua filename\nerr: %s\n");
				if (err < 0)
					return 1;
				attach_lua_file = 1;
				break;
			case 'p':
				err = try_strncpy(filename, optarg,
						MAXFILENAMELEN, "Invalid bpf prog filename\nerr: %s");
				if (err < 0)
					return 1;
				attach_ebpf = 1;
				break;
			case 'd':
				detach = 1;
				break;
			case 'i':
				script_len = try_strncpy(ifname, optarg, IFNAMSIZ,
								"Invalid interface name\nerr: %s");
				if (script_len < 0)
					return 1;
				ifindex = if_nametoindex(optarg);
				break;
			case 'm':
				monitor = 1;
				break;
			case 's': {
				err = try_strncpy(script, optarg, XDP_LUA_MAX_SCRIPT_LEN,
								"Invalid lua script\nerr: %s");
				if (err < 0)
					return 1;
				attach_lua_script = 1;
				break;
		    }
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
		int ret = 0;
		size_t extracted_script_len;
		char *extracted_script = extract_script(lua_filename,
									&extracted_script_len);
		if (!extracted_script)
			return 1;

		if (do_attach_lua(extracted_script, extracted_script_len) < 0)
			ret = 1;

		free(extracted_script);
		return ret;
	}

	if (attach_lua_script)
		if (do_attach_lua(script, script_len) < 0)
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
