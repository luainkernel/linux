#include <linux/if_link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <getopt.h>

#include "bpf/libbpf.h"

struct match {
	unsigned int saddr;
	bool has_saddr;
	unsigned int daddr;
	bool has_daddr;
	unsigned int sport;
	bool has_sport;
	unsigned int dport;
	bool has_dport;
	unsigned int if_index;
	unsigned int proto;
	bool has_proto;
};

enum subtype { source, dest};
struct sub {
	unsigned int saddr;
	bool has_saddr;
	unsigned int daddr;
	bool has_daddr;
	unsigned int sport;
	bool has_sport;
	unsigned int dport;
	bool has_dport;
};

static int do_attach_prog(int idx, char *lua_prog)
{
	int err = 0;

	err = bpf_set_link_xdp_lua_prog(idx, lua_prog);
	if (err < 0)
		printf("ERROR: failed to attach lua script\n");

	return err;
}

#define fillsub(ip, port)				\
	if (postcolon) {				\
		s->ip = inet_network(precolon);		\
		s->has_##ip = true;			\
		s->port = atoi(postcolon);		\
		s->has_##port = true;			\
	} else {					\
		if (sub_str[0] == ':') {		\
			s->port = atoi(precolon);	\
			s->has_##port = true;     	\
		} else {				\
			s->ip = inet_network(precolon); \
			s->has_##ip = true;		\
		}					\
	}

static void parse_sub(char *sub_str, struct sub *s, enum subtype stype) {
	char *precolon;
	char *postcolon;

	precolon = strtok(sub_str, ":");
	postcolon = strtok(NULL, ":");

	switch (stype) {
		case source:
			fillsub(saddr, sport);
			break;
		case dest:
			fillsub(daddr, dport);
			break;
	}
}

#define copyoptpar(table, dst, optpar, has_par)				\
	if (has_par) {							\
		sprintf(dst, "entry."#table"."#dst" = %u\n", optpar);	\
		strcat(script, dst);					\
	}

static int send_script(struct match m, struct sub s) {
	char saddr[32];
	char daddr[32];
	char sport[32];
	char dport[32];
	char proto[32];
	char ifindex[32];
	char script[8192];

	strcpy(script, "local entry = {}\nentry.match = {}\nentry.sub = {}\n");
	copyoptpar(match, saddr, m.saddr, m.has_saddr);
	copyoptpar(match, daddr, m.daddr, m.has_daddr);
	copyoptpar(match, sport, m.sport, m.has_sport);
	copyoptpar(match, dport, m.dport, m.has_dport);
	copyoptpar(match, proto, m.proto, m.has_proto);
	copyoptpar(match, ifindex, m.if_index, true);

	copyoptpar(sub, saddr, s.saddr, s.has_saddr);
	copyoptpar(sub, daddr, s.daddr, s.has_daddr);
	copyoptpar(sub, sport, s.sport, s.has_sport);
	copyoptpar(sub, dport, s.dport, s.has_dport);
	strcat(script, "xdp.addtotable(entry)");
	do_attach_prog(m.if_index, script);
	return 1;
}

int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	const char *optstr = "i:s:d:S:D:p:";
	int opt;
	int opt_dummy;
	int opt_arg;
	struct match m;
	struct sub s;
	struct in_addr saddr;
	struct in_addr daddr;
	struct option longopts[] = {
		{ "to-source", required_argument, &opt_arg, 0 },
		{ "to-destination", required_argument, &opt_arg, 1 },
		{ "source", required_argument, NULL, 's' },
		{ "destination", required_argument, NULL, 'd' },
		{ "dport", required_argument, NULL, 'D' },
		{ "sport", required_argument, NULL, 'S' },
		{ "protocol", required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 }
	};

	memset(&m, 0, sizeof(struct match));
	memset(&s, 0, sizeof(struct sub));
	while ((opt = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
		switch (opt) {
			case 's':
				m.saddr = inet_network(optarg);
				m.has_saddr = true;
				break;
			case 'd':
				m.daddr = inet_network(optarg);
				m.has_daddr = true;
				break;
			case 'S':
				m.sport = atoi(optarg);
				m.has_sport = true;
				break;
			case 'D':
				m.dport = atoi(optarg);
				m.has_dport = true;
				break;
			case 'p':
				if (!strcmp(optarg, "udp")){
					m.proto = 17;
				} else if (!strcmp(optarg, "tcp")) {
					m.proto = 6;
				} else {
					printf("ERROR: protocol not supported\n");
					return 1;
				}
				m.has_proto = true;
				break;
			case 0:
				switch (opt_arg) {
					case 0:
						parse_sub(optarg, &s, source);
						break;
					case 1:
						parse_sub(optarg, &s, dest);
						break;
				}
				break;
			default:
				return 1;
		}
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	if (optind == argc) {
		printf("ERROR: interface name not specified\n");
		return 1;
	}

	m.if_index = if_nametoindex(argv[optind]);
	if (!m.if_index) {
		perror("if_nametoindex");
		return 1;
	}

	send_script(m, s);
	return 0;
}
