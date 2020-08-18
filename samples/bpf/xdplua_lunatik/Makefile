# Copyright (c) 2020 Matheus Rodrigues <matheussr61@gmail.com>
# Copyright (C) 2017-2019  CUJO LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

CC = gcc

KPATH = /lib/modules/$(shell uname -r)/source

CFLAGS = -fPIC -Wall -O2 -g -Wno-unused-variable -D_UNUSED \
		-I/usr/include/lua5.3/\
		-Wmissing-prototypes \
		-Wstrict-prototypes \
		-DHAVE_ATTR_TEST=0 \
		-I $(KPATH)/tools/lib \
		-I $(KPATH)/tools/perf \
		-I $(KPATH)/tools/include \
		-I $(KPATH)/tools/testing/selftests/bpf \
		-I $(KPATH)/samples/bpf		

LDFLAGS = -shared -llua5.3 -lelf -lz -L$(KPATH)/tools/lib/bpf -lbpf

RM = rm -f

LIBS = xdplua.so
OBJS = $(patsubst %.c,%.o,$(wildcard *.c))
DEPS = $(OBJS:.o=.d)

.PHONY: all
all: $(LIBS)

%.so:
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

-include $(DEPS)

.PHONY: clean
clean:
	$(RM) $(LIBS) $(OBJS) $(DEPS)

$(LIBS): $(OBJS)