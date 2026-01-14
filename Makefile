# SPDX-License-Identifier: GPL-2.0
# SPDX-FileCopyrightText: Copyright (C) 2026 Edera, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see
# <https://www.gnu.org/licenses/>.

all: vmpressured

BPF_HEADERS = vmlinux.h

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

BPF_OBJS = vmpressure.bpf.o

$(BPF_OBJS): $(BPF_HEADERS)

%.bpf.o: %.bpf.c
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

ALL_HEADERS += $(BPF_HEADERS)
ALL_OBJS += $(BPF_OBJS)

VM_HEADERS = vmpressure.skel.h
VM_OBJS = vmpressured.o vmpressured-observer.o
ALL_HEADERS += $(VM_HEADERS)
ALL_OBJS += $(VM_OBJS)

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

$(VM_OBJS): $(VM_HEADERS)

BPF_CFLAGS = $(shell pkg-config libbpf --cflags)
BPF_LIBS = $(shell pkg-config libbpf --libs)
CPPFLAGS += $(BPF_CFLAGS)

ELF_CFLAGS = $(shell pkg-config libelf --cflags)
ELF_LIBS = $(shell pkg-config libelf --libs)
CPPFLAGS += $(ELF_CFLAGS)

ZLIB_CFLAGS = $(shell pkg-config zlib --cflags)
ZLIB_LIBS = $(shell pkg-config zlib --libs)
CPPFLAGS += $(ZLIB_CFLAGS)

CFLAGS ?= -O2 -Wall -g -std=gnu2x

%.o: %.c
	gcc $(CPPFLAGS) $(CFLAGS) -c $< -o $@

VM_LIBS += $(BPF_LIBS)
VM_LIBS += $(ELF_LIBS)
VM_LIBS += $(ZLIB_LIBS)

vmpressured: $(BPF_OBJS) $(VM_OBJS)
	gcc -o $@ $(VM_OBJS) $(VM_LIBS) $(LDFLAGS)

clean:
	rm -f $(ALL_HEADERS) $(ALL_OBJS) vmpressured
