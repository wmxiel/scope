CC ?= cc
LD ?= ld
OBJCOPY ?= objcopy
CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-pie -fno-stack-protector -fno-builtin -mno-red-zone -mgeneral-regs-only

.PHONY: all check clean

all: build/disk

build:
	mkdir -p build

build/boot.o: boot.S | build
	$(CC) -c -m64 -fno-pie $< -o $@

build/guest.o: guest.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/guest: build/boot.o build/guest.o layout.ld
	$(LD) -T layout.ld build/boot.o build/guest.o -o $@

build/disk: build/guest
	$(OBJCOPY) -O binary $< $@
	python3 -c 'from pathlib import Path; p = Path("$@"); b = p.read_bytes(); assert len(b) <= 61440; p.write_bytes(b.ljust(61952, b"\0"))'

check: build/disk
	python3 verify.py ../_build/default/bin/main.exe build/disk

clean:
	rm -rf build
