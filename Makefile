CLANG=clang-13

default: test

fmt:
	cargo fmt

test: functions examples
	cargo test -- --nocapture

empty:
	cargo run -- \
		-o tmp/out.exe \
		build/clang-glibc/empty_main.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/crt1.o
	exec tmp/out.exe

gcc:
	cargo run -- \
		-o tmp/out.exe \
		build/clang-glibc/print_main.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/crt1.o 
	exec tmp/out.exe


sdl:
	cargo run -- \
		-o tmp/out.exe \
		build/clang-glibc/sdltest.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/libSDL2.so \
		/usr/lib/x86_64-linux-gnu/crt1.o
	@echo RUN
	exec tmp/out.exe ./testfiles/grumpy-cat.bmp

musl:
	cargo run -- \
		--interp /usr/lib/ld-musl-x86_64.so.1 \
		-o tmp/out.exe \
		build/clang-musl/empty_main.o \
		/usr/lib/x86_64-linux-musl/libc.so \
		/usr/lib/x86_64-linux-musl/crt1.o \
		/usr/lib/x86_64-linux-musl/crti.o \
		/usr/lib/x86_64-linux-musl/crtn.o
	exec tmp/out.exe

examples: gcc empty musl

dump:
	readelf -aW tmp/out.exe
	#objdump -d -j .plt tmp/out.exe
	objdump -s -j .got -j .got.plt tmp/out.exe
	#objdump -s -j .got -j .got.plt -j .rodata -j .data tmp/out.exe
	#objdump -d tmp/out.exe
	#objdump -R tmp/out.exe
	objdump -d -j .plt -j .plt.got tmp/out.exe
	objdump -d -j .text tmp/out.exe

x:
	$(CLANG) -v -mno-relax -fPIE -v -pie -Wl,--no-relax link/testfiles/empty_main.c -o tmp/x.exe
	readelf -aW tmp/x.exe
	objdump -d -j .plt -j .plt.got tmp/x.exe
	objdump -d -j .text tmp/x.exe
	exec tmp/x.exe

read: gcc
	cargo run --example read -- tmp/out.exe
	#readelf -aW tmp/out.exe
	#objdump -d -j .plt tmp/out.exe
	#objdump -s -j .got -j .got.plt tmp/out.exe

static: #functions
	RUST_LOG=debug cargo run --example write
	readelf -aW tmp/static.exe
	objdump -D tmp/static.exe
	readelf -sW tmp/static.exe
	#objdump -t tmp/static.exe
	exec tmp/static.exe

dynamic: #functions
	RUST_LOG=debug cargo run --example write_dynamic

read2:
	elfcat tmp/out.exe
	RUST_LOG=debug cargo run --example read tmp/out.exe


all: build functions test doc

build:
	cargo build

doc:
	cargo doc --all --no-deps

deps:
	cargo modules generate graph --package link --lib --orphans | dot -Tpng > link.png && open link.png
	cargo depgraph --build-deps --workspace-only | dot -Tpng > crates.png && open crates.png

CFLAGS=-fPIC -fno-direct-access-external-data ${NIX_CFLAGS_COMPILE}
CFLAGS_MUSL=-I/usr/include/x86_64-linux-musl ${CFLAGS}

functions2:
	zig build
	$(CLANG) ${CFLAGS} -c testfiles/empty_main.c -o ./build/clang-glibc/empty_main.o

functions:
	mkdir -p build/clang-glibc build/clang-musl build/gcc-glibc build/testlibs
	cp $(shell python3 scripts/findlib.py libz.so) build/testlibs
	$(CLANG) ${CFLAGS} -c testfiles/testfunction.c -o ./build/clang-glibc/testfunction.o
	$(CLANG) ${CFLAGS} -c testfiles/simplefunction.c -o ./build/clang-glibc/simplefunction.o
	$(CLANG) ${CFLAGS} -c testfiles/asdf.c -o ./build/clang-glibc/asdf.o
	$(CLANG) ${CFLAGS} -c testfiles/segfault.c -o ./build/clang-glibc/segfault.o
	$(CLANG) ${CFLAGS} -c testfiles/link_shared.c -o ./build/clang-glibc/link_shared.o
	$(CLANG) ${CFLAGS} -c testfiles/live.c -o ./build/clang-glibc/live.o
	$(CLANG) ${CFLAGS} -c testfiles/empty_main.c -o ./build/clang-glibc/empty_main.o
	$(CLANG) ${CFLAGS} -c testfiles/print_main.c -o ./build/clang-glibc/print_main.o
	$(CLANG) ${CFLAGS} -c testfiles/sdltest.c -o ./build/clang-glibc/sdltest.o

	$(CLANG) ${CFLAGS_MUSL} -v -c testfiles/empty_main.c -o ./build/clang-musl/empty_main.o
	$(CLANG) ${CFLAGS_MUSL} -v -c testfiles/print_main.c -o ./build/clang-musl/print_main.o

	gcc -fPIC -c testfiles/sdltest.c -o ./build/gcc-glibc/sdltest.o
	gcc -fPIC -c testfiles/empty_main.c -o ./build/gcc-glibc/empty_main.o
	gcc -fPIC testfiles/empty_main.c -o ./build/gcc-glibc/empty_main

	$(CLANG) ${CFLAGS} -g testfiles/empty_main.c -o ./build/clang-glibc/empty_main
	$(CLANG) ${CFLAGS} -v -fpie testfiles/empty_main.c -o ./build/clang-glibc/empty_main

	$(CLANG) ${CFLAGS} -c testfiles/uvtest.c -o ./build/clang-glibc/uvtest.o
	$(CLANG) ${CFLAGS} -c testfiles/globals.c -o ./build/clang-glibc/globals.o
	$(CLANG) ${CFLAGS} -c testfiles/call_extern.c -o ./build/clang-glibc/call_extern.o
	$(CLANG) ${CFLAGS} -c testfiles/print_stuff.c -o ./build/clang-glibc/print_stuff.o
	$(CLANG) ${CFLAGS} -c testfiles/print_string.c -o ./build/clang-glibc/print_string.o
	$(CLANG) ${CFLAGS} -g testfiles/segfault_handle.c -o ./build/clang-glibc/segfault_handle
	$(CLANG) ${CFLAGS} -g testfiles/segfault_handle2.c -o ./build/clang-glibc/segfault_handle2

	#ar -rv tmp/liblive.a ./tmp/live.o ./tmp/globals.o
	#$(CLANG) -fPIC -shared ./tmp/liblive.a -o ./tmp/live.so
	#$(CLANG) -shared -fpic -Wl,--no-undefined testfiles/live.c -o ./build/clang-glibc/live.so

	#$(CLANG) ${CFLAGS} -c -nostdlib testfiles/start.c -o ./tmp/start.o
	#$(CLANG) -nostdlib testfiles/globals.c testfiles/start.c -o ./tmp/start
	$(CLANG) ${CFLAGS} -shared testfiles/live.c -o ./build/clang-glibc/live.so
	$(CLANG) ${CFLAGS} -nostdlib -shared testfiles/globals.c -o ./build/clang-glibc/globals.so

	$(CLANG) ${CFLAGS} -g testfiles/invoke_print.c -o ./build/clang-glibc/invoke_print

