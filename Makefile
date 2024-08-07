CLANG=clang-13

default: test

fmt:
	cargo fmt
	clang-format -i testfiles/*.c
	python3 -m black *.py

test: functions examples unittests testsuites

unittests:
	cargo test -- --nocapture

empty_dynamic:
	cargo run --bin link -- --dynamic -v \
		build/clang-glibc/empty_main.o \
		/usr/lib/x86_64-linux-gnu/crt1.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6

empty_dynamic_debug:
	exec rust-gdb --args ./target/debug/link --dynamic -v \
		build/clang-glibc/empty_main.o \
		/usr/lib/x86_64-linux-gnu/crt1.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6

empty:
	cargo run --bin link -- -v --link \
		-o tmp/empty.exe \
		build/clang-glibc/empty_main.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/crt1.o
	objdump -d --full-contents --section=.text tmp/empty.exe
	#readelf -aW tmp/empty.exe
	readelf -tW tmp/empty.exe
	objdump -d --full-contents --section=.plt.got --section=.plt --section=.got --section=.got.plt tmp/empty.exe
	exec tmp/empty.exe

empty_ref:
	${CLANG} \
		-o build/clang-glibc/empty \
		build/clang-glibc/empty_main.o
	#readelf -sW build/clang-glibc/empty
	objdump -d --full-contents --section=.text build/clang-glibc/empty
	readelf -tW build/clang-glibc/empty
	objdump -d --full-contents --section=.plt.got --section=.plt --section=.got --section=.got.plt build/clang-glibc/empty
	exec build/clang-glibc/empty

gcc_dynamic:
	cargo run --bin link -- --dynamic -v \
		build/clang-glibc/print_main1.o \
		build/clang-glibc/asdf1.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6

gcc_dynamic_debug:
	exec rust-gdb --args ./target/debug/link --dynamic -v \
		build/clang-glibc/print_main1.o \
		build/clang-glibc/asdf1.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6

gcc_ref:
	${CLANG} \
		-o build/clang-glibc/print_main1 \
		build/clang-glibc/print_main1.o \
		build/clang-glibc/asdf1.o
	readelf -srW build/clang-glibc/print_main1
	objdump -d --full-contents --section=.plt.got --section=.plt --section=.got --section=.got.plt build/clang-glibc/print_main1

	exec build/clang-glibc/print_main1

gcc:
	cargo run --bin link -- -v --link \
		-o tmp/gcc.exe \
		build/clang-glibc/print_main1.o \
		build/clang-glibc/asdf1.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/crt1.o 
	readelf -srW tmp/gcc.exe
	objdump -d --full-contents --section=.plt.got --section=.plt --section=.got --section=.got.plt tmp/gcc.exe
	exec tmp/gcc.exe

gcc2:
	cargo run --bin link -- -v --link \
		-o tmp/gcc2.exe \
		build/clang-glibc/print_main2.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/crt1.o 
	readelf -srW tmp/gcc2.exe
	objdump -d --full-contents --section=.plt.got --section=.plt --section=.got --section=.got.plt tmp/gcc2.exe
	exec tmp/gcc2.exe

gcc2_dynamic:
	cargo run --bin link -- --dynamic -v \
		build/clang-glibc/print_main2.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6

gcc2_dynamic_debug:
	exec rust-gdb --args ./target/debug/link --dynamic -v \
		build/clang-glibc/print_main2.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6

gcc2_ref:
	${CLANG} \
		-o build/clang-glibc/print_main2 \
		build/clang-glibc/print_main2.o 
	readelf -aW build/clang-glibc/print_main2
	objdump -d --full-contents --section=.text --section=.data --section=.rodata build/clang-glibc/print_main2
	objdump -d --full-contents --section=.plt.got --section=.plt --section=.got --section=.got.plt build/clang-glibc/print_main2
	exec build/clang-glibc/print_main2

link_shared:
	cargo run --bin link -- -v --link \
		-o tmp/link_shared.exe \
		build/clang-glibc/link_shared.o \
		build/clang-glibc/print_main1.o \
		build/clang-glibc/asdf1.o \
		build/testlibs/libz.so \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/crt1.o 
	readelf -srW tmp/link_shared.exe
	objdump -d --full-contents --section=.plt.got --section=.plt --section=.got --section=.got.plt tmp/link_shared.exe
	exec tmp/link_shared.exe


dup:
	cargo run --bin link -- -v --link \
		-o tmp/dup.exe \
		build/clang-glibc/print_main1.o \
		build/clang-glibc/asdf1.o \
		build/clang-glibc/asdf2.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/crt1.o 
	readelf -aW tmp/dup.exe
	exec tmp/dup.exe

sdl:
	cargo run --bin link -- -v --link \
		-o tmp/sdl.exe \
		build/clang-glibc/sdltest.o \
		/usr/lib/x86_64-linux-gnu/libc.so.6 \
		/usr/lib/x86_64-linux-gnu/libSDL2.so \
		/usr/lib/x86_64-linux-gnu/crt1.o
	@echo RUN
	exec tmp/sdl.exe ./testfiles/grumpy-cat.bmp

musl:
	cargo run --bin link -- -v --link \
		--interp /usr/lib/ld-musl-x86_64.so.1 \
		-o tmp/musl.exe \
		build/clang-musl/empty_main.o \
		/usr/lib/x86_64-linux-musl/libc.so \
		build/clang-glibc/print_string.o \
		/usr/lib/x86_64-linux-musl/crt1.o \
		/usr/lib/x86_64-linux-musl/crti.o \
		/usr/lib/x86_64-linux-musl/crtn.o
	exec tmp/musl.exe

examples: gcc empty musl dup link_shared empty_dynamic gcc2_dynamic gcc_dynamic

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
	cargo run --bin read -- tmp/gcc.exe
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

CFLAGS=-fPIC -fno-lto -fno-direct-access-external-data
CFLAGS_MUSL=-I/usr/include/x86_64-linux-musl ${CFLAGS}

functions: ninja.build
	mkdir -p build/clang-glibc build/clang-musl build/gcc-glibc build/testlibs
	cp $(shell python3 scripts/findlib.py libz.so) build/testlibs
	gcc -fPIC testfiles/empty_main.c -o ./build/gcc-glibc/empty_main
	$(CLANG) ${CFLAGS} -g testfiles/empty_main.c -o ./build/clang-glibc/empty_main
	$(CLANG) ${CFLAGS} -v -fpie testfiles/empty_main.c -o ./build/clang-glibc/empty_main
	$(CLANG) ${CFLAGS} -g testfiles/segfault_handle.c -o ./build/clang-glibc/segfault_handle
	$(CLANG) ${CFLAGS} -g testfiles/segfault_handle2.c -o ./build/clang-glibc/segfault_handle2
	$(CLANG) ${CFLAGS} -c -nostdlib testfiles/start.c -o ./build/clang-glibc/start.o
	#$(CLANG) -nostdlib testfiles/globals.c testfiles/start.c -o ./tmp/start
	$(CLANG) ${CFLAGS} -shared testfiles/live.c -o ./build/clang-glibc/live.so
	$(CLANG) ${CFLAGS} -nostdlib -shared testfiles/globals.c -o ./build/clang-glibc/globals.so
	$(CLANG) ${CFLAGS} -g testfiles/invoke_print.c -o ./build/clang-glibc/invoke_print
	ninja -v testfiles

clean:
	rm -rf build/c-testsuite build/clang-glibc build/clang-musl


ninja.build: build.py
	python3 build.py tests/c-testsuite/tests/single-exec

testsuites: ninja.build
	ninja -v testsuite-clang-glibc

