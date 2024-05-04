# Generate simple shell commands like run, run debug, run gdb
# This makefile should not be able to actually create an executable at all (hopefully)

.PHONY: all run debug gdb

all: run

run: 
	make -C build
	./build/FullCrypto

debug: 
	make -C build
	valgrind -s --leak-check=yes ./build/FullCrypto

gdb: 
	make -C build
	gdb ./build/FullCrypto