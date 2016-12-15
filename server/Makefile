.PHONY:all

all: tunneld lz4.so

tunneld:
	make -C silly/ TARGET=../tunneld linux

lz4.so: lualib-lz4.c ../lib/lz4.c
	gcc -g -Wall -Isilly/lua/ -I../lib/ --share -fPIC -o $@ $^


