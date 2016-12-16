.PHONY:all

all: tunneld lz4.so

tunneld:
	make -C silly/ TARGET=../tunneld macosx

lz4.so: lualib-lz4.c ../lib/lz4.c
	gcc -g -Wall -Isilly/lua/ -I../lib/ -dynamiclib -fPIC -Wl,-undefined,dynamic_lookup -o $@ $^


