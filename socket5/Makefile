.PHONY:all clean

all:tunnelc

tunnelc:main.o tunnel.o buffer.o socket5.o aux.o socket5_zproto.o zproto.o zprotowire.o crypt.o sha256.o aes.o ../lib/lz4.c
	g++ -std=c++0x -I../lib/ -Wall -g -o $@ $^ -lpthread

%.o:%.c
	gcc -Wall -g -c $<

%.o:%.cc
	g++ -std=c++0x -Wall -g -c $<

%.o:%.cpp
	g++ -std=c++0x -I../lib/ -Wall -g -c $<


clean:
	-rm *.o
	-rm tunnelc

