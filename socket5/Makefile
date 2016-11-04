.PHONY:all clean

all:tunnelc

tunnelc:main.o tunnel.o socket5_zproto.o zproto.o zprotowire.o crypt.o sha256.o aes.o
	g++ -std=c++0x -Wall -g -o $@ $^ -lpthread

%.o:%.c
	gcc -Wall -g -c $<

%.o:%.cc
	g++ -std=c++0x -Wall -g -c $<

%.o:%.cpp
	g++ -std=c++0x -Wall -g -c $<


clean:
	-rm *.o
	-rm tunnelc

