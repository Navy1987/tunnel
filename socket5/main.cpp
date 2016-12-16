#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include "aux.h"
#include "socket5.h"
#include "tunnel.h"

struct {
	char lip[64]; //listen ip
	int lport; //listen port
	char sip[64]; //server ip
	int sport; //server port
	char key[256];
	int keylen;
} cfg;

int main(int argc, char *argv[])
{
	int fd;
	int err;
	int enable = 1;
	struct sockaddr addr;
	const char *usage = "USAGE: ./tunnelc <listen ip> <listen port> <server ip> <server port> <crypt key>\n";
	if (argc != 6) {
		printf("%s", usage);
		return 0;
	}
	strcpy(cfg.lip, argv[1]);
	cfg.lport = strtoul(argv[2], NULL, 0);
	strcpy(cfg.sip, argv[3]);
	cfg.sport = strtoul(argv[4], NULL, 0);
	strcpy(cfg.key, argv[5]);
	cfg.keylen = strlen(cfg.key);
	signal(SIGPIPE, SIG_IGN);
	tunnel::init(cfg.sip, cfg.sport, cfg.key);
	aux::tosockaddr(&addr, cfg.lip, cfg.lport);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd > 0);
	aux::nonblock(fd);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	err = bind(fd, &addr, sizeof(addr));
	assert(err >= 0);
	listen(fd, 5);
	for (;;) {
		fd_set rset;
		struct timeval tv;
		FD_SET(fd, &rset);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		select(fd + 1, &rset, NULL, NULL, &tv);
		if (FD_ISSET(fd, &rset)) {
			int s = accept(fd, NULL, NULL);
			if (s > 0)
				socket5_new(s);
		}
		socket5_io();
		usleep(1000);
	}
	return 0;
}

