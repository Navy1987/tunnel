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
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>
#include "tunnel.h"

struct tunnel_config cfg;

int main(int argc, char *argv[])
{
	int fd;
	int err;
	int enable = 1;
	struct sockaddr addr;
	struct tunnel *root = NULL;
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
	signal(SIGPIPE, SIG_IGN);
	tosockaddr(&addr, cfg.lip, cfg.lport);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd > 0);
	nonblock(fd);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	err = bind(fd, &addr, sizeof(addr));
	assert(err >= 0);
	listen(fd, 5);
	for (;;) {
		fd_set rset;
		struct timeval tv;
		struct tunnel *t;
		FD_SET(fd, &rset);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		select(fd + 1, &rset, NULL, NULL, &tv);
		if (FD_ISSET(fd, &rset)) {
			int s = accept(fd, NULL, NULL);
			if (s > 0) {
				struct tunnel *t = tunnel_create(s, &cfg);
				tunnel_append(t, &root);
			}
		}
		t = root;
		while (t != NULL) {
			int err;
			struct tunnel *tmp = t;
			t = t->next;
			err = tunnel_io(tmp);
			if (err < 0) {
				tunnel_free(tmp, &root);
				continue;
			}
			err = tunnel_do(tmp);
			if (err < 0)
				tunnel_free(tmp, &root);
		}
		usleep(1000);
	}
	return 0;
}

