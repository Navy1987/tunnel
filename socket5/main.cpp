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

static void *
thread_socket(void *arg)
{
	struct tunnel T = {};
	tunnel_init(&T, (intptr_t)arg, &cfg);
	for (;;) {
		int err = tunnel_process(&T);
		if (err < 0)
			return NULL;
	}
	return NULL;
}

static void
thread_create(pthread_t *tid, void *(*start)(void *), void *arg)
{
	int err;
	err = pthread_create(tid, NULL, start, arg);
	if (err < 0) {
		fprintf(stderr, "thread create fail:%d\n", err);
		exit(-1);
	}
	return ;
}

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
	signal(SIGPIPE, SIG_IGN);
	tosockaddr(&addr, cfg.lip, cfg.lport);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd > 0);
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
	err = bind(fd, &addr, sizeof(addr));
	assert(err >= 0);
	listen(fd, 5);
	for (;;) {
		pthread_t pid;
		int s = accept(fd, NULL, NULL);
		printf("---------------accept:%d\n", s);
		if (s < 0)
			continue;
		thread_create(&pid, thread_socket, (void *)(intptr_t)s);
	}
	return 0;
}

