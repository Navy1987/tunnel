#ifndef	_AUX_H
#define	_AUX_H

#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define	tou8(n)		(*((uint8_t *)(n)))
#define	tou16(n)	(*((uint16_t *)(n)))
#define	tou32(n)	(*((uint32_t *)(n)))

namespace aux {

static void inline
nonblock(int fd)
{
	int err;
	int flag;
	flag = fcntl(fd, F_GETFL, 0);
	if (flag < 0) {
		perror("nonblock F_GETFL");
		return ;
	}
	flag |= O_NONBLOCK;
	err = fcntl(fd, F_SETFL, flag);
	if (err < 0) {
		perror("nonblock F_SETFL");
		return ;
	}
	return ;
}

static void inline
tosockaddr(struct sockaddr *addr, const char *ip, int port)
{
	struct sockaddr_in *in = (struct sockaddr_in *)addr;
	bzero(addr, sizeof(*addr));
	in->sin_family = AF_INET;
	in->sin_port = htons(port);
	inet_pton(AF_INET, ip, &in->sin_addr);
}



int doconnect(const char *ip, int port);

}

#endif

