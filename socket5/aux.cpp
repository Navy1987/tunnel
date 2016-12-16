#include "aux.h"

namespace aux {

int doconnect(const char *ip, int port)
{
	int fd;
	int err;
	struct sockaddr addr;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd > 0);
	tosockaddr(&addr, ip, port);
	err = connect(fd, &addr, sizeof(addr));
	if (err < 0) {
		fprintf(stderr, "doconnect%s:%d fail\n",
				ip,port);
		return err;
	}
	assert(err == 0);
	nonblock(fd);
	return fd;
}

}


