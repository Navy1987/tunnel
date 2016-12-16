#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "buffer.h"

#if EAGAIN == EWOULDBLOCK
#define ETRYAGAIN EAGAIN
#else
#define ETRYAGAIN EAGAIN: case EWOULDBLOCK
#endif


buffer::buffer()
{
	data = NULL;
	datacap = 0;
	datasz = 0;
}

buffer::~buffer()
{
	if (data)
		free(data);
}

int
buffer::tryread(int s, void *buff, size_t sz)
{
	int err;
	assert(sz > 0);
	for (;;) {
		err = ::read(s, buff, sz);
		if (err >= 0)
			return err;
		switch (errno) {
		case ETRYAGAIN:
			continue;
		default:
			return -1;
		}
	}
	return -1;
}


