#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "tunnel.h"
extern "C" {
#include "crypt.h"
}
#include "socket5_zproto.hpp"

#if EAGAIN == EWOULDBLOCK
#define ETRYAGAIN EAGAIN
#else
#define ETRYAGAIN EAGAIN: case EWOULDBLOCK
#endif

#pragma pack(push, 1)

struct authreq {
	uint8_t ver;
	uint8_t nr;
	uint8_t method[1];
};

struct authack {
	uint8_t ver;
	uint8_t method;
};

struct head {
	uint8_t ver;
	uint8_t req;	//req type
	uint8_t rev;
	uint8_t addr;	//req addr
};

#pragma pack(pop)
socket5_zproto::serializer *S = new socket5_zproto::serializer;

static void
nonblock(int fd, int on)
{
	int err;
	int flag;
	flag = fcntl(fd, F_GETFL, 0);
	if (flag < 0) {
		perror("nonblock F_GETFL");
		return ;
	}
	if (on)
		flag |= O_NONBLOCK;
	else
		flag &= ~O_NONBLOCK;
	err = fcntl(fd, F_SETFL, flag);
	if (err < 0) {
		perror("nonblock F_SETFL");
		return ;
	}
	return ;
}

static int
tryread(int s, void *buff, size_t sz)
{
	int err;
	for (;;) {
		err = read(s, buff, sz);
		if (err > 0)
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

static int
readsz(int s, void *buff, size_t sz)
{
	int last = sz;
	while (last != 0) {
		int err = tryread(s, buff, last);
		if (err < 0)
			return err;
		last -= err;
		buff = (uint8_t *)buff + err;
	}
	return sz;
}

static void
closetunnel(struct tunnel *t)
{
	if (t->s > 0)
		close(t->s);
	if (t->t > 0)
		close(t->t);
	return ;
}

#define	readcheck(s, d, sz, n)\
	n = tryread(s, d, sz);\
	if (n < 0) {\
		closetunnel(t);\
		printf("close\n");\
		return -1;\
	}

#define	readsize(s, d, sz, n)\
	n = readsz(s, d, sz);\
	if (n < 0) {\
		closetunnel(t);\
		printf("close\n");\
		return -1;\
	}

static int
testmethod(const uint8_t *buff, size_t n, int method)
{
	size_t i;
	for (i = 0; i < n; i++) {
		if (buff[i] == method)
			return 1;
	}
	return 0;
}

#if 0
//for test
static int
connectip(struct tunnel *t, const char *ip, int port)
{
	int err;
	struct sockaddr addr;
	printf("connect ip:%s\n", ip);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd);
	tosockaddr(&addr, ip, port);
	err = connect(fd, &addr, sizeof(addr));
	assert(err == 0);
	assert(t->t == 0);
	t->t = fd;
	nonblock(err, 1);
	nonblock(t->s, 1);
	return 0;
}

static int
connectdomain(struct tunnel *t, const char *url, int port)
{
	int err;
	int errn;
	char buff[1024];
	const char *ip;
	struct hostent *h;
	struct hostent host;
	err = gethostbyname_r(url, &host, buff, sizeof(buff), &h, &errn);
	if (h == NULL) {
		printf("gethostbyname_r errno:%s %d %d %d\n", url, err, errn, HOST_NOT_FOUND);
		return -1;
	}

	ip = inet_ntop(h->h_addrtype, h->h_addr_list[0],
				buff, sizeof(buff));
	err = connectip(t, ip, port);
	return err;
}

static int
tunnel_transfer(struct tunnel *t)
{
	int err;
	fd_set set;
	char buff[512];
	FD_ZERO(&set);
	FD_SET(t->s, &set);
	FD_SET(t->t, &set);
	select((t->s > t->t ? t->s : t->t) + 1, &set,
			NULL, NULL, NULL);
	if (FD_ISSET(t->s, &set)) {
		readcheck(t->s, buff, sizeof(buff), err);
		//printf("+%c", buff[0]);
		write(t->t, buff, err);
	}
	if (FD_ISSET(t->t, &set)) {
		readcheck(t->t, buff, sizeof(buff), err);
		write(t->s, buff, err);
	}
	return 0;
}

#else

static int
bridge(struct tunnel *t)
{
	int fd;
	int err;
	struct sockaddr addr;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd > 0);
	tosockaddr(&addr, t->cfg->sip, t->cfg->sport);
	err = connect(fd, &addr, sizeof(addr));
	if (err < 0) {
		fprintf(stderr, "bridge %s:%d fail\n", t->cfg->sip,
				t->cfg->sport);
		return err;
	}
	assert(err == 0);
	assert(t->t == 0);
	t->t = fd;
	return 0;
}

static int
connectdomain(struct tunnel *t, const char *url, int port)
{
	int err;
	size_t sz;
	std::string dat;
	socket5_zproto::connect req;
	req.type = 2;
	req.addr = url;
	req.port = port;
	S->encode(req, dat);
	sz = dat.size();
	err = bridge(t);
	if (err < 0)
		return err;
	err = write(t->t, &sz, sizeof(uint16_t));
	assert(err == sizeof(uint16_t));
	err = write(t->t, dat.c_str(), sz);
	assert((size_t)err == sz);
	return 0;
}

static int
tunnel_transfer(struct tunnel *t)
{
	int err;
	fd_set set;
	FD_ZERO(&set);
	FD_SET(t->s, &set);
	FD_SET(t->t, &set);
	select((t->s > t->t ? t->s : t->t) + 1, &set,
			NULL, NULL, NULL);

	nonblock(t->s, 1);
	if (FD_ISSET(t->s, &set)) {
		readcheck(t->s, t->buff, sizeof(t->buff), err);
		write(t->t, &err, sizeof(uint16_t));
		//crypt_encode((uint8_t *)t->cfg->key, strlen(t->cfg->key), t->buff, err);
		printf("send:%d\n", err);
		write(t->t, t->buff, err);
	}

	nonblock(t->s, 0);
	if (FD_ISSET(t->t, &set)) {
		uint16_t sz;
		readsize(t->t, &sz, sizeof(sz), err);
		assert(sz < sizeof(t->buff));
		readsize(t->t, t->buff, sz, err);
		assert(sz == err);
		//crypt_decode((uint8_t *)t->cfg->key, strlen(t->cfg->key), t->buff, sz);
		printf("recv:%d-%d\n", sz, err);
		write(t->s, t->buff, sz);
	}
	return 0;
}


#endif



static int
tunnel_auth(struct tunnel *t)
{
	int err;
	int noauth;
	int s = t->s;
	struct authreq req;
	struct authack ack;

	//read proto
	readcheck(s, &req, sizeof(req), err);
	assert(req.ver = 0x05);
	if (req.nr > 1) {
		uint8_t buff[req.nr - 1];
		readcheck(s, buff, req.nr - 1, err);
		printf("auth:%d\n", req.method[0]);
		noauth = testmethod(buff, req.nr - 1, 0x00);
	}
	if (req.method[0] == 0x00)
		noauth = 1;
	ack.ver = 0x05;
	if (noauth != 1) {
		printf("only support noauth\n");
		ack.method = 0xff;
		write(s, &ack, sizeof(ack));
		closetunnel(t);
		return -1;
	}
	//ack proto
	ack.method = 0x00;
	err = write(s, &ack, sizeof(ack));
	if (err < 0) {
		printf("=============\n");
		closetunnel(t);
		return 0;
	}
	t->state = 'C';
	return 0;
}

#define	tou16(n)	(*((uint16_t *)n))
#define	tou8(n)		(*((uint8_t *)n))
static int
tunnel_connect(struct tunnel *t)
{
	int err;
	int s = t->s;
	struct head hdr;
	uint8_t ack3[] = {0x05, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0xe9, 0xc7};
	readcheck(s, &hdr, sizeof(hdr), err);
	assert(hdr.req == 0x01); //only support connect
	switch (hdr.addr) {
	case 1: //ipv4
		assert(0);
		break;
	case 3: { //domain
		int port;
		uint8_t n;
		char buff[128];
		readcheck(s, buff, 5, err);	//pre-read, at leastest 5 bytes(n, '.com')
		n = tou8(buff);
		readcheck(s, &buff[5], n - 4, err); //read last domain
		buff[n + 1] = 0;
		readcheck(s, &buff[n + 2], sizeof(uint16_t), err);
		port = ntohs(tou16(&buff[n + 2]));
		err = connectdomain(t, &buff[1], port);
		if (err < 0) {
			closetunnel(t);
			return 0;
		}
		*((unsigned short *)&ack3[8]) = htons(port);
		write(s, ack3, sizeof(ack3));
		t->state = 'T';
		break;
	}
	case 4: //ipv6
		assert(0);
		break;
	}
	return 0;
}

int
tunnel_process(struct tunnel *t)
{
	switch (t->state) {
	case 'A':	//auth
		return tunnel_auth(t);
	case 'C':	//connect
		return tunnel_connect(t);
	case 'T':	//tunnel
		return tunnel_transfer(t);
	default:
		assert(!"oh, my god!");
	}
	return -1;
}

void
tunnel_init(struct tunnel *t, int fd, struct tunnel_config *cfg)
{
	t->state = 'A';
	t->s = fd;
	t->cfg = cfg;
	return ;
}


