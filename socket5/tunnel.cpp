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
#include "lz4.h"
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

#if 0
static void
dumptofile(int fd, const uint8_t *data, size_t sz)
{
	/*
	char name[64];
	FILE *fp;
	sprintf(name, "%d.dat", fd);
	fp = fopen(name, "ab+");
	fwrite(data, sz, 1, fp);
	fclose(fp);
	*/
	return ;
}
#endif


static int
tryread(int s, void *buff, size_t sz)
{
	int err;
	assert(sz > 0);
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

static void
closetunnel(struct tunnel *t)
{
	if (t->s > 0)
		close(t->s);
	if (t->t > 0)
		close(t->t);
	t->close = 1;
	return ;
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


#define	ISCOMPLETE(b, n)\
	if (b.datasz < n)\
		return 0;

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
	crypt_encode((uint8_t *)t->cfg->key, t->cfg->keylen, (uint8_t *)dat.c_str(), sz);
	err = write(t->t, dat.c_str(), sz);
	assert((size_t)err == sz);
	return 0;
}

static inline void
checkbuff(struct buffer *b, size_t need)
{
	if (b->datasz + need <= b->datacap)
		return ;
	b->datacap = b->datasz + need;
	b->data = (uint8_t *)realloc(b->data, b->datacap);
	return ;
}

static void inline
buffout(struct buffer *b, size_t n)
{
	size_t delta = 0;
	assert(n <= b->datasz);
	if (b->datasz > n) {
		delta = b->datasz - n;
		memmove(b->data, &b->data[n], delta);
	}
	b->datasz = delta;
	return ;
}

static void inline
buffin(struct buffer *b, const void *data, size_t n)
{
	checkbuff(b, n);
	memcpy(&b->data[b->datasz], data, n);
	b->datasz += n;
	return ;
}

static int
buffread(int fd, struct buffer *b)
{
	int err;
	if (b->datasz == b->datacap)
		checkbuff(b, 64 * 1024);
	err = tryread(fd, &b->data[b->datasz], b->datacap - b->datasz);
	if (err < 0)
		return -1;
	b->datasz += err;
	return 0;
}

static int
buffwrite(int fd, struct buffer *b)
{
	int err;
	err = write(fd, b->data, b->datasz);
	if (err <= 0)
		return err;
	assert(err >= 1);
	buffout(b, err);
	return err;
}

static int
tunnel_auth(struct tunnel *t)
{
	size_t sz;
	int noauth;
	struct authreq *req;
	struct authack ack;
	//read proto
	sz = sizeof(*req);
	ISCOMPLETE(t->sock.recv, sz);
	req = (struct authreq *)t->sock.recv.data;
	assert(req->ver = 0x05);
	if (req->nr > 1) {
		sz += sizeof(uint8_t) * (req->nr - 1);
		ISCOMPLETE(t->sock.recv, sz);
		printf("auth:%d\n", req->method[0]);
		noauth = testmethod(&req->method[1], req->nr - 1, 0x00);
	}
	if (req->method[0] == 0x00)
		noauth = 1;

	buffout(&t->sock.recv, sz);

	//ack proto
	ack.ver = 0x05;
	if (noauth != 1) {
		printf("only support noauth\n");
		ack.method = 0xff;
		buffin(&t->sock.send, &ack, sizeof(ack));
		closetunnel(t);
		return -1;
	}

	//ack proto
	ack.method = 0x00;
	buffin(&t->sock.send, &ack, sizeof(ack));
	t->state = 'C';
	printf("auth\n");
	return 0;
}

#define	tou16(n)	(*((uint16_t *)(n)))
#define	tou8(n)		(*((uint8_t *)(n)))
static int
tunnel_connect(struct tunnel *t)
{
	size_t sz;
	struct head *hdr;
	uint8_t ack3[] = {0x05, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0xe9, 0xc7};
	sz = sizeof(*hdr);
	ISCOMPLETE(t->sock.recv, sz);
	hdr = (struct head *)t->sock.recv.data;
	assert(hdr->req == 0x01); //only support connect
	switch (hdr->addr) {
	case 1: //ipv4
		assert(0);
		break;
	case 3: { //domain
		int err;
		int port;
		uint8_t n;
		//length
		n =tou8(t->sock.recv.data + sz);
		sz += sizeof(uint8_t);
		ISCOMPLETE(t->sock.recv, sz);
		//domain
		char domain[n + 1];
		domain[n] = 0;
		memcpy(domain, t->sock.recv.data + sz, n);
		sz += n;
		ISCOMPLETE(t->sock.recv, sz);
		//port
		ISCOMPLETE(t->sock.recv, sz + sizeof(uint16_t));
		port = tou16(t->sock.recv.data + sz);
		port = ntohs(port);
		sz += sizeof(uint16_t);
		buffout(&t->sock.recv, sz);
		//connect
		err = connectdomain(t, domain, port);
		if (err < 0) {
			closetunnel(t);
			return 0;
		}
		*((unsigned short *)&ack3[8]) = htons(port);
		buffin(&t->sock.send, ack3, sizeof(ack3));
		t->state = 'T';
		//nonblock
		nonblock(t->s);
		nonblock(t->t);
		printf("connect %s %d\n", domain, t->t);
		break;
	}
	case 4: //ipv6
		assert(0);
		break;
	}
	return 0;
}

int
tunnel_io(struct tunnel *t)
{
	int maxn;
	struct timeval tv;
	fd_set rset;
	fd_set wset;
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	FD_SET(t->s, &rset);
	FD_SET(t->s, &wset);
	FD_SET(t->t, &rset);
	FD_SET(t->t, &wset);
	maxn = (t->s > t->t ? t->s : t->t) + 1;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	select(maxn, &rset, &wset, NULL, &tv);

	if (FD_ISSET(t->s, &rset))
		buffread(t->s, &t->sock.recv);
	if (FD_ISSET(t->s, &wset))
		buffwrite(t->s, &t->sock.send);
	if (FD_ISSET(t->t, &rset))
		buffread(t->t, &t->tunnel.recv);
	if (FD_ISSET(t->t, &wset))
		buffwrite(t->t, &t->tunnel.send);
	return 0;
}

#define	BUFFSZ (64 * 1024)

static const uint8_t *
decompress(const void *src, size_t srcsz, size_t originsz)
{
	static uint8_t *buff = NULL;
	static size_t buffsz = 0;

	if (buffsz < originsz) {
		buffsz = (originsz + BUFFSZ - 1) / BUFFSZ * BUFFSZ;
		buff = (uint8_t *)realloc(buff, buffsz);
	}
	LZ4_decompress_fast((const char *)src, (char *)buff, originsz);
	return buff;
}

static int
tunnel_transfer(struct tunnel *t)
{
	//process tunnel
	if (t->tunnel.recv.datasz > sizeof(uint16_t)) {
		int offset;
		int compress;
		const uint8_t *dat;
		size_t sz = tou16(t->tunnel.recv.data);
		assert(sz > 0);
		size_t total = sz + sizeof(uint16_t);
		if (t->tunnel.recv.datasz < total)
			return 0;
		offset = sizeof(uint16_t);
		compress = tou8(t->tunnel.recv.data + offset);
		assert(compress == 1 || compress == 0);
		offset += sizeof(uint8_t);
		if (compress) {	//compress
			size_t origin = tou16(t->tunnel.recv.data + offset);
			crypt_decode((uint8_t *)t->cfg->key, t->cfg->keylen,
					t->tunnel.recv.data + offset, sz - 3);
			offset += sizeof(uint16_t);
			dat = decompress(t->tunnel.recv.data + offset, sz - 3, origin);
			sz = origin;
		} else {	//uncompress
			crypt_decode((uint8_t *)t->cfg->key, t->cfg->keylen,
					t->tunnel.recv.data + offset, sz - 1);
			dat = t->tunnel.recv.data + offset;
			sz -= 1;
		}
		buffin(&t->sock.send, dat, sz);
		buffout(&t->tunnel.recv, total);
	}

	if (t->sock.recv.datasz > 0) {
		uint16_t n;
		if (t->sock.recv.datasz > 0xff)
			n = 0xff;
		else
			n = t->sock.recv.datasz;

		buffin(&t->tunnel.send, &n, sizeof(n));
		crypt_encode((uint8_t *)t->cfg->key, t->cfg->keylen, t->sock.recv.data, n);
		buffin(&t->tunnel.send, t->sock.recv.data, n);
		buffout(&t->sock.recv, n);
	}
	return 0;
}

int
tunnel_do(struct tunnel *t)
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

struct tunnel *
tunnel_create(int fd, struct tunnel_config *cfg)
{
	struct tunnel *t;
	t = (struct tunnel *)malloc(sizeof(*t));
	memset(t, 0, sizeof(*t));
	t->state = 'A';
	t->s = fd;
	t->cfg = cfg;
	return t;
}

static void inline
freebuff(struct buffer *b)
{
	if (b->data)
		free(b->data);
}

void
tunnel_append(struct tunnel *t, struct tunnel **parent)
{
	t->prev = NULL;
	t->next = *parent;

	if (*parent)
		(*parent)->prev = t;

	*parent = t;
	return ;
}

void
tunnel_free(struct tunnel *t, struct tunnel **root)
{
	if (t == NULL)
		return ;
	if (t->next)
		t->next->prev = t->prev;

	if (t->prev == NULL)
		*root = t->next;
	else
		t->prev->next = t->next;

	freebuff(&t->sock.send);
	freebuff(&t->sock.recv);
	freebuff(&t->tunnel.send);
	freebuff(&t->tunnel.recv);
	freebuff(&t->buff);
	free(t);
	return ;
}


