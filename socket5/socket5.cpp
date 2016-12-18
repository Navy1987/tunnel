#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <vector>
#include <unordered_map>
#include "aux.h"
#include "buffer.h"
#include "tunnel.h"

#define	SUCCESS (0)
#define	ERROR (-1)
#define	INCOMPLETE (-2)

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

struct proxy {
	int fd;
	int tfd;
	int state;
	struct {
		buffer send;
		buffer recv;
	} buffer;
};


#define	ISCOMPLETE(b, n)\
	if (b.datasz < n)\
		return INCOMPLETE;



//static std::vector<int> proxycooks;
static std::unordered_map<int, int> handleproxy;	//handle, proxy
static std::unordered_map<int, int> tunnelproxy;	//tunnel, proxy
static std::unordered_map<int, struct proxy> proxys;

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

static void
closeproxy(struct proxy *p)
{
	int fd = p->fd;
	close(fd);
	if (p->tfd > 0)
		tunnel::close(p->tfd);
	if (p->state == 'B') {
		printf("close handle:%d\n", p->tfd);
		handleproxy.erase(p->tfd);
	} else if (p->state == 'T') {
		printf("close tunnel:%d\n", p->tfd);
		tunnelproxy.erase(p->tfd);
	}
	printf("close fd:%d\n", fd);
	proxys.erase(fd);
	return ;
}

static int
proxy_auth(struct proxy *t)
{
	size_t sz;
	int noauth;
	struct authreq *req;
	struct authack ack;
	//read proto
	sz = sizeof(*req);
	ISCOMPLETE(t->buffer.recv, sz);
	req = (struct authreq *)t->buffer.recv.data;
	assert(req->ver = 0x05);
	if (req->nr > 1) {
		sz += sizeof(uint8_t) * (req->nr - 1);
		ISCOMPLETE(t->buffer.recv, sz);
		printf("auth:%d\n", req->method[0]);
		noauth = testmethod(&req->method[1], req->nr - 1, 0x00);
	}
	if (req->method[0] == 0x00)
		noauth = 1;
	t->buffer.recv.out(sz);

	//ack proto
	ack.ver = 0x05;
	if (noauth != 1) {
		printf("only support noauth\n");
		return ERROR;
	}

	//ack proto
	ack.method = 0x00;
	t->buffer.send.in(&ack, sizeof(ack));
	t->state = 'C';
	printf("auth\n");
	return 0;

}

static int
proxy_connect(struct proxy *t)
{
	size_t sz;
	struct head *hdr;
	uint8_t ack3[] = {0x05, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00, 0xe9, 0xc7};
	sz = sizeof(*hdr);
	ISCOMPLETE(t->buffer.recv, sz);
	hdr = (struct head *)t->buffer.recv.data;
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
		n =tou8(t->buffer.recv.data + sz);
		sz += sizeof(uint8_t);
		ISCOMPLETE(t->buffer.recv, sz);
		//domain
		char domain[n + 1];
		domain[n] = 0;
		memcpy(domain, t->buffer.recv.data + sz, n);
		sz += n;
		ISCOMPLETE(t->buffer.recv, sz);
		//port
		ISCOMPLETE(t->buffer.recv, sz + sizeof(uint16_t));
		port = tou16(t->buffer.recv.data + sz);
		port = ntohs(port);
		sz += sizeof(uint16_t);
		t->buffer.recv.out(sz);
		//connect
		err = tunnel::connecting(tunnel::DOMAIN, domain, port);
		if (err < 0)
			return ERROR;
		*((unsigned short *)&ack3[8]) = htons(port);
		t->buffer.send.in(ack3, sizeof(ack3));
		t->state = 'B';
		assert(t->tfd == -1);
		handleproxy[err] = t->fd;
		printf("connect %s handle %d fd:%d \n", domain, err, t->fd);
		break;
	}
	case 4: //ipv6
		assert(0);
		break;
	}
	return 0;

}

static int
proxy_bridge(struct proxy *p)
{
	return INCOMPLETE;
}

static int
proxy_pourout(struct proxy *p)
{
	size_t sz = p->buffer.recv.datasz;
	if (sz == 0)
		return INCOMPLETE;
	tunnel::send(p->tfd, p->buffer.recv.data, sz);
	p->buffer.recv.out(sz);
	return 0;
}

static std::unordered_map<int, int (*)(struct proxy *p)> router = {
	{'A', proxy_auth},
	{'C', proxy_connect},
	{'B', proxy_bridge},
	{'P', proxy_pourout},
};

static void
process()
{
	std::vector<struct proxy *> errors;
	for (auto &iter:proxys) {
		auto &p = iter.second;
		int err;
		do {
			err = router[p.state](&p);
		} while (err == SUCCESS);
		if (err == ERROR)
			errors.push_back(&p);
	}
	for (auto p:errors)
		closeproxy(p);
	//proxycooks.clear();
	return ;
}

static void
dumptofile(int fd, const uint8_t *data, size_t sz)
{
	char name[64];
	FILE *fp;
	sprintf(name, "s%d.dat", fd);
	fp = fopen(name, "ab+");
	fwrite(data, sz, 1, fp);
	fclose(fp);
	return ;
}


int socket5_io()
{
	fd_set rset;
	fd_set wset;
	int maxfd = 0;
	struct timeval tv = {};
	struct tunnel::event e;
	//proxy IO
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	for (const auto &iter:proxys) {
		int fd = iter.first;
		FD_SET(fd, &rset);
		FD_SET(fd, &wset);
		if (fd > maxfd)
			maxfd = fd;
	}
	select(maxfd + 1, &rset, &wset, NULL, &tv);
	for (auto const &iter:proxys) {
		int fd = iter.first;
		if (FD_ISSET(fd, &rset)) {
			int err;
			//proxycooks.push_back(fd);
			assert(proxys[fd].state != 0);
			err = proxys[fd].buffer.recv.read(fd);
			if (err == 0) {
				printf("socket5 active close:%d\n", fd);
				closeproxy(&proxys[fd]);
				continue;
			}
		}
		if (FD_ISSET(fd, &wset)) {
			assert(proxys[fd].state != 0);
			proxys[fd].buffer.send.write(fd);
		}
	}

	process();

	//tunnel IO
	for (;;) {
		tunnel::poll(&e);
		switch (e.type) {
		case tunnel::NONE:
			goto out;
		case tunnel::OPEN: {
			assert(handleproxy.count(e.open.handle) == 1);
			int fd = handleproxy[e.open.handle];
			printf("connecting:%d-%d:%d\n", e.open.handle, e.open.fd, fd);
			assert(proxys[fd].tfd == -1);
			assert(proxys[fd].state == 'B');
			proxys[fd].tfd = e.open.fd;
			proxys[fd].state = 'P';
			handleproxy.erase(e.open.handle);
			tunnelproxy[e.open.fd] = fd;
			//proxycooks.push_back(fd);
			break;}
		case tunnel::CLOSE: {
			int fd = tunnelproxy[e.close.fd];
			closeproxy(&proxys[fd]);
			break;}
		case tunnel::DATA: {
			int fd = tunnelproxy[e.data.fd];
			if (proxys.count(fd)) {
				assert(proxys[fd].state != 0);
				proxys[fd].buffer.send.in(e.data.data, e.data.sz);
			}
			break;}
		default:
			assert(0);
			break;
		}
	};
out:
	return 0;
}

int socket5_new(int fd)
{
	assert(proxys.count(fd) == 0);
	aux::nonblock(fd);
	proxys[fd].fd = fd;
	proxys[fd].tfd = -1;
	proxys[fd].state = 'A';
	return 0;
}


