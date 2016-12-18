#include <assert.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unordered_map>
#include "socket5_zproto.hpp"
#include "buffer.h"
#include "aux.h"
#include "tunnel.h"

extern "C" {
#include "lz4.h"
#include "crypt.h"
}

namespace tunnel {

#define	TUNNEL_NR (128)

static int addrport;
static std::string addrip;
static std::string cryptkey;
static int handleidx = 0;
static int tunnelidx = 0;
static int tunnelcookidx = 0;
static std::string tempbuffer;
static std::vector<int> tunnels;		//tunnelfd
//static std::vector<int> tunnelcooked;		//tunnelfd
static std::vector<int> closesession;
static std::unordered_map<int, int> tunnelmap;	//session, tunnelfd
static std::unordered_map<int, buffer> tunnelsend;	//tunnelfd, buffer
static std::unordered_map<int, buffer> tunnelrecv;	//tunnelfd, buffer

static socket5_zproto::connect_ack openpacket;
static socket5_zproto::close closepacket;
static socket5_zproto::data datapacket;
static socket5_zproto::serializer *S = new socket5_zproto::serializer;

#if 0
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

static void
dumptofile(int fd, const uint8_t *data, size_t sz)
{
	char name[64];
	FILE *fp;
	sprintf(name, "%d.dat", fd);
	fp = fopen(name, "ab+");
	fwrite(data, sz, 1, fp);
	fclose(fp);
	return ;
}

#endif

static int
ensureget(int idx)
{
	int fd;
	fd = tunnels[idx];
	if (fd == 0) {
		fd = aux::doconnect(addrip.c_str(), addrport);
		printf("ensureget:%d\n", fd);
		if (fd < 0)
			return fd;
		tunnels[idx] = fd;
	}
	return fd;

}

static int
fetchtunnel()
{
	int fd;
	size_t tsz = tunnels.size();
	if (tunnelidx < (int)tsz)
		return ensureget(tunnelidx++);

	if (tsz >= TUNNEL_NR) {
		tunnelidx = 0;
		return ensureget(tunnelidx++);
	}

	fd = aux::doconnect(addrip.c_str(), addrport);
	if (fd < 0)
		return fd;
	printf("ensureget:%d\n", fd);
	tunnels.push_back(fd);
	++tunnelidx;
	return fd;
}

static void
cleartunnel(int fd)
{
	//clear tunnel session
	for (auto &iter:tunnelmap) {
		if (iter.second == fd)
			closesession.push_back(iter.first);
	}
	for (auto id:closesession)
		tunnelmap.erase(id);
	//clear cooked
	/*
	for (int i = 0; i < tunnelcooked.size(); i++) {
		if (tunnelcooked[i] == fd) {
			tunnelcooked.erase(tunnelcooked.begin());
			break;
		}
	}*/
	//clear tunnels
	for (int i = 0; i < tunnels.size(); i++) {
		if (tunnels[i] == fd) {
			tunnels[i] = 0;
			break;
		}
	}
}

static void
writepacket(int tfd, int cmd, const zprotobuf::wire &obj)
{
	uint32_t sz;
	auto &buff = tunnelsend[tfd];

	S->encode(obj, tempbuffer);
	sz = tempbuffer.size();
	crypt_encode((uint8_t *)cryptkey.data(), cryptkey.size(), (uint8_t *)tempbuffer.data(), sz);
	sz += 1;
	buff.in((uint8_t *)&sz, sizeof(sz));
	buff.in(tempbuffer.c_str(), tempbuffer.size());
	buff.in((uint8_t *)&cmd, 1);
	//printf("send %d %d\n", tfd, sz);
}

static int
readpacket(int tfd, int *cmd)
{
	uint32_t sz;
	auto &buff = tunnelrecv[tfd];
	zprotobuf::wire *obj;
	if (buff.datasz <= 4)
		return -1;
	sz = tou32(buff.data);
	if (buff.datasz < sz + 4)
		return -1;
	crypt_decode((uint8_t *)cryptkey.c_str(), cryptkey.size(), buff.data + 4, sz - 1);
	*cmd = tou8(buff.data + 4 + sz - 1);
	switch (*cmd) {
	case OPEN:
		obj = &openpacket;
		break;
	case CLOSE:
		obj = &closepacket;
		break;
	case DATA:
		obj = &datapacket;
		break;
	default:
		assert(!"invalid cmd");
		break;
	}
	int err = S->decode(*obj, buff.data + 4, sz - 1);
	assert(err == (sz - 1));
	/*
	if (*cmd == DATA)
		dumptofile(datapacket.session, buff.data, sz + 4);
	*/
	buff.out(sz + 4);
	return 0;
}

int
connecting(enum connect type, const char *addr, int port)
{
	int h = ++handleidx;
	int t = fetchtunnel();
	assert(t > 0);
	socket5_zproto::connect_req req;
	req.type = (int)type;
	req.addr = addr;
	req.port = port;
	req.handle = h;
	writepacket(t, OPEN, req);
	return h;
}

void
close(int fd)
{
	int t = fetchtunnel();
	socket5_zproto::close req;
	assert(t > 0);
	req.session = fd;
	writepacket(t, CLOSE, req);
	return ;
}

int
send(int fd, const uint8_t *dat, size_t sz)
{
	int t;
	if (tunnelmap.count(fd) == 0)
		return -1;

	t = tunnelmap[fd];
	assert(t > 0);
	socket5_zproto::data req;
	//dumptofile(fd, dat, sz);
	req.session = fd;
	req.data.assign((const char *)dat, sz);
	writepacket(t, DATA, req);
	return 0;
}

static int
pullpacket(struct event *e)
{
	//report close
	int cs = closesession.size();
	if (cs > 0) {
		int fd;
		cs -= 1;
		fd = closesession[cs];
		e->type = CLOSE;
		e->close.fd = fd;
		closesession.resize(cs);
		return 0;
	}
	size_t sz = tunnels.size();
	for (; tunnelcookidx < (int)sz; tunnelcookidx++) {
		int cmd;
		int tfd = tunnels[tunnelcookidx];
		//printf("pullpacket:%d\n", tfd);
		if (readpacket(tfd, &cmd) < 0)
			continue;
		//printf("read packet:%d %u\n", cmd);
		switch (cmd) {
		case OPEN:
			e->type = OPEN;
			e->open.handle = openpacket.handle;
			e->open.fd = openpacket.session;
			tunnelmap[e->open.fd] =  tfd;
			break;
		case CLOSE:
			e->type = CLOSE;
			e->close.fd = closepacket.session;
			printf("close session:%d\n", e->close.fd);
			tunnelmap.erase(e->close.fd);
			break;
		case DATA:
			e->type = DATA;
			e->data.fd = datapacket.session;
			e->data.data = (uint8_t *)datapacket.data.data();
			e->data.sz = datapacket.data.size();
			//printf("datasz:%u\n", e->data.sz);
			break;
		default:
			assert(!"invalid cmd");
			break;
		}
		return 0;
	}
	tunnelcookidx = 0;
	//tunnelcooked.clear();
	return -1;
}

int
poll(struct event *e)
{
	fd_set rset;
	fd_set wset;
	int maxfd = 0;
	struct timeval tv = {};
	static std::vector<int> errors;
	if (pullpacket(e) == 0)
		return 0;
	//IO
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	for (auto fd:tunnels) {
		FD_SET(fd, &rset);
		FD_SET(fd, &wset);
		if (fd > maxfd)
			maxfd = fd;
	}
	select(maxfd + 1, &rset, &wset, NULL, &tv);
	for (auto fd:tunnels) {
		if (FD_ISSET(fd, &rset)) {
			//tunnelcooked.push_back(fd);
			int err = tunnelrecv[fd].read(fd);
			if (err == 0)
				errors.push_back(fd);
			printf("read err:%d - %d\n", fd, err);
			//assert(err);
		}
		if (FD_ISSET(fd, &wset))
			tunnelsend[fd].write(fd);
	}

	//clear error
	for (auto id:errors)
		cleartunnel(id);

	errors.clear();

	e->type = NONE;

	return 0;
}

int
init(const char *ip, int port, const char *key)
{
	int fd;
	addrip = ip;
	addrport = port;
	cryptkey = key;
	fd = fetchtunnel();
	return fd;
}

void
exit()
{
	for (auto id:tunnels)
		close(id);
	return ;
}

}


