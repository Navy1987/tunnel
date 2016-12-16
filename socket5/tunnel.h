#ifndef	_TUNNEL_H
#define	_TUNNEL_H

#undef DOMAIN

namespace tunnel {
	enum connect {
		IP = 1,
		DOMAIN = 2
	};

	enum protocol {
		OPEN = 1,
		CLOSE = 2,
		DATA = 3,
		NONE = 9,
	};

	struct event {
		int type;
		union {
			struct {
				int fd;
				int handle;
			} open;
			struct {
				int fd;
			} close;
			struct {
				int fd;
				const uint8_t *data;
				size_t sz;
			} data;
		} ;
	};

	//return temp handle
	int connecting(enum connect type, const char *addr, int port);
	void close(int fd);

	int send(int fd, const uint8_t *dat, size_t sz);
	int poll(struct event *e);

	int init(const char *ip, int port, const char *cryptkey);
	void exit();
};


#endif

