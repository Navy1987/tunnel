#ifndef	_TUNNEL_H
#define	_TUNNEL_H

struct tunnel_config {
	char lip[64]; //listen ip
	int lport; //listen port
	char sip[64]; //server ip
	int sport; //server port
	char key[256];
	int keylen;
};

struct buffer {
	uint8_t *data;
	size_t  datasz;
	size_t  datacap;
};

struct tunnel {
	int s;	//socket
	int t;	//tunnel socket
	int close;
	int state;
	struct {
		struct buffer send;
		struct buffer recv;
	} sock;
	struct {
		struct buffer send;
		struct buffer recv;
	} tunnel;
	struct buffer buff;	//for compact
	const struct tunnel_config *cfg;
	struct tunnel *next;
	struct tunnel *prev;
};

void tunnel_append(struct tunnel *t, struct tunnel **parent);

struct tunnel *tunnel_create(int fd, struct tunnel_config *cfg);
void tunnel_free(struct tunnel *t, struct tunnel **root);

int tunnel_io(struct tunnel *t);
int tunnel_do(struct tunnel *t);


//aux
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


#endif

