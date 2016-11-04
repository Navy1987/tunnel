#ifndef	_TUNNEL_H
#define	_TUNNEL_H

struct tunnel_config {
	char lip[64]; //listen ip
	int lport; //listen port
	char sip[64]; //server ip
	int sport; //server port
	char key[256];
};

struct tunnel {
	int s;	//socket
	int t;	//tunnel socket
	int state;
	uint8_t buff[64 * 1024 + 256];
	const struct tunnel_config *cfg;
};

void tunnel_init(struct tunnel *t, int fd, struct tunnel_config *cfg);
int tunnel_process(struct tunnel *t);

static inline void
tosockaddr(struct sockaddr *addr, const char *ip, int port)
{
	struct sockaddr_in *in = (struct sockaddr_in *)addr;
	bzero(addr, sizeof(*addr));
	in->sin_family = AF_INET;
	in->sin_port = htons(port);
	inet_pton(AF_INET, ip, &in->sin_addr);
}


#endif

