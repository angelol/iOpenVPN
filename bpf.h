#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define	NULL_HDRLEN 4

struct _bpf_ctx_t {
	int infd, outfd;
	uint8_t *buf;
	u_int bufsize;
	u_int size;
};
typedef struct _bpf_ctx_t *bpf_ctx_t;

static inline struct ip *bpf_get_ip_header(bpf_ctx_t c)
{
	return (struct ip *) c->buf;
}
 

void print_bpf_header(bpf_ctx_t c);
bpf_ctx_t bpf_new(void);
int bpf_open(bpf_ctx_t c);
int bpf_attach(bpf_ctx_t c, char *ifname);
void bpf_wait_and_recv_packet(bpf_ctx_t c, void (*handlePacket)(bpf_ctx_t c, size_t size));

