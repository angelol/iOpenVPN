#include "bpf.h"

bpf_ctx_t bpf_new(void)
{
	bpf_ctx_t c = calloc(1, sizeof(bpf_ctx_t));
	return c;
}

static int open_free_bpf()
{
	char devname[12];
	int i = 0, fd = -1;
	for (i=0; i<100; i++){
		sprintf(devname, "/dev/bpf%u", i);
		fd = open(devname, O_RDWR);
		if (fd == -1 && errno == EBUSY)
			continue;
		else {
			//printf("Device %s is free. Taking it.\n", devname);
			break;	
		}
	}

	if (fd == -1){
		printf("unable to open bpf\n");
		exit(4);
	}
	
	return fd;
}


/*
 * compute an IP header checksum.
 * don't modifiy the packet.
 */
u_short
in_cksum(const u_short *addr, register u_int len, int csum)
{
	int nleft = len;
	const u_short *w = addr;
	u_short answer;
	int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
		sum += htons(*(u_char *)w<<8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}


static void
hexdump (void *data, int len)
{	
	unsigned char *ptr ;
	int k ;

	ptr = data ;

	puts ("---------------------------------------------------------") ;
	while (len >= 16) {	
		for (k = 0 ; k < 16 ; k++)
			printf ("%02X ", ptr [k] & 0xFF) ;
		printf ("   ") ;
		for (k = 0 ; k < 16 ; k++)
			printf ("%c", isprint (ptr [k]) ? ptr [k] : '.') ;
		puts ("") ;
		ptr += 16 ;
		len -= 16 ;
	}
}


int bpf_open(bpf_ctx_t c)
{
	if(!c)
		return 0;
	if(geteuid()) {
		printf("Needs root, young man.\n");
		exit(-1);
	}
	int ret = 0;
	int infd = open_free_bpf();
	int outfd = open_free_bpf();
	
	/* Set BIOCIMMEDIATE to true, so we will be able to use select on it */
	u_int on = 1;
	if(ioctl(infd, BIOCIMMEDIATE, &on) < 0) {
		perror("Couldn't set BIOCIMMEDIATE");
		goto err;
	}
	
	/* get the required buffer size for reading from bpf */
	u_int v;
	if(ioctl(infd, BIOCGBLEN, (caddr_t)&v) < 0) {
		perror("Couldn't set BIOCGBLEN");
		goto err;
	}
	
	c->infd = infd;
	c->outfd = outfd;
	c->bufsize = v;
	c->buf = calloc(1, v);	

	ret = 1;
	return ret;
	
	err:
	close(infd);
	return ret;
}

int bpf_attach(bpf_ctx_t c, char *ifname)
{
	if(!c || !ifname || strlen(ifname) == 0)
		return 0;
		
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	
	if(ioctl(c->infd, BIOCSETIF, (caddr_t)&ifr) < 0) {
		perror("Halp, couldn't set BIOCSETIF!!!");
		goto err;
	}
	if(ioctl(c->outfd, BIOCSETIF, (caddr_t)&ifr) < 0) {
		perror("Halp, couldn't set BIOCSETIF!!!");
		goto err;
	}

	return 1;
	
	err:
	return 0;
}

void bpf_wait_and_recv_packet(bpf_ctx_t c, void (*handlePacket)(bpf_ctx_t c, size_t size))
{
	struct timeval timeout;
	fd_set readFDs;
	
	while(1) {
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		FD_ZERO (&readFDs);
		FD_SET(c->infd, &readFDs);
		
		int numFDs = select (c->infd + 1, &readFDs, NULL, NULL, &timeout);
		if(numFDs < 1)
			continue;
		
		if(!FD_ISSET(c->infd, &readFDs))
			continue;
		
		int n = read(c->infd, c->buf, c->bufsize);
		if(n < 0) {
			perror("recvfrom failed");
			continue;
		}		
		
				
		/* skip bpf header + DLT_NULL header */
		struct bpf_hdr *bpf_header = (struct bpf_hdr *)c->buf;
		c->buf += (bpf_header->bh_hdrlen + NULL_HDRLEN);
		
		c->size = n - bpf_header->bh_hdrlen - NULL_HDRLEN ;
		
		
		struct ip *iph = bpf_get_ip_header(c);
		// skip packages that we injected into bpf 
		// ALFIXME: make my IP dynamic vs hard-coded
		if(strcmp(inet_ntoa(iph->ip_dst), "23.23.23.23")==0)
			continue;
		
		handlePacket(c, n);
	}
}

/* read from bpf and store packet in buf. return bytes read minus the bpf header. */
int bpf_wait_and_recv(bpf_ctx_t c, char *buf, int len)
{
	struct timeval timeout;
	fd_set readFDs;
	
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	FD_ZERO (&readFDs);
	FD_SET(c->infd, &readFDs);
	
	int numFDs = select (c->infd + 1, &readFDs, NULL, NULL, &timeout);
	if(numFDs < 1)
		return 0;
		
	if(!FD_ISSET(c->infd, &readFDs))
		return 0;
	
	int n = read(c->infd, buf, len);
	if(n < 0) {
		perror("recv failed");
		return n;
	}
	
	// Skip packets that we injected ourselves
	struct ip *iph = bpf_get_ip_header(c);
	if(strcmp(inet_ntoa(iph->ip_dst), "10.12.22.202"))
		return 0;
	
	/* skip bpf header + DLT_NULL header */
	//fprintf(stderr, "%s\n", c->buf);
	struct bpf_hdr *bpf_header = (struct bpf_hdr *)buf;
	buf += (bpf_header->bh_hdrlen + NULL_HDRLEN);
	
	int size = n - bpf_header->bh_hdrlen - NULL_HDRLEN - 1;
	
	return size;
}


int bpf_write_packet(bpf_ctx_t c)
{	
	struct ip *iph = bpf_get_ip_header(c);
	iph->ip_sum = 0;
	iph->ip_sum = in_cksum((u_short*)iph, 20, 0);
	
	return write(c->outfd, c->buf, c->size);	
}

int bpf_send_icmp_response(bpf_ctx_t c)
{	
	/* reverse target and source address */
	struct in_addr tmp;
	struct ip *iph = bpf_get_ip_header(c);
	memcpy(&tmp, &iph->ip_dst, sizeof(struct in_addr));
	memcpy(&iph->ip_dst, &iph->ip_src, sizeof(struct in_addr));
	memcpy(&iph->ip_src, &tmp, sizeof(struct in_addr));
	
	printf("sending ICMP response:\n");
	printf("IP SRC: %s\n", inet_ntoa(iph->ip_src)); 
	printf("IP DST: %s\n\n", inet_ntoa(iph->ip_dst));
	

	/* update icmp checksum */
	struct icmp *icmp_header = (struct icmp *) (c->buf + 20);
	icmp_header->icmp_type = 0;
	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum = in_cksum((u_short*)icmp_header, 64, 0);
	return bpf_write_packet(c);	
}

void print_bpf_header(bpf_ctx_t c)
{
	struct bpf_hdr *h = (struct bpf_hdr *)c->buf;
	printf("Time stamp: %d\n", h->bh_tstamp.tv_sec);
	printf("Length of captured portion: %d\n",h->bh_caplen);
	printf("Original length of packet: %d\n", h->bh_datalen);
	printf("Length of BPF header: %d\n\n",h->bh_hdrlen);
}



