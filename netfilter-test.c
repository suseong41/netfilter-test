#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct ipHeader
{
	uint8_t version_ihl;
	uint8_t dscp_ecn;
	uint16_t total_len;
	uint16_t identification;
	uint16_t flags_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_ip;
	uint32_t dst_ip;
}ip_h;

typedef struct tcpHeader
{
	uint16_t src_port;
    uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t dataOffset_reserved;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
}tcp_h;

const char *host_deny_addr = NULL;

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;


	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    unsigned char *packet;
    int ret;

    ret = nfq_get_payload(nfa, &packet);
    if (ret < 0)
    {
        return -1;
    }

    ip_h *ip_hdr = (ip_h *)packet;
    if (ip_hdr->protocol != IPPROTO_TCP) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    int ip_len = (ip_hdr->version_ihl & 0x0F) * 4;
    
    tcp_h *tcp_hdr = (tcp_h *)(packet + ip_len);
    if (ntohs(tcp_hdr->dst_port) != 80) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    

    int tcp_len = (tcp_hdr->dataOffset_reserved >> 4) * 4;
    unsigned char *http_data = packet + ip_len + tcp_len;
    int http_len = ret - (ip_len + tcp_len);

    if (http_len <= 0) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        
    const char *host_start_tag = "Host: ";
    const int host_start_tag_len = 6;
    const char *host_end_tag = "\r\n";
    const int host_end_tag_len = 2;
    
    unsigned char *host_name_start = NULL;
    unsigned char *host_name_end = NULL;
    
    for (int i = 0; i <= http_len - host_start_tag_len; i++) {
        bool match = true;
        for (int j = 0; j < host_start_tag_len; j++) {
            if (http_data[i+j] != host_start_tag[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            host_name_start = http_data + i + host_start_tag_len;
            break;
        }
    }
    if (host_name_start != NULL) {
        int search_start_offset = host_name_start - http_data;
        for (int i = search_start_offset; i <= http_len - host_end_tag_len; i++) {
            bool match = true;
            for (int j = 0; j < host_end_tag_len; j++) {
                if (http_data[i+j] != host_end_tag[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                host_name_end = http_data + i;
                break;
            }
        }
    }
    
    if (host_name_start != NULL && host_name_end != NULL) {
        int host_name_len = host_name_end - host_name_start;
        int harmful_host_len = strlen(host_deny_addr); 

        if (host_name_len == harmful_host_len) {
            bool match = true;
            for (int i = 0; i < host_name_len; i++) {
                if (host_name_start[i] != host_deny_addr[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                printf("http request denied:  %.*s\n", host_name_len, (const char *)host_name_start);
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }
    }
	
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        exit(1);
    }
    
	host_deny_addr = argv[1];
	
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) 
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) 
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) 
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) 
	{
		
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) 
		{
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) 
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}