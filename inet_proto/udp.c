#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "../inet_proto.h"
#include "../utils.h"
#include "../pcap_stat.h"


static int udp_handler(struct pkt_buff *pb)
{
	struct iphdr *iph;
	struct udphdr *uh;
	uint32_t saddr, daddr, param1, param2;
	struct pcap_stat_node *stat;

	/* sanity check */
	/* TODO: Do we need to do the checksum check? */
	if ((pb->tail - pb->data) < sizeof(struct udphdr))
		goto hdr_error;

	iph = (struct iphdr *)pb_network_header(pb);
	uh = (struct udphdr *)pb_transport_header(pb);

	saddr = ntohl(iph->saddr);
	daddr = ntohl(iph->daddr);
	param1 = ntohs(uh->source);
	param2 = ntohs(uh->dest);
	stat = pcap_stat_node_get(saddr, daddr, L4_PROTO_UDP, param1, param2);
	if(!stat)
		stat = pcap_stat_node_add(saddr, daddr, L4_PROTO_UDP, param1, param2);
	stat->count++;
	
	//DBGMSG("saddr:%s daddr:%s\n", ip2str(ntohl(iph->saddr)), ip2str(ntohl(iph->daddr)));


	return 0;

hdr_error:
	DBGMSG("udp header error!\n");
	return -1;
}

static struct inet_proto udp_proto = {
	.name 		= "UDP",
	.proto 		= IPPROTO_UDP,
	.handler 	= udp_handler,
};

void __init udp_init(void)
{
	inet_proto_register(&udp_proto);
}

