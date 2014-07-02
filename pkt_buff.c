#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkt_buff.h"


void pkt_dump(struct pkt_buff *pb)
{
	char tmp[80];
	const unsigned char *p = pb->head;
	char *t = tmp;
	int i, len = pb->len;

	printf("===============dump pkt====================\n");

	for (i = 1; i <= len; i++) {
		t += sprintf(t, "%02x ", *p++ & 0xff);
		if ((i & 0x0f) == 0) {
			printf("%04x:  %s\n", i, tmp);
			t = tmp;
		}
	}

	if (i & 0x07)
		printf("%04x:  %s\n", (i + 16 - (i%16)), tmp);

	printf("===========================================\n");
}

struct pkt_buff *pkt_alloc(const unsigned char *packet, struct pcap_pkthdr *header)
{
	struct pkt_buff *pb;

	pb = malloc(sizeof(struct pkt_buff));
	if(!pb)
		return NULL;

	pb->len = header->caplen;
	pb->transport_header = pb->network_header = pb->mac_header = 0;
	pb->head = pb->data = (unsigned char *) malloc(header->caplen);
	pb->tail = pb->head + pb->len;
	memcpy(pb->head, packet, header->caplen);

	return pb;
}

void pkt_free(struct pkt_buff *pb)
{
	free(pb->head);
	pb->head = pb->data = pb->tail = NULL;
	pb->len = pb->transport_header = pb->network_header = pb->mac_header = 0;
	free(pb);
}
