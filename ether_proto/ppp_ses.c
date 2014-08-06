
#define aligned_u64 unsigned long long __attribute__((aligned(8))) 
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include "../ether_proto.h"
#include "../utils.h"

static int ppp_ses_handler(struct pkt_buff *pb)
{
	struct pppoe_hdr *ph;
        int ret = 0;
        unsigned int len;

        if ((pb->tail - pb->data) < sizeof(struct pppoe_hdr))
                goto hdr_error;

	pb->data = pb->data + sizeof(struct pppoe_hdr) + 2;
        pb_set_network_header(pb, (pb->data - pb->head));

        //printf("saddr:%s daddr:%s\n", ip2str(ntohl(iph->saddr)), ip2str(ntohl(iph->daddr)));

        inet_proto_handler(pb);

        return 0;

hdr_error:
        DBGMSG("ppp_ses header error!\n");
        return -1;
}


static struct ether_proto ppp_ses_proto = {
        .name           = "PPPOES",
        .proto          = ETH_P_PPP_SES,
        .handler        = ppp_ses_handler,
};

void __init ppp_ses_init(void)
{
        ether_proto_register(&ppp_ses_proto);
}

