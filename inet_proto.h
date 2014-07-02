#ifndef _INET_PROTO_H
#define _INET_PROTO_H

#include "pkt_buff.h"
#include "list.h"

#define __init __attribute__((constructor))

struct inet_proto {
	char 			*name;
	unsigned short		proto;	/* Please see /usr/include/linux/in.h */
	int			(*handler)(struct pkt_buff *pb);
	struct list_head	list;
};


extern void inet_proto_register(struct inet_proto *iprot);
extern void inet_proto_handler(struct pkt_buff *pb);


#endif
