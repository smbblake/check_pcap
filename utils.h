#ifndef _UTILS_H
#define _UTILS_H

#if 1
#define DBGMSG(fmt, args...) printf("%s(%d): " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define DBGMSG(fmt, args...)
#endif

#define DBENTER() DBGMSG("Enter %s\n", __FUNCTION__)
#define DBLEAVE() DBGMSG("Leave %s\n", __FUNCTION__)

extern unsigned int str2ip(char *ip);
extern char *ip2str(unsigned int ip);

#endif
