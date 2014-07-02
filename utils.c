#include <stdio.h>
#include <string.h>
#include "utils.h"


unsigned int str2ip(char *ip)
{
	unsigned char buf[4];
	unsigned int rst;

	if(ip && !strlen(ip))
		return 0;

	if(sscanf(ip, "%hhd.%hhd.%hhd.%hhd", &buf[3], &buf[2], &buf[1], &buf[0]) != 4)
		return 0;

	rst = *((unsigned int *) buf);

	return rst;
}

char *ip2str(unsigned int ip)
{
	static char buf[4][20];
	static int index = 0;
	unsigned char *ptr = (unsigned char *) &ip;

	index = (index + 1) % 4;
	sprintf(buf[index], "%hhu.%hhu.%hhu.%hhu", ptr[3], ptr[2], ptr[1], ptr[0]);
	return buf[index];
}

