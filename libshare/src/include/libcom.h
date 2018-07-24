#ifndef __LIBCOM_H__
#define __LIBCOM_H__
#include "list.h"
typedef struct user_query_info
{
	int auth_type;
	char username[32];
	char password[32];
	char mac[32];
	int vlan;
	int if_exist;
	char user_ip[32];
	char user_agent[256];
	struct list_head user_list;
}user_query_info_t;


extern int igd_md5sum(char *file, void *md5);
extern time_t uptime();
extern unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base);
extern char * strdup(const char *s);



#define IGD_BITS_LONG (sizeof(long)*8)
#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(n) ((n + (sizeof(long)*8) - 1)/ (sizeof(long)* 8))
#endif
#define MAC_SPLIT(mac) mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]


#endif

