#ifndef _TOOLS_H_
#define _TOOLS_H_
#include "type.h"

extern char *mac2str(uint8 *mac);
extern int str2mac(char *str, unsigned char *mac);
extern int macformat(char *mac, char split);
extern void urlencode(const unsigned char *s, char *t);
extern void urldecode(char *p);

#endif