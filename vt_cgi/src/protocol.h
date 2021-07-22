#ifndef _http_protocol_h_
#define _http_protocol_h_
#include "connection.h"

#define PRO_BASE_ARG_ERR 20100000


typedef struct _cgi_protocol_t{
	const char *name;
	int (*handler)(connection_t *);
}cgi_protocol_t;

extern cgi_protocol_t *find_pro_handler(const char *pro_opt);



#endif