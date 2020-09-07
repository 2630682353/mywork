#ifndef __connection_h_
#define __connection_h_
#include <stdlib.h>
#include "cJSON.h"
typedef struct v_list{
	char *key;
	char *value;
	struct v_list *next;
}v_list_t;

typedef struct connection{
	v_list_t head;
	cJSON *response;
	void (*free)(struct connection*);
	int function;
}connection_t;

extern void connection_init(connection_t *con);
extern void connection_parse(connection_t *con, char *src);
extern char *con_value_get(connection_t *con, char*key);
#endif