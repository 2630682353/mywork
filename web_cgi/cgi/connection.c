#include <stdlib.h>
#include "connection.h"
#include <string.h>
#include <stdio.h>
void connection_free(connection_t *con);

void v_list_init (v_list_t *head)
{
	head->next = NULL;
}

int v_list_add(v_list_t *head, char*key, char*value)
{
	v_list_t *list;
	
	list = malloc(sizeof(v_list_t));
	if(list == NULL)
		return -1;
	list->key = strdup(key);
	if (list->key== NULL) {
		free(list);
		return -1;
	}
	list->value = strdup(value);
	list->next = head->next;
	if (list->value== NULL) {
		free(list->key);
		free(list);
		return -1;
	}
	head->next = list;
	return 0;
}

char *v_list_get(v_list_t *head, char*key)
{
	v_list_t *p;
	
	for(p = head->next; p; p = p->next) {
		if (strcmp(key, p->key) == 0) {
			return p->value;
		}
	}
	return NULL;
}
void v_list_free(v_list_t *head)
{
	v_list_t *p;
	v_list_t *q;
	
	for(p = head->next; p; p = q) {
		free(p->key);
		free(p->value);
		q = p->next;
		free(p);
	}
	head->next = NULL;
}

char *con_value_get(connection_t *con, char*key)
{
	return v_list_get(&con->head, key);
}

void connection_parse(connection_t *con, char *src)
{
	char*key = src;
	char *pend;
	char *value;
	
	while (key != NULL) {
		pend=strchr(key,'&');
		if(pend != NULL){
			*pend = '\0';
			pend++;
		}
		value = strchr(key,'=');
		if(value == NULL){
			key = pend;
			continue;
		}
		*value++ = '\0';
		v_list_add(&con->head,key,value);
		key = pend;
	}
	return;
}

void connection_handel(connection_t *con)
{
	char *query = getenv("QUERY_STRING");
	connection_parse(con, query);
	int error = 0;
	error = cgi_protocol_handler(con, con->response);
	cJSON_AddNumberToObject(con->response, "error", error);
	char *out;
	out = cJSON_Print(con->response);
	printf("%s\r\n\r\n","application/json");
	printf("%s", out);
	free(out);
}


void connection_init(connection_t *con)
{
	con->response = cJSON_CreateObject();
	con->free = connection_free;
	v_list_init(&con->head);
	con->function = -1;
}
void connection_free(connection_t *con)
{
	v_list_free(&con->head);
	cJSON_Delete(con->response);
}

int connection_is_set(connection_t *con)
{
	char* function = NULL;
	
	if (con->function != -1)
		return con->function;
	function = con_value_get(con, "function");
	if (function == NULL)
		return -1;
	if (strcmp(function, "get") == 0) {
		con->function = 0;
		return 0;
	} else if (strcmp(function, "set") == 0) {
		con->function = 1;
		return 1;
	}
	return -1;
}