#include <stdlib.h>
#include "connection.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "log.h"
void connection_free(connection_t *con);

int replace_str(char *src, char *match_str, char *replace_str)
{
        int  string_len, ret = -1;
		int max_len = strlen(src) + 1000;
        char *new_str = malloc(max_len);

        char *find_pos = strstr(src, match_str);
        if( (!find_pos) || (!new_str) )
                goto out;

        while( find_pos )
        {
                memset(new_str, 0, max_len);
                string_len = find_pos - src;
                memcpy(new_str, src, string_len);
                memcpy(new_str + string_len, replace_str, strlen(replace_str));
                char *left = find_pos + strlen(match_str);
                memcpy(new_str + string_len + strlen(replace_str), left, strlen(left));
                memcpy(src, new_str, strlen(new_str) + 1);
                find_pos = strstr(src, match_str);
        }
		ret = 0;
out:
	if (new_str)
		free(new_str);
	return ret;
	
}

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

void urldecode(char *p)  
{  
	register i=0;  
	while(*(p+i))  
	{  
	   if ((*p=*(p+i)) == '%')  
	   {  
	    *p=*(p+i+1) >= 'A' ? ((*(p+i+1) & 0XDF) - 'A') + 10 : (*(p+i+1) - '0');  
	    *p=(*p) * 16;  
	    *p+=*(p+i+2) >= 'A' ? ((*(p+i+2) & 0XDF) - 'A') + 10 : (*(p+i+2) - '0');  
	    i+=2;  
	   }  
	   else if (*(p+i)=='+')  
	   {  
	    *p=' ';  
	   }  
	   p++;  
	}  
	*p='\0';  
} 

int html_tag_add(struct list_head *list, char *key, char *value) 
{
	html_tag_t *ht = malloc(sizeof(html_tag_t));
	ht->key = strdup(key);
	ht->value = strdup(value);
	list_add(&ht->list, list);
	return 0;
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
		urldecode(value);
		v_list_add(&con->head,key,value);
		key = pend;
	}
	return;
}

void connection_handel(connection_t *con)
{
	char *query = getenv("QUERY_STRING");
	connection_parse(con, query);
	char *str_len = NULL;
	str_len = getenv("CONTENT_LENGTH");
	int len = 0, file_size = 0, ret = 0;
	char buf[100] = {0};
	FILE *file = NULL;
	char *out_buf = NULL;
	html_tag_t *ht = NULL;
	struct stat st;
	
	if ((str_len == NULL) || (sscanf(str_len, "%d", &len)!=1) || (len>300)) {
		
	} else {
		fgets(buf, len+1, stdin);
		connection_parse(con, buf);
	}
	
	con->html_path = "portal/error.html";
	ret = cgi_protocol_handler(con);
	CGI_LOG(LOG_DEBUG, "ret = %d\n", ret);
	if (ret == 1) {
		printf("%s\r\n\r\n","Content-Type:application/json;charset=UTF-8");		
		char *str = cJSON_PrintUnformatted(con->response);
		if (str) {
			printf("%s", str);
			free(str);
		}
		
	} else if (ret == 0){
		printf("%s\r\n\r\n","Content-Type:text/html;charset=UTF-8");
		file = fopen(con->html_path,"r");    
		if(stat(con->html_path, &st)) {
			CGI_LOG(LOG_ERR, "html stat index error\n"); 
			goto out;
		} else {
		
			file_size = st.st_size;     //获取文件大小   
			out_buf = malloc(file_size + 1000);   
			memset(out_buf,'\0',file_size+1000);   
			fread(out_buf, sizeof(char), file_size, file);
			
			list_for_each_entry(ht, &con->tag_list, list) {	
				replace_str(out_buf, ht->key, ht->value);		
			}
			printf("%s\n", out_buf);
		}
	}
		
out:
	if (out_buf)
		free(out_buf);
	if (file)
		fclose(file);

/*
	cJSON_AddNumberToObject(con->response, "error", error);
	char *out;
	out = cJSON_Print(con->response);
	printf("%s\r\n\r\n","application/json");
	printf("%s", out);
	free(out);
*/
}


void connection_init(connection_t *con)
{
	con->response = cJSON_CreateObject();
	con->free = connection_free;
	v_list_init(&con->head);
	INIT_LIST_HEAD(&con->tag_list);
	con->html_path = NULL;
	con->function = -1;
}
void connection_free(connection_t *con)
{
	v_list_free(&con->head);
	cJSON_Delete(con->response);
	html_tag_t *p = NULL, *next = NULL;
	list_for_each_entry_safe(p, next, &con->tag_list, list){
		free(p->key);
		free(p->value);
		list_del(&p->list);
		free(p);
	}
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
