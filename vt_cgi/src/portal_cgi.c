#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "message.h"
#include "log.h"
#include "protocol.h"
#include "connection.h"


int main()
{
/*
	char *str_len = NULL;
	int len = 0;
	char buf[100] = {0};
	user_info_t user;
	cJSON *root;
	char *out = NULL;	
	int ret = -1;
	
	str_len = getenv("CONTENT_LENGTH");
	if ((str_len == NULL) || (sscanf(str_len, "%d", &len)!=1) || (len>80)) {
	
		root = cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"login",0);
		cJSON_AddNumberToObject(root,"error",CGI_ERR_OTHER);
		goto reply_print;
	}
	fgets(buf, len+1, stdin);
	memset(&user, 0, sizeof(user_info_t));
	sscanf(buf, "name=%[^&]&password=%s",user.name,user.pwd);
	memset(user.mac, 0xFF, 6);
	root = cJSON_CreateObject();
	ret = auth_handle(&user);
	cJSON_AddNumberToObject(root,"login",0);
	cJSON_AddNumberToObject(root,"error",ret);

reply_print:
	printf("%s\r\n\r\n","Content-Type:application/json;charset=UTF-8"); 

	out=cJSON_Print(root);
	cJSON_Delete(root);
	printf("%s\n", out);
	if (out)
		free(out);
*/
	connection_t con;
	connection_init(&con);
	connection_handel(&con);
	con.free(&con);
	return 0;
}