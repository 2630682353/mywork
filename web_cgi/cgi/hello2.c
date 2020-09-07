#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "connection.h"

extern int set_session(char *name,char *pwd);
extern int start_session();
extern void kill_session();
extern void clean_session_file();

int main()
{
	char *str_len = NULL;
	int len = 0;
	char buf[100] = {0};
	char user[20] ={0};
	char passwd[20] = {0};
	int err = 0;
	if (err = start_session()) {
		cJSON *root;
		char *out;	
		str_len = getenv("CONTENT_LENGTH");
		if ((str_len == NULL) || (sscanf(str_len, "%d", &len)!=1) || (len>80)) {
			printf("%s\r\n\r\n","application/json");	
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root,"opt","check_login");
			cJSON_AddStringToObject(root,"function","get");
			cJSON_AddNumberToObject(root,"login",0);
			cJSON_AddNumberToObject(root,"error",10007);
			out=cJSON_Print(root);
			cJSON_Delete(root);
			printf("%s\n", out);
			free(out);
			return 0;
		}
		fgets(buf, len+1, stdin);
		sscanf(buf, "name=%[^&]&password=%s",user,passwd);
		if((strcmp(user,"admin")==0)&&(strcmp(passwd,"admin")==0)){
			set_session(user,passwd);
			printf("%s\r\n\r\n","application/json");
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root,"opt","check_login");
			cJSON_AddStringToObject(root,"function","get");
			cJSON_AddNumberToObject(root,"login",1);
			cJSON_AddNumberToObject(root,"error",0);
			out=cJSON_Print(root);
			cJSON_Delete(root);
			printf("%s\n", out);
			free(out);
			return 0;
		}
		else {
			printf("%s\r\n\r\n","application/json");
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root,"opt","check_login");
			cJSON_AddStringToObject(root,"function","get");
			cJSON_AddNumberToObject(root,"login",0);
			cJSON_AddNumberToObject(root,"error",10007);
			cJSON_AddNumberToObject(root,"login_error",1);
			out=cJSON_Print(root);
			cJSON_Delete(root);
			printf("%s\n", out);
			free(out);
			return 0;
		}
	}
	connection_t con;
	connection_init(&con);
	connection_handel(&con);
	con.free(&con);
	return 0;
}