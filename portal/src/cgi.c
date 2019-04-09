#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "cJSON.h"
#include "message.h"
#include "sock.h"
#include "log.h"
#include "tools.h"
#include "protocol.h"
#include "connection.h"
#include "libcom.h"
#include <sys/stat.h>
#include <fcntl.h>

enum {

CGI_ERR_NAMEPASSWD = 10001,
CGI_ERR_OTHER = 10002
};

typedef struct user_info
{
	char name[20];		//字符串
	char pwd[20];		//字符串
	unsigned char mac[6];
	uint32 ipaddr;
}user_info_t;

typedef struct user_tel_info
{
	char tel[20];		//字符串
	char pwd[20];
	unsigned char mac[6];
}user_tel_info_t;

enum {
	CGI_ERR_FAIL = 10001,
	CGI_ERR_INPUT,
	CGI_ERR_MALLOC,
	CGI_ERR_EXIST,
	CGI_ERR_NONEXIST,
	CGI_ERR_FULL,
	CGI_ERR_NOLOGIN,
	CGI_ERR_NOSUPPORT,
	CGI_ERR_ACCOUNT_NOTREADY,
	CGI_ERR_TIMEOUT,
	CGI_ERR_FILE,
	CGI_ERR_RULE,
};
	
void strlower(char *s)
{
	int i;
	for(i=0;i<strlen(s);i++)//此处要从0开始计数，因为字符串第一个字符是s[0]
	{
		if(*(s+i)>=65 && *(s+i)<=92)
			*(s+i)+=32;
	}
}

int cgi_free_rcvbuf(void *rcv_buf)
{
	msg_t *msg = container_of(rcv_buf, msg_t, data);
	free((void *)msg);
	return 0;
}

int cgi_snd_msg(int cmd, void *snd, int snd_len, void **rcv, int *rcv_len)
{
	int temp_fd = 0, len = 0, ret = -1;
	char file_temp[20] = {0};
	msg_t *snd_msg = NULL;
	msg_t *rcv_msg = NULL;
	socket_t *temp_sock = NULL;
	int8 *rcv_buf = NULL;
	strcpy(file_temp, "/tmp/test.XXXXXX");
	snd_msg = malloc(sizeof(msg_t));
	
	snd_msg->cmd = cmd;
	snd_msg->dmid = MODULE_GET(cmd);
	snd_msg->dlen = snd_len;
	if ((temp_fd = mkstemp(file_temp)) < 0) {
		CGI_LOG(LOG_ERR, "mktemp sock error\n");
		goto out;
	}
	temp_sock = unix_sock_init(file_temp);
	
	sock_addr_u dst_addr;
	dst_addr.un_addr.sun_family = AF_UNIX;
	memset(dst_addr.un_addr.sun_path, 0, sizeof(dst_addr.un_addr.sun_path));
	snprintf(dst_addr.un_addr.sun_path, sizeof(dst_addr.un_addr.sun_path)-1, "/tmp/%d_rcv", MODULE_GET(snd_msg->cmd));
	if (!temp_sock)
		goto out;
	len = sock_sendmsg_unix(temp_sock, snd_msg, sizeof(msg_t), snd, snd_len, &dst_addr);
	
	if (len <= 0)
		goto out;
	rcv_buf = malloc(2048);
	len = sock_recvfrom(temp_sock, rcv_buf, 2048, NULL);
	if (len <= 0)
		goto out;
	rcv_msg = rcv_buf;
	ret = rcv_msg->result;
	if (ret || !rcv || !rcv_len)
		goto out;
	*rcv = rcv_msg->data;
	*rcv_len = rcv_msg->dlen;

out:
	if (temp_fd > 0)
		close(temp_fd);
	if (snd_msg)
		free(snd_msg);
	if (temp_sock) 
		sock_delete(temp_sock);
	if (ret) {
		if (rcv && rcv_len) {
			*rcv = NULL;
			*rcv_len = 0;
		}
		if (rcv_buf)
			free(rcv_buf);
	} else {
		if (!rcv || !rcv_len) {
			if (rcv_buf)
				free(rcv_buf);
		}
	}
	return ret;
}

int cgi_sys_auth_handler(connection_t *con)
{
	char *name = con_value_get(con,"name");
	char *pwd = con_value_get(con, "pwd");
	char *mac = con_value_get(con,"mac");
	char *vlan = con_value_get(con,"vlan");
	char *user_ip = con_value_get(con, "user_ip");
	user_query_info_t user;
	memset(&user, 0, sizeof(user));
	if (!name || !pwd || !mac || !vlan || !user_ip) {

		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}
		
	strncpy(user.username, name, sizeof(user.username) - 1);
	strncpy(user.password, pwd, sizeof(user.password) - 1);
	strncpy(user.user_ip, user_ip, sizeof(user.user_ip) -1);
	strncpy(user.mac, mac, sizeof(user.mac) -1);
	user.vlan = atoi(vlan);
	
	if (cgi_snd_msg(MSG_CMD_RADIUS_USER_AUTH, &user, sizeof(user), NULL, NULL) == 0) {
		cJSON_AddNumberToObject(con->response, "code", 0);
	} else {
		cJSON_AddNumberToObject(con->response, "code", 1);
	}
	
out:
	return 1;
	
}

int cgi_sys_login_handler(connection_t *con)
{
	char *mac = con_value_get(con,"mac");
	char *ip = con_value_get(con,"ip");
	user_info_t user= {{0}, {0}, {0}, 0};
	struct in_addr user_ip;
	user_ip.s_addr = inet_addr(ip);
	
	strncpy(user.name, "18202822785", sizeof(user.name) - 1);
	strncpy(user.pwd, "1231245", sizeof(user.pwd) - 1);
	str2mac(mac, user.mac);
	user.ipaddr = user_ip.s_addr;
	
	if (cgi_snd_msg(MSG_CMD_RADIUS_USER_AUTH, &user, sizeof(user), NULL, NULL) == 0) {
		con->html_path = "portal/auth_success.html";
	} else {
		con->html_path = "portal/auth_fail.html";
	}
	
out:
	return 0;	
}

int cgi_sys_query_handler(connection_t *con)
{	
	char *user_ip = getenv("REMOTE_ADDR");
	char *user_agent = getenv("HTTP_USER_AGENT");
	char *temp_agent = NULL;
	int os_type = -1, i = 0, ret = -1;
	char *phone_os[8] = {"iphone", "ipad", "ipod", "android", "linux", "blackberry",
						"symbianos", "windows phone"};
	char *pc_os[4] = {"mac", "hpwos", "windows", "ie"};

	user_query_info_t user;
	memset(&user, 0, sizeof(user_query_info_t));
	if (user_agent) {
		strncpy(user.user_agent, user_agent, sizeof(user.user_agent) - 1);
		strlower(user_agent);
		for (i = 0; i < 8; i++) {
			temp_agent = strstr(user_agent, phone_os[i]);
			if (temp_agent) {
				os_type = 0;
				break;
			}
		}
		if (os_type == -1) {
			for (i = 0; i < 4; i++) {
				temp_agent = strstr(user_agent, pc_os[i]);
				if (temp_agent) {
					os_type = 1;
					break;
				}
			}
		}
	}else {
		strcpy(user.user_agent, 
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
			"AppleWebKit/537.36 (KHTML, like Gecko) "
			"Chrome/60.0.3112.101 Safari/537.36");
	}
	
//	if (!mac || !user_ip || !vlan) {
//		con->html_path = "portal/error.html";
//		html_tag_add(&con->tag_list, "zc:error", "error_input");
//		goto out;
//	}
	if (!user_ip) {
		con->html_path = "portal/error.html";
		html_tag_add(&con->tag_list, "zc:error", "error_input");
		goto out;
	}
	char *mac = arp_get(user_ip);
	char *vlan = "1";
	strncpy(user.mac, mac, sizeof(user.mac) - 1);
	user.vlan = atoi(vlan);
	strncpy(user.user_ip, user_ip, sizeof(user.user_ip) - 1);
	user.auth_type = 1;
	if (os_type == 1)
		con->html_path = "portal/module/pc/mobileAuth.html";
	else
		con->html_path = "portal/module/mobile/mobileAuth.html";
	
	user_query_info_t *query_back = NULL;
	int rcv_len = 0;
	ret = cgi_snd_msg(MSG_CMD_MANAGE_USER_QUERY, &user, sizeof(user), &query_back, &rcv_len);
	if (ret == 0 && query_back->if_exist == 0) {   //0为存在该用户
  		
		html_tag_add(&con->tag_list, "jfwx:tel", query_back->username);
		html_tag_add(&con->tag_list, "jfwx:pwd", query_back->password);
		html_tag_add(&con->tag_list, "jfwx:mac", query_back->mac);
		char tem_vlan[6] = {0};
		snprintf(tem_vlan, 5, "%d", query_back->vlan);
		html_tag_add(&con->tag_list, "jfwx:vlan", tem_vlan);
		html_tag_add(&con->tag_list, "jfwx:user_ip", query_back->user_ip);
		html_tag_add(&con->tag_list, "jfwx:isOld", "1");
	
	} else if (ret == 0 && query_back->if_exist == 1){
		html_tag_add(&con->tag_list, "jfwx:mac", mac);
		char tem_vlan[6] = {0};
		snprintf(tem_vlan, 5, "%d", user.vlan);
		html_tag_add(&con->tag_list, "jfwx:vlan", tem_vlan);
		html_tag_add(&con->tag_list, "jfwx:user_ip", user.user_ip);
		html_tag_add(&con->tag_list, "jfwx:isOld", "0");
	} else {
		con->html_path = "portal/error.html";
	}
	CGI_LOG(LOG_DEBUG, "before free\n");
	if (ret == 0)
		cgi_free_rcvbuf(query_back);
	CGI_LOG(LOG_DEBUG, "after free\n");
	
out:
	if (mac)
		free(mac);
	return 0;
}

int cgi_sys_user_register_handler(connection_t *con)
{	
	int ret = 1;
	char *name = con_value_get(con,"name");
	char *pwd = con_value_get(con, "pwd");
	char *mac = con_value_get(con,"mac");
	char *vlan = con_value_get(con,"vlan");
	char *user_ip = con_value_get(con, "user_ip");
	CGI_LOG(LOG_DEBUG, "new user register come name: %s, pwd: %s, msc: %s\n", name, pwd, mac);
	user_query_info_t user;
	memset(&user, 0, sizeof(user));
	user.auth_type = 1;
	
	if (!name || !pwd || !mac || !vlan) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}
		
	strncpy(user.username, name, sizeof(user.username) - 1);
	strncpy(user.password, pwd, sizeof(user.password) - 1);
	strncpy(user.mac, mac, sizeof(user.mac) - 1);
	strncpy(user.user_ip, user_ip, sizeof(user.user_ip) - 1);
	user.vlan = atoi(vlan);
	ret = cgi_snd_msg(MSG_CMD_MANAGE_USER_REGISTER, &user, sizeof(user), NULL, NULL);

	if ( ret== 0) {
		cJSON_AddNumberToObject(con->response, "code", 0);
	} else if (ret == 3){
		cJSON_AddNumberToObject(con->response, "code", 3);
	} else {
		cJSON_AddNumberToObject(con->response, "code", 1);
	}
out:
	return 1;
}

int cgi_sys_text_code_handler(connection_t *con)
{	
	char *name = con_value_get(con,"name");
//	char *mac = con_value_get(con,"mac");

	user_query_info_t user;
	memset(&user, 0, sizeof(user));
	user.auth_type = 1;
	
	if (!name) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}
		
	strncpy(user.username, name, sizeof(user.username) - 1);
	int code = -1;
	code = cgi_snd_msg(MSG_CMD_MANAGE_TEXT_SEND, &user, sizeof(user), NULL, NULL);
	cJSON_AddNumberToObject(con->response, "code", code);
	
out:
	return 1;
}

int cgi_sys_start_app_handler(connection_t *con)
{	
	char *app = con_value_get(con, "app");
	if (!app) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}

	
	if (cgi_snd_msg(MSG_CMD_MANAGE_START_APP, app, strlen(app) + 1, NULL, NULL) == 0) {
		cJSON_AddNumberToObject(con->response, "code", 0);
	} else {
		cJSON_AddNumberToObject(con->response, "code", 1);
	}
out:
	return 1;
}

int cgi_sys_stop_app_handler(connection_t *con)
{	
	char *app = con_value_get(con, "app");
	if (!app) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}

	
	if (cgi_snd_msg(MSG_CMD_MANAGE_STOP_APP, app, strlen(app) + 1, NULL, NULL) == 0) {
		cJSON_AddNumberToObject(con->response, "code", 0);
	} else {
		cJSON_AddNumberToObject(con->response, "code", 1);
	}
out:
	return 1;
}




