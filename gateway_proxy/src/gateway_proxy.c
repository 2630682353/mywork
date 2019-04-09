#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include    "cJSON.h"
#include	"message.h"
#include    "nlk_ipc.h"
#include    "log.h"
#include    "def.h"
#include    "list.h"
#include    "uci_fn.h"
#include    "tools.h"
#include    "cpu.h"
#include    "dpi.h"
#include    "igd_md5.h"
#include <errno.h>
#include <fcntl.h>
#include "timer.h"
#include "libcom.h"
#include <sys/wait.h>
#include <unistd.h>
#include <curl/curl.h>

#define MAX_JSON_LEN 2048

#define PORTAL_FILE "/tmp/portal.tar.gz"
#define SYSBIN_FILE "/tmp/openwrt-ramips-mt7621-mt7621-squashfs-sysupgrade.bin"
#define NETWORK_FILE "/tmp/network"
#define WIFI_FILE   "/tmp/wireless"

#define PORTAL_WEB_DIR "/www/"
#define HTTP_TIMEOUT  5

enum task_id {
	TASK_SYSTEM_REBOOT   = 100,
	TASK_SYSTEM_UPGRADE  = 101,           
	TASK_NETWORK_UPDATE     = 200,  
	TASK_WIFI_UPDATE       = 201,
	TASK_PORTAL_HTML_UPDATE   = 300,        
	TASK_PORTAL_RADIUS_UPDATE = 301
};


static int pipefd[2];
static LIST_HEAD(query_user_list);
pthread_mutex_t query_mutex;
pthread_mutex_t text_mutex;
pthread_mutex_t have_send_text_mutex;
pthread_mutex_t authing_mutex;
static int heart_beat_interval = 60;
static int queryuser_cache_time = 60;
static int dropbear_time = 600;

typedef struct portal_cfg_st{
    int32 apply;/*0:interface; 1:vlan*/
    union {
        int8 ifname[IFNAME_SIZE];
        uint16 vlan_id;
    };
    int8 url[URL_SIZE];
}portal_cfg_t;

enum {
	TASK_UPDATE_POTAL_HTML,
	TASK_UPDATE_AAA_ADDRESS,
	TASK_UPDATE_ADVERTISE_JS,
	TASK_UPDATE_SYSTEM_FIRMWARE
};

typedef struct gateway_info {
	char mac[20];
	char hard_version[8];
	char soft_version[8];
	char vendor[20];
	char cpu_load[32];
	char wan_mode[8];
	char ssid[32];
	int memory_total;
	int memory_free;
	int disk_total;
	int disk_available;
	char wan_ip[20];
	char lan_ip[20];
	char v3_ip[20];
	char v4_ip[20];
	char v5_ip[20];
	int date;
	int uptime;
	char token_url[128];
	char text_code_url[128];
	char user_query_url[128];
	char user_register_url[128];
	char gmc_url_result[128];
	char gmc_url_heart[128];
	char text_str[128];
}gateway_info_t;

typedef struct advertising_cfg_st{
    uint32 id;
    int32 type;
    int8 url[URL_SIZE];
}advertising_cfg_t;

typedef enum ads_policy_en{
    ADS_POLICY_NONE           = 0x00, /*none*/
    ADS_POLICY_TIME_INTERVAL  = 0x01, /*time interval*/
    ADS_POLICY_FLOW_INTERVAL  = 0x02, /*flow interval*/
    ADS_POLICY_EVERYTIME      = 0x04  /*everytime. valid when ads->type is ADS_TYPE_EMBED*/
}ads_policy_e;
/*advertising option*/
typedef enum ads_option_en{
    ADS_OPTION_RANDOM   = 0x00, /*random*/
    ADS_OPTION_LOOPING  = 0x01  /*looping*/
}ads_option_e;

typedef struct advertising_policy_st{
    int32 policy;
    int32 option;
    int32 type;
    uint64 time_interval;
    uint64 flow_interval;
}advertising_policy_t;

static gateway_info_t gateway;

static LIST_HEAD(tel_text_users);    
static LIST_HEAD(authing_users); 
static LIST_HEAD(have_send_tel_text);

typedef struct token_info_st{
	char token_val[64];
	int token_time;
	int if_lgoin;
}token_info_t;

static token_info_t gw_token;

int report_task(int id, int code,int result, char *msg);
int gateway_info_update();

size_t receive_data(void *buffer, size_t size, size_t nmemb, void *receive_buf) {
	GATEWAY_LOG(LOG_INFO, "receive_data: %s\n", buffer);
	int origin_len = strlen(receive_buf);
	int rlen = size*nmemb;
	if (origin_len + rlen > 4096)
		return -1;
    memcpy((char *)receive_buf + origin_len, buffer, rlen);
	((char *)receive_buf)[rlen + origin_len] = '\0';
    return rlen;
}

int http_send(char *url, cJSON *send, cJSON **recv, char *http_headers[])
{
	int ret = -1;
	char *jstr = NULL, *back_str = NULL;
	cJSON *obj = NULL;
	back_str = (char*)malloc(4096);
	memset(back_str, 0, 4096);
	
	char header_str[256] = {0};

	struct curl_slist *headers = NULL;
	CURLcode res = CURLE_OK;
	CURL *mycurl = curl_easy_init();
	snprintf(header_str, sizeof(header_str) - 1, "DevMac: %s", gateway.mac);
	headers = curl_slist_append(headers, header_str);
	if (http_headers) {
		int i = 0;
		while (http_headers[i]) {
			headers = curl_slist_append(headers, http_headers[i]);
			i++;
		}

	}
		
	if (!mycurl)
		goto out;
	curl_easy_setopt(mycurl, CURLOPT_URL, url);
	curl_easy_setopt(mycurl, CURLOPT_TIMEOUT, HTTP_TIMEOUT); 
	curl_easy_setopt(mycurl, CURLOPT_WRITEFUNCTION, receive_data);
	curl_easy_setopt(mycurl, CURLOPT_WRITEDATA, back_str);
	
	if (!send) {
		curl_easy_setopt(mycurl, CURLOPT_HTTPHEADER, headers);
		res = curl_easy_perform(mycurl);

	} else {
		snprintf(header_str, sizeof(header_str) - 1, "Content-Type:application/json");
		headers = curl_slist_append(headers, header_str); 
		jstr = cJSON_PrintUnformatted(send); 
		GATEWAY_LOG(LOG_DEBUG, "http send %s\n", jstr);
		curl_easy_setopt(mycurl, CURLOPT_HTTPHEADER, headers); 
		curl_easy_setopt(mycurl, CURLOPT_POSTFIELDS, jstr); 
		res = curl_easy_perform(mycurl);
	}
	if (res != CURLE_OK) {
		GATEWAY_LOG(LOG_WARNING, "curl_easy_perform() failed: %d\n", res);
		goto out;
    }
	GATEWAY_LOG(LOG_DEBUG, "http recv %s\n", back_str);
	obj = cJSON_Parse(back_str);
	if (!obj)
		goto out;
	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result)
		goto out;
	ret = result->valueint;
	if (ret)
		goto out;
	*recv = obj;
out:
	if (back_str)
		free(back_str);
	if (jstr)
		free(jstr);
	if (ret) {
		recv = NULL;
		if (obj)
			cJSON_Delete(obj);
	}
	if (headers)
		curl_slist_free_all(headers);
	curl_easy_cleanup(mycurl);
	return ret;
}

int get_token()
{
	char *back_str = NULL;
	char temp_url[1024] = {0};
	int ret = -1;
	cJSON *obj = NULL;
	back_str = (char*)malloc(4096);
	memset(back_str, 0, 4096);
	gw_token.token_time = time(NULL);


	CURLcode res = CURLE_OK;
	CURL *mycurl = curl_easy_init();
	snprintf(temp_url, sizeof(temp_url) - 1, "%s%d", gateway.token_url, gw_token.token_time);

	if (!mycurl)
		goto out;
	curl_easy_setopt(mycurl, CURLOPT_URL, temp_url);
	curl_easy_setopt(mycurl, CURLOPT_TIMEOUT, HTTP_TIMEOUT); 
	curl_easy_setopt(mycurl, CURLOPT_WRITEFUNCTION, receive_data);
	curl_easy_setopt(mycurl, CURLOPT_WRITEDATA, back_str);
	res = curl_easy_perform(mycurl);

	if (res != CURLE_OK) {
		GATEWAY_LOG(LOG_ERR, "get tocken curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto out;
    }
	GATEWAY_LOG(LOG_DEBUG, "token back: %s\n", back_str);
	obj = cJSON_Parse(back_str);
	if (!obj)
		goto out;
	cJSON *code = cJSON_GetObjectItem(obj, "code");
	if (!code || code->valueint)
		goto out;
	cJSON *data = cJSON_GetObjectItem(obj, "data");
	if (!data || !data->valuestring)
		goto out;
	strncpy(gw_token.token_val, data->valuestring, sizeof(gw_token.token_val) - 1);
	gw_token.if_lgoin = 1;
	ret = 0;
out:
	if (obj)
		cJSON_Delete(obj);
	if (back_str)
		free(back_str);
	curl_easy_cleanup(mycurl);
	return ret;
}

int query_list_clear(void *para)
{
	user_query_info_t *p= NULL, *n = NULL;
	pthread_mutex_lock(&query_mutex);
	list_for_each_entry_safe(p, n, &query_user_list, user_list) {
		list_del(&p->user_list);
		free(p);
	}
	pthread_mutex_unlock(&query_mutex);
	return 0;
}

int32 user_query_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{

	int ret = -1;
	cJSON *root = NULL, *obj = NULL;
	char url[128] = {0};
	root = cJSON_CreateObject();
	
	//if (!gw_token.if_lgoin)
	//	get_token();

	user_query_info_t *user_info = (user_query_info_t *)ibuf;
	user_query_info_t *p;
	/*已经查询过直接返回结果，查询信息在网关心跳里清空*/
	pthread_mutex_lock(&query_mutex);
	list_for_each_entry(p, &query_user_list, user_list) {
		if (strcmp(user_info->mac, p->mac) == 0 && user_info->auth_type == p->auth_type) {
			memcpy(obuf, p, sizeof(user_query_info_t));
			*olen = sizeof(user_query_info_t);
			ret = 0;
			pthread_mutex_unlock(&query_mutex);
			goto out;
		}
	}
	pthread_mutex_unlock(&query_mutex);
	cJSON_AddStringToObject(root, "userMac", user_info->mac);
	
	cJSON_AddNumberToObject(root, "userType", user_info->auth_type);

//	snprintf(url, sizeof(url) - 1, "%s%d/%s", gateway.user_query_url, 
//		gw_token.token_time, gw_token.token_val);
	snprintf(url, sizeof(url) - 1, "%s", gateway.user_query_url);

	char *headers[2] = {user_info->user_agent, NULL};
	
	ret = http_send(url, root, &obj, headers);
	
	user_query_info_t *qu = (user_query_info_t *)obuf;
	memcpy(qu, user_info, sizeof(user_query_info_t));
	qu->if_exist = ret;
	if (!ret) {
		cJSON *data = cJSON_GetObjectItem(obj, "data");
		if (!data || !data->child)
			goto out;
		
		cJSON *utype = cJSON_GetObjectItem(data, "userType");
		cJSON *umac = cJSON_GetObjectItem(data, "userMac");
		cJSON *uname = cJSON_GetObjectItem(data, "username");
		cJSON *upassword = cJSON_GetObjectItem(data, "password");
		if (!utype || !umac || !uname || !upassword)
			goto out;
		qu->auth_type = utype->valueint;
		strncpy(qu->mac, umac->valuestring, sizeof(qu->mac) - 1);
		strncpy(qu->username, uname->valuestring, sizeof(qu->username) - 1);
		strncpy(qu->password, upassword->valuestring, sizeof(qu->password) - 1);
		user_query_info_t *query_cache = malloc(sizeof(user_query_info_t));
		memcpy(query_cache, qu, sizeof(user_query_info_t));
		pthread_mutex_lock(&query_mutex);
		list_add(&query_cache->user_list, &query_user_list);
		pthread_mutex_unlock(&query_mutex);
	} else if (ret == 1) {
		strncpy(qu->mac, user_info->mac, sizeof(qu->mac) - 1);
		qu->auth_type = user_info->auth_type;
		user_query_info_t *query_cache = malloc(sizeof(user_query_info_t));
		memcpy(query_cache, qu, sizeof(user_query_info_t));
		pthread_mutex_lock(&query_mutex);
		list_add(&query_cache->user_list, &query_user_list);
		pthread_mutex_unlock(&query_mutex);
	} else {
		goto out;
	}
	*olen = sizeof(user_query_info_t);
	ret = 0;
out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	if (ret)
		*olen = 0;
	return ret;
}

int32 user_register_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{

	int ret = -1, matched = 0;
	cJSON *root = NULL, *obj = NULL;
	char url[128] = {0};
	user_query_info_t *user_info = ibuf;
	user_query_info_t *p = NULL, *n = NULL;
	/*验证码比较*/
	pthread_mutex_lock(&text_mutex);
	list_for_each_entry_safe(p, n, &tel_text_users, user_list) {
		if (strcmp(user_info->username, p->username) == 0 && 
				strcmp(user_info->password, p->password) == 0) {
			matched = 1;
			list_del(&p->user_list);
			free(p);
			break;
		}
	}
	pthread_mutex_unlock(&text_mutex);
	if (!matched) {
		ret = 3;
		goto out;
	}
	root = cJSON_CreateObject();
	
	cJSON_AddStringToObject(root, "userMac", user_info->mac);

	cJSON_AddNumberToObject(root, "userType", user_info->auth_type);
//	cJSON_AddStringToObject(root, "devIp", gateway.wan_ip);
	cJSON_AddStringToObject(root, "devMac", gateway.mac);
//	cJSON_AddStringToObject(root, "ssid", "jfwx608");
	cJSON_AddStringToObject(root, "username", user_info->username);
	cJSON_AddStringToObject(root, "password", user_info->password);

//	snprintf(url, sizeof(url) - 1, "%s%d/%s", gateway.user_register_url, 
//		gw_token.token_time, gw_token.token_val);

	snprintf(url, sizeof(url) - 1, "%s", gateway.user_register_url);

	if ((ret = http_send(url, root, &obj, NULL)))
		goto out;

	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result || result->valueint)
		goto out;
	/*删除查询用户不存在信息*/
	pthread_mutex_lock(&query_mutex);
	list_for_each_entry_safe(p, n, &query_user_list, user_list) {
		if (strcmp(user_info->mac, p->mac) == 0 && user_info->auth_type == p->auth_type) {
			list_del(&p->user_list);
			free(p);
		}
	}
	pthread_mutex_unlock(&query_mutex);
	
	ret = msg_send_syn(MSG_CMD_RADIUS_USER_AUTH, user_info, sizeof(user_query_info_t), NULL,0);

	*olen = 0;
out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	if (ret)
		*olen = 0;
	return ret;
}

int32 clear_tel(void *para)
{
	user_query_info_t *p;
	user_query_info_t *n;
	if (!para)
		return -1;
	pthread_mutex_lock(&have_send_text_mutex);
	list_for_each_entry_safe(p, n, &have_send_tel_text, user_list) {
		if (memcmp(p->username, para, strlen(p->username)) == 0) {
			list_del(&p->user_list);
			free(p);
		}
	}
	pthread_mutex_unlock(&have_send_text_mutex);
	return 0;
}

int32 send_tel_code_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	int ret = -1, verify_code = 0;
	cJSON *root = NULL, *obj = NULL;
	char *jstr = NULL, *back_str = NULL;
	char code_str[64] = {0};
	root = cJSON_CreateObject();

	user_query_info_t *user_info = ibuf;
	user_query_info_t *tel_temp;
	int matched = 0;
	pthread_mutex_lock(&have_send_text_mutex);
	list_for_each_entry(tel_temp, &have_send_tel_text, user_list) {
		if (memcmp(tel_temp->username, user_info->username, strlen(user_info->username)) == 0) {
			matched = 1;
			break;
		}
	}
	pthread_mutex_unlock(&have_send_text_mutex);
	if (matched) {
		ret = 2;
		goto out;
	}
	cJSON_AddStringToObject(root, "ecName", "成都捷通易科技有限公司");
	cJSON_AddStringToObject(root, "apId", "jty_io");
	cJSON_AddStringToObject(root, "secretKey", "jty3939");
	cJSON_AddStringToObject(root, "mobiles", user_info->username);
	verify_code = time(NULL); 
	verify_code = verify_code%1000000;
	snprintf(code_str, sizeof(code_str) - 1, "%06d", verify_code);
	cJSON_AddStringToObject(root, "content", code_str);
	cJSON_AddStringToObject(root, "sign", "jiwROAp1k");
	cJSON_AddStringToObject(root, "addSerial", "");
	

	oemMD5_CTX context;
	oemMD5Init(&context);
	char md5_before[1024] = {0};
	snprintf(md5_before, sizeof(md5_before) - 1, "成都捷通易科技有限公"
		"司jty_iojty3939%s%sjiwROAp1k", user_info->username, code_str);
	oemMD5Update(&context, md5_before, strlen(md5_before));
	unsigned char md5_after[16] = {0};
	oemMD5Final(md5_after, &context);
	char md5_temp[33] = {0};
	int i = 0;
	for (i=0;i<16;i++) {
		sprintf(&md5_temp[i*2], "%02x", md5_after[i]);
	}
	cJSON_AddStringToObject(root, "mac", md5_temp);
	jstr = cJSON_PrintUnformatted(root);
	GATEWAY_LOG(LOG_DEBUG, "http send %s\n", jstr);
	char base64str[2048] = {0};
	base64_encode(jstr, base64str);
	GATEWAY_LOG(LOG_DEBUG, "http send base64str %s\n", base64str);
	back_str = (char*)malloc(4096);
	memset(back_str, 0, 4096);
	
	struct curl_slist *headers = NULL;
	CURLcode res = CURLE_OK;
	CURL *mycurl = curl_easy_init();
	headers = curl_slist_append(headers, "Content-Type:application/json");
	if (!mycurl)
		goto out;
	curl_easy_setopt(mycurl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(mycurl, CURLOPT_URL, gateway.text_code_url);
	curl_easy_setopt(mycurl, CURLOPT_TIMEOUT, HTTP_TIMEOUT); 
	curl_easy_setopt(mycurl, CURLOPT_WRITEFUNCTION, receive_data);
	curl_easy_setopt(mycurl, CURLOPT_WRITEDATA, back_str);
	curl_easy_setopt(mycurl, CURLOPT_POSTFIELDS, base64str); 
	res = curl_easy_perform(mycurl);

	if (res != CURLE_OK) {
		GATEWAY_LOG(LOG_ERR, "send txtcode curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		goto out;
    }
	
	GATEWAY_LOG(LOG_INFO, "http recv %s\n", back_str);
	obj = cJSON_Parse(back_str);
	if (!obj)
		goto out;
	cJSON *success = cJSON_GetObjectItem(obj, "success");
	if (!success)
		goto out;
	if (success->type != cJSON_True) {
		ret = 101;
		goto out;
	}
	ret = 0;
	*olen = 0;
	
	user_query_info_t *need_verify = malloc(sizeof(user_query_info_t));
	memcpy(need_verify, user_info, sizeof(user_query_info_t));
	snprintf(need_verify->password, sizeof(need_verify->password) - 1, "%06d", verify_code);

	user_query_info_t *have_send_text = malloc(sizeof(user_query_info_t));
	memcpy(have_send_text, need_verify, sizeof(user_query_info_t));
	pthread_mutex_lock(&have_send_text_mutex);
	list_add(&have_send_text->user_list, &have_send_tel_text);
	pthread_mutex_unlock(&have_send_text_mutex);
	char *tel = malloc(16);
	strcpy(tel, have_send_text->username);
	add_timer(clear_tel, 60, 0, 60, tel, 0);
	
	user_query_info_t *p = NULL;
	matched = 0;

	pthread_mutex_lock(&text_mutex);
	list_for_each_entry(p, &tel_text_users, user_list) {
		if (strcmp(p->username, need_verify->username) == 0) {
			strcpy(p->password, need_verify->password);
			free(need_verify);
			matched = 1;
			break;
		}
	}
	if (!matched)
		list_add(&need_verify->user_list, &tel_text_users);
	pthread_mutex_unlock(&text_mutex);
	
out:
	if (jstr)
		free(jstr);
	if (back_str)
		free(back_str);
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	if (ret)
		*olen = 0;
	if (headers)
		curl_slist_free_all(headers);
	curl_easy_cleanup(mycurl);
	return ret;
}

int kill_app(void *para)
{
	char cmd[64] = {0};
	if (para) {
		snprintf(cmd, sizeof(cmd) - 1, "killall %s", para);
		system(cmd);
	}
	return 0;
}

int32 log_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	int ret = -1;
	log_leveljf = *(int *)ibuf;
	*olen = 0;
	ret = 0;
	return ret;
}

int32 start_app_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	int ret = -1;
	if (strcmp(ibuf, "dropbear") == 0) {
		system("killall dropbear");
		system("/usr/sbin/dropbear -F -P /var/run/dropbear.1.pid -p 22 -k 300 &");
		char *para = strdup("dropbear");
		if (para)
			add_timer(kill_app, dropbear_time, 0, 10000, para, DROPBEAR_TIMER);
		ret = 0;
		*olen = 0;
	} else {
		*olen = 0;
	}
out:

	return ret;
}

int32 stop_app_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	int ret = -1;
	if (strcmp(ibuf, "dropbear") == 0) {
		system("killall dropbear");
		del_timer(DROPBEAR_TIMER);
		ret = 0;
		*olen = 0;
	} else {
		*olen = 0;
	}
out:

	return ret;
}

void sig_hander( int sig )  
{  
	int save_errno = errno;
	int msg = sig;
	printf("have recv sig %d\n", msg);
	send(pipefd[1], &msg, 4, 0);
	errno = save_errno;
}

int file_get(char *url, char *md5, char *outfile, char *push_msg) 
{
	int ret = -1,i = 0;
	char cmd[512];
	unsigned char temp_md5[32];
	snprintf(cmd, sizeof(cmd) - 1, "wget -O %s -T 60 %s", outfile, url);

	for (i = 0; i < 3; i++) {
		if (!system(cmd))
			break;
		sleep(3);
	}
	if (i > 3)
		goto err;
	if (igd_md5sum(outfile, temp_md5)) {
		GATEWAY_LOG(LOG_ERR, "%s calc md5 fail\n", outfile);
		goto err;
	}

	for (i = 0; i < 16; i++)
		sprintf(&cmd[i*2], "%02X", temp_md5[i]);
	if (strncasecmp(cmd, md5, 32)) {
			GATEWAY_LOG(LOG_ERR, "MD5ERR:\n%s\n%s\n", cmd, md5);
			strncpy(push_msg, "md5 check err", 31);
			goto err;
	}
	ret = 0;
err:
	return ret;
}

int portal_wget(int id, int code, char *md5, char *url)
{
	int i = 0, pid = -1;
	char cmd[512];
	
	char push_msg[32] = {0};
	pid = fork();
	if (pid < 0)
		return -1;
	else if (pid > 0) 
		return 0;

	if (file_get(url, md5, PORTAL_FILE, push_msg))
		goto err;
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s/portal");
	system(cmd);
	snprintf(cmd, sizeof(cmd) - 1, "tar -zxvf %s -C %s",
			PORTAL_FILE, PORTAL_WEB_DIR);
	system(cmd);
	report_task(id, code, 0, NULL);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", PORTAL_FILE);
	system(cmd);
	exit(0);
err:
	report_task(id, code, 1, push_msg);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", PORTAL_FILE);
	system(cmd);
	exit(-1);
	
}

int sysbin_wget(int id, int code, char *md5, char *url)
{
	int i = 0, pid = -1;
	char cmd[512];
	char push_msg[32] = {0};
	pid = fork();
	if (pid < 0)
		return -1;
	else if (pid > 0) 
		return 0;

	if (file_get(url, md5, SYSBIN_FILE, push_msg))
		goto err;
	report_task(id, code, 0, NULL);
	snprintf(cmd, sizeof(cmd) - 1, "sysupgrade %s &", SYSBIN_FILE);
	system(cmd);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", SYSBIN_FILE);
	system(cmd);
	exit(0);
err:
	report_task(id, code, 1, push_msg);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", SYSBIN_FILE);
	system(cmd);
	exit(-1);
	
}

int network_wget(int id, int code, char *md5, char *url)
{
	int i = 0, pid = -1;
	char cmd[512];
	char push_msg[32] = {0};
	pid = fork();
	if (pid < 0)
		return -1;
	else if (pid > 0) 
		return 0;

	if (file_get(url, md5, NETWORK_FILE, push_msg))
		goto err;
	report_task(id, code, 0, NULL);
	snprintf(cmd, sizeof(cmd) - 1, "cp %s /etc/config/network;/etc/init.d/network restart", NETWORK_FILE);
	system(cmd);
	exit(0);
err:
	report_task(id, code, 1, push_msg);
	exit(-1);
	
}

int wifi_wget(int id, int code, char *md5, char *url)
{
	int i = 0, pid = -1;
	char cmd[512];
	char push_msg[32] = {0};
	pid = fork();
	if (pid < 0)
		return -1;
	else if (pid > 0) 
		return 0;

	if (file_get(url, md5, WIFI_FILE, push_msg))
		goto err;
	snprintf(cmd, sizeof(cmd) - 1, "cp %s /etc/config/wireless;/etc/init.d/network restart", WIFI_FILE);
	system(cmd);
	report_task(id, code, 0, NULL);
	exit(0);
err:
	report_task(id, code, 1, push_msg);
	exit(-1);
	
}


int report_task(int id, int code,int result, char *msg) {

	int ret = -1;
	cJSON *root = cJSON_CreateObject();
	cJSON *task_arr = cJSON_CreateArray();
	cJSON *obj = NULL;

	obj = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "devMac", gateway.mac);
	cJSON_AddNumberToObject(obj, "id", id);
	cJSON_AddNumberToObject(obj, "taskCode", code);
	cJSON_AddNumberToObject(obj, "result", result);
	if (msg)
		cJSON_AddStringToObject(obj, "message", msg);
	else
		cJSON_AddNullToObject(obj, "message");
	cJSON_AddItemToArray(task_arr, obj);

	cJSON_AddItemToObject(root, "taskList",task_arr);
	if ((ret = http_send(gateway.gmc_url_result, root, &obj, NULL)))
		goto out;
	
out:
	if (root)
		cJSON_Delete(root);
	return ret;
}

int do_task(cJSON *task_list)
{
	cJSON *child_item = task_list->child;
	cJSON *task_id = NULL, *task_code = NULL, *task_para = NULL,
			*md5_code = NULL;
	cJSON *download_url = NULL;
	
	char *bask_str = (char*)malloc(4096);
//	char cmd_task[4096] = {0};
	int rlen = 0;
	while (child_item) {
		task_id = cJSON_GetObjectItem(child_item, "id");
		task_code = cJSON_GetObjectItem(child_item, "taskCode");
		if (task_code) {
			switch(task_code->valueint) {
			case TASK_SYSTEM_REBOOT:
//				uuci_set("task_record.need_report.reboot=1");
				
				report_task(task_id->valueint, task_code->valueint, 0, NULL);
				rlen = shell_printf("reboot", bask_str, 4096);
				GATEWAY_LOG(LOG_INFO, "task reboot\n");
				break;
			case TASK_PORTAL_HTML_UPDATE:
				task_para = cJSON_GetObjectItem(child_item, "taskParam");
				if (!task_para) {
					GATEWAY_LOG(LOG_ERR, "task no param\n");
					break;
				}
				download_url = cJSON_GetObjectItem(task_para, "url");
				md5_code = cJSON_GetObjectItem(task_para, "md5Code");
				if (!download_url || !md5_code) {
					GATEWAY_LOG(LOG_ERR, "no url, or no md5 code");
					break;
				}			
				portal_wget(task_id->valueint, task_code->valueint, md5_code->valuestring, download_url->valuestring);
				break;
			case TASK_SYSTEM_UPGRADE:
				task_para = cJSON_GetObjectItem(child_item, "taskParam");
				if (!task_para) {
					GATEWAY_LOG(LOG_ERR, "task no param\n");
					break;
				}
				download_url = cJSON_GetObjectItem(task_para, "url");
				md5_code = cJSON_GetObjectItem(task_para, "md5Code");
				if (!download_url || !md5_code) {
					GATEWAY_LOG(LOG_ERR, "no url, or no md5 code");
					break;
				}			
				sysbin_wget(task_id->valueint, task_code->valueint, md5_code->valuestring, download_url->valuestring);
				break;
			case TASK_NETWORK_UPDATE:
				task_para = cJSON_GetObjectItem(child_item, "taskParam");
				if (!task_para) {
					GATEWAY_LOG(LOG_ERR, "task no param\n");
					break;
				}
				download_url = cJSON_GetObjectItem(task_para, "url");
				md5_code = cJSON_GetObjectItem(task_para, "md5Code");
				GATEWAY_LOG(LOG_DEBUG, "task network update url = %s md5", download_url->valuestring);
				if (!download_url || !md5_code) {
					GATEWAY_LOG(LOG_ERR, "no url, or no md5 code");
					break;
				}			
				network_wget(task_id->valueint, task_code->valueint, md5_code->valuestring, download_url->valuestring);
				break;
		
			case TASK_WIFI_UPDATE:
				task_para = cJSON_GetObjectItem(child_item, "taskParam");
				if (!task_para) {
					GATEWAY_LOG(LOG_ERR, "task no param\n");
					break;
				}
				download_url = cJSON_GetObjectItem(task_para, "url");
				md5_code = cJSON_GetObjectItem(task_para, "md5Code");
				GATEWAY_LOG(LOG_DEBUG, "task wifi update url = %s md5 %s", download_url->valuestring);
				if (!download_url || !md5_code) {
					GATEWAY_LOG(LOG_ERR, "no url, or no md5 code");
					break;
				}			
				wifi_wget(task_id->valueint, task_code->valueint, md5_code->valuestring, download_url->valuestring);
				break;
			}
		}
		child_item = child_item->next;
	
	}
	if (bask_str)
		free(bask_str);
	
	return 0;

}

int send_heart_beat(void *para)
{

	int ret = -1, status = 0, w_pid = 0;
	cJSON *root = NULL, *obj = NULL;
//	if (!gw_token.if_lgoin)
//		get_token();
	gateway_info_update();
	
	w_pid = waitpid(-1, &status, WNOHANG);

	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "devMac", gateway.mac);
	cJSON_AddStringToObject(root, "hardVersion", gateway.hard_version);
	cJSON_AddStringToObject(root, "softVersion", gateway.soft_version);
	cJSON_AddStringToObject(root, "vendor", gateway.vendor);
	cJSON_AddStringToObject(root, "wanMode", gateway.wan_mode);
	cJSON_AddStringToObject(root, "wanIp", gateway.wan_ip);
	cJSON_AddStringToObject(root, "lanIp", gateway.lan_ip);
	cJSON_AddStringToObject(root, "cpu", gateway.cpu_load);
	cJSON_AddNumberToObject(root, "memoryTotal", gateway.memory_total);
	cJSON_AddNumberToObject(root, "memoryFree", gateway.memory_free);
	cJSON_AddNumberToObject(root, "diskTotal", gateway.disk_total);
	cJSON_AddNumberToObject(root, "diskAvailable", gateway.disk_available);
	cJSON_AddNumberToObject(root, "date", gateway.date);
	cJSON_AddNumberToObject(root, "uptime", gateway.uptime);
	cJSON_AddStringToObject(root, "ssid", gateway.ssid);
	
	if ((ret = http_send(gateway.gmc_url_heart, root, &obj, NULL)))
		goto out;

	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result || result->valueint)
		goto out;	
	cJSON *data = cJSON_GetObjectItem(obj, "data");
	if (data && data->child && !strcmp(data->child->string, "taskList"))
		do_task(data->child);
	ret = 0;

out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	return ret;

}

int gateway_info_init()
{
	char **array = NULL;
	int num = 0, rlen = 0;
	char temp_disk[10] = {0};
	time_t rawtime;
	struct sysinfo info;

	if (!uuci_get("gateway_config.gateway_base.gateway_proxy_loglevel", &array, &num)) {
		log_leveljf = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("gateway_config.gateway_base.heartbeat_interval", &array, &num)) {
		heart_beat_interval = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("gateway_config.gateway_base.queryuser_cache_time", &array, &num)) {
		queryuser_cache_time = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("gateway_config.gateway_base.dropbear_timeout", &array, &num)) {
		dropbear_time = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("gateway_config.gateway_base.gmc_url_heart", &array, &num)) {
		strcpy(gateway.gmc_url_heart, array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("gateway_config.gateway_base.gmc_url_result", &array, &num)) {
		strcpy(gateway.gmc_url_result, array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("gateway_config.gateway_base.token_url", &array, &num)) {
		strcpy(gateway.token_url, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("gateway_config.gateway_base.user_query_url", &array, &num)) {
		strcpy(gateway.user_query_url, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("gateway_config.gateway_base.user_register_url", &array, &num)) {
		strcpy(gateway.user_register_url, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("gateway_config.gateway_base.gmc_url_result", &array, &num)) {
		strcpy(gateway.gmc_url_result, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("gateway_config.gateway_base.text_code_url", &array, &num)) {
		strcpy(gateway.text_code_url, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("gateway_config.gateway_base.text_str", &array, &num)) {
		strcpy(gateway.text_str, array[0]);
		uuci_get_free(array, num);
	}
	 
	if ((rlen = shell_printf("cat /sys/class/net/eth0/address",
					gateway.mac, sizeof(gateway.mac))) > 0) {
		gateway.mac[rlen - 1] = '\0';
	}
					
	if (!uuci_get("network.wan.proto", &array, &num)) {
		arr_strcpy(gateway.wan_mode, array[0]);
		uuci_get_free(array, num);
	}
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}'",
					gateway.wan_ip, sizeof(gateway.wan_ip))) > 0) {
		gateway.wan_ip[rlen - 1] = '\0';
	}
	if (!uuci_get("gateway_config.gateway_sys.hard_version", &array, &num)) {
		arr_strcpy(gateway.hard_version, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("gateway_config.gateway_sys.soft_version", &array, &num)) {
		arr_strcpy(gateway.soft_version, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("gateway_config.gateway_sys.vendor", &array, &num)) {
		arr_strcpy(gateway.vendor, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("wireless.default_radio0.ssid", &array, &num)) {
		arr_strcpy(gateway.ssid, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.lan.ipaddr", &array, &num)) {
		arr_strcpy(gateway.lan_ip, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.V3.ipaddr", &array, &num)) {
		arr_strcpy(gateway.v3_ip, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.V4.ipaddr", &array, &num)) {
		arr_strcpy(gateway.v4_ip, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.V5.ipaddr", &array, &num)) {
		arr_strcpy(gateway.v5_ip, array[0]);
		uuci_get_free(array, num);
	}

	shell_printf("df | grep rootfs | awk '{printf $2}'", temp_disk, sizeof(temp_disk));
	gateway.disk_total = atoi(temp_disk);
	memset(temp_disk, 0, sizeof(temp_disk));
	shell_printf("df | grep rootfs | awk '{printf $4}'", temp_disk, sizeof(temp_disk));
	gateway.disk_available = atoi(temp_disk);

	time(&rawtime);
	gateway.date = rawtime;
	
	cpu_info_get(gateway.cpu_load);
	
	if (!sysinfo(&info)) {
		gateway.uptime = info.uptime;
		gateway.memory_free = info.freeram;
		gateway.memory_total = info.totalram;
		
	}
	return 0;
					
}

int gateway_info_update()
{
	char **array = NULL;
	int num = 0, rlen = 0;
	char temp_disk[10] = {0};
	time_t rawtime;
	struct sysinfo info;
	if (!uuci_get("network.wan.proto", &array, &num)) {
		arr_strcpy(gateway.wan_mode, array[0]);
		uuci_get_free(array, num);
	}
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}'",
					gateway.wan_ip, sizeof(gateway.wan_ip))) > 0) {
		gateway.wan_ip[rlen - 1] = '\0';
	}
	if (!uuci_get("network.lan.ipaddr", &array, &num)) {
		arr_strcpy(gateway.lan_ip, array[0]);
		uuci_get_free(array, num);
	}

	shell_printf("df | grep rootfs | awk '{printf $4}'", temp_disk, sizeof(temp_disk));
	gateway.disk_available = atoi(temp_disk);
	
	time(&rawtime);
	gateway.date = rawtime;
	cpu_info_get(gateway.cpu_load);
	
	if (!sysinfo(&info)) {
		gateway.uptime = info.uptime;
		gateway.memory_free = info.freeram;
	}
	return 0;
}

void black_white_list_add_send()
{
	unsigned char black_white_mac[6] = {0};
	char **array = NULL;
	int num = 0, i = 0;
	if (!uuci_get("acct_config.total_config.black_white_enable", &array, &num)) {
		int enable = atoi(array[0]);
		uuci_get_free(array, num);
		if (!enable)
			return;
	}
	
	if (!uuci_get("acct_config.white_list.white", &array, &num)) {
		char cmd[128] = {0};
		for(i = 0; i < num; i++) {
			snprintf(cmd, sizeof(cmd) - 1, "iptables -t mangle -A sjwx_white_outgoing -m mac"
			" --mac-source %s -j sjwx_mark_accept", array[i]);
			system(cmd);
			str2mac(array[i], black_white_mac);
			GATEWAY_LOG(LOG_ERR, "MSG_CMD_AS_WhiteLIST_ADD success\n ");
		}
		uuci_get_free(array, num);
	}
		
}

/*
void black_list_del_send()
{
	if (msg_send_syn( MSG_CMD_AS_BLACKLIST_DELETE, black_white_mac, sizeof(black_white_mac), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_BLACKLIST_DELETE err\n ");
		}else {
			printf("black delete success\n");
			}
}
*/

advertising_cfg_t temp_adv;
void add_advertise()
{
	
}

int tempid;
void delete_advertise()
{
	temp_adv.id = tempid;
	temp_adv.type = 1;
	snprintf(temp_adv.url, sizeof(temp_adv.url), "http://%s/portal/test.html", gateway.lan_ip);

	int tp_size = tempid%5, i = 0;
	tp_size+=1;
	advertising_cfg_t *temp_adv2 = malloc(sizeof(advertising_cfg_t) * tp_size);
	for (i = 0;i < tp_size; i++) {
		memcpy(&temp_adv2[i], &temp_adv, sizeof(temp_adv));
	}
	
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_DELETE, temp_adv2, sizeof(advertising_cfg_t) * tp_size, NULL, NULL) != 0) {
			GATEWAY_LOG(LOG_ERR, "MSG_CMD_AS_ADVERTISING_DELETE err\n ");
		}else {
			GATEWAY_LOG(LOG_INFO, "adv delete success\n");
			}
	free(temp_adv2);
}

/*
void query_advertise()
{
	temp_adv.id = 1;
	temp_adv.type = 1;
	snprintf(temp_adv.url, sizeof(temp_adv.url), "http://ss0.bdstatic.com/jquery-1.10.2_d88366fd.js")
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_QUERY, temp_adv, sizeof(temp_adv), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_ADVERTISING_DELETE err\n ");
		}else {
			printf("adv delete success");
			}
}
*/

advertising_policy_t temp_policy;
int temp_ssss = 0;

void set_adv_policy()
{
	char **array = NULL;
	char *res;
	int num = 0;
	if (!uuci_get("acct_config.adv_config.adv_policy", &array, &num)) {
		temp_policy.policy = atoi(array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.adv_option", &array, &num)) {
		temp_policy.option = atoi(array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.adv_type", &array, &num)) {
		temp_policy.type = atoi(array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.time_interval", &array, &num)) {
		temp_policy.time_interval= simple_strtoull(array[0], &res, 10);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.flow_interval", &array, &num)) {
		temp_policy.flow_interval= simple_strtoull(array[0], &res, 10);
		uuci_get_free(array, num);
	}

	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_POLICY_SET, &temp_policy, sizeof(temp_policy), NULL, NULL) != 0) {
			GATEWAY_LOG(LOG_ERR, "MSG_CMD_AS_ADVERTISING_POLICY_SET err\n ");
		}else {
			GATEWAY_LOG(LOG_INFO, "adv_policy set success\n");
		}
}

void query_adv_policy()
{
	int policy_size = 0;
	advertising_policy_t *res_policy = NULL;
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_POLICY_QUERY, NULL, 0, &res_policy, &policy_size) != 0) {
			GATEWAY_LOG(LOG_ERR, "MSG_CMD_AS_ADVERTISING_POLICY_QUERY err\n ");
	}else {
			GATEWAY_LOG(LOG_INFO, "policy query success policy_oprion = %d\n", res_policy->option);
			free_rcv_buf(res_policy);
			
	}
} 

int portal_url_set()
{
	char cmd[2048] = {0};
	snprintf(cmd, sizeof(cmd) - 1, 
		"iptables -t nat -A prerouting_rule -m mark --mark 0x2 -j RETURN;"
		"iptables -t nat -A prerouting_rule -d %s -j RETURN;"
		"iptables -t nat -A prerouting_rule -p tcp --dport 80 -j REDIRECT --to-ports 4001;"
		"iptables -t nat -A prerouting_rule -p tcp --dport 443 -j REDIRECT --to-ports 4002;"
		"iptables -N sjwx_out_internet;"
		"iptables -A sjwx_out_internet -m mark --mark 0x2 -j RETURN;"
		"iptables -A sjwx_out_internet -p tcp --dport 67 -j RETURN;"
		"iptables -A sjwx_out_internet -p udp --dport 67 -j RETURN;"
		"iptables -A sjwx_out_internet -p tcp --dport 68 -j RETURN;"
		"iptables -A sjwx_out_internet -p udp --dport 68 -j RETURN;"
		"iptables -A sjwx_out_internet -p tcp --dport 53 -j RETURN;"
		"iptables -A sjwx_out_internet -p udp --dport 53 -j RETURN;"
		"iptables -A sjwx_out_internet -j REJECT;"
		"iptables -I FORWARD -i br-lan -j sjwx_out_internet;"
		"iptables -t mangle -N sjwx_brlan_outgoing;"
		"iptables -t mangle -A PREROUTING -i br-lan -j sjwx_brlan_outgoing;"
		"iptables -t mangle -N sjwx_white_outgoing;"
		"iptables -t mangle -I PREROUTING -i br-lan -j sjwx_white_outgoing;"
		"iptables -t mangle -N sjwx_mark_accept;"
		"iptables -t mangle -A sjwx_mark_accept -j MARK --set-mark 0x2;"
		"iptables -t mangle -A sjwx_mark_accept -j ACCEPT;" 
		, gateway.lan_ip);

	system(cmd);	
	return 0;

}

int setnonblocking(int fd)
{
	int old_option = fcntl(fd, F_GETFL);
	int new_option = old_option | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_option);
	return old_option;
}

int gateway_sig_init()
{
	sigset_t sig;

	sigemptyset(&sig);
	sigaddset(&sig, SIGABRT);
	sigaddset(&sig, SIGPIPE);
	sigaddset(&sig, SIGQUIT);
	sigaddset(&sig, SIGUSR1);
	sigaddset(&sig, SIGUSR2);
	sigaddset(&sig, SIGHUP);
	sigaddset(&sig, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);
	
	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);
//	signal(SIGBUS, sig_hander);
//	signal(SIGFPE, sig_hander);
//	signal(SIGSEGV, sig_hander);
	return 0;

}

int iptables_final()
{
	char cmd[1024] = {0};
	snprintf(cmd, sizeof(cmd) - 1, 
		"iptables -t nat -F prerouting_rule;"
		"iptables -t mangle -F sjwx_brlan_outgoing;"
		"iptables -t mangle -F sjwx_white_outgoing;"
		"iptables -t mangle -F sjwx_mark_accept;"
		"iptables -t mangle -D PREROUTING -i br-lan -j sjwx_brlan_outgoing;"
		"iptables -t mangle -D PREROUTING -i br-lan -j sjwx_white_outgoing;"
		"iptables -t mangle -X sjwx_brlan_outgoing;"
		"iptables -t mangle -X sjwx_white_outgoing;"
		"iptables -t mangle -X sjwx_mark_accept;"
		"iptables -F sjwx_out_internet;"
		"iptables -D FORWARD -i br-lan -j sjwx_out_internet;"
		"iptables -t filter -X sjwx_out_internet");
	system(cmd);
}

int main (int argc, char **argv)
{
	
	int ret = 0, i = 0;
	gateway_info_init();
	pthread_mutex_init(&query_mutex, NULL);
	pthread_mutex_init(&text_mutex, NULL);
	pthread_mutex_init(&authing_mutex, NULL);
	gateway_sig_init();
	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
	if (ret == -1)
		return -1;
	setnonblocking(pipefd[1]);
	msg_init(MODULE_MANAGE);
	msg_cmd_register(MSG_CMD_MANAGE_USER_QUERY, user_query_handler);
	msg_cmd_register(MSG_CMD_MANAGE_USER_REGISTER, user_register_handler);
	msg_cmd_register(MSG_CMD_MANAGE_TEXT_SEND, send_tel_code_handler);
	msg_cmd_register(MSG_CMD_MANAGE_START_APP, start_app_handler);
	msg_cmd_register(MSG_CMD_MANAGE_STOP_APP, stop_app_handler);
	msg_cmd_register(MSG_CMD_MANAGE_LOG, log_handler);
	msg_dst_module_register_unix(MODULE_RADIUS);
	curl_global_init(CURL_GLOBAL_ALL);

	struct timeval tv;
	fd_set fds;
	int max_fd = 0;
	timer_list_init();
	add_timer(send_heart_beat, 2, 1, heart_beat_interval, NULL, 0);
	add_timer(query_list_clear, 2, 1, queryuser_cache_time, NULL, 0);
	portal_url_set();
	black_white_list_add_send();
//	dpi_policy_send();
//	add_advertise();
	while (1) {
		tv.tv_sec = 60;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(pipefd[0], &fds);
		if (pipefd[0] > max_fd)
			max_fd = pipefd[0];
		
		if (select(max_fd + 1, &fds, NULL, NULL, &tv) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
		}

		if (FD_ISSET(pipefd[0], &fds)) {
			int signals[100];
			ret = recv(pipefd[0], signals, sizelen(signals), 0);
			if (ret > 0) {
				for(i = 0; i < ret; i++) {
					printf("signalsi is %d  sigint %d sigterm %d", signals[i], SIGINT, SIGTERM);
					switch(signals[i]) {
					case SIGTERM:
					case SIGINT:
						msg_final(); 
						curl_global_cleanup();
						iptables_final();
						exit(0);
						break;
					}
				}
			}
		}
		timer_handler();
	}
	return 0;
}
