#include "protocol.h"
#include "ipc_msg.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define IPC_PATH "/mnt/data/serversocketfile"
#define CGI_LOG_PATH  "/tmp/cgi_log"
#define GETREQUEST 0xc0
#define SETREQUEST 0xc1
#define GETRESPONSE 0xc4
#define SETRESPONSE 0xc5


extern int upload_file();

struct my_time{
	unsigned short year;
	unsigned char month;
	unsigned char day;
	unsigned char week;
	unsigned char hour;
	unsigned char minite;
	unsigned char second;
	unsigned char dontcare[4];
};
struct obis_attr{
	unsigned short class_id;
	unsigned char obis[6];
	unsigned char attr;
	unsigned char set0;
};

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
int nbuf_to_int(unsigned char *buf)
{
	int addr = 0;
	*((unsigned char *)(&addr)+3) = buf[0];
	*((unsigned char *)(&addr)+2) = buf[1];
	*((unsigned char *)(&addr)+1) = buf[2];
	*((unsigned char *)(&addr)+0) = buf[3];
	return addr;
}
int int_to_nbuf(int addr, unsigned char *buf)
{
	
	buf[0] = *((unsigned char *)(&addr)+3);
	buf[1] = *((unsigned char *)(&addr)+2);
	buf[2] = *((unsigned char *)(&addr)+1);
	buf[3] = *((unsigned char *)(&addr)+0);
	return 0;
}

unsigned short nbuf_to_short(unsigned char *buf)
{
	unsigned short port1 = 0;
	*((unsigned char *)(&port1)+1) = buf[0];
	*((unsigned char *)(&port1)) = buf[1];
	return port1;
}
int short_to_nbuf(unsigned short port1, unsigned char *buf)
{
	buf[0] = *((unsigned char *)(&port1)+1);
	buf[1] = *((unsigned char *)(&port1));
	return 0;
}

#define CGI_PRINT(fmt,args...) do{ \
	cgi_log(CGI_LOG_PATH, "[IPC:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)

void cgi_log(char *file, const char *fmt, ...)
{
	va_list ap;
	FILE *fp = NULL;
	char bakfile[32] = {0,};

	fp = fopen(file, "a+");
	if (fp == NULL)
		return;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	if (ftell(fp) > 10*1024)
		snprintf(bakfile, sizeof(bakfile), "%s.bak", file);
	fclose(fp);
	if (bakfile[0])
		rename(file, bakfile);
}

int cgi_check_login_handler(connection_t *con, cJSON *response)
{	
	cJSON_AddNumberToObject(response, "login", 1);
	return 0;
}

int cgi_sys_main_handler(connection_t *con, cJSON *response)
{	
	int i;
	struct obis_attr time_obis[2]=
				{{0x01,{0x00,0x00,0x19,0x04,0x81,0xff},0x02,0x00}, //terminal
				{0x01,{0x00,0x00,0x19,0x04,0x80,0xff},0x02,0x00}};//master
	for(i =0; i < 2; i++) {
		time_obis[i].class_id = htons(time_obis[i].class_id); 
	}

	int judge_result = -1;
	unsigned char judge2[3] = {0x00,0x02,0x0e};
	unsigned char ter_buf[200] = {0};
	if (sys_get(&(time_obis[0]), sizeof(struct obis_attr), ter_buf, 102,judge2,sizeof(judge2),&judge_result))
		return CGI_ERR_FAIL;
	struct in_addr inaddr;
	inaddr.s_addr=htonl(nbuf_to_int(&ter_buf[2]));
	cJSON_AddStringToObject(response, "ter_ip1", inet_ntoa(inaddr));
	inaddr.s_addr=htonl(nbuf_to_int(&ter_buf[8]));
	cJSON_AddStringToObject(response, "ter_mask1", inet_ntoa(inaddr));
	inaddr.s_addr=htonl(nbuf_to_int(&ter_buf[14]));
	cJSON_AddStringToObject(response, "ter_gateway1", inet_ntoa(inaddr));

	unsigned char judge3[3] = {0x00,0x02,0x13};

	if (sys_get(&(time_obis[1]), sizeof(struct obis_attr), ter_buf, 193,judge3,sizeof(judge3),&judge_result))
		return CGI_ERR_FAIL;

	inaddr.s_addr=htonl(nbuf_to_int(&ter_buf[2]));
	cJSON_AddStringToObject(response, "master_ip1", inet_ntoa(inaddr));
	cJSON_AddNumberToObject(response, "master_port1", nbuf_to_short(&ter_buf[8]));
	cJSON_AddStringToObject(response, "master_apn", &ter_buf[60]);
	cJSON_AddStringToObject(response, "user", &ter_buf[78]);
	cJSON_AddStringToObject(response, "pwd", &ter_buf[96]);
	cJSON_AddNumberToObject(response, "heartbeat", nbuf_to_short(&ter_buf[175]));

	return 0;
}

int cgi_sys_main2_handler(connection_t *con, cJSON *response)
{	
	struct my_time t;
	int i;
	struct obis_attr time_obis[3]=
				{{0x08,{0x00,0x00,0x01,0x00,0x00,0xff},0x02,0x00},//time
				{0x01,{0x00,0x00,0x60,0x39,0x00,0xff},0x02,0x00}, //version
				{0x01,{0x00,0x00,0x60,0x50,0x00,0xff},0x02,0x00}};//manage
	for(i =0; i < 3; i++) {
		time_obis[i].class_id = htons(time_obis[i].class_id); 
	}
	unsigned char judge[2] = {0x00,0x19};
	int judge_result = -1;

	if (sys_get(&(time_obis[0]), sizeof(struct obis_attr), &t, sizeof(t),judge,sizeof(judge),&judge_result))
		return CGI_ERR_FAIL;
	char mtime[20] = {0};
	snprintf(mtime, 20, "%04d-%02d-%02d/%02d:%02d:%02d",ntohs(t.year),t.month,t.day,t.hour,t.minite,t.second);
	cJSON_AddStringToObject(response, "time", mtime);


	unsigned char judge2[3] = {0x00,0x02,0x08};
	unsigned char ter_buf[63] = {0};


	if (sys_get(&time_obis[1], sizeof(struct obis_attr), ter_buf, sizeof(ter_buf),judge2,sizeof(judge2),&judge_result))
		return CGI_ERR_FAIL;

	char temp[15] = {0};
	memcpy(temp, &ter_buf[7], 13);
	cJSON_AddStringToObject(response, "device_id", temp);
	memset(temp, 0, sizeof(temp));
	memcpy(temp, &ter_buf[22], 4);
	cJSON_AddStringToObject(response, "soft_version", temp);
	memset(temp, 0, sizeof(temp));
	unsigned short year = nbuf_to_short(&ter_buf[27]);
	snprintf(temp, 15, "%04d-%02d-%02d",year,ter_buf[29],ter_buf[30]);
	cJSON_AddStringToObject(response, "soft_pubdate", temp);
	memset(temp, 0, sizeof(temp));
	memcpy(temp, &ter_buf[53], 4);
	cJSON_AddStringToObject(response, "hard_version", temp);


	unsigned char judge3[3] = {0x00,0x02,0x05};

	if (sys_get(&time_obis[2], sizeof(struct obis_attr), ter_buf, 21,judge3,sizeof(judge3),&judge_result))
		return CGI_ERR_FAIL;

	cJSON_AddNumberToObject(response, "cao_interval", ter_buf[13]);

	return 0;
}

int cgi_sys_time_handler(connection_t *con, cJSON *response)
{

	struct my_time t;
	struct obis_attr time_obis={0x08,{0x00,0x00,0x01,0x00,0x00,0xff},0x02,0x00};
	time_obis.class_id = htons(time_obis.class_id); 
	int judge_result = -1;
	unsigned char judge[2] = {0x00,0x19};

	if (sys_get(&time_obis, sizeof(struct obis_attr), &t, sizeof(t),judge,sizeof(judge),&judge_result))
		return CGI_ERR_FAIL;
	if (connection_is_set(con)) {
		char *set_time = NULL;
		set_time = con_value_get(con, "time");
		if (!set_time)
			return CGI_ERR_INPUT;
		CGI_PRINT("%s\n",set_time);
		int tem_time[6];
		sscanf(set_time, "%d-%d-%d/%d:%d:%d", &tem_time[0],&tem_time[1],&tem_time[2],&tem_time[3],&tem_time[4],&tem_time[5]);
		t.year = tem_time[0];
		t.month = tem_time[1];
		t.day = tem_time[2];
		t.hour = tem_time[3];
		t.minite = tem_time[4];
		t.second = tem_time[5];
		CGI_PRINT("this is %d-%d-%d/%d:%d:%d\n", t.year,t.month,t.day,t.hour,t.minite,t.second);
		t.year = htons(t.year);
		unsigned char type_length = 0x19;

		char *send_buf = malloc(sizeof(struct obis_attr)+sizeof(type_length)+sizeof(t));	
		memcpy(send_buf, &time_obis, sizeof(struct obis_attr));
		memcpy(send_buf + sizeof(time_obis), &type_length, sizeof(type_length));
		memcpy(send_buf + sizeof(time_obis)+1, &t, sizeof(t));
		
		if (sys_set(send_buf, sizeof(struct obis_attr)+sizeof(type_length)+sizeof(t))) {
			free(send_buf);
			return CGI_ERR_FAIL;
		}
		free(send_buf);
		return 0;
	}
	char mtime[20] = {0};
	snprintf(mtime, 20, "%04d-%02d-%02d/%02d:%02d:%02d",ntohs(t.year),t.month,t.day,t.hour,t.minite,t.second);
	cJSON_AddStringToObject(response, "time", mtime);
	return 0;
}

int cgi_sys_terminal_handler(connection_t *con, cJSON *response)
{
	struct obis_attr time_obis={0x01,{0x00,0x00,0x19,0x04,0x81,0xff},0x02,0x00};
	time_obis.class_id = htons(time_obis.class_id); 
	int judge_result = -1;
	unsigned char judge[3] = {0x00,0x02,0x0e};
	unsigned char ter_buf[102] = {0};
	if (sys_get(&time_obis, sizeof(struct obis_attr), ter_buf, sizeof(ter_buf),judge,sizeof(judge),&judge_result))
		return CGI_ERR_FAIL;
	if (connection_is_set(con)) {
		char *ter_ip = con_value_get(con,"ter_ip");
		char *ter_mask = con_value_get(con,"ter_mask");
		char *ter_gateway = con_value_get(con,"ter_gateway");
		int_to_nbuf(ntohl(inet_addr(ter_ip)),&ter_buf[2]);
		int_to_nbuf(ntohl(inet_addr(ter_mask)),&ter_buf[8]);
		int_to_nbuf(ntohl(inet_addr(ter_gateway)),&ter_buf[14]);
		unsigned char type_length[2] = {0x02,0x0e};
		char *send_buf = malloc(sizeof(struct obis_attr)+sizeof(type_length)+sizeof(ter_buf));	
		memcpy(send_buf, &time_obis, sizeof(struct obis_attr));
		memcpy(send_buf + sizeof(time_obis), type_length, sizeof(type_length));
		memcpy(send_buf + sizeof(time_obis)+sizeof(type_length), ter_buf, sizeof(ter_buf));
		if (sys_set(send_buf, sizeof(struct obis_attr)+sizeof(type_length)+sizeof(ter_buf))) {
			free(send_buf);
			return CGI_ERR_FAIL;
		}
		free(send_buf);
		return 0;
	}
	struct in_addr inaddr;
	inaddr.s_addr=htonl(nbuf_to_int(&ter_buf[2]));
	cJSON_AddStringToObject(response, "ip1", inet_ntoa(inaddr));
	inaddr.s_addr=htonl(nbuf_to_int(&ter_buf[8]));
	cJSON_AddStringToObject(response, "mask1", inet_ntoa(inaddr));
	inaddr.s_addr=htonl(nbuf_to_int(&ter_buf[14]));
	cJSON_AddStringToObject(response, "gateway1", inet_ntoa(inaddr));
	return 0;
}

int cgi_sys_master_handler(connection_t *con, cJSON *response)
{
	struct obis_attr time_obis={0x01,{0x00,0x00,0x19,0x04,0x80,0xff},0x02,0x00};
	time_obis.class_id = htons(time_obis.class_id); 
	int judge_result = -1;
	unsigned char judge[3] = {0x00,0x02,0x13};
	unsigned char ter_buf[193] = {0};
	if (sys_get(&time_obis, sizeof(struct obis_attr), ter_buf, sizeof(ter_buf),judge,sizeof(judge),&judge_result))
		return CGI_ERR_FAIL;
	if (connection_is_set(con)) {
		char *master_ip = con_value_get(con,"master_ip");
		char *master_port = con_value_get(con,"master_port");
		char *master_apn = con_value_get(con,"master_apn");
		char *user = con_value_get(con,"user");
		char *pwd = con_value_get(con,"pwd");
		char *heartbeat = con_value_get(con,"heartbeat");

		int_to_nbuf(ntohl(inet_addr(master_ip)),&ter_buf[2]);
		short_to_nbuf((unsigned short)atoi(master_port),&ter_buf[8]);
		strcpy(&ter_buf[60], master_apn);
		strcpy(&ter_buf[78], user);
		strcpy(&ter_buf[96], pwd);
		short_to_nbuf((unsigned short)atoi(heartbeat),&ter_buf[175]);

		unsigned char type_length[2] = {0x02,0x13};

		char *send_buf = malloc(sizeof(struct obis_attr)+sizeof(type_length)+sizeof(ter_buf));	
		memcpy(send_buf, &time_obis, sizeof(struct obis_attr));
		memcpy(send_buf + sizeof(time_obis), type_length, sizeof(type_length));
		memcpy(send_buf + sizeof(time_obis)+sizeof(type_length), ter_buf, sizeof(ter_buf));

		if (sys_set(send_buf, sizeof(struct obis_attr)+sizeof(type_length)+sizeof(ter_buf))) {
			free(send_buf);
			return CGI_ERR_FAIL;
		}
		free(send_buf);
		return 0;
	}
	int addr1 = nbuf_to_int(&ter_buf[2]);
	struct in_addr inaddr;
	inaddr.s_addr=htonl(addr1);
	cJSON_AddStringToObject(response, "ip1", inet_ntoa(inaddr));
	cJSON_AddNumberToObject(response, "port1", nbuf_to_short(&ter_buf[8]));
	//char mtime[20] = {0};
	//snprintf(mtime, 20, "%04d-%02d-%02d %02d-%02d-%02d",ntohs(t.year),t.month,t.day,t.hour,t.minite,t.second);
	//cJSON_AddStringToObject(response, "time", mtime);
	return 0;
}

int cgi_sys_manage_handler(connection_t *con, cJSON *response)
{
	struct obis_attr time_obis={0x01,{0x00,0x00,0x60,0x50,0x00,0xff},0x02,0x00};
	time_obis.class_id = htons(time_obis.class_id); 
	int judge_result = -1;
	unsigned char judge[3] = {0x00,0x02,0x05};
	unsigned char ter_buf[21] = {0};
	if (sys_get(&time_obis, sizeof(struct obis_attr), ter_buf, sizeof(ter_buf),judge,sizeof(judge),&judge_result))
		return CGI_ERR_FAIL;
	if (connection_is_set(con)) {
		char *flag = con_value_get(con,"flag");
		if (strcmp(flag,"interval") == 0) {
			char *cao_interval = con_value_get(con,"cao_interval");
			if (!cao_interval)
				return CGI_ERR_INPUT;
			ter_buf[13] = atoi(cao_interval);
			unsigned char type_length[2] = {0x02,0x5};

			char *send_buf = malloc(sizeof(struct obis_attr)+sizeof(type_length)+sizeof(ter_buf));	
			memcpy(send_buf, &time_obis, sizeof(struct obis_attr));
			memcpy(send_buf + sizeof(time_obis), type_length, sizeof(type_length));
			memcpy(send_buf + sizeof(time_obis)+sizeof(type_length), ter_buf, sizeof(ter_buf));
			if (sys_set(send_buf, sizeof(struct obis_attr)+sizeof(type_length)+sizeof(ter_buf))) {
				free(send_buf);
				return CGI_ERR_FAIL;
			}
			free(send_buf);
			return 0;
		}
		else if(strcmp(flag,"reset") == 0) {

			unsigned char data_obis_set[10] = {0x00,0x01,0x00,0x00,0x60,0x50,0x00,0xff,0x81,0x00};

			char *send_buf = malloc(sizeof(data_obis_set));	
			memcpy(send_buf, data_obis_set, sizeof(data_obis_set));

			if (sys_action(send_buf, sizeof(data_obis_set))) {
				free(send_buf);
				return CGI_ERR_FAIL;
			}
			free(send_buf);
			return 0;
		}
		else if(strcmp(flag,"data_reset") == 0) {
	
			unsigned char data_obis_set[10] = {0x00,0x01,0x00,0x00,0x60,0x50,0x00,0xff,0x82,0x00};

			char *send_buf = malloc(sizeof(data_obis_set));	
			memcpy(send_buf, data_obis_set, sizeof(data_obis_set));
		
			if (sys_action(send_buf, sizeof(data_obis_set))) {
				free(send_buf);
				return CGI_ERR_FAIL;
			}
			free(send_buf);
			return 0;
		}
		else if(strcmp(flag,"part_init") == 0) {
	
			unsigned char data_obis_set[10] = {0x00,0x01,0x00,0x00,0x60,0x50,0x00,0xff,0x83,0x00};

			char *send_buf = malloc(sizeof(data_obis_set));	
			memcpy(send_buf, data_obis_set, sizeof(data_obis_set));
		
			if (sys_action(send_buf, sizeof(data_obis_set))) {
				free(send_buf);
				return CGI_ERR_FAIL;
			}
			free(send_buf);
			return 0;
		}
		else if(strcmp(flag,"all_init") == 0) {
	
			unsigned char data_obis_set[10] = {0x00,0x01,0x00,0x00,0x60,0x50,0x00,0xff,0x84,0x00};

			char *send_buf = malloc(sizeof(data_obis_set));	
			memcpy(send_buf, data_obis_set, sizeof(data_obis_set));
		
			if (sys_action(send_buf, sizeof(data_obis_set))) {
				free(send_buf);
				return CGI_ERR_FAIL;
			}
			free(send_buf);
			return 0;
		}else
			return CGI_ERR_FAIL;
	}
	cJSON_AddNumberToObject(response, "cao_interval", ter_buf[13]);
	return 0;
}

int cgi_sys_meter_point_handler(connection_t *con, cJSON *response)
{
	struct obis_attr time_obis={0x01,{0x00,0x00,0x60,0x51,0x02,0xff},0x02,0x00};
	time_obis.class_id = htons(time_obis.class_id); 
	int judge_result = -1;
	unsigned char judge[3] = {0x00,0x02,0x13};
	unsigned char ter_buf[193] = {0};


	if (sys_get(&time_obis, sizeof(struct obis_attr), ter_buf, sizeof(ter_buf),judge,sizeof(judge),&judge_result))
		return CGI_ERR_FAIL;


	//char mtime[20] = {0};
	//snprintf(mtime, 20, "%04d-%02d-%02d %02d-%02d-%02d",ntohs(t.year),t.month,t.day,t.hour,t.minite,t.second);
	//cJSON_AddStringToObject(response, "time", mtime);
	return 0;
}

int cgi_sys_data_source_handler(connection_t *con, cJSON *response)
{
	struct obis_attr time_obis={0x01,{0x00,0x00,0x60,0x51,0x00,0xff},0x02,0x00};
	unsigned char data_obis[14] = {0x00,0x01,0x00,0x00,0x60,0x51,0x00,0xff,0x02,0x01,0x01,0x12,0x00,0x00};
	
	int judge_result = -1;
	unsigned char judge[5] = {0x00,0x01,0x01,0x02,0x0f};
	unsigned char ter_buf[43] = {0};
	char *meter_num = con_value_get(con, "meter_num");
	if (!meter_num)
		return CGI_ERR_INPUT;
	unsigned short number = (unsigned short)atoi(meter_num);
	short_to_nbuf(number, &data_obis[12]);
	int not_set = 0;

	if (sys_get(&data_obis, sizeof(data_obis), ter_buf, sizeof(ter_buf),judge,sizeof(judge),&judge_result)) {
		unsigned char null_judge[2] = {0x00,0x00};
		if (sys_get(&data_obis, sizeof(data_obis), NULL, 0,null_judge,sizeof(null_judge),&judge_result))
			return CGI_ERR_FAIL;
		not_set = 1;
	}
	if (connection_is_set(con)) {
		char *device_number = con_value_get(con,"device_number");
		char *baud_rate = con_value_get(con,"baud_rate");
		char *guiyue = con_value_get(con,"guiyue");
		char *jiexian = con_value_get(con,"jiexian");
		char *tongxunfangshi = con_value_get(con,"tongxunfangshi");
		if (!meter_num || !device_number || !baud_rate || !guiyue || !jiexian || !tongxunfangshi)
			return CGI_ERR_INPUT;
		unsigned char default_buf[43] = {0x12, 0x00, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 
						0x10, 0x11, 0x1f, 0x11, 0x00, 0x11, 0x03, 0x11, 0x08, 0x11, 0x00, 
						0x11, 0x00, 0x11, 0x00, 0x11, 0x00, 0x11, 0x00, 0x11, 0x00, 0x09, 
						0x04, 0x00, 0x00, 0x00, 0x00, 0x09, 0x02, 0x00, 0x00, 0x11, 0x05};
		if (not_set) {
			memcpy(ter_buf,default_buf,sizeof(default_buf));
		}
		int i = 0;
		int temp[6] = {0};
		sscanf(device_number, "%02x%02x%02x%02x%02x%02x", &temp[0],&temp[1],&temp[2],&temp[3],&temp[4],&temp[5]);
		for (i = 0;i<6;i++) {
			ter_buf[10-i]= temp[i];
		}
		short_to_nbuf(number, &ter_buf[1]);

		ter_buf[14] = atoi(baud_rate);
		ter_buf[16] = atoi(guiyue);
		ter_buf[30] = atoi(jiexian);
		ter_buf[42] = atoi(tongxunfangshi);

		unsigned char type_length[5] = {0x01,0x01,0x01,0x02,0x0f};
		unsigned char data_obis_set[9] = {0x00,0x01,0x00,0x00,0x60,0x51,0x00,0xff,0x81};

		char *send_buf = malloc(sizeof(data_obis_set)+sizeof(type_length)+sizeof(ter_buf));	
		memcpy(send_buf, data_obis_set, sizeof(data_obis_set));
		memcpy(send_buf + sizeof(data_obis_set), type_length, sizeof(type_length));
		memcpy(send_buf + sizeof(data_obis_set)+sizeof(type_length), ter_buf, sizeof(ter_buf));

		if (sys_action(send_buf, sizeof(data_obis_set)+sizeof(type_length)+sizeof(ter_buf))) {
			free(send_buf);
			return CGI_ERR_FAIL;
		}
		free(send_buf);
		return 0;
	}
	if (not_set) {
		cJSON_AddStringToObject(response, "meter_num", meter_num);
		cJSON_AddStringToObject(response, "device_number", "000000000000");
		cJSON_AddNumberToObject(response, "baud_rate", 0);
		cJSON_AddNumberToObject(response, "guiyue", 3);
		cJSON_AddNumberToObject(response, "jiexian", 0);
		cJSON_AddNumberToObject(response, "tongxunfangshi", 0);
		cJSON_AddNumberToObject(response, "not_set", 1);
		return 0;
	}

	char temp[15] = {0};
	snprintf(temp, 15, "%02x%02x%02x%02x%02x%02x", ter_buf[10], ter_buf[9], ter_buf[8], ter_buf[7],
			ter_buf[6], ter_buf[5]);
	cJSON_AddStringToObject(response, "meter_num", meter_num);
	cJSON_AddStringToObject(response, "device_number", temp);
	cJSON_AddNumberToObject(response, "baud_rate", ter_buf[14]);
	cJSON_AddNumberToObject(response, "guiyue", ter_buf[16]);
	cJSON_AddNumberToObject(response, "jiexian", ter_buf[30]);
	cJSON_AddNumberToObject(response, "tongxunfangshi", ter_buf[42]);
	cJSON_AddNumberToObject(response, "not_set", 0);
	return 0;
}

int cgi_sys_version_handler(connection_t *con, cJSON *response)
{
	struct obis_attr time_obis={0x01,{0x00,0x00,0x60,0x39,0x00,0xff},0x02,0x00};
	time_obis.class_id = htons(time_obis.class_id); 
	int judge_result = -1;
	unsigned char judge[3] = {0x00,0x02,0x08};
	unsigned char ter_buf[63] = {0};


	if (sys_get(&time_obis, sizeof(struct obis_attr), ter_buf, sizeof(ter_buf),judge,sizeof(judge),&judge_result))
		return CGI_ERR_FAIL;

	char temp[15] = {0};
	memcpy(temp, &ter_buf[7], 13);
	cJSON_AddStringToObject(response, "device_id", temp);
	memset(temp, 0, sizeof(temp));
	memcpy(temp, &ter_buf[22], 4);
	cJSON_AddStringToObject(response, "soft_version", temp);
	memset(temp, 0, sizeof(temp));
	unsigned short year = nbuf_to_short(&ter_buf[27]);
	snprintf(temp, 15, "%04d-%02d-%02d",year,ter_buf[29],ter_buf[30]);
	cJSON_AddStringToObject(response, "soft_pubdate", temp);
	memset(temp, 0, sizeof(temp));
	memcpy(temp, &ter_buf[53], 4);
	cJSON_AddStringToObject(response, "hard_version", temp);
	return 0;
}

int cgi_sys_meter_detail_handler(connection_t *con, cJSON *response)
{
	unsigned char data_obis1[14] = {0x00,0x01,0x00,0x00,0x60,0x51,0x00,0xff,0x02,0x01,0x01,0x12,0x00,0x00};
	
	int judge_result = -1;
	unsigned char judge1[5] = {0x00,0x01,0x01,0x02,0x0f};
	unsigned char ter_buf1[43] = {0};
	char *meter_num = con_value_get(con, "meter_num");
	if (!meter_num)
		return CGI_ERR_INPUT;
	unsigned short number = (unsigned short)atoi(meter_num);
	short_to_nbuf(number, &data_obis1[12]);
	int not_set = 0;

	if (sys_get(&data_obis1, sizeof(data_obis1), ter_buf1, sizeof(ter_buf1),judge1,sizeof(judge1),&judge_result)) {
		unsigned char null_judge[2] = {0x00,0x00};
		if (sys_get(&data_obis1, sizeof(data_obis1), NULL, 0,null_judge,sizeof(null_judge),&judge_result))
			return CGI_ERR_FAIL;
		not_set = 1;
	}

	if (not_set) {
		cJSON_AddStringToObject(response, "meter_num", meter_num);
		cJSON_AddStringToObject(response, "device_number", "000000000000");
		cJSON_AddNumberToObject(response, "not_set", 1);
		return 0;
	}

	char temp[15] = {0};
	snprintf(temp, 15, "%02x%02x%02x%02x%02x%02x", ter_buf1[10], ter_buf1[9], ter_buf1[8], ter_buf1[7],
			ter_buf1[6], ter_buf1[5]);
	cJSON_AddStringToObject(response, "meter_num", meter_num);
	cJSON_AddStringToObject(response, "device_number", temp);


	struct obis_attr time_obis[2]={{0x03,{0x01,0x00,0x20,0x07,0x00,0xff},0x02,0x00},
					{0x03,{0x01,0x00,0x1f,0x07,0x00,0xff},0x02,0x00}};
	int i;
	for(i =0; i < 2; i++) {
		time_obis[i].class_id = htons(time_obis[i].class_id); 
	}
	unsigned char judge[2] = {0x00,0x12};
	unsigned char ter_buf[2] = {0};

	if (meter_detail(&time_obis[0], sizeof(struct obis_attr), ter_buf, sizeof(ter_buf),judge,sizeof(judge),&judge_result,number))
		return CGI_ERR_FAIL;

	unsigned char judge2[2] = {0x00,0x06};
	unsigned char ter_buf2[4] = {0};

	if (meter_detail(&time_obis[1], sizeof(struct obis_attr), ter_buf2, sizeof(ter_buf2),judge2,sizeof(judge2),&judge_result,number))
		return CGI_ERR_FAIL;

	cJSON_AddNumberToObject(response, "voltage", nbuf_to_short(ter_buf));
	cJSON_AddNumberToObject(response, "current", nbuf_to_int(ter_buf2));

	return 0;
}

int cgi_sys_upload_file_handler(connection_t *con, cJSON *response)
{
	if (upload_file())
		return CGI_ERR_FAIL;
	return 0;
}
