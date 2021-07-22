#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "cJSON.h"
#include "message.h"
#include "log.h"
#include "tools.h"
#include "protocol.h"
#include "libcom.h"
#include "connection.h"
#include "uci_fn.h"
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

enum {
	TYPE_HTML = 0,
	TYPE_JSON,
	TYPE_PLAIN,
	TYPE_JSON_PLAIN,
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

int cgi_sys_start_app_handler(connection_t *con)
{	
	char *app = con_value_get(con, "app");
	if (!app) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}

	

	cJSON_AddNumberToObject(con->response, "code", 1);
out:
	return 1;
}

int cgi_sys_status_information_handler(connection_t *con)
{	

	char temp[32] = {0};
	char default_dev[16] = {0};
	char active[16] = {0};
	char wlface[16] = {0};
	char iface_uptime[16] = {0};
	cJSON *item = NULL;
	char cmd[160] = {0};
	char droute[128] = {0};
	
	system("echo `date +%s` >/tmp/sysinfo/luci-avtive");
	shell_printf("ip route|grep 'default'|head -n1|awk BEGIN'{FS=\"dev \"}{print $2}'|awk '{printf $1}'", 
					default_dev, sizeof(default_dev));
	if (!strcmp(default_dev, "wlan0") || !strcmp(default_dev, "wlan1") || !strcmp(default_dev, "apcli0") || !strcmp(default_dev, "apclii0")) {
		if (!strcmp(default_dev, "wlan1"))
			strncpy(wlface, "wwan1", sizeof(wlface)-1);
		else {
			strncpy(wlface, "wwan0", sizeof(wlface)-1);
		}
		snprintf(cmd, sizeof(cmd), "head -c1 /tmp/run/track-%s 2>/dev/null", wlface);
		shell_printf(cmd, active, sizeof(active));
		snprintf(cmd, sizeof(cmd), "ubus call network.interface.%s status | grep uptime|awk '{print $2}'", wlface);
		if (shell_printf(cmd, iface_uptime, sizeof(iface_uptime)) > 0)
			iface_uptime[strlen(iface_uptime)] = '\0';
		
		shell_printf("ip route|grep default|head -n1|awk BEGIN'{FS=\"dev \"}{printf $2}'", droute, sizeof(droute));
		snprintf(cmd, sizeof(cmd), "iwinfo %s info", default_dev);
		char iwinfo[512] = {0};
		char mode[16] = "loading---"; char ssid[32] = "loading---"; char rate[32] = "loading---";
		char bssid[32] = "loading---"; char quality[16] = "loading---"; int channel = 0; char blank[256] = {0};
		shell_printf(cmd, iwinfo, sizeof(iwinfo));

		char *index = strstr(iwinfo, "ESSID: \"");
		if (index) {
			sscanf(index + strlen("ESSID: \""), "%s ", ssid);
			ssid[strlen(ssid)-1] = '\0';
		}
		index = strstr(iwinfo, "Mode: ");
		if (index)
			sscanf(index + strlen("Mode: "), "%s ", mode);
		index = strstr(iwinfo, "Channel: ");
		if (index)
			sscanf(index + strlen("Channel: "), "%d ", &channel);
		index = strstr(iwinfo, "Rate: ");
		if (index)
			sscanf(index + strlen("Rate: "), "%s ", rate);
		index = strstr(iwinfo, "Point: ");
		if (index)
			sscanf(index + strlen("Point: "), "%s ", bssid);
		index = strstr(iwinfo, "Quality: ");
		if (index)
			sscanf(index + strlen("Quality: "), "%s ", quality);
		
		cJSON_AddNumberToObject(con->response, "time", atoi(iface_uptime)); 
		cJSON_AddStringToObject(con->response, "rate", rate);
		cJSON_AddStringToObject(con->response, "bssid", bssid);
		cJSON_AddStringToObject(con->response, "quality", quality);
		cJSON_AddStringToObject(con->response, "ssid", ssid); 
		cJSON_AddStringToObject(con->response, "mode", mode); 
		cJSON_AddNumberToObject(con->response, "channel", channel); 
		
		
	} else if (!strcmp(default_dev, "")) {

	} else {
		snprintf(cmd, sizeof(cmd), "uci show network|grep \"\\.ifname=\"|grep %s |cut -d . -f2|tr -d '\n'" , default_dev);
		shell_printf(cmd, wlface, sizeof(wlface));
		if (!strcmp(wlface, "4g") || !strcmp(default_dev, "3g-4g")) {
			if (!strcmp(default_dev, "3g-4g"))
				strncpy(wlface, "4g", sizeof(wlface));
			snprintf(cmd, sizeof(cmd), "head -c1 /tmp/run/track-%s 2>/dev/null", wlface);
			shell_printf(cmd, active, sizeof(active));
			snprintf(cmd, sizeof(cmd), "ubus call network.interface.%s status | grep uptime|awk '{print $2}'", wlface);
			if (shell_printf(cmd, iface_uptime, sizeof(iface_uptime)) > 0)
				iface_uptime[strlen(iface_uptime) - 1] = '\0';
			shell_printf("ip route|grep default|head -n1|awk BEGIN'{FS=\"via \"}{printf $2}'", droute, sizeof(droute));
			FILE *fp = fopen("/tmp/sysinfo/info4g","r");
			if (fp == NULL)
				goto out;
			char info4g[512] = {0};
			fgets(info4g, sizeof(info4g), fp);
			fclose(fp);
			char sim[64] = "loading---"; char sig[64] = "loading---"; char adr[64] = "loading---"; char cimi[64] = "loading---"; 
			char regs[64] = "loading---"; char regt[64] = "loading---"; char ccid[64] = "loading---"; char imei[64] = "loading---"; char fwversion[64] = "loading---"; 
			char *index = NULL;
			if (!memcmp(info4g, "sim:", strlen("sim:")))
				sscanf(info4g + strlen("sim:"), "%[^ ] ", sim);
			index = strstr(info4g, "sig:");
			if (index)
				sscanf(index + strlen("sig:"), "%[^ ] ", sig);
			index = strstr(info4g, "ip:");
			if (index)
				sscanf(index + strlen("ip:"), "%[^ ] ", adr);
			index = strstr(info4g, "cimi:");
			if (index)
				sscanf(index + strlen("cimi:"), "%[^ ] ", cimi);
			index = strstr(info4g, "regs:");
			if (index)
				sscanf(index + strlen("regs:"), "%[^ ] ", regs);
			index = strstr(info4g, "regt:");
			if (index)
				sscanf(index + strlen("regt:"), "%[^ ] ", regt);
			index = strstr(info4g, "ccid:");
			if (index)
				sscanf(index + strlen("ccid:"), "%[^ ] ", ccid);
			index = strstr(info4g, "imei:");
			if (index)
				sscanf(index + strlen("imei:"), "%[^ ] ", imei);
			index = strstr(info4g, "fwversion:");
			if (index)
				sscanf(index + strlen("fwversion:"), "%[^ ] ", fwversion);
			cJSON_AddStringToObject(con->response, "sim", sim); 
			cJSON_AddStringToObject(con->response, "sig", sig);
			cJSON_AddStringToObject(con->response, "adr", adr);
			cJSON_AddStringToObject(con->response, "cimi", cimi);
			cJSON_AddNumberToObject(con->response, "time", atoi(iface_uptime)); 
			cJSON_AddStringToObject(con->response, "regs", regs); 
			cJSON_AddStringToObject(con->response, "regt", regt); 
			cJSON_AddStringToObject(con->response, "ccid", ccid);
			cJSON_AddStringToObject(con->response, "imei", imei);
			cJSON_AddStringToObject(con->response, "fwversion", fwversion);

		} else {
			if (!strcmp(default_dev, "pppoe-wan"))
				strncpy(wlface, "wan", sizeof(wlface));
			if (!strcmp(default_dev, "pptp-pptp"))
				strncpy(wlface, "pptp", sizeof(wlface));
			snprintf(cmd, sizeof(cmd), "head -c1 /tmp/run/track-%s 2>/dev/null", wlface);
			shell_printf(cmd, active, sizeof(active));
			char if_status[2048] = {0};
			snprintf(cmd, sizeof(cmd), "ubus -S call network.interface.%s status", wlface);
			shell_printf(cmd, if_status, sizeof(if_status));
			char proto[16] = {0}; char wanip[32] = {0}; char device[16] = {0};
			
			cJSON *json_status = cJSON_Parse(if_status);
			
			if (json_status) {
				item = cJSON_GetObjectItem(json_status, "uptime");
				if (item)
					cJSON_AddNumberToObject(con->response, "time", item->valueint);
				item = cJSON_GetObjectItem(json_status, "proto");
				if (item)
					cJSON_AddStringToObject(con->response, "proto", item->valuestring);
				item = cJSON_GetObjectItem(json_status, "ipv4-address");
				if (item)
					item = cJSON_GetArrayItem(item, 0);
					if (item)
						item = cJSON_GetObjectItem(item, "address");
						if (item)
							cJSON_AddStringToObject(con->response, "wanip", item->valuestring);
						
				item = cJSON_GetObjectItem(json_status, "device");
				if (item)
					strcpy(device, item->valuestring);
				cJSON_Delete(json_status);
				
			}
			
			shell_printf("ip route|grep default|head -n1|awk BEGIN'{FS=\"dev \"}{printf $2}'", droute, sizeof(droute));

			char if_info[2048] = {0}; char wanmac[32] = {0}; char rx_bytes[32] = {0}; char tx_bytes[32] = {0};
			if (!strcmp(default_dev, "pptp-pptp"))
				strcpy(device, "pptp-pptp");
			snprintf(cmd, sizeof(cmd), "ubus call network.device status \"{\\\"name\\\":\\\"%s\\\"}\" 2>/dev/null", device);
			shell_printf(cmd, if_info, sizeof(if_info));
			//CGI_LOG(LOG_INFO, "ubus:%s   out:%s\n", cmd, if_info);
			cJSON *iface_info = cJSON_Parse(if_info);
			if (iface_info) {
				item = cJSON_GetObjectItem(iface_info, "macaddr");
				if (item)
					cJSON_AddStringToObject(con->response, "wanmac", item->valuestring);
				cJSON *statistics = cJSON_GetObjectItem(iface_info, "statistics");
				if (statistics) {
					item = cJSON_GetObjectItem(statistics, "rx_bytes");
					cJSON_AddNumberToObject(con->response, "rx", item->valuedouble);
					item = cJSON_GetObjectItem(statistics, "tx_bytes");
					cJSON_AddNumberToObject(con->response, "tx", item->valuedouble);

				}
				item = cJSON_GetObjectItem(iface_info, "macaddr");
				if (item)
					cJSON_AddStringToObject(con->response, "wanmac", item->valuestring);
				cJSON_Delete(iface_info);

			}
			
			//if (!strcmp(wanmac, "00:00:00:00:00:00") && !strcmp(proto, "pppoe"))
			if (!strcmp(default_dev, "pptp-pptp"))
				cJSON_AddStringToObject(con->response, "name", "pptp"); 
			else {
				cJSON_AddStringToObject(con->response, "name", device); 
			}

		}
	}

	int assoclist1 = 0;
	char wlif[16] = {0};
	shell_printf("uci -q get wireless.@wifi-iface[0].ifname | tr -d '\n'", 
					wlif, sizeof(wlif));
	char *pscmd="iwinfo|grep 'ESSID: '|awk '{printf $1}'";
	if (!strcmp(wlif, "apcli0") || !strcmp(wlif, "ra0")) 
		pscmd = "iwinfo ra0 info |grep 'ESSID: '|awk '{printf $1}'";
	else if (!strcmp(wlif, "apclii0") || !strcmp(wlif, "rai0"))
		pscmd = "iwinfo rai0 info |grep 'ESSID: '|awk '{printf $1}'";
	//CGI_LOG(LOG_DEBUG, "before\n");
	if (shell_printf(pscmd, temp, sizeof(temp)) > 0) {
		char iwinfos[4][128]; int cnt = 0;
		cnt = split(iwinfos, temp, "\n");
		for (int i=0; i< cnt;i++) {
			snprintf(cmd, sizeof(cmd),"iwinfo %s a 2>/dev/null|grep -c RX:|awk '{printf $1}'", iwinfos[i]);
			if (shell_printf(cmd, temp, sizeof(temp)) > 0)
				assoclist1 = assoclist1 + atoi(temp);
		}
	}
	//CGI_LOG(LOG_DEBUG, "after\n");
	if (!strcmp(default_dev, "wlan0") || !strcmp(default_dev, "wlan1") ||
		!strcmp(default_dev, "apcli0") || !strcmp(default_dev, "apclii0"))
		assoclist1 = 0;
	
	time_t t = uptime();
	char ethinfo[512] = {0};
	shell_printf("ethinfo", ethinfo, sizeof(ethinfo));
	
	cJSON_AddStringToObject(con->response, "ethinfo", ethinfo);       
	cJSON_AddStringToObject(con->response, "default", wlface);
	cJSON_AddStringToObject(con->response, "active", active);
	cJSON_AddStringToObject(con->response, "droute", droute);
	cJSON_AddNumberToObject(con->response, "assoclist", assoclist1);
	cJSON_AddNumberToObject(con->response, "uptime", t);
out:
	return TYPE_JSON;
}

int cgi_sys_wan_traffic_handler(connection_t *con)
{	
	char *name = con_value_get(con, "name");
	char *id = con_value_get(con, "id");
	char  temp[16] = {0};
	uint64 rx_pre = 0;
	uint64 tx_pre = 0;
	uint64 rx_next = 0;
	uint64 tx_next = 0;
	char cmd[256] = {0};
	snprintf(cmd, sizeof(cmd), "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $2}'", name);
	shell_printf(cmd, temp, sizeof(temp));
	char *res = NULL;
	rx_pre = strtoull(temp, &res, 10);
	snprintf(cmd, sizeof(cmd), "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $10}'", name);
	shell_printf(cmd, temp, sizeof(temp));
	tx_pre = strtoull(temp, &res, 10);
	sleep(1);

	snprintf(cmd, sizeof(cmd), "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $2}'", name);
	shell_printf(cmd, temp, sizeof(temp));
	
	rx_next = strtoull(temp, &res, 10);
	snprintf(cmd, sizeof(cmd), "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $10}'", name);
	shell_printf(cmd, temp, sizeof(temp));
	
	tx_next = strtoull(temp, &res, 10);
	cJSON *item = cJSON_CreateObject();
	cJSON_AddStringToObject(item, "ifc", name);
	cJSON_AddStringToObject(item, "id", id);
	//CGI_LOG(LOG_INFO, "ifc:%s;rx:%lld;tx:%lld;rx_pre:%lld;tx_next:%lld;cmd:%s;temp:%s\n",
	//			name, rx_next-rx_pre,tx_next-tx_pre,rx_pre,tx_next,cmd,temp);
	cJSON_AddNumberToObject(item, "rx", rx_next-rx_pre);
	cJSON_AddNumberToObject(item, "tx", tx_next-tx_pre);
	cJSON *arr = cJSON_CreateArray();
	cJSON_AddItemToArray(arr, item);
	cJSON_Delete(con->response);
	con->response = arr;

out:
	return TYPE_JSON;
}

int cgi_sys_sys_log_handler(connection_t *con)
{	
	char *log_text = malloc(40*1024);
	if (log_text)
		shell_printf("logread -l 200", log_text, 40*1024);
	con->text_plain = log_text;

out:
	return TYPE_PLAIN;
}

int cgi_sys_dmesg_log_handler(connection_t *con)
{	
	char *log_text = malloc(20*1024);
	if (log_text)
		shell_printf("dmesg -s 20470", log_text, 20*1024);
	con->text_plain = log_text;

out:
	return TYPE_PLAIN;
}

int cgi_sys_nlbw_list_handler(connection_t *con)
{	
	char list[128] = {0};
	cJSON *arr = cJSON_CreateArray();
	cJSON *item = NULL;
	if (shell_printf("/usr/sbin/nlbw -c list", list, sizeof(list)) > 0) {
		char nlbwlist[4][128]; int cnt = 0;
		cnt = split(nlbwlist, list, "\n");
		for (int i=0; i< cnt;i++) {
			item = cJSON_CreateString(nlbwlist[i]);
			cJSON_AddItemToArray(arr, item);
		}
	}

	cJSON_Delete(con->response);
	con->response = arr;

out:
	return TYPE_JSON;
}

int cgi_sys_tty_info_handler(connection_t *con)
{	
	char tty_info[1024] = {0};
	cJSON *arr = cJSON_CreateArray();
	
	cJSON *item = NULL;
	char *index = NULL;
	if (shell_printf("serlist", tty_info, sizeof(tty_info)) > 0) {
		char tty_list[20][128]; int cnt = 0;
		cnt = split(tty_list, tty_info, "\n");
		int ret = 0;
		for (int i=0; i< cnt;i++) {
			char tty_dev[32] = {0}; char baud[16] = {0}; char pid[16] = {0};
			char pro[64] = {0};
			ret = sscanf(tty_list[i], "dev:%[^ ] baud:%[^ ] pid:%[^ ]", tty_dev, baud, pid);
			if (ret > 0) {
				item = cJSON_CreateObject();
				cJSON_AddStringToObject(item, "dev", tty_dev);
				index = strstr(tty_list[i], "pro:");
				if (index)
					sscanf(index + strlen("pro:"), "%s ", pro);
				if (strlen(baud) == 0)
					strcpy(baud, "null");
				cJSON_AddStringToObject(item, "baud", baud);
				if (strlen(pid)>0)
					cJSON_AddStringToObject(item, "use", "using");
				else
					cJSON_AddStringToObject(item, "use", "idle");
				if (strlen(pid) == 0)
					strcpy(pid, "null");
				cJSON_AddStringToObject(item, "pid", pid);
				if (strlen(pro) == 0)
					strcpy(pro, "null");
				cJSON_AddStringToObject(item, "pro", pro);
				cJSON_AddItemToArray(arr, item);
			}
		}
	}
	cJSON_AddItemToObject(con->response, "ttylist", arr);
out:
	return TYPE_JSON;
}

int cgi_sys_nlbw_data_handler(connection_t *con)
{
	char *period = con_value_get(con, "period");
	char *group_by = con_value_get(con, "group_by");
	char *order_by = con_value_get(con, "order_by");
	char *type = con_value_get(con, "type");
	char *delim = con_value_get(con, "delim");
	if (!type)
		type = "json";
	if (!delim)
		delim = ";";
	if (strcmp(type, "json") && strcmp(type, "csv")) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}
out:
	return TYPE_JSON_PLAIN;
	
}

int cgi_sys_stop_app_handler(connection_t *con)
{	
	char *app = con_value_get(con, "app");
	if (!app) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}

	cJSON_AddNumberToObject(con->response, "code", 0);

out:
	return TYPE_JSON;
}

int cgi_sys_iface_traffic_handler(connection_t *con)
{	
	char *iface = con_value_get(con, "iface");
	char *id = con_value_get(con, "id");
	if (!iface) {
		cJSON_AddNumberToObject(con->response, "code", 1);
		goto out;
	}
	char traffic_bytes[16] = {0};
	char iface_arr[5][128]; char id_arr[5][128]; 
	int cnt = 0;
	uint64 pre_rx_bytes[5] = {0};
	uint64 pre_tx_bytes[5] = {0};
	uint64 next_rx_bytes[5] = {0};
	uint64 next_tx_bytes[5] = {0};
	cJSON *arr = cJSON_CreateArray();
	cJSON *item = NULL;
	cnt = split(iface_arr, iface, ",");
	split(id_arr, id, ",");
	char cmd[128] = {0}; char *res;
	for (int i=0; i< cnt;i++) {
		snprintf(cmd, sizeof(cmd), "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $2}'", iface_arr[i]);
		if (shell_printf(cmd, traffic_bytes, sizeof(traffic_bytes)) > 0)
			pre_rx_bytes[i] = strtoull(traffic_bytes, &res, 10);
		else 
			pre_rx_bytes[i] = 0;

		snprintf(cmd, sizeof(cmd) - 1, "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $10}'", iface_arr[i]);
		if (shell_printf(cmd, traffic_bytes, sizeof(traffic_bytes)) > 0)
			pre_tx_bytes[i] = strtoull(traffic_bytes, &res, 10);
		else
			pre_tx_bytes[i] = 0;
	}
	sleep(1);
	for (int i=0; i< cnt;i++) {
		item = cJSON_CreateObject();
		snprintf(cmd, sizeof(cmd), "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $2}'", iface_arr[i]);
		if (shell_printf(cmd, traffic_bytes, sizeof(traffic_bytes)) > 0)
			next_rx_bytes[i] = strtoull(traffic_bytes, &res, 10);
		else
			next_rx_bytes[i] = 0;

		snprintf(cmd, sizeof(cmd) - 1, "cat /proc/net/dev | grep %s | sed 's/:/ /g' | awk '{print $10}'", iface_arr[i]);
		if (shell_printf(cmd, traffic_bytes, sizeof(traffic_bytes)) > 0)
			next_tx_bytes[i] = strtoull(traffic_bytes, &res, 10);
		else
			next_tx_bytes[i] = 0;

		cJSON_AddStringToObject(item, "ifc", iface_arr[i]);
		cJSON_AddNumberToObject(item, "rx", next_rx_bytes[i]-pre_rx_bytes[i]);
		cJSON_AddNumberToObject(item, "tx", next_tx_bytes[i]-pre_tx_bytes[i]);
		cJSON_AddStringToObject(item, "id", id_arr[i]);
		cJSON_AddItemToArray(arr, item);
	}

	cJSON_Delete(con->response);
	con->response = arr;

out:
	return TYPE_JSON;
}

int cgi_sys_vpn_status_handler(connection_t *con)
{
	char **array = NULL;
	int num = 0, rlen = 0;
	char mode_type[16] = {0};
	char cmd_out[64] = {0};
	char cmd[160] = {0};
	cJSON *json_status = NULL, *item = NULL, *json_addr = NULL;
	if (!uuci_get("openvpn.client.mode_type", &array, &num)) {
		strncpy(mode_type, array[0], sizeof(mode_type));
		uuci_get_free(array, num);
	}
	if (!strcmp(mode_type, "openvpn")) {
		rlen = shell_printf("ps|grep 'openvpn(client)' 2>/dev/null|grep -v grep|awk '{printf $1}'", cmd_out, sizeof(cmd_out));
		cJSON_AddStringToObject(con->response, "running", cmd_out);
		char ovpn_file[64] = {0};
		char iface_status[1024] = {0};
		if (rlen > 0) {
			if (!uuci_get("openvpn.client.ovpn", &array, &num)) {
				strncpy(ovpn_file, array[0], sizeof(ovpn_file));
				uuci_get_free(array, num);
				
				char vpn_dev[16] = {0};
				char ip[16] = {0}; char rx[16] = {0};
				char tx[16] = {0};
				char mask[16] = {0};
				char *key;
				snprintf(cmd, sizeof(cmd), "grep \"dev t\" %s|grep -v '#'|grep -v ';'|awk '{printf $2}'|head -n1", ovpn_file);
				if (shell_printf(cmd, vpn_dev, sizeof(vpn_dev)) > 0) {
					snprintf(cmd, sizeof(cmd), "ifconfig %s0", vpn_dev);
					if (shell_printf(cmd, iface_status, sizeof(iface_status))>0) {
					
						key = strstr(iface_status, "inet addr:");
						if (key) {
							sscanf(key + strlen("inet addr:"), "%s ", ip);
							cJSON_AddStringToObject(con->response, "address", ip);
						}
						
						key = strstr(iface_status, "RX bytes:");
						if (key) {
							sscanf(key + strlen("RX bytes:"), "%s ", rx);
							cJSON_AddStringToObject(con->response, "rx", rx);
						}
						key = strstr(iface_status, "TX bytes:");
						if (key) {
							sscanf(key + strlen("TX bytes:"), "%s ", tx);
							cJSON_AddStringToObject(con->response, "tx", tx);
						}
						key = strstr(iface_status, "Mask:");
						if (key) {
							sscanf(key + strlen("Mask:"), "%s ", mask);
							cJSON_AddStringToObject(con->response, "mask", mask);
						}
					}
				}
				snprintf(cmd, sizeof(cmd), "ubus -S call network.interface.%s status", vpn_dev);
				if (shell_printf(cmd, iface_status, sizeof(iface_status)) > 0) {
					json_status = cJSON_Parse(iface_status);
					if (json_status) {
						item = cJSON_GetObjectItem(json_status, "uptime");
						if (item)
							cJSON_AddNumberToObject(con->response, "uptime", item->valueint);
					}
				}
				
			}
		}
	} else if (!strcmp(mode_type, "pptp")) {
		rlen = shell_printf("ps|grep 'pptp-ppt' 2>/dev/null|grep -v grep|awk '{print $1}'|tr '\n' ' '|awk '{print $1}'", cmd_out, sizeof(cmd_out));
		cJSON_AddStringToObject(con->response, "running", cmd_out);
		if (rlen > 0) {
			char pptp_out[2048] = {0};
			shell_printf("ubus -S call network.interface.pptp status", pptp_out, sizeof(pptp_out));
			json_status = cJSON_Parse(pptp_out);
			
			if (json_status) {
				item = cJSON_GetObjectItem(json_status, "uptime");
				if (item)
					cJSON_AddNumberToObject(con->response, "uptime", item->valueint);
				item = cJSON_GetObjectItem(json_status, "ipv4-address");
				if (item) {
					json_addr = cJSON_GetArrayItem(item, 0);
					if (json_addr) {
						item = cJSON_GetObjectItem(json_addr, "address");
						if (item)
							cJSON_AddStringToObject(con->response, "address", item->valuestring);
						item = cJSON_GetObjectItem(json_addr, "mask");
						if (item)
							cJSON_AddNumberToObject(con->response, "mask", item->valueint);
						item = cJSON_GetObjectItem(json_addr, "ptpaddress");
						if (item)
							cJSON_AddStringToObject(con->response, "ptpaddress", item->valuestring);
						shell_printf("ubus -S call network.device status \"{\\\"name\\\":\\\"pptp-pptp\\\"}\" 2>/dev/null",
									pptp_out, sizeof(pptp_out));
						cJSON *pptp_info = cJSON_Parse(pptp_out);
						if (pptp_info) {
							cJSON *statistics = cJSON_GetObjectItem(pptp_info, "statistics");
							if (statistics) {
								item = cJSON_GetObjectItem(statistics, "rx_bytes");
								cJSON_AddNumberToObject(con->response, "rx", item->valuedouble);
								item = cJSON_GetObjectItem(statistics, "tx_bytes");
								cJSON_AddNumberToObject(con->response, "tx", item->valuedouble);

							}
							cJSON_Delete(pptp_info);
						}
					}
				}
				cJSON_Delete(json_status);
			}
		}
		
	} else if (!strcmp(mode_type, "l2tp")) {
		shell_printf("ps -w|grep 'options.l2tp' 2>/dev/null|grep -v grep|awk '{print $1}'|tr '\n' ' '|awk '{print $1}'", cmd_out, sizeof(cmd_out));
		cJSON_AddStringToObject(con->response, "running", cmd_out);
	}
	char log_out[20480] = {0};
	shell_printf("tail -n 100 /tmp/log/openvpn-client.log 2>/dev/null|tr '<' '('|tr '>' ')' 2>/dev/null|sed 's/openwrt/vantronos/g' 2>/dev/null",
					log_out, sizeof(log_out));
	cJSON_AddStringToObject(con->response, "Log", log_out);

out:
	return TYPE_JSON;
}

int cgi_sys_4g_status_handler(connection_t *con)
{
	int rlen = 0;
	char cmd[160] = {0};
	FILE *fp = fopen("/tmp/sysinfo/info4g","r");
	if (fp == NULL)
		goto out;
	char file_info4g[512] = {0};
	fgets(file_info4g, sizeof(file_info4g), fp);
	fclose(fp);
	char traffic_info4g[512] = {0}; char *index = NULL; char month_traffic[16] = {0};
	char day_traffic[16] = {0};
	fp = fopen("/usr/share/traffic/traffic_info", "r");
	if (fp) {
		fgets(traffic_info4g, sizeof(traffic_info4g), fp);
		fclose(fp);
		index = strstr(traffic_info4g, "month_traffic:");
		if (index)
			sscanf(index + strlen("month_traffic:"), "%s ", month_traffic);
		cJSON_AddStringToObject(con->response, "month", month_traffic);
		index = strstr(traffic_info4g, "day_traffic:");
		if (index)
			sscanf(index + strlen("day_traffic:"), "%s ", day_traffic);
		cJSON_AddStringToObject(con->response, "day", day_traffic);

	}else {
		cJSON_AddStringToObject(con->response, "month", "0");
		cJSON_AddStringToObject(con->response, "day", "0");
	}
	char board_name[32] = {0};
	shell_printf("awk '{printf $1}' /tmp/sysinfo/board_name", board_name, sizeof(board_name));
	if (!strcmp(board_name, "vt-m2m-r102") || !strcmp(board_name, "vt-m2m-g202")) {
		char sim0[4] = {0}; char sim1[4] = {0}; char sim_use[4] = {0};
		if (shell_printf("head -c1 /sys/class/gpio/sim1/value", sim0, sizeof(sim0)) == 0)
			strcpy(sim0, "1");
		if (shell_printf("head -c1 /sys/class/gpio/sim2/value", sim1, sizeof(sim1)) == 0)
			strcpy(sim1, "1");
		shell_printf("head -c1 /sys/class/leds/vantron:green:sim_select/brightness", sim_use, sizeof(sim_use));
		cJSON_AddStringToObject(con->response, "sim0", sim0);
		cJSON_AddStringToObject(con->response, "sim1", sim1);
		cJSON_AddStringToObject(con->response, "sim_use", sim_use);
		cJSON_AddStringToObject(con->response, "board_name", board_name);
	}
	
	char log_out[10240] = {0};
	shell_printf("tail -n 50 /tmp/log/dial 2>/dev/null", log_out, sizeof(log_out));
	cJSON_AddStringToObject(con->response, "Log", log_out);
	char mod[16] = {0};
	if (shell_printf("sed -n 1p /tmp/sysinfo/usb4g 2>/dev/null|tr -d '\n'", mod, sizeof(mod)) == 0)
		strcpy(mod, "loading---");
	cJSON_AddStringToObject(con->response, "mod", mod);
	char dev[128] = {0};
	if (shell_printf("echo -e `sed -n 4p /tmp/sysinfo/usb4g`' on '`sed -n 3p /tmp/sysinfo/usb4g`",
		dev, sizeof(dev)) == 0)
		strcpy(dev, "loading---");
	cJSON_AddStringToObject(con->response, "dev", dev);
	
	char sim[64] = {0}; char sig[64] = {0}; char adr[64] = {0}; char cimi[64] = "loading---"; 
	char regs[64] = "loading---"; char regt[64] = "loading---"; char ccid[64] = "loading---"; char imei[64] = {0}; char fwversion[64] = "loading---"; 
	if (!memcmp(file_info4g, "sim:", strlen("sim:")))
		sscanf(file_info4g + strlen("sim:"), "%[^ ] ", sim);
	index = strstr(file_info4g, "sig:");
	if (index)
		sscanf(index + strlen("sig:"), "%[^ ] ", sig);
	index = strstr(file_info4g, "ip:");
	if (index)
		sscanf(index + strlen("ip:"), "%[^ ] ", adr);
	index = strstr(file_info4g, "cimi:");
	if (index)
		sscanf(index + strlen("cimi:"), "%[^ ] ", cimi);
	index = strstr(file_info4g, "regs:");
	if (index)
		sscanf(index + strlen("regs:"), "%[^ ] ", regs);
	index = strstr(file_info4g, "regt:");
	if (index)
		sscanf(index + strlen("regt:"), "%[^ ] ", regt);
	index = strstr(file_info4g, "ccid:");
	if (index)
		sscanf(index + strlen("ccid:"), "%[^ ] ", ccid);
	index = strstr(file_info4g, "imei:");
	if (index)
		sscanf(index + strlen("imei:"), "%[^ ] ", imei);
	index = strstr(file_info4g, "fwversion:");
	if (index)
		sscanf(index + strlen("fwversion:"), "%[^ ] ", fwversion);
	if (strcmp(sim, "?") && strcmp(mod, "0") && strcmp(adr, "0.0.0.0")) {
		uint64 rx_pre = 0, tx_pre = 0, rx_next = 0, tx_next = 0;char  temp[16] = {0};
		char *res = NULL;
		shell_printf("cat /proc/net/dev | grep '3g-4g'| sed 's/:/ /g' | awk '{print $2}'", temp, sizeof(temp));
		rx_pre = strtoull(temp, &res, 10);
		shell_printf("cat /proc/net/dev | grep '3g-4g'| sed 's/:/ /g' | awk '{print $10}'", temp, sizeof(temp));
		tx_pre = strtoull(temp, &res, 10);
		sleep(1);
		shell_printf("cat /proc/net/dev | grep '3g-4g'| sed 's/:/ /g' | awk '{print $2}'", temp, sizeof(temp));
		rx_next = strtoull(temp, &res, 10);
		shell_printf("cat /proc/net/dev | grep '3g-4g'| sed 's/:/ /g' | awk '{print $10}'", temp, sizeof(temp));
		tx_next = strtoull(temp, &res, 10);
		cJSON_AddNumberToObject(con->response, "rx", rx_next-rx_pre); 
		cJSON_AddNumberToObject(con->response, "tx", tx_next-tx_pre); 
	} else {
		cJSON_AddNumberToObject(con->response, "rx", 0); 
		cJSON_AddNumberToObject(con->response, "tx", 0); 
	}
	cJSON_AddStringToObject(con->response, "sim", sim); 
	cJSON_AddStringToObject(con->response, "sig", sig);
	cJSON_AddStringToObject(con->response, "adr", adr);
	cJSON_AddStringToObject(con->response, "cimi", cimi);
	cJSON_AddStringToObject(con->response, "regs", regs); 
	cJSON_AddStringToObject(con->response, "regt", regt); 
	cJSON_AddStringToObject(con->response, "ccid", ccid);
	cJSON_AddStringToObject(con->response, "imei", imei);
	cJSON_AddStringToObject(con->response, "fwversion", fwversion);
	

out:
	return TYPE_JSON;
}


int cgi_sys_iface_status_handler(connection_t *con)
{
	char *iface = con_value_get(con, "iface");
	if (!iface) {
		cJSON_AddStringToObject(con->response, "code", "iface null");
		goto out;
	}
	char cmd[128] = {0};
	char iface_arr[5][128];
	int cnt = 0;
	cJSON *json_status, *item, *out_item;
	cJSON *arr = cJSON_CreateArray();
	cnt = split(iface_arr, iface, ",");
	for (int i=0; i< cnt; i++) {
		char iface_out[1024] = {0};
		snprintf(cmd, sizeof(cmd), "ubus -S call network.interface.%s status", iface_arr[i]);
		shell_printf(cmd, iface_out, sizeof(iface_out));
		json_status = cJSON_Parse(iface_out);
		if (json_status) {
			item = cJSON_CreateObject();
			out_item = cJSON_GetObjectItem(json_status, "proto");
			if (out_item)
				cJSON_AddStringToObject(item, "proto", out_item->valuestring);
			
			out_item = cJSON_GetObjectItem(json_status, "up");
			cJSON_AddBoolToObject(item, "is_up", out_item->type);
			if (out_item->type == cJSON_False) {
				
			}
			out_item = cJSON_GetObjectItem(json_status, "ipv4-address");
			if (out_item)
				cJSON_AddItemToObject(item, "ipaddrs", out_item);

		}
			
	}

	//cJSON_AddStringToObject(con->response, "timestring", str);

out:
	return TYPE_JSON;
}

int cgi_sys_local_time_handler(connection_t *con)
{
	time_t t;
	struct tm *timeinfo;
	time(&t);
	timeinfo = localtime(&t);
	char *str = asctime(timeinfo);
	str[strlen(str) - 1] = '\0';

	cJSON_AddStringToObject(con->response, "timestring", str);

out:
	return TYPE_JSON;
}

int cgi_sys_logout_handler(connection_t *con)
{
	char cmd[512] = {0};
	//char *sess = con_value_get(con, "sess");
	char *cookie_tmp = getenv("HTTP_COOKIE");
	char sess[64] = {0};
	if (!cookie_tmp)
		return 0;
	char *key = strstr(cookie_tmp, "sysauth3=");
	if (!key)
		return 0;
	strncpy(sess, key + strlen("sysauth3="), sizeof(sess));
	char *temp = strstr(sess, ";");
	if (temp)
		*temp = '\0';
	snprintf(cmd, sizeof(cmd), "ubus call session destroy \"{\\\"ubus_rpc_session\\\":\\\"%s\\\"}\"", sess);
	cJSON_AddStringToObject(con, "code", "success");
out:
	return TYPE_JSON;
}


