#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>

#include "timer.h"
#include "type.h"
#include "log.h"
#include "cJSON.h"
#include "igd_share.h"
#include "hash_table.h"
#include <curl/curl.h>

static int pipefd[2];
#define HTTP_TIMEOUT 7;

typedef struct flow_statis_t{
	uint64 total_up;
	uint64 total_down;
	uint32 up_time;
	uint32 local_time;
	uint32 upincrease_num;
	uint32 downincrease_num;
}flow_statis;

typedef struct ap_info {
	char mac[20];
	char hard_version[8];
	char soft_version[8];
	char vendor[20];
	char cpu_load[32];
	char wan_mode[8];
	int memory_total;
	int memory_free;
	int disk_total;
	int disk_available;
	char wan_ip[20];
	char lan_ip[20];
	int date;
	int uptime;
	int http_timeout;
	int report_flow_interval;
	char flow_report_url[128];
	int enable_ip_statistics;
}ap_info_t;

typedef struct perip_flow_t {
	uint32 start_time;
	uint64 last_statis_down;
	uint64 last_statis_up;
	uint64 increase_down;
	uint64 increase_up;
	char mac[20];
	char ip[20];
	char host_name[64];
}perip_flow;

static ap_info_t ap_info;
static flow_statis last_statis;
static int report_flow_interval = 600;
static HashTable *ht;

int ap_info_update()
{
	char **array = NULL;
	int num = 0, rlen = 0;
	char temp_disk[10] = {0};
	time_t rawtime;
	struct sysinfo info;
	if (!uuci_get("network.wan.proto", &array, &num)) {
		arr_strcpy(ap_info.wan_mode, array[0]);
		uuci_get_free(array, num);
	}
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}'",
					ap_info.wan_ip, sizeof(ap_info.wan_ip))) > 0) {
		ap_info.wan_ip[rlen - 1] = '\0';
	}
	if (!uuci_get("network.lan.ipaddr", &array, &num)) {
		arr_strcpy(ap_info.lan_ip, array[0]);
		uuci_get_free(array, num);
	}
	if (!sysinfo(&info)) {
		ap_info.uptime = info.uptime;
		ap_info.memory_free = info.freeram;
		ap_info.memory_total = info.totalram;
	}
	if ((rlen = shell_printf("uptime | awk '{print $8 $9 $10}'",
					ap_info.cpu_load, sizeof(ap_info.cpu_load))) > 0) {
		ap_info.cpu_load[rlen - 1] = '\0';
	}
	return 0;
}

int ap_info_init()
{
	char **array = NULL;
	int num = 0, rlen = 0;
	char temp_disk[10] = {0};
	time_t rawtime;
	struct sysinfo info;

	if (!uuci_get("ap_config.ap_base.sjmain_loglevel", &array, &num)) {
		log_leveljf = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("ap_config.ap_base.enable_ip_statistics", &array, &num)) {
		ap_info.enable_ip_statistics = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("ap_config.ap_base.http_timeout", &array, &num)) {
		ap_info.http_timeout = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("ap_config.ap_base.report_flow_interval", &array, &num)) {
		ap_info.report_flow_interval = atoi(array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("ap_config.ap_base.flow_report_url", &array, &num)) {
		strcpy(ap_info.flow_report_url, array[0]);
		uuci_get_free(array, num);
	}

	if (!uuci_get("network.wan.ifname", &array, &num)) {
		char cmd[256] = {0};
		snprintf(cmd, sizeof(cmd) - 1, "cat /sys/class/net/%s/address", array[0]);
		rlen = shell_printf(cmd, ap_info.mac, sizeof(ap_info.mac));
		ap_info.mac[rlen - 1] = '\0';
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.wan.proto", &array, &num)) {
		arr_strcpy(ap_info.wan_mode, array[0]);
		uuci_get_free(array, num);
	}
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}'",
					ap_info.wan_ip, sizeof(ap_info.wan_ip))) > 0) {
		ap_info.wan_ip[rlen - 1] = '\0';
	}
	if (!uuci_get("system.@system[0].hard_version", &array, &num)) {
		arr_strcpy(ap_info.hard_version, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("system.@system[0].soft_version", &array, &num)) {
		arr_strcpy(ap_info.soft_version, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("system.@system[0].vendor", &array, &num)) {
		arr_strcpy(ap_info.vendor, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.lan.ipaddr", &array, &num)) {
		arr_strcpy(ap_info.lan_ip, array[0]);
		uuci_get_free(array, num);
	}
	if (!sysinfo(&info)) {
		ap_info.uptime = info.uptime;
		ap_info.memory_free = info.freeram;
		ap_info.memory_total = info.totalram;
	}
	if ((rlen = shell_printf("uptime | awk '{print $8 $9 $10}'",
					ap_info.cpu_load, sizeof(ap_info.cpu_load))) > 0) {
		ap_info.cpu_load[rlen - 1] = '\0';
	}
	return 0;
					
}

void ht_free_item(void *pf)
{
	if (pf)
		free(pf);
}

void sig_hander( int sig )  
{  
	int save_errno = errno;
	int msg = sig;
	send(pipefd[1], &msg, 4, 0);
	errno = save_errno;
} 

size_t receive_data(void *buffer, size_t size, size_t nmemb, void *receive_buf) {
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
	curl_easy_setopt(mycurl, CURLOPT_TIMEOUT, ap_info.http_timeout); 
	curl_easy_setopt(mycurl, CURLOPT_WRITEFUNCTION, receive_data);
	curl_easy_setopt(mycurl, CURLOPT_WRITEDATA, back_str);
	
	if (!send) {
		curl_easy_setopt(mycurl, CURLOPT_HTTPHEADER, headers);
		res = curl_easy_perform(mycurl);

	} else {
		snprintf(header_str, sizeof(header_str) - 1, "Content-Type:application/json");
		headers = curl_slist_append(headers, header_str); 
		jstr = cJSON_PrintUnformatted(send); 
		SJMAIN_LOG(LOG_DEBUG, "http send %s\n", jstr);
		curl_easy_setopt(mycurl, CURLOPT_HTTPHEADER, headers); 
		curl_easy_setopt(mycurl, CURLOPT_POSTFIELDS, jstr); 
		res = curl_easy_perform(mycurl);
	}
	if (res != CURLE_OK) {
		SJMAIN_LOG(LOG_WARNING, "curl_easy_perform() failed: %d\n", res);
		goto out;
    }
	SJMAIN_LOG(LOG_DEBUG, "http recv %s\n", back_str);
	obj = cJSON_Parse(back_str);
	if (!obj)
		goto out;
	cJSON *result = cJSON_GetObjectItem(obj, "code");
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

int do_flow_report() {
	printf("in report\n");
	int ret = -1;
	cJSON *root = cJSON_CreateObject();
	cJSON *obj = NULL;

	cJSON_AddStringToObject(root, "ap_mac", ap_info.mac);
	
	cJSON_AddNumberToObject(root, "upstream", last_statis.upincrease_num);
	cJSON_AddNumberToObject(root, "downstream", last_statis.downincrease_num);
	cJSON_AddNumberToObject(root, "timestamp", last_statis.local_time);
	if ((ret = http_send(ap_info.flow_report_url, root, &obj, NULL)))
		goto out;
	
out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	return ret;

}

int chain_config_update()
{
	char dhcp_result[4096] = {0};
	char iptables_result[8192] = {0};
	shell_printf("cat /tmp/dhcp.leases | awk '{printf $2\" \"$4\" \"$3\" \"}'", dhcp_result, sizeof(dhcp_result));
	printf("dhcp_result is %s\n", dhcp_result);
	shell_printf("iptables -L ip_statistics -nv | grep -E -o \"([0-9]{1,3}[\.]){3}[0-9]{1,3} \" | uniq",
		iptables_result, sizeof(iptables_result));
	int i = 0;
	char *strdup1 = strdup(dhcp_result);
	char *str_start = strdup1;
	char *current = strchr(str_start, ' ');
	perip_flow *pf = NULL;
	perip_flow *pf2 = NULL;
	char cmd[256] = {0};
	while (current) {
		*current = '\0';
		if (i == 0) {
			pf = malloc(sizeof(perip_flow));
			memset(pf, 0, sizeof(perip_flow));
			strcpy(pf->mac, str_start);
		}
		if (i == 1)
			strcpy(pf->host_name, str_start);
		if (i == 2) {
			if (!strstr(iptables_result, str_start)) {
				
				snprintf(cmd, sizeof(cmd) - 1, "iptables -A ip_statistics -s %s -j RETURN;"
				"iptables -A ip_statistics -d %s -j RETURN", str_start, str_start);
				system(cmd);
				strcpy(pf->ip, str_start);
				hash_table_put2(ht, pf->ip, pf, ht_free_item);
			} else {
				if ((pf2 = hash_table_get(ht, str_start))) {
					if (strcmp(pf2->mac, pf->mac)) {
						strcpy(pf2->mac, pf->mac);
						strcpy(pf2->host_name, pf->host_name);
						snprintf(cmd, sizeof(cmd) - 1, "iptables -D ip_statistics -s %s -j RETURN;"
						"iptables -A ip_statistics -s %s -j RETURN;iptables -D ip_statistics -d %s -j RETURN;"
						"iptables -A ip_statistics -d %s -j RETURN;", str_start, str_start,
						str_start, str_start);
						system(cmd);
					}
				}
				if (pf)
					free(pf);
			}
		}
		str_start = current + 1;
		i++;
		if (i == 3)
			i = 0;
		current = strchr(str_start, ' ');
	}
	char *strdup2 = strdup(iptables_result);
	str_start = strdup2;
	current = strchr(str_start, '\n');
	while (current) {
		*current = '\0';
		if (!strstr(dhcp_result, str_start)) {
			char cmd[256] = {0};
			snprintf(cmd, sizeof(cmd) - 1, "iptables -D ip_statistics -s %s -j RETURN;"
			"iptables -D ip_statistics -d %s -j RETURN", str_start, str_start);
			system(cmd);
			hash_table_rm(ht, str_start);
		}
		str_start = current + 1;
		current = strchr(str_start, ' ');
	}
	free(strdup1);
	free(strdup2);
}

int update_ip_statistics()
{
	time_t t = time(NULL);
	time_t ut = uptime();
	int temp = t%ap_info.report_flow_interval;
	printf("in update_ip_statistics\n");
	chain_config_update();
	if (temp >= ap_info.report_flow_interval - 30 || temp < 30) {
		//上次查的时间小于120秒则不再继续查
		if (ut - last_statis.up_time <= 120)
			return;
		char traffic_detail[4096];
		uint64 total_up;
		uint64 total_down;
		perip_flow *pf = NULL;
		char *res;
		shell_printf("iptables -L ip_statistics -nvx | grep all | awk '{printf $2\" \"$8\" \"}'", traffic_detail, sizeof(traffic_detail));
		printf("traffic_detail is %s\n", traffic_detail);

		char *strdup1 = strdup(traffic_detail);
		char *str_start = strdup1;
		char *current = strchr(str_start, ' ');
		char *check_ip;
		int index = 0;
		while (current) {
			char line[256] = {0};
			*current = '\0';
			if (index == 0)
				total_up = strtoull(str_start, &res, 10);
			if (index == 1)
				check_ip = str_start;
			if (index == 2)
				total_down = strtoull(str_start, &res, 10);
			if (index == 3) {
				pf = hash_table_get(ht, check_ip);
				if (pf)
					pf->increase_down = total_down - pf->last_statis_down;
					pf->increase_up = total_up - pf->last_statis_up;
					pf->last_statis_down = total_down;
					pf->last_statis_up = total_up;
					
					IP_FLOW_RECORD("%lld  %lld  %lld  %lld  %s  %s  %s  %u  %u\n", 
						pf->increase_up/1024, pf->increase_down/1024, total_up/1024, total_down/1024,
					 pf->mac, pf->host_name, check_ip, ut, t);
			}
				
			str_start = current + 1;
			current = strchr(str_start, ' ');
			index++;
			if (index == 4)
				index = 0;
		}
		free(strdup1);
	}
}

int do_statistics()
{
	time_t t = time(NULL);
	time_t ut = uptime();
	int temp = t%ap_info.report_flow_interval;
	printf("in do_statistics\n");
	if (temp >= ap_info.report_flow_interval - 30 || temp < 30) {
		//上次查的时间小于120秒则不再继续查
		if (ut - last_statis.up_time <= 120)
			return;
		char traffic_bytes[16];
		uint64 total_up;
		uint64 total_down;
		char *res;
		shell_printf("iptables -L -nvx | grep sjwx_upload | awk '{printf $2}'", traffic_bytes, sizeof(traffic_bytes));
		printf("traffic is %s\n", traffic_bytes);
		total_up = strtoull(traffic_bytes, &res, 10);	
		total_up = total_up/1024;
		shell_printf("iptables -L -nvx | grep sjwx_download | awk '{printf $2}'", traffic_bytes, sizeof(traffic_bytes));
		total_down = strtoull(traffic_bytes, &res, 10);
		total_down = total_down/1024;

		last_statis.up_time = ut;
		last_statis.local_time = t;
		last_statis.upincrease_num = total_up - last_statis.total_up;
		last_statis.downincrease_num = total_down - last_statis.total_down;
		last_statis.total_down = total_down;
		last_statis.total_up = total_up;
		FLOW_RECORD("%lld  %lld  %d  %d  %u  %u\n", last_statis.total_up, last_statis.total_down, 
			last_statis.upincrease_num,
			last_statis.downincrease_num, last_statis.up_time, last_statis.local_time);
		do_flow_report();
	}
}

int sig_init()
{
	sigset_t sig;
	sigemptyset(&sig);
	sigaddset(&sig, SIGABRT);
	sigaddset(&sig, SIGPIPE);
	sigaddset(&sig, SIGQUIT);
	sigaddset(&sig, SIGUSR1);
	sigaddset(&sig, SIGUSR2);
	sigaddset(&sig, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);
	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);

	return 0;
}

int iptables_init()
{
	char cmd[256] = {0};
	char **array = NULL;
	int num = 0;
	if (!uuci_get("network.wan.ifname", &array, &num)) {
		snprintf(cmd, sizeof(cmd) - 1, "iptables -A forwarding_rule -i %s -j"
			" RETURN -m comment --comment \"sjwx_download\"", array[0]);
		system(cmd);
		snprintf(cmd, sizeof(cmd) - 1, "iptables -A forwarding_rule -o %s -j"
			" RETURN -m comment --comment \"sjwx_upload\"", array[0]);
		system(cmd);
		uuci_get_free(array, num);
	}

	snprintf(cmd, sizeof(cmd) - 1, "rm /tmp/ip_record;rm /tmp/flow_record");
	system(cmd);

	if (ap_info.enable_ip_statistics) {
		char cmd[256] = {0};
		snprintf(cmd, sizeof(cmd) - 1, "iptables -t filter -N ip_statistics;iptables -I forwarding_rule -j"
			" ip_statistics");
		system(cmd);
		add_timer(chain_config_update, 0, 1, 60, NULL, 0);
		add_timer(update_ip_statistics, 0, 1, 60, NULL, 0);
		ht = hash_table_new();
	}
}

int iptables_final()
{
	char cmd[256] = {0};
	char **array = NULL;
	int num = 0;
	if (!uuci_get("network.wan.ifname", &array, &num)) {
		snprintf(cmd, sizeof(cmd) - 1, "iptables -D forwarding_rule -i %s -j"
			" RETURN -m comment --comment \"sjwx_download\"", array[0]);
		system(cmd);
		snprintf(cmd, sizeof(cmd) - 1, "iptables -D forwarding_rule -o %s -j"
			" RETURN -m comment --comment \"sjwx_upload\"", array[0]);
		system(cmd);
		uuci_get_free(array, num);
	}

	if (ap_info.enable_ip_statistics) {
		char cmd[256] = {0};
		snprintf(cmd, sizeof(cmd) - 1, "iptables -t filter -F ip_statistics;iptables -t filter -D "
		"forwarding_rule -j ip_statistics;iptables -t filter -X ip_statistics");
		system(cmd);
		hash_table_delete(ht);
	}
}

int main(int argc, char **argv)
{

	int i = 0, ret = -1;
	sig_init();
	
	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
	if (ret == -1)
		printf("sock err\n");
	ap_info_init();
	timer_list_init();
	add_timer(do_statistics, 0, 1, 60, NULL, 0);
	iptables_init();
	
	curl_global_init(CURL_GLOBAL_ALL);
	struct timeval tv;
	fd_set fds;
	int max_fd = 0;
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
			ret = recv(pipefd[0], signals, sizeof(signals), 0);
			if (ret > 0) {
				for(i = 0; i < ret; i++) {
					switch(signals[i]) {
					case SIGTERM:
					case SIGINT:
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
