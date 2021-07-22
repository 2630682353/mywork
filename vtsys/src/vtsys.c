#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "log.h"
#include <sys/time.h>
#include <time.h>
#include "libcom.h"


void usage(char *argv)
{
	printf("Usage:\t%s {info|set|get|send} [target] [value]\n", argv);
}

void sys_info()
{
	char ubus_out[1024] = {0};
	char cmd_out[256] = {0};
	char cmd[128] = {0};
	shell_printf("ubus -S call system info", ubus_out, sizeof(ubus_out));

	cJSON *json_ubus = cJSON_Parse(ubus_out);
	cJSON *out, *item;
	out = cJSON_CreateObject();
	if (json_ubus) {
		item = cJSON_GetObjectItem(json_ubus, "uptime");
		if (item)
			cJSON_AddNumberToObject(out, "uptime", item->valueint);
		item = cJSON_GetObjectItem(json_ubus, "localtime");
		if (item)
			cJSON_AddNumberToObject(out, "localtime", item->valueint);
		item = cJSON_GetObjectItem(json_ubus, "memory");
		if (item)
			cJSON_AddItemReferenceToObject(out, "memory", item);	
		
	}
	shell_printf("ubus -S call system board", ubus_out, sizeof(ubus_out));
	json_ubus = cJSON_Parse(ubus_out);
	if (json_ubus) {
		item = cJSON_GetObjectItem(json_ubus, "kernel");
		if (item)
			cJSON_AddStringToObject(out, "kernel", item->valuestring);
		item = cJSON_GetObjectItem(json_ubus, "hostname");
		if (item)
			cJSON_AddStringToObject(out, "hostname", item->valuestring);
		item = cJSON_GetObjectItem(json_ubus, "system");
		if (item)
			cJSON_AddStringToObject(out, "cpuinfo", item->valuestring);
		item = cJSON_GetObjectItem(json_ubus, "model");
		if (item)
			cJSON_AddStringToObject(out, "model", item->valuestring);
		item = cJSON_GetObjectItem(json_ubus, "board_name");
		if (item)
			cJSON_AddStringToObject(out, "board_name", item->valuestring);
		item = cJSON_GetObjectItem(json_ubus, "release");
		if (item)
			cJSON_AddItemReferenceToObject(out, "release", item);
	}
//	item = cJSON_CreateObject();
//	shell_printf("cat /etc/xos_release | grep DESCRIPTION | awk -F '=' '{print $2}'| tr -d \"\'\\n\"", cmd_out, sizeof(cmd_out));
//	cJSON_AddStringToObject(item, "distrib_description", cmd_out);
//	shell_printf("cat /etc/xos_release | grep DISTRIB_TARGET | awk -F '=' '{print $2}'| tr -d \"\'\\n\"", cmd_out, sizeof(cmd_out));
//	cJSON_AddStringToObject(item, "distrib_target", cmd_out);
//	shell_printf("cat /etc/xos_release | grep DISTRIB_ARCH | awk -F '=' '{print $2}'| tr -d \"\'\\n\"", cmd_out, sizeof(cmd_out));
//	cJSON_AddStringToObject(item, "distrib_arch", cmd_out);
//	cJSON_AddItemReferenceToObject(out, "release", item);
	
	shell_printf("grep 'model name' /proc/cpuinfo | wc -l", cmd_out, sizeof(cmd_out));
	cJSON_AddNumberToObject(out, "cpu_cores", atoi(cmd_out));
	shell_printf("grep 'BogoMIPS' /proc/cpuinfo | uniq | awk '{printf $3}'", cmd_out, sizeof(cmd_out));
	cJSON_AddStringToObject(out, "BogoMIPS", cmd_out);
	shell_printf("cat /proc/loadavg | awk '{printf $1\" \"$2\" \"$3}'", cmd_out, sizeof(cmd_out));
	cJSON_AddStringToObject(out, "load_average", cmd_out);


	char default_dev[16] = {0};
	char wlface[16] = {0};
	shell_printf("ip route|grep 'default'|head -n1|awk BEGIN'{FS=\"dev \"}{print $2}'|awk '{printf $1}'", 
					default_dev, sizeof(default_dev));
	if (!strcmp(default_dev, "wlan0") || !strcmp(default_dev, "wlan1") || !strcmp(default_dev, "apcli0") || !strcmp(default_dev, "apclii0")) {
		if (!strcmp(default_dev, "wlan1"))
			strncpy(wlface, "wwan1", sizeof(wlface)-1);
		else {
			strncpy(wlface, "wwan0", sizeof(wlface)-1);
		}
	}else if (!strcmp(default_dev, "")) {

	} else {
		snprintf(cmd, sizeof(cmd), "uci show network|grep \"\\.ifname=\"|grep %s |cut -d . -f2|tr -d '\n'" , default_dev);
		shell_printf(cmd, wlface, sizeof(wlface));
		if (!strcmp(wlface, "4g") || !strcmp(default_dev, "3g-4g")) {
			if (!strcmp(default_dev, "3g-4g"))
				strncpy(wlface, "4g", sizeof(wlface));
		} else {
			if (!strcmp(default_dev, "pppoe-wan"))
				strncpy(wlface, "wan", sizeof(wlface));
			if (!strcmp(default_dev, "pptp-pptp"))
				strncpy(wlface, "pptp", sizeof(wlface));
		}
	}
	if (strlen(wlface) > 0) {
//		snprintf(cmd, sizeof(cmd), "ubus call network.interface.%s status | grep \\\"address\\\""
//			" | grep -oE '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'", wlface);
		snprintf(cmd, sizeof(cmd), "ubus call network.interface.%s status", wlface);
		shell_printf(cmd, ubus_out, sizeof(ubus_out));
		json_ubus = cJSON_Parse(ubus_out);
			
		if (json_ubus) {
			item = cJSON_GetObjectItem(json_ubus, "ipv4-address");
			if (item)
				item = cJSON_GetArrayItem(item, 0);
				if (item)
					item = cJSON_GetObjectItem(item, "address");
					if (item)
						cJSON_AddStringToObject(out, "wanip", item->valuestring);
					
			item = cJSON_GetObjectItem(json_ubus, "route");
			if (item)
				if (item)
				item = cJSON_GetArrayItem(item, 0);
				if (item)
					item = cJSON_GetObjectItem(item, "nexthop");
					if (item)
						cJSON_AddStringToObject(out, "nexthop", item->valuestring);
			cJSON_Delete(json_ubus);
			
		}

	} else 
		cJSON_AddStringToObject(out, "wanip", "");
//	shell_printf("ubus call network.interface.lan status | grep \\\"address\\\""
//			" | grep -oE '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'", ubus_out, sizeof(ubus_out));
	shell_printf("ubus call network.interface.lan status", ubus_out, sizeof(ubus_out));
	json_ubus = cJSON_Parse(ubus_out);

	if (json_ubus) {
		item = cJSON_GetObjectItem(json_ubus, "ipv4-address");
		if (item)
			item = cJSON_GetArrayItem(item, 0);
			if (item)
				item = cJSON_GetObjectItem(item, "address");
				if (item)
					cJSON_AddStringToObject(out, "lanip", item->valuestring);
		cJSON_Delete(json_ubus);
	}
	char *str = cJSON_PrintUnformatted(out);
	/*
	if (str) {
		printf("%s", str);
		free(str);
	}*/
	str = cJSON_Print(out);
	if (str) {
		printf("%s", str);
		free(str);
	}
}

int main(int argc, char *argv[])
{
	
	struct timeval tvpre,tvafter;
	if (argc < 2)
		sys_info();
	else if(argc < 3 && !strcmp("info", argv[1])){
		
		gettimeofday(&tvpre,NULL);
		sys_info();
		gettimeofday(&tvafter,NULL);
		printf("lasttime:%d ms\n",(int)((tvafter.tv_sec-tvpre.tv_sec)*1000+(tvafter.tv_usec- tvpre.tv_usec)/1000));
			
	} else{
		usage(argv[0]);

		}
	return 0;
}


