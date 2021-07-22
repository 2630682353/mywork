#include "connection.h"
#include "protocol.h"

#define PRO_SYS_QUERY  "query"
#define PRO_SYS_AUTH  "auth"
#define PRO_SYS_LOGIN  "login"
#define PRO_SYS_REGISTER  "register"
#define PRO_SYS_TEXT_CODE  "text_code"
#define PRO_SYS_START_APP  "start_app"
#define PRO_SYS_STOP_APP	"stop_app"
#define PRO_SYS_LOCAL_TIME   "local_time"
#define PRO_SYS_STATUS_INFORMATION "information"
#define PRO_SYS_WAN_TRAFFIC "wan_traffic"
#define PRO_SYS_SYS_LOG "sys_log"
#define PRO_SYS_DMESG_LOG "dmesg_log"
#define PRO_SYS_NLBW_LIST "nlbw_list"
#define PRO_SYS_IFACE_TRAFFIC "iface_traffic"
#define PRO_SYS_IFACE_STATUS "iface_status"
#define PRO_SYS_VPN_STATUS "vpn_status"
#define PRO_SYS_LOGOUT "logout"
#define PRO_SYS_TTY_INFO "tty_info"
#define PRO_SYS_4G_STATUS "4g_status"

extern int cgi_sys_start_app_handler(connection_t *con);   //开启程序
extern int cgi_sys_stop_app_handler(connection_t *con);
extern int cgi_sys_test_handler(connection_t *con);
extern int cgi_sys_status_information_handler(connection_t *con);
extern int cgi_sys_wan_traffic_handler(connection_t *con);
extern int cgi_sys_sys_log_handler(connection_t *con);
extern int cgi_sys_dmesg_log_handler(connection_t *con);
extern int cgi_sys_nlbw_list_handler(connection_t *con);
extern int cgi_sys_local_time_handler(connection_t * con);
extern int cgi_sys_iface_traffic_handler(connection_t * con);
extern int cgi_sys_vpn_status_handler(connection_t * con);
extern int cgi_sys_logout_handler(connection_t * con);
extern int cgi_sys_iface_status_handler(connection_t *con);
extern int cgi_sys_tty_info_handler(connection_t *con);
extern int cgi_sys_4g_status_handler(connection_t *con);

static cgi_protocol_t pro_list[] ={
	{PRO_SYS_START_APP,cgi_sys_start_app_handler},
	{PRO_SYS_STOP_APP,cgi_sys_stop_app_handler},
	{PRO_SYS_STATUS_INFORMATION,cgi_sys_status_information_handler},
	{PRO_SYS_WAN_TRAFFIC,cgi_sys_wan_traffic_handler},
	{PRO_SYS_SYS_LOG,cgi_sys_sys_log_handler},
	{PRO_SYS_DMESG_LOG,cgi_sys_dmesg_log_handler},
	{PRO_SYS_NLBW_LIST,cgi_sys_nlbw_list_handler},
	{PRO_SYS_LOCAL_TIME, cgi_sys_local_time_handler},
	{PRO_SYS_IFACE_TRAFFIC, cgi_sys_iface_traffic_handler},
	{PRO_SYS_IFACE_STATUS, cgi_sys_iface_status_handler},
	{PRO_SYS_VPN_STATUS, cgi_sys_vpn_status_handler},
	{PRO_SYS_LOGOUT,cgi_sys_logout_handler},
	{PRO_SYS_TTY_INFO,cgi_sys_tty_info_handler},
	{PRO_SYS_4G_STATUS,cgi_sys_4g_status_handler},
	{NULL,NULL},
};

int cgi_protocol_handler(connection_t *con)
{
	cJSON *obj;
	cgi_protocol_t *cur_protocol;
	char* opt = con_value_get(con,"opt");
	//char* fname = con_value_get(con,"fname");

	if(!opt)
		return PRO_BASE_ARG_ERR; 

	cur_protocol = find_pro_handler(opt);
	if(!cur_protocol)
		return PRO_BASE_ARG_ERR;

/*

	cJSON_AddStringToObject(response,"opt", opt);

	if (connection_is_set(con) == -1)
		return PRO_BASE_ARG_ERR; 
	if (connection_is_set(con)) {
		cJSON_AddStringToObject(response,"function", "set");
	} else {
		cJSON_AddStringToObject(response,"function", "get");
	}
*/
	return cur_protocol->handler(con);
}

cgi_protocol_t *find_pro_handler(const char *pro_opt)
{
    int i;
    if(pro_opt == NULL)
        return NULL;
    i = 0;
    while(1){
        if(pro_list[i].name == NULL)
            return NULL;
        if(strcmp(pro_list[i].name, pro_opt) == 0){
            return &pro_list[i];
        }
        i++;
    }
        return NULL;
}
