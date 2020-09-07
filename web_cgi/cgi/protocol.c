#include "connection.h"
#include "protocol.h"

#define PRO_SYS_MAIN  "main"
#define PRO_SYS_MAIN2  "main2"
#define PRO_SYS_CHECK_LOGIN  "check_login"
#define PRO_SYS_TIME  "time"
#define PRO_SYS_TERMINAL  "terminal"
#define PRO_SYS_MASTER  "master"
#define PRO_SYS_MANAGE  "manage"
#define PRO_SYS_METER_POINT  "meter_point"
#define PRO_SYS_DATA_SOURCE  "data_source"
#define PRO_SYS_VERSION  "version"
#define PRO_SYS_UPLOAD_FILE  "upload_file"
#define PRO_SYS_METER_DETAIL "meter_detail"

extern int cgi_sys_main_handler(connection_t *con, cJSON *response);   //主信息获取
extern int cgi_sys_main2_handler(connection_t *con, cJSON *response);	//主2信息获取
extern int cgi_check_login_handler(connection_t *con, cJSON *response);	 //登录检查
extern int cgi_sys_time_handler(connection_t *con, cJSON *response);	//时间处理
extern int cgi_sys_terminal_handler(connection_t *con, cJSON *response);  //集中器网络处理
extern int cgi_sys_master_handler(connection_t *con, cJSON *response);	//主站网络处理
extern int cgi_sys_manage_handler(connection_t *con, cJSON *response);  //集中器管理
extern int cgi_sys_meter_point_handler(connection_t *con, cJSON *response);	
extern int cgi_sys_data_source_handler(connection_t *con, cJSON *response);	//测量点数据处理
extern int cgi_sys_version_handler(connection_t *con, cJSON *response);		//版本处理
extern int cgi_sys_upload_file_handler(connection_t *con, cJSON *response);	//文件上传
extern int cgi_sys_meter_detail_handler(connection_t *con, cJSON *response);	//电表数据

static cgi_protocol_t pro_list[] ={
	{PRO_SYS_MAIN, cgi_sys_main_handler},
	{PRO_SYS_MAIN2, cgi_sys_main2_handler},
	{PRO_SYS_CHECK_LOGIN, cgi_check_login_handler},
	{PRO_SYS_TIME, cgi_sys_time_handler},
	{PRO_SYS_TERMINAL, cgi_sys_terminal_handler},
	{PRO_SYS_MASTER, cgi_sys_master_handler},
	{PRO_SYS_MANAGE, cgi_sys_manage_handler},
	{PRO_SYS_METER_POINT, cgi_sys_meter_point_handler},
	{PRO_SYS_DATA_SOURCE, cgi_sys_data_source_handler},
	{PRO_SYS_VERSION, cgi_sys_version_handler},
	{PRO_SYS_UPLOAD_FILE, cgi_sys_upload_file_handler},
	{PRO_SYS_METER_DETAIL, cgi_sys_meter_detail_handler},
	{NULL,NULL},
};

int cgi_protocol_handler(connection_t *con,cJSON* response)
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

	cJSON_AddStringToObject(response,"opt", opt);

	if (connection_is_set(con) == -1)
		return PRO_BASE_ARG_ERR; 

	if (connection_is_set(con)) {
		cJSON_AddStringToObject(response,"function", "set");
	} else {
		cJSON_AddStringToObject(response,"function", "get");
	}
	return cur_protocol->handler(con,response);
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
