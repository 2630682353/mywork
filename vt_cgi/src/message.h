#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"

#define DEFINE_CMD(module, type ,code) (((module)<<24)|((type)<<16)|(code))
#define MODULE_GET(cmd) ((cmd)>>24)
#define MODULE_TYPE_GET(cmd) (((cmd)>>16) & 0x00FF)

enum module_type {
	USER_MODULE = 0,
	KERNEL_MODULE
};

enum module_mid {
	MODULE_MANAGE   = 1,    /*GATEWAY-MANAGE MODULE*/
	MODULE_DPI,             /*DPI MODULE*/
	MODULE_WS,              /*WEB SERVICE MODULE*/
	MODULE_RADIUS,          /*RADIUS-CLIENT MODULE*/
	MODULE_AS,              /*ACCESS-SERVICE MODULE*/
	MODULE_VIDEO_CACHE,
	MODULE_VC,
	MODULE_MAX              /*must be end*/
};

enum msg_cmd_en {
    /*manage module*/
    MSG_CMD_MANAGE_START                = DEFINE_CMD(MODULE_MANAGE, USER_MODULE, 1),
    MSG_CMD_MANAGE_HEARTBEAT            = MSG_CMD_MANAGE_START,
    MSG_CMD_MANAGE_USER_QUERY           = MSG_CMD_MANAGE_START+1,
    MSG_CMD_MANAGE_USER_REGISTER        = MSG_CMD_MANAGE_START+2,
    MSG_CMD_MANAGE_TEXT_SEND            = MSG_CMD_MANAGE_START+3,
    MSG_CMD_MANAGE_START_APP            = MSG_CMD_MANAGE_START+4,
    MSG_CMD_MANAGE_STOP_APP             = MSG_CMD_MANAGE_START+5,
    MSG_CMD_MANAGE_LOG					= MSG_CMD_MANAGE_START+6,
    
    /*web server module*/
    MSG_CMD_WS_START                    = DEFINE_CMD(MODULE_WS, USER_MODULE, 1),
    
    /*dpi module*/
    MSG_CMD_DPI_START                   = DEFINE_CMD(MODULE_DPI, KERNEL_MODULE, 1),
    MSG_CMD_DPI_POLICY_ADD              = MSG_CMD_DPI_START + 0, /*app --> kernel*/
    MSG_CMD_DPI_POLICY_DELETE           = MSG_CMD_DPI_START + 1, /*app --> kernel*/
    MSG_CMD_DPI_END                     = MSG_CMD_DPI_START + 2,
    
    /*AAA module*/
    MSG_CMD_RADIUS_START                = DEFINE_CMD(MODULE_RADIUS, USER_MODULE, 1),
    MSG_CMD_RADIUS_AUTH_TIMEOUT         = MSG_CMD_RADIUS_START + 0, /*kernel --> app, Time out & Flow out*/
    MSG_CMD_RADIUS_USER_AUTH			= MSG_CMD_RADIUS_START + 1, 
    MSG_CMD_RADIUS_LOG					= MSG_CMD_RADIUS_START + 2,
    
    /*access service module*/
    MSG_CMD_AS_START                    = DEFINE_CMD(MODULE_AS, KERNEL_MODULE, 1),
    MSG_CMD_AS_AUTHENTICATED_ADD        = MSG_CMD_AS_START + 0, /*app --> kernel*/
    MSG_CMD_AS_AUTHENTICATED_DELETE     = MSG_CMD_AS_START + 1, /*app --> kernel*/
    MSG_CMD_AS_AUTHENTICATED_QUERY      = MSG_CMD_AS_START + 2, /*app --> kernel*/
    MSG_CMD_AS_BLACKLIST_ADD            = MSG_CMD_AS_START + 3, /*app --> kernel*/
    MSG_CMD_AS_BLACKLIST_DELETE         = MSG_CMD_AS_START + 4, /*app --> kernel*/
    MSG_CMD_AS_BLACKLIST_QUERY          = MSG_CMD_AS_START + 5, /*app --> kernel*/
    MSG_CMD_AS_WHITELIST_ADD            = MSG_CMD_AS_START + 6, /*app --> kernel*/
    MSG_CMD_AS_WHITELIST_DELETE         = MSG_CMD_AS_START + 7, /*app --> kernel*/
    MSG_CMD_AS_WHITELIST_QUERY          = MSG_CMD_AS_START + 8, /*app --> kernel*/
    MSG_CMD_AS_ADVERTISING_ADD          = MSG_CMD_AS_START + 9, /*app --> kernel*/
    MSG_CMD_AS_ADVERTISING_DELETE       = MSG_CMD_AS_START + 10,/*app --> kernel*/
    MSG_CMD_AS_ADVERTISING_QUERY        = MSG_CMD_AS_START + 11,/*app --> kernel*/
    MSG_CMD_AS_ADVERTISING_POLICY_SET   = MSG_CMD_AS_START + 12,/*app --> kernel*/
    MSG_CMD_AS_ADVERTISING_POLICY_QUERY = MSG_CMD_AS_START + 13,/*app --> kernel*/
    MSG_CMD_AS_PORTAL_ADD               = MSG_CMD_AS_START + 14,/*app --> kernel*/
    MSG_CMD_AS_PORTAL_DELETE            = MSG_CMD_AS_START + 15,/*app --> kernel*/
    MSG_CMD_AS_END                      = MSG_CMD_AS_START + 16,

	MSG_CMD_VIDEO_CACHE_START           = DEFINE_CMD(MODULE_VIDEO_CACHE, USER_MODULE, 1),
	MSG_CMD_VIDEO_CACHE_URL             = MSG_CMD_VIDEO_CACHE_START + 1,

	MSG_CMD_VC_START                    = DEFINE_CMD(MODULE_VC, KERNEL_MODULE, 1),
	MSG_CMD_VC_POLICY                   = MSG_CMD_VC_START + 1,
	MSG_CMD_VC_REDIRECT					= MSG_CMD_VC_START + 2,
	
};


#define NETLINK_EVENT     30
#define NETLINK_UMSG     31

enum error_code {
    SUCCESS             = 0,
	ERR_CODE_NONECMD    = 1,
	ERR_CODE_INPUT,
	ERR_CODE_FILE,
	ERR_CODE_MALLOC,
	ERR_CODE_AUTHFAIL,
	ERR_CODE_QUERYNONE,
	ERR_CODE_PARAMETER,
	ERR_CODE_UNSUPPORTED,
	ERR_CODE_OPERATE_ADD,
	ERR_CODE_OPERATE_DELETE,
	ERR_CODE_OPERATE_UPDATE,
	ERR_CODE_OPERATE_QUERY,
};

typedef int32 (*msg_cmd_handle_cb)(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen);

typedef struct msg_st{
    int16    ver;        /*版本号,目前为0x01*/
 	int16    flag;       /*0:表示请求报文;1:表示应答报文*/
    int32   cmd;        /*操作命令字,详见msg_cmd_e的定义*/
    int16   smid;       /*源模块ID*/
    int16   dmid;       /*目的模块ID*/
    int16   sn;         /*序列号,请求报文和应答报文中的序列号必须相同*/
    int16   result;     /*操作结果,请求报文中恒为0,应答报文中返回0或错误码*/
    int32   dlen;       /*数据长度,不包含协议头*/
    int8    data[0];    /*数据*/
}msg_t;

/*参数:模块id，线程数，域套接字接收地址，域套接字发送地址*/
extern int32 msg_init(const int16 module_id); 
extern int32 msg_dst_module_register_unix(const int32 mid);
extern int32 msg_dst_module_register_netlink(const int32 mid);
extern int32 msg_dst_module_unregister(const int32 mid);
extern void msg_final(void);

//kernel module的函数
extern int32 msg_cmd_register(const int32 cmd, msg_cmd_handle_cb cb);
extern int32 msg_cmd_unregister(const int32 cmd);
extern int32 msg_send_syn(int32 cmd, void *sbuf, int32 slen, void **rbuf, int32 *rlen);
extern int32 free_rcv_buf(void *rcv_buf);
extern int32 msg_send_no_reply(int32 cmd, void *sbuf, int32 slen);

#ifdef  __cplusplus
}
#endif

#endif /*__MESSAGE_H__*/

