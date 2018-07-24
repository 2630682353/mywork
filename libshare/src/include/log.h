#ifndef __CWMP_LOG_H__
#define __CWMP_LOG_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"
#include <stdarg.h>
#include <stdlib.h>

#define CGI_LOG_PATH  "/tmp/cgi_log"
#define IPC_LOG_PATH  "/tmp/ipc_log"
#define AAA_LOG_PATH  "/tmp/aaa_log"
#define GATEWAY_LOG_PATH "/tmp/gateway_log"
#define SJMAIN_LOG_PATH "/tmp/sjmain_log"
#define FLOW_RECORD_PATH "/tmp/flow_record"


enum log_enum{
	LOG_ERR = 1,
	LOG_WARNING = 2,
	LOG_INFO = 3,
	LOG_DEBUG = 4
};


extern char *log_array[];
extern unsigned int log_leveljf;

#define IPC_LOG(logl,fmt,args...) do{ \
    my_log(logl,IPC_LOG_PATH, "[IPC:%05d,%d,%s]:"fmt, __LINE__, getpid(), log_array[logl - 1], ##args); \
}while(0)

#define CGI_LOG(logl,fmt,args...) do{ \
    my_log(logl,CGI_LOG_PATH, "[CGI:%05d,%d,%s]:"fmt, __LINE__, getpid(), log_array[logl - 1], ##args); \
}while(0)

#define AAA_LOG(logl,fmt,args...) do{ \
    my_log(logl,AAA_LOG_PATH, "[AAA:%05d,%d,%s]:"fmt, __LINE__, getpid(), log_array[logl - 1], ##args); \
}while(0)

#define GATEWAY_LOG(logl,fmt,args...) do{ \
    my_log(logl,GATEWAY_LOG_PATH, "[gateway:%05d,%d,%s]:"fmt, __LINE__, getpid(), log_array[logl - 1], ##args); \
}while(0)

#define SJMAIN_LOG(logl,fmt,args...) do{ \
    my_log(logl,SJMAIN_LOG_PATH, "[sjmain:%05d,%s]:"fmt, __LINE__, log_array[logl - 1], ##args); \
}while(0)

#define FLOW_RECORD(fmt,args...) do{ \
    write_file(FLOW_RECORD_PATH, fmt, ##args); \
}while(0)


extern void my_log(int logl, char *file, const char *fmt, ...);
extern void write_file(char *file, const char *fmt, ...);


#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_LOG_H__*/
