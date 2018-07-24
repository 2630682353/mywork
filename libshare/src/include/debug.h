#ifndef __CWMP_DEBUG_H__
#define __CWMP_DEBUG_H__

#include "type.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum debug_level_en{
    DEBUG_LEVEL_INF     = 0x00,
    DEBUG_LEVEL_WAR     = 0x01,
    DEBUG_LEVEL_ERR     = 0x02,
    DEBUG_LEVEL_PARAM   = 0x03,
    DEBUG_LEVEL_POS     = 0x04,
    DEBUG_LEVEL_TRACE   = 0x05
}debug_level_e;
#define DEBUG_LEVEL_VALID(level)    ((level)>=DEBUG_LEVEL_INF && (level)<=DEBUG_LEVEL_TRACE)

int32 debug_init(void);
void debug_final(void);
int32 debug_print(int8 *fmt,...);
int32 debug(const int32 level,
            const int8 *func,
            const int32 line,
            const char *file,
            int8 *fmt,...);
void hexdump(int8 *p_title, 
             int8 *p_data,
             uint32 dlen,
             uint32 width);

#ifdef DEBUG
#ifndef PRINTF
#define PRINTF(fmt,ARGS...)     debug_print(fmt,##ARGS)
#endif /*PRINTF*/
#ifndef DB_INF
#define DB_INF(fmt,ARGS...)     debug(DEBUG_LEVEL_INF,__func__, __LINE__,__FILE__,fmt,##ARGS)
#endif /*DB_INF*/
#ifndef DB_WAR
#define DB_WAR(fmt,ARGS...)     debug(DEBUG_LEVEL_WAR,__func__, __LINE__,__FILE__,fmt,##ARGS)
#endif /*DB_WAR*/
#ifndef DB_ERR
#define DB_ERR(fmt,ARGS...)     debug(DEBUG_LEVEL_ERR,__func__, __LINE__,__FILE__,fmt,##ARGS)
#endif /*DB_ERR*/
#ifndef DB_PARAM
#define DB_PARAM(fmt,ARGS...)   debug(DEBUG_LEVEL_PARAM,__func__, __LINE__,__FILE__,fmt,##ARGS)
#endif /*DB_PARAM*/
#ifndef DB_POS
#define DB_POS()                debug(DEBUG_LEVEL_POS,__func__, __LINE__,__FILE__,NULL,##ARGS)
#endif /*DB_POS*/
#ifndef TRACE
#define TRACE(fmt,ARGS...)      debug(DEBUG_LEVEL_TRACE,__func__, __LINE__,__FILE__,fmt,##ARGS)
#endif /*TRACE*/
#else /*not define DEBUG*/
#ifndef PRINTF
#define PRINTF(fmt,ARGS...)
#endif /*PRINTF*/
#ifndef DB_INF
#define DB_INF(fmt,ARGS...)
#endif /*DB_INF*/
#ifndef DB_WAR
#define DB_WAR(fmt,ARGS...)
#endif /*DB_WAR*/
#ifndef DB_ERR
#define DB_ERR(fmt,ARGS...)
#endif /*DB_ERR*/
#ifndef DB_PARAM
#define DB_PARAM(fmt,ARGS...)
#endif /*DB_PARAM*/
#ifndef DB_POS
#define DB_POS()
#endif /*DB_POS*/
#ifndef TRACE
#define TRACE(fmt,ARGS...)
#endif /*TRACE*/
#endif /*end of DEBUG*/

#include <assert.h>
#define ASSERT(x)       assert(x)

#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_DEBUG_H__*/
