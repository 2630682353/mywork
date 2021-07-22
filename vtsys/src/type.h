#ifndef __TYPE_H__
#define __TYPE_H__

#ifdef  __cplusplus
extern "C" {
#endif

typedef char                int8;
typedef short               int16;
typedef int                 int32;
typedef long long           int64;
typedef unsigned char       uint8;
typedef unsigned short      uint16;
typedef unsigned int        uint32;
typedef unsigned long long  uint64;

typedef enum {
    FALSE = 0,
    TRUE  = 1
}BOOL;

#define ARRAY_SIZE(x)       (sizeof((x)) / sizeof((x)[0]))
#define ALIGN_4_BYTES(s)    ((((s) + 3) / 4) * 4)

typedef struct buffer_st{
    int8 *buf;              /*point to alloced memory buffer*/
    uint32 size;            /*buffer total size*/
    uint32 offset;          /*buffer used offset*/
    uint32 len;             /*buffer used length*/
    //struct buffer_st *next; /*next buffer*/
}buffer_t;

#ifdef  __cplusplus
}
#endif

#endif /*__TYPE_H__*/
