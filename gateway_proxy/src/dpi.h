#ifndef __DPI_H__
#define __DPI_H__
#include "type.h"

enum {
    DPI_POSITION_AUTH_UPLINK    = 0x00,
    DPI_POSITION_AUTH_DOWNLINK  = 0x01,
    DPI_POSITION_BLACK_UPLINK   = 0x02,
    DPI_POSITION_BLACK_DOWNLINK = 0x03,
    DPI_POSITION_WHITE_UPLINK   = 0x04,
    DPI_POSITION_WHITE_DOWNLINK = 0x05,
    
    DPI_POSITION_MAXNUM         = 0x06
};
#define DPI_POSITION_VALID(pos) ((pos)>=DPI_POSITION_AUTH_UPLINK && (pos)<DPI_POSITION_MAXNUM)
enum {
    DPI_L4_PROTO_ALL    = 0x00000000,
    DPI_L4_PROTO_TCP    = 0x00000001,
    DPI_L4_PROTO_UDP    = 0x00000002,
    DPI_L4_PROTO_OTHER  = 0xffffffff
};

typedef struct dpi_policy_st{
    int32 position;
    uint64 maxcnt;  /*最多抓取的数据包的个数*/
    uint64 maxsecs; /*最长抓取的数据包的时间(单位:秒)*/
    uint8 intra_mac[6]; /*00:00:00:00:00:00全部; 否则指定mac地址*/
    uint32 intra_ip;
    uint32 intra_mask;
    uint32 outer_ip;
    uint32 outer_mask;
    int32 l4_proto;
    union {
        /*l4_proto == DPI_L4_PROTO_TCP || l4_proto == DPI_L4_PROTO_UDP*/
        struct {
            uint16 outer_port;
        }port;
    };
}dpi_policy_t;

extern void dpi_policy_send();

#endif

