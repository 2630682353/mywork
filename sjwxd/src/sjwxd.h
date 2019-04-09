#ifndef DATALINK_H
#define DATALINK_H

#define SOCKET_SJWXDC_CGI "/tmp/sjwxdcCgi"
#define PACKET_CONFIG_SIZE (34)

#define closesocket(s) close(s)

/* Windows sockets compatibility defines */
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define ioctlsocket ioctl
#define MAKEWORD(a, b)
#define WSAStartup(a, b) (0)
#define	WSACleanup()
#ifdef __MAC__
/* The constants for these are a little screwy in the prelinked
	MSL GUSI lib and we can't rebuild it, so roll with it */
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAEAGAIN EAGAIN
#define WSAEINPROGRESS EINPROGRESS
#else
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAEAGAIN EAGAIN
#define WSAEINPROGRESS EINPROGRESS
#endif /* __MAC__ */
#define WSAEINTR EINTR
#define SOCKET int
#define GetLastError() (errno)
typedef struct {
	int dummy;
} WSADATA;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifdef DEBUG
#define PERROR perror
#else
#define PERROR(x) 
#endif /* DEBUG */

/* We've got to get FIONBIO from somewhere. Try the Solaris location
        if it isn't defined yet by the above includes. */
#ifndef FIONBIO
#include <sys/filio.h>
#endif /* FIONBIO */

typedef enum PACKET_VERSION{
    PACKET_VERSION_V1 = 1,
    PACKET_VERSION_V2 = 2,
}PACKET_VERSION_E;

typedef enum {
	PACKET_CMD_CLIENT_INFO,
	PACKET_CMD_CONNECT,
	PACKET_CMD_CONNECT_RESULT,
	PACKET_CMD_TICK,
	PACKET_CMD_DOCMD,
	
	PACKET_CTL_GET_TOTAL,
    PACKET_CTL_GET_MAC,
    PACKET_CTL_SWITCH_CHANNEL,
    PACKET_CTL_QUERY_MAC,
    PACKET_CTL_DOCMD,
    PACKET_CTL_STAT,
    PACKET_CTL_RET,

    PACKET_DATA,
    PACKET_DATA_ACK,
}packet_type_e;

typedef struct client_info {
    /* 11:22:33:44:55:66\0 */
    unsigned char mac[18];
    unsigned char ip[4];
}client_info_t;

typedef struct connect_config {
    char remote_host[32];
    unsigned short remote_port;
    char local_host[32];
    unsigned short local_port;
}connect_config_t;

#define LINK_BUFF_SIZE (32)
#define LINK_BUFF_SIZE_MAX (4 * 1024)

/* 数据通道建立后，预留 CMD_RESERVE_SIZE 字节用于命令通信 */
#define CMD_RESERVE_SIZE (1024)

typedef struct _ring_buff {
    unsigned int head;
    unsigned int tail;
    unsigned int count;
    unsigned int buffSize;
    unsigned char *buff;
}ring_buff_t;

typedef struct _line_buff {
    unsigned int head;
    unsigned int tail;
    unsigned int count;
    unsigned int buffSize;
    unsigned char *buff;
}line_buff_t;

/* 线程相关数据 */
typedef struct _pthread_data {
    struct event_base *eBase;
    
    /* 连接链表的头部 */
    struct datalink_info *datalink_head;
    
    /* 当前激活的连接，以及设备的MAC */
    struct datalink_info *datalink_current;
    unsigned char datalink_current_mac[32];

    struct __link **servLinks;

    int tick;

#ifdef CLIENT
    int client_nr;
    char serverHost[32];
    unsigned short serverCmdPort;
    int (*get_socket)(const char *sk_name);
#endif
    
}pthread_data_t;

typedef enum {
    REMOTE_WARN_TYPE_NONE = 0,
    REMOTE_WARN_TYPE_RESUME = 1,
    REMOTE_WARN_TYPE_SLOWDOWN = 2,
	REMOTE_WARN_TYPE_STOP = 3,
}remote_warn_type_e;

typedef struct __link {
    pthread_data_t *pdata;
    int fd;
    
    struct event *send_event;
    struct event *recv_event;

    /* ringbuff 用于收发packet */
    ring_buff_t *packet_buff_send;
    ring_buff_t *packet_buff_recv;
    
    /* linebuff 用于转发数据 */
    /* 指向connect_t 的data_buff，由connect_t负责释放 */
    line_buff_t *data_buff_send;
#if VERSION == 1
    line_buff_t *data_buff_recv;
#endif

    /* 指向stat_t 的forward_in_bytes 或forward_out_bytes */
    unsigned long *write_bytes;
    unsigned long *read_bytes;

    struct datalink_info *datalink;
    struct _connect *connect;

    /* 客户端信息 */
    struct client_info *client_info;
    
#if VERSION == 2
    int remote_data_buff_spare;
    remote_warn_type_e remote_data_buff_spare_warn;
    time_t remote_data_buff_spare_update_time;
#endif

    struct __link *peer;
}link_t;

typedef struct _connect {
    link_t *remote_link;
    link_t *local_link;

    int half_connect;

#if VERSION == 1
    /* linebuff 用于转发数据 */
    line_buff_t *data_buff_in;
    line_buff_t *data_buff_out;
#endif

#if VERSION == 2
    line_buff_t *data_buff_write;
#endif

    unsigned char reAddresses[4];

    /* token格式
        * token[0..7]       server id
        * token[8..15]      client id
        * token[16..23]     rand
        * token[24..30]     reserve
        * token[31]         check_sum
        */
    unsigned char connect_token[32];

    time_t remote_accept_tick;

    struct _connect *prev;
    struct _connect *next;
}connect_t;

#define REMOTE_LINK_TIMEOUT (60)

typedef struct datalink_info {
    /* 命令通道 */
    link_t *cmd_link;

    connect_t *connect;

    struct datalink_info *prev;
    struct datalink_info *next;
}datalink_t;

/* 新建立的数据通道 */
typedef struct dataConnect {
    /* 通道 socket */
    SOCKET socket;

    /* 建立时间，用于超时离线 */
    unsigned int startTime;

    struct dataConnect *prev;
    struct dataConnect *next;
}dataConnect_t;

#pragma pack(push,1)

typedef struct _packet_head {
    unsigned char magic_l;
    unsigned char magic_h;
    unsigned char version;      /* 版本号 */
    unsigned char dataLen_l;
    unsigned char dataLen_h;    /* 包含数据校验和 */
    unsigned char head_sum;
}packet_head_t;

typedef struct _packet {
    int totalLen;
    packet_head_t head;
    unsigned char data[0];        /* 包含数据校验和 */
}packet_t;

#pragma pack(pop)

#define PACKET_HEAD_MAGIC    (0x8a85)
#define PACKET_HEAD_SIZE (6)

typedef struct _stat {
    int client_nr;
    int heartbeat;
    
    int connect_nr;
        
    int cmd_accept;
    int service_accept;
    int data_accept;
    int cgi_accept;

    int write_lost_bytes;
    int read_skip_bytes;
    int magic_match_failed;
    int version_match_failed;

    int malloc_nr;
    int free_nr;

    int link_nr;

    unsigned long forward_in_bytes;
    unsigned long forward_out_bytes;
}stat_t;

extern stat_t stat;
extern time_t started_time;

/* 服务器地址、端口，用于客户端上线后主动连接服务端 */
extern char *serverHost;
extern unsigned short serverCmdPort;

extern connect_config_t config[];
extern const int config_nr;

/* 新建的数据连接 */
extern dataConnect_t *newDataConnectHead;

/* 心跳包周期 */
extern unsigned int heartBeatSecond;

/* 离线超时时间，超时收不到心跳包，即认为离线 */
extern unsigned int heartBeatTimeOutSecond;

/* 用于cgi交互的socket */
extern SOCKET cgi_lsn_fd;

void __destroyLink(link_t *link);
void __destroyConnectLink(link_t *link);
datalink_t *datalinkNewNode(pthread_data_t *pdata, int cmdFd);
int __datalinkDeleteNode(pthread_data_t *pdata, datalink_t *datalink);
connect_t *connectNewNode(connect_t **head);
int connectDeleteNode(connect_t **head, connect_t *node);
int handleCmdRead(link_t *link, packet_t *packet);
void handleCmdWrite(datalink_t *link);
void handleDataAccept(SOCKET dataListen);
void handleNewConnect_Server(datalink_t *datalink, link_t *servLink, int config_index);
void handleNewConnect_Client(datalink_t *datalink, 
            const char *local_host, unsigned short local_port, 
            const unsigned char *connect_token);
int handleCgiAccept(SOCKET cgiListen);
link_t *new_link(pthread_data_t *pdata, int fd);
packet_t *make_packet(const unsigned char *buff, int len);
packet_t *get_packet_from_ringbuff(ring_buff_t *rbuff);

#define FREE_LINK(link)\
    do\
    {\
        if (link != NULL)\
        {\
            free_link(link);\
            link = NULL;\
        }\
    }while(0)

#define FREE_MEM(p)\
    do\
    {\
        if (p != NULL)\
        {\
            free(p);\
            p = NULL;\
        }\
    }while(0)

#define FREE_LINE_BUFF(lbuff)\
    do\
    {\
        if (lbuff != NULL)\
        {\
            free_line_buff(lbuff);\
            lbuff = NULL;\
        }\
    }while(0)


#define FREE_EVENT(event)\
    do\
    {\
        if (event != NULL)\
        {\
            event_del(event);\
            free(event);\
            event = NULL;\
        }\
    }while(0)

#ifdef MEMDEBUG

#define malloc(count) \
    ({void *p = malloc(count);\
    __sync_fetch_and_add(&stat.malloc_nr, 1);\
    /*printf("malloc_debug[%s][%d][%p][%d]\n", __FUNCTION__, __LINE__, p, count);*/\
    p;})

#define free(p) \
    do{\
        __sync_fetch_and_add(&stat.free_nr, 1);\
        /*printf("free_debug[%s][%d][%p]\n", __FUNCTION__, __LINE__, p);*/\
        free(p);\
    }while(0)

#endif

#ifdef DESTROYDEBUG

#define datalinkDeleteNode(pdata, datalink) \
    do{\
        printf("datalinkDeleteNode[%s][%d][%p]\n", __FUNCTION__, __LINE__, datalink);\
        __datalinkDeleteNode(pdata, datalink);\
    }while(0)

#define destroyLink(link) \
    do{\
        printf("destroyLink[%s][%d][%p]\n", __FUNCTION__, __LINE__, link);\
        __destroyLink(link);\
    }while(0)

#define connectDeleteNode(head, node) \
    do{\
        printf("connectDeleteNode[%s][%d][%p][%p]\n", __FUNCTION__, __LINE__, head, node);\
        __connectDeleteNode(head, node);\
    }while(0)

#else   // DESTROYDEBUG

#define datalinkDeleteNode __datalinkDeleteNode
#define destroyLink __destroyLink
#define connectDeleteNode __connectDeleteNode

#endif  // DESTROYDEBUG

#endif // DATALINK_H

