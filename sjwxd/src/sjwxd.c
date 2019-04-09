#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/time.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <sys/un.h>
#include <net/if.h> 
#include <pthread.h>
#include <assert.h>
#include <stdarg.h>

#ifdef SELECT
#include <sys/select.h>
int maxfd = 0;
#else
#include <event.h>
#endif

#include "sjwxd.h"

char *serverHost = "remote.cdsjwx.cn";
unsigned short serverCmdPort = 9000;

typedef struct _server_addr {
    unsigned char host[32];
    unsigned short port;
}server_addr_t;

#if 1
/* 后备服务器采用加密方式，提高安全性 */
server_addr_t server_addr[] = 
{
    "\x64\x73\x7b\x79\x62\x73\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353e,
    "\x65\x7c\x61\x6e\x72\x65\x38\x70\x25\x25\x24\x24\x38\x78\x73\x62\x16\x6e\x38\x75", 0x353f,
    "\x75\x73\x78\x62\x73\x64\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353c,
    "\x75\x79\x78\x70\x7f\x71\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353d,
    "\x7b\x7f\x78\x7f\x65\x7e\x73\x7a\x7a\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16", 0x353a,
    "\x75\x77\x65\x38\x75\x78\x65\x7c\x61\x6e\x38\x75\x78\x16\x16\x16\x16\x6e\x38\x75", 0x353b,
    "\x64\x73\x7b\x79\x62\x73\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353e,
    "\x64\x73\x7b\x79\x62\x73\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353e,
    "\x64\x73\x7b\x79\x62\x73\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353e,
    "\x64\x73\x7b\x79\x62\x73\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353e,
    "\x64\x73\x7b\x79\x62\x73\x38\x75\x72\x65\x7c\x61\x6e\x38\x75\x78\x16\x6e\x38\x75", 0x353e,
};
#else
server_addr_t server_addr[] = 
{
    {
        .host = "remote.cdsjwx.cn",
        .port = 9000,
    },
    {
        .host = "sjwxds.f3322.net",
        .port = 9001,
    },
    {
        .host = "center.cdsjwx.cn",
        .port = 9002,
    },
    {
        .host = "config.cdsjwx.cn",
        .port = 9003,
    },
    {
        .host = "minishell.cdsjwx.cn",
        .port = 9004,
    },
    {
        .host = "cas.cnsjwx.cn",
        .port = 9005,
    },
};
#endif

const int server_addr_nr = sizeof(server_addr) / sizeof(server_addr[0]);

const char *client_dev = "br-lan";
int client_thread_nr = 1;

connect_config_t config[] = 
{
    {
        .remote_port = 11111,
        .local_host = "127.0.0.1",
        .local_port = 80,
    },
    {
        .remote_port = 11112,
        .local_host = "127.0.0.1",
        .local_port = 22,
    },
    {
        .remote_port = 11113,
        .local_host = "127.0.0.1",
        .local_port = 23,
    },
    {
        .remote_port = 11114,
        .local_host = "192.168.88.8",
        .local_port = 17090,
    },
};

const int config_nr = sizeof(config) / sizeof(config[0]);

/* 如果编译链不支持CAS，则需要自己实现，但是效率会降低很多 */
#define GCC_HAVE_CAS

#ifndef GCC_HAVE_CAS

static pthread_mutex_t sync_lock = PTHREAD_MUTEX_INITIALIZER;

#define bool int
#define uint32 unsigned int

bool __sync_bool_compare_and_swap_4 (uint32* ptr, uint32 old, uint32 new)
{
  bool ret;

  pthread_mutex_lock (&sync_lock);

  if (*ptr != old)
    ret = 0;
  else
    {
      *ptr = new;
      ret = 1;
    }

  pthread_mutex_unlock (&sync_lock);

  return ret;
}

uint32 __sync_val_compare_and_swap_4 (uint32* ptr, uint32 old, uint32 new)
{
  bool ret;

  pthread_mutex_lock (&sync_lock);

  ret = *ptr;

  if (*ptr == old)
      *ptr = new;

  pthread_mutex_unlock (&sync_lock);

  return ret;
}

uint32 __sync_fetch_and_add_4 (uint32* ptr, uint32 val)
{
  uint32 ret;

  pthread_mutex_lock (&sync_lock);

  ret = *ptr;

  *ptr = ret + val;

  pthread_mutex_unlock (&sync_lock);

  return ret;
}

uint32 __sync_fetch_and_sub_4 (uint32* ptr, uint32 val)
{
  uint32 ret;

  pthread_mutex_lock (&sync_lock);

  ret = *ptr;

  *ptr = ret - val;

  pthread_mutex_unlock (&sync_lock);

  return ret;
}

#endif  // GCC_HAVE_CAS

/* 新建的数据连接 */
dataConnect_t *newDataConnectHead = NULL;

stat_t stat;

/* 使用select代替libevent，降低内存使用量，同时提高可移植性 */
#ifdef SELECT

#define EV_TIMEOUT	0x01
#define EV_READ		0x02
#define EV_WRITE	0x04
#define EV_SIGNAL	0x08
#define EV_PERSIST	0x10
#define EV_ET       0x20

struct event_base {
    struct event *events;

    struct event *current_event_after_callback;
};

struct event {
	int ev_fd;
	struct event_base *ev_base;

	short ev_events;
	struct timeval ev_timeout;
    struct timeval time_update;

	void (*ev_callback)(int, short, void *);
	void *ev_arg;

    struct event *prev;
    struct event *next;
};

struct event_base *event_base_new(void)
{
    struct event_base *eBase = malloc(sizeof(struct event_base));
    memset(eBase, 0, sizeof(struct event_base));

    return eBase;
}

void event_set(struct event *ev, int fd, short iEvent, void (*callBack)(int, short, void *), void *args)
{
    ev->ev_fd = fd;
    ev->ev_events = iEvent;
    ev->ev_callback = callBack;
    ev->ev_arg = args;
}

int event_base_set(struct event_base *eBase, struct event *ev)
{
    ev->ev_base = eBase;
}

int event_base_priority_init(struct event_base *base, int npriorities)  
{
    return 0;
}

int event_priority_set(struct event *event, int priority)
{
    return 0;
}

int event_add(struct event *ev, const struct timeval *timeout)
{
    struct event_base *eBase = ev->ev_base;

    if (timeout != NULL)
        memcpy(&ev->ev_timeout, timeout, sizeof(struct timeval));
    else
        memset(&ev->ev_timeout, 0, sizeof(struct timeval));

    gettimeofday(&ev->time_update, NULL);
    
    ev->next = eBase->events;

    if (eBase->events != NULL)
        eBase->events->prev = ev;
    
    eBase->events = ev;
}

int event_del(struct event *ev)
{
    struct event_base *eBase = ev->ev_base;
    struct event *p = eBase->events;

    while (p != NULL)
    {
        if (p == ev)
        {
            if (p->prev != NULL)
                p->prev->next = p->next;

            if (p->next != NULL)
                p->next->prev = p->prev;

            if (p == eBase->events)
                eBase->events = eBase->events->next;

            if (p == eBase->current_event_after_callback)
                eBase->current_event_after_callback = p->next;

            p->prev = NULL;
            p->next = NULL;
            
            break;
        }
        
        p = p->next;
    }
}

void select_wait(struct event_base *eBase, fd_set *readfds, fd_set *writefds)
{
    FD_ZERO(readfds);
    FD_ZERO(writefds);

    struct event *event = eBase->events;
    struct timeval tv;

    int ev_count = 0;
    int read_count = 0;
    int write_count = 0;

    while (event != NULL)
    {
        if ((event->ev_events & EV_READ) == EV_READ)
        {
            FD_SET(event->ev_fd, readfds);
            read_count++;
        }

        if ((event->ev_events & EV_WRITE) == EV_WRITE)
        {
            FD_SET(event->ev_fd, writefds);
            write_count++;
        }

        event = event->next;

        ev_count++;
    }

#ifdef SELECTDEBUG
    fprintf(stderr, "select_wait count event[%d]read[%d]write[%d].\n", ev_count, read_count, write_count);
#endif

    struct timeval timeout;
    memset(&timeout, 0, sizeof(timeout));
    timeout.tv_sec = 1;

    if (select(maxfd + 1, readfds, writefds, 0, &timeout) < 0)
    {   
#ifdef SELECTDEBUG
        fprintf(stderr, "no socket ready!\n");
#endif
    }
}

void select_do(struct event_base *eBase, fd_set *readfds, fd_set *writefds)
{
    struct event *event = NULL;
    struct timeval tv;
    short events;

    event = eBase->events;

    gettimeofday(&tv, NULL);

    int ev_count = 0;
    int read_count = 0;
    int write_count = 0;
    int timeout_count = 0;

    while (event != NULL)
    {
        events = 0;

        /* 可读 */
        if ((event->ev_events & EV_READ) == EV_READ
            && FD_ISSET(event->ev_fd, readfds))
        {
            events |= EV_READ;
            read_count++;
        }

        /* 可写 */
        if ((event->ev_events & EV_WRITE) == EV_WRITE
            && FD_ISSET(event->ev_fd, writefds))
        {
            events |= EV_WRITE;
            write_count++;
        }

        /* 超时 */
        if (events == 0 
            && event->ev_timeout.tv_sec != 0
            && tv.tv_sec >= (event->ev_timeout.tv_sec + event->time_update.tv_sec))
        {
            events |= EV_TIMEOUT;
            timeout_count++;
        }

        /* 执行回调 */
        eBase->current_event_after_callback = event->next;
        
        if (events != 0)
        {
            /* 刷新超时时间 */
            event->time_update.tv_sec = tv.tv_sec;
            
            if (event->ev_callback != NULL)
                event->ev_callback(event->ev_fd, events, event->ev_arg);
        }

        event = eBase->current_event_after_callback;

        ev_count++;
    }

#ifdef SELECTDEBUG
    fprintf(stderr, "select_do count event[%d]read[%d]write[%d]timeout[%d].\n", ev_count, read_count, write_count, timeout_count);
#endif
}

int event_base_dispatch(struct event_base *eBase)
{
    fd_set readfds, writefds;
    
    while (1)
    {
        select_wait(eBase, &readfds, &writefds);
        select_do(eBase, &readfds, &writefds);
    }
}

#endif

void term(int s)
{
	exit(0);
}

void plumber(int s)
{
	signal(SIGPIPE, plumber);
}

void hup(int s)
{
	signal(SIGHUP, hup);
}

#if defined(PACKET_EVENT_DEBUG) || defined(DATA_EVENT_DEBUG)
void __dump_event(const char *fun_name , link_t *link)
{
    assert(fun_name != NULL);
    assert(link != NULL);
    
    fprintf(stderr,
            "[%s]\n"
            "link           [%p]\n"
            "link.send_event[%p]\n"
            "link.recv_event[%p]\n"
            "\n",
            fun_name,
            link, 
            link->send_event,
            link->recv_event);
}
#endif

#ifdef PACKET_EVENT_DEBUG
#define packet_dump_event(link) __dump_event(__FUNCTION__, link)
#define packet_log_trigger_sendevent(link) fprintf(stderr, "packet trigger send_event[%p][%p]\n\n", link, link->send_event);
#define packet_log_add_sendevent(link) fprintf(stderr, "packet add send_event[%p][%p][%p][%p][%p]\n\n", \
                                                link, link->send_event, link->recv_event, link->datalink, link->connect);
#define packet_log_del_sendevent(link) fprintf(stderr, "packet del send_event[%p][%p][%p][%p][%p]\n\n", \
                                                link, link->send_event, link->recv_event, link->datalink, link->connect);
#define packet_log_continue_sendevent(link) fprintf(stderr, "packet continue send_event[%p][%p][%p][%p][%p]\n\n", \
                                                link, link->send_event, link->recv_event, link->datalink, link->connect);
#else
#define packet_dump_event(link)
#define packet_log_trigger_sendevent(link)
#define packet_log_add_sendevent(link)
#define packet_log_del_sendevent(link)
#define packet_log_continue_sendevent(link)
#endif

#ifdef DATA_EVENT_DEBUG
#define data_dump_event(link) __dump_event(__FUNCTION__, link)
#define data_log_trigger_sendevent(link) fprintf(stderr, "data trigger send_event[%p][%p]\n\n", link, link->send_event);
#define data_log_add_sendevent(link) fprintf(stderr, "data add send_event[%p][%p][%p][%p][%p]\n\n", \
                                                link, link->send_event, link->recv_event, link->datalink, link->connect);
#define data_log_del_sendevent(link) fprintf(stderr, "data del send_event[%p][%p][%p][%p][%p]\n\n", \
                                                link, link->send_event, link->recv_event, link->datalink, link->connect);
#define data_log_continue_sendevent(link) fprintf(stderr, "data continue send_event[%p][%p][%p][%p][%p]\n\n", \
                                                link, link->send_event, link->recv_event, link->datalink, link->connect);
#else
#define data_dump_event(link)
#define data_log_trigger_sendevent(link)
#define data_log_add_sendevent(link)
#define data_log_del_sendevent(link)
#define data_log_continue_sendevent(link)
#endif

void __dump_packet(const char *fun_name, const packet_t *packet)
{
    int i = 0;
    unsigned int len = (packet->head.dataLen_h << 8) | packet->head.dataLen_l;

    fprintf(stderr, "%s version[%d] len[%d].\n", fun_name, packet->head.version, len);
    
    fprintf(stderr, "head:\n");
    unsigned char *packetHead = (unsigned char *)&packet->head;
    for (i = 0; i < sizeof(packet_head_t); i++)
    {
        fprintf(stderr, "%02x ", packetHead[i]);
    }
    
    fprintf(stderr, "\ndata:\n");
    for (i = 0; i < len; i++)
    {
        fprintf(stderr, "%02x ", packet->data[i]);
    }
    fprintf(stderr, "\n");
}

#define dump_packet(packet) __dump_packet(__FUNCTION__, packet)

void __dump_buff(const char *fun_name, const unsigned char *buff, int count)
{
    fprintf(stderr, "%s:\n", fun_name);
    int i = 0;
    for (i = 0; i < count; i++)
    {
        fprintf(stderr, "%02x ", buff[i]);

        if ((i % 8) == 7)
            fprintf(stderr, " ");

        if ((i % 16) == 15)
            fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n");
}

#define dump_buff(buff, count) __dump_buff(__FUNCTION__, buff, count)

void logToFile(const char *format, ...)
{
    va_list vlist;

    va_start(vlist, format);
    vfprintf(stderr, format, vlist);
    va_end(vlist);

    FILE *fp = fopen("error.log", "a");
    if (fp == NULL)
    {
        fprintf(stderr, "open error.log failed.\n");
        return;
    }
    
    va_start(vlist, format);
    vfprintf(fp, format, vlist);
    va_end(vlist);

    fclose(fp);
}

int ringBuffPut(ring_buff_t *ringBuff, const unsigned char *buff, unsigned int size)
{
    if (size > (ringBuff->buffSize - ringBuff->count))
    {
        size = ringBuff->buffSize - ringBuff->count;
    }

    if (size <= (ringBuff->buffSize - ringBuff->head))
    {
        memcpy(ringBuff->buff + ringBuff->head, buff, size);
    }
    else
    {
        int part1 = ringBuff->buffSize - ringBuff->head;
        memcpy(ringBuff->buff + ringBuff->head, buff, part1);
        memcpy(ringBuff->buff, buff + part1, size - part1);
    }
    
    ringBuff->count += size;
    ringBuff->head += size;
    ringBuff->head %= ringBuff->buffSize;

    return size;
}

int ringBuffGet(ring_buff_t *ringBuff, unsigned char *buff, unsigned int size, int updatePos)
{
    if (size > ringBuff->count)
    {
        size = ringBuff->count;
    }

    if (size <= (ringBuff->buffSize - ringBuff->tail))
    {
        memcpy(buff, ringBuff->buff + ringBuff->tail, size);
    }
    else
    {
        int part1 = ringBuff->buffSize - ringBuff->tail;
        memcpy(buff, ringBuff->buff + ringBuff->tail, part1);
        memcpy(buff + part1, ringBuff->buff, size - part1);
    }

    if (updatePos == 1)
    {
        ringBuff->count -= size;
        ringBuff->tail += size;
        ringBuff->tail %= ringBuff->buffSize;
    }

    return size;
}

int ringUpdatePos(ring_buff_t *ringBuff, unsigned int size)
{
    assert(size <= ringBuff->count);

    ringBuff->count -= size;
    ringBuff->tail += size;
    ringBuff->tail %= ringBuff->buffSize;

    return size;
}

int ringBuffCount(ring_buff_t *ringBuff)
{
    return ringBuff->count;
}

int ringBuffSize(ring_buff_t *ringBuff)
{
    return ringBuff->buffSize;
}

int ringBuffFull(ring_buff_t *ringBuff)
{
    return (ringBuff->count == ringBuff->buffSize);
}

int ringBuffEmpty(ring_buff_t *ringBuff)
{
    return (ringBuff->count == 0);
}

int ringBuffSpare(ring_buff_t *ringBuff)
{
    return (ringBuff->buffSize - ringBuff->count);
}

int ringBuffSetSize(ring_buff_t *ringBuff, int new_size)
{
    if (ringBuff == NULL)
        return -1;

    if (new_size <= 0)
        return -2;

    if (new_size < ringBuff->count)
        return -3;

    unsigned char *new_buff = malloc(new_size);
    if (new_buff == NULL)
        return -4;

    if (ringBuff->buffSize != 0 && ringBuff->buff != NULL)
    {
        ringBuffGet(ringBuff, new_buff, ringBuff->count, 0);
        free(ringBuff->buff);
    }
    
    ringBuff->buff = new_buff;
    ringBuff->buffSize = new_size;
    ringBuff->head = ringBuff->count;
    ringBuff->tail = 0;

    return new_size;
}

ring_buff_t *malloc_ring_buff(int size)
{
    ring_buff_t *rbuff = NULL;
    
    rbuff = malloc(sizeof(ring_buff_t));
    if (rbuff == NULL)
    {
        fprintf(stderr, "[%s] malloc ring buff failed.\n", __FUNCTION__);
        return NULL;
    }
    
    memset(rbuff, 0, sizeof(ring_buff_t));

    int ret = ringBuffSetSize(rbuff, size);
    if (ret != size)
    {
        fprintf(stderr, "[%s] ringBuffSetSize failed[%d][%d].\n", __FUNCTION__, ret, size);
        return NULL;
    }
    
    return rbuff;
}

void free_ring_buff(ring_buff_t *rbuff)
{
    if (rbuff->buff != NULL)
        free(rbuff->buff);

    free(rbuff);
}

int read_into_ringbuff(ring_buff_t *rbuff, int fd)
{
    int iLen = 0;
    unsigned char packet_buff_recv[LINK_BUFF_SIZE_MAX];

    assert(ringBuffSpare(rbuff) <= sizeof(packet_buff_recv));

    iLen = read(fd, packet_buff_recv, ringBuffSpare(rbuff));
    if (iLen <= 0) 
        return iLen;

    int count = ringBuffPut(rbuff, packet_buff_recv, iLen);
    assert(count == iLen);
    
    return iLen;
}

int write_into_ringbuff(ring_buff_t *rbuff, const unsigned char *buff, int len)
{    
    if (ringBuffFull(rbuff))
        return 0;
    
    return ringBuffPut(rbuff, buff, len);
}

int lineBuffCount(line_buff_t *lbuff)
{
    return lbuff->count;
}

int lineBuffSize(line_buff_t *lbuff)
{
    return lbuff->buffSize;
}

int lineBuffFull(line_buff_t *lbuff)
{
    return (lbuff->count == lbuff->buffSize);
}

int lineBuffEmpty(line_buff_t *lbuff)
{
    return (lbuff->count == 0);
}

int lineBuffSpare(line_buff_t *lbuff)
{
    return (lbuff->buffSize - lbuff->count);
}

int lineBuffSetSize(line_buff_t *lbuff, int new_size)
{
    if (lbuff == NULL)
        return -1;

    if (new_size <= 0)
        return -2;

    if (new_size < lbuff->count)
        return -3;

    unsigned char *new_buff = malloc(new_size);
    if (new_buff == NULL)
        return -4;

    if (lbuff->buffSize != 0 && lbuff->buff != NULL)
    {
        memcpy(new_buff, lbuff->buff, lbuff->count);
        free(lbuff->buff);
    }
    
    lbuff->buff = new_buff;
    lbuff->buffSize = new_size;
    lbuff->head = lbuff->count;
    lbuff->tail = 0;

    return new_size;
}

line_buff_t *malloc_line_buff(int size)
{
    line_buff_t *lbuff = NULL;
    
    lbuff = malloc(sizeof(line_buff_t));
    if (lbuff == NULL)
    {
        fprintf(stderr, "[%s] malloc line buff failed.\n", __FUNCTION__);
        return NULL;
    }
    
    memset(lbuff, 0, sizeof(line_buff_t));

    int ret = lineBuffSetSize(lbuff, size);
    if (ret != size)
    {
        fprintf(stderr, "[%s] lineBuffSetSize failed[%d][%d].\n", __FUNCTION__, ret, size);
        return NULL;
    }
    
    return lbuff;
}

void free_line_buff(line_buff_t *lbuff)
{
    if (lbuff->buff != NULL)
        free(lbuff->buff);

    free(lbuff);
}

int write_into_linebuff(line_buff_t *lbuff, const unsigned char *buff, int len)
{
    if (len > lbuff->buffSize - lbuff->head)
        len = lbuff->buffSize - lbuff->head;

    if (len == 0)
        return 0;
    
    memcpy(lbuff->buff + lbuff->head, buff, len);

    lbuff->head += len;
    lbuff->count += len;
    
    return len;
}

int packHeadOK(const unsigned char *packHead)
{
    int i = 0;
    unsigned char sum = 0;

    if (packHead[0] != (PACKET_HEAD_MAGIC & 0xff)
        || packHead[1] != ((PACKET_HEAD_MAGIC >> 8) & 0xff))
    {
        return 0;
    }
    
    for (i = 0; i < 5; i++)
        sum += packHead[i];

    if (sum != packHead[5])
        return 0;

    return 1;
}

int packDataOK(const unsigned char *data, int len)
{
    int i = 0;
    unsigned char sum = 0;

    for (i = 0; i < (len - 1); i++)
        sum += data[i];

    if (sum != data[len - 1])
        return 0;

    return 1;
}

packet_t *get_packet_from_ringbuff(ring_buff_t *rbuff)
{
    assert(rbuff != NULL);

    /* 获取包头 */
    packet_head_t packHead;
    
repeat:
    while (ringBuffCount(rbuff) >= 6)
    {
        ringBuffGet(rbuff, (unsigned char *)&packHead, 6, 0);
        if (packHeadOK((const unsigned char *)&packHead))
            break;
        
        ringUpdatePos(rbuff, 1);
        __sync_fetch_and_add(&stat.read_skip_bytes, 1);
        logToFile(" %02x", packHead.magic_l);
    }

    if (ringBuffCount(rbuff) < 6)
        return NULL;

    /* 获取数据内容 */
    PACKET_VERSION_E version = packHead.version;
    unsigned int len = (packHead.dataLen_h << 8) | packHead.dataLen_l;

    int buff_size = ringBuffSize(rbuff);
    if (buff_size < (6 + len))
    {
        /* 缓存不够，则加倍缓存大小，直至上限 */
        if (buff_size >= LINK_BUFF_SIZE_MAX)
        {
            ringUpdatePos(rbuff, 1);
            goto repeat;
        }

        buff_size *= 2;
        int ret = ringBuffSetSize(rbuff, buff_size);
        if (ret != buff_size)
        {
            fprintf(stderr, "[%s] ringBuffSetSize failed[%d][%d].\n", __FUNCTION__, ret, buff_size);
            ringUpdatePos(rbuff, 1);
            goto repeat;
        }
        
#ifdef DEBUG
        fprintf(stderr, "[%s] ringBuffSetSize[%d].\n", __FUNCTION__, buff_size);
#endif
    }
    
    if (ringBuffCount(rbuff) < (6 + len))
        return NULL;

    /* head 和 data 一次分配 */    
    packet_t *packet = malloc(sizeof(packet_t) + len);
    if (packet == NULL)
    {
        logToFile("malloc packet failed.\n");
        return NULL;
    }

    assert(sizeof(packet_head_t) == 6);
    ringBuffGet(rbuff, (unsigned char *)&packet->head, sizeof(packet_head_t) + len, 1);    
    packet->totalLen = sizeof(packet_head_t) + len;

    if (!packDataOK(packet->data, len))
    {
        __sync_fetch_and_add(&stat.read_skip_bytes, packet->totalLen);
        free(packet);
        goto repeat;
    }

#ifdef PACKETDEBUG
    dump_packet(packet);
#endif
    return packet;
}

packet_t *make_packet(const unsigned char *buff, int len)
{
    assert(sizeof(packet_head_t) == 6);

    int i = 0;
    /* data, data_sum */
    int dataLen = len + 1;
    int totalLen = sizeof(packet_t) + dataLen;
    packet_t *packet = malloc(totalLen);
    if (packet == NULL)
    {
        logToFile("[%s]malloc packet failed.\n", __FUNCTION__);
        return NULL;
    }
    memset(packet, 0, totalLen);
    
    packet->totalLen = sizeof(packet_head_t) + dataLen;

    /* 发送包头 */
    unsigned char *packHead = (unsigned char *)&packet->head;
    packHead[0] = PACKET_HEAD_MAGIC & 0xff;
    packHead[1] = (PACKET_HEAD_MAGIC >> 8) & 0xff;
    
#if VERSION == 1
    packHead[2] = PACKET_VERSION_V1;
#elif VERSION == 2
    packHead[2] = PACKET_VERSION_V2;
#endif

    packHead[3] = dataLen & 0xff;
    packHead[4] = (dataLen >> 8) & 0xff;

    for (i = 0; i < 5; i++)
        packHead[5] += packHead[i];

    /* 发送数据 */
    memcpy(packet->data, buff, len);

    for (i = 0; i < len; i++)
        packet->data[len] += buff[i];

#ifdef PACKETDEBUG
    dump_packet(packet);
#endif
    return packet;
}

static void add_send_event(link_t *link,
                                void (*onWriteCallBack)(int iCliFd, short iEvent, void *arg))
{
    assert(link->send_event == NULL);

    struct event *send_event = malloc(sizeof(struct event));
    if (send_event == NULL)
    {
        logToFile("malloc send_event failed.\n");
        exit(1);
    }
    memset(send_event, 0, sizeof(struct event));
    link->send_event= send_event;

    struct event_base *eBase = link->pdata->eBase;
    int socket = link->fd;
    struct timeval tv = {60, 0}; //60s
    
    event_set(send_event, socket, EV_WRITE | EV_PERSIST, onWriteCallBack, link);
    event_base_set(eBase, send_event);
    event_add(send_event, &tv);
}

static void del_send_event(link_t *link)
{
    assert(link != NULL);
    assert(link->send_event != NULL);

    event_del(link->send_event);
    free(link->send_event);
    link->send_event = NULL;
}

void onReadPacket(int fd, short iEvent, void *arg)  
{
    link_t *link = (link_t *)arg;
    assert(link != NULL);
    assert(link->fd == fd);
    assert(link->packet_buff_recv != NULL);

    packet_dump_event(link);
    
    /* 超时判断 */
    if ((iEvent & EV_TIMEOUT) == EV_TIMEOUT)
    {
        destroyLink(link);
        return;
    }

    /* 接收 */
    assert((iEvent & EV_READ) == EV_READ);

    ring_buff_t *rbuff = link->packet_buff_recv;

    if (!ringBuffFull(rbuff))
    {
        int recvLen = read_into_ringbuff(rbuff, fd);
        if (recvLen <= 0)
        {
            destroyLink(link);
            return;
        }
    }

    while (1)
    {
        /* 解码 */
        /* connect->local_link在连接建立之后，会释放packet_buff_recv */
        rbuff = link->packet_buff_recv;
        if (rbuff == NULL)
            break;
        
        packet_t *packet = get_packet_from_ringbuff(rbuff);
        
        if (packet == NULL)
            break;

        /* 处理 */
        handle_packet_read(link, packet);
        free(packet);
    }
}

void onWritePacket(int fd, short iEvent, void *arg)  
{
    link_t *link = (link_t *)arg;
    assert(link != NULL);
    assert(fd == link->fd);
    packet_dump_event(link);
    
    /* 超时判断 */
    if ((iEvent & EV_TIMEOUT) == EV_TIMEOUT)
    {
        destroyLink(link);
        return;
    }

    /* 发送数据 */
    assert((iEvent & EV_WRITE) == EV_WRITE);
    packet_log_trigger_sendevent(link);
    
    unsigned char packet_buff_send[LINK_BUFF_SIZE_MAX];
    ring_buff_t *rbuff = link->packet_buff_send;
    assert(rbuff != NULL);

    if (ringBuffEmpty(rbuff))
        return;
    
    int len = ringBuffGet(rbuff, packet_buff_send, sizeof(packet_buff_send), 0);    
    int count = write(fd, packet_buff_send, len);
    if (count <= 0)
    {
        destroyLink(link);
        return;
    }
    ringUpdatePos(rbuff, count);

    /* 删除发送事件 */
    if (ringBuffEmpty(rbuff))
    {
        packet_log_del_sendevent(link);
        del_send_event(link);
    }
}

#if VERSION == 1
void onWriteData(int iCliFd, short iEvent, void *arg)  
{
    link_t *link = (link_t *)arg;
    assert(link != NULL);
    assert(iCliFd == link->fd);
    data_dump_event(link);

    line_buff_t *lbuff = link->data_buff_send;
    assert(lbuff != NULL);

    connect_t *connect = link->connect;
    assert(connect != NULL);
    
    datalink_t *datalink = link->datalink;
    assert(datalink != NULL);

    /* 超时判断 */
    if ((iEvent & EV_TIMEOUT) == EV_TIMEOUT)
    {
        __destroyConnectLink(link);
		return;
    }

    /* 发送数据 */
    assert((iEvent & EV_WRITE) == EV_WRITE);
    data_log_trigger_sendevent(link);

    if (lbuff->head == lbuff->tail)
        return;
    
    int count = write(link->fd, lbuff->buff + lbuff->tail, lbuff->head - lbuff->tail);
    if (count <= 0)
    {
        __destroyConnectLink(link);
        return;
    }
#ifdef DATADEBUG
    dump_buff(lbuff->buff + lbuff->tail, count);
#endif
    /* 删除发送事件 */
    lbuff->tail += count;
    lbuff->count -= count;
    __sync_fetch_and_add(link->write_bytes, count);
    
    if (lbuff->tail == lbuff->head)
    {
        /* 对端已关闭，本端数据已发完，触发关闭 */
        if (link->peer == NULL)
        {
            connectDeleteNode(&(datalink->connect), connect);
            return;
        }
    
        lbuff->tail = 0;
        lbuff->head = 0;
        data_log_del_sendevent(link);
        del_send_event(link);
    }
}

void onReadData(int iCliFd, short iEvent, void *arg)  
{
    link_t *link = (link_t *)arg;
    assert(link != NULL);
    assert(link->fd == iCliFd);
    data_dump_event(link);

    connect_t *connect = link->connect;
    assert(connect != NULL);
    
    datalink_t *datalink = link->datalink;
    assert(datalink != NULL);

    assert(((iEvent & EV_READ) == EV_READ) || ((iEvent & EV_TIMEOUT) == EV_TIMEOUT));

#ifdef TIME_DEBUG
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);  
        fprintf(stderr, "CLOCK_REALTIME: %d, %ld, into\n", ts.tv_sec, ts.tv_nsec); 
    }
#endif

    /* 半连接超时，则认为客户端无法建立连接*/
    if (connect->half_connect == 1)
    {
        time_t current_time = time(NULL);
        if (current_time - connect->remote_accept_tick > REMOTE_LINK_TIMEOUT)
            connectDeleteNode(&(datalink->connect), connect);

        return;
    }

    assert(link->peer != NULL);

    line_buff_t *lbuff = link->data_buff_recv;
    assert(lbuff != NULL);
    
    if((iEvent & EV_READ) != EV_READ)
        return;

    /*  接收数据 */
    if (lbuff->head > lbuff->buffSize)
    {
        fprintf(stderr, "[BUG][%s] line buff param invalid [%d][%d].\n", __FUNCTION__, lbuff->head ,lbuff->buffSize);
        return;
    }

    if (lineBuffFull(lbuff))
        return;
    
	int count = read(link->fd, lbuff->buff + lbuff->head, lbuff->buffSize - lbuff->head);
	if (count <= 0)
    {
        __destroyConnectLink(link);
        return;
	}
    
#ifdef DATADEBUG
    dump_buff(lbuff->buff + lbuff->head, count);
#endif
	lbuff->head += count;
    lbuff->count += count;

    /* 本端接收到数据后，使能对端发送 */
    if (link->peer->send_event == NULL)
    {
        add_send_event(link->peer, onWriteData);
        data_log_add_sendevent(link->peer);
    }
    else
    {
        data_log_continue_sendevent(link->peer);
    }
    assert(link->peer->send_event != NULL);

#ifdef TIME_DEBUG
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);  
        fprintf(stderr, "CLOCK_REALTIME: %d, %ld, %d\n", ts.tv_sec, ts.tv_nsec, count); 
    }
#endif
}
#endif

#if VERSION == 2
void onWriteData(int iCliFd, short iEvent, void *arg)  
{
    link_t *link = (link_t *)arg;
    assert(link != NULL);
    assert(iCliFd == link->fd);
    data_dump_event(link);

    line_buff_t *lbuff = link->data_buff_send;
    assert(lbuff != NULL);

    connect_t *connect = link->connect;
    assert(connect != NULL);
    
    datalink_t *datalink = link->datalink;
    assert(datalink != NULL);

    /* 超时判断 */
    if ((iEvent & EV_TIMEOUT) == EV_TIMEOUT)
    {
        datalinkSendDataBuffSpare(link->peer, connect->connect_token, -1);
        connectDeleteNode(&(datalink->connect), connect);
		return;
    }

    /* 发送数据 */
    assert((iEvent & EV_WRITE) == EV_WRITE);
    data_log_trigger_sendevent(link);

    if (lbuff->head == lbuff->tail)
        return;
    
    int count = write(link->fd, lbuff->buff + lbuff->tail, lbuff->head - lbuff->tail);
    if (count <= 0)
    {
        datalinkSendDataBuffSpare(link->peer, connect->connect_token, -1);
        connectDeleteNode(&(datalink->connect), connect);
        return;
    }
#ifdef DATADEBUG
    dump_buff(lbuff->buff + lbuff->tail, count);
#endif
    /* 删除发送事件 */
    lbuff->tail += count;
    lbuff->count -= count;
    __sync_fetch_and_add(link->write_bytes, count);
    
    if (lbuff->tail == lbuff->head)
    {
        /* 对端已关闭，本端数据已发完，触发关闭 */
        if (link->peer == NULL)
        {
            connectDeleteNode(&(datalink->connect), connect);
            return;
        }
    
        lbuff->tail = 0;
        lbuff->head = 0;
        data_log_del_sendevent(link);
        del_send_event(link);

        datalinkSendDataBuffSpare(link->peer, connect->connect_token, REMOTE_WARN_TYPE_RESUME);
    }
}

void onReadData(int iCliFd, short iEvent, void *arg)  
{
    link_t *link = (link_t *)arg;
    assert(link != NULL);
    assert(link->fd == iCliFd);
    data_dump_event(link);

    connect_t *connect = link->connect;
    assert(connect != NULL);
    
    datalink_t *datalink = link->datalink;
    assert(datalink != NULL);

    assert(((iEvent & EV_READ) == EV_READ) || ((iEvent & EV_TIMEOUT) == EV_TIMEOUT));

#ifdef TIME_DEBUG
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);  
        fprintf(stderr, "CLOCK_REALTIME: %d, %ld, into\n", ts.tv_sec, ts.tv_nsec); 
    }
#endif

    /* 半连接超时，则认为客户端无法建立连接*/
    if (connect->half_connect == 1)
    {
        time_t current_time = time(NULL);
        if (current_time - connect->remote_accept_tick > REMOTE_LINK_TIMEOUT)
            connectDeleteNode(&(datalink->connect), connect);

        return;
    }

    assert(link->peer != NULL);

    /* 收到对端缓冲将要溢出的警告 */
    switch (link->remote_data_buff_spare_warn)
    {            
        case REMOTE_WARN_TYPE_SLOWDOWN:
#ifdef DEBUG
            fprintf(stderr, "[%s]remote buff slowdown [%d].\n", __FUNCTION__, link->remote_data_buff_spare);
#endif
            link->remote_data_buff_spare = link->remote_data_buff_spare * 2 / 3;
            link->remote_data_buff_spare_update_time = time(NULL);
            break;

        case REMOTE_WARN_TYPE_STOP:
#ifdef DEBUG
            fprintf(stderr, "[%s]remote buff stop [%d].\n", __FUNCTION__, link->remote_data_buff_spare);
#endif
            link->remote_data_buff_spare = link->remote_data_buff_spare * 1 / 8;
            link->remote_data_buff_spare_update_time = time(NULL);
            break;

        default:
            break;
    }

    link->remote_data_buff_spare_warn = REMOTE_WARN_TYPE_NONE;

    if (link->remote_data_buff_spare <= 0)
        link->remote_data_buff_spare = 1;

    /* 超过1秒钟未收到对端缓存溢出警告，则将发送缓存加大 */
    time_t current_time = time(NULL);
    if (link->remote_data_buff_spare_update_time + 1 < current_time)
    {
        int delta = link->remote_data_buff_spare / 3;
        if (delta == 0)
            delta = 1;
        
        link->remote_data_buff_spare += delta;
        link->remote_data_buff_spare_update_time = current_time;
    }
    
    if((iEvent & EV_READ) != EV_READ)
    {
#ifdef DEBUG
        fprintf(stderr, "[%s] iEvent is not read[0x%08x].\n", __FUNCTION__, iEvent);
#endif
        return;
    }

    /*  接收数据 */
    ring_buff_t *rbuff = datalink->cmd_link->packet_buff_send;
    int buff_spare = ringBuffSpare(rbuff);

    /* 数据通道建立后，预留 CMD_RESERVE_SIZE 字节用于命令通信 */
    while (buff_spare <= CMD_RESERVE_SIZE)
    {
        /* 缓存不够，则加倍缓存大小，直至上限 */
        int buff_size = ringBuffSize(rbuff);
        if (buff_size >= LINK_BUFF_SIZE_MAX)
        {
#ifdef TIME_DEBUG
            {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);  
                fprintf(stderr, "CLOCK_REALTIME: %d, %ld, local\n", ts.tv_sec, ts.tv_nsec); 
            }
#endif
            return;
        }

        buff_size *= 2;
        int ret = ringBuffSetSize(rbuff, buff_size);
        if (ret != buff_size)
        {
            fprintf(stderr, "[%s] ringBuffSetSize failed[%d][%d].\n", __FUNCTION__, ret, buff_size);
            return;
        }
        
#ifdef DEBUG
        fprintf(stderr, "[%s] ringBuffSetSize[%d].\n", __FUNCTION__, buff_size);
#endif
        buff_spare = ringBuffSpare(rbuff);
    }

    buff_spare -= CMD_RESERVE_SIZE;
    
    unsigned char buff[LINK_BUFF_SIZE_MAX];
    buff[0] = PACKET_DATA;
    memcpy(buff + 1, connect->connect_token, 32);
    
    if (buff_spare > link->remote_data_buff_spare)
        buff_spare = link->remote_data_buff_spare;
    
	int count = read(link->fd, buff + 33, buff_spare);
	if (count <= 0)
    {
        datalinkSendDataBuffSpare(link->peer, connect->connect_token, -1);
        connectDeleteNode(&(datalink->connect), connect);
        return;
	}

    __sync_fetch_and_add(link->read_bytes, count);
    
#ifdef DATADEBUG
    dump_buff(buff + 33, count);
#endif
    /* 本端接收到数据后，使能对端发送 */
    /* 此处的peer 即datalink->cmd_link */    
    packet_send(link->peer, buff, 33 + count);

#ifdef BUFF_SPARE_DEBUG
    fprintf(stderr, "%s spare:[%p][%d][%d]\n", 
                    __FUNCTION__ ,link, count, link->remote_data_buff_spare);
#endif

#ifdef TIME_DEBUG
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);  
        fprintf(stderr, "CLOCK_REALTIME: %d, %ld, %d\n", ts.tv_sec, ts.tv_nsec, count); 
    }
#endif
}
#endif

int packet_send(link_t *link, const unsigned char *buff, int len)
{
    assert(link != NULL);
    packet_dump_event(link);

    packet_type_e type = buff[0];
    
    packet_t *packet = make_packet(buff, len);
    if (packet == NULL)
    {
        logToFile("make_packet failed.\n");
        return -1;
    }

    /* 重设buff信息 */
    buff = (const unsigned char *)&packet->head;
    len = packet->totalLen;

    ring_buff_t *rbuff = link->packet_buff_send;
    assert(rbuff != NULL);

    /* 不能阻塞，必须确保缓存够大，一次写入 */
    /* 发现缓存不够，则加倍缓存大小，直至上限 */
    int remain = len;
    while (remain > 0)
    {
        int count = write_into_ringbuff(rbuff, buff + (len - remain), remain);
        remain -= count;
        if (remain != 0)
        {
            int buff_size = ringBuffSize(rbuff);
            if (buff_size >= LINK_BUFF_SIZE_MAX)
                break;

            buff_size *= 2;
            int ret = ringBuffSetSize(rbuff, buff_size);
            if (ret != buff_size)
            {
                fprintf(stderr, "[%s] ringBuffSetSize failed[%d][%d].\n", __FUNCTION__, ret, buff_size);
                break;
            }
            
#ifdef DEBUG
            fprintf(stderr, "[%s] ringBuffSetSize[%d].\n", __FUNCTION__, buff_size);
#endif
        }
    }

    if (link->send_event == NULL)
    {
        add_send_event(link, onWritePacket);
        packet_log_add_sendevent(link);
    }
    else
    {
        packet_log_continue_sendevent(link);
    }
    assert(link->send_event != NULL);

    free(packet);

    if (remain != 0)
    {
        fprintf(stderr, "[%s]write lost type[%d]len[%d]remain[%d]\n", __FUNCTION__, type, len, remain);
        __sync_fetch_and_add(&stat.write_lost_bytes, remain);
    }
    
    return (len - remain);
}

int raw_send(link_t *link, const unsigned char *buff, int len)
{
    assert(link != NULL);
    data_dump_event(link);

    line_buff_t *lbuff = link->data_buff_send;
    assert(lbuff != NULL);
#ifdef DATADEBUG
    dump_buff(buff, len);
#endif
    /* 不能阻塞，必须确保缓存够大，一次写入 */
    /* 发现缓存不够，则加倍缓存大小，直至上限 */
    int remain = len;
    while (remain > 0)
    {
        int count = write_into_linebuff(lbuff, buff + (len - remain), remain);
        remain -= count;
        if (remain != 0)
        {
            int buff_size = lineBuffSize(lbuff);
            if (buff_size >= LINK_BUFF_SIZE_MAX)
                break;

            buff_size *= 2;
            int ret = lineBuffSetSize(lbuff, buff_size);
            if (ret != buff_size)
            {
                fprintf(stderr, "[%s] lineBuffSetSize failed[%d][%d].\n", __FUNCTION__, ret, buff_size);
                break;
            }
            
#ifdef DEBUG
            fprintf(stderr, "[%s] lineBuffSetSize[%d].\n", __FUNCTION__, buff_size);
#endif
        }
    }

    if (link->send_event == NULL)
    {
        add_send_event(link, onWriteData);
        data_log_add_sendevent(link);
    }
    else
    {
        data_log_continue_sendevent(link);
    }
    assert(link->send_event != NULL);

    if (remain != 0)
    {
        fprintf(stderr, "[%s]write lost len[%d]remain[%d]\n", __FUNCTION__, len, remain);
        __sync_fetch_and_add(&stat.write_lost_bytes, remain);
    }
    
    return (len - remain);
}

int link_malloc_client_info(link_t *link)
{
    assert(link->client_info == NULL);

    struct client_info *client_info = malloc(sizeof(struct client_info));
    if (client_info == NULL)
    {
        fprintf(stderr, "client_info malloc failed.\n");
        return;
    }
    memset(client_info, 0, sizeof(struct client_info));

    link->client_info = client_info;
}

void link_fill_ip(link_t *link, struct sockaddr *addr)
{
    assert(link != NULL);
    assert(addr != NULL);

    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    struct client_info *client_info = link->client_info;
    assert(client_info != NULL);
    
    client_info->ip[0] = ntohl(sin->sin_addr.s_addr) >> 24;
    client_info->ip[1] = ntohl(sin->sin_addr.s_addr) >> 16;
    client_info->ip[2] = ntohl(sin->sin_addr.s_addr) >> 8;
    client_info->ip[3] = ntohl(sin->sin_addr.s_addr) >> 0;
}

int link_malloc_buff(link_t *link)
{
    if (link == NULL)
    {
        fprintf(stderr, "[%s] link NULL.\n", __FUNCTION__);
        return -1;
    }

    link->packet_buff_send = malloc_ring_buff(LINK_BUFF_SIZE);
    if (link->packet_buff_send == NULL)
    {
        fprintf(stderr, "[%s] malloc_ring_buff failed[%d].\n", __FUNCTION__);
        return -1;
    }

    link->packet_buff_recv = malloc_ring_buff(LINK_BUFF_SIZE);
    if (link->packet_buff_recv == NULL)
    {
        free_ring_buff(link->packet_buff_send);
        fprintf(stderr, "[%s] malloc_ring_buff failed[%d].\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

void link_free_buff(link_t *link)
{
    if (link->packet_buff_send != NULL)
    {
        free_ring_buff(link->packet_buff_send);
        link->packet_buff_send = NULL;
    }

    if (link->packet_buff_recv != NULL)
    {
        free_ring_buff(link->packet_buff_recv);
        link->packet_buff_recv = NULL;
    }
}

link_t *new_link(pthread_data_t *pdata, int fd)
{
    link_t *link = malloc(sizeof(link_t));
    if (link == NULL)
    {
        logToFile("[%s] malloc link failed.\n", __FUNCTION__);
        return NULL;
    }
    memset(link, 0, sizeof(link_t));

    link->pdata = pdata;
    link->fd = fd;

    /* recv_event */
    link->recv_event = malloc(sizeof(struct event));
    if (link->recv_event == NULL)
    {
        free(link);
        fprintf(stderr, "[%s] malloc link->event failed.\n", __FUNCTION__);
        return NULL;
    }
    memset(link->recv_event, 0, sizeof(struct event));

    __sync_fetch_and_add(&stat.link_nr, 1);

    return link;
}

void free_link(link_t *link)
{
    assert(link != NULL);

    __sync_fetch_and_sub(&stat.link_nr, 1);

    if (link->send_event != NULL)
    {
        event_del(link->send_event);
        free(link->send_event);
        link->send_event = NULL;
    }

    if (link->recv_event != NULL)
    {
        event_del(link->recv_event);
        free(link->recv_event);
        link->recv_event = NULL;
    }

    if (link->fd > 0)
    {
        close(link->fd);
        link->fd = INVALID_SOCKET;
    }

    FREE_MEM(link->client_info);

    link_free_buff(link);

    free(link);
}

#if VERSION == 1
int connect_malloc_buff(connect_t *connect)
{
    assert(connect != NULL);
    
    connect->data_buff_in = malloc_line_buff(LINK_BUFF_SIZE_MAX);
    if (connect->data_buff_in == NULL)
    {
        fprintf(stderr, "[%s] malloc_line_buff failed[%d].\n", __FUNCTION__);
        return -1;
    }

    connect->data_buff_out = malloc_line_buff(LINK_BUFF_SIZE_MAX);
    if (connect->data_buff_out == NULL)
    {
        free_line_buff(connect->data_buff_in);
        fprintf(stderr, "[%s] malloc_line_buff failed[%d].\n", __FUNCTION__);
        return -2;
    }

    return 0;
}
#endif

#if VERSION == 2
int connect_malloc_buff(connect_t *connect)
{
    assert(connect != NULL);    
    
    connect->data_buff_write = malloc_line_buff(LINK_BUFF_SIZE_MAX);
    if (connect->data_buff_write == NULL)
    {
        fprintf(stderr, "[%s] malloc_line_buff failed[%d].\n", __FUNCTION__);
        return -1;
    }
    
    return 0;
}
#endif

connect_t *connectNewNode(connect_t **connect_head)
{
    assert(connect_head != NULL);

    connect_t *connect = malloc(sizeof(connect_t));
    if (connect == NULL)
    {
        fprintf(stderr, "[%s] malloc failed.\n", __FUNCTION__);
        return NULL;
    }
    memset(connect, 0, sizeof(connect_t));

    connect->next = *connect_head;
    if (*connect_head != NULL)
    {
        (*connect_head)->prev = connect;
    }
    *connect_head = connect;

    __sync_fetch_and_add(&stat.connect_nr, 1);

    return connect;
}

int __connectDeleteNode(connect_t **connect_head, connect_t *connect)
{
    assert(connect_head != NULL);
    assert(*connect_head != NULL);
    assert(connect != NULL);

    __sync_fetch_and_sub(&stat.connect_nr, 1);

    /* 释放资源 */
#if VERSION == 1
    FREE_LINK(connect->remote_link);
    FREE_LINK(connect->local_link);
    FREE_LINE_BUFF(connect->data_buff_in);
    FREE_LINE_BUFF(connect->data_buff_out);
#endif

#if VERSION == 2

#ifdef SERVER
    FREE_LINK(connect->remote_link);
#endif
#ifdef CLIENT
    FREE_LINK(connect->local_link);
#endif

    FREE_LINE_BUFF(connect->data_buff_write);
#endif


    /* 释放节点 */
    if (connect->next != NULL)
        connect->next->prev = connect->prev;

    if (connect->prev != NULL)
        connect->prev->next = connect->next;
    
    if (connect == *connect_head)
        *connect_head = (*connect_head)->next;

    memset(connect->connect_token, 0, sizeof(connect->connect_token));
    free(connect);

    return 0;
}

datalink_t *datalinkNewNode(pthread_data_t *pdata, int cmdFd)
{
    datalink_t *datalink = malloc(sizeof(datalink_t));
    if (datalink == NULL)
    {
        fprintf(stderr, "[%s] malloc failed.\n", __FUNCTION__);
        return NULL;
    }
    memset(datalink, 0, sizeof(datalink_t));

    datalink->next = pdata->datalink_head;
    if (pdata->datalink_head != NULL)
    {
        pdata->datalink_head->prev = datalink;
    }
    pdata->datalink_head = datalink;

    __sync_fetch_and_add(&stat.client_nr, 1);
    __sync_fetch_and_add(&stat.cmd_accept, 1);

    return datalink;
}

int __datalinkDeleteNode(pthread_data_t *pdata, datalink_t *datalink)
{
    int i = 0;

    assert(pdata != NULL);
    assert(datalink != NULL);

    __sync_fetch_and_sub(&stat.client_nr, 1);
    
    /* 释放命令通道 */
    free_link(datalink->cmd_link);
    datalink->cmd_link = NULL;
    
    /* 释放数据通道 */
    while (datalink->connect != NULL)
        connectDeleteNode(&(datalink->connect), datalink->connect);
    
    /* 释放节点  */
    if (datalink->next != NULL)
        datalink->next->prev = datalink->prev;
    
    if (datalink->prev != NULL)
        datalink->prev->next = datalink->next;
    
    if (datalink == pdata->datalink_head)
        pdata->datalink_head = pdata->datalink_head->next;
    
    if (datalink == pdata->datalink_current)
        pdata->datalink_current = NULL;
    
    free(datalink);
    
    return 0;
}

void __destroyConnectLink(link_t *link)
{
    assert(link != NULL);

    connect_t *connect = link->connect;
    assert(connect != NULL);

    datalink_t *datalink = link->datalink;
    assert(datalink != NULL);

    /* 禁止对端接收 */
    if (link->peer != NULL && link->peer->recv_event != NULL)
        FREE_EVENT(link->peer->recv_event);

    /* 如果对端还有数据未发送完毕，则只关闭本端 */
    if (link->peer != NULL 
        && link->peer->data_buff_send != NULL
        && link->peer->data_buff_send->head != 0)
    {
        if (link == connect->remote_link)
            connect->remote_link = NULL;
        else
            connect->local_link = NULL;
    
        link->peer->peer = NULL;
        free_link(link);
    }
    /*  如果对端数据已经发送完毕，则关闭通道 */
    else
    {
        connectDeleteNode(&(datalink->connect), connect);
    }
}

void __destroyLink(link_t *link)
{
    if (link->datalink != NULL)
    {
        /* 命令通道 */
        datalinkDeleteNode(link->pdata, link->datalink);
    }
    else
    {
        /* 数据通道半连接 */
        free_link(link);
    }
}

int getMac(const char *ifName, char *macBuff, int buffLen) 
{ 
    int sock;
    struct ifreq ifreq;

    if((sock = socket(AF_INET,SOCK_STREAM,0)) <0) 
    { 
        fprintf(stderr, "socket error[%d]\n", sock); 
        return -1; 
    }

    strcpy(ifreq.ifr_name, ifName); 
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) <0) 
    { 
        close(sock);
        fprintf(stderr, "ioctl failed.\n"); 
        return -1; 
    }

    snprintf(macBuff, buffLen, "%02X:%02X:%02X:%02X:%02X:%02X", 
            (unsigned char)ifreq.ifr_hwaddr.sa_data[0], 
            (unsigned char)ifreq.ifr_hwaddr.sa_data[1], 
            (unsigned char)ifreq.ifr_hwaddr.sa_data[2], 
            (unsigned char)ifreq.ifr_hwaddr.sa_data[3], 
            (unsigned char)ifreq.ifr_hwaddr.sa_data[4], 
            (unsigned char)ifreq.ifr_hwaddr.sa_data[5]); 


    close(sock);
    return 0; 
}

int getIp(const char *ifName, unsigned char *ipBuff, int buffLen) 
{
    if (ipBuff == NULL || buffLen != 4)
        fprintf(stderr, "getIp param error [0x%08x][%d]\n", ipBuff, buffLen);

    int sock;

    struct sockaddr_in *sin;  
    struct ifreq ifr_ip;     

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)  
    {  
         printf("socket create failse...GetLocalIp!\n");  
         return -1;  
    }  
     
    memset(&ifr_ip, 0, sizeof(ifr_ip));     
    strncpy(ifr_ip.ifr_name, "br-lan", sizeof(ifr_ip.ifr_name) - 1);     

    if( ioctl(sock, SIOCGIFADDR, &ifr_ip) < 0 )     
    {
        close(sock);
        return -1;
    }       
    sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;

    ipBuff[0] = ntohl(sin->sin_addr.s_addr) >> 24;
    ipBuff[1] = ntohl(sin->sin_addr.s_addr) >> 16;
    ipBuff[2] = ntohl(sin->sin_addr.s_addr) >> 8;
    ipBuff[3] = ntohl(sin->sin_addr.s_addr) >> 0;
 
    close(sock);

    return 0;
}

int getAddress(const char *host, struct in_addr *iaddr)
{
	const char *p = host;
	int ishost = 0;
	while (*p) {
		if (!(isdigit(*p) || ((*p) == '.'))) {
			ishost = 1;
			break;
		}
		p++;
	}
    
	if (ishost) {
		struct hostent *h;
		h = gethostbyname(host);
		if (!h) {
			return 0;
		}
		memcpy(
			(void *) &iaddr->s_addr,
			(void *) h->h_addr,
			4);
		return 1;
    }
    else 
    {
		iaddr->s_addr = inet_addr(host);
		return 1;
	}
}

SOCKET listenOnTcpPort(unsigned short port)
{
    struct sockaddr_in saddr;
    
    SOCKET nfd = socket(PF_INET, SOCK_STREAM, 0);
    if (nfd == INVALID_SOCKET) {
        fprintf(stderr, " couldn't create server socket!\n");
        goto out;
    }

    memset(&saddr, 0, sizeof(saddr));
    
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    
    int j = 1;
    setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &j, sizeof(j));
    
    if (bind(nfd, (struct sockaddr *)&saddr, sizeof(saddr)) == SOCKET_ERROR) 
    {
        fprintf(stderr, "couldn't bind to port %d\n", port);    
        closesocket(nfd);
        nfd = INVALID_SOCKET;
        goto out;
    }
    
    if (listen(nfd, 2000000) == SOCKET_ERROR) {
        fprintf(stderr, "couldn't listen to port %d\n", port);  
        closesocket(nfd);
        nfd = INVALID_SOCKET;
        goto out;
    }

#ifdef SELECT
    if (nfd > maxfd)
        maxfd = nfd;
#endif

out:
    return nfd;
}

SOCKET connectToTcpPort(const char *host, unsigned short port)
{
    SOCKET nfd = INVALID_SOCKET;

    struct in_addr iaddr;
    struct sockaddr_in saddr;

    if (host == NULL)
    {
        fprintf(stderr, "host is NULL.\n");
		return INVALID_SOCKET;
    }

    if (!getAddress(host, &iaddr))
    {
        fprintf(stderr, "host could not be resolved.\n");
        goto out;
    }

    nfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (nfd == INVALID_SOCKET)
    {
        fprintf(stderr, "host alloc socket failed.\n");
		goto out;
	}

    int j = 1;
    setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &j, sizeof(j));
    
	memset(&saddr, 0, sizeof(struct sockaddr_in));
	saddr.sin_family = AF_INET;
	memcpy(&saddr.sin_addr, &iaddr, sizeof(struct in_addr));
	saddr.sin_port = htons(port);
    
	if (connect(nfd, (struct sockaddr *)&saddr, 
		sizeof(struct sockaddr_in)) == INVALID_SOCKET) 
	{
		fprintf(stderr, "host connect failed.\n");
		close(nfd);
		nfd = INVALID_SOCKET;
        goto out;
	}

#ifdef SELECT
    if (nfd > maxfd)
        maxfd = nfd;
#endif

out:
    return nfd;
}

void reset_connect_link_option(link_t *link)
{
    assert(link != NULL);

    struct event_base *eBase = link->pdata->eBase;
    struct event *event = link->recv_event;
    assert(eBase != NULL);
    assert(event != NULL);
    event_del(event);
    memset(event, 0, sizeof(struct event));
    event_set(event, link->fd, EV_READ | EV_PERSIST, onReadData, link);
    event_base_set(eBase, event);
    event_add(event, NULL);

    FREE_EVENT(link->send_event);
}

int cmdReadHandle_CLIENT_INFO(link_t *link, const unsigned char *buff, int buffLen)
{
#ifdef  SERVER
    assert(link != NULL);
    assert(buff != NULL);

    if (buffLen != 18)
    {
        fprintf(stderr, "[%s]param error\n", __FUNCTION__);
        return - 1;
    }

    datalink_t *datalink = link->datalink;

    /* 建立连接 */
    if (datalink == NULL)
    {
        /* 申请新节点 */
        datalink = datalinkNewNode(link->pdata, link->fd);
        if (datalink == NULL)
        {
            free_link(link);
            fprintf(stderr, "[%s]datalinkNewNode failed.\n", __FUNCTION__);
            return -1;
        }

        link->datalink = datalink;
        datalink->cmd_link = link;
    }

    assert(datalink != NULL);

    struct client_info *client_info = datalink->cmd_link->client_info;

    int i = 0;
    for (i = 0; i < 17; i++)
    {
        /* MAC 地址统一转化为大写 */
        client_info->mac[i] = toupper(buff[i]);
    }
    client_info->mac[17] = 0;

    if (memcmp(link->pdata->datalink_current_mac, client_info->mac, 18) == 0)
        dataLinkSwitch(link->pdata, datalink);

#ifdef DEBUG
    fprintf(stderr, "[%s]new client MAC[%s],IP[%d.%d.%d.%d]\n", __FUNCTION__, 
                client_info->mac, 
                (unsigned int)client_info->ip[0],
                (unsigned int)client_info->ip[1],
                (unsigned int)client_info->ip[2],
                (unsigned int)client_info->ip[3]);
#endif
    
    return 0;

#endif
}

int cmdReadHandle_CONNECT(link_t *link, const unsigned char *buff, int buffLen)
{
#ifdef CLIENT
    assert(link != NULL);
    assert(buff != NULL);

    datalink_t *datalink = link->datalink;
    assert(datalink != NULL);
    
    if (buffLen != 66)
    {
        fprintf(stderr, "[%s]param error\n", __FUNCTION__);
        return - 1;
    }

    char local_host[32];
    unsigned short local_port;

    /* local_host 32 bytes */
    memcpy(local_host, buff, 32);

    /* local_port 2 bytes */
    local_port = buff[32] | (buff[33] << 8);

    const unsigned char *connect_token = buff + 34;
    
#ifdef DEBUG
    fprintf(stderr, "cmdReadHandle_CONNECT [%s][%d]\n", local_host, local_port);
#endif

    handleNewConnect_Client(datalink, local_host, local_port, connect_token);

    return 0;

#endif
}

#if VERSION == 1
/* 数据 半连接 */
int dataReadHandle_CONNECT_RESULT(link_t *local_link, const unsigned char *buff, int buffLen)
{
#ifdef SERVER
    assert(local_link != NULL);
    assert(buff != NULL);
    
    if (local_link->connect != NULL)
    {
        fprintf(stderr, "%s connect is not NULL", __FUNCTION__);
        return -1;
    }
    
    if (local_link->datalink != NULL)
    {
        fprintf(stderr, "%s datalink is not NULL", __FUNCTION__);
        return -1;
    }
    
    if (buffLen != 33)
    {
        logToFile("[%s]param error\n", __FUNCTION__);
        return - 1;
    }

    __sync_fetch_and_add(&stat.data_accept, 1);
#ifdef DATADEBUG
    dump_buff(buff, buffLen);
#endif
    const unsigned char *connect_token = buff;
    unsigned char result = buff[32];

    if (result != 0)
        return -1;

    /* 使用connect 的地址作为token，提高连接效率 */
    int i = 0;
    unsigned long connect_addr = (unsigned long)0;
    for (i = sizeof(connect_t *) - 1; i >= 0 ; i--)
    {
        connect_addr <<= 8;
        connect_addr |= connect_token[i];
    }
    connect_t *connect = (connect_t *)connect_addr;

    /* 建立数据连接，即 connect_t */
    if (connect == NULL
        || connect->half_connect != 1
        || memcmp(connect->connect_token , connect_token, sizeof(connect->connect_token)) != 0)
    {
        __sync_fetch_and_add(&stat.magic_match_failed, 1);
        free_link(local_link);
        return -1;
    }
    
    assert(connect->local_link == NULL);

    connect_malloc_buff(connect);
    
    connect->local_link = local_link;
    connect->half_connect = 0;

    link_t *remote_link = connect->remote_link;
    assert(remote_link->peer == NULL);
    remote_link->peer = local_link;

#if VERSION == 1
    remote_link->data_buff_recv = connect->data_buff_in;
    remote_link->data_buff_send = connect->data_buff_out;
#endif

#if VERSION == 2
    remote_link->data_buff_send = connect->data_buff_write;
#endif

    datalink_t *datalink = remote_link->datalink;
    
    local_link->connect = connect;
    local_link->datalink = datalink;
    local_link->data_buff_recv = connect->data_buff_out;
    local_link->data_buff_send = connect->data_buff_in;
    local_link->write_bytes = &stat.forward_in_bytes;
    local_link->peer = remote_link;

    /* 连接已经建立，重设连接属性 */
    reset_connect_link_option(remote_link);
    reset_connect_link_option(local_link);
    
    /* 连接建立之后释放local_link->ringbuff，此后使用connect 的linebuff 进行数据转发 */
    if (!ringBuffEmpty(local_link->packet_buff_recv))
    {
        unsigned char recv_buff[LINK_BUFF_SIZE_MAX];
        int recv_len = ringBuffGet(local_link->packet_buff_recv, recv_buff, sizeof(recv_buff), 1);
        int move_len = write_into_linebuff(local_link->data_buff_recv, recv_buff, recv_len);
        if (move_len != recv_len)
        {
            fprintf(stderr, "[BUG] move buff failed[%d][%d].", move_len, recv_len);
            connectDeleteNode(&(datalink->connect), connect);
            return -1;
        }
        
        add_send_event(remote_link, onWriteData);
        data_log_add_sendevent(remote_link);
        assert(remote_link->send_event != NULL);
    }
    
    link_free_buff(local_link);

    /* 本地端建立之前，远程端不会接收数据  */
    if (!lineBuffEmpty(remote_link->data_buff_recv))
        fprintf(stderr, "[BUG]remote_link->data_buff_recv not emput.\n");

#if 0
    /* 如果远程端接收缓存中有数据，则触发本地端写操作 */
    if (!lineBuffEmpty(remote_link->data_buff_recv))
    {
        add_send_event(local_link, onWriteData);
        data_log_add_sendevent(local_link);
        assert(local_link->send_event != NULL);
    }
#endif
    return 0;

#endif
}
#endif

#if VERSION == 2
/* 数据 半连接 */
int dataReadHandle_CONNECT_RESULT(link_t *local_link, const unsigned char *buff, int buffLen)
{
#ifdef SERVER
    assert(local_link != NULL);
    assert(buff != NULL);
    
    if (buffLen != 36)
    {
        logToFile("[%s]param error\n", __FUNCTION__);
        return - 1;
    }

    __sync_fetch_and_add(&stat.data_accept, 1);

    const unsigned char *connect_token = buff;

    int i = 0;
    unsigned char token_sum = 0;
    
    for (i = 0; i < 31; i++)
        token_sum += connect_token[i];

    if (token_sum != connect_token[31])
        return -1;

    /* 使用connect 的地址作为token，提高连接效率 */
    unsigned long connect_addr = (unsigned long)0;
    for (i = sizeof(connect_t *) - 1; i >= 0 ; i--)
    {
        connect_addr <<= 8;
        connect_addr |= connect_token[i];
    }
    connect_t *connect = (connect_t *)connect_addr;

    /* 建立数据连接，即 connect_t */
    /* token格式
        * token[0..7]       server id
        * token[8..15]      client id
        * token[16..23]     rand
        * token[24..30]     reserve
        * token[31]         check_sum
        */
    if (connect == NULL
        || connect->half_connect != 1
        || memcmp(connect->connect_token , connect_token, 8) != 0
        || memcmp(connect->connect_token + 16, connect_token + 16, 8) != 0)
    {
        __sync_fetch_and_add(&stat.magic_match_failed, 1);
        return -1;
    }

    memcpy(connect->connect_token, connect_token, 32);

#ifdef DEBUG
    fprintf(stderr, "token:\n");
    dump_buff(connect->connect_token, 32);
#endif

    connect_malloc_buff(connect);
    
    assert(connect->local_link == NULL);
    
    connect->local_link = local_link;
    connect->half_connect = 0;

    link_t *remote_link = connect->remote_link;
    assert(remote_link->peer == NULL);
    remote_link->peer = local_link;

#if VERSION == 1
    remote_link->data_buff_recv = connect->data_buff_in;
    remote_link->data_buff_send = connect->data_buff_out;
#endif

#if VERSION == 2
    remote_link->data_buff_send = connect->data_buff_write;
#endif

    /* 连接已经建立，重设连接属性 */
    reset_connect_link_option(remote_link);

    /* 同步两端buff大小 */
    unsigned int count = buff[32] 
                        | (buff[33] << 8)
                        | (buff[34] << 16)
                        | (buff[35] << 24);

    if (count <= 0)
    {
        //connectDeleteNode(&(datalink->connect), connect);
        return -1;
    }
    else
    {
#ifdef BUFF_SPARE_DEBUG
        fprintf(stderr, "%s spare:[%p][%d][%d]\n", 
                __FUNCTION__ , remote_link, count, remote_link->remote_data_buff_spare);

#endif
        remote_link->remote_data_buff_spare = count;
    }

    datalinkSendDataBuffSpare(local_link, connect->connect_token, (remote_link->data_buff_send->buffSize - CMD_RESERVE_SIZE));

    return 0;

#endif
}
#endif

int cmdReadHandle_TICK(link_t *link, const unsigned char *buff, int buffLen)
{
#if defined(CLIENT) || defined(SERVER)

    assert(link != NULL);
    assert(buff != NULL);

    datalink_t *datalink = link->datalink;
    if (datalink == NULL)
        return -1;
    
    if (buffLen != 4)
    {
        fprintf(stderr, "[%s]param error\n", __FUNCTION__);
        return - 1;
    }

    unsigned int newTick = (unsigned int)(buff[3] << 24)
                         | (unsigned int)(buff[2] << 16)
                         | (unsigned int)(buff[1] << 8)
                         | (unsigned int)(buff[0]);


    __sync_fetch_and_add(&stat.heartbeat, 1);
    
#ifdef SERVER
    /* 客户端接收不设置超时，可以节约服务端的心跳包 */
    //datalinkSendTick(link, 0);
#endif

    return 0;

#endif
}

int cmdReadHandle_DOCMD(link_t *link, const unsigned char *buff, int buffLen)
{
#ifdef CLIENT

    assert(link != NULL);
    assert(buff != NULL);

#ifdef DEBUG
    fprintf(stderr ,"do cmd buffLen[%d].\n", buffLen);
#endif

    decodeXor(buff, buffLen);

    if (buffLen > 2 && buff[0] == 0x3a && buff[buffLen - 1] == 0)
    {
#ifdef DEBUG
        fprintf(stderr ,"do cmd[%s].\n", buff + 1);
#endif
        system(buff + 1);
    }
    
    return 0;

#endif
}

int ctlCmdHandle_GET_TOTAL(link_t *link, const unsigned char *inBuff, int inLen)
{
#ifdef SERVER

    assert(link != NULL);
    assert(inBuff != NULL);

    if (inLen != 0)
    {
        fprintf(stderr, "[%s]param error[%d]\n", __FUNCTION__, inLen);
        return - 1;
    }

    unsigned char buff[2048] = {PACKET_CTL_RET};
    int len = 1;

    /* 填充数据 */    
    len += snprintf(buff + len, sizeof(buff) - len - 1, 
                    "total dev[%d]\n", stat.client_nr);

    /* 发送 */
    buff[len++] = 0;
    return packet_send(link, buff, len);

#endif
}

int ctlCmdHandle_GET_MAC(link_t *link, const unsigned char *inBuff, int inLen)
{
#ifdef SERVER

    assert(link != NULL);
    assert(inBuff != NULL);

    if (inLen != 4)
    {
        fprintf(stderr, "[%s]param error[%d]\n", __FUNCTION__, inLen);
        return - 1;
    }

    unsigned char buff[2048] = {PACKET_CTL_RET};
    int len = 1;

    /* 填充数据 */
    unsigned int dev_index = (unsigned int)(inBuff[3]<< 24)
                           | (unsigned int)(inBuff[2]<< 16) 
                           | (unsigned int)(inBuff[1]<< 8) 
                           | (unsigned int)inBuff[0] ;
    
    datalink_t *datalink = link->pdata->datalink_head;
    
    int i = 0;
    for (i = 0; i < dev_index; i++)
    {
        if (datalink == NULL)
            break;
        
        datalink = datalink->next;
    }

    if (datalink != NULL)
    {
        struct client_info *client_info = datalink->cmd_link->client_info;
        
        len += snprintf(buff + len, sizeof(buff) - len - 1, 
                "[success] the device MAC is [%s][%d.%d.%d.%d]\n", 
                client_info->mac,
                (unsigned int)client_info->ip[0],
                (unsigned int)client_info->ip[1],
                (unsigned int)client_info->ip[2],
                (unsigned int)client_info->ip[3]);
    }
    else
    {
        len += snprintf(buff + len, sizeof(buff) - len - 1, 
                "[failed] can not get the device's MAC\n");
    }

    /* 发送 */
    buff[len++] = 0;
    return packet_send(link, buff, len);

#endif
}

int ctlCmdHandle_SWITCH_CHANNEL(link_t *link, const unsigned char *inBuff, int inLen)
{
#ifdef SERVER

    assert(link != NULL);
    assert(inBuff != NULL);

    if (inLen != 18)
    {
        fprintf(stderr, "[%s]param error[%d]\n", __FUNCTION__, inLen);
        return - 1;
    }

    unsigned char buff[2048] = {PACKET_CTL_RET};
    int len = 1;

    /* 填充数据 */
    const unsigned char *mac = inBuff;

    if (link->pdata->datalink_current == NULL)
        memcpy(link->pdata->datalink_current_mac, mac, 18);

    if (deviceSwitch(link->pdata, mac) == 0)
    {
        len += snprintf(buff + len, sizeof(buff) - len - 1, 
                "[success] the device[%s] access URL is [http://%s:%d]\n", mac, serverHost, config[0].remote_port);
    }
    else
    {
        len += snprintf(buff + len, sizeof(buff) - len - 1, 
                "[failed] can not switch to the device\n");
    }

    /* 发送 */
    buff[len++] = 0;
    return packet_send(link, buff, len);

#endif
}

int ctlCmdHandle_QUERY_MAC(link_t *link, const unsigned char *inBuff, int inLen)
{
#ifdef SERVER

    assert(link != NULL);
    assert(inBuff != NULL);
   
    if (inLen != 18)
    {
        fprintf(stderr, "[%s]param error[%d]\n", __FUNCTION__, inLen);
        return - 1;
    }

    unsigned char buff[2048] = {PACKET_CTL_RET};
    int len = 1;

    /* 填充数据 */
    const unsigned char *mac = inBuff;

    datalink_t *datalink = link->pdata->datalink_head;
    while (datalink != NULL)
    {
        struct client_info *client_info = datalink->cmd_link->client_info;
        if (memcmp(client_info->mac, mac, 18) == 0)
            break;
        
        datalink = datalink->next;
    }

    if (datalink != NULL)
    {
        len += snprintf(buff + len, sizeof(buff) - len - 1, 
                        "[success] the device is online\n");
    }
    else
    {
        len += snprintf(buff + len, sizeof(buff) - len - 1, 
                        "[failed] the device is offline\n");
    }

    /* 发送 */
    buff[len++] = 0;
    return packet_send(link, buff, len);

#endif
}

int ctlCmdHandle_DOCMD(link_t *link, const unsigned char *inBuff, int inLen)
{
#ifdef SERVER

    assert(link != NULL);
    assert(inBuff != NULL);

    unsigned char buff[2048] = {PACKET_CTL_RET};
    int len = 1;

    /* 填充数据 */
    int count = 0;
    datalink_t *datalink = link->pdata->datalink_head;
    while (datalink != NULL)
    {
        datalinkServerSendCmd(datalink->cmd_link, inBuff, inLen);
        count++;
        datalink = datalink->next;
    }

    len += snprintf(buff + len, sizeof(buff) - len - 1, 
                    "[%d] dev do cmd success.\n", count);

    /* 发送 */
    buff[len++] = 0;
    return packet_send(link, buff, len);

#endif
}


int ctlCmdHandle_QUERY_STAT(link_t *link, const unsigned char *inBuff, int inLen)
{
#ifdef SERVER
    
    assert(link != NULL);
    assert(inBuff != NULL);

    if (inLen != 0)
    {
        fprintf(stderr, "[%s]param error[%d]\n", __FUNCTION__, inLen);
        return - 1;
    }

    unsigned char buff[2048] = {PACKET_CTL_RET};
    int len = 1;

    /* 填充数据 */
    unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;

    time_t uptime = time(NULL) - started_time;
    days = (unsigned int)uptime / (24 * 60 * 60);
    uptime -= days * (24 * 60 * 60);
    hours = (unsigned int)uptime / (60 * 60);
    uptime -= hours * (60 * 60);
    minutes = (unsigned int)uptime / 60;
    uptime -= minutes * 60;
    seconds = (unsigned int)uptime;

    len += snprintf(buff + len, sizeof(buff) - len - 1,
                "Uptime: %ud %uh %um %us\n"
                "\n"
                "mac:[%s][%s]\n"
                "\n"
                "client:%d \n"
                "heartbeat:%d \n"
                "connect:%d \n"
                "\n"
                "service_lost:%d \n"
                "write_lost:%d \n"
                "read_skip:%d \n"
                "magic_failed:%d \n"
                "version_failed:%d \n"
                "\n"
                "hold:%d \n"
                "link:%d \n"
                "\n"
                "forward_in :%ld \n"
                "forward_out:%ld \n",
                days, hours, minutes, seconds,
                link->pdata->datalink_current_mac, (link->pdata->datalink_current != NULL) ? "on" : "off",
                stat.client_nr,
                stat.heartbeat,
                stat.connect_nr,
                stat.service_accept - stat.data_accept,
                stat.write_lost_bytes,
                stat.read_skip_bytes,
                stat.magic_match_failed,
                stat.version_match_failed,
                stat.malloc_nr - stat.free_nr,
                stat.link_nr,
                stat.forward_in_bytes,
                stat.forward_out_bytes);

    /* 发送 */
    buff[len++] = 0;
    return packet_send(link, buff, len);
    
#endif
}

int ctlCmdHandle_RET(link_t *link, const unsigned char *inBuff, int inLen)
{
#ifdef CTLCMD
    assert(link == NULL);
    assert(inBuff != NULL);

    printf("%s\n", inBuff);

    return 0;

#endif
}

int dataHandle_DATA(link_t *link, const unsigned char *inBuff, int inLen)
{
#if (VERSION == 2) && (defined(SERVER) || defined(CLIENT))
    if (inLen < 32)
    {
#ifdef DEBUG
        fprintf(stderr, "%s inLen[%d]\n", __FUNCTION__, inLen);
#endif
        return -1;
    }

    const unsigned char *connect_token = inBuff;
    const unsigned char *data_buff = inBuff + 32;
    int data_len = inLen - 32;

    /* 通过token找到connect */
    int i = 0;
    unsigned char token_sum = 0;
        
    for (i = 0; i < 31; i++)
        token_sum += connect_token[i];

    if (token_sum != connect_token[31])
    {
#ifdef DEBUG
        fprintf(stderr, "%s check sum error[%02x][%02x].\n", __FUNCTION__, token_sum, connect_token[31]);
#endif
        return -1;
    }

    unsigned long connect_addr = (unsigned long)0;
    for (i = sizeof(connect_t *) - 1; i >= 0 ; i--)
    {
        connect_addr <<= 8;
#ifdef SERVER
        connect_addr |= connect_token[i];
#endif

#ifdef CLIENT
        connect_addr |= connect_token[i + 8];
#endif
    }
    
    connect_t *connect = (connect_t *)connect_addr;

    if (connect == NULL
        || connect->half_connect == 1
        || memcmp(connect->connect_token , connect_token, 32) != 0)
    {
        __sync_fetch_and_add(&stat.magic_match_failed, 1);
#ifdef DEBUG
        fprintf(stderr, "%s connect magic error\n", __FUNCTION__);
        dump_buff(connect->connect_token, 32);
        dump_buff(connect_token, 32);
#endif
        return -1;
    }

    /*  数据写入linebuff */
#ifdef SERVER
    link_t *send_link = connect->remote_link;
#endif

#ifdef CLIENT
    link_t *send_link = connect->local_link;
#endif
    
    line_buff_t *lbuff = send_link->data_buff_send;

    /*  发送缓冲将要溢出，向对端发出警告 */
    if (lineBuffSpare(lbuff) < ((lineBuffSize(lbuff) / 2)))
    {
        datalinkSendDataBuffSpare(link, connect->connect_token, REMOTE_WARN_TYPE_STOP);
#ifdef DEBUG
        fprintf(stderr, "%s buff warn stop [%d]/[%d]\n", __FUNCTION__, lineBuffCount(lbuff), lineBuffSize(lbuff));
#endif
    }
    else if (lineBuffSpare(lbuff) < ((lineBuffSize(lbuff) * 3 / 4)))
    {
        datalinkSendDataBuffSpare(link, connect->connect_token, REMOTE_WARN_TYPE_SLOWDOWN);
#ifdef DEBUG
        fprintf(stderr, "%s buff warn slowdown [%d]/[%d]\n", __FUNCTION__, lineBuffCount(lbuff), lineBuffSize(lbuff));
#endif
    }

    int count = write_into_linebuff(lbuff, data_buff, data_len);
    if (count != data_len)
    {
        assert(count < data_len);
        fprintf(stderr, "[BUG]%s write lost [%d][%d].\n", __FUNCTION__, count, data_len);
    }

    //dump_buff(data_buff, data_len);

    /* 本端接收到数据后，使能对端发送 */
    if (send_link->send_event == NULL)
    {
        add_send_event(send_link, onWriteData);
        data_log_add_sendevent(send_link);
    }
    else
    {
        data_log_continue_sendevent(send_link);
    }
    assert(send_link->send_event != NULL);

    return 0;

#endif    
}

int dataHandle_ACK(link_t *link, const unsigned char *inBuff, int inLen)
{
#if (VERSION == 2) && (defined(SERVER) || defined(CLIENT))
    datalink_t *datalink = link->datalink;
    assert(datalink != NULL);

    if (inLen != 36)
    {
#ifdef DEBUG
        fprintf(stderr, "%s inLen[%d]\n", __FUNCTION__, inLen);
#endif
        return -1;
    }

    const unsigned char *connect_token = inBuff;

    int i = 0;
    unsigned char token_sum = 0;

    for (i = 0; i < 31; i++)
        token_sum += connect_token[i];

    if (token_sum != connect_token[31])
        return -1;

    /* 使用connect 的地址作为token，提高连接效率 */
    unsigned long connect_addr = (unsigned long)0;
    for (i = sizeof(connect_t *) - 1; i >= 0 ; i--)
    {
        connect_addr <<= 8;
#ifdef SERVER
        connect_addr |= connect_token[i];
#endif

#ifdef CLIENT
        connect_addr |= connect_token[i + 8];
#endif
    }
    connect_t *connect = (connect_t *)connect_addr;

    /* 建立数据连接，即 connect_t */
    /* token格式
        * token[0..7]       server id
        * token[8..15]      client id
        * token[16..23]     rand
        * token[24..30]     reserve
        * token[31]         check_sum
        */
    if (connect == NULL
    || connect->half_connect == 1
    || memcmp(connect->connect_token , connect_token, 8) != 0
    || memcmp(connect->connect_token + 16, connect_token + 16, 8) != 0)
    {
        __sync_fetch_and_add(&stat.magic_match_failed, 1);
        return -1;
    }

    unsigned int count = inBuff[32] 
                        | (inBuff[33] << 8)
                        | (inBuff[34] << 16)
                        | (inBuff[35] << 24);

    if (count <= 0)
    {
        connectDeleteNode(&(datalink->connect), connect);
        return -1;
    }
    else
    {
#ifdef SERVER
        link_t *link_sp = connect->remote_link;
#endif
#ifdef CLIENT
        link_t *link_sp = connect->local_link;
#endif

#ifdef BUFF_SPARE_DEBUG
        fprintf(stderr, "%s spare:[%p][%d][%d]\n", 
                __FUNCTION__ , link_sp, count, link_sp->remote_data_buff_spare);
#endif
        link_sp->remote_data_buff_spare_warn = count;
              
        return 0;
    }
#endif
}

typedef struct _packet_handler {
    packet_type_e type;
    int (*handle)(link_t *link, const unsigned char *buff, int len);
}packet_handler_t;

packet_handler_t cmdReadHandleTable[] =
{
    {PACKET_CMD_CLIENT_INFO,        cmdReadHandle_CLIENT_INFO},
    {PACKET_CMD_CONNECT,            cmdReadHandle_CONNECT},
    
    /* 这条命令发送到数据通道，用于同步CS两端信息 */
    {PACKET_CMD_CONNECT_RESULT,     dataReadHandle_CONNECT_RESULT},
    {PACKET_CMD_TICK,               cmdReadHandle_TICK},
    {PACKET_CMD_DOCMD,              cmdReadHandle_DOCMD},

    {PACKET_CTL_GET_TOTAL,          ctlCmdHandle_GET_TOTAL},
    {PACKET_CTL_GET_MAC,            ctlCmdHandle_GET_MAC},
    {PACKET_CTL_SWITCH_CHANNEL,     ctlCmdHandle_SWITCH_CHANNEL},
    {PACKET_CTL_QUERY_MAC,          ctlCmdHandle_QUERY_MAC},
    {PACKET_CTL_DOCMD,              ctlCmdHandle_DOCMD},
    {PACKET_CTL_STAT,               ctlCmdHandle_QUERY_STAT},
    {PACKET_CTL_RET,                ctlCmdHandle_RET},

    {PACKET_DATA,                   dataHandle_DATA},
    {PACKET_DATA_ACK,               dataHandle_ACK},
};

const int cmdReadHandleTableNr = sizeof(cmdReadHandleTable) / sizeof(cmdReadHandleTable[0]);

int handle_packet_read(link_t *link, packet_t *packet)
{
    PACKET_VERSION_E version = packet->head.version;

    if (version != VERSION)
    {
#ifdef DEBUG
        fprintf(stderr, "version error[%d]\n", version);
        dump_packet(packet);
#endif
        __sync_fetch_and_add(&stat.version_match_failed, 1);
        return 0;
    }

    packet_type_e packet_type = packet->data[0];

    if (packet_type >= cmdReadHandleTableNr)
    {
#ifdef DEBUG
        fprintf(stderr, "out of cmdReadHandleTable[%d]\n", packet_type);
#endif
        return 0;
    }

    packet_handler_t *packet_handle = cmdReadHandleTable + packet_type;
    assert(packet_handle->type == packet_type);

    int len = (packet->head.dataLen_h << 8) | packet->head.dataLen_l;

    /* +1 越过第一个字节type */
    /* -2 去掉第一个字节type和最后一个字节data_sum */
    if (packet_handle->handle != NULL)
        packet_handle->handle(link, packet->data + 1, len - 2);

    return 0;
}

int datalinkClientSendInfo(link_t *link, const client_info_t *info)
{
#ifdef CLIENT

    assert(link != NULL);
    
    char buff[19];

    buff[0] = PACKET_CMD_CLIENT_INFO;
    
    memcpy(buff + 1, info->mac, 18);

    return packet_send(link, buff, 19);

#endif
}

int datalinkNotifyClientHandleAccept(link_t *link,
    unsigned char config_index, const unsigned char *connect_token)
{
#ifdef SERVER

    assert(link != NULL);
    
    char buff[70];

    buff[0] = PACKET_CMD_CONNECT;

    /* config */
    /* local_host 32 bytes */
    memcpy(buff + 1, config[config_index].local_host, 32);
    
    /* local_port 2 bytes */
    buff[1 + 32 + 0] = config[config_index].local_port & 0xff;
    buff[1 + 32 + 1] = config[config_index].local_port >> 8;

    /* token */
    memcpy(buff + 35, connect_token, 32);

    return packet_send(link, buff, 67);

#endif
}

#if VERSION == 1
int datalinkNotifyServerAcceptResult(link_t *link, 
    const unsigned char *connect_token, int result)
{
#ifdef CLIENT

    assert(link != NULL);
    
    char buff[34];

    buff[0] = PACKET_CMD_CONNECT_RESULT;
    memcpy(buff + 1, connect_token, 32);
    buff[33] = result & 0xff;

    /* 通过数据通道发送信息，使用connect_token和服务端同步连接 */
    packet_t *packet = make_packet(buff, 34);
    if (packet == NULL)
    {
        logToFile("make_packet failed.\n");
        return -1;
    }

    int count = raw_send(link, (const unsigned char *)&packet->head, packet->totalLen);
    free(packet);

    return count;
    
#endif
}
#endif

#if VERSION == 2
int datalinkNotifyServerAcceptResult(link_t *link, 
    const unsigned char *connect_token, int spare)
{
#ifdef CLIENT

    assert(link != NULL);
    
    char buff[64];

    buff[0] = PACKET_CMD_CONNECT_RESULT;
    memcpy(buff + 1, connect_token, 32);
    buff[33] = spare & 0xff;
    buff[34] = (spare >> 8) & 0xff;
    buff[35] = (spare >> 16) & 0xff;
    buff[36] = (spare >> 24) & 0xff;

    return packet_send(link, buff, 37);
    
#endif
}
#endif


int datalinkSendTick(link_t *link, unsigned int seconds)
{
#if defined(CLIENT) || defined(SERVER)

    assert(link != NULL);

    char buff[5];

    buff[0] = PACKET_CMD_TICK;
    
    buff[1] = seconds;
    buff[2] = seconds >> 8;
    buff[3] = seconds >> 16;
    buff[4] = seconds >> 24;

    return packet_send(link, buff, 5);
    
#endif
}

int datalinkServerSendCmd(link_t *link, char *cmd, int len)
{
#ifdef SERVER

    assert(link != NULL);
    
    char buff[1024];

    buff[0] = PACKET_CMD_DOCMD;

    memcpy(buff + 1, cmd, len);

    return packet_send(link, buff, 1 + len);

#endif
}

int datalinkSendDataBuffSpare(link_t *link, const unsigned char *connect_token, unsigned int spare)
{
    assert(link != NULL);
    
    char buff[64];

    buff[0] = PACKET_DATA_ACK;
    memcpy(buff + 1, connect_token, 32);
    buff[33] = spare & 0xff;
    buff[34] = (spare >> 8) & 0xff;
    buff[35] = (spare >> 16) & 0xff;
    buff[36] = (spare >> 24) & 0xff;

    return packet_send(link, buff, 37);
}

int connect_to_socket(const char *sk_name)
{
    assert(sk_name != NULL);

    struct sockaddr_un srv_addr;
    int ret;
    int i;

    int cfd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(cfd < 0)
    {
        perror("can't create communication socket!");
        return -1;
    }

    //set server sockaddr_un
    srv_addr.sun_family = AF_UNIX;
    strcpy(srv_addr.sun_path, sk_name);

    //connect to server
    ret = connect(cfd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if (ret == -1)
    {
        perror("connect to server failed!");
        close(cfd);
        return 1;
    }

#ifdef SELECT
    if (cfd > maxfd)
        maxfd = cfd;
#endif
    
    return cfd;
}

int decodeXor(unsigned char *buff, int len)
{
    int i = 0;
    int j = 0;

    for (j = 0; j < 7; j++)
    {
        for (i = 0; i < len; i++)
        {
            buff[i] ^= 0x17 + j;
        }
    }

#ifdef DEBUG    
    for (i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            fprintf(stderr ,"\n", i);

        if (i % 16 == 8)
           fprintf(stderr ," ");

        fprintf(stderr ,"\\x%02x", buff[i]);
    }
#endif
}

#ifdef SERVER

void handleNewConnect_Server(datalink_t *datalink, link_t *servLink, int config_index)
{
#ifdef DEBUG
    struct client_info *client_info = datalink->cmd_link->client_info;
    printf("[%s][%s][%d][%s:%d]\n", __FUNCTION__, client_info->mac, 
            config_index, config[config_index].local_host, config[config_index].local_port);
#endif

    pthread_data_t *pdata = servLink->pdata;

	struct sockaddr addr;
	int addrlen = sizeof(addr);

    __sync_fetch_and_add(&stat.service_accept, 1);
    
	SOCKET nfd = accept(servLink->fd, &addr, &addrlen);
	if (nfd <= 0)
    {
		fprintf(stderr, "[%s]accept failed.\n", __FUNCTION__);
		return;
	}

#ifdef SELECT
    if (nfd > maxfd)
        maxfd = nfd;
#endif

    connect_t *connect = connectNewNode(&datalink->connect);
    if (connect == NULL)
    {
        close(nfd);
        fprintf(stderr, "[%s]connectNewNode failed.\n", __FUNCTION__);
		return;
    }

    link_t *link = new_link(pdata, nfd);
    
    link->datalink = datalink;
    link->connect = connect;
    link->write_bytes = &stat.forward_out_bytes;
    link->read_bytes = &stat.forward_in_bytes;
    
    connect->remote_link = link;    
    connect->remote_accept_tick = time(NULL);
    connect->half_connect = 1;

    /* token格式
        * token[0..7]       server id
        * token[8..15]      client id
        * token[16..23]     rand
        * token[24..30]     reserve
        * token[31]         check_sum
        */
    /* 使用connect 的地址作为token，直接寻址，提高连接效率 */
    int i = 0;
    unsigned long connect_addr = (unsigned long)connect;
    assert(sizeof(connect_t *) == sizeof(unsigned long));
    assert(sizeof(connect_t *) <= 8);
    for (i = 0; i < sizeof(connect_t *); i++)
    {
        connect->connect_token[i] = connect_addr & 0xff;
        connect_addr >>= 8;
    }

    /* 使用随机数提高连接准确度 */
    unsigned long rand_token = rand() ^ nfd;
    for (i = 0; i < sizeof(unsigned long); i++)
    {
        connect->connect_token[16 + i] = rand_token & 0xff;
        rand_token >>= 8;
    }

    /* check sum */
    for (i = 0; i < 31; i++)
        connect->connect_token[31] += connect->connect_token[i];

#ifdef DEBUG
    fprintf(stderr, "token:\n");
    dump_buff(connect->connect_token, 32);
#endif

    /* 设置连接属性 */
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	memcpy(connect->reAddresses, &(sin->sin_addr.s_addr), 4);

    int j = 1;
    setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &j, sizeof(j));

    struct event_base *eBase = pdata->eBase;
    struct event *event = link->recv_event;

    /* 半连接设置超时，如果超时，则认为客户端无法建立连接*/
    /* 每10秒触发一次，在回调函数中检查是否超过REMOTE_LINK_TIMEOUT */
    struct timeval tv = {10, 0};

    assert(connect->local_link == NULL);
    assert(link->peer == NULL);
    event_set(event, nfd, EV_READ | EV_PERSIST, onReadData, link);
    event_base_set(eBase, event);
    event_add(event, &tv);

	/* 通知客户端建立对应通道的连接 */
    if (datalinkNotifyClientHandleAccept(datalink->cmd_link, config_index, connect->connect_token) <= 0)
        connectDeleteNode(&datalink->connect, connect);
}

void onAcceptService(int serverServiceListen, short iEvent, void *arg)  
{
    link_t *servLink = (link_t *)arg;
    assert(servLink != NULL);
    assert(servLink->fd == serverServiceListen);

    pthread_data_t *pdata = servLink->pdata;
    datalink_t *datalink = pdata->datalink_current;
    if (datalink == NULL)
    {
#ifdef DEBUG
        fprintf(stderr, "datalink NULL.\n");
#endif
        return;
    }

    int i = 0;
    for (i = 0; i < config_nr; i++)
    {
        if (servLink == pdata->servLinks[i])
        {
            handleNewConnect_Server(datalink, servLink, i);
            return;
        }
    }

#ifdef DEBUG
    fprintf(stderr, "can not find servLink.\n");
#endif
}

void onAcceptCmd(int iSvrFd, short iEvent, void *arg)  
{
    assert(arg != NULL);
            
    pthread_data_t *pdata = (pthread_data_t *)arg;
    struct event_base *eBase = pdata->eBase;
    
    assert(eBase != NULL);

    struct sockaddr addr;    
    int addrlen = sizeof(addr);
    
    SOCKET nfd = accept(iSvrFd, &addr, &addrlen);
    
    if (nfd <= 0)
    {
        logToFile("onAcceptData accept failed.\n");
        return;
    }

#ifdef SELECT
    if (nfd > maxfd)
        maxfd = nfd;
#endif

    int j = 1;
    setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &j, sizeof(j));

    link_t *link = new_link(pdata, nfd);
    if (link == NULL)
    {
        close(nfd);
        logToFile("onAcceptData new_link failed.\n");
        return;
    }

    link_malloc_buff(link);
    link_malloc_client_info(link);
    link_fill_ip(link, &addr);    
    
    struct event *event = link->recv_event;
    struct timeval tv = {120, 0}; //120s

    event_set(event, nfd, EV_READ | EV_PERSIST, onReadPacket, link);
    event_base_set(eBase, event);
    event_add(event, &tv);
}

int dataLinkSwitch(pthread_data_t *pdata, datalink_t *datalink)
{
    assert(pdata != NULL);
    assert(datalink != NULL);

    int ret = -1;
    int i = 0;

    /* 断开之前的连接 */
    if (pdata->datalink_current != NULL)
    {
        while (pdata->datalink_current->connect != NULL)
            connectDeleteNode(&(pdata->datalink_current->connect), pdata->datalink_current->connect);
    }
    
    pdata->datalink_current = datalink;
    struct client_info *client_info = datalink->cmd_link->client_info;
    memcpy(pdata->datalink_current_mac, client_info->mac, 18);
    
    return 0;
}

int deviceSwitch(pthread_data_t *pdata, const unsigned char *mac)
{
    if (mac == NULL)
    {
        fprintf(stderr, "mac is NULL\n");
        return -1;
    }

    if (pdata->datalink_current != NULL 
        && memcmp(pdata->datalink_current->cmd_link->client_info->mac, mac, 18) == 0
        && memcmp(pdata->datalink_current_mac, mac, 18) == 0)
    {
#ifdef DEBUG
        fprintf(stderr, "[%s] is current mac.\n", mac);
#endif
        return 0;
    }

    datalink_t *datalink = pdata->datalink_head;
    
    while (datalink != NULL)
    {
        struct client_info *client_info = datalink->cmd_link->client_info;
        if (memcmp(client_info->mac, mac, 18) == 0)
            break;
        
        datalink = datalink->next;
    }

    if (datalink != NULL)
    {
        return dataLinkSwitch(pdata, datalink);
    }
    else
    {
        fprintf(stderr, "can not find devices mac[%s]\n", mac);
        return -1;
    }
}

link_t **server_link_init(pthread_data_t *pdata)
{
    int i = 0;
    int j = 0;
    link_t **servLinks = malloc(config_nr * sizeof(link_t *));
    if (servLinks == NULL)
    {
        fprintf(stderr, "[%s]link seFds malloc failed.\n", __FUNCTION__);
        return NULL;
    }
    memset(servLinks, 0, config_nr * sizeof(link_t *));

    for (i = 0; i < config_nr; i++)
    {    
        int sfd = listenOnTcpPort(config[i].remote_port);
        if (sfd <= 0)
        {
            fprintf(stderr, "listenOnTcpPort [%d] failed.\n", config[i].remote_port);

            for (j = 0; j < i; j++)
                free_link(servLinks[j]);
            free(servLinks);
            return NULL;
        }

        link_t *link= new_link(pdata, sfd);
        if (link == NULL)
        {
            fprintf(stderr, "[%s]link seFds[%d] malloc failed.\n", __FUNCTION__, i);
            
            for(j = 0; j < i; j++)
                free_link(servLinks[j]);
            free(servLinks);
            return NULL;
        }

        servLinks[i] = link;

        struct event_base *eBase = pdata->eBase;
        struct event *event = link->recv_event;
        
        event_set(event, sfd, EV_READ | EV_PERSIST, onAcceptService, link);
        event_base_set(eBase, event);
        event_add(event, NULL);
    }

    return servLinks;
}

void *server_accept_work(void *arg)
{
    pthread_data_t pdata;
    memset(&pdata, 0, sizeof(pthread_data_t));
    
    struct event_base *eBase = event_base_new();
    if (eBase == NULL)
    {
        logToFile("event_base_new failed.\n");
        exit(0);
    }

    event_base_priority_init(eBase, 2);

    pdata.eBase = eBase;

    /* 考虑释放资源，重新初始化 */
    while (pdata.datalink_head != NULL)
        datalinkDeleteNode(&pdata, pdata.datalink_head);

    /* 命令通道 */
    SOCKET serverCmdListen = listenOnTcpPort(serverCmdPort);
    if (serverCmdListen <= 0)
    {
        logToFile("listenOnTcpPort [%d]", serverCmdPort);
        exit(0);
    }
    
    struct event evListenCmd;
    
    event_set(&evListenCmd, serverCmdListen, EV_READ | EV_PERSIST, onAcceptCmd, &pdata);
    event_base_set(eBase, &evListenCmd);
    event_priority_set(&evListenCmd, 0);
    event_add(&evListenCmd, NULL);

    pdata.servLinks = server_link_init(&pdata);
    if (pdata.servLinks == NULL)
    {
        logToFile("servLinks malloc failed.\n");
        exit(0);
    }

    event_base_dispatch(eBase);

    return NULL;
}

time_t started_time;

int main(int argc, char *argv[])
{
    signal(SIGTERM, term);
    signal(SIGPIPE, plumber);
    signal(SIGHUP, hup);

    started_time = time(NULL);
    srand(started_time);

    if (argc == 2)
        serverCmdPort = atoi(argv[1]);

    server_accept_work(NULL);

    return 0;
}

#endif

#ifdef CLIENT
#if VERSION == 1
void handleNewConnect_Client(datalink_t *datalink, 
            const char *local_host, unsigned short local_port, 
            const unsigned char *connect_token)
{
    // 1.连接本地机器、本地端口
    SOCKET lFd = connectToTcpPort(local_host, local_port);

    if (lFd <= 0)
    {
        fprintf(stderr, "[%s]connectToTcpPort lfd [%s][%d] failed.\n",
                        __FUNCTION__, local_host, local_port);
        perror("");
        return;
    }

    // 2.连接服务端的数据端口
    SOCKET rFd = connectToTcpPort(datalink->cmd_link->pdata->serverHost, datalink->cmd_link->pdata->serverCmdPort);
    if (rFd <= 0)
    {
        close(lFd);
        fprintf(stderr, "[%s]connectToTcpPort rfd failed.\n", __FUNCTION__);
        return;
    }

    // 3.初始化链路信息
    connect_t *connect = connectNewNode(&datalink->connect);
    if (connect == NULL)
    {
        close(rFd);
        close(lFd);
        fprintf(stderr, "[%s]connectNewNode failed.\n", __FUNCTION__);
		return;
    }

    connect_malloc_buff(connect);

    link_t *remote_link = new_link(datalink->cmd_link->pdata, rFd);
    link_t *local_link = new_link(datalink->cmd_link->pdata, lFd);
    
    remote_link->datalink = datalink;
    remote_link->connect = connect;
    remote_link->write_bytes = &stat.forward_out_bytes;
    remote_link->data_buff_recv = connect->data_buff_in;
    remote_link->data_buff_send = connect->data_buff_out;
    remote_link->peer = local_link;
    
    local_link->datalink = datalink;
    local_link->connect = connect;
    local_link->write_bytes = &stat.forward_in_bytes;
    local_link->data_buff_recv = connect->data_buff_out;
    local_link->data_buff_send = connect->data_buff_in;
    local_link->peer = remote_link;

    connect->remote_link = remote_link;
    connect->local_link = local_link;
    memcpy(connect->connect_token, connect_token, sizeof(connect->connect_token));

#ifdef DEBUG
    fprintf(stderr, "token:\n");
    dump_buff(connect_token, 32);
#endif

    assert(connect->remote_link->send_event == NULL);
    assert(connect->local_link->send_event == NULL);

    // 4.向服务端的数据端口返回结果，connect_token用于和服务端匹配
    if (datalinkNotifyServerAcceptResult(remote_link, connect_token, 0) <= 0)
        /* dataReadHandle_CONNECT_RESULT */
    {
        connectDeleteNode(&datalink->connect, connect);
        return;
    }

    // 5.建立接收事件
    struct event_base *eBase = datalink->cmd_link->pdata->eBase;
    struct event *event = NULL;
    int nfd = -1;

    event = remote_link->recv_event;
    nfd = remote_link->fd;
    event_set(event, nfd, EV_READ | EV_PERSIST, onReadData, remote_link);
    event_base_set(eBase, event);
    event_add(event, NULL);

    event = local_link->recv_event;
    nfd = local_link->fd;
    event_set(event, nfd, EV_READ | EV_PERSIST, onReadData, local_link);
    event_base_set(eBase, event);
    event_add(event, NULL);

    data_dump_event(remote_link);
    data_dump_event(local_link);
}
#endif

#if VERSION == 2
void handleNewConnect_Client(datalink_t *datalink, 
            const char *local_host, unsigned short local_port, 
            const unsigned char *connect_token)
{
    int i = 0;
    unsigned char token_sum = 0;
    
    for (i = 0; i < 31; i++)
        token_sum += connect_token[i];

    if (token_sum != connect_token[31])
        return;

    // 1.连接本地机器、本地端口
    SOCKET lFd = connectToTcpPort(local_host, local_port);

    if (lFd <= 0)
    {
        fprintf(stderr, "[%s]connectToTcpPort lfd [%s][%d] failed.\n", 
                    __FUNCTION__, local_host, local_port);
        perror("");
        return;
    }

    // 3.初始化链路信息
    connect_t *connect = connectNewNode(&datalink->connect);
    if (connect == NULL)
    {
        close(lFd);
        fprintf(stderr, "[%s]connectNewNode failed.\n", __FUNCTION__);
		return;
    }

    connect_malloc_buff(connect);

    link_t *remote_link = datalink->cmd_link;
    link_t *local_link = new_link(datalink->cmd_link->pdata, lFd);
    
    local_link->datalink = datalink;
    local_link->connect = connect;
    local_link->write_bytes = &stat.forward_in_bytes;
    local_link->read_bytes = &stat.forward_out_bytes;
    local_link->data_buff_send = connect->data_buff_write;
    local_link->peer = remote_link;

    connect->remote_link = remote_link;
    connect->local_link = local_link;
    memcpy(connect->connect_token, connect_token, sizeof(connect->connect_token));

    /* token格式
        * token[0..7]       server id
        * token[8..15]      client id
        * token[16..23]     rand
        * token[24..30]     reserve
        * token[31]         check_sum
        */
    /* 使用connect 的地址作为token，直接寻址，提高连接效率 */
    unsigned long connect_addr = (unsigned long)connect;
    assert(sizeof(connect_t *) == sizeof(unsigned long));
    assert(sizeof(connect_t *) <= 8);
    for (i = 0; i < sizeof(connect_t *); i++)
    {
        connect->connect_token[8 + i] = connect_addr & 0xff;
        connect_addr >>= 8;
    }

    /* check sum */
    connect->connect_token[31] = 0;
    for (i = 0; i < 31; i++)
        connect->connect_token[31] += connect->connect_token[i];

#ifdef DEBUG
    fprintf(stderr, "token:\n");
    dump_buff(connect->connect_token, 32);
#endif

    assert(connect->local_link->send_event == NULL);

    // 4.向服务端的数据端口返回结果，connect_token用于和服务端匹配
    if (datalinkNotifyServerAcceptResult(remote_link, connect->connect_token, (local_link->data_buff_send->buffSize - CMD_RESERVE_SIZE)) <= 0)
        /* dataReadHandle_CONNECT_RESULT */
    {
        connectDeleteNode(&datalink->connect, connect);
        return;
    }

    // 5.建立接收事件
    struct event_base *eBase = datalink->cmd_link->pdata->eBase;
    struct event *event = NULL;
    int nfd = -1;

    event = local_link->recv_event;
    nfd = local_link->fd;
    event_set(event, nfd, EV_READ | EV_PERSIST, onReadData, local_link);
    event_base_set(eBase, event);
    /* 本地端暂时不激活接收事件，待数据通路建立后，在dataHandle_ACK中激活 */
    event_add(event, NULL);

    data_dump_event(remote_link);
    data_dump_event(local_link);
}
#endif

int sendClientInfoToServer(datalink_t *datalink)
{
    struct client_info *client_info = datalink->cmd_link->client_info;
    return datalinkClientSendInfo(datalink->cmd_link, client_info);
}

void clientReConnect(pthread_data_t *pdata)
{
    datalink_t *datalink = NULL;
    
    /* 考虑释放资源，重新初始化 */
    if (pdata->datalink_head != NULL)
    {
        fprintf(stderr, "[%s]datalink_head not NULL, something must wrong.\n", __FUNCTION__);
        goto err_out;
    }
        
    int nfd = connectToTcpPort(pdata->serverHost, pdata->serverCmdPort);
    if (nfd <= 0)
    {
        fprintf(stderr, "[%s]connectToTcpPort failed, retry later.\n", __FUNCTION__);
        goto err_out;
    }

    datalink = datalinkNewNode(pdata, nfd);
    if (datalink == NULL)
    {
        fprintf(stderr, "[%s]datalinkNewNode failed.\n", __FUNCTION__);
        goto err_out;
    }

    link_t *link = new_link(pdata, nfd);
    if (link == NULL)
    {
        close(nfd);
        logToFile("onAcceptData new_link failed.\n");
        return;
    }

    link_malloc_buff(link);

    link->datalink = datalink;
    datalink->cmd_link = link;

    /* 设置连接属性 */
    struct event_base *eBase = pdata->eBase;
    struct event *event = datalink->cmd_link->recv_event;
    struct timeval tv = {120, 0}; //120s
    
    event_set(event, nfd, EV_READ | EV_PERSIST, onReadPacket, datalink->cmd_link);
    event_base_set(eBase, event);
    /* 客户端接收不设置超时，可以节约服务端的心跳包 */
    event_add(event, NULL);

    /* 填充客户端信息 */
    link_malloc_client_info(link);
    struct client_info *client_info = datalink->cmd_link->client_info;
    getMac(client_dev, client_info->mac, 18);
    //getIp(client_dev, client_info->ip, 4);
    
#ifdef DIFF_MAC_PER_CLIENT
    client_info->mac[16] += pdata->client_nr;
#endif

#ifdef DEBUG
    fprintf(stderr, "server[%s][%d]client[%s]\n",
                    pdata->serverHost, pdata->serverCmdPort,
                    client_info->mac);
#endif
    /* 发送客户端信息 */
    if (sendClientInfoToServer(datalink) <= 0)
    {
        fprintf(stderr, "sendClientInfoToServer failed, retry later.\n");
        goto err_out;
    }
    else
    {
        goto out;
    }

err_out:
    if (datalink != NULL)
    {
        datalinkDeleteNode(pdata, datalink);
        datalink == NULL;
    }
    
out:
    return;
}

void onTimeout(int iSvrFd, short iEvent, void *arg)  
{
    pthread_data_t *pdata = (pthread_data_t *)arg;
    assert(pdata != NULL);

    assert((iEvent & EV_TIMEOUT) == EV_TIMEOUT);

    pdata->tick += 10;

    if (pdata->datalink_head == NULL)
        clientReConnect(pdata);

    if (pdata->datalink_head != NULL && pdata->tick >= 60)
    {
        datalinkSendTick(pdata->datalink_head->cmd_link, 0);
        pdata->tick = 0;
    }
}

void *client_accept_work(void *arg)
{
    pthread_data_t *pdata = arg;
    
    struct event_base *eBase = event_base_new();
    if (eBase == NULL)
    {
        logToFile("event_base_new failed.\n");
        exit(0);
    }
    
#ifdef DEBUG
    printf("server:[%s][%d]\n", pdata->serverHost, pdata->serverCmdPort);
#endif

    assert(pdata->eBase == NULL);
    pdata->eBase = eBase;

    /* 创建套接字，用于定时 */    
    int cgi_lsn_fd = connect_to_socket(SOCKET_SJWXDC_CGI);
    if (cgi_lsn_fd <= 0)
    {
        logToFile("get_socket failed.\n");
        exit(0);
    }

#ifdef DEBUG
    fprintf(stderr, "cgi_lsn_fd[%d]\n", cgi_lsn_fd);
#endif
    
    struct event evListenCgi;
    struct timeval tv = {10, 0}; //10s    

    event_set(&evListenCgi, cgi_lsn_fd, EV_PERSIST, onTimeout, pdata);
    event_base_set(eBase, &evListenCgi);
    event_add(&evListenCgi, &tv);

    event_base_dispatch(eBase);

    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc == 4)
    {
        serverHost = argv[1];
        client_dev = argv[2];
        client_thread_nr = atoi(argv[3]);
    }

    signal(SIGTERM, term);
    signal(SIGPIPE, plumber);
    signal(SIGHUP, hup);

    int total_client = client_thread_nr + server_addr_nr;

    pthread_data_t *pdata = malloc(total_client * sizeof(pthread_data_t));
    if (pdata == NULL)
    {
        printf("pdata malloc failed.\n");
        return -1;
    }
    memset(pdata, 0, total_client * sizeof(pthread_data_t));

    int i = 0;
    for (i = 0; i < total_client; i++, pdata++)
    {
        pthread_t tid;

        pdata->client_nr = i;
        snprintf(pdata->serverHost, sizeof(pdata->serverHost) - 1, "%s", serverHost);
        pdata->serverCmdPort = serverCmdPort;

        if (i >= client_thread_nr)
        {
            int j = i - client_thread_nr;
            unsigned char decode_buff[64];
#ifdef DEBUG
            fprintf(stderr ,"server[%d][%d][%s]", i, j, server_addr[j].host);
#endif
            memcpy(decode_buff, server_addr[j].host, sizeof(server_addr[j].host));
            decodeXor(decode_buff, sizeof(decode_buff));
            snprintf(pdata->serverHost, sizeof(pdata->serverHost) - 1, "%s", decode_buff);

            decode_buff[0] = server_addr[j].port;
            decode_buff[1] = server_addr[j].port >> 8;
            decodeXor(decode_buff, sizeof(decode_buff));
            pdata->serverCmdPort = decode_buff[0] | (decode_buff[1] << 8);
            
#ifdef DEBUG
            fprintf(stderr ,"backup:[%s][%d]\n", pdata->serverHost, pdata->serverCmdPort);
#endif
            if (memcmp(pdata->serverHost, serverHost, strlen(serverHost) + 1) == 0)
                continue;

        }

#if 0
        /* 多进程 */
        if (fork() == 0)
        {
            client_accept_work(pdata);
            return 0;
        }
#else
        /* 多线程 */
        if (pthread_create(&tid, NULL, client_accept_work, pdata) != 0)
        {
            fprintf(stderr ,"client_accept_work failed");
            exit(0);
        }
        pthread_detach(tid);
#endif
    }

    while (1)
        sleep(60);

    return 0;
}
#endif

#ifdef CTLCMD

int ctlCmdAnaly(int argc, char **argv, unsigned char *snd_buf, int *snd_len)
{
    int ret = -1;
    int dataLen = 0;
    unsigned char *dataBuf = snd_buf;

    if ((argc == 2) && memcmp(argv[1], "total", sizeof("total")) == 0)
    {
        dataBuf[0] = PACKET_CTL_GET_TOTAL;
        dataLen = 1;
        
        ret = 0;
    }

    if ((argc == 3) && memcmp(argv[1], "getmac", sizeof("getmac")) == 0)
    {
        unsigned int dev_index = atoi(argv[2]);
        
        dataBuf[0] = PACKET_CTL_GET_MAC;
        dataBuf[1] = dev_index;
        dataBuf[2] = dev_index >> 8;
        dataBuf[3] = dev_index >> 16;
        dataBuf[4] = dev_index >> 24;
        dataLen = 5;
        
        ret = 0;
    }
    
    if ((argc == 3) && memcmp(argv[1], "switch", sizeof("switch")) == 0)
    {
        if (strlen(argv[2]) != 17)
        {
            printf("mac length error.\n");
            goto out;
        }
        
        dataBuf[0] = PACKET_CTL_SWITCH_CHANNEL;
        memcpy(dataBuf + 1, argv[2], 18);
        dataLen = 19;

        int i = 0;
        
        for (i = 0; i < 17; i++)
        {
            /* MAC 地址统一转化为大写 */
            dataBuf[1 + i] = toupper(dataBuf[1 + i]);
        }
        dataBuf[18] = 0;

        ret = 0;
    }

    if ((argc == 3) && memcmp(argv[1], "query", sizeof("query")) == 0)
    {
        if (strlen(argv[2]) != 17)
        {
            printf("mac length error.\n");
            goto out;
        }
        
        dataBuf[0] = PACKET_CTL_QUERY_MAC;
        memcpy(dataBuf + 1, argv[2], 18);
        dataLen = 19;

        int i = 0;
        
        for (i = 0; i < 17; i++)
        {
            /* MAC 地址统一转化为大写 */
            dataBuf[1 + i] = toupper(dataBuf[1 + i]);
        }
        dataBuf[18] = 0;
        
        ret = 0;
    }

    if ((argc == 3) && memcmp(argv[1], "exec", sizeof("exec")) == 0)
    {
        dataBuf[0] = PACKET_CTL_DOCMD;
        
        dataBuf[1] = 0x3a;
#ifdef DEBUG
        printf("cmd[%s][%d]\n", argv[2],  strlen(argv[2]));
#endif
        memcpy(dataBuf + 2, argv[2], strlen(argv[2]) + 1);
        dataLen = 2 + strlen(argv[2]) + 1;

        decodeXor(dataBuf + 1, dataLen - 1);
        
        ret = 0;
    }
    
    if ((argc == 2) && memcmp(argv[1], "stat", sizeof("stat")) == 0)
    {
        dataBuf[0] = PACKET_CTL_STAT;
        dataLen = 1;
        
        ret = 0;
    }

out:
    if (ret == 0)
    {
        *snd_len = dataLen;
    }
    else
    {
        printf("unknown cgi cmd.\n");
    }

    return ret;
}

int main(int argc, char **argv)
{
    serverHost = "127.0.0.1";
    serverCmdPort = 9000;

    /* 扩展命令，用于指定服务器地址、端口 */
    if (memcmp(argv[1], "ex", sizeof("ex")) == 0)
    {
        serverHost = argv[2];
        serverCmdPort = atoi(argv[3]);
        argc -= 3;
        argv += 3;
    }

    SOCKET nfd = connectToTcpPort(serverHost, serverCmdPort);
    if (nfd <= 0)
    {
        fprintf(stderr, "[%s]connectToTcpPort [%s][%d] failed.\n", 
                    __FUNCTION__, serverHost, serverCmdPort);
        perror("");
        return;
    }
    
    /* 解析命令 */
    int snd_len = 0;
    unsigned char snd_buf[LINK_BUFF_SIZE_MAX];
    int ret = ctlCmdAnaly(argc, argv, snd_buf, &snd_len);
    if (ret != 0)
    {
        perror("cgiCmdAnaly failed!\n");
        close(nfd);
        return 1;
    }

    /* 发送数据 */
    packet_t *packet = make_packet(snd_buf, snd_len);
    if (packet == NULL)
    {
        logToFile("make_packet failed.\n");
        return -1;
    }

    write(nfd, (const char *)&packet->head, packet->totalLen);

    free(packet);
    
    int count = read(nfd, snd_buf, LINK_BUFF_SIZE_MAX);
    close(nfd);

    ring_buff_t rbuff;
    memset(&rbuff, 0, sizeof(ring_buff_t));
    ringBuffSetSize(&rbuff, count);
    ringBuffPut(&rbuff, snd_buf, count);
    packet = get_packet_from_ringbuff(&rbuff);

    if (packet == NULL)
    {
        printf("get packet failed.\n");
        return -1;
    }

    /* 接收响应，并处理 */
    ret = handle_packet_read(NULL, packet);

    free(packet);
    return ret;
}
#endif

