#include "debug.h"
#include "def.h"
#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

//#define CLIENT_UDP_HEARTBEAT_FREQUENCY      (10) /*10 seconds*/
#define CLIENT_UDP_HEARTBEAT_MAXINTERVAL    (5*60) /*if not receive client's heartbeat beyond 5mins, delete client*/

typedef struct dbg_client_info_st{
    BOOL used;
    time_t latest;
    uint32 ipaddr;  /*ipaddr: network order*/
    uint16 port;    /*port: network order*/
    uint16 reserve;
}dbg_client_info_t;

#define CLIENT_MAXNUM_DEFAULT           (16)
#define CLEINT_MAXNUM_INCREASE_INTERVAL (8)
#define DBG_BUFFER_MAXSIZE              (64*1024)
typedef struct dbg_info_st{
    int32 listen_fd;
    BOOL destroying;
    pthread_t thdid;
    pthread_mutex_t mutex;
    uint32 maxnum;  /*client max number*/
    uint32 curnum;  /*client current number*/
    dbg_client_info_t *clients;
}dbg_info_t;

static dbg_info_t *gsp_dbg_info = NULL;

static dbg_client_info_t *dbg_client_get(const dbg_client_info_t *client)
{
    uint32 i = 0;
    for (i=0; i<gsp_dbg_info->curnum; ++i)
    {
        ASSERT(TRUE == gsp_dbg_info->clients[i].used);
        if (client->ipaddr == gsp_dbg_info->clients[i].ipaddr
            && client->port == gsp_dbg_info->clients[i].port)
            return &gsp_dbg_info->clients[i];
    }
    return NULL;
}

static void dbg_client_all_dump(const int8 *describe)
{
/*
    uint32 i = 0;
    printf("----------- debug client all dump begin [maxnum:%u, curnum:%u] <%s> -----------\r\n", 
        gsp_dbg_info->maxnum, gsp_dbg_info->curnum, describe);
    for (i=0; i<gsp_dbg_info->curnum; ++i)
        printf("\t%u. used:%d, latest:%lu ipaddr:0x%x, port:%u\r\n", 
            i+1, gsp_dbg_info->clients[i].used, gsp_dbg_info->clients[i].latest, 
            ntohl(gsp_dbg_info->clients[i].ipaddr), ntohs(gsp_dbg_info->clients[i].port));
    printf("+++++++++++ debug client all dump end [maxnum:%u, curnum:%u] +++++++++++\r\n", 
        gsp_dbg_info->maxnum, gsp_dbg_info->curnum);
*/
}

static void dbg_client_dump(const dbg_client_info_t *client,
                            const int8 *describe)
{
/*
    ASSERT(NULL != client);
    printf("client information <%s> [used:%d, latest:%lu, ipaddr:0x%x, port:%u]\r\n",
        describe, client->used, client->latest, ntohl(client->ipaddr), ntohs(client->port));
*/
}

static void dbg_client_add(const dbg_client_info_t *client)
{
    dbg_client_info_t *client_tmp = NULL;
    ASSERT(NULL != client);
    dbg_client_dump(client, __func__);
    client_tmp = dbg_client_get(client);
    if (NULL == client_tmp)
    {
        if (gsp_dbg_info->curnum >= gsp_dbg_info->maxnum)
        {
            uint32 i = 0;
            gsp_dbg_info->maxnum += CLEINT_MAXNUM_INCREASE_INTERVAL;
            gsp_dbg_info->clients = realloc(gsp_dbg_info->clients, sizeof(*gsp_dbg_info->clients) * gsp_dbg_info->maxnum);
            for (i=gsp_dbg_info->curnum; i<gsp_dbg_info->maxnum; ++i)
            {
                gsp_dbg_info->clients[i].used = FALSE;
            }
        }
        gsp_dbg_info->clients[gsp_dbg_info->curnum].ipaddr = client->ipaddr;
        gsp_dbg_info->clients[gsp_dbg_info->curnum].port = client->port;
        gsp_dbg_info->clients[gsp_dbg_info->curnum].used = TRUE;
        client_tmp = &gsp_dbg_info->clients[gsp_dbg_info->curnum];
        ++(gsp_dbg_info->curnum);
    }
    client_tmp->latest = time(NULL);
    dbg_client_all_dump(__func__);
}

static void dbg_client_del(const dbg_client_info_t *client)
{
    uint32 i = 0;
    uint32 index = gsp_dbg_info->curnum;
    dbg_client_dump(client, __func__);
    for (i=0; i<gsp_dbg_info->curnum; ++i)
    {
        if (client->ipaddr == gsp_dbg_info->clients[i].ipaddr
            && client->port == gsp_dbg_info->clients[i].port)
        {
            index = i;
            break;
        }
    }
    if (index < gsp_dbg_info->curnum)
    {
        for (i=index; i < (gsp_dbg_info->curnum-1); ++i)
        {
            gsp_dbg_info->clients[i].ipaddr = gsp_dbg_info->clients[i+1].ipaddr;
            gsp_dbg_info->clients[i].port = gsp_dbg_info->clients[i+1].port;
            gsp_dbg_info->clients[i].used = gsp_dbg_info->clients[i+1].used;
            gsp_dbg_info->clients[i].latest = gsp_dbg_info->clients[i+1].latest;
        }
        gsp_dbg_info->clients[gsp_dbg_info->curnum-1].used = FALSE;
        --gsp_dbg_info->curnum;
    }
    dbg_client_all_dump(__func__);
}

static void dbg_client_die_detect_delete(void)
{
    int32 i = 0;
    time_t now = time(NULL);
#if 0
    for (i=0; i<gsp_dbg_info->curnum; ++i)
    {
        if ((now - gsp_dbg_info->clients[i].latest) > CLIENT_UDP_HEARTBEAT_MAXINTERVAL)
        {
            dbg_client_dump(&gsp_dbg_info->clients[i], __func__);
            dbg_client_del(&gsp_dbg_info->clients[i]);
            --i;
        }
    }
#else
    int32 die_first_index = -1;
    int32 die_num = 0;
    for (i=0; i<gsp_dbg_info->curnum; ++i)
    {
        if ((now - gsp_dbg_info->clients[i].latest) > CLIENT_UDP_HEARTBEAT_MAXINTERVAL)
        {
            dbg_client_dump(&gsp_dbg_info->clients[i], __func__);
            gsp_dbg_info->clients[i].used = FALSE;
            ++die_num;
            if (die_first_index < 0)
                die_first_index = i;
        }
        else
        {
            if (die_first_index >= 0)
            {
                gsp_dbg_info->clients[die_first_index].used = gsp_dbg_info->clients[i].used;
                gsp_dbg_info->clients[die_first_index].latest = gsp_dbg_info->clients[i].latest;
                gsp_dbg_info->clients[die_first_index].ipaddr = gsp_dbg_info->clients[i].ipaddr;
                gsp_dbg_info->clients[die_first_index].port = gsp_dbg_info->clients[i].port;
                gsp_dbg_info->clients[i].used = FALSE;
                ++die_first_index;
            }
        }
    }
    gsp_dbg_info->curnum -= die_num;
#endif
    dbg_client_all_dump(__func__);
}

static void *dbg_listen_thread_cb(void *arg)
{
    fd_set rfds;
    int32 maxfd1 = -1;
    struct timeval tv;
    int32 ret = -1;
    uint32 rcvlen = 0;
    int8 buf[128];
    dbg_info_t *dbginfo = (dbg_info_t *)arg;
    dbg_client_info_t client;
    int32 count = 0;
    struct sockaddr_in addr;
    int32 *operate = NULL;
    socklen_t addrlen = sizeof(addr);
    while (1)
    {
        pthread_mutex_lock(&dbginfo->mutex);
        if (TRUE == dbginfo->destroying)
        {
            pthread_mutex_unlock(&dbginfo->mutex);
            break;
        }
        FD_ZERO(&rfds);
        FD_SET(dbginfo->listen_fd, &rfds);
        maxfd1 = dbginfo->listen_fd+1;
        pthread_mutex_unlock(&dbginfo->mutex);
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        ret = select (maxfd1, &rfds, NULL, NULL, &tv);
            
        if (0 == ret)
        {
            sleep(1);
        }
        else if (ret > 0)
        {
            bzero(buf, sizeof(buf));
            bzero(&addr, sizeof(addr));
            addrlen = sizeof(addr);
            pthread_mutex_lock(&dbginfo->mutex);
            rcvlen = recvfrom(dbginfo->listen_fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen);
            if (rcvlen != sizeof(*operate))
            {
                printf("received is not a debug client's connect request!! "
                    "because \"rcvlen(%u) != sizeof(*operate)(%u))\"!!\n",
                    rcvlen, (uint32)sizeof(*operate));
            }
            else
            {
                operate = (int32 *)buf;
                *operate = ntohl(*operate);
                client.ipaddr = addr.sin_addr.s_addr;
                client.port = addr.sin_port;
                if (0 == *operate)
                    dbg_client_add(&client);
                else if (1 == *operate)
                    dbg_client_del(&client);
            }
            pthread_mutex_unlock(&dbginfo->mutex);
        }
        else
        {
            perror("select()");
            sleep(1);
        }
        /*delete timeout client*/
        ++count;
        if (0 == (count % 5))
        {
            pthread_mutex_lock(&dbginfo->mutex);
            dbg_client_die_detect_delete();
            pthread_mutex_unlock(&dbginfo->mutex);
        }
    }
    return arg;
}

#define DBG_SERVER_PORT (3803)
int32 debug_init(void)
{
    struct sockaddr_in addr;
    int32 ret = -1;
    uint32 i = 0;
    BOOL mutex_inited = FALSE;
    
    if (NULL != gsp_dbg_info)
        return 0;
    gsp_dbg_info = (dbg_info_t *)calloc(1, sizeof(*gsp_dbg_info));
    ASSERT(NULL != gsp_dbg_info);
    gsp_dbg_info->listen_fd = -1;
    gsp_dbg_info->destroying = FALSE;
    gsp_dbg_info->maxnum = CLIENT_MAXNUM_DEFAULT;
    gsp_dbg_info->curnum = 0;
    gsp_dbg_info->clients = (dbg_client_info_t *)calloc(gsp_dbg_info->maxnum, sizeof(*gsp_dbg_info->clients));
    for (i=0; i<gsp_dbg_info->maxnum; ++i)
        gsp_dbg_info->clients[i].used = FALSE;
    gsp_dbg_info->listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (gsp_dbg_info->listen_fd < 0)
    {
        perror("socket()");
        goto out;
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(DBG_SERVER_PORT);
    if (bind(gsp_dbg_info->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind()");
        goto out;
    }
    if (pthread_mutex_init(&(gsp_dbg_info->mutex), NULL) < 0)
    {
        perror("pthread_mutex_init()");
        goto out;
    }
    mutex_inited = TRUE;
    if (pthread_create(&(gsp_dbg_info->thdid), NULL, dbg_listen_thread_cb, gsp_dbg_info) < 0)
    {
        perror("pthread_create()");
        goto out;
    }

    ret = 0;
out:
    if (0 != ret)
    {
        if (NULL != gsp_dbg_info)
        {
            if (gsp_dbg_info->listen_fd >= 0)
                close(gsp_dbg_info->listen_fd);
            if (TRUE == mutex_inited)
                pthread_mutex_destroy(&(gsp_dbg_info->mutex));
            if (NULL != gsp_dbg_info->clients)
                free(gsp_dbg_info->clients);
            free(gsp_dbg_info);
            gsp_dbg_info = NULL;
        }
    }
    return ret;
}

void debug_final(void)
{
    if (NULL == gsp_dbg_info)
        return;
    pthread_mutex_lock(&(gsp_dbg_info->mutex));
    gsp_dbg_info->destroying = TRUE;
    pthread_mutex_unlock(&(gsp_dbg_info->mutex));
    pthread_join(gsp_dbg_info->thdid, NULL);
    if (gsp_dbg_info->listen_fd >= 0)
        close(gsp_dbg_info->listen_fd);
    pthread_mutex_destroy(&(gsp_dbg_info->mutex));
    if (NULL != gsp_dbg_info->clients)
        free(gsp_dbg_info->clients);
    free(gsp_dbg_info);
    gsp_dbg_info = NULL;
}

int32 debug_print(int8 *fmt,...)
{
    int8 buf[DBG_BUFFER_MAXSIZE];
    va_list va;
    bzero(buf, sizeof(buf));
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
#ifdef DEBUG_STDOUT
    printf("%s", buf);
#endif
    if (NULL != gsp_dbg_info)
    {
        uint32 i = 0;
        struct sockaddr_in addr;
        pthread_mutex_lock(&(gsp_dbg_info->mutex));
        for (i=0; i<gsp_dbg_info->curnum; ++i)
        {
            ASSERT(TRUE == gsp_dbg_info->clients[i].used);
            bzero(&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = gsp_dbg_info->clients[i].ipaddr;
            addr.sin_port = gsp_dbg_info->clients[i].port;
            if (sendto(gsp_dbg_info->listen_fd, buf, strlen(buf), 0, 
                        (const struct sockaddr *)&addr, sizeof(addr)) < 0)
            {
                perror("sendto()");
                printf("ipaddr:0x%x, port:%u\r\n", 
                    ntohl(gsp_dbg_info->clients[i].ipaddr), 
                    ntohs(gsp_dbg_info->clients[i].port));
            }
        }
        pthread_mutex_unlock(&(gsp_dbg_info->mutex));
    }
    return strlen(buf);

}

int32 debug(const int32 level,
            const int8 *func,
            const int32 line,
            const char *file,
            int8 *fmt,...)
{
    int8 buf[DBG_BUFFER_MAXSIZE];
    int8 *p = NULL;
    int32 len = 0;
    va_list va;
    int8 *levelstr[] = {
            [DEBUG_LEVEL_INF]   = "INF",
            [DEBUG_LEVEL_WAR]   = "WAR",
            [DEBUG_LEVEL_ERR]   = "ERR",
            [DEBUG_LEVEL_PARAM] = "PARAM",
            [DEBUG_LEVEL_POS]   = "POS",
            [DEBUG_LEVEL_TRACE] = "TRACING"
        };
    
    ASSERT(DEBUG_LEVEL_VALID(level));
    bzero(buf, sizeof(buf));
    snprintf(buf, sizeof(buf), "[%s]<%s@%u %s> ", levelstr[level], func, line, file);
    len = strlen(buf);
    p = buf + len;
    va_start(va, fmt);
    vsnprintf(p, sizeof(buf)-len, fmt, va);
    va_end(va);
    len = strlen(buf);
    p = buf + len;
    snprintf(p, sizeof(buf)-len, "\r\n");
#ifdef DEBUG_STDOUT
    printf("%s", buf);
#endif
    if (NULL != gsp_dbg_info)
    {
        uint32 i = 0;
        struct sockaddr_in addr;
        pthread_mutex_lock(&(gsp_dbg_info->mutex));
        for (i=0; i<gsp_dbg_info->curnum; ++i)
        {
            ASSERT(TRUE == gsp_dbg_info->clients[i].used);
            bzero(&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = gsp_dbg_info->clients[i].ipaddr;
            addr.sin_port = gsp_dbg_info->clients[i].port;
            if (sendto(gsp_dbg_info->listen_fd, buf, strlen(buf), 0, 
                        (const struct sockaddr *)&addr, sizeof(addr)) < 0)
            {
                perror("sendto()");
                printf("ipaddr:0x%x, port:%u\r\n", 
                    ntohl(gsp_dbg_info->clients[i].ipaddr), 
                    ntohs(gsp_dbg_info->clients[i].port));
            }
        }
        pthread_mutex_unlock(&(gsp_dbg_info->mutex));
    }
    return strlen(buf);
}

void hexdump(int8 *p_title, 
             int8 *p_data,
             uint32 dlen,
             uint32 width)
{
	int32 i, j;
	uint32 c;
	int8 buf[256];
	int8 *p;
	int32 size;
	int32 n;

	ASSERT(width>=4 && width<=64);
	PRINTF("---------------- hexdump begin[%s],dlen[%u] ----------------\r\n", 
			p_title, dlen);
	for (i=0; i<dlen; i+=width)
	{
	    bzero(buf,sizeof(buf));
		p = buf;
		size = sizeof(buf);
		n = snprintf(p,size,"%p: ",p_data+i);
		ASSERT(n>=0);
		size -= n;
		p += n;
		for (j=i; j<dlen && j<(i+width); ++j)
		{
			c = p_data[j];
			c &= 0x000000ff;
			n = snprintf(p, size, "%02X", c);
			ASSERT(n>=0);
			size -= n;
			ASSERT(size>=0);
			p += n;
			if (0 == ((j+1)%2))
			{
				n = snprintf(p, size, " ");
				ASSERT(n>=0);
				size -= n;
				ASSERT(size>=0);
				p += n;
			}
		}
		PRINTF("%s", buf);

        PRINTF("    |    ");
        
	    bzero(buf,sizeof(buf));
        p = buf;
        size = sizeof(buf);
        for (j=i; j<dlen && j<(i+width); ++j)
		{
		    if (isprint(p_data[j]))
                sprintf(p,"%c",p_data[j]);
            else
                sprintf(p," ");
            ++p;
		}
		PRINTF("%s\r\n", buf);
	}
	PRINTF("---------------- hexdump end[%s],dlen[%u] ----------------\r\n", 
			p_title, dlen);
}


