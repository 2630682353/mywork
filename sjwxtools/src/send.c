#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/time.h>

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>  
#include <sys/un.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "sjwx.h"

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

#endif  // GCC_HAVE_CAS

stat_t stat;

pthread_t send_thread_id = (pthread_t)-1;

typedef struct _mysql_cmd {
    char *cmdStr;
    int len;
}mysql_cmd_t;

typedef struct _cmd_queue {
    int maxcount;
    int head;
    int tail;
    mysql_cmd_t *cmd;
}cmd_queue_t;

cmd_queue_t *cmd_queue = NULL;

#define CMD_QUEUE_POWER 10
#define CMD_QUEUE_SIZE (1 << CMD_QUEUE_POWER)
#define CMD_QUEUE_MASK (CMD_QUEUE_SIZE - 1)

#define cmd_head_val(cmd_queue)      (__sync_val_compare_and_swap(&(cmd_queue)->head, 0, 0))
#define cmd_tail_val(cmd_queue)      (__sync_val_compare_and_swap(&(cmd_queue)->tail, 0, 0))
#define cmd_queue_len(cmd_queue)   (cmd_head_val(cmd_queue) - cmd_tail_val(cmd_queue))
#define cmd_queue_empty(cmd_queue) (cmd_queue_len(cmd_queue) == 0)
#define cmd_queue_full(cmd_queue)  (cmd_queue_len(cmd_queue) == CMD_QUEUE_SIZE)
#define cmd_queue_offset(val)           ((val) & CMD_QUEUE_MASK)

int queue_init(void)
{
    cmd_queue = malloc(sizeof(cmd_queue_t));
    cmd_queue->maxcount = CMD_QUEUE_SIZE;
    cmd_queue->head = 0;
    cmd_queue->tail = 0;
    cmd_queue->cmd = malloc(cmd_queue->maxcount * sizeof(mysql_cmd_t));
    if (cmd_queue->cmd == NULL)
    {
        printf("cmd_queue->cmd malloc failed.\n");
        return -1;
    }
    memset(cmd_queue->cmd, 0, cmd_queue->maxcount * sizeof(mysql_cmd_t));
    return 0;
}

int process_data(const unsigned char *buff, int len)
{
    char *ins_buff = malloc(len + 1);
    if (ins_buff == NULL)
    {
        printf("malloc ins_buff failed.\n");
        return -1;
    }
    memcpy(ins_buff, buff, len);

    __sync_fetch_and_add(&stat.cap_nr, 1);

    /* 插入队列 */
    int head = 0;
    do
    {
        head = cmd_queue->head;
        
        if (cmd_queue_full(cmd_queue))
        {
            pthread_kill(send_thread_id, SIGUSR1);
            __sync_fetch_and_add(&stat.enqeue_drop, 1);
            free(ins_buff);
            return -1;
        }
    }while (!__sync_bool_compare_and_swap(&cmd_queue->head, head, head + 1));

    if (__sync_val_compare_and_swap(&cmd_queue->cmd[cmd_queue_offset(head)].cmdStr, NULL, NULL) != NULL)
    {
        printf("bug:cmd_queue head is not NULL.\n");
        exit(0);
    }

    cmd_queue->cmd[cmd_queue_offset(head)].len = len;

    while(!__sync_bool_compare_and_swap(&cmd_queue->cmd[cmd_queue_offset(head)].cmdStr, 
                NULL, ins_buff));
    
    pthread_kill(send_thread_id, SIGUSR1);
    return 0;
}

extern time_t started_time;

int process_cmd(unsigned char *recv_buff, int recv_len, 
            unsigned char *send_buff, int max_send_len, int *send_len)
{
    unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;

    time_t uptime = time(NULL) - started_time;
    days = (unsigned int)uptime / (24 * 60 * 60);
    uptime -= days * (24 * 60 * 60);
    hours = (unsigned int)uptime / (60 * 60);
    uptime -= hours * (60 * 60);
    minutes = (unsigned int)uptime / 60;
    uptime -= minutes * 60;
    seconds = (unsigned int)uptime;

    *send_len = snprintf(send_buff, max_send_len,
                "sjwxtool status\n\n"
                "Uptime: %ud %uh %um %us\n\n"
                "cap_nr:%d \n"
                "enqeue_drop:%d \n"
                "enqeue_len:%d/%d \n\n"
                "send_sucess:%d \n"
                "send_failed:%d \n",
                days, hours, minutes, seconds,
                stat.cap_nr,
                stat.enqeue_drop,
                cmd_queue_len(cmd_queue), CMD_QUEUE_SIZE,
                stat.send_sucess,
                stat.send_failed);

    send_buff[*send_len] = 0;
    *send_len++;
    
    return 0;
}

#define PACKET_HEAD_MAGIC (0x8a85)

typedef enum PACKET_TYPE{
    PACKET_TYPE_NORMAL = 0x80,  /* 未压缩的普通数据包 */
}PACKET_TYPE_E;

int TcpSend(const char *msg, int needSend, int port)
{
    int i = 0;
    static int sock_cli = -1;

    /* 建立连接 */
    if (sock_cli == -1)
    {
        char host_ip[32];
        int ret = gethostIpbyname(CenterHost, host_ip, sizeof(host_ip));
        if (ret != 0)
        {
            printf("get host[%s] Ip failed.\n", CenterHost);
            return -1;
        }
    
        sock_cli = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_cli <= 0)
        {
            printf("alloc socket failed.\n");
            sock_cli = -1;
            return -1;
        }
    	struct sockaddr_in servaddr;
    	memset(&servaddr, 0, sizeof(servaddr));
    	servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(port);
    	servaddr.sin_addr.s_addr = inet_addr(host_ip);

        struct timeval timeout = {30,0}; //30s
        if (setsockopt(sock_cli,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout)) != 0
          || setsockopt(sock_cli,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout)) != 0)
        {
            printf("setsockopt failed.\n");
            close(sock_cli);
            sock_cli = -1;
            return -1;
        }

    	if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) == 0)
        {
            printf(" CenterHost%s:%d connect success ! \n", CenterHost, port);
    	}
        else
        {
            printf(" CenterHost%s:%d connect error ! \n", CenterHost, port);
            close(sock_cli);
            sock_cli = -1;
            return -1;
        }
    }

    /* 发送包头 */
    int len = 0;    
    unsigned char packHead[6];
    memset(packHead, 0, sizeof(packHead));

    packHead[0] = PACKET_HEAD_MAGIC & 0xff;
    packHead[1] = (PACKET_HEAD_MAGIC >> 8) & 0xff;
    packHead[2] = PACKET_TYPE_NORMAL;
    packHead[3] = needSend & 0xff;
    packHead[4] = (needSend >> 8) & 0xff;

    for (i = 0; i < 5; i++)
        packHead[5] += packHead[i];

    int pos = 0;
    while (pos < 6)
    {
        len = send(sock_cli, packHead + pos, 6 - pos, 0);
        if (len <= 0)
            goto sendError;

        pos += len;
    }

    /* 发送数据 */
    pos = 0;
	while (pos < needSend)
    {
		len = send(sock_cli, msg + pos, needSend - pos, 0);
		if (len <= 0)
            goto sendError;
        
		pos += len;
	}

    return 0;

sendError:
    printf("send failed.\n");
	close(sock_cli);
    sock_cli = -1;
	return -1;
}

void *send_thread(void *args)
{
    printf("send_thread start.\n");
    
    sigset_t signal_mask, oldmask;
    int rc, sig_caught;

    sigemptyset (&oldmask);
    sigemptyset (&signal_mask);
    sigaddset (&signal_mask, SIGUSR1);

    while(1)
    {
        while (cmd_queue_empty(cmd_queue) 
            || (__sync_val_compare_and_swap(&cmd_queue->cmd[cmd_queue_offset(cmd_queue->tail)].cmdStr, NULL, NULL) == NULL)) 
        {
            rc = sigwait (&signal_mask, &sig_caught);
            if (rc != 0) {
                printf("sigwait failed\n");
                pthread_exit(NULL);
            }
        }

        rc = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
        if (rc != 0) 
        {
            printf("SIG_SETMASK failed\n");
            pthread_exit(NULL);
        }

        while (!cmd_queue_empty(cmd_queue) 
            && (__sync_val_compare_and_swap(&cmd_queue->cmd[cmd_queue_offset(cmd_queue->tail)].cmdStr, NULL, NULL) != NULL)) 
        {
            char *sendStr = cmd_queue->cmd[cmd_queue_offset(cmd_queue->tail)].cmdStr;
            int len = cmd_queue->cmd[cmd_queue_offset(cmd_queue->tail)].len;
            int ret = TcpSend(sendStr, len, DataPort);
            if (ret == 0)
            {
                free(cmd_queue->cmd[cmd_queue_offset(cmd_queue->tail)].cmdStr);
                cmd_queue->cmd[cmd_queue_offset(cmd_queue->tail)].cmdStr = NULL;
                cmd_queue->cmd[cmd_queue_offset(cmd_queue->tail)].len = 0;
                __sync_fetch_and_add(&cmd_queue->tail, 1);
                stat.send_sucess++;
            }
            else
            {
                stat.send_failed++;
                sleep(10);
            }
        }
    }
}

