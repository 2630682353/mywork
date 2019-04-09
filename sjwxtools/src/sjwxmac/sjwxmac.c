//Mac 18090收集版本2016-4-9修改 
//多系统版本使用。2016-10-30
// Mac地址收集优化。2017-06-20
//上传升级 2017-08-21
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <byteswap.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <getopt.h>
#include <netdb.h>
#include "sjwxmac.h"
#include "sjwx.h"

uint8_t run_stop   = 0;
uint8_t run_daemon = 0;

uint32_t frames_captured = 0;
uint32_t frames_filtered = 0;

 const unsigned char llcnull[4] = {0, 0, 0, 0};

int capture_sock = -1;
const char *ifname = NULL;

struct AP_info *ap_1st = NULL;
struct ST_info *st_1st = NULL;
struct ST_info *na_1st = NULL;

void showmsg(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (run_daemon)
		vsyslog(LOG_INFO | LOG_USER, fmt, ap);
	else
		vfprintf(stderr, fmt, ap);

	va_end(ap);
}

int check_type(void)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(capture_sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;

	return (ifr.ifr_hwaddr.sa_family == ARPHRD_IEEE80211_RADIOTAP);
}

void sig_teardown(int sig)
{
	run_stop = 1;
}
 
void SendMac( struct ST_info *st_cur, int online)
{
    char Msg[2048];
    memset(Msg, 0, sizeof(Msg));

	char smac[18];
	memset(smac,'\0',18);

	snprintf(smac,18,"%s",st_cur->stmac);
	
	if((strstr(smac,"FF-FF")==NULL)&&(strstr(smac,"00-00-00")==NULL) )
	{
		
		char ssid[256],apmac[18];
		memset(ssid,'\0',256);
		memset(apmac,'\0',18);		
		if(st_cur->base!=NULL)
		{			
			snprintf(apmac,18,"%02X-%02X-%02X-%02X-%02X-%02X",st_cur->base->bssid[0],st_cur->base->bssid[1],st_cur->base->bssid[2],st_cur->base->bssid[3],st_cur->base->bssid[4],st_cur->base->bssid[5]);
			snprintf(ssid,256,"%s",st_cur->base->essid);
		}
		
		char stime[30]={'\0'};
		char ltime[30]={'\0'};		
		fill_time_str(stime,st_cur->tinit);
		fill_time_str(ltime,st_cur->tlast);
        char tstamp[11] = {'\0'};

        if (online == 1)
        {
            snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO apclient VALUES('0','%s','%s','%s','%s',NULL,'%s.%s.%s','%s',null,'','%d','%s','','','','','%s');",
                     smac,ssid,apmac,stime,st_cur->probes[0],st_cur->probes[1],st_cur->probes[2],UnitCode,st_cur->power,APid, timeStamp(tstamp)); 
        }
        else
        {
    		snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO apclient VALUES('0','%s','%s','%s','%s','%s','%s.%s.%s','%s',null,'','%d','%s','','','','','%s');",
                     smac,ssid,apmac,stime,ltime,st_cur->probes[0],st_cur->probes[1],st_cur->probes[2],UnitCode,st_cur->power,APid, timeStamp(tstamp)); 
        }
		
		APIPost(Msg, strlen(Msg), "/v1");
	}
}

void SendAP( struct AP_info *ap_cur, int online)
{
    char Msg[2048];
    memset(Msg, 0, sizeof(Msg));
    
	if(strstr(ap_cur->bssid,"FF-FF-FF")==NULL)
	{
		char strbuf[6] = {'\0'};
		char stime[30]={'\0'};
		char ltime[30]={'\0'};		
		fill_time_str(stime,ap_cur->tinit);
		fill_time_str(ltime,ap_cur->tlast);
        char tstamp[11] = {'\0'};

        if (online == 1)
        {
            snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO ssid VALUES ('0','%s','%s','%d','%d','%s','%s',NULL,'%s',null,'%s','%s','%s','','%s');",
                ap_cur->bssid,ap_cur->essid,ap_cur->channel,ap_cur->avg_power,strbuf,stime,UnitCode,APid,longde,latde, timeStamp(tstamp));

        }
        else
        {
            snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO ssid VALUES ('0','%s','%s','%d','%d','%s','%s','%s','%s',null,'%s','%s','%s','','%s');",
                ap_cur->bssid,ap_cur->essid,ap_cur->channel,ap_cur->avg_power,strbuf,stime,ltime,UnitCode,APid,longde,latde, timeStamp(tstamp));
        }
        
        APIPost(Msg,strlen(Msg),"/v1");	
	}
}

void ApClientSend(void)
{
	int timeout =310;
	
	struct ST_info *st_cur = NULL;
    struct ST_info *st_prv = NULL;
	struct ST_info *st_next = NULL;
	
	st_cur = st_1st;
	 
	while( st_cur != NULL )
    {
		st_next =st_cur->next;
		if(time( NULL ) - st_cur->tlast >= timeout)
		{	
			//修改为离开以后才上传
			SendMac(st_cur, 0);
			
			if(st_cur == st_1st)
			{
				st_prv=st_1st = st_next;
			}
			else
			{
				st_prv->next = st_next;
				
			}
			free(st_cur);
		}
		else
		{			
			st_prv = st_cur;
		}
		st_cur = st_next;
    }
}

void ApHotSend(void)
{
	int timeout =310;
	
	struct AP_info *ap_cur = NULL;
    struct AP_info *ap_prv = NULL;
	struct AP_info *ap_next = NULL;
	
	ap_cur = ap_1st;
	 
	while( ap_cur != NULL )
    {
		ap_next =ap_cur->next;
        
		if (time( NULL ) - ap_cur->tlast >= timeout)
		{	
			//修改为离开以后才上传
			SendAP(ap_cur, 0);
			
			if (ap_cur == ap_1st)
			{
				ap_prv = ap_1st = ap_next;
			}
			else
			{
				ap_prv->next = ap_next;
				
			}
			free(ap_cur);
		}
		else
		{			
			ap_prv = ap_cur;
		}
		ap_cur = ap_next;
    }
}

static int stringIsValid(unsigned char *str)
{
    while (*str != 0)
    {
        if (*str >= 0x20 && *str <= 0x7e)
        {
            str++;
            continue;
        }

        if (((*str & 0xf0) == 0xe0)
            && ((*(str + 1) & 0xc0) == 0x80)
            && ((*(str + 2) & 0xc0) == 0x80))
        {
            unsigned short code = (((unsigned short)*str & 0x0f) << 12)
                                | (((unsigned short)*(str + 1) & 0x3f) << 6)
                                | (((unsigned short)*(str + 2) & 0x3f) << 0);
//            printf("code[%0x]\n", code);
            if (code >= (unsigned short)0x4E00 && code <= (unsigned short)0x9FBF)
            {
                /* 是utf8中文 */
                str += 3;
                continue;
            }
        }

        /* 处理乱码 */
        *str = 0;
        return 0;
    }

    return 1;
}

typedef struct _char {
    char *pos;
    char value;
}char_t;

static void addSlant(char *str)
{
    int i = 0;
    int j = 0;
    int len = 0;
    char_t char_value[20];
    char buff[256];
    char *p = str;

    memset(char_value , 0, sizeof(char_value));
    while (*p != 0)
    {
        if (*p == '\'' || *p == '\"' || *p == '\\')
        {
            char_value[i].pos = p;
            char_value[i].value = *p;
            *p = 0;
            i++;
        }
        p++;
    }

    len = 0;
    snprintf(buff + len, sizeof(buff) - len - 1, "%s", str);
    len = strlen(buff);
    for (j = 0; j < i; j++)
    {
        buff[len++] = '\\';
        buff[len++] = char_value[j].value;
        snprintf(buff + len, sizeof(buff) - len - 1, "%s", char_value[j].pos + 1);
        len = strlen(buff);
    }

    memcpy(str, buff, len + 1);
}

void mysql_format(char *str)
{
    /* 去掉乱码，即:发现乱码就截断字符串 */
    stringIsValid((unsigned char *)str);

    /* 转义字符添加 \ */
    addSlant(str);
}

int ap_add_packet( unsigned char *pktbuf, int len)
{
    int i, n,offset, power=-1;
    int type, length, numuni=0, numauth=0;
    char *str = NULL;

    unsigned char *p = pktbuf;

    struct AP_info *ap_new = NULL;
    struct AP_info *ap_cur = NULL;
    struct AP_info *ap_prv = NULL;

    while (p < pktbuf + len)
    {
        str = p;
        while((*p != '\n') && (p < pktbuf + len))
        {
            p++;
        }
        if (p < pktbuf + len)
        {
            *p++ = 0;
        }

        if( ! ( ap_new = (struct AP_info *) malloc(
                         sizeof( struct AP_info ) ) ) )
        {
            perror( "malloc failed." );
            return( 1 );
        }
        memset( ap_new, 0, sizeof( struct AP_info ) );

//        printf("--------------get apMac[%s]\n", str);

        sscanf(str, "apMac:%s channel:%d power:%d ssid:%[^\n]", 
                ap_new->bssid, &(ap_new->channel), &(ap_new->avg_power), ap_new->essid);

        /* 格式化essid */
        mysql_format(ap_new->essid);

        ap_new->bssid[17] = 0;

        if (strlen(ap_new->bssid) != 17
            || ap_new->bssid[2] != '-'
            || ap_new->bssid[5] != '-'
            || ap_new->bssid[8] != '-'
            || ap_new->bssid[11] != '-'
            || ap_new->bssid[14] != '-')
        {
            free(ap_new);
            return -1;
        }

//        printf("apMac:%s channel:%d power:%d ssid:%s\n", 
//                ap_new->bssid, ap_new->channel, ap_new->avg_power, ap_new->essid);

        /* 查找是否已在链表中 */
        ap_cur = ap_1st;
        ap_prv = NULL;

        while( ap_cur != NULL )
        {
            if( ! memcmp( ap_cur->bssid, ap_new->bssid, 17 ) )
                break;

            ap_prv = ap_cur;
            ap_cur = ap_cur->next;
        }

        /* if it's a new client, add it */
        if( ap_cur == NULL )
        {
            ap_cur = ap_new;
            
            if( ap_1st == NULL )
                ap_1st = ap_cur;
            else
                ap_prv->next  = ap_cur;

            ap_cur->prev = ap_prv;
            ap_cur->tinit = time( NULL );
            ap_cur->tlast = time( NULL );

        	SendAP(ap_cur, 1);
        }
        else
        {
            free(ap_new);
            
            /* update the last time seen */
            ap_cur->tlast = time( NULL );
        }
    }	

    return 0;
}

int dump_add_packet( unsigned char *pktbuf, int len)
{
    int i, n,offset, power=-1;
    int type, length, numuni=0, numauth=0;

    unsigned char *p = pktbuf;

    p[17] = 0;

    if (strlen(p) != 17
        || p[2] != '-'
        || p[5] != '-'
        || p[8] != '-'
        || p[11] != '-'
        || p[14] != '-')
    {
        return -1;
    }

    struct ST_info *st_cur = NULL;
    struct ST_info *st_prv = NULL;

    while (p < pktbuf + len)
    {
        st_cur = st_1st;
        st_prv = NULL;

        while( st_cur != NULL )
        {
            if( ! memcmp( st_cur->stmac, p, 17 ) )
                break;

            st_prv = st_cur;
            st_cur = st_cur->next;
        }

        /* if it's a new client, add it */
        if( st_cur == NULL )
        {
            if( ! ( st_cur = (struct ST_info *) malloc(
                             sizeof( struct ST_info ) ) ) )
            {
                perror( "malloc failed" );
                return( 1 );
            }

            memset( st_cur, 0, sizeof( struct ST_info ) );

            if( st_1st == NULL )
                st_1st = st_cur;
            else
                st_prv->next  = st_cur;

            memcpy(st_cur->stmac, p, 17);
            st_cur->stmac[17] = 0;

            st_cur->base = NULL;
            st_cur->prev = st_prv;
            st_cur->tinit = time( NULL );
            st_cur->tlast = time( NULL );
            power = -50 - (1.0 * rand() / RAND_MAX * 30);
            st_cur->power = power;
        	st_cur->probe_index = -1;
            for( i = 0; i < NB_PRB; i++ )
            {
                memset( st_cur->probes[i], 0, sizeof(
                        st_cur->probes[i] ) );          
            }
        	SendMac(st_cur, 1);
        }

        /* update the last time seen */
        st_cur->tlast = time( NULL );

        p += 18;
    }	

    return 0;
}

#define MACLIST_PROC_ENTRY "/proc/maclist_root/maclist_entry"
#define APLIST_PROC_ENTRY "/proc/aplist_root/aplist_entry"

void *sjwxmac_main(void *args)
{
	uint8_t pktbuf[0xFFFF];
    int pktlen;
	ssize_t macNumber;
    time_t tt1 = time(NULL);

    printf("sjwxmac_main start.\n");

	while (1)
	{
	    sleep(5);

        FILE *pf = fopen(MACLIST_PROC_ENTRY, "r+");
        if (pf == NULL)
        {
            showmsg("open %s failed.\n", MACLIST_PROC_ENTRY);
    		printf("open /proc/maclist_root/maclist_entry failed.\n");
            return NULL;
        }

        /* 先对proc节点写入字符's'，然后才能读取数据 */
        fseek(pf, 0, SEEK_SET);
        fwrite("s", 1, 1, pf);

        /* 每个mac长度为18bytes，例如11:22:33:44:55:66 */
        fseek(pf, 0, SEEK_SET);
        macNumber = fread(pktbuf, 18, 64, pf);
        fclose(pf);
        if (macNumber > 0)
        {
            dump_add_packet( pktbuf, macNumber * 18);
        }
	printf("xxxxxxxxxxxxxxxxxxxx\n");
        pf = fopen(APLIST_PROC_ENTRY, "r+");
        if (pf == NULL)
        {
            showmsg("open %s failed.\n", APLIST_PROC_ENTRY);
		printf("open /proc/aplist_root failed.\n");
            return NULL;
        }

        /* 先对proc节点写入字符's'，然后才能读取数据 */
        fseek(pf, 0, SEEK_SET);
        fwrite("s", 1, 1, pf);

        /* 每个mac长度为18bytes，例如11:22:33:44:55:66 */
        fseek(pf, 0, SEEK_SET);
        pktlen = fread(pktbuf, 1, sizeof(pktbuf), pf);
        fclose(pf);
        if (pktlen > 0)
        {
            ap_add_packet( pktbuf, pktlen);
        }

		if (time( NULL ) - tt1 >= 300)
        {
			tt1 = time( NULL );
			showmsg("tt1 run  ...\n");	
			ApClientSend();
            ApHotSend();
		}
	}
}
