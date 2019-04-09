/*
2016-6-29 区分联想板的配置文件读取，
适用于多种环境的校时，在线，本机外网ip发送。
2016-11-09，不再区分不同的上线端口，所有心跳端口都改成18090。
2017-10-2 上线机制升级。

*/
# include<stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netinet/in.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include "sjwx.h"

char Vers[64]="Unkonw";
char DevType[64]="Unkonw";

void ReadDev()
{
	FILE *fp;	
	int len;
	char buff[512];
	if ((fp=fopen("/etc/openwrt_release","r")))
	{	
		printf("open openwrt_release!\n");
		len = fread(buff, 1, sizeof(buff), fp);
        fclose(fp);
	}
	else
	{
		printf("Error in open /etc/openwrt_release !\n");
		
	}

    printf("len[%d]\n", len);
    
    if (len <= 0)
    {
        printf("invalid len.\n");
        return;
    }

    int i = 0;
    while((memcmp(buff + i, "DISTRIB_REVISION", sizeof("DISTRIB_REVISION") - 1) != 0)
        && (i < len - sizeof("DISTRIB_REVISION") - 1))
    {
        i++;
    }
	
	if(i < len - sizeof("DISTRIB_REVISION") - 1)
	{
		sscanf(buff + i, "DISTRIB_REVISION=\"%s\"", DevType);
	}
	printf("Vers:[%s]\n", DevType);
}

void ReadVer()
{
	FILE *fp;	
	int len;
	char buff[512];
	if ((fp=fopen("/etc/openwrt_release","r")))
	{	
		printf("open openwrt_release!\n");
		len = fread(buff, 1, sizeof(buff), fp);
        fclose(fp);
	}
	else
	{
		printf("Error in open /etc/openwrt_release !\n");
		
	}

    printf("len[%d]\n", len);
    
    if (len <= 0)
    {
        printf("invalid len.\n");
        return;
    }

    int i = 0;
    while((memcmp(buff + i, "DISTRIB_DESCRIPTION", sizeof("DISTRIB_DESCRIPTION") - 1) != 0)
        && (i < len - sizeof("DISTRIB_DESCRIPTION") - 1))
    {
        i++;
    }
	
	if(i < len - sizeof("DISTRIB_DESCRIPTION") - 1)
	{
		sscanf(buff + i, "DISTRIB_DESCRIPTION=\"%s\"", Vers);
	}
	printf("Vers:[%s]\n", Vers);
}

void SendOnline()
{
    char Msg[10240];
    memset(Msg, 0, sizeof(Msg));
    
    char tstamp[11] = {'\0'};
	char timenow[30]= {'\0'};
	make_time_str(timenow);
	
	snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO unit VALUES ('0','%s','',null,'%s','1','%s');",UnitCode,timenow, timeStamp(tstamp));
	APIPost(Msg,strlen(Msg),"/v1");
}

void SendOperate()
{
    char Msg[10240];
    memset(Msg, 0, sizeof(Msg));
    
    char tstamp[11] = {'\0'};
	char timenow[30]= {'\0'};
	make_time_str(timenow);
	
	snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO unitoperate VALUES ('0','%s','%s','%s','%s','%s','','%s');",UnitCode,APid,DevType,Vers,timenow, timeStamp(tstamp));
	APIPost(Msg,strlen(Msg),"/v3");
}

void *sjwxcomm_main(void *args)
{
    printf("sjwxcomm_main start.\n");
    
	ReadDev();
    ReadVer();
    
	time_t tt1 = 0;
	int online=11;
    
	while(1)
    {
		if(time( NULL ) - tt1 >= 300) 
        {   
			tt1=time( NULL );

            /* 每5分钟发送一次心跳，表明设备还在线*/
            SendOnline();
            
            /* 每50分钟发送一下本机外网ip */
			if (online++ > 10)
			{
				online = 0;
				SendOperate();
			}
		}
		
		sleep(5);
	}
	return NULL;
}