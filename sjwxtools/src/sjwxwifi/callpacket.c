/*************************************
 *
 *************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <syslog.h>
#include <pthread.h>
#include <semaphore.h>
#include <memory.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "callpacket.h"
#include <ctype.h>
#include <netdb.h> 
#include "sjwx.h"

// 短整型大小端互换
#define BigLittleSwap16(A)  ((((UINT2)(A) & 0xff00) >> 8) | \
                            (((UINT2)(A) & 0x00ff) << 8))
 // 长整型大小端互换
 
  // 本机大端返回1，小端返回0
int checkCPUendian()
{
       union{
              unsigned long int i;
              unsigned char s[4];
       }c;
 
       c.i = 0x12345678;
       return (0x12 == c.s[0]);
}
unsigned short int t_ntohs(unsigned short int n)
{
       // 若本机为大端，与网络字节序同，直接返回
       // 若本机为小端，网络数据转换成小端再返回
       return checkCPUendian() ? n : BigLittleSwap16(n);
}
unsigned short int t_htons(unsigned short int h)
{
       // 若本机为大端，与?缱纸谛蛲苯臃祷?
       // 若本机为小端，转换成大端再返回
       return checkCPUendian() ? h : BigLittleSwap16(h);
}



#define BUFF_SIZE 2048
struct Client_info * Client_cur = NULL;
struct Mac_link* MAChead=NULL;

char * Add_Mac_link(struct Client_info  * clinet_cur);


///////////////////////////////////////////////
//获取mysql入库时间
char *make_mysqltime_str(char *time_str)
{
    struct tm tm;
    time_t time_now = time(0);
    localtime_r(&time_now, &tm);
    sprintf(time_str,"%4d-%02d-%02dT%02d:%02d:%02d+00:00", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);
    return time_str;
}
char * fill_mysqltime_str(char *time_str, time_t time_now )
{
    struct tm tm;
    localtime_r(&time_now, &tm);

    sprintf(time_str,"%4d-%02d-%02dT%02d:%02d:%02d+00:00", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);
    
    return time_str;
}
char *make_time_str(char *time_str)
{

    struct tm tm;
    time_t time_now = time(0);

    localtime_r(&time_now, &tm);
    sprintf(time_str,"%4d-%02d-%02d %02d:%02d:%02d", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);

    return time_str;

}
char * fill_time_str(char *time_str, time_t time_now )
{
    struct tm tm;
    localtime_r(&time_now, &tm);
    sprintf(time_str,"%4d-%02d-%02d %02d:%02d:%02d", 1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday,tm.tm_hour,tm.tm_min, tm.tm_sec);
    
    return time_str;
}
//当前时间戳
char* timeStamp(char* timestamp){
	time_t t;
	t=time(0);
	sprintf(timestamp,"%d",t);
	return timestamp;
}

//兆物、网盈区分登录身份类型（返回对应编码）
char* fill_logintype(char* cType,char * IdType){

	strcpy(IdType,cType);
	
	if (!strcmp(cType,"WeiXin")){//微信
		memset(IdType,'\0',5);
		strcpy(IdType,"1030036");
	}
	else if (!strcmp(cType,"QQ")){
		memset(IdType,'\0',5);
		strcpy(IdType,"1030001");
	}
	//购物类
	else if (!strcmp(cType,"TaoBao")){//淘宝网
		memset(IdType,'\0',5);
		strcpy(IdType,"1220007");
	}

	
	return IdType;
}

void APIPost(char *msg, int needSend, char *cmd)
{
    //printf("\n%s\n", msg);
    
#if 1
    process_data(msg, needSend);
#else
	char  m[10240];

	int blen = strlen(msg);
	snprintf(m,10240,"POST %s HTTP/1.1\r\nHost: %s:%d\r\nAccept: application/json*/*\r\nContent-Type: application/json\r\nContent-Length:%d\r\n\r\n%s",cmd,CenterHost,DataPort,blen,msg);//去掉ip tcp头的长度

	int len = strlen(m);
	TcpSend(m,len,DataPort);
#endif
}

//***************数据整理发送***************//
//上线事件
void SendMacOnline(struct Mac_link *na_cur)
{
    char Msg[10240];
    memset(Msg, 0, sizeof(Msg));
	
	char tstamp[11] = {'\0'};
	char mysqltime[30] = {'\0'};
	fill_time_str(mysqltime,na_cur->onlinetime);
    
    snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO jz_clientlog VALUES ('0','%s','%s','%s','%s','%s','%s',%s,'%s','%s','%s','%s','%s');",
        UnitCode,
        na_cur->mac,
        na_cur->dmac,
        na_cur->lan_ip,
        na_cur->sessionid,
        mysqltime,
        "NULL",   
        na_cur->mac,          
        APid,
        longde,
        latde,
        timeStamp(tstamp));
		
	APIPost(Msg, strlen(Msg), "/v2");
}

void SendNetidOnline(struct Mac_link *na_cur,struct NetID_link *netid_cur, char *Format)
{
    char Msg[10240];
    memset(Msg, 0, sizeof(Msg));

	char tstamp[11] = {'\0'};
	char mysqltime[30] = {'\0'};
	fill_time_str(mysqltime,netid_cur->eventtime);
	char idtype[64] = {'\0'};
	fill_logintype(netid_cur->idtype,idtype);
	
	snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO jz_netidlog VALUES ('0','%s','%s','%s','%s','','%s','%s',%s,'%s','%s','%s','','%s','%s','%s','1','','%s','%s','');",
        UnitCode,
        na_cur->mac,
        na_cur->dmac,
        na_cur->lan_ip,
        na_cur->sessionid,
        mysqltime,
        "NULL",
        netid_cur->loginid,
        idtype,
        "",
        APid,
        longde,
        latde,
        Format,
        timeStamp(tstamp));
    
	APIPost(Msg, strlen(Msg), "/v2");
}

void SendUrllog(struct Client_info *Client_cur,char *host,char *uri,char *type)
{
    char Msg[10240];
    memset(Msg, 0, sizeof(Msg));

	char tstamp[11] = {'\0'};
	char mysqltime[30] = {'\0'};	
	make_time_str(mysqltime);

	snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO jz_httplog VALUES ('0','%s','%s','%s','','%s','%s','%s','%s','http://%s%s ','%s','%s','%s','','','','','','','','','','','','','%s','');",
        Client_cur->smac,
        Client_cur->dmac,
        APid,
        Client_cur->sip,
        Client_cur->dip,
        mysqltime,
        host,
        host,
        uri,
        type,
        UnitCode,
        Add_Mac_link(Client_cur),
        timeStamp(tstamp));   
	APIPost(Msg, strlen(Msg), "/v2");	
}

//下线事件
void SendMacOffline(struct Mac_link *na_cur)
{
    char Msg[10240];
    memset(Msg, 0, sizeof(Msg));

    char tstamp[11] = {'\0'};

	char mysqltime[50] = {'\0'};	
	fill_time_str(mysqltime,na_cur->onlinetime);
	char mysqltimenow[50] = {'\0'};	
	fill_time_str(mysqltimenow,na_cur->lasttime);
	
    snprintf(Msg, sizeof(Msg) - 1,"INSERT INTO jz_clientlog VALUES ('0','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s');",
        UnitCode,
        na_cur->mac,
        na_cur->dmac,
        na_cur->lan_ip,
        na_cur->sessionid,
        mysqltime,
        mysqltimenow,   
        na_cur->mac,          
        APid,
        longde,
        latde,
        timeStamp(tstamp));
	
	APIPost(Msg, strlen(Msg), "/v2");
}

//***************数据整理结束***************//

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

//***************虚拟身份链表处理***************//
/*虚拟身份链表处理*/
////
void FreeNetID(struct NetID_link *pBhead){
	struct NetID_link * st_cur = pBhead;
    struct NetID_link * st_next= NULL;

    while(st_cur != NULL)
    {
        st_next = st_cur->next;
	     free(st_cur);
        st_cur = st_next;
    }
}
//增加节点 虚拟身份集合
void add_NetID(struct Mac_link * na_cur, char *Type, char * Netid, char *Format){
	
	struct NetID_link * link_cur = na_cur->phead;
    struct NetID_link * link_prv = NULL;
	
    while( link_cur != NULL )
    {
		//遍历链表
		//printf("****MAC :  %s\nonlinetime : %s\nofflinetime : %s\nip : %s\nsessionid : %s\n",link_cur->loginid,link_cur->idtype,link_cur->eventtime,link_cur->nickname,link_cur->offlinetime);
        
		if(!strcmp(link_cur->loginid,Netid)&&!strcmp(link_cur->idtype,Type))
		{
			
            return;
		}
		
        link_prv = link_cur;
        link_cur = link_cur->next;
    }

    /* if it's a new mac, add it */
	
    if( link_cur == NULL )
    {
        if( ! ( link_cur = (struct NetID_link *) malloc(
                         sizeof( struct NetID_link ) ) ) )
        {
            perror( "malloc failed" );
            return;
        }

		memset(link_cur,'\0',sizeof(struct NetID_link));
		
//		char linetime[30];
//		memset(linetime,'\0',30);
//		make_mysqltime_str(linetime);//当前时间
	
		
		
		strcpy(link_cur->loginid,Netid);//登录ID
		strcpy(link_cur->idtype,Type);//登录ID类型
		link_cur->eventtime = time( NULL );//事件时间
		
		
        if( na_cur->phead == NULL )
            na_cur->phead = link_cur;
        else
            link_prv->next  = link_cur;
		SendNetidOnline(na_cur,link_cur,Format);
	}
    
	return ;
	
}
//***************虚拟身份链表结束***************//

//***************MAC链表处理开始***************//
//删除节点
void Free_Mac_link(struct Mac_link * na_cur){
	FreeNetID(na_cur->phead);
	free(na_cur);
}
//超时下线机制
int Timeout_Mac_link(){
	struct Mac_link *na_cur = NULL;
    struct Mac_link *na_prv = NULL;
	struct Mac_link *na_next = NULL;


    na_cur = MAChead;
	
	
    while( na_cur != NULL )
    {				
		if(time( NULL ) - na_cur->lasttime >OutTime)//修改判断条件
		{
			na_next=na_cur->next;
			if(na_cur == MAChead)
			{
				MAChead = na_cur->next;
			}
			else
			{
				na_prv->next = na_cur->next;
			}
		
			//启动下线事件
			SendMacOffline(na_cur);
			
			//释放内存
			Free_Mac_link(na_cur);	
			na_cur = na_next;			
       
		}else
		{
			na_prv = na_cur;
			na_cur = na_cur->next;
		}
	
		
		
		
    }
	
	

    return 0;
	
}
//增加MAC节点
char * Add_Mac_link(struct Client_info * clinet_cur){
	

	
	struct Mac_link * Mac_link_cur = MAChead;
    struct Mac_link * Mac_link_prv = NULL;
	
    while( Mac_link_cur != NULL )
    {
		
		if(!strcmp(Mac_link_cur->mac,clinet_cur->smac))
		{
			Mac_link_cur->lasttime=time( NULL );
			return Mac_link_cur->sessionid;
		}
		
        Mac_link_prv = Mac_link_cur;
        Mac_link_cur = Mac_link_cur->next;
    }

    /* if it's a new mac, add it */
	char sessionid[64];//会话ID
	memset(sessionid,'\0',64);
    if( Mac_link_cur == NULL )
    {
        if( ! ( Mac_link_cur = (struct Mac_link *) malloc( sizeof(struct Mac_link ) ) ) )
        {
            perror( "malloc failed" );
            return "";
        }
		
		memset(Mac_link_cur,'\0',sizeof(struct Mac_link));
		
		char smac[20] = {'\0'};//MAC（无 ：）
		memset(smac,'\0',20);
		int n=0,b=0;
		while(n<20)
		{
			if(clinet_cur->smac[n]!='-')
			{
				smac[b]=clinet_cur->smac[n];
				b++;
			}
			n++;
		}
		
	
		
		char timestamp[20] = {'\0'}; //时间戳
		memset(timestamp,'\0',20);
		timeStamp(timestamp);//获取当前时间戳

        sprintf(sessionid,"%s%s%s",UnitCode,smac,timestamp);

        strcpy(Mac_link_cur->mac,clinet_cur->smac);//终端设备MAC
        strcpy(Mac_link_cur->dmac,clinet_cur->dmac);//路由mac
        Mac_link_cur->onlinetime = time( NULL );
        Mac_link_cur->lasttime = time( NULL );		
        strcpy(Mac_link_cur->lan_ip,clinet_cur->sip);//内网IP地址
        strcpy(Mac_link_cur->sessionid,sessionid);

        if(MAChead == NULL)
        { 
            MAChead = Mac_link_cur;
        }
        else
        {
            Mac_link_prv->next = Mac_link_cur;
        }
        
		SendMacOnline(Mac_link_cur);
	}
	
	
	return Mac_link_cur->sessionid;
	
}
int IMEIfilter(char * Netid){
	if(strlen(Netid)<6)
	{
		return 0;
	}
	if(Netid[0]>48&&Netid[0]<58&&Netid[2]>47&&Netid[2]<58&&Netid[4]>47&&Netid[4]<58&&Netid[5]>47&&Netid[5]<58)
	{
		return 0;
	}
	return 1;
}
int Add_Netid_link(struct Client_info *clinet_cur, char *Type, char *Netid, char *Format)
{
	if (!strcmp(Type,"IMEI")||!strcmp(Type,"IMSI")){
		if(IMEIfilter(Netid)){
			return 0;
		}
	}
	
	struct Mac_link * Mac_link_cur = MAChead;
	struct Mac_link * Mac_link_prv = NULL;
	
	while( Mac_link_cur != NULL ){

		if(!strcmp(Mac_link_cur->mac,clinet_cur->smac)){
			Mac_link_cur->lasttime=time( NULL );
			//增加虚拟身份节点；
			if(Netid!=NULL){
				add_NetID(Mac_link_cur, Type,Netid,Format);
			}
			return 1;
		}
        Mac_link_prv = Mac_link_cur;
        Mac_link_cur = Mac_link_cur->next;
    }

    /* if it's a new mac, add it */
	char sessionid[64];//会话ID
	memset(sessionid,'\0',64);
	if( Mac_link_cur == NULL ){
		if( ! ( Mac_link_cur = (struct Mac_link *) malloc( sizeof(struct Mac_link ) ) ) ){
            perror( "malloc failed" );
            return 0;
        }
		memset(Mac_link_cur,'\0',sizeof(struct Mac_link));
		char smac[20] = {'\0'};//MAC（无 ：）
		memset(smac,'\0',20);
		int n=0,b=0;
		while(n<20){
			if(clinet_cur->smac[n]!='-'){
				smac[b]=clinet_cur->smac[n];
				b++;
			}
			n++;
		}
		char timestamp[20] = {'\0'}; //时间戳
		memset(timestamp,'\0',20);
		timeStamp(timestamp);//获取当前时间戳
		sprintf(sessionid,"%s%s%s",UnitCode,smac,timestamp);
		strcpy(Mac_link_cur->mac,clinet_cur->smac);//终端设备MAC	
		strcpy(Mac_link_cur->dmac,clinet_cur->dmac);//路由mac
		Mac_link_cur->onlinetime = time( NULL );
        Mac_link_cur->lasttime = time( NULL );		
		strcpy(Mac_link_cur->lan_ip,clinet_cur->sip);//内网IP地址
		strcpy(Mac_link_cur->sessionid,sessionid);
		SendMacOnline(Mac_link_cur);
		//增加虚拟身份节点；
		if(Netid!=NULL){
			add_NetID(Mac_link_cur, Type,Netid,Format);
		}
        if( MAChead == NULL ){
            MAChead = Mac_link_cur;
		}
        else{
            Mac_link_prv->next = Mac_link_cur;
		}
	}
	return 1;
}
int Add_Netid_RElink(struct Client_info *clinet_cur, char *Type, char *Netid, char *Format){
	
	if (!strcmp(Type,"IMEI")||!strcmp(Type,"IMSI")){		
		if(IMEIfilter(Netid))
		{
			return 0;
		}
	}

	struct Mac_link * Mac_link_cur = MAChead;
    struct Mac_link * Mac_link_prv = NULL;
	
    while( Mac_link_cur != NULL )
    {
		
		if(!strcmp(Mac_link_cur->mac,clinet_cur->dmac))
		{
			Mac_link_cur->lasttime=time( NULL );
			//增加虚拟身份节点；
			if(Netid!=NULL)
			{
				add_NetID(Mac_link_cur, Type,Netid,Format);
			}
			
			return 1;
		}
		
        Mac_link_prv = Mac_link_cur;
        Mac_link_cur = Mac_link_cur->next;
    }

    /* if it's a new mac, add it */
	char sessionid[64];//会话ID
	memset(sessionid,'\0',64);
    if( Mac_link_cur == NULL )
    {
        if( ! ( Mac_link_cur = (struct Mac_link *) malloc( sizeof(struct Mac_link ) ) ) )
        {
            perror( "malloc failed" );
            return 0;
        }

		memset(Mac_link_cur,'\0',sizeof(struct Mac_link));
		
		char smac[20] = {'\0'};//MAC（无 ：）
		memset(smac,'\0',20);
		int n=0,b=0;
		while(n<20)
		{
			if(clinet_cur->dmac[n]!='-')
			{
				smac[b]=clinet_cur->dmac[n];
				b++;
			}
			n++;
		}
		


		
		char timestamp[20] = {'\0'}; //时间戳
		memset(timestamp,'\0',20);
		timeStamp(timestamp);//获取当前时间戳
		sprintf(sessionid,"%s%s%s",UnitCode,smac,timestamp);
		strcpy(Mac_link_cur->mac,clinet_cur->dmac);//终端设备MAC
		strcpy(Mac_link_cur->dmac,clinet_cur->dmac);//路由mac		
		Mac_link_cur->onlinetime = time( NULL );
        Mac_link_cur->lasttime = time( NULL );		
        strcpy(Mac_link_cur->lan_ip,clinet_cur->dip);//内网IP地址
        strcpy(Mac_link_cur->sessionid,sessionid);		
		SendMacOnline(Mac_link_cur);
		
		//增加虚拟身份节点；
		if(Netid!=NULL)
		{
			//strcpy(Mac_link_cur->dmac,clinet_cur->dmac);//路由mac
			add_NetID(Mac_link_cur, Type,Netid,Format);
		}
	
        if( MAChead == NULL )
            MAChead = Mac_link_cur;
        else
            Mac_link_prv->next  = Mac_link_cur;
	}
	
	return 1;
	
}

//***************MAC链表处理结束***************//

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

//  以太包
typedef struct ether { 
	UINT1 dest[6];  //目标MAC
	UINT1 src[6];	//源MAC 		
	UINT2 proto;  	//协议类型
	UINT1 data[0];  //包含数据
} tEther; 
//  IP包
typedef struct iip { 
	UINT1 hlen; 	//首部长度+版本 
	UINT1 tos;   	//服务 
	UINT2 len;   	//总长度 
	UINT2 ipid;   	//标示  
	UINT2 flagoff;  //标示加偏移  
	UINT1 ttl;   	//生存时间  
	UINT1 proto;   	//协议  
	UINT2 cksum;   	//首部检验和 
	UINT4 src;   	//源IP地址 
	UINT4 dest;   	//目地IP地址  
	UINT1 data[0];  //包含数据
} tIp; 
//  TCP包
typedef struct tcp { 
	UINT2 sport; 	//源端口
	UINT2 dport; 	//目标端口
	UINT4 seq; 		//序列号
	UINT4 ack; 		//确认序列号
	char hlen; 		//包长度
	UINT1 code; 	//代码
	UINT2 window; 	//滑动窗口大小
	UINT2 chsum; 	//检验和
	UINT2 urg; 		//紧急字段指针
	char data[0]; 	//包含数据
} tTcp; 
//  UDP包
typedef struct udp { 
	UINT2 sport; 	//源端口
	UINT2 dport; 	//目标端口
	UINT2 hlen;  	//包长度
	UINT2 chsum; 	//检验和
	char data[0];	//包含数据
} tUdp; 
//将网络字节序的ip地址以及网络掩码转换转化为人们常用的形式 
void net_host (UINT4 ip_mask_net  ,char *ip) { 

    unsigned int ip_mask = ntohl(ip_mask_net);  

	UINT4 one, two, three, four; 
	one = ip_mask; 
	one = one >> 24; 
	two = ip_mask; 
	two = two >> 16; 
	two = two & 0xff; 
	three = ip_mask; 
	three = three >> 8; 
	three = three & 0xff; 
	four = ip_mask; 
	four = four & 0xff; 
    
	memset(ip,'\0',20);
	sprintf (ip,"%u.%u.%u.%u", one, two, three, four); 

	return;
} 
//截取start与end之间的字符串
int httpget(char *pdata,int httplen,char* start,char *end ,char *rult ,int rultlen){
	int i=0;
	int Fhead,Fend;
	Fhead=Fend=0;
	int hlen = strlen(start);
	int elen=strlen(end);
	while(i<httplen){
		if( pdata[i]==*start){
			Fhead =1;
			int b;
			//匹配 head_str 的其他字符
			for(b=1; b<hlen; b++) {
				if(pdata[i+b] != *(start+b)){
					Fhead =0;
					break;
				}
			}	
			if(Fhead ==1){
				Fhead=i=i+b;
				while(i<httplen){
					if(pdata[i]==*end){
						Fend=i;
						//匹配 head_str 的其他字符
						for(b=1; b<elen; b++) {
							if(pdata[i+b] != *(end+b)){
								Fend =0;
								break;
							}
						}
						if(Fend>0){
						
							if((i-Fhead)<(rultlen-1))
								memcpy(rult,pdata+Fhead,i-Fhead);
							else
								memcpy(rult,pdata+Fhead,rultlen-1);
							return 1;
						}
					}
					
					if(pdata[i]==';'||pdata[i]=='&'||pdata[i]=='\r'){
						Fend=i;						
						if(Fend>0){
						
							if((i-Fhead)<(rultlen-1))
								memcpy(rult,pdata+Fhead,i-Fhead);
							else
								memcpy(rult,pdata+Fhead,rultlen-1);
							return 1;
						}
					}
					
					i++;
				}
			}
		}
		i++;
	}
	return 0;
}
//截取start之后的字符串
int httpGetend(char *pdata,int httplen,char* start,char *rult,int rultlen){
	int i=0;
	int Fhead,Fend;
	Fhead=Fend=0;
	int hlen = strlen(start);
	while(i<httplen){
		if( pdata[i]==*start){
			Fhead =1;
			int b;
			//匹配 head_str 的其他字符
			for(b=1; b<hlen; b++) {
				if(pdata[i+b] != *(start+b)){
					Fhead =0;
					break;
				}
			}	
			if(Fhead ==1){
				Fhead=i=i+b;
				while(i<httplen){
					if(pdata[i]==';'||pdata[i]=='&'||pdata[i]=='\r'){
						if((i-Fhead)<(rultlen-1))
							memcpy(rult,pdata+Fhead,i-Fhead);
						else
							memcpy(rult,pdata+Fhead,rultlen-1);		
							return 1;
					}
					i++;
				}
			}
		}
		i++;
	}
	return 0;
}
//URL解码   将%FF%FF%FF%FF%FF%FF之类的URL编码格式的字符串转化为unicode编码     
void urldecode(char *p)  {  
	//register i=0;  
	int i = 0;
	while(*(p+i))  {  
		if ((*p=*(p+i)) == '%'){  
			*p=*(p+i+1) >= 'A' ? ((*(p+i+1) & 0XDF) - 'A') + 10 : (*(p+i+1) - '0');  
			*p=(*p) * 16;  
			*p+=*(p+i+2) >= 'A' ? ((*(p+i+2) & 0XDF) - 'A') + 10 : (*(p+i+2) - '0');  
			i+=2;  
		}  
		else if (*(p+i)=='+'){  
			*p=' ';  
		}  
		p++;  
	}  
	*p='\0';  
} 

////////////////////////////////////////////////////////////////////////////////

//****************************************************************************//

////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////

//腾讯数据处理函数 
 void WeiXinQQBLL(unsigned char *pdata,struct Client_info * Client_cur,int Issend)	{ 
 
 	char UserName[128];
	memset(UserName,'\0',128);
	
	if(pdata[7] == 0x01)//WeiXin           
	{	
		if(pdata[8] == 0x3b &&pdata[9] == 0x9a && pdata[10] == 0xca && pdata[19] == 0x00 && pdata[20] == 0x00 && pdata[21] == 0x00)
		{
			
			int pos=22;
			if(pdata[pos] == 0x00)
				pos=23;
			unsigned int qq ;
			
			qq = (pdata[pos]& 0xff);
			qq = (qq << 8) + (pdata[pos+1]&0xff);
			qq = (qq << 8) + (pdata[pos+2]&0xff);
			qq = (qq << 8) + (pdata[pos+3]&0xff);
			if(qq>10000000)
			{			
				snprintf(UserName,128,"%u",qq);	
				printf("weixin:%s\n", UserName);
				if(Issend)
				{
					Add_Netid_link(Client_cur,"WeiXin",UserName,"1");	
				}else
				{
					Add_Netid_RElink(Client_cur,"WeiXin",UserName,"1");							
				}
			}
		}
		else if(pdata[8] == 0x00 &&pdata[9] == 0x00 && pdata[10] == 0x00 && pdata[18] == 0x5f)
		{
			
			int pos=23;
		
			unsigned int qq ;
			
			qq = (pdata[pos]& 0xff);
			qq = (qq << 8) + (pdata[pos+1]&0xff);
			qq = (qq << 8) + (pdata[pos+2]&0xff);
			qq = (qq << 8) + (pdata[pos+3]&0xff);
			if(qq>10000000)
			{
				
					snprintf(UserName,128,"%u",qq);
					printf("weixin:%s\n", UserName);
					if(Issend)
					{
						Add_Netid_link(Client_cur,"WeiXin",UserName,"1");
						
					}else
					{
						Add_Netid_RElink(Client_cur,"WeiXin",UserName,"1");
							
					}
		
			}
			
		}
	} 		
	else if(pdata[7] == 0x08 ||pdata[7] == 0x09 || pdata[7] == 0x0b)
	{
		int pos=17;					
		int len =(int)	pdata[pos];
		
		if(len>5&&len<15&&pdata[pos+1]>0x30&&pdata[pos+1]<0x40 )
		{			
		
			memcpy(UserName,pdata+pos+1,len-4);

			if(strlen(UserName)>6)
			{
			
			
					if(Issend)
					{
						Add_Netid_link(Client_cur,"QQ",UserName,"1");
						
					}else
					{
						Add_Netid_RElink(Client_cur,"QQ",UserName,"1");
							
					}	
			}
		}
	
	}

 }
//Get数据处理函数
void GetDeal(char* pdata,int httplen,char* host,struct Client_info* Client_cur){
		
		char UserName[IDSIZE];//用户名 登录身份账号
		char referer[STRSIZE]; //网址
		memset(UserName,'\0',IDSIZE);
		char imei[IDSIZE],imsi[IDSIZE];
		char *start = NULL;
		char *end = NULL;
	
	
		//在GET中找有用的虚拟身份			
		char uri[STRSIZE];			
		memset(uri,'\0',STRSIZE);
		
		start ="GET ";
		end ="HTTP/";
		//处理数据 
		if(httpget(pdata,httplen,start,end ,uri,STRSIZE)==1)
		{
			
			if(sendUrl)
			{
				if(strlen(uri) < 50)
				{
					
					SendUrllog(Client_cur ,host,uri,"GET");			
					
				}
			
			}
			
		}
		
	if(strstr(host,"baidu.com")!=NULL){//百度搜索 优步
		
	
		
		if(strstr(host,"newvector.map.baidu.com")!=NULL){//优步
			start = "cuid=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"Uberx",UserName,"1");
			}
		}
		else if(strstr(host,"tieba.baidu.com")!=NULL){//贴吧

			start = "uid=";
			end ="&";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){		
				//URL解码
				urldecode(UserName);
				//上线事件
				//Add_Netid_link(Client_cur,"JD",UserName,"1");
				if (strlen(UserName) < 12 && strlen(UserName) > 1) {
					printf("tieba.baidu.com  uid=%s\n", UserName);
					Add_Netid_link(Client_cur,"tieba", UserName,"1");
				} else if (strlen(UserName) < 20) {
					char *space = strchr(UserName, ' ');
					if (space) {
						*space = 0;
						printf("tieba.baidu.com  space uid=%s\n", UserName);
						Add_Netid_link(Client_cur,"tieba", UserName,"1");
					}
				}
			}
		}
	}
	
	else if(strstr(host,".jd.com")!=NULL){//京东

		start = " pin=";
		end =";";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){		
			//URL解码
			urldecode(UserName);
			//上线事件
			Add_Netid_link(Client_cur,"JD",UserName,"1");
		}
	}
	else if(strstr(host,"qq.com")!=NULL){//QQ
		if(strstr(host,"mail.qq.com")!=NULL){
			start = "uin=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){				
				//上线事件
				Add_Netid_link(Client_cur,"Qmail",UserName,"1");				
			}			
		}
		else if(strstr(host,"now.qq.com")!=NULL){
			start = "&uin=";
			end = "&deviceid=";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){				
				//上线事件
				Add_Netid_link(Client_cur,"1030001",UserName,"1");				
			}	
		}
		else if(strstr(host,"weixin.qq.com")!=NULL){
			start = "uin=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
								
				Add_Netid_link(Client_cur,"WeiXin",UserName,"1");	
				printf("weixinget:%s\n", UserName);
			}			
		}
		else if(strstr(host,".t.qq.com")!=NULL){ // 腾讯微博
			start = "p_uin=";
			end = "\r\n";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"QQweibo",UserName,"1");
			}
		}
		else if(strstr(host,"qfwd.qq.com") != NULL){ //QQBBS
			memset(referer,'\0',STRSIZE);
			start = "Referer: ";
			end ="\r\n";
			if(httpget(pdata,httplen,start,end ,referer,STRSIZE) == 1){
				if(strstr(referer,"http://bbs.qq.com/")!=NULL){			
					start ="uin="; 
					end = "&";
					if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){

						//上线事件
						Add_Netid_link(Client_cur,"QQBBS",UserName,"1");						
					}
				}
			}
		}
		else if(strstr(host,"auto.qq.com") != NULL){ //QQBBS
			memset(referer,'\0',STRSIZE);
			start = "Referer: ";
			end ="\r\n";
			if(httpget(pdata,httplen,start,end ,referer,STRSIZE) == 1){
				if(strstr(referer,"http://bbs.qq.com/")!=NULL){			
					start ="uin="; 
					end = "&";
					if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){

						//上线事件
						Add_Netid_link(Client_cur,"QQBBS",UserName,"1");						
					}
				}
			}
		}
		else if(strstr(host,"trace.qq.com")!=NULL || strstr(host,"btrace.qq.com")!=NULL){ //腾讯微博	
			memset(referer,'\0',STRSIZE);
			start = "Referer: ";
			end ="\r\n";
			if(httpget(pdata,httplen,start,end ,referer,STRSIZE) == 1){
				if(strstr(referer,"http://t.qq.com/")!=NULL){	
					start = "ptui_loginuin=";
					end =";";
					if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
						
						//上线事件
						Add_Netid_link(Client_cur,"QQweibo",UserName,"1");
					}
				}
			}
		}
		else if(strstr(host,"qzone.qq.com")!=NULL){ // QQ空间    
			start = "pt2gguin=o0";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				
				//上线事件
				Add_Netid_link(Client_cur,"Qzone",UserName,"1");
				
			}
			start = "uin=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				
				//上线事件
				Add_Netid_link(Client_cur,"Qzone",UserName,"1");
				
			}
			start = "uin=o0";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				
				//上线事件
				Add_Netid_link(Client_cur,"Qzone",UserName,"1");
				
			}
		
		}
		else if(strstr(host,"isdspeed.qq.com")!=NULL){ // QQ    
			start = "; uin=o";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"1030001",UserName,"1");
			}
			start = "; pt2gguin=o";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"1030001",UserName,"1");
			}
		
		}
		else if(strstr(host,"dp3.qq.com")!=NULL){ // QQ空间    
			
			start = "uin=o";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				
				//上线事件
				Add_Netid_link(Client_cur,"Qzone",UserName,"1");
				
			}
		
		}
		else if(strstr(host,"showxml.qq.com")!=NULL){ // QQ空间    
			start = "&uin=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"Qzone",UserName,"1");
			}
			start = "uin_cookie=";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"Qzone",UserName,"1");
			}
			start = "\r\nClientUin: ";
			end = "\r\n";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"Qzone",UserName,"1");
			}
		}
	}
	else if(strstr(host,".qpic.cn")!=NULL){//QQ空间
				
				//QQ
				start = " uin=o";
				end =";";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName) > 5){
						//上线事件
						Add_Netid_link(Client_cur,"Qzone",UserName,"1");
					}
				}
				//QQ
				start = "&vuin=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName) > 5){
						//上线事件
						Add_Netid_link(Client_cur,"Qzone",UserName,"1");
					}
				}
				
			}
	else if(strstr(host,"123.130.127.")!=NULL){ // QQ空间    
		start = "&vuin=";
		end = "&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			
			//上线事件
			Add_Netid_link(Client_cur,"Qzone",UserName,"1");
			
		}
	}

	else if(strstr(host,".taobao.com")!=NULL){//淘宝 ，天猫cooki
		
		start ="nick=";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){
			//上线事件
			Add_Netid_link(Client_cur,"TaoBao",UserName,"1");	
		}
		
		start = "_w_tb_nick=";
		end = ";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){		
			//上线事件
			Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
		}
		
		start = "tracknick=";
		end = ";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){			
			//上线事件
			Add_Netid_link(Client_cur,"Tmall",UserName,"1");	
		}
		
		if(strstr(host,".tmall.")!=NULL || strstr(pdata,"tmall")!=NULL || strstr(pdata,"_ANDROID_TM")!=NULL){
			//昵称
			start = "loginId=cntaobao";
			end ="&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)!=0){
					urldecode(UserName);
					//上线事件
					Add_Netid_link(Client_cur,"Tmall",UserName,"1");
				}
			}
		}
		else {
			//昵称
			start = "loginId=cntaobao";
			end ="&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)!=0){
					urldecode(UserName);
					//上线事件
					Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
				}
			}
		}
		
	}
	else if(strstr(host,".hupan.com")!=NULL){//淘宝 
								
			//昵称
			start = "user_id=cntaobao";
			end ="&";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){				
				//URL解码
				urldecode(UserName);
				//上线事件
				Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
			}
			memset(UserName,'\0',IDSIZE);
			start ="user_id=cntaobao";
			end =";";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){				
				//上线事件
				Add_Netid_link(Client_cur,"AliWangWang",UserName,"1");
			}
			//昵称
			start = "loginId=cntaobao";
			end ="&os";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){				
				//URL解码
				urldecode(UserName);
				//上线事件
				Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
			}
				
		}
	else if(strstr(host,".alicdn.com")!=NULL){//旺信
								
			//昵称
			start = "&uids=cntaobao";
			end ="&";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){				
				//URL解码
				urldecode(UserName);
				//上线事件
				Add_Netid_link(Client_cur,"Aliwx",UserName,"1");
			}
	}
	else if(strstr(host,".mi.com")!=NULL){ // 米聊
		start = "; userId=";
		end = ";";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			//上线事件
			Add_Netid_link(Client_cur,"Miliao",UserName,"1");
		}
		start = "; nick=";
		end = ";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){			
			urldecode(UserName);
			//上线事件
			Add_Netid_link(Client_cur,"Miliao",UserName,"1");
		}
	}
	else if(strstr(host,".immomo.com")!=NULL){ // 陌陌
		start = "&account=";
		end = "&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){			
			//上线事件
			Add_Netid_link(Client_cur,"Momo",UserName,"1");
		}
		start = "fr=";
		end = " ";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Momo",UserName,"1");	
		}
		start = ";momo_session=";
		end = ";";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Momo",UserName,"1");	
		}
	}
	else if(strstr(host,"nrtf.pushmail.cn")!=NULL){ // 139MailAPP
		
		start = "mobileNum=";
		end = "&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}	
	}
	else if(strstr(host,"mobile.sina.cn")!=NULL){ // 新浪微博
		start = "&uin=";
		end = "&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Weibo",UserName,"1");
		}
		start = "uid=";
		end = "&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Weibo",UserName,"1");
		}
	}
	else if(strstr(host,"weibo.cn")!=NULL){ // 新浪微博
		start = "Uid: ";
		end = "\r";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Weibo",UserName,"1");
		}
	}
	else if(strstr(host,".weibo.com")!=NULL){//新浪微博

			start = "X-Log-Uid: ";
			end ="\r\n";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>9){
					//上线事件
					Add_Netid_link(Client_cur,"weibo",UserName,"1");
				}
			}
		}else if(strstr(host,".sinaimg.cn")!=NULL){ // 新浪微博
		start = "Uid:";
		end = "\r\n";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Weibo",UserName,"1");
		}
	}
	else if(strstr(host,".meituan.com")!=NULL){ // 美团外卖 大众点评APP
		
		char pragma[STRSIZE];			
		memset(pragma,'\0',STRSIZE);
		
		start ="pragma-os: ";
		end ="\r\n";
		if(httpget(pdata,httplen,start,end ,pragma,STRSIZE)==1){}
		
		if(strstr(pragma,"dianping")!=NULL){ 
			start = "&userid=";
			end = "&";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>5 && strlen(UserName)<30){
				//上线事件
				Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
				}
			}
			start = "userid: ";
			end = "\r\n";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>5 && strlen(UserName)<30){
				//上线事件
				Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
				}
			}
		}
		// 美团外卖
		else {
			
			start = "&userid=";
			end = "&";
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>5 && strlen(UserName)<30){
				//上线事件
				Add_Netid_link(Client_cur,"Meituan",UserName,"1");
				}
			}
			
			start = "acf_nickname=";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>5 && strlen(UserName)<30){
				//上线事件
				Add_Netid_link(Client_cur,"Meituan",UserName,"1");
				}
			}
		}
	}	
	else if(strstr(host,".vip.com")!=NULL){//唯品会
		
		start = ";VipRNAME=";
		end =";";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Vip",UserName,"1");
		}
		start = ";login_username=";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			if(strstr(UserName,"*****")==NULL){
				Add_Netid_link(Client_cur,"Vip",UserName,"1");
			}
		}
	}	
	else if(strstr(host,".appvipshop.com")!=NULL){//唯品会
		
		start = "&vipruid=";
		end ="&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			if(strstr(UserName,"*****")==NULL){
				Add_Netid_link(Client_cur,"Vip",UserName,"1");
			}
		}
		
		start = "&userid=";
		end ="&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			if(strstr(UserName,"*****")==NULL){
				Add_Netid_link(Client_cur,"Vip",UserName,"1");
			}
		}
		
	}							
	else if(strstr(host,".meituan.com")!=NULL || strstr(host,"140.207.217.32")!=NULL){//美团 大众点评
			if(strstr(pdata,"com.dianping.")!=NULL){
				
				//UID
				start = "&userid=";
				end = " HTTP/";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					//上线事件
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
				//UID
				start = "\r\nuser_id: ";
				end = "\r\n";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					//上线事件
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
			}else{
				
				//UID
				start = "&userid=";
				end = " HTTP/";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					//上线事件
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
				//UID
				start = "\r\nuser_id: ";
				end = "\r\n";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					//上线事件
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
			}
		}
	else if(strstr(host,"blog.sina.com")!=NULL){ //SinaBlog		
		start = "SUS=SID-";
		end = "-";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"SinaBlog",UserName,"1");			
		
		}
	}
	else if(strstr(host,"beacon.sina.com.cn")!=NULL){ //SinaBBS SinaMail
		memset(referer,'\0',STRSIZE);
		start = "Referer: ";
		end ="\r\n";
		if(httpget(pdata,httplen,start,end ,referer,STRSIZE) == 1){  
			if(strstr(referer,"http://bbs.sina.com.cn/")!=NULL || (strstr(referer,"club.")!=NULL && strstr(referer,".sina.com.cn/")!=NULL)){	//SinaBBS	
				start = "SUS=SID-";
				end = "-";
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					//上线事件
					Add_Netid_link(Client_cur,"SinaBBS",UserName,"1");
				}
			}
			else if(strstr(referer,"mail.sina.com.cn/")!=NULL){		//SinaMail
			
				start = "SUS=SID-";
				end = "-";
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					//上线事件
					Add_Netid_link(Client_cur,"SinaMail",UserName,"1");
				}				
			}
		}			
		//UID
		start = "||::";
		end ="::||";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			if(strlen(UserName)>5){
				//上线事件
				Add_Netid_link(Client_cur,"SinaBBS",UserName,"1");
			}
		}
	}	
	else if(strstr(host,".58.com")!=NULL){ //58同城
		start = "pptuname=";
		end = ";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName); //URL解码
			Add_Netid_link(Client_cur,"58",UserName,"1");
		}
		start = "\r\nuid: ";
		end = "\r\n";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName); //URL解码
			Add_Netid_link(Client_cur,"58",UserName,"1");
		}
		start = "UID=";
		end = "&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName); //URL解码
			Add_Netid_link(Client_cur,"58",UserName,"1");
		}
		start = "&UN=";
		end = "&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName); //URL解码
			Add_Netid_link(Client_cur,"58",UserName,"1");
		}
		start = "\r\ntn: ";
		end = "\r\n";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName); //URL解码
			Add_Netid_link(Client_cur,"58",UserName,"1");
		}
		//用户名
		start = "\"userid=";
		end = "&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			//审计上线
			Add_Netid_link(Client_cur,"58",UserName,"1");
		}
		//用户名
		start = "&username=";
		end = "&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			//审计上线
			Add_Netid_link(Client_cur,"58",UserName,"1");
		}
	}
	else if(strstr(host,".ganji.com")!=NULL){ // 赶集网
		
		//用户名
		//start = "\"user_id\":\"";
		//end = "\",\"";
		start = "\"user_id\":";
		end = ",\"";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			//审计上线
			Add_Netid_link(Client_cur,"Ganji",UserName,"1");
		}
		//用户名
		//start = "\"nickname\":\"";
		//end = "\"}";
		start = "%22%2C%22nickname%22%3A%22";
		end = "%22%7D;";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			//审计上线
			Add_Netid_link(Client_cur,"Ganji",UserName,"1");
		}
		start = "\"nickname\":\"";
		end = "\"}";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			//审计上线
			Add_Netid_link(Client_cur,"Ganji",UserName,"1");
		}
		
	}
	else if(strstr(host,".ctrip.com")!=NULL){//携程
			//UID
			start = "&userID=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>2){
					//上线事件
					Add_Netid_link(Client_cur,"Ctrip",UserName,"1");
				}
			}
		}
	else if(strstr(host,".qunar.com")!=NULL){ // 去哪儿APP		
	start = "qrid: ";
	end = "\r\n";
	if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
		//上线事件
		Add_Netid_link(Client_cur,"Qunar",UserName,"1");
	}	
	}
	else if(strstr(host,".tianya.cn")!=NULL){//天涯论坛 
		start = "user=w=";
		end ="&id=";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"TianyaBBS",UserName,"1");
		}										
	}
	else if(strstr(host,"mail.sina.com.cn")!=NULL){ //新浪免费Mail							
		start = "freeName=";
		end =";";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"SinaMail",UserName,"1");	
		}
		
		memset(UserName,'\0',IDSIZE);
		start = "userid\":\"";
		end ="\",";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"SinaMail",UserName,"1");	
		}
			
	}
	else if(strstr(host,"mail.126.com")!=NULL){ 	//126网易Mail		 													
		start = "mail_uid=";
		end =";";   
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"126Mail",UserName,"1");
		}
	}												
	else if(strstr(host,"mail.10086.cn")!=NULL){ 	//139手机移动Mail
		start = "udata_account_";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}
	}
	//////////////////////////////////////////////////////////////
	else if(strstr(host,".udache.com")!=NULL || strstr(host,".xiaojukeji.com")!=NULL || strstr(host,".diditaxi.com")!=NULL){ // 滴滴打车
		start = "phone=";
		end = "&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Didi",UserName,"1");
		}		
		start = "src=";
		end = "&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"Didi",UserName,"1");
		}
	}	
}
//POST数据处理函数 
void PostDeal(char *pdata, int httplen,char *host,struct Client_info * Client_cur){

	char referer[STRSIZE]; //网址
	char uri[STRSIZE];	
	char UserName[IDSIZE];
	char imei[IDSIZE];
	char imsi[IDSIZE];
	memset(uri,'\0',STRSIZE);
	memset(UserName,'\0',IDSIZE);
	memset(imei,'\0',IDSIZE);
	memset(imsi,'\0',IDSIZE);
	
	//形成mysql当前时间
//	char mysqltime[50] = {'\0'};	
//	make_mysqltime_str(mysqltime);
	
	char *start ="POST ";
	char *end ="HTTP/";
	if(httpget(pdata,httplen,start,end ,uri,STRSIZE)==1){//uri
	}
	//printf("this is 80  is PostDeal url end ,start netid\n");
	if(strstr(host,".jd.com")!=NULL){//京东

		start = " pin=";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){		
			//URL解码
			urldecode(UserName);
			//上线事件
			Add_Netid_link(Client_cur,"JD",UserName,"1");
		}	
		//用户名
		start = "jdc-backup: pin=";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			//上线事件
			Add_Netid_link(Client_cur,"JD",UserName,"1");
		}
		
	}
	else if(strstr(host,"qq.com")!=NULL){//QQ		
		if(strstr(host,"now.qq.com")!=NULL){
			start = "&uin=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				Add_Netid_link(Client_cur,"1030001",UserName,"1");	
			}	
		}
		else if(strstr(host,"mail.qq.com")!=NULL){
			start = "uin=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				//上线事件
				Add_Netid_link(Client_cur,"Qmail",UserName,"1");
			}	
		}
		else if(strstr(host,"weixin.qq.com")!=NULL){
			start = "uin=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				Add_Netid_link(Client_cur,"WeiXin",UserName,"1");	
				printf("weixinpost:%s\n", UserName);
			}	
		}
		else if(strstr(host,".t.qq.com")!=NULL){ // 腾讯微博
			start = "p_uin=";
			end = "\r\n";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				Add_Netid_link(Client_cur,"QQweibo",UserName,"1");
				
			}
			start = "p_luin=o0";
			end = ";";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				Add_Netid_link(Client_cur,"QQweibo",UserName,"1");
			}
		}
		else if(strstr(host,".qzone.")!=NULL){//QQ空间
				//QQ
				start = "pt2gguin=o0";
				end =";";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName) > 5){
						Add_Netid_link(Client_cur,"Qzone",UserName,"1");
					}
				}
				//QQ
				start = "?uin=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName) > 5){
						Add_Netid_link(Client_cur,"Qzone",UserName,"1");
					}
				}
				//QQ
				start = "p_uin=o0";
				end =";";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName) > 5){
						Add_Netid_link(Client_cur,"Qzone",UserName,"1");
					}
				}
			}
		
		
	}
	else if(strstr(host,".weibo.cn")!=NULL){//新浪微博	
		start = "uid=";
		end = "&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"Weibo",UserName,"1");
		}
	}
	else if(strstr(host,"connperf.immomo.com")!=NULL){ // 陌陌
		start = "fr=";
		end = " ";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"Momo",UserName,"1");
		}
	}
	else if(strstr(host,".taobao.com")!=NULL){//淘宝  旺信
								
		//昵称
		start = "\r\nsid=";
		end ="&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){				
			urldecode(UserName);
			Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
		}
		if(strstr(host,"wxapi.taobao.com")!=NULL){
			
			start = "&user_id=cnhhupan";
			end ="&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				urldecode(UserName);
				Add_Netid_link(Client_cur,"Aliwx",UserName,"1");
			}
		}
		if(strstr(host,".tmall.")!=NULL || strstr(pdata,"tmall")!=NULL || strstr(pdata,"_ANDROID_TM")!=NULL){//天猫
				//UID
				start = "\r\nsid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"Tmall",UserName,"1");
				}
				//UID
				start = "&sid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"Tmall",UserName,"1");
				}
				//昵称
				start = "&user_id=cntaobao";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"Tmall",UserName,"1");
					}
				}
				//昵称
				start = "; _w_tb_nick=";
				end =";";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"Tmall",UserName,"1");
					}
				}
			}
			else {
				//////////////////////////////////////
				//amdc.m.taobao.com
				//UID
				start = "\r\nsid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
				}
				//UID
				start = "&sid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
				}
				//amdc.m.taobao.com
				//////////////////////////////////////
				//////////////////////////////////////
				//api.m.taobao.com
				//昵称
				start = "&user_id=cntaobao";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
					}
				}
				//昵称
				start = "; _w_tb_nick=";
				end =";";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
					}
				}
				//api.m.taobao.com
				//////////////////////////////////////
			}
			
		
				
	}
	else if(strstr(host,".alicdn.com")!=NULL){//淘宝
			if(strstr(host,"wxapi.")!=NULL){//旺信
				//昵称
				start = "&user_id=cntaobao";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"Aliwx",UserName,"1");
					}
				}
			}
			//天猫
			if(strstr(host,".tmall.")!=NULL || strstr(pdata,"tmall")!=NULL || strstr(pdata,"_ANDROID_TM")!=NULL){//天猫
				//UID
				start = "\r\nsid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"Tmall",UserName,"1");
				}
				//UID
				start = "&sid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"Tmall",UserName,"1");
				}
				//昵称
				start = "&user_id=cntaobao";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"Tmall",UserName,"1");
					}
				}
				//昵称
				start = "; _w_tb_nick=";
				end =";";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"Tmall",UserName,"1");
					}
				}
			}
			else{//淘宝
				
				start = "\r\nsid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
				}
				//UID
				start = "&sid=";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
				}
				//amdc.m.taobao.com
				//////////////////////////////////////
				//////////////////////////////////////
				//api.m.taobao.com
				//昵称
				start = "&user_id=cntaobao";
				end ="&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
					}
				}
				//昵称
				start = "; _w_tb_nick=";
				end =";";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)!=0){
						urldecode(UserName);
						Add_Netid_link(Client_cur,"TaoBao",UserName,"1");
					}
				}
				//api.m.taobao.com
				//////////////////////////////////////
			}
			
		}
	else if(strstr(host,".meituan.com")!=NULL){//美团
		if(strstr(pdata,"\"appnm\":\"dianping_nova\",\"")!=NULL || strstr(pdata,"com.dianping.")!=NULL){
				
				//UID
				start = "\"uid\":\"";
				end = "\",\"";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
				//UID
				start = "\"biz_id\":\"";
				end = "\",\"";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
				
				//UID
				start = "&userid=";
				end = "&";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
				//UID
				start = "\r\nuser_id: ";
				end = "\r\n";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
				//UID
				start = "\"userId\":";
				end = ",\"";
				memset(UserName,'\0',IDSIZE);
				if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
					if(strlen(UserName)>5 && strlen(UserName)<30){
					Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
					}
				}
			}
		else {
			
			//UID
			start = "&userid=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>5 && strlen(UserName)<30){
				Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
				}
			}
			//UID
			start = "\r\nuser_id: ";
			end = "\r\n";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>5 && strlen(UserName)<30){
				Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
				}
			}
			//UID
			start = "\"userId\":";
			end = ",\"";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				if(strlen(UserName)>5 && strlen(UserName)<30){
				Add_Netid_link(Client_cur,"DzDianPing",UserName,"1");
				}
			}
		}
	}
	else if(strstr(host,"fetion.com.cn")!=NULL){//飞信
		start ="user ";
		end ="/>";
		memset(uri,'\0',STRSIZE);
		if(httpget(pdata,httplen,start,end ,uri,STRSIZE)==1){
			memset(UserName,'\0',IDSIZE);
			if(httpget(uri,strlen(uri),"\"","\"" ,UserName,IDSIZE)==1){	
				Add_Netid_link(Client_cur,"Fetion",UserName,"1");
			}
		}		
	}
	else if(strstr(host,".feixin.10086.cn")!=NULL){//飞信 
		start = "routeCode=";
		end =",";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			Add_Netid_link(Client_cur,"Fetion",UserName,"1");
		}
	}
	else if(strstr(host,".kuaidadi.com")!=NULL){//快的打车 
		start = ",\"phone\":\"";
		end ="\"}";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			Add_Netid_link(Client_cur,"Kuaidadi",UserName,"1");
		}
		start = ",\"mob\":\"";
		end ="\",\"";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			Add_Netid_link(Client_cur,"Kuaidadi",UserName,"1");
		}
	}
	else if(strstr(host,".ctrip.com")!=NULL){//ctrip携程
		start ="\"uid\":\"";
		end ="\"";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){
			Add_Netid_link(Client_cur,"Ctrip",UserName,"1");
		}
		
		start ="line1Number\":\"+86";
		end ="\"";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){
			Add_Netid_link(Client_cur,"Ctrip",UserName,"1");
		}
		//UID
		start = "\"UID\":\"";
		end = "\"";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			if(strlen(UserName)>2){
				Add_Netid_link(Client_cur,"Ctrip",UserName,"1");
			}
		}
	}
	else if(strstr(host,".qunar.com")!=NULL){ // 去哪儿
		start = "; _q=U.";
		end = ";";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"Qunar",UserName,"1");
		}		
	}
	else if(strstr(host,".tianya.cn")!=NULL){ // 天涯论坛
		//用户名
		start = "&userName=";
		end ="&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"TianyaBBS",UserName,"1");
		}
		//用户名
		start = "user=w=";
		end ="&id=";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"TianyaBBS",UserName,"1");
		}
		//UID
		start = "&id=";
		end ="&f=";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"TianyaBBS",UserName,"1");
		}	
		//UID
		start = "&userId=";
		end ="&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"TianyaBBS",UserName,"1");
		}	
	} 
	else if(strstr(host,"mail.163.com")!=NULL){ 	//163网易Mail			
		start = "uid="; 
		end ="&";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"163Mail",UserName,"1");
		}
	}
	else if(strstr(host,".mobile.sina.")!=NULL){//
		//UID
		start = "&uid=";
		end ="&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			if(strlen(UserName)>5){
				Add_Netid_link(Client_cur,"Sina",UserName,"1");
			}
		}
	}
	else if(strstr(host,"mail.sina.com")!=NULL || strstr(host,"mail.sina.cn")!=NULL ){ //新浪免费Mail
		start = "freeName=";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"SinaMail",UserName,"1");	
		}
		start = "userid\":\"";
		end ="\",";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"SinaMail",UserName,"1");	
		}
		start = "&from=";
		end ="&";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"SinaMail",UserName,"1");	
		}
		
		start = "Content-Disposition: form-data;name=\"from\"\r\n\r\n";
		end ="\r\n";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
			Add_Netid_link(Client_cur,"SinaMail",UserName,"1");
		}
		start = "%7B%22userid%22%3A%22";
		end ="%22%2C";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			if(strlen(UserName) > 0){
				urldecode(UserName);
				Add_Netid_link(Client_cur,"SinaMail",UserName,"1");
			}
		}
	}
	else if(strstr(host,".mail.126.com")!=NULL){ //126网易Mail
		start = "uid="; 
		end ="&";   
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"126Mail",UserName,"1");
		}
	}												
	else if(strstr(host,"mail.10086.cn")!=NULL){ //139Mail
		start = "udata_account_";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}
		start = "Login_UserNumber=";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			//上线事件
			Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}
		start ="UserNumber=";
		end =";";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){
			//上线事件
			Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}
		//UID
		start = "<UserNumber>";
		end ="</UserNumber>";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){				
				Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}
	}
	else if(strstr(host,"gdleadtone.com")!=NULL){//139Mail
		start ="mobileNum";
		end ="\0";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE)==1){
			Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}
	}
	else if(strstr(host,".189.cn")!=NULL){ 	//189Mail
		start = "189ACCOUNT=";
		end =";";
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			Add_Netid_link(Client_cur,"189Mail",UserName,"1");
		}
	}
	else if(strstr(host,".58.com")!=NULL){ // 58
			//用户名
			start = "\r\ntn: ";
			end = "\r\n";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				Add_Netid_link(Client_cur,"58",UserName,"1");
			}
			//用户名
			start = "UID=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				Add_Netid_link(Client_cur,"58",UserName,"1");
			}
			//用户名
			start = "&UN=";
			end = "&";
			memset(UserName,'\0',IDSIZE);
			if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
				Add_Netid_link(Client_cur,"58",UserName,"1");
			}
			
		} //////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////
	
}

void SubDataDeal(char* pdata,int httplen,struct Client_info* Client_cur){
	
	char UserName[IDSIZE];
	memset(UserName,'\0',IDSIZE);
	
	char *start = "POST ";
	char *end ="HTTP/";
	
	if(strstr(pdata,"@139.com</string>")!=NULL){ //139Mail
		start = "<string name=\"account\">";
		end = "</string>";
		memset(UserName,'\0',IDSIZE);
		if(httpget(pdata,httplen,start,end ,UserName,IDSIZE) == 1){
			urldecode(UserName);
				Add_Netid_link(Client_cur,"139Mail",UserName,"1");
		}
		
	}
	
	
}


////////////////////////////////////////////////////////////////////////////////

//****************************************************************************//

////////////////////////////////////////////////////////////////////////////////

//定时处理
time_t tt1=0;


//包分析、数据处理函数
void FilterSend( const u_char * pkt_data, int pktlen ){

	if(pktlen>80){

		tEther *pEther; 
		tIp *pIp; 
		pEther = (tEther *) pkt_data;
		pIp = (tIp *) pEther->data; 

		//-- TCP --//
		if( pIp->proto  == 0x06 ){
			
			//定时处理终端的下线
			if( time( NULL ) - tt1 >= 300 ) {
				tt1=time( NULL );
				Timeout_Mac_link();
			}
			
			tTcp *pTcp; 
			pTcp = (tTcp *) pIp->data; 
			int src_port,dst_port;
			src_port = t_ntohs(pTcp->sport);
			dst_port = t_ntohs(pTcp->dport);
			
			//形成当前结构体
			memset(Client_cur,'\0',sizeof( struct Client_info ));
			snprintf(Client_cur->smac, 20, "%02X-%02X-%02X-%02X-%02X-%02X",pEther->src[0], pEther->src[1], pEther->src[2],pEther->src[3],pEther->src[4], pEther->src[5]);				
			snprintf(Client_cur->dmac, 20, "%02X-%02X-%02X-%02X-%02X-%02X",pEther->dest[0], pEther->dest[1], pEther->dest[2],pEther->dest[3],pEther->dest[4], pEther->dest[5]);
			net_host( pIp->src,Client_cur->sip);
			net_host( pIp->dest,Client_cur->dip);
			
			//目标端口为80，http
			if( dst_port == 80){
				
				int tcplen =(int)(pIp->data[12]/16*4);
				char * pdata = (char *)pIp->data+tcplen;
				int httplen =pktlen-tcplen-34;
				
				if( pdata[0] == 0 && pdata[1] == 0){//腾迅数据包
				    //printf("80 here weixin data\n");
					unsigned char *Udata =	pIp->data+tcplen;
					WeiXinQQBLL(Udata,Client_cur,1);
				}
				else if(pdata[0]==0x47&&pdata[1]==0x45&&pdata[2]==0x54){ //处理Get数据
					char *start="Host: ";
					char *end ="\r\n";
					char host[STRSIZE];
					memset(host,'\0',STRSIZE);
					if(httpget(pdata,httplen,start,end ,host,STRSIZE)==1){//有Host 的数据包
							//Get数据处理函数 （数据存在与Cookie中）
							GetDeal(pdata,httplen,host,Client_cur);
							//postAndget(pdata,httplen,host,Client_cur);
					}
				}
				else if(pdata[0]==0x50&&pdata[1]==0x4f&&pdata[2]==0x53&&pdata[3]==0x54){//处理Post数据 
					char *start="Host: ";
					char *end ="\r\n";
					char host[STRSIZE];
					memset(host,'\0',STRSIZE);
					if(httpget(pdata,httplen,start,end ,host,STRSIZE)==1){//有Host 的数据包
						
						//Post数据处理函数
						PostDeal(pdata,httplen,host,Client_cur);
					}
				}
				
				else{
					SubDataDeal(pdata,httplen,Client_cur);
				}
		 	}
			//端口为443,或源端口为443 QQ微信
			else if(dst_port==443||src_port==443){
				
				int tcplen =(int)(pIp->data[12]/16*4);		
				unsigned char *pdata = pIp->data+tcplen;	
				int httplen = pktlen-tcplen-34;
				if(httplen>22){
					if( pdata[0] == 0 && pdata[1] == 0){
						printf("443 here weixin data\n");
						if(dst_port==443){	
							//腾讯数据处理函数
							WeiXinQQBLL(pdata,Client_cur,1);	
						}
						else if(src_port==443){
							//腾讯数据处理函数
							WeiXinQQBLL(pdata,Client_cur,0);	
						}
					}	
				}
			} 
		}
		//-- UDP --//
		else if( pIp->proto  == 0x11 ){
			tUdp *pUdp;
			pUdp = (tUdp *) pIp->data; 
			int src_port,dst_port;
			src_port = t_ntohs(pUdp->sport);
			dst_port = t_ntohs(pUdp->dport);
			
			//端口为8000， QQ
			if(( src_port ==8000)||(dst_port == 8000)){
				if( pUdp->data[0] == 0x02 && (pUdp->data[1] == 0x37||pUdp->data[1] == 0x36||pUdp->data[1] == 0x35)){				
					//形成当前结构体
					memset(Client_cur,'\0',sizeof( struct Client_info ));
					snprintf(Client_cur->smac, 20, "%02X-%02X-%02X-%02X-%02X-%02X",pEther->src[0], pEther->src[1], pEther->src[2],pEther->src[3],pEther->src[4], pEther->src[5]);				
					snprintf(Client_cur->dmac, 20, "%02X-%02X-%02X-%02X-%02X-%02X",pEther->dest[0], pEther->dest[1], pEther->dest[2],pEther->dest[3],pEther->dest[4], pEther->dest[5]);
					net_host( pIp->src,Client_cur->sip);
					net_host( pIp->dest,Client_cur->dip);

					int pos=7;
					unsigned int qq ;
					
					qq = (pUdp->data[pos]& 0xff);
					qq = (qq << 8) + (pUdp->data[pos+1]&0xff);
					qq = (qq << 8) + (pUdp->data[pos+2]&0xff);
					qq = (qq << 8) + (pUdp->data[pos+3]&0xff);
					if(qq>1000){
						char UserName[32];//用户名 登录身份账号
						memset(UserName,'\0',32);
						snprintf(UserName,32,"%u",qq);
						if(dst_port == 8000){
							Add_Netid_link(Client_cur,"QQ",UserName,"1");
						}
						else {
							Add_Netid_RElink(Client_cur,"QQ",UserName,"1");
						}
					}
				}
			}
		}
		
	}
}
