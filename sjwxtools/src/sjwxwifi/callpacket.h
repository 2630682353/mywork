/*
	2016-11-30 端口定义放到.h文件里
	2017-03-08 升级解析
*/

#ifndef __L_PCAP_H__
#define __L_PCAP_H__


//加入解析
#define HIGHEST_CHANNEL 221
typedef unsigned char UINT1; 
typedef unsigned short UINT2; 
typedef unsigned int UINT4; 
#define STRSIZE 1024
#define IDSIZE 64
#define BUFFER_MAX_LENGTH 65536 

//wifi场所端口
#define OutTime (60 * 20)

//////////////////////////////
//    结构体
//////////////////////////////
//MAC IP 信息 结构体
struct Client_info{
	char smac[18],dmac[18]; //源MAC、目标MAC
	char sip[20],dip[20];	//源IP 、目标IP
};



//基本信息链表
struct Mac_link{
	
	struct Mac_link * prev;
	struct Mac_link * next;
	char mac[18],dmac[18];//终端MAC地址   	
	time_t onlinetime, lasttime; 
	char lan_ip[20];//内网IP地址 32
	char sessionid[64];//会话ID 64
	struct NetID_link* phead;//绑定身份集合

};

//绑定身份集合
struct NetID_link {
	struct NetID_link * prev;
	struct NetID_link * next;
	char loginid[64];//登录ID
	char idtype[64]; //登录ID类型
	time_t eventtime;//事件时间
};



//////////////////////////////
//    函数声明
//////////////////////////////


//包分析、数据处理函数
extern void FilterSend( const u_char * pkt_data, int pktlen );



#endif
