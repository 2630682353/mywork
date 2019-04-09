#ifndef SJWX_H_
#define SJWX_H_

typedef struct _stat {
    int cap_nr;
    int enqeue_drop;
    
    int send_sucess;
    int send_failed;
}stat_t;

extern char UnitCode[20];//场所编码
extern char CenterIP[20];//中心IP
extern char CenterHost[128];//中心域名
extern int DataPort;
extern int  sendUrl;
extern char APid[22];//无线AP编码
extern char longde[12];//经度
extern char latde[12];//纬度
extern char APMac[17+1];//MAC 地址

void *sjwxmac_main(void *args);
void *sjwxcomm_main(void *args);
void *sjwxwifi_main(const char *dev);

int queue_init(void);
int process_data(const unsigned char *buff, int len);
int process_cmd(unsigned char *recv_buff, int recv_len, 
            unsigned char *send_buff, int max_send_len, int *send_len);
void *send_thread(void *args);

char *timeStamp(char* timestamp);
char *make_time_str(char *time_str);
void APIPost(char *msg, int needSend, char *cmd);
char * fill_time_str(char *time_str, time_t time_now );
int gethostIpbyname(const char *name, char *host_ip, int maxLen);

extern pthread_t send_thread_id;

#endif // SJWX_H_
