#include <ctype.h>
#include <stdio.h>  
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <getopt.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <malloc.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/un.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "callpacket.h"
#include "sjwx.h"

//全局变量
char UnitCode[20];//场所编码
char CenterIP[20];//中心IP
char CenterHost[128];//中心域名
int DataPort;
int deep=0;//默认不深度发掘，网盈路面设备使用nwcap.conf配置文件没有开启项。
int sendUrl = 0;
char APid[22];//无线AP编码
char longde[12];//经度
char latde[12];//纬度
char APMac[17+1];//MAC 地址

extern struct Client_info * Client_cur;

int gethostIpbyname(const char *name, char *host_ip, int maxLen)
{
    struct hostent *remoteHost = NULL;
    struct in_addr addr;
    
    remoteHost = gethostbyname(name);

    if (remoteHost == NULL)
    {
        return -1;
    }
    
    addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];
    snprintf(host_ip, maxLen, "%s", inet_ntoa(addr));
    
    return 0;
}

#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#define LOCKFILE "/tmp/fp.pid"
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)


/* set advisory lock on file */
int lockfile(int fd)
{
        struct flock fl;
 
        fl.l_type = F_WRLCK;  /* write lock */
        fl.l_start = 0;
        fl.l_whence = SEEK_SET;
        fl.l_len = 0;  //lock the whole file
 
        return(fcntl(fd, F_SETLK, &fl));
}

/* 通过配置服务器获取审计服务器信息 */
int fetch_config_server(const char *mac)
{
    /* 尝试100次，如果失败，则使用本地保存的信息 */
    static int retry = 100;
    char hostname[128];
    int data_port;

    int ret = -1;
    char buffer[10 * 1024];
    int needSend = 0;
    char url[128];
    char result[32];

    memset(result, 0, sizeof(result));

    if (mac == NULL)
    {
        return -2;
    }

    printf("fetch_config_server retry[%d].\n", retry);

    if (retry-- <= 0)
    {
        retry = 100;
        /* 尝试100次，如果失败，则使用本地保存的信息 */
        FILE *pf = fopen("/etc/config/shenji.conf", "r");
        if (pf == NULL)
        {
            printf("open /etc/config/shenji.conf failed.\n");
            return -1;
        }

        ret = fread(buffer, 1, sizeof(buffer), pf);
        if (ret < 0)
        {
            printf("read /etc/config/shenji.conf failed.\n");
            fclose(pf);
            return -1;
        }

        ret = sscanf(buffer,
            "result=%s "
            "Hostname=%s "
            "DataPort=%d ",
            result,
            hostname,
            &data_port);

        printf(
            "local:result=%s "
            "Hostname=%s "
            "DataPort=%d\n",
            result,
            hostname,
            data_port);

        if (memcmp(result, "success", strlen("success") + 1)
            || ret != 3)
        {
            printf("fetch_config_server local failed.\n");
            fclose(pf);
            return -1;
        }

        snprintf(CenterHost, sizeof(CenterHost) - 1, "%s", hostname);
        DataPort = data_port;

        fclose(pf);
        return 0;
    }
    
#if 1
    const char *host = "config.cdsjwx.cn";
    int port = 8080;
    snprintf(url, sizeof(url) - 1, "/api/shenji_conf.php?mac=%s", mac);
#else
    const char *host = "127.0.0.1";
    int port = 80;
    snprintf(url, sizeof(url) - 1, "/shenji_server.html");
#endif

    struct hostent *remoteHost = gethostbyname(host);

    if (remoteHost == NULL)
    {
        printf("get host ip failed.\n");
        return -1;
    }

	snprintf(buffer, sizeof(buffer) - 1,
    	"GET %s HTTP/1.1\r\n"
    	"Host: %s:%d\r\n"
    	"Content-Type: text/html\r\n\r\n",
    	url, host, port);

    needSend = strlen(buffer);

    int sock_cli = socket(AF_INET,SOCK_STREAM, 0);
    
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = *(u_long *) remoteHost->h_addr_list[0];

    struct timeval timeout = {30,0}; //30s
    if (setsockopt(sock_cli,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout)) != 0
        || setsockopt(sock_cli,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout)) != 0)
    {
        printf("setsockopt failed.");	 
        return -1;
    }

    if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf(" CenterHost:%s:%d connect error\n",host,port);	 
        return -1;
    }

    int pos=0;
    int len=0;
    /* 发送 */
    while (pos < needSend)
    {
        if((needSend - pos) > 2048)
        {
            len = send(sock_cli, buffer + pos, 2048, 0);
        }
        else
        {
            len = send(sock_cli, buffer + pos, needSend - pos, 0);
        }
        
        if(len <= 0)
        {
            printf("Send ERRPR!\n");
            close(sock_cli);
            return -1;
        }
        pos += len;
    }

    /* 接收 */
    pos = 0;
    len = 0;
    do{
        len = recv(sock_cli, buffer + pos, sizeof(buffer) - pos - 1, 0);

        if (len < 0)
        {
            printf("Recv ERRPR!\n");
            close(sock_cli);
            return -1;
        }
        else if (len == 0)
        {
            break;
        }
        
        pos += len;
    }while(pos < sizeof(buffer) - 1);
    buffer[pos] = 0;
    
    close(sock_cli);

    printf("buffer pos[%d]\n[%s]\n", pos, buffer);

    if (pos > 100)
    {
        const char *p = buffer;
        while (memcmp(p, "result=", strlen("result=")) 
            && (p < buffer + pos - strlen("result=")))
        {
            p++;
        }
    
        ret = sscanf(p,
            "result=%s "
            "Hostname=%s "
            "DataPort=%d ",
            result,
            hostname,
            &data_port);
        
        printf(
            "got:result=%s "
            "Hostname=%s "
            "DataPort=%d\n",
            result,
            hostname,
            data_port);
    }
    else
    {
        printf("invalid len[%d]\n[%s]\n", pos, buffer);
    }

    if (memcmp(result, "success", strlen("success") + 1)
        || ret != 3)
    {
        printf("fetch_config_server content error.\n");
        return -1;
    }
    else
    {
        /* 从配置服务器成功获取到审计服务器信息 */
        snprintf(CenterHost, sizeof(CenterHost) - 1, "%s", hostname);
        DataPort = data_port;
    
        /* 保存审计服务器信息 */
        /* 读取本地信息 */
        FILE *pf = fopen("/etc/config/shenji.conf", "rb+");
        if (pf == NULL)
        {
            printf("open /etc/config/shenji.conf failed.\n");
            return 0;
        }

        fseek(pf, 0, SEEK_SET);
        memset(buffer, 0 ,sizeof(buffer));
        ret = fread(buffer, 1, sizeof(buffer), pf);
        if (ret < 0)
        {
            printf("read /etc/config/shenji.conf failed.\n");
            fclose(pf);
            return 0;
        }
        buffer[sizeof(buffer) - 1] = 0;

        printf("buffer:[%s].\n", buffer);

        ret = sscanf(buffer,
            "result=%s "
            "Hostname=%s "
            "DataPort=%d ",
            result,
            hostname,
            &data_port);
        
        /* 比对是否和服务器信息一致 */
        /* 如果不一致，则更新 */
        if (ret != 3
            || memcmp(result, "success", strlen("success") + 1)
            || memcmp(hostname, CenterHost, strlen(CenterHost) + 1)
            || (data_port != DataPort))
        {
            printf("refresh server info.\n");
        
            snprintf(buffer, sizeof(buffer),
            "result=success "
            "Hostname=%s "
            "DataPort=%d",
            CenterHost,
            DataPort);

            fseek(pf, 0, SEEK_SET);
            fwrite(buffer, 1, strlen(buffer) + 1, pf);
            fflush(pf);
        }

        fclose(pf);
        return 0;
    }
}

/* 通过mac地址，去服务器查询审计配置信息 */
int get_config_from_server(const char *mac)
{
    /* 尝试100次，如果失败，则使用本地保存的信息 */
    static int retry = 100;

    int ret = -1;
    char buffer[512];
    int needSend = 0;
    char url[128];
    char result[32];

    char local_UnitCode[20];//场所编码
    int local_deep=0;//默认不深度发掘，网盈路面设备使用nwcap.conf配置文件没有开启项。
    int local_sendUrl = 0;
    char local_longde[12];//经度
    char local_latde[12];//纬度

    printf("get_config_from_server retry[%d].\n", retry);

    if (retry-- <= 0)
    {
        retry = 100;
        /* 尝试100次，如果失败，则使用本地保存的信息 */
        FILE *pf = fopen("/etc/config/sjwxwifi", "r");
        if (pf == NULL)
        {
            printf("open /etc/config/sjwxwifi failed.\n");
            return -1;
        }

        ret = fread(buffer, 1, sizeof(buffer), pf);
        if (ret < 0)
        {
            printf("read /etc/config/sjwxwifi failed.\n");
            fclose(pf);
            return -1;
        }

        ret = sscanf(buffer,
            "result=%s "
            "unitcode=%s "
            "sendurl=%d "
            "deepermac=%d "
            "long=%s "
            "lat=%s ", 
            result,
            UnitCode,
            &sendUrl,
            &deep,
            longde,
            latde);
        printf(
            "got:result=%s\n"
            "unitcode=%s\n"
            "sendurl=%d\n"
            "deepermac=%d\n"
            "long=%s\n"
            "lat=%s\n", 
            result,
            UnitCode,
            sendUrl,
            deep,
            longde,
            latde);

        if (memcmp(result, "success", strlen("success") + 1)
            || ret != 6)
        {
            printf("get_config_from_server local failed.\n");
            fclose(pf);
            return -1;
        }

        fclose(pf);
        return 0;
    }
    
#if 1
    const char *host = CenterHost;
    int port = 8080;
    snprintf(url, sizeof(url) - 1, "/device/getInfo.php?mac=%s", mac);
#else
    const char *host = "192.168.18.210";
    int port = 80;
    snprintf(url, sizeof(url) - 1, "/param.html");
#endif

    char host_ip[32];
    ret = gethostIpbyname(host, host_ip, sizeof(host_ip));
    if (ret != 0)
    {
        printf("get host[%s] Ip failed.\n", host);
        return -1;
    }

	snprintf(buffer, sizeof(buffer) - 1,
    	"GET %s HTTP/1.1\r\n"
    	"Host: %s:%d\r\n"
    	"Content-Type: text/html\r\n\r\n",
    	url, host, port);

    needSend = strlen(buffer);

    int sock_cli = socket(AF_INET,SOCK_STREAM, 0);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = inet_addr(host_ip);

    struct timeval timeout = {30,0}; //30s
    if (setsockopt(sock_cli,SOL_SOCKET,SO_SNDTIMEO,(const char*)&timeout,sizeof(timeout)) != 0
        || setsockopt(sock_cli,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout)) != 0)
    {
        printf("setsockopt failed.");	 
        return -1;
    }

    if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        printf(" CenterHost:%s:%d connect error\n",host,port);	 
        return -1;
    }

    int pos=0;
    int len=0;
    /* 发送 */
    while (pos < needSend)
    {
        if((needSend - pos) > 2048)
        {
            len = send(sock_cli, buffer + pos, 2048, 0);
        }
        else
        {
            len = send(sock_cli, buffer + pos, needSend - pos, 0);
        }
        
        if(len <= 0)
        {
            printf("Send ERRPR!\n");
            close(sock_cli);
            return -1;
        }
        pos += len;
    }

    /* 接收 */
    pos = 0;
    len = 0;
    do{
        len = recv(sock_cli, buffer + pos, sizeof(buffer) - pos -1, 0);

        if (len < 0)
        {
            printf("Recv ERRPR!\n");
            close(sock_cli);
            return -1;
        }
        else if (len == 0)
        {
            break;
        }
        
        pos += len;
    }while(pos < sizeof(buffer) - 1);
    buffer[pos] = 0;
    
    close(sock_cli);

    printf("buffer pos[%d]\n[%s]\n", pos, buffer);

    if (pos > 100)
    {
        const char *p = buffer;
        while (memcmp(p, "result=", strlen("result=")) 
            && (p < buffer + pos - strlen("result=")))
        {
            p++;
        }
    
        ret = sscanf(p,
            "result=%s "
            "unitcode=%s "
            "sendurl=%d "
            "deepermac=%d "
            "long=%s "
            "lat=%s ", 
            result,
            UnitCode,
            &sendUrl,
            &deep,
            longde,
            latde);
        printf(
            "got:result=%s\n"
            "unitcode=%s\n"
            "sendurl=%d\n"
            "deepermac=%d\n"
            "long=%s\n"
            "lat=%s\n", 
            result,
            UnitCode,
            sendUrl,
            deep,
            longde,
            latde);
    }
    else
    {
        printf("invalid len[%d]\n[%s]\n", pos, buffer);
    }

    if (memcmp(result, "success", strlen("success") + 1)
        || ret != 6)
    {
        return -1;
    }
    else
    {
        /* 从配置服务器成功获取到审计服务器信息 */   
        /* 保存审计服务器信息 */
        /* 读取本地信息 */
        FILE *pf = fopen("/etc/config/sjwxwifi", "rb+");
        if (pf == NULL)
        {
            printf("open /etc/config/sjwxwifi failed.\n");
            return 0;
        }

        fseek(pf, 0, SEEK_SET);
        memset(buffer, 0 ,sizeof(buffer));
        ret = fread(buffer, 1, sizeof(buffer), pf);
        if (ret < 0)
        {
            printf("read /etc/config/sjwxwifi failed.\n");
            fclose(pf);
            return 0;
        }
        buffer[sizeof(buffer) - 1] = 0;

        printf("buffer:[%s].\n", buffer);

        ret = sscanf(buffer,
            "result=%s "
            "unitcode=%s "
            "sendurl=%d "
            "deepermac=%d "
            "long=%s "
            "lat=%s ", 
            result,
            local_UnitCode,
            &local_sendUrl,
            &local_deep,
            local_longde,
            local_latde);
        
        /* 比对是否和服务器信息一致 */
        /* 如果不一致，则更新 */
        if (ret != 6
            || memcmp(result, "success", strlen("success") + 1)
            || memcmp(local_UnitCode, UnitCode, strlen(UnitCode) + 1)
            || (local_sendUrl != sendUrl)
            || (local_deep != deep)
            || memcmp(local_longde, longde, strlen(longde) + 1)
            || memcmp(local_latde, latde, strlen(latde) + 1))
        {
            printf("refresh shenji info.\n");
        
            snprintf(buffer, sizeof(buffer),
                "result=success "
                "unitcode=%s "
                "sendurl=%d "
                "deepermac=%d "
                "long=%s "
                "lat=%s ",
                UnitCode,
                sendUrl,
                deep,
                longde,
                latde);

            fseek(pf, 0, SEEK_SET);
            fwrite(buffer, 1, strlen(buffer) + 1, pf);
            fflush(pf);
        }

        fclose(pf);
        return 0;
    }
}

char dev[128];

void AEI_get_lan_macaddr(char *addr)
{
	int fd;
	struct ifreq intf;
	if (addr == NULL)
		return;
	if((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("socket error!\n");
		return;
	}
	strcpy(intf.ifr_name, dev);
	if(ioctl(fd, SIOCGIFHWADDR, &intf) != -1)
	{
		sprintf(addr, "%02x%02x%02x%02x%02x%02x",  (unsigned char)intf.ifr_hwaddr.sa_data[0],
				(unsigned char)intf.ifr_hwaddr.sa_data[1],
				(unsigned char)intf.ifr_hwaddr.sa_data[2],
				(unsigned char)intf.ifr_hwaddr.sa_data[3],
				(unsigned char)intf.ifr_hwaddr.sa_data[4],
				(unsigned char)intf.ifr_hwaddr.sa_data[5]);
	}
	close(fd);
	printf("addr==%s\n",addr);
	return;

}

void ReadConf(void)
{
    int ret = -1;
    int i = 0;
    
	AEI_get_lan_macaddr(APid);
	printf("mac is %s\n",APid);
	i= 0;
	for(i = 0;i< strlen(APid);i++)
	{
		APid[i]=toupper(APid[i]);
	}

    /* 从配置服务器获取审计服务器信息 */
    do{
        ret = fetch_config_server(APid);
        if (ret != 0)
        {
            printf("!!!fetch_config_server failed[%d].\n", ret);
            sleep(5);
        }
    }while(ret != 0);

    /* 从审计服务器获取审计相关信息 */
    do{
        ret = get_config_from_server(APid);
        if (ret != 0)
        {
            printf("!!!get_config_from_server failed[%d].\n", ret);
            sleep(5);
        }
    }while(ret != 0);
}

void pcap_callback(u_char *useless,
	const struct pcap_pkthdr* pkthdr, const u_char *packet)
{
    FilterSend(packet,pkthdr->caplen);
}

void wait_net_time_sync(void)
{
    time_t now = 0;

    /* 该函数需要系统配合实现: */
    /* 系统启动的时候将时间设置为UTC 1970-01-01 00:00:00 ，即:0秒*/
    /* 应用程序通过时间判断网络时间是否同步 */
    while (1)
    {
        /* 读取现在的UTC时间秒数*/
        time(&now);
        
        if (now > (86400 * 10))
        {
            return;
        }

        printf("wait_net_time_sync failed.\n");
        sleep(1);
    }
}

void *sjwxwifi_main(const char *dev)
{
    printf("sjwxwifi_main start.\n");
    
    /* 全局变量初始化 */
    Client_cur = malloc(sizeof(struct Client_info));
    if (Client_cur == NULL)
    {
        printf( "Client_info malloc failed" );
        exit(1);
    }
    memset(Client_cur, 0, sizeof(struct Client_info));

    /* 开始抓包 */
    pcap_t *handle; /* 会话句柄 */  
    
    char errbuf[PCAP_ERRBUF_SIZE]; /* 存储错误信息的字符串 */  
    struct bpf_program filter; /* 已经编译好的过滤器 */  
//  char filter_app[] = "len>80"; /* 过滤表达式 */  
    bpf_u_int32 mask; /* 所在网络的掩码 */  
    bpf_u_int32 net; /* 主机的IP地址 */  
    
    /* Define the device */  
    printf("Device: %s\n", dev);  
    /* 探查设备属性 */  
    int ret = pcap_lookupnet(dev, &net, &mask, errbuf);  
    if (ret == -1)
    {
        printf("pcap_lookupnet failed [%s]\n", errbuf);
    }
    /* 以混杂模式打开会话 */  
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);  
    if (handle == NULL)
    {
        printf("pcap_open_live failed [%s]\n", errbuf);
    }
    /* 编译并应用过滤器 */  
    //pcap_compile(handle, &filter, filter_app, 0, net);  
    //pcap_setfilter(handle, &filter);  
    /* 截获一个包 */  
    pcap_loop(handle, -1, pcap_callback, 0);

    /* 关闭会话 */  
    pcap_close(handle);
}

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
    fprintf(stderr, "hup\n");
	signal(SIGHUP, hup);
}

static void sig_do_nothing(int signo)
{
    return;
}

#define SOCKET_RECEIVER "/tmp/sjwxtool.socket"
int cgi_lsn_fd = -1;
pthread_t cgi_lsn_thread = (pthread_t)-1;

void *createSocketWithCgi(void *args)
{
    struct sockaddr_un srv_addr;
    int ret;
    int i;

    cgi_lsn_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(cgi_lsn_fd < 0)
    {
        perror("can't create communication socket!");
        return (void *)1;
    }

    int j = 1;
//	ioctlsocket(cgi_lsn_fd, FIONBIO, &j);

    srv_addr.sun_family = AF_UNIX;
    strncpy(srv_addr.sun_path, SOCKET_RECEIVER, sizeof(srv_addr.sun_path) - 1);
    unlink(SOCKET_RECEIVER);

    //bind sockfd and sockaddr
    ret = bind(cgi_lsn_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if(ret == -1)
    {
        perror("can't bind local sockaddr!");
        close(cgi_lsn_fd);
        unlink(SOCKET_RECEIVER);
        return (void *)-1;
    }

    //listen cgi_lsn_fd, try listen 1
    ret = listen(cgi_lsn_fd, 1);
    if(ret == -1)
    {
        perror("can't listen client connect request");
        close(cgi_lsn_fd);
        unlink(SOCKET_RECEIVER);
        return (void *)1;
    }

    system("chmod 777 "SOCKET_RECEIVER);

    int client_socket = -1;
    struct sockaddr_un addr;
    int addrlen = sizeof(addr);

    while (1)
    {
        client_socket = accept(cgi_lsn_fd, (struct sockaddr *)&addr, &addrlen);

        if (client_socket <= 0)
        {
            perror("stat_connect_failed");
            continue;
        }

//        printf("rctl accept a connect\n");

#define BUFF_SIZE (4 * 1024)
        unsigned char send_buff[BUFF_SIZE];
        unsigned char recv_buff[BUFF_SIZE];
        int maxLen = sizeof(recv_buff) - 100;
        int offset = 0;
        int got = 0;
        int send_len = 0;
        
        offset = read(client_socket, recv_buff + offset, maxLen - offset);

        recv_buff[offset] = 0;

//        printf("rctl accept a cmd:%s\n", recv_buff);

        /* 处理命令 */
        process_cmd(recv_buff, offset, send_buff, maxLen, &send_len);

//        printf("rctl send result:%s\n", send_buff);

        got = write(client_socket, send_buff, send_len);
    
        close(client_socket);
    }
    
    return (void *)0;
}


pthread_t heartbeat_thread_id = (pthread_t)-1;
void *heartbeat_thread(void *args)
{
    unsigned char beat = 0;

    while (1)
    {
        sleep(60);
        process_data(&beat, 0);
    }
    
    return NULL;
}

time_t started_time = 0;

int main(int argc, char *argv[])  
{  
    signal(SIGTERM, term);
    signal(SIGPIPE, plumber);
    signal(SIGHUP, hup);
    signal(SIGUSR1, sig_do_nothing);

	int opt;
	int foreground = 0;
    memset(dev, 0 ,sizeof(dev));

	while ((opt = getopt(argc, argv, "i:f")) != -1)
	{
		switch (opt)
		{
    		case 'i':
                snprintf(dev, sizeof(dev) - 1, "%s", optarg);
    			break;

    		case 'f':
    			foreground = 1;
    			break;

            default:
                break;
		}
	}

    wait_net_time_sync();
	ReadConf();

    started_time = time(NULL);

	if (strlen(dev) == 0)
	{
		printf("dev is Null\n");
		exit(1);
	}

    printf("dev is %s\n", dev);
	
	if (!foreground)
	{
		switch (fork())
		{
			case -1:
				printf("Unable to fork\n");
				return 8;

			case 0:
				umask(0077);
				chdir("/");
				freopen("/dev/null", "r", stdin);
				freopen("/dev/null", "w", stdout);
				freopen("/dev/null", "w", stderr);
				
				break;

			default:
				printf("Daemon launched ...\n");
				return 0;
		}
	}

    /* 初始化队列 */
    if (queue_init() != 0)
    {
        perror("queue_init fail.");
        return 0;
    }

    /* 启动sjwxmac、sjwxcomm、sjwxwifi线程 */
    pthread_t pid_mac, pid_comm, pid_wifi;
    //wifi探针
    if(pthread_create(&pid_mac, NULL, sjwxmac_main, NULL) != 0)
    {
        perror("pthread_create sjwxmac_main");
        return 0;
    } 
    pthread_detach(pid_mac);

    if(pthread_create(&pid_comm, NULL, sjwxcomm_main, NULL) != 0)
    {
        perror("pthread_create sjwxcomm_main");
        return 0;
    } 
    pthread_detach(pid_comm);

    /* 启动发送线程 */
    if(pthread_create(&send_thread_id, NULL, send_thread, NULL) != 0)
    {
        perror("pthread_create send_thread");
        return 0;
    } 
    pthread_detach(send_thread_id);

    /* cgi通信线程 */
    if (pthread_create(&cgi_lsn_thread, NULL, createSocketWithCgi, NULL) != 0) 
    {
        perror("createSocketWithCgi failed");
        return 0;
    }
    pthread_detach(cgi_lsn_thread);

    /* 启动心跳线程 为了保证和服务器通信不断线*/
    if (pthread_create(&heartbeat_thread_id, NULL, heartbeat_thread, NULL) != 0) 
    {
        perror("heartbeat_thread failed");
        return 0;
    }
    pthread_detach(heartbeat_thread_id);
	//审计抓包
    sjwxwifi_main(dev);

	return 0;
}  
