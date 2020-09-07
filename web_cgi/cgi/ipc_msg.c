#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/un.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include "ipc_msg.h"

#define IPC_LOG_PATH  "/tmp/ipc_log"
#define GETREQUEST 0xc0
#define SETREQUEST 0xc1
#define ACTIONREQUEST 0xc3
#define GETRESPONSE 0xc4
#define SETRESPONSE 0xc5
#define ACTIONRESPONSE 0xc7
#define IPC_PATH "/mnt/data/serversocketfile"
#define IPC_TIMEOUT 60



#define IPC_ERROR(fmt,args...) do{ \
	ipc_log(IPC_LOG_PATH, "[IPC:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)

void ipc_log(char *file, const char *fmt, ...)
{
	va_list ap;
	FILE *fp = NULL;
	char bakfile[32] = {0,};

	fp = fopen(file, "a+");
	if (fp == NULL)
		return;
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
	if (ftell(fp) > 10*1024)
		snprintf(bakfile, sizeof(bakfile), "%s.bak", file);
	fclose(fp);
	if (bakfile[0])
		rename(file, bakfile);
}

static int ipc_client_init(char *path)
{
	int sock = 0, len = 0, ret = 0;
	struct sockaddr_un addr;

	if ((!path) || (!strlen(path))) {
		return -1;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		IPC_ERROR("create socket fail, errno:%d, %s\n", errno, strerror(errno));
		return -1;
	}

	memset (&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
	len = sizeof(addr.sun_family) + sizeof(addr.sun_path);

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		close(sock);
		IPC_ERROR("connect error:%d, path:%s\n", ret, path);
		return -1;
	} else {
	}
	return sock;
}

static int ipc_setsock(int sock, int time)
{
	struct timeval timeout;

	timeout.tv_sec = time;
	timeout.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		IPC_ERROR("rcvtimeo fail, %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int ipc_write(int fd, char *buf, int len)
{
	int wlen = 0, ylen = 0, offset = 0;

	if ((!buf) || (len <= 0)) {
		//IPC_ERROR("data err\n");
		return -1;
	}

	wlen = len;
	while((ylen = write(fd, &buf[offset], wlen)) != wlen) {
		if(ylen > 0) {
			offset += ylen;
			wlen -= ylen;
		} else if (errno == EAGAIN || errno == EINTR) {
		  	continue;
		} else {
			//IPC_ERROR("ylen:%d, errno:%d, err:%s\n", ylen, errno, strerror(errno));
			return -1;
		}
	}
	return 0;
}

int ipc_read(int fd, char *buf, int len)
{
	int rlen = 0, ylen = 0, offset = 0;

	if ((!buf) || (len <= 0)){
		//IPC_ERROR("data err\n");
		return -1;
	}

	rlen = len;
	while ((ylen = read(fd, &buf[offset], rlen)) != rlen) {
		if(ylen > 0) {
			offset += ylen;
			rlen -= ylen;
		} else if (ylen == 0) {
			break;
		} else if (errno == EAGAIN || errno == EINTR) {
		  	continue;
		} else {
			//IPC_ERROR("ylen:%d, errno:%d, err:%s\n", ylen, errno, strerror(errno));
			return -1;
		}
	}
	return 0;
}

int ipc_send(char *path, void *send_buf, int send_len, void *recv_buf, int recv_len)
{
	struct header *hd;
	int sock = 0;
	int offset = 0;
	int ret = -1;
	if ((!path) || (!strlen(path))) {
		return ret;
	}
	if (!send_buf)
		send_len = 0;
	if (!recv_buf)
		recv_len = 0;
	sock = ipc_client_init(path);
	if (sock < 0)
		return ret;

	ipc_setsock(sock, IPC_TIMEOUT);

	int i = 0;
	char * str =(char *)malloc(recv_len*3+4);
	char * str2 =(char *)malloc(send_len*3+4);
	memset(str,0, recv_len*3+4);
	memset(str2,0, send_len*3+4);
	char temp[4] = {0};

	for(i=0;i<send_len;i++) {
		snprintf(temp, 4, "%02x ", ((unsigned char*)send_buf)[i]);
		strcat(str2,temp);
	}
	IPC_ERROR("send %s\n",str2);
	if (ipc_write(sock, (char *)send_buf, send_len) < 0) {
		goto err;
	}
	hd = (struct header *)recv_buf;
	
	if (read(sock, (char *)hd, sizeof(struct header)) != sizeof(struct header)){
		goto err;
		
	}
	unsigned short get_len = ((unsigned short)(hd->lenh)<<8)+hd->lenl;
	if (recv_len != sizeof(struct header) + get_len-3)
		goto err;

	//char *my = (char *)malloc(get_len+sizeof(struct header)-3);
	//if (ipc_read(sock, (char *)my + sizeof(struct header), get_len-3) < 0)
	//	goto err;
	
	if (ipc_read(sock, (char *)hd + sizeof(struct header), get_len-3) < 0)
		goto err;

	//memcpy(my, hd, sizeof(struct header));
	for(i=0;i<get_len+sizeof(struct header)-3;i++) {
		snprintf(temp, 4, "%02x ", ((unsigned char*)hd)[i]);
		strcat(str,temp);
	}
	IPC_ERROR("recv %s\n",str);
	ret = 0;
err:
	free(str);
	free(str2);
	close(sock);
	return ret;
}

int sys_get(void *send_buf, int send_len, void *recv_buf, int recv_len,void *judge,int judge_len,int *judge_result)
{
	struct header *hd,*hd2;
	int ret = -1;
	hd = (struct header *)malloc(send_len+sizeof(struct header));
	hd2 = (struct header *)malloc(recv_len+sizeof(struct header) + judge_len);
	memset(hd2, 0, recv_len+sizeof(struct header)+judge_len);
	unsigned char temp_shead[6] = {0x00,0x01,0x00,0x88,0x00,0x00};
	memcpy(hd, temp_shead, 6);
	hd->lenh=(unsigned char)(htons(3+send_len)&0x00ff);
	hd->lenl=(unsigned char)(htons(3+send_len)>>8);
	hd->method=GETREQUEST;
	hd->ifnormal=0x01;
	hd->priority=0x42;
	memcpy((char *)hd + sizeof(struct header), send_buf,send_len);
	if (ipc_send(IPC_PATH, hd, send_len+sizeof(struct header), hd2, recv_len+sizeof(struct header) + judge_len)) {
		*judge_result = IPC_ERR;
		goto err;
	}
	if (hd2->method != GETRESPONSE) {
		*judge_result = RESPONSE_ERR;
		goto err;
	}
	if (memcmp((char *)hd2 + sizeof(struct header), judge, judge_len)) {
		*judge_result = JUDGE_ERR;
		goto err;
	}
	memcpy(recv_buf,(char *)hd2 + sizeof(struct header)+judge_len,recv_len);
	ret = 0;
err:
	free(hd);
	free(hd2);
	return ret;
}

int sys_set(void *send_buf, int send_len)
{
	struct header *hd,*hd2;
	int ret = -1;
	hd = (struct header *)malloc(send_len+sizeof(struct header));
	hd2 = (struct header *)malloc(sizeof(struct header) + 1);
	memset(hd2, 0, sizeof(struct header)+1);
	unsigned char temp_shead[6] = {0x00,0x01,0x00,0x88,0x00,0x00};
	memcpy(hd, temp_shead, 6);
	hd->lenh=(unsigned char)(htons(3+send_len)&0x00ff);
	hd->lenl=(unsigned char)(htons(3+send_len)>>8);
	hd->method=SETREQUEST;
	hd->ifnormal=0x01;
	hd->priority=0x42;
	memcpy((char *)hd + sizeof(struct header), send_buf,send_len);
	if (ipc_send(IPC_PATH, hd, send_len+sizeof(struct header), hd2, 1+sizeof(struct header))) {
		goto err;
	}
	if (hd2->method != SETRESPONSE) {
		goto err;
	}
	if (*((char *)hd2 + sizeof(struct header))) {
		goto err;
	}
	ret = 0;
err:
	free(hd);
	free(hd2);
	return ret;
}

int sys_action(void *send_buf, int send_len)
{
	struct header *hd,*hd2;
	int ret = -1;
	hd = (struct header *)malloc(send_len+sizeof(struct header));
	hd2 = (struct header *)malloc(sizeof(struct header) + 2);
	memset(hd2, 0, sizeof(struct header)+2);
	unsigned char temp_shead[6] = {0x00,0x01,0x00,0x88,0x00,0x00};
	memcpy(hd, temp_shead, 6);
	hd->lenh=(unsigned char)(htons(3+send_len)&0x00ff);
	hd->lenl=(unsigned char)(htons(3+send_len)>>8);
	hd->method=ACTIONREQUEST;
	hd->ifnormal=0x01;
	hd->priority=0x42;
	memcpy((char *)hd + sizeof(struct header), send_buf,send_len);
	if (ipc_send(IPC_PATH, hd, send_len+sizeof(struct header), hd2, 2+sizeof(struct header))) {
		goto err;
	}
	if (hd2->method != ACTIONRESPONSE) {
		goto err;
	}
	if (*((char *)hd2 + sizeof(struct header))) {
		goto err;
	}
	ret = 0;
err:
	free(hd);
	free(hd2);
	return ret;
}

int meter_detail(void *send_buf, int send_len, void *recv_buf, int recv_len,void *judge,int judge_len,int *judge_result,unsigned short num)
{
	struct header *hd,*hd2;
	int ret = -1;
	hd = (struct header *)malloc(send_len+sizeof(struct header));
	hd2 = (struct header *)malloc(recv_len+sizeof(struct header) + judge_len);
	memset(hd2, 0, recv_len+sizeof(struct header)+judge_len);
	unsigned char temp_shead[6] = {0x00,0x01,0x00,0x88,0x00,0x00};
	temp_shead[4] = ((unsigned char*)&num)[1];
	temp_shead[5] = ((unsigned char*)&num)[0];
	memcpy(hd, temp_shead, 6);
	hd->lenh=(unsigned char)(htons(3+send_len)&0x00ff);
	hd->lenl=(unsigned char)(htons(3+send_len)>>8);
	hd->method=GETREQUEST;
	hd->ifnormal=0x01;
	hd->priority=0x42;
	memcpy((char *)hd + sizeof(struct header), send_buf,send_len);
	if (ipc_send(IPC_PATH, hd, send_len+sizeof(struct header), hd2, recv_len+sizeof(struct header) + judge_len)) {
		*judge_result = IPC_ERR;
		goto err;
	}
	if (hd2->method != GETRESPONSE) {
		*judge_result = RESPONSE_ERR;
		goto err;
	}
	if (memcmp((char *)hd2 + sizeof(struct header), judge, judge_len)) {
		*judge_result = JUDGE_ERR;
		goto err;
	}
	memcpy(recv_buf,(char *)hd2 + sizeof(struct header)+judge_len,recv_len);
	ret = 0;
err:
	free(hd);
	free(hd2);
	return ret;
}