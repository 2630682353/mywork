#include <unistd.h>
#include <stdlib.h>
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
#include <pthread.h>  
#include <sys/un.h>

#define SOCKET_RECEIVER "/tmp/sjwxtool.socket"

int main(int argc, char **argv)
{
    int connect_fd;
    struct sockaddr_un srv_addr;
    int ret;
    int i;

    //create client socket
    connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(connect_fd < 0)
    {
        perror("client create socket failed");
        return 1;
    }

    //set server sockaddr_un
    srv_addr.sun_family = AF_UNIX;
    strcpy(srv_addr.sun_path, SOCKET_RECEIVER);

    //connect to server
    ret = connect(connect_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if (ret == -1)
    {
        perror("connect to server failed!");
        close(connect_fd);
        return 1;
    }

//    printf("connect success.\n");

#define BUFF_SIZE (4 * 1024)
    unsigned char send_buff[BUFF_SIZE];
    unsigned char recv_buff[BUFF_SIZE];
    int maxLen = sizeof(recv_buff) - 100;
    int offset = 0;
    int got = 0;
    int send_len = 0;

    send_len = snprintf(send_buff, maxLen, "status");
    send_buff[send_len++] = 0;

    /* 发送数据 */    
//    printf("send:%s.\n", send_buff);
    got = write(connect_fd, send_buff, send_len);
    if (got != send_len)
    {
        perror("send packet failed!\n");
        close(connect_fd);
        return 1;
    }

    /* 接收响应，并处理 */
//    printf("recv...\n");
    offset = 0;
    got = 0;
    do
    {
        offset += got;
        got = read(connect_fd, recv_buff + offset, maxLen - offset);
    }while (got > 0 && (offset + got < maxLen));

    recv_buff[offset] = 0;
    close(connect_fd);

    printf("%s\n", recv_buff);
    
    return ret;
}