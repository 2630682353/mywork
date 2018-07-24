#ifndef __UTILS_SOCK_H__
#define __UTILS_SOCK_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"
#include <netinet/in.h>
//#include <linux/in.h>
//#include <linux/in6.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <linux/netlink.h>

typedef union sock_addr_u{
    struct sockaddr     addr;
    struct sockaddr_un  un_addr;
    struct sockaddr_in  in_addr;
    struct sockaddr_in6 in6_addr;
	struct sockaddr_nl nl_addr;
}sock_addr_u;

typedef struct socket_st{
    int32 fd;
    int32 type;
    int32 proto;
    sock_addr_u addr;
}socket_t;


struct nlk_sock {
	struct sockaddr_nl src_addr;
	struct sockaddr_nl dst_addr;
	int sock_fd;
	unsigned int seq;
};




#define sock_addrfamily_valid(ptr) ((AF_INET == (ptr)->addr.sa_family) \
                                    || (AF_INET6 == (ptr)->addr.sa_family) \
                                    || (AF_UNIX == (ptr)->addr.sa_family) \
                                    || (AF_NETLINK == (ptr)->addr.sa_family))

static int32 inline sock_addrlen(sock_addr_u *addr)
{
    if (AF_INET == addr->addr.sa_family)
        return sizeof(addr->in_addr);
    else if (AF_INET6 == addr->addr.sa_family)
        return sizeof(addr->in6_addr);
    else if (AF_UNIX == addr->addr.sa_family)
        return SUN_LEN(&addr->un_addr);
    else
        return 0;
}
void sock_delete(socket_t *sock);
socket_t *sock_create(int32 domain,
                      int32 type,
                      int32 proto);
int32 sock_bind(socket_t *sock);
int32 sock_listen(socket_t *sock);
int32 sock_accept(socket_t *sock,
                  socket_t **accept_sock);
int32 sock_send(socket_t *sock,
                const void *buf,
                int32 size);
int32 sock_recv(socket_t *sock,
                void *buf,
                int32 size);
int32 sock_sendto(socket_t *sock,
                  const void *buf,
                  int32 size,
                  sock_addr_u *daddr);
int32 sock_recvfrom(socket_t *sock,
                    void *buf,
                    int32 size,
                    sock_addr_u *saddr);

socket_t *unix_sock_init(char *path);
socket_t *netlink_sock_init(uint32 type,uint32 src_grp, uint32 port_id);
int sock_sendmsg_unix(socket_t *sock, void* head, int32 hlen,void *sbuf, int32 slen, sock_addr_u *addr);
int sock_sendmsg_netlink(socket_t *sock, void* head, int32 hlen, void *sbuf, int32 slen, sock_addr_u *addr);




#ifdef  __cplusplus
}
#endif

#endif /*__UTILS_SOCK_H__*/

