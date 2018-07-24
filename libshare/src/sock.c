#include "sock.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define LISTEN_QUEUE    (10)

void sock_delete(socket_t *sock)
{
    if (NULL == sock)
        return;
    if (sock->fd >= 0) {
        close(sock->fd);
    	}
    if ((AF_UNIX == sock->addr.addr.sa_family) && (strlen(sock->addr.un_addr.sun_path) > 0))
        remove(sock->addr.un_addr.sun_path);
    free(sock);
}

socket_t *sock_create(int32 domain,
                      int32 type,
                      int32 proto)
{
    socket_t *sock = NULL;
    int32 ret = -1;
    sock = (socket_t *)calloc(1, sizeof(*sock));
    if (NULL == sock)
    {
        perror("calloc()");
        goto out;
    }
    sock->fd = socket(domain, type, proto);
    if (sock->fd < 0)
    {
        perror("socket()");
        goto out;
    }
    sock->type = type;
    sock->proto = proto;
    sock->addr.addr.sa_family = domain;
    ret = 0;
out:
    if (0 != ret)
    {
        sock_delete(sock);
        sock = NULL;
    }
    return sock;
}

int32 sock_bind(socket_t *sock)
{
    int32 ret = -1;
    int32 addrlen = 0;
    if ((NULL == sock) || (sock->fd < 0))
    {
        if (NULL == sock)
            printf("sock(%p) is NULL!!\n", sock);
        else
            printf("Invalid sock->fd(%d)!!\n", sock->fd);
        goto out;
    }
    addrlen = sock_addrlen(&sock->addr);
    if (addrlen <= 0)
    {
        printf("Unsupported sa_family(%u) now!!\n", sock->addr.addr.sa_family);
        goto out;
    }
    ret = bind(sock->fd, &(sock->addr.addr), addrlen);
    if (ret < 0)
        perror("bind()");
    else
        ret = 0;
out:
    return ret;
}

int32 sock_listen(socket_t *sock)
{
    if ((NULL == sock) || (sock->fd < 0))
    {
        if (NULL == sock)
            printf("Invalid sock(%p)!!\n", sock);
        else
            printf("Invalid sock->fd(%d)!!\n", sock->fd);
        return -1;
    }
    else
    {
        int32 ret = listen(sock->fd, LISTEN_QUEUE);
        if (ret < 0)
        {
            int8 errbuf[128];
            bzero(errbuf, sizeof(errbuf));
            snprintf(errbuf, sizeof(errbuf), "listen() failed!! sock(%p), sock->fd(%d)!!", sock, sock->fd);
            perror(errbuf);
            ret = -1;
        }
        else
            ret = 0;
        return ret;
    }
}

int32 sock_accept(socket_t *sock,
                  socket_t **accept_sock)
{
    int32 ret = -1;
    socket_t *s = NULL;
    int32 addrlen = 0;
    if ((NULL == sock) || (sock->fd < 0))
    {
        if (NULL == sock)
            printf("sock(%p) is NULL!!\n", sock);
        else
            printf("Invalid sock->fd(%d)!!\n", sock->fd);
        goto out;
    }
    s = (socket_t *)calloc(1, sizeof(*s));
    if (NULL == s)
    {
        perror("calloc()");
        goto out;
    }
    addrlen = sizeof(s->addr);
    s->fd = accept(sock->fd, &(s->addr.addr), (socklen_t *)&addrlen);
    if (s->fd < 0)
    {
        perror("accept()");
        goto out;
    }
    if (s->addr.addr.sa_family != sock->addr.addr.sa_family)
    {
        printf("accepted s->addr.addr.sa_family(%u) != sock->addr.addr.sa_family(%u)\n", 
            s->addr.addr.sa_family, sock->addr.addr.sa_family);
        goto out;
    }
    s->type = sock->type;
    s->proto = sock->proto;

    ret = 0;
out:
    if (0 != ret)
    {
        sock_delete(s);
        s = NULL;
    }
    *accept_sock = s;
    return ret;
}

int32 sock_send(socket_t *sock,
                const void *buf,
                int32 size)
{
    int32 len = -1;
    if ((NULL == sock) || (sock->fd < 0))
    {
        if (NULL == sock)
            printf("sock(%p) is NULL!!\n", sock);
        else
            printf("Invalid sock->fd(%d)!!\n", sock->fd);
        goto out;
    }
    if ((NULL == buf) || (0 == size))
    {
        len = 0;
        goto out;
    }
    len = send(sock->fd, buf, size, 0);
    if (len < 0)
        perror("send()");
out:
    return len;
}

int32 sock_recv(socket_t *sock,
                void *buf,
                int32 size)
{
    int32 len = -1;
    if ((NULL == sock) || (sock->fd < 0))
    {
        if (NULL == sock)
            printf("sock(%p) is NULL!!\n", sock);
        else
            printf("Invalid sock->fd(%d)!!\n", sock->fd);
        goto out;
    }
    if ((NULL == buf) || (0 == size))
    {
        printf("buf(%p) is NULL or 0 == size(%d)\n", buf, size);
        len = -1;
        goto out;
    }
    len = recv(sock->fd, buf, size, 0);
    if (len < 0)
        perror("recv()");
out:
    return len;
}

int32 sock_sendto(socket_t *sock,
                  const void *buf,
                  int32 size,
                  sock_addr_u *daddr)
{
    int32 len = -1;
    if ((NULL == sock) || (sock->fd < 0))
    {
        if (NULL == sock)
            printf("sock(%p) is NULL!!\n", sock);
        else
            printf("Invalid sock->fd(%d)!!\n", sock->fd);
        goto out;
    }
    if ((NULL == buf) || (0 == size))
    {
        len = 0;
        goto out;
    }
    if ((NULL == daddr) || !sock_addrfamily_valid(daddr))
    {
        printf("daddr(%p) is NULL or daddr->sa_family is invalid!!\n", daddr);
        goto out;
    }
    if (sock->addr.addr.sa_family != daddr->addr.sa_family)
    {
        printf("sock->addr.addr.sa_family(%u) != daddr->addr.sa_family(%u)!!\n",
            sock->addr.addr.sa_family, daddr->addr.sa_family);
        goto out;
    }
    len = sendto(sock->fd, buf, size, 0, &daddr->addr, sock_addrlen(daddr));
    if (len < 0)
        perror("sendto()");
out:
    return len;
}

int32 sock_recvfrom(socket_t *sock,
                    void *buf,
                    int32 size,
                    sock_addr_u *saddr)
{
    int32 len = -1;
    if ((NULL == sock) || (sock->fd < 0))
    {
        if (NULL == sock)
            printf("sock(%p) is NULL!!\n", sock);
        else
            printf("Invalid sock->fd(%d)!!\n", sock->fd);
        goto out;
    }
    if ((NULL == buf) || (0 == size))
    {
        printf("buf(%p) is NULL or 0 == size(%d)\n", buf, size);
        len = -1;
        goto out;
    }
    if (NULL == saddr)
        len = recvfrom(sock->fd, buf, size, 0, NULL, NULL);
    else
    {
        int32 addrlen = sizeof(*saddr);
        len = recvfrom(sock->fd, buf, size, 0, &saddr->addr, (socklen_t *)&addrlen);
    }
    if (len < 0)
        perror("recvfrom()");
    if ((NULL != saddr) && (sock->addr.addr.sa_family != saddr->addr.sa_family))
    {
        printf("sock->addr.addr.sa_family(%u) != saddr->addr.sa_family(%u)!!\n",
            sock->addr.addr.sa_family, saddr->addr.sa_family);
        len = -1;
        goto out;
    }
out:
    return len;
}

socket_t *unix_sock_init(char *path)
{
	int len = 0, ret = -1;
	socket_t *sock = NULL;
	sock = sock_create(AF_UNIX, SOCK_DGRAM, 0);
	if (!sock) {
		printf("create socket fail, %s", strerror(errno));
		goto out;
	}
	unlink(path);
	memset(sock->addr.un_addr.sun_path, 0, sizeof(sock->addr.un_addr.sun_path));
	strncpy(sock->addr.un_addr.sun_path, path, sizeof(sock->addr.un_addr.sun_path)-1);
	len = sizeof(sock->addr.un_addr.sun_family) + strlen(sock->addr.un_addr.sun_path);

	if (bind(sock->fd, (struct sockaddr *)&(sock->addr.un_addr), len) < 0) {
		printf("bind socket fail, %s", strerror(errno));
		goto out;
	}
	struct timeval timeout;

	timeout.tv_sec = 6;
	timeout.tv_usec = 0;
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		printf("rcvtimeo fail, %s", strerror(errno));
		goto out;
	}
	ret = 0;
out:
	if (ret != 0 && sock != NULL) {
		sock_delete(sock);
		sock = NULL;
	}
	return sock;
	
}


socket_t *netlink_sock_init(uint32 type,uint32 src_grp, uint32 port_id)
{
	int size = 0;
	int ret = -1;
	socket_t *sock = NULL;
	sock = sock_create(PF_NETLINK, SOCK_RAW, type);
	if (!sock) {
		printf("create socket fail, %s", strerror(errno));
		goto out;
	}

	sock->addr.nl_addr.nl_family = AF_NETLINK;
	sock->addr.nl_addr.nl_pid = port_id;
	sock->addr.nl_addr.nl_groups = src_grp;

	if (bind(sock->fd, (struct sockaddr * )&(sock->addr.nl_addr), sizeof(sock->addr.nl_addr)) < 0) {
		printf("bind socket fail, %s", strerror(errno));
		goto out;
	}
	struct timeval timeout;
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
		printf("rcvtimeo fail, %s", strerror(errno));
		goto out;
	}

	size = 65535;
	setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	size = 65535;
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	ret = 0;
out:
	if (ret != 0 && sock != NULL) {
		sock_delete(sock);
		sock = NULL;
	}
	return sock;
}

int sock_sendmsg_unix(socket_t *sock, void* head, int32 hlen, void *sbuf, int32 slen, sock_addr_u *addr)
{
	struct msghdr msg;
	struct iovec iov[2];

	iov[0].iov_base = (void *)head;
	iov[0].iov_len = hlen;
	iov[1].iov_base = (void *)sbuf;
	iov[1].iov_len = slen;
	msg.msg_name = (void *)&addr->un_addr;
	msg.msg_namelen = sizeof(addr->un_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov)/sizeof(iov[0]);
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	return sendmsg(sock->fd, &msg, 0);
}

int sock_sendmsg_netlink(socket_t *sock, void* head, int32 hlen, void *sbuf, int32 slen, sock_addr_u *addr)
{
	struct msghdr msg;
	struct iovec iov[3];
	struct nlmsghdr nlh;

	nlh.nlmsg_len = sizeof(struct nlmsghdr) + hlen + slen;
    nlh.nlmsg_flags = 0;
    nlh.nlmsg_type = 0;
    nlh.nlmsg_seq = 0;
    nlh.nlmsg_pid = sock->addr.nl_addr.nl_pid; //self port

	iov[0].iov_base = (void*)&nlh;
	iov[0].iov_len = sizeof(struct nlmsghdr);
	iov[1].iov_base = (void *)head;
	iov[1].iov_len = hlen;
	iov[2].iov_base = (void *)sbuf;
	iov[2].iov_len = slen;
	msg.msg_name = (void *)&addr->nl_addr;
	msg.msg_namelen = sizeof(addr->nl_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov)/sizeof(iov[0]);
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	return sendmsg(sock->fd, &msg, 0);
}


