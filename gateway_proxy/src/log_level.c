#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "message.h"
#include    "log.h"
#include    "def.h"
#include    "uci_fn.h"
#include "sock.h"


int cgi_snd_msg(int cmd, void *snd, int snd_len, void **rcv, int *rcv_len)
{
	int temp_fd = 0, len = 0, ret = -1;
	char file_temp[20] = {0};
	msg_t *snd_msg = NULL;
	msg_t *rcv_msg = NULL;
	socket_t *temp_sock = NULL;
	int8 *rcv_buf = NULL;
	strcpy(file_temp, "/tmp/test.XXXXXX");
	snd_msg = malloc(sizeof(msg_t));
	
	snd_msg->cmd = cmd;
	snd_msg->dmid = MODULE_GET(cmd);
	snd_msg->dlen = snd_len;
	if ((temp_fd = mkstemp(file_temp)) < 0) {
		goto out;
	}
	temp_sock = unix_sock_init(file_temp);
	
	sock_addr_u dst_addr;
	dst_addr.un_addr.sun_family = AF_UNIX;
	memset(dst_addr.un_addr.sun_path, 0, sizeof(dst_addr.un_addr.sun_path));
	snprintf(dst_addr.un_addr.sun_path, sizeof(dst_addr.un_addr.sun_path)-1, "/tmp/%d_rcv", MODULE_GET(snd_msg->cmd));
	if (!temp_sock)
		goto out;
	len = sock_sendmsg_unix(temp_sock, snd_msg, sizeof(msg_t), snd, snd_len, &dst_addr);
	
	if (len <= 0)
		goto out;
	rcv_buf = malloc(2048);
	len = sock_recvfrom(temp_sock, rcv_buf, 2048, NULL);
	if (len <= 0)
		goto out;
	rcv_msg = rcv_buf;
	ret = rcv_msg->result;
	if (ret || !rcv || !rcv_len)
		goto out;
	*rcv = rcv_msg->data;
	*rcv_len = rcv_msg->dlen;

out:
	if (temp_fd > 0)
		close(temp_fd);
	if (snd_msg)
		free(snd_msg);
	if (temp_sock) 
		sock_delete(temp_sock);
	if (ret) {
		if (rcv && rcv_len) {
			*rcv = NULL;
			*rcv_len = 0;
		}
		if (rcv_buf)
			free(rcv_buf);
	} else {
		if (!rcv || !rcv_len) {
			if (rcv_buf)
				free(rcv_buf);
		}
	}
	return ret;
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("use: log_level processname(gateway_proxy radius_client portal_cgi) \n"
				"level(err, warning, info, debug) \n");
		return 0;
	}
	int i = 0;
	int temp_level = 0;
	while (log_array[i]) {
		if (strcmp(log_array[i], argv[2]) == 0) {
			temp_level = i + 1;
			break;
		}
		i++;
	}
	if (temp_level == 0) {
		printf("use: log_level processname level(err, warning, info, debug)");
		return 0;
	}
	if (strcmp("gateway_proxy", argv[1]) == 0) {
		if (cgi_snd_msg(MSG_CMD_MANAGE_LOG, &temp_level, sizeof(int), NULL, NULL))
			printf("snd logcmd err");
	} else if (strcmp("radius_client", argv[1]) == 0) {
		cgi_snd_msg(MSG_CMD_RADIUS_LOG, &temp_level, sizeof(int), NULL, NULL); 
	} else if (strcmp("portal_cgi", argv[1]) == 0) {
		char cmd[128] = {0};
		snprintf(cmd, sizeof(cmd), "acct_config.gateway_base.portal_cgi=%d", temp_level);
		uuci_set(cmd);
	}
	return 0;
}
