#ifndef __ipc_msg_h
#define __ipc_msg_h
struct header {
	unsigned char head[6];
	unsigned char lenh;
	unsigned char lenl;
	unsigned char method;
	unsigned char ifnormal;
	unsigned char priority;
};

enum {
	IPC_ERR = 1,
	RESPONSE_ERR,
	JUDGE_ERR,
	GET_DATA_RESULT,
	DATA_TYPE,
	DATA_LEN,
};

extern int ipc_send(char *path, void *send_buf, int send_len, void *recv_buf, int recv_len);

#endif