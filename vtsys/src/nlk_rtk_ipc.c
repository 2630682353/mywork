#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <assert.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <stdarg.h>
#include "nlk_ipc.h"
#include "ioos_uci.h"
#include "aes.h"
#include "uci_fn.h"


int set_wifi_led(int action)
{
	switch (action) {
	case NLK_ACTION_ADD:
		system("echo 1 > /proc/wlan0/led");
		break;
	default:
		system("echo 0 > /proc/wlan0/led");
		break;
	}
	return 0;
}

int shell_printf(char *cmd, char *dst, int dlen)
{
	FILE *fp;
	int rlen;

	if (!cmd || !dst|| dlen <= 1)
		return -1;
	if ((fp = popen(cmd, "r")) == NULL)
		return IGD_ERR_NO_RESOURCE;
	rlen = fread(dst, sizeof(char), dlen - 1, fp);
//	dst[dlen-1] = 0;
	dst[rlen] = 0;

	pclose(fp);
	return rlen;
}


/*  return 0 if success, or -1 */
int read_mac(unsigned char *mac)
{
	char buf[64] = {0, };
	int ret;
	ret = shell_printf("cat /sys/devices/virtual/net/eth0.2/address", buf, sizeof(buf));
	if (ret < 0) 
		return ret;
	sscanf(buf, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", MAC_SPLIT(&mac));

	return 0;
}

