#include "dpi.h"
#include "message.h"
#include "log.h"

void dpi_policy_send()
{
	dpi_policy_t dp;
	char **array = NULL;
	int num = 0, item_num = 0, i = 0;
	if (!uuci_get("dpi_config.dpi_base.dpi_enable", &array, &num)) {
		if(!atoi(array[0])) {
			uuci_get_free(array, num);
			return;
		}
	}
	
	if (!uuci_get("dpi_config.dpi_base.item_num", &array, &num)) {
		item_num = atoi(array[0]);
		uuci_get_free(array, num);
	}
	if (item_num < 1)
		return;
	for (i = 0; i < item_num; i++) {
		char str[64] = {0};
		memset(&dp, 0, sizeof(dpi_policy_t));
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].position", i);
		if (!uuci_get(str, &array, &num)) {
			dp.position = atoi(array[0]);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].maxcnt", i);
		if (!uuci_get(str, &array, &num)) {
			dp.maxcnt = atoi(array[0]);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].maxsecs", i);
		if (!uuci_get(str, &array, &num)) {
			dp.maxsecs = atoi(array[0]);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].intra_mac", i);
		if (!uuci_get(str, &array, &num)) {
			str2mac(array[0], dp.intra_mac);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].intra_ip", i);
		if (!uuci_get(str, &array, &num)) {
			dp.intra_ip = inet_addr(array[0]);
			dp.intra_ip = ntohl(dp.intra_ip);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].intra_mask", i);
		if (!uuci_get(str, &array, &num)) {
			dp.intra_mask = inet_addr(array[0]);
			dp.intra_mask = ntohl(dp.intra_mask);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].outer_ip", i);
		if (!uuci_get(str, &array, &num)) {
			dp.outer_ip = inet_addr(array[0]);
			dp.outer_ip = ntohl(dp.outer_ip);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].outer_mask", i);
		if (!uuci_get(str, &array, &num)) {
			dp.outer_mask = inet_addr(array[0]);
			dp.outer_mask = ntohl(dp.outer_mask);
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].l4_proto", i);
		if (!uuci_get(str, &array, &num)) {
			if (!strcmp(array[0], "tcp"))
				dp.l4_proto = 1;
			else if (!strcmp(array[0], "udp"))
				dp.l4_proto = 2;
			else
				dp.l4_proto = 0xffffffff;
			uuci_get_free(array, num);
		}
		snprintf(str, sizeof(str) - 1, "dpi_config.@dpi_item[%d].outer_port", i);
		if (!uuci_get(str, &array, &num)) {
			dp.port.outer_port = atoi(array[0]);
			uuci_get_free(array, num);
		}
		if (msg_send_syn( MSG_CMD_DPI_POLICY_ADD, &dp, sizeof(dpi_policy_t), NULL, NULL) != 0) {
			GATEWAY_LOG(LOG_ERR, "MSG_CMD_DPI_POLICY_ADD err\n ");
		}else {
			GATEWAY_LOG(LOG_INFO, "dpi policy add success\n");
		}
	}
	
}

