#include<stdio.h>
#include<stdlib.h>
#include<signal.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/socket.h>
#include <netinet/in.h>

#include<sys/types.h>
#include<sys/wait.h>
#include<errno.h>
#include<string.h>

#include "log.h"
#include "hash_table.h"
#include "timer.h"
#include "tools.h"

static int pipefd[2];
static int report_flow_interval = 180;
static HashTable *ht;
char wan[32] = {0};
char lan[32] = {0};
char *config_file = "/etc/netctl.conf";

typedef struct flow_statis_t
{
	uint64 total_up;
	uint64 total_down;
	uint32 up_time;
	uint32 local_time;
	uint32 upincrease_num;
	uint32 downincrease_num;
}flow_statis;

typedef struct perip_flow_t
{
	uint32 start_time;
	uint64 last_statis_down;
	uint64 last_statis_up;
	uint64 increase_down;
	uint64 increase_up;
	char mac[20];
	char ip[20];
	char host_name[64];
}perip_flow;

static flow_statis last_statis;
void sig_hander( int sig )  
{  
	int save_errno = errno;
	int msg = sig;
	send(pipefd[1], &msg, 4, 0);
	errno = save_errno;
}

int sig_init()
{
	sigset_t sig;
	sigemptyset(&sig);
	sigaddset(&sig, SIGABRT);
	sigaddset(&sig, SIGPIPE);
	sigaddset(&sig, SIGQUIT);
	sigaddset(&sig, SIGUSR1);
	sigaddset(&sig, SIGUSR2);
	sigaddset(&sig, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);
	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);
	return 0;
}

int cmd(const char * cmdstring)
{ 
	pid_t pid;
	int status;
	if(cmdstring == NULL)
	{
		return (1);
	}
	if((pid = vfork())<0)
	{
		status = -1;
	}
	else if(pid == 0)
	{
		//printf("process forked. pid=%d ppid=%d\n", getpid(), getppid());

		pid_t cpid;
		if ((cpid = vfork()) < 0)
		{
			_exit(127);
		} else if (cpid == 0)
		{
			execl("/bin/sh", "sh", "-c", cmdstring, (char *)0);
			_exit(127); //子进程正常执行则不会执行此语句 
		} else
		{
			exit(0);
		}
	}
	else{
		while(waitpid(pid, &status, 0) < 0)
		{
			if(errno != EINTR)
			{
				status = -1;
				break;
			}
		}
	}
	return status;
}

//更新每个子设备的流量统计
int update_ip_statistics()
{
	time_t t = time(NULL);
	time_t ut = uptime();
	int temp = t%report_flow_interval;
	if (temp >= report_flow_interval - 30 || temp < 30)
	{
		//上次查的时间小于120秒则不再继续查
		if (ut - last_statis.up_time <= 120)
			return 0;
		char traffic_src[4096];
		char traffic_dst[4096];
		uint64 total_up;
		uint64 total_down;
		perip_flow *pf = NULL;
		char *res;
		shell_printf("ipset list srcip | grep bytes | awk '{printf $1\" \"$5\" \"}'", traffic_src, sizeof(traffic_src));
		shell_printf("ipset list dstip | grep bytes | awk '{printf $1\" \"$5\" \"}'", traffic_dst, sizeof(traffic_dst));
		printf("traffic_src is %s\n", traffic_src);
		printf("traffic_dst is %s\n", traffic_dst);

		char *strdup1 = strdup(traffic_src);
		char *strdup2 = strdup(traffic_dst);
		char *str_start1 = strdup1;
		char *str_start2 = strdup2;
		char *current = strchr(str_start1, ' ');
		char *check_ip;
		char *tmp;
		char downbytes[20] = {0};
		int index = 0;
		while (current)
		{
			*current = '\0';
			if (index == 0)
			{
				check_ip = str_start1;
			}
				
			if (index == 1) 
			{
				memset(downbytes, 0, sizeof(downbytes));
				total_up = strtoull(str_start1, &res, 10);
				if((tmp = strstr(str_start2, check_ip)) != NULL) 
				{
					tmp = strchr(tmp, ' ');
					memcpy(downbytes, tmp+1, strchr(tmp+1, ' ')-tmp-1);
				}
				
				total_down = strtoull(downbytes, &res, 10);
				printf("after memcpy\n");
		
				pf = hash_table_get(ht, check_ip);
				if (pf)
				{
					pf->increase_down = total_down - pf->last_statis_down;
					pf->increase_up = total_up - pf->last_statis_up;
					pf->last_statis_down = total_down;
					pf->last_statis_up = total_up;
					
					IP_FLOW_RECORD("%lld  %lld  %lld  %lld  %s  %s  %s  %u  %u\n", 
						pf->increase_up/1024, pf->increase_down/1024, total_up/1024, total_down/1024,
					 pf->mac, pf->host_name, check_ip, ut, t);
				}
			}
				
			str_start1 = current + 1;
			current = strchr(str_start1, ' ');
			index++;
			if (index == 2)
			{
				index = 0;
			}
		}
		free(strdup2);
		free(strdup1);
		NETCTL_LOG(LOG_DEBUG, "after ip_record\n ");
	}
	return 0;
}

//更新网关的流量统计
int do_statistics()
{
	time_t t = time(NULL);
	time_t ut = uptime();
	int temp = t%report_flow_interval;	
	if (temp >= report_flow_interval - 30 || temp < 30)
	{
		//上次查的时间小于120秒则不再继续查
		if (ut - last_statis.up_time <= 120)
		{
			return 0;
		}
		char traffic_bytes[16];
		uint64 total_up;
		uint64 total_down;
		char *res;
		shell_printf("iptables -L -nvx | grep genvict_upload | awk '{printf $2}'", traffic_bytes, sizeof(traffic_bytes));
		printf("traffic is %s\n", traffic_bytes);
		total_up = strtoull(traffic_bytes, &res, 10);	
		total_up = total_up/1024;
		shell_printf("iptables -L -nvx | grep genvict_download | awk '{printf $2}'", traffic_bytes, sizeof(traffic_bytes));
		total_down = strtoull(traffic_bytes, &res, 10);
		total_down = total_down/1024;

		last_statis.up_time = ut;
		last_statis.local_time = t;
		last_statis.upincrease_num = total_up - last_statis.total_up;
		last_statis.downincrease_num = total_down - last_statis.total_down;
		last_statis.total_down = total_down;
		last_statis.total_up = total_up;
		FLOW_RECORD("%lld  %lld  %d  %d  %u  %u\n", last_statis.total_up, last_statis.total_down, 
			last_statis.upincrease_num,
			last_statis.downincrease_num, last_statis.up_time, last_statis.local_time);
		//do_flow_report();
		NETCTL_LOG(LOG_DEBUG, "after flow record\n");
	}
	return 0;
}


int route_init()
{
	//cmd("route add -net 192.168.110.0/24 dev bridge0");
	return 0;
}

int vlan_init()
{
	return 0;
}

int qos_init()
{
	return 0;
}

void ht_free_item(void *pf)
{
	if(pf)
	{
		free(pf);
	}
}

//根据邻居连接状态，动态调整ipset集合
int ipset_ip_update()
{
	char arp_result[4096] = {0};
	char ipset_result[8192] = {0};
	shell_printf("ip -4 neigh | grep br-lan | grep REACHABLE | awk '{printf $1\" \"$5\" \"}'", arp_result, sizeof(arp_result));
	shell_printf("ipset list srcip | grep bytes | awk '{printf $1\" \"}'", ipset_result, sizeof(ipset_result));
	NETCTL_LOG(LOG_DEBUG, "arp_result:%s \n ipset_result:%s", arp_result, ipset_result);
	int i = 0;
	char *strdup1 = strdup(arp_result);
	char *str_start = strdup1;
	char *current = strchr(str_start, ' ');
	perip_flow *pf = NULL;
	perip_flow *pf2 = NULL;
	char cmd[256] = {0};
	while (current) 
	{
		*current = '\0';
		if (i == 0)
		{
			pf = malloc(sizeof(perip_flow));
			memset(pf, 0, sizeof(perip_flow));
			strcpy(pf->ip, str_start);
			strcpy(pf->host_name, "unknown");
		}
		
		if (i == 1)
		{
			strcpy(pf->mac, str_start);
			if (!strstr(ipset_result, pf->ip)) 
			{
				snprintf(cmd, sizeof(cmd) - 1, "ipset add srcip %s;ipset add dstip %s", pf->ip, pf->ip);
				system(cmd);
				hash_table_put2(ht, pf->ip, pf, ht_free_item);
			} else
			{
				if ((pf2 = hash_table_get(ht, pf->ip)))
				{
					if (strcasecmp(pf2->mac, pf->mac))
					{
						memset(pf2, 0, sizeof(*pf2));
						strcpy(pf2->mac, pf->mac);
						strcpy(pf2->ip, pf->ip);
						strcpy(pf2->host_name, pf->host_name);
						snprintf(cmd, sizeof(cmd) - 1, "ipset del srcip %s;ipset del dstip %s;"
						"ipset add srcip %s;ipset add dstip %s", pf2->ip, pf2->ip,
						pf2->ip, pf2->ip);
						system(cmd);
					}
				}
				if (pf)
				{
					free(pf);
				}
			}
			
		}
		str_start = current + 1;
		i++;
		if (i == 2)
		{
			i = 0;
		}
		current = strchr(str_start, ' ');
	}
	char *strdup2 = strdup(ipset_result);
	str_start = strdup2;
	current = strchr(str_start, ' ');
	while (current)
	{
		*current = '\0';
		if (!strstr(arp_result, str_start))
		{
			char cmd[256] = {0};
			snprintf(cmd, sizeof(cmd) - 1, "ipset del srcip %s;ipset del dstip %s",
			str_start, str_start);
			system(cmd);
			hash_table_rm(ht, str_start);
		}
		str_start = current + 1;
		current = strchr(str_start, ' ');
	}
	if (strdup1)
	{
		free(strdup1);
	}
	if (strdup2)
	{
		free(strdup2);
	}
	return 0;
}

//流量统计初始化，包括总流量和基于mac的流量。
int statistic_init()
{
	char cmd_buff[2048] = {0};
	snprintf(cmd_buff, sizeof(cmd_buff) - 1,
		"iptables -A forwarding_rule -i %s -j RETURN -m comment --comment \"genvict_download\";"
		"iptables -A forwarding_rule -o %s -j RETURN -m comment --comment \"genvict_upload\";"
		"iptables -t filter -N ip_statistics;"
		"iptables -I forwarding_rule -j ip_statistics;"

		"ipset create srcip hash:ip hashsize 2048 counters;"
		"ipset create dstip hash:ip hashsize 2048 counters;"
		"iptables -I ip_statistics -m set --match-set srcip src -j RETURN;"
		"iptables -I ip_statistics -m set --match-set dstip dst -j RETURN;",
		wan,
		wan
		);
	cmd(cmd_buff);
	add_timer(do_statistics, 0, 1, 60, NULL, 0);
	add_timer(ipset_ip_update, 0, 1, 60, NULL, 0);
	add_timer(update_ip_statistics,0, 1, 60, NULL, 0);
	ht = hash_table_new(1024);
	return 0;
}
int statistic_final()
{
	cmd("iptables -D forwarding_rule -i eth0.2 -j RETURN -m comment --comment \"genvict_download\";"
		"iptables -D forwarding_rule -o eth0.2 -j RETURN -m comment --comment \"genvict_upload\";"
		"iptables -D ip_statistics -m set --match-set srcip src -j RETURN;"
		"iptables -D ip_statistics -m set --match-set dstip dst -j RETURN;"
		"iptables -D forwarding_rule -j ip_statistics;"
		"iptables -t filter -X ip_statistics;"
		"ipset destroy srcip;ipset destroy dstip;"
		);
	return 0;
}

int firewall_init()
{
	char cmd_buff[2048] = {0};
	snprintf(cmd_buff, sizeof(cmd_buff) - 1,
		"iptables -t nat -A POSTROUTING -s 0.0.0.0/0 -d 0.0.0.0/0 -o %s  -j MASQUERADE;"
		"iptables -P FORWARD DROP;"
		"iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;"
		"iptables -A FORWARD -i %s -o %s -j ACCEPT;"
		"iptables -A FORWARD -i %s -o %s -j ACCEPT;"
		"iptables -A FORWARD -i %s -m conntrack --ctstate DNAT -j ACCEPT;"
		"iptables -A FORWARD -i %s -m conntrack --ctstate DNAT -j ACCEPT;"
		"iptables -A FORWARD -j REJECT;",
		wan,
		lan, wan,
		lan, lan,
		lan,
		wan
		);
	cmd(cmd_buff);
	snprintf(cmd_buff, sizeof(cmd_buff) - 1,
		 "iptables -A INPUT -i lo -j ACCEPT;"
		 "iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 30 -j REJECT;"
		 "iptables -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT;"
		 "iptables -t filter -N syn_flood;"
		 "iptables -A INPUT -j syn_flood;"
		 "iptables -A syn_flood -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix 'syn_flood_log' --log-level 6;"
		 "iptables -A INPUT -i %s -j ACCEPT;"
		 "iptables -A INPUT -i %s -p udp --dport 68 -j ACCEPT;"
		 "iptables -A INPUT -i %s -p icmp --icmp 8 -j ACCEPT;"
		 "iptables -A INPUT -i %s -m conntrack --ctstate DNAT -j ACCEPT;"	
		 "iptables -A INPUT -i %s -j REJECT;", 
		 lan,
		 wan,
		 wan,
		 wan,
		 wan
		 );
	cmd(cmd_buff);
	return 0;
}

int firewall_final()
{
	cmd("iptables -F;iptables -P FORWARD ACCEPT;"
		"iptables -t filter -X syn_flood");
	
	return 0;
}


int config_init()
{
	char buffer[64] = {0};
	getfile_info(config_file, "wan", wan);
	getfile_info(config_file, "lan", lan);
	getfile_info(config_file, "report_flow_interval",buffer);
	report_flow_interval = atoi(buffer);
	memset(buffer, 0, sizeof(buffer));
	getfile_info(config_file, "log_level",buffer);
	log_leveljf = atoi(buffer);
	NETCTL_LOG(LOG_INFO, "wan=%s lan=%s interval=%d log_level=%d\n", wan, lan, report_flow_interval, log_leveljf);
	return 0;
}

int net_init()
{
	
	config_init();
	route_init();
	vlan_init();
	firewall_init();
	//statistic_init();
	return 0;
}

int main()
{
	int i = 0, ret = -1;
	sig_init();
	
	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
	if (ret == -1)
	{
		NETCTL_LOG(LOG_ERR,"sock err\n");
		return 0;
	}
	net_init();

	
	
	struct timeval tv;
	fd_set fds;
	int max_fd = 0;
	while (1) 
	{
		tv.tv_sec = 60;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(pipefd[0], &fds);
		if (pipefd[0] > max_fd)
		{
			max_fd = pipefd[0];
		}
		if (select(max_fd + 1, &fds, NULL, NULL, &tv) < 0) 
		{
			if (errno == EINTR || errno == EAGAIN)
			{
				continue;
			}
		}
		if (FD_ISSET(pipefd[0], &fds))
		{
			int signals[100];
			ret = recv(pipefd[0], signals, sizeof(signals), 0);
			if (ret > 0) 
			{
				for(i = 0; i < ret; i++)
				{
					switch(signals[i])
					{
					case SIGTERM:
					case SIGINT:
						//statistic_final();
						firewall_final();
						exit(0);
						break;
					}
				}
			}
		}
		timer_handler();
	}
	return 0;
}
