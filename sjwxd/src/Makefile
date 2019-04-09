LCFLAGS += -I./ -I../include -DLINUX
LCFLAGS += -D VERSION=1				# 协议版本号，和枚举 PACKET_VERSION_E 一致
LCFLAGS += -DSELECT				# 客户端使用select代替libevent，提高可移植性
#LDLIBS += -levent
#LCFLAGS += -DDEBUG
#LCFLAGS += -DSELECTDEBUG
#LCFLAGS += -g
#LCFLAGS += -DPACKET_EVENT_DEBUG
#LCFLAGS += -DPACKETDEBUG
#LCFLAGS += -DDATA_EVENT_DEBUG
#LCFLAGS += -DDATADEBUG
LCFLAGS += -DNDEBUG		# 定义NDEBUG，用于屏蔽assert
LCFLAGS += -DMEMDEBUG
#LCFLAGS += -DDESTROYDEBUG
#LCFLAGS += -DDIFF_MAC_PER_CLIENT
#LCFLAGS += -DBUFF_SPARE_DEBUG
#LCFLAGS += -DTIME_DEBUG
LDFLAGS += -L../lib
LDLIBS += -lpthread

AFLAGS = $(LCFLAGS) $(LDFLAGS) $(LDLIBS)

all:
	$(CC) $(AFLAGS) -DCLIENT sjwxd.c -o sjwxdc
	$(CC) $(AFLAGS) -DSERVER sjwxd.c -o sjwxds
	$(CC) $(AFLAGS) -DCTLCMD sjwxd.c -o sjwxds_ctl
	
clean:
	rm -rf sjwxdc sjwxds sjwxds_ctl *.o core
	 
