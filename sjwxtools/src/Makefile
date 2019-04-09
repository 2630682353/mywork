.PHONY:all clean

all: sjwxtool

LCFLAGS += -I./ -I../include
LCFLAGS += -DDEBUG
LLDFLAGS += -L../lib
LLDFLAGS += -lpcap -lpthread

sjwxtool: sjwxwifi/fp.c sjwxwifi/callpacket.c sjwxwifi/callpacket.h \
			sjwxcomm/sjwxcomm.c \
			sjwxmac/sjwxmac.c sjwxmac/sjwxmac.h \
			send.c
	$(CC) sjwxwifi/fp.c sjwxwifi/callpacket.c sjwxcomm/sjwxcomm.c sjwxmac/sjwxmac.c send.c $(LCFLAGS) $(LLDFLAGS) -o $@
	$(CC) -o sctl sctl.c

clean:
	rm -rf sjwxtool sctl *.o
	
