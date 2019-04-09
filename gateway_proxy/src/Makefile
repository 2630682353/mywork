CFLAGS= -Wall -Os 

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
GATEWAYOBJS=cpu.o timer.o gateway_proxy.o dpi.o
LOGLEVELOBJS=log_level.o

gateway_proxy: $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(GATEWAYOBJS) -o gateway_proxy -lipc -lshare -lcurl -lpthread
	$(CC) $(LDFLAGS) $(CFLAGS) $(LOGLEVELOBJS) -o log_level -lipc -lshare

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o gateway_proxy