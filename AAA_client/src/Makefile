CFLAGS= -Wall -Os 

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

all:radius_client
radacct: radacct.o
	$(CC) $(LDFLAGS) $(CFLAGS) radacct.o -lfreeradius-client -o radacct 

radius_client: radius_client.o 
	$(CC) $(LDFLAGS) $(CFLAGS) radius_client.o -lfreeradius-client -lipc -lshare -lpthread -o radius_client 

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o radius_client radacct