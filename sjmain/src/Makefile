CFLAGS= -Wall -Os 

SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)
SJMAINOBJS=sjmain.o

sjmain: $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(SJMAINOBJS) -o sjmain  -lshare -lpthread -lcurl
	
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o sjmain