CFLAGS= -Wall -Os -Iinclude
LDFLAGS = -L../../libshare/src


SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

netctl: $(OBJS)
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o netctl  -lpthread
	
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -rf .depfile *.o netctl
