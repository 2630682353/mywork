CFLAGS=-Wall  -fPIC -Iinclude -Os



SRC=$(wildcard *.c)
OBJS=$(SRC:.c=.o)
DSTLIB=libshare.so




all:$(OBJS)
	$(CC) -o $(DSTLIB) -shared $^ $(CFLAGS) $(LDFLAGS) -luci -lubox -lpthread -lm
	$(STRIP) $(DSTLIB)

%.o:%.c
	$(CC) -c -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f *.o *.so 
