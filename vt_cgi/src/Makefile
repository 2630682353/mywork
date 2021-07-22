CFLAGS= -Wall -Iinclude -Os
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

all: $(OBJS)
	$(CC) -o vt_cgi $(OBJS) $(CFLAGS) -lm -luci

sinclude .depfile
dep:
	$(CC) -MM $(CFLAGS) $(SRCS) > .depfile

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

clean:
	rm -rf .depfile *.o *.so vt_cgi
