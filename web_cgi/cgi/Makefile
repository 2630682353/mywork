
CC=arm-none-linux-gnueabi-gcc

hello.cgi:hello2.o session.o cJSON.o  connection.o cgi.o protocol.o ipc_msg.o upload.o
	${CC} -o hello.cgi hello2.c session.c cJSON.c  connection.c cgi.c protocol.c ipc_msg.c upload.c -lm -Os
	cp hello.cgi /home/work/clou2/clou/www/cgi-bin/
	tar -czvf /home/work/clou2/clou.tgz /home/work/clou2/clou
