.PHONY:all clean

all: minishell

LCFLAGS += -I./ -I../include
#LCFLAGS += -DDEBUG

minishell: minishell.c 
	$(CC) -o minishell minishell.c 
	$(STRIP) -s $@

clean:
	rm -rf minishell