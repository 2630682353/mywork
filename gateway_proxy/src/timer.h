#include "list.h"
#include <stdlib.h>
#include <time.h>

enum timer_type{
	TIMER_DEFAULT  = 0,
	DROPBEAR_TIMER = 1
};

typedef struct util_timer_st {
	time_t expire;
	int (*cb_func)(void *para);
	int loop;
	int interval;
	int timer_type;
	void *para;
	struct list_head list;
}util_timer;

extern void timer_handler();
extern util_timer *add_timer(int (*cb_func)(),int delay, int loop, int interval, void *para, int type);
extern int del_timer(int type);
extern int timer_list_init();