#include "timer.h"
#include <signal.h>

static LIST_HEAD(my_timer_list); 
static int timer_timeslot;
static pthread_mutex_t timer_mutex;

void timer_handler() {
	time_t cur = uptime();
	util_timer *p = NULL;
	util_timer *n = NULL;
	pthread_mutex_lock(&timer_mutex);
	list_for_each_entry_safe(p, n, &my_timer_list, list) {
		if (cur >= p->expire) {
			p->cb_func(p->para);
			if (!p->loop) {
				list_del(&p->list);
				if (p->para)
					free(p->para);
				free(p);
			}
			else {
				p->expire = cur + p->interval;
			}
		}
	}
	pthread_mutex_unlock(&timer_mutex);
}

util_timer *add_timer(int (*cb_func)(),int delay,int loop, int interval, void *para, int type) {
	util_timer *t = malloc(sizeof(util_timer));
	t->cb_func = cb_func;
	t->expire = uptime() + delay;
	t->interval = interval;
	t->loop = loop;
	t->para = para;
	t->timer_type = type;
	pthread_mutex_lock(&timer_mutex);
	list_add(&t->list, &my_timer_list);
	pthread_mutex_unlock(&timer_mutex);
	return t;
}

int del_timer(int type)
{
	util_timer *p = NULL;
	util_timer *n = NULL;
	pthread_mutex_lock(&timer_mutex);
	list_for_each_entry_safe(p, n, &my_timer_list, list) {
		if (p->timer_type == type) {
			list_del(&p->list);
			if (p->para)
				free(p->para);
			free(p);
		}			
	}
	pthread_mutex_unlock(&timer_mutex);
	return 0;
}

int timer_list_init()
{
	pthread_mutex_init(&timer_mutex, NULL);
	return 0;
}