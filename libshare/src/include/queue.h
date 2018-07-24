#ifndef __CWMP_QUEUE_H__
#define __CWMP_QUEUE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"

typedef struct queue_item_st{
    void *arg;
    struct queue_item_st *next;
}queue_item_t;

typedef struct queue_head_st{
    queue_item_t *head;
    queue_item_t *tail;
    uint32 size;
    BOOL destroying;
	pthread_mutex_t mutex;
}queue_head_t;

static inline int32 queue_init(queue_head_t *queue)
{
    if (NULL == queue)
        return -1;
    queue->head = NULL;
    queue->tail = NULL;
    queue->size = 0;
    queue->destroying = FALSE;
    return 0;
}

static inline void queue_destroy(queue_head_t *queue)
{
    if (NULL != queue)
        return;
    queue->destroying = TRUE;
}

static inline BOOL queue_empty(queue_head_t *queue)
{
    return (0 == queue->size) ? TRUE : FALSE;
}

static inline int32 queue_enqueue(queue_head_t *queue,
                                  queue_item_t *item)
{
    if ((NULL == queue) || (TRUE == queue->destroying) || (NULL == item))
        return -1;
    item->next = NULL;
    if (0 != queue->size)
        queue->tail->next = item;
    else /*first item*/
        queue->head = item;
    queue->tail = item;
    ++(queue->size);
    return 0;
}

static inline queue_item_t *queue_dequeue(queue_head_t *queue)
{
    queue_item_t *item = NULL;
    if (queue->size > 0)
    {
        item = queue->head;
        --(queue->size);
        queue->head = item->next;
        if (0 == queue->size)
            queue->tail = NULL;
    }
    return item;
}


#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_QUEUE_H__*/
