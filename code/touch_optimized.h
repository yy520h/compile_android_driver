#ifndef TOUCH_OPTIMIZED_H
#define TOUCH_OPTIMIZED_H

#include <linux/input.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#define MAX_EVENTS 1024

struct ovo_touch_event {
    unsigned int type;
    unsigned int code;
    int value;
};

struct event_pool {
    struct ovo_touch_event events[MAX_EVENTS];
    unsigned long size;
    spinlock_t event_lock;
};

struct event_pool *get_event_pool(void);
struct input_dev *find_touch_device(void);
int input_event_cache(unsigned int type, unsigned int code, int value, struct event_pool *pool, int lock);
int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock);
int init_touch(void);
void exit_touch(void);

#endif
