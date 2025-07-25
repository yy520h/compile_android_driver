#include "touch_optimized.h"

static struct event_pool *pool = NULL;

static struct kprobe kp_input_event = {
    .symbol_name = "input_event"
};

static void handle_cache_events(struct input_dev *dev) {
    if (!pool->size) return;

    spin_lock(&dev->event_lock);
    for (int i = 0; i < pool->size; ++i) {
        struct ovo_touch_event event = pool->events[i];
        input_event(dev, event.type, event.code, event.value);
    }
    spin_unlock(&dev->event_lock);
    pool->size = 0;
}

static int input_event_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct input_dev *dev = (struct input_dev *)regs->regs[0];
    unsigned int type = (unsigned int)regs->regs[1];

    if (type == EV_SYN) {
        handle_cache_events(dev);
    }
    return 0;
}

struct input_dev *find_touch_device(void) {
    static struct input_dev *device = NULL;
    if (device) return device;

    struct input_dev *dev;
    struct list_head *input_dev_list = (struct list_head *)kallsyms_lookup_name("input_dev_list");
    struct mutex *input_mutex = (struct mutex *)kallsyms_lookup_name("input_mutex");

    if (!input_dev_list || !input_mutex) {
        printk(KERN_ERR "Failed to find symbols!\n");
        return NULL;
    }

    mutex_lock(input_mutex);
    list_for_each_entry(dev, input_dev_list, node) {
        if (test_bit(EV_ABS, dev->evbit) &&
            (test_bit(ABS_MT_POSITION_X, dev->absbit) || test_bit(ABS_X, dev->absbit))) {
            device = dev;
            break;
        }
    }
    mutex_unlock(input_mutex);
    return device;
}

struct event_pool *get_event_pool(void) {
    return pool;
}

int input_event_cache(unsigned int type, unsigned int code, int value, int lock) {
    if (!pool) return -EINVAL;
    if (lock) spin_lock(&pool->event_lock);
    if (pool->size >= MAX_EVENTS) {
        if (lock) spin_unlock(&pool->event_lock);
        return -EFAULT;
    }
    pool->events[pool->size++] = (struct ovo_touch_event){type, code, value};
    if (lock) spin_unlock(&pool->event_lock);
    return 0;
}

int input_mt_report_slot_state_cache(unsigned int tool_type, bool active, int lock) {
    struct input_dev *dev = find_touch_device();
    if (!dev || !dev->mt) return -EINVAL;

    if (!active) {
        input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, -1, lock);
        return 0;
    }

    struct input_mt_slot *slot = &dev->mt->slots[dev->mt->slot];
    int id = input_mt_get_value(slot, ABS_MT_TRACKING_ID);
    if (id < 0) id = input_mt_new_trkid(dev->mt);

    input_event_cache(EV_ABS, ABS_MT_TRACKING_ID, id, lock);
    input_event_cache(EV_ABS, ABS_MT_TOOL_TYPE, tool_type, lock);
    return id;
}

int init_touch(void) {
    int ret;

    pool = kmalloc(sizeof(struct event_pool), GFP_KERNEL);
    if (!pool) return -ENOMEM;
    pool->size = 0;
    spin_lock_init(&pool->event_lock);

    kp_input_event.pre_handler = input_event_handler_pre;
    ret = register_kprobe(&kp_input_event);
    if (ret) {
        kfree(pool);
        return ret;
    }

    return 0;
}

void exit_touch(void) {
    unregister_kprobe(&kp_input_event);
    if (pool) kfree(pool);
}
