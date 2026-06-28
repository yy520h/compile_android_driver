#include <linux/module.h>
#include <linux/init.h>
#include "driver.h"

MODULE_LICENSE("GPL");

struct mem_tool_device *memdev = NULL;
dev_t mem_tool_dev_t = 0;
struct class *mem_tool_class = NULL;
const char *devicename = NULL;
char mod_obf_name[16] = "hidden_module";
rwlock_t pid_locks[LOCK_BUCKETS];
struct key_hook_state *key_info = NULL;
struct input_handler key_hook_handler;
atomic_t bound_dev_count = ATOMIC_INIT(0);
atomic_t target_bound_mask = ATOMIC_INIT(0);
struct touch_hook_state *touch_info = NULL;
struct input_dev *target_ts_dev = NULL;
int hw_min_x = 0, hw_max_x = 0, hw_min_y = 0, hw_max_y = 0;
int hw_screen_w = 0, hw_screen_h = 0;

static struct input_dev *original_ts_dev = NULL;

void print_touch_debug(const char *format, ...) {
    char buf[512];
    va_list args;
    int len;
    va_start(args, format);
    len = vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    if (len < 0) {
        printk(KERN_ERR "[qwq] vsnprintf failed\n");
        return;
    }
    if ((size_t)len >= sizeof(buf)) {
        printk(KERN_WARNING "[qwq] debug message truncated (%d chars)\n", len);
        buf[sizeof(buf) - 1] = '\0';
    }
    printk(KERN_INFO "[qwq] %s\n", buf);
}

/* ==================== 驱动层触摸拦截辅助函数 ==================== */


static void find_evdev_handle(struct input_dev *dev) {
    struct input_handle *h;
    if (!dev || !touch_info || touch_info->evdev_found)
        return;
    list_for_each_entry(h, &dev->h_list, d_node) {
        if (h->handler && h->handler->name && strcmp(h->handler->name, "evdev") == 0) {
            touch_info->evdev_handle = h;
            touch_info->evdev_found = true;
            print_touch_debug("找到 evdev handle: %s", h->name ? h->name : "null");
            break;
        }
    }
}

static bool check_obstacle(int px, int py) {
    int i;
    unsigned long flags;
    bool swallowed = false;
    spin_lock_irqsave(&touch_info->obstacle_lock, flags);
    for (i = 0; i < touch_info->obstacle_count; i++) {
        if (px >= touch_info->obstacles[i].x &&
            px <= touch_info->obstacles[i].x + touch_info->obstacles[i].w &&
            py >= touch_info->obstacles[i].y &&
            py <= touch_info->obstacles[i].y + touch_info->obstacles[i].h) {
            swallowed = true;
            break;
        }
    }
    spin_unlock_irqrestore(&touch_info->obstacle_lock, flags);
    return swallowed;
}

static void enqueue_intercepted(int slot, int x, int y, int action) {
    unsigned long flags;
    int next;
    spin_lock_irqsave(&touch_info->q_lock, flags);
    next = (touch_info->q_tail + 1) % INTERCEPT_QUEUE_SIZE;
    if (next == touch_info->q_head) {
        touch_info->q_head = (touch_info->q_head + 1) % INTERCEPT_QUEUE_SIZE;
    }
    touch_info->intercept_queue[touch_info->q_tail].slot = slot;
    touch_info->intercept_queue[touch_info->q_tail].x = x;
    touch_info->intercept_queue[touch_info->q_tail].y = y;
    touch_info->intercept_queue[touch_info->q_tail].action = action;
    touch_info->intercept_queue[touch_info->q_tail].timestamp = jiffies;
    touch_info->q_tail = next;
    spin_unlock_irqrestore(&touch_info->q_lock, flags);
    wake_up_interruptible(&touch_info->q_waitq);
}

static bool dequeue_intercepted(struct intercepted_touch *out) {
    unsigned long flags;
    bool ret = false;
    spin_lock_irqsave(&touch_info->q_lock, flags);
    if (touch_info->q_head != touch_info->q_tail) {
        *out = touch_info->intercept_queue[touch_info->q_head];
        touch_info->q_head = (touch_info->q_head + 1) % INTERCEPT_QUEUE_SIZE;
        ret = true;
    }
    spin_unlock_irqrestore(&touch_info->q_lock, flags);
    return ret;
}

/* ============================================================== */

static void cleanup_client_virtual_points(struct client_state *client) {
    unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
    int i, slot;
    bool need_btn_touch_reset = false;
    bool use_evh = (touch_info && touch_info->evdev_found && touch_info->evdev_handle);
    if (!client || !touch_info || !target_ts_dev) {
        print_touch_debug("cleanup_client_virtual_points: 无效参数");
        return;
    }
    release_client_hijacked_slots(client);
    print_touch_debug("强制清理客户端 %d (PID=%d) 的虚拟点，数量=%d",
                     client->client_id, client->pid, client->virtual_point_count);
    LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    for (slot = 0; slot < MAX_SLOTS; slot++) {
        if (touch_info->slots[slot].in_use &&
            touch_info->slots[slot].client_id == client->client_id) {
            print_touch_debug("清理槽位 %d (客户端 %d, 跟踪ID=%d)",
                             slot, client->client_id, touch_info->slots[slot].tracking_id);
            touch_info->virtual_touch_count--;
            touch_info->slots[slot].in_use = false;
            touch_info->slots[slot].tracking_id = -1;
            touch_info->slots[slot].x = -1;
            touch_info->slots[slot].y = -1;
            touch_info->slots[slot].client_id = -1;
            if (use_evh) {
                struct input_handle *evh = touch_info->evdev_handle;
                evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
                evh->handler->event(evh, EV_ABS, ABS_MT_TRACKING_ID, -1);
            } else {
                input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
                input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
            }
        }
    }
    if (touch_info->virtual_touch_count == 0 &&
        touch_info->physical_touch_count == 0) {
        need_btn_touch_reset = true;
        touch_info->virtual_touch_active = false;
    }
    if (touch_info->virtual_touch_count < 0) {
        touch_info->virtual_touch_count = 0;
    }
    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    if (use_evh) {
        struct input_handle *evh = touch_info->evdev_handle;
        if (need_btn_touch_reset) {
            evh->handler->event(evh, EV_KEY, BTN_TOUCH, 0);
            print_touch_debug("发送BTN_TOUCH=0（所有虚拟点清理 via evdev）");
        }
        evh->handler->event(evh, EV_SYN, SYN_REPORT, 0);
    } else {
        if (need_btn_touch_reset) {
            input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
            print_touch_debug("发送BTN_TOUCH=0（所有虚拟点清理）");
        }
        input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    }
    for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
        if (client->virtual_points[i].in_use) {
            print_touch_debug("清除客户端虚拟点记录[%d]: 槽位=%d",
                             i, client->virtual_points[i].slot);
            client->virtual_points[i].in_use = false;
            client->virtual_points[i].slot = -1;
            client->virtual_points[i].tracking_id = -1;
        }
    }
    client->virtual_point_count = 0;
    print_touch_debug("客户端 %d 虚拟点清理完成，剩余虚拟点数=%d", client->client_id, touch_info->virtual_touch_count);
}


static void release_client_hijacked_slots(struct client_state *client) {
    unsigned long flags;
    int slot;
    if (!client || !touch_info) {
        return;
    }
    spin_lock_irqsave(&touch_info->hijack_lock, flags);
    for (slot = 0; slot < MAX_SLOTS; slot++) {
        if (touch_info->slot_hijack[slot].hijacked &&
            touch_info->slot_hijack[slot].hijacker_client_id == client->client_id) {
            touch_info->slot_hijack[slot].hijacked = false;
            touch_info->slot_hijack[slot].hijacker_client_id = -1;
            print_touch_debug("客户端 %d 断开，释放 hijack slot %d", client->client_id, slot);
        }
    }
    spin_unlock_irqrestore(&touch_info->hijack_lock, flags);
}

static void heartbeat_timeout_callback(struct timer_list *timer) {
    struct client_heartbeat *hb = from_timer(hb, timer, heartbeat_timer);
    struct client_state *client;
    if (!hb || !touch_info) {
        print_touch_debug("心跳回调：参数无效");
        return;
    }
    client = hb->client;
    if (!client) {
        print_touch_debug("心跳回调：客户端无效");
        kfree(hb);
        return;
    }
    if (!hb->alive) {
        print_touch_debug("客户端 %d (PID=%d) 心跳超时，标记为退出", client->client_id, client->pid);
        client->exited = true;
        /* === 新增：心跳超时主动清理障碍物和虚拟点 === */
        if (touch_info) {
            unsigned long obs_flags;
            spin_lock_irqsave(&touch_info->obstacle_lock, obs_flags);
            touch_info->obstacle_count = 0;
            spin_unlock_irqrestore(&touch_info->obstacle_lock, obs_flags);
            print_touch_debug("心跳超时，清除所有障碍物");
        }
        cleanup_client_virtual_points(client);
    } else {
        hb->alive = false;
        hb->last_heartbeat = jiffies;
        mod_timer(&hb->heartbeat_timer, jiffies + msecs_to_jiffies(60000));
    }
}


static struct client_state* find_client_by_file(struct file *filp) {
    struct client_state *client;
    unsigned long flags;
    if (!filp || !touch_info) return NULL;
    spin_lock_irqsave(&touch_info->client_lock, flags);
    list_for_each_entry(client, &touch_info->client_list, list) {
        if (client->anon_file == filp) {
            spin_unlock_irqrestore(&touch_info->client_lock, flags);
            return client;
        }
    }
    spin_unlock_irqrestore(&touch_info->client_lock, flags);
    return NULL;
}

static struct client_state* find_client_by_pid(pid_t pid) {
    struct client_state *client;
    unsigned long flags;
    if (!touch_info) return NULL;
    spin_lock_irqsave(&touch_info->client_lock, flags);
    list_for_each_entry(client, &touch_info->client_list, list) {
        if (client->pid == pid) {
            spin_unlock_irqrestore(&touch_info->client_lock, flags);
            return client;
        }
    }
    spin_unlock_irqrestore(&touch_info->client_lock, flags);
    return NULL;
}

static struct client_state* create_client(pid_t pid, uid_t uid, struct file *filp) {
    struct client_state *client;
    unsigned long flags;
    int i;
    struct client_state *existing_client;
    int slot;
    int tracking_id;
    bool slot_in_use;
    int slot_client_id;
    bool need_btn_touch_reset;
    struct client_heartbeat *hb;
    existing_client = find_client_by_pid(pid);
    if (existing_client) {
        print_touch_debug("已存在PID=%d的客户端，强制清理旧连接", pid);
        existing_client->exited = true;
        if (existing_client->heartbeat) {
            del_timer_sync(&existing_client->heartbeat->heartbeat_timer);
            kfree(existing_client->heartbeat);
            existing_client->heartbeat = NULL;
        }
        for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
            if (existing_client->virtual_points[i].in_use) {
                slot = existing_client->virtual_points[i].slot;
                tracking_id = existing_client->virtual_points[i].tracking_id;
                print_touch_debug("清理旧客户端虚拟点[%d]：槽位=%d, ID=%d",
                                 i, slot, tracking_id);
                if (slot >= 0 && slot < MAX_SLOTS && target_ts_dev) {
                    unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
                    LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    slot_in_use = touch_info->slots[slot].in_use;
                    slot_client_id = touch_info->slots[slot].client_id;
                    if (slot_in_use && slot_client_id == existing_client->client_id) {
                        need_btn_touch_reset = false;
                        touch_info->virtual_touch_count--;
                        if (touch_info->virtual_touch_count <= 0) {
                            touch_info->virtual_touch_count = 0;
                            touch_info->virtual_touch_active = false;
                        }
                        if (touch_info->virtual_touch_count == 0 &&
                            touch_info->physical_touch_count == 0) {
                            need_btn_touch_reset = true;
                        }
                        touch_info->slots[slot].in_use = false;
                        touch_info->slots[slot].tracking_id = -1;
                        touch_info->slots[slot].x = -1;
                        touch_info->slots[slot].y = -1;
                        touch_info->slots[slot].client_id = -1;
                        UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                        if (touch_info->evdev_found && touch_info->evdev_handle) {
                            struct input_handle *evh = touch_info->evdev_handle;
                            evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
                            evh->handler->event(evh, EV_ABS, ABS_MT_TRACKING_ID, -1);
                            if (need_btn_touch_reset) {
                                evh->handler->event(evh, EV_KEY, BTN_TOUCH, 0);
                                print_touch_debug("发送BTN_TOUCH=0（清理旧客户端 via evdev）");
                            }
                            evh->handler->event(evh, EV_SYN, SYN_REPORT, 0);
                        } else {
                            input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
                            input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                            if (need_btn_touch_reset) {
                                input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
                                print_touch_debug("发送BTN_TOUCH=0（清理旧客户端）");
                            }
                            input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
                        }
                        print_touch_debug("清理旧客户端槽位：槽位=%d, ID=%d, 剩余虚拟点=%d",
                            slot, tracking_id, touch_info->virtual_touch_count);
                    } else {
                        UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    }
                }
                existing_client->virtual_points[i].in_use = false;
                existing_client->virtual_points[i].slot = -1;
                existing_client->virtual_points[i].tracking_id = -1;
            }
        }
        existing_client->virtual_point_count = 0;
        remove_client(existing_client);
        release_client_hijacked_slots(existing_client);
        kfree(existing_client);
    }
    client = kzalloc(sizeof(struct client_state), GFP_KERNEL);
    if (!client) {
        print_touch_debug("分配客户端结构失败");
        return NULL;
    }
    INIT_LIST_HEAD(&client->list);
    client->pid = pid;
    client->uid = uid;
    client->anon_file = filp;
    client->ref_count = 1;
    client->exited = false;
    spin_lock_irqsave(&touch_info->client_lock, flags);
    client->client_id = touch_info->next_client_id++;
    list_add_tail(&client->list, &touch_info->client_list);
    spin_unlock_irqrestore(&touch_info->client_lock, flags);
    for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
        client->virtual_points[i].in_use = false;
        client->virtual_points[i].slot = -1;
        client->virtual_points[i].tracking_id = -1;
    }
    client->virtual_point_count = 0;
    hb = kzalloc(sizeof(struct client_heartbeat), GFP_KERNEL);
    if (hb) {
        hb->client = client;
        hb->alive = true;
        hb->last_heartbeat = jiffies;
        timer_setup(&hb->heartbeat_timer, heartbeat_timeout_callback, 0);
        mod_timer(&hb->heartbeat_timer, jiffies + msecs_to_jiffies(60000));
        client->heartbeat = hb;
        print_touch_debug("为客户端 %d (PID=%d) 启动心跳检测",
                         client->client_id, pid);
    } else {
        print_touch_debug("分配心跳结构失败，将继续创建客户端");
        client->heartbeat = NULL;
    }
    print_touch_debug("创建客户端成功: ID=%d, PID=%d, UID=%d",
                     client->client_id, pid, uid);
    return client;
}

static void remove_client(struct client_state *client) {
    unsigned long flags;
    if (!client) {
        print_touch_debug("remove_client: 客户端为空");
        return;
    }
    print_touch_debug("从客户端列表移除: ID=%d, PID=%d", client->client_id, client->pid);
    if (client->heartbeat) {
        del_timer_sync(&client->heartbeat->heartbeat_timer);
        kfree(client->heartbeat);
        client->heartbeat = NULL;
    }
    spin_lock_irqsave(&touch_info->client_lock, flags);
    list_del(&client->list);
    spin_unlock_irqrestore(&touch_info->client_lock, flags);
}

static void touch_down(int slot, int x, int y, struct client_state *client) {
    unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
    int tracking_id;
    bool need_btn_touch = false;
    int old_virtual_count;
    int client_slot = -1;
    int i;
    if (!client) {
        print_touch_debug("触摸按下失败：客户端无效");
        return;
    }
    if (client->exited) {
        print_touch_debug("触摸按下失败：客户端 %d 已退出", client->client_id);
        return;
    }
    if (client->heartbeat && !client->heartbeat->alive) {
        print_touch_debug("触摸按下失败：客户端 %d 心跳异常", client->client_id);
        return;
    }
    if (slot < 0 || slot >= MAX_SLOTS) {
        print_touch_debug("触摸按下失败：无效槽位=%d", slot);
        return;
    }
    if (client && client->virtual_point_count >= MAX_SLOTS_PER_CLIENT) {
        print_touch_debug("客户端已达到最大虚拟点数限制");
        return;
    }
    LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    if (touch_info->slots[slot].in_use) {
        UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
        print_touch_debug("触摸按下失败：槽位=%d 已被占用", slot);
        return;
    }
    tracking_id = ++touch_info->next_tracking_id;
    touch_info->slots[slot].in_use = true;
    touch_info->slots[slot].x = x;
    touch_info->slots[slot].y = y;
    touch_info->slots[slot].tracking_id = tracking_id;
    touch_info->slots[slot].client_id = client ? client->client_id : -1;
    touch_info->slots[slot].down_jiffies = jiffies + msecs_to_jiffies(60000);
    old_virtual_count = touch_info->virtual_touch_count;
    touch_info->virtual_touch_count++;
    touch_info->virtual_touch_active = true;
    if (old_virtual_count == 0 && touch_info->physical_touch_count == 0) {
        need_btn_touch = true;
    }
    if (client) {
        for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
            if (!client->virtual_points[i].in_use) {
                client->virtual_points[i].in_use = true;
                client->virtual_points[i].slot = slot;
                client->virtual_points[i].tracking_id = tracking_id;
                client->virtual_points[i].x = x;
                client->virtual_points[i].y = y;
                client->virtual_point_count++;
                client_slot = i;
                break;
            }
        }
    }
    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    if (touch_info && touch_info->evdev_found && touch_info->evdev_handle) {
        struct input_handle *evh = touch_info->evdev_handle;
        evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
        evh->handler->event(evh, EV_ABS, ABS_MT_TRACKING_ID, tracking_id);
        evh->handler->event(evh, EV_ABS, ABS_MT_POSITION_X, x);
        evh->handler->event(evh, EV_ABS, ABS_MT_POSITION_Y, y);
        evh->handler->event(evh, EV_ABS, ABS_MT_PRESSURE, 1);
        evh->handler->event(evh, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
        evh->handler->event(evh, EV_ABS, ABS_MT_TOOL_TYPE, 0);
        if (need_btn_touch) {
            evh->handler->event(evh, EV_KEY, BTN_TOUCH, 1);
            print_touch_debug("发送BTN_TOUCH=1 (via evdev)");
        }
        evh->handler->event(evh, EV_SYN, SYN_REPORT, 0);
    } else {
        input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
        input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, tracking_id);
        input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, x);
        input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, y);
        input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
        input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
        input_event(target_ts_dev, EV_ABS, ABS_MT_TOOL_TYPE, 0);
        if (need_btn_touch) {
            input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 1);
            print_touch_debug("发送BTN_TOUCH=1");
        }
        input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    }
    print_touch_debug("虚拟触摸按下：客户端=%d, 槽位=%d, ID=%d, 坐标=(%d,%d), 虚拟点数=%d",
        client ? client->client_id : -1, slot, tracking_id, x, y,
        touch_info->virtual_touch_count);
    if (!timer_pending(&touch_info->auto_up_timer))
        mod_timer(&touch_info->auto_up_timer, jiffies + msecs_to_jiffies(500));
}

static void touch_up(int slot, struct client_state *client) {
    unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
    int tracking_id = -1;
    bool need_btn_touch_reset = false;
    bool was_in_use = false;
    bool owned_by_client = false;
    int i;
    if (slot < 0 || slot >= MAX_SLOTS || !target_ts_dev)
        return;
    LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    was_in_use = touch_info->slots[slot].in_use;
    tracking_id = touch_info->slots[slot].tracking_id;
    if (was_in_use) {
        if (!client || touch_info->slots[slot].client_id == client->client_id) {
            owned_by_client = true;
            touch_info->virtual_touch_count--;
            if (touch_info->virtual_touch_count <= 0) {
                touch_info->virtual_touch_count = 0;
                touch_info->virtual_touch_active = false;
            }
            if (touch_info->virtual_touch_count == 0 &&
                touch_info->physical_touch_count == 0) {
                need_btn_touch_reset = true;
            }
            if (client) {
                for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
                    if (client->virtual_points[i].in_use &&
                        client->virtual_points[i].slot == slot) {
                        client->virtual_points[i].in_use = false;
                        client->virtual_points[i].slot = -1;
                        client->virtual_points[i].tracking_id = -1;
                        client->virtual_point_count--;
                        if (client->virtual_point_count < 0)
                            client->virtual_point_count = 0;
                        break;
                    }
                }
            }
            touch_info->slots[slot].in_use = false;
            touch_info->slots[slot].tracking_id = -1;
            touch_info->slots[slot].x = -1;
            touch_info->slots[slot].y = -1;
            touch_info->slots[slot].client_id = -1;
            touch_info->slots[slot].down_jiffies = 0;
        }
    }
    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    if (touch_info && touch_info->evdev_found && touch_info->evdev_handle) {
        struct input_handle *evh = touch_info->evdev_handle;
        evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
        evh->handler->event(evh, EV_ABS, ABS_MT_TRACKING_ID, -1);
        if (need_btn_touch_reset) {
            evh->handler->event(evh, EV_KEY, BTN_TOUCH, 0);
            print_touch_debug("发送BTN_TOUCH=0 (via evdev)");
        }
        evh->handler->event(evh, EV_SYN, SYN_REPORT, 0);
    } else {
        input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
        input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
        if (need_btn_touch_reset) {
            input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
            print_touch_debug("发送BTN_TOUCH=0");
        }
        input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    }
    if (was_in_use && owned_by_client) {
        print_touch_debug("虚拟触摸抬起：客户端=%d, 槽位=%d, ID=%d, 剩余=%d",
            client ? client->client_id : -1, slot, tracking_id,
            touch_info->virtual_touch_count);
    }
}

static void touch_auto_up_callback(struct timer_list *timer) {
    int slot;
    int idx;
    int expired_count;
    int expired_slots[MAX_SLOTS];
    int expired_clients[MAX_SLOTS];
    unsigned long flags;
    unsigned long now;
    if (!touch_info || !target_ts_dev)
        return;
    now = jiffies;
    expired_count = 0;
    spin_lock_irqsave(&touch_info->auto_up_lock, flags);
    for (slot = 0; slot < MAX_SLOTS; slot++) {
        if (touch_info->slots[slot].in_use &&
            touch_info->slots[slot].down_jiffies != 0 &&
            time_after(now, touch_info->slots[slot].down_jiffies)) {
            expired_slots[expired_count] = slot;
            expired_clients[expired_count] =
                touch_info->slots[slot].client_id;
            expired_count++;
        }
    }
    spin_unlock_irqrestore(&touch_info->auto_up_lock, flags);
    for (idx = 0; idx < expired_count; idx++) {
        struct client_state *cs = NULL;
        int cid = expired_clients[idx];
        int sl = expired_slots[idx];
        if (cid >= 0) {
            unsigned long cflags;
            struct client_state *c;
            spin_lock_irqsave(&touch_info->client_lock, cflags);
            list_for_each_entry(c, &touch_info->client_list, list) {
                if (c->client_id == cid) {
                    cs = c;
                    break;
                }
            }
            spin_unlock_irqrestore(&touch_info->client_lock, cflags);
        }
        touch_up(sl, cs);
    }
    if (expired_count > 0 || touch_info->virtual_touch_active)
        mod_timer(&touch_info->auto_up_timer,
                  jiffies + msecs_to_jiffies(500));
}

static void touch_move(int slot, int x, int y, struct client_state *client) {
    unsigned long flags_physical, flags_virtual, flags_slots;
    unsigned long now;
    bool slot_in_use;
    int slot_client_id;
    if (slot < 0 || slot >= MAX_SLOTS || !target_ts_dev)
        return;
    LOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);
    slot_in_use = touch_info->slots[slot].in_use;
    slot_client_id = touch_info->slots[slot].client_id;
    if (!slot_in_use) {
        UNLOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);
        return;
    }
    if (client && slot_client_id != client->client_id) {
        UNLOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);
        return;
    }
    now = jiffies;
    if (touch_info->slots[slot].down_jiffies != 0 &&
        time_after(now + msecs_to_jiffies(200),
                   touch_info->slots[slot].down_jiffies)) {
        UNLOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);
        return;
    }
    touch_info->slots[slot].x = x;
    touch_info->slots[slot].y = y;
    UNLOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);
    if (touch_info && touch_info->evdev_found && touch_info->evdev_handle) {
        struct input_handle *evh = touch_info->evdev_handle;
        evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
        evh->handler->event(evh, EV_ABS, ABS_MT_POSITION_X, x);
        evh->handler->event(evh, EV_ABS, ABS_MT_POSITION_Y, y);
        evh->handler->event(evh, EV_ABS, ABS_MT_PRESSURE, 1);
        evh->handler->event(evh, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
        evh->handler->event(evh, EV_SYN, SYN_REPORT, 0);
    } else {
        input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
        input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, x);
        input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, y);
        input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
        input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
        input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    }
}

static int input_mt_reinit_slots(struct input_dev *dev, unsigned int new_num_slots) {
    int ret;
    struct input_dev *new_dev;
    const struct input_absinfo *abs_x, *abs_y;
    int i;
    if (!dev || !dev->mt) {
        print_touch_debug("无效设备或mt未初始化\n");
        return -EINVAL;
    }
    print_touch_debug("开始重初始化设备: %s, slots: %d -> %d\n", dev->name, dev->mt->num_slots, new_num_slots);
    if (new_num_slots > 32) {
        print_touch_debug("新slot数量过大: %d\n", new_num_slots);
        return -EINVAL;
    }
    if (!original_ts_dev) {
        original_ts_dev = dev;
        print_touch_debug("备份原始设备指针: %s\n", dev->name);
    }
    abs_x = &dev->absinfo[ABS_MT_POSITION_X];
    abs_y = &dev->absinfo[ABS_MT_POSITION_Y];
    new_dev = input_allocate_device();
    if (!new_dev) {
        print_touch_debug("分配新input_dev失败\n");
        return -ENOMEM;
    }
    new_dev->name = kstrdup(dev->name, GFP_KERNEL);
    if (!new_dev->name) {
        input_free_device(new_dev);
        return -ENOMEM;
    }
    new_dev->id = dev->id;
    if (dev->phys)
        new_dev->phys = kstrdup(dev->phys, GFP_KERNEL);
    if (dev->uniq)
        new_dev->uniq = kstrdup(dev->uniq, GFP_KERNEL);
    memcpy(new_dev->evbit, dev->evbit, sizeof(dev->evbit));
    memcpy(new_dev->keybit, dev->keybit, sizeof(dev->keybit));
    memcpy(new_dev->absbit, dev->absbit, sizeof(dev->absbit));
    memcpy(new_dev->relbit, dev->relbit, sizeof(dev->relbit));
    input_set_abs_params(new_dev, ABS_MT_SLOT, 0, new_num_slots - 1, 0, 0);
    input_set_abs_params(new_dev, ABS_MT_TRACKING_ID, -1, new_num_slots, 0, 0);
    input_set_abs_params(new_dev, ABS_MT_POSITION_X, abs_x->minimum, abs_x->maximum, abs_x->fuzz, abs_x->flat);
    input_set_abs_params(new_dev, ABS_MT_POSITION_Y, abs_y->minimum, abs_y->maximum, abs_y->fuzz, abs_y->flat);
    for (i = 0; i < ABS_CNT; i++) {
        if (test_bit(i, dev->absbit) &&
            i != ABS_MT_SLOT && i != ABS_MT_TRACKING_ID &&
            i != ABS_MT_POSITION_X && i != ABS_MT_POSITION_Y) {
            const struct input_absinfo *abs = &dev->absinfo[i];
            input_set_abs_params(new_dev, i, abs->minimum, abs->maximum, abs->fuzz, abs->flat);
        }
    }
    input_unregister_device(dev);
    print_touch_debug("The original device has been deregistered and is waiting to be re-registered..\n");
    msleep(200);
    ret = input_register_device(new_dev);
    if (ret) {
        print_touch_debug("Failed to register new device: %d! The framework may not be able to automatically recover.\n", ret);
        input_free_device(new_dev);
        return ret;
    }
    target_ts_dev = new_dev;
    if (touch_info && touch_info->ts_handle) {
        touch_info->ts_handle->dev = new_dev;
    }
    print_touch_debug("Device re-registration successful, new slot count: %d, the framework will recognize it automatically\n", new_num_slots);
    return 0;
}

static phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    spinlock_t *ptl;
    phys_addr_t page_addr = 0;
    uintptr_t page_offset;
    struct page *page = NULL;
    int ret;
retry:
    spin_lock(&mm->page_table_lock);
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) goto out_unlock;
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) goto out_unlock;
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) goto out_unlock;
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) goto out_unlock;
    if (pmd_bad(*pmd)) goto out_unlock;
    if (pmd_trans_huge(*pmd)) {
        page_addr = (phys_addr_t)pmd_pfn(*pmd) << PAGE_SHIFT;
        page_offset = va & ~PAGE_MASK;
        spin_unlock(&mm->page_table_lock);
        return page_addr + page_offset;
    }
    pte = pte_offset_map_lock(mm, pmd, va, &ptl);
    if (!pte) goto out_unlock;
    if (!pte_present(*pte)) {
        pte_unmap_unlock(pte, ptl);
        spin_unlock(&mm->page_table_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        down_read(&mm->mmap_lock);
        ret = get_user_pages_remote(mm, va, 1, FOLL_FORCE, &page, NULL);
        up_read(&mm->mmap_lock);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        down_read(&mm->mmap_lock);
        ret = get_user_pages_remote(mm, va, 1, FOLL_FORCE, &page, NULL, NULL);
        up_read(&mm->mmap_lock);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
        down_read(&mm->mmap_sem);
        ret = get_user_pages_remote(mm, va, 1, FOLL_FORCE, &page, NULL, NULL);
        up_read(&mm->mmap_sem);
#else
        down_read(&mm->mmap_sem);
        ret = get_user_pages_remote(NULL, mm, va, 1, FOLL_FORCE, &page, NULL, NULL);
        up_read(&mm->mmap_sem);
#endif
        if (ret <= 0) {
            printk(KERN_ERR "[qwq] get_user_pages failed: %d\n", ret);
            return 0;
        }
        put_page(page);
        goto retry;
    }
    page_addr = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
    page_offset = va & (PAGE_SIZE - 1);
    pte_unmap_unlock(pte, ptl);
    spin_unlock(&mm->page_table_lock);
    return page_addr + page_offset;
out_unlock:
    spin_unlock(&mm->page_table_lock);
    return 0;
}

static bool safe_rw_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size, bool is_write) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    void *va;
    size_t offset, chunk;
    bool result = true;
    unsigned long irq_flags;
    rwlock_t *lock;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return false;
    }
    get_task_struct(task);
    rcu_read_unlock();
    mm = get_task_mm(task);
    if (!mm) goto put_task;
    lock = lock_for_pid(pid);
    if (is_write)
        write_lock_irqsave(lock, irq_flags);
    else
        read_lock_irqsave(lock, irq_flags);
    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        if (!pa) {
            printk(KERN_ERR "[qwq] 地址转换失败: 0x%lx\n", addr);
            result = false;
            break;
        }
        if (!pfn_valid(__phys_to_pfn(pa))) {
            printk(KERN_ERR "[qwq] 无效物理地址: 0x%llx\n", (unsigned long long)pa);
            result = false;
            break;
        }
        va = phys_to_virt(pa);
        if (!va) {
            printk(KERN_ERR "[qwq] phys_to_virt 失败: 0x%llx\n", (unsigned long long)pa);
            result = false;
            break;
        }
        offset = addr & (PAGE_SIZE - 1);
        chunk = min_t(size_t, PAGE_SIZE - offset, size);
        if (is_write) {
            if (copy_from_user(va, user_buffer, chunk)) {
                result = false;
                break;
            }
            smp_wmb();
        } else {
            smp_rmb();
            if (copy_to_user(user_buffer, va, chunk)) {
                result = false;
                break;
            }
        }
        user_buffer += chunk;
        addr += chunk;
        size -= chunk;
    }
    if (is_write)
        write_unlock_irqrestore(lock, irq_flags);
    else
        read_unlock_irqrestore(lock, irq_flags);
    mmput(mm);
put_task:
    put_task_struct(task);
    return result;
}

static bool read_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size) {
    return safe_rw_memory(pid, addr, user_buffer, size, false);
}

static bool write_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size) {
    return safe_rw_memory(pid, addr, user_buffer, size, true);
}

uintptr_t get_module_base(pid_t pid, const char *name) {
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    struct vm_area_struct *vma = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    struct vma_iterator vmi;
#endif
    char buf[256];
    char *path_nm = NULL;
    uintptr_t base = 0;
    bool found = false;
    bool task_acquired = false;
    bool mm_acquired = false;
    if (!name || strlen(name) == 0) {
        pr_err("[qwq] 模块名为空\n");
        return 0;
    }
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        pr_err("[qwq] 进程 %d 不存在\n", pid);
        return 0;
    }
    if (!get_task_struct(task)) {
        rcu_read_unlock();
        return 0;
    }
    task_acquired = true;
    rcu_read_unlock();
    mm = get_task_mm(task);
    if (!mm) {
        goto cleanup;
    }
    mm_acquired = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    down_read(&mm->mmap_lock);
#else
    down_read(&mm->mmap_sem);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    vma_iter_init(&vmi, mm, 0);
    vma = vma_next(&vmi);
    while (vma != NULL) {
#else
    vma = mm->mmap;
    while (vma != NULL) {
#endif
        if (!vma->vm_file) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
            vma = vma_next(&vmi);
#else
            vma = vma->vm_next;
#endif
            continue;
        }
        path_nm = d_path(&vma->vm_file->f_path, buf, sizeof(buf)-1);
        if (IS_ERR(path_nm)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
            vma = vma_next(&vmi);
#else
            vma = vma->vm_next;
#endif
            continue;
        }
        if (strstr(path_nm, name)) {
            base = vma->vm_start;
            found = true;
            if (base == 0x8000) {
                pr_info("[qwq] 检测到 PIE 基址 0x8000，调整为 0\n");
                base = 0;
            }
            pr_info("[qwq] 找到模块 %s 基址: 0x%lx (来自 %s)\n",
                    name, base, path_nm);
            break;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        vma = vma_next(&vmi);
#else
        vma = vma->vm_next;
#endif
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    up_read(&mm->mmap_lock);
#else
    up_read(&mm->mmap_sem);
#endif
cleanup:
    if (mm_acquired)
        mmput(mm);
    if (task_acquired)
        put_task_struct(task);
    return base;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
pid_t get_process_pid(const char *comm) {
    struct task_struct *task = NULL;
    pid_t tgid = 0;
    char buf[TASK_COMM_LEN] = {0};
    if (!comm || strlen(comm) == 0) {
        print_touch_debug("获取PID: 进程名为空");
        return 0;
    }
    rcu_read_lock();
    for_each_process(task) {
        get_task_comm(buf, task);
        if (strstr(buf, comm)) {
            tgid = task_tgid_vnr(task);
            print_touch_debug("找到进程: %s -> PID=%d", comm, tgid);
            break;
        }
    }
    rcu_read_unlock();
    if (!tgid) {
        print_touch_debug("未找到进程: %s", comm);
    }
    return tgid;
}
#else
pid_t get_process_pid(const char *comm) {
    struct task_struct *task;
    pid_t tgid = 0;
    size_t comm_len = strlen(comm);
    if (!comm || comm_len == 0 || comm_len > TASK_COMM_LEN) {
        print_touch_debug("获取PID: 进程名无效（空或过长）");
        return 0;
    }
    rcu_read_lock();
    for_each_process(task) {
        if (task->state == TASK_DEAD || !pid_task(find_vpid(task->tgid), PIDTYPE_PID)) {
            continue;
        }
        if (strncmp(task->comm, comm, TASK_COMM_LEN) == 0) {
            tgid = task_tgid_vnr(task);
            print_touch_debug("找到进程: %s -> PID=%d", comm, tgid);
            break;
        }
    }
    rcu_read_unlock();
    if (!tgid) {
        print_touch_debug("未找到进程: %s", comm);
    }
    return tgid;
}
#endif

static char* get_rand_str(void) {
    static char string[9];
    const char *str = "9k7Qn3WzjxUYV0dRf5c1bGp4EsHwTrMhS6XlN-tFymoZDvKuPiedIOC_";
    int lstr = strlen(str);
    int i;
    for (i = 0; i < 8; i++) {
        int seed, flag;
        get_random_bytes(&seed, sizeof(int));
        flag = abs(seed % lstr);
        string[i] = str[flag];
    }
    string[8] = '\0';
    return string;
}

static void add_key_event(int trp, int key_code) {
    struct event_node *node;
    unsigned long flags;
    int current_count;
    if (trp == 0 && key_code != 0) {
        return;
    }
    if (key_info->event_count >= EVENT_QUEUE_SIZE) {
        return;
    }
    node = kmalloc(sizeof(struct event_node), GFP_ATOMIC);
    if (!node) {
        return;
    }
    node->event.trp = trp;
    node->event.key_code = key_code;
    spin_lock_irqsave(&key_info->lock, flags);
    list_add_tail(&node->list, &key_info->event_list);
    key_info->event_count++;
    current_count = key_info->event_count;
    spin_unlock_irqrestore(&key_info->lock, flags);
}

static bool get_user_event(USER_EVENT *event) {
    struct event_node *node;
    unsigned long flags;
    spin_lock_irqsave(&key_info->lock, flags);
    if (list_empty(&key_info->event_list)) {
        spin_unlock_irqrestore(&key_info->lock, flags);
        return false;
    }
    node = list_first_entry(&key_info->event_list, struct event_node, list);
    *event = node->event;
    list_del(&node->list);
    kfree(node);
    key_info->event_count--;
    spin_unlock_irqrestore(&key_info->lock, flags);
    return true;
}

static void restart_system_server_secure(void) {
    struct task_struct *tsk;
    struct task_struct *target_task = NULL;
    pid_t target_pid = 0;
    uid_t dynamic_uid = 0;
    kuid_t kuid_to_match;
    int name_match_count = 0;
    rcu_read_lock();
    for_each_process(tsk) {
        if (!strcmp(tsk->comm, "system_server")) {
            target_task = tsk;
            target_pid = tsk->pid;
            kuid_to_match = task_uid(tsk);
            dynamic_uid = from_kuid(current_user_ns(), kuid_to_match);
            name_match_count++;
        }
    }
    rcu_read_unlock();
    if (name_match_count == 0) {
        print_touch_debug("未找到 system_server 进程\n");
        return;
    }
    if (name_match_count > 1) {
        print_touch_debug("警告：找到 %d 个同名进程，将重启 UID=%d 的\n", name_match_count, dynamic_uid);
    }
    rcu_read_lock();
    for_each_process(tsk) {
        if (!strcmp(tsk->comm, "system_server") &&
            uid_eq(task_uid(tsk), kuid_to_match)) {
            get_task_struct(tsk);
            send_sig_info(SIGKILL, SEND_SIG_PRIV, tsk);
            print_touch_debug("已重启system_server: PID=%d, UID=%d\n", tsk->pid, dynamic_uid);
            put_task_struct(tsk);
            break;
        }
    }
    rcu_read_unlock();
}

static DEFINE_MUTEX(mt_replace_lock);

static int key_hook_connect(struct input_handler *handler, struct input_dev *dev, const struct input_device_id *id) {
    struct input_handle *handle;
    int ret, i, dev_index = -1;
    bool is_target = false;
    unsigned int mask;
    const struct input_absinfo *abs_x;
    const struct input_absinfo *abs_y;
    struct device_node *node;
    u32 val;
    int fb_width, fb_height;
    int old_slots;
    int new_slots;
    size_t old_size;
    size_t new_size;
    struct input_mt *new_mt;
    if (!dev || !dev->name)
        return -ENODEV;
    if (strstr(dev->name, "NVTCapacitiveTouchScreen")) {
        if (!target_ts_dev) {
            target_ts_dev = dev;
            get_device(&dev->dev);
            print_touch_debug("触摸屏捕获：%s\n", dev->name);
            handle = kzalloc(sizeof(*handle), GFP_KERNEL);
            if (!handle) {
                print_touch_debug("分配触摸屏handle失败\n");
                return -ENOMEM;
            }
            handle->dev = dev;
            handle->handler = handler;
            handle->name = "touch_hook";
            ret = input_register_handle(handle);
            if (ret) {
                print_touch_debug("注册触摸屏handle失败: %d\n", ret);
                kfree(handle);
                return ret;
            }
            ret = input_open_device(handle);
            if (ret) {
                print_touch_debug("打开触摸屏设备失败: %d\n", ret);
                input_unregister_handle(handle);
                kfree(handle);
                return ret;
            }
            touch_info->ts_handle = handle;
            print_touch_debug("触摸屏handle注册成功\n");
            /* === 独占物理设备 + 查找 evdev handle === */
            mutex_lock(&dev->mutex);
            if (dev->grab) {
                mutex_unlock(&dev->mutex);
                print_touch_debug("设备已被其他 handle 独占，拒绝绑定");
                input_close_device(handle);
                input_unregister_handle(handle);
                kfree(handle);
                put_device(&dev->dev);
                target_ts_dev = NULL;
                return -EBUSY;
            }
            rcu_assign_pointer(dev->grab, handle);
            mutex_unlock(&dev->mutex);
            print_touch_debug("已独占触摸屏设备");
            find_evdev_handle(dev);

            /* ======================================== */
            mutex_lock(&mt_replace_lock);
            old_slots = dev->mt->num_slots;
            new_slots = old_slots + 3;
            old_size = sizeof(struct input_mt) + old_slots * sizeof(struct input_mt_slot);
            new_size = sizeof(struct input_mt) + new_slots * sizeof(struct input_mt_slot);
            new_mt = kzalloc(new_size, GFP_KERNEL);
            if (!new_mt) {
                print_touch_debug("扩 mt 内存失败\n");
            } else {
                memcpy(new_mt, dev->mt, old_size);
                new_mt->num_slots = new_slots;
                memset(&new_mt->slots[old_slots], 0, 3 * sizeof(struct input_mt_slot));
                kfree(dev->mt);
                dev->mt = new_mt;
                dev->absinfo[ABS_MT_SLOT].maximum = new_slots - 1;
                print_touch_debug("slot 已扩大 %d -> %d，安全区 %d-%d\n",
                       old_slots, new_slots, old_slots, new_slots-1);
            }
            mutex_unlock(&mt_replace_lock);
            abs_x = &dev->absinfo[ABS_MT_POSITION_X];
            abs_y = &dev->absinfo[ABS_MT_POSITION_Y];
            node = dev->dev.of_node;
            hw_min_x = abs_x->minimum;
            hw_max_x = abs_x->maximum;
            hw_min_y = abs_y->minimum;
            hw_max_y = abs_y->maximum;
            hw_screen_w = hw_max_x - hw_min_x;
            hw_screen_h = hw_max_y - hw_min_y;
            print_touch_debug("硬件: w=%d, h=%d (min_x=%d, max_x=%d, min_y=%d, max_y=%d)\n", hw_screen_w, hw_screen_h, hw_min_x, hw_max_x, hw_min_y, hw_max_y);
        }
        return 0;
    }
    for (i = 0; i < TARGET_DEV_COUNT; i++) {
        if (strstr(dev->name, target_devices[i])) {
            is_target = true;
            dev_index = i;
            break;
        }
    }
    if (!is_target)
        return -ENODEV;
    mask = atomic_read(&target_bound_mask);
    if (mask & (1 << dev_index))
        return -EEXIST;
    handle = kzalloc(sizeof(*handle), GFP_KERNEL);
    if (!handle)
        return -ENOMEM;
    handle->dev = dev;
    handle->handler = handler;
    handle->name = "key_hook";
    ret = input_register_handle(handle);
    if (ret)
        goto err_reg;
    ret = input_open_device(handle);
    if (ret)
        goto err_open;
    atomic_inc(&bound_dev_count);
    atomic_or(1 << dev_index, &target_bound_mask);
    print_touch_debug("设备绑定成功: %s（索引: %d）\n", dev->name, dev_index);
    return 0;
err_open:
    input_unregister_handle(handle);
err_reg:
    kfree(handle);
    return ret;
}

static void key_hook_disconnect(struct input_handle *handle) {
    int i;
    int dev_index = -1;
    struct input_dev *dev = handle->dev;
    if (!dev || !dev->name)
        goto out;
    if (strstr(dev->name, "NVTCapacitiveTouchScreen")) {
        if (touch_info && touch_info->ts_handle == handle) {
            print_touch_debug("触摸屏设备断开连接: %s\n", dev->name);

            /* === 释放独占 + 清理 evdev === */
            mutex_lock(&dev->mutex);
            if (rcu_access_pointer(dev->grab) == handle) {
                rcu_assign_pointer(dev->grab, NULL);
                print_touch_debug("已释放触摸屏独占");
            }
            mutex_unlock(&dev->mutex);
            synchronize_rcu();
            touch_info->evdev_handle = NULL;
            touch_info->evdev_found = false;
            /* ============================== */

            touch_info->ts_handle = NULL;
            target_ts_dev = NULL;
            put_device(&dev->dev);
        }
        goto out_cleanup;
    }
    for (i = 0; i < TARGET_DEV_COUNT; i++) {
        if (strstr(dev->name, target_devices[i])) {
            dev_index = i;
            break;
        }
    }
    if (dev_index >= 0) {
        atomic_dec(&bound_dev_count);
        atomic_and(~(1 << dev_index), &target_bound_mask);
        print_touch_debug("设备断开连接: %s（索引: %d）\n", dev->name, dev_index);
    }
out_cleanup:
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
out:
    return;
}

static int probe_device_callback(struct device *dev, void *data) {
    struct input_dev *input_dev;
    int i;
    bool is_target;
    input_dev = to_input_dev(dev);
    is_target = false;
    if (!input_dev || !input_dev->name) {
        return 0;
    }
    for (i = 0; i < TARGET_DEV_COUNT; i++) {
        if (strstr(input_dev->name, target_devices[i])) {
            is_target = true;
            break;
        }
    }
    if (is_target) {
        print_touch_debug("等待内核自动绑定: %s", input_dev->name);
    }
    return 0;
}

static bool filter_key_event(struct input_handle *handle, unsigned int type, unsigned int code, int value) {
    int i;
    bool is_target = false;
    struct input_dev *dev = handle->dev;
    unsigned long flags_physical, flags_virtual, flags_hijack;
    int slot;
    bool should_intercept = false;
    bool virtual_active = false;
    int virtual_count = 0;
    char slot_buf[256] = {0};
    int buf_pos = 0;
    int intercepted_slots[MAX_SLOTS] = {0};
    int intercepted_count = 0;
    bool hijacked = false;
    if (dev && dev->name && strstr(dev->name, "NVTCapacitiveTouchScreen")) {
        if (type == EV_ABS && code == ABS_MT_SLOT) {
            LOCK_ORDER_1(flags_physical);
            touch_info->current_slot = value;
            UNLOCK_ORDER_1(flags_physical);
            return false;
        }
        if (type == EV_KEY && code == BTN_TOUCH) {
            if (value == 0) {
                LOCK_ORDER_2(flags_physical, flags_virtual);
                virtual_active = touch_info->virtual_touch_active;
                virtual_count = touch_info->virtual_touch_count;
                if (virtual_active && virtual_count > 0 && !touch_info->evdev_found) {
                    should_intercept = true;
                    for (i = 0; i < MAX_SLOTS; i++) {
                        if (touch_info->physical_slots_active[i]) {
                            intercepted_slots[intercepted_count++] = i;
                            touch_info->physical_slots_active[i] = false;
                            touch_info->physical_slots_tracking_id[i] = -1;
                        }
                    }
                    touch_info->physical_touch_count = 0;
                    if (intercepted_count > 0) {
                        buf_pos += snprintf(slot_buf + buf_pos, sizeof(slot_buf) - buf_pos, "槽位[");
                        for (i = 0; i < intercepted_count && buf_pos < sizeof(slot_buf)-10; i++) {
                            if (i > 0) buf_pos += snprintf(slot_buf + buf_pos, sizeof(slot_buf) - buf_pos, ",");
                            buf_pos += snprintf(slot_buf + buf_pos, sizeof(slot_buf) - buf_pos, "%d", intercepted_slots[i]);
                        }
                        buf_pos += snprintf(slot_buf + buf_pos, sizeof(slot_buf) - buf_pos, "]");
                    } else {
                        snprintf(slot_buf, sizeof(slot_buf), "无物理槽位");
                    }
                    print_touch_debug("拦截物理抬起（虚拟点:%d，%s，已清除物理状态）", virtual_count, slot_buf);
                } else {
                    for (i = 0; i < MAX_SLOTS; i++) {
                        touch_info->physical_slots_active[i] = false;
                        touch_info->physical_slots_tracking_id[i] = -1;
                    }
                    touch_info->physical_touch_count = 0;
                }
                UNLOCK_ORDER_2(flags_physical, flags_virtual);
                if (should_intercept) {
                    return true;
                }
            }
            return false;
        }
        else if (type == EV_ABS && code == ABS_MT_TRACKING_ID) {
            LOCK_ORDER_1(flags_physical);
            slot = touch_info->current_slot;
            if (slot >= 0 && slot < MAX_SLOTS) {
                if (value == -1) {
                    if (touch_info->physical_slots_active[slot]) {
                        touch_info->physical_slots_active[slot] = false;
                        touch_info->physical_slots_tracking_id[slot] = -1;
                        if (touch_info->physical_touch_count > 0) {
                            touch_info->physical_touch_count--;
                        }
                    }
                } else if (value >= 0) {
                    if (value > 0) {
                        if (!touch_info->physical_slots_active[slot]) {
                            touch_info->physical_slots_active[slot] = true;
                            touch_info->physical_touch_count++;
                        }
                        touch_info->physical_slots_tracking_id[slot] = value;
                    }
                }
                if (value == -1) {
                    spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
                    if (slot >= 0 && slot < MAX_SLOTS && touch_info->slot_hijack[slot].hijacked) {
                        touch_info->slot_hijack[slot].hijacked = false;
                        touch_info->slot_hijack[slot].hijacker_client_id = -1;
                        print_touch_debug("槽位 %d 手指抬起，释放 hijack", slot);
                    }
                    spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
                }
            }
            UNLOCK_ORDER_1(flags_physical);
            return false;
        }
        if (type == EV_ABS && (code == ABS_MT_POSITION_X || code == ABS_MT_POSITION_Y)) {
            slot = touch_info->current_slot;
            if (slot >= 0 && slot < MAX_SLOTS) {
                spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
                hijacked = touch_info->slot_hijack[slot].hijacked;
                spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
                if (hijacked) {
                    return true;
                }
            }
        }
        return false;
    }
    for (i = 0; i < TARGET_DEV_COUNT; i++) {
        if (dev && dev->name && strstr(dev->name, target_devices[i])) {
            is_target = true;
            break;
        }
    }
    if (!is_target) {
        return false;
    }
    if (type != EV_KEY) {
        return false;
    }
    if (code == KEY_POWER) {
        if (value == 1) {
            key_info->power_key_pressed = true;
            key_info->power_press_time = ktime_get();
            key_info->combo_triggered = false;
            key_info->combo_type = 0;
            print_touch_debug("关机键按下，等待音量键组合...");
        } else {
            key_info->power_key_pressed = false;
            print_touch_debug("关机键抬起");
            if (key_info->combo_triggered) {
                if (key_info->combo_type == 1 && !key_info->volup_pressed) {
                    key_info->state = STATE_INTERCEPT;
                    add_key_event(1, 0);
                    key_info->combo_triggered = false;
                    return true;
                }
                else if (key_info->combo_type == 2 && !key_info->voldown_pressed) {
                    key_info->state = STATE_NORMAL;
                    add_key_event(0, 0);
                    key_info->combo_triggered = false;
                    return true;
                }
            }
        }
        return false;
    }
    if (code == KEY_VOLUMEUP) {
        key_info->volup_pressed = (value == 1);
        print_touch_debug("音量加状态：%s", value == 1 ? "按下" : "抬起");
    } else if (code == KEY_VOLUMEDOWN) {
        key_info->voldown_pressed = (value == 1);
        print_touch_debug("音量减状态：%s", value == 1 ? "按下" : "抬起");
    }
    if (value == 1 && (code == KEY_VOLUMEUP || code == KEY_VOLUMEDOWN)) {
        if (key_info->power_key_pressed) {
            s64 time_diff = ktime_ms_delta(ktime_get(), key_info->power_press_time);
            if (time_diff >= 0 && time_diff < COMBO_KEY_TIMEOUT) {
                key_info->combo_triggered = true;
                key_info->combo_type = (code == KEY_VOLUMEUP) ? 1 : 2;
                print_touch_debug("组合键触发条件满足（等待抬起确认）");
                return true;
            }
        }
    }
    if (value == 0 && (code == KEY_VOLUMEUP || code == KEY_VOLUMEDOWN)) {
        if (key_info->combo_triggered && !key_info->power_key_pressed) {
            if (key_info->combo_type == 1) {
                key_info->state = STATE_INTERCEPT;
                add_key_event(1, 0);
                key_info->combo_triggered = false;
                return true;
            }
            else if (key_info->combo_type == 2) {
                key_info->state = STATE_NORMAL;
                add_key_event(0, 0);
                key_info->combo_triggered = false;
                return true;
            }
        }
    }
    if (key_info->state == STATE_INTERCEPT) {
        if (code == KEY_VOLUMEUP) {
            int key_code = (value == 1) ? 1 : 2;
            add_key_event(1, key_code);
            return true;
        } else if (code == KEY_VOLUMEDOWN) {
            int key_code = (value == 1) ? 3 : 4;
            add_key_event(1, key_code);
            return true;
        }
    }
    return false;
}

static void key_hook_event(struct input_handle *handle, unsigned int type, unsigned int code, int value) {
    struct input_dev *dev;
    struct input_handle *evh;
    int i;
    int slot;
    bool any_outside;
    unsigned long flags;
    dev = handle->dev;
    if (!dev || !dev->name || !strstr(dev->name, "NVTCapacitiveTouchScreen"))
        return;
    if (!touch_info)
        return;
    if (!touch_info->evdev_found) {
        find_evdev_handle(dev);
        if (!touch_info->evdev_found) {
            print_touch_debug("未找到 evdev handle，丢弃事件");
            return;
        }
    }
    evh = touch_info->evdev_handle;
    if (type != EV_SYN || code != SYN_REPORT) {
        if (touch_info->evt_count < 64) {
            touch_info->evt_buffer[touch_info->evt_count].type = type;
            touch_info->evt_buffer[touch_info->evt_count].code = code;
            touch_info->evt_buffer[touch_info->evt_count].value = value;
            touch_info->evt_count++;
        }
        return;
    }
    for (i = 0; i < touch_info->evt_count; i++) {
        struct input_event *e = &touch_info->evt_buffer[i];
        if (e->type == EV_ABS && e->code == ABS_MT_SLOT) {
            touch_info->parse_slot = e->value;
        } else if (e->type == EV_ABS && e->code == ABS_MT_TRACKING_ID) {
            touch_info->frame_slots[touch_info->parse_slot].tracking_id = e->value;
            touch_info->frame_slots[touch_info->parse_slot].updated = true;
        } else if (e->type == EV_ABS && e->code == ABS_MT_POSITION_X) {
            touch_info->frame_slots[touch_info->parse_slot].x = e->value;
            touch_info->frame_slots[touch_info->parse_slot].has_x = true;
            touch_info->frame_slots[touch_info->parse_slot].updated = true;
        } else if (e->type == EV_ABS && e->code == ABS_MT_POSITION_Y) {
            touch_info->frame_slots[touch_info->parse_slot].y = e->value;
            touch_info->frame_slots[touch_info->parse_slot].has_y = true;
            touch_info->frame_slots[touch_info->parse_slot].updated = true;
        } else if (e->type == EV_KEY && e->code == BTN_TOUCH) {
            touch_info->frame_btn_touch = e->value;
            touch_info->frame_has_btn = true;
        }
    }
    any_outside = false;
    for (slot = 0; slot < MAX_SLOTS; slot++) {
        if (!touch_info->frame_slots[slot].updated)
            continue;
        if (touch_info->frame_slots[slot].tracking_id >= 0) {
            if (!touch_info->slot_down_decided[slot]) {
                if (touch_info->frame_slots[slot].has_x && touch_info->frame_slots[slot].has_y) {
                    touch_info->slot_swallowed[slot] = check_obstacle(
                        touch_info->frame_slots[slot].x,
                        touch_info->frame_slots[slot].y);
                }
                touch_info->slot_down_decided[slot] = true;
            }
            if (touch_info->slot_swallowed[slot]) {
                enqueue_intercepted(slot,
                    touch_info->frame_slots[slot].x,
                    touch_info->frame_slots[slot].y,
                    touch_info->slot_down_decided[slot] ? 1 : 0);
            } else {
                evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
                evh->handler->event(evh, EV_ABS, ABS_MT_TRACKING_ID,
                    touch_info->frame_slots[slot].tracking_id);
                if (touch_info->frame_slots[slot].has_x)
                    evh->handler->event(evh, EV_ABS, ABS_MT_POSITION_X,
                        touch_info->frame_slots[slot].x);
                if (touch_info->frame_slots[slot].has_y)
                    evh->handler->event(evh, EV_ABS, ABS_MT_POSITION_Y,
                        touch_info->frame_slots[slot].y);
                evh->handler->event(evh, EV_ABS, ABS_MT_PRESSURE, 1);
                evh->handler->event(evh, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
                any_outside = true;
            }
        } else if (touch_info->frame_slots[slot].tracking_id == -1) {
            if (touch_info->slot_swallowed[slot]) {
                enqueue_intercepted(slot, 0, 0, 2);
            } else {
                evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
                evh->handler->event(evh, EV_ABS, ABS_MT_TRACKING_ID, -1);
                any_outside = true;
            }
            touch_info->slot_swallowed[slot] = false;
            touch_info->slot_down_decided[slot] = false;
            touch_info->frame_slots[slot].tracking_id = -2;
        }
        touch_info->frame_slots[slot].updated = false;
        touch_info->frame_slots[slot].has_x = false;
        touch_info->frame_slots[slot].has_y = false;
        /* tracking_id 保留旧值供滑动复用；仅在 UP 时重置为 -2 */
    }
    if (touch_info->frame_has_btn) {
        evh->handler->event(evh, EV_KEY, BTN_TOUCH, touch_info->frame_btn_touch);
        any_outside = true;
        touch_info->frame_has_btn = false;
    }
    if (any_outside) {
        evh->handler->event(evh, EV_SYN, SYN_REPORT, 0);
    }
    touch_info->evt_count = 0;
}

static const struct input_device_id key_hook_ids[] = {
    {
        .evbit = { BIT_MASK(EV_KEY) },
        .driver_info = 1
    },
    { }
};
MODULE_DEVICE_TABLE(input, key_hook_ids);
/* ---------------- UNIX域套接字通讯模块 ---------------- */
static int debug = 0;
static const char unix_socket_name[] = "zmem";
enum {
    ST_CLOSED,
    ST_LISTEN
};
static atomic_t g_state = ATOMIC_INIT(ST_CLOSED);
static struct socket *g_listen_sock = NULL;
static struct task_struct *g_listen_thread = NULL;
static DEFINE_MUTEX(g_socket_mutex);
static const struct file_operations anon_fops;
static atomic_t anon_ref = ATOMIC_INIT(0);

static int create_listen_socket(void) {
    int ret = 0;
    struct sockaddr_un addr;
    size_t name_len = strlen(unix_socket_name);
    size_t addr_len;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, unix_socket_name, name_len);
    addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;
    mutex_lock(&g_socket_mutex);
    if (g_listen_sock || atomic_read(&g_state) != ST_CLOSED) {
        ret = -EBUSY;
        goto out_unlock;
    }
    ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &g_listen_sock);
    if (ret < 0) {
        print_touch_debug("创建套接字失败: %d\n", ret);
        goto out_unlock;
    }
    ret = kernel_bind(g_listen_sock, (struct sockaddr *)&addr, addr_len);
    if (ret < 0) {
        print_touch_debug("绑定失败: %d\n", ret);
        sock_release(g_listen_sock);
        g_listen_sock = NULL;
        goto out_unlock;
    }
    ret = g_listen_sock->ops->listen(g_listen_sock, 1);
    if (ret < 0) {
        print_touch_debug("监听失败: %d\n", ret);
        sock_release(g_listen_sock);
        g_listen_sock = NULL;
        goto out_unlock;
    }
    atomic_set(&g_state, ST_LISTEN);
    print_touch_debug("UNIX套接字监听成功\n");
out_unlock:
    mutex_unlock(&g_socket_mutex);
    return ret;
}

static void close_listen_socket(void) {
    mutex_lock(&g_socket_mutex);
    if (g_listen_sock) {
        kernel_sock_shutdown(g_listen_sock, SHUT_RDWR);
        sock_release(g_listen_sock);
        g_listen_sock = NULL;
    }
    print_touch_debug("UNIX域套接字已关闭\n");
    atomic_set(&g_state, ST_CLOSED);
    mutex_unlock(&g_socket_mutex);
}

static int unix_send_fd(struct socket *sock, int fd) {
    struct kvec iov;
    char dummy = 0;
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    struct msghdr msg;
    iov.iov_base = &dummy;
    iov.iov_len = 1;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, iov.iov_len);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = fd;
    return kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
}

static void force_close_listen_socket(void) {
    mutex_lock(&g_socket_mutex);
    if (g_listen_sock) {
        kernel_sock_shutdown(g_listen_sock, SHUT_RDWR);
        sock_release(g_listen_sock);
        g_listen_sock = NULL;
    }
    print_touch_debug("对接成功，关闭UNIX套接字\n");
    atomic_set(&g_state, ST_CLOSED);
    mutex_unlock(&g_socket_mutex);
}

static int unix_client_handler(void *data) {
    struct socket *cli = data;
    struct file *file;
    int fd, ret;
    struct sock *sk;
    const struct cred *peer_cred;
    uid_t uid;
    pid_t peer_pid;
    struct task_struct *task;
    struct pid *peer_pid_struct;
    char comm[TASK_COMM_LEN];
    bool allowed = false;
    struct client_state *client = NULL;
    static const char *allowed_clients[] = {
        "demo",
        "AImGui",
        NULL
    };
    sk = cli->sk;
    peer_cred = sk->sk_peer_cred;
    if (!peer_cred || !uid_valid(peer_cred->uid)) {
        print_touch_debug("无法获取客户端凭证信息\n");
        sock_release(cli);
        return -EACCES;
    }
    uid = from_kuid(current_user_ns(), peer_cred->uid);
    if (sk->sk_peer_pid) {
        peer_pid = pid_nr(sk->sk_peer_pid);
        peer_pid_struct = find_get_pid(peer_pid);
    } else {
        print_touch_debug("无法获取客户端PID\n");
        sock_release(cli);
        return -EACCES;
    }
    if (!peer_pid_struct) {
        print_touch_debug("无效的客户端PID\n");
        sock_release(cli);
        return -EACCES;
    }
    rcu_read_lock();
    task = pid_task(peer_pid_struct, PIDTYPE_PID);
    if (task) {
        get_task_comm(comm, task);
        print_touch_debug("客户端信息: PID=%d, UID=%d, 进程名='%s'\n", peer_pid, uid, comm);
    } else {
        rcu_read_unlock();
        put_pid(peer_pid_struct);
        print_touch_debug("无法获取客户端任务结构\n");
        sock_release(cli);
        return -ESRCH;
    }
    rcu_read_unlock();
    put_pid(peer_pid_struct);
    if (uid != 0) {
        print_touch_debug("拒绝非root用户连接: PID=%d, UID=%d, 进程名='%s'\n", peer_pid, uid, comm);
        sock_release(cli);
        return -EACCES;
    }
    if (allowed_clients[0] != NULL) {
        int i;
        for (i = 0; allowed_clients[i] != NULL; i++) {
            if (strcmp(comm, allowed_clients[i]) == 0) {
                allowed = true;
                break;
            }
        }
    } else {
        allowed = true;
    }
    if (!allowed) {
        print_touch_debug("拒绝非白名单进程连接: PID=%d, 进程名='%s'\n", peer_pid, comm);
        sock_release(cli);
        return -EACCES;
    }
    file = anon_inode_getfile("unix_anon_fd", &anon_fops, NULL, O_RDWR);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        sock_release(cli);
        return ret;
    }
    fd = get_unused_fd_flags(O_RDWR);
    if (fd < 0) {
        fput(file);
        sock_release(cli);
        return fd;
    }
    atomic_inc(&anon_ref);
    fd_install(fd, file);
    ret = unix_send_fd(cli, fd);
    if (ret < 0) {
        print_touch_debug("发送FD失败: %d\n", ret);
        put_unused_fd(fd);
        fput(file);
        sock_release(cli);
        return ret;
    }
    /* === 新增：释放驱动自己持有的 fd 和 file 引用，避免泄漏导致 anon_release 永不触发 === */
    __close_fd(current->files, fd);
    client = create_client(peer_pid, uid, file);
    if (!client) {
        print_touch_debug("创建客户端状态失败\n");
        fput(file);
        sock_release(cli);
        return -ENOMEM;
    }
    file->private_data = client;
    print_touch_debug("对接成功: PID=%d, UID=%d, 进程名='%s', 匿名FD=%d\n", peer_pid, uid, comm, fd);
    sock_release(cli);
    return 0;
}

static int unix_listen_thread(void *data) {
    int ret;
    struct socket *cli_sock = NULL;
    if (atomic_read(&g_state) == ST_CLOSED) {
        ret = create_listen_socket();
        if (ret != 0) {
            print_touch_debug("初始创建监听失败，将重试\n");
        }
    }
    while (!kthread_should_stop()) {
        if (atomic_read(&g_state) == ST_LISTEN) {
            if (!g_listen_sock) {
                atomic_set(&g_state, ST_CLOSED);
                msleep(500);
                continue;
            }
            ret = sock_create_kern(&init_net, PF_UNIX, SOCK_STREAM, 0, &cli_sock);
            if (ret < 0) {
                msleep(500);
                continue;
            }
            ret = g_listen_sock->ops->accept(g_listen_sock, cli_sock, 0, false);
            if (ret < 0) {
                sock_release(cli_sock);
                cli_sock = NULL;
                if (ret != -EAGAIN) msleep(500);
                continue;
            }
            kthread_run(unix_client_handler, cli_sock, "unix_cli_handler");
            cli_sock = NULL;
        } else {
            msleep(1000);
            if (atomic_read(&g_state) == ST_CLOSED) {
                create_listen_socket();
            }
        }
        msleep(200);
    }
    if (cli_sock) {
       sock_release(cli_sock);
    }
    return 0;
}

static int anon_release(struct inode *inode, struct file *filp) {
    struct client_state *client;
    unsigned long flags;
    int i;
    print_touch_debug("客户端断开，开始清理对应虚拟点");
    client = find_client_by_file(filp);
    if (!client) {
        print_touch_debug("未找到对应客户端状态");
        goto cleanup_ref;
    }
    print_touch_debug("清理客户端 %d (PID=%d) 的虚拟点，当前虚拟点数=%d",
                     client->client_id, client->pid, client->virtual_point_count);
    for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
        if (client->virtual_points[i].in_use) {
            int slot = client->virtual_points[i].slot;
            int tracking_id = client->virtual_points[i].tracking_id;
            print_touch_debug("处理客户端虚拟点[%d]：槽位=%d, ID=%d", i, slot, tracking_id);
            if (slot >= 0 && slot < MAX_SLOTS && target_ts_dev) {
                unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
                bool slot_in_use = false;
                int slot_client_id = -1;
                LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                slot_in_use = touch_info->slots[slot].in_use;
                slot_client_id = touch_info->slots[slot].client_id;
                if (slot_in_use && slot_client_id == client->client_id) {
                    bool need_btn_touch_reset = false;
                    touch_info->virtual_touch_count--;
                    if (touch_info->virtual_touch_count <= 0) {
                        touch_info->virtual_touch_count = 0;
                        touch_info->virtual_touch_active = false;
                    }
                    if (touch_info->virtual_touch_count == 0 &&
                        touch_info->physical_touch_count == 0) {
                        need_btn_touch_reset = true;
                    }
                    touch_info->slots[slot].in_use = false;
                    touch_info->slots[slot].tracking_id = -1;
                    touch_info->slots[slot].x = -1;
                    touch_info->slots[slot].y = -1;
                    touch_info->slots[slot].client_id = -1;
                    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    if (touch_info->evdev_found && touch_info->evdev_handle) {
                        struct input_handle *evh = touch_info->evdev_handle;
                        evh->handler->event(evh, EV_ABS, ABS_MT_SLOT, slot);
                        evh->handler->event(evh, EV_ABS, ABS_MT_TRACKING_ID, -1);
                        if (need_btn_touch_reset) {
                            evh->handler->event(evh, EV_KEY, BTN_TOUCH, 0);
                            print_touch_debug("发送BTN_TOUCH=0（客户端断开 via evdev）");
                        }
                        evh->handler->event(evh, EV_SYN, SYN_REPORT, 0);
                    } else {
                        input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
                        input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                        if (need_btn_touch_reset) {
                            input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
                            print_touch_debug("发送BTN_TOUCH=0（客户端断开）");
                        }
                        input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
                    }
                    print_touch_debug("强制抬起成功：槽位=%d, ID=%d, 剩余虚拟点=%d",
                        slot, tracking_id, touch_info->virtual_touch_count);
                } else {
                    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    print_touch_debug("槽位=%d 状态不匹配(in_use=%d, client_id=%d)，跳过",
                        slot, slot_in_use, slot_client_id);
                }
            }
            client->virtual_points[i].in_use = false;
            client->virtual_points[i].slot = -1;
            client->virtual_points[i].tracking_id = -1;
        }
    }
    client->virtual_point_count = 0;
    release_client_hijacked_slots(client);
    if (client->heartbeat) {
        del_timer_sync(&client->heartbeat->heartbeat_timer);
        kfree(client->heartbeat);
        client->heartbeat = NULL;
    }
    remove_client(client);

    /* === 新增：客户端断开后清除所有障碍物，停止拦截 === */
    {
        unsigned long obs_flags;
        spin_lock_irqsave(&touch_info->obstacle_lock, obs_flags);
        touch_info->obstacle_count = 0;
        spin_unlock_irqrestore(&touch_info->obstacle_lock, obs_flags);
        print_touch_debug("客户端断开，清除所有障碍物");
    }
    /* ================================================ */

    kfree(client);
cleanup_ref:
    atomic_dec(&anon_ref);
    print_touch_debug("客户端清理完成，剩余引用计数=%d", atomic_read(&anon_ref));
    return 0;
}


static long anon_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[0x100] = {0};
    USER_EVENT user_ev = {0};
    touch_move_t tm;
    touch_down_t td;
    touch_up_t tu;
    switch (cmd) {
        case CMD_OPEN_UNIX:
            mutex_lock(&g_socket_mutex);
            if (atomic_read(&g_state) == ST_CLOSED && !g_listen_sock) {
                ret = create_listen_socket();
                if (ret == 0) atomic_set(&g_state, ST_LISTEN);
            } else ret = -EBUSY;
            mutex_unlock(&g_socket_mutex);
            print_touch_debug("命令触发：手动开启监听\n");
            break;
        case OP_HEARTBEAT: {
            struct client_state *client = find_client_by_file(filp);
            if (client && client->heartbeat) {
                client->heartbeat->alive = true;
                client->heartbeat->last_heartbeat = jiffies;
                print_touch_debug("客户端 %d 心跳更新", client->client_id);
            } else {
                print_touch_debug("心跳更新失败：未找到客户端或心跳结构");
            }
            break;
        }
        case CMD_CLOSE_UNIX:
            close_listen_socket();
            print_touch_debug("命令触发：手动关闭监听\n");
            break;
        case CMD_REOPEN_UNIX:
            mutex_lock(&g_socket_mutex);
            if (atomic_read(&g_state) == ST_CLOSED && !g_listen_sock) {
                ret = create_listen_socket();
                if (ret == 0) {
                    atomic_set(&g_state, ST_LISTEN);
                    print_touch_debug("命令触发：重新开启监听（可对接下一个进程）\n");
                }
            } else ret = -EBUSY;
            mutex_unlock(&g_socket_mutex);
            break;
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                return -EFAULT;
            if (ret != 0)
                return -EFAULT;
            break;
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                return -EFAULT;
            if (ret != 0)
                return -EFAULT;
            break;
        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)))
                return -EFAULT;
            if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1))
                return -EFAULT;
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)))
                return -EFAULT;
            break;
        case OP_MODULE_PID:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)))
                return -EFAULT;
            if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1))
                return -EFAULT;
            mb.pid = get_process_pid(name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)))
                return -EFAULT;
            break;
        case OP_GET_EVENT:
            if (get_user_event(&user_ev)) {
            } else {
                user_ev.trp = (key_info->state == STATE_INTERCEPT) ? 1 : 0;
                user_ev.key_code = 0;
            }
            if (copy_to_user((void __user*)arg, &user_ev, sizeof(user_ev)))
                return -EFAULT;
            break;
        case OP_TOUCH_DOWN: {
            bool slot_used;
            unsigned long flags;
            struct client_state *client;
            if (copy_from_user(&td, (void __user*)arg, sizeof(td))) {
                return -EFAULT;
            }
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            client = find_client_by_file(filp);
            if (!client) {
                print_touch_debug("未找到客户端状态\n");
                return -EINVAL;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[td.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (slot_used) {
                print_touch_debug("槽位=%d 已被占用，无法按下\n", td.slot);
                return -EBUSY;
            }
            touch_down(td.slot, td.x, td.y, client);
            break;
        }
        case OP_TOUCH_UP: {
            bool slot_used;
            unsigned long flags;
            struct client_state *client;
            if (copy_from_user(&tu, (void __user*)arg, sizeof(tu))) {
                return -EFAULT;
            }
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            client = find_client_by_file(filp);
            if (!client) {
                print_touch_debug("未找到客户端状态\n");
                return -EINVAL;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[tu.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (!slot_used) {
                print_touch_debug("槽位=%d 未按下，无法抬起\n", tu.slot);
                return -EINVAL;
            }
            touch_up(tu.slot, client);
            break;
        }
        case OP_TOUCH_MOVE: {
            bool slot_used;
            unsigned long flags;
            struct client_state *move_client;
            if (copy_from_user(&tm, (void __user*)arg, sizeof(tm)))
                return -EFAULT;
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            move_client = find_client_by_file(filp);
            if (!move_client) {
                print_touch_debug("未找到客户端状态\n");
                return -EINVAL;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[tm.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (!slot_used) {
                return 0;
            }
            touch_move(tm.slot, tm.x, tm.y, move_client);
            break;
        }
        case OP_HIJACK_SLOT: {
            hijack_slot_t hs;
            bool physical_active;
            if (copy_from_user(&hs, (void __user*)arg, sizeof(hs)))
                return -EFAULT;
            if (!touch_info || !target_ts_dev)
                return -ENODEV;
            if (hs.slot < 0 || hs.slot >= MAX_SLOTS)
                return -EINVAL;
            if (hs.enable) {
                unsigned long flags_phy, flags_hijack;
                spin_lock_irqsave(&touch_info->physical_lock, flags_phy);
                physical_active = touch_info->physical_slots_active[hs.slot];
                spin_unlock_irqrestore(&touch_info->physical_lock, flags_phy);
                if (!physical_active) {
                    print_touch_debug("hijack失败：槽位 %d 没有物理手指按下", hs.slot);
                    return -EINVAL;
                }
                spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
                touch_info->slot_hijack[hs.slot].hijacked = true;
                touch_info->slot_hijack[hs.slot].hijacker_client_id = -1;
                spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
                print_touch_debug("hijack成功：槽位 %d", hs.slot);
            } else {
                unsigned long flags_hijack;
                spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
                touch_info->slot_hijack[hs.slot].hijacked = false;
                touch_info->slot_hijack[hs.slot].hijacker_client_id = -1;
                spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
                print_touch_debug("hijack释放：槽位 %d", hs.slot);
            }
            break;
        }
        case OP_HIJACK_MOVE: {
            hijack_move_t hm;
            bool slot_hijacked;
            unsigned long flags_hijack;
            if (copy_from_user(&hm, (void __user*)arg, sizeof(hm)))
                return -EFAULT;
            if (!touch_info || !target_ts_dev)
                return -ENODEV;
            if (hm.slot < 0 || hm.slot >= MAX_SLOTS)
                return -EINVAL;
            spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
            slot_hijacked = touch_info->slot_hijack[hm.slot].hijacked;
            spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
            if (!slot_hijacked) {
                print_touch_debug("hijack_move失败：槽位 %d 未被抢夺", hm.slot);
                return -EPERM;
            }
            input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, hm.slot);
            input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, hm.x);
            input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, hm.y);
            input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
            input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
            input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
            break;
        }
        case OP_SET_OBSTACLES: {
            struct obstacle_payload payload;
            if (copy_from_user(&payload, (void __user*)arg, sizeof(payload)))
                return -EFAULT;
            if (payload.count < 0 || payload.count > MAX_OBSTACLES)
                return -EINVAL;
            {
                unsigned long flags;
                spin_lock_irqsave(&touch_info->obstacle_lock, flags);
                touch_info->obstacle_count = payload.count;
                if (payload.count > 0)
                    memcpy(touch_info->obstacles, payload.obs,
                        sizeof(struct touch_obstacle) * payload.count);
                spin_unlock_irqrestore(&touch_info->obstacle_lock, flags);
            }
          //  print_touch_debug("障碍物已设置: %d 个", payload.count);
            break;
        }
        case OP_GET_INTERCEPTED_TOUCH: {
            struct intercepted_touch it;
            if (!dequeue_intercepted(&it)) {
                return -EAGAIN;
            }
            if (copy_to_user((void __user*)arg, &it, sizeof(it)))
                return -EFAULT;
            break;
        }
        default:
            ret = -ENOIOCTLCMD;
            break;
    }
    return ret;
}

static const struct file_operations anon_fops = {
    .owner          = THIS_MODULE,
    .release        = anon_release,
    .unlocked_ioctl = anon_ioctl,
};

static int unix_socket_init(void) {
    int ret = 0;
    mutex_init(&g_socket_mutex);
    atomic_set(&g_state, ST_CLOSED);
    g_listen_thread = kthread_run(unix_listen_thread, NULL, "unix_listen_thread");
    if (IS_ERR(g_listen_thread)) {
        ret = PTR_ERR(g_listen_thread);
        print_touch_debug("启动监听线程失败: %d\n", ret);
        return ret;
    }
    print_touch_debug("UNIX套接字模块初始化完成\n");
    return 0;
}

static void unix_socket_cleanup(void) {
    if (g_listen_thread) {
        kthread_stop(g_listen_thread);
        g_listen_thread = NULL;
    }
    close_listen_socket();
    mutex_destroy(&g_socket_mutex);
    print_touch_debug("UNIX套接字模块清理完成\n");
}

static long my_dev_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg) {
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[0x100] = {0};
    USER_EVENT user_ev = {0};
    touch_move_t tm;
    touch_down_t td;
    touch_up_t tu;
    int ret=0;
    struct client_state *client;
    switch (cmd) {
        case OP_HEARTBEAT: {
            struct client_state *client = find_client_by_file(file);
            if (client && client->heartbeat) {
                client->heartbeat->alive = true;
                client->heartbeat->last_heartbeat = jiffies;
                print_touch_debug("客户端 %d 心跳更新", client->client_id);
            } else {
                print_touch_debug("心跳更新失败：未找到客户端或心跳结构");
            }
            break;
        }
        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)))
                return -EFAULT;
            if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1))
                return -EFAULT;
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)))
                return -EFAULT;
            break;
        case OP_MODULE_PID:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)))
                return -EFAULT;
            if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1))
                return -EFAULT;
            mb.pid = get_process_pid(name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)))
                return -EFAULT;
            break;
        case OP_GET_EVENT:
            if (get_user_event(&user_ev)) {
            } else {
                user_ev.trp = (key_info->state == STATE_INTERCEPT) ? 1 : 0;
                user_ev.key_code = 0;
            }
            if (copy_to_user((void __user*)arg, &user_ev, sizeof(user_ev)))
                return -EFAULT;
            break;
        case OP_TOUCH_DOWN: {
            bool slot_used;
            unsigned long flags;
            struct client_state *client;
            if (copy_from_user(&td, (void __user*)arg, sizeof(td))) {
                return -EFAULT;
            }
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            client = find_client_by_file(file);
            if (!client) {
                print_touch_debug("未找到客户端状态\n");
                return -EINVAL;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[td.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (slot_used) {
                print_touch_debug("槽位=%d 已被占用，无法按下\n", td.slot);
                return -EBUSY;
            }
            touch_down(td.slot, td.x, td.y, client);
            break;
        }
        case OP_TOUCH_UP: {
            bool slot_used;
            unsigned long flags;
            struct client_state *client;
            if (copy_from_user(&tu, (void __user*)arg, sizeof(tu))) {
                return -EFAULT;
            }
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            client = find_client_by_file(file);
            if (!client) {
                print_touch_debug("未找到客户端状态\n");
                return -EINVAL;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[tu.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (!slot_used) {
                print_touch_debug("槽位=%d 未按下，无法抬起\n", tu.slot);
                return -EINVAL;
            }
            touch_up(tu.slot, client);
            break;
        }
        case OP_TOUCH_MOVE: {
            bool slot_used;
            unsigned long flags;
            struct client_state *move_client;
            if (copy_from_user(&tm, (void __user*)arg, sizeof(tm)))
                return -EFAULT;
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            move_client = find_client_by_file(file);
            if (!move_client) {
                print_touch_debug("未找到客户端状态\n");
                return -EINVAL;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[tm.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (!slot_used) {
                return 0;
            }
            touch_move(tm.slot, tm.x, tm.y, move_client);
            break;
        }
        case OP_HIJACK_SLOT: {
            hijack_slot_t hs;
            bool physical_active;
            if (copy_from_user(&hs, (void __user*)arg, sizeof(hs)))
                return -EFAULT;
            if (!touch_info || !target_ts_dev)
                return -ENODEV;
            if (hs.slot < 0 || hs.slot >= MAX_SLOTS)
                return -EINVAL;
            if (hs.enable) {
                unsigned long flags_phy, flags_hijack;
                spin_lock_irqsave(&touch_info->physical_lock, flags_phy);
                physical_active = touch_info->physical_slots_active[hs.slot];
                spin_unlock_irqrestore(&touch_info->physical_lock, flags_phy);
                if (!physical_active) {
                    print_touch_debug("hijack失败：槽位 %d 没有物理手指按下", hs.slot);
                    return -EINVAL;
                }
                spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
                touch_info->slot_hijack[hs.slot].hijacked = true;
                touch_info->slot_hijack[hs.slot].hijacker_client_id = -1;
                spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
                print_touch_debug("hijack成功：槽位 %d", hs.slot);
            } else {
                unsigned long flags_hijack;
                spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
                touch_info->slot_hijack[hs.slot].hijacked = false;
                touch_info->slot_hijack[hs.slot].hijacker_client_id = -1;
                spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
                print_touch_debug("hijack释放：槽位 %d", hs.slot);
            }
            break;
        }
        case OP_HIJACK_MOVE: {
            hijack_move_t hm;
            bool slot_hijacked;
            unsigned long flags_hijack;
            if (copy_from_user(&hm, (void __user*)arg, sizeof(hm)))
                return -EFAULT;
            if (!touch_info || !target_ts_dev)
                return -ENODEV;
            if (hm.slot < 0 || hm.slot >= MAX_SLOTS)
                return -EINVAL;
            spin_lock_irqsave(&touch_info->hijack_lock, flags_hijack);
            slot_hijacked = touch_info->slot_hijack[hm.slot].hijacked;
            spin_unlock_irqrestore(&touch_info->hijack_lock, flags_hijack);
            if (!slot_hijacked) {
                print_touch_debug("hijack_move失败：槽位 %d 未被抢夺", hm.slot);
                return -EPERM;
            }
            input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, hm.slot);
            input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, hm.x);
            input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, hm.y);
            input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
            input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
            input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
            break;
        }
        case OP_SET_OBSTACLES: {
            struct obstacle_payload payload;
            if (copy_from_user(&payload, (void __user*)arg, sizeof(payload)))
                return -EFAULT;
            if (payload.count < 0 || payload.count > MAX_OBSTACLES)
                return -EINVAL;
            {
                unsigned long flags;
                spin_lock_irqsave(&touch_info->obstacle_lock, flags);
                touch_info->obstacle_count = payload.count;
                if (payload.count > 0)
                    memcpy(touch_info->obstacles, payload.obs,
                        sizeof(struct touch_obstacle) * payload.count);
                spin_unlock_irqrestore(&touch_info->obstacle_lock, flags);
            }
        //    print_touch_debug("障碍物已设置: %d 个", payload.count);
            break;
        }
        case OP_GET_INTERCEPTED_TOUCH: {
            struct intercepted_touch it;
            if (!dequeue_intercepted(&it)) {
                return -EAGAIN;
            }
            if (copy_to_user((void __user*)arg, &it, sizeof(it)))
                return -EFAULT;
            break;
        }
        default:
            return -ENOTTY;
    }
    return 0;
}

static int my_dev_open(struct inode *node, struct file *file) {
    touch_move_ctx_t *mv = kzalloc(sizeof(*mv), GFP_KERNEL);
    if (!mv) return -ENOMEM;
    mv->last_x = mv->last_y = -1;
    file->private_data = mv;
    print_touch_debug("设备已打开，move_ctx=%p，当前=%s\n", mv, devicename);
    return 0;
}

static int my_dev_close(struct inode *node, struct file *file) {
    touch_move_ctx_t *mv = file->private_data;
    kfree(mv);

    /* 字符设备关闭时清除障碍物，停止拦截 */
    if (touch_info) {
        unsigned long obs_flags;
        spin_lock_irqsave(&touch_info->obstacle_lock, obs_flags);
        touch_info->obstacle_count = 0;
        spin_unlock_irqrestore(&touch_info->obstacle_lock, obs_flags);
        print_touch_debug("字符设备关闭，清除所有障碍物");
    }

    mutex_lock(&dev_lifecycle_lock);
    device_destroy(mem_tool_class, mem_tool_dev_t);
    print_touch_debug("已删除旧设备文件：%s\n", devicename);
    devicename = get_rand_str();
    memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename);
    if (IS_ERR(memdev->dev)) {
        print_touch_debug("重新创建设备文件失败 (错误码=%ld)\n", PTR_ERR(memdev->dev));
        memdev->dev = NULL;
    } else {
        print_touch_debug("设备已关闭，创建：%s\n", devicename);
    }
    mutex_unlock(&dev_lifecycle_lock);
    return 0;
}


struct file_operations dev_functions = {
    .owner   = THIS_MODULE,
    .open    = my_dev_open,
    .release = my_dev_close,
    .unlocked_ioctl = my_dev_ioctl,
};

static void hide_module(void) {
    struct module *mod = THIS_MODULE;
    remove_proc_subtree("sched_debug", NULL);
    remove_proc_entry("uevents_records", NULL);
    list_del_init(&mod->list);
    kobject_del(&mod->mkobj.kobj);
    if (mod->holders_dir) {
        kobject_del(mod->holders_dir);
        mod->holders_dir = NULL;
    }
    mod->state = MODULE_STATE_UNFORMED;
#if defined(CONFIG_STRICT_MODULE_RWX) && defined(set_memory_ro) && defined(set_memory_nx)
    set_memory_ro((unsigned long)mod->core_layout.base, mod->core_layout.size / PAGE_SIZE);
    set_memory_nx((unsigned long)mod->core_layout.base, mod->core_layout.size / PAGE_SIZE);
    set_memory_ro((unsigned long)mod->core_layout.base, mod->core_layout.size >> PAGE_SHIFT);
#endif
    strncpy(mod->name, mod_obf_name, sizeof(mod->name) - 1);
    mod->name[sizeof(mod->name) - 1] = '\0';
    mod->version = NULL;
    mod->srcversion = NULL;
    mod->exit = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    mod->noinstr_text_size = 0;
#endif
    mod->num_syms = 0;
    mod->syms = NULL;
    mod->crcs = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
    mod->init_size = 0;
    mod->init_text_size = 0;
    mod->num_debug = 0;
    mod->debug = NULL;
#endif
#if defined(CONFIG_ARM64) && defined(flush_cache_all)
    flush_cache_all();
#elif defined(CONFIG_ARM64) && defined(flush_cache_page)
    flush_cache_page();
#endif
    print_touch_debug("模块隐藏操作完成");
}

static int __init driver_entry(void) {
    int ret;
    int i;
    ret = 0;
    for (i = 0; i < LOCK_BUCKETS; i++) {
        rwlock_init(&pid_locks[i]);
    }
    touch_info = kzalloc(sizeof(struct touch_hook_state), GFP_KERNEL);
    if (!touch_info) {
        print_touch_debug("分配触摸状态结构失败\n");
        ret = -ENOMEM;
        goto err_touch_init;
    }
    spin_lock_init(&touch_info->lock);
    spin_lock_init(&touch_info->virtual_lock);
    spin_lock_init(&touch_info->physical_lock);
    spin_lock_init(&touch_info->client_lock);
    spin_lock_init(&touch_info->auto_up_lock);
    spin_lock_init(&touch_info->hijack_lock);
    for (i = 0; i < MAX_SLOTS; i++) {
        touch_info->slot_hijack[i].hijacked = false;
        touch_info->slot_hijack[i].hijacker_client_id = -1;
    }
    spin_lock_init(&touch_info->obstacle_lock);
    spin_lock_init(&touch_info->q_lock);
    init_waitqueue_head(&touch_info->q_waitq);
    touch_info->obstacle_count = 0;
    touch_info->evdev_handle = NULL;
    touch_info->evdev_found = false;
    touch_info->q_head = 0;
    touch_info->q_tail = 0;
    touch_info->evt_count = 0;
    touch_info->frame_has_btn = false;
    touch_info->parse_slot = 0;
    for (i = 0; i < MAX_SLOTS; i++) {
        touch_info->slot_swallowed[i] = false;
        touch_info->slot_down_decided[i] = false;
        touch_info->frame_slots[i].tracking_id = -2;
        touch_info->frame_slots[i].updated = false;
        touch_info->frame_slots[i].has_x = false;
        touch_info->frame_slots[i].has_y = false;
    }
    for (i = 0; i < MAX_SLOTS; i++) {
        touch_info->slots[i].in_use = false;
        touch_info->slots[i].tracking_id = -1;
        touch_info->slots[i].x = -1;
        touch_info->slots[i].y = -1;
        touch_info->slots[i].client_id = -1;
        touch_info->physical_slots_active[i] = false;
        touch_info->physical_slots_tracking_id[i] = -1;
    }
    touch_info->next_tracking_id = 1000;
    touch_info->virtual_touch_active = false;
    touch_info->virtual_touch_count = 0;
    touch_info->physical_touch_count = 0;
    touch_info->current_slot = 0;
    touch_info->ts_handle = NULL;
    touch_info->next_client_id = 0;
    key_info = kzalloc(sizeof(struct key_hook_state), GFP_KERNEL);
    if (!key_info) {
        print_touch_debug("分配按键状态结构失败\n");
        ret = -ENOMEM;
        goto err_key_init;
    }
    spin_lock_init(&key_info->lock);
    init_waitqueue_head(&key_info->waitq);
    INIT_LIST_HEAD(&key_info->event_list);
    INIT_LIST_HEAD(&touch_info->client_list);
    key_info->state = STATE_NORMAL;
    key_info->power_key_pressed = false;
    key_info->volup_pressed = false;
    key_info->voldown_pressed = false;
    key_info->combo_triggered = false;
    key_info->touch_intercept_enabled = true;
    key_hook_handler.filter = filter_key_event;
    key_hook_handler.event = key_hook_event;
    key_hook_handler.connect = key_hook_connect;
    key_hook_handler.disconnect = key_hook_disconnect;
    key_hook_handler.name = "key_hook_handler";
    key_hook_handler.id_table = key_hook_ids;
    ret = input_register_handler(&key_hook_handler);
    if (ret) {
        print_touch_debug("注册输入处理器失败 (ret=%d)\n", ret);
        goto err_input_register;
    }
    

    
    if (debug==1) {
        devicename = get_rand_str();
        ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
        if (ret < 0) {
            print_touch_debug("分配设备号 (ret=%d)\n", ret);
            goto err_alloc_chrdev;
        }
        print_touch_debug("设备号: %d:%d\n", MAJOR(mem_tool_dev_t), MINOR(mem_tool_dev_t));
        memdev = kzalloc(sizeof(struct mem_tool_device), GFP_KERNEL);
        if (!memdev) {
            ret = -ENOMEM;
            print_touch_debug("分配设备结构失败\n");
            goto err_memdev_alloc;
        }
        cdev_init(&memdev->cdev, &dev_functions);
        memdev->cdev.owner = THIS_MODULE;
        ret = cdev_add(&memdev->cdev, mem_tool_dev_t, 1);
        if (ret) {
            print_touch_debug("添加字符设备失败 (ret=%d)\n", ret);
            goto err_cdev_add;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
        mem_tool_class = class_create(devicename);
#else
        mem_tool_class = class_create(THIS_MODULE, devicename);
#endif
        if (IS_ERR(mem_tool_class)) {
            ret = PTR_ERR(mem_tool_class);
            print_touch_debug("创建设备类失败 (ret=%d)\n", ret);
            goto err_class_create;
        }
        memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename);
        if (IS_ERR(memdev->dev)) {
            ret = PTR_ERR(memdev->dev);
            print_touch_debug("创建设备节点失败 (ret=%d)\n", ret);
            goto err_device_create;
        }
        print_touch_debug("设备初始化完成：/dev/%s\n", devicename);
    }
    if (debug==0) {
        ret = unix_socket_init();
        if (ret != 0) {
            print_touch_debug("UNIX套接字模块初始化失败 (ret=%d)\n", ret);
            goto err_unix_init;
        }
    }
    spin_lock_init(&touch_info->auto_up_lock);
    timer_setup(&touch_info->auto_up_timer, touch_auto_up_callback, 0);
    mod_timer(&touch_info->auto_up_timer, jiffies + msecs_to_jiffies(1000));
    print_touch_debug("60秒超时自动抬起定时器已初始化并启动");
    msleep(300);
    restart_system_server_secure();
    msleep(300);
    hide_module();
    print_touch_debug("驱动模块加载完成\n");
    return 0;
err_unix_init:
    device_destroy(mem_tool_class, mem_tool_dev_t);
err_device_create:
    class_destroy(mem_tool_class);
err_class_create:
    cdev_del(&memdev->cdev);
err_cdev_add:
    kfree(memdev);
err_memdev_alloc:
    unregister_chrdev_region(mem_tool_dev_t, 1);
err_alloc_chrdev:
    input_unregister_handler(&key_hook_handler);
err_input_register:
    kfree(key_info);
err_key_init:
    kfree(touch_info);
err_touch_init:
    return ret;
}

static void __exit driver_unload(void) {
    struct event_node *node, *tmp;
    struct client_state *client, *client_tmp;
    unsigned long flags;
    int i;
    if (touch_info) {
        del_timer_sync(&touch_info->auto_up_timer);
        print_touch_debug("60秒超时自动抬起定时器已清理");
    }
    if (touch_info) {
        spin_lock_irqsave(&touch_info->client_lock, flags);
        list_for_each_entry_safe(client, client_tmp, &touch_info->client_list, list) {
            print_touch_debug("清理残留客户端: ID=%d, PID=%d",
                             client->client_id, client->pid);
            for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
                if (client->virtual_points[i].in_use) {
                    int slot = client->virtual_points[i].slot;
                    if (slot >= 0 && slot < MAX_SLOTS && target_ts_dev) {
                        input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
                        input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                    }
                }
            }
            if (client->heartbeat) {
                del_timer_sync(&client->heartbeat->heartbeat_timer);
                kfree(client->heartbeat);
            }
            list_del(&client->list);
            kfree(client);
        }
        spin_unlock_irqrestore(&touch_info->client_lock, flags);
    }
    unix_socket_cleanup();
    list_for_each_entry_safe(node, tmp, &key_info->event_list, list) {
        list_del(&node->list);
        kfree(node);
    }
    if (touch_info && touch_info->ts_handle) {
        input_close_device(touch_info->ts_handle);
        input_unregister_handle(touch_info->ts_handle);
        kfree(touch_info->ts_handle);
    }
    if (target_ts_dev) {
        put_device(&target_ts_dev->dev);
        target_ts_dev = NULL;
    }
    device_destroy(mem_tool_class, mem_tool_dev_t);
    class_destroy(mem_tool_class);
    cdev_del(&memdev->cdev);
    kfree(memdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
    input_unregister_handler(&key_hook_handler);
    kfree(key_info);
    if (touch_info) {
        kfree(touch_info);
    }
    print_touch_debug("驱动模块卸载完成\n");
}

module_init(driver_entry);
module_exit(driver_unload);

module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "0=套接字fd通讯，1=dev通讯");

MODULE_LICENSE("GPL");
MODULE_INFO(srcversion, "000000000000000000000000");
MODULE_INFO(cfi, "n");
MODULE_INFO(lto, "n");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_IMPORT_NS(__kprobes);
MODULE_DESCRIPTION("Kernel Driver with Key/Touch/Network Intercept");
MODULE_AUTHOR("Custom");
