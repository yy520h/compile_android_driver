#include <linux/module.h>   // 必须直接包含，确保模块宏正确展开
#include <linux/init.h>     // 包含 __init 和 __exit 宏
#include "driver.h"

MODULE_LICENSE("GPL");
// 全局变量定义
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

// 静态全局变量
static struct input_dev *original_ts_dev = NULL;


void print_touch_debug(const char *format, ...) {
    char buf[512];  // 使用更大的缓冲区
    va_list args;
    int len;
    
    // 初始化参数列表
    va_start(args, format);
    // 安全地格式化字符串
    len = vsnprintf(buf, sizeof(buf), format, args);
    // 结束参数列表
    va_end(args);
    // 检查格式化是否成功
    if (len < 0) {
        // 格式化失败，直接打印错误
        printk(KERN_ERR "[qwq] vsnprintf failed\n");
        return;
    }
    // 检查是否截断
    if ((size_t)len >= sizeof(buf)) {
        printk(KERN_WARNING "[qwq] debug message truncated (%d chars)\n", len);
        buf[sizeof(buf) - 1] = '\0';  // 确保以null结尾
    }
    // 打印到内核日志
    printk(KERN_INFO "[qwq] %s\n", buf);
}






// 强制清理客户端虚拟点
static void cleanup_client_virtual_points(struct client_state *client) {
    unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
    int i, slot;
    bool need_btn_touch_reset = false;
    
    if (!client || !touch_info || !target_ts_dev) {
        print_touch_debug("cleanup_client_virtual_points: 无效参数");
        return;
    }
    
    print_touch_debug("强制清理客户端 %d (PID=%d) 的虚拟点，数量=%d", 
                     client->client_id, client->pid, client->virtual_point_count);
    
    LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    
    // 遍历所有槽位，清理属于该客户端的槽位
    for (slot = 0; slot < MAX_SLOTS; slot++) {
        if (touch_info->slots[slot].in_use && 
            touch_info->slots[slot].client_id == client->client_id) {
            
            print_touch_debug("清理槽位 %d (客户端 %d, 跟踪ID=%d)", 
                             slot, client->client_id, touch_info->slots[slot].tracking_id);
            
            // 减少虚拟触摸计数
            touch_info->virtual_touch_count--;
            
            // 重置槽位状态
            touch_info->slots[slot].in_use = false;
            touch_info->slots[slot].tracking_id = -1;
            touch_info->slots[slot].x = -1;
            touch_info->slots[slot].y = -1;
            touch_info->slots[slot].client_id = -1;
            
            // 立即发送触摸抬起事件（在锁内发送，避免竞态）
            input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
            input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
        }
    }
    
    // 检查是否需要发送 BTN_TOUCH=0
    if (touch_info->virtual_touch_count == 0 && 
        touch_info->physical_touch_count == 0) {
        need_btn_touch_reset = true;
        touch_info->virtual_touch_active = false;
    }
    
    // 重置虚拟触摸计数（防止负数）
    if (touch_info->virtual_touch_count < 0) {
        touch_info->virtual_touch_count = 0;
    }
    
    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
    
    // 发送同步报告（在锁外发送，避免死锁）
    if (need_btn_touch_reset) {
        input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
        print_touch_debug("发送BTN_TOUCH=0（所有虚拟点清理）");
    }
    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    
    // 清理客户端内部的虚拟点记录
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
    
    print_touch_debug("客户端 %d 虚拟点清理完成，剩余虚拟点数=%d", 
                     client->client_id, touch_info->virtual_touch_count);
}

// 心跳超时回调
// 心跳超时回调函数
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
        print_touch_debug("客户端 %d (PID=%d) 心跳超时，标记为退出", 
                         client->client_id, client->pid);
        client->exited = true;
        
        // 这里不立即清理，等待文件描述符关闭时清理
        // 因为客户端可能还在使用文件描述符
    } else {
        // 重置状态，等待下一次心跳
        hb->alive = false;
        hb->last_heartbeat = jiffies;
        
        // 重新设置定时器（3秒后检查）
        mod_timer(&hb->heartbeat_timer, jiffies + msecs_to_jiffies(3000));
    }
}
// 客户端管理辅助函数
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
    struct client_state *existing_client;  // 提前声明所有变量
    int slot;
    int tracking_id;
    bool slot_in_use;
    int slot_client_id;
    bool need_btn_touch_reset;
    struct client_heartbeat *hb;  // 心跳变量提前声明
    
    // 检查是否已存在相同PID的客户端
    existing_client = find_client_by_pid(pid);
    if (existing_client) {
        print_touch_debug("已存在PID=%d的客户端，强制清理旧连接", pid);
        // 标记旧客户端为已退出
        existing_client->exited = true;
        
        // 停止心跳定时器
        if (existing_client->heartbeat) {
            del_timer_sync(&existing_client->heartbeat->heartbeat_timer);
            kfree(existing_client->heartbeat);
            existing_client->heartbeat = NULL;
        }
        
        // 清理旧客户端的虚拟点
        for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
            if (existing_client->virtual_points[i].in_use) {
                slot = existing_client->virtual_points[i].slot;
                tracking_id = existing_client->virtual_points[i].tracking_id;
                
                print_touch_debug("清理旧客户端虚拟点[%d]：槽位=%d, ID=%d", 
                                 i, slot, tracking_id);
                
                if (slot >= 0 && slot < MAX_SLOTS && target_ts_dev) {
                    unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
                    
                    // 检查槽位状态
                    LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    
                    slot_in_use = touch_info->slots[slot].in_use;
                    slot_client_id = touch_info->slots[slot].client_id;
                    
                    // 确认是这个旧客户端的槽位才清理
                    if (slot_in_use && slot_client_id == existing_client->client_id) {
                        need_btn_touch_reset = false;
                        
                        // 更新虚拟触摸计数
                        touch_info->virtual_touch_count--;
                        if (touch_info->virtual_touch_count <= 0) {
                            touch_info->virtual_touch_count = 0;
                            touch_info->virtual_touch_active = false;
                        }
                        
                        // 检查是否需要发送 BTN_TOUCH=0
                        if (touch_info->virtual_touch_count == 0 && 
                            touch_info->physical_touch_count == 0) {
                            need_btn_touch_reset = true;
                        }
                        
                        // 重置槽位状态
                        touch_info->slots[slot].in_use = false;
                        touch_info->slots[slot].tracking_id = -1;
                        touch_info->slots[slot].x = -1;
                        touch_info->slots[slot].y = -1;
                        touch_info->slots[slot].client_id = -1;
                        
                        UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                        
                        // 发送MT触摸抬起事件
                        input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
                        input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                        
                        if (need_btn_touch_reset) {
                            input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
                            print_touch_debug("发送BTN_TOUCH=0（清理旧客户端）");
                        }
                        
                        input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
                        print_touch_debug("清理旧客户端槽位：槽位=%d, ID=%d, 剩余虚拟点=%d", 
                            slot, tracking_id, touch_info->virtual_touch_count);
                    } else {
                        UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    }
                }
                
                // 清除客户端记录
                existing_client->virtual_points[i].in_use = false;
                existing_client->virtual_points[i].slot = -1;
                existing_client->virtual_points[i].tracking_id = -1;
            }
        }
        
        existing_client->virtual_point_count = 0;
        
        // 从列表中移除旧客户端
        remove_client(existing_client);
        kfree(existing_client);
    }
    
    // 创建新客户端
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
    
    // 创建心跳检测
    hb = kzalloc(sizeof(struct client_heartbeat), GFP_KERNEL);
    if (hb) {
        hb->client = client;
        hb->alive = true;
        hb->last_heartbeat = jiffies;
        timer_setup(&hb->heartbeat_timer, heartbeat_timeout_callback, 0);
        mod_timer(&hb->heartbeat_timer, jiffies + msecs_to_jiffies(3000));
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
    
    // 停止心跳定时器
    if (client->heartbeat) {
        del_timer_sync(&client->heartbeat->heartbeat_timer);
        kfree(client->heartbeat);
        client->heartbeat = NULL;
    }
    
    // 从列表中移除
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
    
    // 检查客户端是否有效
    if (!client) {
        print_touch_debug("触摸按下失败：客户端无效");
        return;
    }
    
    // 检查客户端是否已退出
    if (client->exited) {
        print_touch_debug("触摸按下失败：客户端 %d 已退出", client->client_id);
        return;
    }
    
    // 检查心跳是否正常
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

    input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, tracking_id);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, x);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, y);
    input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);

    if (need_btn_touch) {
        input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 1);
        print_touch_debug("发送虚拟BTN_TOUCH=1（首个虚拟点）");
    }

    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    print_touch_debug("虚拟触摸按下：客户端=%d, 槽位=%d, ID=%d, 坐标=(%d,%d), 虚拟点数=%d", 
        client ? client->client_id : -1, slot, tracking_id, x, y, touch_info->virtual_touch_count);
}

static void touch_up(int slot, struct client_state *client) {
    unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
    int tracking_id;
    bool need_btn_touch_reset = false;
    int client_slot = -1;
    int i;
    
    // 检查客户端是否有效
    if (!client) {
        print_touch_debug("触摸抬起失败：客户端无效");
        return;
    }
    
    // 检查客户端是否已退出
    if (client->exited) {
        print_touch_debug("触摸抬起失败：客户端 %d 已退出", client->client_id);
        return;
    }
    
    // 检查心跳是否正常
    if (client->heartbeat && !client->heartbeat->alive) {
        print_touch_debug("触摸抬起失败：客户端 %d 心跳异常", client->client_id);
        return;
    }
    
    if (slot < 0 || slot >= MAX_SLOTS) {
        print_touch_debug("触摸抬起失败：无效槽位=%d", slot);
        return;
    }

    LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);

    if (!touch_info->slots[slot].in_use) {
        UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
        print_touch_debug("触摸抬起失败：槽位=%d 未按下", slot);
        return;
    }

    if (client && touch_info->slots[slot].client_id != client->client_id) {
        UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
        print_touch_debug("触摸抬起失败：槽位=%d 不属于客户端=%d", slot, client->client_id);
        return;
    }

    tracking_id = touch_info->slots[slot].tracking_id;

    touch_info->virtual_touch_count--;
    if (touch_info->virtual_touch_count <= 0) {
        touch_info->virtual_touch_count = 0;
        touch_info->virtual_touch_active = false;
    }

    if (touch_info->virtual_touch_count == 0 && touch_info->physical_touch_count == 0) {
        need_btn_touch_reset = true;
    }

    if (client) {
        for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
            if (client->virtual_points[i].in_use && 
                client->virtual_points[i].slot == slot &&
                client->virtual_points[i].tracking_id == tracking_id) {
                client->virtual_points[i].in_use = false;
                client->virtual_points[i].slot = -1;
                client->virtual_points[i].tracking_id = -1;
                client->virtual_point_count--;
                if (client->virtual_point_count < 0) client->virtual_point_count = 0;
                client_slot = i;
                break;
            }
        }
    }

    touch_info->slots[slot].in_use = false;
    touch_info->slots[slot].tracking_id = -1;
    touch_info->slots[slot].x = -1;
    touch_info->slots[slot].y = -1;
    touch_info->slots[slot].client_id = -1;

    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);

    input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);

    if (need_btn_touch_reset) {
        input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
        print_touch_debug("发送虚拟BTN_TOUCH=0（最后虚拟点抬起）");
    }

    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    print_touch_debug("虚拟触摸抬起：客户端=%d, 槽位=%d, ID=%d, 剩余虚拟点数=%d", 
        client ? client->client_id : -1, slot, tracking_id, touch_info->virtual_touch_count);
}
static void touch_move(int slot, int x, int y) {
    unsigned long flags_physical, flags_virtual, flags_slots;

    if (slot < 0 || slot >= MAX_SLOTS) {
        print_touch_debug("触摸移动失败：无效槽位=%d", slot);
        return;
    }

    LOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);

    if (!touch_info->slots[slot].in_use) {
        UNLOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);
        print_touch_debug("触摸移动失败：槽位=%d 未按下", slot);
        return;
    }

    touch_info->slots[slot].x = x;
    touch_info->slots[slot].y = y;

    UNLOCK_ORDER_3(flags_physical, flags_virtual, flags_slots);

    input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, touch_info->slots[slot].tracking_id);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, x);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, y);
    input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
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
    
    // 备份原始设备指针（用于模块卸载时正确清理）
    if (!original_ts_dev) {
        original_ts_dev = dev;
        print_touch_debug("备份原始设备指针: %s\n", dev->name);
    }
    
    // 获取当前设备的ABS参数
    abs_x = &dev->absinfo[ABS_MT_POSITION_X];
    abs_y = &dev->absinfo[ABS_MT_POSITION_Y];
    
    // 创建新的 input_dev（核心步骤）
    new_dev = input_allocate_device();
    if (!new_dev) {
        print_touch_debug("分配新input_dev失败\n");
        return -ENOMEM;
    }
    
    // 设置设备名称（从原设备复制）
    new_dev->name = kstrdup(dev->name, GFP_KERNEL);
    if (!new_dev->name) {
        input_free_device(new_dev);
        return -ENOMEM;
    }
    
    // 复制关键硬件属性
    new_dev->id = dev->id;
    if (dev->phys)
        new_dev->phys = kstrdup(dev->phys, GFP_KERNEL);
    if (dev->uniq)
        new_dev->uniq = kstrdup(dev->uniq, GFP_KERNEL);
    
    // 复制事件类型位图（确保所有原始功能保留）
    memcpy(new_dev->evbit, dev->evbit, sizeof(dev->evbit));
    memcpy(new_dev->keybit, dev->keybit, sizeof(dev->keybit));
    memcpy(new_dev->absbit, dev->absbit, sizeof(dev->absbit));
    memcpy(new_dev->relbit, dev->relbit, sizeof(dev->relbit));
    
    // 设置ABS参数，使用新的slot数量（关键修改点）
    input_set_abs_params(new_dev, ABS_MT_SLOT, 0, new_num_slots - 1, 0, 0);
    input_set_abs_params(new_dev, ABS_MT_TRACKING_ID, -1, new_num_slots, 0, 0);
    input_set_abs_params(new_dev, ABS_MT_POSITION_X, abs_x->minimum, abs_x->maximum, abs_x->fuzz, abs_x->flat);
    input_set_abs_params(new_dev, ABS_MT_POSITION_Y, abs_y->minimum, abs_y->maximum, abs_y->fuzz, abs_y->flat);
    
    // 复制其他MT相关参数（压力、接触面积等）
    for (i = 0; i < ABS_CNT; i++) {
        if (test_bit(i, dev->absbit) && 
            i != ABS_MT_SLOT && i != ABS_MT_TRACKING_ID && 
            i != ABS_MT_POSITION_X && i != ABS_MT_POSITION_Y) {
            const struct input_absinfo *abs = &dev->absinfo[i];
            input_set_abs_params(new_dev, i, abs->minimum, abs->maximum, abs->fuzz, abs->flat);
        }
    }
    
    // 【关键步骤1】注销原设备（这会删除 /dev/input/eventX）
    input_unregister_device(dev);
    print_touch_debug("The original device has been deregistered and is waiting to be re-registered..\n");
    
    // 短暂延迟，确保设备完全注销
    msleep(200);
    
    // 【关键步骤2】注册新设备（这会创建新的 /dev/input/eventX）
    ret = input_register_device(new_dev);
    if (ret) {
        print_touch_debug("Failed to register new device: %d! The framework may not be able to automatically recover.\n", ret);
        input_free_device(new_dev);
        return ret;
    }
    
    // 更新全局触摸屏设备指针
    target_ts_dev = new_dev;
    
    // 更新触摸信息中的handle（如果存在）
    if (touch_info && touch_info->ts_handle) {
        touch_info->ts_handle->dev = new_dev;
    }
    
    print_touch_debug("Device re-registration successful, new slot count: %d, the framework will recognize it automatically\n", new_num_slots);
    return 0;
}





















//虚拟地址转物理地址
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
        
// ========== 内核版本适配开始 ==========
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
        // 6.5+ 版本：6个参数，移除 locked 参数
        down_read(&mm->mmap_lock);
        ret = get_user_pages_remote(mm, va, 1, FOLL_FORCE, &page, NULL);
        up_read(&mm->mmap_lock);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
        // 5.10 - 6.4 版本：7个参数
        down_read(&mm->mmap_lock);
        ret = get_user_pages_remote(mm, va, 1, FOLL_FORCE, &page, NULL, NULL);
        up_read(&mm->mmap_lock);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
        // 5.9 版本：7个参数，但用 mmap_sem（过渡版本，很少见）
        down_read(&mm->mmap_sem);
        ret = get_user_pages_remote(mm, va, 1, FOLL_FORCE, &page, NULL, NULL);
        up_read(&mm->mmap_sem);
#else
        // 5.4 及以下：8个参数（含 vmas 参数）
        down_read(&mm->mmap_sem);
        ret = get_user_pages_remote(NULL, mm, va, 1, FOLL_FORCE, &page, NULL, NULL);
        up_read(&mm->mmap_sem);
#endif
// ========== 内核版本适配结束 ==========
        
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
            // 使用标准屏障替代 __flush_dcache_area
            smp_wmb();
        } else {
            // 使用标准屏障
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
    struct vma_iterator vmi;  // 6.1+ 迭代器
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

    // 彻底绕开 for_each_vma 宏：手动迭代（适配所有内核）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    // Linux 6.1+：手动初始化迭代器 + 循环
    vma_iter_init(&vmi, mm, 0);
    vma = vma_next(&vmi);
    while (vma != NULL) {
#else
    // Linux 6.1-：传统链表手动遍历
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

            // PIE 基址特殊处理
            if (base == 0x8000) {
                pr_info("[qwq] 检测到 PIE 基址 0x8000，调整为 0\n");
                base = 0;
            }

            pr_info("[qwq] 找到模块 %s 基址: 0x%lx (来自 %s)\n",
                    name, base, path_nm);
            break;  // 退出循环
        }

        // 下一个 VMA
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













// 生成随机设备名
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

    // 非拦截模式下，仅允许组合键切换事件（key_code=0表示模式切换）
    if (trp == 0 && key_code != 0) {
        return;
    }

    if (key_info->event_count >= EVENT_QUEUE_SIZE) {
        // print_touch_debug("事件队列已满, 丢弃事件 (trp=%d, key=%d)", trp, key_code);
        return;
    }
    node = kmalloc(sizeof(struct event_node), GFP_ATOMIC);
    if (!node) {
        // print_touch_debug("分配事件节点失败 (trp=%d, key=%d)", trp, key_code);
        return;
    }
    node->event.trp = trp;
    node->event.key_code = key_code;

    spin_lock_irqsave(&key_info->lock, flags);
    list_add_tail(&node->list, &key_info->event_list);
    key_info->event_count++;
    current_count = key_info->event_count;
    spin_unlock_irqrestore(&key_info->lock, flags);
    //print_touch_debug("事件加入队列: trp=%d, key=%d, 队列大小=%d", trp, key_code, current_count);
}

// 从队列获取事件
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



/* 通过进程名找 system_server，发 SIGKILL 让上层重新读取修改后的 maximum=11 
上层框架重启读取： system_server  重启后，InputManagerService 会重新：
读取  /sys/class/input/eventX/device/absinfo  获取  ABS_MT_SLOT  的  max
分配新的  InputDevice  对象和  InputMapper
建立新的触控点跟踪表*/
static void restart_system_server_secure(void) {
    struct task_struct *tsk;
    struct task_struct *target_task = NULL;
    pid_t target_pid = 0;
    uid_t dynamic_uid = 0;
    kuid_t kuid_to_match;
    int name_match_count = 0;
    
    // ---- 第一阶段：查找 system_server，记录其 UID ----
    rcu_read_lock();
    for_each_process(tsk) {
        if (!strcmp(tsk->comm, "system_server")) {
            target_task = tsk;
            target_pid = tsk->pid;
            kuid_to_match = task_uid(tsk);  // 读取内核UID结构
            dynamic_uid = from_kuid(current_user_ns(), kuid_to_match);  // 转换为用户空间UID
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
    //print_touch_debug("找到 system_server: PID=%d, UID=%d\n", target_pid, dynamic_uid);
    // ---- 第二阶段：用动态读取的 UID 精确匹配并重启 ----
    rcu_read_lock();
    for_each_process(tsk) {
        // 同时匹配名称和UID（精确识别）
        if (!strcmp(tsk->comm, "system_server") && 
            uid_eq(task_uid(tsk), kuid_to_match)) {
            get_task_struct(tsk);  // 安全引用，防止进程在操作期间退出
            send_sig_info(SIGKILL, SEND_SIG_PRIV, tsk);  // 发送 SIGKILL
            print_touch_debug("已重启system_server: PID=%d, UID=%d\n", tsk->pid, dynamic_uid);
            put_task_struct(tsk);
            break;  // 只重启第一个精确匹配的
        }
    }
    rcu_read_unlock();
}






//保护 input_dev->mt 指针替换（避免并发访问冲突）
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

    /* 处理触摸屏：注册handle以拦截事件 */
    if (strstr(dev->name, "NVTCapacitiveTouchScreen")) {
        if (!target_ts_dev) {//判断  只执行一次，避免重复注册handle
            target_ts_dev = dev;
            get_device(&dev->dev);
            print_touch_debug("触摸屏捕获：%s\n", dev->name);

            /* ===== 为触摸屏创建并注册handle ===== */
            handle = kzalloc(sizeof(*handle), GFP_KERNEL);
            if (!handle) {
                print_touch_debug("分配触摸屏handle失败\n");
                return -ENOMEM;
            }
            
            handle->dev = dev;
            handle->handler = handler;
            handle->name = "touch_hook";
            
            ret = input_register_handle(handle);//注册
            if (ret) {
                print_touch_debug("注册触摸屏handle失败: %d\n", ret);
                kfree(handle);
                return ret;
            }
            
            ret = input_open_device(handle);//打开设备
            if (ret) {
                print_touch_debug("打开触摸屏设备失败: %d\n", ret);
                input_unregister_handle(handle);
                kfree(handle);
                return ret;
            }
            
            // 保存handle到touch_info
            touch_info->ts_handle = handle;
            print_touch_debug("触摸屏handle注册成功\n");
            
            //原5.10 柔性数组安全扩大 
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
            
          /*  ret = input_mt_reinit_slots(dev, new_slots);// 会导致重启
            if (ret < 0) {
                print_touch_debug("警告：重初始化slots失败: %d，将使用原slots: %d\n", ret, old_slots);
            }*/
            mutex_unlock(&mt_replace_lock);
            

            
            // ========== 获取硬件分辨率 ==========
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

//后续音量拦截
    /* 原有音量键设备绑定逻辑 */
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



// 输入设备断开连接函数
static void key_hook_disconnect(struct input_handle *handle) {
    int i;
    int dev_index = -1;
    struct input_dev *dev = handle->dev;

    if (!dev || !dev->name)
        goto out;

    /* 处理触摸屏设备断开 */
    if (strstr(dev->name, "NVTCapacitiveTouchScreen")) {
        if (touch_info && touch_info->ts_handle == handle) {
            print_touch_debug("触摸屏设备断开连接: %s\n", dev->name);
            touch_info->ts_handle = NULL;
            target_ts_dev = NULL;
            put_device(&dev->dev);
        }
        goto out_cleanup;
    }

    /* 原有按键设备断开逻辑 */
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

// 回调函数：遍历设备并识别目标设备
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
    unsigned long flags_physical, flags_virtual;
    int slot;
    bool should_intercept = false;
    bool virtual_active = false;
    int virtual_count = 0;
    char slot_buf[256] = {0};
    int buf_pos = 0;
    int intercepted_slots[MAX_SLOTS] = {0};
    int intercepted_count = 0;
    
    // 1. 检查是否为触摸屏设备
    if (dev && dev->name && strstr(dev->name, "NVTCapacitiveTouchScreen")) {
        // 跟踪当前槽位
        if (type == EV_ABS && code == ABS_MT_SLOT) {
            LOCK_ORDER_1(flags_physical);
            touch_info->current_slot = value;
            UNLOCK_ORDER_1(flags_physical);
            return false;
        }
        
        // 处理触摸屏事件
        if (type == EV_KEY && code == BTN_TOUCH) {
            if (value == 1) {
                // 物理BTN_TOUCH按下
                    } else if (value == 0) {
            // 物理BTN_TOUCH抬起 - 需要检查虚拟状态
            LOCK_ORDER_2(flags_physical, flags_virtual);
            
            virtual_active = touch_info->virtual_touch_active;
            virtual_count = touch_info->virtual_touch_count;
            
            if (virtual_active && virtual_count > 0) {
                should_intercept = true;
                
                // 【修复】检查哪些物理槽位活跃，并清除它们的状态
                for (i = 0; i < MAX_SLOTS; i++) {
                    if (touch_info->physical_slots_active[i]) {
                        intercepted_slots[intercepted_count++] = i;
                        // 清除物理槽位状态
                        touch_info->physical_slots_active[i] = false;
                        touch_info->physical_slots_tracking_id[i] = -1;
                    }
                }
                // 重置物理触摸计数
                touch_info->physical_touch_count = 0;
                
                // 构建调试信息
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
                // 没有虚拟点，清除所有物理槽位状态
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
        // 跟踪MT_TRACKING_ID事件
        else if (type == EV_ABS && code == ABS_MT_TRACKING_ID) {
            LOCK_ORDER_1(flags_physical);
            
            slot = touch_info->current_slot;
            
            if (slot >= 0 && slot < MAX_SLOTS) {
                if (value == -1) {
                    // 物理触摸点抬起（MT槽位）
                    if (touch_info->physical_slots_active[slot]) {
                        touch_info->physical_slots_active[slot] = false;
                        touch_info->physical_slots_tracking_id[slot] = -1;
                        if (touch_info->physical_touch_count > 0) {
                            touch_info->physical_touch_count--;
                        }
                        // print_touch_debug("抬起 槽位=%d 剩余=%d", slot, touch_info->physical_touch_count);
                    }
                } else if (value >= 0) {
                    // 物理触摸点按下（MT槽位）
                    // 只有在value>0时才计数，避免0值重复计数
                    if (value > 0) {
                        if (!touch_info->physical_slots_active[slot]) {
                            touch_info->physical_slots_active[slot] = true;
                            touch_info->physical_touch_count++;
                        }
                        touch_info->physical_slots_tracking_id[slot] = value;
                        // print_touch_debug("按下 槽位=%d ID=%d 总数=%d", slot, value, touch_info->physical_touch_count);
                    }
                }
            }
            
            UNLOCK_ORDER_1(flags_physical);
        }
        
        return false; // 不拦截其他触摸事件
    }
    

    // 2. 原有的按键设备处理逻辑（保持不变）
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
    
    // 1. 关机键事件处理
    if (code == KEY_POWER) {
        if (value == 1) {  // 关机键按下
            key_info->power_key_pressed = true;
            key_info->power_press_time = ktime_get();
            key_info->combo_triggered = false;
            key_info->combo_type = 0;
            print_touch_debug("关机键按下，等待音量键组合...");
        } else {  // 关机键抬起
            key_info->power_key_pressed = false;
            print_touch_debug("关机键抬起");
            // 组合键确认：两键均抬起后触发模式切换
            if (key_info->combo_triggered) {
                // 音量加组合 → 进入拦截模式（trp=1, key_code=0）
                if (key_info->combo_type == 1 && !key_info->volup_pressed) {
                    key_info->state = STATE_INTERCEPT;
                    add_key_event(1, 0);  // 拦截模式开启
                    key_info->combo_triggered = false;
                    return true;
                }
                // 音量减组合 → 退出拦截模式（trp=0, key_code=0）
                else if (key_info->combo_type == 2 && !key_info->voldown_pressed) {
                    key_info->state = STATE_NORMAL;
                    add_key_event(0, 0);  // 拦截模式关闭
                    key_info->combo_triggered = false;
                    return true;
                }
            }
        }
        return false;
    }
    
    // 2. 音量键状态跟踪
    if (code == KEY_VOLUMEUP) {
        key_info->volup_pressed = (value == 1);
        print_touch_debug("音量加状态：%s", value == 1 ? "按下" : "抬起");
    } else if (code == KEY_VOLUMEDOWN) {
        key_info->voldown_pressed = (value == 1);
        print_touch_debug("音量减状态：%s", value == 1 ? "按下" : "抬起");
    }
    
    // 3. 组合键触发判断（600ms内按下）
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
    
    // 4. 组合键确认：音量键抬起后检查
    if (value == 0 && (code == KEY_VOLUMEUP || code == KEY_VOLUMEDOWN)) {
        if (key_info->combo_triggered && !key_info->power_key_pressed) {
            // 音量加组合 → 进入拦截
            if (key_info->combo_type == 1) {
                key_info->state = STATE_INTERCEPT;
                add_key_event(1, 0);  // 拦截模式开启
                key_info->combo_triggered = false;
                return true;
            }
            // 音量减组合 → 退出拦截
            else if (key_info->combo_type == 2) {
                key_info->state = STATE_NORMAL;
                add_key_event(0, 0);  // 拦截模式关闭
                key_info->combo_triggered = false;
                return true;
            }
        }
    }
    
    // 5. 拦截模式下：生成按键事件
    if (key_info->state == STATE_INTERCEPT) {
        if (code == KEY_VOLUMEUP) {
            // 音量加按下（trp=1, key_code=1）/抬起（trp=1, key_code=2）
            int key_code = (value == 1) ? 1 : 2;
            add_key_event(1, key_code);
            return true;
        } else if (code == KEY_VOLUMEDOWN) {
            // 音量减按下（trp=1, key_code=3）/抬起（trp=1, key_code=4）
            int key_code = (value == 1) ? 3 : 4;
            add_key_event(1, key_code);
            return true;
        }
    }
    
    return false;
}


// 输入事件处理函数（仅处理被filter拦截的事件）
static void key_hook_event(struct input_handle *handle, unsigned int type, unsigned int code, int value) {
    // 此处无需额外逻辑，被拦截的事件已在filter中处理
    // 仅打印日志确认拦截
    // print_touch_debug("事件已拦截: type=%d, code=%d, value=%d\n", type, code, value);
}

// 输入设备匹配表
static const struct input_device_id key_hook_ids[] = {
    {
        .evbit = { BIT_MASK(EV_KEY) },  // 匹配支持按键事件的设备
        .driver_info = 1
    },
    { }  // 结束标记
};
MODULE_DEVICE_TABLE(input, key_hook_ids);







/* ---------------- UNIX域套接字通讯模块 ---------------- */
static int debug = 0;  // 0=套接字fd通讯，1=dev通讯

// UNIX域套接字路径定义，路径定义为普通字符数组（不带\0前缀）
static const char unix_socket_name[] = "zmem";
enum {
    ST_CLOSED,      // 关闭状态
    ST_LISTEN       // 监听状态
};
static atomic_t g_state = ATOMIC_INIT(ST_CLOSED);
static struct socket *g_listen_sock = NULL;
static struct task_struct *g_listen_thread = NULL;
static DEFINE_MUTEX(g_socket_mutex);
static const struct file_operations anon_fops;
static atomic_t anon_ref = ATOMIC_INIT(0);




//安全创建监听套接字，地址长度计算（兼容32/64位，旧版隐性兼容，新版显式修正）
static int create_listen_socket(void) {
    int ret = 0;
    struct sockaddr_un addr;
    size_t name_len = strlen(unix_socket_name);
    size_t addr_len;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';  // 抽象命名空间
    memcpy(addr.sun_path + 1, unix_socket_name, name_len);
    // 关键修复：用offsetof计算地址长度（旧版隐性正确，新版显式修正）
    addr_len = offsetof(struct sockaddr_un, sun_path) + 1 + name_len;

    mutex_lock(&g_socket_mutex);
    if (g_listen_sock || atomic_read(&g_state) != ST_CLOSED) {
        ret = -EBUSY;
        goto out_unlock;
    }

    // 套接字创建（复用旧版稳定逻辑）
    ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &g_listen_sock);
    if (ret < 0) {
        print_touch_debug("创建套接字失败: %d\n", ret);
        goto out_unlock;
    }

    // 绑定+监听（旧版无状态切换问题，直接复用）
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





// 安全关闭监听套接字
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

// 发送文件描述符
static int unix_send_fd(struct socket *sock, int fd) {
    struct kvec iov;
    char dummy = 0;
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;
    struct msghdr msg; // 先声明，再初始化（兼容C90）

    // 1. 初始化数据缓冲区（kvec）
    iov.iov_base = &dummy;
    iov.iov_len = 1;
    // 2. 初始化msghdr（5.10内核用msg_iter替代msg_iov/msg_iovlen）
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cbuf;          // 控制消息缓冲区（存fd）
    msg.msg_controllen = sizeof(cbuf);
    iov_iter_kvec(&msg.msg_iter, WRITE, &iov, 1, iov.iov_len); // 适配5.10内核
    // 3. 构造控制消息（传递fd，SCM_RIGHTS是标准用法）
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = fd;
    // 4. 发送消息（kernel_sendmsg参数适配msg_iter）
    return kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
}





// 强制关闭监听套接字（对接成功后立即调用）
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





// 客户端对接处理：对接成功→发FD→关套接字→保持通讯→退出
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
    
    // 进程名白名单（可以修改）
    static const char *allowed_clients[] = {
        "demo",               // 进程名
        "KISS",
        NULL                        // 结束标记
    };

    // 获取套接字信息
    sk = cli->sk;
    peer_cred = sk->sk_peer_cred;
    if (!peer_cred || !uid_valid(peer_cred->uid)) {
        print_touch_debug("无法获取客户端凭证信息\n");
        sock_release(cli);
        return -EACCES;
    }
    // 获取客户端UID
    uid = from_kuid(current_user_ns(), peer_cred->uid);
    // 获取客户端PID
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
    // 获取客户端进程名
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
    // 检查UID权限（必须为root）
    if (uid != 0) {
        print_touch_debug("拒绝非root用户连接: PID=%d, UID=%d, 进程名='%s'\n", peer_pid, uid, comm);
        sock_release(cli);
        return -EACCES;
    }
    // 检查进程名是否在白名单中
    if (allowed_clients[0] != NULL) {
        int i;
        for (i = 0; allowed_clients[i] != NULL; i++) {
            if (strcmp(comm, allowed_clients[i]) == 0) {
                allowed = true;
                break;
            }
        }
    } else {
        // 如果白名单为空，则允许所有root进程连接
        allowed = true;
    }
    if (!allowed) {
        print_touch_debug("拒绝非白名单进程连接: PID=%d, 进程名='%s'\n", peer_pid, comm);
        sock_release(cli);
        return -EACCES;
    }
    // 创建匿名inode文件
    file = anon_inode_getfile("unix_anon_fd", &anon_fops, NULL, O_RDWR);
    if (IS_ERR(file)) {
        ret = PTR_ERR(file);
        sock_release(cli);
        return ret;
    }
    // 分配FD号
    fd = get_unused_fd_flags(O_RDWR);
    if (fd < 0) {
        fput(file);
        sock_release(cli);
        return fd;
    }
    atomic_inc(&anon_ref);
    // 安装文件到FD
    fd_install(fd, file);
    // 发送FD给客户端
    ret = unix_send_fd(cli, fd);
    if (ret < 0) {
        print_touch_debug("发送FD失败: %d\n", ret);
        // 清理：移除FD并关闭文件
        put_unused_fd(fd);
        fput(file);
        sock_release(cli);
        return ret;
    }
    
    // 创建客户端状态
    client = create_client(peer_pid, uid, file);
    if (!client) {
        print_touch_debug("创建客户端状态失败\n");
        fput(file);
        sock_release(cli);
        return -ENOMEM;
    }

    // 设置文件私有数据，便于后续查找
    file->private_data = client;
    // 成功发送：fd已被sendmsg转移给客户端
    print_touch_debug("对接成功: PID=%d, UID=%d, 进程名='%s', 匿名FD=%d\n", peer_pid, uid, comm, fd);
    sock_release(cli);
    return 0;
}




// 主监听线程：对接→关套接字→退出→自动重开（循环）
static int unix_listen_thread(void *data) {
    int ret;
    struct socket *cli_sock = NULL;

    // 旧版核心逻辑：线程启动后自动尝试创建监听（避免卡住）
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
            // 接受客户端连接（旧版稳定逻辑）
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
            // 启动客户端处理线程（旧版无状态切换问题）
            kthread_run(unix_client_handler, cli_sock, "unix_cli_handler");
            cli_sock = NULL;
        } else {
            // 旧版逻辑：关闭状态下重试创建（避免一直卡住）
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



// 客户端退出触发：标记退出，触发自动重开（无参数控制，强制开启）
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
    
    // 强制清理该客户端的所有虚拟点
    for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
        if (client->virtual_points[i].in_use) {
            int slot = client->virtual_points[i].slot;
            int tracking_id = client->virtual_points[i].tracking_id;
            
            print_touch_debug("处理客户端虚拟点[%d]：槽位=%d, ID=%d", i, slot, tracking_id);
            
            if (slot >= 0 && slot < MAX_SLOTS && target_ts_dev) {
                unsigned long flags_physical, flags_virtual, flags_slots, flags_client;
                bool slot_in_use = false;
                int slot_client_id = -1;
                
                // 检查槽位状态
                LOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                
                slot_in_use = touch_info->slots[slot].in_use;
                slot_client_id = touch_info->slots[slot].client_id;
                
                // 只有确认是这个客户端的槽位才清理
                if (slot_in_use && slot_client_id == client->client_id) {
                    bool need_btn_touch_reset = false;
                    
                    // 更新虚拟触摸计数
                    touch_info->virtual_touch_count--;
                    if (touch_info->virtual_touch_count <= 0) {
                        touch_info->virtual_touch_count = 0;
                        touch_info->virtual_touch_active = false;
                    }
                    
                    // 检查是否需要发送 BTN_TOUCH=0
                    if (touch_info->virtual_touch_count == 0 && 
                        touch_info->physical_touch_count == 0) {
                        need_btn_touch_reset = true;
                    }
                    
                    // 重置槽位状态
                    touch_info->slots[slot].in_use = false;
                    touch_info->slots[slot].tracking_id = -1;
                    touch_info->slots[slot].x = -1;
                    touch_info->slots[slot].y = -1;
                    touch_info->slots[slot].client_id = -1;
                    
                    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    
                    // 发送MT触摸抬起事件（无锁）
                    input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
                    input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                    
                    if (need_btn_touch_reset) {
                        input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
                        print_touch_debug("发送BTN_TOUCH=0（客户端断开）");
                    }
                    
                    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
                    print_touch_debug("强制抬起成功：槽位=%d, ID=%d, 剩余虚拟点=%d", 
                        slot, tracking_id, touch_info->virtual_touch_count);
                } else {
                    UNLOCK_ORDER_4(flags_physical, flags_virtual, flags_slots, flags_client);
                    print_touch_debug("槽位=%d 状态不匹配(in_use=%d, client_id=%d)，跳过", 
                        slot, slot_in_use, slot_client_id);
                }
            }
            
            // 清除客户端记录
            client->virtual_points[i].in_use = false;
            client->virtual_points[i].slot = -1;
            client->virtual_points[i].tracking_id = -1;
        }
    }
    
    client->virtual_point_count = 0;
    
    // 停止心跳定时器
    if (client->heartbeat) {
        del_timer_sync(&client->heartbeat->heartbeat_timer);
        kfree(client->heartbeat);
        client->heartbeat = NULL;
    }
    
    // 移除客户端
    remove_client(client);
    
    // 释放客户端内存
    kfree(client);
    
cleanup_ref:
    atomic_dec(&anon_ref);
    print_touch_debug("客户端清理完成，剩余引用计数=%d", atomic_read(&anon_ref));
    return 0;
}








// 匿名inode文件操作：ioctl（处理UNIX套接字控制命令）
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
        // 手动开启监听（首次对接前用）
        case CMD_OPEN_UNIX:
            mutex_lock(&g_socket_mutex);
            if (atomic_read(&g_state) == ST_CLOSED && !g_listen_sock) {
                ret = create_listen_socket();
                if (ret == 0) atomic_set(&g_state, ST_LISTEN);
            } else ret = -EBUSY;
            mutex_unlock(&g_socket_mutex);
            print_touch_debug("命令触发：手动开启监听\n");
            break;
// 在OP_TOUCH_MOVE case后添加
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
        // 手动关闭监听（可选）
        case CMD_CLOSE_UNIX:
           // force_close_listen_socket();
            close_listen_socket();
            print_touch_debug("命令触发：手动关闭监听\n");
            break;

        // 第一个进程发送：重新开启监听（一对多核心命令）
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

        // 原有IOCTL命令（内存读写/触摸控制等）保持不变
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                return -EFAULT;
       //     ret = read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size);
            if (ret != 0)
                return -EFAULT;
            break;
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                return -EFAULT;
       //     ret = write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size);
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
    // 获取客户端
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
    // 获取客户端
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
            if (copy_from_user(&tm, (void __user*)arg, sizeof(tm)))
                return -EFAULT;
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[tm.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (!slot_used) {
                print_touch_debug("槽位=%d 未按下，无法移动\n", tm.slot);
                return -EINVAL;
            }
            touch_move(tm.slot, tm.x, tm.y);
            break;
        }

        default:
            ret = -ENOIOCTLCMD;
            break;
    }
    return ret;
}


// 匿名inode文件操作集
static const struct file_operations anon_fops = {
    .owner          = THIS_MODULE,
    .release        = anon_release,
    .unlocked_ioctl = anon_ioctl,
};

// UNIX套接字模块初始化
static int unix_socket_init(void) {
    int ret = 0;
    mutex_init(&g_socket_mutex);
    atomic_set(&g_state, ST_CLOSED);

    // 启动监听线程（自动开启首次监听）
    g_listen_thread = kthread_run(unix_listen_thread, NULL, "unix_listen_thread");
    if (IS_ERR(g_listen_thread)) {
        ret = PTR_ERR(g_listen_thread);
        print_touch_debug("启动监听线程失败: %d\n", ret);
        return ret;
    }

    print_touch_debug("UNIX套接字模块初始化完成\n");
    return 0;
}


// UNIX套接字模块清理
static void unix_socket_cleanup(void) {
    // 停止监听线程
    if (g_listen_thread) {
        kthread_stop(g_listen_thread);
        g_listen_thread = NULL;
    }
   close_listen_socket();
    // 销毁锁
    mutex_destroy(&g_socket_mutex);
    print_touch_debug("UNIX套接字模块清理完成\n");
}







/* ---------------- IOCTL命令处理（兼容双通讯模式） ---------------- */
static long my_dev_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg) {
        COPY_MEMORY cm;
        MODULE_BASE mb;
        char name[0x100] = {0};
        USER_EVENT user_ev = {0};
        touch_move_t tm;
        touch_down_t td;
        touch_up_t tu;
		int ret=0;
		struct client_state *client;  // 添加声明

        switch (cmd) {
/*
            case OP_READ_MEM:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                    return -EFAULT;
                ret = read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size);
                if (ret != 0)
                    return -EFAULT;
                break;

            case OP_WRITE_MEM:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                    return -EFAULT;
                ret = write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size);
                if (ret != 0)
                    return -EFAULT;
                break;
*/
// 在OP_TOUCH_MOVE case后添加
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
    // 获取客户端
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
    // 获取客户端
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
                if (copy_from_user(&tm, (void __user*)arg, sizeof(tm)))
                    return -EFAULT;
                if (!target_ts_dev) {
                    print_touch_debug("未找到触摸屏设备\n");
                    return -ENODEV;
                }
                spin_lock_irqsave(&touch_info->lock, flags);
                slot_used = touch_info->slots[tm.slot].in_use;
                spin_unlock_irqrestore(&touch_info->lock, flags);
                if (!slot_used) {
                    print_touch_debug("槽位=%d 未按下，无法移动\n", tm.slot);
                    return -EINVAL;
                }
                touch_move(tm.slot, tm.x, tm.y);
                break;
            }
            
            default:
                return -ENOTTY;
        }
        return 0;
}

// 设备打开操作（修复节点销毁问题）
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

// 设备操作函数集
struct file_operations dev_functions = {
    .owner   = THIS_MODULE,
    .open    = my_dev_open,
    .release = my_dev_close,
    .unlocked_ioctl = my_dev_ioctl,
};











// 隐藏模块（对抗检测）
static void hide_module(void) {
    struct module *mod = THIS_MODULE;

    // 【GKI兼容】直接删除，无需先检查文件是否存在（删除失败忽略）
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
    /*整段 .text 设为只读，破坏 bpf trampoline 写入 */
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
    int cpu;
    ret = 0;
    
    // 初始化 PID 读写锁
    for (i = 0; i < LOCK_BUCKETS; i++) {
        rwlock_init(&pid_locks[i]);
    }
    
    // 初始化触摸状态
    touch_info = kzalloc(sizeof(struct touch_hook_state), GFP_KERNEL);
    if (!touch_info) {
        print_touch_debug("分配触摸状态结构失败\n");
        ret = -ENOMEM;
        goto err_touch_init;
    }
    
    spin_lock_init(&touch_info->lock);          // slots 锁
    spin_lock_init(&touch_info->virtual_lock);   // 虚拟状态锁
    spin_lock_init(&touch_info->physical_lock);  // 物理状态锁
    spin_lock_init(&touch_info->client_lock);

    // 初始化触摸槽位状态
    for (i = 0; i < MAX_SLOTS; i++) {
        // 虚拟槽位
        touch_info->slots[i].in_use = false;
        touch_info->slots[i].tracking_id = -1;
        touch_info->slots[i].x = -1;
        touch_info->slots[i].y = -1;
        touch_info->slots[i].client_id = -1;
        // 物理槽位
        touch_info->physical_slots_active[i] = false;
        touch_info->physical_slots_tracking_id[i] = -1;
    }
    // 初始化计数器
    touch_info->next_tracking_id = 1000;
    touch_info->virtual_touch_active = false;
    touch_info->virtual_touch_count = 0;
    touch_info->physical_touch_count = 0;
    touch_info->current_slot = 0;//触摸槽位范围[0-9] 修改后[0-12]  不建议改为-1
    touch_info->ts_handle = NULL;
    touch_info->next_client_id = 0;

    // 初始化按键状态管理
    key_info = kzalloc(sizeof(struct key_hook_state), GFP_KERNEL);
    if (!key_info) {
        print_touch_debug("分配按键状态结构失败\n");
        ret = -ENOMEM;
        goto err_key_init;
    }
    
    spin_lock_init(&key_info->lock);
    init_waitqueue_head(&key_info->waitq);
    INIT_LIST_HEAD(&key_info->event_list);
    INIT_LIST_HEAD(&touch_info->client_list);//初始化客户端列表
    key_info->state = STATE_NORMAL;
    key_info->power_key_pressed = false;
    key_info->volup_pressed = false;
    key_info->voldown_pressed = false;
    key_info->combo_triggered = false;
    key_info->touch_intercept_enabled = true; // 启用触摸拦截
    
    // 注册输入事件处理器
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
    // 分配字符设备号
    devicename = get_rand_str();
    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
    if (ret < 0) {
        print_touch_debug("分配设备号 (ret=%d)\n", ret);
        goto err_alloc_chrdev;
    }
    print_touch_debug("设备号: %d:%d\n", MAJOR(mem_tool_dev_t), MINOR(mem_tool_dev_t));
    // 初始化字符设备
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
    // 创建设备类
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
    // 创建设备节点
    memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename);
    if (IS_ERR(memdev->dev)) {
        ret = PTR_ERR(memdev->dev);
        print_touch_debug("创建设备节点失败 (ret=%d)\n", ret);
        goto err_device_create;
    }
    print_touch_debug("设备初始化完成：/dev/%s\n", devicename);
}


if (debug==0) {
    // 初始化UNIX套接字模块
    ret = unix_socket_init();
    if (ret != 0) {
        print_touch_debug("UNIX套接字模块初始化失败 (ret=%d)\n", ret);
        goto err_unix_init;
    }
}

    msleep(300);
    /* 让触摸上层框架重新读取 slot maximum */
	restart_system_server_secure();//重启system_server
    msleep(300);
        hide_module(); // 模块隐藏
    print_touch_debug("驱动模块加载完成\n");
    return 0;

    // 错误处理流程
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
    int i;  // 添加变量声明
    
    // 清理所有客户端
    if (touch_info) {
        spin_lock_irqsave(&touch_info->client_lock, flags);
        list_for_each_entry_safe(client, client_tmp, &touch_info->client_list, list) {
            print_touch_debug("清理残留客户端: ID=%d, PID=%d", 
                             client->client_id, client->pid);
            
            // 清理虚拟点
            for (i = 0; i < MAX_SLOTS_PER_CLIENT; i++) {
                if (client->virtual_points[i].in_use) {
                    int slot = client->virtual_points[i].slot;
                    if (slot >= 0 && slot < MAX_SLOTS && target_ts_dev) {
                        // 发送触摸抬起事件
                        input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
                        input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
                    }
                }
            }
            
            // 停止心跳定时器
            if (client->heartbeat) {
                del_timer_sync(&client->heartbeat->heartbeat_timer);
                kfree(client->heartbeat);
            }
            
            // 从列表中移除并释放
            list_del(&client->list);
            kfree(client);
        }
        spin_unlock_irqrestore(&touch_info->client_lock, flags);
    }
    
    unix_socket_cleanup();//清理UNIX套接字模块
    // 清理事件队列
    list_for_each_entry_safe(node, tmp, &key_info->event_list, list) {
        list_del(&node->list);
        kfree(node);
    }
    // 清理触摸屏handle
    if (touch_info && touch_info->ts_handle) {
        input_close_device(touch_info->ts_handle);
        input_unregister_handle(touch_info->ts_handle);
        kfree(touch_info->ts_handle);
    }
    // 释放target_ts_dev引用
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




// 使用模块宏
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