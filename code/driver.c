#ifndef DRIVER_H
#define DRIVER_H
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <asm/pgtable.h>
#include <linux/set_memory.h>
#include <linux/version.h>
#include <linux/rwlock.h>
#include <linux/input.h>
#include <linux/wait.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/kobject.h>
#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/input/mt.h>
#include <linux/of.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <asm/unistd.h>
#include <linux/rcupdate.h>
#include <linux/uio.h>
#include <asm/processor.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <asm/barrier.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/pid_namespace.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/rculist_bl.h>
#include <linux/sched/task.h>
#include <linux/hash.h>
#include <linux/proc_ns.h>
#include <linux/ptrace.h>
#include <linux/cgroup.h>
#include <linux/cgroup-defs.h>
#include <linux/fb.h>
#include <drm/drm_device.h>
#include <drm/drm_drv.h>
#include <drm/drm_crtc.h>
#include <drm/drm_connector.h>
#include <drm/drm_modes.h>
#include <linux/un.h>
#include <linux/anon_inodes.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/fdtable.h>
#include <linux/module.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/preempt.h>
#include <asm/mte.h>
#include <linux/kprobes.h>  // 添加kprobes支持
#include <linux/pagemap.h>
#include <linux/pfn.h>
#include <linux/memory.h>





// 设备与常量定义
#define DEVICE_NAME "qwqet"
#define LOCK_BUCKETS 256
#define EVENT_QUEUE_SIZE 32  // 事件队列大小
#define COMBO_KEY_TIMEOUT 600  // 组合键时间窗口(ms)
#define UNIX_PATH_LEN 32

// 按键编码（与硬件匹配）
#define KEY_POWER 116
#define KEY_VOLUMEUP 115
#define KEY_VOLUMEDOWN 114

// IOCTL操作命令
enum OPERATIONS {
    OP_INIT_KEY = 0x200,
    OP_READ_MEM = 0x201,
    OP_WRITE_MEM = 0x202,
    OP_MODULE_BASE = 0x203,//获取so模块地址
    OP_MODULE_PID = 0x204,//获取进程pid
    OP_HIDE_PID = 205,//隐藏进程pid
    OP_GET_EVENT = 0x206,//获取拦截状态+按键事件
    OP_TOUCH_MOVE = 0x207, //触摸移动，可在操作途中动态更换目标点，形成曲线移动轨迹
    OP_TOUCH_DOWN = 0x208,    // 触摸按下（仅按下，不自动抬起）
    OP_TOUCH_UP = 0x209,      // 触摸抬起（显式调用才抬起）
};

// UNIX域套接字专用命令
#define CMD_OPEN_UNIX  _IO('X', 2)  // 打开UNIX域套接字
#define CMD_CLOSE_UNIX _IO('X', 3)  // 关闭UNIX域套接字
#define CMD_REOPEN_UNIX _IO('X', 1) // 重新打开UNIX域套接字

// 事件类型宏定义（清晰区分事件含义）
#define EVENT_ENTER_INTERCEPT 1  // 进入拦截模式
#define EVENT_EXIT_INTERCEPT 0   // 退出拦截模式
#define EVENT_KEY_PRESS 1        // 按键按下
#define EVENT_KEY_RELEASE 0      // 按键抬起

// 数据结构定义
typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

// 按键事件结构（用户空间与内核同步）
typedef struct _KEY_EVENT {
    int tp;         // 事件类型（模式切换/按键动作）
    int key_code;   // 1=音量加, 2=音量减, 0=模式切换
} KEY_EVENT, *PKEY_EVENT;

// 拦截状态枚举
enum KEY_HOOK_STATE {
    STATE_NORMAL = 0,       // 正常模式
    STATE_INTERCEPT = 1     // 拦截模式
};

typedef struct _USER_EVENT {
    int trp;         // 0=非拦截模式, 1=拦截模式
    int key_code;    // 0=无事件, 1=音量加按下, 2=音量加抬起, 3=音量减按下, 4=音量减抬起
} USER_EVENT, *PUSER_EVENT;

// 事件队列节点（使用统一结构体）
struct event_node {
    struct list_head list;
    USER_EVENT event;  // 存储统一事件结构
};

struct key_hook_state {
    enum KEY_HOOK_STATE state;       // 当前拦截状态
    bool power_key_pressed;          // 关机键按下状态
    bool volup_pressed;             // 音量加按下状态
    bool voldown_pressed;           // 音量减按下状态
    ktime_t power_press_time;        // 关机键按下时间戳
    bool combo_triggered;            // 组合键是否触发（核心标记）
    int combo_type;                 // 新增：1=音量加组合, 2=音量减组合, 0=未触发
    wait_queue_head_t waitq;         // 等待队列
    struct list_head event_list;     // 事件队列
    spinlock_t lock;                 // 自旋锁
    int event_count;                 // 事件计数
    bool touch_intercept_enabled; //触摸拦截标志
};

// 设备管理结构
struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
    int max;
};

// 目标设备白名单（需绑定的按键设备）
static const char *target_devices[] = {
    "gpio-keys",               // 音量加
    "pmic_resin",              // 音量减
    "pmic_pwrkey",             // 电源键
    "NVTCapacitiveTouchScreen" // 触摸屏
};

#define TARGET_DEV_COUNT ARRAY_SIZE(target_devices)

// 全局变量
static struct mem_tool_device *memdev;
static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;
static char mod_obf_name[16] = {0};
static rwlock_t pid_locks[LOCK_BUCKETS];
static struct key_hook_state *key_info;
static struct input_handler key_hook_handler;
static DEFINE_MUTEX(dev_lifecycle_lock);   /* 保护 create/destroy */

// 设备绑定跟踪
static atomic_t bound_dev_count = ATOMIC_INIT(0);
static atomic_t target_bound_mask = ATOMIC_INIT(0);

/* ---------------- 基础工具函数 ---------------- */
// 获取PID对应的读写锁
static rwlock_t *lock_for_pid(pid_t pid) {
    return &pid_locks[pid % LOCK_BUCKETS];
}

typedef struct {
    int last_x, last_y;          // 每次移动的起点
} touch_move_ctx_t;







// 添加调试打印函数，避免编码问题
static void print_touch_debug(const char *format, ...) {
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






#define MAX_SLOTS 13
// 触摸按下/移动/抬起参数结构体（新增slot字段，支持指定槽位）
typedef struct {
    int slot;  // 新增：指定要按下的槽位（0~9）
    int x, y;  // 按下的屏幕坐标
} touch_down_t;

typedef struct {
    int slot;  // 新增：指定要移动的槽位（0~9）
    int x, y;  // 目标坐标
} touch_move_t;

typedef struct {
    int slot;  // 新增：指定要抬起的槽位（0~9）
    int dummy;
} touch_up_t;



struct touch_hook_state {
    struct {
        bool in_use;
        int x, y;
        int tracking_id;
    } slots[MAX_SLOTS];
    spinlock_t lock;
    int next_tracking_id;
    // 虚拟触摸状态
    bool virtual_touch_active;
    int virtual_touch_count;
    spinlock_t virtual_lock;
    // 物理触摸状态（按槽位跟踪）
    bool physical_slots_active[MAX_SLOTS];  // 新增：每个槽位的物理触摸状态
    int physical_slots_tracking_id[MAX_SLOTS];  // 新增：每个槽位的tracking_id
    int physical_touch_count;
    spinlock_t physical_lock;
    // 触摸屏的input_handle
    struct input_handle *ts_handle;
    // 当前处理的槽位
    int current_slot;  //跟踪当前槽位
};


// 全局变量初始化（移除原单点状态变量）
static struct touch_hook_state *touch_info;
static struct input_dev *target_ts_dev = NULL;

// 全局分辨率变量（保持不变）
static int hw_min_x, hw_max_x, hw_min_y, hw_max_y;
static int hw_screen_w, hw_screen_h;
//static int sys_screen_w = 1800;
//static int sys_screen_h = 2880;

/*static void map_coords_to_ts(int *x, int *y) {
    *x = hw_min_x + (*x * hw_screen_w) / sys_screen_w;
    *y = hw_min_y + (*y * hw_screen_h) / sys_screen_h;
    *x = clamp_t(int, *x, hw_min_x, hw_max_x);
    *y = clamp_t(int, *y, hw_min_y, hw_max_y);
}*/



// 辅助宏：确保锁顺序一致
#define LOCK_PHYSICAL_THEN_VIRTUAL(flags_phys, flags_virt) \
    do { \
        spin_lock_irqsave(&touch_info->physical_lock, (flags_phys)); \
        spin_lock_irqsave(&touch_info->virtual_lock, (flags_virt)); \
    } while (0)

#define UNLOCK_VIRTUAL_THEN_PHYSICAL(flags_phys, flags_virt) \
    do { \
        spin_unlock_irqrestore(&touch_info->virtual_lock, (flags_virt)); \
        spin_unlock_irqrestore(&touch_info->physical_lock, (flags_phys)); \
    } while (0)

// 触摸按下 - 修复锁顺序
static void touch_down(int slot, int x, int y) {
    unsigned long flags_physical, flags_virtual;
    int tracking_id;
    bool need_btn_touch = false;
    int old_virtual_count;
    
    if (slot < 0 || slot >= MAX_SLOTS) {
        print_touch_debug("触摸按下失败：无效槽位=%d", slot);
        return;
    }
    //坐标有效性检查
    if (x < -1 || x >= hw_screen_w || y < -1 || y >= hw_screen_h) {
        print_touch_debug("触摸按下失败：坐标(%d,%d)超出屏幕范围", x, y);
        return;
    }

    // 按照锁顺序：先physical_lock，后virtual_lock
    LOCK_PHYSICAL_THEN_VIRTUAL(flags_physical, flags_virtual);
    
    // 检查该槽位是否已被占用
    if (touch_info->slots[slot].in_use) {
        UNLOCK_VIRTUAL_THEN_PHYSICAL(flags_physical, flags_virtual);
        print_touch_debug("触摸按下失败：槽位=%d 已被占用", slot);
        return;
    }
    
    // 分配唯一tracking_id，标记槽位状态
    tracking_id = ++touch_info->next_tracking_id;
    touch_info->slots[slot].in_use = true;
    touch_info->slots[slot].x = x;
    touch_info->slots[slot].y = y;
    touch_info->slots[slot].tracking_id = tracking_id;
    
    // 更新虚拟触摸计数
    old_virtual_count = touch_info->virtual_touch_count;
    touch_info->virtual_touch_count++;
    touch_info->virtual_touch_active = true;
    
    // 检查是否需要发送 BTN_TOUCH=1
    // 如果这是第一个虚拟触摸点，且没有物理触摸，则需要发送BTN_TOUCH=1
    if (old_virtual_count == 0 && touch_info->physical_touch_count == 0) {
        need_btn_touch = true;
    }
    
    UNLOCK_VIRTUAL_THEN_PHYSICAL(flags_physical, flags_virtual);
    
    // 发送MT触摸按下事件
    input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, tracking_id);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, x);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, y);
    input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
    
    // 需要时发送 BTN_TOUCH=1
    if (need_btn_touch) {
        input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 1);
        print_touch_debug("发送虚拟BTN_TOUCH=1（首个虚拟点）");
    }
    
    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    print_touch_debug("虚拟触摸按下：槽位=%d, ID=%d, 坐标=(%d,%d), 虚拟点数=%d", slot, tracking_id, x, y, touch_info->virtual_touch_count);
}

// 触摸抬起 - 修复锁顺序
static void touch_up(int slot) {
    unsigned long flags_physical, flags_virtual;
    int tracking_id;
    bool need_btn_touch_reset = false;
    
    if (slot < 0 || slot >= MAX_SLOTS) {
        print_touch_debug("触摸抬起失败：无效槽位=%d", slot);
        return;
    }
    
    // 按照锁顺序：先physical_lock，后virtual_lock
    LOCK_PHYSICAL_THEN_VIRTUAL(flags_physical, flags_virtual);
    
    // 检查该槽位是否已按下
    if (!touch_info->slots[slot].in_use) {
        UNLOCK_VIRTUAL_THEN_PHYSICAL(flags_physical, flags_virtual);
        print_touch_debug("触摸抬起失败：槽位=%d 未按下", slot);
        return;
    }
    
    tracking_id = touch_info->slots[slot].tracking_id;
    
    // 更新虚拟触摸计数
    touch_info->virtual_touch_count--;
    if (touch_info->virtual_touch_count <= 0) {
        touch_info->virtual_touch_count = 0;
        touch_info->virtual_touch_active = false;
    }
    
    // 检查是否需要发送 BTN_TOUCH=0
    // 如果没有虚拟触摸点了，且没有物理触摸，则需要发送BTN_TOUCH=0
    if (touch_info->virtual_touch_count == 0 && touch_info->physical_touch_count == 0) {
        need_btn_touch_reset = true;
    }
    
    // 重置该槽位状态
    touch_info->slots[slot].in_use = false;
    touch_info->slots[slot].tracking_id = -1;
    touch_info->slots[slot].x = -1;
    touch_info->slots[slot].y = -1;
    
    UNLOCK_VIRTUAL_THEN_PHYSICAL(flags_physical, flags_virtual);
    
    // 发送MT触摸抬起事件
    input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
    
    // 需要时发送 BTN_TOUCH=0
    if (need_btn_touch_reset) {
        input_event(target_ts_dev, EV_KEY, BTN_TOUCH, 0);
        print_touch_debug("发送虚拟BTN_TOUCH=0（最后虚拟点抬起）");
    }
    
    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    print_touch_debug("虚拟触摸抬起：槽位=%d, ID=%d, 剩余虚拟点数=%d", slot, tracking_id, touch_info->virtual_touch_count);
}

// 触摸移动 - 只使用 slots 锁
static void touch_move(int slot, int x, int y) {
    unsigned long flags;
    
    if (slot < 0 || slot >= MAX_SLOTS) {
        print_touch_debug("触摸移动失败：无效槽位=%d", slot);
        return;
    }
    
    spin_lock_irqsave(&touch_info->lock, flags);
    
    // 检查该槽位是否已按下
    if (!touch_info->slots[slot].in_use) {
        spin_unlock_irqrestore(&touch_info->lock, flags);
        print_touch_debug("触摸移动失败：槽位=%d 未按下", slot);
        return;
    }
    
    // 更新该槽位坐标
    touch_info->slots[slot].x = x;
    touch_info->slots[slot].y = y;
    
    spin_unlock_irqrestore(&touch_info->lock, flags);
    
    // 发送MT触摸移动事件
    input_event(target_ts_dev, EV_ABS, ABS_MT_SLOT, slot);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TRACKING_ID, touch_info->slots[slot].tracking_id);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_X, x);
    input_event(target_ts_dev, EV_ABS, ABS_MT_POSITION_Y, y);
    input_event(target_ts_dev, EV_ABS, ABS_MT_PRESSURE, 1);
    input_event(target_ts_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 5);
    input_event(target_ts_dev, EV_SYN, SYN_REPORT, 0);
    // print_touch_debug("触摸移动：槽位=%d, 坐标=(%d,%d)", slot, x, y);
}








// 在文件顶部添加全局变量，用于保存原始设备引用
static struct input_dev *original_ts_dev = NULL;
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
    print_touch_debug("原设备已注销，等待重新注册...\n");
    
    // 短暂延迟，确保设备完全注销
    msleep(200);
    
    // 【关键步骤2】注册新设备（这会创建新的 /dev/input/eventX）
    ret = input_register_device(new_dev);
    if (ret) {
        print_touch_debug("注册新设备失败: %d！框架可能无法自动恢复\n", ret);
        input_free_device(new_dev);
        return ret;
    }
    
    // 更新全局触摸屏设备指针
    target_ts_dev = new_dev;
    
    // 更新触摸信息中的handle（如果存在）
    if (touch_info && touch_info->ts_handle) {
        touch_info->ts_handle->dev = new_dev;
    }
    
    print_touch_debug("设备重注册成功，新slot数量: %d，框架将自动识别\n", new_num_slots);
    return 0;
}















// ============= 错误码定义 =============
enum translate_error {
    TRANSLATE_SUCCESS = 0,
    ERR_INVALID_MM = -EINVAL,
    ERR_INVALID_ARGS = -EINVAL,
    ERR_PGD_INVALID = -EFAULT,
    ERR_P4D_INVALID = -EFAULT,
    ERR_PUD_INVALID = -EFAULT,
    ERR_PMD_INVALID = -EFAULT,
    ERR_PTE_INVALID = -EFAULT,
    ERR_PAGE_NOT_PRESENT = -EFAULT,
    ERR_PERMISSION_DENIED = -EACCES,
    ERR_PAGE_SWAP = -EAGAIN,
    ERR_PFN_INVALID = -EFAULT,
    ERR_HUGE_PAGE = 1,
};

// ============= 5.10内核兼容层 =============
#ifndef TASK_SIZE_MAX
#define TASK_SIZE_MAX TASK_SIZE
#endif

#ifndef pgd_large
#define pgd_large(pgd) false
#endif

#ifndef pud_large
#define pud_large(pud) false
#endif

#ifndef pte_swapped
#define pte_swapped(pte) (!pte_present(pte) && !pte_none(pte))
#endif

// ============= 页表遍历（仅调试） =============
static int walk_page_table(struct mm_struct *mm, unsigned long va, phys_addr_t *pa, bool *is_huge, bool *is_swap) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    int ret = TRANSLATE_SUCCESS;
    spinlock_t *ptl;
    
    if (!mm || !pa)
        return ERR_INVALID_ARGS;
    
    if (is_huge) *is_huge = false;
    if (is_swap) *is_swap = false;
    
    if (va >= TASK_SIZE)
        return ERR_INVALID_ARGS;
    
    down_read(&mm->mmap_lock);
    
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
        ret = ERR_PGD_INVALID;
        goto out;
    }
    
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) {
        ret = ERR_P4D_INVALID;
        goto out;
    }
    
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
        ret = ERR_PUD_INVALID;
        goto out;
    }
    
    if (pud_leaf(*pud) || pud_large(*pud)) {
        if (!pud_present(*pud)) {
            ret = ERR_PAGE_NOT_PRESENT;
            goto out;
        }
        *pa = pud_pfn(*pud) << PAGE_SHIFT;
        *pa |= va & ~PUD_MASK;
        *is_huge = true;
        ret = ERR_HUGE_PAGE;
        goto out;
    }
    
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) {
        ret = ERR_PMD_INVALID;
        goto out;
    }
    
    if (pmd_trans_huge(*pmd) || pmd_leaf(*pmd)) {
        if (!pmd_present(*pmd)) {
            ret = ERR_PAGE_NOT_PRESENT;
            goto out;
        }
        *pa = pmd_pfn(*pmd) << PAGE_SHIFT;
        *pa |= va & ~PMD_MASK;
        *is_huge = true;
        ret = ERR_HUGE_PAGE;
        goto out;
    }
    
    pte = pte_offset_map_lock(mm, pmd, va, &ptl);
    if (!pte) {
        ret = ERR_PTE_INVALID;
        goto out;
    }
    
    if (pte_none(*pte)) {
        pte_unmap_unlock(pte, ptl);
        ret = ERR_PTE_INVALID;
        goto out;
    }
    
    if (pte_swapped(*pte)) {
        pte_unmap_unlock(pte, ptl);
        if (is_swap) *is_swap = true;
        ret = ERR_PAGE_SWAP;
        goto out;
    }
    
    if (!pte_present(*pte)) {
        pte_unmap_unlock(pte, ptl);
        ret = ERR_PAGE_NOT_PRESENT;
        goto out;
    }
    
    if (!pfn_valid(pte_pfn(*pte))) {
        pte_unmap_unlock(pte, ptl);
        ret = ERR_PFN_INVALID;
        goto out;
    }
    
    *pa = pte_pfn(*pte) << PAGE_SHIFT;
    *pa |= va & ~PAGE_MASK;
    pte_unmap_unlock(pte, ptl);
    ret = TRANSLATE_SUCCESS;
    
out:
    up_read(&mm->mmap_lock);
    return ret;
}

// ============= 核心读写函数 =============
static int safe_rw_memory_pages(struct mm_struct *mm, unsigned long va, void *user_buffer, size_t size, bool is_write) {
    struct page **pages = NULL;
    unsigned long start_va, end_va;
    int nr_pages, i, ret = 0;
    size_t bytes_done = 0;
    int locked = 1; // 必须初始化
    
    start_va = va & PAGE_MASK;
    end_va = PAGE_ALIGN(va + size);
    nr_pages = (end_va - start_va) >> PAGE_SHIFT;
    
    if (nr_pages == 0 || nr_pages > 64)
        return ERR_INVALID_ARGS;
    
    pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
    if (!pages)
        return -ENOMEM;
    
    down_read(&mm->mmap_lock);
    nr_pages = get_user_pages_remote(mm, start_va, nr_pages, is_write ? FOLL_WRITE : 0, pages, NULL, &locked);
    if (locked)
        up_read(&mm->mmap_lock);
    
    if (nr_pages <= 0) {
        ret = nr_pages ? nr_pages : -EFAULT;
        goto free_pages;
    }
    
    for (i = 0; i < nr_pages; i++) {
        void *kern_addr;
        size_t offset, chunk_size;
        struct page *page = pages[i];
        
        offset = (i == 0) ? (va & ~PAGE_MASK) : 0;
        chunk_size = min_t(size_t, PAGE_SIZE - offset, size - bytes_done);
        
        if (PageSwapCache(page)) {
            ret = ERR_PAGE_SWAP;
            put_page(page);
            break;
        }
        
        kern_addr = kmap(page);
        if (!kern_addr) {
            put_page(page);
            ret = -ENOMEM;
            break;
        }
        
        if (is_write) {
            if (copy_from_user(kern_addr + offset, user_buffer + bytes_done, chunk_size)) {
                kunmap(page);
                put_page(page);
                ret = -EFAULT;
                break;
            }
            set_page_dirty_lock(page);
        } else {
            if (copy_to_user(user_buffer + bytes_done, kern_addr + offset, chunk_size)) {
                kunmap(page);
                put_page(page);
                ret = -EFAULT;
                break;
            }
        }
        
        kunmap(page);
        put_page(page);
        bytes_done += chunk_size;
    }
    
free_pages:
    kvfree(pages);
    return ret < 0 ? ret : bytes_done;
}

// Android 12 + 5.10未导出ptrace_may_access
static bool check_process_access(struct task_struct *task) {
    return capable(CAP_SYS_PTRACE);
}

// ============= 安全入口 =============
static bool safe_process_memory_rw(pid_t pid, uintptr_t addr, void *user_buffer, size_t size, bool is_write) {
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    long ret;
    
    if (!user_buffer || size == 0 || size > SIZE_MAX - addr)
        return false;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    rcu_read_unlock();
    if (!task) {
        printk(KERN_ERR "[qwq] 进程不存在 (pid=%d)\n", pid);
        return false;
    }
    
    // 使用capability检查替代ptrace_may_access
    if (!check_process_access(task)) {
        printk(KERN_ERR "[qwq] 权限不足，无法访问进程 %d (uid=%d)\n", pid, task_uid(task).val);
        return false;
    }
    
    if (task->flags & PF_EXITING) {
        printk(KERN_ERR "[qwq] 进程正在退出 (pid=%d)\n", pid);
        return false;
    }
    
    mm = get_task_mm(task);
    if (!mm) {
        printk(KERN_ERR "[qwq] 获取内存描述符失败 (pid=%d)\n", pid);
        return false;
    }
    
    if (addr >= TASK_SIZE || addr + size > TASK_SIZE) {
        printk(KERN_ERR "[qwq] 地址越界: 0x%lx + %zu\n", addr, size);
        mmput(mm);
        return false;
    }
    
    ret = safe_rw_memory_pages(mm, addr, user_buffer, size, is_write);
    
    mmput(mm);
    
    if (ret < 0) {
        printk(KERN_ERR "[qwq] 内存操作失败: pid=%d, addr=0x%lx, size=%zu, err=%ld\n", pid, addr, size, ret);
        return false;
    }
    
    return ret == size;
}












// 获取进程内模块基址
static uintptr_t get_module_base(pid_t pid, const char *name) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    char buf[256];
    char *path_nm = NULL;
    uintptr_t base = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        print_touch_debug("查找模块: 进程不存在 (pid=%d)", pid);
        return 0;
    }
    // 修复：检查get_task_struct返回值
    if (!get_task_struct(task)) {
        rcu_read_unlock();
        print_touch_debug("查找模块: 获取进程引用失败 (pid=%d)", pid);
        return 0;
    }
    rcu_read_unlock();
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        print_touch_debug("查找模块: 获取内存结构失败 (pid=%d)", pid);
        return 0;
    }
    // 修复：适配内核版本的mmap锁操作
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    down_read(&mm->mmap_lock);
#else
    down_read(&mm->mmap_sem);
#endif
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            path_nm = d_path(&vma->vm_file->f_path, buf, sizeof(buf)-1);
            // 修复：检查d_path返回值是否为错误指针
            if (IS_ERR(path_nm)) {
                print_touch_debug("d_path失败 (err=%ld, pid=%d)", PTR_ERR(path_nm), pid);
                continue;
            }
            // 修复：用strstr匹配模块名（兼容路径前缀，避免误判）
            if (strstr(path_nm, name)) {
                base = vma->vm_start;
                print_touch_debug("找到模块基址: %s -> 0x%lx", path_nm, base);
                break;
            }
        }
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    up_read(&mm->mmap_lock);
#else
    up_read(&mm->mmap_sem);
#endif
    mmput(mm);
    put_task_struct(task);
    if (!base) {
        print_touch_debug("未找到模块: %s (pid=%d)", name, pid);
    }
    return base;
}


pid_t get_process_pid(const char *comm) {
    struct task_struct *task = NULL;
    pid_t tgid = 0;
    char cmdline[256] = {0};
    size_t cmdline_len = sizeof(cmdline) - 1;
    size_t i;  // C89兼容：变量声明在开头
    //  print_touch_debug("目标进程名=%s（长度=%zu）", comm ? comm : "NULL", comm ? strlen(comm) : 0);
    if (!comm || strlen(comm) == 0) {
        print_touch_debug("获取PID: 进程名为空");
        return 0;
    }
    rcu_read_lock();
    for_each_process(task) {
        struct mm_struct *mm = get_task_mm(task);
        if (!mm) continue;
        if (access_process_vm(task, mm->arg_start, cmdline, cmdline_len, 0) > 0) {
            for (i = 0; i < cmdline_len; i++) {
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            }
            if (strstr(cmdline, comm)) {
                tgid = task_tgid_vnr(task);
                // print_touch_debug("找到进程: cmdline=%s, PID=%d", cmdline, tgid);
                print_touch_debug("进程=%s（长度=%zu）PID=%d", comm, strlen(comm), tgid);
                mmput(mm);
                break;
            }
        }
        mmput(mm);
    }
    rcu_read_unlock();
    if (!tgid) print_touch_debug("未找到进程: %s", comm);
    return tgid;
}

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
            spin_lock_irqsave(&touch_info->physical_lock, flags_physical);
            touch_info->current_slot = value;
            spin_unlock_irqrestore(&touch_info->physical_lock, flags_physical);
            return false;
        }
        
        // 处理触摸屏事件
        if (type == EV_KEY && code == BTN_TOUCH) {
            // 获取物理锁
            spin_lock_irqsave(&touch_info->physical_lock, flags_physical);
            
            if (value == 1) {
                // 物理BTN_TOUCH按下
            } else if (value == 0) {
               // 需要检查虚拟状态，所以获取虚拟锁（按顺序）
                spin_lock_irqsave(&touch_info->virtual_lock, flags_virtual);
                virtual_active = touch_info->virtual_touch_active;
                virtual_count = touch_info->virtual_touch_count;
                spin_unlock_irqrestore(&touch_info->virtual_lock, flags_virtual);
                
                if (virtual_active && virtual_count > 0) {
                    should_intercept = true;
                    
                    for (i = 0; i < MAX_SLOTS; i++) {
                        if (touch_info->physical_slots_active[i]) {
                            intercepted_slots[intercepted_count++] = i;
                        }
                    }
                    
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
                    
                    print_touch_debug("拦截物理抬起（虚拟点:%d，%s）", virtual_count, slot_buf);
                    // 注意：因为我们拦截了BTN_TOUCH=0，所以不清除物理槽位状态
                } else {
                    // 没有虚拟点，需要清除所有物理槽位状态
                    for (i = 0; i < MAX_SLOTS; i++) {
                        touch_info->physical_slots_active[i] = false;
                        touch_info->physical_slots_tracking_id[i] = -1;
                    }
                    touch_info->physical_touch_count = 0;
                }
            }
            spin_unlock_irqrestore(&touch_info->physical_lock, flags_physical);
            // 如果应该拦截，返回true阻止事件传递
            if (should_intercept) {
                return true;
            }
        }
        // 跟踪MT_TRACKING_ID事件
        else if (type == EV_ABS && code == ABS_MT_TRACKING_ID) {
            spin_lock_irqsave(&touch_info->physical_lock, flags_physical);
            
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
            
            spin_unlock_irqrestore(&touch_info->physical_lock, flags_physical);
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



//隐藏pid功能区域
#define PF_INVISIBLE 0x80000000
#define HIDE_CTX_MAX 1024
#define PROC_ROOT_PATH "/"

static pid_t hidden_pid = -1;
static spinlock_t hidden_pid_lock;
static spinlock_t hide_ctx_lock;
static spinlock_t proc_hook_lock;

struct hide_ctx {
    bool is_used;
};

static struct hide_ctx hide_ctx_array[HIDE_CTX_MAX];

// 1. 从 dentry 获取 PID（纯数字目录）
static pid_t dentry_get_pid(struct dentry *dentry) {
    pid_t pid;
    char *name;
    if (!dentry || !d_is_dir(dentry))
        return -1;

    name = (char *)dentry->d_name.name;
    if (kstrtoint(name, 10, &pid) != 0)
        return -1;
    return pid;
}
static pid_t file_get_parent_pid(struct file *file) {
    struct dentry *parent_dentry = file->f_path.dentry->d_parent;
    return dentry_get_pid(parent_dentry);
}

static const struct file_operations *orig_proc_root_fops;
static struct file_operations new_proc_root_fops;
static bool proc_root_hooked = false;

static const char *get_dentry_name(struct dentry *dentry) {
    if (!dentry || !d_is_dir(dentry))
        return NULL;
    // 5.10内核通过dentry->d_name.name直接获取目录名（struct qstr的name字段）
    return dentry->d_name.name;
}

static int hook_proc_root_iterate_shared(struct file *file, struct dir_context *ctx) {
    int ret;
    pid_t pid;
    const char *dir_name;
    struct dentry *current_dentry;
    struct list_head *list_node; // 新增：链表节点指针

    // 循环遍历：跳过目标PID目录，返回其他目录项
    while (1) {
        // 1. 调用原生遍历函数，获取下一个目录项
        ret = orig_proc_root_fops->iterate_shared(file, ctx);
        if (ret != 0)
            break; // 遍历结束或出错

        // 2. 5.10内核：通过d_subdirs链表遍历目录项（修复指针类型）
        list_node = file->f_path.dentry->d_subdirs.next;
        // 跳过链表头（避免遍历到自身）
        if (list_node == &file->f_path.dentry->d_subdirs)
            continue;

        // 关键：用container_of从list_head解析出dentry结构体
        current_dentry = container_of(list_node, struct dentry, d_child);

        // 3. 获取目录项名称（纯数字=PID目录）
        dir_name = get_dentry_name(current_dentry);
        if (!dir_name || *dir_name == '\0')
            continue;

        // 4. 识别PID目录，跳过目标PID
        if (kstrtoint(dir_name, 10, &pid) == 0) {
            spin_lock(&hidden_pid_lock);
            if (pid == hidden_pid) {
                print_touch_debug("proc根目录过滤：屏蔽PID=%d\n", pid);
                continue; // 跳过目标PID，继续遍历下一个
            }
            spin_unlock(&hidden_pid_lock);
        }

        // 5. 非目标PID，返回成功（用户空间可见）
        return 0;
    }

    return ret;
}

static int hook_proc_pid_open(struct inode *inode, struct file *file) {
    pid_t target_pid = file_get_parent_pid(file);
    pid_t hide_pid;

    // 内核空间/非 PID 目录文件放行
    if (!current->mm || target_pid == -1) {
        return orig_proc_root_fops->open(inode, file);
    }

    spin_lock(&hidden_pid_lock);
    hide_pid = hidden_pid;
    spin_unlock(&hidden_pid_lock);

    if (target_pid == hide_pid) {
        print_touch_debug("拦截访问：/proc/%d/*（权限拒绝）\n", target_pid);
        return -EACCES;
    }

    return orig_proc_root_fops->open(inode, file);
}

static ssize_t hook_proc_pid_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    pid_t target_pid = file_get_parent_pid(file);
    pid_t hide_pid;

    // 内核空间/非 PID 目录文件放行
    if (!current->mm || target_pid == -1) {
        return orig_proc_root_fops->read(file, buf, count, ppos);
    }

    spin_lock(&hidden_pid_lock);
    hide_pid = hidden_pid;
    spin_unlock(&hidden_pid_lock);

    if (target_pid == hide_pid) {
        print_touch_debug("过滤读取：/proc/%d/%s（空数据）\n", target_pid, file->f_path.dentry->d_name.name);
        return 0;
    }

    return orig_proc_root_fops->read(file, buf, count, ppos);
}

static int hook_proc_init(void) {
    struct file *proc_file;
    int ret = 0;

    // 初始化锁和上下文
    spin_lock_init(&hidden_pid_lock);
    spin_lock_init(&hide_ctx_lock);
    spin_lock_init(&proc_hook_lock);
    memset(hide_ctx_array, 0, sizeof(hide_ctx_array));

    // 打开/proc目录，获取原生file_operations
    proc_file = filp_open(PROC_ROOT_PATH, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(proc_file)) {
        ret = PTR_ERR(proc_file);
        print_touch_debug("打开/proc失败：%d\n", ret);
        return ret;
    }

    // 保存原生fops，替换关键成员（5.10内核直接用file_operations）
    orig_proc_root_fops = proc_file->f_op;
    memcpy(&new_proc_root_fops, orig_proc_root_fops, sizeof(struct file_operations));
    new_proc_root_fops.iterate_shared = hook_proc_root_iterate_shared; // 目录遍历过滤
    new_proc_root_fops.open = hook_proc_pid_open; // 文件打开拦截
    new_proc_root_fops.read = hook_proc_pid_read; // 文件读取过滤

    // 挂钩/proc根目录fops
    spin_lock(&proc_hook_lock);
    proc_file->f_op = &new_proc_root_fops;
    proc_root_hooked = true;
    spin_unlock(&proc_hook_lock);

    filp_close(proc_file, NULL);
    print_touch_debug("proc过滤挂钩完成（适配5.10内核）\n");
    return 0;
}

static void unhook_proc(void) {
    struct file *proc_file;
    if (!proc_root_hooked)
        return;

    // 打开 /proc 目录，恢复原生 fops
    proc_file = filp_open(PROC_ROOT_PATH, O_RDONLY | O_DIRECTORY, 0);
    if (!IS_ERR(proc_file)) {
        spin_lock(&proc_hook_lock);
        if (proc_file->f_op == &new_proc_root_fops) {
            proc_file->f_op = orig_proc_root_fops;
        }
        spin_unlock(&proc_hook_lock);
        filp_close(proc_file, NULL);
    }

    proc_root_hooked = false;
    print_touch_debug("proc过滤解钩完成\n");
}

static struct task_struct* get_target_task(pid_t pid) {
    struct pid *pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    task = NULL;
    if (pid_struct) {
        task = get_pid_task(pid_struct, PIDTYPE_PID);
        put_pid(pid_struct);
    } else {
        print_touch_debug("未找到PID=%d的pid_struct\n", pid);
    }

    return task;
}

/* 隐藏：从 ptraced 链表摘下 */
static void safe_unlink_ptraced(struct task_struct *tsk) {
    unsigned long flags;
    spin_lock_irqsave(&tsk->alloc_lock, flags);
    list_del_init(&tsk->ptraced);
    spin_unlock_irqrestore(&tsk->alloc_lock, flags);
}

/* 解除：挂回 ptraced 链表 */
static void safe_relink_ptraced(struct task_struct *tsk) {
    unsigned long flags;
    spin_lock_irqsave(&tsk->alloc_lock, flags);
    list_add_tail(&tsk->ptraced, &tsk->parent->ptraced);
    spin_unlock_irqrestore(&tsk->alloc_lock, flags);
}

int do_toggle_process_hide(pid_t pid) {
    struct task_struct *tsk;
    unsigned long flags;
    struct hide_ctx *ctx;
    unsigned int ctx_idx;
    int ret;

    // PID 有效性校验
    if (pid <= 0 || pid == 1 || pid > PID_MAX_LIMIT) {
        print_touch_debug("非法PID：%d\n", pid);
        return -EINVAL;
    }

    // 安全获取进程结构体
    rcu_read_lock();
    tsk = get_target_task(pid);
    if (!tsk) {
        rcu_read_unlock();
        print_touch_debug("未找到进程：PID=%d\n", pid);
        return -ESRCH;
    }
    get_task_struct(tsk);
    rcu_read_unlock();

    // 禁止隐藏当前进程/内核线程
    if (tsk == current || (tsk->flags & PF_KTHREAD)) {
        put_task_struct(tsk);
        print_touch_debug("禁止隐藏当前进程/内核线程\n");
        return -EINVAL;
    }

    // 检查上下文占用
    ctx_idx = pid % HIDE_CTX_MAX;
    spin_lock_irqsave(&hide_ctx_lock, flags);
    ctx = &hide_ctx_array[ctx_idx];
    if (!(tsk->flags & PF_INVISIBLE) && ctx->is_used) {
        spin_unlock_irqrestore(&hide_ctx_lock, flags);
        put_task_struct(tsk);
        print_touch_debug("PID=%d上下文已占用\n", pid);
        return -EBUSY;
    }
    spin_unlock_irqrestore(&hide_ctx_lock, flags);

    // 切换隐藏状态
    ret = 0;
    if (!(tsk->flags & PF_INVISIBLE)) {
        // 隐藏进程pid
        spin_lock_irqsave(&hide_ctx_lock, flags);
        ctx->is_used = true;
        spin_unlock_irqrestore(&hide_ctx_lock, flags);
        tsk->flags |= PF_INVISIBLE;
        safe_unlink_ptraced(tsk);
        spin_lock(&hidden_pid_lock);
        /*删除父子进程链表（tasks + sibling）不要开，会导致重启
        list_del_rcu(&tsk->tasks);
        list_del_rcu(&tsk->sibling);
        //删除线程组双链表（thread_group + thread_node）
        list_del_rcu(&tsk->thread_group);
        list_del_rcu(&tsk->thread_node);
        //置空核心字段（thread_pid + tgid）
        tsk->thread_pid = NULL;*/
        hidden_pid = pid;
        spin_unlock(&hidden_pid_lock);
        print_touch_debug("成功屏蔽PID=%d（匹配内核定义）\n", pid);
    } else {
        // 解除恢复隐藏
        tsk->flags &= ~PF_INVISIBLE;
        safe_relink_ptraced(tsk);
        spin_lock_irqsave(&hide_ctx_lock, flags);
        ctx->is_used = false;
        spin_unlock_irqrestore(&hide_ctx_lock, flags);
        spin_lock(&hidden_pid_lock);
        hidden_pid = -1;
        spin_unlock(&hidden_pid_lock);
        print_touch_debug("成功解除PID=%d屏蔽\n", pid);
    }

    put_task_struct(tsk);
    return ret;
}





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
    
    // 进程名白名单（可以修改）
    static const char *allowed_clients[] = {
        "demo",               // 进程名
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
    int i;
    unsigned long flags_physical, flags_virtual;
    bool slot_used;

    print_touch_debug("客户端断开，开始清理虚拟点\n");
    // 清理所有虚拟触摸点
    for (i = 0; i < MAX_SLOTS; i++) {
        slot_used = false;
        // 检查槽位状态
        spin_lock_irqsave(&touch_info->lock, flags_physical);
        slot_used = touch_info->slots[i].in_use;
        spin_unlock_irqrestore(&touch_info->lock, flags_physical);
        
        if (slot_used) {
            touch_up(i);  // 抬起虚拟点
            print_touch_debug("清理虚拟点：槽位=%d", i);
        }
    }
    // 重置虚拟触摸状态
    LOCK_PHYSICAL_THEN_VIRTUAL(flags_physical, flags_virtual);
    touch_info->virtual_touch_active = false;
    touch_info->virtual_touch_count = 0;
    UNLOCK_VIRTUAL_THEN_PHYSICAL(flags_physical, flags_virtual);
    
    print_touch_debug("虚拟点清理完成，监听线程将自动重开\n");
    atomic_dec(&anon_ref);
    atomic_set(&g_state, ST_CLOSED);//直接重置，让监听线程自动重试
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
            if (!safe_process_memory_rw(cm.pid, cm.addr, cm.buffer, cm.size, false))
                return -EFAULT;
            break;
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                return -EFAULT;
            if (!safe_process_memory_rw(cm.pid, cm.addr, cm.buffer, cm.size, true))
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
        case OP_HIDE_PID: {
            int hide_ret;
            MODULE_BASE mb;
            char name[0x100] = {0};
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)))
                return -EFAULT;
            if (mb.name) {
                if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1)) {
                    print_touch_debug("IOCTL OP_HIDE_PID: copy_from_user name failed\n");
                    return -EFAULT;
                }
            }
            name[sizeof(name)-1] = '\0';
            if (mb.pid > PID_MAX_LIMIT || mb.pid <= 0) {
                print_touch_debug("IOCTL OP_HIDE_PID: invalid PID=%d\n", mb.pid);
                return -EINVAL;
            }
            hide_ret = do_toggle_process_hide(mb.pid);
            if (hide_ret != 0) {
                print_touch_debug("隐藏进程失败, ret=%d\n", hide_ret);
                return hide_ret;
            }
            break;
        }
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
            if (copy_from_user(&td, (void __user*)arg, sizeof(td)))
                return -EFAULT;
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[td.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (slot_used) {
                print_touch_debug("槽位=%d 已被占用，无法按下\n", td.slot);
                return -EBUSY;
            }
            touch_down(td.slot, td.x, td.y);
            break;
        }
        case OP_TOUCH_UP: {
            bool slot_used;
            unsigned long flags;
            if (copy_from_user(&tu, (void __user*)arg, sizeof(tu)))
                return -EFAULT;
            if (!target_ts_dev) {
                print_touch_debug("未找到触摸屏设备\n");
                return -ENODEV;
            }
            spin_lock_irqsave(&touch_info->lock, flags);
            slot_used = touch_info->slots[tu.slot].in_use;
            spin_unlock_irqrestore(&touch_info->lock, flags);
            if (!slot_used) {
                print_touch_debug("槽位=%d 未按下，无法抬起\n", tu.slot);
                return -EINVAL;
            }
            touch_up(tu.slot);
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

        switch (cmd) {
            case OP_READ_MEM:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                    return -EFAULT;
                if (!safe_process_memory_rw(cm.pid, cm.addr, cm.buffer, cm.size, false))
                    return -EFAULT;
                break;

            case OP_WRITE_MEM:
                if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)))
                    return -EFAULT;
                if (!safe_process_memory_rw(cm.pid, cm.addr, cm.buffer, cm.size, true))
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

            case OP_HIDE_PID: {
                int hide_ret;
                MODULE_BASE mb;
                char name[0x100] = {0};
                if (copy_from_user(&mb, (void __user*)arg, sizeof(mb))) {
                    return -EFAULT;
                }
                if (mb.name) {
                    if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1)) {
                        print_touch_debug("IOCTL OP_HIDE_PID: copy_from_user name failed\n");
                        return -EFAULT;
                    }
                }
                name[sizeof(name)-1] = '\0';
                if (mb.pid > PID_MAX_LIMIT || mb.pid <= 0) {
                    print_touch_debug("IOCTL OP_HIDE_PID: invalid PID=%d\n", mb.pid);
                    return -EINVAL;
                }
                print_touch_debug("IOCTL OP_HIDE_PID: 接收PID=%d，进程名=%s\n", mb.pid, name);
                hide_ret = do_toggle_process_hide(mb.pid);
                if (hide_ret != 0) {
                    print_touch_debug("隐藏进程失败, ret=%d\n", hide_ret);
                    return hide_ret;
                }
                break;
            }

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
                if (copy_from_user(&td, (void __user*)arg, sizeof(td)))
                    return -EFAULT;
                if (!target_ts_dev) {
                    print_touch_debug("未找到触摸屏设备\n");
                    return -ENODEV;
                }
                spin_lock_irqsave(&touch_info->lock, flags);
                slot_used = touch_info->slots[td.slot].in_use;
                spin_unlock_irqrestore(&touch_info->lock, flags);
                if (slot_used) {
                    print_touch_debug("槽位=%d 已被占用，无法按下\n", td.slot);
                    return -EBUSY;
                }
                touch_down(td.slot, td.x, td.y);
                print_touch_debug("IOCTL触摸按下：槽位=%d, x=%d, y=%d\n", td.slot, td.x, td.y);
                break;
            }

            case OP_TOUCH_UP: {
                bool slot_used;
                unsigned long flags;
                if (copy_from_user(&tu, (void __user*)arg, sizeof(tu)))
                    return -EFAULT;
                if (!target_ts_dev) {
                    print_touch_debug("未找到触摸屏设备\n");
                    return -ENODEV;
                }
                spin_lock_irqsave(&touch_info->lock, flags);
                slot_used = touch_info->slots[tu.slot].in_use;
                spin_unlock_irqrestore(&touch_info->lock, flags);
                if (!slot_used) {
                    print_touch_debug("槽位=%d 未按下，无法抬起\n", tu.slot);
                    return -EINVAL;
                }
                touch_up(tu.slot);
                print_touch_debug("IOCTL触摸抬起：槽位=%d\n", tu.slot);
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
    if (!IS_ERR(filp_open("/proc/sched_debug", O_RDONLY, 0))) {
        remove_proc_subtree("sched_debug", NULL); //移除/proc/sched_debug
    }
    if (!IS_ERR(filp_open("/proc/uevents_records", O_RDONLY, 0))) {
        remove_proc_entry("uevents_records", NULL); //移除/proc/uevents_records
    }
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
    
    
    ret = hook_proc_init();
    if (ret != 0) {
        print_touch_debug("proc挂钩失败：%d\n", ret);
        return ret;
    }

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
    // 初始化触摸槽位状态
    for (i = 0; i < MAX_SLOTS; i++) {
        // 虚拟槽位
        touch_info->slots[i].in_use = false;
        touch_info->slots[i].tracking_id = -1;
        touch_info->slots[i].x = -1;
        touch_info->slots[i].y = -1;
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
    mem_tool_class = class_create(THIS_MODULE, devicename);
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






// 模块卸载
static void __exit driver_unload(void) {
    struct event_node *node, *tmp;
    
    
    unix_socket_cleanup();//清理UNIX套接字模块
    unhook_proc();//清理proc挂钩
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
#endif // DRIVER_H