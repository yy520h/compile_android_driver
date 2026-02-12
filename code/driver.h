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
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/preempt.h>
//#include <asm/mte.h> 5.4没有这个文件
#include <linux/kprobes.h>
#include <linux/pagemap.h>
#include <linux/pfn.h>
#include <linux/memory.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/dma-buf.h>
#include <linux/platform_device.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
// 5.10+ 用 mmap_lock，get_user_pages_remote 7 个参数
#include <linux/pgtable.h>
#include <linux/dma-heap.h>
#else
// 5.4 及以下用 mmap_sem，get_user_pages_remote 8 个参数（多传 NULL 作为 vmas 参数）
#include <linux/uio.h>
#include <asm/unistd.h>
ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned int flags);
#endif







// 设备与常量定义
#define DEVICE_NAME "qwqet"
#define LOCK_BUCKETS 256
#define EVENT_QUEUE_SIZE 32
#define COMBO_KEY_TIMEOUT 600
#define UNIX_PATH_LEN 32

// 按键编码
#define KEY_POWER 116
#define KEY_VOLUMEUP 115
#define KEY_VOLUMEDOWN 114

// IOCTL操作命令
enum OPERATIONS {
    OP_INIT_KEY = 0x200,
    OP_READ_MEM = 0x201,
    OP_WRITE_MEM = 0x202,
    OP_MODULE_BASE = 0x203,
    OP_MODULE_PID = 0x204,
    OP_GET_EVENT = 0x206,
    OP_TOUCH_MOVE = 0x207,
    OP_TOUCH_DOWN = 0x208,
    OP_TOUCH_UP = 0x209,
    OP_PROTECT_PID = 0x210,
    OP_UNPROTECT_PID = 0x211,
    OP_HEARTBEAT = 0x212,
};

// UNIX域套接字专用命令
#define CMD_OPEN_UNIX  _IO('X', 2)
#define CMD_CLOSE_UNIX _IO('X', 3)
#define CMD_REOPEN_UNIX _IO('X', 1)

// 事件类型宏定义
#define EVENT_ENTER_INTERCEPT 1
#define EVENT_EXIT_INTERCEPT 0
#define EVENT_KEY_PRESS 1
#define EVENT_KEY_RELEASE 0

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

// 按键事件结构
typedef struct _KEY_EVENT {
    int tp;
    int key_code;
} KEY_EVENT, *PKEY_EVENT;

// 拦截状态枚举
enum KEY_HOOK_STATE {
    STATE_NORMAL = 0,
    STATE_INTERCEPT = 1
};

// 用户事件结构 - 必须在event_node之前定义
typedef struct _USER_EVENT {
    int trp;
    int key_code;
} USER_EVENT, *PUSER_EVENT;

// 事件队列节点 - 使用USER_EVENT
struct event_node {
    struct list_head list;
    USER_EVENT event;
};

struct key_hook_state {
    enum KEY_HOOK_STATE state;
    bool power_key_pressed;
    bool volup_pressed;
    bool voldown_pressed;
    ktime_t power_press_time;
    bool combo_triggered;
    int combo_type;
    wait_queue_head_t waitq;
    struct list_head event_list;
    spinlock_t lock;
    int event_count;
    bool touch_intercept_enabled;
};

// 设备管理结构
struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
    int max;
};

// 目标设备白名单
static const char *target_devices[] = {
    "gpio-keys",
    "pmic_resin",
    "pmic_pwrkey",
    "NVTCapacitiveTouchScreen"
};

#define TARGET_DEV_COUNT (sizeof(target_devices) / sizeof(target_devices[0]))

// 全局变量声明 - 使用extern避免重复定义
extern struct mem_tool_device *memdev;
extern dev_t mem_tool_dev_t;
extern struct class *mem_tool_class;
extern const char *devicename;
extern char mod_obf_name[16];
extern rwlock_t pid_locks[LOCK_BUCKETS];
extern struct key_hook_state *key_info;
extern struct input_handler key_hook_handler;
extern atomic_t bound_dev_count;
extern atomic_t target_bound_mask;

// 触摸相关配置
#define MAX_SLOTS 13
#define MAX_SLOTS_PER_CLIENT 5
#define MAX_CLIENTS 3

// 触摸参数结构体
typedef struct {
    int slot;
    int x, y;
} touch_down_t;

typedef struct {
    int slot;
    int x, y;
} touch_move_t;

typedef struct {
    int slot;
    int dummy;
} touch_up_t;


// 心跳结构
struct client_heartbeat {
    struct timer_list heartbeat_timer;
    struct client_state *client;
    bool alive;
    unsigned long last_heartbeat;
};
// 客户端状态结构
struct client_state {
    struct list_head list;
    pid_t pid;
    uid_t uid;
    struct file *anon_file;
    int ref_count;
    int client_id;
    struct {
        bool in_use;
        int slot;
        int tracking_id;
        int x, y;
    } virtual_points[MAX_SLOTS_PER_CLIENT];
    int virtual_point_count;
    bool exited;  // 标记进程是否已退出
    struct client_heartbeat *heartbeat;  // 心跳检测
};

// 触摸钩子状态结构
struct touch_hook_state {
    struct {
        bool in_use;
        int x, y;
        int tracking_id;
        int client_id;
    } slots[MAX_SLOTS];
    spinlock_t lock;
    int next_tracking_id;
    bool virtual_touch_active;
    int virtual_touch_count;
    spinlock_t virtual_lock;
    bool physical_slots_active[MAX_SLOTS];
    int physical_slots_tracking_id[MAX_SLOTS];
    int physical_touch_count;
    spinlock_t physical_lock;
    struct input_handle *ts_handle;
    int current_slot;
    struct list_head client_list;
    spinlock_t client_lock;
    int next_client_id;
};

// 全局变量声明
extern struct touch_hook_state *touch_info;
extern struct input_dev *target_ts_dev;
extern int hw_min_x, hw_max_x, hw_min_y, hw_max_y;
extern int hw_screen_w, hw_screen_h;

// 网络保护
#define MAX_PROTECTED_PIDS 16

struct network_protect_state {
    pid_t protected_pids[MAX_PROTECTED_PIDS];
    int protected_count;
    spinlock_t lock;
};

// 锁顺序宏
#define LOCK_ORDER_1(flags1) spin_lock_irqsave(&touch_info->physical_lock, (flags1))
#define UNLOCK_ORDER_1(flags1) spin_unlock_irqrestore(&touch_info->physical_lock, (flags1))

#define LOCK_ORDER_2(flags1, flags2) \
    do { \
        spin_lock_irqsave(&touch_info->physical_lock, (flags1)); \
        spin_lock_irqsave(&touch_info->virtual_lock, (flags2)); \
    } while (0)

#define UNLOCK_ORDER_2(flags1, flags2) \
    do { \
        spin_unlock_irqrestore(&touch_info->virtual_lock, (flags2)); \
        spin_unlock_irqrestore(&touch_info->physical_lock, (flags1)); \
    } while (0)

#define LOCK_ORDER_3(flags1, flags2, flags3) \
    do { \
        spin_lock_irqsave(&touch_info->physical_lock, (flags1)); \
        spin_lock_irqsave(&touch_info->virtual_lock, (flags2)); \
        spin_lock_irqsave(&touch_info->lock, (flags3)); \
    } while (0)

#define UNLOCK_ORDER_3(flags1, flags2, flags3) \
    do { \
        spin_unlock_irqrestore(&touch_info->lock, (flags3)); \
        spin_unlock_irqrestore(&touch_info->virtual_lock, (flags2)); \
        spin_unlock_irqrestore(&touch_info->physical_lock, (flags1)); \
    } while (0)

#define LOCK_ORDER_4(flags1, flags2, flags3, flags4) \
    do { \
        spin_lock_irqsave(&touch_info->physical_lock, (flags1)); \
        spin_lock_irqsave(&touch_info->virtual_lock, (flags2)); \
        spin_lock_irqsave(&touch_info->lock, (flags3)); \
        spin_lock_irqsave(&touch_info->client_lock, (flags4)); \
    } while (0)

#define UNLOCK_ORDER_4(flags1, flags2, flags3, flags4) \
    do { \
        spin_unlock_irqrestore(&touch_info->client_lock, (flags4)); \
        spin_unlock_irqrestore(&touch_info->lock, (flags3)); \
        spin_unlock_irqrestore(&touch_info->virtual_lock, (flags2)); \
        spin_unlock_irqrestore(&touch_info->physical_lock, (flags1)); \
    } while (0)

// 函数声明
extern void print_touch_debug(const char *format, ...);

static uintptr_t get_module_base(pid_t pid, const char *name);
static bool read_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size);
static bool write_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size);
static pid_t get_process_pid(const char *comm);
static int do_toggle_process_hide(pid_t pid);
static void touch_down(int slot, int x, int y, struct client_state *client);
static void touch_up(int slot, struct client_state *client);
static void touch_move(int slot, int x, int y);
static void restart_system_server_secure(void);
static struct client_state* find_client_by_file(struct file *filp);
static struct client_state* create_client(pid_t pid, uid_t uid, struct file *filp);
static void remove_client(struct client_state *client);
static void unix_socket_cleanup(void);

// 静态互斥锁定义
static DEFINE_MUTEX(dev_lifecycle_lock);

// 获取PID对应的读写锁
static inline rwlock_t *lock_for_pid(pid_t pid) {
    return &pid_locks[pid % LOCK_BUCKETS];
}

typedef struct {
    int last_x, last_y;
} touch_move_ctx_t;

// 补充Android GKI模块依赖声明（避免编译警告）
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_IMPORT_NS(__kprobes);

#endif // DRIVER_H
