#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include "comm.h"
#include "touch_optimized.h"
#include "memory.h"
#include "process.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
    MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver); 
#endif

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg);
struct file_operations dispatch_functions = {
    .owner  = THIS_MODULE,
    .open   = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
    int max;
};
static struct mem_tool_device *memdev;
static struct list_head *prev_module;
static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;

int dispatch_open(struct inode *node, struct file *file) {
    file->private_data = memdev;
    prev_module = __this_module.list.prev;
    list_del_init(&__this_module.list);
    device_destroy(mem_tool_class, mem_tool_dev_t);
    class_destroy(mem_tool_class);
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    list_add(&__this_module.list, prev_module);
    mem_tool_class = class_create(THIS_MODULE, devicename);
    memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename);
    return 0;
}

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name[0x100] = {0};
    static TouchEvent touch_event;
    struct event_pool *pool;

    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                return -1;
            }
            if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                return -1;
            }
            break;

        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
                return -1;
            }
            if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
                return -1;
            }
            break;

        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 || 
                copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
                return -1;
            }
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
                return -1;
            }
            break;

        case OP_MODULE_PID:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 || 
                copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
                return -1;
            }
            mb.pid = get_process_pid(name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
                return -1;
            }
            break;

        case OP_TOUCH_PRESS:
        case OP_TOUCH_MOVE:
        case OP_TOUCH_RELEASE:
            if (copy_from_user(&touch_event, (void __user*)arg, sizeof(touch_event)) != 0) {
                return -1;
            }

            pool = get_event_pool();
            if (!pool) {
                return -1;
            }

            switch (cmd) {
                case OP_TOUCH_PRESS:
                    input_event_cache(EV_ABS, ABS_MT_POSITION_X, touch_event.value, pool, 1);
                    input_event_cache(EV_ABS, ABS_MT_POSITION_Y, touch_event.value, pool, 1);
                    input_event_cache(EV_KEY, BTN_TOUCH, 1, pool, 1);
                    input_event_cache(EV_SYN, SYN_REPORT, 0, pool, 1);
                    break;

                case OP_TOUCH_MOVE:
                    input_event_cache(EV_ABS, ABS_MT_POSITION_X, touch_event.value, pool, 1);
                    input_event_cache(EV_ABS, ABS_MT_POSITION_Y, touch_event.value, pool, 1);
                    input_event_cache(EV_SYN, SYN_REPORT, 0, pool, 1);
                    break;

                case OP_TOUCH_RELEASE:
                    input_event_cache(EV_KEY, BTN_TOUCH, 0, pool, 1);
                    input_event_cache(EV_SYN, SYN_REPORT, 0, pool, 1);
                    break;
            }

            break;

        default:
            break;
    }
    return 0;
}

static int __init driver_entry(void) {
    int ret;
    devicename = DEVICE_NAME;
    devicename = get_rand_str();

    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
    if (ret < 0) return ret;

    memdev = kmalloc(sizeof(struct mem_tool_device), GFP_KERNEL);
    if (!memdev) goto done;
    memset(memdev, 0, sizeof(struct mem_tool_device));

    cdev_init(&memdev->cdev, &dispatch_functions);
    memdev->cdev.owner = THIS_MODULE;

    ret = cdev_add(&memdev->cdev, mem_tool_dev_t, 1);
    if (ret) goto done;

    mem_tool_class = class_create(THIS_MODULE, devicename);
    if (IS_ERR(mem_tool_class)) goto done;
    memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename);
    if (IS_ERR(memdev->dev)) goto done;

    unregister_chrdev_region(mem_tool_dev_t, 1);

    ret = init_touch();
    if (ret) {
        printk(KERN_ERR "Failed to initialize touch functionality\n");
        goto done;
    }

    return 0;
done:
    return ret;
}

static void __exit driver_unload(void) {
    device_destroy(mem_tool_class, mem_tool_dev_t);
    class_destroy(mem_tool_class);
    cdev_del(&memdev->cdev);
    kfree(memdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
    exit_touch();
}

module_init(driver_entry);
module_exit(driver_unload);
MODULE_LICENSE("GPL");
