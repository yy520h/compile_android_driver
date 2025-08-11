#ifndef DRIVER_H
#define DRIVER_H
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/mm.h>        
#include <asm/pgtable.h>     
#include <asm/cacheflush.h>  
#include <linux/set_memory.h>
#include <asm/cacheflush.h>
#include <linux/version.h>
#include <linux/rwlock.h>  // 引入读写锁支持

#define DEVICE_NAME "qwqet"
#define LOCK_BUCKETS 256

enum OPERATIONS {
    OP_INIT_KEY = 0x200,
    OP_READ_MEM = 0x201,
    OP_WRITE_MEM = 0x202,
    OP_MODULE_BASE = 0x203,
    OP_MODULE_PID = 0x204,
};

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

struct mem_tool_device {
    struct cdev cdev;
    struct device *dev;
    int max;
};

static struct mem_tool_device *memdev;
static dev_t mem_tool_dev_t;
static struct class *mem_tool_class;
const char *devicename;
static char mod_obf_name[16] = {0};

// 改为读写锁数组
static rwlock_t pid_locks[LOCK_BUCKETS];

/* 获取PID对应的锁 */
static rwlock_t *lock_for_pid(pid_t pid) {
    return &pid_locks[pid % LOCK_BUCKETS];
}

/* 虚拟地址转物理地址 */
static phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t page_addr;
    uintptr_t page_offset;

    // 获取页表锁
    spin_lock(&mm->page_table_lock);    
    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        spin_unlock(&mm->page_table_lock);
        return 0;
    }    
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        spin_unlock(&mm->page_table_lock);
        return 0;
    }    
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) {
        spin_unlock(&mm->page_table_lock);
        return 0;
    }   
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) {
        spin_unlock(&mm->page_table_lock);
        return 0;
    }    
    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte)) {
        spin_unlock(&mm->page_table_lock);
        return 0;
    }    
    if (!pte_present(*pte)) {
        spin_unlock(&mm->page_table_lock);
        return 0;
    }  
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);   
    spin_unlock(&mm->page_table_lock);
    return page_addr + page_offset;
}

/* 改进后的内存读写函数 */
static bool safe_rw_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size, bool is_write) {
    struct task_struct* task = NULL;
    struct mm_struct* mm = NULL;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;
    char* buffer = NULL;
    char* va;
    size_t total = size;
    rwlock_t *lock = lock_for_pid(pid);
    unsigned long flags;
    bool result = false;
    
    // 使用RCU保护任务查找
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return false;
    }
    
    // 增加任务引用计数
    if (!get_task_struct(task)) {
        rcu_read_unlock();
        return false;
    }
    rcu_read_unlock();
    
    // 获取内存结构（不需要锁保护）
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return false;
    }
    
    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        mmput(mm);
        put_task_struct(task);
        return false;
    }
    
    // 根据操作类型使用合适的锁
    if (is_write) {
        // 写操作使用写锁
        write_lock_irqsave(lock, flags);
    } else {
        // 读操作使用读锁
        read_lock_irqsave(lock, flags);
    }
    
    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        if (!pa) {
            goto cleanup;
        }
        
        va = (char*)phys_to_virt(pa);
        if (!va) {
            goto cleanup;
        }
        
        max = min_t(size_t, PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min_t(size_t, size, PAGE_SIZE));
        
        if (is_write) {
            if (copy_from_user(buffer, user_buffer, max)) {
                goto cleanup;
            }
            memcpy(va, buffer, max);
            flush_dcache_page(virt_to_page(va));
        } else {
            memcpy(buffer, va, max);
            flush_dcache_page(virt_to_page(va));
            if (copy_to_user(user_buffer, buffer, max)) {
                goto cleanup;
            }
        }
        
        count += max;
        size -= max;
        user_buffer += max;
        addr += max;
    }
    
    result = (count == total);
    
cleanup:
    kfree(buffer);
    
    // 释放锁
    if (is_write) {
        write_unlock_irqrestore(lock, flags);
    } else {
        read_unlock_irqrestore(lock, flags);
    }
    
    mmput(mm);
    put_task_struct(task);
    return result;
}





static bool read_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size) {
    return safe_rw_memory(pid, addr, user_buffer, size, false);
}

static bool write_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size) {
    return safe_rw_memory(pid, addr, user_buffer, size, true);
}

/* 获取进程内模块基址 */
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
        return 0;
    }    
    if (!get_task_struct(task)) {
        rcu_read_unlock();
        return 0;
    }
    rcu_read_unlock();    
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return 0;
    }    
   // 遍历进程的所有VMA（使用mmap_lock）
    down_read(&mm->mmap_lock);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            path_nm = d_path(&vma->vm_file->f_path, buf, sizeof(buf)-1);
            if (!IS_ERR(path_nm) && !strcmp(kbasename(path_nm), name)) {
                base = vma->vm_start;
                break;
            }
        }
    }
    up_read(&mm->mmap_lock);
    mmput(mm);
    put_task_struct(task);
    return base;
}

/* 通过进程名获取PID */
static pid_t get_process_pid(char *comm) {
    struct task_struct *task;
    pid_t pid = 0;    
    rcu_read_lock();
    for_each_process(task) {
        if (strcmp(task->comm, comm) == 0) {
            pid = task->pid;
            break;
        }
    }
    rcu_read_unlock();    
    return pid;
}

/* 生成5位随机设备名 */
static char* get_rand_str(void) {
    static char string[6];
    const char *str = "9k7Qn3WzjxUYV0dRf5c1bGp4EsHwTrMhS6XlNtFymoZDvKuPiedIOC";
    int lstr = strlen(str);
    int i;
    
    for (i = 0; i < 5; i++) {
        int seed, flag;
        get_random_bytes(&seed, sizeof(int));
        flag = abs(seed % lstr);
        string[i] = str[flag];
    }
    string[5] = '\0';
    return string;
}

/* IOCTL命令处理 */
static long my_dev_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg) {
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[0x100] = {0}; // 使用局部变量替代静态变量
    
    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) return -EFAULT;
            break;
            
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) return -EFAULT;
            break;
            
        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb))) return -EFAULT;
            if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1)) return -EFAULT;
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) return -EFAULT;
            break;
            
        case OP_MODULE_PID:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb))) return -EFAULT;
            if (copy_from_user(name, (void __user*)mb.name, sizeof(name)-1)) return -EFAULT;
            mb.pid = get_process_pid(name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) return -EFAULT;
            break;
            
        default:
            return -ENOTTY;
    }
    return 0;
}


/* 隐藏模块 (完美隐藏，无法查找到痕迹，也无法卸载，只能重启设备恢复)*/
static void hide_module(void) {
    struct module *mod = THIS_MODULE;
    list_del_init(&mod->list); // 从内核模块链表移除
    kobject_del(&mod->mkobj.kobj); // 删除sysfs中的kobject(完全删除)
    //隐藏sysfs条目 上面启用kobject_del 那这就不用启用 kobject_del 会连带holders_dir /proc/modules 一起删除
    if (mod->holders_dir) {//建议保留，防止kobject结构变化
        kobject_del(mod->holders_dir);
        mod->holders_dir = NULL;
    }
    mod->state = MODULE_STATE_UNFORMED;//隐藏/proc/modules

    //内存隐藏增强 设置内存[只读]和[不可执行]属性，防止通过/proc/kcore扫描代码段，对抗特征码扫描
#if defined(CONFIG_STRICT_MODULE_RWX) && defined(set_memory_ro) && defined(set_memory_nx)
    // 如果内核支持且函数可用，使用标准方法
    set_memory_ro((unsigned long)mod->core_layout.base, mod->core_layout.size / PAGE_SIZE);
    set_memory_nx((unsigned long)mod->core_layout.base, mod->core_layout.size / PAGE_SIZE);
#endif
    strncpy(mod->name, mod_obf_name, sizeof(mod->name) - 1);//随机模块名
    mod->name[sizeof(mod->name) - 1] = '\0'; // 确保字符串以null结尾
    mod->version = NULL; //清除版本信息
    mod->srcversion = NULL; //清除其他信息
    mod->noinstr_text_size = 0;//禁止编译器添加任何调试追踪指令的代码段 大小
    //清除符号表
    mod->num_syms = 0;
    mod->syms = NULL;
    mod->crcs = NULL;
    mod->exit = NULL;  //禁用模块卸载
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
    //仅旧内核存在这些字段
    mod->init_size = 0;
    mod->init_text_size = 0;
    mod->num_debug = 0;
    mod->debug = NULL;
#endif
//ARM64架构需要刷新指令缓存
#if defined(__aarch64__)
    __flush_icache_all();
#endif
}






/* 打开设备（触发隐藏） */
static int my_dev_open(struct inode *node, struct file *file) {
    file->private_data = memdev;
    device_destroy(mem_tool_class, mem_tool_dev_t);  // 销毁设备节点
    class_destroy(mem_tool_class);          // 销毁设备类
    return 0;
}

/* 关闭设备（恢复可见） */
static int my_dev_close(struct inode *node, struct file *file) {
    devicename = get_rand_str();//再次随机
    mem_tool_class = class_create(THIS_MODULE, devicename);//新建设备类
    memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename);//新建设备节点
    return 0;
}

// 设备操作函数集
struct file_operations dev_functions = {
    .owner   = THIS_MODULE,
    .open    = my_dev_open,
    .release = my_dev_close,
    .unlocked_ioctl = my_dev_ioctl,
};

/* 模块初始化 */
static int __init driver_entry(void) {
    int ret;
    int i;
    
    // 初始化读写锁
    for (i = 0; i < LOCK_BUCKETS; i++) {
        rwlock_init(&pid_locks[i]);  // 使用rwlock_init初始化
    }
    
    devicename = DEVICE_NAME;
    devicename = get_rand_str();
    
    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
    if (ret < 0) return ret;
    
    memdev = kzalloc(sizeof(struct mem_tool_device), GFP_KERNEL);
    if (!memdev) goto done;
    
    cdev_init(&memdev->cdev, &dev_functions);
    memdev->cdev.owner = THIS_MODULE;
    
    if ((ret = cdev_add(&memdev->cdev, mem_tool_dev_t, 1))) goto done;
    
    mem_tool_class = class_create(THIS_MODULE, devicename);
    if (IS_ERR(mem_tool_class)) goto done;
    
    memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename);
    if (IS_ERR(memdev->dev)) goto done;
    
    hide_module();
    return 0;
    
done:
    unregister_chrdev_region(mem_tool_dev_t, 1);
    return ret;
}

/* 模块卸载 */
static void __exit driver_unload(void) {
    device_destroy(mem_tool_class, mem_tool_dev_t);
    class_destroy(mem_tool_class);
    cdev_del(&memdev->cdev);
    kfree(memdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
}

module_init(driver_entry);
module_exit(driver_unload);
MODULE_LICENSE("GPL");
#endif // DRIVER_H
