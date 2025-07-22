#include "linux/sched/signal.h"
#include "linux/types.h"
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/io.h>
#include <linux/memory.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/page.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#define ARC_PATH_MAX 256

#include <linux/fs.h>    // For file and d_path
#include <linux/path.h>  // For struct path
#include <linux/dcache.h>// For d_path
#ifndef ARC_PATH_MAX
#define ARC_PATH_MAX PATH_MAX
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static size_t get_module_base(pid_t pid, char* name) {
	struct task_struct* task;
	struct mm_struct* mm;
	struct vm_area_struct *vma;
	size_t count = 0;
	char buf[ARC_PATH_MAX];
	char *path_nm = NULL;
	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	mm = get_task_mm(task);
	if (!mm) {
		return 0;
	}
	vma = find_vma(mm, 0);
	while (vma) {
		if (vma->vm_file) {
			path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX-1);
			if (!IS_ERR(path_nm) && !strcmp(kbasename(path_nm), name)) {
				count = (uintptr_t)vma->vm_start;
				break;
			}
		}
		if (vma->vm_end >= ULONG_MAX) break; // 防止缠绕
		vma = find_vma(mm, vma->vm_end);
	}
	mmput(mm);
	return count;
}
#else
uintptr_t get_module_base(pid_t pid, const char *name) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    size_t count = 0;
    char buf[ARC_PATH_MAX];
    char *path_nm = "";
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        return 0;
    }
    mm = task->mm;
    if (!mm) {
        return 0;
    }
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
            struct file *file = vma->vm_file;
            if (file) {
                path_nm = d_path(&file->f_path, buf, ARC_PATH_MAX-1);
                if (!strcmp(kbasename(path_nm), name)) {
                    count = vma->vm_start;
                    break;
                }
            }
    }
    mmput(mm);
    return count;
}
#endif

/*常见的  vm_flags  标志
VM_READ 表示该内存区域可读
VM_WRITE 表示该内存区域可写
VM_EXEC 表示该内存区域可执行
VM_SHARED 表示该内存区域是共享的(如共享库)
VM_IO 表示该内存区域用于 I/O 操作
VM_DONTDUMP 表示该内存区域在生成 core dump 时不会被转储
VM_PFNMAP 表示该内存区域映射了物理页帧
VM_LOCKED 表示该内存区域被锁定在内存中，不会被交换到磁盘。

如何选择  vm_flag  参数如果你希望查找所有可执行的内存区域，可以传入  VM_EXEC 。
如果你只关心共享的内存区域（如共享库），可以传入  VM_SHARED 。
如果你对内存区域的标志没有特殊要求，或者想搜索所有类型的内存区域，可以将  vm_flag  设置为  0 ，这样就不会进行任何过滤*/

//隐藏性更好
uintptr_t get_module_base_vm(pid_t pid, char *name, int vm_flag) {
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif
    uintptr_t result;
	struct dentry *dentry;
	size_t name_len, dname_len;
    result = 0;
	name_len = strlen(name);
	if (name_len == 0) {
		//printk("模块名称为空");
		return 0;
	}
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
		//printk("未能找到pid_struct");
        return 0;
    }
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
		//printk("未能从pid_struct获取任务");
        return 0;
    }
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
		//printk("未能从任务中获取mm");
        return 0;
    }
    MM_READ_LOCK(mm)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
        for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (vma->vm_file) {
			if (vm_flag && !(vma->vm_flags & vm_flag)) {
				continue;
			}
			dentry = vma->vm_file->f_path.dentry;
			dname_len = dentry->d_name.len;
			if (!memcmp(dentry->d_name.name, name, min(name_len, dname_len))) {
				result = vma->vm_start;
				goto ret;
			}
        }
    }
    ret:
    MM_READ_UNLOCK(mm)
    mmput(mm);
    return result;
}



pid_t get_process_pid(char *comm) {
    struct task_struct *task;
    for_each_process(task) {
        // 使用 strcmp 比较字符串内容，而不是检查内存地址是否相等
        if (strcmp(task->comm, comm) == 0) {
            return task->tgid; // 返回线程组 ID（即用户空间中看到的进程 ID）
        }
    }
    return -1; // 如果未找到，返回 0（注意：PID 0 是 swapper 进程）
}
