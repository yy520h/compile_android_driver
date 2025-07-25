#ifndef PROCESS_H
#define PROCESS_H

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/sched/signal.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/pid.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#define ARC_PATH_MAX 256

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#ifndef ARC_PATH_MAX
#define ARC_PATH_MAX PATH_MAX
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static size_t get_module_base(pid_t pid, char* name)
{
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
        if (vma->vm_end >= ULONG_MAX) break;
        vma = find_vma(mm, vma->vm_end);
    }
    mmput(mm);
    return count;
}
#else
uintptr_t get_module_base(pid_t pid, const char *name)
{
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

pid_t get_process_pid(char *comm)
{
    struct task_struct *task;
    for_each_process(task) {
        if (task->comm == comm) {
            return task->pid;
        }
    }
    return 0;
}


int ovo_flip_open(const char *filename, int flags, umode_t mode, struct file **f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    *f = filp_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#else
    static struct file* (*reserve_flip_open)(const char *filename, int flags, umode_t mode) = NULL;

    if (reserve_flip_open == NULL) {
        reserve_flip_open = (struct file* (*)(const char *filename, int flags, umode_t mode))kallsyms_lookup_name("filp_open");
        if (reserve_flip_open == NULL) {
            return -1;
        }
    }

    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#endif
}

int ovo_flip_close(struct file **f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    filp_close(*f, id);
    return 0;
#else
    static struct file* (*reserve_flip_close)(struct file **f, fl_owner_t id) = NULL;

    if (reserve_flip_close == NULL) {
        reserve_flip_close = (struct file* (*)(struct file **f, fl_owner_t id))kallsyms_lookup_name("filp_close");
        if (reserve_flip_close == NULL) {
            return -1;
        }
    }

    reserve_flip_close(f, id);
    return 0;
#endif
}

bool is_file_exist(const char *filename) {
    struct file* fp;

    if(ovo_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            ovo_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }

    return false;
}

int is_pid_alive(pid_t pid) {
    struct pid *pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return 0;

    return pid_alive(task);
}

int mark_pid_root(pid_t pid) {
    static struct cred* (*my_prepare_creds)(void) = NULL;

    struct pid *pid_struct;
    struct task_struct *task;
    kuid_t kuid;
    kgid_t kgid;
    struct cred *new_cred;

    kuid = KUIDT_INIT(0);
    kgid = KGIDT_INIT(0);

    pid_struct = find_get_pid(pid);

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (task == NULL){
        printk(KERN_ERR "[ovo] Failed to get current task info.\n");
        return -1;
    }

    if (my_prepare_creds == NULL) {
        my_prepare_creds = (void *)kallsyms_lookup_name("prepare_creds");
        if (my_prepare_creds == NULL) {
            printk(KERN_ERR "[ovo] Failed to find prepare_creds\n");
            return -1;
        }
    }

    new_cred = my_prepare_creds();
    if (new_cred == NULL) {
        printk(KERN_ERR "[ovo] Failed to prepare new credentials\n");
        return -ENOMEM;
    }
    new_cred->uid = kuid;
    new_cred->gid = kgid;
    new_cred->euid = kuid;
    new_cred->egid = kgid;

    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}

#endif
