#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/module.h>
#include <linux/highmem.h>

#define ARC_PATH_MAX 256

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t page_addr;
    uintptr_t page_offset;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return 0;
    }
    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd)) {
        return 0;
    }
    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte)) {
        return 0;
    }
    if (!pte_present(*pte)) {
        return 0;
    }
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);

    return page_addr + page_offset;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;
    char* buffer = NULL;
    char* va;
    size_t total = size;

    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate kernel buffer\n");
        return false;
    }

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "Failed to find task with PID: %d\n", pid);
        kfree(buffer);
        return false;
    }

    mm = get_task_mm(task);
    if (!mm) {
        printk(KERN_ERR "Failed to get mm_struct for PID: %d\n", pid);
        kfree(buffer);
        return false;
    }

    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        if (!pa) {
            printk(KERN_ERR "Failed to translate linear address 0x%lx for PID: %d\n", addr, pid);
            goto error;
        }

        va = (char*)phys_to_virt(pa);
        if (!va) {
            printk(KERN_ERR "phys_to_virt failed for physical address: 0x%lx\n", pa);
            goto error;
        }

        max = min_t(size_t, PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min_t(size_t, size, PAGE_SIZE));
        memcpy(buffer, va, max);

        if (copy_to_user(user_buffer, buffer, max)) {
            printk(KERN_ERR "copy_to_user failed\n");
            goto error;
        }

        count += max;
        size -= max;
        user_buffer += max;
        addr += max;
    }

    mmput(mm);
    kfree(buffer);

    return count == total;
error:
    mmput(mm);
    kfree(buffer);
    return false;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* user_buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    phys_addr_t pa;
    size_t max;
    size_t count = 0;
    char* buffer = NULL;
    char* va;
    size_t total = size;

    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate kernel buffer\n");
        return false;
    }

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "Failed to find task with PID: %d\n", pid);
        kfree(buffer);
        return false;
    }

    mm = get_task_mm(task);
    if (!mm) {
        printk(KERN_ERR "Failed to get mm_struct for PID: %d\n", pid);
        kfree(buffer);
        return false;
    }

    while (size > 0) {
        pa = translate_linear_address(mm, addr);
        if (!pa) {
            printk(KERN_ERR "Failed to translate linear address 0x%lx for PID: %d\n", addr, pid);
            goto error;
        }

        va = (char*)phys_to_virt(pa);
        if (!va) {
            printk(KERN_ERR "phys_to_virt failed for physical address: 0x%lx\n", pa);
            goto error;
        }

        max = min_t(size_t, PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min_t(size_t, size, PAGE_SIZE));
        if (copy_from_user(buffer, user_buffer, max)) {
            printk(KERN_ERR "copy_from_user failed\n");
            goto error;
        }

        memcpy(va, buffer, max);

        count += max;
        size -= max;
        user_buffer += max;
        addr += max;
    }

    mmput(mm);
    kfree(buffer);

    return count == total;
error:
    mmput(mm);
    kfree(buffer);
    return false;
}
