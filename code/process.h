#include <linux/sched.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif
#define ARC_PATH_MAX 256

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
				if(strstr(kbasename(path_nm),".so")!=NULL) {
					size_t add = (uintptr_t)vma->vm_start;
					vma = find_vma(mm, vma->vm_end);
					if (vma->vm_file) {
						path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX-1);
						if (!IS_ERR(path_nm) && !strcmp(kbasename(path_nm), name)) {
							count = add;
							break;
						}
					}else{
						vma = find_vma(mm, vma->vm_end);
						if (vma->vm_file) {
							path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX-1);
							if (!IS_ERR(path_nm) && !strcmp(kbasename(path_nm), name)) {
								count = add;
								break;
							}
						}
					}
				}else{
					count = (uintptr_t)vma->vm_start;
					break;
				}
			}
		}
		if (vma->vm_end >= ULONG_MAX) break; // Prevent wrapping around
		vma = find_vma(mm, vma->vm_end);
	}
	mmput(mm);
	return count;
}