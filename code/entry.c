#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
//#include "verify.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
	MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver); 
#endif

long dispatch_ioctl(struct file* const file, unsigned int const cmd, unsigned long const arg)
{
	static COPY_MEMORY cm;
	static MODULE_BASE mb;
	static char name[0x100] = {0};
	/*static char key[0x100] = {0};
	static bool is_verified = false;
	if(cmd == OP_INIT_KEY && !is_verified) {
		if (copy_from_user(key, (void __user*)arg, sizeof(key)-1) != 0) {
			return -1;
		}
		is_verified = init_key(key, sizeof(key));
	}
	if(is_verified == false) {
		return -1;
	}*/
	switch (cmd) {
		case OP_READ_MEM:
			{
				if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
					return -1;
				}
				if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
					return -1;
				}
			}
			break;
		case OP_WRITE_MEM:
			{
				if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) != 0) {
					return -1;
				}
				if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false) {
					return -1;
				}
			}
			break;
		case OP_MODULE_BASE:
			{
				if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) != 0 
				|| copy_from_user(name, (void __user*)mb.name, sizeof(name)-1) !=0) {
					return -1;
				}
				mb.base = get_module_base(mb.pid, name);
				if (copy_to_user((void __user*)arg, &mb, sizeof(mb)) !=0) {
					return -1;
				}
			}
			break;
		default:
			break;
	}
	return 0;
}

struct file_operations dispatch_functions = {
	.owner  = THIS_MODULE,
	.open	= dispatch_open,
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

int dispatch_open(struct inode *node, struct file *file)
{
	//将设备结构体指针赋值给文件私有数据指针
	file->private_data = memdev;
	prev_module = __this_module.list.prev;
	list_del_init(&__this_module.list); //摘除链表，/proc/modules 中不可见。
	device_destroy(mem_tool_class, mem_tool_dev_t); //删除设备文件
	class_destroy(mem_tool_class); //删除设备类
	printk("打开文件成功\n");
	return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
	list_add(&__this_module.list, prev_module); //创建链表
	mem_tool_class = class_create(THIS_MODULE, devicename); //创建设备类
	memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename); //创建设备文件
	printk("关闭文件成功\n");
	return 0;
}

static int __init driver_entry(void)
{
	int ret;
	devicename = DEVICE_NAME;
	devicename = get_rand_str();//注释此行关闭随机驱动

	//1.动态申请设备号
	ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, devicename);
	if (ret < 0) {
		printk("设备编号分配失败: %d\n", ret);
		return ret;
	}

	//2.动态申请设备结构体的内存
	memdev = kmalloc(sizeof(struct mem_tool_device), GFP_KERNEL);
	if (!memdev) {
		printk("内存分配失败: %d\n", ret);
		goto done;
	}
	memset(memdev, 0, sizeof(struct mem_tool_device));

	//3.初始化并且添加cdev结构体
	cdev_init(&memdev->cdev, &dispatch_functions); //初始化cdev设备
	memdev->cdev.owner = THIS_MODULE; //使驱动程序属于该模块
	memdev->cdev.ops = &dispatch_functions; //cdev连接file_operations指针

	ret = cdev_add(&memdev->cdev, mem_tool_dev_t, 1); //将cdev注册到系统中
	if (ret) {
		printk("注册cdev失败: %d\n", ret);
		goto done;
	}

	//4.创建设备文件
	mem_tool_class = class_create(THIS_MODULE, devicename); //创建设备类
	if (IS_ERR(mem_tool_class)) {
		printk("创建设备类失败: %d\n", ret);
		goto done;
	}
	memdev->dev = device_create(mem_tool_class, NULL, mem_tool_dev_t, NULL, "%s", devicename); //创建设备文件
	if (IS_ERR(memdev->dev)) {
		printk("创建设备文件失败: %d\n", ret);
		goto done;
	}

	if (!IS_ERR(filp_open("/proc/sched_debug", O_RDONLY, 0))) {
		remove_proc_subtree("sched_debug", NULL); //移除/proc/sched_debug。
	}
	if (!IS_ERR(filp_open("/proc/uevents_records", O_RDONLY, 0))) {
		remove_proc_entry("uevents_records", NULL); //移除/proc/uevents_records。
	}
	unregister_chrdev_region(mem_tool_dev_t, 1); //释放设备号，/proc/devices 中不可见。
	list_del_init(&__this_module.list); //摘除链表，/proc/modules 中不可见。
	kobject_del(&THIS_MODULE->mkobj.kobj); //摘除kobj，/sys/modules/中不可见。

	printk("设备创建成功 %s\n", devicename);
	return 0;

done:
	return ret;
}

static void __exit driver_unload(void)
{
	device_destroy(mem_tool_class, mem_tool_dev_t); //删除设备文件
	class_destroy(mem_tool_class); //删除设备类

	cdev_del(&memdev->cdev); //注销cdev
	kfree(memdev);// 释放设备结构体内存
	unregister_chrdev_region(mem_tool_dev_t, 1); //释放设备号

	printk("设备删除成功 %s\n", devicename);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
//by----时光弟弟开源