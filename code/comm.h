#ifndef COMM_H
#define COMM_H

#include <linux/slab.h>
#include <linux/random.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

#define DEVICE_NAME "qwqbai"

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

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
    OP_MODULE_PID = 0x804,
    OP_TOUCH_PRESS = 0x805,
    OP_TOUCH_MOVE = 0x806,
    OP_TOUCH_RELEASE = 0x807
};

typedef struct {
    unsigned int type;
    unsigned int code;
    int value;
} TouchEvent;

char* get_rand_str(void)
{
	static char string[10];
	int lstr,seed,flag,i;
	char *str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	lstr = strlen(str);
	for (i = 0; i < 6; i++)
	{
		get_random_bytes(&seed, sizeof(int));
		flag = seed % lstr;
		if (flag < 0)
			flag = flag * -1;
		string[i] = str[flag];
	}
	string[6] = '\0';
	return string;
}


int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);

// 导出 kallsyms_lookup_name 函数
extern unsigned long kallsyms_lookup_name(const char *symbol_name);
EXPORT_SYMBOL(kallsyms_lookup_name);

#endif
