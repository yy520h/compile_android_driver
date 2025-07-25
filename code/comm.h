#ifndef COMM_H
#define COMM_H

#include <linux/slab.h>
#include <linux/random.h>

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

// 触摸事件结构体定义，用于用户空间和内核空间的数据传递
typedef struct {
    unsigned int type;
    unsigned int code;
    int value;
} TouchEvent;

char* get_rand_str(void);

int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);

// 导出 kallsyms_lookup_name 函数以便其他模块可以使用
extern unsigned long kallsyms_lookup_name(const char *symbol_name);

#endif
