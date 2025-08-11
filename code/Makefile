obj-m := driver.o

CONFIG_SYSFS=y
CONFIG_DEVICE_CLASS=y
CONFIG_FB=y
CONFIG_FB_DEVICE=y
CONFIG_KPROBES=y


CONFIG_KPROBES=y
CONFIG_HAVE_KPROBES=y
CONFIG_KPROBES_ON_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y


EXTRA_CFLAGS += -DCONFIG_ARM64
EXTRA_CFLAGS += -DINJECT_SYSCALLS=1     # 启用SYSCALL注入
EXTRA_CFLAGS += -DHIDE_SELF_MODULE=1    # 是否在模块表中移除自己

EXTRA_CFLAGS += -DBUILD_REMAP=1         # 关闭内存重映射API(不再需要)
EXTRA_CFLAGS += -DENABLE_REMAP2=1        # 关闭新的REMAP接口(不再需要)
EXTRA_CFLAGS += -DBIG_PAGE            # 注释掉大页支持(不再需要)

# EXTRA_CFLAGS += -O2                     # 优化等级2 优化牺牲的是性能  不需要
EXTRA_CFLAGS += -fvisibility=hidden     # 隐藏符号
EXTRA_CFLAGS += -fomit-frame-pointer    # 省略帧指针
# EXTRA_CFLAGS += -g0                   # 去除调试信息
EXTRA_CFLAGS += -fno-pic -fvisibility=hidden
EXTRA_CFLAGS += -fno-stack-protector
# 禁用特定警告
EXTRA_CFLAGS += -Wno-unused-function
EXTRA_CFLAGS += -Wno-unused-variable
EXTRA_CFLAGS += -Wno-error
EXTRA_CFLAGS += -DKASAN_DISABLE
#如果出现 "symbol not found" 错误 在 Makefile 中添加以下选项
#EXTRA_CFLAGS += -D__KERNEL_MODULE

# ARM架构优化
#EXTRA_CFLAGS += -march=armv8-a           # 适用于ARMv8架构
#EXTRA_CFLAGS += -mtune=cortex-a53        # 针对Cortex-A53优化
#EXTRA_CFLAGS += -mfpu=neon-fp-armv8     # 使用NEON和VFP单元
#EXTRA_CFLAGS += -mfloat-abi=hard        # 硬件浮点

all:
	make -C $(KDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
