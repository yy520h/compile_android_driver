obj-m           := driver.o

# ===== 基础配置 =====
CONFIG_SYSFS               := y
CONFIG_DEVICE_CLASS        := y
CONFIG_FB                  := y
CONFIG_FB_DEVICE           := y
CONFIG_KPROBES             := y
CONFIG_HAVE_KPROBES        := y
CONFIG_KPROBES_ON_FTRACE   := y
CONFIG_FUNCTION_TRACER     := y
CONFIG_KALLSYMS            := y
CONFIG_KALLSYMS_ALL        := y
CONFIG_STRICT_KERNEL_RWX   := n

# ===== 功能宏 =====
EXTRA_CFLAGS += -DCONFIG_ARM64
EXTRA_CFLAGS += -DINJECT_SYSCALLS=1
EXTRA_CFLAGS += -DHIDE_SELF_MODULE=1
EXTRA_CFLAGS += -DBUILD_REMAP=1
EXTRA_CFLAGS += -DENABLE_REMAP2=1
EXTRA_CFLAGS += -DBIG_PAGE
EXTRA_CFLAGS += -DKASAN_DISABLE

# ===== 常规硬化 =====
EXTRA_CFLAGS += -fvisibility=hidden
EXTRA_CFLAGS += -fomit-frame-pointer
EXTRA_CFLAGS += -fno-stack-protector
EXTRA_CFLAGS += -fno-pic
EXTRA_CFLAGS += -Wno-unused-function
EXTRA_CFLAGS += -Wno-unused-variable
EXTRA_CFLAGS += -Wno-error

# ===== 2025-06-25 新增：LTO + 去调试信息 + strip =====
EXTRA_CFLAGS += -flto
EXTRA_CFLAGS += -fno-unwind-tables
EXTRA_CFLAGS += -fno-asynchronous-unwind-tables
EXTRA_CFLAGS += -fno-ident
# EXTRA_CFLAGS += -Wno-lto-type-mismatch   # AOSP12 Clang 无此选项

# 链接阶段彻底剥符号
KBUILD_LDFLAGS += -s

# ===== 编译规则 =====
all:
	$(MAKE) -C $(KDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

# ===== 剥光符号 =====
targets := driver.ko
quiet_cmd_strip = STRIP   $@
      cmd_strip = $(OBJCOPY) --strip-all $@

$(obj)/driver.ko: FORCE
	$(call cmd,strip)


clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
