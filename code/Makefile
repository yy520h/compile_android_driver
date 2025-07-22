MODULE_NAME := hack
RESMAN_CORE_OBJS:=entry.o
RESMAN_GLUE_OBJS:=
ifneq ($(KERNELRELEASE),)
	obj-m := $(MODULE_NAME).o
	$(MODULE_NAME)-objs:=$(RESMAN_GLUE_OBJS) $(RESMAN_CORE_OBJS)
else
	KDIR := /home/administrator/桌面/munch-s-oss/out
all:
	make -j$(nproc) -C $(KDIR) M=$(shell pwd) LLVM=1 LLVM_IAS=1 ARCH=arm64 CC=clang LD=ld.lld OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump NM=llvm-nm STRIP=llvm-strip modules
	rm -rf *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions
	llvm-strip --strip-debug $(MODULE_NAME).ko
clean:
	rm -rf *.ko *.o *.mod .*.*.cmd *.mod.o *.mod.c *.symvers *.order .tmp_versions
endif
