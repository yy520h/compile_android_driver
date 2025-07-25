obj-m += hack.o

# 禁用 LTO 编译
hackflags := -fno-lto
hack.o: CFLAGS += $(hackflags)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
