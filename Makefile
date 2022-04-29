hook-objs := main.o util.o
obj-m += hook.o

KERNEL_PATH := /home/code/android_kernel_samsung_gta4xl
CCPATH := /home/code/toolchains/clang-r428724/bin:/home/code/toolchains/aarch64-linux-android-4.9/bin
ARCH=arm64

export PATH := ${CCPATH}:${PATH}
export CLANG_TRIPLE = aarch64-linux-gnu-
export CROSS_COMPILE = aarch64-linux-android-

all:
	make CC=clang ARCH=$(ARCH) CFLAGS=$(CFLAGS) -C $(KERNEL_PATH) M=$(PWD) modules -j$(nproc --all)

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
