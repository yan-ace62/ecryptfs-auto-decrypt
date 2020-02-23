#
# Makefile for the Linux eCryptfs
#

ksrc_dir = /lib/modules/$(shell uname -r)/build

ccflags-y := -std=gnu99 -Wno-declaration-after-statement

obj-m += csecryptfs.o

csecryptfs-y := dentry.o file.o inode.o main.o super.o mmap.o read_write.o \
	      crypto.o keystore.o kthread.o debug.o hook.o netlink.o

all:
	make -C $(ksrc_dir) M=$(PWD) modules
clean:
	make -C $(ksrc_dir) M=$(PWD) clean
