#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <asm/unaligned.h>
#include "ecryptfs_kernel.h"


static long cs_do_stat(uintptr_t myfunc, const char * __user filename, 
                       unsigned int fd, struct stat __user *statbuf) 
{
    long err = 0;

    if (myfunc == (uintptr_t)old_stat) 
        err = old_stat(filename, statbuf);
    else if (myfunc == (uintptr_t)old_lstat) 
        err = old_lstat(filename, statbuf); 
    else if (myfunc == (uintptr_t)old_fstat) 
        err = old_fstat(fd, statbuf);

    return err;
}

asmlinkage long cs_stat(const char __user *filename, struct stat __user *statbuf)
{
    return cs_do_stat((uintptr_t)old_stat, filename, 0, statbuf);
}

asmlinkage long cs_lstat(const char __user *filename, struct stat __user *statbuf)
{
    return cs_do_stat((uintptr_t)old_lstat, filename, 0, statbuf);
}

asmlinkage long cs_fstat(unsigned int fd, struct stat __user *statbuf)
{
    return cs_do_stat((uintptr_t)old_fstat, 0, fd, statbuf);
}