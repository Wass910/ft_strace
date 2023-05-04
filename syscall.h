#ifndef SYSCALL_H
# define SYSCALL_H

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

char			*ft_itoa(unsigned long n, int base);


#endif