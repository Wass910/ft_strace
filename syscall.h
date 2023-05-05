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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <elf.h>

#define TNONE 0
#define TINT 1
#define TUINT 2
#define TSTR 3
#define TLSTR 4
#define TPTR 5

typedef struct user_regs_struct32
{
  unsigned int ebx;
  unsigned int ecx;
  unsigned int edx;
  unsigned int esi;
  unsigned int edi;
  unsigned int ebp;
  unsigned int eax;
  unsigned int xds;
  unsigned int xes;
  unsigned int xfs;
  unsigned int xgs;
  unsigned int orig_eax;
  unsigned int eip;
  unsigned int xcs;
  unsigned int eflags;
  unsigned int esp;
  unsigned int xss;
}				t_regs_32;

typedef struct			s_syscall
{
	int						code64;
	int						code32;
	char					*name;
	int						arg[6];
	int						ret;
}						t_syscall;

typedef struct			s_sig
{
	int						num;
	char				 	*name;
}						t_sig;


char			*ft_itoa(unsigned long n, int base);


#endif