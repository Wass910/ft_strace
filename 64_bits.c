#include "syscall.h"

void print_read_args(pid_t pid, struct user_regs_struct regs) {
    int i;
    long data;
    char buf[4096];
    size_t nread;
    if (regs.rdx <= sizeof(buf)) {
        nread = regs.rdx;
    } else {
        nread = sizeof(buf);
    }
    memset(buf, 0, sizeof(buf));
    i = 0;
	do {
		data = ptrace(PTRACE_PEEKDATA, pid, regs.rsi + i, NULL);
		if (data == -1) {
			perror("ptrace");
			return;
		}
		memcpy(buf + i, &data, sizeof(long));
		i += sizeof(long);
	} while (i < sizeof(buf) && *(buf + i - 1) != '\0');
    if (strncmp(g_summary->name, "/bin/bash", strlen("/bin/bash")) == 1)
		printf("\"%s\"", buf);
		
}

void print_syscall_64(unsigned long sys, struct user_regs_struct regs, int pid)
{

	if (strncmp("exit_group", g_syscall[sys].name, 10) == 0)
		return ;
	if (sys == 59 )
		return ;
	printf("%s(", g_syscall[sys].name );
	int i = 0;
	int e = 0;
	char buf[100000];
	long data = 0;
	long long arg_registre[6] = {regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9};

	while (i < 6){
		if (g_syscall[sys].arg[i] != 0 && i > 0)
			printf(", ");
		if (g_syscall[sys].arg[i] == 1)
		{
			printf("%d", (int)arg_registre[i]);
		}
		if (g_syscall[sys].arg[i] == 2)
		{
			printf("%u", (unsigned int)arg_registre[i]);
		}
		if (g_syscall[sys].arg[i] == 3 )
		{
			if (sys == SYS_access)
			{
				do 
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rdi + e, NULL);
					if (data == -1) {
						perror("ptrace");
						return ;
					}
					buf[e] = data;
					e++;
				} while (data && e < sizeof(buf));
				printf("\"%s\"", buf);
				e = 0;
			}
			else{
				print_read_args(pid, regs);
			}
		}
		if (g_syscall[sys].arg[i] == 4)
		{
			if (sys == SYS_access)
			{
				do 
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rdi + e, NULL);
					if (data == -1) {
						perror("ptrace");
						return ;
					}
					buf[e] = data;
					e++;
				} while (data && e < sizeof(buf));
				printf("\"%s\"", buf);
				e = 0;
			}
			else{
				print_read_args(pid, regs);
			}
		}
		if (g_syscall[sys].arg[i] == 5)
		{
			if ((void *)arg_registre[i] == NULL)
				printf("NULL");
			else
				printf("%p", (void *)arg_registre[i]);
		}
		i++;
	}
	if (sys == SYS_restart_syscall)
		printf("%s", "<... resuming interrupted nanosleep ...>");
	if (g_syscall[sys].ret == 5){
		char *str = ft_itoa(regs.rax, 16);
		printf(") = 0x%s\n", str);
		free(str);
	}
	else{
		if (regs.orig_rax == SYS_write)
			printf(") = %llu\n", regs.rdx);
		else
			printf(") = %d\n", (int)regs.rax );
	}
	return ;
    
}

void summary_activate_64(unsigned long sys, struct user_regs_struct regs, int pid)
{
	int i = 0;
	struct timeval start, end;
    gettimeofday(&start, NULL);

	while (i < 6){
		if (g_syscall[sys].arg[i] != 0 && i > 0){};
		if (g_syscall[sys].arg[i] == 1){};
		if (g_syscall[sys].arg[i] == 2){};
		if (g_syscall[sys].arg[i] == 3 )
		{
			if (sys == SYS_access){};
		}
		if (g_syscall[sys].arg[i] == 4)
		{
			if (sys == SYS_access){};
		}
		if (g_syscall[sys].arg[i] == 5){};
		i++;
	}

	gettimeofday(&end, NULL);
    long long elapsed_time = time_in_microseconds(start, end);
    //printf("Le temps écoulé est de %lld microsecondes.\n", elapsed_time);
	if (g_syscall[sys].ret != 5 && (int)regs.rax < 0)
	{
		if (check_summary(sys, 1) == 1)
		{
			return;
		}
		else
			ft_lstadd_back(&g_summary, ft_fill_summary(1, 1, sys , elapsed_time));

	}
	else
	{
		if (check_summary(sys, 0) == 1)
		{
			return ;
		}
		else
			ft_lstadd_back(&g_summary, ft_fill_summary(1, 0, sys, elapsed_time));

	}
	return ;
}