#include "syscall.h"

void print_read_args_32(pid_t pid, t_regs_32 regs) {
    int i;
    long data;
    char buf[4096];
    size_t nread;
    if (regs.edx <= sizeof(buf)) {
        nread = regs.edx;
    } else {
        nread = sizeof(buf);
    }
    memset(buf, 0, sizeof(buf));
    i = 0;
	do {
		data = ptrace(PTRACE_PEEKDATA, pid, regs.ecx + i, NULL);
		if (data == -1) {
			perror("ptrace");
			return;
		}
		memcpy(buf + i, &data, sizeof(long));
		i += sizeof(long);
	} while (i < sizeof(buf) && *(buf + i - 1) != '\0');
    printf("\"%s\"", buf);
}

void summary_activate_32(unsigned long sys, t_regs_32 regs, int pid)
{
	int i = 0;
	int count = 0;
    while (g_syscall[count].code32 && g_syscall[count].code32 != sys )
        count++;
	struct timeval start, end;
    gettimeofday(&start, NULL);

	while (i < 6){
		if (g_syscall[count].arg[i] != 0 && i > 0){};
		if (g_syscall[count].arg[i] == 1){};
		if (g_syscall[count].arg[i] == 2){};
		if (g_syscall[count].arg[i] == 3 )
		{
			if (sys == SYS_access){};
		}
		if (g_syscall[count].arg[i] == 4)
		{
			if (sys == SYS_access){};
		}
		if (g_syscall[count].arg[i] == 5){};
		i++;
	}

	gettimeofday(&end, NULL);
    long long elapsed_time = time_in_microseconds(start, end);
    //printf("Le temps écoulé est de %lld microsecondes.\n", elapsed_time);
	if (g_syscall[count].ret != 5 && (int)regs.eax < 0)
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

void print_syscall_32(unsigned long sys, t_regs_32 regs, int pid)
{
	if (sys == 11 )
		return ;
    int count = 0;
    while (g_syscall[count].code32 && g_syscall[count].code32 != sys )
        count++;
	if (strncmp("exit_group", g_syscall[count].name, 10) == 0)
		return ;
	printf("%s(", g_syscall[count].name );
	int i = 0;
	int e = 0;
	char buf[100000];
	long data = 0;
	long long arg_registre[6] = {regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp};

	while (i < 6){
		if (g_syscall[count].arg[i] != 0 && i > 0)
			printf(", ");
		if (g_syscall[count].arg[i] == 1)
		{
			printf("%d", (int)arg_registre[i]);
		}
		if (g_syscall[count].arg[i] == 2)
		{
			printf("%u", (unsigned int)arg_registre[i]);
		}
		if (g_syscall[count].arg[i] == 3 )
		{
			if (sys == 33)
			{
				do 
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)regs.ebx + e, NULL);
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
				print_read_args_32(pid, regs);
			}
		}
		if (g_syscall[count].arg[i] == 4)
		{
			if (sys == 33)
			{
				do 
				{
					data = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)regs.ebx + e, NULL);
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
				print_read_args_32(pid, regs);
			}
		}
		if (g_syscall[count].arg[i] == 5)
		{
			if ((void *)arg_registre[i] == NULL)
				printf("NULL");
			else
				printf("%p", (void *)arg_registre[i]);
		}
		i++;
	}
	if (sys == 0)
		printf("%s", "<... resuming interrupted nanosleep ...>");
	if (g_syscall[count].ret == 5){
		char *str = ft_itoa(regs.eax, 16);
		printf(") = 0x%s\n", str);
		free(str);
	}
	else{
		if (sys == 4)
			printf(") = %u\n", regs.edx);
		else
			printf(") = %d\n", (int)regs.eax);
	}
	return ;
}