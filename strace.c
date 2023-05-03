#include "syscall.h"

typedef struct user_regs_struct64
{
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
  unsigned long fs_base;
  unsigned long gs_base;
  unsigned long ds;
  unsigned long es;
  unsigned long fs;
  unsigned long gs;
}				t_regs_64;

char *syscall_tab[300];

void fill_syscall_tab()
{                                                                
    syscall_tab[62] = "lseek";
    syscall_tab[202] = "accept";
    syscall_tab[242] = "accept4";
    syscall_tab[89] = "acct";
    syscall_tab[217] = "add_key";
    syscall_tab[171] = "adjtimex";
    syscall_tab[200] = "bind";
    syscall_tab[214] = "brk";
    syscall_tab[90] = "capget";
    syscall_tab[91] = "capset";
    syscall_tab[49] = "chdir";
    syscall_tab[51] = "chroot";
    syscall_tab[114] = "clock_getres";
    syscall_tab[113] = "clock_gettime";
    syscall_tab[115] = "clock_nanosleep";
    syscall_tab[112] = "clock_settime";
    syscall_tab[220] = "clone";
    syscall_tab[57] = "close";
    syscall_tab[203] = "connect";
    syscall_tab[106] = "delete_module";
    syscall_tab[23] = "dup";
    syscall_tab[21] = "epoll_ctl";
    syscall_tab[22] = "epoll_pwait";
    syscall_tab[221] = "execve";
    syscall_tab[93] = "exit";
    syscall_tab[94] = "exit_group";
    syscall_tab[48] = "faccessat";
    syscall_tab[223] = "fadvise64";
    syscall_tab[47] = "fallocate";
    syscall_tab[50] = "fchdir";
    syscall_tab[52] = "fchmod";
    syscall_tab[53] = "fchmodat";
    syscall_tab[55] = "fchown";
    syscall_tab[54] = "fchownat";
    syscall_tab[25] = "fcntl";
    syscall_tab[83] = "fdatasync";
    syscall_tab[10] = "fgetxattr";
    syscall_tab[13] = "flistxattr";
    syscall_tab[32] = "flock";
    syscall_tab[16] = "fremovexattr";
    syscall_tab[7] = "fsetxattr";
    syscall_tab[80] = "fstat";
    syscall_tab[44] = "fstatfs";
    syscall_tab[82] = "fsync";
    syscall_tab[46] = "ftruncate";
    syscall_tab[98] = "futex";
    syscall_tab[236] = "get_mempolicy";
    syscall_tab[100] = "get_robust_list";
    syscall_tab[168] = "getcpu";
    syscall_tab[17] = "getcwd";
    syscall_tab[61] = "getdents64";
    syscall_tab[177] = "geteg";
    syscall_tab[175] = "geteu";
    syscall_tab[176] = "getg";
    syscall_tab[158] = "getgroups";
    syscall_tab[102] = "getitimer";
    syscall_tab[205] = "getpeername";
    syscall_tab[155] = "getpg";
    syscall_tab[172] = "getp";
    syscall_tab[173] = "getpp";
    syscall_tab[141] = "getpriority";
    syscall_tab[150] = "getresg";
    syscall_tab[148] = "getresu";
    syscall_tab[163] = "getrlimit";
    syscall_tab[165] = "getrusage";
    syscall_tab[156] = "gets";
    syscall_tab[204] = "getsockname";
    syscall_tab[209] = "getsockopt";
    syscall_tab[178] = "gett";
    syscall_tab[169] = "gettimeofday";
    syscall_tab[174] = "getu";
    syscall_tab[8] = "getxattr";
    syscall_tab[105] = "init_module";
    syscall_tab[27] = "inotify_add_watch";
    syscall_tab[28] = "inotify_rm_watch";
    syscall_tab[3] = "io_cancel";
    syscall_tab[1] = "io_destroy";
    syscall_tab[4] = "io_getevents";
    syscall_tab[0] = "io_setup";
    syscall_tab[2] = "io_submit";
    syscall_tab[29] = "ioctl";
    syscall_tab[31] = "ioprio_get";
    syscall_tab[30] = "ioprio_set";
    syscall_tab[104] = "kexec_load";
    syscall_tab[219] = "keyctl";
    syscall_tab[129] = "kill";
    syscall_tab[9] = "lgetxattr";
    syscall_tab[37] = "linkat";
    syscall_tab[201] = "listen";
    syscall_tab[11] = "listxattr";
    syscall_tab[12] = "llistxattr";
    syscall_tab[18] = "lookup_dcookie";
    syscall_tab[15] = "lremovexattr";
    syscall_tab[6] = "lsetxattr";
    syscall_tab[233] = "madvise";
    syscall_tab[235] = "mbind";
    syscall_tab[238] = "migrate_pages";
    syscall_tab[232] = "mincore";
    syscall_tab[34] = "mkdirat";
    syscall_tab[33] = "mknodat";
    syscall_tab[228] = "mlock";
    syscall_tab[230] = "mlockall";
    syscall_tab[222] = "mmap";
    syscall_tab[40] = "mount";
    syscall_tab[239] = "move_pages";
    syscall_tab[226] = "mprotect";
    syscall_tab[185] = "mq_getsetattr";
    syscall_tab[184] = "mq_notify";
    syscall_tab[180] = "mq_open";
    syscall_tab[183] = "mq_timedreceive";
    syscall_tab[182] = "mq_timedsend";
    syscall_tab[181] = "mq_unlink";
    syscall_tab[216] = "mremap";
    syscall_tab[187] = "msgctl";
    syscall_tab[186] = "msgget";
    syscall_tab[188] = "msgrcv";
    syscall_tab[189] = "msgsnd";
    syscall_tab[227] = "msync";
    syscall_tab[229] = "munlock";
    syscall_tab[231] = "munlockall";
    syscall_tab[215] = "munmap";
    syscall_tab[101] = "nanosleep";
    syscall_tab[42] = "nfsservctl";
    syscall_tab[56] = "openat";
    syscall_tab[92] = "personality";
    syscall_tab[41] = "pivot_root";
    syscall_tab[73] = "ppoll";
    syscall_tab[167] = "prctl";
    syscall_tab[67] = "pread64";
    syscall_tab[72] = "pselect6";
    syscall_tab[117] = "ptrace";
    syscall_tab[68] = "pwrite64";
    syscall_tab[60] = "quotactl";
    syscall_tab[63] = "read";
    syscall_tab[78] = "readlinkat";
    syscall_tab[65] = "readv";
    syscall_tab[142] = "reboot";
    syscall_tab[207] = "recvfrom";
    syscall_tab[212] = "recvmsg";
    syscall_tab[234] = "remap_file_pages";
    syscall_tab[14] = "removexattr";
    syscall_tab[38] = "renameat";
    syscall_tab[218] = "request_key";
    syscall_tab[128] = "restart_syscall";
    syscall_tab[134] = "rt_sigaction";
    syscall_tab[136] = "rt_sigpending";
    syscall_tab[135] = "rt_sigprocmask";
    syscall_tab[138] = "rt_sigqueueinfo";
    syscall_tab[139] = "rt_sigreturn";
    syscall_tab[133] = "rt_sigsuspend";
    syscall_tab[137] = "rt_sigtimedwait";
    syscall_tab[125] = "sched_get_priority_max";
    syscall_tab[126] = "sched_get_priority_min";
    syscall_tab[123] = "sched_getaffinity";
    syscall_tab[121] = "sched_getparam";
    syscall_tab[120] = "sched_getscheduler";
    syscall_tab[127] = "sched_rr_get_interval";
    syscall_tab[122] = "sched_setaffinity";
    syscall_tab[118] = "sched_setparam";
    syscall_tab[119] = "sched_setscheduler";
    syscall_tab[124] = "sched_yield";
    syscall_tab[191] = "semctl";
    syscall_tab[190] = "semget";
    syscall_tab[193] = "semop";
    syscall_tab[192] = "semtimedop";
    syscall_tab[71] = "sendfile";
    syscall_tab[211] = "sendmsg";
    syscall_tab[206] = "sendto";
    syscall_tab[237] = "set_mempolicy";
    syscall_tab[99] = "set_robust_list";
    syscall_tab[96] = "set_tid_address";
    syscall_tab[162] = "setdomainname";
    syscall_tab[152] = "setfsg";
    syscall_tab[151] = "setfsu";
    syscall_tab[144] = "setg";
    syscall_tab[159] = "setgroups";
    syscall_tab[161] = "sethostname";
    syscall_tab[103] = "setitimer";
    syscall_tab[154] = "setpg";
    syscall_tab[140] = "setpriority";
    syscall_tab[143] = "setreg";
    syscall_tab[149] = "setresg";
    syscall_tab[147] = "setresu";
    syscall_tab[145] = "setreu";
    syscall_tab[164] = "setrlimit";
    syscall_tab[157] = "sets";
    syscall_tab[208] = "setsockopt";
    syscall_tab[170] = "settimeofday";
    syscall_tab[146] = "setu";
    syscall_tab[5] = "setxattr";
    syscall_tab[196] = "shmat";
    syscall_tab[195] = "shmctl";
    syscall_tab[197] = "shmdt";
    syscall_tab[194] = "shmget";
    syscall_tab[210] = "shutdown";
    syscall_tab[132] = "sigaltstack";
    syscall_tab[198] = "socket";
    syscall_tab[199] = "socketpair";
    syscall_tab[76] = "splice";
    syscall_tab[43] = "statfs";
    syscall_tab[225] = "swapoff";
    syscall_tab[224] = "swapon";
    syscall_tab[36] = "symlinkat";
    syscall_tab[81] = "sync";
    syscall_tab[84] = "sync_file_range";
    syscall_tab[179] = "sysinfo";
    syscall_tab[116] = "syslog";
    syscall_tab[77] = "tee";
    syscall_tab[131] = "tgkill";
    syscall_tab[107] = "timer_create";
    syscall_tab[111] = "timer_delete";
    syscall_tab[109] = "timer_getoverrun";
    syscall_tab[108] = "timer_gettime";
    syscall_tab[110] = "timer_settime";
    syscall_tab[85] = "timerfd_create";
    syscall_tab[87] = "timerfd_gettime";
    syscall_tab[86] = "timerfd_settime";
    syscall_tab[153] = "times";
    syscall_tab[130] = "tkill";
    syscall_tab[45] = "truncate";
    syscall_tab[166] = "umask";
    syscall_tab[39] = "umount2";
    syscall_tab[160] = "uname";
    syscall_tab[35] = "unlinkat";
    syscall_tab[97] = "unshare";
    syscall_tab[88] = "utimensat";
    syscall_tab[58] = "vhangup";
    syscall_tab[75] = "vmsplice";
    syscall_tab[260] = "wait4";
    syscall_tab[95] = "wait";
    syscall_tab[64] = "write";
    syscall_tab[66] = "writev";
    syscall_tab[79] = "newfstatat";
    syscall_tab[261] = "prlimit64";
    syscall_tab[293] = "rseq";
    return ;
}

void print_user_regs_struct(t_regs_64 regs) {
    printf("r15: %lu\n", regs.r15);
    printf("r14: %lu\n", regs.r14);
    printf("r13: %lu\n", regs.r13);
    printf("r12: %lu\n", regs.r12);
    printf("rbp: %lu\n", regs.rbp);
    printf("rbx: %lu\n", regs.rbx);
    printf("r11: %lu\n", regs.r11);
    printf("r10: %lu\n", regs.r10);
    printf("r9: %lu\n", regs.r9);
    printf("r8: %lu\n", regs.r8);
    printf("rax: %lu\n", regs.rax);
    printf("rcx: %lu\n", regs.rcx);
    printf("rdx: %lu\n", regs.rdx);
    printf("rsi: %lu\n", regs.rsi);
    printf("rdi: %lu\n", regs.rdi);
    printf("orig_rax: %ld\n", regs.orig_rax);
    printf("rip: %lu\n", regs.rip);
    printf("cs: %lu\n", regs.cs);
    printf("eflags: %lu\n", regs.eflags);
    printf("rsp: %lu\n", regs.rsp);
    printf("ss: %lu\n", regs.ss);
    printf("fs_base: %lu\n", regs.fs_base);
    printf("gs_base: %lu\n", regs.gs_base);
    printf("ds: %lu\n", regs.ds);
    printf("es: %lu\n", regs.es);
    printf("fs: %lu\n", regs.fs);
    printf("gs: %lu\n", regs.gs);
}

void binary(char *filename) {
    struct stat st;

    if (stat(filename, &st) == 0) {
        if ((st.st_mode & S_IFMT) == S_IFREG && (st.st_mode & S_IXUSR)) {
            printf("%s est un fichier binaire exécutable.\n", filename);
        } else {
            printf("%s n'est pas un fichier binaire exécutable.\n", filename);
            exit(1);
        }
    } else {
        printf("Impossible d'obtenir les informations du fichier %s.\n", filename);
        exit(1);
    }

    return ;
}

int main(int argc, char **argv, char **env)
{
    pid_t pid;
    struct iovec iov;
    t_regs_64 regs;
    int status;

    fill_syscall_tab();
    pid = fork();
    int i = 0;
    if (pid == 0) {
        /* Child process */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve(argv[1], argv, env);
        
    } else {
        /* Parent process */
        while (1) {
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                break;
            }
            iov.iov_base = &regs;
            iov.iov_len = sizeof(regs);
            ptrace(PTRACE_GETREGSET, pid, 1, &iov);
            if (i % 2 == 0){
                //if (regs.r9 == SYS_mmap || regs.r9 == SYS_mmap)
                    //print_user_regs_struct(regs);
                char *str = ft_itoa(regs.r15);
                if (regs.r15 > __INT_MAX__)
                    printf("%s(%s) = 0x%s\n", syscall_tab[regs.r9], ft_itoa(regs.rcx),str);
                else
                    printf("%s(%s) = %ld\n", syscall_tab[regs.r9], ft_itoa(regs.rcx), regs.r15);
                free(str);
            }
            i++;
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
    }
    //printf("syscall = %d\n", SYS_rseq);
    return 0;
}



