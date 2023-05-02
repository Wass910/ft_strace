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
    syscall_tab[62] = "SYS_lseek";
    syscall_tab[202] = "SYS_accept";
    syscall_tab[242] = "SYS_accept4";
    syscall_tab[89] = "SYS_acct";
    syscall_tab[217] = "SYS_add_key";
    syscall_tab[171] = "SYS_adjtimex";
    syscall_tab[200] = "SYS_bind";
    syscall_tab[214] = "SYS_brk";
    syscall_tab[90] = "SYS_capget";
    syscall_tab[91] = "SYS_capset";
    syscall_tab[49] = "SYS_chdir";
    syscall_tab[51] = "SYS_chroot";
    syscall_tab[114] = "SYS_clock_getres";
    syscall_tab[113] = "SYS_clock_gettime";
    syscall_tab[115] = "SYS_clock_nanosleep";
    syscall_tab[112] = "SYS_clock_settime";
    syscall_tab[220] = "SYS_clone";
    syscall_tab[57] = "SYS_close";
    syscall_tab[203] = "SYS_connect";
    syscall_tab[106] = "SYS_delete_module";
    syscall_tab[23] = "SYS_dup";
    syscall_tab[21] = "SYS_epoll_ctl";
    syscall_tab[22] = "SYS_epoll_pwait";
    syscall_tab[221] = "SYS_execve";
    syscall_tab[93] = "SYS_exit";
    syscall_tab[94] = "SYS_exit_group";
    syscall_tab[48] = "SYS_faccessat";
    syscall_tab[223] = "SYS_fadvise64";
    syscall_tab[47] = "SYS_fallocate";
    syscall_tab[50] = "SYS_fchdir";
    syscall_tab[52] = "SYS_fchmod";
    syscall_tab[53] = "SYS_fchmodat";
    syscall_tab[55] = "SYS_fchown";
    syscall_tab[54] = "SYS_fchownat";
    syscall_tab[25] = "SYS_fcntl";
    syscall_tab[83] = "SYS_fdatasync";
    syscall_tab[10] = "SYS_fgetxattr";
    syscall_tab[13] = "SYS_flistxattr";
    syscall_tab[32] = "SYS_flock";
    syscall_tab[16] = "SYS_fremovexattr";
    syscall_tab[7] = "SYS_fsetxattr";
    syscall_tab[80] = "SYS_fstat";
    syscall_tab[44] = "SYS_fstatfs";
    syscall_tab[82] = "SYS_fsync";
    syscall_tab[46] = "SYS_ftruncate";
    syscall_tab[98] = "SYS_futex";
    syscall_tab[236] = "SYS_get_mempolicy";
    syscall_tab[100] = "SYS_get_robust_list";
    syscall_tab[168] = "SYS_getcpu";
    syscall_tab[17] = "SYS_getcwd";
    syscall_tab[61] = "SYS_getdents64";
    syscall_tab[177] = "SYS_geteg";
    syscall_tab[175] = "SYS_geteu";
    syscall_tab[176] = "SYS_getg";
    syscall_tab[158] = "SYS_getgroups";
    syscall_tab[102] = "SYS_getitimer";
    syscall_tab[205] = "SYS_getpeername";
    syscall_tab[155] = "SYS_getpg";
    syscall_tab[172] = "SYS_getp";
    syscall_tab[173] = "SYS_getpp";
    syscall_tab[141] = "SYS_getpriority";
    syscall_tab[150] = "SYS_getresg";
    syscall_tab[148] = "SYS_getresu";
    syscall_tab[163] = "SYS_getrlimit";
    syscall_tab[165] = "SYS_getrusage";
    syscall_tab[156] = "SYS_gets";
    syscall_tab[204] = "SYS_getsockname";
    syscall_tab[209] = "SYS_getsockopt";
    syscall_tab[178] = "SYS_gett";
    syscall_tab[169] = "SYS_gettimeofday";
    syscall_tab[174] = "SYS_getu";
    syscall_tab[8] = "SYS_getxattr";
    syscall_tab[105] = "SYS_init_module";
    syscall_tab[27] = "SYS_inotify_add_watch";
    syscall_tab[28] = "SYS_inotify_rm_watch";
    syscall_tab[3] = "SYS_io_cancel";
    syscall_tab[1] = "SYS_io_destroy";
    syscall_tab[4] = "SYS_io_getevents";
    syscall_tab[0] = "SYS_io_setup";
    syscall_tab[2] = "SYS_io_submit";
    syscall_tab[29] = "SYS_ioctl";
    syscall_tab[31] = "SYS_ioprio_get";
    syscall_tab[30] = "SYS_ioprio_set";
    syscall_tab[104] = "SYS_kexec_load";
    syscall_tab[219] = "SYS_keyctl";
    syscall_tab[129] = "SYS_kill";
    syscall_tab[9] = "SYS_lgetxattr";
    syscall_tab[37] = "SYS_linkat";
    syscall_tab[201] = "SYS_listen";
    syscall_tab[11] = "SYS_listxattr";
    syscall_tab[12] = "SYS_llistxattr";
    syscall_tab[18] = "SYS_lookup_dcookie";
    syscall_tab[15] = "SYS_lremovexattr";
    syscall_tab[6] = "SYS_lsetxattr";
    syscall_tab[233] = "SYS_madvise";
    syscall_tab[235] = "SYS_mbind";
    syscall_tab[238] = "SYS_migrate_pages";
    syscall_tab[232] = "SYS_mincore";
    syscall_tab[34] = "SYS_mkdirat";
    syscall_tab[33] = "SYS_mknodat";
    syscall_tab[228] = "SYS_mlock";
    syscall_tab[230] = "SYS_mlockall";
    syscall_tab[222] = "SYS_mmap";
    syscall_tab[40] = "SYS_mount";
    syscall_tab[239] = "SYS_move_pages";
    syscall_tab[226] = "SYS_mprotect";
    syscall_tab[185] = "SYS_mq_getsetattr";
    syscall_tab[184] = "SYS_mq_notify";
    syscall_tab[180] = "SYS_mq_open";
    syscall_tab[183] = "SYS_mq_timedreceive";
    syscall_tab[182] = "SYS_mq_timedsend";
    syscall_tab[181] = "SYS_mq_unlink";
    syscall_tab[216] = "SYS_mremap";
    syscall_tab[187] = "SYS_msgctl";
    syscall_tab[186] = "SYS_msgget";
    syscall_tab[188] = "SYS_msgrcv";
    syscall_tab[189] = "SYS_msgsnd";
    syscall_tab[227] = "SYS_msync";
    syscall_tab[229] = "SYS_munlock";
    syscall_tab[231] = "SYS_munlockall";
    syscall_tab[215] = "SYS_munmap";
    syscall_tab[101] = "SYS_nanosleep";
    syscall_tab[42] = "SYS_nfsservctl";
    syscall_tab[56] = "SYS_openat";
    syscall_tab[92] = "SYS_personality";
    syscall_tab[41] = "SYS_pivot_root";
    syscall_tab[73] = "SYS_ppoll";
    syscall_tab[167] = "SYS_prctl";
    syscall_tab[67] = "SYS_pread64";
    syscall_tab[72] = "SYS_pselect6";
    syscall_tab[117] = "SYS_ptrace";
    syscall_tab[68] = "SYS_pwrite64";
    syscall_tab[60] = "SYS_quotactl";
    syscall_tab[63] = "SYS_read";
    syscall_tab[78] = "SYS_readlinkat";
    syscall_tab[65] = "SYS_readv";
    syscall_tab[142] = "SYS_reboot";
    syscall_tab[207] = "SYS_recvfrom";
    syscall_tab[212] = "SYS_recvmsg";
    syscall_tab[234] = "SYS_remap_file_pages";
    syscall_tab[14] = "SYS_removexattr";
    syscall_tab[38] = "SYS_renameat";
    syscall_tab[218] = "SYS_request_key";
    syscall_tab[128] = "SYS_restart_syscall";
    syscall_tab[134] = "SYS_rt_sigaction";
    syscall_tab[136] = "SYS_rt_sigpending";
    syscall_tab[135] = "SYS_rt_sigprocmask";
    syscall_tab[138] = "SYS_rt_sigqueueinfo";
    syscall_tab[139] = "SYS_rt_sigreturn";
    syscall_tab[133] = "SYS_rt_sigsuspend";
    syscall_tab[137] = "SYS_rt_sigtimedwait";
    syscall_tab[125] = "SYS_sched_get_priority_max";
    syscall_tab[126] = "SYS_sched_get_priority_min";
    syscall_tab[123] = "SYS_sched_getaffinity";
    syscall_tab[121] = "SYS_sched_getparam";
    syscall_tab[120] = "SYS_sched_getscheduler";
    syscall_tab[127] = "SYS_sched_rr_get_interval";
    syscall_tab[122] = "SYS_sched_setaffinity";
    syscall_tab[118] = "SYS_sched_setparam";
    syscall_tab[119] = "SYS_sched_setscheduler";
    syscall_tab[124] = "SYS_sched_yield";
    syscall_tab[191] = "SYS_semctl";
    syscall_tab[190] = "SYS_semget";
    syscall_tab[193] = "SYS_semop";
    syscall_tab[192] = "SYS_semtimedop";
    syscall_tab[71] = "SYS_sendfile";
    syscall_tab[211] = "SYS_sendmsg";
    syscall_tab[206] = "SYS_sendto";
    syscall_tab[237] = "SYS_set_mempolicy";
    syscall_tab[99] = "SYS_set_robust_list";
    syscall_tab[96] = "SYS_set_tid_address";
    syscall_tab[162] = "SYS_setdomainname";
    syscall_tab[152] = "SYS_setfsg";
    syscall_tab[151] = "SYS_setfsu";
    syscall_tab[144] = "SYS_setg";
    syscall_tab[159] = "SYS_setgroups";
    syscall_tab[161] = "SYS_sethostname";
    syscall_tab[103] = "SYS_setitimer";
    syscall_tab[154] = "SYS_setpg";
    syscall_tab[140] = "SYS_setpriority";
    syscall_tab[143] = "SYS_setreg";
    syscall_tab[149] = "SYS_setresg";
    syscall_tab[147] = "SYS_setresu";
    syscall_tab[145] = "SYS_setreu";
    syscall_tab[164] = "SYS_setrlimit";
    syscall_tab[157] = "SYS_sets";
    syscall_tab[208] = "SYS_setsockopt";
    syscall_tab[170] = "SYS_settimeofday";
    syscall_tab[146] = "SYS_setu";
    syscall_tab[5] = "SYS_setxattr";
    syscall_tab[196] = "SYS_shmat";
    syscall_tab[195] = "SYS_shmctl";
    syscall_tab[197] = "SYS_shmdt";
    syscall_tab[194] = "SYS_shmget";
    syscall_tab[210] = "SYS_shutdown";
    syscall_tab[132] = "SYS_sigaltstack";
    syscall_tab[198] = "SYS_socket";
    syscall_tab[199] = "SYS_socketpair";
    syscall_tab[76] = "SYS_splice";
    syscall_tab[43] = "SYS_statfs";
    syscall_tab[225] = "SYS_swapoff";
    syscall_tab[224] = "SYS_swapon";
    syscall_tab[36] = "SYS_symlinkat";
    syscall_tab[81] = "SYS_sync";
    syscall_tab[84] = "SYS_sync_file_range";
    syscall_tab[179] = "SYS_sysinfo";
    syscall_tab[116] = "SYS_syslog";
    syscall_tab[77] = "SYS_tee";
    syscall_tab[131] = "SYS_tgkill";
    syscall_tab[107] = "SYS_timer_create";
    syscall_tab[111] = "SYS_timer_delete";
    syscall_tab[109] = "SYS_timer_getoverrun";
    syscall_tab[108] = "SYS_timer_gettime";
    syscall_tab[110] = "SYS_timer_settime";
    syscall_tab[85] = "SYS_timerfd_create";
    syscall_tab[87] = "SYS_timerfd_gettime";
    syscall_tab[86] = "SYS_timerfd_settime";
    syscall_tab[153] = "SYS_times";
    syscall_tab[130] = "SYS_tkill";
    syscall_tab[45] = "SYS_truncate";
    syscall_tab[166] = "SYS_umask";
    syscall_tab[39] = "SYS_umount2";
    syscall_tab[160] = "SYS_uname";
    syscall_tab[35] = "SYS_unlinkat";
    syscall_tab[97] = "SYS_unshare";
    syscall_tab[88] = "SYS_utimensat";
    syscall_tab[58] = "SYS_vhangup";
    syscall_tab[75] = "SYS_vmsplice";
    syscall_tab[260] = "SYS_wait4";
    syscall_tab[95] = "SYS_wait";
    syscall_tab[64] = "SYS_write";
    syscall_tab[66] = "SYS_writev";
    syscall_tab[79] = "SYS_newfstatat";
    syscall_tab[261] = "SYS_prlimit64";
    syscall_tab[293] = "SYS_rseq";
    return ;
}

void print_user_regs_struct(t_regs_64 regs) {
    // printf("r15: %lu\n", regs.r15);
    // printf("r14: %lu\n", regs.r14);
    // printf("r13: %lu\n", regs.r13);
    // printf("r12: %lu\n", regs.r12);
    // printf("rbp: %lu\n", regs.rbp);
    // printf("rbx: %lu\n", regs.rbx);
    // printf("r11: %lu\n", regs.r11);
    // printf("r10: %lu\n", regs.r10);
    // printf("r9: %lu\n", regs.r9);
    printf("r8: %lu\n", regs.r8);
    // printf("rax: %lu\n", regs.rax);
    // printf("rcx: %lu\n", regs.rcx);
    // printf("rdx: %lu\n", regs.rdx);
    // printf("rsi: %lu\n", regs.rsi);
    // printf("rdi: %lu\n", regs.rdi);
    printf("orig_rax: %ld\n", regs.orig_rax);
    // printf("rip: %lu\n", regs.rip);
    // printf("cs: %lu\n", regs.cs);
    // printf("eflags: %lu\n", regs.eflags);
    // printf("rsp: %lu\n", regs.rsp);
    // printf("ss: %lu\n", regs.ss);
    // printf("fs_base: %lu\n", regs.fs_base);
    // printf("gs_base: %lu\n", regs.gs_base);
    // printf("ds: %lu\n", regs.ds);
    // printf("es: %lu\n", regs.es);
    // printf("fs: %lu\n", regs.fs);
    // printf("gs: %lu\n", regs.gs);
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
            printf("%s()\n", syscall_tab[regs.r9]);
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
    }
    //printf("syscall = %d\n", SYS_rseq);
    return 0;
}

