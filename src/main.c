#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* syscall_names[4096] = {0};

void init_names() {
    syscall_names[SYS_read] = "read";
    syscall_names[SYS_write] = "write";
    syscall_names[SYS_open] = "open";
    syscall_names[SYS_close] = "close";
    syscall_names[SYS_stat] = "stat";
    syscall_names[SYS_fstat] = "fstat";
    syscall_names[SYS_lstat] = "lstat";
    syscall_names[SYS_poll] = "poll";
    syscall_names[SYS_lseek] = "lseek";
    syscall_names[SYS_mmap] = "mmap";
    syscall_names[SYS_mprotect] = "mprotect";
    syscall_names[SYS_munmap] = "munmap";
    syscall_names[SYS_brk] = "brk";
    syscall_names[SYS_rt_sigaction] = "rt_sigaction";
    syscall_names[SYS_rt_sigprocmask] = "rt_sigprocmask";
    syscall_names[SYS_rt_sigreturn] = "rt_sigreturn";
    syscall_names[SYS_ioctl] = "ioctl";
    syscall_names[SYS_pread64] = "pread64";
    syscall_names[SYS_pwrite64] = "pwrite64";
    syscall_names[SYS_readv] = "readv";
    syscall_names[SYS_writev] = "writev";
    syscall_names[SYS_access] = "access";
    syscall_names[SYS_pipe] = "pipe";
    syscall_names[SYS_select] = "select";
    syscall_names[SYS_sched_yield] = "sched_yield";
    syscall_names[SYS_mremap] = "mremap";
    syscall_names[SYS_msync] = "msync";
    syscall_names[SYS_mincore] = "mincore";
    syscall_names[SYS_madvise] = "madvise";
    syscall_names[SYS_shmget] = "shmget";
    syscall_names[SYS_shmat] = "shmat";
    syscall_names[SYS_shmctl] = "shmctl";
    syscall_names[SYS_dup] = "dup";
    syscall_names[SYS_dup2] = "dup2";
    syscall_names[SYS_pause] = "pause";
    syscall_names[SYS_nanosleep] = "nanosleep";
    syscall_names[SYS_getitimer] = "getitimer";
    syscall_names[SYS_alarm] = "alarm";
    syscall_names[SYS_setitimer] = "setitimer";
    syscall_names[SYS_getpid] = "getpid";
    syscall_names[SYS_sendfile] = "sendfile";
    syscall_names[SYS_socket] = "socket";
    syscall_names[SYS_connect] = "connect";
    syscall_names[SYS_accept] = "accept";
    syscall_names[SYS_sendto] = "sendto";
    syscall_names[SYS_recvfrom] = "recvfrom";
    syscall_names[SYS_sendmsg] = "sendmsg";
    syscall_names[SYS_recvmsg] = "recvmsg";
    syscall_names[SYS_shutdown] = "shutdown";
    syscall_names[SYS_bind] = "bind";
    syscall_names[SYS_listen] = "listen";
    syscall_names[SYS_getsockname] = "getsockname";
    syscall_names[SYS_getpeername] = "getpeername";
    syscall_names[SYS_socketpair] = "socketpair";
    syscall_names[SYS_setsockopt] = "setsockopt";
    syscall_names[SYS_getsockopt] = "getsockopt";
    syscall_names[SYS_clone] = "clone";
    syscall_names[SYS_fork] = "fork";
    syscall_names[SYS_vfork] = "vfork";
    syscall_names[SYS_execve] = "execve";
    syscall_names[SYS_exit] = "exit";
    syscall_names[SYS_wait4] = "wait4";
    syscall_names[SYS_kill] = "kill";
    syscall_names[SYS_uname] = "uname";
    syscall_names[SYS_semget] = "semget";
    syscall_names[SYS_semop] = "semop";
    syscall_names[SYS_semctl] = "semctl";
    syscall_names[SYS_shmdt] = "shmdt";
    syscall_names[SYS_msgget] = "msgget";
    syscall_names[SYS_msgsnd] = "msgsnd";
    syscall_names[SYS_msgrcv] = "msgrcv";
    syscall_names[SYS_msgctl] = "msgctl";
    syscall_names[SYS_fcntl] = "fcntl";
    syscall_names[SYS_flock] = "flock";
    syscall_names[SYS_fsync] = "fsync";
    syscall_names[SYS_fdatasync] = "fdatasync";
    syscall_names[SYS_truncate] = "truncate";
    syscall_names[SYS_ftruncate] = "ftruncate";
    syscall_names[SYS_getdents] = "getdents";
    syscall_names[SYS_getcwd] = "getcwd";
    syscall_names[SYS_chdir] = "chdir";
    syscall_names[SYS_fchdir] = "fchdir";
    syscall_names[SYS_rename] = "rename";
    syscall_names[SYS_mkdir] = "mkdir";
    syscall_names[SYS_rmdir] = "rmdir";
    syscall_names[SYS_creat] = "creat";
    syscall_names[SYS_link] = "link";
    syscall_names[SYS_unlink] = "unlink";
    syscall_names[SYS_symlink] = "symlink";
    syscall_names[SYS_readlink] = "readlink";
    syscall_names[SYS_chmod] = "chmod";
    syscall_names[SYS_fchmod] = "fchmod";
    syscall_names[SYS_chown] = "chown";
    syscall_names[SYS_fchown] = "fchown";
    syscall_names[SYS_lchown] = "lchown";
    syscall_names[SYS_umask] = "umask";
    syscall_names[SYS_gettimeofday] = "gettimeofday";
    syscall_names[SYS_getrlimit] = "getrlimit";
    syscall_names[SYS_getrusage] = "getrusage";
    syscall_names[SYS_sysinfo] = "sysinfo";
    syscall_names[SYS_times] = "times";
    syscall_names[SYS_ptrace] = "ptrace";
    syscall_names[SYS_getuid] = "getuid";
    syscall_names[SYS_syslog] = "syslog";
    syscall_names[SYS_getgid] = "getgid";
    syscall_names[SYS_setuid] = "setuid";
    syscall_names[SYS_setgid] = "setgid";
    syscall_names[SYS_geteuid] = "geteuid";
    syscall_names[SYS_getegid] = "getegid";
    syscall_names[SYS_setpgid] = "setpgid";
    syscall_names[SYS_getppid] = "getppid";
    syscall_names[SYS_getpgrp] = "getpgrp";
    syscall_names[SYS_setsid] = "setsid";
    syscall_names[SYS_setreuid] = "setreuid";
    syscall_names[SYS_setregid] = "setregid";
    syscall_names[SYS_getgroups] = "getgroups";
    syscall_names[SYS_setgroups] = "setgroups";
    syscall_names[SYS_setresuid] = "setresuid";
    syscall_names[SYS_getresuid] = "getresuid";
    syscall_names[SYS_setresgid] = "setresgid";
    syscall_names[SYS_getresgid] = "getresgid";
    syscall_names[SYS_getpgid] = "getpgid";
    syscall_names[SYS_setfsuid] = "setfsuid";
    syscall_names[SYS_setfsgid] = "setfsgid";
    syscall_names[SYS_getsid] = "getsid";
    syscall_names[SYS_capget] = "capget";
    syscall_names[SYS_capset] = "capset";
    syscall_names[SYS_rt_sigpending] = "rt_sigpending";
    syscall_names[SYS_rt_sigtimedwait] = "rt_sigtimedwait";
    syscall_names[SYS_rt_sigqueueinfo] = "rt_sigqueueinfo";
    syscall_names[SYS_rt_sigsuspend] = "rt_sigsuspend";
    syscall_names[SYS_sigaltstack] = "sigaltstack";
    syscall_names[SYS_utime] = "utime";
    syscall_names[SYS_mknod] = "mknod";
    syscall_names[SYS_uselib] = "uselib";
    syscall_names[SYS_personality] = "personality";
    syscall_names[SYS_ustat] = "ustat";
    syscall_names[SYS_statfs] = "statfs";
    syscall_names[SYS_fstatfs] = "fstatfs";
    syscall_names[SYS_sysfs] = "sysfs";
    syscall_names[SYS_getpriority] = "getpriority";
    syscall_names[SYS_setpriority] = "setpriority";
    syscall_names[SYS_sched_setparam] = "sched_setparam";
    syscall_names[SYS_sched_getparam] = "sched_getparam";
    syscall_names[SYS_sched_setscheduler] = "sched_setscheduler";
    syscall_names[SYS_sched_getscheduler] = "sched_getscheduler";
    syscall_names[SYS_sched_get_priority_max] = "sched_get_priority_max";
    syscall_names[SYS_sched_get_priority_min] = "sched_get_priority_min";
    syscall_names[SYS_sched_rr_get_interval] = "sched_rr_get_interval";
    syscall_names[SYS_mlock] = "mlock";
    syscall_names[SYS_munlock] = "munlock";
    syscall_names[SYS_mlockall] = "mlockall";
    syscall_names[SYS_munlockall] = "munlockall";
    syscall_names[SYS_vhangup] = "vhangup";
    syscall_names[SYS_modify_ldt] = "modify_ldt";
    syscall_names[SYS_pivot_root] = "pivot_root";
    syscall_names[SYS__sysctl] = "_sysctl";
    syscall_names[SYS_prctl] = "prctl";
    syscall_names[SYS_arch_prctl] = "arch_prctl";
    syscall_names[SYS_adjtimex] = "adjtimex";
    syscall_names[SYS_setrlimit] = "setrlimit";
    syscall_names[SYS_chroot] = "chroot";
    syscall_names[SYS_sync] = "sync";
    syscall_names[SYS_acct] = "acct";
    syscall_names[SYS_settimeofday] = "settimeofday";
    syscall_names[SYS_mount] = "mount";
    syscall_names[SYS_umount2] = "umount2";
    syscall_names[SYS_swapon] = "swapon";
    syscall_names[SYS_swapoff] = "swapoff";
    syscall_names[SYS_reboot] = "reboot";
    syscall_names[SYS_sethostname] = "sethostname";
    syscall_names[SYS_setdomainname] = "setdomainname";
    syscall_names[SYS_iopl] = "iopl";
    syscall_names[SYS_ioperm] = "ioperm";
    syscall_names[SYS_create_module] = "create_module";
    syscall_names[SYS_init_module] = "init_module";
    syscall_names[SYS_delete_module] = "delete_module";
    syscall_names[SYS_get_kernel_syms] = "get_kernel_syms";
    syscall_names[SYS_query_module] = "query_module";
    syscall_names[SYS_quotactl] = "quotactl";
    syscall_names[SYS_nfsservctl] = "nfsservctl";
    syscall_names[SYS_getpmsg] = "getpmsg";
    syscall_names[SYS_putpmsg] = "putpmsg";
    syscall_names[SYS_afs_syscall] = "afs_syscall";
    syscall_names[SYS_tuxcall] = "tuxcall";
    syscall_names[SYS_security] = "security";
    syscall_names[SYS_gettid] = "gettid";
    syscall_names[SYS_readahead] = "readahead";
    syscall_names[SYS_setxattr] = "setxattr";
    syscall_names[SYS_lsetxattr] = "lsetxattr";
    syscall_names[SYS_fsetxattr] = "fsetxattr";
    syscall_names[SYS_getxattr] = "getxattr";
    syscall_names[SYS_lgetxattr] = "lgetxattr";
    syscall_names[SYS_fgetxattr] = "fgetxattr";
    syscall_names[SYS_listxattr] = "listxattr";
    syscall_names[SYS_llistxattr] = "llistxattr";
    syscall_names[SYS_flistxattr] = "flistxattr";
    syscall_names[SYS_removexattr] = "removexattr";
    syscall_names[SYS_lremovexattr] = "lremovexattr";
    syscall_names[SYS_fremovexattr] = "fremovexattr";
    syscall_names[SYS_tkill] = "tkill";
    syscall_names[SYS_time] = "time";
    syscall_names[SYS_futex] = "futex";
    syscall_names[SYS_sched_setaffinity] = "sched_setaffinity";
    syscall_names[SYS_sched_getaffinity] = "sched_getaffinity";
    syscall_names[SYS_set_thread_area] = "set_thread_area";
    syscall_names[SYS_io_setup] = "io_setup";
    syscall_names[SYS_io_destroy] = "io_destroy";
    syscall_names[SYS_io_getevents] = "io_getevents";
    syscall_names[SYS_io_submit] = "io_submit";
    syscall_names[SYS_io_cancel] = "io_cancel";
    syscall_names[SYS_get_thread_area] = "get_thread_area";
    syscall_names[SYS_lookup_dcookie] = "lookup_dcookie";
    syscall_names[SYS_epoll_create] = "epoll_create";
    syscall_names[SYS_epoll_ctl_old] = "epoll_ctl_old";
    syscall_names[SYS_epoll_wait_old] = "epoll_wait_old";
    syscall_names[SYS_remap_file_pages] = "remap_file_pages";
    syscall_names[SYS_getdents64] = "getdents64";
    syscall_names[SYS_set_tid_address] = "set_tid_address";
    syscall_names[SYS_restart_syscall] = "restart_syscall";
    syscall_names[SYS_semtimedop] = "semtimedop";
    syscall_names[SYS_fadvise64] = "fadvise64";
    syscall_names[SYS_timer_create] = "timer_create";
    syscall_names[SYS_timer_settime] = "timer_settime";
    syscall_names[SYS_timer_gettime] = "timer_gettime";
    syscall_names[SYS_timer_getoverrun] = "timer_getoverrun";
    syscall_names[SYS_timer_delete] = "timer_delete";
    syscall_names[SYS_clock_settime] = "clock_settime";
    syscall_names[SYS_clock_gettime] = "clock_gettime";
    syscall_names[SYS_clock_getres] = "clock_getres";
    syscall_names[SYS_clock_nanosleep] = "clock_nanosleep";
    syscall_names[SYS_exit_group] = "exit_group";
    syscall_names[SYS_epoll_wait] = "epoll_wait";
    syscall_names[SYS_epoll_ctl] = "epoll_ctl";
    syscall_names[SYS_tgkill] = "tgkill";
    syscall_names[SYS_utimes] = "utimes";
    syscall_names[SYS_vserver] = "vserver";
    syscall_names[SYS_mbind] = "mbind";
    syscall_names[SYS_set_mempolicy] = "set_mempolicy";
    syscall_names[SYS_get_mempolicy] = "get_mempolicy";
    syscall_names[SYS_mq_open] = "mq_open";
    syscall_names[SYS_mq_unlink] = "mq_unlink";
    syscall_names[SYS_mq_timedsend] = "mq_timedsend";
    syscall_names[SYS_mq_timedreceive] = "mq_timedreceive";
    syscall_names[SYS_mq_notify] = "mq_notify";
    syscall_names[SYS_mq_getsetattr] = "mq_getsetattr";
    syscall_names[SYS_kexec_load] = "kexec_load";
    syscall_names[SYS_waitid] = "waitid";
    syscall_names[SYS_add_key] = "add_key";
    syscall_names[SYS_request_key] = "request_key";
    syscall_names[SYS_keyctl] = "keyctl";
    syscall_names[SYS_ioprio_set] = "ioprio_set";
    syscall_names[SYS_ioprio_get] = "ioprio_get";
    syscall_names[SYS_inotify_init] = "inotify_init";
    syscall_names[SYS_inotify_add_watch] = "inotify_add_watch";
    syscall_names[SYS_inotify_rm_watch] = "inotify_rm_watch";
    syscall_names[SYS_migrate_pages] = "migrate_pages";
    syscall_names[SYS_openat] = "openat";
    syscall_names[SYS_mkdirat] = "mkdirat";
    syscall_names[SYS_mknodat] = "mknodat";
    syscall_names[SYS_fchownat] = "fchownat";
    syscall_names[SYS_futimesat] = "futimesat";
    syscall_names[SYS_newfstatat] = "newfstatat";
    syscall_names[SYS_unlinkat] = "unlinkat";
    syscall_names[SYS_renameat] = "renameat";
    syscall_names[SYS_linkat] = "linkat";
    syscall_names[SYS_symlinkat] = "symlinkat";
    syscall_names[SYS_readlinkat] = "readlinkat";
    syscall_names[SYS_fchmodat] = "fchmodat";
    syscall_names[SYS_faccessat] = "faccessat";
    syscall_names[SYS_pselect6] = "pselect6";
    syscall_names[SYS_ppoll] = "ppoll";
    syscall_names[SYS_unshare] = "unshare";
    syscall_names[SYS_set_robust_list] = "set_robust_list";
    syscall_names[SYS_get_robust_list] = "get_robust_list";
    syscall_names[SYS_splice] = "splice";
    syscall_names[SYS_tee] = "tee";
    syscall_names[SYS_sync_file_range] = "sync_file_range";
    syscall_names[SYS_vmsplice] = "vmsplice";
    syscall_names[SYS_move_pages] = "move_pages";
    syscall_names[SYS_utimensat] = "utimensat";
    syscall_names[SYS_epoll_pwait] = "epoll_pwait";
    syscall_names[SYS_signalfd] = "signalfd";
    syscall_names[SYS_timerfd_create] = "timerfd_create";
    syscall_names[SYS_eventfd] = "eventfd";
    syscall_names[SYS_fallocate] = "fallocate";
    syscall_names[SYS_timerfd_settime] = "timerfd_settime";
    syscall_names[SYS_timerfd_gettime] = "timerfd_gettime";
    syscall_names[SYS_accept4] = "accept4";
    syscall_names[SYS_signalfd4] = "signalfd4";
    syscall_names[SYS_eventfd2] = "eventfd2";
    syscall_names[SYS_epoll_create1] = "epoll_create1";
    syscall_names[SYS_dup3] = "dup3";
    syscall_names[SYS_pipe2] = "pipe2";
    syscall_names[SYS_inotify_init1] = "inotify_init1";
    syscall_names[SYS_preadv] = "preadv";
    syscall_names[SYS_pwritev] = "pwritev";
    syscall_names[SYS_rt_tgsigqueueinfo] = "rt_tgsigqueueinfo";
    syscall_names[SYS_perf_event_open] = "perf_event_open";
    syscall_names[SYS_recvmmsg] = "recvmmsg";
    syscall_names[SYS_fanotify_init] = "fanotify_init";
    syscall_names[SYS_fanotify_mark] = "fanotify_mark";
    syscall_names[SYS_prlimit64] = "prlimit64";
    syscall_names[SYS_name_to_handle_at] = "name_to_handle_at";
    syscall_names[SYS_open_by_handle_at] = "open_by_handle_at";
    syscall_names[SYS_clock_adjtime] = "clock_adjtime";
    syscall_names[SYS_syncfs] = "syncfs";
    syscall_names[SYS_sendmmsg] = "sendmmsg";
    syscall_names[SYS_setns] = "setns";
    syscall_names[SYS_getcpu] = "getcpu";
    syscall_names[SYS_process_vm_readv] = "process_vm_readv";
    syscall_names[SYS_process_vm_writev] = "process_vm_writev";
    syscall_names[SYS_kcmp] = "kcmp";
    syscall_names[SYS_finit_module] = "finit_module";
    syscall_names[SYS_sched_setattr] = "sched_setattr";
    syscall_names[SYS_sched_getattr] = "sched_getattr";
    syscall_names[SYS_renameat2] = "renameat2";
    syscall_names[SYS_seccomp] = "seccomp";
    syscall_names[SYS_getrandom] = "getrandom";
    syscall_names[SYS_memfd_create] = "memfd_create";
    syscall_names[SYS_kexec_file_load] = "kexec_file_load";
    syscall_names[SYS_bpf] = "bpf";
    syscall_names[SYS_execveat] = "execveat";
    syscall_names[SYS_userfaultfd] = "userfaultfd";
    syscall_names[SYS_membarrier] = "membarrier";
    syscall_names[SYS_mlock2] = "mlock2";
    syscall_names[SYS_copy_file_range] = "copy_file_range";
    syscall_names[SYS_preadv2] = "preadv2";
    syscall_names[SYS_pwritev2] = "pwritev2";
    syscall_names[SYS_pkey_mprotect] = "pkey_mprotect";
    syscall_names[SYS_pkey_alloc] = "pkey_alloc";
    syscall_names[SYS_pkey_free] = "pkey_free";
    syscall_names[SYS_statx] = "statx";
}

int child_main(int argc, char* argv[]) {
    if (-1 == ptrace(PTRACE_TRACEME,0,0,0)) {
        perror("ptrace");
        return 1;
    }
    char** child_argv = argv+1;
    if (-1 == execvp(child_argv[0], child_argv)) {
        perror("execvp");
        return 1;
    }
    return 0;
}

char* read_string(pid_t pid, unsigned long address) {
    unsigned long size = 4096, offset = 0;
    char* data = malloc(size);
    if (data == 0) { perror("malloc"); return 0; }
    union { long ret; char bytes[sizeof(long)]; } result;
    do {
        result.ret = ptrace(PTRACE_PEEKDATA, pid, address+offset, 0);
        if (result.ret == -1) { data[offset] = 0; break; }
        if (offset + sizeof(result) > size) {
            size *= 2;
            data = realloc(data, size);
            if (data == 0) { perror("realloc"); return 0; }
        }
        memcpy(data+offset, result.bytes, sizeof(result));
        offset += sizeof(result);
    } while (memchr(result.bytes, 0, sizeof(result)) == 0);
    return data;
}

void store_path(FILE* out, const char* path) {
    if (path == 0) { return; }
    struct stat st;
    if (stat(path, &st) == -1 || (st.st_mode & S_IFMT) == S_IFDIR) {
        return;
    }
    fputs(path, out);
    fputc('\n', out);
    char* rpath = realpath(path, 0);
    if (rpath != 0 && strcmp(path, rpath) != 0) {
        fputs(rpath, out);
        fputc('\n', out);
    }
    free(rpath);
}

void on_syscall(FILE* out, pid_t pid, struct user_regs_struct* regs) {
    #ifdef __x86_64__
    long n = regs->orig_rax;
    #else
    long n = regs->orig_eax;
    #endif
    char* f = 0;
    char* f2 = 0;
    switch (n) {
        #ifdef SYS_open
        case SYS_open: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_openat
        case SYS_openat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_creat
        case SYS_creat: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_mkdir
        case SYS_mkdir: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_mkdirat
        case SYS_mkdirat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_access
        case SYS_access: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_faccessat
        case SYS_faccessat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_stat
        case SYS_stat: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_statx
        case SYS_statx: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_lstat
        case SYS_lstat: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_fstatat
        case SYS_fstatat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_new_fstatat
        case SYS_new_fstatat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_execve
        case SYS_execve: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_execveat
        case SYS_execveat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_truncate
        case SYS_truncate: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_chdir
        case SYS_chdir: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_rename
        case SYS_rename:
            f=read_string(pid, regs->rdi);
            f2=read_string(pid, regs->rsi);
            break;
        #endif
        #ifdef SYS_renameat
        case SYS_renameat:
            f=read_string(pid, regs->rsi);
            f2=read_string(pid, regs->r10);
            break;
        #endif
        #ifdef SYS_rmdir
        case SYS_rmdir: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_link
        case SYS_link:
            f=read_string(pid, regs->rdi);
            f2=read_string(pid, regs->rsi);
            break;
        #endif
        #ifdef SYS_linkat
        case SYS_linkat:
            f=read_string(pid, regs->rsi);
            f2=read_string(pid, regs->r10);
            break;
        #endif
        #ifdef SYS_unlink
        case SYS_unlink: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_unlinkat
        case SYS_unlinkat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_symlink
        case SYS_symlink:
            f=read_string(pid, regs->rdi);
            f2=read_string(pid, regs->rsi);
            break;
        #endif
        #ifdef SYS_symlinkat
        case SYS_symlinkat:
            f=read_string(pid, regs->rdi);
            f2=read_string(pid, regs->rdx);
            break;
        #endif
        #ifdef SYS_readlink
        case SYS_readlink: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_readlinkat
        case SYS_readlinkat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_chmod
        case SYS_chmod: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_fchmodat
        case SYS_fchmodat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_chown
        case SYS_chown: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_lchown
        case SYS_lchown: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_fchownat
        case SYS_fchownat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_mknod
        case SYS_mknod: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_mknodat
        case SYS_mknodat: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_statfs
        case SYS_statfs: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_chroot
        case SYS_chroot: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_acct
        case SYS_acct: f=read_string(pid, regs->rdi); break;
        #endif
            // TODO mount???
        #ifdef SYS_setxattr
        case SYS_setxattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_lsetxattr
        case SYS_lsetxattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_getxattr
        case SYS_getxattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_lgetxattr
        case SYS_lgetxattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_listxattr
        case SYS_listxattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_llistxattr
        case SYS_llistxattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_removexattr
        case SYS_removexattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_lremovexattr
        case SYS_lremovexattr: f=read_string(pid, regs->rdi); break;
        #endif
        #ifdef SYS_inotify_add_watch
        case SYS_inotify_add_watch: f=read_string(pid, regs->rsi); break;
        #endif
        #ifdef SYS_name_to_handle_at
        case SYS_name_to_handle_at: f=read_string(pid, regs->rsi); break;
        #endif
    }
    //if (n == SYS_fork || n == SYS_clone || n == SYS_vfork || n == SYS_execve) {
    //    fprintf(stderr, "%s %s %s\n", syscall_names[n], f, f2);
    //}
    store_path(out, f);
    store_path(out, f2);
    free(f);
    free(f2);
}

int on_child_start(pid_t child_pid) {
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
        PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC;
    if (-1 == ptrace(PTRACE_SETOPTIONS,child_pid,0,options)) {
        perror("ptrace");
        return -1;
    }
    if (-1 == ptrace(PTRACE_SYSCALL, child_pid, 0, 0)) {
        perror("ptrace");
        return -1;
    }
    return 0;
}

int parent_main(int argc, char* argv[], pid_t child_pid) {
    int status = 0;
    if (-1 == waitpid(child_pid, &status, 0)) {
        perror("waitpid");
        return 1;
    }
    if (-1 == on_child_start(child_pid)) {
        return 1;
    }
    FILE* out = fopen("whitelist", "w");
    int ret = 1;
    while (1) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (-1 == pid) {
            if (errno == ECHILD) { break; }
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status)) { ret = WEXITSTATUS(status); break; }
        if (WIFSIGNALED(status)) { ret = WTERMSIG(status); break; }
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == (SIGTRAP|0x80)) {
                struct user_regs_struct regs;
                if (-1 == ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                on_syscall(out, pid, &regs);
                if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
                    perror("ptrace");
                    ret = 1;
                    break;
                }
            } else if (WSTOPSIG(status) == SIGTRAP) {
                fprintf(stderr, "status %d %d\n", (((status >> 8) & 0xffff)), (SIGTRAP | (PTRACE_EVENT_EXEC<<8)));
                pid_t new_pid = 0;
                if (-1 == ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid)) {
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                fprintf(stderr, "new pid %d\n", new_pid);
                if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                if (-1 == ptrace(PTRACE_SYSCALL, new_pid, 0, 0) && errno != ESRCH) {
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                //fprintf(stderr, "status %d %d %d %d %d %d\n", status, SIGTRAP, WSTOPSIG(status), SIGTRAP|0x80, (status>>16)&0xffff, (PTRACE_EVENT_CLONE));
            } else {
                fprintf(stderr, "status2 %d %d\n", (((status >> 8) & 0xffff)), (SIGTRAP | (PTRACE_EVENT_EXEC<<8)));
            }
        }
    }
    fclose(out);
    return ret;
}

int main(int argc, char* argv[]) {
    init_names();
    pid_t pid = fork();
    switch (pid) {
        case -1: perror("fork"); return 1;
        case  0: return child_main(argc, argv);
        default: return parent_main(argc, argv, pid);
    }
    return 0;
}
