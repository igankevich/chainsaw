/*
Copyright © 2019–2021 Ivan Gankevich
SPDX-License-Identifier: Unlicense
*/

#define _GNU_SOURCE

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <errno.h>

#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "syscalls.h"

enum ptrace_events {
    event_exec = SIGTRAP | (PTRACE_EVENT_EXEC<<8),
    event_fork = SIGTRAP | (PTRACE_EVENT_FORK<<8),
    event_vfork = SIGTRAP | (PTRACE_EVENT_VFORK<<8),
    event_clone = SIGTRAP | (PTRACE_EVENT_CLONE<<8),
    event_stop = SIGTRAP | (PTRACE_EVENT_STOP<<8),
    event_vfork_done = SIGTRAP | (PTRACE_EVENT_VFORK_DONE<<8),
    event_seccomp = SIGTRAP | (PTRACE_EVENT_SECCOMP<<8),
    event_exit = SIGTRAP | (PTRACE_EVENT_EXIT<<8),
};

void store_path(const char* path);

FILE* out = 0;

static int
callback(struct dl_phdr_info* info, size_t size, void* data) {
    if (strstr(info->dlpi_name, "ld-linux")) {
        store_path(info->dlpi_name);
    }
    return 0;
}

void store_shebang(const char* filename) {
    if (!filename) { return; }
    FILE* in = fopen(filename, "r");
    if (!in) { return; }
    const size_t size = 4096;
    char* data = malloc(size);
    if (data == 0) { perror("malloc"); return; }
    size_t nread = fread(data, 1, size, in);
    if (nread <= 0) { perror("fread"); free(data); return; }
    if (nread > 2 && data[0] == '#' && data[1] == '!') {
        char* first = data;
        char* last = data + nread;
        first += 2;
        while (first != last && *first <= ' ') { ++first; }
        char* path = first;
        while (first != last && *first > ' ') { ++first; }
        if (*first <= ' ') {
            *first = 0;
        }
        store_path(path);
    }
    free(data);
}

int child_main(int argc, char* argv[]) {
    out = fopen("whitelist", "a");
    if (out == 0) {
        perror("fopen");
        return 1;
    }
    dl_iterate_phdr(callback, 0);
    char** child_argv = argv+1;
    store_path(child_argv[0]);
    store_shebang(child_argv[0]);
    if (fclose(out) == -1) {
        perror("fclose");
        return 1;
    }
    if (-1 == ptrace(PTRACE_TRACEME,0,0,0)) {
        perror("ptrace");
        return 1;
    }
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

void store_path(const char* path) {
    if (path == 0) { return; }
    struct stat st;
    if (stat(path, &st) == -1 || (st.st_mode & S_IFMT) == S_IFDIR) {
        return;
    }
    char* rpath = realpath(path, 0);
    if (rpath != 0 && strcmp(path, rpath) != 0) {
        fputs(rpath, out);
        fputc('\n', out);
    }
    if (path[0] == '/') {
        fputs(path, out);
        fputc('\n', out);
    }
    free(rpath);
}

void on_syscall(pid_t pid, struct user_regs_struct* regs) {
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
        case SYS_execve: f=read_string(pid, regs->rdi);
                         store_shebang(f);
                         break;
        #endif
        #ifdef SYS_execveat
        case SYS_execveat: f=read_string(pid, regs->rsi);
                           store_shebang(f);
                           break;
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
    //if (f) {
    //    fprintf(stderr, "%d: %s %s %s\n", pid, syscall_names[n], f, f2);
    //}
    store_path(f);
    store_path(f2);
    free(f);
    free(f2);
}

const long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE |
    PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC;

int on_child_start(pid_t child_pid) {
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
    out = fopen("whitelist", "a");
    if (out == 0) {
        perror("fopen");
        return 1;
    }
    // whitelist child binary
    {
        char buf[4096];
        snprintf(buf, sizeof(buf), "/proc/%d/exe", child_pid);
        char path[4096];
        int ret = readlink(buf, path, sizeof(path));
        if (ret == -1) {
            perror("readlink");
            return 1;
        }
        store_path(path);
    }
    int ret = 0;
    while (1) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (-1 == pid) {
            if (errno == ECHILD) { break; }
            perror("waitpid");
            return 1;
        }
        //if (WIFEXITED(status)) { ret = WEXITSTATUS(status); break; }
        //if (WIFSIGNALED(status)) { ret = WTERMSIG(status); break; }
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == (SIGTRAP|0x80)) {
                struct user_regs_struct regs;
                if (-1 == ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
                    if (errno == ESRCH) { continue; }
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                on_syscall(pid, &regs);
                if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
                    if (errno == ESRCH) { continue; }
                    perror("ptrace");
                    ret = 1;
                    break;
                }
            } else if (WSTOPSIG(status) == SIGTRAP) {
                int event = (status >> 8) & 0xffff;
                if (event == event_fork || event == event_vfork || event == event_clone) {
                    pid_t new_pid = 0;
                    if (-1 == ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid)) {
                        if (errno == ESRCH) { continue; }
                        perror("ptrace");
                        ret = 1;
                        break;
                    }
                    fprintf(stderr, "fork %d from %d\n", new_pid, pid);
                    if (-1 == ptrace(PTRACE_SYSCALL, new_pid, 0, 0) && errno != ESRCH) {
                        perror("ptrace");
                        ret = 1;
                        break;
                    }
                    if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
                        if (errno == ESRCH) { continue; }
                        perror("ptrace");
                        ret = 1;
                        break;
                    }
                } else if (event == event_exec) {
                    fprintf(stderr, "ignore exec\n");
                    if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
                        if (errno == ESRCH) { continue; }
                        perror("ptrace");
                        ret = 1;
                        break;
                    }
                } else {
                    switch (event) {
                        case SIGTRAP | (PTRACE_EVENT_EXEC<<8): fprintf(stderr, "exec\n"); break;
                        case SIGTRAP | (PTRACE_EVENT_FORK<<8): fprintf(stderr, "fork\n"); break;
                        case SIGTRAP | (PTRACE_EVENT_VFORK<<8): fprintf(stderr, "vfork\n"); break;
                        case SIGTRAP | (PTRACE_EVENT_CLONE<<8): fprintf(stderr, "clone\n"); break;
                        case SIGTRAP | (PTRACE_EVENT_STOP<<8): fprintf(stderr, "stop\n"); break;
                        case SIGTRAP | (PTRACE_EVENT_VFORK_DONE<<8): fprintf(stderr, "vfork done\n"); break;
                        case SIGTRAP | (PTRACE_EVENT_SECCOMP<<8): fprintf(stderr, "seccomp\n"); break;
                        case SIGTRAP | (PTRACE_EVENT_EXIT<<8): fprintf(stderr, "exit\n"); break;
                        case SIGTRAP: fprintf(stderr, "sigtrap\n"); break;
                        default: fprintf(stderr, "unknown %d\n", ((status>>8)&0xffff));
                    }
                    if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
                        if (errno == ESRCH) { continue; }
                        perror("ptrace");
                        ret = 1;
                        break;
                    }
                }
                //fprintf(stderr, "status %d %d %d %d %d %d\n", status, SIGTRAP, WSTOPSIG(status), SIGTRAP|0x80, (status>>16)&0xffff, (PTRACE_EVENT_CLONE));
            } else {
                fprintf(stderr, "signal %d\n", WSTOPSIG(status));
                if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status))) {
                    if (errno == ESRCH) { continue; }
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                /*
                struct user_regs_struct regs;
                if (-1 == ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                on_syscall(pid, &regs);
                if (-1 == ptrace(PTRACE_SYSCALL, pid, 0, 0)) {
                    perror("ptrace");
                    ret = 1;
                    break;
                }
                */
                //fprintf(stderr, "status2 %d %d\n", (((status >> 8) & 0xffff)), (SIGTRAP | (PTRACE_EVENT_EXEC<<8)));
            }
        }
    }
    fclose(out);
    return ret;
}

void print_usage(const char* name) {
    printf("usage: %s [-h] [--help] [--version] args...\n", name);
    printf("example: %s find . -type f\n", name);
}

void print_version() {
    printf("%s\n", CHAINSAW_VERSION);
}

int main(int argc, char* argv[]) {
    if (argc <= 1) { print_usage(argv[0]); exit(1); }
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        exit(0);
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        print_version();
        exit(0);
    }
    init_names();
    pid_t pid = fork();
    switch (pid) {
        case -1: perror("fork"); return 1;
        case  0: return child_main(argc, argv);
        default: return parent_main(argc, argv, pid);
    }
    return 0;
}
