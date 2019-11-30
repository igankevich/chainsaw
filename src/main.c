#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syscall.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int child_main(int argc, char* argv[]) {
    ptrace(PTRACE_TRACEME,0,0,0);
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
        case SYS_open:
            fprintf(stderr, "%s %s\n", "open", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_openat
        case SYS_openat:
            fprintf(stderr, "%s %s\n", "openat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_creat
        case SYS_creat:
            fprintf(stderr, "%s %s\n", "creat", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_mkdir
        case SYS_mkdir:
            fprintf(stderr, "%s %s\n", "mkdir", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_mkdirat
        case SYS_mkdirat:
            fprintf(stderr, "%s %s\n", "mkdirat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_access
        case SYS_access:
            fprintf(stderr, "%s %s\n", "access", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_faccessat
        case SYS_faccessat:
            fprintf(stderr, "%s %s\n", "faccessat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_stat
        case SYS_stat:
            fprintf(stderr, "%s %s\n", "stat", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_statx
        case SYS_statx:
            fprintf(stderr, "%s %s\n", "statx", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_lstat
        case SYS_lstat:
            fprintf(stderr, "%s %s\n", "lstat", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_fstatat
        case SYS_fstatat:
            fprintf(stderr, "%s %s\n", "fstatat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_new_fstatat
        case SYS_new_fstatat:
            fprintf(stderr, "%s %s\n", "new_fstatat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_execve
        case SYS_execve:
            fprintf(stderr, "%s %s\n", "execve", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_execveat
        case SYS_execveat:
            fprintf(stderr, "%s %s\n", "execveat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_truncate
        case SYS_truncate:
            fprintf(stderr, "%s %s\n", "truncate", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_chdir
        case SYS_chdir:
            fprintf(stderr, "%s %s\n", "chdir", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_rename
        case SYS_rename:
            fprintf(stderr, "%s %s %s\n", "rename",
                    f=read_string(pid, regs->rdi),
                    f2=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_renameat
        case SYS_renameat:
            fprintf(stderr, "%s %s %s\n", "renameat",
                    f=read_string(pid, regs->rsi),
                    f2=read_string(pid, regs->r10));
            break;
        #endif
        #ifdef SYS_rmdir
        case SYS_rmdir:
            fprintf(stderr, "%s %s\n", "rmdir", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_link
        case SYS_link:
            fprintf(stderr, "%s %s %s\n", "link",
                    f=read_string(pid, regs->rdi),
                    f2=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_linkat
        case SYS_linkat:
            fprintf(stderr, "%s %s %s\n", "linkat",
                    f=read_string(pid, regs->rsi),
                    f2=read_string(pid, regs->r10));
            break;
        #endif
        #ifdef SYS_unlink
        case SYS_unlink:
            fprintf(stderr, "%s %s\n", "unlink", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_unlinkat
        case SYS_unlinkat:
            fprintf(stderr, "%s %s\n", "unlinkat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_symlink
        case SYS_symlink:
            fprintf(stderr, "%s %s %s\n", "symlink",
                    f=read_string(pid, regs->rdi),
                    f2=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_symlinkat
        case SYS_symlinkat:
            fprintf(stderr, "%s %s %s\n", "symlinkat",
                    f=read_string(pid, regs->rdi),
                    f2=read_string(pid, regs->rdx));
            break;
        #endif
        #ifdef SYS_readlink
        case SYS_readlink:
            fprintf(stderr, "%s %s\n", "readlink", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_readlinkat
        case SYS_readlinkat:
            fprintf(stderr, "%s %s\n", "readlinkat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_chmod
        case SYS_chmod:
            fprintf(stderr, "%s %s\n", "chmod", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_fchmodat
        case SYS_fchmodat:
            fprintf(stderr, "%s %s\n", "fchmodat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_chown
        case SYS_chown:
            fprintf(stderr, "%s %s\n", "chown", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_lchown
        case SYS_lchown:
            fprintf(stderr, "%s %s\n", "lchown", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_fchownat
        case SYS_fchownat:
            fprintf(stderr, "%s %s\n", "fchownat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_mknod
        case SYS_mknod:
            fprintf(stderr, "%s %s\n", "mknod", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_mknodat
        case SYS_mknodat:
            fprintf(stderr, "%s %s\n", "mknodat", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_statfs
        case SYS_statfs:
            fprintf(stderr, "%s %s\n", "statfs", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_chroot
        case SYS_chroot:
            fprintf(stderr, "%s %s\n", "chroot", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_acct
        case SYS_acct:
            fprintf(stderr, "%s %s\n", "acct", f=read_string(pid, regs->rdi));
            break;
        #endif
            // TODO mount???
        #ifdef SYS_setxattr
        case SYS_setxattr:
            fprintf(stderr, "%s %s\n", "setxattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_lsetxattr
        case SYS_lsetxattr:
            fprintf(stderr, "%s %s\n", "lsetxattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_getxattr
        case SYS_getxattr:
            fprintf(stderr, "%s %s\n", "getxattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_lgetxattr
        case SYS_lgetxattr:
            fprintf(stderr, "%s %s\n", "lgetxattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_listxattr
        case SYS_listxattr:
            fprintf(stderr, "%s %s\n", "listxattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_llistxattr
        case SYS_llistxattr:
            fprintf(stderr, "%s %s\n", "llistxattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_removexattr
        case SYS_removexattr:
            fprintf(stderr, "%s %s\n", "removexattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_lremovexattr
        case SYS_lremovexattr:
            fprintf(stderr, "%s %s\n", "lremovexattr", f=read_string(pid, regs->rdi));
            break;
        #endif
        #ifdef SYS_inotify_add_watch
        case SYS_inotify_add_watch:
            fprintf(stderr, "%s %s\n", "inotify_add_watch", f=read_string(pid, regs->rsi));
            break;
        #endif
        #ifdef SYS_name_to_handle_at
        case SYS_name_to_handle_at:
            fprintf(stderr, "%s %s\n", "name_to_handle_at", f=read_string(pid, regs->rsi));
            break;
        #endif
        default: fprintf(stderr, "syscall %ld\n", n);
    }
    free(f);
    free(f2);
}

int parent_main(int argc, char* argv[], pid_t child_pid) {
    enum { BEFORE_SYSCALL, AFTER_SYSCALL } state = BEFORE_SYSCALL;
    while (1) {
        int status = 0;
        if (-1 == waitpid(child_pid, &status, 0)) {
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status)) { return WEXITSTATUS(status); }
        if (WIFSIGNALED(status)) { return WTERMSIG(status); }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            if (state == BEFORE_SYSCALL) {
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                on_syscall(child_pid, &regs);
                state = AFTER_SYSCALL;
            } else {
                state = BEFORE_SYSCALL;
            }
            ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        }
    }
    return 1;
}

int main(int argc, char* argv[]) {
    pid_t pid = fork();
    switch (pid) {
        case -1: perror("fork"); return 1;
        case  0: return child_main(argc, argv);
        default: return parent_main(argc, argv, pid);
    }
    return 0;
}
