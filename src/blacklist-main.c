/*
Copyright © 2021 Ivan Gankevich
SPDX-License-Identifier: Unlicense
*/

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <linux/magic.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>

#include "config.h"

void print_usage(const char* name) {
    printf("usage: %s [-h] [--help] [--version] directory\n", name);
    printf("example: %s /\n", name);
}

void print_version() {
    printf("%s\n", CHAINSAW_VERSION);
}

int main(int argc, char* argv[]) {
    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        exit(0);
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        print_version();
        exit(0);
    }
    int ret = 0;
    char* root = (argc == 2) ? argv[1] : ".";
    char* new_root = realpath(root, 0);
    if (new_root == NULL) {
        fprintf(stderr, "Unable to get real path of %s\n", root);
        ret = 1;
        goto end;
    }
    root = new_root;
    struct stat status;
    struct statfs fs_status;
    FILE* out = fopen("blacklist", "w");
    if (out == NULL) {
        fprintf(stderr, "Unable to open blacklist\n");
        ret = 1;
        goto end;
    }
    struct dirent* entry;
    size_t dirs_size = 4096 / sizeof(char*);
    char** dirs = malloc(dirs_size*sizeof(char*));
    dirs[0] = root;
    int ndirs = 1;
    do {
        char* current_dir = dirs[ndirs-1];
        --ndirs;
        /* We skip home directory for safety reasons: who knows
           how virtualization technologies will mount home directories
           in the future... */
        if (strncmp(current_dir, "/home", 5) == 0 ||
            /* We skip /tmp directory because Singularity stores
               old root there. */
            strncmp(current_dir, "/tmp", 4) == 0 ||
            /* We skip /dev because we can't distinguish between
               tmpfs and devtmpfs using stat.f_type. */
            strncmp(current_dir, "/dev", 4) == 0) {
            goto free;
        }
        DIR* d = opendir(current_dir);
        if (d == NULL) {
            fprintf(stderr, "Unable to open directory %s\n", current_dir);
            ret = 1;
            goto close;
        }
        int dfd = dirfd(d);
        if (dfd == -1) {
            fprintf(stderr, "Unable to get directory file descriptor: %s\n",
                    current_dir);
            ret = 1;
            goto close;
        }
        if (-1 == fstatfs(dfd, &fs_status)) {
            fprintf(stderr, "Unable to get file system of %s\n", current_dir);
            ret = 1;
            break;
        }
        // skip virtual file systems
        switch (fs_status.f_type) {
            case RAMFS_MAGIC:
            case PROC_SUPER_MAGIC:
            case SYSFS_MAGIC:
            case DEVPTS_SUPER_MAGIC:
            case DEBUGFS_MAGIC:
            case CGROUP_SUPER_MAGIC:
            case CGROUP2_SUPER_MAGIC:
                goto close;
        }
        while ((entry = readdir(d)) != NULL) {
            const char* name = entry->d_name;
            // skip . and .. entries
            if ((name[0] == 0) ||
                (name[0] == '.' && name[1] == 0) ||
                (name[0] == '.' && name[1] == '.' && name[2] == 0)) {
                continue;
            }
            if (-1 == fstatat(dfd, name, &status, AT_SYMLINK_NOFOLLOW)) {
                fprintf(stderr, "Unable to stat %s/%s\n", current_dir, name);
                ret = 1;
                break;
            }
            // add the current entry to the stack
            size_t n1 = strlen(current_dir);
            if ((status.st_mode & S_IFMT) == S_IFDIR) {
                const size_t n2 = strlen(name);
                char* full_name = malloc(n1+n2+2);
                if (full_name == NULL) {
                    fprintf(stderr, "Memory allocation error\n");
                    ret = 1;
                    break;
                }
                memcpy(full_name, current_dir, n1);
                // remove slash at the end of the path
                if (full_name[n1-1] != '/') {
                    full_name[n1] = '/';
                    ++n1;
                }
                strcpy(full_name + n1, name);
                if (ndirs == dirs_size) {
                    dirs_size *= 2;
                    dirs = realloc(dirs, dirs_size*sizeof(char*));
                    if (dirs == NULL) {
                        fprintf(stderr, "Memory allocation error\n");
                        ret = 1;
                        break;
                    }
                }
                dirs[ndirs] = full_name;
                ++ndirs;
            } else {
               fputs(current_dir, out);
                // remove slash at the end of the path
               if (current_dir[n1-1] != '/') { fputc('/', out); }
               fputs(name, out);
               fputc('\n', out);
            }
        }
close:
        closedir(d);
free:
        free(current_dir);
    } while (ndirs >= 1);
    fclose(out);
    free(dirs);
end:
    return ret;
}
