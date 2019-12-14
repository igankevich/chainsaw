#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
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
    if (-1 == stat(root, &status)) {
        fprintf(stderr, "Unable to stat %s\n", root);
        ret = 1;
        goto end;
    }
    dev_t root_dev = status.st_dev;
    FILE* out = fopen("blacklist", "w");
    if (out == NULL) {
        fprintf(stderr, "Unable to open blacklist\n");
        ret = 1;
        goto end;
    }
    struct dirent* entry;
    char* dirs[4096 / sizeof(const char*)] = {0};
    dirs[0] = root;
    int ndirs = 1;
    do {
        char* current_dir = dirs[ndirs-1];
        --ndirs;
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
        while ((entry = readdir(d)) != NULL) {
            const char* name = entry->d_name;
            // skip . and .. entries
            if ((name[0] == 0) ||
                (name[0] == '.' && name[1] == 0) ||
                (name[0] == '.' && name[1] == '.' && name[2] == 0)) {
                continue;
            }
            if (-1 == fstatat(dfd, name, &status, 0)) {
                fprintf(stderr, "Unable to stat %s/%s\n", current_dir, name);
                ret = 1;
                break;
            }
            // skip files from different devices
            if (status.st_dev != root_dev) { continue; }
            // add the current entry to the stack
            if ((status.st_mode & S_IFMT) == S_IFDIR) {
                size_t n1 = strlen(current_dir);
                size_t n2 = strlen(name);
                char* full_name = malloc(n1+n2+2);
                if (full_name == NULL) {
                    fprintf(stderr, "Memory allocation error\n");
                    ret = 1;
                    break;
                }
                memcpy(full_name, current_dir, n1);
                full_name[n1] = '/';
                strcpy(full_name + n1 + 1, name);
                dirs[ndirs++] = full_name;
            } else {
               fputs(current_dir, out);
               fputc('/', out);
               fputs(name, out);
               fputc('\n', out);
            }
        }
close:
        closedir(d);
        free(current_dir);
    } while (ndirs != 0);
    fclose(out);
end:
    return ret;
}
