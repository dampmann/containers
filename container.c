#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sched.h>
#include <limits.h>
#include <libgen.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

/* 
   requires that / is shared mounted
   pivot_root will fail with EINVAL
   in this case do unshare -m first 
   then run this program
*/

const int stack_size = 1024*1024;

struct container {
    char *cdir;
    char new_root[PATH_MAX];
    char old_root[PATH_MAX];
    char *name;
    char *exe;
};

void err_func(const char *msgfmt , ...) {
    va_list fargs;
    va_start(fargs, msgfmt);
    vfprintf(stderr, msgfmt, fargs);
    va_end(fargs);
    exit(EXIT_FAILURE);
}

static int child(void *arg) {
    struct container *argvv = (struct container*)arg;
    if(mount(argvv->new_root, argvv->new_root, "", MS_BIND|MS_REC, "") == -1) {
        err_func("mount %s (bind, recursive) failed: %s\n", 
                argvv->new_root, strerror(errno));
    }

    if(chdir(argvv->new_root) == -1) {
        err_func("chdir to %s failed: %s\n", argvv->new_root, strerror(errno));
    }

    if(pivot_root(argvv->new_root, argvv->old_root) == -1) {
        if(errno == EINVAL) {
            fprintf(stderr, "pivot_root failed: try unshare -m\n");
        } 
        err_func("pivot_root failed: %s\n", strerror(errno));
    }

    if(chdir("/") == -1) {
        err_func("chdir failed to new / failed: %s\n", strerror(errno));
    }

    if(umount2("/.pivot_root", MNT_DETACH) == -1) {
        err_func("umount2 (detach /.pivot_root) failed: %s\n", strerror(errno));
    } 

    if(mount("proc", "proc", "proc", 0, "") == -1) {
        err_func("mount /proc failed: %s\n", strerror(errno));
    }

    if(mount("sys", "sys", "sysfs", 0, "") == -1) {
        err_func("mount /sys failed: %s\n", strerror(errno));
    }

    if(mount("devtmpfs", "dev", "devtmpfs", 0, "") == -1) {
        err_func("mount /dev failed: %s\n", strerror(errno));
    }

    if(mount("devpts", "dev/pts", "devpts", 0, "") == -1) {
        err_func("mount /dev/pts failed: %s\n", strerror(errno));
    }

    if(mount("shmfs", "dev/shm", "tmpfs", 0, "") == -1) {
        err_func("mount /dev/shm failed: %s\n", strerror(errno));
    }

    if(mount("tmp", "tmp", "tmpfs", 0, "") == -1) {
        err_func("mount /tmp failed: %s\n", strerror(errno));
    }

    if(rmdir("/.pivot_root") == -1) {
        err_func("rmdir /.pivot_root failed: %s\n", strerror(errno));
    }

    if(execlp(argvv->exe, argvv->exe, NULL) == -1) {
        err_func("execlp failed for %s: %s\n", argvv->exe, strerror(errno));
    }

    return(EXIT_SUCCESS);
}

void cleanup(struct container *c, char *stack) {
    if(c != NULL) {
        if(c->name != NULL) {
            free(c->name);
        }

        if(c->exe != NULL) {
            free(c->exe);
        }

        if(c->cdir != NULL) {
            free(c->cdir);
        }

        free(c);
    }

    if(stack != NULL) {
        free(stack);
    }
}

int main(int argc, char **argv) {
    int status = -1;
    int opt;
    struct container *c = malloc(sizeof(struct container));
    if(c == NULL) {
        err_func("Out of memory when allocating struct container\n");
    }

    c->name = NULL;
    c->exe = NULL;

    while ((opt = getopt(argc, argv, "c:n:r:")) != -1) {
    switch (opt) {
        case 'c':
            c->cdir = strdup(optarg);
            if(c->cdir == NULL) {
                cleanup(c, NULL);
                err_func("Out of memory strdup option arg -c\n");
            }
            break;
        case 'n':
            c->name = strdup(optarg);
            if(c->name == NULL) {
                cleanup(c, NULL);
                err_func("Out of memory strdup option arg -n\n");
            }
            break;
        case 'r':
            c->exe = strdup(optarg);
            if(c->exe == NULL) {
                cleanup(c, NULL);
                err_func("Out of memory strdup option arg -r\n");
            }
            break;
        default:
            cleanup(c, NULL);
            fprintf(stderr, 
                "Usage: %s -c container_dir"
                " -n container_name -r executable\n",
            argv[0]);
            exit(EXIT_FAILURE);
       }
    }

    if(optind != 7) {
        cleanup(c, NULL);
        fprintf(stderr, 
            "Usage: %s -c container_dir"
            " -n container_name -r executable\n",
        argv[0]);
        exit(EXIT_FAILURE);
    }

    if(snprintf(c->new_root , PATH_MAX, "%s/%s/rootfs", c->cdir, c->name) < 0) {
        cleanup(c, NULL);
        err_func("snprintf failed for %s/%s/rootfs: %s\n", 
                c->cdir, c->name, strerror(errno));
    }

    if(snprintf(c->old_root , PATH_MAX, "%s/.pivot_root", c->new_root) < 0) {
        cleanup(c, NULL);
        err_func("snprintf failed for %s/.pivot_root: %s\n", 
                c->new_root, strerror(errno));
    }

    fprintf(stderr, "Using %s as rootfs to start container %s\n", 
            c->new_root, c->name);

    if((status = mkdir(c->old_root, 0700)) == -1) {
        if(errno != EEXIST) {
            cleanup(c, NULL);
            err_func("mkdir %s failed: %s\n", c->old_root, strerror(errno));
        }
    }

    pid_t pid;
    char *stack;
    char *stack_top;
    stack = malloc(stack_size);
    if(stack == NULL) {
        cleanup(c, NULL);
        err_func("unable to allocate stack memory for child: %s\n", 
                strerror(errno));
    }

    stack_top = stack + stack_size;
    pid = clone(child, stack_top, 
                CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, 
                c);
    if((pid_t)-1 == pid) {
        cleanup(c, stack);
        err_func("clone failed: %s\n", strerror(errno));
    }

    if(waitpid(pid, &status, 0) == -1) {
        cleanup(c, stack);
        err_func("waitpid failed: %s\n", strerror(errno));
    }

    cleanup(c, stack);
    return(EXIT_SUCCESS);
}

