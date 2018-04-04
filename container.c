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

static int child(void *arg) {
    struct container *argvv = (struct container*)arg;
    if(mount(argvv->new_root, argvv->new_root, "", MS_BIND|MS_REC, "") == -1) {
        fprintf(stderr, "Mount failed %s\n", strerror(errno));
        return(127);
    }

    if(chdir(argvv->new_root) == -1) {
        fprintf(stderr, "chdir failed %s\n", strerror(errno));
        return(127);
    }

    if(pivot_root(argvv->new_root, argvv->old_root) == -1) {
        if(errno == EINVAL) {
            fprintf(stderr, "pivot_root failed: try unshare -m\n");
        } 
        fprintf(stderr, "Pivot_root failed %s\n", strerror(errno));
        return(127);
    }

    if(chdir("/") == -1) {
        fprintf(stderr, "chdir failed %s\n", strerror(errno));
        return(127);
    }

    if(umount2("/.pivot_root", MNT_DETACH) == -1) {
        fprintf(stderr, "umount failed %s\n", strerror(errno));
        return(127);
    } 

    if(mount("proc", "proc", "proc", 0, "") == -1) {
        fprintf(stderr, "Mount failed %s\n", strerror(errno));
        return(127);
    }

    if(mount("sys", "sys", "sysfs", 0, "") == -1) {
        fprintf(stderr, "Mount failed %s\n", strerror(errno));
        return(127);
    }

    if(mount("devtmpfs", "dev", "devtmpfs", 0, "") == -1) {
        fprintf(stderr, "Mount failed %s\n", strerror(errno));
        return(127);
    }

    if(mount("devpts", "dev/pts", "devpts", 0, "") == -1) {
        fprintf(stderr, "Mount failed %s\n", strerror(errno));
        return(127);
    }

    if(mount("shmfs", "dev/shm", "tmpfs", 0, "") == -1) {
        fprintf(stderr, "Mount failed %s\n", strerror(errno));
        return(127);
    }

    if(mount("tmp", "tmp", "tmpfs", 0, "") == -1) {
        fprintf(stderr, "Mount failed %s\n", strerror(errno));
        return(127);
    }

    if(rmdir("/.pivot_root") == -1) {
        fprintf(stderr, "rmdir failed %s\n", strerror(errno));
        return(127);
    }

    if(execlp(argvv->exe, argvv->exe, NULL) == -1) {
        fprintf(stderr, "execlp failed %s\n", strerror(errno));
        return(127);
    }

    return(0);
}

void cleanup(struct container *c) {
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

int main(int argc, char **argv) {
    int status = -1;
    int opt;
    struct container *c = malloc(sizeof(struct container));
    if(c == NULL) {
        fprintf(stderr, "Out of memory\n");
        return(127);
    }

    c->name = NULL;
    c->exe = NULL;

    while ((opt = getopt(argc, argv, "c:n:r:")) != -1) {
    switch (opt) {
        case 'c':
            c->cdir = strdup(optarg);
            if(c->cdir == NULL) {
                cleanup(c);
                fprintf(stderr, "Out of memory\n");
                return(127);
            }
            break;
        case 'n':
            c->name = strdup(optarg);
            if(c->name == NULL) {
                cleanup(c);
                fprintf(stderr, "Out of memory\n");
                return(127);
            }
            break;
        case 'r':
            c->exe = strdup(optarg);
            if(c->exe == NULL) {
                cleanup(c);
                fprintf(stderr, "Out of memory\n");
                return(127);
            }
            break;
        default:
            fprintf(stderr, "Usage: %s -c container_dir -n container_name -r executable\n",
                   argv[0]);
            exit(EXIT_FAILURE);
       }
    }

    if(optind != 7) {
        cleanup(c);
        fprintf(stderr, "Usage: %s -c container_dir -n container_name -r executable\n",
                   argv[0]);
        exit(EXIT_FAILURE);
    }

    if(snprintf(c->new_root , PATH_MAX, "%s/%s/rootfs", c->cdir, c->name) < 0) {
        fprintf(stderr, "snprintf failed\n");
        cleanup(c);
        return(127);
    }

    if(snprintf(c->old_root , PATH_MAX, "%s/.pivot_root", c->new_root) < 0) {
        fprintf(stderr, "snprintf failed\n");
        cleanup(c);
        return(127);
    }

    fprintf(stderr, "Using %s as rootfs to start container %s\n", c->new_root, 
            c->name);
    pid_t pid;
    char *stack;
    char *stack_top;

    if((status = mkdir(c->old_root, 0700)) == -1) {
        if(errno != EEXIST) {
            fprintf(stderr, "Mkdir failed %s\n", strerror(errno));
            cleanup(c);
            return(127);
        }
    }

    stack = malloc(stack_size);
    if(stack == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        cleanup(c);
        return(127);
    }
    stack_top = stack + stack_size;
    pid = clone(child, stack_top, 
                CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, 
                c);
    if(waitpid(pid, &status, 0) == -1) {
        fprintf(stderr, "Waitpid failed\n");
        cleanup(c);
        free(stack);
        return(127);
    }
    free(stack);
    cleanup(c);
    return(0);
}

