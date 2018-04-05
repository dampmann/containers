#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sched.h>
#include <linux/sched.h>
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
    char *name;
    char *exe;
    char new_root[PATH_MAX];
    char old_root[PATH_MAX];
    //int pipe_fd[2];
};

void err_func(const char *msgfmt , ...) {
    va_list fargs;
    va_start(fargs, msgfmt);
    vfprintf(stderr, msgfmt, fargs);
    va_end(fargs);
    exit(EXIT_FAILURE);
}

static void mnt_cgroup_dir(const char *p) {
    char d[PATH_MAX];
    if(snprintf(d, PATH_MAX, "/sys/fs/cgroup/%s", p) < 0) {
        err_func("snprintf failed: %s\n", strerror(errno));
    }

    if(mkdir(d, 0555) == -1) {
        err_func("mkdir %s failed: %s\n", d, strerror(errno));
    }

    if(mount(p, d, "cgroup", (MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME), p) == -1) {
        err_func("mount %s failed: %s\n", d, strerror(errno));
    }
}

static int child(void *arg) {
    //char ch;
    struct container *argvv = (struct container*)arg;
    /*
    close(argvv->pipe_fd[1]);
    if(read(argvv->pipe_fd[0], &ch, 1) != 0) {
        err_func("pipe synchronization failed: %s", strerror(errno));
    }

    char proc_mount[128];
    if(snprintf(proc_mount, 128, "%s/proc", argvv->new_root) < 0) {
        err_func("snprintf failed: %s\n", strerror(errno));
    }

    if(mount("/proc", proc_mount, "", MS_BIND|MS_REC, "") == -1) {
        err_func("mount %s (bind, recursive) failed: %s\n", 
                proc_mount, strerror(errno));
    }

    char sys_mount[128];
    if(snprintf(sys_mount, 128, "%s/sys", argvv->new_root) < 0) {
        err_func("snprintf failed: %s\n", strerror(errno));
    }

    if(mount("/sys", sys_mount, "", MS_BIND|MS_REC, "") == -1) {
        err_func("mount %s (bind, recursive) failed: %s\n", 
                sys_mount, strerror(errno));
    }

    char dev_mount[128];
    if(snprintf(dev_mount, 128, "%s/dev", argvv->new_root) < 0) {
        err_func("snprintf failed: %s\n", strerror(errno));
    }

    if(mount("/dev", dev_mount, "", MS_BIND|MS_REC, "") == -1) {
        err_func("mount %s (bind, recursive) failed: %s\n", 
                dev_mount, strerror(errno));
    }


    */
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

    if(mount("tmp", "tmp", "tmpfs", 0, "") == -1) {
        err_func("mount /tmp failed: %s\n", strerror(errno));
    }

    if(mount("sysfs", "sys", "sysfs", 0, "") == -1) {
        err_func("mount /sys failed: %s\n", strerror(errno));
    }

    if(mount("tmpfs", "/sys/fs/cgroup", "tmpfs", 0, "") == -1) {
        err_func("mount /sys/fs/cgroup failed: %s\n", strerror(errno));
    }

    mnt_cgroup_dir("blkio");
    mnt_cgroup_dir("cpu,cpuacct");
    mnt_cgroup_dir("cpuset");
    mnt_cgroup_dir("devices");
    mnt_cgroup_dir("freezer");
    mnt_cgroup_dir("hugetlb");
    mnt_cgroup_dir("memory");
    mnt_cgroup_dir("net_cls,net_prio");
    mnt_cgroup_dir("perf_event");
    mnt_cgroup_dir("pids");
    if(symlink("/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu") == -1) {
        err_func("symlink failed: %s\n", strerror(errno));
    }

    if(symlink("/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpuacct") == -1) {
        err_func("symlink failed: %s\n", strerror(errno));
    }

    if(symlink("/sys/fs/cgroup/net_cls,net_prio", 
                "/sys/fs/cgroup/net_cls") == -1) {
        err_func("symlink failed: %s\n", strerror(errno));
    }

    if(symlink("/sys/fs/cgroup/net_cls,net_prio", 
                "/sys/fs/cgroup/net_prio") == -1) {
        err_func("symlink failed: %s\n", strerror(errno));
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

    if(unshare(CLONE_NEWNS) == -1) {
        cleanup(c, NULL);
        err_func("unshare failed: %s\n", strerror(errno));
    }

    if(mount("none", "/", "", MS_PRIVATE|MS_REC, "") == -1) {
        cleanup(c, NULL);
        err_func("mount / (private, recursive) failed: %s\n", strerror(errno));
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

    /*
    if(pipe(c->pipe_fd) == -1) {
        cleanup(c, NULL);
        err_func("pipe failed: %s\n", strerror(errno));
    }
    */

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
        (/*CLONE_NEWUSER |*/ CLONE_NEWUTS | CLONE_NEWPID | 
         CLONE_NEWNS | CLONE_NEWCGROUP | SIGCHLD), c);
    if((pid_t)-1 == pid) {
        cleanup(c, stack);
        err_func("clone failed: %s\n", strerror(errno));
    }

    /*
    char uidmap[PATH_MAX];
    if(snprintf(uidmap , PATH_MAX, "/proc/%ld/uid_map", (long)pid) < 0) {
        cleanup(c, stack);
        err_func("snprintf failed for /proc/%ld/uid_map: %s\n", 
                (long)pid, strerror(errno));
    }

    char gidmap[PATH_MAX];
    if(snprintf(gidmap , PATH_MAX, "/proc/%ld/gid_map", (long)pid) < 0) {
        cleanup(c, stack);
        err_func("snprintf failed for /proc/%ld/gid_map: %s\n", 
                (long)pid, strerror(errno));
    }

    int fd1 = open(uidmap, O_RDWR);
    if(fd1 == -1) {
        cleanup(c, stack);
        err_func("Failed to update %s: %s", uidmap, strerror(errno));
    }

    char uidmapping[128];
    if(snprintf(uidmapping, 128, "%u %u 1\n", 0, getuid()) < 0) {
        cleanup(c, stack);
        close(fd1);
        err_func("sprintf failed: %s", strerror(errno));
    }

    if(write(fd1, uidmapping, strlen(uidmapping)) != strlen(uidmapping)) {
        cleanup(c, stack);
        close(fd1);
        err_func("Failed to write uidmapping %s: %s\n",
                uidmap, strerror(errno));
    }

    close(fd1);

    char setgroups[128];
    if(snprintf(setgroups, 128, "/proc/%ld/setgroups", (long)pid) < 0) {
        cleanup(c, stack);
        err_func("sprintf failed: %s\n", strerror(errno));
    }

    int fdg = open(setgroups, O_RDWR);
    if(fdg == -1) {
        cleanup(c, stack);
        err_func("Failed to open %s: %s", setgroups, strerror(errno));
    }

    if(write(fdg, "deny", strlen("deny")) != strlen("deny")) {
        cleanup(c, stack);
        err_func("Failed to write to %s: %s\n", setgroups, strerror(errno));
    }

    close(fdg);

    int fd2 = open(gidmap, O_RDWR);
    if(fd2 == -1) {
        cleanup(c, stack);
        err_func("Failed to update %s: %s\n", gidmap, strerror(errno));
    }

    char gidmapping[128];
    if(snprintf(gidmapping, 128, "%u %u 1\n", 0, getgid()) < 0) {
        cleanup(c, stack);
        close(fd2);
        err_func("sprintf failed: %s\n", strerror(errno));
    }

    if(write(fd2, gidmapping, strlen(gidmapping)) != strlen(gidmapping)) {
        cleanup(c, stack);
        close(fd2);
        err_func("Failed to write gidmapping %s: %s\n", 
                gidmap, strerror(errno));
    }

    close(fd2);
    close(c->pipe_fd[1]);
    */
    if(waitpid(pid, &status, 0) == -1) {
        cleanup(c, stack);
        err_func("waitpid failed: %s\n", strerror(errno));
    }

    cleanup(c, stack);
    return(EXIT_SUCCESS);
}

