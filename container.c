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
#include <stdbool.h>

const int stack_size = 1024*1024;

struct container {
    char *cdir;
    char *name;
    char *exe;
    char *cidr;
    char new_root[PATH_MAX];
    char old_root[PATH_MAX];
    int pipe_fd[2];
};

void err_func(const char *msgfmt , ...) {
    va_list fargs;
    va_start(fargs, msgfmt);
    vfprintf(stderr, msgfmt, fargs);
    va_end(fargs);
    exit(EXIT_FAILURE);
}

void err_warn(const char *msgfmt , ...) {
    va_list fargs;
    va_start(fargs, msgfmt);
    vfprintf(stderr, msgfmt, fargs);
    va_end(fargs);
}

static int mount_cgroup(const char *p) {
    char d[PATH_MAX];
    if(snprintf(d, PATH_MAX, "/sys/fs/cgroup/%s", p) < 0) {
        err_warn("snprintf failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mkdir(d, 0555) == -1) {
        err_warn("mkdir %s failed: %s\n", d, strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mount("cgroup", d, "cgroup", (MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_RELATIME), p) == -1) {
        err_warn("mount %s failed: %s\n", d, strerror(errno));
    }

    return(EXIT_SUCCESS);
}

static int child(void *arg) {
    char ch;
    struct container *argvv = (struct container*)arg;
    
    if(mount(argvv->new_root, argvv->new_root, "", MS_BIND|MS_REC, "") == -1) {
        err_warn("mount %s (bind, recursive) failed: %s\n", 
                argvv->new_root, strerror(errno));
        return(EXIT_FAILURE);
    }

    if(chdir(argvv->new_root) == -1) {
        err_warn("chdir to %s failed: %s\n", argvv->new_root, strerror(errno));
        return(EXIT_FAILURE);
    }

    if(pivot_root(argvv->new_root, argvv->old_root) == -1) {
        if(errno == EINVAL) {
            fprintf(stderr, "pivot_root failed: try unshare -m\n");
        } 
        err_warn("pivot_root failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(chdir("/") == -1) {
        err_warn("chdir failed to new / failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(umount2("/.pivot_root", MNT_DETACH) == -1) {
        err_warn("umount2 (detach /.pivot_root) failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    } 

    if(mount("proc", "proc", "proc", 0, "") == -1) {
        err_warn("mount /proc failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mount("tmp", "tmp", "tmpfs", 0, "") == -1) {
        err_warn("mount /tmp failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mount("sysfs", "sys", "sysfs", 0, "") == -1) {
        err_warn("mount /sys failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mount("tmpfs", "/sys/fs/cgroup", "tmpfs", 0, "") == -1) {
        err_warn("mount /sys/fs/cgroup failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    /*Wait for the cgroup setup */
    close(argvv->pipe_fd[1]);
    if(read(argvv->pipe_fd[0], &ch, 1) != 0) {
        err_warn("Failed reading from pipe: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    /* Warn about problems mounting but don't make it mandatory,
       it depends on the underlying system
       bail out for snprintf and mkdir problems
    */
    if(mount_cgroup("blkio") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("cpu,cpuacct") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("cpuset") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("devices") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("freezer") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("hugetlb") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("memory") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("net_cls,net_prio") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("perf_event") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(mount_cgroup("pids") != EXIT_SUCCESS) return(EXIT_FAILURE);
    if(symlink("/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu") == -1) {
        err_warn("symlink failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(symlink("/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpuacct") == -1) {
        err_warn("symlink failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(symlink("/sys/fs/cgroup/net_cls,net_prio", 
                "/sys/fs/cgroup/net_cls") == -1) {
        err_warn("symlink failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(symlink("/sys/fs/cgroup/net_cls,net_prio", 
                "/sys/fs/cgroup/net_prio") == -1) {
        err_warn("symlink failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mount("devtmpfs", "dev", "devtmpfs", 0, "") == -1) {
        err_warn("mount /dev failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mount("devpts", "dev/pts", "devpts", 0, "") == -1) {
        err_warn("mount /dev/pts failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(mount("shmfs", "dev/shm", "tmpfs", 0, "") == -1) {
        err_warn("mount /dev/shm failed: %s\n", strerror(errno));
        return(EXIT_FAILURE);
    }

    if(rmdir("/.pivot_root") == -1) {
        err_warn("rmdir /.pivot_root failed: %s\n", strerror(errno));
    }

    if(sethostname(argvv->name, strlen(argvv->name)) == -1) {
        err_warn("set hostname failed: %s\n", strerror(errno));
    }

    if(execlp(argvv->exe, argvv->exe, NULL) == -1) {
        err_warn("execlp failed for %s: %s\n", argvv->exe, strerror(errno));
        return(EXIT_FAILURE);
    }

    /* Never reached */
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

        if(c->cidr != NULL) {
            free(c->cidr);
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
    bool flagc = false;
    bool flagn = false;
    bool flagr = false;
    bool flagi = false;

    struct container *c = malloc(sizeof(struct container));
    if(c == NULL) {
        err_func("Out of memory when allocating struct container\n");
    }

    c->cdir = NULL;
    c->cidr = NULL;
    c->name = NULL;
    c->exe = NULL;

    while ((opt = getopt(argc, argv, "c:n:r:i:")) != -1) {
    switch (opt) {
        case 'c':
            flagc = true;
            c->cdir = strdup(optarg);
            if(c->cdir == NULL) {
                cleanup(c, NULL);
                err_func("Out of memory strdup option arg -c\n");
            }
            break;
        case 'n':
            flagn = true;
            c->name = strdup(optarg);
            if(c->name == NULL) {
                cleanup(c, NULL);
                err_func("Out of memory strdup option arg -n\n");
            }
            break;
        case 'r':
            flagr = true;
            c->exe = strdup(optarg);
            if(c->exe == NULL) {
                cleanup(c, NULL);
                err_func("Out of memory strdup option arg -r\n");
            }
            break;
        case 'i':
            flagi = true;
            c->cidr = strdup(optarg);
            if(c->cidr == NULL) {
                cleanup(c, NULL);
                err_func("Out of memory strdup option arg -i\n");
            }
            break;
        default:
            cleanup(c, NULL);
            fprintf(stderr, 
                "Usage: %s -c container_dir"
                " -n container_name -i cidr -r executable\n",
            argv[0]);
            exit(EXIT_FAILURE);
       }
    }

    if(!(flagc && flagn && flagr && flagi)) {
        cleanup(c, NULL);
        fprintf(stderr, 
            "Usage: %s -c container_dir"
            " -n container_name -i cidr -r executable\n",
        argv[0]);
        exit(EXIT_FAILURE);
    }

    char preconfig[PATH_MAX];

    if(snprintf(preconfig , PATH_MAX, "./pre-config.sh %s", c->name) < 0) {
        cleanup(c, NULL);
        err_func("snprintf failed for preconfig: %s\n", strerror(errno));
    }

    if((status = system(preconfig)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", preconfig,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", preconfig,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", preconfig, status);
        }
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

    fprintf(stderr, "Creating container %s with ip %s\n"
            "rootfs %s\n", c->name, c->cidr, c->new_root);

    if((status = mkdir(c->old_root, 0700)) == -1) {
        if(errno != EEXIST) {
            cleanup(c, NULL);
            err_func("mkdir %s failed: %s\n", c->old_root, strerror(errno));
        }
    }

    if(pipe(c->pipe_fd) == -1) {
        cleanup(c, NULL);
        err_func("pipe failed: %s\n", strerror(errno));
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
        (/*CLONE_NEWUSER |*/ CLONE_NEWUTS | CLONE_NEWPID | 
         CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWNET | SIGCHLD), c);
    if((pid_t)-1 == pid) {
        cleanup(c, stack);
        err_func("clone failed: %s\n", strerror(errno));
    }

    char cgroupcmd[PATH_MAX];
    if(snprintf(cgroupcmd, PATH_MAX, "./cgroup_config.sh %ld %s", 
                (long)pid, c->name) < 0) {
        err_func("snprintf failed: %s\n", strerror(errno));
    }

    if((status = system(cgroupcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", cgroupcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", cgroupcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", 
                    cgroupcmd, status);
        }
    }

    close(c->pipe_fd[1]);

    if(mkdir("/var/run/netns", 0755) == -1) {
        if(errno != EEXIST) {
            err_func("mkdir /var/run/netns failed: %s\n", strerror(errno));
        }
    }

    char nslnks[PATH_MAX];
    if(snprintf(nslnks, PATH_MAX, "/proc/%ld/ns/net", (long)pid) < 0) {
        err_func("snprintf failed: %s\n", strerror(errno));
    }

    char nslnkt[PATH_MAX];
    if(snprintf(nslnkt, PATH_MAX, "/var/run/netns/%s", c->name) < 0) {
        err_func("snprintf failed: %s\n", strerror(errno));
    }

    if(symlink(nslnks, nslnkt) == -1) {
        err_func("symlink failed (netns): %s\n", strerror(errno));
    }

    char vethcmd[256];
    if(snprintf(vethcmd, 256, "ip link set c%s netns %s",
                c->name, c->name) < 0) {
        err_func("snprintf failed for vethcmd: %s\n", c->name);
    }

    if((status = system(vethcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", vethcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", vethcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", vethcmd, status);
        }
    }

    if(snprintf(vethcmd, 256, "ip netns exec %s ip link set dev c%s name eth0",
                c->name, c->name) < 0) {
        err_func("snprintf failed for vethcmd: %s\n", c->name);
    }

    if((status = system(vethcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", vethcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", vethcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", vethcmd, status);
        }
    }

    if(snprintf(vethcmd, 256, "ip netns exec %s ip addr add %s dev eth0", 
                c->name, c->cidr) < 0) {
        err_func("snprintf failed for vethcmd: %s\n", c->name);
    }

    if((status = system(vethcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", vethcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", vethcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", vethcmd, status);
        }
    }

    if(snprintf(vethcmd, 256, "ip netns exec %s ip link set eth0 up", 
                c->name) < 0) {
        err_func("snprintf failed for vethcmd: %s\n", c->name);
    }

    if((status = system(vethcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", vethcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", vethcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", vethcmd, status);
        }
    }

    if(snprintf(vethcmd, 256, "ip netns exec %s ip addr add 127.0.0.1/8 dev lo", 
                c->name) < 0) {
        err_func("snprintf failed for vethcmd: %s\n", c->name);
    }

    if((status = system(vethcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", vethcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", vethcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", vethcmd, status);
        }
    }

    if(snprintf(vethcmd, 256, "ip netns exec %s ip link set lo up", 
                c->name) < 0) {
        err_func("snprintf failed for vethcmd: %s\n", c->name);
    }

    if((status = system(vethcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", vethcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", vethcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", vethcmd, status);
        }
    }

    if(snprintf(vethcmd, 256, 
        "ip netns exec %s ip route add default via 172.20.0.1", c->name) < 0) {
        err_func("snprintf failed for vethcmd: %s\n", c->name);
    }

    if((status = system(vethcmd)) != 0) {
        if(status == -1) {
            err_func("Failed to create child for %s: %s\n", vethcmd,
                    strerror(errno));
        } else if(status == 127) {
            err_func("Failed to create shell for %s: %s\n", vethcmd,
                    strerror(errno));
        } else {
            err_func("command %s failed with exit code %d\n", vethcmd, status);
        }
    }

    if(waitpid(pid, &status, 0) == -1) {
        cleanup(c, stack);
        err_func("waitpid failed: %s\n", strerror(errno));
    }

    if(unlink(nslnkt) != 0) {
        err_warn("Failed to remove netns symlink %s: %s\n", 
                nslnkt, strerror(errno));
    }

    cleanup(c, stack);
    return(status);
}

