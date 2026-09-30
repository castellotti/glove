/*
 * glove-tighten — the seccomp filter glove's apply-seccomp installs.
 *
 * srt's own filter (vendor/seccomp-src/seccomp-unix-block.c) blocks
 * socket(AF_UNIX) and io_uring. glove adds a re-tightening of the namespace and
 * mount surface that the container's relaxed seccomp profile (nested-userns)
 * had to open for bwrap: apply-seccomp installs this filter in its worker AFTER
 * its own unshare, so nothing below it — the harness and every tool command —
 * can create or join a namespace, or mount.
 *
 *   gcc -static -O2 -o glove-tighten glove-tighten.c -lseccomp
 *   ./glove-tighten <out.bpf>
 *
 * The output replaces srt's unix-block-bpf.h when apply-seccomp is compiled
 * (see the Dockerfile beside this file).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

static int deny(scmp_filter_ctx c, int err, int sc) {
    int rc = seccomp_rule_add(c, SCMP_ACT_ERRNO(err), sc, 0);
    if (rc < 0) fprintf(stderr, "glove-tighten: rule %d: %s\n", sc, strerror(-rc));
    return rc;
}

/* EPERM when flags (arg 0) carry `bit`. */
static int deny_flag(scmp_filter_ctx c, int sc, unsigned long bit) {
    int rc = seccomp_rule_add(c, SCMP_ACT_ERRNO(EPERM), sc, 1, SCMP_A0(SCMP_CMP_MASKED_EQ, bit, bit));
    if (rc < 0) fprintf(stderr, "glove-tighten: rule %d/%#lx: %s\n", sc, bit, strerror(-rc));
    return rc;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <out.bpf>\n", argv[0]);
        return 2;
    }
    scmp_filter_ctx c = seccomp_init(SCMP_ACT_ALLOW);
    if (!c) return 1;
    int rc = 0;

    /* srt's rules, unchanged: no new AF_UNIX sockets, no io_uring (it can
     * create sockets without the socket() syscall). */
    rc |= seccomp_rule_add(c, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                           SCMP_A0(SCMP_CMP_MASKED_EQ, 0xffffffff, AF_UNIX));
    rc |= deny(c, EPERM, SCMP_SYS(io_uring_setup));
    rc |= deny(c, EPERM, SCMP_SYS(io_uring_enter));
    rc |= deny(c, EPERM, SCMP_SYS(io_uring_register));

    /* Namespaces: any CLONE_NEW* bit, on unshare and clone. */
    unsigned long ns[] = {CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
                          CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET};
    for (size_t i = 0; i < sizeof ns / sizeof ns[0]; i++) {
        rc |= deny_flag(c, SCMP_SYS(unshare), ns[i]);
        rc |= deny_flag(c, SCMP_SYS(clone), ns[i]);
    }
    /* clone's low byte is the exit signal, so CLONE_NEWTIME is unshare-only. */
    rc |= deny_flag(c, SCMP_SYS(unshare), CLONE_NEWTIME);
    /* clone3 passes its flags in a struct seccomp cannot read: ENOSYS makes
     * libc fall back to clone, which the rules above check. */
    rc |= deny(c, ENOSYS, SCMP_SYS(clone3));

    /* Joining namespaces and every way to mount. */
    int calls[] = {SCMP_SYS(setns), SCMP_SYS(mount), SCMP_SYS(umount2), SCMP_SYS(pivot_root),
                   SCMP_SYS(chroot), SCMP_SYS(fsopen), SCMP_SYS(fsconfig), SCMP_SYS(fsmount),
                   SCMP_SYS(fspick), SCMP_SYS(open_tree), SCMP_SYS(move_mount),
                   SCMP_SYS(mount_setattr)};
    for (size_t i = 0; i < sizeof calls / sizeof calls[0]; i++) rc |= deny(c, EPERM, calls[i]);

    if (rc) {
        fprintf(stderr, "glove-tighten: could not build the filter\n");
        return 1;
    }
    int fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || seccomp_export_bpf(c, fd) < 0) {
        perror("glove-tighten: export");
        return 1;
    }
    close(fd);
    seccomp_release(c);
    return 0;
}
