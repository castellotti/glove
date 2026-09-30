/*
 * glove-pty — terminal plumbing for a harness wrapped by srt.
 *
 * srt runs everything under `bwrap --new-session`: the harness has no
 * controlling terminal, so it never gets SIGWINCH (a TUI does not re-lay out
 * on resize) and a cooked-mode ^C signals srt instead of the harness. Removing
 * --new-session would reopen TIOCSTI injection into the user's terminal, so
 * glove gives the sandbox its own terminal instead:
 *
 *   glove-pty relay -- <cmd...>   outside the sandbox: run <cmd> on a fresh pty
 *                                 whose size follows ours (SIGWINCH →
 *                                 TIOCSWINSZ) and copy bytes both ways. The
 *                                 sandbox never holds an fd to the real
 *                                 terminal, so TIOCSTI can only feed itself.
 *   glove-pty ctty -- <cmd...>    inside the sandbox: become a session leader
 *                                 and take stdin (the relay's pty) as the
 *                                 controlling terminal.
 *   glove-pty notty -- <cmd...>   before a tool command: give up the
 *                                 controlling terminal (TIOCNOTTY), keeping the
 *                                 process group, so the command cannot open
 *                                 /dev/tty and inject keystrokes into the
 *                                 harness (TIOCSTI). As a session leader it
 *                                 runs the command in a new session instead.
 *
 * Without a terminal (tests, print mode) relay and ctty just exec <cmd>.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t winch = 1, chld = 0;
static pid_t child = -1;
static void on_winch(int s) { (void)s; winch = 1; }
static void on_chld(int s) { (void)s; chld = 1; }
static void on_fwd(int s) { if (child > 0) kill(child, s); }

static int status_of(int st) { return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st); }

static int run(char **argv) {
    execvp(argv[0], argv);
    fprintf(stderr, "glove-pty: exec %s: %s\n", argv[0], strerror(errno));
    return 127;
}

static int copy(int from, int to) {
    char buf[16384];
    ssize_t n = read(from, buf, sizeof buf);
    if (n <= 0) return -1;
    for (ssize_t off = 0; off < n;) {
        ssize_t w = write(to, buf + off, (size_t)(n - off));
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += w;
    }
    return 0;
}

static int relay(char **argv) {
    if (!isatty(0)) return run(argv);
    struct winsize ws = {0};
    ioctl(0, TIOCGWINSZ, &ws);
    int master, slave;
    if (openpty(&master, &slave, NULL, NULL, &ws) < 0) {
        perror("glove-pty: openpty");
        return 1;
    }
    struct sigaction sa = {0};
    sa.sa_handler = on_winch;
    sigaction(SIGWINCH, &sa, NULL);
    sa.sa_handler = on_chld;
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_handler = on_fwd;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    child = fork();
    if (child < 0) {
        perror("glove-pty: fork");
        return 1;
    }
    if (child == 0) {
        /* No setsid/TIOCSCTTY here: the slave must stay free for `ctty`. */
        dup2(slave, 0);
        dup2(slave, 1);
        dup2(slave, 2);
        close(master);
        if (slave > 2) close(slave);
        _exit(run(argv));
    }
    close(slave);
    struct termios saved, raw;
    int have = tcgetattr(0, &saved) == 0;
    if (have) {
        raw = saved;
        cfmakeraw(&raw);
        tcsetattr(0, TCSANOW, &raw);
    }
    struct pollfd p[2] = {{0, POLLIN, 0}, {master, POLLIN, 0}};
    int in_open = 1;
    for (;;) {
        if (winch) {
            winch = 0;
            if (ioctl(0, TIOCGWINSZ, &ws) == 0) ioctl(master, TIOCSWINSZ, &ws);
        }
        p[0].fd = in_open ? 0 : -1;
        int r = poll(p, 2, chld ? 50 : -1);
        if (r < 0 && errno != EINTR) break;
        if (r > 0 && (p[1].revents & (POLLIN | POLLHUP | POLLERR)) && copy(master, 1) < 0) break;
        if (r > 0 && (p[0].revents & (POLLIN | POLLHUP)) && copy(0, master) < 0) in_open = 0;
        if (chld && r == 0) break; /* the child is gone and the pty is drained */
    }
    if (have) tcsetattr(0, TCSANOW, &saved);
    int st = 0;
    while (waitpid(child, &st, 0) < 0 && errno == EINTR) {}
    return status_of(st);
}

static int ctty(char **argv) {
    if (isatty(0)) {
        if (setsid() < 0) { /* a process-group leader cannot: fork first */
            pid_t c = fork();
            if (c < 0) {
                perror("glove-pty: fork");
                return 1;
            }
            if (c > 0) {
                int st = 0;
                while (waitpid(c, &st, 0) < 0 && errno == EINTR) {}
                return status_of(st);
            }
            setsid();
        }
        if (ioctl(0, TIOCSCTTY, 0) < 0) perror("glove-pty: TIOCSCTTY (continuing without a terminal)");
    }
    return run(argv);
}

static int notty(char **argv) {
    int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) return run(argv); /* no controlling terminal: nothing to give up */
    if (getsid(0) != getpid()) {
        /* The usual case (a child of the harness): drop the terminal, keep the
         * process group, so an abort of the group still kills the command. */
        if (ioctl(fd, TIOCNOTTY) < 0) {
            perror("glove-pty: TIOCNOTTY");
            return 1; /* fail closed: never run the command still holding the terminal */
        }
        close(fd);
        return run(argv);
    }
    /* A session leader cannot give up its terminal without SIGHUPing its
     * group: run the command in a new session (no terminal) instead, tied to
     * us so it dies with us. */
    close(fd);
    struct sigaction sa = {0};
    sa.sa_handler = on_fwd;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    pid_t parent = getpid();
    child = fork();
    if (child < 0) {
        perror("glove-pty: fork");
        return 1;
    }
    if (child == 0) {
        if (setsid() < 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
            perror("glove-pty: setsid");
            _exit(1);
        }
        if (getppid() != parent) _exit(1); /* the parent is already gone */
        _exit(run(argv));
    }
    int st = 0;
    while (waitpid(child, &st, 0) < 0 && errno == EINTR) {}
    return status_of(st);
}

int main(int argc, char **argv) {
    if (argc < 4 || strcmp(argv[2], "--") != 0) {
        fprintf(stderr, "usage: glove-pty relay|ctty|notty -- <cmd...>\n");
        return 2;
    }
    if (!strcmp(argv[1], "relay")) return relay(argv + 3);
    if (!strcmp(argv[1], "ctty")) return ctty(argv + 3);
    if (!strcmp(argv[1], "notty")) return notty(argv + 3);
    fprintf(stderr, "glove-pty: unknown mode %s\n", argv[1]);
    return 2;
}
