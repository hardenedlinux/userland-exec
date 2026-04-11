/*
 * victim_server.c — intentionally vulnerable TCP service
 *
 * DEMO PURPOSE ONLY.  This is a deliberately vulnerable network service
 * that simulates a realistic target for rce_demonstrating noexec bypass via
 * userland execution.
 *
 * ── Architecture ─────────────────────────────────────────────────────────────
 *
 *   The server implements a trivial line-oriented protocol.  Each client
 *   connection goes through two phases:
 *
 *     1. GREETING — the server reads a "username" and echoes it back inside
 *        a greeting string.  The echo path contains a FORMAT STRING
 *        VULNERABILITY: the user-supplied name is passed directly as the
 *        format argument to snprintf(), allowing the attacker to leak
 *        arbitrary stack content (libc addresses, stack pointers, etc.).
 *
 *     2. COMMAND — the server reads a "command" into a fixed-size stack
 *        buffer.  This path contains a classic STACK BUFFER OVERFLOW:
 *        recv() is called with a 4096-byte max into a 64-byte buffer.
 *
 *   Both bugs are on the same TCP connection, allowing a single-connection
 *   exploit that first leaks, then smashes.
 *
 * ── Why the binary links libuserland-exec ────────────────────────────────────
 *
 *   The static library is linked into the binary.  This causes the linker
 *   to pull in PLT stubs for open, write, close, mmap, memfd_create,
 *   munmap, etc. — all the syscall wrappers that userland_exec.c uses
 *   internally.  These PLT entries exist at fixed addresses (non-PIE) and
 *   become the building blocks for the attacker's multi-call ROP chain.
 *
 *   The function userland_execv() itself also lives in .text at a fixed
 *   address.  The attacker's ROP chain ultimately calls it to map and
 *   execute the payload ELF without execve(2).
 *
 *   There are NO "recv_and_exec()" or other convenience functions.
 *   The attacker must chain individual PLT calls via ROP gadgets sourced
 *   from libc (whose base is leaked via the format string).
 *
 * ── Compile flags (set in rce_demo/CMakeLists.txt) ───────────────────────────────
 *
 *   -fno-stack-protector   no stack canary
 *   -no-pie                fixed virtual addresses (no ASLR on .text/.data)
 *   -O0                    predictable stack layout
 *   -g                     DWARF info for nm(1)
 *   -Wl,-z,norelro         writable GOT
 *
 *   NOTE: ASLR is still in effect for libc / stack / heap.
 *         The format string leak is required to defeat it.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "userland_exec.h"

/* ── tunables ─────────────────────────────────────────────────────────────── */

#define SERVER_PORT     4444
#define VULN_BUFSIZE      64   /* intentionally tiny */

/*
 * PAYLOAD_PATH — where the ROP chain writes the ELF on the noexec partition.
 * At a fixed .rodata address (non-PIE); the ROP chain uses this as the
 * filename argument to open().
 */
const char PAYLOAD_PATH[] = "/tmp/noexec_rce_demo/payload";

/*
 * g_client_fd — current client socket.  Global so that process_request()
 * has exactly ONE local variable (the 64-byte buffer), keeping the overflow
 * offset deterministic.
 */
int g_client_fd;

/*
 * g_iobuf — 1 MiB BSS buffer.  In normal operation it serves as an I/O
 * staging area for the service.  The attacker's ROP chain repurposes it
 * as the recv() destination for the incoming ELF payload, and carves out
 * small regions for the synthetic argv[] and empty environ[] needed by
 * userland_execv().  Its address is fixed (non-PIE BSS).
 */
char g_iobuf[0x100000];

/*
 * g_orig_stack — captured from main()'s argv.  Required by userland_execv()
 * to reconstruct the auxiliary vector (AT_RANDOM, AT_SYSINFO_EHDR, etc.).
 */
size_t *g_orig_stack;


/* ── greeting handler (FORMAT STRING VULNERABILITY) ───────────────────────── */

/*
 * greet_client()
 *
 * Reads a "username" from the client and echoes it back inside a greeting.
 * The bug: the username is passed directly as the format string to snprintf().
 *
 * An attacker sending "%p|%p|%p|..." will receive leaked stack values,
 * including return addresses into libc — defeating ASLR for libc.
 *
 * This models real-world format string bugs found in logging paths,
 * error messages, and protocol greetings.
 */
static void greet_client(void)
{
    char name[256];
    char response[4096];
    ssize_t n;
    int len;

    n = recv(g_client_fd, name, sizeof(name) - 1, 0);
    if (n <= 0)
        return;
    name[n] = '\0';

    /* Strip trailing newline if present */
    if (n > 0 && name[n - 1] == '\n')
        name[n - 1] = '\0';

    /*
     * FORMAT STRING BUG
     *
     * Intended code:  snprintf(response, sizeof(response), "Hello, %s!\n", name);
     * Actual code:    snprintf(response, sizeof(response), name);
     *
     * The user-controlled 'name' is used as the format string.
     * %p directives dump stack content; %n could write memory.
     * Here the attacker only needs %p to leak libc addresses.
     */
    len = snprintf(response, sizeof(response), name);
    if (len < 0)
        return;
    if ((size_t)len >= sizeof(response))
        len = (int)sizeof(response) - 1;

    send(g_client_fd, response, (size_t)len, 0);
}


/* ── command handler (BUFFER OVERFLOW) ────────────────────────────────────── */

/*
 * process_request()
 *
 * Reads a "command" from the client.  The bug: recv() allows up to 4096
 * bytes into a 64-byte stack buffer.
 *
 * x86-64 stack layout (-O0, no canary):
 *
 *   rbp + 8  : saved RIP    ← attacker overwrites (offset 72)
 *   rbp + 0  : saved RBP    ← clobbered (offset 64)
 *   rbp - 64 : cmd[]        ← overflow starts here (offset 0)
 *
 * After process_request() returns, the attacker's ROP chain executes.
 *
 * IMPORTANT: NO other local variables in this function.
 */
static void __attribute__((noinline)) process_request(void)
{
    char cmd[VULN_BUFSIZE];

    recv(g_client_fd, cmd, 4096, 0);   /* BUFFER OVERFLOW */
}


/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    (void)argc;
    g_orig_stack = (size_t *)argv - 1;

    int server_fd, opt = 1;
    struct sockaddr_in addr;

    printf("+---------------------------------------------------------+\n");
    printf("|    VICTIM SERVER  (format string + buffer overflow)     |\n");
    printf("+---------------------------------------------------------+\n\n");
    printf("[server] Port           : %d\n", SERVER_PORT);
    printf("[server] PAYLOAD_PATH   @ %p\n", (const void *)PAYLOAD_PATH);
    printf("[server] g_iobuf        @ %p  (%zu bytes)\n",
           (void *)g_iobuf, sizeof(g_iobuf));
    printf("[server] g_orig_stack   = %p\n", (void *)g_orig_stack);
    printf("[server] userland_execv @ %p\n\n",
           (void *)(uintptr_t)userland_execv);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(SERVER_PORT);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 5);

    printf("[server] Listening on 0.0.0.0:%d\n\n", SERVER_PORT);

    while (1) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        char peer_ip[INET_ADDRSTRLEN];

        g_client_fd = accept(server_fd, (struct sockaddr *)&peer, &plen);
        if (g_client_fd < 0)
            break;

        inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
        printf("[server] Connection from %s:%d\n",
               peer_ip, ntohs(peer.sin_port));

        greet_client();       /* phase 1: format string (info leak) */
        process_request();    /* phase 2: buffer overflow (ROP)     */

        close(g_client_fd);
        printf("[server] Connection closed.\n\n");
    }

    close(server_fd);
    return 0;
}
