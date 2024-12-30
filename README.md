# Userland Exec

Userland exec replaces the existing process image within the current address space with a new one. It mimics the behavior of the system call `execve`, but the process structures describing the process image remain unchanged. In other words, the process name reported by system utilities will retain the old process name.

This technique can be used to achieve stealth after gaining arbitrary code execution. It can also be used to execute binaries stored in `noexec` partitions.

The first userland exec was created by [grugq](https://grugq.github.io/docs/ul_exec.txt). This repository is highly inspired by the [Rapid7 Mettle library](https://github.com/rapid7/mettle), which includes a comprehensive [blog description](https://www.rapid7.com/blog/post/2019/01/03/santas-elfs-running-linux-executables-without-execve/) of the technique.

Initially, a large part of this repository's code mimicked the Mettle library, but it has since been extended to include additional complexity to bypass SELinux verification.

## SELinux Verification Bypass
SELinux includes the [execmem](https://selinuxproject.org/page/ObjectClassesPerms#process) verification, which ensures:
- A page that was once writable cannot become executable (i.e., changing `PROT_WRITE` to `PROT_EXEC` using `mprotect` is disallowed).
- No page can be both writable and executable simultaneously (W ^ X policy).

### Bypassing `mprotect`
To bypass `mprotect`, it is necessary to create a temporary file. This can be achieved using `memfd_create` combined with `munmap` and `mmap`, thereby avoiding the `mprotect` system call altogether.

### Bypassing W ^ X
The [`elf_debugger.c`](examples/elf_debugger.c) example demonstrates that any ELF contains a `PT_LOAD` region that is both executable and writable. This region is required to load the program information during execution. To address this, the [`bypass_wx.c`](examples/bypass_wx.c) implementation was created. This design:
- Marks a page as executable.
- On write attempts to this page, triggers a `SIGSEGV` signal.
- Intercepts the signal and dynamically changes the page protection from `PROT_EXEC` to `PROT_WRITE`.

## Build and Usage
This section describes how to build for Android and x86 machines. Ensure `libelf` is installed before proceeding.

### x86
#### Build
```bash
mkdir build && cd build
cmake ..
make
```

#### Usage
```bash
desktop % strace ./uexec hello others args here 2>&1 | grep exec
execve("./uexec", ["./uexec", "hello", "others", "args", "here"], 0x7ffc34ec02f0 /* 54 vars */) = 0
desktop % strace bash -c ./hello 2>&1 | grep exec
execve("/usr/bin/bash", ["bash", "-c", "./hello"], 0x7ffebecc3130 /* 54 vars */) = 0
newfstatat(AT_FDCWD, "/desktop/userland-exec/build", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
newfstatat(AT_FDCWD, "/desktop/userland-exec", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
execve("./hello", ["./hello"], 0x5fb22658e2a0 /* 54 vars */) = 0
```

#### Debug Build
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

### Android
#### Build
```bash
mkdir build && cd build
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-14 ..
make
```

#### Usage
```bash
desktop % adb push uexec hello /data/local/tmp
uexec: 1 file pushed, 0 skipped. 113.9 MB/s (22912 bytes in 0.000s)
hello: 1 file pushed, 0 skipped. 184.9 MB/s (6936 bytes in 0.000s)
2 files pushed, 0 skipped. 0.3 MB/s (29848 bytes in 0.090s)

desktop % adb shell
dm3q:/ $ cd /data/local/tmp
dm3q:/data/local/tmp $ chmod +x uexec
dm3q:/data/local/tmp $ ./hello
Hello World
dm3q:/data/local/tmp $ ./uexec hello
Hello World
dm3q:/data/local/tmp $
```

## Troubleshoot
On `CentOS`, the libc library may exhibit unusual behavior. To address this issue, a simple "Hello, World" program written in assembly, [`hello_nolibc.s`](x86_64_examples/hello_nolibc.s), has been provided. This example together with the cmake demonstrates how to build and execute a program without linking to libc.

## License
This repository uses the [GPL-3.0 License](https://spdx.org/licenses/GPL-3.0.html).
