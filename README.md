
# Userland exec

Userland exec replaces the existing process image within the current address
space with a new one.
Userland exec mimics the behavior of the system call execve(), but the process structures which describe the process image remain unchanged, in other words the process name reported by system utilities will be the old process name. 

This technique can be used to become stealth after gain arbitrary code execution. Also can be used to execute binaries stored in noexec partitions. 

The first userland exec was created by [grugq](https://grugq.github.io/docs/ul_exec.txt), but this repository is higher inspired in the [Rapid7 mettle library](https://github.com/rapid7/mettle) that contains a good [blog descrition](https://www.rapid7.com/blog/post/2019/01/03/santas-elfs-running-linux-executables-without-execve/) about the technique as well.


This repository try to mimics big part of the mettle code but always focusing in embembed systems like smartphones, raspberry pies and so on.

## Build and usage
In this section I will describe how to build for Android and x86 machines. Do not forget to install libelf.

### x86
Build:

```bash
mkdir build && cd build
cmake ..
make
```
Usage:
```bash
desktop % strace ./uexec hello others args here 2>&1 | grep exec
execve("./uexec", ["./uexec", "hello", "others", "args", "here"], 0x7ffc34ec02f0 /* 54 vars */) = 0
desktop % strace bash -c ./hello 2>&1 | grep exec
execve("/usr/bin/bash", ["bash", "-c", "./hello"], 0x7ffebecc3130 /* 54 vars */) = 0
newfstatat(AT_FDCWD, "/desktop/userland-exec/build", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
newfstatat(AT_FDCWD, "/desktop/userland-exec", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
newfstatat(AT_FDCWD, "/desktop/userland-exec/build", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
newfstatat(AT_FDCWD, "/desktop/userland-exec", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
execve("./hello", ["./hello"], 0x5fb22658e2a0 /* 54 vars */) = 0
```

### Android

Build:

```bash
mkdir build && cd build
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-14 ..
make
```
Usage:
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

## License
This repository uses [GPL-3.0 License](https://spdx.org/licenses/GPL-3.0.html)

