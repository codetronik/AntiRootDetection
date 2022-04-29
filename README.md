# Android Anti Root Detection

It bypasses Root detection from the app (such as Game or Banking)

Root permission is required to execute the Loadable kernel module.

## Features
- When the app searches for root-related files, it returns a fake file or path.
- Provides a fake su that is used when su is not installed. (type fakesu in shell)

## Build Enviroment
- Download and build kernel sources such as Lineage OS.
  - Build guide : https://codetronik.tistory.com/151
- Android cross compiler is required.
  - Download : https://github.com/Shubhamvis98/toolchains
- Open the Makefile and modify the kernel source path and compiler path.

## Output
- Loadable kernel module (.ko)


## Execution Error Types
The error type can be checked with the dmesg command.
- failed to load hook.ko: Invalid argument
  - (dmesg) disagrees about version of symbol printk
  - (demsg) Unknown symbol printk (err -22)
    - When compiling a kernel, the compiler should use Android-aarch.
- failed to load hook.ko: Exec format error
  - (dmesg) disagrees about version of symbol module_layout
    - Kernel and Loadable kernel module versions must match perfectly.
    - modinfo hook.ko and uname -r in your mobile device.
- failed to load hook.ko: Exec format error
  - (dmesg) LKM is not allowed by Samsung security policy.
    - LKM is not allowed in Samsung mobile phones :: In this case, bypass it or install Lineage OS

## Test Environment
AARCH64 (ARM64)
- Galaxy Tab S6 Lite (Android 11) / Lineage OS 18.1
