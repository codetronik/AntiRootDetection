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
- make

## Output
- Loadable kernel module (.ko)

## Test Environment
AARCH64 (ARM64)
- Galaxy Tab S6 Lite (Android 11) / Lineage OS 18.1
