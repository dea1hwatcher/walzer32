# Walzer32

**Walzer32** is a high-performance in-process ARM32 (ARMv7-A / Thumb-2) to AArch64 (ARMv8/v9-A) Dynamic Binary Translator designed to run 32-bit legacy Android games and native libraries seamlessly on modern 64-bit-only Android devices (such as Pixel 7/8/9, Galaxy S24, Xiaomi 14/15, and Cortex-X3/X4/A715/A720 platforms).

---

## Architecture Overview

```
                                      +-------------------------+
                                      |   64-bit ART Process    |
                                      +------------+------------+
                                                   | JNI
                                                   v
+---------------------------------------------------------------------------------------------------+
| Walzer32 In-Process Container (libwalzer32.so)                                                   |
|                                                                                                   |
|  +------------------+    +-------------------+    +-------------------+    +--------------------+ |
|  |  walzer32-elf    |    |  walzer32-decoder |    |   walzer32-ir     |    | walzer32-emitter   | |
|  |  ELF32 Loader &  |--->|  ARMv7 / Thumb-2  |--->|  SSA IR, Opts &   |--->| AArch64 Superblock | |
|  |  Dynamic Fixups  |    |  Instruction Dec  |    |  Dead Flag Elim   |    | Direct JIT Engine  | |
|  +------------------+    +-------------------+    +-------------------+    +--------------------+ |
|                                                                                                   |
|  +----------------------------------------------------------------------------------------------+ |
|  | walzer32-rt: Tier-1 Basic Block JIT / Tier-2 Superblock Optimizer / AOT Disk Cache / Signals | |
|  +----------------------------------------------------------------------------------------------+ |
|                                                                                                   |
|  +----------------------------------------------------------------------------------------------+ |
|  | walzer32-bridge: Bionic ABI / GLES Passthrough / Vulkan / OpenSLES / AAudio / Android NDK    | |
|  +----------------------------------------------------------------------------------------------+ |
+---------------------------------------------------------------------------------------------------+
```

---

## Workspace Crates

| Crate | Purpose |
|---|---|
| [`walzer32-core`](crates/walzer32-core) | Core data types, guest virtual address space (`GuestAddr`), 4GB memory arena allocator, CPU state (`CpuState`), and exclusive monitors |
| [`walzer32-decoder`](crates/walzer32-decoder) | Fast ARMv7-A and Thumb-2 instruction decoders covering scalar ALU, load/store, branch, DSP/media, VFP, and NEON SIMD |
| [`walzer32-ir`](crates/walzer32-ir) | Intermediate representation, superblock lifter, and optimization pipeline (Dead Flag Elimination, Constant Folding) |
| [`walzer32-emitter-a64`](crates/walzer32-emitter-a64) | Low-level AArch64 machine code assembler and direct JIT superblock compiler |
| [`walzer32-interp`](crates/walzer32-interp) | Fallback ARMv7/VFP interpreter for cold code and rare system instructions |
| [`walzer32-elf`](crates/walzer32-elf) | 32-bit ELF parser, relocation fixups (`R_ARM_GLOB_DAT`, `R_ARM_JUMP_SLOT`, `R_ARM_ABS32`), and symbol resolution |
| [`walzer32-rt`](crates/walzer32-rt) | DBT runtime: Tier-1 basic block JIT, Tier-2 superblock optimizer, async background JIT, AOT disk caching, SMC detection, Futex, and host signal translation |
| [`walzer32-bridge`](crates/walzer32-bridge) | Bionic libc/libm bridge, GLES 1.x/2.0/3.x passthrough, Vulkan translation, OpenSLES/AAudio low-latency ring buffer, and NDK subsystems |
| [`walzer32-apk`](crates/walzer32-apk) | APK parser, repackaging engine, DEX native method inspection, ZIP page-alignment (4KB), and 64-bit stub injection |
| [`walzer32-android`](crates/walzer32-android) | High-level Android JNI entry points, `libwalzer32.so` container, lifecycle orchestration, and OBB/VFS mounting |
| [`walzer32-cli`](crates/walzer32-cli) | Development CLI for AOT precompilation, APK repackaging, ADB on-device testing, and benchmarking |

---

## Getting Started

### Prerequisites

- **Rust**: 1.85+ (Edition 2024)
- **Target**: `rustup target add aarch64-linux-android`
- **Android NDK**: r21+ (configured in `.cargo/config.toml`)

### Running Tests

```bash
# Run all workspace tests (over 400 tests)
cargo test --workspace --release
```

### Compiling `libwalzer32.so` for Android Devices

```bash
# Automated build using PowerShell
pwsh ./scripts/build_android.ps1

# Or directly with Cargo
cargo build --profile release-android --target aarch64-linux-android -p walzer32-android
```

The resulting library `libwalzer32.so` will be placed into `android/app/src/main/jniLibs/arm64-v8a/`.

### Packaging an APK for 64-bit Devices

```bash
cargo run --release -p walzer32-cli -- package game.apk -o game_arm64.apk
```

---

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
