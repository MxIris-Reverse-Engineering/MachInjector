# Loader Dylib 内部构造

## 面向读者

- 需要改 `loader_arm64_remap.s` / `loader_arm64_remap_fixup.c` / `loader_arm64_remap_handoff.c` 三份源文件之一；
- 或者要理解 `MIMachInjectorRemap.m` 里的 `dlsym("cfg_...")` / `dlsym("apply_fixups")` / `dlsym("remap_stage1_entry")` 都是从哪里冒出来的；
- 或者 loader dylib 编译 / 打包出问题（`build_loader.sh` 报错、embedded byte header 没同步等）。

读之前先看 [`RemapArchitecture.md`](RemapArchitecture.md) 知道 loader 在整个 pipeline 里的位置。

## Loader 是什么

Loader 是一个**独立编译的 arm64 + arm64e fat dylib**，产物名 `loader_arm64_remap.dylib`。它**从来不作为 dylib 文件存在于最终产品里**——`build_loader.sh` 编出来后立刻被 `xxd -i` 转成 C byte array 塞进 `loader_arm64_remap_dylib.h`，链入 `MIMachInjectorRemap.m`。runtime 时 `MIMachInjectorRemap.m` 把这些字节 `write()` 到 `/private/tmp/MIMachInjectorRemap_loader_XXXXXX.dylib`、`dlopen` 它、用 `dlsym` 拿几个关键符号地址、`mach_vm_remap` 它的 `__TEXT` + `__DATA` 到 target，然后 `unlink` 掉 tmp 文件（dyld 保留 fd）。

**为什么走"编译成真 dylib 再嵌进 header"这么绕**：

1. Loader 需要 `__DATA` 段做**可写配置槽**（6 个 `_cfg_*` 变量供 injector patch）。asm shellcode 常量只有 `__TEXT`，办不到；
2. Loader 里同时有 asm (`stage1`) + freestanding C (`apply_fixups`) + hosted C (`pthread_thunk` + `perform_runtime_handoff`)。分开源文件编再 `ld` 起来最简单——一个 clang 命令搞定；
3. dlopen 后 `dlsym` 可以按名字拿符号地址（`_apply_fixups` / `_pthread_thunk` / `_remap_stage1_entry` / `_cfg_*`）——不用像纯 shellcode 那样手工算偏移；
4. Loader 拿了自己的完整 Mach-O 头 + LC_SEGMENT，方便 injector 里 `EnumerateSegments` 一次性拿到段布局；
5. `mach_vm_remap` 保留源代码签名（ad-hoc sign 后），AMFI 若开启也不拒。

## 三份源文件的职责边界

三份源文件都在仓库根的 `Loader/` 目录里，**不在 `Sources/MachInjector/` 的 SPM target 内**。这是刻意的：它们只该被 `build_loader.sh` 编成独立 dylib，进产品的只有生成出来的 byte array。2026-08-11 之前它们放在 target 里，结果 SwiftPM 一直在额外编译它们一遍，把 `_apply_fixups` / `_remap_stage1_entry` / `_pthread_thunk` / `_cfg_*` 这几个没人用的符号链进了 `libMachInjector` 和所有下游二进制（`MIMachInjectorRemap.m` 取符号一律走 dlopen 后的 `dlsym`，从不静态引用）。不要把它们搬回去。

| 源文件 | 运行位置 | 编译约束 | 主要输出符号 |
|:---|:---|:---|:---|
| `loader_arm64_remap.s` | raw mach thread | 纯 asm，无堆栈 protector 需求 | `_remap_stage1_entry`（`__TEXT`）+ 6 个 `_cfg_*` 数据槽（`__DATA`） |
| `loader_arm64_remap_fixup.c` | raw mach thread | `-fno-stack-protector -fno-builtin -ffreestanding` | `_apply_fixups`（`__TEXT`） |
| `loader_arm64_remap_handoff.c` | pthread | 同上 + `__has_feature(ptrauth_intrinsics)` gate | `_pthread_thunk`（`__TEXT`）+ 一堆 static helper |

**为什么 handoff.c 要跟 fixup.c 用同样严格的编译约束**：虽然 `pthread_thunk` 跑在 pthread 里，本可以用 hosted C——但编译约束是**整个 dylib 统一的**（一个 clang 命令一次编三份 .s/.c 生成一个 fat dylib）。而 fixup.c 里的 `apply_fixups` 必须 freestanding，所以三份都受这套约束。好处是 dylib 自包含度极高，不 pull 任何 libc/libSystem 依赖，`mach_vm_remap` 到 target 后能自足运行。

**`__has_feature(ptrauth_intrinsics)` 分支**：`loader_arm64_remap_fixup.c` 和 `loader_arm64_remap_handoff.c` 里所有 `__builtin_ptrauth_*` 调用都被这个宏 gate。arm64 slice 里这些 intrinsic 不可用（编译期就 fail），要么绕过、要么整段代码 skip。arm64e slice 里正常展开成 `pacia` / `pacib` / `pacda` / `pacdb` 指令。这样一个 fat dylib 同时能跑在 arm64 和 arm64e，虽然 arm64 slice 里 `apply_fixups` 遇到 auth entry 是 no-op（打不到 target，因为 arm64 daemon 不是我们 remap 的目标）。

## `__DATA` 段：6 个 `_cfg_*` 槽 + 1 个 `_cfg_pthread_out`

Loader 的 `__DATA` 段布局（见 `loader_arm64_remap.s:116-142`）：

```asm
.section __DATA,__data
.p2align 3

.globl _cfg_pthread_create_addr
_cfg_pthread_create_addr:    .quad 0    ; pthread_create_from_mach_thread 地址
.globl _cfg_pthread_start_addr
_cfg_pthread_start_addr:     .quad 0    ; 真实 payload entry 地址
.globl _cfg_pthread_arg
_cfg_pthread_arg:            .quad 0    ; MIMachInjectorRemapPayloadConfig* in target
.globl _cfg_pthread_out
_cfg_pthread_out:            .quad 0    ; pthread_create out param slot

.globl _cfg_payload_base
_cfg_payload_base:           .quad 0    ; payload __TEXT 起始地址 in target
.globl _cfg_fixup_worklist
_cfg_fixup_worklist:         .quad 0    ; MIRemapFixupEntry[] 地址 in target
.globl _cfg_fixup_count
_cfg_fixup_count:            .quad 0    ; entry 数量
```

7 个 `.quad`，共 56 字节，全部 8-byte 对齐。

**谁写谁读**：

| 槽 | 写入 by | 读取 by | 用途 |
|:---|:---|:---|:---|
| `_cfg_pthread_create_addr` | Injector | Stage1 asm（读到 x9，然后 `blr x9`） | 调 pthread_create_from_mach_thread |
| `_cfg_pthread_start_addr` | Injector | pthread_thunk（`cfg_pthread_start_addr` 变量） | 拿到 payload entry 后 sign + tail-call |
| `_cfg_pthread_arg` | Injector | Stage1 asm（读到 x3，作 `pthread_create_from_mach_thread` 的第 4 个参数） | 传给 pthread_thunk 的 arg（其实是 `MIMachInjectorRemapPayloadConfig *`） |
| `_cfg_pthread_out` | Stage1 asm（`pthread_create_from_mach_thread` 写入的 out `pthread_t`） | 无人读（占位符） | libsystem_pthread 要一个写入空间 |
| `_cfg_payload_base` | Injector | Stage1 asm（读到 x0，作 `apply_fixups` 的第一个参数） | payload __TEXT 起始 |
| `_cfg_fixup_worklist` | Injector | Stage1 asm（读到 x1，作 `apply_fixups` 的第二个参数） | worklist 数组地址 |
| `_cfg_fixup_count` | Injector | Stage1 asm（读到 w2，作 `apply_fixups` 的第三个参数） | worklist 元素数 |

**注入侧 patch 时机**：`MIMachInjectorRemap.m:1141-1162` 干这活。injector 先本地 `mach_vm_protect(mach_task_self(), loader_data, size, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)` 强制 CoW 拿到自己私有的 `__DATA` 副本，然后用 `*(uint64_t *)configPthreadCreateAddr = ...` 直接内存写，然后 `mach_vm_remap` loader 到 target—— patch 好的 `__DATA` 内容跟着 remap 一起过去。这样 target 里 stage1 从 `__DATA` 读到的就是 injector 写好的值。

**为什么 patch loader `__DATA` 而不是把 config 单独 mach_vm_write 到 target**：也可以，但 stage1 就要多一层 indirection——从 loader `__DATA` 拿 config page 地址，再从 config page 拿真值。目前的方案 stage1 asm 极简，直接读 `__DATA` 槽。**唯一独立 mach_vm_write 到 target 的是 `MIMachInjectorRemapPayloadConfig`**（12 个 uint64_t 的 payload metadata），因为它 pthread_thunk 内部要 deref，不像 `_cfg_*` 只是给 stage1 拿去 pass as arg。

**为什么 `__DATA` 段是**独立段**而不是 `__DATA_CONST`**：`__DATA_CONST` 在 dyld 完成 fixup 后会被 dyld 通过 `LC_DYLD_INFO` 里的 permission 表 flip 回 R-only。`__DATA` 保持 R+W 才能被 injector patch。且 loader 的 `_cfg_*` 需要 injector 那侧的 fixup 结束后再写，此时 dyld 已经把 `__DATA_CONST` 锁 R 了。

## `__TEXT` 段：三份代码的合并布局

Linker 把三份 `.o` 里的 `__TEXT` 合并成一个 `__TEXT` segment：

```
__TEXT segment:
  __text section:
    _remap_stage1_entry               ← 来自 .s
    _apply_fixups                     ← 来自 fixup.c
    _pthread_thunk                    ← 来自 handoff.c
    _perform_runtime_handoff (static) ← 来自 handoff.c
    _MIRemapHandoffMarkInvoke (static)← 来自 handoff.c
    _MIRemapCallSwiftRegister (static)← 来自 handoff.c

__DATA_CONST segment:
  __const section:
    _MIRemapHandoffMarkBlockDescriptor← 来自 handoff.c（layout-scalar，无 pointer，remap 后天然可用）
```

**排布顺序**：靠 clang / ld 决定，我们不 pin。但只要每个符号能被 `dlsym` 找到就行，我们**不依赖任何相对位置**。

**PC-relative 保证**：所有跨函数 call（`_remap_stage1_entry` bl `_apply_fixups`；`_pthread_thunk` bl `_perform_runtime_handoff`）用的是 `bl` 指令，`bl` 是 PC-relative（±128MiB 内的偏移）。loader dylib 只有几 KB 大小，怎么都够。**`mach_vm_remap` 到 target 后 loader base 变了，但因为 `bl` 是 PC-relative + 我们保留段间相对偏移（见下），指令自动指向 target 里的 loader 内函数**——这是整套架构能自足的关键。

**跨段访问（`__TEXT` 里代码要访问 `__DATA` 里的 `_cfg_*`）**：用 `adrp + add + ldr`：
```asm
adrp x0, _cfg_pthread_create_addr@PAGE
add  x0, x0, _cfg_pthread_create_addr@PAGEOFF
ldr  x9, [x0]
```
`adrp` 也是 PC-relative（±4GiB 内）。同样 `mach_vm_remap` 后段间相对距离不变，`adrp` 得出的地址就是 target 里 loader `__DATA` 里对应槽的地址。

## 段间相对偏移保证

Loader 有 `__TEXT`、`__DATA`、`__DATA_CONST`、`__LINKEDIT` 四个段。`MIMachInjectorRemap.m` 里 `RemapSegments`：

```c
mach_vm_allocate(target, &remoteBase, totalSpan, VM_FLAGS_ANYWHERE);
for (i = 0; i < count; ++i) {
    remoteSegment = remoteBase + (segments[i].vmaddr - minVmaddr);
    mach_vm_remap(target, &remoteSegment, ..., mach_task_self(), segments[i].localStart, ...);
}
```

关键：每个段的 target 地址 = `remoteBase + (vmaddr - minVmaddr)`——**段之间的相对偏移与 injector 里保持一致**。这样：
- `__TEXT` 起始离 `__DATA` 起始的距离，injector 和 target 一样
- `adrp + add` 在 target 里算出的地址精确对应 target 里的段位置
- 每个 `_cfg_*` 变量在 target 的 `__DATA` 里，相对 loader `__TEXT` 的偏移和 injector 里一样

`minVmaddr` 是**所有段中最小的 vmaddr**——一般是 `__TEXT` 段的 `vmaddr`（通常是 0）。所以 `remoteBase` 就是 target 里 loader `__TEXT` 的起始地址。

**`__LINKEDIT` 段被 `EnumerateSegments` 跳过**（只 remap 真正代码/数据段）。`__LINKEDIT` 里有 dyld 元数据（symbol table、chained fixups blob 等），target 里没人读，remap 过去纯浪费内存。

## `build_loader.sh` 干了什么

```bash
#!/bin/bash
set -euo pipefail

DYLIB="$(mktemp -t loader_arm64_remap).dylib"
trap 'rm -f "$DYLIB"' EXIT

clang -dynamiclib -arch arm64 -arch arm64e \
    -fno-stack-protector -fno-builtin -ffreestanding \
    -Oz -fno-common -fvisibility=hidden \
    -o "$DYLIB" \
    loader_arm64_remap.s \
    loader_arm64_remap_fixup.c \
    loader_arm64_remap_handoff.c

codesign -f -s - "$DYLIB"    # ad-hoc sign

{
    echo "// AUTO-GENERATED by build_loader.sh — do not edit by hand."
    echo "..."
    xxd -i -n "MIMachInjectorRemapLoaderDylib" "$DYLIB"
} > "$GENERATED_HEADER_PATH"   # ../Sources/MachInjector/loader_arm64_remap_dylib.h
```

**逐个 flag 解释**：

- `-dynamiclib` — 编成 dylib，能被 `dlopen`
- `-arch arm64 -arch arm64e` — fat binary，两个 slice
- `-fno-stack-protector` — 关掉 `__stack_chk_guard`。raw mach thread 无 TLS，`__stack_chk_guard` 在 TLS 里访问会 trap
- `-fno-builtin` — 阻止 clang 把 loop 优化成 `memcpy` / `memset` 之类的 libc 调用。loader 必须自足，不能 pull libc symbol
- `-ffreestanding` — 告诉 clang "不假设 hosted 环境存在"。避免 clang 生成任何隐含的 stdlib 依赖
- `-Oz` — 优化代码大小到最少（loader 会被 remap 进每个 target，size 越小 target 越好）
- `-fno-common` — 让 uninitialized global 直接进 `__DATA` 而不是 common section。common section 由链接器 late-allocate，导致 layout 不可预测
- `-fvisibility=hidden` — 默认 hidden，我们只想让 `_apply_fixups` / `_pthread_thunk` / `_remap_stage1_entry` / `_cfg_*` 显式 export（用 `__attribute__((visibility("default"), used))` 或 asm 里 `.globl`）

**ad-hoc sign**：`codesign -f -s -` 用一个 "identity" 为空（`-`）的 code signature。虽然是 ad-hoc，但字节级确定——`dlopen` 到 injector 后 dyld 验签通过。`mach_vm_remap` 用 `copy=FALSE` 保留源签名，所以 target 里 loader 页也带这个 ad-hoc sign，AMFI（如果开启）会认。

**xxd → `.h`**：
```
xxd -i -n "MIMachInjectorRemapLoaderDylib" "$DYLIB"
```
产出：
```c
unsigned char MIMachInjectorRemapLoaderDylib[] = { 0xcf, 0xfa, ... };
unsigned int MIMachInjectorRemapLoaderDylib_len = 851968;
```
`MIMachInjectorRemap.m` `#include` 这个 `.h`，运行时 `write()` 这些字节到 tmp path，然后 `dlopen`。

**运行时机**：手工跑，或每次改 loader 源码后跑一次。`build_loader.sh` 不自动挂到 SPM/Xcode build phase 里，原因：
1. build 产物是 checked-in 的 `.h`，避免每次 clean build 都要重编 loader；
2. `mktemp` + `codesign -f -s -` 在 CI 环境里可能 flaky；
3. loader 改动频率低，手工跑一次几秒钟；
4. loader 源码本来就在 `Loader/`、SPM target 之外，SwiftPM 连看都不该看它们一眼。

**脚本的工作目录**：`cd` 到脚本自身所在的 `Loader/`，三份源码都是同目录的相对路径；只有生成的
`.h` 写到隔壁 target 里（`GENERATED_HEADER_PATH`）。

**产物字节不是可复现的**：连着跑两次 `build_loader.sh`，`.h` 会有约 19 行差异——`LC_UUID` 每次链接
随机生成，code signature 的 CDHash 跟着变。代码字节本身不变。所以 diff 里只看到这几处变化时，说明
loader 逻辑没动，不必细究。

**手工跑触发点**：改 `loader_arm64_remap.s` / `loader_arm64_remap_fixup.c` / `loader_arm64_remap_handoff.c` 任一之后。改 header 或 `.m` 不需要。

**注意**：`Xcode` 不会自动追踪 `loader_arm64_remap_dylib.h` 的变化。改了这个 `.h`，需要 `touch MIMachInjectorRemap.m` 让 Xcode 认为它 dirty，否则不会重编嵌入的字节。这曾经踩过坑（sharingd 一直崩，就是 `.h` 更新了但 `.m` 没重编）。

## Stage1 asm 逐句解读

`loader_arm64_remap.s:63-114`：

```asm
_remap_stage1_entry:
    ; ---- Phase 1: apply_fixups(payloadBase, worklist, count) ----
    adrp x0, _cfg_payload_base@PAGE       ; x0 = page containing _cfg_payload_base
    add  x0, x0, _cfg_payload_base@PAGEOFF ; x0 = &_cfg_payload_base
    ldr  x0, [x0]                          ; x0 = payloadBase (patched value)

    adrp x1, _cfg_fixup_worklist@PAGE
    add  x1, x1, _cfg_fixup_worklist@PAGEOFF
    ldr  x1, [x1]                          ; x1 = worklist ptr

    adrp x2, _cfg_fixup_count@PAGE
    add  x2, x2, _cfg_fixup_count@PAGEOFF
    ldr  w2, [x2]                          ; w2 = count (32-bit load)

    bl _apply_fixups                       ; PC-relative call

    ; ---- Phase 2: pthread_create_from_mach_thread(&out, NULL, thunk, arg) ----
    adrp x0, _cfg_pthread_out@PAGE
    add  x0, x0, _cfg_pthread_out@PAGEOFF  ; x0 = &_cfg_pthread_out

    mov x1, xzr                            ; x1 = NULL attr

    adrp x2, _pthread_thunk@PAGE
    add  x2, x2, _pthread_thunk@PAGEOFF    ; x2 = _pthread_thunk (start_routine)

    adrp x3, _cfg_pthread_arg@PAGE
    add  x3, x3, _cfg_pthread_arg@PAGEOFF
    ldr  x3, [x3]                          ; x3 = config ptr in target (patched)

    adrp x9, _cfg_pthread_create_addr@PAGE
    add  x9, x9, _cfg_pthread_create_addr@PAGEOFF
    ldr  x9, [x9]                          ; x9 = pthread_create_from_mach_thread (patched)

    blr x9                                 ; call

    ; ---- spin until injector terminates us ----
1:  b 1b
```

**逐点解读**：

- **为什么不用 `adr` 而用 `adrp+add`**：`adr` 只覆盖 ±1MiB 段内偏移。loader 从 `__TEXT` 编址到 `__DATA` 一定跨段，需要 `adrp+add`（覆盖 ±4GiB）。
- **为什么 `_cfg_fixup_count` 用 `ldr w2`（32-bit）**：`apply_fixups` 签名里 `count` 是 `uint32_t`。上位 32 位不会被 read，用 32-bit load 更贴合语义（其实 64-bit load 也没 bug，因为 `_cfg_fixup_count` 是 `.quad 0`，高 32 位是 0，但 `w2` 明确表达意图）。
- **`bl _apply_fixups`**：`bl` 保存 PC 到 x30 (LR)，然后跳转。`apply_fixups` 结束时 `ret` 用 x30 返回 PC，跳回本函数。注意：raw mach thread 里 `ret` 是可以用的，因为 `bl` 已经填好了 x30。**只有从最外层的 `_remap_stage1_entry` `ret` 才崩**（因为进来时 x30 = 0，是 `thread_create_running` 起来的）。
- **`x2 = _pthread_thunk 地址`**：这是 loader 里的一个函数，用 `adrp+add` 拿 PC-relative 地址。后面 `pthread_create_from_mach_thread` 会把这个当 `start_routine`，起 pthread 后 pthread 就跳去 `_pthread_thunk` 执行。
- **`x9 = pthread_create_from_mach_thread 地址`**：injector 侧从 libsystem_pthread `dlsym` 拿到、`ptrauth_strip` 掉，写到 `_cfg_pthread_create_addr`。target 里 shared cache slide 跟 injector 一致，直接 `blr x9` 就跳到 libsystem_pthread 里的函数。
- **`blr x9` 后不检查返回值**：pthread_create 失败也没辙，反正 mach thread 会被 injector kill。且 pthread_create 极少失败（只在 memory 极紧张时）。
- **`1: b 1b`**：无限循环。raw mach thread 不能 `ret`（x30=0）。injector 会在 `usleep(2s)` 后 `thread_terminate` 掉这条 mach thread。

## `apply_fixups` 内部（fixup.c）

见 [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md) "apply_fixups (target 侧)" 一节。这里只强调**编译约束**：

- 全函数只用 `__builtin_ptrauth_*` intrinsic + 算术运算 + `*slot = value` 存取
- 没有任何函数调用（不 call `memcpy` 因为 `-fno-builtin`，不 call libc 因为 `-ffreestanding`）
- 没有 stack-protector overhead（`-fno-stack-protector`）
- 结果：编译出来是纯粹的算术 + 位操作 + `pacia/pacib/pacda/pacdb` + `str` —— 无外部依赖，无 TLS 依赖，能在 raw mach thread 上安全跑。

## `pthread_thunk` 内部（handoff.c）

```c
extern uint64_t cfg_pthread_start_addr;    // 声明；定义在 .s 的 __DATA

void *pthread_thunk(void *arg) {
    perform_runtime_handoff((const struct MIRemapPayloadConfig *)arg);

    uint64_t rawEntry = cfg_pthread_start_addr;
    if (rawEntry == 0) return NULL;

#if __has_feature(ptrauth_intrinsics)
    MIRemapPayloadEntry entry =
        (MIRemapPayloadEntry)__builtin_ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)rawEntry, ptrauth_key_asia, 0);
#else
    MIRemapPayloadEntry entry = (MIRemapPayloadEntry)(uintptr_t)rawEntry;
#endif
    return entry(arg);
}
```

**关键点**：

- `arg` 就是 stage1 asm 传来的第 4 个参数 = `_cfg_pthread_arg` = payload config page 地址（in target）；
- 先 handoff（调 libobjc + swift_register\*）；
- 再从 `_cfg_pthread_start_addr` 读 raw payload entry 地址；
- arm64e 上用 `sign_unauthenticated(rawEntry, IA, 0)` 重签成"函数指针 R-value ABI"（详见 [`PACHandbookForRemap.md`](PACHandbookForRemap.md)）；
- **tail-call** `entry(arg)`——被 clang `-Oz` 优化成 `braaz`（带签名的 branch），栈帧不留下，返回 pthread_start 直接 pass through。

**关于 `extern uint64_t cfg_pthread_start_addr`**：这个变量的**定义**在 `.s` 里（`__DATA` 段的一个 quad）。C 代码 `extern` 声明后可以直接读。clang 会生成 `adrp+add+ldr` 拿这个变量的值——PC-relative，remap 后照样对。

## `perform_runtime_handoff` 三步细节

```c
static void perform_runtime_handoff(const struct MIRemapPayloadConfig *config) {
    if (config == NULL) return;

    // (1) libobjc map_images
    if (config->mapImages != 0 && config->payloadMachHeader != 0) {
        struct MIRemapDyldObjCNotifyMappedInfo mappedInfo = {
            .machHeader = (const struct mach_header *)(uintptr_t)config->payloadMachHeader,
            .path = (const char *)(uintptr_t)config->payloadPath,
            .sectionLocationMetadata = NULL,
            .flags = 0,
        };

        struct MIRemapBlockLayout markBlock;
        markBlock.isa = NULL;
        markBlock.flags = 0;
        markBlock.reserved = 0;
        markBlock.invoke = __builtin_ptrauth_sign_unauthenticated(
            __builtin_ptrauth_strip((void *)MIRemapHandoffMarkInvoke, ptrauth_key_asia),
            ptrauth_key_asia,
            __builtin_ptrauth_blend_discriminator(&markBlock.invoke, 0));
        markBlock.descriptor = &MIRemapHandoffMarkBlockDescriptor;

        MIRemapMapImagesFunction mapImages =
            (MIRemapMapImagesFunction)__builtin_ptrauth_sign_unauthenticated(
                (void *)(uintptr_t)config->mapImages, ptrauth_key_asia, 0);
        mapImages(1, &mappedInfo, &markBlock);
    }

    // (2) swift_registerTypeMetadataRecords
    MIRemapCallSwiftRegister(config->swiftRegisterTypes,
                             config->swift5TypesBegin,
                             config->swift5TypesEnd);
    // (3) swift_registerProtocols
    MIRemapCallSwiftRegister(config->swiftRegisterProtocols,
                             config->swift5ProtosBegin,
                             config->swift5ProtosEnd);
    // (4) swift_registerProtocolConformances
    MIRemapCallSwiftRegister(config->swiftRegisterConformances,
                             config->swift5ProtoBegin,
                             config->swift5ProtoEnd);
}
```

**为什么 mark block 手搓而不是用 `^(uint32_t idx) { }` 语法**：

clang block literal 语法会生成一个静态 `_NSConcreteGlobalBlock` 结构在 `__DATA_CONST`。这个结构的 `descriptor` 字段是一个到静态 descriptor 的**签名指针**，descriptor 里还有函数指针 metadata。这些 pointer 在 **injector 侧**被 dyld fixup（chained fixups apply 后），指向 injector 里的 `_NSConcreteGlobalBlock`。当我们 `mach_vm_remap` payload 到 target 后，这个签名指针**依然指向 injector 的 libSystem 地址**——虽然 shared cache slide 跨进程一致所以地址表面上正确，但那个签名是 injector 的 PAC keys 签的，target 里 `autia` 会失败。

手搓 block 完全绕开这一层：`markBlock` 是**栈上**结构，字段全部在 runtime 填，没有任何 injector 侧 fixup 参与。`invoke` 我们自己按 target PAC keys 签；`descriptor` 指向 `__DATA_CONST` 里的 `MIRemapHandoffMarkBlockDescriptor`（纯数据、无指针，remap 后天然对）；`isa` 我们知道 libobjc 在这条 hot path 上不 deref，直接 NULL。

**为什么 `blend_discriminator(&markBlock.invoke, 0)`**：libobjc 里 `mark(idx)` 调用点用的 PAC schema 是 clang 默认的 `PointerAuthSchema(ASIA, addr_diverse=true, Discrimination::None)`。**addr_diverse** = modifier 里混入 storage 地址；**Discrimination::None** = 不加 constant。所以 modifier = `blend(storageAddr, 0)` = `storageAddr`（because blend with 0 keeps address as-is）。我们的 storage = 栈上 `markBlock.invoke`，`&markBlock.invoke` 就是那个 storage 地址。

**为什么先 `strip` 再 sign**：`(void *)MIRemapHandoffMarkInvoke` 是把函数指针名当 R-value 使用——arm64e ABI 让 clang 隐式发射 `paciza`（IA 签，const=0，addr_diverse=0）。签好的指针再进 `sign_unauthenticated` 会**再签一次**（double sign），结果不匹配 libobjc 的 authenticate schema。必须先 `strip` 掉 paciza 那层，拿到 raw 函数地址，再按 block invoke schema 签。详见 [`PACHandbookForRemap.md`](PACHandbookForRemap.md) "Double-sign 陷阱" 一节。

**Step 2/3/4 的 `MIRemapCallSwiftRegister`**：

```c
static void MIRemapCallSwiftRegister(uint64_t rawFunction,
                                     uint64_t sectionBegin,
                                     uint64_t sectionEnd) {
    if (rawFunction == 0 || sectionBegin == 0 || sectionEnd == 0) return;
    if (sectionBegin == sectionEnd) return;

    MIRemapSwiftRegisterSectionFunction function =
        (MIRemapSwiftRegisterSectionFunction)__builtin_ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)rawFunction, ptrauth_key_asia, 0);
    function((const void *)(uintptr_t)sectionBegin,
             (const void *)(uintptr_t)sectionEnd);
}
```

**要点**：
- **guard NULL 和 empty range**：如果 payload 没有 Swift（`sectionBegin == 0`），或没有 Swift class（`sectionBegin == sectionEnd`），直接 return。这让 pure-ObjC payload 也能用；
- **sign IA+0**：函数指针 R-value 的默认 arm64e ABI；
- **不 handle Swift runtime 冷启动**：假设 target 里 libswiftCore 已加载。sharingd 加载 libswiftCore（因为它自己是 Swift & ObjC 混合的），大部分现代 daemon 都会。若 target 完全没 Swift（罕见），`config.swift*` 会是 0，这里直接 return，也没问题。

## `_dyld_objc_notify_mapped_info` 布局

Loader 里 `struct MIRemapDyldObjCNotifyMappedInfo` 复刻自 `<mach-o/dyld_priv.h>`：

```c
struct MIRemapDyldObjCNotifyMappedInfo {
    const struct mach_header *machHeader;             // +0,  8 bytes
    const char *path;                                 // +8,  8 bytes
    const void *sectionLocationMetadata;              // +16, 8 bytes
    uint32_t flags;                                   // +24, 4 bytes (bit-field: dyldObjCRefsOptimized:1|flags:31)
    // total: 32 bytes (aligned to 8)
};
```

**填的值**：
- `machHeader` = payload 的 `payloadRemoteBase`（就是 target 里 payload `__TEXT` 起始，`mach_header_64` 就在那里）
- `path` = target 里 config page 里存的 payload path C-string
- `sectionLocationMetadata` = **NULL**（关键）
- `flags` = **0**（关键）

**`sectionLocationMetadata = NULL` 的意义**：正常 dyld 加载路径下这个字段会被 dyld 填成一个 `Loader*`（内部对象），libobjc `_dyld_lookup_section_info` 用这个来快速找 section 位置。我们 payload 不在 dyld 的 Loader 集合里，所以传 NULL。libobjc 的实现 `dyld/DyldAPIs.cpp:3038`：

```cpp
if ( sectionLocations == nullptr ) {
    SectionLocations metadata;
    JustInTimeLoader::parseSectionLocations(hdr, metadata);
    return lookupObjCInfo(kind, hdr, &metadata);
}
```

——传 NULL 会走 `parseSectionLocations(hdr, metadata)`，直接从 mach_header 的 LC_SEGMENT_64 里遍历 sections 找 `__objc_selrefs` / `__objc_classlist` / `__objc_imageinfo`。这是官方支持的 fallback path。

**`flags = 0` 的意义**：`dyldObjCRefsOptimized:1|flags:31` 位域全 0 表示 payload 没走 shared cache preopt。libobjc 会走完整的 selref uniquify + class register 路径。这是我们想要的。

**为什么不用 clang bit-field 语法**：手写 `uint32_t flags = 0;` 直接 0 就够。C 的 bit-field layout 严格来说不 guaranteed，用普通 uint32_t 避免 ABI surprise。

## 未来扩展方向

- **loader 支持 x86_64**：目前只 arm64/arm64e。x86_64 也可以做，但需要单独 stage1 asm（Intel calling convention）、无 arm64e-specific 的 PAC 操作、需要处理 x86_64 shared cache 位置差异；
- **多 payload 并发注入**：目前每次 `+ injectToPID:` 独立 `dlopen` loader（tmp path 各不同）；如果同一 injector 短时间内多次注入同一 payload，可以复用；
- **`__DATA` 槽压缩**：目前 7 个独立 quad，一共 56 字节。可以合并成一个 struct，一次 mach_vm_write 出去。目前分开写代码更简单。

## 相关

- [`RemapArchitecture.md`](RemapArchitecture.md) — 端到端总览
- [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md) — `apply_fixups` 里的算法细节
- [`PACHandbookForRemap.md`](PACHandbookForRemap.md) — PAC 备忘（block invoke schema 详解在这里）
- `Loader/loader_arm64_remap.s` — stage1 asm
- `Loader/loader_arm64_remap_fixup.c` — apply_fixups
- `Loader/loader_arm64_remap_handoff.c` — pthread_thunk + perform_runtime_handoff
- `Loader/build_loader.sh` — 编译 + xxd 脚本
