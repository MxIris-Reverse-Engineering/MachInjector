# PAC 备忘（Remap 场景专用）

## 面向读者

- 需要在 injector 或 loader 代码里加 / 改任何 `ptrauth_*` / `__builtin_ptrauth_*` 调用；
- 遇到"注入后 target 崩在 `autia` / `braaa` 之类 PAC 相关指令"；
- 想理解为什么 [`LoaderDylibInternals.md`](LoaderDylibInternals.md) 里 block invoke 要 `strip` 再 `sign`。

这份不是通用 PAC 教程，只讲**这个项目里用到的 PAC 事实**，尤其是那些"看起来合理但会崩"的坑。想 general 学 PAC 去看 Apple 的 [arm64e ABI 文档](https://opensource.apple.com/source/xnu/xnu-11417.60.4/osfmk/arm/pmap/pmap.h) 或 LLVM 的 `clang/PointerAuthentication.rst`。

## 一分钟版

arm64e 上每个签名指针 = **加密后指针**，携带一个 12 位签名塞在 bit 47-54（user-space canonical 47-bit VA，剩下的高位用来放签名）。

- **产生签名**：`pacia x, mod` = 用 IA key 和 modifier `mod` 签指针 `x`；
- **验证 + 剥离签名**：`autia x, mod` = 用 IA key 和 modifier `mod` 验签，验通过后指针变回明文（bit 55-63 清 0）；验签失败就把指针**加密变废**（下次 deref 会崩）；
- **无验证剥离**：`xpaci x` = 直接抠掉高位（不管签名对不对）；
- **无验证签名**：`__builtin_ptrauth_sign_unauthenticated(ptr, key, mod)` = 直接签，不 auth；
- **组合签名**：`__builtin_ptrauth_blend_discriminator(addr, int)` = 把 16 位 int 塞进 addr 的 bit 48-63 生成 modifier。

**四把 key**（每个进程独立、boot 时随机化）：

| 名字 | 别名 | 用途 |
|:-|:-|:-|
| IA | `ptrauth_key_process_independent_code` = `ptrauth_key_asia` = `ptrauth_key_function_pointer` | 函数指针（默认） |
| IB | `ptrauth_key_process_dependent_code` = `ptrauth_key_asib` | 特殊函数指针（block invoke 的某些 schema、__ptrauth 手工声明） |
| DA | `ptrauth_key_process_independent_data` = `ptrauth_key_asda` = `ptrauth_key_cxx_vtable_pointer` | vtable 之类数据指针 |
| DB | `ptrauth_key_process_dependent_data` = `ptrauth_key_asdb` | 其他数据指针 |

**跨进程签名不成立**：因为 keys 是 per-process 的。injector 里签的指针到 target 里 `autia` 一定失败。所以我们的方案永远是：**injector 侧 strip → 通过配置槽把 raw address 传到 target → target 侧 sign_unauthenticated 重签**。

## 跨进程签名接力：为什么必须两半

**问题**：注入路径涉及多种"函数指针 / 数据指针跨越 injector 和 target 边界"。

**核心 fact**：
- arm64e 的 4 把 PAC key（IA / IB / DA / DB）由内核在进程创建时**随机化**并保存在进程 kernel state 里。父进程 fork 出的子进程 keys 也是重新随机的。**没有任何方式**跨进程共享或推导。
- 用户空间的所有 `pac*` / `aut*` 指令用的是"当前进程的 keys"。injector 里 `pacia x, mod` 出来的签名 = f(IA_of_injector, x, mod)；target 里 `autia same_signed_ptr, mod` = g(IA_of_target, signed_ptr, mod)。因为 IA_of_injector ≠ IA_of_target，验签一定 fail。

**接力策略**：

| 场景 | Injector 侧做什么 | 通过什么传递 | Target 侧做什么 |
|:---|:---|:---|:---|
| 函数指针（`map_images`、`swift_register*`、payload entry、`pthread_create_from_mach_thread`） | `dlsym` → `ptrauth_strip(fp_key)` 拿 raw addr | 写入 `_cfg_*` 或 `MIMachInjectorRemapPayloadConfig` 里 | `sign_unauthenticated(raw, IA, 0)` 重签成"函数指针 R-value" |
| Chained fixup 里的 auth entry 目标（rebase / bind） | 解析 chain 拿 target address（raw）+ key + diversity + addrDiv | 写入 `MIRemapFixupEntry` | `apply_fixups` 里 `sign_unauthenticated(raw, key_by_flags, modifier)` |
| Chained fixup 里的 plain entry 目标 | 同上但无签名信息 | 同上，`flags = 0` | 直接 `*slot = raw`，无签名 |
| Block invoke（`markBlock.invoke`） | 无（loader 里 static function） | Loader 自己就在 target 里 | Loader 内 `sign_unauthenticated(strip(&func), IA, blend(&storage, 0))` |

**Data 指针的 PAC 剥离怎么办**：`ptrauth_strip` 对函数指针（key=fp_key）和数据指针都是安全的。对 data 指针，签名占的位数（bits 47-63 的一部分）在 user-space canonical 47-bit VA 下天然是 0，strip 是 no-op，不影响。所以 injector 里对函数指针和数据指针都可以统一 strip 一遍，不会引入 bug。

## arm64e ABI 里三种"函数指针的 PAC schema"

这是**最容易搞混**的一块。同一个函数，在不同上下文用不同的 schema 签。

### Schema A：函数指针 R-value 语义

**触发**：把函数名当值使用，比如 `void *p = my_func;` 或 `(void *)my_func`。

**Schema**：`__ptrauth(ptrauth_key_asia, address_diversify=0, discriminator=0)`

Clang 隐式发射 `paciza x` 完成签名（`z` = zero discriminator，即 modifier = 0）。

```c
void my_func(void);
void *p = (void *)my_func;
// 等价于:
// void *raw = /* my_func 的 raw 地址 */;
// void *p = ptrauth_sign_unauthenticated(raw, ptrauth_key_asia, 0);
```

**同名调用点**：`my_func()` 直接跳（编译期就知道，不签）。但 `((void (*)(void))p)()` 会 `braaz p`（`z` = 无 discriminator）验签后跳。

### Schema B：函数指针存储语义（`__ptrauth`-qualified 变量）

**触发**：手工在类型上加 `__ptrauth`，比如：
```c
void (* __ptrauth(ptrauth_key_asia, 1, 0x1234) callback)(void);
```

**Schema**：由 `__ptrauth(...)` 参数决定。这里是 `IA + addr_diverse=1 + const=0x1234`。

赋值时 clang 发射 `pacia x, mod` where `mod = blend(&callback, 0x1234)`；读值时 `autia val, mod`。

**Remap 项目里我们不用这个 schema**——因为写代码时你**看不出**变量哪里存了。项目里对 config struct 里的 uint64_t 字段，通过 `ptrauth_sign_unauthenticated` 显式签，schema 由我们控制。

### Schema C：Block invoke 语义

**触发**：一个 block object 的 `invoke` 字段。

**Schema**：clang 默认 `PointerAuthSchema(ptrauth_key_asia, address_diversify=true, Discrimination::None)`，即 `IA + addr_diverse=1 + const=0`。

Block object 的调用点（`blockPtr->invoke(...)`）编译成：
```asm
ldr x8, [x0, #0x10]           ; x8 = block->invoke（signed）
mov x16, x0                    ; block ptr
add x16, x16, #0x10            ; x16 = &block->invoke (storage addr)
autia x8, x16                  ; auth with IA + addr_diverse (modifier = storage addr)
blraaz x8                      ; branch (`z` = no additional const discriminator on braa)
```

Wait 上面 `blraaz` 是"branch with auth ASIA zero"——但 `autia` 已经 auth 过了，`blraaz` 里的 `z` 用 modifier=0 再 auth 一次？

**实际生成的更精确**：clang 一般会 fold 掉两次 auth。要么是 `autia + blr` 要么是 `braa`（一步搞定）。具体看 optimization level。但**语义**是一样的：验签的 modifier = `blend(storage_addr, 0)`。

**因此**：如果我们要**手搓一个 block object**（不用 clang `^{...}` 语法），要 mirror 这个 schema：
```c
markBlock.invoke = __builtin_ptrauth_sign_unauthenticated(
    /* raw func addr */,
    ptrauth_key_asia,
    __builtin_ptrauth_blend_discriminator(&markBlock.invoke, 0));
```

## Double-sign 陷阱

**问题**：以下代码看起来对，但会 double sign，导致 libobjc 里 `autia` 失败：

```c
// WRONG!
markBlock.invoke = __builtin_ptrauth_sign_unauthenticated(
    (void *)MIRemapHandoffMarkInvoke,               // ← 这里已经 paciza 过了
    ptrauth_key_asia,
    __builtin_ptrauth_blend_discriminator(&markBlock.invoke, 0));
```

**为什么错**：`(void *)MIRemapHandoffMarkInvoke`——把函数名 cast 到 `void *`，触发 arm64e ABI 的 **schema A**（R-value）：clang **隐式发射 `paciza`**，产生一个 IA+0 签名的指针。再进 `sign_unauthenticated`，等于对已经签好的指针再签一次。结果是签名指针 bits 里已经带了 12 位 sig 的高位被又拿去当 raw ptr signed，产生一个 nonsense signature。libobjc 里 `autia` 验签失败 → 崩。

**正确做法**：先 `strip` 掉隐式 paciza，再签自己的 schema：

```c
// RIGHT!
markBlock.invoke = __builtin_ptrauth_sign_unauthenticated(
    __builtin_ptrauth_strip((void *)MIRemapHandoffMarkInvoke, ptrauth_key_asia),
    ptrauth_key_asia,
    __builtin_ptrauth_blend_discriminator(&markBlock.invoke, 0));
```

`__builtin_ptrauth_strip(x, key)` 编译成 `xpaci` 指令，无验证清掉 bits 47-63 里的签名残留。之后拿到的是纯 47-bit 地址，可以用作重签的输入。

**规律**：**任何时候把函数名 cast 到 `void *` 又要重新签，都必须 strip 中间那次**。同理适用于：
- `(function_ptr_type)variable_of_void_star_type` —— void* 到函数指针 cast 也会 sign
- 从 struct 里 `ldr` 一个 `__ptrauth`-qualified 字段 —— 会隐式 auth 后再 R-value cast 时又 sign

**checkpoints**：写完 signing 代码后，用 `otool -Vt` 反汇编看有没有意外的 `pac*` 双联签名。

## 项目里所有 sign 位置汇总

| 位置 | 目的 | Schema | 代码 |
|:---|:---|:---|:---|
| Injector `+ injectToPID:` line 1197 | 给 stage1 entry 签，作 arm_thread_state64 的 PC | IA + 0 | `ptrauth_sign_unauthenticated((void *)stage1EntryRemote, ptrauth_key_asia, 0)` |
| Target `apply_fixups` (auth rebase/bind) | 用 target keys 重签 chained-fixup slot | 按 fixup entry 的 `flags` 分派 IA/IB/DA/DB + modifier by addrDiv | `__builtin_ptrauth_sign_unauthenticated(rawTarget, key, modifier)` |
| Target `pthread_thunk` | 签 payload entry 用于 tail-call | IA + 0（R-value schema） | `__builtin_ptrauth_sign_unauthenticated((void *)rawEntry, ptrauth_key_asia, 0)` |
| Target `perform_runtime_handoff` step 1 | 签 map_images 函数指针用于调用 | IA + 0（R-value schema） | 同上 |
| Target `perform_runtime_handoff` step 1 | 签 markBlock.invoke（block invoke schema） | IA + addr_diverse=1 + const=0 | `sign_unauthenticated(strip(&func), IA, blend(&invoke, 0))` |
| Target `MIRemapCallSwiftRegister` | 签 swift_register* 函数指针用于调用 | IA + 0（R-value schema） | 同上 R-value schema |
| Target `_remap_stage1_entry` Phase 2 | 签 `_pthread_thunk`，作 `pthread_create_from_mach_thread` 的 start routine | IA + 0（R-value schema） | `paciza x2`（`loader_arm64_remap.s`） |

**注意**：从来没有一次 sign 用 `ptrauth_key_asib` / `ptrauth_key_asda` / `ptrauth_key_asdb` 之外的组合——除了 `apply_fixups` 里 fixup entry 自己带来的 key 位（0-3 都可能）。

### 唯一一次踩过的坑：交给 libpthread 的 start routine

`pthread_create_from_mach_thread` 的第三个参数类型是 `void *(*)(void *)`，在 arm64e 上就是 **Schema A 的 IA+0 函数指针**，跟其它任何函数指针参数没有区别。汇编里用 `adrp` + `add` 算出来的是 **raw address**，必须补一条 `paciza` 才符合 ABI。

漏签的后果不是"调用失败"而是**目标进程被杀**，且现场极具误导性：`pthread_create_from_mach_thread` 本身返回 0（成功），libpthread 把这个指针重签进自己的 `pthread_s.fun` 字段，直到 `_pthread_start` 认证并 branch 时才炸。崩溃报告里看到的是：

- `termination.namespace = PAC_EXCEPTION`
- `EXC_BAD_ACCESS`，`subtype` 形如 `KERN_INVALID_ADDRESS at 0xd54e80010c4d84cc -> 0x000000010c4d84cc (possible pointer authentication failure)`
- 栈只有三帧：`<未知> / _pthread_start / thread_start`
- 剥掉 PAC 位后的地址正好落在 remap 进去的 loader `__TEXT` 区间内，偏移等于 `_pthread_thunk` 的符号偏移

也就是说 **thunk 一条指令都没执行**，很容易误判成"handoff 挂了"而去查 map_images / swift_register。判断方法：把 `far` 的低位地址拿去和 `nm -arch arm64e -n` 出来的 loader 符号偏移比对。

这条在 2026-08-06 回归过一次：start routine 从 injector 填的 config 槽位（`_cfg_pthread_start_addr`）改成 loader 内部符号 `_pthread_thunk` 时，签名没跟着搬过来。`build_loader.sh` 现在会在汇编后反汇编 `_remap_stage1_entry` 并检查 `paciza` 是否存在，缺了就直接让生成失败。

## 项目里所有 strip 位置汇总

| 位置 | 目的 | 为什么 strip |
|:---|:---|:---|
| Injector `dlsym` 结果的 `ptrauth_strip(result, ptrauth_key_function_pointer)` | 拿到 raw address 好写到 config 里，让 target 侧重签 | 跨进程签名不成立，raw 才有意义 |
| Injector `ResolveBindImport` 的 `ptrauth_strip(symbolAddress, ptrauth_key_function_pointer)` | 同上，写到 `MIRemapFixupEntry.rawTargetAddress` | 同上 |
| Target `perform_runtime_handoff` 里 `__builtin_ptrauth_strip((void *)MIRemapHandoffMarkInvoke, ptrauth_key_asia)` | 去掉 arm64e ABI 的隐式 paciza | 避免 double sign |

**注意 injector strip 用 `ptrauth_key_function_pointer`**：这是 IA 的别名。函数指针默认 IA。数据指针（vtable 等）应该用 `ptrauth_key_asda` 或 `ptrauth_key_asdb`，但项目里我们没直接 strip 数据指针（chained fixup 里 auth data slot 是被 `apply_fixups` 直接用 dspecific key 签的，不经过 injector strip）。

## `blend_discriminator` 深入

```c
uintptr_t __builtin_ptrauth_blend_discriminator(void *address, unsigned integer);
```

**做什么**：把 `integer`（16 位）塞进 `address` 的 bits 48-63，返回结果作 modifier。

**生成的汇编**：
```asm
mov x17, x0                    ; x17 = address
movk x17, #<integer>, lsl 48   ; blend integer into upper 16 bits
```

**为什么这么设计**：
- `pacia x, mod` 里 `mod` 是 64-bit modifier；
- ARM 官方推荐用 address（64-bit）+ small constant（<= 16 bit）组合成 modifier；
- Blend 用 movk 是最快的（一条指令），比 `add` / `or` 更符合 pipeline；
- Address 部分保持不动（低 48 位）是因为 user-space canonical VA 只有 47 位，upper 16 位反正是 0，正好塞 discriminator。

**用法举例**：

```c
// 项目里的实际用法：
// 1. Chained fixup auth entry with addrDiv=1
modifier = blend(slotAddress, diversity);           // e.g. slotAddress=0x104300, diversity=0x5678
                                                     // → 0x5678_0000_0010_4300

// 2. Block invoke (const=0):
modifier = blend(&markBlock.invoke, 0);              // e.g. &invoke=0x1600bfc00
                                                     // → 0x0000_0001_600b_fc00 (unchanged, since const=0)
```

**边界情形**：`blend(x, 0)` = x（如果 x 高 16 位本来就是 0）。所以 block invoke 的 `blend(&invoke, 0)` 就是 `&invoke` 本身。

## 项目里所有 `_cfg_*` / config 字段的 signing convention

**Loader `__DATA` 里 7 个 `_cfg_*` 槽**：全部存**raw address**（stripped，unsigned）。stage1 asm 里读到之后：
- `_cfg_payload_base` / `_cfg_fixup_worklist` / `_cfg_fixup_count` 直接作参数传给 `apply_fixups`（`apply_fixups` 里对指针参数不做验签，只读 `entries[i]->rawTargetAddress` 等字段）；
- `_cfg_pthread_create_addr` 直接 `blr x9` 调用—— arm64e 里 `blr` 会 skip auth（不像 `blraa/blraaz`）。这里我们用 raw address + 普通 `blr` 是**故意的**：从 `_cfg_pthread_create_addr` 读到的就是 raw address，用 `blr` 不 auth 直接跳。
- `_cfg_pthread_start_addr` 传给 pthread_thunk 用 `cfg_pthread_start_addr` C 变量读取。pthread_thunk 里显式 `sign_unauthenticated(..., IA, 0)` 后 tail-call。

**`MIMachInjectorRemapPayloadConfig` 里的字段**：也全部 raw address。pthread_thunk / perform_runtime_handoff 里显式 sign 后使用。

**约定**：所有跨进程传递的地址，从 injector 到 target 全用 raw（stripped）。target 里显式签成需要的 schema。永远不要在 config 里存已签的地址。

## Target 里对 shared cache 函数的正确调用

假设我们要在 target 里调 libobjc `map_images`。config 里传入的是 stripped raw address。我们需要签一次才能调：

```c
MIRemapMapImagesFunction mapImages =
    (MIRemapMapImagesFunction)__builtin_ptrauth_sign_unauthenticated(
        (void *)(uintptr_t)config->mapImages,   // raw addr, safe—already stripped by injector
        ptrauth_key_asia,                        // function pointer default
        0);                                      // R-value schema: no discriminator
mapImages(1, &mappedInfo, &markBlock);
```

**为什么 `(void *)(uintptr_t)config->mapImages` 这两个 cast**：
- `config->mapImages` 类型是 `uint64_t`；
- `(uintptr_t)` 强调它是"地址级"整数；
- `(void *)` 转成指针以便传给 `sign_unauthenticated`；
- 这两个 cast 都不触发 arm64e ABI 的隐式 sign（因为源类型是整数，不是函数指针），所以**不需要 strip**。

**调用点**：`mapImages(...)` 因为 `mapImages` 类型是签名函数指针，clang 生成 `blraaz mapImages`（或 optimize 成等价）——用 IA + 0 验签后跳。因为我们刚刚用 IA + 0 签的，验签一定通过。

## 常见崩溃模式与诊断

**`EXC_BAD_ACCESS` at `braaz` / `blraa` in target**  
→ 签名不匹配。检查 schema：签的 schema 是不是跟调用点的 schema 一致（key、addr_diverse、discriminator 都要吻合）。

**目标进程被杀，`termination.namespace = PAC_EXCEPTION`，栈只有 `_pthread_start` / `thread_start` 两帧**  
→ 交给 `pthread_create_from_mach_thread` 的 start routine 没签成 IA+0。注意 `pthread_create_from_mach_thread` 会返回 0，看起来一切正常；thunk 一条指令都没跑。把 `far` 剥掉 PAC 位得到的地址，和 `nm -arch arm64e -n <loader>` 的符号偏移比对即可确认落点是 `_pthread_thunk`。详见上面「唯一一次踩过的坑」。

**`EXC_BAD_ACCESS` at `autia` / `autib` / `autda` / `autdb` in target**  
→ 签名验证失败。对 fixup entry：检查 `apply_fixups` 里 key/modifier 计算是不是对；对 markBlock.invoke：检查 sign 是不是 double 了；对 config 里传下来的函数指针：检查 injector 侧是不是漏 strip。

**Payload 起来但一段时间后 crash 在 vtable call**  
→ auth data slot 签错。fixup entry 里 `key` 位可能是 2 (DA) 或 3 (DB)——`apply_fixups` 里 switch 要覆盖到。

**注入后立刻 crash 在 CoreFoundation 里**  
→ Symbol bind 目标签错。可能是 injector `ResolveBindImport` 里 `dlsym` 拿的地址 strip 不彻底，或 target 里签的 schema 跟 clang 生成的调用点 schema 不一致。

**`log stream --predicate 'subsystem == "com.mxiris.machinjector.remap"'`** 里 fixup 计数正常但 payload 崩  
→ 逻辑对（chain 全走过），但**具体某几个 auth entry 签错了**。目前 diag 只统计 total，找不到具体是哪个 slot 出错。debug 手法：分批注入（只把 fixup 的前一半 auth entry 签进去，剩下 plain 处理，看崩不崩），二分定位。

## 参考

- LLVM PointerAuthentication：`clang/docs/PointerAuthentication.rst`
- Apple arm64e ABI overview（社区版）：https://blog.svenpeter.dev/posts/pac_arm64/
- dyld chained fixups 代码：`dyld/Fixups.cpp` 里 `fixupPointerAuth64`
- 项目内相关文档：
  - [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md) — 每种 auth slot 的位编码和 modifier 计算
  - [`LoaderDylibInternals.md`](LoaderDylibInternals.md) — block invoke 手搓的完整背景
  - [`StrictSeatbeltPayloadRuntimeHandoff.md`](StrictSeatbeltPayloadRuntimeHandoff.md) — 为什么 handoff 要在 pthread 里做（跟 PAC 无关，但常连着一起遇到）
