# Chained Fixups 全链路

## 面向读者

- 已经读过 [`RemapArchitecture.md`](RemapArchitecture.md)，知道 chained fixups 是"injector 解析、target 重签"两半分工
- 正在改 `MIMachInjectorRemap.m` 里 `ParseChainedFixups` 或 `loader_arm64_remap_fixup.c` 里 `apply_fixups`
- 或者遇到"注入后 payload 里某个函数调用 crash 在奇怪的地址"想弄清 fixup 是不是没处理对

如果新的 payload 类型（比如 arm64 slice 而不是 arm64e、或者 Swift Package Manager 编出来的 dylib）解析出错，读这份文档定位问题。

## 背景：dyld 做了什么、我们跳过了什么

正常情况下，一个 arm64e dylib 加载时：
1. dyld 从 `LC_DYLD_CHAINED_FIXUPS` load command 找到 chained fixups 区（在 `__LINKEDIT` 里）；
2. 遍历每个 segment 里的每个 chain，每个 chain 节点是一个 `uint64_t` slot，编码里同时含：
   - **是 rebase 还是 bind**（本 image 内地址 vs. 外部符号）
   - **是 auth 还是 plain**（需要 PAC 签名 vs. 明文写入）
   - 目标地址 / 目标符号 ordinal
   - 若是 auth：PAC key (IA/IB/DA/DB) + 16 位 diversity + address diversify 位
   - 到下一个 chain 节点的 stride 增量
3. 对每个 slot：
   - plain rebase → 写 `imageSlide + targetOffset`
   - plain bind → 写 `dlsym(RTLD_DEFAULT, symbolName)`
   - auth rebase → 写 `pacia/pacib/pacda/pacdb(rebased_addr, modifier)` where `modifier = blend(slotAddr, diversity)` if addrDiv else `diversity`
   - auth bind → 同 auth rebase，但 target 是 dlsym 结果不是 imageSlide+offset

**remap 路径跳过了 dyld 完全**——payload 段被 `mach_vm_remap` 到 target 后，`__DATA_CONST` / `__DATA` / `__AUTH_CONST` 里那些 chain 节点还是"未 fixup 的原始编码"。也就是说：
- payload 里所有 rebase slot 存的还是 chain metadata，不是可用的指针；
- payload 里所有 bind slot 存的还是 ordinal encoding，跟目标符号地址无关；
- payload 一旦开始跑，第一次触到这些 slot 就会拿一个 chain-encoding 的 nonsense 值去 dereference 或 call → crash。

`ParseChainedFixups` + `apply_fixups` 就是把这套 dyld work 补上。

## 分工：injector vs target

**为什么必须两半**：arm64e PAC keys 是**每个进程独立**的（内核在进程创建时随机初始化 `IA/IB/DA/DB` 四把 key）。injector 里 `pacia x` 签出来的指针，扔到 target 里 `autia x` 会 auth 失败 → BRK。所以 injector 只能算到"raw target address + PAC 参数"，最后的 sign 一定要在 target 里进行。

具体分工：

| 阶段 | 谁做 | 目标 |
|:---|:---|:---|
| A. 定位 chain 数据 | injector | 从 payload FILE mmap 找 `LC_DYLD_CHAINED_FIXUPS` blob 位置 |
| B. 定位 arm64e slice | injector | fat binary 里选对 CPU subtype |
| C. 遍历 chain 每个 slot | injector | 解析 rawFixup 位编码，判断 rebase/bind × auth/plain |
| D. 解析 bind 目标 | injector | `dlsym(RTLD_DEFAULT, symbolName)` + `ptrauth_strip`（injector 里的目标地址 = target 里的目标地址，因 shared cache slide 跨进程一致） |
| E. 解析 rebase 目标 | injector | `payloadRemoteBase + targetOffset` |
| F. 序列化到 `MIRemapFixupEntry` | injector | 保留 `flags`（key + auth + addrDiv）、`diversity`、`slotOffsetInPayload`、`rawTargetAddress` |
| G. `mach_vm_write` worklist 到 target | injector | 交给 target 里的 apply_fixups 用 |
| H. `apply_fixups(base, entries, count)` | target（raw mach thread） | 遍历 entries，签或直写 slot |

**关键 invariant**（写错就崩）：**Injector 必须从 payload 的文件 mmap 读 chain 数据，不能从 dlopen 后的 image 读**。理由：injector 里 `dlopen(payloadPath)` 之后，dyld 会把 payload 的 `__DATA_CONST` / `__AUTH_CONST` 里所有 chain slot 都改写成 fixup 后的（签好的）指针。这时候读 chain 拿到的是签好的指针值，chain walker 一走 `next` bits 就跳飞。文件 mmap 保留的是链接器原始输出的 chain 编码，是 chain walker 唯一能正确解析的数据源。

## `DYLD_CHAINED_PTR_ARM64E_USERLAND24`（format 12）位编码

这是 arm64e macOS 应用 / 框架的标准 chained pointer 格式，是我们**唯一支持**的格式。其他格式（`DYLD_CHAINED_PTR_64_OFFSET`，`DYLD_CHAINED_PTR_ARM64E_KERNEL`，……）在 `ParseChainedFixups` 里被 skip（`if (segInfo->pointer_format != DYLD_CHAINED_PTR_ARM64E_USERLAND24) continue;`）。

每个 chain node 是一个 `uint64_t`，stride = 8 字节。位编码分四种：

### 四种 slot 的位布局

```
bit index:  63    62    61-51                    ...
            ┌─────┬─────┬────────────────────────
            │auth │bind │next (11 bits)          │
            └─────┴─────┴────────────────────────
```

**判定优先级**：先看 bit 63 (auth) 和 bit 62 (bind)：

```
auth  bind  slot type
─────────────────────
  0    0   plain rebase   ← 本 image 内地址，明文
  0    1   plain bind     ← 外部符号，明文
  1    0   auth rebase    ← 本 image 内地址，PAC 签名
  1    1   auth bind      ← 外部符号，PAC 签名
```

`next` 字段（11 位）表示"下一个 chain 节点距离本节点的 stride 倍数"。`next == 0` 表示 chain 结束。

### Plain rebase（bit 63=0, bit 62=0）

```
bit index:  63    62   61-51                 50-43       42-0
            ┌────┬────┬────────────────────┬────────┬──────────────┐
            │ 0  │ 0  │ next               │ high8  │ targetOffset │
            └────┴────┴────────────────────┴────────┴──────────────┘
```

- `targetOffset`（43 位）：相对 payload `__TEXT.vmaddr` 的偏移
- `high8`（8 位）：目标指针最高字节的 tag（保留在最终指针的 bits 55-63，用作 ObjC tagged pointer 之类）
- 解析出的 `rawTargetAddress = payloadRemoteBase + targetOffset`，然后 `if (high8) resolved |= ((uint64_t)high8 << 56);`
- `flags = 0`（auth=0, addrDiv=0, key=0）

对应代码：`MIMachInjectorRemap.m:777-785`

### Auth rebase（bit 63=1, bit 62=0）

```
bit index:  63    62   61-51            50-49    48       47-32          31-0
            ┌────┬────┬─────────────────┬────────┬────────┬──────────────┬──────────────┐
            │ 1  │ 0  │ next            │ key    │addrDiv │ diversity    │ targetOffset │
            └────┴────┴─────────────────┴────────┴────────┴──────────────┴──────────────┘
```

- `targetOffset`（32 位）：相对 payload `__TEXT.vmaddr` 的偏移（注意只有 32 位，因为 auth 版没有 high8）
- `diversity`（16 位）：PAC discriminator
- `addrDiv`（1 位）：是否把 slot address 混进 discriminator
- `key`（2 位）：`00`=IA, `01`=IB, `10`=DA, `11`=DB
- 解析出的 `rawTargetAddress = payloadRemoteBase + targetOffset`
- `flags = MI_FIXUP_FLAG_AUTH | key | (addrDiv ? MI_FIXUP_FLAG_ADDR_DIV : 0)`
- `entry.diversity = diversity`

对应代码：`MIMachInjectorRemap.m:767-775`

### Plain bind (bit 63=0, bit 62=1)（也叫 bind24）

```
bit index:  63    62   61-51            50-32                 31-24  23-0
            ┌────┬────┬─────────────────┬─────────────────────┬──────┬──────────┐
            │ 0  │ 1  │ next            │ addend (19-bit sign)│ 0    │ ordinal  │
            └────┴────┴─────────────────┴─────────────────────┴──────┴──────────┘
```

- `ordinal`（24 位）：`fixupsHeader->imports` 表的下标
- `addend`（19 位，signed）：从解析后的 target 地址上加多少（一般是 0 或小整数）
- `bit 24-31` 保留为 0
- 解析流程：`targetAddress = ResolveBindImport(fixupsHeader, ordinal)`，再 `rawTargetAddress = targetAddress + sign_extend(addend)`
- `flags = 0`

对应代码：`MIMachInjectorRemap.m:759-765`

**sign extend addend 的细节**：19 位有符号数，bit 18 是符号位。代码：
```c
int32_t addend = (int32_t)((rawFixup >> 32) & 0x7FFFF);
if (addend & 0x40000) addend |= (int32_t)0xFFF80000;
```

### Auth bind（bit 63=1, bit 62=1）

```
bit index:  63    62   61-51            50-49    48       47-32          31-24   23-0
            ┌────┬────┬─────────────────┬────────┬────────┬──────────────┬───────┬──────────┐
            │ 1  │ 1  │ next            │ key    │addrDiv │ diversity    │ 0     │ ordinal  │
            └────┴────┴─────────────────┴────────┴────────┴──────────────┴───────┴──────────┘
```

- `ordinal`（24 位）：同 plain bind
- `diversity` / `addrDiv` / `key`：同 auth rebase
- 无 addend（auth bind 不支持 addend）
- 解析流程：`targetAddress = ResolveBindImport(fixupsHeader, ordinal)`，`rawTargetAddress = targetAddress`
- `flags = MI_FIXUP_FLAG_AUTH | key | (addrDiv ? MI_FIXUP_FLAG_ADDR_DIV : 0)`
- `entry.diversity = diversity`

对应代码：`MIMachInjectorRemap.m:751-758`

## `MIRemapFixupEntry` 序列化格式

`ParseChainedFixups` 把每个 slot 序列化成：

```c
typedef struct {
    uint32_t slotOffsetInPayload;   // slot 相对 payload __TEXT 起始的字节偏移
    uint32_t flags;                 // 见下
    uint64_t rawTargetAddress;      // rebase: payloadRemoteBase + off
                                    // bind:   ptrauth_strip(dlsym result)
    uint16_t diversity;             // 16-bit PAC discriminator
    uint16_t _pad0;
    uint32_t _pad1;
} MIRemapFixupEntry;
```

`flags` 位编码：

| bits | mask | 含义 |
|:-|:-|:-|
| 0-1 | `MI_FIXUP_FLAG_KEY_MASK = 0x03` | PAC key：0=IA, 1=IB, 2=DA, 3=DB |
| 2 | `MI_FIXUP_FLAG_AUTH = 0x04` | 是否 auth slot |
| 3 | `MI_FIXUP_FLAG_ADDR_DIV = 0x08` | 是否 address diversify |

**结构体大小**：sizeof = 24 字节（4+4+8+2+2+4）。`_pad0` / `_pad1` 是为了让每个 entry 大小对齐 8 字节，便于 mach_vm_write 的 chunk 计算 + 便于将来加字段不破坏 layout。

**layout 约束**：这个结构必须 layout-identical 在两处代码里：
- `Sources/MachInjector/MIMachInjectorRemap.m` 里 `typedef struct { ... } MIRemapFixupEntry;`
- `Sources/MachInjector/loader_arm64_remap_fixup.c` 里 `struct MIRemapFixupEntry { ... };`

改动其中一处**必须**同步改另一处，否则 injector 序列化的 entry 到了 target 里字段错位。

## `MIRemapFixupEntry[]` 生命周期

```
injector 侧:
  malloc(cap * sizeof(MIRemapFixupEntry))      ← 首次分配 cap=4096
  循环 realloc(cap*2) when count == cap        ← 边走 chain 边扩容
  mach_vm_allocate(target, worklistRemote, size, VM_FLAGS_ANYWHERE)
  mach_vm_write(target, worklistRemote, entries, size)
  free(entries)                                 ← injector 侧释放
```

- 分配容量策略：4096 起，`realloc(cap*2)` doubling，实测 RuntimeViewerServer.framework 会产出 ~29k 条 entry
- **不 dedupe** —— chain 里每个 slot 都产生一条 entry。dyld 也是这么做的
- `fixupWorklistRemote` 一旦 `mach_vm_write` 完就与 injector 无关；target 里 apply_fixups 消费完也不 free（用一次就丢，target 里 mach_vm_deallocate 得等 injector 特意 clean up——目前不做，反正 target 一般 24×7 常驻，这个 leak 是 bounded 的一小块，大约 700KB 数量级）

## `apply_fixups`（target 侧）

```c
void apply_fixups(uint64_t payloadBase,
                  const struct MIRemapFixupEntry *entries,
                  uint32_t count);
```

**约束**（写错就崩）：
- 只能用 `__builtin_ptrauth_*` intrinsic + 纯算术。任何外部 symbol call 都会 blow up——GOT 里的函数指针正是我们要 fix 的东西，first call 就 auth failure；
- 编译时 `-fno-stack-protector`：raw mach thread 没 TLS，`__stack_chk_guard` 访问会 trap；
- 编译时 `-fno-builtin -ffreestanding`：防止 clang 把 loop 优化成 `memset`/`memcpy` 之类的 library call。

具体算法（`loader_arm64_remap_fixup.c:46-97`）：

```c
for (index = 0; index < count; ++index) {
    entry = &entries[index];
    slotAddress = payloadBase + entry->slotOffsetInPayload;
    slot = (uint64_t *)slotAddress;
    rawTarget = entry->rawTargetAddress;

    if (entry->flags & MI_FIXUP_FLAG_AUTH) {
        modifier = entry->diversity;
        if (entry->flags & MI_FIXUP_FLAG_ADDR_DIV) {
            modifier = blend_discriminator(slotAddress, entry->diversity);
        }
        key = entry->flags & MI_FIXUP_FLAG_KEY_MASK;
        signedPointer = switch (key):
            case 0: sign_unauthenticated(rawTarget, IA, modifier)
            case 1: sign_unauthenticated(rawTarget, IB, modifier)
            case 2: sign_unauthenticated(rawTarget, DA, modifier)
            case 3: sign_unauthenticated(rawTarget, DB, modifier)
        *slot = (uint64_t)signedPointer;
    } else {
        *slot = rawTarget;
    }
}
```

**Modifier 计算细节**：
- `addrDiv == 0`：`modifier = diversity`（just a 16-bit constant）
- `addrDiv == 1`：`modifier = blend(slotAddress, diversity)` = 用 `movk` 把 diversity 塞进 slotAddress 的 bits 48-63

**为什么用 `slotAddress` 而不是 `slotOffsetInPayload`**：blend discriminator 的意义是把"slot 存放的位置"作为签名 modifier 的一部分，这样即使攻击者复制一个签好的指针到别的 slot 里，签名也不匹配。所以必须用 slot 的实际 runtime 地址（=`payloadBase + slotOffsetInPayload`），不是 link-time 偏移。

## `ResolveBindImport` 深入

对 bind slot，我们要在 injector 里 `dlsym` 找到目标地址：

```c
static uint64_t ResolveBindImport(fixupsHeader, ordinal, *outWeak);
```

流程：

1. 从 `fixupsHeader->imports_offset` 找 imports 表；
2. 用 `ordinal` 索引到对应的 import entry；
3. 根据 `fixupsHeader->imports_format` 分派：
   - `DYLD_CHAINED_IMPORT`：small entry（8 字节），无 addend；
   - `DYLD_CHAINED_IMPORT_ADDEND`：带 32 位 addend（我们**不用** entry 里的 addend，用 chain slot 里的 19 位 addend）；
   - `DYLD_CHAINED_IMPORT_ADDEND64`：带 64 位 addend（同上不用）。
4. 从 entry 里拿 `name_offset`，去 `fixupsHeader->symbols_offset` 找符号名 C-string；
5. 符号名去头下划线（Mach-O 里符号名是 `_symname`，`dlsym` 要 `symname`）；
6. `dlsym(RTLD_DEFAULT, symname)` —— 因为 injector 已经 `dlopen` 了 payload，payload 依赖的所有 dylib 都已经在 injector 里加载，`RTLD_DEFAULT` 能看到所有；
7. `ptrauth_strip(result, ptrauth_key_function_pointer)` —— data 指针 strip 是 no-op（upper bits 已经是 0），function 指针 strip 才有用；
8. 返回 raw address。

**跨进程可用性保证**：injector 里 `dlsym` 拿到的地址在 target 里能直接用，因为——**arm64e 同一次 boot 里 shared cache slide 跨进程一致**。libSystem / libobjc / libswiftCore / libdyld 这些常用 dylib 在 injector 和 target 里映射到**同一个虚拟地址**。所以 `dlsym` in injector = 目标地址 in target。可以用 `vmmap $(pgrep -x <daemon>) | grep libswiftCore` 交叉验证。

## `ParseChainedFixups` 主循环细节

```c
for (segIndex = 0; segIndex < startsInImage->seg_count; ++segIndex) {
    segInfoOffset = startsInImage->seg_info_offset[segIndex];
    if (segInfoOffset == 0) continue;                 // 该段无 fixup

    segInfo = ...;
    if (segInfo->pointer_format != DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
        continue;                                     // 只支持这一个格式
    }
    stride = 8;

    for (page = 0; page < segInfo->page_count; ++page) {
        pageStart = segInfo->page_start[page];
        if (pageStart == DYLD_CHAINED_PTR_START_NONE) continue;

        chainStartInSegment = page * segInfo->page_size + pageStart;
        chainCursor = sliceBase + segInfo->segment_offset + chainStartInSegment;

        while (1) {
            memcpy(&rawFixup, chainCursor, 8);        // 读一个 8-byte slot
            next = (rawFixup >> 51) & 0x7FF;
            isBind = (rawFixup >> 62) & 0x1;
            isAuth = (rawFixup >> 63) & 0x1;

            entry.slotOffsetInPayload = chainCursor - sliceBase;
            ... 按四种情况填 entry ...
            entries[count++] = entry;

            if (next == 0) break;                     // chain 结束
            chainCursor += next * stride;
        }
    }
}
```

**page 概念**：一个 segment 被 dyld 按 `page_size`（一般 16KB on Apple Silicon）划分。每个 page 里 chain 独立起点（`page_start[page]`），如果 page 里没有 fixup 就是 `DYLD_CHAINED_PTR_START_NONE = 0xFFFF`。这样设计的动机是让 dyld 可以并行、按 page 分片处理。

**stride = 8**：`DYLD_CHAINED_PTR_ARM64E_USERLAND24` 定死每个 chain 节点占 8 字节。`next` 是"下一个节点距离当前节点多少个 stride"，所以下一个 cursor = `current + next * 8`。

**segment_offset**：dyld 语义里是"该 segment 在**映像**中的起始偏移"。对典型 dylib，`fileoff == vmaddr`（identity mapping），所以这个字段既是文件偏移也是 vmaddr 偏移。我们用文件 mmap，所以 `sliceBase + segInfo->segment_offset` 就是 segment 起点。

## Fat binary 处理：`FindMachOSliceOffset`

payload 可能是 arm64e-only thin binary，也可能是 arm64+arm64e 的 fat binary。我们只关心 arm64e slice。

支持的 magic：
- `MH_MAGIC_64` / `MH_CIGAM_64`：thin arm64/arm64e，验 `cputype` 匹配后返回 offset 0
- `MH_MAGIC` / `MH_CIGAM`：thin 32-bit，arm64e 用不上，直接返回 -1
- `FAT_CIGAM`：32-bit fat header，遍历 `fat_arch[]`，找 cputype+cpusubtype 匹配的 slice
- `FAT_CIGAM_64`：64-bit fat header（超大 dylib 用），同上但用 `fat_arch_64[]`

**cpusubtype 匹配**：忽略 `CPU_SUBTYPE_MASK` 高位（capabilities bits），只比 base subtype。这样带 `PTRAUTH_ABI_MASK` 之类的 tag 不会导致 mismatch。

## Diagnostic 日志

Injector 侧诊断日志集中在 `os_log_debug(MIRemapDiagLog(), "MIRemap.diag ...")`，subsystem 是 `com.mxiris.machinjector.remap`。开启：

```
log stream --predicate 'subsystem == "com.mxiris.machinjector.remap"' --level debug
```

fixup 相关日志一览：

- `fixup_parse count=%u payloadBase=0x%llx span=0x%llx auth_bind=%u auth_rebase=%u plain_bind=%u plain_rebase=%u`
  - 4 类 slot 分别有多少条。常见分布（RuntimeViewerServer arm64e）：`auth_bind ~1500, auth_rebase ~2500, plain_bind ~800, plain_rebase ~24000`
- `first_plain_rebase index=%u slot=0x%x target=0x%llx (payloadOff=0x%llx)`
  - 首个 plain rebase 采样。这个 slot 通常是 `__objc_selrefs` 里第一项，`payloadOff` 应该指向 `__objc_methname` 里的 C-string
- `fixup_tail[%u] slot=0x%x target=0x%llx flags=0x%x div=0x%x`
  - 最后 4 条 entry 采样。用来看看 chain 有没有正常收尾

如果计数完全为 0，说明 `LC_DYLD_CHAINED_FIXUPS` 没找到或 slice 挑错了；ParseChainedFixups 返回的 error message 会解释原因。

## 出错 patterns

**症状：`unrecognized selector sent to class` 在 payload 里**  
→ 检查 `plain_rebase` 计数：一般 `__objc_selrefs` 走 plain rebase 到 `__objc_methname` string，如果全 0 说明 fixup 完全没做。可能：worklist 没 mach_vm_write 成功；loader dylib 里 `apply_fixups` 版本不对（symbol 不存在会让 stage1 asm 里 bl 崩掉，但如果 loader 里被 stub 掉，行为会更诡异）。

**症状：payload 里 call 一个 external symbol 时 `EXC_BAD_ACCESS`**  
→ 检查 `auth_bind` 计数：如果 0，说明 bind 一个都没解析出，那 payload 每个外部 call 都是 nonsense。可能：`fixupsHeader->imports_format` 是我们没处理的类型（当前支持 0/1/2）；或者 injector 里 `dlsym` 失败（bind target 被 skip，slot 保留 0，call 崩在 NULL）。

**症状：payload 起来后一段时间就死，PC 在很奇怪的位置**  
→ auth slot 的 modifier 算错了。常见：`addrDiv=1` 时忘了 blend 到 slot address，或 blend 用了 `slotOffset` 而不是 `slotAddress`。也可能是 `key` 位分派错（IA vs IB）。看 `fixup_tail` 里 flags 是不是符合预期。

**症状：不同 payload 之间行为不一样**  
→ 检查 `pointer_format`：如果 payload 是 arm64 slice（不是 arm64e），格式是 `DYLD_CHAINED_PTR_64_OFFSET` 而不是 `USERLAND24`，我们会 skip 那个 segment。arm64 payload 塞到 arm64e daemon 里理论上 vec 也可以工作（因为 arm64e 兼容 arm64 code），但 fixup 处理路径完全不同。目前 arm64e 是唯一验证过的路径。

## 未来扩展方向

- **支持更多 pointer_format**：`DYLD_CHAINED_PTR_ARM64E_FIRMWARE` / `_KERNEL` 用不上（那是 kext / iBoot 场景）；`DYLD_CHAINED_PTR_64_OFFSET` 是 arm64 slice 格式，可以加，但需要对应的 non-PAC apply_fixups path；
- **imports_format 3+**：dyld 后续版本可能加新格式，届时 `ParseChainedFixups` 的 switch 要跟；
- **weak import 的正确处理**：当前 weak import fail 时 slot 保留 0，payload 触到会 NULL deref。可以考虑 fall through 到 sentinel 值让 payload 主动 check；
- **worklist 序列化紧凑化**：目前 24 字节/entry，其中 `_pad0/_pad1` 8 字节浪费。如果 fixup 数超过 100k 级，值得压。

## 相关

- 位编码参考：`<mach-o/fixup-chains.h>`（Apple 头文件）
- dyld 侧实现：`dyld/Fixups.cpp` 中的 `fixupPage64bit` / `fixupPointerAuth64` 系列
- `MIMachInjectorRemap.m:429-800`（`ParseChainedFixups` 及其 helpers）
- `loader_arm64_remap_fixup.c`（99 行，`apply_fixups` 全体）
- 总体架构：[`RemapArchitecture.md`](RemapArchitecture.md)
- PAC 备忘：[`PACHandbookForRemap.md`](PACHandbookForRemap.md)
