# 0001 - Remap 前把 payload 可写段恢复为文件原始内容

- **状态**: Implemented
- **作者**: JH
- **创建日期**: 2026-08-10
- **最后更新**: 2026-08-10
- **所属愿景**: 无
- **关联提案**: 无
- **实现分支 / PR**: main（与本提案同批次提交）
- **配套文档**: [注入器运行时脏状态 —— 以及为什么它伪装成 PAC bug](../Internal/InjectorRuntimeDirtyState.md)

## 摘要

`MIMachInjectorRemap` 目前把**注入器进程里 `dlopen` 之后**的 payload 镜像整段 `mach_vm_remap`
进目标。这份镜像不只被 dyld 应用过 fixup，还被 Swift / Objective-C 运行时**写入过运行时状态**
（泛型元数据缓存、`swift_once` 标志、已 realize 的 class 记录等）。这些状态不在
`LC_DYLD_CHAINED_FIXUPS` 覆盖范围内，`apply_fixups()` 永远不会纠正它们，于是注入器进程的
私有指针被原样搬进目标，payload 一读就崩。

本提案在注入管线中新增一步：remap 之后、`apply_fixups()` 之前，把 payload 的可写段
（`__DATA_CONST` / `__DATA` / `__AUTH_CONST` / `__AUTH`）用**payload 文件里的原始字节**覆盖回去，
`filesize` 之外的 zerofill 尾部清零。目标里的 payload 由此等价于「刚映射完、dyld 还没跑」，
随后 `apply_fixups()` 重写全部 fixup 槽。

## 动机

一个真实崩溃：向 Finder（pid 564）注入一个 Swift payload，走 `dlopen` 路径完全正常，
走 `MIMachInjectorRemap` 必崩，且崩在 payload 的第一条日志之前。

崩溃报告 `~/Library/Logs/DiagnosticReports/Finder-2026-08-10-140148.ips`：

```
EXC_BAD_ACCESS (SIGSEGV)
KERN_INVALID_ADDRESS at 0x0020000183fe3d98 -> 0x0000000183fe3d98
  (possible pointer authentication failure)
esr: (Data Abort) byte read Translation fault
```

表象是 PAC 认证失败 —— 指针值合法（落在 Foundation 的映射范围内），只有 bit 53 被置位。
这个表象极具误导性：它看起来像 `loader_arm64_remap_fixup.c` 的签名逻辑写错了 key 或
discriminator，而实际上**签名逻辑完全正确**（见「前期调研」的逐槽比对）。

真正的因果链是：注入器进程 `dlopen` payload 时，Swift 运行时把一个泛型元数据指针写进了
payload `__DATA` 里的一个缓存字。该字在文件里是全 0，不是任何 fixup 的目标，因此
`apply_fixups()` 不会碰它。remap 把它连同注入器的私有指针一起搬进 Finder，Finder 里的
payload 读到后直接当作元数据使用，取 value witness table 时认证失败。

这不是回归，是 remap 路径自 `9e064f3`（引入该路径的提交）起就存在的架构缺陷。
[`Design/RemapArchitecture.md`](../Design/RemapArchitecture.md) 已经注意到「不能从 dlopen 后的
镜像读 chain 数据，因为 dyld 已经改写过它」，但没有注意到对称的另一半：**被 remap 搬走的正是
那份被改写过、而且被运行时写脏过的镜像**。

## 前期调研

**验证环境**（本项目 README 要求交代）：macOS 26.5.2 (25F84)，Apple M1 Max，arm64e，
SIP disabled，`boot-args` 只有 `-arm64e_preview_abi`。目标为 Finder 1828.5.2（平台 arm64e
二进制）。payload 为第三方 Swift 动态库框架，fat `x86_64 arm64 arm64e`，链 Foundation /
AppKit / OSLog。崩溃报告与 payload 二进制均取自同一台机器的同一次崩溃，非构造场景。

### 现状代码怎么走的

- `Sources/MachInjector/MIMachInjectorRemap.m:991` —— 注入器 `dlopen(payloadPath, RTLD_NOW | RTLD_LOCAL)`，
  目的只是拿 mach-header 布局与 entry symbol 偏移。
- `Sources/MachInjector/MIMachInjectorRemap.m:1077` —— `RemapSegments()` 把**这份已加载镜像**的
  各段 `mach_vm_remap` 进目标。搬的是注入器的 VM，不是文件。
- `Sources/MachInjector/MIMachInjectorRemap.m:1096-1109` —— 把 `__DATA_CONST` / `__DATA` /
  `__AUTH_CONST` / `__AUTH` 在目标里改成 `VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY`。
- `Sources/MachInjector/MIMachInjectorRemap.m:684` `ParseChainedFixups()` —— 从 payload **文件**
  mmap 读原始 chain（这一步是对的），产出 `MIRemapFixupEntry[]`。
- `Sources/MachInjector/loader_arm64_remap_fixup.c:62` `apply_fixups()` —— 在目标里逐条重写，
  auth 槽用目标的 PAC 密钥重签。

关键在于：`apply_fixups()` 的工作范围**恰好等于** chained fixups 的槽集合。凡是运行时写入而非
链接期决定的字，都在它的射程之外。

### 崩溃点的精确定位

从崩溃报告的 `instructionByteStream` 反汇编出崩溃现场（payload `__TEXT+0x2c98`）：

```
2c70: adrp x0, 0x15e000 ; add x0, x0, #0x340     ; cache = __DATA+0x15E340
2c78: adrp x1, 0x129000 ; add x1, x1, #0x6a0     ; mangled type name
2c80: bl   ___swift_instantiateConcreteTypeFromMangledNameV2
2c84: subs x8, x0, #8
2c88: ldur x16, [x0, #-8]                        ; metadata[-1] = value witness table
2c8c: mov  x17, x8
2c90: movk x17, #0x2e3f, lsl #48                 ; Swift value witness table 的 ptrauth schema
2c94: autda x16, x17
2c98: ldr  x8, [x16, #0x40]                      ; 崩溃：读 VWT.size
```

用这 80 字节指令流在 payload 二进制里精确匹配，定位到 `payloadRemoteBase = 0x125fc4000`，
据此符号化整条调用栈：

```
_pthread_start
 → <payload>_payload_remap_entry +0x18
 → <payload>_payload_initialize +0x10
 → PayloadCore.<payload>_payload_initialize() +0x10
 → PayloadCore.Entry.start() +0x1a4              ← 崩溃点
```

`Entry.start()` 开头就要实例化一个泛型类型 —— 这解释了为什么崩溃发生在 payload 的第一条
`os_log` 之前。

编译器生成的 helper 不做任何校验，缓存非零就直接当元数据返回：

```
24c0: ldr x8, [x0]        ; 读 cache
24c8: and x8, x8, #1      ; 低位是「这是 mangled name 而非已解析元数据」的标记
24d0: b.eq slow_path
24e4: cbz x8, slow_path
      ret                 ; 否则直接返回缓存值
```

### 验证过什么

**1. chained-fixup 解析与签名逻辑是清白的（被证伪的假设）。**
最初的怀疑方向是 `ParseChainedFixups()` 漏槽、stride 取错、或 discriminator 算错。
用 Python 完整复刻 `ParseChainedFixups()` 的位字段解码与 chain walking，与
`dyld_info -arch arm64e -fixup_chain_details` 的输出逐槽比对：

```
dyld_info slots: 5396
replica slots  : 5396
missing from replica: 0
extra in replica   : 0
```

**零遗漏零多余。** `DYLD_CHAINED_PTR_ARM64E_USERLAND24` 的 stride 8、各字段位置、
key 编码（0=IA 1=IB 2=DA 3=DB）、`addrDiv` 的 blend 语义全部正确。这条路彻底排除。

顺带核对了段布局：`__TEXT` / `__DATA_CONST` / `__DATA` 的 `vmaddr` 与 `fileoff` 完全相等，
所以 `ParseChainedFixups()` 用 `segment_offset` 充当文件偏移在这三段上成立 ——
但这个等式在整个 payload 上并**不**成立，边界见下面单独一节。

**2. 崩溃的那个字不在 fixup 列表里，文件里是全 0。**

```
0x15e340 in fixup list: False    (相邻的 0x15e000..0x15e138 全都在列表里)
file bytes at __DATA+0x15E340: 0000 0000 0000 0000
```

**3. 一次裸 `dlopen` 就足以写脏它。** 写了个 arm64e 探针程序，只做 `dlopen` 再读该字：

```
payload loaded at 0x105ef4000
  metadata cache (crash site)  __DATA+0x15e340 = 0x00000001edb60cd8   <-- DIRTY
  neighbour cache word         __DATA+0x15e348 = 0x00000001edb618d0   <-- DIRTY
  neighbour cache word         __DATA+0x15e338 = 0x00000001edb61e48   <-- DIRTY
```

`0x1edb60cd8` 落在 libswiftCore 的 `InitialAllocationPool` 内 —— 正是崩溃现场
`x0 = InitialAllocationPool+11608` 所在的那块静态池。

**4. 为什么表现成 PAC 失败。** `InitialAllocationPool` 是 libswiftCore 里的静态数组，
在注入器与目标里**地址相同**（同一份 dyld shared cache，同一 slide），但两个进程的分配进度
不同。目标里那个地址上是另一个对象，`[-8]` 读出来的不是 value witness table
（崩溃报告把它符号化成 `nominal type descriptor for LockedState._Buffer`），用 VWT 的
schema 认证自然失败。**指针值合法、只有 PAC 位错**这一表象由此而来。

**5. 污染面不止一个字。** 同一探针全段扫描，逐字对照文件原始字节与 fixup 覆盖表：

| 段 | 与文件不同、有 fixup 覆盖 | 与文件不同、**无** fixup 覆盖 | zerofill 尾部非零 |
|---|---|---|---|
| `__DATA_CONST` | 3681 | **0** | 0 |
| `__DATA` | 1715 | **168** | **102** |

**270 个字**会被原样搬进目标且无法纠正。崩溃的那个只是最先被读到的一个。

**6. 与 `-arm64e_preview_abi` 无关（被证伪的假设）。** 曾怀疑第三方 arm64e preview ABI
与系统 arm64e ABI 在 ptrauth 细节上分岔。不成立：loader 与 payload 的切片都由**同一个注入器
进程的 `dlopen`** 决定，天然一致；且第 1 条已逐条验证 discriminator 正确。

### 一个已在真实 payload 上失效、但尚未致害的假设

调查过程中顺带查证的，与本提案的修复无关，但会影响将来谁去动 `ParseChainedFixups()`。

崩溃 payload 的 arm64e 段布局（`otool -l` 实测）：

| 段 | vmaddr | vmsize | fileoff | filesize | vmaddr − fileoff | zerofill 尾部 |
|---|---|---|---|---|---|---|
| `__TEXT` | 0x00000000 | 0x150000 | 0x00000000 | 0x150000 | 0 | 0 |
| `__DATA_CONST` | 0x00150000 | 0x00c000 | 0x00150000 | 0x00c000 | 0 | 0 |
| `__DATA` | 0x0015c000 | 0x018000 | 0x0015c000 | 0x008000 | 0 | **65536** |
| `__LINKEDIT` | 0x00174000 | 0x214000 | 0x00164000 | 0x213580 | **65536** | 2688 |

关键在于：**`vmaddr == fileoff` 这个等式在这个 payload 上已经不成立了** —— `__LINKEDIT`
差了 65536 字节，正是被 `__DATA` 的 zerofill 尾部（`vmsize − filesize = 65536`）撑开的。
也就是说这不是「恰好没触发」，而是「已经在触发，只是触发的那个段不承载 fixup」。

代码里有两处涉及这个等式，**结论截然不同**：

- **`FindChainedFixupsHeaderInSlice()`（`MIMachInjectorRemap.m:539`）—— 代码正确，注释错误。**
  它用 `chainedFixupsCmd->dataoff` 索引文件 mmap。`dataoff` 本来就是**文件偏移**，索引文件
  mmap 无条件正确，跟 `vmaddr == fileoff` 毫无关系。但该函数的注释写着「`dataoff` is a file
  offset — same as a slice-relative offset for a Mach-O whose `LC_SEGMENT_64.fileoff` / `vmaddr`
  are identity (typical for dylibs)」，**凭空给出了一个既错误又多余的前提**：这个 payload 的
  `__LINKEDIT` 恰恰不满足 identity（0x174000 vs 0x164000），而代码照样正确。
  实测 `dataoff = 0x164000` 落在 `__LINKEDIT` 的**文件**区间内、落在其 **VM** 区间之外，
  正说明必须按文件偏移理解它。这条注释会让下次维护的人误以为此处藏着一个脆弱假设而去「修」它。

- **`ParseChainedFixups()`（`MIMachInjectorRemap.m:780`）—— 这里才是真正的假设。**
  它用 `segInfo->segment_offset` 索引文件 mmap，而 `segment_offset` 在 dyld 的定义里是
  「offset in memory to start of segment」，是 **VM 偏移**。只有当该段 `vmaddr == fileoff`
  时这样用才对。

因此，判据不是笼统的「payload 的 `vmaddr` 与 `fileoff` 是否相等」，而是：

> **承载 fixup 的段（`__DATA_CONST` / `__DATA` / `__AUTH_CONST` / `__AUTH`）之前，
> 按文件顺序是否存在带 zerofill 尾部（`vmsize > filesize`）的段。**

常规 dylib 里 zerofill 只出现在最后一个数据段，所以它撑开的只有 `__LINKEDIT`，而
`__LINKEDIT` 既不承载 fixup 也不被 `segment_offset` 索引 —— 这就是为什么至今无害。
但这是链接器的习惯，不是 Mach-O 格式的保证。

同样的边界也适用于本提案新增的恢复函数：它必须用各段真实的 `fileoff` / `filesize`
（这正是「详细设计」给 `MIRemapSegment` 加这两个字段的原因），**不得**沿用「用 `vmaddr`
当文件偏移」的写法，否则会把这个既有假设复制到新代码里。

### `__AUTH_CONST` / `__AUTH` 在 macOS 上不是默认产物

第 7b 步的段名白名单包含 `__AUTH_CONST` / `__AUTH`，本提案的恢复动作沿用同一份名单。
但实测表明，**这两个段在 macOS 的 arm64e 二进制上并不默认出现**：

- 崩溃 payload 的 arm64e 切片只有 `__TEXT` / `__DATA_CONST` / `__DATA` / `__LINKEDIT`，
  认证指针全部落在 `__DATA_CONST` 里。
- Finder 自己（系统 arm64e 平台二进制）同样只有这四段（外加 `__PAGEZERO`）。
- 自己编一个 arm64e C++ dylib（含虚函数表、含 `const` 函数指针数组）—— **不产生**
  `__AUTH_CONST`。试过 `-Wl,-fixup_chains` / `-Wl,-init_offsets` / `-Wl,-data_const`，
  均无效。
- 但系统上确实存在带 `__AUTH_CONST` 的 arm64e 二进制（`libsystem_pthread.dylib`、
  `libsystem_kernel.dylib`、`libRPAC.dylib` 等），其 `__AUTH_CONST` 装的是
  `__auth_got` / `__got` / `__data` / `__objc_selrefs` 之类。它们与 Finder 的
  `LC_BUILD_VERSION`（platform 1、minos 26.5、sdk 26.5）完全一致，**差异不来自 SDK 版本**。

可以用显式 section 属性强制产生该段，实测有效：

```c
static void handlerOne(void) {}
static void handlerTwo(void) {}
__attribute__((section("__AUTH_CONST,__auth_ptr"), used, visibility("default")))
void (* const kAuthTable[2])(void) = { handlerOne, handlerTwo };
```

产出的 `__AUTH_CONST` 段 `initprot` 为 `0x3`（R+W），且**确实参与 chained fixups** ——
`dyld_info -fixup_chains` 显示它作为独立的 `seg[]` 条目出现，`pointer_format` 同为
`12 (DYLD_CHAINED_PTR_ARM64E_USERLAND24)`，段内槽为 auth-rebase。

**对本提案的意义**：真实注入验证（落地步骤第 5 步）用的夹具覆盖不到 `__AUTH_CONST` /
`__AUTH`。这个缺口必须显式承认，不能把「Finder 那次过了」当成全覆盖的证据。缓解办法见
「详细设计」对恢复循环的硬性约束，以及落地步骤第 5 步的说明。

### 前人怎么做的

`dlopen` 路径不受此影响：payload 在目标进程里加载，所有运行时状态从一开始就属于目标。
这也解释了为什么同一个 payload 走 `dlopen` 稳定运行、走 remap 必崩 —— 这个 A/B 对照本身
就是根因在「跨进程搬运运行时状态」而不在「PAC 签名」的强证据。

### 一条容易误判的下游观察

下游脚手架项目（`InjectionScaffold`）在文档里把「remap 会先在注入器进程里 `dlopen` 一次
payload，构造函数因此在错误的进程里跑起来」的对策记为「按可执行文件名判断并提前 return」。
`MIMachInjectorRemap.m:990` 里的 `RUNTIMEVIEWERSERVER_SKIP_CONSTRUCTOR` 环境变量是同一思路。

**这类守卫是必要但不充分的**：它能阻止 payload 自己的逻辑在注入器里执行，却阻止不了
Swift / Objective-C 运行时在 `dlopen` 期间写脏 `__DATA` —— 而被搬进目标的正是后者。
本次崩溃的 payload 就带着这样一个守卫，照样崩了。这一点必须在实现说明里点明，否则下游会
据此认定「注入器里那次 `dlopen` 是无害的」而错判。

## 提议方案

在注入管线的第 7b 步（`mach_vm_protect` 放开可写段）之后、第 8 步（写入 fixup 工作列表）之前，
新增一步 **7c：把 payload 的可写段恢复为文件原始内容**。

对 `__DATA_CONST` / `__DATA` / `__AUTH_CONST` / `__AUTH` 中每一个存在的段：

1. `[0, filesize)` 区间：用 payload 文件里该段的原始字节 `mach_vm_write` 覆盖目标；
2. `[filesize, vmsize)` 区间（zerofill 尾部）：写零。

之后 `apply_fixups()` 照常重写全部 fixup 槽。目标里的 payload 镜像由此等价于
「刚按 load command 映射完、dyld 还没开始跑」的状态。

`__TEXT` **不做任何处理**，继续从 `dlopen` 的镜像 remap —— 目标进程有代码签名强制，
映射一段自造的可执行内存会被拒绝，这正是当初必须 `dlopen` 的原因。可写段不涉及执行权限，
不受此约束，可以自由重建。

顺带效果：libobjc 在注入器里 realize 过的 class 状态（`class_rw_t` 指针写在 `__DATA` 的
`__objc_data` 里，同样不是 fixup 槽）也一并被清回未 realize 状态，目标的 `map_images`
因此看到的是它期望的形态。这修掉了一个尚未暴露、但一旦暴露会更难查的隐患。

### 非目标

- **不改 `__TEXT` 的获取方式。** 继续 `dlopen` + remap，理由如上（代码签名强制）。
- **不改 chained-fixup 解析与签名逻辑。** 已逐槽验证正确，本次不动。
- **不解决「payload 构造函数在注入器进程里产生外部副作用」。** 开线程、注册通知、写文件这类
  副作用发生在注入器进程内，本提案的恢复动作只作用于目标里的镜像，管不到注入器自己。
  这是独立问题，需要时另开提案。
- **不修 `ParseChainedFixups()` 把 `segment_offset` 当文件偏移用这一隐含假设。**
  详见「前期调研」中的「一个已在真实 payload 上失效、但尚未致害的假设」。本提案只在自己新增的代码里用
  真实的 `fileoff` / `filesize`，不回头改既有逻辑。
- **不引入公开 API。** 本次改动完全在 `+injectToPID:payloadPath:entrySymbol:error:` 内部。

## 详细设计

### `MIRemapSegment` 新增两个字段

恢复动作需要知道每段在文件里的位置与长度，当前结构没有记录：

```objc
typedef struct {
    char name[16];
    uint64_t localStart;
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;    // 新增：段在 slice 内的文件偏移
    uint64_t filesize;   // 新增：段的文件长度；vmsize - filesize 即 zerofill 尾部
    vm_prot_t initprot;
} MIRemapSegment;
```

`EnumerateSegments()`（`MIMachInjectorRemap.m:190`）在填充时一并记录
`segmentCommand->fileoff` 与 `segmentCommand->filesize`。该函数同时服务于 loader 与 payload，
新增字段对 loader 路径无影响（loader 不做恢复）。

### 恢复函数

```objc
// Overwrite the target's copy of the payload's writable segments with the
// bytes from the payload FILE, zeroing each segment's zerofill tail.
//
// mach_vm_remap hands the target the injector's *running* image: dyld has
// applied its fixups and, worse, the Swift and Objective-C runtimes have
// written process-private state into __DATA (generic metadata caches,
// swift_once flags, realized-class records). None of that is covered by
// LC_DYLD_CHAINED_FIXUPS, so apply_fixups() cannot correct it, and the
// injector's private pointers would be read by the payload in the target.
// Restoring the on-disk bytes puts the target's copy back into the state a
// freshly mapped, never-executed image would have; apply_fixups() then
// rewrites every chained-fixup slot on top.
//
// __TEXT is deliberately not restored: the target enforces code signing, so
// its executable pages must keep coming from the dlopen'd image via
// mach_vm_remap.
static kern_return_t RestoreWritableSegmentsFromFile(mach_port_t target,
                                                     const uint8_t *sliceBase,
                                                     size_t sliceAvailable,
                                                     const MIRemapSegment *segments,
                                                     int segmentCount,
                                                     uint64_t minVmaddr,
                                                     mach_vm_address_t remoteBase,
                                                     NSString **outErrorMessage);
```

判定「可写段」沿用第 7b 步既有的段名白名单（`__DATA_CONST` / `__DATA` / `__AUTH_CONST` /
`__AUTH`），两处共用一个 `SegmentNeedsWritableRestore()` 辅助函数，避免两张名单漂移 ——
第 7b 放开了写权限却没恢复内容，或反过来，都是静默的错误。

**硬性约束：四个段名必须走同一段循环，不得为 `__AUTH_CONST` / `__AUTH` 开任何单独分支。**
理由见「前期调研」中 `__AUTH_CONST` 一节 —— 真实注入验证的夹具里根本没有这两个段，
任何只在 `__AUTH*` 上执行的代码路径都将是**未验证**的。把段名收敛成纯粹的过滤条件、
其余逻辑一视同仁，是让「验证了 `__DATA_CONST` / `__DATA`」这件事能外推到 `__AUTH*` 的
唯一依据。若将来确实需要为 `__AUTH*` 特殊处理，那一刻起就必须补上带 `__AUTH_CONST` 的
第二夹具，不能再靠外推。

zerofill 尾部用一块 `calloc` 的零缓冲分批 `mach_vm_write`（分批以免为 `vmsize` 巨大的段
一次性分配过多内存）。

### 文件映射的复用

`ParseChainedFixups()` 已经在内部 `open` + `mmap` payload 文件并定位 arm64e slice，用完即
`munmap`。恢复动作需要同一份映射。为避免映射两次、以及两处各自解析 fat header 产生分歧，
把「打开 payload 文件 + 定位 slice」抽成一个小的 RAII 式辅助结构，由调用方持有，
`ParseChainedFixups()` 与 `RestoreWritableSegmentsFromFile()` 共用：

```objc
typedef struct {
    int fileDescriptor;      // 已 close，仅保留供诊断
    void *fileMap;           // mmap 基址，调用方负责 munmap
    size_t fileSize;
    const uint8_t *sliceBase; // fileMap + slice offset
    size_t sliceAvailable;    // 从 sliceBase 起可安全读取的字节数
} MIRemapPayloadFileMapping;
```

`sliceAvailable` 用于边界检查：`fileoff + filesize` 超出该值时判为畸形 payload 并报错返回，
而不是越界读注入器自己的内存。

### 管线中的位置

```
 7.  RemapSegments(payload)                    ← 不变
 7b. mach_vm_protect → R+W+COPY                ← 不变
 7c. RestoreWritableSegmentsFromFile()         ← 新增
 8.  ParseChainedFixups() + 写入工作列表         ← 复用 7c 的文件映射
 ...
 12. 起 mach 线程跑 stage1 → apply_fixups()     ← 不变
```

`VM_PROT_COPY` 已在第 7b 步触发 copy-on-write 拆分，因此第 7c 步的写入落在目标的私有副本上，
不会回流污染注入器的 `__DATA_CONST`。

## 替代方案考量

**A. 完全不 `dlopen` payload，自己按 load command 建立映射。**
最彻底 —— payload 的所有段都来自文件，从未被执行过。**否决理由**：`__TEXT` 必须是可执行映射，
而目标进程有代码签名强制，`mach_vm_remap` 一段由注入器自行分配、未经签名验证的可执行内存会被
内核拒绝。当前实现之所以要先 `dlopen`，正是为了借 dyld 建立一个已通过签名验证的可执行映射再
搬走。本提案实际上是方案 A 在**可写段**上的落地 —— 可写段没有这个约束。

**B. 在注入器里识别并逐个清零已知的运行时缓存模式。**
不 `dlopen`、不动管线，只针对性地把泛型元数据缓存等已知位置清零。**否决理由**：需要枚举
Swift / Objective-C 运行时所有会写 `__DATA` 的位置，且这份清单随每个系统版本变化。本次扫描
已发现 270 个受污染的字，分属多种机制；靠模式识别去覆盖它们既不可靠也无法验证。恢复文件原始
内容是**唯一有明确正确性判据**的做法：目标里的字节应当等于「从未运行过」的字节。

**C. 让 payload 作者负责，通过守卫避免在注入器里执行任何代码。**
即现有 `RUNTIMEVIEWERSERVER_SKIP_CONSTRUCTOR` 的思路推广。**否决理由**：见「前期调研」最后
一节 —— 守卫挡不住运行时自身在 `dlopen` 期间写 `__DATA`。本次崩溃的 payload 带着守卫照样崩。
把正确性寄托在每个 payload 作者的配合上，也违背「payload 只需实现 `void *entry(void *)`」
这一既定契约（见 `loader_arm64_remap_handoff.c` 的开头说明）。

**D. `dlopen` 后立刻 `dlclose`，再从文件重建。**
**否决理由**：`MIMachInjectorRemap.m:915-920` 已记录，`dlclose` 会触发 dyld 的卸载路径去
`mprotect` 这些页，而保护位变更会经共享 VM 对象传导进目标，令目标下次触碰共享页时以
`KERN_PROTECTION_FAILURE` 崩溃。三个 handle 故意泄漏正是为此。

## 影响

### 源码兼容性（source compatibility）

**纯新增** —— 不破坏任何现有调用点。

改动全部位于 `MIMachInjectorRemap.m` 的实现内部：`MIRemapSegment` 是文件内静态类型，
`EnumerateSegments()` / `RestoreWritableSegmentsFromFile()` 均为 static 函数。
公开头文件 `include/MIMachInjectorRemap.h` 的 API 签名与 `MIMachInjectorRemapErrorCode`
枚举取值均不变。

行为上是**修复**而非改变契约：此前 payload 在目标里读到注入器的私有状态属于未定义行为，
没有调用方能依赖它。

若为新增的失败路径引入错误码，只在枚举**末尾追加**，不改动既有取值 —— 现有调用方对旧错误码的
`switch` 不受影响。

### ABI 兼容性

不适用 —— 本库以 SPM 源码分发，使用方每次重新编译。

### 下游影响

- 本仓库内：仅 `MachInjector` target。`Example/` 下的示例工程不需要改动。
- 下游仓库：`swift-helper-service` 经由它调用 `MIMachInjectorRemap`；
  `FinderSidebarIconFix` 与 `InjectionScaffold` 生成的项目是实际使用者。
  三者都**不需要改代码**，升级依赖即可 —— 但 `InjectionScaffold` 的文档需要修正
  「守卫即足够」的表述（见「前期调研」最后一节）。

### 文档与示例

- [`Design/RemapArchitecture.md`](../Design/RemapArchitecture.md) —— 数据流图新增 7c 步；
  补上「remap 搬的是注入器的运行时镜像」这一约束。
- [`Design/ChainedFixupsPipeline.md`](../Design/ChainedFixupsPipeline.md) —— 明确
  `apply_fixups()` 的射程边界：它只覆盖 chained-fixup 槽，运行时写入的字不在其中。
- 新增实现说明 `Documentations/Internal/`，记录「PAC 认证失败这一表象为何会指向错误方向」
  的完整推理链 —— 这正是「下次维护会踩、但代码本身看不出来」的决策。
- README 面向使用方，行为修复不改变用法，**不需要更新**。

## API 演进与废弃策略

无 API 变更，不涉及废弃。不需要 semver major 跃迁；作为 bug 修复走 patch 或 minor 版本
（当前最新 tag `0.4.3`）。

## 落地步骤

1. **先写复现测试。** 构造一个 payload，其 `__DATA` 里有一个「`dlopen` 会写脏、且不在
   chained fixups 覆盖范围内」的字（Swift 泛型类型实例化即可触发），断言 remap 进目标后该字
   等于文件原始值。**确认它在修复前失败。**
2. `MIRemapSegment` 增加 `fileoff` / `filesize`，`EnumerateSegments()` 填充之。
   此步单独可编译通过、无行为变化。
3. 抽出 `MIRemapPayloadFileMapping` 与 `SegmentNeedsWritableRestore()`，
   `ParseChainedFixups()` 改为接收现成的映射。行为不变，纯重构。
4. 实现 `RestoreWritableSegmentsFromFile()`，接入管线 7c 步。第 1 步的测试转为通过。
5. 在真实目标上验证：向 Finder 注入触发过本次崩溃的那个 Swift payload，并与 `dlopen` 路径做
   A/B 对照（同一 payload 走 `dlopen` 已稳定运行）。验证夹具与判据由 `FinderSidebarIconFix`
   一侧提供，**三条日志全部出现才算通过**：

   | 日志 | 证明什么 |
   |---|---|
   | `Payload attached to Finder (<pid>)` | 过了泛型元数据实例化那一关 —— 正是本次的崩溃槽 |
   | `Installed 1 hook(s)` | Objective-C 运行时交互正常 |
   | `Refreshed N sidebar cell(s)`，N > 0 | 主线程调度正常，且 payload 能驱动宿主 UI |

   这个夹具对本 bug 是灵敏探针：该 payload 的 `Entry.start()` 开头就实例化泛型类型，
   修复若失效会立刻崩在第一条日志之前。

   **这一步是部分验证，不是全覆盖。** 该夹具（以及 Finder 自己）都只有
   `__TEXT` / `__DATA_CONST` / `__DATA` / `__LINKEDIT`，**没有 `__AUTH_CONST` / `__AUTH`**，
   所以它证明的是 `__DATA_CONST` + `__DATA` 两条路径正确，`__AUTH*` 仍未被真实注入覆盖。
   缺口靠「详细设计」里那条硬性约束（四个段名走同一循环）来承担：既然 `__AUTH*` 不存在
   独立代码路径，验证结果才能外推过去。**记录这一点，是为了防止将来把「Finder 那次过了」
   当成 `__AUTH*` 也验证过的证据。**

   若日后需要真正覆盖 `__AUTH*`，用「前期调研」里那段 `__attribute__((section("__AUTH_CONST,__auth_ptr")))`
   构造第二夹具 —— 已实测该写法能产出真实的 `__AUTH_CONST` 段且参与 chained fixups。
   本次不做，因为在恢复循环无分支的前提下它的边际价值不足以抵掉多维护一个夹具的成本。
6. 修正 `FindChainedFixupsHeaderInSlice()`（`MIMachInjectorRemap.m:539`）的注释：删掉
   「same as a slice-relative offset for a Mach-O whose `fileoff` / `vmaddr` are identity」
   这个错误且多余的前提，改为说明 `dataoff` 本就是文件偏移、索引文件 mmap 无条件正确；
   并在 `ParseChainedFixups()` 里把 `segment_offset` 是 **VM 偏移**、当文件偏移用才是真正
   假设这一点写明，附上判据（承载 fixup 的段之前是否有 zerofill 尾部）。
   **纯注释改动，不改行为**，但必须做 —— 现有注释会把下次维护的人引向错误的那一处。
7. 横向排查：确认 loader dylib 自身的 `__DATA` 不存在同类问题 —— 它的可写内容只有
   `loader_arm64_remap.s` 末尾那几个由注入器显式 `mach_vm_write` 填充的配置槽，
   但必须查证而非假定。
8. 同批次更新「文档与示例」列出的各篇文档，并把提案状态改为 `Implemented`。

**收尾时必须判断两件事**：

- **配套专题文章** —— 倾向于**要写**一篇实现说明：「为什么 PAC 认证失败这一表象会把人引向
  错误方向」以及「`apply_fixups()` 的射程边界」都属于代码本身看不出来的决策。落地时确认并
  登记到头部「配套文档」。
- **新术语** —— 「运行时脏状态」（injector-side runtime dirty state）是本提案引入的说法，
  落地时评估是否值得进项目术语表；若进，`Documentations/Glossary.md` 尚不存在，需一并新建
  并登记进文档索引。

## 决策日志

| 日期 | 变更 | 说明 |
|------|------|------|
| 2026-08-10 | Created as Draft | 起因是 Finder 注入崩溃（`Finder-2026-08-10-140148.ips`）。调查排除了 chained-fixup 解析错误（复刻解析器与 `dyld_info` 逐槽比对 5396/5396 一致）与 `-arm64e_preview_abi` 两个假设，定位到 remap 搬运注入器进程运行时脏状态这一架构缺陷。 |
| 2026-08-10 | Draft → Implemented | 实现落地。**配套文档**：写了实现说明《注入器运行时脏状态》—— 判据是「PAC 认证失败这一表象为何指向错误方向」属于代码本身看不出来的决策，符合「下次维护会踩」的标准。**新术语**：评估「运行时脏状态」后决定**不单独建术语表** —— 该词只在本提案与其实现说明中出现，且已在实现说明标题处解释清楚，为一个词新建 `Glossary.md` 并维护索引不划算；若后续再出现两个以上此类自造词，再一并建表。**验证**：单元测试 6 条全绿（`swift test` 退出码 0），并已确认关键两条在恢复逻辑被临时停用时失败（退出码 1）；真实注入验证（第 5 步）交由 `FinderSidebarIconFix` 一侧执行，结果回报后补记。 |
| 2026-08-10 | 承认第 5 步的验证缺口，并加上恢复循环无分支的硬性约束 | 下游指出验证夹具与 Finder 都没有 `__AUTH_CONST` / `__AUTH` 段。实测确认：macOS 上普通 arm64e dylib（含 C++ 虚表、`const` 函数指针数组）不产生该段，`-Wl,-fixup_chains` 等标志也不触发，必须用显式 section 属性强制；但系统库（`libsystem_pthread` 等）确实有。据此把第 5 步标为部分验证，并把「四个段名走同一循环、不为 `__AUTH*` 开分支」写成详细设计的硬性约束 —— 这是让验证结果能外推到 `__AUTH*` 的唯一依据。 |
| 2026-08-10 | 补充「一个已在真实 payload 上失效、但尚未致害的假设」一节 | 下游（`FinderSidebarIconFix`）实测指出该 payload 的 `__LINKEDIT` 已经 `vmaddr != fileoff`（差 65536，由 `__DATA` 的 zerofill 尾部撑开）。据此把判据从笼统的「等式是否成立」收紧为「承载 fixup 的段之前是否存在带 zerofill 尾部的段」，并查证出 `FindChainedFixupsHeaderInSlice()` 的注释给了一个错误且多余的前提（代码本身正确）。同时把落地步骤第 5 步的验证判据细化为三条具体日志。 |
