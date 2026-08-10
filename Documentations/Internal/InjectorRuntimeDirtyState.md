# 注入器运行时脏状态 —— 以及为什么它伪装成 PAC bug

- **面向读者**：维护 `MIMachInjectorRemap` 的人，尤其是正在查一个「payload 在 target 里崩在
  奇怪地址」的崩溃
- **配套提案**：[0001 - Remap 前把 payload 可写段恢复为文件原始内容](../Evolutions/0001-restore-payload-writable-segments-before-fixups.md)
- **相关代码**：`Sources/MachInjector/MIMachInjectorRemapRestore.c`（步骤 7c），
  `MIMachInjectorRemap.m` 里 7b/7c 两段

## 一句话

remap 搬进 target 的不是 payload 文件，而是 **injector 进程里那份已经被 `dlopen` 跑过的
payload**；它的 `__DATA` 里有一批「运行时写入、而非链接期决定」的字，`apply_fixups()` 够不着，
必须在步骤 7c 用文件字节覆盖回去。

## 为什么这件事值得单独写一篇

因为**症状会把人引向完全错误的地方**，而且引得非常有说服力。这一节是本文的主要价值。

2026-08-10 的一次真实崩溃（向 Finder 注入 Swift payload）：

```
EXC_BAD_ACCESS (SIGSEGV)
KERN_INVALID_ADDRESS at 0x0020000183fe3d98 -> 0x0000000183fe3d98
  (possible pointer authentication failure)
```

指针值**完全合法**（落在 Foundation 的映射范围内），只有 bit 53 被置位 —— 这是没开 FPAC 的
硬件上 PAC 认证失败污染指针的典型特征。崩溃点的指令是：

```
ldur x16, [x0, #-8]      ; 取 value witness table
movk x17, #0x2e3f, lsl #48
autda x16, x17           ; ← 认证失败
ldr  x8, [x16, #0x40]    ; ← SIGSEGV
```

`0x2e3f` 是 Swift value witness table 的 ptrauth discriminator，`autda` 用的是 DA key。
**一切都在说「PAC 签名算错了」**：要么 `loader_arm64_remap_fixup.c` 用错了 key，要么
discriminator 的 blend 算错了，要么第三方 arm64e preview ABI 与系统 arm64e ABI 在 ptrauth
细节上分岔。

**这三条全是错的。** 实际排查结论：

- 用 Python 完整复刻 `ParseChainedFixups` 的位解码与 chain walking，与
  `dyld_info -fixup_chain_details` 逐槽比对：**5396 / 5396 完全一致，零遗漏零多余**。
  key 编码、`addrDiv` 的 blend、stride 8 全部正确。
- 与 `-arm64e_preview_abi` 无关：loader 与 payload 的切片都由**同一个 injector 进程的
  `dlopen`** 决定，天然一致。

真正的原因是：崩溃现场那个指针**根本不该有值**。它来自 payload `__DATA` 里的一个 Swift 泛型
元数据缓存字，injector `dlopen` 时被 Swift runtime 填上了 injector 进程的元数据地址。

而 `__swift_instantiateConcreteTypeFromMangledNameV2` 的实现是：

```
ldr x8, [x0]        ; 读 cache
and x8, x8, #1      ; 低位是「这是 mangled name 而非已解析元数据」的标记
b.eq slow_path
cbz x8, slow_path
ret                 ; 非 0 且低位为 0 → 直接当元数据返回，不做任何校验
```

**缓存非空就直接返回。** 于是 target 里的 payload 拿到 injector 的元数据指针继续跑。

## 为什么值合法、只有 PAC 位错

这是整件事最误导的一环，值得单独说清楚：

`InitialAllocationPool` 是 libswiftCore 里的**静态数组**，在 injector 和 target 里**地址完全相同**
（同一份 dyld shared cache，同一 slide）。但两个进程的分配进度不同 —— 同一个偏移在 target 里
是另一个对象。于是：

- 指针指向的地址**是合法的、已映射的、甚至是有意义的 Swift 元数据区** → 看起来不像野指针
- 但 `[-8]` 处读出的不是 value witness table 而是别的字段（崩溃报告把它符号化成
  `nominal type descriptor for LockedState._Buffer`）
- 用 VWT 的 schema 去 `autda` 它，自然失败

**「指针值合法 + 只有 PAC 位错」这个组合会让人直奔签名算法，而问题根本不在那里。**
下次再遇到这个组合，先问一句：**这个槽本来就该有值吗？**

## 污染面有多大

对崩溃 payload 实测（逐字对照文件原始字节与 fixup 覆盖表）：

| 段 | 与文件不同、有 fixup 覆盖 | 与文件不同、**无** fixup 覆盖 | zerofill 尾部非零 |
|---|---|---|---|
| `__DATA_CONST` | 3681 | **0** | 0 |
| `__DATA` | 1715 | **168** | **102** |

**270 个字**在修复前会被原样搬进 target 且永远不会被纠正。崩溃的那个只是最先被读到的一个。
同类还有 `swift_once` token、Swift 全局变量 storage、libobjc realize 过的 class 状态 ——
后两类如果被 target 的 `map_images` 撞上，症状会比这次更难查。

一个裸 `dlopen`（不跑 payload 任何自有逻辑）就足以写脏它们，实测：

```
payload loaded at 0x105ef4000
  metadata cache  __DATA+0x15e340 = 0x00000001edb60cd8   <-- DIRTY
```

## 一个必须点破的下游误解

下游脚手架（`InjectionScaffold`）曾把「remap 会先在 injector 里 dlopen 一次 payload，构造函数
因此在错误的进程跑起来」的对策记为「按可执行文件名判断并提前 return」；
`MIMachInjectorRemap.m` 里的 `RUNTIMEVIEWERSERVER_SKIP_CONSTRUCTOR` 环境变量是同一思路。

**这类守卫必要但不充分。** 它拦得住 payload 自己的逻辑，拦不住 Swift / ObjC 运行时在 `dlopen`
期间写脏 `__DATA` —— 而被搬进 target 的正是后者。引发本次崩溃的 payload 就带着这样一个守卫。

看到守卫存在就认定「injector 里那次 dlopen 是无害的」，是这条链路上最容易犯的判断错误。

## 与提案的差异

无。实现与提案 0001 的「提议方案」「详细设计」一致：

- `MIRemapSegment` 增加 `fileOffsetInSlice` / `fileBackedSize`
- 抽出 `MIRemapPayloadFileMapping` 供 fixup 解析与恢复共用
- 恢复循环对四个段名一视同仁，`__AUTH*` 无独立分支
- `__TEXT` 不恢复

## 已知边界

- **`__AUTH_CONST` / `__AUTH` 未经真实注入验证。** macOS 上这两个段不是 arm64e 的默认产物
  （payload 和 Finder 都没有），验证夹具覆盖不到。缺口靠「四个段名走同一循环、不开分支」
  这条设计约束承担 —— 见 `MIMachInjectorRemapRestore.c` 里
  `MIRemapSegmentNeedsWritableRestore` 的注释。**若将来要为 `__AUTH*` 特殊处理，必须同时补
  带 `__AUTH_CONST` 的第二夹具**，构造方法见提案 0001。
- **loader dylib 自身不受此问题影响**，已查证：两个切片都是**零 chained fixups、零 imports**，
  `__DATA` 里只有注入器显式 `mach_vm_write` 的配置槽。这是 `-ffreestanding -fno-builtin` +
  不调用任何外部符号的结果。改动 loader 的编译方式时需要重新查证这一点。
- `ParseChainedFixups` 仍然把 `segment_offset`（一个 **VM 偏移**）当文件偏移用。危险条件不是
  「payload 的 `vmaddr == fileoff` 是否成立」（通常不成立），而是「承载 fixup 的段之前是否有
  带 zerofill 尾部的段」。详见该处注释与提案 0001。步骤 7c 的恢复**没有**沿用这个捷径。
