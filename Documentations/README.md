# MachInjector 文档索引

macOS 代码注入库。三条互不相同的注入路径：两条在目标进程里调用 `dlopen`，
一条完全绕开 `dlopen`（`mach_vm_remap` + 手工复刻 dyld 的工作）。

**新增或重命名任何文档都必须同步更新这份索引。**

> **项目类型：库（源码分发）**。SPM library product，使用方每次重新编译，
> 无 ABI 约束，但**源码兼容性必须评估**。提案见 [`Evolutions/README.md`](Evolutions/README.md)。

## 从这里开始

**[三条注入路径 —— 总览与选型](Design/InjectionStrategies.md)** ——
每种注入方式是怎么实现的、何时用哪条、所有路径共同要解决的四个问题
（task port、执行上下文、arm64e 指针签名、沙盒），以及各自的失败模式与平台支持矩阵。
**不确定该读哪篇就先读它。**

## 按路径深入

### dlopen 路径（`MIMachInjector` / `MIMachInjectorAsync`）

- [dlopen 注入路径的实现 —— 同步与异步](Design/DlopenInjectionInternals.md) ——
  两阶段线程（裸 mach 线程 → pthread）为什么必须存在、裸 mach 线程的三个禁忌
  （不能 `ret`、不能 `mach_msg`、不能自己 `thread_terminate`）、shellcode 布局与数据槽、
  结果页/notepad 的发布顺序、异步版让 pthread 反杀 mach 线程的由来、沙盒扩展的能与不能、
  x86_64 差异、排查对照表。

### remap 路径（`MIMachInjectorRemap`）

这条路径要手工复刻 dyld 做的每一件事，所以文档最多。**按顺序读**：

1. [端到端架构](Design/RemapArchitecture.md) —— **总入口**。完整数据流，
   以及 chained fixups「注入器解析、目标重签」的两半分工。后面几篇都假定已读过它。
2. 按要动的部分选读：
   - [Chained Fixups 全链路](Design/ChainedFixupsPipeline.md) —— 重定位的解析与重签，
     以及 `apply_fixups()` 的射程边界（它只管 chained-fixup 槽）。
   - [Loader Dylib 内部构造](Design/LoaderDylibInternals.md) —— 前置：要改
     `loader_arm64_remap.s` / `loader_arm64_remap_fixup.c` / `loader_arm64_remap_handoff.c` 之一。
   - [PAC 备忘（Remap 场景专用）](Design/PACHandbookForRemap.md) —— 前置：要在注入器或 loader 里
     增改任何 `ptrauth_*` / `__builtin_ptrauth_*` 调用。**arm64e 上改指针签名前必读。**
   - [Strict-Seatbelt Payload Runtime Handoff](Design/StrictSeatbeltPayloadRuntimeHandoff.md) ——
     前置：想理解 loader 里 `pthread_thunk` 为什么存在。严格沙盒下 payload 运行时的交接。

## 实现说明（[`Internal/`](Internal/)）

面向维护者，记录「代码本身看不出来、下次维护会踩」的决策。

| 文档 | 覆盖什么 |
|---|---|
| [注入器运行时脏状态 —— 以及为什么它伪装成 PAC bug](Internal/InjectorRuntimeDirtyState.md) | remap 搬进目标的是注入器里**已经跑过**的 payload，`__DATA` 里被 Swift / ObjC 运行时写入的状态不在 chained fixups 覆盖范围内。为什么一个「指针值合法、只有 PAC 位错」的崩溃根因不在签名算法；污染面实测数据（270 个字）；`__AUTH*` 的验证缺口与堵法。**排查 remap 注入的崩溃前先读这篇。** |

## 提案（[`Evolutions/`](Evolutions/README.md)）

状态总表见 [`Evolutions/README.md`](Evolutions/README.md)。

| # | 标题 | 状态 |
|---|---|---|
| [0001](Evolutions/0001-restore-payload-writable-segments-before-fixups.md) | Remap 前把 payload 可写段恢复为文件原始内容 | Implemented |
| [0002](Evolutions/0002-classify-and-publish-injection-error-codes.md) | 把注入失败分类成可判定的错误码，并公开三个 domain 的枚举 | Draft |
