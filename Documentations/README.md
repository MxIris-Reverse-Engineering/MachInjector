# MachInjector 文档索引

代码注入库，核心是 `mach_vm_remap` 注入路径（`MIMachInjectorRemap`）。
**新增或重命名任何文档都必须同步更新这份索引。**

> **项目类型：库（源码分发）**。SPM library product，使用方每次重新编译，
> 无 ABI 约束，但**源码兼容性必须评估**。提案见 [`Evolutions/README.md`](Evolutions/README.md)。

## 阅读顺序

这几篇文档有明确的依赖关系，**从总入口开始读**：

1. [MIMachInjectorRemap 端到端架构](Design/RemapArchitecture.md) —— **总入口**。remap 注入路径的整体设计，
   以及 chained fixups「injector 解析、target 重签」的两半分工。后面几篇都假定你已读过它。

2. 按你要动的部分选读：

   - [Chained Fixups 全链路](Design/ChainedFixupsPipeline.md) —— 前置：已读总入口。
     解析与重签的完整链路。
   - [Loader Dylib 内部构造](Design/LoaderDylibInternals.md) —— 前置：要改
     `loader_arm64_remap.s` / `loader_arm64_remap_fixup.c` / `loader_arm64_remap_handoff.c` 之一。
   - [PAC 备忘（Remap 场景专用）](Design/PACHandbookForRemap.md) —— 前置：要在 injector 或 loader 里
     增改任何 `ptrauth_*` / `__builtin_ptrauth_*` 调用。**arm64e 上改指针签名前必读。**
   - [Strict-Seatbelt Payload Runtime Handoff](Design/StrictSeatbeltPayloadRuntimeHandoff.md) ——
     前置：想理解 loader 里 `pthread_thunk` 为什么存在。严格沙盒下 payload 运行时的交接。
