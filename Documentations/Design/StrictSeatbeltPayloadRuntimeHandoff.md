# Strict-Seatbelt Payload Runtime Handoff

## 面向读者

- 想理解 loader 里 `pthread_thunk` 存在的意义；
- 要改 `perform_runtime_handoff` 的顺序或添加新的 runtime notification；
- 想知道"为什么 payload 只需要实现一个 `void *(*)(void *)` 就够了、之前不是这样的"。

先读 [`RemapArchitecture.md`](RemapArchitecture.md) 拿到整体图，再读这份看 handoff 的具体设计与历史演化。

## 背景

`MIMachInjectorRemap` 用 `mach_vm_remap` 把 payload segment 投射到 target，完全绕过 dyld。dyld 平时在 load time 会：

1. 应用 chained fixups（用 target 的 PAC keys 签指针）；
2. 调 libobjc `map_images`（uniquify `__objc_selrefs`、注册 classes / categories / protocols）；
3. 通过 objc 或 Swift add-image hook 通知 libswiftCore（注册 Swift type metadata / protocols / conformances）；
4. 调 payload 的 `__attribute__((constructor))`；
5. 让 payload 的代码开始跑。

我们**跳过了整个 dyld**，所以 1-4 都要在 target 里手工补上（第 5 步是 `mach_vm_remap` 的直接结果）。第 1 步在 stage1 asm + `apply_fixups` 里完成（详见 [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md)）。第 2-3 步就是本文档主题——**runtime handoff**。第 4 步（constructor）由 payload 自己在 entry 里显式重跑（我们**不代替 payload 做**，因为不同 payload 的 constructor 不一样，且很多"constructor" 只是 Swift `@_cdecl` 的初始化，payload 里 call 一次就行）。

## Handoff 到底做了什么

`perform_runtime_handoff(config)`（在 `loader_arm64_remap_handoff.c` 里）分四步：

**Step 1**：libobjc `map_images(1, &mappedInfo, &markBlock)`
- 传入 payload 的 mach_header + path（`sectionLocationMetadata = NULL`，让 libobjc 走 fallback）
- 传入手搓的 mark block（详见 [`LoaderDylibInternals.md`](LoaderDylibInternals.md) 的 handoff 章节）
- libobjc 干的事：
  - Uniquify `__objc_selrefs`（否则第一个 objc_msgSend 就崩）
  - 注册 payload 里的 classes、categories、protocols
  - 若有 warm Swift add-image hook 已注册，fan-out 通知它（这是 fallback 路径的一部分）

**Step 2**：`swift_registerTypeMetadataRecords(config->swift5TypesBegin, config->swift5TypesEnd)`
- 传入 `__TEXT,__swift5_types` section 的 target-space 范围
- libswiftCore 干的事：把这个范围登记到 `ConcurrentReadableArray<TypeMetadataRecord>`（内部 push_back，无 dedupe）
- **冷 Swift runtime**：这是主注册通道
- **热 Swift runtime**（step 1 已 fan-out 过）：这是冗余但廉价的 push_back

**Step 3**：`swift_registerProtocols(...swift5Protos...)`
- 同理，对 `__TEXT,__swift5_protos` section

**Step 4**：`swift_registerProtocolConformances(...swift5Proto...)`
- 同理，对 `__TEXT,__swift5_proto` section（名字里少个 s 是 dyld / Swift runtime 历史遗留，本该叫 conformances）

## 为什么 handoff 要在 pthread 里，不能在 raw mach thread 里

这条 invariant 踩过深坑，专门写清楚。

**背景**：`MIMachInjectorRemap` 的 stage2 用 `pthread_create_from_mach_thread` 从原始 mach thread 拉起一条 pthread。**raw mach thread 没 TLS**（`TPIDRRO_EL0 = 0`），**pthread 有完整 TLS**。

**libobjc 的 `map_images` 内部依赖**：

- 拿 `runtimeLock`（一个 pthread_mutex_t）
- 第一次调时走 `preopt_init()`，里面有 `dispatch_once`
- 调 `sel_registerNameNoLock`，用 pthread-primitive tables 做 selector cache

这些**在 raw mach thread 上不会立刻崩**，会**静默走错分支**：
- `pthread_mutex_lock` 内部检查 pthread self 是不是当前线程，raw mach thread 上 pthread self 是 garbage，某些 fast path 可能刚好 pass
- `dispatch_once` 用 pthread TLS 存 slow path 状态，raw mach thread 上会认为 "not done yet"，但一次执行完的 state 存不进 TLS，下次再进 dispatch_once 会重复初始化
- `sel_registerNameNoLock` 内部有 pthread-per-thread selector cache，raw mach thread 上 cache lookup 全 miss，逻辑上走 fresh registration，但把 result 存进 cache 时又对不上号

结果：**`map_images` 会正常 return，但 `__objc_selrefs` 里没有一项被 uniquify**。payload 后续跑 Swift Foundation 初始化，触发 `Bundle.main` 相关的 `dispatch_once`，然后 `objc_msgSend(NSBundle, someSelector)`——这个 someSelector 是 payload 里 raw string ptr，不是 uniqued SEL，libobjc dispatch 失败：

```
+[NSBundle (dynamic selector)]: unrecognized selector sent to class 0x1f4484f58
```

崩溃堆栈里全是 Foundation / dispatch，看不出跟 injection 有关。**这个症状离 root cause 十万八千里**——真正的原因是 `map_images` 跑在了错误的线程上下文。

**正解**：stage1 asm 只做 `apply_fixups`（纯 `__builtin_ptrauth_*` intrinsic + 算术，无 TLS 依赖）。所有需要 pthread TLS / mutex / dispatch 的操作**全部推到 pthread 里**由 `pthread_thunk` 完成。

具体 loader 里就是：

```
stage1 (raw mach thread):
  apply_fixups()                                    ← 纯算术，raw thread 上安全
  pthread_create_from_mach_thread(..., pthread_thunk, config)
  spin forever until injector kills us

pthread_thunk (in pthread, has TLS):
  perform_runtime_handoff(config)                   ← libobjc / libswiftCore 依赖的 TLS 都有了
  entry = sign(cfg_pthread_start_addr, IA + 0)
  return entry(config)                              ← tail-call payload entry
```

## Payload contract 变迁史

Runtime handoff 的实现位置换过三次。每次换都对应一次踩坑 → 修复。

### 第一版：Handoff 在 raw mach thread 上（`stage1 asm` 内直接调用）

**做法**：早期 stage1 汇编里 `apply_fixups` 之后直接 `bl map_images`。省一次 pthread bootstrap。

**结果**：上一节描述的静默 selref 失败。`+[NSBundle (dynamic selector)]` 崩，反查半天不知所以。

### 第二版：Handoff 在 payload 的 entry 函数里

**做法**：stage1 asm 只 `apply_fixups` + `pthread_create_from_mach_thread`。start_routine 是 payload 自己的 entry，比如 `runtime_viewer_server_start`。payload 的 entry **手工做完整个 runtime handoff**：
- 复刻 `MIMachInjectorRemapPayloadConfig` 结构（因为 payload 不 include MachInjector.h）
- 复刻 `_dyld_objc_notify_mapped_info` 结构
- 复刻 arm64e block layout
- 手动 `ptrauth_sign_unauthenticated` mark block invoke（还得考虑 double-sign 陷阱）
- 手动 `ptrauth_sign_unauthenticated` 从 injector 传来的 raw function pointer（`map_images`、三个 `swift_register*`）
- 顺序调 `map_images` → `swift_register*`
- 然后 tail-call `swift_initializeRuntimeViewerServer`

**问题**：每个 payload 都要复制粘贴一大堆 ABI 代码，跟 payload 本身的业务无关。Apple 侧任何 ABI 微调（`map_images` signature 加参数、`_dyld_objc_notify_mapped_info` 加字段、Swift register API 数量变化）都要同步改所有 payload。这些是 injection 机制的固有职责，应该由 MachInjector 承担。RuntimeViewerServer 的 `main.m` 一度到 167 行，全部是 ABI dance 代码。

### 第三版（当前）：Handoff 在 loader 的 `pthread_thunk` 里

**做法**：给 loader 加第三份源文件 `loader_arm64_remap_handoff.c`，里面有：
- `pthread_thunk`：pthread 的 start_routine，先做 handoff，再 tail-call payload entry
- `perform_runtime_handoff`：包含所有 mark block signing / map_images call / swift_register\* call 的逻辑
- 各种手搓 struct / signing helper

Stage1 asm 的 `pthread_create_from_mach_thread` 的 start_routine 从 `_cfg_pthread_start_addr` 改成 loader-internal 的 `_pthread_thunk`。`_cfg_pthread_start_addr` 保留，pthread_thunk 从这里读 payload entry 的 raw address，签 IA + 0 后 tail-call。

**Payload contract 现在**：
```c
__attribute__((visibility("default"), used))
void *my_payload_entry(void *arg) {
    (void)arg;              // loader 已经完成 runtime handoff
    my_real_initializer();  // 直接跑业务
    return NULL;
}
```

RuntimeViewerServer 的 `main.m` 从 167 行缩到 48 行。

## 关键设计选择

**选择 1**：`perform_runtime_handoff` 里 `map_images` 在 `swift_register*` 之前

理由：
1. dyld 自己（`DyldRuntimeState.cpp`）就是这个顺序——先 objc mapped3 callback，再 Swift add-image hook；
2. libobjc `map_images` 里会 fan-out 给已注册的 Swift add-image hook（`swift/stdlib/public/runtime/ImageInspectionMachO.cpp:237-249`），所以热 Swift runtime 会通过这条路径自动拿到 payload；
3. 反过来的话，`swift_register*` 会先 push_back 到 `ConcurrentReadableArray`，接着 `map_images` fan-out 时又 push_back 一次—— `ConcurrentReadableArray` 不 dedupe，double push 不 crash 但浪费内存。

**选择 2**：mark block 手搓，不用 `^{...}` 语法

理由（详见 [`LoaderDylibInternals.md`](LoaderDylibInternals.md) 里"为什么 mark block 手搓"）：
- clang block literal 会生成 `_NSConcreteGlobalBlock` 引用（injector 里 fixup 后指向 injector 的 libSystem）；
- descriptor 指针在 clang literal 里是 signed pointer（signed by injector），target 里 auth 失败；
- 手搓的话所有 pointer 在 runtime 里填，没有 injector 侧 fixup 参与。

**选择 3**：block invoke 的签名用 `blend(&invoke, 0)` 作 modifier

理由：clang 默认的 block invoke schema 是 `PointerAuthSchema(ptrauth_key_asia, address_diversify=true, Discrimination::None)`。**address_diversify** 意味着 modifier 里混入 storage 地址；**Discrimination::None** 意味着不加 constant。所以 modifier = `blend(storage_addr, 0)` = `storage_addr` 本身。我们的 storage = 栈上 `markBlock.invoke`，`&markBlock.invoke` 就是那个地址。

**选择 4**：函数指针 R-value 语义先 `strip` 再 sign

`(void *)MIRemapHandoffMarkInvoke` 在 arm64e ABI 下会隐式 `paciza`（sign IA + 0）。如果不 strip 直接进 `sign_unauthenticated`，就是 double sign，target 里 `autia` 会失败。详见 [`PACHandbookForRemap.md`](PACHandbookForRemap.md) "Double-sign 陷阱" 一节。

**选择 5**：pthread_thunk tail-call payload entry

`return entry(arg);` 被 clang `-Oz` 优化成 tail-call（`braaz`）。栈帧不留下，从 pthread_start 视角看，pthread_thunk 直接返回了它调用的 payload entry 的返回值。这样 stack trace 里 pthread_thunk 就消失了，crash log 里看不到我们的 helper。

## 出错排查

**症状：payload 起来立刻崩，PC 在 `_pthread_start` 之后 payload 内部**  
→ pthread_thunk 里 `perform_runtime_handoff` 崩了。debug：改 `perform_runtime_handoff` 里加 `os_log` 输出，看到最后一条日志在哪一步之前。

**症状：注入后 payload 运行一小段时间，第一次 `objc_msgSend` 时崩 `unrecognized selector`**  
→ `map_images` 没成功 uniquify。检查：
  - loader 版本是不是最新（`build_loader.sh` 跑过、`MIMachInjectorRemap.o` 重编过）
  - `sectionLocationMetadata` 是不是 NULL（我们的 fallback path）
  - `flags` 是不是 0

**症状：`__objc_selrefs` 是空的（用 lldb 看）**  
→ 说明 `map_images` 根本没被调用，或者 mark block invoke 签名错。检查 mark block signing 是不是 strip 了、是不是用 `blend(&invoke, 0)` 作 modifier。

**症状：Swift class metadata 找不到**  
→ `swift_registerTypeMetadataRecords` 没被调用。检查 config 里 `swift5TypesBegin` / `swift5TypesEnd` 是不是正确指向 payload `__TEXT,__swift5_types` 范围。可以用 `otool -l` 看 payload 里这个 section 存在且非空。

**症状：Swift Task 起来后崩**  
→ 可能是 Swift protocol conformance 找不到——检查 `swift_registerProtocolConformances` 的 range 是不是对（`__TEXT,__swift5_proto`，不是 `__swift5_protos`）。

## Payload 作者需要注意什么

1. **entry symbol 必须 exported**（`__attribute__((visibility("default"), used))`）。injector 从 payload 里 `dlsym` entry symbol；
2. **entry signature 必须是 `void *(*)(void *)`**。传入 `arg` 是 `MIMachInjectorRemapPayloadConfig *`，多数 payload 可忽略；
3. **entry 里要跑 payload 的初始化逻辑**（`__attribute__((constructor))` 里做的事）。因为 dyld 不跑 constructor，payload 需要自己在 entry 里做一次；
4. **avoid triggering payload constructor in injector**：payload 的 constructor 在 injector 里 `dlopen(payload)` 时会跑一次（injector 只是为了拿 mach-header 和 entry symbol 地址）。给 constructor 加一个 env-var 门（比如 `RUNTIMEVIEWERSERVER_SKIP_CONSTRUCTOR`），让它 skip inject 用的 dlopen 但正常跑其他场景。

## 相关

- [`RemapArchitecture.md`](RemapArchitecture.md) — 端到端总览
- [`LoaderDylibInternals.md`](LoaderDylibInternals.md) — loader dylib 内部构造（包含 handoff 里 mark block、schema 手搓的完整细节）
- [`PACHandbookForRemap.md`](PACHandbookForRemap.md) — PAC 备忘（Double-sign 陷阱 / 三种函数指针 schema 说明在这里）
- [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md) — chained fixup 走完之后才轮到 handoff
