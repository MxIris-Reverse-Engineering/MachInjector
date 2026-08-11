# MIMachInjectorRemap 端到端架构

## 面向读者

这份文档是 remap 注入路径的**总入口**。谁应该读：
- 新接触 MachInjector 想理解 remap 是怎么绕过 `dlopen` 的
- 老 maintainer 回来改代码前想重建整体心智模型
- payload 作者想弄清楚 loader 到底替他做了什么

先读完这份，再按需读 [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md)（chained fixup 深度）/ [`LoaderDylibInternals.md`](LoaderDylibInternals.md)（loader dylib 内部构造）/ [`PACHandbookForRemap.md`](PACHandbookForRemap.md)（arm64e PAC 备忘）。

## 为什么需要 remap 路径

原有两条注入路径（`MIMachInjector` sync / `MIMachInjectorAsync`）都依赖**target 里能跑 `dlopen(payloadPath)`**。这条前提对普通进程成立，对 strict-seatbelt 系统守护进程（`sharingd`、`rapportd` 及其亲戚）**不成立**——它们的 sandbox profile 里明确 `(deny file-map-executable)`（除极少数系统白名单目录）。任何位于用户目录、`/Library/Frameworks` 之下的 payload，`dlopen` 会立刻栽在 dyld 的 `file-map-executable` sandbox check 上。

sandbox extension（`APP_SANDBOX_READ` 之流）**救不了**——它只解锁 `file-read*` predicate，不 touch `file-map-executable`。所以路子只能换。

**remap 路径的思路**：完全绕过 target 里的 `dlopen`。改成——
1. 在 **injector 进程**里 `dlopen` payload 一次，只为了：拿到 mach-header 布局 + 找到 entry symbol 的偏移；
2. 用 `mach_vm_remap` 把 payload 的 `__TEXT` / `__DATA_CONST` / `__DATA` / `__AUTH_CONST` / `__AUTH` 段**从 injector 的 VM 直接投射到 target 的 VM**。这是 Mach 层的 VM-to-VM mapping，绕过 vnode，也就绕过 sandbox 的 `file-map-executable` predicate；
3. 在 target 里跑一段小 shellcode（loader dylib），把 dyld 本该做但被跳过的两件事补上：**apply chained fixups** + **replay libobjc/libswiftCore runtime notifications**；
4. 最后 shellcode tail-call 到 payload 的 entry symbol，payload 从此以为自己是被正常 `dlopen` 进来的。

Xcode 的 `DVTInstrumentsFoundation`（`RemoteInjectionAgent` + `libRemoteInjectionPayload.dylib`）用的是同一套技术——从 Instruments 附着到系统守护进程。

## 顶层数据流

先看一张时序草图，每个矩形是一个进程 / 组件：

```
+------------------- INJECTOR PROCESS -------------------+     +---- TARGET PROCESS ----+
| 0. dlopen(loader.dylib) — 拿 stage1 + 6 个 config 槽    |     |                        |
| 1. dlopen(payload.dylib) — 拿 mach-header + entry addr |     |                        |
| 2. dlopen(libswiftCore) — 拿 swift_register* 3 个 API   |     |                        |
| 3. gAPIs scan — 拿 libobjc map_images                   |     |                        |
| 4. dlsym pthread_create_from_mach_thread                |     |                        |
| 5. task_for_pid → target port                           |     |                        |
| 6. mach_vm_remap(payload segments)                     ────▶│  payload __TEXT/DATA... |
| 7. mach_vm_protect(payload __DATA*, R+W+COPY)          ────▶│  (writable in target)   |
| 7c. 用 payload FILE 的原始字节覆盖 __DATA*，             ────▶│  __DATA* = 文件内容      |
|     zerofill 尾部清零（抹掉 injector dlopen 时           |     |  （像刚映射、没跑过）     |
|     被运行时写脏的状态）                                  |     |                        |
| 8. ParseChainedFixups(payload FILE) → worklist          |     |                        |
| 9. mach_vm_allocate + mach_vm_write(worklist)          ────▶│  fixup 工作表            |
| 10. mach_vm_allocate + mach_vm_write(payload config)   ────▶│  config page            |
| 11. 本地 COW-flip loader __DATA 到 R+W；patch 6 个       |     |                        |
|     __DATA 槽（pthread_create / start / arg / payload_ |     |                        |
|     base / fixup_worklist / fixup_count）               |     |                        |
| 12. mach_vm_remap(loader segments) — __DATA 带着 patch  ────▶│  loader __TEXT + __DATA  |
| 13. mach_vm_allocate(stack, 16KB)                      ────▶│  raw mach thread stack  |
| 14. thread_convert_thread_state — PC = stage1EntryRemote|     |                        |
|     (arm64e-signed IA+0), SP = stack top                |     |                        |
| 15. thread_create_running                              ────▶│  raw mach thread 起!    |
|                                                         |     |                        |
|                                                         |     | ▶ stage1 (in loader): |
|                                                         |     |   Phase 1: apply_fixups|
|                                                         |     |   Phase 2: pthread_    |
|                                                         |     |     create_from_mach_  |
|                                                         |     |     thread(start_      |
|                                                         |     |     routine=pthread_   |
|                                                         |     |     thunk)             |
|                                                         |     |                        |
|                                                         |     | ▶ pthread_thunk:       |
|                                                         |     |   perform_runtime_     |
|                                                         |     |     handoff(config)    |
|                                                         |     |     ├─ map_images(1,   |
|                                                         |     |     │    mappedInfo,   |
|                                                         |     |     │    markBlock)    |
|                                                         |     |     └─ swift_register* |
|                                                         |     |         × 3            |
|                                                         |     |   tail-call payload    |
|                                                         |     |     entry              |
| 16. usleep(2s) 让 pthread bootstrap 完成                 |     |                        |
| 17. thread_terminate(raw mach thread)                  ────▶│  raw mach thread 死!    |
| 18. 返回 YES；三个 dlopen handle 全部 LEAK               |     | payload entry 继续跑    |
+---------------------------------------------------------+     +------------------------+
```

**关键读法**：
- 步骤 0–5 都是 injector 侧准备，不 touch target；
- **步骤 6 搬的是 injector 进程里那份「已经跑过」的 payload**，不是文件 —— dyld 在 injector
  里应用过 fixup，Swift / ObjC 运行时还往 `__DATA` 写过进程私有状态（泛型元数据缓存、
  `swift_once` 标志、已 realize 的 class 记录）。这些都不是 chained-fixup 槽，`apply_fixups()`
  够不着，所以必须靠步骤 7c 用文件字节覆盖回去。缺了这一步，payload 会在 target 里读到
  injector 的指针 —— 详见 [提案 0001](../Evolutions/0001-restore-payload-writable-segments-before-fixups.md)；
- 步骤 6–15 是 injector 用 Mach VM API 把 loader / payload / worklist / config / stack 布置到 target；
- 步骤 15 起 target 里开始跑代码；
- injector 步骤 16–17 只是善后（收原始 mach thread），不影响 payload 的执行；
- 步骤 18 特别要注意：**三个 `dlopen` handle 故意不 close**（原因见下"Handle 泄漏"一节）。

## 三条相关代码单元

remap 路径实际由**四份源文件 + 一份 embedded byte header** 构成：

| 文件 | 运行位置 | 主要职责 |
|:---|:---|:---|
| `Sources/MachInjector/MIMachInjectorRemap.m` | injector 进程 | 编排整个流程；chained fixup 解析；libobjc map_images 定位；`+ injectToPID:...:` 对外 API |
| `Loader/loader_arm64_remap.s` | target 进程（raw mach thread） | stage1 shim；读 6 个 `__DATA` 配置槽；bl `_apply_fixups`；再 bl `pthread_create_from_mach_thread` |
| `Loader/loader_arm64_remap_fixup.c` | target 进程（raw mach thread） | `apply_fixups`：遍历 worklist，用 target PAC keys 重签每个 auth slot |
| `Loader/loader_arm64_remap_handoff.c` | target 进程（**pthread**！有 TLS） | `pthread_thunk` + `perform_runtime_handoff`；调 libobjc `map_images` + 三个 `swift_register*`；tail-call payload entry |
| `Sources/MachInjector/loader_arm64_remap_dylib.h` | build 产物 | 上面三个 loader 源文件编成 fat dylib 后 xxd 出来的字节数组 |

其中 loader 三份是**独立编译成一个 arm64+arm64e 的 fat dylib**，然后 xxd 成 C byte array，链入 `MIMachInjectorRemap.m`。build 步骤见 [`Loader/build_loader.sh`](../../Loader/build_loader.sh)，内部细节见 [`LoaderDylibInternals.md`](LoaderDylibInternals.md)。

## Target 里的"三线程时序"

remap 路径在 target 里会同时出现 3 种执行上下文，弄清楚它们的边界对理解代码至关重要：

**① Target 原有线程**（每个都跟 injection 无关，我们 touch 不到）

**② Raw mach thread**（我们从 injector 通过 `thread_create_running` 拉起来的）
- 由 `thread_create_running` 起，PC 落在 loader 的 `_remap_stage1_entry`
- **没有 TLS**（`TPIDRRO_EL0 = 0`）→ **不能**：调 pthread mutex / dispatch_once / mach MIG 调用 / `ret`（LR = 0）
- **能**：任何纯汇术 / 纯算术 / `mach_msg` 之外的 pthread family 里少数不依赖 TLS 的调用（`pthread_create_from_mach_thread` 是其中之一）
- 由这个线程执行的代码：**stage1 asm** + **`apply_fixups`**（纯 `__builtin_ptrauth_*` 内建 + 算术，绝不 call 任何符号）
- 结束时机：`pthread_create_from_mach_thread` 返回后 spin 在 `b 1b`，等 injector 从外部 `thread_terminate` 掉它

**③ Pthread**（由 raw mach thread 起的 `pthread_thunk`）
- 由 `pthread_create_from_mach_thread(_, _, pthread_thunk, config)` 创建
- **有 TLS**、有真正的 pthread stack、有 dispatch/malloc/os_log/Foundation/Swift 全套 runtime 保证
- 由这个线程执行的代码：**`pthread_thunk`** → **`perform_runtime_handoff`**（调 libobjc `map_images` + 三个 `swift_register*`）→ tail-call **payload entry**（`runtime_viewer_server_start` 或用户的 entry）
- 后续 payload 起 Swift Task / spawn 其他 pthread 都在这条线上 fork 出去

**关键 invariant**（这条搞错就会崩，具体教训见 [`PACHandbookForRemap.md`](PACHandbookForRemap.md) 尾部）：**libobjc `map_images` 只能在 pthread 里跑，不能在 raw mach thread 里跑**。

原因：`map_images` 会拿 `runtimeLock`（pthread mutex）、走 `preopt_init`（内含 `dispatch_once`）、调 `sel_registerNameNoLock`（用 pthread TLS）。raw mach thread 上这些不会立刻崩，会**静默走错分支**——`map_images` 表面上 return 了，但 `__objc_selrefs` 没被 uniquify。payload 后续第一个 `dispatch_once + objc_msgSend`（一般是 Swift Foundation 的 `Bundle.main` init）就会崩成 `+[NSBundle (dynamic selector)]: unrecognized selector`，堆栈里离 root cause 十万八千里，非常难 debug。

这就是为什么 loader 里要塞一个 `pthread_thunk` 拐一下：stage1 里只做 `apply_fixups`（纯算术，无 TLS 依赖），把所有需要 TLS / mutex / dispatch 的动作全都推到 pthread 里由 `pthread_thunk` 完成。

## Injector 里的 4 个"隐性 handle"

`+ injectToPID:...:` 里会 `dlopen` 三个东西 + `task_for_pid` 一个 mach port，它们的生命周期不太符合直觉：

**① loader dylib 的 `dlopen` handle** — **故意不 close**
- 原因：loader 的 `__TEXT` + `__DATA` 已经被 `mach_vm_remap` 到 target（`copy=FALSE`, `VM_INHERIT_SHARE`）。injector 侧 `dlclose(loaderHandle)` 会让 dyld 走 unload path，包括 `mprotect` 那几页回到某个"卸载中"状态。这些 protection 变化**会通过共享 VM object 传播到 target**——下一次 target 里的 loader 代码执行时会 `KERN_PROTECTION_FAILURE`，直接崩 target。所以泄漏。

**② payload dylib 的 `dlopen` handle** — **故意不 close**
- 同上理由，payload 也 `mach_vm_remap` 到 target 了。dlclose 会同样把 protection 改动传染过去。

**③ libswiftCore 的 `dlopen` handle** — **故意不 close**
- 这个不涉及 remap，但 injector 主进程通常 injection 完就退出，close 意义不大；留着更方便同一次 process 里多次 inject。

**④ target 的 mach task port**（`task_for_pid` 拿到的）— 不显式 `mach_port_deallocate`，进程退出时自然释放。

**唯一显式清理的**：loader dylib 落在 `/private/tmp/MIMachInjectorRemap_loader_XXXXXX.dylib` 的临时文件，会 `unlink` 掉——dyld 内部保留 fd，unlink 只是删目录条目，inode 会活到 handle 释放。

## Chained fixup 的两半分工

remap 跳过了 dyld，就要自己补 dyld 会在 load time 做的 chained-fixup 处理。这块非常关键，独立成文：**详见 [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md)**。

这里只说**分工**：
- **injector 侧**（`ParseChainedFixups` in `MIMachInjectorRemap.m`）：
  - 从 payload 的**文件 mmap**（`open()` + `mmap()`）读原始 chain 数据，**不能**从 dlopen 后的 image 读（那里 dyld 已经把 chain slot 改写成签好的指针）；
  - 定位 arm64e slice（fat binary 处理）；
  - 走 `DYLD_CHAINED_PTR_ARM64E_USERLAND24` chain，对每个 slot 生成一个 `MIRemapFixupEntry`：
    - rebase：`rawTargetAddress = payloadRemoteBase + target_offset`
    - bind：`rawTargetAddress = ptrauth_strip(dlsym(RTLD_DEFAULT, symname), fp_key)`
    - 保留 `flags` 里的 auth 位、key 位、addrDiv 位；`diversity` 从 chain 里原样搬
  - `malloc` 一个 `MIRemapFixupEntry[]` 交给下游
- **target 侧**（`apply_fixups` in `loader_arm64_remap_fixup.c`）：
  - 遍历 `entries[]`
  - **auth entry**：`__builtin_ptrauth_sign_unauthenticated(rawTargetAddress, key_asia/asib/asda/asdb, modifier)`——key 用 flags 里的 2 位分派，modifier 用 `blend_discriminator(slotAddress, diversity)`（若 addrDiv=1）或纯 `diversity`（若 addrDiv=0）
  - **plain entry**：直接 `*slot = rawTargetAddress`

**为什么必须两半**：arm64e PAC keys 是**每个进程独立**的（内核在进程创建时随机化）。injector 进程 sign 出来的指针在 target 进程里 `autia` 会失败。所以 injector 只能负责"解析 chain 得到 raw address"，实际的 sign 必须在 target 里完成。

## Runtime handoff 的三步

payload 的 `__objc_selrefs` / `__objc_classlist` / Swift metadata 也需要通知运行时才有效——原本这是 dyld `map_images` callback 的活。remap 跳过了 dyld，就要手工调一遍。

具体在 `loader_arm64_remap_handoff.c` 的 `perform_runtime_handoff`：

**Step 1**：libobjc `map_images(1, &mappedInfo, &markBlock)`
- `mappedInfo` = `_dyld_objc_notify_mapped_info` 一份，指向 payload 的 mach_header + path
- `markBlock` 是一个手搓的 block（**不是** `^{}` 语法），它的 `invoke` 字段按 `PointerAuthSchema(ASIA, addr_diverse, Discrimination::None)` 签名（详见 [`PACHandbookForRemap.md`](PACHandbookForRemap.md)）
- libobjc 拿到这个通知后：**uniquify `__objc_selrefs`**、注册 payload 的 classes / categories / protocols、fan-out 给已注册的 Swift add-image hook

**Step 2**：libswiftCore `swift_registerTypeMetadataRecords(begin, end)`
- 范围来自 payload 的 `__TEXT,__swift5_types` section
- 内部是 `push_back` 到 `ConcurrentReadableArray`（**不 dedupe**）
- 冷 runtime 时这是主注册通道；热 runtime（step 1 已 fan-out 过）时这里就是冗余但廉价的 push_back

**Step 3 + 4**：`swift_registerProtocols` + `swift_registerProtocolConformances`
- 同上，分别对 `__TEXT,__swift5_protos` 和 `__TEXT,__swift5_proto`
- 后者的名字是 dyld / Swift runtime 历史遗留（本该叫 conformances）

**Step 5**：pthread_thunk tail-call `signed(cfg_pthread_start_addr, IA+0)`
- `cfg_pthread_start_addr` 由 injector patch，值是**payload entry 的 raw 地址**（已 strip PAC）
- tail-call 时用 `braaz` — 指针带签名分支

**为什么 map_images 要在 swift_register 之前**：
1. dyld 自己的顺序（`DyldRuntimeState.cpp`）就是先 objc `mapped3` 再 Swift add-image；
2. libobjc `map_images` 内部会 fan-out 到已注册的 Swift add-image hook（`swift/stdlib/public/runtime/ImageInspectionMachO.cpp:237-249`）；
3. 反过来会 double-register `__swift5_types`（不 crash，但浪费）。

## 关键设计决策 & 权衡

**1. 为什么 loader 是独立编译的 dylib，不是 asm shellcode 常量？**

早期 POC 只有 stage1 asm，直接 `xxd` 成常量塞代码。但一旦 stage1 需要 `pthread_create_from_mach_thread(fn_ptr, arg)`——这两个参数是运行时才知道的——就需要**可写的 `__DATA` 配置槽**。asm 常量做不到（要么写入 injector 自己 __TEXT，破坏签名；要么费劲搞 PIE-relative 二次修补）。改成真 dylib 后：
- `__DATA` 段自然可写；
- `adrp+add` 可以从 loader `__TEXT` 编址到 loader `__DATA`（覆盖 ±4GiB，比 `adr` 的 ±1MiB 宽）；
- 在 injector 里通过 COW-flip 直接修改 loader 的 `__DATA`，然后 `mach_vm_remap` 到 target——patch 好的 `__DATA` 顺着 remap 就过去了；
- loader 每个符号可以有 symbol table 项，方便 `dlsym` 拿 stage1 entry / 6 个配置槽的地址。

**2. 为什么 `mach_vm_remap` 用 `copy=FALSE` + `VM_INHERIT_SHARE`？**
- `copy=FALSE`：源 VM object 直接共享，target 见到的就是 injector 里 loader / payload 的同一份物理页——省内存，也保留原代码签名（AMFI 若开启也不拒）；
- `VM_INHERIT_SHARE`：让 target 后续 `fork` 也能 inherit（虽然 target 一般不 fork，纯保险）；
- 副作用：任何一侧对页保护做改动都会传播到另一侧（这就是为什么 injector 不能 dlclose payload/loader）。

**3. 为什么 payload `__DATA_CONST` 要在 target 里 flip 成 R+W+COPY？**

`mach_vm_remap` 时 target 段继承源段的 `cur_protection`。dyld 早就在 injector 里把 payload `__DATA_CONST` flip 回 R-only（因为 injector 里 dyld 已经完成 fixup，不需要写了）。target 里 stage2 loader 需要**重新写 chained-fixup slot**——所以要手动 `mach_vm_protect` 到 R+W。同时 `VM_PROT_COPY` 触发 CoW，让 target 的写不会传染回 injector 的 `__DATA_CONST`（否则 race dyld 在 injector 里的 bookkeeping）。

**4. 为什么 stage1 之后要 `usleep(2s)` 才 `thread_terminate` 原 raw mach thread？**

pthread bootstrap 需要一点时间。太早 kill mach thread 会打乱 `pthread_create_from_mach_thread` 内部状态，观察到过 target 陷入 unstable 状态。2 秒是经验值，实际所需时间可能远小于此，但保守起见。

**5. 为什么 `MIMachInjectorRemap.m` 用 `__arm64__` gate？**

`ARM_THREAD_STATE64_COUNT` / `arm_thread_state64_t` / arm64e-专属的 PAC 内建都是 arm64-only 类型。SPM target 编译 arm64+arm64e+x86_64，x86_64 slice 需要一个 stub 让链接通过，任何 API call 返回 "arm64-only" 错误。

## 出错时的排查顺序

按下面顺序**证伪**，别乱改代码：

1. **确认 target 里 shared cache slide 与 injector 一致**（arm64e 同一次 boot 里跨进程一致）：`vmmap $(pgrep -x <daemon>) | grep -iE 'libswiftCore|libobjc\.A|libdyld'` 跟 injector 里对比。任何一个不一致，injector 传出去的函数地址全废。
2. **看 daemon crash log**（`~/Library/Logs/DiagnosticReports/<daemon>-*.ips`）判定崩溃在哪一层：
   - PC 在 libobjc 内部 → ABI 或 `_dyld_objc_notify_mapped_info` layout 变了；
   - PC 在 `swift_getTypeByMangledNameInContext` / `swift_conformsToProtocol` → Swift metadata 没 register 或 chained fixup 没 apply；
   - PC 在 payload 自己的 Swift 代码 → runtime 层 bug，跟 injection 无关；
   - `KERN_PROTECTION_FAILURE at __DATA_CONST` → 忘了 `mach_vm_protect` payload `__DATA_CONST` 到 R+W+COPY；
   - `+[<SystemClass> (dynamic selector)]: unrecognized selector` → `map_images` 没跑 selref uniquify（往往是 handoff 跑在了 raw mach thread 上，或 loader dylib 版本没更新）。
3. **看 injector 侧 diag 日志**（subsystem `com.mxiris.machinjector.remap`）：
   ```
   log stream --predicate 'subsystem == "com.mxiris.machinjector.remap"' --level debug
   ```
   `FindLibObjCMapImages` 有 step1/2/3/4 详细日志；`ParseChainedFixups` 后有 `auth_bind` / `auth_rebase` / `plain_bind` / `plain_rebase` 计数 + first plain rebase sample + last 4 fixup tail sample。这些直接说明 injector 侧解析结果是不是合理。
4. **确认 injector 用的是本地 MachInjector checkout 不是远端 SPM tag**：改了 loader 但注入进去还是老行为，99% 是 SPM 拉的远端。看 `Package.resolved` 里有没有 `machinjector` remote entry；有就说明还在用远端。

## 相关文档

- [`ChainedFixupsPipeline.md`](ChainedFixupsPipeline.md) — 位编码 + 算法细节
- [`LoaderDylibInternals.md`](LoaderDylibInternals.md) — loader dylib 内部构造 + `__DATA` 配置槽 layout
- [`PACHandbookForRemap.md`](PACHandbookForRemap.md) — arm64e PAC 备忘 + 每一处坑
- [`StrictSeatbeltPayloadRuntimeHandoff.md`](StrictSeatbeltPayloadRuntimeHandoff.md) — handoff 抽到 loader 的具体设计 + 历史演化
- RuntimeViewer 侧的 `Documentations/ResolvedIssues/2026-07-17-mach-vm-remap-poc-milestones.md` — 早期 M1/M2/M3 POC 里程碑（多段 remap → Swift Foundation → libobjc register 的实证过程）
