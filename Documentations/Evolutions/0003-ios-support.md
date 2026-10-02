# 0003 - 支持 iOS：补一个 `mach_vm` 兼容头，并把 remap 路径按平台关掉

- **状态**: Implemented
- **作者**: JH
- **创建日期**: 2026-10-02
- **最后更新**: 2026-10-02
- **所属愿景**: 无
- **关联提案**: 无（下游触发方是 RuntimeViewer 的「越狱版 RV iOS：枚举设备进程并注入」）
- **实现分支 / PR**: `feature/ios-support`
- **配套文档**: 无单独成文 —— 三条「代码看不出来」的结论写进了 `AGENTS.md` 的 Hazards（两条 iOS 陷阱）与 `Documentations/Design/InjectionStrategies.md` 的「平台支持 / 操作系统」一节，判定理由见决策日志末行

## 摘要

把本库的平台从 `macOS` 扩到 `macOS + iOS`，让两条 dlopen 注入路径（`MIMachInjector` /
`MIMachInjectorAsync`）能在 iOS 上编译并运行。**注入逻辑一行都不改**：iOS 内核暴露的是同一套
`task_for_pid` + `mach_vm_*` + `thread_create_running` 接口，差异全在 SDK 头文件的缺失上，
所以本次只补一个声明兼容头 `MIMachVMCompat.h`、换四处 `#include`、加一条 `platforms` 条目。

两件必须随之明确的事：**iOS 上必须编 arm64e**（iOS 的 arm64 target 拒绝 `paciza` / `pacibsp`，
而 macOS 的 arm64 target 接受，所以这个约束在 macOS 上永远不暴露），以及 **remap 路径在 iOS
上按平台关掉** —— 它内嵌的 loader 是一个 macOS dylib，在 iOS 上编得过但必然在运行时失败，
关掉它既把失败从运行时提前到编译期，也把那 11167 行 dylib 字节从每个 iOS 产物里拿掉。

## 动机

本库今天声明 `platforms: [.macOS(.v10_15)]`，README 第 3 行写的是「injecting a dylib into a
running **macOS** process」，`AGENTS.md` 的 Project Overview 写「Platform: macOS 10.15+」。
这不是因为 iOS 做不到，而是因为**从来没人试过**。

触发方是 RuntimeViewer：它的 iOS 版今天只能检视自己这一个进程，因为 iOS 侧没有任何注入能力。
而「有 root / 有越狱权限的 iOS 设备上枚举并注入其它进程」这个场景现在日常可得 —— Apple 自己的
`com.apple.private.virtualization.security-research` 平台（vphone）跑的是真的 iOS 26.6.2，
拿得到 root；越狱真机同理。

关键发现是：**iOS 上不需要 macOS 那套特权 daemon**。macOS 上注入要靠 `SMAppService` 装一个
root daemon、再经 XPC 委托，因为普通 App 拿不到别人的 task port。iOS 上一个 uid 501 的 App 只要
带三条 entitlement 就能自己完成枚举和注入（实测，见下）。也就是说，只要这个库能在 iOS 上编出来，
调用方就能直接在 App 进程里用它 —— 整个 daemon 层在 iOS 上是多余的。

所以卡住的东西就只有「能不能编出来」这一件，而答案是能，代价是五处表层改动。

## 前期调研

### 验证环境（本库有专门要求，逐条交代）

| 项 | 值 |
|---|---|
| 宿主 | macOS 27.0（Darwin 27.0.0），Apple silicon（Mac Studio Ultra） |
| 工具链 | Xcode 27，iPhoneOS27.0.sdk / MacOSX27.0.sdk |
| 目标系统 | **iOS 26.6.2**，在 Apple `com.apple.private.virtualization.security-research` 平台上运行的虚拟 iPhone（真 iOS 内核，非模拟器） |
| 目标架构 | **arm64e**（已验：产物 `LC_BUILD_VERSION` 为 `platform 2`（PLATFORM_IOS，非模拟器）、`minos 15.0`、`sdk 27.0`；`lipo -info` 报 `arm64e`） |
| 验证范围 | 两条 dlopen 路径的编译 + 链接 + **端到端注入**；remap 路径只验到编译 |

**未在物理 iPhone 上验证**，也未在 iOS 26 以外的版本上验证。虚拟机跑的是真内核与真
`task_for_pid`（含越狱常见的那处内核放行逻辑），但「虚拟机上成立」不等于「每台越狱真机上成立」
—— 本提案对真机的论断仅限于「entitlement 的最小集与越狱安装器本来就会授予的一致」，这一条是
从 entitlement 矩阵推出的，不是在真机上测的。

### 两个 SDK 头文件缺失，其中一个会骗过 `__has_include`

| 头 | iOS SDK 上的情况 | 符号本身 |
|---|---|---|
| `<mach/mach_vm.h>` | **文件存在，内容是一行 `#error mach_vm.h unsupported.`** | `_mach_vm_allocate` / `_deallocate` / `_protect` / `_read` / `_read_overwrite` / `_write` / `_remap` **全部在公开 `usr/lib/libSystem.B.tbd` 里导出** |
| `<bsm/libbsm.h>` | 不存在 | 本库只用它取 `audit_token_t`，而那个类型在 iOS 上由 `<mach/message.h>` 提供 |

第一条是个真陷阱：**头文件存在，所以 `__has_include(<mach/mach_vm.h>)` 会报成功**，然后构建在
头文件内部炸掉。能区分两种平台的只有 `TARGET_OS_*` 判断，不能用 `__has_include` 探测。这一条
值得写进代码注释，因为「加个 `__has_include` 更稳妥」是任何人看到这个兼容头时的第一反应。

其余本库用到的跨进程原语在 iOS SDK 上都有头或都已导出，无需兼容层：`task_for_pid`、
`thread_create_running`、`thread_convert_thread_state`（`mach/thread_act.h`，MIG 生成，
无可用性标注）、`sandbox_extension_issue_file_to_process`。

### 原型必须逐字抄，有一处类型差异会「编过然后行为错」

`mach_vm_*` 是 MIG 生成的调用，原型就是线格式。`mach_vm_read` 与 `mach_vm_read_overwrite`
的第一个参数是 **`vm_map_read_t`**，不是 `vm_map_t`；其余几个是 `vm_map_t`。两者互抄能编过
（都是 `mach_port_t` 的 typedef），但 MIG 的类型检查依赖它。因此兼容头里的声明从 macOS SDK
逐字复制，不重新打字。

### arm64e 是硬约束，而且这个约束在 macOS 上永远不暴露

本库的 shellcode 用 `paciza` 签入口地址、用 `pacibsp` 签栈帧。实测：

| target | `paciza` / `pacibsp` |
|---|---|
| `arm64e-apple-macos*` | 接受 |
| **`arm64-apple-macos*`** | **接受** |
| `arm64e-apple-ios*` | 接受 |
| **`arm64-apple-ios*`** | **拒绝**（指令需要 pauth） |

也就是说 macOS 的 arm64 target 把 pauth 指令放行了，iOS 的没有。后果是：一个只在 macOS 上构建
过的人不会知道「必须 arm64e」这件事，而 iOS 上第一次编 arm64 就会撞墙。这条要进 README 的平台
支持表。

### remap 路径：编得过，但在 iOS 上必然失败

`Loader/build_loader.sh:39` 是

```bash
clang -dynamiclib -arch arm64 -arch arm64e \
```

没有 `-target`、没有 `-isysroot`。产物因此是一个 **macOS** dylib，被 `build_loader.sh` 转成
`loader_arm64_remap_dylib.h` 里 11167 行的字节数组内嵌进库。`MIMachInjectorRemap.m` 在目标进程
里 map 这段字节并跳进去 —— 在 iOS 上那是一个平台不匹配的 Mach-O。

所以 remap 路径在 iOS 上的状态是「编译通过、链接通过、运行必败」。这是本提案唯一一处需要主动做
决定的地方，不是单纯补头文件能解决的。

### 权限边界（逐级实测，10 个被注入靶子全部存活，事后 guest 已清理）

| 注入方 | 目标 | 结果 |
|---|---|---|
| root（LaunchDaemon） | uid 501 | ✅ |
| uid 501 + 沙盒逃逸 | uid 501 | ✅ → **不需要 root** |
| uid 501 + 沙盒逃逸 | **uid 0** | ❌ 拿不到 task port → **root 目标仍需 root** |

调用方 App 的 entitlement 最小集（七个变体对照）：

| 沙盒逃逸 | task-port entitlement | 枚举进程 | 注入 |
|---|---|---|---|
| — | 无 | ❌ `EPERM` | ❌ |
| — | `platform-application` + `task_for_pid-allow` + `system-task-ports` | ❌ `EPERM` | ❌ |
| ✅ | 无 | ✅ | ❌ |
| ✅ | `platform-application` | ✅ | ❌ |
| ✅ | `com.apple.system-task-ports` | ✅ | ❌ |
| ✅ | **`task_for_pid-allow`** | ✅ | **✅** |

两条反直觉的结论：容器化状态下 task-port entitlement **完全无效**（加三个和不加行为一致）；
注入**只认** `task_for_pid-allow`，Apple 自己的 `com.apple.system-task-ports` 和
`platform-application` 都不管用。

这三条（`com.apple.private.security.no-sandbox` / `no-container` / `task_for_pid-allow`）正是
越狱安装器本来就会授予的，所以这件事不绑任何特定虚拟化方案。**这些都是调用方的责任，不是本库
的** —— 写在这里是为了让「库能编出来但注入失败」有个可查的解释，提案不为此新增任何 API。

### 一个把我坑过一次的排查陷阱

一次 uid 501 注入失败被我误判成权限问题，实际是**目标进程已经退出**。暴露它的是对照组：同一个
目标换 root 身份注入，报出的是**不同的错误码**。按提案 0002 的编号，`3` 是 `task_for_pid` 直接
失败，`28` 是拿到了无效的目标端口 —— 含义不同。**判定任何权限结论之前先确认目标存活。**

### 前人怎么做的

越狱生态里的注入器（`choicy`、各类 tweak injector、TrollStore 系工具）走的是
`DYLD_INSERT_LIBRARIES` + 启动时注入，不是对运行中进程做 `task_for_pid`。对运行中进程注入的
公开实现少，且普遍直接声明 `mach_vm_*` 原型 —— 和本提案的做法一致，因为 iOS SDK 从来没提供过
那个头。没有找到可以直接引用的「官方做法」。

## 提议方案

### 1. `Package.swift` 加 iOS

```swift
platforms: [.macOS(.v10_15), .iOS(.v15)]
```

iOS 15 的依据：本库代码不使用任何有版本门槛的 API（`mach_vm_*` 与 `thread_*` 是 MIG 生成的，
头文件里没有可用性标注），所以下限不由代码决定；15 是实测产物的 `minos`，并且低于全部已知消费方
的下限（RuntimeViewer 的 iOS 侧是 18）。将来要降低它是纯新增、无破坏。

### 2. 新增 `Sources/MachInjector/MIMachVMCompat.h`

macOS 上 `#include <mach/mach_vm.h>` 原样转发；其它平台声明那七个 `mach_vm_*`，原型从 macOS SDK
逐字复制。头注释里写明「文件存在所以 `__has_include` 会误报」这一条，否则下一个人会把平台判断
改成 `__has_include`。

### 3. 四处 `#include` 替换

| 文件 | 改动 |
|---|---|
| `MIMachInjector.m` | `<mach/mach_vm.h>` → `"MIMachVMCompat.h"`；`<bsm/libbsm.h>` → `<mach/task_info.h>`；`<Cocoa/Cocoa.h>` → `<Foundation/Foundation.h>` |
| `MIMachInjectorAsync.m` | `<mach/mach_vm.h>` → `"MIMachVMCompat.h"`；`<Cocoa/Cocoa.h>` → `<Foundation/Foundation.h>` |
| `MIMachInjectorRemap.m` | `<mach/mach_vm.h>` → `"MIMachVMCompat.h"` |
| `MITargetSymbolResolver.m` | `<mach/mach_vm.h>` → `"MIMachVMCompat.h"` |

`<Cocoa/Cocoa.h>` → Foundation 实测不 load-bearing（两个文件都不碰 AppKit），顺手改掉是因为
Cocoa 在 iOS 上不存在。

### 4. remap 路径在非 macOS 上整体关掉

`MIMachInjectorRemap.h` 的声明与 `MIMachInjectorRemap.m` 的实现（含 `loader_arm64_remap_dylib.h`
的内嵌字节）一并包在 `#if TARGET_OS_OSX` 里，`MIMachInjectorRemapRestore.c` 同理。iOS 上
`MIMachInjectorRemap` 这个类**不存在**。

理由：这条路在 iOS 上只能在运行时失败（内嵌 loader 是 macOS dylib），而编译期不存在比运行时失败
好；顺带把 11167 行 dylib 字节从每个 iOS 产物里拿掉。把它做成能用的需要教 `build_loader.sh` 带
`-target` / `-isysroot` 产出第二份字节数组，而 remap 是三条路里最依赖平台细节的一条（PAC 签名、
chained fixups 格式），按本仓库的规矩必须交代在什么架构什么系统版本上验证过 —— 那是另一份提案
的工作量，不该塞进这一份。

### 非目标

- **不实现 iOS 上的 remap 路径。** 见上。解禁它是纯新增（给 `build_loader.sh` 加目标、生成第二份
  字节数组、翻转那个 `#if`），不会和本次改动冲突。
- **不改任何注入逻辑。** 失败点、错误码、超时预算、内存回收策略、shellcode 一律不动。本提案的
  全部改动都在 `#include` 和平台声明上。
- **不新增任何 API。** 不加「当前平台支不支持」的查询、不加 entitlement 检查、不加 iOS 专用入口。
  调用方的 entitlement 是调用方的事，而「支不支持」已经由编译期的类存在性回答了。
- **不加 iOS 的单元测试目标。** 现有测试用 clang 在运行时编译 dylib fixture 并做跨进程注入，
  这在 iOS 上既没有 clang 也没有权限。iOS 侧的回归只能是「能编出 arm64e 静态库」这一条，
  放进落地步骤的验证标准，不做成测试。
- **不碰 `Example/`。** 那是 macOS 的 App，不为 iOS 再做一个。
- **不声明 iOS 之外的新平台**（tvOS / watchOS / visionOS）。没验过。

## 详细设计

### `MIMachVMCompat.h`

```objc
#ifndef MIMachVMCompat_h
#define MIMachVMCompat_h

#include <TargetConditionals.h>

#if TARGET_OS_OSX || TARGET_OS_MACCATALYST

#include <mach/mach_vm.h>

#else

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/vm_region.h>

__BEGIN_DECLS

extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_read(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
extern kern_return_t mach_vm_remap(vm_map_t target_task, mach_vm_address_t *target_address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src_task, mach_vm_address_t src_address, boolean_t copy, vm_prot_t *cur_protection, vm_prot_t *max_protection, vm_inherit_t inheritance);

__END_DECLS

#endif
#endif /* MIMachVMCompat_h */
```

实际文件里每个声明按 macOS 头的多行形式排布并带完整头注释；这里压成单行只为提案可读。

**它不进 `include/`。** 和两个 `*Internal.h` 一样，这是实现细节不是 API —— 公开它等于把
「本库在 iOS 上自己声明 mach_vm」变成消费方可以依赖的契约。

### remap 的平台门

`MIMachInjectorRemap.h`（380 行）全文包进：

```objc
#include <TargetConditionals.h>

#if TARGET_OS_OSX

// ... 现有全部声明 ...

#endif /* TARGET_OS_OSX */
```

`MIMachInjectorRemap.m`、`MIMachInjectorRemapRestore.c` 同样处理。两个文件在 iOS 上编出空的
translation unit，SwiftPM 不需要知道这件事（不用 `exclude:`，那个参数不能按平台条件化）。

测试目标 `MachInjectorTests` 保持 macOS-only —— 它本来就只在 macOS 上跑。

## 替代方案考量

- **用 `__has_include(<mach/mach_vm.h>)` 判断要不要走兼容声明。** 否。iOS SDK 上那个文件**存在**，
  只是内容是 `#error`，所以探测会报成功、然后在头文件内部炸掉。这不是「不够优雅」，是会错。
- **把 macOS 的 `mach_vm.h` 整个复制进仓库。** 否。那份头里有大量 MIG 的 request/reply 结构体与
  subsystem 表，本库一个都不用；复制进来是把 1000 多行不属于自己的生成代码揽进维护范围，而且
  下次 SDK 改了没人会去同步。只声明用到的七个函数。
- **自己发 MIG 消息，不链 `mach_vm_*`。** 否。那些符号在公开 `libSystem.B.tbd` 里导出、可直接
  链接，没有任何理由绕开它们自己拼消息 —— 那才是真的会随系统演进而坏掉的东西。
- **weak-link + `dlsym` 兜底。** 否。这是为「符号可能不存在」准备的，而符号确实存在（已验证
  导出且链接通过）。加一层间接只会让失败模式变隐蔽。
- **在 iOS 上保留 remap 路径、让它运行时失败。** 否，这是 spike 的原始状态。一条**只能**失败的
  路不该是可调用的；而且它拖着 11167 行 macOS dylib 字节进每个 iOS 产物。
- **顺手把 `build_loader.sh` 教会编 iOS loader，一次把 remap 也做出来。** 否。remap 是三条路里
  最依赖平台细节的一条，本仓库的提案规矩明确要求交代验证的架构与系统版本，而 PAC 签名与
  chained fixups 在 iOS 上要重新逐槽验证。把它和「补个头文件」放进同一份提案，会让一份低风险
  改动背上一份高风险改动的验证负担。单独提案。
- **把平台支持做成一个运行时查询 API**（`+[MIMachInjector isSupportedOnCurrentPlatform]`）。否。
  平台支持在编译期就是已知的，运行时查询只会让调用方写出永远走不到的分支。

## 影响

### 源码兼容性（source compatibility）

**纯新增。** macOS 上的编译结果与改动前一致：

- 四处 `#include` 替换在 macOS 上展开成与原先逐字相同的内容（`MIMachVMCompat.h` 在 macOS 分支
  里就是 `#include <mach/mach_vm.h>`；`<mach/task_info.h>` 提供的 `audit_token_t` 与
  `<bsm/libbsm.h>` 带来的是同一个类型；两个文件都不使用 AppKit）。
- remap 的 `#if TARGET_OS_OSX` 在 macOS 上恒为真。
- `platforms` 是加一条，不动 macOS 那条。

没有任何现有调用点需要修改，不需要 `@available(*, deprecated)` 过渡。

**iOS 上有一处需要调用方知道的事实，但它不是兼容性破坏**（iOS 此前根本不能编）：
`MIMachInjectorRemap` 在 iOS 上不存在。

### ABI 兼容性（条件项）

不适用 —— 本库以 SPM 源码分发，使用方每次重新编译。

### 下游影响

本仓库内：`MachInjector` target 唯一受影响；`MachInjectorTests` 与 `Example/` 保持 macOS-only。

跨仓库：

- **`swift-helper-service`** —— 今天唯一的直接消费方（`Package.swift:136/140/215`）。它是 macOS
  的特权 daemon 框架，本次改动对它完全透明。**它不需要跟着支持 iOS** —— iOS 上不需要 daemon。
- **`RuntimeViewer`** —— 通过 `swift-helper-service` 间接消费，且那条依赖在
  `RuntimeViewerPackages/Package.swift` 里被 `condition: .when(platforms: appkitPlatforms)` 挡在
  AppKit 平台。RuntimeViewer 的 iOS 侧要用本库，**需要新增一条对 MachInjector 的直接依赖**，
  那是它自己提案的工作。

### 文档与示例

要改三处，与实现同批次：

- `README.md:3` 的「a running macOS process」与 `:23` 的「macOS 10.15 or later」；
  以及 `:210` 附近的平台支持矩阵 —— 加 iOS 一列，写明 **iOS 只有 arm64e**、**remap 不可用**。
- `AGENTS.md` 的 Project Overview：「Platform: macOS 10.15+」改为两行；三条路径的架构表加 iOS 列。
- `AGENTS.md` 的 Hazards：新增两条 —— iOS SDK 的 `mach_vm.h` 是 `#error`（所以不能用
  `__has_include` 探测）、iOS 的 arm64 target 拒绝 pauth 指令（所以这个约束在 macOS 上不暴露）。

`Documentations/README.md` 要登记本提案。

## API 演进与废弃策略

无 API 被替代或废弃，不需要 deprecation 周期。

**版本号：minor。** 纯新增一个平台，没有破坏面。不需要 major 跃迁。

## 落地步骤

1. **兼容头与四处 `#include` 替换**（已在 `feature/ios-support` 上完成，待提交）。
   验证标准：`swift build` 在 macOS 上无回归（已验，exit 0）。
2. **remap 的 `#if TARGET_OS_OSX` 门。**
   验证标准：macOS `swift build` + `swift test` 全绿（证明门在 macOS 上恒真）；iOS 产物里不含
   `loader_arm64_remap_dylib` 的字节（`nm` / `size` 对比）。
3. **`Package.swift` 加 `.iOS(.v15)`。**
   验证标准：`xcodebuild -destination 'generic/platform=iOS'` 能编出 `libMachInjector.a`，
   `lipo -info` 报 `arm64e`，`LC_BUILD_VERSION` 的 `platform` 为 2（PLATFORM_IOS，非模拟器）。
4. **文档三处同批次更新**（README 平台矩阵、AGENTS.md 的 Overview 与 Hazards），并把本提案
   登记进 `Documentations/README.md` 与 `Documentations/Evolutions/README.md`。
5. **合入 `main` 时分配编号**（`draft-ios-support.md` → `0003-ios-support.md`，标题行与索引同步），
   状态改 `Implemented`，发一个 minor tag。下游 RuntimeViewer 要抬 pin 才能用。
6. **收尾判断**（结论写进决策日志，不允许沉默跳过）：
   - 配套文档：倾向**要写实现说明** —— 两个 SDK 头缺失陷阱、`vm_map_read_t` 的类型差异、
     arm64e 约束在 macOS 上不暴露这三条，都是「代码本身看不出来、下次维护会踩」的。
     落地时判定是单独成文还是并进 `AGENTS.md` 的 Hazards。
   - 新术语：无。`arm64e` / `pauth` / `MIG` / entitlement 名都是既有术语，不是本项目自造。


## 落地实测结果

全部在 macOS 27.0 / Xcode 27 / iPhoneOS27.0.sdk 上测的。

| 验证项 | 结果 |
|---|---|
| macOS `swift build` 无回归 | ✅ exit 0 |
| macOS 测试无回归 | ✅ exit 0，28 个全过（含 remap 的 10 个 `MITargetSymbolResolverTests`） |
| iOS arm64e 全部源文件编译 | ✅ 7 个源文件零错误（只有一条 macOS 上同样存在的既有 `-Wcomment` 警告） |
| 产物平台 | ✅ `platform 2`（PLATFORM_IOS，非模拟器）/ `minos 15.0` / `sdk 27.0`，`lipo -info` 报 `arm64e` |
| remap 的 loader 字节不进 iOS 产物 | ✅ `MIMachInjectorRemap.o`：macOS **221,272** 字节 → iOS **4,448** 字节；`nm` 在 iOS 产物里找不到任何 `loader_arm64_remap` / `remap_stage1` 符号 |

每个 iOS 产物因此省掉约 **217 KB**。

## 决策日志

| 日期 | 变更 | 说明 |
|------|------|------|
| 2026-10-02 | Created as Draft | 起因是 RuntimeViewer 要给 iOS 版加注入能力。移植先以 spike 形式验通（分支 `feature/ios-support`，worktree `.worktrees/MachInjector-IOSPort`），再回头补本提案。按本仓库规矩，实现代码此前只存在于未合入的 feature 分支上。 |
| 2026-10-02 | 确认「iOS 不需要 macOS 那套 daemon + XPC」 | 原以为 iOS 也得像 macOS 一样靠特权 daemon 代做注入。实测 uid 501 的 App 带三条 entitlement 即可自行枚举与注入。这决定了本库在 iOS 上的角色是「被 App 直接链接」，而不是「被某个 iOS 版 daemon 链接」—— 所以本提案不需要为 iOS 设计任何新的进程模型。 |
| 2026-10-02 | 平台判断只能用 `TARGET_OS_*`，不能用 `__has_include` | iOS SDK 的 `mach/mach_vm.h` **文件存在**、内容是一行 `#error`。探测会报成功然后在头文件内部炸掉。我自己先用 `ls` 看到文件存在、据此判断「iOS 有这个头」，是编译才推翻的。 |
| 2026-10-02 | 原型逐字抄，不重新打字 | `mach_vm_read` / `mach_vm_read_overwrite` 的第一个参数是 `vm_map_read_t` 而非 `vm_map_t`。两者都是 `mach_port_t` 的 typedef，抄错能编过，但 MIG 的类型检查依赖它 —— 属于「编过然后行为错」。 |
| 2026-10-02 | arm64e 定为 iOS 上的硬约束并写进 README | 实测 iOS 的 arm64 target 拒绝 `paciza` / `pacibsp`，而 **macOS 的 arm64 target 接受**。后果是这个约束在 macOS 上永远不暴露，只构建过 macOS 的人不会知道它存在。因此它必须进平台支持表，而不是只写在提案里。 |
| 2026-10-02 | remap 路径改为按平台关掉，而非保留成运行时失败 | spike 的原始状态是「iOS 上编得过」，但 `Loader/build_loader.sh:39` 的 `clang` 不带 `-target` / `-isysroot`，内嵌 loader 是 macOS dylib，运行必败。改为 `#if TARGET_OS_OSX` 整体关闭：编译期不存在优于运行时失败，顺带去掉 11167 行 dylib 字节。做成可用需要重新逐槽验证 PAC 与 chained fixups，按本仓库规矩要交代验证架构与系统版本 —— 单独提案，解禁是纯新增。 |
| 2026-10-02 | iOS 下限定 15，依据是实测 `minos` 与消费方下限 | 代码不使用任何有版本门槛的 API（`mach_vm_*` / `thread_*` 是 MIG 生成的，头里无可用性标注），所以下限不由代码决定。15 是实测产物的 `minos`，且低于全部已知消费方（RuntimeViewer 的 iOS 侧是 18）。将来降低是纯新增。 |
| 2026-10-02 | 不加 iOS 测试目标，iOS 侧回归只有「能编出 arm64e 静态库」 | 现有测试在运行时用 clang 编译 dylib fixture 并做跨进程注入，iOS 上既没有 clang 也没有权限。把这一条写进落地步骤的验证标准，而不是假装能做成测试。 |
| 2026-10-02 | 记下一个排查陷阱 | 一次 uid 501 注入失败被误判成权限问题，实际是目标进程已退出。是对照组（同目标换 root）报出**不同错误码**才暴露的。按 0002 的编号，`3` 是 `task_for_pid` 失败、`28` 是目标端口无效。判定权限结论前必须先确认目标存活。 |
| 2026-10-02 | **偏离提案**：remap 改为复用既有的 stub 两臂，而非「iOS 上类不存在」 | 提案原写「`MIMachInjectorRemap.h` 全文包进 `#if TARGET_OS_OSX`，iOS 上这个类不存在」。实现时发现 `MIMachInjectorRemap.m` **本来就**是两臂结构 —— `#ifdef __arm64__` 是真实现、`#else` 是返回 `ArchitectureUnsupported` 的 stub（给 x86_64 用）。于是改为把那个条件收紧成 `#if defined(__arm64__) && TARGET_OS_OSX`，让 iOS 落进同一个 stub 臂。理由：**这个库自己已经为 x86_64 回答过同一个问题**，选的是「保留符号、明确报错」而不是「符号不存在」；跨平台调用方只需要一种形状，不必为 iOS 写 `#if`。提案关心的两个结果都没丢 —— 没有运行时才失败的路径（stub 立即报错），loader 字节也不进 iOS 产物（它在 arm64 那一臂里）。 |
| 2026-10-02 | 新增错误码 18 `PlatformUnsupported`，不复用 17 | 17 `ArchitectureUnsupported` 的含义是「这台机器不是 arm64,去用 `MIMachInjector`,它支持 x86_64」。在 arm64e 的 iOS 上架构是对的、平台不对,补救也不同（「remap 还没有 iOS loader」），拿 17 糊过去是错的错误信息。按本 header 既定规则追加在最高值之后,不重编号。 |
| 2026-10-02 | `MIMachInjectorRemapRestore.c` 与 `MIMachInjectorRemapInternal.h` 不加门 | 它们是平台中立的纯字节操作（段恢复），在 iOS 上编得过也无害，而真正的大块（11167 行 loader 字节数组）已经在 `__arm64__ && TARGET_OS_OSX` 那一臂里。给它们加门需要连测试一起处理，换来的体积收益接近零。 |
| 2026-10-02 | 收尾判断：不单独写实现说明；无新术语 | 三条「代码本身看不出来」的结论（iOS 的 `mach_vm.h` 是 `#error` 所以不能用 `__has_include` 探测、`vm_map_read_t` 的类型差异、arm64e 约束在 macOS 上不暴露）都是**维护时会撞上**的点，所以放进 `AGENTS.md` 的 Hazards 与 `InjectionStrategies.md` 的平台支持节 —— 那两处正是下一个人动这块代码前会读的地方，单独成文反而更容易被绕过。新术语：无，`arm64e` / `pauth` / `MIG` / entitlement 名都是既有术语。 |
| 2026-10-02 | 0.6.0 漏了一条:iOS 的 arm64 切片编不过,下游**一定**会被要求编它 | 下游集成时才暴露。提案和 README 都写了「iOS 必须 arm64e」,但那只说对了一半 —— **Xcode 的 `iOSPackagesShouldBuildARM64e` 是往包的架构里追加 arm64e,不是替换 arm64**,所以即使 App target 写 `ARCHS = arm64e`,包仍会 arm64 与 arm64e 两份一起编,arm64 那份在 `loader_arm64.s` 上报 `instruction requires: pauth`,整个构建失败。修法:在两个 `.s` 的 `#ifdef __arm64__` 内加 `.arch_extension pauth`。**实测 10 个切片(iOS/macOS × arm64/arm64e/x86_64)全部汇编通过;arm64e 的 `__DATA` 字节与改动前逐字节一致**(`otool -s __DATA __data` 比对),`paciza` 的编码仍在产物里。语义上也站得住:PAC 指令在无该特性的硬件上架构定义为 no-op,所以 arm64 切片是自洽的(指针不签名、`retab` 等同 `ret`)—— **但那只是架构保证,未在 A11 及更早的真机上实测**,iOS 注入仍要求 arm64e。按「明显 bug 修复」免提案,记在此处。 |
