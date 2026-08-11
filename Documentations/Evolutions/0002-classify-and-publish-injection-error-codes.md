# 0002 - 把注入失败分类成可判定的错误码，并公开三个 domain 的枚举

- **状态**: Draft
- **作者**: JH
- **创建日期**: 2026-08-11
- **最后更新**: 2026-08-11
- **所属愿景**: 无
- **关联提案**: 无
- **实现分支 / PR**: 待定
- **配套文档**: 待定（落地时评估，见「落地步骤」收尾）

## 摘要

`MIMachInjector`（同步 dlopen 路径）的 28 个失败点全部返回 `code:1`，区分它们唯一的依据是
`userInfo[NSLocalizedDescriptionKey]` 里的那句英文。而本库的典型部署形态是「特权 daemon 里注入、
错误跨 XPC 回到 App」，`userInfo` 在这个过程中会被丢弃。两者叠加的结果是调用方拿到
`MIMachInjectorErrorDomain error 1`，零信息量。

横向排查发现这不是同步路径独有：**三条路径没有一条把错误码枚举公开**。异步路径连枚举都没有，
是二十多个裸魔术数字，只在头文件注释里有张表；remap 路径有枚举但声明在 `.m` 里。调用方无论走哪条
路径，都只能照着注释表格硬编码整数字面量。

本提案做四件事：

1. 给同步路径引入 `MIMachInjectorErrorCode`，**编号语义与异步路径逐个对齐**（`3` = 拿不到
   task port，`18` = 目标拒绝加载 dylib，`19` = 超时），同步路径不存在的失败点保留为编号空洞；
2. 把异步路径注释表格里的编号变成真正的 `MIMachInjectorAsyncErrorCode`，取值一字不改；
3. 把 remap 路径的 `MIMachInjectorRemapErrorCode` 从 `.m` 移到公开头文件，取值一字不改；
4. 同步路径把 `dlerror` 原文从描述字符串里拆出来，放进专用的 userInfo key，与异步路径的
   `remoteErrorMessage` 对齐。

## 动机

一次真实排查。`FinderSidebarIconFix` 向 Finder 注入 payload，App 界面只显示：

```
The operation couldn't be completed. (MIMachInjectorErrorDomain error 1.)
```

注入机制本身**完全正常** —— 远程线程建起来了，shellcode 跑通了，`MI_INJECTION_DONE` 收到了。
栽在最后一步：目标进程的 `dlopen` 拒绝了 payload。内核日志给出了真正的理由：

```
kernel: (AppleMobileFileIntegrity) [com.apple.MobileFileIntegrity:library_validation_failure]
Library Validation failed: Rejecting '.../FinderSidebarIconFixPayload'
(Team ID: D5Q73692VW, platform: no) for process 'Finder(74995)' (Team ID: N/A, platform: yes),
reason: mapping process is a platform binary, but mapped file is not
```

`c65d9c2`（让同步路径把目标的 dlopen 拒绝如实上报，而不是谎报成功）正确抓到了这次失败 ——
问题不在检测，在**传递**。信息在两道关卡上各丢一次：

- **第一道**：`MIMachInjectorErrorMake` 把 `code:1` 写死，「拿不到 task port」「分配栈失败」
  「注入超时」「目标拒绝加载」全都是 `error 1`。
- **第二道**：全部信息只写进 `userInfo[NSLocalizedDescriptionKey]`，跨 XPC 回传时被丢弃，
  客户端只剩 domain + code。

单看任何一道都还能救：码分了类，userInfo 丢了也剩下码；userInfo 留得住，码恒为 1 也无妨。
两道叠在一起才归零。**本提案修第一道** —— 它在库这一侧，且修完之后第二道即使不修，
调用方也至少知道自己撞的是哪一类墙。

分类不是为了好看，是为了**调用方能采取不同行动**。以「目标拒绝加载 dylib」这一类为例：它是
唯一一个「注入机制完全正常、纯粹是宿主环境配置」的失败，正确的应对是提示用户去改系统配置
（见下文 AMFI 一节）或改走 remap 路径；而「拿不到 task port」应对的是权限，改系统配置和换路径
都没用 —— remap 路径同样要 `task_for_pid`。当前的下游代码正因为分不出这两类，对**任何**
dlopen 失败都回退去试 remap，其中一部分是注定失败的尝试，且不是免费的（见「前期调研」）。

## 前期调研

**验证环境**（本项目约定必须交代）：macOS 26.6 (25G72)，Apple Silicon，SIP disabled，
`boot-args` 含 `-arm64e_preview_abi`。仓库状态 `0.4.3-5-g9f9354a`。上游排查由
`FinderSidebarIconFix` 一侧完成（macOS 26.6，目标为 Finder，平台 arm64e 二进制）；
本节标注「本机核实」的条目是在本仓库这台机器上独立复核过的。

### 三条路径的错误码现状

| 路径 | 枚举 | 声明位置 | 是否公开 | 失败点数 |
|---|---|---|---|---|
| `MIMachInjector`（同步） | **无** | — | — | 28 处，**全部 `code:1`** |
| `MIMachInjectorAsync`（异步） | **无** | — | — | 21 处，裸字面量 `MakeError(17, …)` |
| `MIMachInjectorRemap` | 有 | `MIMachInjectorRemap.m:145`，`static` 作用域 | **否** | 16 处 |

三者的共同点是**调用方拿不到任何符号**。异步与 remap 的编号只存在于头文件注释表格
（`MIMachInjectorAsync.h:148-171`、`MIMachInjectorRemap.h:131-160`）与 README 里，调用方要判断
「是不是 dlopen 被拒」只能写 `error.code == 18` 这样的字面量，且没有任何编译期保障。

同步路径最糟：它连注释表格都没有，因为没有可列的东西。

### 同步路径 28 个失败点的完整清单

`MIMachInjector.m`，按管线顺序（`x86` / `arm64` 标记的是仅在该架构分支上存在的）：

| 行 | 失败 | 当前码 |
|---:|---|---:|
| 175 | invalid pid | 1 |
| 181 | `task_for_pid` 失败 | 1 |
| 207 | 签发 sandbox extension token 失败（arm64） | 1 |
| 214 | 分配远程栈失败 | 1 |
| 221 | 写远程栈失败 | 1 |
| 227 | 设置栈保护失败 | 1 |
| 253 / 321 | 分配远程 code 段失败（x86 / arm64） | 1 |
| 260 / 328 | 本地 shellcode 缓冲 `malloc` 失败 | 1 |
| 280 / 350 | dylib 路径过长 | 1 |
| 359 | sandbox token 过长（arm64） | 1 |
| 287 / 367 | 写 shellcode 到目标失败 | 1 |
| 293 / 373 | 设置 code 段可执行失败 | 1 |
| 385 | 加载 `thread_convert_thread_state` 失败（arm64） | 1 |
| 301 / 393 | `thread_create` 失败 | 1 |
| 401 | `thread_convert_thread_state` 失败（arm64） | 1 |
| 415 | `thread_create_running` 失败（arm64，macOS 14.4+ 分支） | 1 |
| 422 | `thread_set_state` 失败（arm64，旧系统分支） | 1 |
| 428 | `thread_resume` 失败（arm64，旧系统分支） | 1 |
| 445 | `thread_get_state` 失败 | 1 |
| 463 | 注入超时 | 1 |
| 498 | **目标在加载 dylib 期间死亡** | 1 |
| 513 | **目标拒绝加载 dylib**（携带 `dlerror` 原文） | 1 |

最后两条是本次排查真正撞上的那两类，也是调用方最需要区分的两类 —— 它们与前面二十多条
「注入机制本身没跑起来」有本质区别。

### 编号必须与异步路径对齐，而不是自成一套

这是本提案最关键的设计约束，理由来自本仓库已经踩过的坑。

`MIMachInjector.m:38-50` 有一段警告：

```
//              value 0            value 1              value 2
//   this file  not reported yet   dlopen succeeded     dlopen failed
//   async path success            dlopen failed        pthread_create failed
```

同步路径的 `MIMachInjectorDlopenResultCode` 与异步路径 notepad 的 `result_code` 是**同一个概念的
两种编码，而 `1` 在两者里意思相反**。这个坑严重到被写进 `AGENTS.md` 的 hazards 清单，两处声明
各自挂着交叉引用的警告。

如果本提案给同步路径自成一套连续编号（1、2、3……按它自己的管线顺序排），就会**在公开 API 层面
重演同一个错误**：`MIMachInjectorErrorDomain error 3` 与 `MIMachInjectorAsyncErrorDomain error 3`
指向不同的东西，而两条路径解决的是同一个问题、调用方经常两条都用（下游 `InjectionService` 就是
先试同步、失败再试 remap）。一个把错误码转成用户提示的 `switch` 会因为漏判 domain 而给出错误的
提示，且这类错误极难在测试里发现。

因此：**同步路径复用异步路径的编号语义，同步路径不存在的失败点保留空洞**。空洞（例如 `4`、`5`
在同步路径上永不出现）是无害的；「同一个数字在两条路径上含义不同」不是。

顺带查证：异步路径的编号里 **`20` 从未被使用**（表格从 19 直接跳到 21，代码里也没有
`MakeError(20, …)`）。本提案不动它，同步路径独有的失败点从 `23` 起编号，`20` 自然保持空洞。

### 下游实测：重新编号的破坏面为零，且分类有实际收益

本库在本机的三个下游仓库：

| 仓库 | 用法 |
|---|---|
| `swift-helper-service` | **唯一的代码消费者**。`InjectionService.swift` 调用 `MachInjector.inject` / `MachInjectorRemap.inject` |
| `FinderSidebarIconFix` | 经 `swift-helper-service` 间接使用；自身只在 payload 侧提及本库 |
| `InjectionScaffold` | 生成的模板同上，只在 payload 侧提及 |

**核实结果：三个仓库里没有任何一处读取 `NSError.code`。** `InjectionService.swift:50-56` 的写法是：

```swift
do {
    try MachInjector.inject(pid: request.pid, dylibPath: payloadPath)
} catch {
    guard mayFallBackToRemap else { throw error }
    try injectViaRemap(request: request, payloadPath: payloadPath, dlopenFailure: error)
    return
}
```

即**任何** dlopen 失败都触发回退到 remap。这有两层含义：

- **重新编号不会破坏任何现有下游代码** —— 没有 `code == 1` 的判断可被打破。这把「源码兼容性」
  一节里的风险评估从推测变成了核实过的事实。
- **分类有可度量的收益。** 回退不是免费的：`InjectionStrategy+Probe.swift` 自己的注释写明
  「a failed attempt permanently leaves a spinning mach thread and a few pages of shellcode in the
  target, which MachInjector deliberately does not reclaim」。对「拿不到 task port」这类失败
  回退去试 remap 是注定失败的（remap 同样要 `task_for_pid`），代价是目标进程里白白多一个空转
  线程和几页永不回收的内存。有了错误码，下游可以只对「目标拒绝加载」回退。

### 跨 XPC 丢失 userInfo —— 边界在哪

这是上游排查报告里的「问题二」。本提案**不认为它是本库的 bug**，但它决定了「把信息只放进
`userInfo` 里」这个设计在本库的真实部署形态下等于没放。

`NSError` 跨 XPC 传递时，`userInfo` 是否存活取决于两端的编解码约定，不由本库控制。本库能做的
只有两件：把关键判据放进 `code`（跨 XPC 必然存活），以及在 README 里点明「跨进程使用时需要
自己转运 `localizedDescription`」。第一件是本提案的主体，第二件是配套文档。

`swift-helper-service` 一侧的对应改动由上游会话同步给那边处理，不在本提案范围内。

### AMFI 库校验：关 SIP 不足以放行，真正的开关是一份 plist

上游会话逆向 macOS 26.6 的 `/usr/libexec/amfid`，给出的判定链是：

```c
// sub_1000056EC — CSR_ALLOW_TASK_FOR_PID = 0x4
byte_100024B68 = (csr_check(4) != 0);
// sub_100005718 — CSR_ALLOW_APPLE_INTERNAL = 0x10
byte_100025210 = (csr_check(16) == 0);

// sub_100005098
if (byte_100024B68 != 1) goto READ_PLIST;   // SIP 关了 → 读
if (byte_100025210 == 1) goto READ_PLIST;   // Apple 内部机 → 读
return;                                      // 否则连读都不读

READ_PLIST:
  读 /Library/Preferences/com.apple.security.libraryvalidation.plist
  的 DisableLibraryValidation，写进全局标志

// sub_100002360 — 内核查询时的应答
if (全局标志 == 1) { 放行; os_log("library validation is globally disabled"); }
```

即：**关 SIP 只打开了「允许读那份 plist」这道门，真正的开关是 plist 里的值。**

**本机核实**（未复核反编译本身，只核实它的三个可观测推论）：

```
$ strings -a /usr/libexec/amfid | grep -i 'libraryvalidation\|library validation'
library validation is globally disabled
/Library/Preferences/com.apple.security.libraryvalidation.plist
DisableLibraryValidation

$ defaults read /Library/Preferences/com.apple.security.libraryvalidation.plist
{ DisableLibraryValidation = 1; }

$ csrutil status
System Integrity Protection status: disabled.
```

三条字符串在同一个二进制里同时出现，与判定链吻合。**未复核**的部分：`csr_check` 的两个常量值
（`CS_ALLOW_TASK_FOR_PID = 0x4`、`CSR_ALLOW_APPLE_INTERNAL = 0x10`）—— 当前 SDK 不带
`sys/csr.h`，本机无法查证，提案照录上游结论并标注来源。

开关方式与生效判据：

```bash
sudo defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist \
    DisableLibraryValidation -bool true
```

`amfid` 用 `xpc_set_event_stream_handler("com.apple.fsevents.matching", …)` 监听该文件，改完一般
即时生效；验证信号是 `amfid` 打出 `library validation is globally disabled`。

**这条前提对本库的每个使用者都成立**，`Example/` 下的 injectd 也一样，属于 README「Requirements」
该讲而没讲的内容 —— 那一节目前只讲了 `task_for_pid`。

### 一个现有结论的理由是错的（已先行修正）

`MIMachInjector.h` 的 docblock 里原本有这样一段（`c65d9c2` 引入）：

> Do not predict a refusal from `csops(CS_OPS_STATUS)` reporting `CS_REQUIRE_LV`. […] with SIP
> disabled, a process signed `library,runtime` and reporting `CS_REQUIRE_LV` loads unsigned,
> ad-hoc, and foreign-Team-ID dylibs without complaint (measured on macOS 26.5). **And SIP is
> disabled on essentially every machine where this class can be used at all** […] so the
> prediction tends to be wrong exactly where it would be consulted.

**结论（不要预测，去试）没错，但理由是错的。** 它把「SIP 关闭」当成了库校验不被强制的
**充分**条件，而按上面的判定链，关 SIP 只是让 amfid 去读那份 plist —— 真正的开关是
`DisableLibraryValidation`。这个错误理由有两个方向的推论，都会咬人：一台刚关掉 SIP、
plist 没设的机器照样拒绝（本次 Finder 就是），而 SIP 开着时把 plist 设上则完全无效。
加粗那句「SIP 在几乎每台能用这个类的机器上都是关的，所以预测总在会被查询的场景里出错」
整个建立在这个错误前提上。

那次测量本身没问题，只是记录不全：用的是自己签名的测试进程（不是平台二进制），
那台机器的 plist 状态也没记。

**这一项已经在提案批准前单独落地**（用户确认该机制已验证过，直接批准修正注释），
不再作为本提案的落地步骤。改动范围：

| 文件 | 改了什么 |
|---|---|
| `include/MIMachInjector.h` | 重写那段的理由：标志是进程属性、强制与否是机器属性，真正的开关是 plist，关 SIP 是必要不充分条件。结论不变。 |
| `include/MIMachInjectorRemap.h` | 「AMFI library validation」那条原本无条件断言 `CS_REQUIRE_LV` 的进程只收 Apple / 同 Team ID 的 dylib，补上「在被强制时」的限定与开关说明；「WHEN TO USE」里「target enforces library validation (`CS_REQUIRE_LV`)」改为点明标志与机器开关两半缺一不可。 |
| `Design/InjectionStrategies.md` | 「不要预测，直接试」一节按同一逻辑重写，并补上失败模式表格里库校验那一行 —— 关键在于它**不是**该退回 remap 的场景，开关才是解法。 |
| `AGENTS.md` | hazards 新增一条「关 SIP 不等于关库校验」。判据是它符合该文件的定位：每换一台机器就会被重新发现一次。 |

`MIMachInjector.h` 的新文字目前**自包含**，没有引用 README —— 因为 README 的运行前提一节
还没写（属于本提案的落地范围）。落地时记得回填这个引用。

### 前人怎么做的

remap 路径（`9e064f3`，2026-07）从第一天起就带着分类错误码与逐码排查提示，`MIMachInjectorRemap.h`
里那份「Debug hints by code」表是本仓库错误码设计的最高水位。异步路径有编号表格但没有枚举。
同步路径是三者里最老的代码（继承自 yabai 与 jslegendre 的 arm64e 实现），一直没有跟上。

也就是说，本提案不是引入新约定，而是**把 remap 已经确立的约定补齐到另外两条路径上**。

## 提议方案

### 1. 同步路径：新增公开的 `MIMachInjectorErrorCode`

在 `include/MIMachInjector.h` 里声明 `NS_ERROR_ENUM(MIMachInjectorErrorDomain, MIMachInjectorErrorCode)`，
取值与异步路径逐个对齐，详见「详细设计」的映射表。

### 2. 异步路径：把注释表格变成枚举

`include/MIMachInjectorAsync.h` 新增 `MIMachInjectorAsyncErrorCode`，**取值与现有注释表格
逐条一致，一个都不改**。`MIMachInjectorAsync.m` 里 21 处 `MakeError(17, …)` 改为具名常量，
`MakeError` 的形参类型从 `NSInteger` 收紧为该枚举。

### 3. remap 路径：把私有枚举移到头文件

`MIMachInjectorRemap.m:145` 的 `MIMachInjectorRemapErrorCode` 移到
`include/MIMachInjectorRemap.h`，**取值不变**。头文件里那份「Debug hints by code」表继续保留，
但改为挂在枚举各 case 的文档注释上，这样调用方在 IDE 里就能看到排查提示。

### 4. 同步路径：`dlerror` 原文放专用 userInfo key

新增 `MIMachInjectorRemoteErrorMessageKey`。目标拒绝加载时，`dlerror` 的原文除了继续拼进
`NSLocalizedDescriptionKey`（保持人类可读），还单独放一份到这个 key 下 —— 与异步路径的
`MIInjectionResult.remoteErrorMessage` 对齐。调用方要程序化判断「是不是签名问题」时，
不必再去字符串里捞子串。

### 5. 三个 domain 的编号互不通用，写进文档

同步与异步对齐，但 **remap 自成一套**（它的 `10` 是 `task_for_pid`，而 dlopen 两条路径的
`task_for_pid` 是 `3`）。这个不一致是刻意保留的（理由见「非目标」），因此必须显式写明：
三个头文件各加一句、README 的错误码一节加一句 —— **先看 domain，再看 code**。

### 非目标

- **不统一 remap 的编号。** remap 的 1–16 已经公开在头文件与 README 里发布了三个版本，
  重新编号会破坏唯一一处真实存在的编号契约，换来的只是「三条路径长得一样」的整齐感。
  代价与收益不成比例。
- **不动 `MIMachInjectorDlopenResultCode` / notepad `result_code`。** 这两个是**注入器与
  shellcode 之间的二进制契约**（偏移与取值写死在 `.s` 文件里），不是 API。统一它们要同时改
  三份汇编，且没有任何调用方能看到它们。两处现有的交叉引用警告继续保留。
- **不做预测式分类。** 不新增「提前判断目标会不会拒绝」的 API。`MIMachInjector.h` 已经论证过
  为什么 `CS_REQUIRE_LV` 不能用作预测，本提案不推翻它。
- **不改任何注入行为。** 失败点、判定逻辑、超时预算、内存回收策略一律不动，只改「失败之后
  往 `NSError` 里填什么」。
- **不替调用方转运 XPC 错误。** 本库不知道调用方的 XPC 编解码约定，也不该知道。
- **不引入错误码分类的辅助 API**（如 `isRecoverable` / `category` 属性）。等有第二个调用方
  真的需要同一套分类时再说 —— 现在加等于替唯一的调用方猜它想要什么。

## 详细设计

### 同步路径的编号映射

左侧是异步路径已发布的语义，中间是同步路径对应的失败点。空白表示该路径不存在这个失败点。

| 码 | 语义（与异步一致） | 同步路径的失败点（`MIMachInjector.m`） |
|---:|---|---|
| 1 | 分配注入上下文失败 | —（同步无上下文对象） |
| 2 | 无效 pid | 175 |
| 3 | `task_for_pid` 失败 | 181 |
| 4 | 分配 notepad 失败 | —（同步的 report 块分配失败不致命，见下） |
| 5 | 初始化 notepad 失败 | — |
| 6 | 分配远程栈失败 | 214 |
| 7 | 设置栈保护失败 | 227 |
| 8 | 分配远程 code 段失败 | 253 / 321 |
| 9 | 本地 shellcode 缓冲分配失败 | 260 / 328 |
| 10 | dylib 路径过长 | 280 / 350 |
| 11 | 写 shellcode 到目标失败 | 287 / 367 |
| 12 | 设置 code 段可执行失败 | 293 / 373 |
| 13 | 加载 `thread_convert_thread_state` 失败 | 385 |
| 14 | 创建远程线程失败 | 301（x86）/ 393 |
| 15 | 转换线程状态失败（arm64e ptrauth） | 401 |
| 16 | 启动远程线程失败 | 415 |
| 17 | 目标内 `pthread_create` 失败 | —（同步表现为超时，见下） |
| 18 | **目标拒绝加载 dylib** | 513 |
| 19 | 注入超时 | 463 |
| 20 | —（异步从未使用，保留空洞） | — |
| 21 | 在目标内分配 mach port 失败 | — |
| 22 | 创建 dispatch source 失败 | — |
| **23** | 写远程栈失败 | 221 |
| **24** | 签发 sandbox extension token 失败 | 207 |
| **25** | sandbox token 过长 | 359 |
| **26** | `thread_set_state` 失败 | 422 |
| **27** | `thread_resume` 失败 | 428 |
| **28** | 读取远程线程状态失败 | 445 |
| **29** | **目标在加载 dylib 期间死亡** | 498 |

23–29 是同步路径独有的，占用异步未使用的号段。**新号一律追加在尾部，不插空洞** —— `1`、`4`、
`5`、`17`、`20`、`21`、`22` 这些空洞必须留着，因为它们在异步路径上有确定含义，占用它们就会
制造出「同一个数字两种含义」的局面，正是「前期调研」里论证要避免的。

两条注释必须写进枚举声明：

- **`4` 在同步路径上永不出现，不代表同步路径没有 report 块。** 同步路径的 report 块分配失败
  是**刻意不致命**的（`MIMachInjector.m:237-239`：分配失败就把地址置零，shellcode 把零地址当作
  「无处可报」，注入照常进行，只是盲注）。这是既有行为，本提案不改。
- **`17` 在同步路径上永不出现，不代表同步路径不会遇到 `pthread_create` 失败。** 异步路径能报
  这一码是因为 notepad 有专门的 result code；同步路径的 shellcode 只在 `pthread_create` 成功后
  才写 `DONE` 寄存器，失败时什么都不写，注入器只能等到超时 —— 于是表现为 `19`。这是路径能力
  差异，不是遗漏。

### 命名

```objc
typedef NS_ERROR_ENUM(MIMachInjectorErrorDomain, MIMachInjectorErrorCode) {
    MIMachInjectorErrorInvalidProcessIdentifier          = 2,
    MIMachInjectorErrorTaskPortUnavailable               = 3,
    MIMachInjectorErrorRemoteStackAllocationFailed       = 6,
    …
    MIMachInjectorErrorTargetRefusedToLoadDylib          = 18,
    MIMachInjectorErrorTimedOut                          = 19,
    MIMachInjectorErrorRemoteStackWriteFailed            = 23,
    …
    MIMachInjectorErrorTargetTerminatedWhileLoading      = 29,
};
```

`NS_ERROR_ENUM` 而非 `NS_ENUM`：它把枚举与 domain 绑定，Swift 侧因此能写
`catch MachInjectorError.targetRefusedToLoadDylib`，而不是先转 `NSError` 再比整数。这是本提案
对 Swift 调用方最直接的收益，也是三个头文件都该用它的理由。

标识符不使用缩写（`ProcessIdentifier` 而非 `PID`），与仓库既有约定一致。

### `MakeError` 的签名收紧

三条路径的错误构造函数首参统一为各自的枚举类型：

```objc
static NSError *MIMachInjectorErrorMake(MIMachInjectorErrorCode code, NSString *format, ...);
```

同步路径现在的签名首参是描述字符串，改动会触及全部 28 个调用点。这是本提案代码改动量的主体，
但每一处都是机械替换，且编译器会强制每个调用点给出一个枚举值 —— 漏掉一处就编译不过。这正是
把魔术数字换成枚举的意义所在（异步路径现在的 `MakeError(NSInteger, …)` 收不到这个保障）。

### 结果判定与 VM 读写的隔离

跨进程的部分没有 root 就无法单元测试，本仓库的既定做法是「把字节级决策从 VM 写入里隔离出来，
测前者」（`MIMachInjectorRemapRestore.c` 是范例）。错误码这里对应的可隔离决策是
**report 块内容 → `NSError`** 这个映射：

```objc
// Verdict for a report block that has been read out of the target. Pure: takes
// the bytes and the liveness answer, returns the error (or nil for success), so
// the mapping from a target's dlopen verdict to an NSError can be tested without
// a task port.
NSError *_Nullable MIMachInjectorErrorForDlopenReport(const MIMachInjectorDlopenReport *report,
                                                      BOOL reportWasReadable,
                                                      BOOL targetIsAlive,
                                                      NSString *dylibPath);
```

`MIMachInjector.m:473-521` 的轮询循环改为调用它。这样码 `18`（目标拒绝，含 `dlerror` 原文的
转运）与码 `29`（目标死亡）都能在单元测试里覆盖 —— 而这两个恰恰是本次排查真正撞上的两类。

轮询、`mach_vm_read_overwrite`、存活探测继续留在 `.m` 里，不动。

### 头文件里的排查提示

remap 路径的「Debug hints by code」表是本仓库最有用的一段文档。同步与异步的枚举同样每个 case
配一句「撞到这个码先看哪里」，至少覆盖这几条：

| 码 | 提示 |
|---:|---|
| 3 | 注入器没有 `task_for_pid`：不是 root、缺 `com.apple.system-task-ports.debug`、或目标已退出。**回退到 remap 路径也救不了，remap 同样要它。** |
| 18 | 目标拒绝了 dylib。看 `MIMachInjectorRemoteErrorMessageKey` 里的 `dlerror` 原文；若提到 code signature / library validation，见 README 的运行前提一节；若目标的 seatbelt 拒绝 `file-map-executable`，改走 `MIMachInjectorRemap`。 |
| 19 | 目标里 `pthread_create` 可能失败了（同步路径看不见它，只能表现为超时），或目标被暂停。 |
| 29 | 目标在加载期间被杀。典型原因是 payload 的页哈希与签名不符 —— 内核在页错入时直接 SIGKILL，`dlopen` 根本没机会返回。 |

## 替代方案考量

**A. 只给同步路径加一个「目标拒绝加载」的码，其余保持 `code:1`。**
最小改动，直接满足上游诉求。**否决理由**：留下的 `code:1` 会变成一个语义模糊的兜底码，
而兜底码会持续吸引新失败点往里塞（这正是它现在覆盖 28 个失败点的成因）。而且真正的收益
——「拿不到 task port 不该回退去试 remap」——恰恰需要那些「其余」失败也可判定。

**B. 同步路径自成一套连续编号 1..28。**
最符合直觉，也与 remap 的做法一致。**否决理由**：见「前期调研」的编号对齐一节。同步与异步
是同一个问题的两种调用形态，调用方常常两条都用；让 `error 3` 在两条路径上指不同的东西，
是在公开 API 层面重演 `MIMachInjectorDlopenResultCode` 那个已经被写进 hazards 清单的坑。

**C. 三条路径合并为一个 domain、一套编号。**
最整齐。**否决理由**：要么重新编号 remap（破坏唯一真实存在的编号契约），要么给同步与异步塞进
remap 的编号空间（remap 的编号按它自己的 13 步管线排，塞不进去）。而且合并 domain 会让
「这个错误来自哪条路径」这一信息消失，而调用方恰恰需要它来决定要不要换路径。

**D. 不动错误码，改为把结构化信息全部塞进 `userInfo`。**
比如加 `MIMachInjectorFailureStageKey`。**否决理由**：`userInfo` 正是这次丢信息的地方。
把判据放进跨 XPC 会被丢弃的容器里，等于没放。`code` 是唯一保证存活的字段。

**E. 在库里检测 AMFI 库校验状态，直接给出「请改 plist」的错误。**
**否决理由**：这是预测式判断的变体，`MIMachInjector.h` 已论证过为什么不可靠。而且检测结果
只在**已经失败之后**才有价值 —— 那时把 `dlerror` 原文交给调用方即可，由调用方决定怎么提示
用户。库不该替 App 决定 UI 文案。

## 影响

### 源码兼容性

**大部分是纯新增，有一处需要显式承认的破坏。**

纯新增的部分：三个枚举、一个 userInfo key、一个可测的映射函数（内部）。现有 API 签名不变，
现有 `catch` / `if !ok` 的写法不受影响。

破坏的部分：**同步路径的 `code` 不再恒为 `1`。** 任何写了 `error.code == 1` 的调用方，其判断
从「任何失败」变成「不存在的失败」（`1` 在新枚举里不分配给同步路径）—— 是**静默变味**，
不是编译错误。

风险评估：本机三个下游仓库**已逐一核实，没有任何一处读取 `NSError.code`**（见「前期调研」）。
本库的 GitHub 仓库是公开的，无法排除外部使用者，因此这一破坏必须写进 README 与 release notes，
不能只在提案里提。

选择让 `1` 落空（而不是把它分配给某个具体失败）是刻意的：落空使旧判断**必然不匹配**，比让它
匹配上某一种失败更容易被发现。

### ABI 兼容性

不适用 —— 本库以 SPM 源码分发，使用方每次重新编译。

### 下游影响

- 本仓库内：`Example/` 下的示例工程只判断成败，不读 code，**不需要改**（落地时核实）。
- `swift-helper-service`：**不需要改就能编译**，但**建议改** —— 把「任何 dlopen 失败都回退
  remap」收紧为「只在 `18`（目标拒绝加载）时回退」。收益是不再对权限类失败做注定失败的尝试，
  也就不再在目标进程里白留空转线程与 shellcode 页。这属于下游的改动，本提案只提供能力。
- `FinderSidebarIconFix` / `InjectionScaffold`：不受影响。

### 文档与示例

- `README.md` —— 三处：
  1. **Requirements 新增运行前提**：AMFI 库校验的全局开关（关 SIP 不足以放行非平台签名的
     dylib 注入平台二进制），含 `defaults write` 命令与 `library validation is globally disabled`
     这个生效判据。写明来源是 `amfid` 逆向，并给出本机可复现的核实方式。
  2. **错误码一节重写**：补上同步路径的表，说明同步与异步编号对齐、remap 自成一套，
     以及「先看 domain」。
  3. **新增跨进程使用注意**：`userInfo` 不保证跨 XPC 存活，判据要从 `code` 取，
     `localizedDescription` 需要调用方自己转运。
- `Documentations/Design/InjectionStrategies.md` —— 失败模式一节补上「怎么从错误码判断该不该
  换路径」。这是选型文档，正是该讲这件事的地方。库校验那条已经先行写进去了（见「前期调研」），
  落地时把它与错误码 `18` 挂上钩。
- `AGENTS.md` 的 hazards 一节 —— 现有那条「两个 result-code 编码含义相反」保留不动，但补一句
  说明公开错误码是另一套东西，别把两者搞混。
- **已先行完成**：`MIMachInjector.h` / `MIMachInjectorRemap.h` / `InjectionStrategies.md` /
  `AGENTS.md` 里关于「关 SIP 与库校验」的错误理由已修正，明细见「前期调研」。落地时唯一的
  遗留动作是给 `MIMachInjector.h` 回填指向 README 新增前提一节的引用。
- **是否新增专题文章**：落地时按判据评估（「实现里有下次维护会踩、但代码本身看不出来的
  决策」）。当前倾向是**不写** —— 编号对齐的理由写在提案与枚举注释里已经够了。若最终决定写，
  在头部「配套文档」登记。

## API 演进与废弃策略

不废弃任何现有 API。同步路径 `code` 语义变化按 semver 属于破坏性变更，但本库尚在 `0.x`
（当前最新 tag `0.4.3`），按惯例发 **minor**（`0.5.0`）并在 release notes 顶部显式列出这条。

将来新增失败点一律**在枚举尾部追加**，绝不复用空洞号，也不改动既有取值。这条规则写进
三个头文件的枚举声明处。

## 落地步骤

1. **先写复现测试。** 断言同步路径两种不同失败（`pid = 0` 与一个不存在的 pid）产生**不同**的
   `code`。这两条都不需要 root。**确认它在修复前失败**（当前两者都是 `1`）。
2. 把 report 块 → `NSError` 的判定抽成 `MIMachInjectorErrorForDlopenReport()`，轮询循环改为
   调用它。行为不变，纯重构。补测试：目标拒绝（含 `dlerror` 原文转运到新 userInfo key）、
   目标死亡、report 不可读但目标存活（应为成功）三种输入。
3. 声明 `MIMachInjectorErrorCode`，`MIMachInjectorErrorMake` 首参改为枚举，逐一替换 28 个
   调用点。第 1 步的测试转为通过。
4. 声明 `MIMachInjectorAsyncErrorCode`（取值不变），替换 21 处裸字面量，`MakeError` 首参收紧。
   **逐条比对头文件注释表格，确认取值一个都没变。**
5. `MIMachInjectorRemapErrorCode` 移到公开头文件，取值不变；「Debug hints by code」表拆到各
   case 的文档注释上。
6. 新增 `MIMachInjectorRemoteErrorMessageKey` 并在同步路径填充。
7. **横向排查**：确认 `Example/` 与仓库内其它位置没有依赖 `code == 1` 的判断；确认三条路径
   没有别的地方还在构造裸 `NSError`（绕过各自的 `MakeError`）。
8. 真实注入验证：向一个平台二进制目标注入非平台签名的 payload，在 plist 开关**关闭**的状态下
   确认拿到 `code 18` 且 `MIMachInjectorRemoteErrorMessageKey` 里有 AMFI 的拒绝理由；打开开关后
   确认注入成功。这一步同时验证了错误码分类与 README 新增的运行前提。**判据是两次结果不同**，
   而不是任何单次的绝对结果 —— 后者会随机器配置漂移。
9. 同批次更新「文档与示例」列出的各篇文档，把提案状态改为 `Implemented`，并在
   `Documentations/README.md` 与 `Evolutions/README.md` 登记。

**收尾时必须判断两件事**（本仓库约定）：

- **配套专题文章** —— 见「文档与示例」最后一条，当前倾向不写，落地时确认并记录判断。
- **新术语** —— 本提案未引入自造词。「平台二进制」（platform binary）是 AMFI 的既有术语，
  首次出现处解释一句即可，不必建术语表。

## 决策日志

| 日期 | 变更 | 说明 |
|------|------|------|
| 2026-08-11 | Created as Draft | 起因是 `FinderSidebarIconFix` 向 Finder 注入只拿到 `MIMachInjectorErrorDomain error 1`，根因（AMFI 库校验拒绝 payload）在传递中丢光。横向排查发现三条路径都没有公开错误码枚举，同步路径最严重（28 个失败点共用 `code:1`）。核心设计决策是**同步路径复用异步路径的编号语义而非自成一套**，理由是仓库里已有 `MIMachInjectorDlopenResultCode` 与 notepad `result_code` 含义相反这个被写进 hazards 的坑，不能在公开 API 上重演。下游三个仓库已核实无一读取 `NSError.code`，故重新编号的实际破坏面为零。AMFI 判定链的三个可观测推论已在本机核实（`amfid` 字符串、plist 内容、SIP 状态），`csr_check` 常量值未复核。 |
| 2026-08-11 | 先行修正「关 SIP 就不强制库校验」这个错误理由 | 用户确认该机制已验证过（amfid 只在 SIP 关闭时才读那份 plist，真正的开关是 `DisableLibraryValidation`），批准在提案落地前单独改注释。改了四个文件，明细见「前期调研」的对应一节。**这一项不再属于本提案的落地范围**，提案保留它只是为了记录理由为什么是错的。 |
