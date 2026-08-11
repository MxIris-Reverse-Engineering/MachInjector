# 三条注入路径 —— 总览与选型

## 面向读者

- 第一次接触 MachInjector，想知道**它到底有几种注入方式、各自怎么实现的**
- 要为一个具体目标进程选路，不确定该用哪个类
- 遇到注入失败，想判断是"这条路走不通"还是"实现有 bug"

这是注入相关文档的**总入口**。读完这篇再按需深入：
[dlopen 两条路径的实现](DlopenInjectionInternals.md)、
[remap 路径的端到端架构](RemapArchitecture.md)。

## 先看结论：三条路径

库里有三个入口类，对应三条互不相同的注入路径：

| 类 | 怎么让目标加载 payload | 何时用 |
|---|---|---|
| `MIMachInjector` | 在目标里跑一段 shellcode 调用 `dlopen` | 默认选择。同步返回成败 |
| `MIMachInjectorAsync` | 同上，但完成通知是事件驱动的 | 需要超时控制、不想阻塞调用线程 |
| `MIMachInjectorRemap` | **完全不调用 `dlopen`**，自己把 payload 映射进去并手工完成 dyld 的活 | 目标拒绝 `dlopen` 时的唯一出路 |

前两条本质是同一件事的两种收尾方式，第三条是**完全不同的机制**。

## 所有路径共同的那部分

不管走哪条，要在别人的进程里执行代码，都绕不开这四件事：

### 1. 拿到目标的 task port

`task_for_pid()`。这是一切的前提，也是最容易卡住的一步 —— 它要求调用方是 root，且通常要求
SIP（System Integrity Protection，系统完整性保护）关闭；对 Apple 的平台二进制更是必须关闭 SIP。
拿不到 task port，三条路都走不通。

### 2. 在目标里造一个执行上下文

macOS 没有 Linux 的 `ptrace(PTRACE_ATTACH)` + 改寄存器那套玩法。这里的做法是：

1. `mach_vm_allocate` 在目标里要一块内存，把 shellcode `mach_vm_write` 进去，
   `vm_protect` 成可执行；
2. 再要一块内存当栈；
3. `thread_create_running()` 起一条**裸 mach 线程**，PC 指向 shellcode，SP 指向栈顶。

"裸 mach 线程"是理解后面所有复杂度的关键 —— 它不是 pthread，**没有线程本地存储（TLS，
Thread-Local Storage）**，因此大部分 libSystem 的函数在它上面不能用。详见
[dlopen 路径实现](DlopenInjectionInternals.md)里的"裸 mach 线程的三个禁忌"。

### 3. 越过 arm64e 的指针签名

在 Apple Silicon 上，目标若是 arm64e 二进制（所有 Apple 自家的应用都是），
**指针认证（PAC，Pointer Authentication Code）** 会介入：函数指针在使用前要通过密码学校验，
校验失败就崩。这带来两个具体障碍：

- **新线程的 PC 必须是签好名的。** 直接把 shellcode 地址塞进 PC 会立刻失败。dlopen 两条路径用
  `thread_convert_thread_state()` 把线程状态从注入器的上下文转换到目标的上下文；
- **PAC 密钥是每进程独立的。** 注入器签出来的指针，在目标里认证必然失败。所以凡是要在目标里
  用的函数指针，都必须**在目标里**签，或者传裸地址过去、由目标侧的代码签。

这条对 remap 路径影响最大，因为它要手工完成 dyld 的全部重定位工作。背景见
[PAC 备忘](PACHandbookForRemap.md)。

### 4. 让目标有权读到 payload 文件

目标若在沙盒里，它未必读得到你放在用户目录下的 dylib。三条路径都用
**沙盒扩展（sandbox extension）** 解决：注入器调用 `sandbox_extension_issue_file()` 为 payload
路径签发一个令牌，把令牌一起写进目标，目标侧的代码先 `sandbox_extension_consume()` 再
`dlopen`。异步路径还用了 `sandbox_extension_issue_file_to_process()`，把令牌绑定到目标的
audit token 上，范围更窄。

> 注意：沙盒扩展解决的是**读文件**的权限，解决不了 `(deny file-map-executable)` ——
> 那条规则禁止的是把文件映射为可执行，是 remap 路径存在的理由之一。

## 三条路径各自的机制

### `MIMachInjector` —— 同步 dlopen

最直接的一条。shellcode 在目标里做两件事：

```
裸 mach 线程:  pthread_create_from_mach_thread(start_routine = __thread_entry)
              → 把 "DONE" 写进 x0，然后原地死循环

pthread:      sandbox_extension_consume(token)
              → dlopen(payloadPath, RTLD_LAZY)
              → 把 handle / dlerror() 写进报告页
```

为什么要多起一个 pthread？因为 `dlopen` 在裸 mach 线程上不能用（没有 TLS）。
`pthread_create_from_mach_thread()` 是少数能在裸 mach 线程上安全调用的函数之一。

注入器侧则是轮询：先轮询线程寄存器 `x0` 是否变成 `"DONE"`（证明 pthread 建起来了），
再轮询报告页拿 `dlopen` 的真实结果。

**为什么需要报告页**：`"DONE"` 只证明 `pthread_create` 返回了，此时 `dlopen` 还没跑。
早期版本到此就报成功，于是一个拒绝加载 payload 的目标和一次成功加载**长得一模一样**。
现在 pthread 会把 `dlopen` 的返回值和 `dlerror()` 的原文写进注入器单独分配的一页
（不能写进 shellcode 那块 —— 它是只读+可执行的），注入器据此报告真实结果。

### `MIMachInjectorAsync` —— 事件驱动的 dlopen

目标里发生的事和同步版几乎一样，差别全在**怎么知道它结束了**。

同步版靠轮询，异步版靠 Mach 端口的死亡通知：

```
裸 mach 线程:  把 mach_thread_self() 存进 notepad
              → pthread_create_from_mach_thread(...)
              → yield 死循环，等着被杀

pthread:      dlopen → 结果写进 notepad
              → 从 notepad 读出 mach 线程的端口
              → thread_terminate(那条 mach 线程)   ← 关键动作
              → 自己正常返回

注入器:        dispatch_source 监听 mach 线程端口
              → MACH_SEND_DEAD 触发 = 注入完成
              → 读 notepad 拿结果 → 调用 completion handler
```

**为什么是 pthread 去杀 mach 线程**，而不是 mach 线程自己退出？这是三次失败尝试之后的结论：

1. 裸 mach 线程**不能 `ret`** —— 它的 x30（链接寄存器）是 0，返回等于跳到地址 0；
2. 不能用 `mach_msg()` 等消息 —— 它内部经 MIG（Mach Interface Generator）拿回复端口，
   要读 TLS，而裸线程的 `TPIDRRO_EL0` 是 0，崩在地址 `0x10`；
3. **也不能自己调 `thread_terminate()`** —— 同样走 MIG，同样的崩法。

所以只能由有完整运行时的 pthread 来终结它。而 mach 线程的死亡恰好能被注入器用
`dispatch_source` 观察到，就顺势当成了"注入完成"的信号。

API 上因此多了超时参数和 completion handler。

### `MIMachInjectorRemap` —— 绕开 dlopen

前两条都依赖目标能成功执行 `dlopen`。这个前提对一类目标不成立：
**严格沙盒的系统守护进程**，其沙盒配置里有 `(deny file-map-executable)`，任何位于用户目录、
`/Library/Frameworks` 之下的 payload，`dlopen` 会直接被 dyld 的沙盒检查拦下。

**库验证（library validation）** 被强制的目标也会拒绝 `dlopen`，但它和 seatbelt 那条性质不同：
seatbelt 那条谁都改不了，只能绕开；库验证是**整台机器的一个开关**，机器主人设上就没有了
（详见下面「不要预测，直接试」）。remap 路径对两者都有效，但只有 seatbelt 那条是**非它不可**。

remap 路径的思路是：**既然目标不让 dyld 加载，那就不用 dyld**。

```
注入器: dlopen 一次 payload（在自己进程里，只为拿到布局和入口偏移）
       → mach_vm_remap 把 payload 的段直接映射进目标
       → 用 payload 文件的原始字节恢复可写段        ← 步骤 7c
       → 解析 LC_DYLD_CHAINED_FIXUPS，生成重定位工作表
       → 把 loader、工作表、配置页都写进目标
       → 起裸 mach 线程执行 loader 的 stage1

目标:   apply_fixups()  ← 手工完成 dyld 的重定位 + PAC 重签
       → pthread_create_from_mach_thread(pthread_thunk)
       → perform_runtime_handoff()  ← 手工补上 dyld 对 libobjc / Swift 运行时的通知
       → 跳进 payload 的入口符号
```

代价是**要手工复刻 dyld 做的每一件事**：chained fixups 的解析与重签、
`map_images` 通知 libobjc、`swift_register*` 通知 Swift 运行时。这三块各自都有坑，
所以 remap 路径的文档最多：

- [端到端架构](RemapArchitecture.md) —— 完整数据流，**先读这篇**
- [Chained Fixups 全链路](ChainedFixupsPipeline.md) —— 重定位的解析与重签
- [Loader Dylib 内部构造](LoaderDylibInternals.md) —— 那个被映射进目标的小 dylib
- [PAC 备忘](PACHandbookForRemap.md) —— arm64e 指针签名
- [运行时交接](StrictSeatbeltPayloadRuntimeHandoff.md) —— 通知 libobjc / Swift 运行时
- [注入器运行时脏状态](../Internal/InjectorRuntimeDirtyState.md) —— 排查 remap 崩溃前必读

remap 路径对 payload 有额外要求：它必须导出一个 `void *entry(void *)` 形式的入口符号，
因为没有 dyld，构造函数不会自动跑。

## 怎么选

```
目标能不能 dlopen？
├─ 不确定 → 直接试 MIMachInjector，失败了再退 MIMachInjectorRemap
│           （不要用 csops 的 CS_REQUIRE_LV 去预测，见下）
├─ 能    → MIMachInjector（要超时/非阻塞就用 MIMachInjectorAsync）
└─ 不能  → MIMachInjectorRemap
           （payload 需改造：导出 void *entry(void *)）
```

**不要预测，直接试。** 一个很自然的想法是用 `csops(CS_OPS_STATUS)` 读 `CS_REQUIRE_LV` 标志来
预判目标会不会拒绝 `dlopen`。这个预测不可靠，原因是**标志和强制不在同一个维度上**：
`CS_REQUIRE_LV` 是**进程**的属性（这个进程请求库验证），而是否真的强制是**整台机器**的状态。
从前者推不出后者。

真正的开关是一份 plist：`amfid` 读
`/Library/Preferences/com.apple.security.libraryvalidation.plist`，发现
`DisableLibraryValidation` 为真就全局放行（日志里会打
`library validation is globally disabled`）。而它**只在 SIP 关闭时才会去读这份文件** ——
SIP 开着则直接忽略，plist 写了也没用。

所以「关 SIP」和「库验证不强制」是**必要不充分**关系：关 SIP 只是解锁了那个开关，它本身不是
开关。这一点值得单独记住，因为它有两个方向的推论，两个都会咬人：

- **关了 SIP 不等于就能注入 Apple 应用。** 平台二进制（Finder、Dock、各种系统服务）加载
  非平台签名的 dylib，在 plist 没设的机器上照样被拒，内核日志写得很直白：
  `mapping process is a platform binary, but mapped file is not`。
- **写了 plist 但 SIP 开着也没用。** amfid 根本不读。

`MIMachInjector` 会如实报告 `dlopen` 的拒绝并带回 `dlerror()` 原文，据此判断即可：
若拒绝理由指向库验证，那是机器配置问题（让机器主人设上面那个开关），不必退回 remap；
若指向 seatbelt 的 `file-map-executable`，才是该退回 remap 的场景。

## 各自的失败模式

| 症状 | 多半是哪条路、什么原因 |
|---|---|
| `task_for_pid` 失败 | 三条通用：不是 root，或 SIP 开着 |
| `dlopen` 返回 NULL，`dlerror` 说 `file system sandbox blocked mmap()` | 目标沙盒禁止映射可执行文件 → 改走 remap |
| `dlopen` 返回 NULL，`dlerror` 说 `code signature invalid` | payload 签名问题（注意 `cp` 一个 framework 会破坏签名） |
| `dlopen` 返回 NULL，内核日志有 `library_validation_failure`、理由是 `mapping process is a platform binary, but mapped file is not` | 这台机器仍在强制库验证 → 设 `DisableLibraryValidation`（需 SIP 已关）。**不是**该退回 remap 的场景，remap 只是绕过它，开关才是解法 |
| **目标进程直接消失**，什么都没报 | 页哈希与签名不符，代码签名监控直接杀进程；`MIMachInjector` 会把它识别为失败 |
| 注入报成功但 payload 没反应 | 检查 payload 的构造函数是否真的跑了；remap 路径不会自动跑构造函数 |
| payload 崩在一个"地址合法、只有 PAC 位错"的指针上 | remap 路径特有，**先读[注入器运行时脏状态](../Internal/InjectorRuntimeDirtyState.md)** |

实测的拒绝时序（macOS 26.5，用于判断超时预算是否够）：路径不存在 0.3 ms，
沙盒拦截 0.7 ms，10 MB dylib 签名无效 15–19 ms。都是同步返回，远小于注入器 2 秒的轮询预算。

## 平台支持

| | arm64e / arm64 | x86_64 |
|---|---|---|
| `MIMachInjector` | 完整（含沙盒扩展、PAC 线程状态转换） | 支持，**无沙盒扩展**（shellcode 里没有该 patch 点） |
| `MIMachInjectorAsync` | 完整 | 支持 |
| `MIMachInjectorRemap` | **仅 arm64/arm64e** | 不支持（整个实现以 `__arm64__` 为条件编译） |

arm64 与 arm64e 的差异在于后者需要 PAC 处理；两者共用同一份 shellcode 源码，
由条件编译和运行时判断分流。

## 相关代码

| 路径 | 实现 | shellcode |
|---|---|---|
| 同步 | `Sources/MachInjector/MIMachInjector.m` | `loader_arm64.s` / `loader_x86_64.s` |
| 异步 | `Sources/MachInjector/MIMachInjectorAsync.m` | `loader_arm64_async.s` |
| remap | `Sources/MachInjector/MIMachInjectorRemap.m`、`MIMachInjectorRemapRestore.c` | `loader_arm64_remap.s` + `loader_arm64_remap_fixup.c` + `loader_arm64_remap_handoff.c`（编成独立 dylib） |
