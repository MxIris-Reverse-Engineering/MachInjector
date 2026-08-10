# dlopen 注入路径的实现 —— 同步与异步

## 面向读者

- 已读[三条注入路径总览](InjectionStrategies.md)，知道这两条路都是"在目标里跑 `dlopen`"
- 要改 `MIMachInjector.m` / `MIMachInjectorAsync.m` 或它们的 shellcode
- 注入报成功但 payload 没反应、或者目标莫名崩溃，想定位在哪一步

remap 路径完全不同，见 [RemapArchitecture.md](RemapArchitecture.md)。

## 全局图：两阶段线程

两条路径共用同一个骨架，理解它就理解了 90%：

```
注入器                          目标进程
------                          --------
task_for_pid ─────────────────▶ (拿到 task port)
mach_vm_allocate(code) ───────▶ shellcode 页（写入后置为 R+X）
mach_vm_allocate(stack) ──────▶ 裸线程的栈
mach_vm_allocate(report) ─────▶ 结果页（R+W）
thread_create_running ────────▶ ┌─ 裸 mach 线程（无 TLS）
                                │    pthread_create_from_mach_thread()
                                │    └───────────┐
                                │                ▼
                                │           ┌─ pthread（有完整运行时）
                                │           │    sandbox_extension_consume()
                                │           │    dlopen(payload)
                                │           │    结果写入 report/notepad
                                │           └─  ...
                                └─ 原地等待（死循环 / 被 pthread 终结）
轮询或事件 ◀────────────────────  结果页
```

**为什么必须是两阶段**：`dlopen` 不能在裸 mach 线程上调用。下一节解释为什么。

## 裸 mach 线程的三个禁忌

`thread_create_running()` 造出来的线程不是 pthread。它没有 pthread 的线程结构，
**没有线程本地存储（TLS，Thread-Local Storage）** —— 在 ARM64 上表现为 `TPIDRRO_EL0` 寄存器
是 0。libSystem 里大量函数隐式依赖 TLS，在这条线程上会以各种方式炸掉。踩过的三个坑：

**1. 不能 `ret`。**
新线程的 x30（链接寄存器）初始化为 0，正常返回等于跳到地址 `0x0`，
立刻 `EXC_BAD_ACCESS (code=1, address=0x0)`。所以 shellcode 里的裸线程部分**必须**以死循环
（`b .` 或 yield 循环）结尾，等着被外部终结。

**2. 不能 `mach_msg()`。**
它内部走 MIG（Mach Interface Generator，Mach 接口生成器）拿回复端口，
`mig_get_reply_port()` 会读 TLS，于是崩在 `EXC_BAD_ACCESS (address=0x10)` ——
那是从空指针偏移 `0x10` 读的结果。

**3. 不能自己调 `thread_terminate()`。**
这条最反直觉：它看起来只是终结自己，但**同样经过 MIG**，同样崩在 `0x10`。
异步路径正是在实现完并测试后才发现这一点（崩在 `thread_terminate + 36 → mig_get_reply_port`），
才改成由 pthread 反过来杀它。

**这条线程上能安全用的**：
- `mach_thread_self()` —— 直接的 Mach trap，不经 MIG
- `pthread_create_from_mach_thread()` —— 专为这个场景设计的入口
- 纯计算、访存指令

**一旦进了 pthread，这些限制全部消失** —— 它有完整的运行时，`dlopen`、`dispatch_once`、
pthread 互斥锁都正常。

## 同步路径 `MIMachInjector`

### shellcode 布局（`loader_arm64.s`）

一整块连续内存，前面是代码、后面是数据，注入器在写入前把数据槽填好：

| 符号 | 用途 |
|---|---|
| `___shellcode_start` | 裸线程入口 |
| `__thread_entry` | pthread 入口 |
| `___patch_pthread_create` | `pthread_create_from_mach_thread` 的地址 |
| `___patch_sandbox_consume` | `sandbox_extension_consume` 的地址 |
| `___patch_dlopen` / `___patch_dlerror` | 同名函数地址 |
| `___data_payload_path` | payload 路径（1280 字节） |
| `___data_sandbox_token` | 沙盒扩展令牌（1280 字节） |
| `___data_report_address` | **结果页在目标里的地址** |

函数地址由注入器 `dlsym(RTLD_DEFAULT, …)` 取得后 **`ptrauth_strip` 去掉签名**再填进去 ——
shellcode 用 `blr` 裸调用，不做认证。这些都是共享缓存里的函数，在所有进程里地址相同，
所以注入器查到的地址在目标里同样有效。

### 执行流

```asm
___shellcode_start:                  ; 裸 mach 线程
    adr    x2, __thread_entry
    paciza x2                        ; ← 必须签名：libpthread 会认证它
    blr    (pthread_create_from_mach_thread)
    movz/movk x0, "DONE"             ; 写进 x0 供注入器轮询
    b .                              ; 原地死循环

__thread_entry:                      ; pthread
    ldr    x19, (报告页地址)
    blr    (sandbox_extension_consume)
    blr    (dlopen)                  ; x0 = handle 或 NULL
    str    x0, [x19, #REPORT_HANDLE]
    cbnz   x0, 成功分支
    blr    (dlerror) → 逐字节拷进报告页
    dmb sy                           ; ← 先发布内容
    str    #2, [x19, #REPORT_RESULT_CODE]   ; 再发布结果码
    retab
```

三个细节值得注意：

**`paciza x2`**：`pthread_create_from_mach_thread` 收的是 `void *(*)(void *)`，在 arm64e 上
这是个 IA/0 签名的函数指针。libpthread 会把它重签进自己的结构，`_pthread_start` 分支前还会
再认证一次。传裸地址过去，新线程会在跑第一条指令之前就死于 PAC 异常，而且**什么线索都不留**。

**先写内容、再写结果码，中间隔一条 `dmb sy`（内存屏障）**：注入器在另一个进程里轮询这页，
没有屏障的话它可能读到"结果码已置位、但 handle 和错误信息还没写完"的半成品。

**报告页为什么单独一页**：shellcode 那块内存被 `vm_protect` 成了 `R+X`（只读+可执行），
pthread 写不进去。所以结果必须写到注入器另外分配的、`R+W` 的一页。

### 注入器侧的收尾

两段轮询：

1. 轮询线程寄存器，等 `x0`（x86_64 上是 `rax`）变成 `"DONE"` —— 证明 pthread 建起来了；
2. 轮询报告页，等结果码变成 `Loaded` 或 `Failed`。

轮询预算是 100 次 × 20 ms = **2 秒**。超时按**成功**处理 —— 这是刻意的：构造函数慢的 payload
不该被误判成失败。所以这个信号的准确语义是"**没检测到失败**"，不是"确认成功"。

有一个例外会被识别为失败：**读不到报告页且目标进程已经不在了**。这种情况发生在代码签名监控
发现页哈希不符时 —— 内核在那一页被换入时直接杀掉进程，`dlopen` 根本没机会返回。
如果不区分这一种，注入器会等满 2 秒然后报告成功，而目标早就没了。

### 线程状态的 PAC 转换

arm64e 上不能直接把 shellcode 地址塞进新线程的 PC。流程是：

```objc
__darwin_arm_thread_state64_set_pc_fptr(state, ptrauth_sign_unauthenticated(code, ptrauth_key_asia, 0));
thread_create(task, &thread);
_thread_convert_thread_state(thread, 2, flavor, &state, ..., &machineState, ...);
```

`thread_convert_thread_state()` 是 libsystem_kernel 里的私有函数（`dlsym` 取得），
把线程状态在"用户态表示"和"机器态表示"之间转换，方向 `2` 是转成机器态。
它负责把 PC 上的签名换成目标线程上下文能接受的形式。

**系统版本差异**：macOS 14.4 起必须 `thread_terminate` 掉先前 `thread_create` 出来的线程，
再用转换后的状态 `thread_create_running` 重新起一条；更早的版本可以直接 `thread_set_state`
然后 resume。代码里按 `NSProcessInfo` 的版本号分流。

## 异步路径 `MIMachInjectorAsync`

目标进程里发生的事和同步版几乎一样，**区别全在完成通知**。

### notepad —— 比报告页多一层

异步版的共享结构叫 notepad，除了 `dlopen` 结果，还多了两个端口字段：

| 偏移 | 字段 | 用途 |
|---|---|---|
| `0x00` | `pthread_port` | pthread 的端口（调试用） |
| `0x04` | `mach_thread_port` | **裸 mach 线程自己的端口** |
| `0x08` | `result_code` | 见下方警告 |
| `0x10` | `handle` | `dlopen` 返回值 |
| `0x18` | `error_message[256]` | `dlerror()` 原文 |

> ⚠️ **`result_code` 的编码与同步版不同，且 `1` 的含义相反**：
> 这里 `0=成功 / 1=dlopen 失败 / 2=pthread 创建失败`，
> 同步版是 `0=尚未上报 / 1=dlopen 成功 / 2=dlopen 失败`。
> 两处代码里都有交叉引用的警告注释。读错会把成功当失败。

### 完成信号：让 pthread 杀掉 mach 线程

```
裸 mach 线程: mach_thread_self() → 存进 notepad   ; 直接 trap，安全
             pthread_create_from_mach_thread(...)
             yield 死循环                          ; 等着被杀

pthread:     dlopen → 结果写进 notepad
             从 notepad 读出 mach 线程端口
             thread_terminate(那个端口)             ; ← pthread 有 TLS，可以调
             retab

注入器:       dispatch_source(DISPATCH_SOURCE_TYPE_MACH_SEND, 监听 mach 线程端口)
             MACH_SEND_DEAD 触发 → 注入完成
             读 notepad → 清理栈和 notepad → 调用 completion handler
```

裸 mach 线程的死亡被注入器观察成端口的死亡通知（`MACH_SEND_DEAD`），顺势当作"注入完成"。
这不是设计之初的方案，而是前述三个禁忌逐个排除后剩下的唯一可行解。

### 两个已知的取舍

**只能单阶段完成。** 原本设想两阶段：mach 线程死 → 清理栈/notepad 并转为监听 pthread；
pthread 死 → 清理代码段并回调。做不到 —— notepad 里存的 `pthread_port` 是**目标进程端口
命名空间里的名字**，在注入器进程里要么不存在，要么指向完全无关的端口，无法用它建
dispatch_source。所以只能在 mach 线程死亡时一次性完成全部收尾。

**代码段故意不回收。** 回调触发时 pthread 可能还在自己的返回序列里（它刚调完
`thread_terminate`，还没执行完 `retab`），此时释放 shellcode 那页会让它踩空。
代价是每次注入泄漏约 2.6 KB，可接受。栈和 notepad 则可以安全释放 —— pthread 那时已经写完了。

## 沙盒扩展

目标若在沙盒里，未必读得到 payload 文件。注入器签发一个令牌随 shellcode 一起送进去：

```objc
char *token = sandbox_extension_issue_file(APP_SANDBOX_READ, path, 0);
// 异步路径用更窄的版本，把令牌绑定到目标的 audit token：
char *token = sandbox_extension_issue_file_to_process(APP_SANDBOX_READ, path, 0, auditToken);
```

目标侧在 `dlopen` 之前 `sandbox_extension_consume(token)`。

**它解决不了什么**：沙盒扩展给的是**读**权限。若目标的沙盒配置里有
`(deny file-map-executable)`，那条规则禁止的是"把文件映射为可执行"，扩展帮不上忙 ——
这正是 remap 路径存在的理由。

## x86_64 的差异

x86_64 的 shellcode（`loader_x86_64.s`）结构相同，但：

- **没有 PAC**，所以没有 `paciza`，也不需要 `thread_convert_thread_state`；
- **没有沙盒扩展**的 patch 点（`___x86_patch_sandbox_consume` 不存在），只有
  `pthread_create` / `dlopen` / `dlerror` 三个；
- 完成信号写在 `rax` 而不是 `x0`；
- 报告页机制与 arm64 一致。

## 排查提示

| 现象 | 查什么 |
|---|---|
| 目标崩在 `pc = 0x0` | 裸线程执行到了 `ret`。检查 shellcode 的死循环是否被改动 |
| 目标崩在 `address=0x10` | 在裸 mach 线程上调用了走 MIG 的函数。把它挪进 pthread |
| 新线程一条指令都没跑就崩 | `paciza` 丢了 —— 传给 libpthread 的是裸函数指针 |
| 注入报成功、payload 无反应 | 报告页可能是超时按成功处理的。看 `dlerror` 有没有内容；确认 payload 构造函数是否执行 |
| `dlopen` 报 `file system sandbox blocked mmap()` | 沙盒禁止映射可执行文件，扩展无解 → 改走 remap |

## 相关代码

- `Sources/MachInjector/MIMachInjector.m` —— 同步路径
- `Sources/MachInjector/MIMachInjectorAsync.m` —— 异步路径（文件头部有更详细的历史记录）
- `Sources/MachInjector/loader_arm64.s` —— 同步 shellcode（arm64/arm64e）
- `Sources/MachInjector/loader_x86_64.s` —— 同步 shellcode（x86_64）
- `Sources/MachInjector/loader_arm64_async.s` —— 异步 shellcode

arm64e 注入路径基于 [Jeremy Legendre](https://github.com/jslegendre) 的工作，
shellcode 骨架源自 kekeimiku（MIT License，见 `loader_arm64.s` 头部）。
