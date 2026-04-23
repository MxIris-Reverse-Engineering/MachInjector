# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

MachInjector is a Swift Package that injects a dylib into a running macOS process via `task_for_pid` + remote shellcode. It is distilled from yabai's injection code and extended with an asynchronous, event-driven variant.

## Build / Run / Test

There is **no test target**. Two ways to build:

1. **Library only (SPM)** — from repo root:
   - `swift package update && swift build 2>&1 | xcsift` (Level 2 per global instructions)
   - Prefer `xcodebuildmcp` when available.
2. **Example app** — open `MachInjector.xcworkspace` (which references `Example/MachInjectorExample/MachInjectorExample.xcodeproj`). Schemes:
   - `MachInjectorExample` — sandboxed AppKit GUI
   - `com.machinjector.injectd` — privileged XPC helper daemon
   - `TestFramework` — a sample dylib to inject as a smoke test
   - `XPCBridge` — local SPM package with shared request/response types

Note: `MachInjector.xcodeproj` at the repo root is an empty stub (no `project.pbxproj`). Do not try to build from it — use SPM or the example workspace.

## Architecture

### Two injection paths (`Sources/MachInjector/`)

| Class (Swift name)       | File                     | Loader shellcode           | ARM64 | x86_64 | Completion model |
|--------------------------|--------------------------|----------------------------|-------|--------|------------------|
| `MachInjector` (sync)    | `MIMachInjector.m`       | `loader_arm64.s`, `loader_x86_64.s` | yes   | yes    | Polls a "DONE" magic written to notepad (`0x444f4e45`) |
| `MachInjectorAsync` (V2) | `MIMachInjectorAsync.m`  | `loader_arm64_async.s`     | yes   | no     | Event-driven via `dispatch_source` on `MACH_SEND_DEAD` of the remote mach thread's port |

The public Objective-C headers (`MIMachInjector.h`, `MIMachInjectorAsync.h`) are the source of truth — `MIMachInjectorAsync.h` contains an extensive design document explaining problems and solutions; read it before touching the async loader or cleanup logic.

### Non-obvious invariants (read before editing the async path)

- **Raw mach threads have no TLS (`TPIDRRO_EL0 = 0`)**. They cannot safely call any MIG-backed function: `mach_msg`, `thread_terminate`, `mach_port_allocate`. `mach_thread_self()` and `pthread_create_from_mach_thread()` are the only safe kernel/runtime calls from the shellcode entry.
- **Raw mach threads cannot `ret`** — `x30 = 0` on entry, so returning jumps to NULL. The mach thread must be terminated externally; it does not self-exit.
- **V2 termination flow**: mach thread saves its own port to notepad → spawns a pthread → enters an infinite yield loop → the pthread calls `dlopen()`, writes results, then calls `thread_terminate(mach_thread_port)` which raises `MACH_SEND_DEAD` in the injector.
- **Why completion cannot wait for the pthread**: `pthread_port` stored in the notepad is a port *name* in the target process's namespace and is meaningless to the injector. Completion fires as soon as `MACH_SEND_DEAD` arrives.
- **Intentional per-injection leaks in the target process**: stack (~16 KB) and code segment (~2.6 KB) are NOT deallocated because the pthread may still be executing its return sequence (`ldp`, `add sp`, `retab`). Only the notepad is freed. This applies to both sync and async paths — do not "fix" this leak without rethinking the return sequence.
- **Notepad layout** (V2, 280 bytes): `pthread_port(4)` `mach_thread_port(4)` `result_code(4)` `padding(4)` `handle(8)` `error_message(256)`. Keep layout in sync with `loader_arm64_async.s`.
- **Error code space**: `MIMachInjectorAsync.h` documents codes 1–22 under `MIMachInjectorAsyncErrorDomain`. Append new codes, don't renumber.
- **Rosetta 2 / translated x86_64 targets**: handled via `liboah.dylib` probing inside the ARM64 shellcode. Native x86_64 injection still goes through the synchronous `MIMachInjector` path.

### Sandbox extension flow (branch `feature/sandbox_support`)

The synchronous ARM64 path uses `sandbox_extension_issue_file(APP_SANDBOX_READ, path, flags)` in the injector, embeds the token into the shellcode at `__data_sandbox_token`, and the remote loader consumes it via `__patch_sandbox_consume` before calling `dlopen`. This lets a sandboxed helper inject dylibs that live outside its container. When modifying loader layout, keep these patch slot symbols in sync between the `.s` file exports and the `extern char __patch_*[]` declarations in `MIMachInjector.m`.

### Example app topology

`Example/MachInjectorExample/` demonstrates the expected deployment shape:

```
GUI (sandboxed, non-privileged)              Daemon (root, via SMAppService)
MachInjectorExample  ── SwiftyXPC ──▶  com.machinjector.injectd
  ViewController                            main.swift
  MachInjectService (XPCConnection)         listener.setMessageHandler(MachInject.inject)
                                              ├── MachInjector.inject(pid:dylibPath:)        (sync)
                                              └── MachInjectorAsync.inject(pid:dylibPath:timeout:) (async)
```

- Shared message types live in the local package `Example/MachInjectorExample/Packages/XPCBridge` (`MachInjectRequest`, `MachInjectResponse`, `MachInjectIdentifiers`, `machService`).
- The daemon is packaged as a LaunchDaemon via `Injectd/launchd.plist` embedded into `__TEXT,__launchd_plist`, and installed by the GUI with `SMAppService.daemon(plistName: "com.machinjector.injectd.plist")`.
- Injection requires `task_for_pid` privilege; the GUI is sandboxed and relies on the helper for that capability. Any new capability that needs `task_for_pid` must stay in the daemon, not the GUI.
- Remote SPM deps used by the example (from `Package.resolved`): `SwiftyXPC` (MxIris fork), `RunningApplicationKit`, `LaunchServicesPrivate`.

## Editing conventions specific to this repo

- When changing the loader assembly, update **all three**: the `.s` file, the matching `extern char __...[]` declarations in `MIMachInjector.m` / `MIMachInjectorAsync.m`, and the header docs if the notepad layout or error codes change.
- The root `Package.swift` targets macOS 11+ and has no test target. Do not add `testTarget(...)` without also wiring a CI/build scheme — there is no existing test harness to model after.
- Public API is Objective-C with `NS_SWIFT_NAME` — keep Swift names (`MachInjector`, `MachInjectorAsync`, `InjectionResult`, `InjectionCompletionHandler`) stable; they are consumed verbatim by `Injectd/main.swift`.
