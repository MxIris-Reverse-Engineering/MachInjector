# MachInjector

A Swift Package for injecting a dylib into a running macOS process via `task_for_pid` and remote shellcode.

Distilled from [yabai](https://github.com/koekeishiya/yabai)'s injection code and extended with an asynchronous, event-driven implementation for ARM64.

> **Warning**
> Dylib injection requires the `com.apple.security.cs.debugger` entitlement (or root) and is typically used for reverse engineering, debugging tools, and accessibility helpers. Use it only on processes you own or are authorized to instrument.

## Features

- Three injection paths under a unified API surface
  - **Synchronous** (`MachInjector`) — works on ARM64 and x86_64; completion is polled via a magic marker
  - **Asynchronous V2** (`MachInjectorAsync`) — ARM64 only; event-driven completion via `dispatch_source` on `MACH_SEND_DEAD`
  - **mach\_vm\_remap** (`MachInjectorRemap`) — arm64 / arm64e only; bypasses `dlopen` inside the target by mapping the payload's segments straight into the target's VM space. Necessary for strict seatbelt daemons (sharingd, rapportd, and similar) that deny `file-map-executable` for any path outside a hard-coded system whitelist.
- Rosetta 2 / translated x86_64 targets supported by the ARM64 shellcode (via `liboah.dylib` probing)
- Detailed `NSError` reporting, including the remote `dlerror()` string when `dlopen()` fails in the target process
- Swift `async/await` import for the asynchronous API
- Optional sandbox-extension support on the synchronous ARM64 path (see [`feature/sandbox_support`](../../tree/feature/sandbox_support))

## Requirements

- macOS 10.15 or later
- Swift 5.9+ / Xcode 15+
- ARM64 (Apple Silicon) for `MachInjectorAsync`; ARM64 or x86_64 for `MachInjector`
- `task_for_pid` privilege on the injecting process. In practice this means one of:
  - Running as root
  - Holding `com.apple.security.cs.debugger` (and being properly code-signed)
  - Delegating injection to a privileged helper (see the [example app](#example-app))

## Installation

### Swift Package Manager

Add to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/MxIris-Reverse-Engineering/MachInjector.git", branch: "main"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: ["MachInjector"]
    ),
]
```

Or in Xcode: **File → Add Package Dependencies…** and enter the repository URL.

## Usage

### Synchronous injection

The synchronous API blocks the calling thread until the remote `dlopen()` completes (or fails). It supports both ARM64 and x86_64 targets.

**Swift**

```swift
import MachInjector

do {
    try MachInjector.inject(pid: targetPID, dylibPath: "/path/to/payload.dylib")
    print("Injected successfully")
} catch {
    print("Injection failed: \(error.localizedDescription)")
}
```

**Objective-C**

```objc
#import <MachInjector/MachInjector.h>

NSError *error = nil;
BOOL ok = [MIMachInjector injectToPID:targetPID
                            dylibPath:@"/path/to/payload.dylib"
                                error:&error];
if (!ok) {
    NSLog(@"Injection failed: %@", error);
}
```

### Asynchronous injection (ARM64)

The asynchronous API returns immediately and notifies completion via a callback on the main thread. It uses `dispatch_source` on the remote mach thread's port to detect termination, avoiding the polling loop of the synchronous path.

**Swift (async/await)**

```swift
import MachInjector

do {
    let result = try await MachInjectorAsync.inject(
        pid: targetPID,
        dylibPath: "/path/to/payload.dylib",
        timeout: 5.0
    )
    print("Injected, remote dlopen handle: 0x\(String(result.handle, radix: 16))")
} catch {
    print("Injection failed: \(error.localizedDescription)")
}
```

**Swift (completion handler)**

```swift
MachInjectorAsync.inject(
    pid: targetPID,
    dylibPath: "/path/to/payload.dylib",
    timeout: 5.0
) { result, error in
    if result.success {
        print("Handle: 0x\(String(result.handle, radix: 16))")
    } else {
        print("Error: \(error?.localizedDescription ?? "unknown")")
        if let remote = result.remoteErrorMessage {
            print("Remote dlerror: \(remote)")
        }
    }
}
```

**Objective-C**

```objc
#import <MachInjector/MachInjector.h>

[MIMachInjectorAsync injectWithPID:targetPID
                         dylibPath:@"/path/to/payload.dylib"
                           timeout:5.0
                 completionHandler:^(MIInjectionResult *result, NSError *error) {
    if (result.success) {
        NSLog(@"Handle: 0x%llx", result.handle);
    } else {
        NSLog(@"Failed: %@ (remote: %@)", error, result.remoteErrorMessage);
    }
}];
```

### mach\_vm\_remap injection (arm64 / arm64e, strict-sandbox targets)

The remap path avoids `dlopen` in the target entirely by projecting the payload's Mach-O segments straight into the target with `mach_vm_remap`. It is the only path that works for strict seatbelt daemons like `sharingd` or `rapportd`, whose sandbox profile denies `file-map-executable` for any path outside a hard-coded system whitelist.

The payload must expose an exported C function whose signature matches `void *(*)(void *)`. That is the entire contract: by the time the entry runs, the loader has already applied every `LC_DYLD_CHAINED_FIXUPS` slot with target-side PAC keys, called `libobjc`'s `map_images` for the payload (uniquing selrefs and registering classes / categories / protocols), and driven `libswiftCore`'s three `swift_register*` APIs over the payload's `__swift5_types` / `__swift5_protos` / `__swift5_proto` sections. The argument is a pointer to a `MachInjectorRemapPayloadConfig` (see `MIMachInjectorRemap.h`) — most payloads can ignore it. Payloads that would ordinarily rely on `__attribute__((constructor))` initialization must invoke that logic themselves from the entry, because `mach_vm_remap` skips dyld's constructor pass. See `Documentations/Design/StrictSeatbeltPayloadRuntimeHandoff.md` for the full derivation.

**Swift**

```swift
import MachInjector

do {
    try MachInjectorRemap.inject(
        pid: sharingdPID,
        payloadPath: "/path/to/RuntimeViewerServer.framework/Versions/A/RuntimeViewerServer",
        entrySymbol: "runtime_viewer_server_start"
    )
} catch {
    print("Remap injection failed: \(error)")
}
```

**Objective-C**

```objc
#import <MachInjector/MachInjector.h>

NSError *error = nil;
BOOL ok = [MIMachInjectorRemap injectToPID:sharingdPID
                               payloadPath:@"/…/RuntimeViewerServer"
                               entrySymbol:@"runtime_viewer_server_start"
                                     error:&error];
if (!ok) NSLog(@"Failed: %@", error);
```

The path ships a small ad-hoc-signed loader dylib as embedded bytes and dumps it to `/private/tmp/MIMachInjectorRemap_loader_XXXXXX.dylib` at injection time; the file is unlinked before the API returns.

**For contributors and maintainers**: the remap path is intricate — cross-process PAC signing, chained-fixup replay, libobjc / libswiftCore runtime notifications, and a 13-step VM-plumbing recipe. Before changing any of `Sources/MachInjector/MIMachInjectorRemap.m`, `Sources/MachInjector/loader_arm64_remap.s`, `Sources/MachInjector/loader_arm64_remap_fixup.c`, or `Sources/MachInjector/loader_arm64_remap_handoff.c`, read [`Documentations/Design/RemapArchitecture.md`](Documentations/Design/RemapArchitecture.md) — it is the entry-point document that then branches into four topical deep-dives (chained fixups, loader dylib internals, arm64e PAC, payload runtime handoff). Every source file's top-of-file docblock links back to the relevant document.

## Architecture

| | `MachInjector` (sync) | `MachInjectorAsync` (V2) |
|---|---|---|
| Architectures | ARM64, x86_64 | ARM64 only (Rosetta 2 targets supported) |
| Loader | `loader_arm64.s`, `loader_x86_64.s` | `loader_arm64_async.s` |
| Completion | Polls a `0x444f4e45` (`"DONE"`) marker in the notepad | Event-driven via `dispatch_source` on `MACH_SEND_DEAD` of the remote mach thread |
| Cleanup | Notepad freed; stack and code intentionally leaked | Notepad freed; stack and code intentionally leaked |
| Error reporting | `NSError` with domain `MIMachInjectorErrorDomain` | `NSError` with domain `MIMachInjectorAsyncErrorDomain`, plus remote `dlerror()` string |

Both paths follow the same high-level recipe:

1. `task_for_pid()` to get the target's task port.
2. Allocate a notepad, stack, and code region in the target via `mach_vm_allocate`.
3. Write the architecture-specific loader shellcode into the code region and mark it executable.
4. Create a raw mach thread via `thread_create_running()` with the loader as its entry point.
5. Wait for completion (poll in V1; `MACH_SEND_DEAD` in V2), read the result from the notepad, and clean up.

### Why raw mach threads are tricky

Threads created by `thread_create_running` have no thread-local storage (`TPIDRRO_EL0 = 0` on ARM64) and a NULL link register. They cannot:

- Call any MIG-backed routine (`mach_msg`, `thread_terminate`, `mach_port_allocate`, …) — these would dereference NULL TLS and crash.
- Use `ret` — there is no return address; the thread must be terminated externally.

The V2 loader works around this by having the mach thread spawn a pthread (which *does* have TLS) via `pthread_create_from_mach_thread()`. The pthread performs the `dlopen()`, writes the result to the notepad, and then calls `thread_terminate()` on the mach thread. The dying mach port raises `MACH_SEND_DEAD` in the injector, which is what `dispatch_source` is monitoring.

See the design notes at the top of [`MIMachInjectorAsync.h`](Sources/MachInjector/include/MIMachInjectorAsync.h) for the full rationale.

### Intentional per-injection leak

Both paths leak a small amount of memory in the target process per injection:

- **Stack:** ~16 KB
- **Code segment:** ~2.6 KB

The pthread spawned by the loader may still be executing its return sequence (`ldp`, `add sp`, `retab`) at the moment the mach thread dies, so we cannot safely free the regions that back its execution. Only the notepad is reclaimed. Do not "fix" this without rethinking the loader's return sequence.

## Example app

`Example/MachInjectorExample/` demonstrates the recommended deployment shape for a sandboxed GUI that needs `task_for_pid` privilege:

```
GUI (sandboxed, non-privileged)              Daemon (root, via SMAppService)
MachInjectorExample  ── SwiftyXPC ──▶  com.machinjector.injectd
  ViewController                            main.swift
  MachInjectService (XPCConnection)         listener.setMessageHandler(MachInject.inject)
                                              ├── MachInjector.inject(pid:dylibPath:)
                                              └── MachInjectorAsync.inject(pid:dylibPath:timeout:)
```

- Schemes (in `MachInjector.xcworkspace`):
  - `MachInjectorExample` — sandboxed AppKit GUI
  - `com.machinjector.injectd` — privileged XPC helper daemon (installed via `SMAppService.daemon`)
  - `TestFramework` — a sample payload dylib used as a smoke test
- Shared message types live in the local SPM package `Example/MachInjectorExample/Packages/XPCBridge`.

Open `MachInjector.xcworkspace` (not the empty `MachInjector.xcodeproj` stub at the repo root) and select the appropriate scheme.

## Error codes

The asynchronous path defines codes 1–22 under `MIMachInjectorAsyncErrorDomain`. See the table in [`MIMachInjectorAsync.h`](Sources/MachInjector/include/MIMachInjectorAsync.h) for the full list — common ones include:

**`MIMachInjectorAsyncErrorDomain`**

| Code | Meaning |
|---:|---|
| 3 | `task_for_pid()` failed (permission denied or process not found) |
| 10 | Dylib path too long (max 1279 bytes) |
| 14 | Failed to create remote thread |
| 18 | `dlopen()` failed in target process (check `remoteErrorMessage`) |
| 19 | Injection timed out |

**`MIMachInjectorRemapErrorDomain`**

| Code | Meaning |
|---:|---|
| 1 | Failed to write embedded loader dylib to temp path |
| 2 | Failed to `dlopen` embedded loader dylib |
| 3 | Loader dylib missing required symbols |
| 4 | Failed to `dlopen` payload dylib in the injector |
| 5 | Payload does not export the requested entry symbol |
| 7 | Failed to open `libswiftCore.dylib` |
| 8 | `libswiftCore` missing required Swift-register APIs |
| 9 | Failed to locate `libobjc`'s `map_images` via dyld gAPIs |
| 10 | `task_for_pid()` failed (permission denied or process not found) |
| 11 | Failed to allocate memory in target process |
| 12 | Failed to `mach_vm_write` config page in target |
| 13 | Failed to `mach_vm_remap` payload segments into target |
| 14 | Failed to `mach_vm_remap` loader segments into target |
| 15 | Failed to convert thread state (arm64e ptrauth) |
| 16 | Failed to start remote mach thread |

## References

- [yabai](https://github.com/koekeishiya/yabai) — the original injection implementation this project is derived from.

## License

MachInjector is released under the MIT License. See [LICENSE](LICENSE) for details.
