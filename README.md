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
- Detailed `NSError` reporting, including the remote `dlerror()` string when `dlopen()` fails in the target process, and detection of a target that was killed mid-load rather than reporting a false success
- Swift `async/await` import for the asynchronous API
- Sandbox-extension support on the ARM64 dlopen paths — the injector issues a read token for the payload path (the async path binds it to the target's audit token) so a sandboxed target can reach a dylib outside its container. Note this grants *read* access only: it cannot defeat a `(deny file-map-executable)` rule, which is what `MachInjectorRemap` is for.

## Requirements

- macOS 10.15 or later
- Swift 5.9+ / Xcode 15+
- ARM64 (Apple Silicon) for `MachInjectorAsync`; ARM64 or x86_64 for `MachInjector`
- `task_for_pid` privilege on the injecting process. In practice this means one of:
  - Running as root
  - Holding `com.apple.security.cs.debugger` (and being properly code-signed)
  - Delegating injection to a privileged helper (see the [example app](#example-app))

### Library validation

The two `dlopen` paths ask the *target* to load your dylib, so the target's
library validation applies to it. A target that is a platform binary — Finder,
Dock, and most of `/System` — refuses any dylib that is not itself a platform
binary, and the refusal surfaces as
`MIMachInjectorErrorTargetRefusedToLoadDylib` / `MachInjector.Error.targetRefusedToLoadDylib`
(code 18) with the kernel logging
`mapping process is a platform binary, but mapped file is not`.

Whether validation is enforced is a property of the machine, not of your
process. `amfid` consults a single global switch:

```bash
sudo defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist \
    DisableLibraryValidation -bool true
```

**Disabling SIP is necessary but not sufficient.** SIP only controls whether
`amfid` reads that file at all: with SIP enabled the key is ignored entirely, and
with SIP disabled but the key unset, validation is still enforced. Both are
required. `amfid` watches the file and generally picks up a change immediately;
the confirmation is `amfid` logging `library validation is globally disabled`.

This does not apply to `MachInjectorRemap`, which never calls `dlopen` in the
target — that is the reason it exists.

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

**For contributors and maintainers**: start from
[`Documentations/README.md`](Documentations/README.md), whose entry point is
[Three injection paths — overview and how to choose](Documentations/Design/InjectionStrategies.md).
It explains how each of the three paths is implemented, the four problems every path has to solve
(task port, execution context, arm64e pointer signing, sandbox), the failure modes of each, and the
platform support matrix. The dlopen paths are then covered in
[dlopen injection internals](Documentations/Design/DlopenInjectionInternals.md).

The remap path is intricate — cross-process PAC signing, chained-fixup replay, libobjc / libswiftCore runtime notifications, and a 13-step VM-plumbing recipe. Before changing any of `Sources/MachInjector/MIMachInjectorRemap.m`, `Loader/loader_arm64_remap.s`, `Loader/loader_arm64_remap_fixup.c`, or `Loader/loader_arm64_remap_handoff.c`, read [`Documentations/Design/RemapArchitecture.md`](Documentations/Design/RemapArchitecture.md) — it is the entry-point document that then branches into four topical deep-dives (chained fixups, loader dylib internals, arm64e PAC, payload runtime handoff). Every source file's top-of-file docblock links back to the relevant document.

## Testing

```bash
swift test
```

Tests are XCTest (the package targets Swift tools 5.9, where `swift-testing` is unavailable). They
build a small dylib fixture with `clang` at run time and use it to reproduce, in-process and without
root, the state that `mach_vm_remap` would otherwise carry from the injector into the target. The
cross-process steps themselves need `task_for_pid` and are therefore not covered by unit tests —
see `Documentations/Evolutions/0001-restore-payload-writable-segments-before-fixups.md` for how the
byte-level decisions are separated from the VM writes so that the former stay testable.

## Architecture

| | `MachInjector` (sync) | `MachInjectorAsync` (V2) |
|---|---|---|
| Architectures | ARM64, x86_64 | ARM64 only (Rosetta 2 targets supported) |
| Loader | `loader_arm64.s`, `loader_x86_64.s` | `loader_arm64_async.s` |
| Completion | Polls the remote thread's register (`x0` / `rax`) for a `0x444f4e45` (`"DONE"`) marker, then polls a separate report page for `dlopen`'s verdict | Event-driven via `dispatch_source` on `MACH_SEND_DEAD` of the remote mach thread |
| Result channel | Report page, allocated read/write by the injector (the shellcode's own page is read+execute, so the pthread cannot write to it) | Notepad, which additionally carries the mach thread's own port so the pthread can terminate it |
| Cleanup | Stack, code, and report page all intentionally leaked | Stack and notepad freed; code intentionally leaked |
| Error reporting | `NSError` with domain `MIMachInjectorErrorDomain`, plus the remote `dlerror()` string when the target refuses the dylib | `NSError` with domain `MIMachInjectorAsyncErrorDomain`, plus remote `dlerror()` string |

`MachInjectorRemap` is deliberately absent from that table: it shares none of those mechanics.
It never calls `dlopen` in the target, so it has no loader shellcode of this shape and no
completion marker — it maps the payload's segments directly and replays dyld's work by hand.
See [InjectionStrategies.md](Documentations/Design/InjectionStrategies.md) for the comparison.

Both dlopen paths follow the same high-level recipe:

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

See the design notes at the top of [`MIMachInjectorAsync.h`](Sources/MachInjector/include/MIMachInjectorAsync.h) for the full rationale, and
[dlopen injection internals](Documentations/Design/DlopenInjectionInternals.md) for the three
prohibitions in detail — including the non-obvious one, that a raw mach thread cannot even call
`thread_terminate()` on itself.

### Intentional per-injection leak

Both paths leak a small amount of memory in the target process per injection:

| | `MachInjector` (sync) | `MachInjectorAsync` (V2) |
|---|---|---|
| Stack (~16 KB) | leaked | reclaimed |
| Code segment (~2.6 KB) | leaked | leaked |
| Report page / notepad | leaked | reclaimed |

The pthread spawned by the loader may still be executing its return sequence (`ldp`, `add sp`, `retab`) at the moment the mach thread dies, so the regions backing its execution cannot be freed safely. The async path can reclaim the stack and notepad because the pthread has demonstrably finished writing to them by the time `MACH_SEND_DEAD` fires — it is the pthread that terminates the mach thread. The sync path has no such ordering guarantee: it returns while the pthread may still be inside `dlopen`, which is also why its report page has to outlive the call. Do not "fix" this without rethinking the loader's return sequence.

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

Each path publishes an enumeration, so a caller branches on a named case rather
than on an integer literal: `MIMachInjectorErrorCode`,
`MIMachInjectorAsyncErrorCode`, and `MIMachInjectorRemapErrorCode`. Every case
carries its own documentation, including where to start looking when you hit it.

In Swift each one is nested under the class it belongs to:

```swift
do {
    try MachInjector.inject(pid: pid, dylibPath: payloadPath)
} catch MachInjector.Error.taskPortUnavailable {
    // Not a permissions problem you can route around: MachInjectorRemap needs
    // the same task port.
} catch MachInjector.Error.targetRefusedToLoadDylib {
    let reason = (error as NSError).userInfo[MachInjector.remoteErrorMessageKey] as? String
    // dlerror's own words — a code signature complaint points at the AMFI
    // switch below, a seatbelt one at MachInjectorRemap.
}
```

`MachInjectorAsync.Error` and `MachInjectorRemap.Error` follow the same shape,
as do `MachInjectorAsync.errorDomain` and `MachInjectorRemap.errorDomain`.

**Read the domain before the code.** The two `dlopen` paths deliberately share
one numbering — `3` is a missing task port in both, `18` is a refused dylib in
both — so a caller that uses both can share one `switch`. The remap path does
not share it: its `10` is the missing task port. Matching a bare integer without
checking `domain` will eventually mislead you.

The values in each enumeration are not contiguous. The synchronous path leaves a
hole wherever the async path has a failure it cannot produce, because giving one
integer two meanings across two domains callers use together is worse than any
number of gaps. New failure points are appended after the highest existing value;
published values never move.

> **Changed in 0.5.0.** The synchronous path previously returned `code: 1` for
> every failure, with the reason only in `userInfo`. It now returns a classified
> code, and `1` is deliberately left unassigned so that a stale `error.code == 1`
> check matches nothing instead of silently matching one specific failure.

**`MIMachInjectorErrorDomain`** (synchronous) — full list in
[`MIMachInjector.h`](Sources/MachInjector/include/MIMachInjector.h); the ones
worth branching on:

| Code | Meaning |
|---:|---|
| 3 | `task_for_pid()` failed. **Falling back to the remap path does not help** — it needs the same port |
| 18 | The target refused the dylib. `userInfo[MIMachInjectorRemoteErrorMessageKey]` (Swift: `MachInjector.remoteErrorMessageKey`) holds `dlerror`'s text. Code signature or library validation → see [Requirements](#library-validation); seatbelt denying `file-map-executable` → use `MachInjectorRemap` |
| 19 | Timed out. Also what an in-target `pthread_create` failure looks like from this path |
| 29 | The target died while loading — usually a payload whose page hashes do not match its signature |

**`MIMachInjectorAsyncErrorDomain`** — full list in
[`MIMachInjectorAsync.h`](Sources/MachInjector/include/MIMachInjectorAsync.h);
common ones:

| Code | Meaning |
|---:|---|
| 3 | `task_for_pid()` failed (permission denied or process not found) |
| 10 | Dylib path too long (max 1279 bytes) |
| 14 | Failed to create remote thread |
| 17 | `pthread_create` failed inside the target (this path can see it; the synchronous one reports 19) |
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
| 17 | Not running on arm64 / arm64e |

### Using these across a process boundary

This library is usually deployed with the injection happening in a privileged
helper and the result travelling back to an app over XPC — which is exactly where
`NSError.userInfo` tends not to survive, since whether it does is up to the two
ends' coding agreement, not up to this library. `domain` and `code` always
survive; treat them as the machine-readable answer and transport
`localizedDescription` (and `MIMachInjectorRemoteErrorMessageKey` / `MachInjector.remoteErrorMessageKey`, when present)
yourself if you want the human-readable one on the far side.

## References

- [yabai](https://github.com/koekeishiya/yabai) — the original injection implementation this project is derived from.

## License

MachInjector is released under the MIT License. See [LICENSE](LICENSE) for details.
