# Strict-seatbelt payload runtime handoff

## Context

`MIMachInjectorRemap` bypasses `dlopen` by remapping a payload dylib's segments
into a target process with `mach_vm_remap`, then jumping into it. `mach_vm_remap`
skips every step dyld normally performs at load time: no chained-fixup
application, no libobjc `map_images` notification, no libswiftCore metadata
registration, and — importantly — no `__attribute__((constructor))` dispatch.

Applying chained fixups is easy; the loader owns that path
(`loader_arm64_remap_fixup.c`). Replaying the runtime notifications is the
tricky part, because they have to run **inside the target** after the payload
is mapped, using the target's per-process libobjc / libswiftCore state.

Until this design landed, the replay code lived in each payload's entry
function. That worked, but shipped the injection mechanism's ABI knowledge
across the boundary between "injector platform" and "payload author".

## Payload contract

A payload is a dylib whose entry point implements one function with a single
signature. That's it:

```c
void *my_payload_entry(void *arg) {
    (void)arg;             // loader already performed the runtime handoff
    my_real_initializer(); // start whatever the payload exists to do
    return NULL;
}
```

`arg` is the `MIMachInjectorRemapPayloadConfig *` the injector allocated in the
target's address space (raw struct declared in `MIMachInjectorRemap.h`).
Payloads that don't need it — most of them — can ignore it. The loader has
already:

- Rewritten every `LC_DYLD_CHAINED_FIXUPS` slot in the payload with values
  signed under the target's PAC keys.
- Called libobjc's `map_images` for the payload, uniquing `__objc_selrefs`,
  registering classes / categories / protocols, and forwarding to any warm
  Swift add-image hook.
- Called `swift_registerTypeMetadataRecords` / `swift_registerProtocols` /
  `swift_registerProtocolConformances` for the payload's `__swift5_*`
  sections.

By the time control reaches the payload entry, the runtime looks — from the
payload's perspective — indistinguishable from a normal `dlopen`-loaded
image. The one thing that never runs is dyld's constructor pass; the entry
function is responsible for whatever the payload's constructor would have
done (typical case: call the module's Swift `@_cdecl` initializer).

## Why the handoff runs in a pthread, not on the raw mach thread

`mach_vm_remap` injection uses `pthread_create_from_mach_thread` to move
execution from the raw mach thread the injector spawns (via
`thread_create_running`) onto a real pthread with TLS. The naive placement
for the handoff — inside stage1 asm, right after `apply_fixups` — is wrong.

libobjc's `map_images` code path:

- Takes `runtimeLock` — a `pthread_mutex_t`.
- On the first call in a process, runs `preopt_init()` — behind a
  `dispatch_once`.
- Uses `sel_registerNameNoLock`, which touches pthread-primitive tables.

None of those primitives assert on a raw mach thread. They all fall through
their fast paths, silently taking the "no pthread state" branch. `map_images`
appears to succeed, but `__objc_selrefs` is never uniqued. The payload runs a
short while, hits its first `objc_msgSend` (typically inside a `dispatch_once`
that Swift Foundation uses during `Bundle.main` initialization), and crashes
as:

```
+[NSBundle (dynamic selector)]: unrecognized selector sent to class 0x1f4484f58
```

The crash is far from the root cause. Diagnosing it takes hours if you don't
already know the pattern.

Fix: stage1 does only `apply_fixups`, then calls
`pthread_create_from_mach_thread` with the loader's own `_pthread_thunk` as
start_routine. The thunk runs on the pthread, does the runtime handoff there,
and tail-calls the real payload entry.

## Loader-internal control flow

```
stage1_entry (raw mach thread, loader __TEXT):
  apply_fixups()                                      -> Phase 1
  pthread_create_from_mach_thread(_, _,
      pthread_thunk,                                  -> Phase 2 start_routine
      config)
  spin (raw mach thread cannot ret; injector will terminate it later)

pthread_thunk (pthread, loader __TEXT):
  perform_runtime_handoff(config)                     -> Phase 3
  entry = sign(cfg_pthread_start_addr, IA + 0)
  return entry(config)                                -> Phase 4, tail-call
```

- Stage1 asm lives in `loader_arm64_remap.s`. It reads its four `_cfg_*` slots
  from the loader's `__DATA` segment; the injector patches those slots with
  `mach_vm_write` after `mach_vm_remap`ping the loader.
- `pthread_thunk` and `perform_runtime_handoff` live in
  `loader_arm64_remap_handoff.c`. Both are compiled into the same standalone
  dylib the loader header (`loader_arm64_remap_dylib.h`) embeds as bytes.
- `_cfg_pthread_start_addr` now stores the raw address of the payload entry.
  The thunk signs it (IA + const 0) and calls it.

## PAC handling in `perform_runtime_handoff`

Two things get signed at runtime:

**Function pointers coming from injector-side `dlsym`**. The injector calls
`ptrauth_strip(...)` on every function pointer it writes into the config
struct, because the injector's PAC keys are not the target's. Inside the
target, we sign with the arm64e ABI default schema for function-pointer call
sites — IA + const 0:

```c
MIRemapMapImagesFunction mapImages =
    (MIRemapMapImagesFunction)__builtin_ptrauth_sign_unauthenticated(
        (void *)(uintptr_t)config->mapImages, ptrauth_key_asia, 0);
```

**The `mark` block's `invoke` field**. libobjc's block-invoke call sites use
the clang default `PointerAuthSchema(ASIA, addr_diverse=true,
Discrimination::None)`. We build the block on the stack — its `invoke`
storage address is the diversifier. `strip` before re-signing is required
because `(void *)MIRemapHandoffMarkInvoke` triggers clang's implicit `paciza`
(arm64e ABI signs every function-pointer R-value); signing again without
stripping produces double-signed garbage that libobjc's `autia` fails on.

```c
markBlock.invoke = __builtin_ptrauth_sign_unauthenticated(
    __builtin_ptrauth_strip((void *)MIRemapHandoffMarkInvoke, ptrauth_key_asia),
    ptrauth_key_asia,
    __builtin_ptrauth_blend_discriminator(&markBlock.invoke, 0));
```

The block's `isa` and `descriptor` are never dereferenced on this hot path
(objc4 goes straight from `mark` to `invoke`), so `isa = NULL` and
`descriptor = &fileprivate-const-struct` are safe. No dependency on
`_NSConcreteGlobalBlock` or the blocks runtime.

## Ordering

`perform_runtime_handoff` calls `map_images` before the `swift_register*`
trio. This matches dyld's own order (`dyld/DyldRuntimeState.cpp` fires the
objc `mapped3` callback before Swift's add-image hook). It also lets a warm
Swift runtime pick up the payload for free — libobjc, as part of
`map_images`, forwards to any Swift add-image hook already registered via
`objc_addLoadImageFunc2`
(`swift/stdlib/public/runtime/ImageInspectionMachO.cpp:237-249`).

The explicit `swift_register*` calls are the primary registration path when
the Swift runtime is still cold; when it's warm, they degrade to a cheap
redundant `push_back` into `ConcurrentReadableArray`
(`swift/stdlib/public/runtime/MetadataLookup.cpp:368-379`), no dedup. Safe
either way.

Reversing the order would double-register the payload's `__swift5_types`
range in the same array. Not a crash, but wasteful.

## Trade-offs and non-goals

**Loader dylib size grows**. Adding `loader_arm64_remap_handoff.c` to the
compiled dylib bumps `loader_arm64_remap_dylib.h` from ~50KB to ~800KB. The
injector still ships that as a single string literal, so build-time only.
Runtime cost is the same three-file compile.

**arm64 slice compiles but does nothing**. `#ifdef __arm64__` gates the
whole file. On arm64 (non-e), `__has_feature(ptrauth_intrinsics)` is false
and the signing calls fall through to plain casts. That branch never runs
in production — arm64e daemons stay on arm64e — but it needs to compile so
the fat loader dylib can link.

**Not a general-purpose plugin API**. The payload contract is intentionally
minimal: one C entry, no callback tables, no version negotiation. Anything
richer (post-handoff hooks, teardown callbacks, capability queries) belongs
in the payload's own protocol with the injector, not in the loader.

## Files

- `Sources/MachInjector/MIMachInjectorRemap.h` — payload contract + example.
- `Sources/MachInjector/loader_arm64_remap.s` — stage1 shim; Phase 2 uses
  `_pthread_thunk` as start_routine.
- `Sources/MachInjector/loader_arm64_remap_fixup.c` — chained-fixup applier
  run in Phase 1 on the raw mach thread.
- `Sources/MachInjector/loader_arm64_remap_handoff.c` — pthread thunk and
  runtime-notification replayer added in this design.
- `Sources/MachInjector/build_loader.sh` — assembles the three sources into
  `loader_arm64_remap.dylib` and regenerates the embedded byte header.

## History

The runtime-handoff logic went through three homes before landing here:

1. **Inline in stage1 asm, on the raw mach thread.** Silent selref-uniquify
   failure. Debugged from an `unrecognized selector` symptom.
2. **Inside the payload's entry function, on the pthread.** Worked, but
   duplicated across every payload and coupled payload authors to dyld ABI
   changes.
3. **Inside the loader's `pthread_thunk`, on the pthread.** Current design.
   Payload contract stays minimal; ABI changes are one-file fixes in
   MachInjector.

Related project-side write-up:
`RuntimeViewer/Documentations/ResolvedIssues/2026-07-18-strict-seatbelt-payload-runtime-handoff.md`.
