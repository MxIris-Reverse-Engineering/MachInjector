// -----------------------------------------------------------------------------
// loader_arm64_remap.s — chained-fixup + pthread-bootstrap shim for
// MIMachInjectorRemap.
// -----------------------------------------------------------------------------
//
// SEE ALSO (before touching this file)
//   Documentations/Design/LoaderDylibInternals.md — line-by-line reading of
//     this stage1 asm, PC-relative resolution across mach_vm_remap, __DATA
//     configuration-slot layout, and why the loader is a real dylib rather
//     than embedded shellcode.
//   Documentations/Design/RemapArchitecture.md — where this shim sits in
//     the overall injection data flow.
//
// This is NOT compiled into the MachInjector library binary the way the other
// loader_arm64*.s files are (via `extern char __shellcode_start[]`). Instead
// it is assembled + linked into a standalone dylib (`loader_arm64_remap.dylib`)
// which the library ships as a bundled resource. MIMachInjectorRemap dlopens
// that dylib in the injector, then `mach_vm_remap`s its __TEXT + __DATA
// segments into the target process. See MIMachInjectorRemap.h for the reason.
//
// The stage-1 entry does two things, in order:
//   1. Call apply_fixups() (loader_arm64_remap_fixup.c) so every chained
//      LC_DYLD_CHAINED_FIXUPS slot in the payload is written with the
//      correct raw or PAC-signed value. dyld normally does this at load
//      time; mach_vm_remap skips dyld so we have to do it ourselves inside
//      the target where the local PAC keys apply.
//   2. Spawn a pthread via pthread_create_from_mach_thread whose start
//      routine is `_pthread_thunk` (loader_arm64_remap_handoff.c). The
//      thunk runs INSIDE the pthread — so it has TLS, and dispatch_once /
//      pthread_mutex / anything libobjc's map_images path leans on
//      behaves correctly — then replays dyld's runtime notifications for
//      the payload (map_images + swift_register*) and tail-calls the
//      real payload entry stored in `_cfg_pthread_start_addr`.
//
// Why the handoff runs in the pthread, not here on the raw mach thread:
//   libobjc's map_images takes runtimeLock (a pthread mutex) and reaches
//   into preopt_init (dispatch_once) + sel_registerNameNoLock (pthread
//   TLS). On a raw mach thread none of those crash outright but they
//   silently take the wrong branch — map_images returns without ever
//   uniquing our selrefs, and the payload later blows up as
//   `+[NSBundle (dynamic selector)]: unrecognized selector` on the very
//   first dispatch_once + objc_msgSend.
//
// Why a real dylib rather than embedded shellcode:
//   * The stage-1 entry needs to call pthread_create_from_mach_thread with a
//     start_routine + arg it reads out of memory. Those two arguments are
//     late-bound by the injector (their values only become known after the
//     payload has been remapped into the target), so the shim needs writable
//     configuration slots in its own address space.
//   * Placing those slots in the __DATA segment lets the injector patch them
//     via mach_vm_write; embedding them in __TEXT would require raising exec
//     memory to writable, which fights the point of remap-based injection.
//   * `adr` can only reach ±1 MiB within a single segment. Reaching __DATA
//     from __TEXT requires `adrp+add`, which the code below uses throughout.
//
// Non-obvious invariants shared with the other loaders:
//   * The mach thread has no TLS. It must not `ret` (x30 = 0 crashes to NULL).
//   * pthread_create_from_mach_thread is one of the few pthread calls safe on
//     a raw mach thread.
//   * After spawning the pthread, the mach thread spins forever (`b 1b`).
//     The injector terminates it later; the pthread runs the user payload.

// The SPM target compiles this file for every slice in the target's arch
// matrix (arm64, arm64e, x86_64, ...). Gate the entire body on __arm64__ so
// that x86_64 slices produce an empty object file instead of failing on
// arm64-only mnemonics like `adrp`, `blr`, or the `@PAGE` / `@PAGEOFF`
// operators — same technique the sibling `loader_arm64.s` / `loader_arm64_async.s`
// files use.
#ifdef __arm64__

    .section __TEXT,__text,regular,pure_instructions
    .globl _remap_stage1_entry
    .p2align 2
_remap_stage1_entry:
    // ---- Phase 1: apply_fixups(payloadBase, worklist, count) ------------
    // Every LC_DYLD_CHAINED_FIXUPS slot in the remapped payload is either
    // untouched (for plain rebase/bind) or PAC-signed here in the target so
    // its authenticate ops in the payload's code succeed.
    adrp    x0, _cfg_payload_base@PAGE
    add     x0, x0, _cfg_payload_base@PAGEOFF
    ldr     x0, [x0]

    adrp    x1, _cfg_fixup_worklist@PAGE
    add     x1, x1, _cfg_fixup_worklist@PAGEOFF
    ldr     x1, [x1]

    adrp    x2, _cfg_fixup_count@PAGE
    add     x2, x2, _cfg_fixup_count@PAGEOFF
    ldr     w2, [x2]

    bl      _apply_fixups

    // ---- Phase 2: pthread bootstrap -----------------------------------
    // x0 = &_cfg_pthread_out  (writable qword in __DATA)
    adrp    x0, _cfg_pthread_out@PAGE
    add     x0, x0, _cfg_pthread_out@PAGEOFF

    // x1 = NULL pthread_attr
    mov     x1, xzr

    // x2 = _pthread_thunk (loader-internal wrapper — replays dyld runtime
    // notifications on the pthread, then tail-calls the real payload entry
    // stored in _cfg_pthread_start_addr).
    adrp    x2, _pthread_thunk@PAGE
    add     x2, x2, _pthread_thunk@PAGEOFF

    // x3 = *(_cfg_pthread_arg)         (patched: pointer to config page in target)
    adrp    x3, _cfg_pthread_arg@PAGE
    add     x3, x3, _cfg_pthread_arg@PAGEOFF
    ldr     x3, [x3]

    // x9 = *(_cfg_pthread_create_addr) (patched: shared-cache pthread_create_from_mach_thread)
    adrp    x9, _cfg_pthread_create_addr@PAGE
    add     x9, x9, _cfg_pthread_create_addr@PAGEOFF
    ldr     x9, [x9]

    // pthread_create_from_mach_thread(&out, NULL, start_routine, arg)
    blr     x9

    // Raw mach threads cannot ret. Spin until the injector terminates us.
1:
    b       1b

    .section __DATA,__data
    .p2align 3
    .globl _cfg_pthread_create_addr
_cfg_pthread_create_addr:
    .quad   0
    .globl _cfg_pthread_start_addr
_cfg_pthread_start_addr:
    .quad   0
    .globl _cfg_pthread_arg
_cfg_pthread_arg:
    .quad   0
    .globl _cfg_pthread_out
_cfg_pthread_out:
    .quad   0
    // Chained-fixup configuration. Filled in by the injector before it
    // remaps this loader into the target. All three slots are in the same
    // __DATA page as the pthread config so the same mach_vm_write covers
    // both blocks.
    .globl _cfg_payload_base
_cfg_payload_base:
    .quad   0
    .globl _cfg_fixup_worklist
_cfg_fixup_worklist:
    .quad   0
    .globl _cfg_fixup_count
_cfg_fixup_count:
    .quad   0

#endif // __arm64__
