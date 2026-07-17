// -----------------------------------------------------------------------------
// loader_arm64_remap.s — pthread-bootstrap shim for MIMachInjectorRemap.
// -----------------------------------------------------------------------------
//
// This is NOT compiled into the MachInjector library binary the way the other
// loader_arm64*.s files are (via `extern char __shellcode_start[]`). Instead
// it is assembled + linked into a standalone dylib (`loader_arm64_remap.dylib`)
// which the library ships as a bundled resource. MIMachInjectorRemap dlopens
// that dylib in the injector, then `mach_vm_remap`s its __TEXT + __DATA
// segments into the target process. See MIMachInjectorRemap.h for the reason.
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
    // x0 = &_cfg_pthread_out  (writable qword in __DATA)
    adrp    x0, _cfg_pthread_out@PAGE
    add     x0, x0, _cfg_pthread_out@PAGEOFF

    // x1 = NULL pthread_attr
    mov     x1, xzr

    // x2 = *(_cfg_pthread_start_addr)  (patched: payload entry in target)
    adrp    x2, _cfg_pthread_start_addr@PAGE
    add     x2, x2, _cfg_pthread_start_addr@PAGEOFF
    ldr     x2, [x2]

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

#endif // __arm64__
