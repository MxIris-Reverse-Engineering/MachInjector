// -----------------------------------------------------------------------------
// loader_arm64_remap_handoff.c — dyld-runtime notifications replayer.
// -----------------------------------------------------------------------------
//
// After stage1's apply_fixups() writes every LC_DYLD_CHAINED_FIXUPS slot in
// the remapped payload, we still need to teach the target's libobjc and
// libswiftCore about the new image before the payload starts running its
// own code. Normally dyld does this as part of its image-loading pipeline —
// mach_vm_remap skips dyld entirely, so we replay the two notifications
// here, inside the target, before jumping to the payload's entry symbol.
//
// This code used to live in each payload's entry function. Moving it into
// the loader means:
//   * Payload authors only implement `void *entry(void *arg)` and get to
//     assume libobjc + Swift runtime already know about their image.
//   * Any future ABI shift on Apple's side (map_images signature, Swift
//     register API count, _dyld_objc_notify_mapped_info layout, …) is a
//     one-file fix — every payload gets it for free the moment they
//     re-embed the new loader dylib.
//
// Ordering: `map_images` first, then `swift_register*`.
//   1. dyld's own order (see DyldRuntimeState.cpp) calls the objc mapped3
//      callback before Swift's add-image hook.
//   2. libobjc — as part of `map_images` — forwards the notification to
//      any Swift add-image hook already registered via objc_addLoadImageFunc2
//      (see swift/stdlib/public/runtime/ImageInspectionMachO.cpp:237-249),
//      so a warm Swift runtime picks up our payload automatically.
//   3. If Swift runtime was still cold in the target when map_images ran,
//      the explicit swift_register* calls that follow are the primary
//      registration path. Swift's _registerTypeMetadataRecords is a plain
//      push_back into a ConcurrentReadableArray without dedup
//      (swift/stdlib/public/runtime/MetadataLookup.cpp:368-379), so the
//      warm-runtime double-register case is a cheap no-op.
//
// Reversing the order double-registers the payload's __swift5_types blob
// in the same array. It doesn't crash, just wastes memory.
//
// PAC handling:
//   * The injector strips ptrauth from every function pointer it writes
//     into MIMachInjectorRemapPayloadConfig (see MIMachInjectorRemap.m).
//     Re-signing here with `ptrauth_key_asia + modifier 0` matches what
//     clang emits for a plain function-pointer call site on arm64e, which
//     is how `objc4` calls `map_images` and how `libswiftCore` exports the
//     swift_register* symbols.
//   * The `mark` block passed to map_images has an arm64e-signed invoke
//     field. clang signs it with `ASIA + addr_diverse=true + const=0` (see
//     clang/lib/Frontend/CompilerInvocation.cpp:1700-1701 — the default
//     PointerAuth schema for BlockInvocationFunctionPointers on arm64e).
//     We build the block on the stack and sign invoke ourselves with the
//     same schema, so libobjc's block call site
//     (objc4/runtime/objc-runtime-new.mm:4200 — a plain `mark(idx)` during
//     selref uniquify) authenticates it as normal.
//   * The block's `isa` and `descriptor` are never dereferenced on this
//     hot path (libobjc goes straight from `mark` to its invoke pointer),
//     so isa=NULL and descriptor=&const-struct are safe and dependency-free
//     — we don't have to pull in _NSConcreteGlobalBlock or the block
//     runtime helpers.
//
// Symbol contract:
//   `_perform_runtime_handoff` is exported so loader_arm64_remap.s's stage1
//   entry can `bl` it after apply_fixups. Nothing else references it.
// -----------------------------------------------------------------------------

#ifdef __arm64__

#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stddef.h>
#include <stdint.h>

// Layout-identical to MIMachInjectorRemapPayloadConfig in MIMachInjectorRemap.h.
// The injector populates every field via matching offsets — do not reorder.
struct MIRemapPayloadConfig {
    uint64_t mapImages;
    uint64_t swiftRegisterTypes;
    uint64_t swiftRegisterProtocols;
    uint64_t swiftRegisterConformances;
    uint64_t payloadMachHeader;
    uint64_t payloadPath;
    uint64_t swift5TypesBegin;
    uint64_t swift5TypesEnd;
    uint64_t swift5ProtosBegin;
    uint64_t swift5ProtosEnd;
    uint64_t swift5ProtoBegin;
    uint64_t swift5ProtoEnd;
};

// Layout-identical to `struct _dyld_objc_notify_mapped_info` in
// <mach-o/dyld_priv.h>. The dyld header expresses the last word as a
// `dyldObjCRefsOptimized : 1, flags : 31` bit-field; a zero-initialized
// uint32_t is the same bit pattern and is exactly what `_objc_map_images`
// synthesises when the caller supplies no dyld optimisation flags
// (see objc4/runtime/objc-runtime-new.mm:3574).
struct MIRemapDyldObjCNotifyMappedInfo {
    const struct mach_header *machHeader;
    const char *path;
    const void *sectionLocationMetadata;
    uint32_t flags;
};

// Standard arm64e block layout (Block_layout in BlocksRuntime). We build
// this on the stack rather than using `^(...)` block syntax because clang
// would emit the descriptor pointer as an initialised static in
// __DATA_CONST that dyld would fix up in the *injector* — after remap,
// that field would still point at the injector-side descriptor. Assigning
// the fields at runtime uses PC-relative computation and comes out with
// target-space addresses.
struct MIRemapBlockLayout {
    void *isa;
    int flags;
    int reserved;
    void *invoke;
    const void *descriptor;
};

struct MIRemapBlockDescriptor {
    unsigned long reserved;
    unsigned long size;
};

typedef void (*MIRemapMapImagesFunction)(
    uint32_t count,
    const struct MIRemapDyldObjCNotifyMappedInfo infos[],
    void *mark);

typedef void (*MIRemapSwiftRegisterSectionFunction)(
    const void *begin,
    const void *end);

// The mark callback is a no-op. libobjc invokes it whenever it writes to
// __objc_selrefs / classrefs / protorefs; we already flipped those payload
// segments to R+W with VM_PROT_COPY on the injector side
// (MIMachInjectorRemap.m:974-987), so there is no further work for the
// mark to do. Its existence just satisfies libobjc's block-call ABI.
static void MIRemapHandoffMarkInvoke(void *block, uint32_t objcImageIndex) {
    (void)block;
    (void)objcImageIndex;
}

// __DATA_CONST-resident, purely scalar — no pointers, so no chained fixup
// touches it, so it survives mach_vm_remap unchanged in both injector and
// target address spaces.
static const struct MIRemapBlockDescriptor MIRemapHandoffMarkBlockDescriptor = {
    0,
    sizeof(struct MIRemapBlockLayout),
};

static void MIRemapCallSwiftRegister(uint64_t rawFunction,
                                     uint64_t sectionBegin,
                                     uint64_t sectionEnd) {
    if (rawFunction == 0 || sectionBegin == 0 || sectionEnd == 0) return;
    if (sectionBegin == sectionEnd) return;
#if __has_feature(ptrauth_intrinsics)
    MIRemapSwiftRegisterSectionFunction function =
        (MIRemapSwiftRegisterSectionFunction)__builtin_ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)rawFunction, ptrauth_key_asia, 0);
#else
    // arm64 slice has no PAC — a plain function pointer already is exactly
    // what a `blr` expects. The arm64 slice never runs against an arm64e
    // daemon anyway, but the loader is fat so this branch still needs to
    // compile.
    MIRemapSwiftRegisterSectionFunction function =
        (MIRemapSwiftRegisterSectionFunction)(uintptr_t)rawFunction;
#endif
    function((const void *)(uintptr_t)sectionBegin,
             (const void *)(uintptr_t)sectionEnd);
}

// Populated by the injector before it remaps the loader — same __DATA slot
// stage1 reads to hand pthread_create_from_mach_thread a start_routine. We
// intercept it here in the pthread thunk so the injector doesn't need to
// know the thunk exists.
extern uint64_t cfg_pthread_start_addr;

typedef void *(*MIRemapPayloadEntry)(void *arg);

// Forward declaration — the function definition sits after pthread_thunk so
// the top-of-file reads top-down "pthread lifecycle first, then handoff
// details".
static void perform_runtime_handoff(const struct MIRemapPayloadConfig *config);

// pthread_create_from_mach_thread's start_routine. Runs on the freshly-
// spawned pthread (so it HAS TLS, dispatch_get_current_queue works,
// pthread_mutex behaves correctly, etc.), which is why we do the runtime
// handoff here rather than on the raw mach thread inside stage1 itself.
// libobjc's map_images path takes runtimeLock (a pthread mutex), runs
// preopt_init() the first time which reaches into dispatch_once, and
// sel_registerNameNoLock uses pthread-primitive tables — none of which
// behave correctly on a raw mach thread without TLS. Symptom of running
// handoff on the raw thread: map_images returns silently without
// uniquing selrefs, and the payload later crashes as
// `+[NSBundle (dynamic selector)]: unrecognized selector` on the first
// dispatch_once + objc_msgSend.
__attribute__((visibility("default"), used))
void *pthread_thunk(void *arg) {
    perform_runtime_handoff((const struct MIRemapPayloadConfig *)arg);

    // The injector wrote the real payload entry (PAC-stripped raw addr)
    // into cfg_pthread_start_addr; stage1's pthread_create now points at
    // us instead of at that entry, so we're the one that needs to sign
    // and tail-call it.
    uint64_t rawEntry = cfg_pthread_start_addr;
    if (rawEntry == 0) return NULL;
#if __has_feature(ptrauth_intrinsics)
    MIRemapPayloadEntry entry =
        (MIRemapPayloadEntry)__builtin_ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)rawEntry, ptrauth_key_asia, 0);
#else
    MIRemapPayloadEntry entry = (MIRemapPayloadEntry)(uintptr_t)rawEntry;
#endif
    return entry(arg);
}

static __attribute__((used))
void perform_runtime_handoff(const struct MIRemapPayloadConfig *config) {
    if (config == NULL) return;

    // (1) libobjc map_images — uniques payload selrefs, registers classes /
    // categories / protocols, forwards to any warm Swift add-image hook.
    if (config->mapImages != 0 && config->payloadMachHeader != 0) {
        struct MIRemapDyldObjCNotifyMappedInfo mappedInfo = {
            .machHeader = (const struct mach_header *)(uintptr_t)config->payloadMachHeader,
            .path = (const char *)(uintptr_t)config->payloadPath,
            .sectionLocationMetadata = NULL,
            .flags = 0,
        };

        struct MIRemapBlockLayout markBlock;
        markBlock.isa = NULL;
        markBlock.flags = 0;
        markBlock.reserved = 0;
#if __has_feature(ptrauth_intrinsics)
        // Casting a function name to `void *` on arm64e goes through an
        // implicit `paciza` (see clang CGCall — arm64e treats every function
        // pointer as `__ptrauth(ASIA, 0, 0)` at the ABI boundary). Feeding
        // that already-signed pointer straight into
        // __builtin_ptrauth_sign_unauthenticated would double-sign it and
        // produce garbage that libobjc's block-invoke auth site
        // (blend(&markBlock.invoke, 0)) would fail on. Strip first, then
        // re-sign with the block-invoke schema.
        markBlock.invoke = __builtin_ptrauth_sign_unauthenticated(
            __builtin_ptrauth_strip((void *)MIRemapHandoffMarkInvoke, ptrauth_key_asia),
            ptrauth_key_asia,
            __builtin_ptrauth_blend_discriminator(&markBlock.invoke, 0));
#else
        markBlock.invoke = (void *)MIRemapHandoffMarkInvoke;
#endif
        markBlock.descriptor = &MIRemapHandoffMarkBlockDescriptor;

#if __has_feature(ptrauth_intrinsics)
        MIRemapMapImagesFunction mapImages =
            (MIRemapMapImagesFunction)__builtin_ptrauth_sign_unauthenticated(
                (void *)(uintptr_t)config->mapImages, ptrauth_key_asia, 0);
#else
        MIRemapMapImagesFunction mapImages =
            (MIRemapMapImagesFunction)(uintptr_t)config->mapImages;
#endif
        mapImages(1, &mappedInfo, &markBlock);
    }

    // (2) Swift metadata sections — cold-runtime fallback / warm-runtime
    // cheap-redundant-push_back. Zero-length ranges and NULL function
    // pointers are skipped by MIRemapCallSwiftRegister.
    MIRemapCallSwiftRegister(config->swiftRegisterTypes,
                             config->swift5TypesBegin,
                             config->swift5TypesEnd);
    MIRemapCallSwiftRegister(config->swiftRegisterProtocols,
                             config->swift5ProtosBegin,
                             config->swift5ProtosEnd);
    MIRemapCallSwiftRegister(config->swiftRegisterConformances,
                             config->swift5ProtoBegin,
                             config->swift5ProtoEnd);
}

#endif // __arm64__
