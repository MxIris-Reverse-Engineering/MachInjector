// -----------------------------------------------------------------------------
// loader_arm64_remap_fixup.c — chained-fixup applier for MIMachInjectorRemap.
// -----------------------------------------------------------------------------
//
// arm64e user-space PAC keys are per-process; a signed pointer produced by the
// injector process cannot be authenticated in the target. dyld normally re-signs
// chained fixups at load time; a mach_vm_remap-based injection skips dyld
// entirely, so the payload arrives with every LC_DYLD_CHAINED_FIXUPS slot still
// unresolved. We resolve them in the target process instead: MIMachInjectorRemap
// walks the payload's chained-fixup tables in the injector, serialises them
// into a MIRemapFixupEntry[] work list, and mach_vm_remaps that work list next
// to the payload. stage1_entry (loader_arm64_remap.s) invokes apply_fixups()
// below before spawning the pthread that jumps to the payload entry, so the
// applier runs inside the target where __builtin_ptrauth_sign_unauthenticated
// resolves against the target's PAC keys and the resulting signed pointers
// pass authentication normally.
//
// apply_fixups() must NOT call any external symbol. The GOT it would traverse
// is precisely what we are about to fix up, so the first stub call would
// authenticate an uninitialised slot and trap. Everything here is inlined
// arithmetic and __builtin_ptrauth_* intrinsics (which emit pac* instructions
// directly, no library call).

#ifdef __arm64__

#include <ptrauth.h>
#include <stddef.h>
#include <stdint.h>

// Must stay layout-identical to MIRemapFixupEntry in MIMachInjectorRemap.m.
// Written by the injector, consumed here.
struct MIRemapFixupEntry {
    uint32_t slotOffsetInPayload;   // slot offset from payloadBase
    uint32_t flags;                 // bit 0..1 = key, bit 2 = auth, bit 3 = addrDiv
    uint64_t rawTargetAddress;      // rebase: payloadBase+target_off; bind: dlsym result
    uint16_t diversity;             // 16-bit discriminator from the fixup chain
    uint16_t _pad0;
    uint32_t _pad1;
};

#define MI_FIXUP_FLAG_KEY_MASK 0x03u
#define MI_FIXUP_FLAG_AUTH     0x04u
#define MI_FIXUP_FLAG_ADDR_DIV 0x08u

__attribute__((visibility("default"), used))
void apply_fixups(uint64_t payloadBase,
                  const struct MIRemapFixupEntry *entries,
                  uint32_t count) {
    if (entries == NULL || count == 0) return;
    for (uint32_t index = 0; index < count; ++index) {
        const struct MIRemapFixupEntry *entry = &entries[index];
        uint64_t slotAddress = payloadBase + entry->slotOffsetInPayload;
        uint64_t *slot = (uint64_t *)slotAddress;
        uint64_t rawTarget = entry->rawTargetAddress;

#if __has_feature(ptrauth_intrinsics)
        // Authenticated rebase/bind. Blend the 16-bit discriminator with the
        // slot address (if the fixup requests address diversity), then sign
        // the raw target using this process's PAC keys. Non-PAC targets
        // (arm64 slice) skip this branch entirely — the payload's fixup
        // chain won't carry auth=1 entries there.
        if (entry->flags & MI_FIXUP_FLAG_AUTH) {
            uint64_t modifier = entry->diversity;
            if (entry->flags & MI_FIXUP_FLAG_ADDR_DIV) {
                modifier = (uint64_t)__builtin_ptrauth_blend_discriminator(
                    (void *)slotAddress, entry->diversity);
            }
            uint32_t keyBits = entry->flags & MI_FIXUP_FLAG_KEY_MASK;
            void *signedPointer;
            switch (keyBits) {
                case 0:
                    signedPointer = __builtin_ptrauth_sign_unauthenticated(
                        (void *)rawTarget, ptrauth_key_asia, modifier);
                    break;
                case 1:
                    signedPointer = __builtin_ptrauth_sign_unauthenticated(
                        (void *)rawTarget, ptrauth_key_asib, modifier);
                    break;
                case 2:
                    signedPointer = __builtin_ptrauth_sign_unauthenticated(
                        (void *)rawTarget, ptrauth_key_asda, modifier);
                    break;
                default:
                    signedPointer = __builtin_ptrauth_sign_unauthenticated(
                        (void *)rawTarget, ptrauth_key_asdb, modifier);
                    break;
            }
            *slot = (uint64_t)signedPointer;
            continue;
        }
#endif

        // Plain rebase or plain bind — the injector already resolved the
        // absolute target, so just drop it in.
        *slot = rawTarget;
    }
}

#endif // __arm64__
