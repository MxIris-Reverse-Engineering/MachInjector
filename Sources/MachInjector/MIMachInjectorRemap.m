/*
 * =============================================================================
 * MIMachInjectorRemap.m — mach_vm_remap-based dylib injection (injector side).
 * =============================================================================
 *
 * This file is the ENTIRE injector-side of the remap path. It runs in the
 * injector process and does all the VM plumbing needed to project a payload
 * dylib into a target process WITHOUT going through the target's dyld:
 *   - Enumerate + remap the payload's segments into the target
 *   - Enumerate + remap the loader dylib's segments into the target
 *   - Parse LC_DYLD_CHAINED_FIXUPS off the payload FILE and serialise a work
 *     list the loader's apply_fixups() will replay in the target
 *   - Locate libobjc's map_images function via dyld's gAPIs table
 *   - Resolve Swift metadata register APIs via dlsym on libswiftCore
 *   - Patch the loader's __DATA config slots with target-space addresses
 *   - Spawn a raw mach thread in the target aimed at the loader's stage1 entry
 *
 * The high-level pipeline is documented in
 *     Documentations/Design/RemapArchitecture.md
 * (start there when reading this file for the first time). Sub-topics:
 *     Documentations/Design/ChainedFixupsPipeline.md
 *     Documentations/Design/LoaderDylibInternals.md
 *     Documentations/Design/PACHandbookForRemap.md
 *     Documentations/Design/StrictSeatbeltPayloadRuntimeHandoff.md
 *
 * =============================================================================
 * FUNCTION MAP (for readers navigating this file)
 * =============================================================================
 *
 * Segment plumbing
 *   EnumerateSegments     — walk LC_SEGMENT_64s, emit MIRemapSegment[]
 *   RemapSegments         — mach_vm_remap N segments preserving intra-image offsets
 *
 * libobjc map_images discovery (heuristic 4-qword scan of dyld gAPIs)
 *   StripPACBits          — clear bits 47-63 so range compare works
 *   ImageTextBounds       — [__TEXT.vmaddr, __TEXT.vmaddr+vmsize) for an image
 *   FindLibObjCMapImages  — walk libdyld __TPRO_CONST,__dyld_apis to find map_images
 *
 * Payload section discovery
 *   FindPayloadSection    — locate a __TEXT,<name> section's target-space range
 *
 * Loader dylib boot
 *   WriteEmbeddedLoaderToTempPath — write byte array to /private/tmp/*.dylib
 *   LoadThreadConvert     — dlsym thread_convert_thread_state for arm64e state fixup
 *
 * Chained-fixup parser (see Documentations/Design/ChainedFixupsPipeline.md)
 *   FindChainedFixupsHeaderInSlice — locate LC_DYLD_CHAINED_FIXUPS blob
 *   FindMachOSliceOffset  — pick the arm64e slice in a thin/fat binary
 *   ResolveBindImport     — dlsym a bind's target from a fixup chain import
 *   ParseChainedFixups    — walk every chain, serialise MIRemapFixupEntry[]
 *
 * Legacy (kept for reference, replaced by ParseChainedFixups)
 *   ResideInternalPointers — POC upper-bit heuristic to reslide internal ptrs.
 *                             The chained-fixup parser subsumes this cleanly;
 *                             this function is no longer wired into the flow
 *                             but is preserved for archaeology.
 *
 * Error surface
 *   MakeError             — build NSError under MIMachInjectorRemapErrorDomain
 *
 * Entry point
 *   +[MIMachInjectorRemap injectToPID:payloadPath:entrySymbol:error:]
 *                         — the 13-step recipe wiring all of the above together
 *
 * =============================================================================
 * ARCHITECTURE GATE
 * =============================================================================
 *
 * The implementation depends on arm64 thread-state types (arm_thread_state64_t,
 * ARM_THREAD_STATE64) and the arm64-only remap loader dylib, so gate the whole
 * real implementation on __arm64__ and provide a "arm64-only" stub for the
 * x86_64 slices SPM otherwise compiles. Same technique MIMachInjectorAsync uses.
 * =============================================================================
 */

#import "MIMachInjectorRemap.h"

// Real implementation is arm64-only (see ARCHITECTURE GATE in top-of-file
// docblock). x86_64 slice falls through to a stub returning arm64-only error.
#ifdef __arm64__

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach-o/fixup-chains.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_status.h>
#include <mach/vm_map.h>
#include <os/log.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "loader_arm64_remap_dylib.h"

// -----------------------------------------------------------------------------
// Chained-fixup work list handed to loader_arm64_remap_fixup.c's apply_fixups().
// Struct layout MUST match the definition in loader_arm64_remap_fixup.c —
// the injector serialises entries here, the loader running inside the target
// consumes them.
// -----------------------------------------------------------------------------
typedef struct {
    uint32_t slotOffsetInPayload;
    uint32_t flags;
    uint64_t rawTargetAddress;
    uint16_t diversity;
    uint16_t _pad0;
    uint32_t _pad1;
} MIRemapFixupEntry;

#define MI_FIXUP_FLAG_KEY_MASK 0x03u
#define MI_FIXUP_FLAG_AUTH     0x04u
#define MI_FIXUP_FLAG_ADDR_DIV 0x08u

// Diagnostic subsystem. All call sites use os_log_debug so nothing is
// persisted by default; enable with
//     log stream --predicate 'subsystem == "com.mxiris.machinjector.remap"' --level debug
// when a new target's map_images heuristic / chained-fixup parser needs
// debugging.
static os_log_t MIRemapDiagLog(void) {
    static os_log_t log = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.mxiris.machinjector.remap", "diag");
    });
    return log;
}

NSErrorDomain const MIMachInjectorRemapErrorDomain = @"MIMachInjectorRemapErrorDomain";

// -----------------------------------------------------------------------------
// Error codes must match the table in MIMachInjectorRemap.h.
// -----------------------------------------------------------------------------
typedef NS_ENUM(NSInteger, MIMachInjectorRemapErrorCode) {
    MIMachInjectorRemapErrorLoaderWriteFailed        = 1,
    MIMachInjectorRemapErrorLoaderDlopenFailed       = 2,
    MIMachInjectorRemapErrorLoaderSymbolsMissing     = 3,
    MIMachInjectorRemapErrorPayloadDlopenFailed      = 4,
    MIMachInjectorRemapErrorPayloadEntryMissing      = 5,
    MIMachInjectorRemapErrorPayloadSegmentsInvalid   = 6,
    MIMachInjectorRemapErrorSwiftCoreDlopenFailed    = 7,
    MIMachInjectorRemapErrorSwiftRegistersMissing    = 8,
    MIMachInjectorRemapErrorMapImagesNotFound        = 9,
    MIMachInjectorRemapErrorTaskForPIDFailed         = 10,
    MIMachInjectorRemapErrorMachVMAllocateFailed     = 11,
    MIMachInjectorRemapErrorMachVMWriteFailed        = 12,
    MIMachInjectorRemapErrorMachVMRemapPayloadFailed = 13,
    MIMachInjectorRemapErrorMachVMRemapLoaderFailed  = 14,
    MIMachInjectorRemapErrorThreadStateConvertFailed = 15,
    MIMachInjectorRemapErrorRemoteThreadStartFailed  = 16,
};

typedef kern_return_t (*thread_convert_thread_state_fn_t)(
    thread_act_t, int, thread_state_flavor_t,
    thread_state_t, mach_msg_type_number_t,
    thread_state_t, mach_msg_type_number_t *);

static NSError *MakeError(MIMachInjectorRemapErrorCode code, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    return [NSError errorWithDomain:MIMachInjectorRemapErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

// -----------------------------------------------------------------------------
// Local Mach-O segment enumeration. Skips __LINKEDIT and __PAGEZERO so the
// caller only ever sees segments they need to remap.
// -----------------------------------------------------------------------------
typedef struct {
    char name[16];
    uint64_t localStart;
    uint64_t vmaddr;
    uint64_t vmsize;
    vm_prot_t initprot;
} MIRemapSegment;

static int EnumerateSegments(const struct mach_header_64 *machHeader,
                             MIRemapSegment *segments, int maxSegments,
                             uint64_t *outMinVmaddr, uint64_t *outMaxVmend) {
    int count = 0;
    uint64_t minVmaddr = UINT64_MAX;
    uint64_t maxVmend = 0;
    const struct load_command *loadCommand = (const struct load_command *)(machHeader + 1);
    for (uint32_t i = 0; i < machHeader->ncmds; ++i) {
        if (loadCommand->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segmentCommand =
                (const struct segment_command_64 *)loadCommand;
            if (strcmp(segmentCommand->segname, SEG_LINKEDIT) != 0 &&
                strcmp(segmentCommand->segname, SEG_PAGEZERO) != 0 &&
                segmentCommand->vmsize > 0) {
                if (count >= maxSegments) return -1;
                strlcpy(segments[count].name, segmentCommand->segname,
                        sizeof segments[count].name);
                segments[count].vmaddr = segmentCommand->vmaddr;
                segments[count].vmsize = segmentCommand->vmsize;
                segments[count].initprot = segmentCommand->initprot;
                segments[count].localStart = (uint64_t)machHeader + segmentCommand->vmaddr;
                if (segmentCommand->vmaddr < minVmaddr) minVmaddr = segmentCommand->vmaddr;
                uint64_t end = segmentCommand->vmaddr + segmentCommand->vmsize;
                if (end > maxVmend) maxVmend = end;
                count++;
            }
        }
        loadCommand = (const struct load_command *)((const char *)loadCommand + loadCommand->cmdsize);
    }
    *outMinVmaddr = minVmaddr;
    *outMaxVmend = maxVmend;
    return count;
}

// -----------------------------------------------------------------------------
// Remap a set of segments into the target, preserving intra-image offsets.
// Uses VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE so the caller can pre-reserve a
// contiguous span with mach_vm_allocate and drop the anonymous reservation
// atomically per segment. That avoids a race window a highly-threaded target
// (sharingd) could win between deallocate and FIXED remap.
// -----------------------------------------------------------------------------
static kern_return_t RemapSegments(mach_port_t target, MIRemapSegment *segments,
                                   int count, uint64_t minVmaddr, uint64_t totalSpan,
                                   mach_vm_address_t *outRemoteBase) {
    mach_vm_address_t remoteBase = 0;
    kern_return_t status = mach_vm_allocate(target, &remoteBase, totalSpan, VM_FLAGS_ANYWHERE);
    if (status != KERN_SUCCESS) return status;
    for (int i = 0; i < count; ++i) {
        mach_vm_address_t remoteSegment = remoteBase + (segments[i].vmaddr - minVmaddr);
        vm_prot_t curProt = 0, maxProt = 0;
        status = mach_vm_remap(target, &remoteSegment, segments[i].vmsize, 0,
                               VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                               mach_task_self(), segments[i].localStart, FALSE,
                               &curProt, &maxProt, VM_INHERIT_SHARE);
        if (status != KERN_SUCCESS) return status;
    }
    *outRemoteBase = remoteBase;
    return KERN_SUCCESS;
}

// -----------------------------------------------------------------------------
// Locate libobjc's map_images via dyld's gAPIs. See M3.a milestone doc for
// why this is a stable 4-consecutive-qwords-in-libobjc scan rather than a
// hardcoded offset.
// -----------------------------------------------------------------------------
// arm64e user-space canonical pointers are 47-bit (MACH_VM_MAX_ADDRESS =
// 0x00007FFFFE000000). PAC signatures occupy bits 47-54 on data pointers, so
// masking off only bits 48-63 leaves bit 47 (and sometimes bit 55) polluted —
// a pointer like 0x800187df3600 that really addresses libobjc 0x187df3600 was
// slipping past the objcTEXT-range check because bit 47 stayed set. Widen the
// clear mask to bit 47-63.
static uintptr_t StripPACBits(uintptr_t pointer) {
    return pointer & 0x00007FFFFFFFFFFFULL;
}

static void ImageTextBounds(const void *symbolInsideImage,
                            uintptr_t *outLo, uintptr_t *outHi) {
    Dl_info info = {0};
    dladdr(symbolInsideImage, &info);
    const struct mach_header_64 *machHeader = (const struct mach_header_64 *)info.dli_fbase;
    uintptr_t base = (uintptr_t)machHeader;
    uintptr_t end = base;
    const uint8_t *loadCommand = (const uint8_t *)(machHeader + 1);
    for (uint32_t i = 0; i < machHeader->ncmds; ++i) {
        const struct load_command *command = (const struct load_command *)loadCommand;
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segmentCommand =
                (const struct segment_command_64 *)command;
            if (strcmp(segmentCommand->segname, "__TEXT") == 0) {
                end = base + segmentCommand->vmsize;
                break;
            }
        }
        loadCommand += command->cmdsize;
    }
    *outLo = base;
    *outHi = end;
}

static void *FindLibObjCMapImages(void) {
    os_log_t log = MIRemapDiagLog();
    os_log_debug(log, "MIRemap.diag begin FindLibObjCMapImages pid=%d", getpid());

    // 1. libdyld's mach_header via any exported dyld API.
    void *dyldApi = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (!dyldApi) {
        os_log_debug(log, "MIRemap.diag step1 dlsym(_dyld_get_image_header)=NULL: %s", dlerror());
        return NULL;
    }
    Dl_info dyldInfo = {0};
    int dyldDladdrOk = dladdr(dyldApi, &dyldInfo);
    const struct mach_header_64 *libdyldMachHeader =
        (const struct mach_header_64 *)dyldInfo.dli_fbase;
    os_log_debug(log, "MIRemap.diag step1 dyldApi=%p dladdr=%d fbase=%p fname=%{public}s",
                 dyldApi, dyldDladdrOk, libdyldMachHeader,
                 dyldInfo.dli_fname ? dyldInfo.dli_fname : "(null)");

    // 2. Read the __TPRO_CONST,__dyld_apis section — its first qword is gAPIs.
    unsigned long tproSize = 0;
    uint8_t *tproSection = getsectiondata((const struct mach_header_64 *)libdyldMachHeader,
                                          "__TPRO_CONST", "__dyld_apis",
                                          &tproSize);
    unsigned long dataConstSize = 0;
    uint8_t *dataConstSection = getsectiondata((const struct mach_header_64 *)libdyldMachHeader,
                                               "__DATA_CONST", "__dyld_apis",
                                               &dataConstSize);
    os_log_debug(log, "MIRemap.diag step2 __TPRO_CONST,__dyld_apis=%p size=%lu __DATA_CONST,__dyld_apis=%p size=%lu",
                 tproSection, tproSize, dataConstSection, dataConstSize);
    uint8_t *apisSection = tproSection ? tproSection : dataConstSection;
    if (!apisSection) {
        os_log_debug(log, "MIRemap.diag step2 both sections missing — no gAPIs pointer");
        return NULL;
    }
    uintptr_t apisRaw = *(uintptr_t *)apisSection;
    uintptr_t gAPIs = StripPACBits(apisRaw);
    os_log_debug(log, "MIRemap.diag step2 apisRaw=0x%lx gAPIs(strip)=0x%lx", apisRaw, gAPIs);

    // 3. libobjc TEXT bounds.
    void *objcInit = dlsym(RTLD_DEFAULT, "_objc_init");
    if (!objcInit) {
        os_log_debug(log, "MIRemap.diag step3 dlsym(_objc_init)=NULL: %s", dlerror());
        return NULL;
    }
    Dl_info objcInfo = {0};
    int objcDladdrOk = dladdr(objcInit, &objcInfo);
    uintptr_t objcLo = 0, objcHi = 0;
    ImageTextBounds(objcInit, &objcLo, &objcHi);
    os_log_debug(log, "MIRemap.diag step3 objcInit=%p dladdr=%d fbase=%p fname=%{public}s objcTEXT=[0x%lx,0x%lx) span=0x%lx",
                 objcInit, objcDladdrOk, objcInfo.dli_fbase,
                 objcInfo.dli_fname ? objcInfo.dli_fname : "(null)",
                 objcLo, objcHi, objcHi - objcLo);

    // 4. Scan RuntimeState memory for 3 consecutive qwords all pointing into
    // libobjc's TEXT range. Historically we required 4-in-a-row — the
    // (_notifyObjCMapped3, PatchClass, Init2, Unmapped) block — but macOS 26.5.2
    // moved the 4th field so `Unmapped` no longer sits adjacent; the first three
    // objc callbacks stay contiguous and are still uniquely locatable inside
    // gAPIs' 0x4000 window, so 3-in-a-row is enough. The first qword remains
    // map_images. Re-tighten to 4-in-a-row if the shorter run ever collides.
    for (size_t offset = 0; offset < 0x4000; offset += 8) {
        uintptr_t *slots = (uintptr_t *)(gAPIs + offset);
        uintptr_t q0 = StripPACBits(slots[0]);
        uintptr_t q1 = StripPACBits(slots[1]);
        uintptr_t q2 = StripPACBits(slots[2]);

        int q0InObjc = (q0 >= objcLo && q0 < objcHi);
        int q1InObjc = (q1 >= objcLo && q1 < objcHi);
        int q2InObjc = (q2 >= objcLo && q2 < objcHi);

        // Log every candidate whose leading qword lands inside libobjc TEXT —
        // useful while the heuristic is still being tuned.
        if (q0InObjc) {
            os_log_debug(log, "MIRemap.diag step4 candidate offset=0x%zx q0=0x%lx q1=0x%lx q2=0x%lx inObjc=%d,%d,%d",
                         offset, q0, q1, q2, q0InObjc, q1InObjc, q2InObjc);
        }

        if (q0InObjc && q1InObjc && q2InObjc) {
            os_log_debug(log, "MIRemap.diag step4 MATCH offset=0x%zx map_images=0x%lx", offset, q0);
            return (void *)q0;
        }
    }
    os_log_debug(log, "MIRemap.diag step4 no match after scanning 0x4000 bytes from gAPIs=0x%lx", gAPIs);
    return NULL;
}

// -----------------------------------------------------------------------------
// Resolve a payload section's target-space [begin, end) range.
// -----------------------------------------------------------------------------
static void FindPayloadSection(const struct mach_header_64 *payloadMachHeader,
                               uint64_t payloadRemoteBase, uint64_t payloadMinVmaddr,
                               const char *segname, const char *sectname,
                               uint64_t *outBegin, uint64_t *outEnd) {
    *outBegin = 0;
    *outEnd = 0;
    const uint8_t *loadCommand = (const uint8_t *)(payloadMachHeader + 1);
    for (uint32_t i = 0; i < payloadMachHeader->ncmds; ++i) {
        const struct load_command *command = (const struct load_command *)loadCommand;
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segmentCommand =
                (const struct segment_command_64 *)command;
            if (strcmp(segmentCommand->segname, segname) == 0) {
                const struct section_64 *section = (const struct section_64 *)(segmentCommand + 1);
                for (uint32_t j = 0; j < segmentCommand->nsects; ++j, ++section) {
                    if (strcmp(section->sectname, sectname) == 0) {
                        *outBegin = payloadRemoteBase + (section->addr - payloadMinVmaddr);
                        *outEnd = *outBegin + section->size;
                        return;
                    }
                }
            }
        }
        loadCommand += command->cmdsize;
    }
}

// -----------------------------------------------------------------------------
// LEGACY — no longer wired into the pipeline. Subsumed by ParseChainedFixups +
// apply_fixups. Kept here for archaeology only; do not call from new code.
//
// The upper-bit heuristic below identifies rebase slots whose value falls
// inside the payload's own image (in the injector) and rewrites them to the
// equivalent target address. It handles the "internal pointer reslide" case
// but is blind to signed bind pointers into libswiftCore / libobjc — those
// are handled correctly only by the LC_DYLD_CHAINED_FIXUPS parser. Reading
// this function does NOT teach you how the current fixup pipeline works;
// read ParseChainedFixups + loader_arm64_remap_fixup.c instead.
// See also: Documentations/Design/ChainedFixupsPipeline.md.
// -----------------------------------------------------------------------------
static void ResideInternalPointers(mach_port_t target,
                                   const struct mach_header_64 *payloadMachHeader,
                                   uint64_t payloadRemoteBase, uint64_t payloadMinVmaddr,
                                   uint64_t payloadSpan,
                                   MIRemapSegment *segments, int segmentCount) {
    uint64_t injectorLocalBase = (uint64_t)payloadMachHeader;
    int64_t slideDelta = (int64_t)payloadRemoteBase - (int64_t)injectorLocalBase;

    for (int i = 0; i < segmentCount; ++i) {
        const char *segName = segments[i].name;
        if (strcmp(segName, "__TEXT") == 0) continue;
        uint64_t segLocal = segments[i].localStart;
        uint64_t segSize = segments[i].vmsize;
        mach_vm_address_t segRemote =
            payloadRemoteBase + (segments[i].vmaddr - payloadMinVmaddr);

        uint64_t *localSlots = (uint64_t *)segLocal;
        uint64_t slotCount = segSize / 8;
        uint64_t *fixedBuffer = malloc(segSize);
        if (!fixedBuffer) continue;
        int rewriteCount = 0;
        for (uint64_t j = 0; j < slotCount; ++j) {
            uint64_t value = localSlots[j];
            uint64_t addrBits = value & 0x00007FFFFFFFFFFFULL;
            if (addrBits >= injectorLocalBase &&
                addrBits < injectorLocalBase + payloadSpan) {
                uint64_t upperBits = value & 0xFFFF800000000000ULL;
                uint64_t newAddr = (addrBits + (uint64_t)slideDelta) & 0x00007FFFFFFFFFFFULL;
                fixedBuffer[j] = upperBits | newAddr;
                rewriteCount++;
            } else {
                fixedBuffer[j] = value;
            }
        }
        if (rewriteCount > 0) {
            vm_prot_t savedProt = segments[i].initprot;
            if (strcmp(segName, "__DATA_CONST") == 0) {
                (void)mach_vm_protect(target, segRemote, segSize, FALSE,
                                      VM_PROT_READ | VM_PROT_WRITE);
                savedProt = VM_PROT_READ;
            }
            (void)mach_vm_write(target, segRemote, (vm_offset_t)fixedBuffer,
                                (mach_msg_type_number_t)segSize);
            (void)mach_vm_protect(target, segRemote, segSize, FALSE, savedProt);
        }
        free(fixedBuffer);
    }
}

// -----------------------------------------------------------------------------
// Write the embedded loader dylib bytes to a per-invocation temp path so
// dlopen can load it. The ad-hoc signature was applied at build time and is
// valid byte-for-byte.
// -----------------------------------------------------------------------------
static NSString *WriteEmbeddedLoaderToTempPath(NSError **error) {
    char templatePath[] = "/private/tmp/MIMachInjectorRemap_loader_XXXXXX.dylib";
    int fd = mkstemps(templatePath, 6);
    if (fd < 0) {
        if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderWriteFailed,
                                      @"mkstemps failed: %s", strerror(errno));
        return nil;
    }
    ssize_t written = write(fd, MIMachInjectorRemapLoaderDylib,
                            MIMachInjectorRemapLoaderDylib_len);
    close(fd);
    if (written != (ssize_t)MIMachInjectorRemapLoaderDylib_len) {
        unlink(templatePath);
        if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderWriteFailed,
                                      @"failed to write full loader (%zd of %u)",
                                      written, MIMachInjectorRemapLoaderDylib_len);
        return nil;
    }
    return [NSString stringWithUTF8String:templatePath];
}

static thread_convert_thread_state_fn_t LoadThreadConvert(void) {
    void *handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOW);
    if (!handle) return NULL;
    return (thread_convert_thread_state_fn_t)dlsym(handle, "thread_convert_thread_state");
}

// -----------------------------------------------------------------------------
// LC_DYLD_CHAINED_FIXUPS parser. Walks the payload's fixup chains and
// serialises every rebase / bind slot into a MIRemapFixupEntry[] that the
// stage2 loader replays (with PAC re-sign) inside the target process. This
// replaces the earlier POC `ResideInternalPointers` upper-bit heuristic —
// which could only rewrite payload-internal pointers and completely missed
// signed bind pointers into libswiftCore / libobjc / etc.
//
// Design summary
//   * arm64e PAC keys are per-process — a signature produced in the injector
//     will not authenticate in the target. dyld normally applies chained
//     fixups (both raw writes and PAC signing) at load time; a remap-based
//     injection skips dyld, so we replay dyld's work in two halves:
//       - injector: parse the fixup chain, resolve bind targets via dlsym,
//         emit a struct MIRemapFixupEntry per slot (auth flag + key + diversity
//         + addrDiv + rawTarget preserved verbatim);
//       - target: loader_arm64_remap_fixup.c iterates the work list and either
//         writes rawTarget directly (plain rebase/bind) or calls
//         __builtin_ptrauth_sign_unauthenticated with the target's keys
//         (auth rebase/bind).
//   * The raw chain data MUST be read from the payload file, not from the
//     dlopen'd image. dyld replaces every chain node in __DATA_CONST /
//     __DATA with its resolved value at load time; reading them back gives
//     us signed pointers, not fixup encodings, and the walker would follow
//     nonsense `next` bits into arbitrary slots. We mmap the file, locate
//     the arm64e slice, and walk the chains against the untouched bytes.
//     LINKEDIT (which holds the fixup header + imports + symbols) is safe
//     to read from either file or memory since dyld doesn't rewrite it.
//   * Only DYLD_CHAINED_PTR_ARM64E_USERLAND24 (format 12, 8-byte stride) is
//     handled explicitly — this is what Xcode ships arm64e dylibs with today
//     for macOS. Segments with any other pointer_format are skipped; on arm64
//     slice targets (which are not our concern here) that leaves the payload
//     un-fixed but avoids emitting a bogus work list.
// -----------------------------------------------------------------------------

// Locate the LC_DYLD_CHAINED_FIXUPS blob inside a Mach-O slice already mmap'd
// into the injector's address space. `sliceBase` is the start of the slice
// (i.e. the mach_header) in the mmap. The returned pointer points into the
// same mmap.
static const struct dyld_chained_fixups_header *
FindChainedFixupsHeaderInSlice(const uint8_t *sliceBase, size_t *outSize) {
    const struct mach_header_64 *machHeader = (const struct mach_header_64 *)sliceBase;
    const struct linkedit_data_command *chainedFixupsCmd = NULL;

    const uint8_t *cursor = (const uint8_t *)(machHeader + 1);
    for (uint32_t i = 0; i < machHeader->ncmds; ++i) {
        const struct load_command *loadCommand = (const struct load_command *)cursor;
        if (loadCommand->cmd == LC_DYLD_CHAINED_FIXUPS) {
            chainedFixupsCmd = (const struct linkedit_data_command *)loadCommand;
            break;
        }
        cursor += loadCommand->cmdsize;
    }
    if (!chainedFixupsCmd) return NULL;

    // `dataoff` is a file offset — same as a slice-relative offset for a
    // Mach-O whose LC_SEGMENT_64.fileoff / vmaddr are identity (typical for
    // dylibs). Since we're indexing directly into the file mmap, dataoff is
    // exactly the byte offset from sliceBase.
    if (outSize) *outSize = chainedFixupsCmd->datasize;
    return (const struct dyld_chained_fixups_header *)(sliceBase + chainedFixupsCmd->dataoff);
}

// Locate the arm64e slice inside a mmap'd payload file. Returns an offset
// into the file mmap where the slice's mach_header sits, or -1 if no matching
// slice was found. Handles both thin and fat (32-bit and 64-bit fat header)
// binaries. The caller passes the cputype/cpusubtype it wants to inject; we
// match on those.
static int64_t FindMachOSliceOffset(const uint8_t *fileBytes, size_t fileSize,
                                    cpu_type_t wantedType, cpu_subtype_t wantedSubtype) {
    if (fileSize < sizeof(uint32_t)) return -1;
    uint32_t magic = *(const uint32_t *)fileBytes;

    // Thin Mach-O — verify cputype matches and return offset 0.
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        if (fileSize < sizeof(struct mach_header_64)) return -1;
        const struct mach_header_64 *header = (const struct mach_header_64 *)fileBytes;
        if (header->cputype == wantedType) return 0;
        return -1;
    }
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        // 32-bit Mach-O — arm64e is a 64-bit ABI, so no match possible.
        return -1;
    }

    // Fat binary — fat_header + fat_arch entries are stored big-endian.
    if (magic == FAT_CIGAM) {
        if (fileSize < sizeof(struct fat_header)) return -1;
        const struct fat_header *fatHeader = (const struct fat_header *)fileBytes;
        uint32_t archCount = OSSwapBigToHostInt32(fatHeader->nfat_arch);
        const struct fat_arch *archs = (const struct fat_arch *)(fileBytes + sizeof(struct fat_header));
        if (fileSize < sizeof(struct fat_header) + (size_t)archCount * sizeof(struct fat_arch)) return -1;
        for (uint32_t i = 0; i < archCount; ++i) {
            cpu_type_t sliceType = (cpu_type_t)OSSwapBigToHostInt32((uint32_t)archs[i].cputype);
            cpu_subtype_t sliceSubtype = (cpu_subtype_t)OSSwapBigToHostInt32((uint32_t)archs[i].cpusubtype);
            uint32_t sliceOffset = OSSwapBigToHostInt32(archs[i].offset);
            if (sliceType == wantedType &&
                (sliceSubtype & ~CPU_SUBTYPE_MASK) == (wantedSubtype & ~CPU_SUBTYPE_MASK)) {
                return (int64_t)sliceOffset;
            }
        }
        return -1;
    }
    if (magic == FAT_CIGAM_64) {
        if (fileSize < sizeof(struct fat_header)) return -1;
        const struct fat_header *fatHeader = (const struct fat_header *)fileBytes;
        uint32_t archCount = OSSwapBigToHostInt32(fatHeader->nfat_arch);
        const struct fat_arch_64 *archs = (const struct fat_arch_64 *)(fileBytes + sizeof(struct fat_header));
        if (fileSize < sizeof(struct fat_header) + (size_t)archCount * sizeof(struct fat_arch_64)) return -1;
        for (uint32_t i = 0; i < archCount; ++i) {
            cpu_type_t sliceType = (cpu_type_t)OSSwapBigToHostInt32((uint32_t)archs[i].cputype);
            cpu_subtype_t sliceSubtype = (cpu_subtype_t)OSSwapBigToHostInt32((uint32_t)archs[i].cpusubtype);
            uint64_t sliceOffset = OSSwapBigToHostInt64(archs[i].offset);
            if (sliceType == wantedType &&
                (sliceSubtype & ~CPU_SUBTYPE_MASK) == (wantedSubtype & ~CPU_SUBTYPE_MASK)) {
                return (int64_t)sliceOffset;
            }
        }
        return -1;
    }
    return -1;
}

// Resolve a bind's (importOrdinal → symbolName) via dlsym in the injector.
// Every dylib the payload depends on is already loaded here because the
// injector dlopen'd the payload just above, so RTLD_DEFAULT sees them all.
// Returns 0 on failure. `outWeak` reports whether the bind was weak.
static uint64_t ResolveBindImport(const struct dyld_chained_fixups_header *fixupsHeader,
                                  uint32_t ordinal, int *outWeak) {
    if (outWeak) *outWeak = 0;
    if (ordinal >= fixupsHeader->imports_count) return 0;

    const uint8_t *fixupsBase = (const uint8_t *)fixupsHeader;
    const char *symbolsBase = (const char *)fixupsBase + fixupsHeader->symbols_offset;

    const char *symbolName = NULL;
    int isWeak = 0;
    switch (fixupsHeader->imports_format) {
        case DYLD_CHAINED_IMPORT: {
            const struct dyld_chained_import *importsTable =
                (const struct dyld_chained_import *)(fixupsBase + fixupsHeader->imports_offset);
            const struct dyld_chained_import *entry = &importsTable[ordinal];
            symbolName = symbolsBase + entry->name_offset;
            isWeak = entry->weak_import;
            break;
        }
        case DYLD_CHAINED_IMPORT_ADDEND: {
            const struct dyld_chained_import_addend *importsTable =
                (const struct dyld_chained_import_addend *)(fixupsBase + fixupsHeader->imports_offset);
            const struct dyld_chained_import_addend *entry = &importsTable[ordinal];
            symbolName = symbolsBase + entry->name_offset;
            isWeak = entry->weak_import;
            break;
        }
        case DYLD_CHAINED_IMPORT_ADDEND64: {
            const struct dyld_chained_import_addend64 *importsTable =
                (const struct dyld_chained_import_addend64 *)(fixupsBase + fixupsHeader->imports_offset);
            const struct dyld_chained_import_addend64 *entry = &importsTable[ordinal];
            symbolName = symbolsBase + entry->name_offset;
            isWeak = entry->weak_import;
            break;
        }
        default:
            return 0;
    }
    if (outWeak) *outWeak = isWeak;
    if (!symbolName || symbolName[0] == '\0') return 0;

    // Mach-O symbol names in the chain start with a leading underscore.
    // dlsym expects the underscore-stripped C name.
    const char *dlsymName = (symbolName[0] == '_') ? symbolName + 1 : symbolName;
    void *symbolAddress = dlsym(RTLD_DEFAULT, dlsymName);
    if (!symbolAddress) return 0;

    // Strip PAC bits for function pointers. Data pointers come back with
    // zero upper bits so the strip is a no-op; safe either way.
    return (uint64_t)ptrauth_strip(symbolAddress, ptrauth_key_function_pointer);
}

// Walk every chain in every segment, emitting one MIRemapFixupEntry per slot.
// Reads raw chain data from a fresh mmap of the payload FILE — the dlopen'd
// image's __DATA_CONST is already fixed up by dyld and would look like noise
// to a chain walker. Returns 0 on success, filling `*outEntries` (heap-allocated
// via malloc, caller frees) and `*outCount`. On failure returns -1 and writes
// an English snippet to `outErrorMessage`.
static int ParseChainedFixups(NSString *payloadPath,
                              cpu_type_t payloadCPUType,
                              cpu_subtype_t payloadCPUSubtype,
                              uint64_t payloadRemoteBase,
                              MIRemapFixupEntry **outEntries,
                              uint32_t *outCount,
                              NSString **outErrorMessage) {
    *outEntries = NULL;
    *outCount = 0;

    // Open + mmap the payload file so we see raw chain data, not dyld's
    // post-fixup memory image.
    int fd = open([payloadPath UTF8String], O_RDONLY);
    if (fd < 0) {
        if (outErrorMessage) *outErrorMessage =
            [NSString stringWithFormat:@"open payload: %s", strerror(errno)];
        return -1;
    }
    struct stat statBuf;
    if (fstat(fd, &statBuf) < 0) {
        if (outErrorMessage) *outErrorMessage =
            [NSString stringWithFormat:@"fstat payload: %s", strerror(errno)];
        close(fd);
        return -1;
    }
    size_t fileSize = (size_t)statBuf.st_size;
    void *fileMap = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (fileMap == MAP_FAILED) {
        if (outErrorMessage) *outErrorMessage =
            [NSString stringWithFormat:@"mmap payload: %s", strerror(errno)];
        return -1;
    }
    const uint8_t *fileBytes = (const uint8_t *)fileMap;

    // Locate the arm64e (or requested) slice inside the file.
    int64_t sliceOffset = FindMachOSliceOffset(fileBytes, fileSize,
                                               payloadCPUType, payloadCPUSubtype);
    if (sliceOffset < 0) {
        munmap(fileMap, fileSize);
        if (outErrorMessage) *outErrorMessage =
            @"payload file has no matching slice for target cputype/cpusubtype";
        return -1;
    }
    const uint8_t *sliceBase = fileBytes + sliceOffset;

    size_t fixupsSize = 0;
    const struct dyld_chained_fixups_header *fixupsHeader =
        FindChainedFixupsHeaderInSlice(sliceBase, &fixupsSize);
    if (!fixupsHeader) {
        munmap(fileMap, fileSize);
        if (outErrorMessage) *outErrorMessage = @"payload has no LC_DYLD_CHAINED_FIXUPS";
        return -1;
    }

    const uint8_t *fixupsBase = (const uint8_t *)fixupsHeader;
    const struct dyld_chained_starts_in_image *startsInImage =
        (const struct dyld_chained_starts_in_image *)(fixupsBase + fixupsHeader->starts_offset);

    // Overestimate up front, grow with realloc.
    uint32_t capacity = 4096;
    uint32_t count = 0;
    MIRemapFixupEntry *entries = malloc(capacity * sizeof(MIRemapFixupEntry));
    if (!entries) {
        munmap(fileMap, fileSize);
        if (outErrorMessage) *outErrorMessage = @"malloc for fixup work list failed";
        return -1;
    }

    for (uint32_t segIndex = 0; segIndex < startsInImage->seg_count; ++segIndex) {
        uint32_t segInfoOffset = startsInImage->seg_info_offset[segIndex];
        if (segInfoOffset == 0) continue;

        const struct dyld_chained_starts_in_segment *segInfo =
            (const struct dyld_chained_starts_in_segment *)((const uint8_t *)startsInImage + segInfoOffset);

        // We only understand the userland arm64e format the linker ships for
        // arm64e dylibs on macOS. Other formats (e.g. DYLD_CHAINED_PTR_64_OFFSET
        // used by arm64 slices) are silently skipped; the arm64 slice isn't
        // what we inject into arm64e daemons anyway.
        if (segInfo->pointer_format != DYLD_CHAINED_PTR_ARM64E_USERLAND24) {
            continue;
        }
        const uint64_t stride = 8;  // 8-byte stride for USERLAND24.

        for (uint32_t page = 0; page < segInfo->page_count; ++page) {
            uint16_t pageStart = segInfo->page_start[page];
            if (pageStart == DYLD_CHAINED_PTR_START_NONE) continue;

            // Chain nodes live in the slice at segment_offset + page*page_size
            // + pageStart. segment_offset is dyld's "offset in memory to start
            // of segment" — for typical dylibs this equals the segment's
            // fileoff (identity mapping between file and vmaddr), which is the
            // right index into our file mmap.
            uint64_t chainStartInSegment = (uint64_t)page * segInfo->page_size + pageStart;
            const uint8_t *chainCursor =
                sliceBase + segInfo->segment_offset + chainStartInSegment;

            while (1) {
                if (count == capacity) {
                    uint32_t nextCapacity = capacity * 2;
                    MIRemapFixupEntry *newEntries =
                        realloc(entries, (size_t)nextCapacity * sizeof(MIRemapFixupEntry));
                    if (!newEntries) {
                        free(entries);
                        munmap(fileMap, fileSize);
                        if (outErrorMessage) *outErrorMessage = @"realloc for fixup work list failed";
                        return -1;
                    }
                    entries = newEntries;
                    capacity = nextCapacity;
                }

                uint64_t rawFixup;
                memcpy(&rawFixup, chainCursor, sizeof rawFixup);

                uint64_t slotOffsetInPayload = (uint64_t)(chainCursor - sliceBase);
                uint32_t next = (uint32_t)((rawFixup >> 51) & 0x7FF);
                int isBind = (int)((rawFixup >> 62) & 0x1);
                int isAuth = (int)((rawFixup >> 63) & 0x1);

                MIRemapFixupEntry entry;
                memset(&entry, 0, sizeof entry);
                entry.slotOffsetInPayload = (uint32_t)slotOffsetInPayload;

                if (isBind) {
                    uint32_t ordinal = (uint32_t)(rawFixup & 0xFFFFFF);
                    int isWeak = 0;
                    uint64_t targetAddress = ResolveBindImport(fixupsHeader, ordinal, &isWeak);
                    if (targetAddress == 0) {
                        // Weak imports may legitimately resolve to NULL; keep
                        // the slot 0. Non-weak failures are unusual (dlsym
                        // should see everything the payload was linked
                        // against) but we still emit a zero entry so the
                        // payload crashes deterministically on first use
                        // rather than us corrupting a neighbouring slot.
                        entry.rawTargetAddress = 0;
                    }
                    if (isAuth) {
                        uint16_t diversity = (uint16_t)((rawFixup >> 32) & 0xFFFF);
                        int addrDiv = (int)((rawFixup >> 48) & 0x1);
                        uint8_t key = (uint8_t)((rawFixup >> 49) & 0x3);
                        entry.rawTargetAddress = targetAddress;
                        entry.diversity = diversity;
                        entry.flags = MI_FIXUP_FLAG_AUTH | (key & MI_FIXUP_FLAG_KEY_MASK);
                        if (addrDiv) entry.flags |= MI_FIXUP_FLAG_ADDR_DIV;
                    } else {
                        // Plain bind24: sign-extended 19-bit addend at bits [32..50].
                        int32_t addend = (int32_t)((rawFixup >> 32) & 0x7FFFF);
                        if (addend & 0x40000) addend |= (int32_t)0xFFF80000;
                        entry.rawTargetAddress = targetAddress + (int64_t)addend;
                        entry.flags = 0;
                    }
                } else {
                    if (isAuth) {
                        uint32_t targetOffset = (uint32_t)(rawFixup & 0xFFFFFFFF);
                        uint16_t diversity = (uint16_t)((rawFixup >> 32) & 0xFFFF);
                        int addrDiv = (int)((rawFixup >> 48) & 0x1);
                        uint8_t key = (uint8_t)((rawFixup >> 49) & 0x3);
                        entry.rawTargetAddress = payloadRemoteBase + targetOffset;
                        entry.diversity = diversity;
                        entry.flags = MI_FIXUP_FLAG_AUTH | (key & MI_FIXUP_FLAG_KEY_MASK);
                        if (addrDiv) entry.flags |= MI_FIXUP_FLAG_ADDR_DIV;
                    } else {
                        // Plain rebase: 43-bit target vmoffset + optional high8
                        // tag byte preserved in the top byte of the final pointer.
                        uint64_t targetOffset = rawFixup & 0x7FFFFFFFFFFULL;
                        uint8_t high8 = (uint8_t)((rawFixup >> 43) & 0xFF);
                        uint64_t resolved = payloadRemoteBase + targetOffset;
                        if (high8) resolved |= ((uint64_t)high8 << 56);
                        entry.rawTargetAddress = resolved;
                        entry.flags = 0;
                    }
                }

                entries[count++] = entry;

                if (next == 0) break;
                chainCursor += (size_t)next * stride;
            }
        }
    }

    munmap(fileMap, fileSize);
    *outEntries = entries;
    *outCount = count;
    return 0;
}

@implementation MIMachInjectorRemap

// -----------------------------------------------------------------------------
// The 13-step recipe. Cross-reference with the ASCII data flow diagram in
// Documentations/Design/RemapArchitecture.md — each numbered comment below
// (`// ----- N. ... -----`) corresponds to one row in that diagram.
//
// Preconditions
//   - Injector holds task_for_pid privilege on `pid` (root, com.apple.system-
//     task-ports.debug entitlement, developer-mode + SIP off, etc.)
//   - `payloadPath` names a dylib containing an arm64e slice with the
//     `entrySymbol` exported as `void *(*)(void *)`.
//   - Target already has libobjc + libswiftCore loaded (true for basically
//     every macOS daemon).
//
// Postconditions on success
//   - Loader dylib bytes remapped into target; loader's __DATA holds
//     patched addresses for target-space pthread_create, payload entry,
//     config page, fixup worklist, fixup count, payload base.
//   - Payload dylib segments remapped into target; __DATA_CONST /
//     __DATA / __AUTH_CONST / __AUTH flipped to R+W+VM_PROT_COPY.
//   - Fixup worklist mach_vm_write'd into a fresh target-side allocation.
//   - Payload config page mach_vm_write'd into a fresh target-side
//     allocation; contains map_images ptr, three swift_register* ptrs,
//     payload mach-header addr, payload path, three __swift5_* section
//     ranges.
//   - Raw mach thread running the loader's stage1 in the target; that
//     thread apply_fixups the payload, then pthread_create_from_mach_thread
//     with start_routine = pthread_thunk.
//   - After ~2 seconds we terminate the raw mach thread — the pthread it
//     spawned continues running perform_runtime_handoff → payload entry.
//
// Postconditions on failure
//   - `*error` populated with domain MIMachInjectorRemapErrorDomain and a
//     code from MIMachInjectorRemapErrorCode enum (matches the table in
//     MIMachInjectorRemap.h).
//   - Target process may or may not be crashed, depending on which step
//     failed. Failures after step 7 (payload segments already remapped)
//     leave stale segments in the target that a subsequent inject won't
//     see, but they cost target VM until it exits — same as a leaked
//     mach_vm_allocate.
//
// Handle-leak convention (see the @finally block for details):
//   - The three dlopen handles (loader / payload / libswiftCore) are
//     intentionally leaked. dlclose would trigger dyld unload paths
//     that mprotect the pages, and those protection changes propagate
//     via the shared VM object into the target and crash it with
//     KERN_PROTECTION_FAILURE next time it touches the shared page.
// -----------------------------------------------------------------------------
+ (BOOL)injectToPID:(pid_t)pid
        payloadPath:(NSString *)payloadPath
        entrySymbol:(NSString *)entrySymbol
              error:(NSError * _Nullable __autoreleasing * _Nullable)error {
    NSString *loaderPath = nil;
    void *loaderHandle = NULL;
    void *payloadHandle = NULL;
    void *swiftCoreHandle = NULL;
    BOOL success = NO;

    @try {
        // ----- 1. Write and dlopen the embedded loader dylib. -----
        loaderPath = WriteEmbeddedLoaderToTempPath(error);
        if (!loaderPath) return NO;

        loaderHandle = dlopen([loaderPath UTF8String], RTLD_NOW | RTLD_LOCAL);
        if (!loaderHandle) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderDlopenFailed,
                                          @"dlopen loader: %s", dlerror());
            return NO;
        }
        void *stage1EntryRaw = dlsym(loaderHandle, "remap_stage1_entry");
        void *configPthreadCreateAddr = dlsym(loaderHandle, "cfg_pthread_create_addr");
        void *configPthreadStartAddr = dlsym(loaderHandle, "cfg_pthread_start_addr");
        void *configPthreadArg = dlsym(loaderHandle, "cfg_pthread_arg");
        void *configPayloadBaseAddr = dlsym(loaderHandle, "cfg_payload_base");
        void *configFixupWorklistAddr = dlsym(loaderHandle, "cfg_fixup_worklist");
        void *configFixupCountAddr = dlsym(loaderHandle, "cfg_fixup_count");
        void *applyFixupsRaw = dlsym(loaderHandle, "apply_fixups");
        if (!stage1EntryRaw || !configPthreadCreateAddr ||
            !configPthreadStartAddr || !configPthreadArg ||
            !configPayloadBaseAddr || !configFixupWorklistAddr ||
            !configFixupCountAddr || !applyFixupsRaw) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderSymbolsMissing,
                                          @"loader missing required symbols");
            return NO;
        }
        void *stage1Entry = (void *)ptrauth_strip(stage1EntryRaw, ptrauth_key_function_pointer);
        Dl_info loaderInfo = {0};
        if (!dladdr(stage1Entry, &loaderInfo)) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderSymbolsMissing,
                                          @"dladdr on loader entry failed");
            return NO;
        }
        const struct mach_header_64 *loaderMachHeader =
            (const struct mach_header_64 *)loaderInfo.dli_fbase;
        uint64_t stage1Offset = (uint64_t)stage1Entry - (uint64_t)loaderMachHeader;

        MIRemapSegment loaderSegments[8];
        uint64_t loaderMinVmaddr = 0, loaderMaxVmend = 0;
        int loaderSegmentCount = EnumerateSegments(loaderMachHeader, loaderSegments, 8,
                                                   &loaderMinVmaddr, &loaderMaxVmend);
        if (loaderSegmentCount < 0) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderSymbolsMissing,
                                          @"loader has too many segments");
            return NO;
        }
        uint64_t loaderSpan = loaderMaxVmend - loaderMinVmaddr;

        // ----- 2. dlopen the payload and resolve the requested entry. -----
        // Some payloads (e.g. RuntimeViewerServer.framework) auto-start their
        // runtime from an `__attribute__((constructor))` — perfect for the
        // dlopen injection path where dlopen happens IN the target. Here it
        // would run inside the injector because we only need dlopen to hand
        // us the payload's mach_header + entry-symbol dladdr result. Cooperating
        // payloads honour this env var and skip their constructor here; the
        // real target picks the runtime up from the entry symbol after
        // mach_vm_remap. Payloads that don't honour it just pay one getenv.
        setenv("RUNTIMEVIEWERSERVER_SKIP_CONSTRUCTOR", "1", 1);
        payloadHandle = dlopen([payloadPath UTF8String], RTLD_NOW | RTLD_LOCAL);
        unsetenv("RUNTIMEVIEWERSERVER_SKIP_CONSTRUCTOR");
        if (!payloadHandle) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorPayloadDlopenFailed,
                                          @"dlopen payload: %s", dlerror());
            return NO;
        }
        void *entryRaw = dlsym(payloadHandle, [entrySymbol UTF8String]);
        if (!entryRaw) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorPayloadEntryMissing,
                                          @"dlsym(%@): %s", entrySymbol, dlerror());
            return NO;
        }
        void *entryStripped = (void *)ptrauth_strip(entryRaw, ptrauth_key_function_pointer);
        Dl_info payloadInfo = {0};
        if (!dladdr(entryStripped, &payloadInfo)) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorPayloadEntryMissing,
                                          @"dladdr on payload entry failed");
            return NO;
        }
        const struct mach_header_64 *payloadMachHeader =
            (const struct mach_header_64 *)payloadInfo.dli_fbase;
        uint64_t entryOffset = (uint64_t)entryStripped - (uint64_t)payloadMachHeader;

        MIRemapSegment payloadSegments[16];
        uint64_t payloadMinVmaddr = 0, payloadMaxVmend = 0;
        int payloadSegmentCount = EnumerateSegments(payloadMachHeader, payloadSegments, 16,
                                                    &payloadMinVmaddr, &payloadMaxVmend);
        if (payloadSegmentCount < 0) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorPayloadSegmentsInvalid,
                                          @"payload has too many segments");
            return NO;
        }
        uint64_t payloadSpan = payloadMaxVmend - payloadMinVmaddr;

        // ----- 3. Locate map_images via dyld gAPIs. -----
        void *mapImagesPtr = FindLibObjCMapImages();
        if (!mapImagesPtr) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorMapImagesNotFound,
                                          @"failed to locate libobjc map_images via gAPIs");
            return NO;
        }

        // ----- 4. Resolve Swift metadata register APIs. -----
        swiftCoreHandle = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_LAZY | RTLD_LOCAL);
        if (!swiftCoreHandle) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorSwiftCoreDlopenFailed,
                                          @"dlopen libswiftCore: %s", dlerror());
            return NO;
        }
        void *swiftRegisterTypesRaw = dlsym(swiftCoreHandle, "swift_registerTypeMetadataRecords");
        void *swiftRegisterProtocolsRaw = dlsym(swiftCoreHandle, "swift_registerProtocols");
        void *swiftRegisterConformancesRaw = dlsym(swiftCoreHandle, "swift_registerProtocolConformances");
        if (!swiftRegisterTypesRaw || !swiftRegisterProtocolsRaw || !swiftRegisterConformancesRaw) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorSwiftRegistersMissing,
                                          @"libswiftCore missing swift_register* APIs");
            return NO;
        }
        void *swiftRegisterTypes =
            (void *)ptrauth_strip(swiftRegisterTypesRaw, ptrauth_key_function_pointer);
        void *swiftRegisterProtocols =
            (void *)ptrauth_strip(swiftRegisterProtocolsRaw, ptrauth_key_function_pointer);
        void *swiftRegisterConformances =
            (void *)ptrauth_strip(swiftRegisterConformancesRaw, ptrauth_key_function_pointer);

        // ----- 5. Shared-cache pthread_create_from_mach_thread. -----
        void *pthreadCreateRaw = dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
        if (!pthreadCreateRaw) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderSymbolsMissing,
                                          @"dlsym pthread_create_from_mach_thread failed");
            return NO;
        }
        void *pthreadCreateAddr =
            (void *)ptrauth_strip(pthreadCreateRaw, ptrauth_key_function_pointer);

        // ----- 6. task_for_pid. -----
        mach_port_t target = MACH_PORT_NULL;
        kern_return_t status = task_for_pid(mach_task_self(), pid, &target);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorTaskForPIDFailed,
                                          @"task_for_pid(%d): %s", pid, mach_error_string(status));
            return NO;
        }

        // ----- 7. Remap payload into the target. -----
        mach_vm_address_t payloadRemoteBase = 0;
        status = RemapSegments(target, payloadSegments, payloadSegmentCount,
                               payloadMinVmaddr, payloadSpan, &payloadRemoteBase);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorMachVMRemapPayloadFailed,
                                          @"remap payload: %s", mach_error_string(status));
            return NO;
        }

        // ----- 7b. Unlock writable payload segments in the target. -----
        // `mach_vm_remap` above inherits the source's cur_protection. dyld has
        // long since finished payload fixups in the injector and dropped
        // __DATA_CONST back to R-only. The stage2 loader inside the target
        // needs to write every chained-fixup slot (auth re-signing + plain
        // rebase/bind writes), so we hand it R+W pages here. VM_PROT_COPY
        // triggers copy-on-write, giving the target private copies so those
        // writes don't leak back to the injector's __DATA_CONST (which would
        // race dyld's own bookkeeping in the injector process). __DATA is
        // already R+W in most payloads; re-applying is a no-op that still
        // enforces the COW split.
        for (int segmentIndex = 0; segmentIndex < payloadSegmentCount; ++segmentIndex) {
            const char *segmentName = payloadSegments[segmentIndex].name;
            if (strcmp(segmentName, "__DATA_CONST") != 0 &&
                strcmp(segmentName, "__DATA") != 0 &&
                strcmp(segmentName, "__AUTH_CONST") != 0 &&
                strcmp(segmentName, "__AUTH") != 0) {
                continue;
            }
            mach_vm_address_t segmentRemote =
                payloadRemoteBase + (payloadSegments[segmentIndex].vmaddr - payloadMinVmaddr);
            (void)mach_vm_protect(target, segmentRemote,
                                  payloadSegments[segmentIndex].vmsize, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        }

        // ----- 8. Parse LC_DYLD_CHAINED_FIXUPS + write the work list into the
        //          target for the loader's apply_fixups to replay. -----
        //
        // arm64e PAC keys are per-process, so the injector CANNOT sign the
        // payload's chained pointers on the target's behalf. Instead we hand
        // the loader (which will run inside the target) a fully decoded work
        // list — every rebase resolved to a target-space raw address, every
        // bind resolved via injector-side dlsym, PAC key / diversity / addrDiv
        // preserved verbatim from the fixup chain. apply_fixups then signs
        // each auth slot using the target's keys. This subsumes the previous
        // POC `ResideInternalPointers` upper-bit heuristic, which only handled
        // payload-internal pointers and left cross-image signed pointers wrong.
        MIRemapFixupEntry *fixupEntries = NULL;
        uint32_t fixupCount = 0;
        NSString *fixupErrorMessage = nil;
        int fixupParseStatus = ParseChainedFixups(payloadPath,
                                                  payloadMachHeader->cputype,
                                                  payloadMachHeader->cpusubtype,
                                                  payloadRemoteBase,
                                                  &fixupEntries, &fixupCount,
                                                  &fixupErrorMessage);
        if (fixupParseStatus != 0) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorPayloadSegmentsInvalid,
                                          @"parse chained fixups: %@", fixupErrorMessage);
            return NO;
        }
        {
            os_log_t log = MIRemapDiagLog();
            uint32_t authBindCount = 0;
            uint32_t authRebaseCount = 0;
            uint32_t plainBindCount = 0;
            uint32_t plainRebaseCount = 0;
            for (uint32_t scanIndex = 0; scanIndex < fixupCount; ++scanIndex) {
                MIRemapFixupEntry *entry = &fixupEntries[scanIndex];
                int isAuth = (entry->flags & MI_FIXUP_FLAG_AUTH) ? 1 : 0;
                // Bind vs rebase — rawTargetAddress in [payloadRemoteBase, payloadRemoteBase+span)
                // for rebase, else bind.
                int isRebase = (entry->rawTargetAddress >= payloadRemoteBase &&
                                entry->rawTargetAddress < payloadRemoteBase + payloadSpan);
                if (isAuth && isRebase) authRebaseCount++;
                else if (isAuth) authBindCount++;
                else if (isRebase) plainRebaseCount++;
                else plainBindCount++;
            }
            os_log_debug(log,
                "MIRemap.diag fixup_parse count=%u payloadBase=0x%llx span=0x%llx auth_bind=%u auth_rebase=%u plain_bind=%u plain_rebase=%u",
                fixupCount, (uint64_t)payloadRemoteBase, (uint64_t)payloadSpan,
                authBindCount, authRebaseCount, plainBindCount, plainRebaseCount);
            // Sample: first plain rebase (candidate __objc_selrefs) if any.
            for (uint32_t scanIndex = 0; scanIndex < fixupCount; ++scanIndex) {
                MIRemapFixupEntry *entry = &fixupEntries[scanIndex];
                if (entry->flags == 0 &&
                    entry->rawTargetAddress >= payloadRemoteBase &&
                    entry->rawTargetAddress < payloadRemoteBase + payloadSpan) {
                    os_log_debug(log,
                        "MIRemap.diag first_plain_rebase index=%u slot=0x%x target=0x%llx (payloadOff=0x%llx)",
                        scanIndex, entry->slotOffsetInPayload, entry->rawTargetAddress,
                        (uint64_t)(entry->rawTargetAddress - payloadRemoteBase));
                    break;
                }
            }
            // Sample: last few entries.
            uint32_t tailStart = fixupCount > 4 ? fixupCount - 4 : 0;
            for (uint32_t previewIndex = tailStart; previewIndex < fixupCount; ++previewIndex) {
                os_log_debug(log,
                    "MIRemap.diag fixup_tail[%u] slot=0x%x target=0x%llx flags=0x%x div=0x%x",
                    previewIndex,
                    fixupEntries[previewIndex].slotOffsetInPayload,
                    fixupEntries[previewIndex].rawTargetAddress,
                    fixupEntries[previewIndex].flags,
                    fixupEntries[previewIndex].diversity);
            }
        }

        mach_vm_address_t fixupWorklistRemote = 0;
        if (fixupCount > 0) {
            size_t worklistSize = (size_t)fixupCount * sizeof(MIRemapFixupEntry);
            status = mach_vm_allocate(target, &fixupWorklistRemote,
                                      (mach_vm_size_t)worklistSize, VM_FLAGS_ANYWHERE);
            if (status != KERN_SUCCESS) {
                free(fixupEntries);
                if (error) *error = MakeError(MIMachInjectorRemapErrorMachVMAllocateFailed,
                                              @"mach_vm_allocate(fixups): %s", mach_error_string(status));
                return NO;
            }
            status = mach_vm_write(target, fixupWorklistRemote,
                                   (vm_offset_t)fixupEntries,
                                   (mach_msg_type_number_t)worklistSize);
            free(fixupEntries);
            fixupEntries = NULL;
            if (status != KERN_SUCCESS) {
                if (error) *error = MakeError(MIMachInjectorRemapErrorMachVMWriteFailed,
                                              @"mach_vm_write(fixups): %s", mach_error_string(status));
                return NO;
            }
        } else {
            // Nothing to fix up — hand the loader a NULL/zero pair so its
            // apply_fixups() returns immediately.
            free(fixupEntries);
            fixupEntries = NULL;
        }

        mach_vm_address_t payloadEntryRemote =
            payloadRemoteBase + (entryOffset - payloadMinVmaddr);

        // ----- 9. Allocate + populate the payload config page in the target. -----
        const char *payloadPathBytes = [payloadPath UTF8String];
        size_t pathLength = strlen(payloadPathBytes) + 1;
        size_t configSize = sizeof(MIMachInjectorRemapPayloadConfig) + pathLength;
        if (configSize < 0x1000) configSize = 0x1000;
        mach_vm_address_t configRemote = 0;
        status = mach_vm_allocate(target, &configRemote, configSize, VM_FLAGS_ANYWHERE);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorMachVMAllocateFailed,
                                          @"mach_vm_allocate(config): %s", mach_error_string(status));
            return NO;
        }
        uint64_t pathRemote = configRemote + sizeof(MIMachInjectorRemapPayloadConfig);
        MIMachInjectorRemapPayloadConfig localConfig = {
            .mapImages                  = (uint64_t)mapImagesPtr,
            .swiftRegisterTypes         = (uint64_t)swiftRegisterTypes,
            .swiftRegisterProtocols     = (uint64_t)swiftRegisterProtocols,
            .swiftRegisterConformances  = (uint64_t)swiftRegisterConformances,
            .payloadMachHeader          = payloadRemoteBase,
            .payloadPath                = pathRemote,
        };
        FindPayloadSection(payloadMachHeader, payloadRemoteBase, payloadMinVmaddr,
                           "__TEXT", "__swift5_types",
                           &localConfig.swift5TypesBegin, &localConfig.swift5TypesEnd);
        FindPayloadSection(payloadMachHeader, payloadRemoteBase, payloadMinVmaddr,
                           "__TEXT", "__swift5_protos",
                           &localConfig.swift5ProtosBegin, &localConfig.swift5ProtosEnd);
        FindPayloadSection(payloadMachHeader, payloadRemoteBase, payloadMinVmaddr,
                           "__TEXT", "__swift5_proto",
                           &localConfig.swift5ProtoBegin, &localConfig.swift5ProtoEnd);

        uint8_t *staging = calloc(1, configSize);
        memcpy(staging, &localConfig, sizeof localConfig);
        memcpy(staging + sizeof localConfig, payloadPathBytes, pathLength);
        status = mach_vm_write(target, configRemote, (vm_offset_t)staging,
                               (mach_msg_type_number_t)configSize);
        free(staging);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorMachVMWriteFailed,
                                          @"mach_vm_write(config): %s", mach_error_string(status));
            return NO;
        }

        // ----- 10. Patch the loader's __DATA slots (privately in-injector via COW). -----
        MIRemapSegment *dataSegment = NULL;
        for (int i = 0; i < loaderSegmentCount; ++i) {
            if (strcmp(loaderSegments[i].name, "__DATA") == 0) {
                dataSegment = &loaderSegments[i];
                break;
            }
        }
        if (!dataSegment) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorLoaderSymbolsMissing,
                                          @"loader missing __DATA segment");
            return NO;
        }
        mach_vm_address_t dataLocal = (mach_vm_address_t)dataSegment->localStart;
        (void)mach_vm_protect(mach_task_self(), dataLocal, dataSegment->vmsize, FALSE,
                              VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        *(uint64_t *)configPthreadCreateAddr = (uint64_t)pthreadCreateAddr;
        *(uint64_t *)configPthreadStartAddr  = (uint64_t)payloadEntryRemote;
        *(uint64_t *)configPthreadArg        = (uint64_t)configRemote;
        *(uint64_t *)configPayloadBaseAddr   = (uint64_t)payloadRemoteBase;
        *(uint64_t *)configFixupWorklistAddr = (uint64_t)fixupWorklistRemote;
        *(uint64_t *)configFixupCountAddr    = (uint64_t)fixupCount;

        // ----- 11. Remap the (patched) loader into the target. -----
        mach_vm_address_t loaderRemoteBase = 0;
        status = RemapSegments(target, loaderSegments, loaderSegmentCount,
                               loaderMinVmaddr, loaderSpan, &loaderRemoteBase);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorMachVMRemapLoaderFailed,
                                          @"remap loader: %s", mach_error_string(status));
            return NO;
        }
        mach_vm_address_t stage1EntryRemote =
            loaderRemoteBase + (stage1Offset - loaderMinVmaddr);

        // ----- 12. Stack for the raw mach thread. -----
        mach_vm_address_t stack = 0;
        const mach_vm_size_t stackSize = 0x4000;
        status = mach_vm_allocate(target, &stack, stackSize, VM_FLAGS_ANYWHERE);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorMachVMAllocateFailed,
                                          @"mach_vm_allocate(stack): %s", mach_error_string(status));
            return NO;
        }

        // ----- 13. Build thread state, convert (arm64e-friendly), start. -----
        thread_convert_thread_state_fn_t convert = LoadThreadConvert();
        if (!convert) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorThreadStateConvertFailed,
                                          @"thread_convert_thread_state unavailable");
            return NO;
        }
        arm_thread_state64_t state = {0};
        arm_thread_state64_t machineState = {0};
        mach_msg_type_number_t machineCount = ARM_THREAD_STATE64_COUNT;
        __darwin_arm_thread_state64_set_pc_fptr(state,
            ptrauth_sign_unauthenticated((void *)stage1EntryRemote, ptrauth_key_asia, 0));
        __darwin_arm_thread_state64_set_sp(state, stack + stackSize - 16);

        thread_act_t placeholder = MACH_PORT_NULL;
        status = thread_create(target, &placeholder);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorRemoteThreadStartFailed,
                                          @"thread_create placeholder: %s", mach_error_string(status));
            return NO;
        }
        status = convert(placeholder, 2, ARM_THREAD_STATE64,
                         (thread_state_t)&state, ARM_THREAD_STATE64_COUNT,
                         (thread_state_t)&machineState, &machineCount);
        thread_terminate(placeholder);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorThreadStateConvertFailed,
                                          @"convert thread state: %s", mach_error_string(status));
            return NO;
        }

        thread_act_t thread = MACH_PORT_NULL;
        status = thread_create_running(target, ARM_THREAD_STATE64,
                                       (thread_state_t)&machineState, machineCount, &thread);
        if (status != KERN_SUCCESS) {
            if (error) *error = MakeError(MIMachInjectorRemapErrorRemoteThreadStartFailed,
                                          @"thread_create_running: %s", mach_error_string(status));
            return NO;
        }

        // Let the pthread come up and hand execution to the payload entry
        // before we terminate the raw mach thread. Terminating the mach
        // thread before the pthread has been fully spawned races the
        // bootstrap; terminating too early has been observed to leave the
        // target in an unstable state under load.
        usleep(2000 * 1000);
        thread_terminate(thread);
        success = YES;
    } @finally {
        // Deliberately leak the payload and loader handles — dlclose in
        // the injector would trigger dyld's unload path (destructor pass +
        // mprotect changes) on pages that the target is sharing via the
        // `copy=FALSE` mach_vm_remap. Those protection changes propagate
        // through the shared VM object and crash the target with
        // KERN_PROTECTION_FAILURE next time it touches the shared page.
        // The injector process typically exits shortly after inject()
        // returns, so the leak is bounded.
        //
        // We can, however, remove the temp file — dlopen keeps an internal
        // fd on the loader dylib so unlink only drops the directory entry;
        // the inode stays alive as long as our reference does.
        if (loaderPath) (void)unlink([loaderPath UTF8String]);
    }
    return success;
}

@end

#else // !__arm64__

// -----------------------------------------------------------------------------
// x86_64 stub — MIMachInjectorRemap requires the arm64 thread-state ABI and
// the arm64-only remap loader dylib. Provide symbols so linking succeeds; any
// call fails with an explicit "arm64-only" error.
// -----------------------------------------------------------------------------

NSErrorDomain const MIMachInjectorRemapErrorDomain = @"MIMachInjectorRemapErrorDomain";

@implementation MIMachInjectorRemap

+ (BOOL)injectToPID:(pid_t)pid
        payloadPath:(NSString *)payloadPath
        entrySymbol:(NSString *)entrySymbol
              error:(NSError * _Nullable __autoreleasing * _Nullable)error {
    (void)pid; (void)payloadPath; (void)entrySymbol;
    if (error) {
        *error = [NSError errorWithDomain:MIMachInjectorRemapErrorDomain
                                     code:1
                                 userInfo:@{
            NSLocalizedDescriptionKey: @"MIMachInjectorRemap is only available on arm64 / arm64e."
        }];
    }
    return NO;
}

@end

#endif // __arm64__
