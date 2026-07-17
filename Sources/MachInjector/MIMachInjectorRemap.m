/*
 * MIMachInjectorRemap — mach_vm_remap-based dylib injection.
 * See MIMachInjectorRemap.h for the design writeup and error code table.
 */

#import "MIMachInjectorRemap.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_status.h>
#include <mach/vm_map.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "loader_arm64_remap_dylib.h"

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
static uintptr_t StripPACBits(uintptr_t pointer) {
    return pointer & 0x0000FFFFFFFFFFFFULL;
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
    // 1. libdyld's mach_header via any exported dyld API.
    void *dyldApi = dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (!dyldApi) return NULL;
    Dl_info dyldInfo = {0};
    dladdr(dyldApi, &dyldInfo);
    const struct mach_header_64 *libdyldMachHeader =
        (const struct mach_header_64 *)dyldInfo.dli_fbase;

    // 2. Read the __TPRO_CONST,__dyld_apis section — its first qword is gAPIs.
    unsigned long apisSectionSize = 0;
    uint8_t *apisSection = getsectiondata((const struct mach_header_64 *)libdyldMachHeader,
                                          "__TPRO_CONST", "__dyld_apis",
                                          &apisSectionSize);
    if (!apisSection) {
        apisSection = getsectiondata((const struct mach_header_64 *)libdyldMachHeader,
                                     "__DATA_CONST", "__dyld_apis",
                                     &apisSectionSize);
    }
    if (!apisSection) return NULL;
    uintptr_t gAPIs = StripPACBits(*(uintptr_t *)apisSection);

    // 3. libobjc TEXT bounds.
    void *objcInit = dlsym(RTLD_DEFAULT, "_objc_init");
    if (!objcInit) return NULL;
    uintptr_t objcLo = 0, objcHi = 0;
    ImageTextBounds(objcInit, &objcLo, &objcHi);

    // 4. Scan RuntimeState memory for 4 consecutive qwords all pointing into
    // libobjc's TEXT range. That's the (_notifyObjCMapped3, PatchClass,
    // Init2, Unmapped) block; the first qword is map_images.
    for (size_t offset = 0; offset < 0x4000; offset += 8) {
        uintptr_t *slots = (uintptr_t *)(gAPIs + offset);
        uintptr_t q0 = StripPACBits(slots[0]);
        uintptr_t q1 = StripPACBits(slots[1]);
        uintptr_t q2 = StripPACBits(slots[2]);
        uintptr_t q3 = StripPACBits(slots[3]);
        if (q0 >= objcLo && q0 < objcHi &&
            q1 >= objcLo && q1 < objcHi &&
            q2 >= objcLo && q2 < objcHi &&
            q3 >= objcLo && q3 < objcHi) {
            return (void *)q0;
        }
    }
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
// Reslide internal payload pointers. Upper-bit heuristic identifies rebase
// slots pointing back into the payload's own image (in the injector) and
// rewrites them to the equivalent target address. This is the POC approach —
// a proper LC_DYLD_CHAINED_FIXUPS parser would be more principled, but the
// heuristic covers what M3.a needs (SwiftMiniTestClass, RuntimeViewerServer
// with ~29k reslid pointers observed in practice).
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

@implementation MIMachInjectorRemap

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
        if (!stage1EntryRaw || !configPthreadCreateAddr ||
            !configPthreadStartAddr || !configPthreadArg) {
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
        payloadHandle = dlopen([payloadPath UTF8String], RTLD_NOW | RTLD_LOCAL);
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

        // ----- 8. Reslide internal pointers. -----
        ResideInternalPointers(target, payloadMachHeader,
                               payloadRemoteBase, payloadMinVmaddr, payloadSpan,
                               payloadSegments, payloadSegmentCount);

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
