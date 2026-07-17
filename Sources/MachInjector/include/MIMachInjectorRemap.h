/*
 * =============================================================================
 * MIMachInjectorRemap — mach_vm_remap-based Dylib Injection for macOS (arm64e)
 * =============================================================================
 *
 * The synchronous and asynchronous injectors in this library both rely on the
 * target process being willing to `dlopen(3)` the payload path. That fails
 * for strict seatbelt platform daemons whose sandbox profile denies
 * `file-map-executable` for any path outside a hard-coded system whitelist —
 * sharingd, rapportd, and their kin. No sandbox extension helps: the
 * `APP_SANDBOX_READ` extension only unlocks `file-read*`, not the executable-map
 * predicate that the deny catches.
 *
 * MIMachInjectorRemap avoids `dlopen` in the target entirely. It maps the
 * payload dylib into the injector, then uses `mach_vm_remap` with
 * `VM_INHERIT_SHARE` to project the payload's segments straight into the
 * target's VM space. Because the projection is a Mach-layer VM-to-VM mapping
 * (no vnode, no seatbelt predicate), the file-map-executable check never runs.
 * A tiny asm shim spawns a pthread that then calls the payload's exported
 * entry point.
 *
 * This is the same technique Xcode's DVTInstrumentsFoundation
 * (RemoteInjectionAgent / libRemoteInjectionPayload.dylib) uses to attach
 * Instruments-style instrumentation into system daemons.
 *
 * =============================================================================
 * WHEN TO USE
 * =============================================================================
 *
 * Use MIMachInjectorRemap when:
 *   - The target is a strict seatbelt daemon that will refuse dlopen.
 *   - You control the payload dylib's entry point (needs an exported symbol,
 *     see below).
 *   - You are running on Apple Silicon (arm64 / arm64e).
 *   - SIP is disabled (task_for_pid on platform daemons).
 *
 * Prefer MIMachInjector / MIMachInjectorAsync when the target is a normal
 * process that accepts dlopen — those paths are cheaper and simpler.
 *
 * =============================================================================
 * PAYLOAD ENTRY REQUIREMENTS
 * =============================================================================
 *
 * The payload dylib must expose an exported C function that matches
 * pthread_start_routine:
 *
 *   __attribute__((visibility("default")))
 *   void *my_payload_entry(void *arg);
 *
 * `arg` will be non-NULL and points at an
 * MIMachInjectorRemapPayloadConfig-shaped record in the target's address
 * space (see below). The pthread runs on a fully-initialized pthread with
 * TLS, so Foundation / Swift / os_log / dispatch are all safe from the entry.
 *
 * Because the payload is remapped (not dlopened), dyld's constructor pass
 * does NOT run. Any state normally set up by
 * `__attribute__((constructor))` must be replicated inside the exported
 * entry — usually by calling the same function the constructor would.
 *
 * =============================================================================
 * PAYLOAD CONFIGURATION LAYOUT
 * =============================================================================
 *
 * The `arg` handed to the payload entry points at:
 *
 *   struct MIMachInjectorRemapPayloadConfig {
 *       uint64_t mapImages;                // libobjc map_images function ptr
 *       uint64_t swiftRegisterTypes;       // libswiftCore swift_registerTypeMetadataRecords
 *       uint64_t swiftRegisterProtocols;   // libswiftCore swift_registerProtocols
 *       uint64_t swiftRegisterConformances;// libswiftCore swift_registerProtocolConformances
 *       uint64_t payloadMachHeader;        // mach_header of remapped payload in target
 *       uint64_t payloadPath;              // path C-string in target
 *       uint64_t swift5TypesBegin;         // __TEXT,__swift5_types range
 *       uint64_t swift5TypesEnd;
 *       uint64_t swift5ProtosBegin;        // __TEXT,__swift5_protos range
 *       uint64_t swift5ProtosEnd;
 *       uint64_t swift5ProtoBegin;         // __TEXT,__swift5_proto range (conformances)
 *       uint64_t swift5ProtoEnd;
 *   };
 *
 * A typical entry:
 *
 *   void *my_payload_entry(void *arg) {
 *       MIMachInjectorRemapPayloadConfig *config = arg;
 *       // 1. Register Swift metadata sections with the runtime.
 *       swiftRegisterFn(config->swiftRegisterTypes,
 *                       (void*)config->swift5TypesBegin,
 *                       (void*)config->swift5TypesEnd);
 *       // …repeat for protos + conformances.
 *
 *       // 2. Tell libobjc about the image (nullptr for sectionLocationMetadata
 *       // makes dyld re-derive sections from the mach_header).
 *       struct _dyld_objc_notify_mapped_info info = {
 *           .mh = (const struct mach_header *)config->payloadMachHeader,
 *           .path = (const char *)config->payloadPath,
 *           .sectionLocationMetadata = NULL,
 *           .flags = 0
 *       };
 *       _dyld_objc_mark_image_mutable mark = ^(uint32_t idx) {};
 *       mapImagesFn(1, &info, mark);
 *
 *       // 3. Run whatever your payload actually does.
 *       my_real_initializer();
 *       return NULL;
 *   }
 *
 * See Documentations/ResolvedIssues/2026-07-17-mach-vm-remap-poc-milestones.md
 * in the RuntimeViewer repository for the design rationale and empirical
 * evidence backing this flow.
 *
 * =============================================================================
 * ERROR CODES  (domain: MIMachInjectorRemapErrorDomain)
 * =============================================================================
 *
 *   Code  Description
 *   ----  -----------
 *   1     Failed to write embedded loader dylib to temp path
 *   2     Failed to dlopen embedded loader dylib
 *   3     Loader dylib missing required symbols
 *   4     Failed to dlopen payload dylib
 *   5     Payload does not export the requested entry symbol
 *   6     Failed to enumerate payload segments (unknown layout)
 *   7     Failed to open libswiftCore for Swift-metadata register APIs
 *   8     libswiftCore missing required Swift register symbols
 *   9     Failed to locate libobjc map_images via dyld gAPIs
 *   10    task_for_pid failed (missing permissions or dead target)
 *   11    Failed to allocate memory in target process
 *   12    Failed to mach_vm_write config page in target
 *   13    Failed to mach_vm_remap payload segments into target
 *   14    Failed to mach_vm_remap loader segments into target
 *   15    Failed to convert thread state (arm64e ptrauth)
 *   16    Failed to start remote mach thread
 *
 * =============================================================================
 * PLATFORM SUPPORT
 * =============================================================================
 *
 * - macOS 11.0 or later
 * - Apple Silicon (arm64 / arm64e). No x86_64 support — the payload must
 *   also be arm64e when injecting arm64e daemons like sharingd.
 * - SIP disabled + task_for_pid permission (root helper, com.apple.system-task-ports.debug, etc.)
 */

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MIMachInjectorRemapErrorDomain
    NS_SWIFT_NAME(MachInjectorRemapErrorDomain);

/// Struct handed to the payload entry point in the target process. All fields
/// are 64-bit unsigned integers. Addresses live in the target's virtual space,
/// except the function pointers which come from the shared cache and thus
/// share the same slide across processes.
typedef struct {
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
} MIMachInjectorRemapPayloadConfig
    NS_SWIFT_NAME(MachInjectorRemapPayloadConfig);

NS_SWIFT_NAME(MachInjectorRemap)
@interface MIMachInjectorRemap : NSObject

/// Inject `payloadPath` into `pid` via mach_vm_remap and call `entrySymbol`
/// on a pthread inside the target. Blocks until the mach thread has spawned
/// the pthread — the payload's actual work may run asynchronously after
/// return.
///
/// @param pid            Target process ID. Must be reachable with
///                       task_for_pid (root, developer tools entitlements,
///                       etc.).
/// @param payloadPath    Absolute filesystem path to the payload dylib. Must
///                       be dlopen-able in the *injector* process. Contains
///                       an arm64e slice.
/// @param entrySymbol    Exported symbol in the payload dylib whose signature
///                       matches `void *(*)(void *)`. Runs on a fresh pthread
///                       inside the target.
/// @param error          Populated on failure with domain
///                       `MIMachInjectorRemapErrorDomain`.
/// @return YES on success (loader + payload segments remapped and mach
///         thread started), NO otherwise.
+ (BOOL)injectToPID:(pid_t)pid
        payloadPath:(NSString *)payloadPath
        entrySymbol:(NSString *)entrySymbol
              error:(NSError * _Nullable __autoreleasing * _Nullable)error
    NS_SWIFT_NAME(inject(pid:payloadPath:entrySymbol:));

@end

NS_ASSUME_NONNULL_END
