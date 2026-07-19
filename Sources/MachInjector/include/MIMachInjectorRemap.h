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
 * By the time the pthread reaches your entry, the loader has already:
 *   * Applied every LC_DYLD_CHAINED_FIXUPS slot in the payload against the
 *     target's PAC keys.
 *   * Called libobjc's `map_images` on the payload's mach_header (so every
 *     __objc_selrefs entry is uniqued against libobjc's canonical SEL
 *     table, and the payload's classes / categories / protocols are
 *     registered).
 *   * Called libswiftCore's `swift_registerTypeMetadataRecords`,
 *     `swift_registerProtocols`, and `swift_registerProtocolConformances`
 *     on the payload's `__TEXT,__swift5_types` / `__swift5_protos` /
 *     `__swift5_proto` ranges.
 *
 * In other words your entry sees a "fully mapped" runtime — as if dyld had
 * loaded the image normally. All you have to do is run whatever the
 * payload actually exists to do.
 *
 * `arg` is non-NULL and points at an MIMachInjectorRemapPayloadConfig
 * record in the target's address space (see below). Payload code that
 * only needs "libobjc + Swift are wired up, let me run" can ignore `arg`
 * completely. Payload code that wants to inspect the payload's own
 * mach_header, path, or metadata section ranges without re-parsing them
 * can read those fields directly from the config.
 *
 * The pthread runs on a fully-initialized pthread with TLS, so Foundation
 * / Swift / os_log / dispatch are all safe from the entry.
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
 * The loader has already used every field to notify the runtime by the
 * time your entry runs — the config is exposed here purely as
 * introspection metadata for payloads that want it.
 *
 * A typical entry:
 *
 *   void *my_payload_entry(void *arg) {
 *       (void)arg;              // loader already did the runtime handoff
 *       my_real_initializer();  // start whatever the payload exists to do
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
 * Debug hints by code (where to start looking when you hit one):
 *   1-2   Disk full / SIP hardened /private/tmp / codesign broken by a
 *         hostile hook. Fresh reboot usually rules disks out.
 *   3     `build_loader.sh` was never run OR the injector's
 *         `MIMachInjectorRemap.o` predates the current
 *         `loader_arm64_remap_dylib.h`. Touch MIMachInjectorRemap.m and
 *         rebuild.
 *   4-5   Payload path wrong, payload lacks an arm64e slice, payload's
 *         entry symbol misspelled, or entry symbol has C++ mangling that
 *         `dlsym` won't resolve (declare it `extern "C"` /
 *         `__attribute__((visibility("default")))`).
 *   6     Payload has more than 16 segments (unusual — bump the local
 *         array size in `+ injectToPID:`) OR a segment with the same
 *         name as SEG_LINKEDIT / SEG_PAGEZERO that's meaningful.
 *   7-8   libswiftCore not installed OR OS updated and renamed symbols.
 *         Confirm with `dlsym(handle, "swift_registerTypeMetadataRecords")`
 *         from a small stand-alone process.
 *   9     dyld gAPIs table layout changed between OS versions. See
 *         FindLibObjCMapImages heuristic — the 3-consecutive-qword scan
 *         window might need re-tuning. Enable the diag log and look at
 *         the step4 candidate list.
 *   10    Injector lacks task_for_pid. On modern macOS: SIP off + running
 *         as root, OR `com.apple.system-task-ports.debug` entitlement +
 *         `Developer Mode` on for the injector's audit token, OR use the
 *         helper daemon pattern in Example/.
 *   11-12 Target process died between task_for_pid and mach_vm_allocate,
 *         OR target's ASLR left no contiguous span (rare).
 *   13-14 Target's VM is full, OR the source pages in the injector are
 *         no longer readable (dyld unloaded a dependency). Never dlclose
 *         payload / loader in the injector — protection changes leak
 *         through the shared mapping.
 *   15    Kernel-side thread_convert_thread_state failure — extremely
 *         unusual; likely a kernel bug or an incompatible OS release.
 *         Diagnose with kext logging.
 *   16    thread_create_running failed — target rejected the ARM
 *         thread state we built. Likely PC address arithmetic wrong
 *         (loaderRemoteBase + stage1Offset) or SP not aligned.
 *
 * When a payload runs but the TARGET crashes shortly after with
 * `+[<SomeClass> (dynamic selector)]: unrecognized selector`, the fault
 * is almost always that `map_images` never uniqued the payload's selrefs.
 * See Documentations/Design/StrictSeatbeltPayloadRuntimeHandoff.md — the
 * usual cause is stale loader shellcode from before pthread_thunk was
 * added.
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
///
/// By the time the payload entry sees this, the loader has already used every
/// field to complete the runtime handoff — it's exposed here as introspection
/// metadata for payloads that want to reason about their own image. All
/// function-pointer fields are stripped of PAC bits by the injector; if the
/// payload wants to CALL any of them itself it must re-sign with the target's
/// keys (see Documentations/Design/PACHandbookForRemap.md).
typedef struct {
    /// libobjc `map_images` in the target's address space (PAC-stripped raw
    /// address). Loader already called it during handoff; usually not needed
    /// by payload code.
    uint64_t mapImages;
    /// libswiftCore `swift_registerTypeMetadataRecords` (PAC-stripped raw
    /// address).
    uint64_t swiftRegisterTypes;
    /// libswiftCore `swift_registerProtocols` (PAC-stripped raw address).
    uint64_t swiftRegisterProtocols;
    /// libswiftCore `swift_registerProtocolConformances` (PAC-stripped raw
    /// address).
    uint64_t swiftRegisterConformances;
    /// Mach-header of the payload remapped in the target's address space —
    /// equivalent to the injector-side `_dyld_get_image_header` result but
    /// for the target.
    uint64_t payloadMachHeader;
    /// C-string (null-terminated) of the payload's filesystem path, stored
    /// on the same config page in the target's address space.
    uint64_t payloadPath;
    /// `__TEXT,__swift5_types` section begin address in the target. Zero if
    /// the payload has no such section (pure ObjC payload).
    uint64_t swift5TypesBegin;
    /// `__TEXT,__swift5_types` section end address (exclusive) in the target.
    uint64_t swift5TypesEnd;
    /// `__TEXT,__swift5_protos` section begin address in the target. Zero if
    /// absent.
    uint64_t swift5ProtosBegin;
    /// `__TEXT,__swift5_protos` section end address (exclusive) in the target.
    uint64_t swift5ProtosEnd;
    /// `__TEXT,__swift5_proto` section begin address in the target (protocol
    /// *conformances* — the missing `s` is a dyld / Swift runtime historical
    /// artifact). Zero if absent.
    uint64_t swift5ProtoBegin;
    /// `__TEXT,__swift5_proto` section end address (exclusive) in the target.
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
