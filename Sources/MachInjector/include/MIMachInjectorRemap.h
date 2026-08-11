/*
 * =============================================================================
 * MIMachInjectorRemap — mach_vm_remap-based Dylib Injection for macOS (arm64e)
 * =============================================================================
 *
 * The synchronous and asynchronous injectors in this library both rely on the
 * target process being willing to `dlopen(3)` the payload path. Two unrelated
 * enforcement layers can refuse that, and neither is fixable from the injector:
 *
 *   - **Seatbelt.** Strict seatbelt platform daemons deny
 *     `file-map-executable` for any path outside a hard-coded system
 *     whitelist — sharingd, rapportd, and their kin. No sandbox extension
 *     helps: the `APP_SANDBOX_READ` extension only unlocks `file-read*`, not
 *     the executable-map predicate that the deny catches.
 *   - **AMFI library validation.** While it is being enforced, a process whose
 *     code-signing status carries `CS_REQUIRE_LV`
 *     (`csops(pid, CS_OPS_STATUS, ...)`) only accepts dylibs signed by Apple or
 *     by its own Team ID. Every Apple application is signed this way — Music,
 *     Finder, Safari, Mail, Xcode — so a developer-signed payload is rejected
 *     with "mapping process and mapped file (non-platform) have different Team
 *     IDs". Note this is orthogonal to the sandbox: those apps are otherwise
 *     unsandboxed, so a `sandbox_check` probe reports everything as allowed.
 *
 *     Whether it is being enforced is a property of the machine, not of the
 *     target: `amfid` lets every load through when
 *     `/Library/Preferences/com.apple.security.libraryvalidation.plist` has
 *     `DisableLibraryValidation` set, and it only reads that file when SIP is
 *     disabled. `CS_REQUIRE_LV` therefore does not predict a refusal — see the
 *     docblock on `+[MIMachInjector injectToPID:dylibPath:error:]`, which spells
 *     the interaction out. This class is the answer when the switch is *not*
 *     set, either because the machine's owner will not set it or because you
 *     cannot ask them to.
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
 *   - Library validation is being enforced on this machine, the target carries
 *     `CS_REQUIRE_LV` (i.e. any Apple application), and the payload is not
 *     signed by the target's Team ID. Note that both halves are required: the
 *     flag alone decides nothing while the machine-wide switch above is set.
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
 * See MIMachInjectorRemapErrorCode below. Each case carries its own
 * description and the first thing to check when you hit it.
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
    NS_SWIFT_NAME(MachInjectorRemap.errorDomain);

/// Why a remap injection failed, in the order the 13-step recipe reaches them:
/// the loader is prepared in the injector (1-3), then the payload (4-9), then
/// everything crosses into the target (10-16).
///
/// **Check the domain before the code.** These values are the ones this header
/// has published since the remap path shipped, and none of them changed when the
/// enumeration became public. They are, deliberately, *not* the numbering the
/// two dlopen paths share: `10` here is a missing task port, which is `3` in
/// `MIMachInjectorErrorCode` and `MIMachInjectorAsyncErrorCode`. Renumbering
/// would have broken the one published contract this library actually had, so
/// the mismatch stays and the domain is what tells them apart.
///
/// In Swift: `MachInjectorRemap.Error`. The dotted `NS_SWIFT_NAME` is required
/// rather than cosmetic — see the note on `MIMachInjectorErrorCode`.
typedef NS_ERROR_ENUM(MIMachInjectorRemapErrorDomain, MIMachInjectorRemapErrorCode) {
    /// Failed to write the embedded loader dylib to its temp path.
    ///
    /// Disk full, a hardened `/private/tmp`, or a hostile hook breaking
    /// `codesign`. A fresh reboot usually rules the disk out.
    MIMachInjectorRemapErrorLoaderWriteFailed = 1,

    /// Failed to `dlopen` the embedded loader dylib in the injector.
    ///
    /// Same causes as `1`.
    MIMachInjectorRemapErrorLoaderDlopenFailed = 2,

    /// The loader dylib does not export the symbols the injector needs.
    ///
    /// `build_loader.sh` was never run, or the injector's
    /// `MIMachInjectorRemap.o` predates the current
    /// `loader_arm64_remap_dylib.h`. Touch `MIMachInjectorRemap.m` and rebuild
    /// — build systems do not track the generated header.
    MIMachInjectorRemapErrorLoaderSymbolsMissing = 3,

    /// Failed to `dlopen` the payload dylib in the injector.
    ///
    /// Wrong path, or the payload has no arm64e slice.
    MIMachInjectorRemapErrorPayloadDlopenFailed = 4,

    /// The payload does not export the requested entry symbol.
    ///
    /// Misspelled, or C++-mangled so `dlsym` will not resolve it — declare it
    /// `extern "C" __attribute__((visibility("default")))`.
    MIMachInjectorRemapErrorPayloadEntryMissing = 5,

    /// Failed to enumerate the payload's segments (unknown layout).
    ///
    /// More than 16 segments (unusual — raise the local array size in
    /// `+injectToPID:`), or a meaningful segment named like `SEG_LINKEDIT` /
    /// `SEG_PAGEZERO`.
    MIMachInjectorRemapErrorPayloadSegmentsInvalid = 6,

    /// Failed to open libswiftCore for the Swift metadata register APIs.
    ///
    /// libswiftCore is not installed, or an OS update renamed the symbols.
    /// Confirm with `dlsym(handle, "swift_registerTypeMetadataRecords")` from a
    /// small stand-alone process.
    MIMachInjectorRemapErrorSwiftCoreDlopenFailed = 7,

    /// libswiftCore is missing the Swift register symbols.
    ///
    /// Same causes as `7`.
    MIMachInjectorRemapErrorSwiftRegistersMissing = 8,

    /// Failed to locate libobjc's `map_images` through dyld's gAPIs table.
    ///
    /// The table's layout changed between OS versions. See the
    /// `FindLibObjCMapImages` heuristic — its 3-consecutive-qword scan window
    /// may need re-tuning. Enable the diagnostic log and inspect the step-4
    /// candidate list.
    MIMachInjectorRemapErrorMapImagesNotFound = 9,

    /// `task_for_pid` failed: missing permissions, or a dead target.
    ///
    /// On modern macOS: SIP off and running as root, or the
    /// `com.apple.system-task-ports.debug` entitlement with Developer Mode on
    /// for the injector's audit token, or the helper daemon pattern in
    /// `Example/`. **The dlopen paths need the same port**, so switching to
    /// them does not help.
    MIMachInjectorRemapErrorTaskForPIDFailed = 10,

    /// Failed to allocate memory in the target process.
    ///
    /// The target died between `task_for_pid` and `mach_vm_allocate`, or its
    /// ASLR left no contiguous span (rare).
    MIMachInjectorRemapErrorMachVMAllocateFailed = 11,

    /// Failed to `mach_vm_write` the config page into the target.
    ///
    /// Same causes as `11`.
    MIMachInjectorRemapErrorMachVMWriteFailed = 12,

    /// Failed to `mach_vm_remap` the payload's segments into the target.
    ///
    /// The target's VM is full, or the source pages in the injector are no
    /// longer readable because dyld unloaded a dependency. **Never `dlclose`
    /// the payload or loader in the injector** — dyld's unload path changes
    /// protections, and the change leaks through the shared mapping into the
    /// target.
    MIMachInjectorRemapErrorMachVMRemapPayloadFailed = 13,

    /// Failed to `mach_vm_remap` the loader's segments into the target.
    ///
    /// Same causes as `13`.
    MIMachInjectorRemapErrorMachVMRemapLoaderFailed = 14,

    /// `thread_convert_thread_state` failed (arm64e ptrauth).
    ///
    /// A kernel-side failure, extremely unusual: likely a kernel bug or an
    /// incompatible OS release. Diagnose with kext logging.
    MIMachInjectorRemapErrorThreadStateConvertFailed = 15,

    /// `thread_create_running` failed to start the remote mach thread.
    ///
    /// The target rejected the ARM thread state that was built for it. Likely
    /// wrong PC arithmetic (`loaderRemoteBase + stage1Offset`) or an unaligned
    /// stack pointer.
    MIMachInjectorRemapErrorRemoteThreadStartFailed = 16,

    /// This class is arm64-only and the process running it is not arm64.
    ///
    /// The remap path needs the arm64 thread-state ABI and an arm64 loader
    /// dylib; neither has an x86_64 equivalent. Use `MIMachInjector`, which
    /// supports x86_64. Appended at 17 because this path numbers its own
    /// failures independently of the two dlopen paths.
    MIMachInjectorRemapErrorArchitectureUnsupported = 17,
} NS_SWIFT_NAME(MachInjectorRemap.Error);

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
