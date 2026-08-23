#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MIMachInjectorErrorDomain
    NS_SWIFT_NAME(MachInjector.errorDomain);

/// The `dlerror` text the target reported, when the failure carries one.
///
/// Present on `MIMachInjectorErrorTargetRefusedToLoadDylib`, and only when the
/// target's `dlopen` actually had something to say. The same text is folded into
/// `localizedDescription`; this key exists so a caller can inspect the reason
/// programmatically instead of matching substrings against a human-readable
/// sentence. It is the synchronous counterpart of the async path's
/// `MIInjectionResult.remoteErrorMessage`.
FOUNDATION_EXPORT NSErrorUserInfoKey const MIMachInjectorRemoteErrorMessageKey
    NS_SWIFT_NAME(MachInjector.remoteErrorMessageKey);

/// Why an injection failed.
///
/// **Check the domain before the code.** The three injection paths publish three
/// separate enumerations, and only two of them agree on numbering: this one and
/// `MIMachInjectorAsyncErrorCode` assign each value the same meaning, so a caller
/// that uses both can share one `switch`. `MIMachInjectorRemapErrorCode` does
/// not — its `10` is a missing task port, which is `3` here. Matching a bare
/// integer without first checking `domain` will eventually mislead you.
///
/// The values below are not contiguous. They mirror the async path's numbering,
/// which means every failure this path cannot produce leaves a hole (`1`, `4`,
/// `5`, `17`, `20`, `21`, `22`). The holes are deliberate: reusing them would
/// give one integer two meanings across two domains that callers routinely use
/// together, and this repository already carries one bug of exactly that shape
/// (see the warning on `MIMachInjectorDlopenResultCode`). New failure points are
/// appended after the highest value in either path; existing values never move.
///
/// `1` is unused here on purpose. Before these codes existed every failure was
/// `1`, so leaving it unassigned makes a stale `code == 1` test fail to match
/// anything rather than silently match one specific failure.
///
/// In Swift this is `MachInjector.Error` (with `MachInjector.Error.Code` for the
/// raw values), matching how `BGTaskSchedulerErrorCode` is published as
/// `BGTaskScheduler.Error`. Note that `NS_SWIFT_NAME` here must carry the dotted
/// form: a flat name like `MachInjectorErrorCode` also compiles, but it renames
/// only the enumeration and leaves the error type Swift synthesizes from
/// `NS_ERROR_ENUM` under its ObjC-derived name, so callers end up with two names
/// for one type. Apple spells the same thing in `.apinotes`, which a
/// source-distributed SPM package cannot use — apinotes are read by the
/// *consumer's* ClangImporter and would require every downstream target to pass
/// `-Xcc -iapinotes-modules`.
typedef NS_ERROR_ENUM(MIMachInjectorErrorDomain, MIMachInjectorErrorCode) {
    /// `pid` was 0.
    MIMachInjectorErrorInvalidProcessIdentifier = 2,

    /// `task_for_pid` was refused, or the target is already gone.
    ///
    /// The injector is not root, lacks
    /// `com.apple.system-task-ports.debug`, is not signed with the
    /// debugger entitlement, or the pid names nothing. **Falling back to
    /// `MIMachInjectorRemap` does not help** — it needs the same task port.
    MIMachInjectorErrorTaskPortUnavailable = 3,

    /// `mach_vm_allocate` for the remote thread's stack failed.
    MIMachInjectorErrorRemoteStackAllocationFailed = 6,

    /// `mach_vm_protect` on the remote stack failed.
    MIMachInjectorErrorRemoteStackProtectionFailed = 7,

    /// `mach_vm_allocate` for the shellcode segment failed.
    MIMachInjectorErrorRemoteCodeAllocationFailed = 8,

    /// The injector could not allocate its own staging buffer for the shellcode.
    MIMachInjectorErrorLocalShellcodeBufferAllocationFailed = 9,

    /// The dylib path does not fit the fixed-size slot in the shellcode.
    MIMachInjectorErrorDylibPathTooLong = 10,

    /// `mach_vm_write` of the shellcode into the target failed.
    MIMachInjectorErrorShellcodeWriteFailed = 11,

    /// `mach_vm_protect` could not make the shellcode segment executable.
    MIMachInjectorErrorRemoteCodeProtectionFailed = 12,

    /// `thread_convert_thread_state` could not be resolved (arm64e).
    MIMachInjectorErrorThreadStateConverterUnavailable = 13,

    /// `thread_create` failed.
    MIMachInjectorErrorRemoteThreadCreationFailed = 14,

    /// `thread_convert_thread_state` failed to sign the state (arm64e ptrauth).
    MIMachInjectorErrorThreadStateConversionFailed = 15,

    /// `thread_create_running` failed to start the remote thread.
    MIMachInjectorErrorRemoteThreadStartFailed = 16,

    /// The target's `dlopen` refused the dylib.
    ///
    /// The injection mechanism itself worked; the target declined the image.
    /// Read `MIMachInjectorRemoteErrorMessageKey` for `dlerror`'s own words. If
    /// it mentions a code signature or library validation, the fix is the
    /// machine-wide AMFI switch documented in the README's requirements — not a
    /// different injection path. If the target's seatbelt profile denied
    /// `file-map-executable`, no switch helps and `MIMachInjectorRemap` is the
    /// way, since it never calls `dlopen` in the target.
    MIMachInjectorErrorTargetRefusedToLoadDylib = 18,

    /// The target never signalled that its pthread had started.
    ///
    /// Also what an in-target `pthread_create` failure looks like from here:
    /// this path's shellcode only reports after a successful `pthread_create`,
    /// so a failed one is indistinguishable from silence. (The async path can
    /// tell them apart and reports `17` for it; this path has no `17`.) A
    /// suspended target produces the same symptom.
    MIMachInjectorErrorTimedOut = 19,

    /// `mach_vm_write` of the initial stack contents failed.
    MIMachInjectorErrorRemoteStackWriteFailed = 23,

    /// A sandbox extension token for the target could not be issued.
    MIMachInjectorErrorSandboxExtensionTokenUnavailable = 24,

    /// The sandbox extension token does not fit its slot in the shellcode.
    MIMachInjectorErrorSandboxExtensionTokenTooLong = 25,

    /// `thread_set_state` failed (pre-macOS 14.4 start sequence).
    MIMachInjectorErrorThreadStateAssignmentFailed = 26,

    /// `thread_resume` failed (pre-macOS 14.4 start sequence).
    MIMachInjectorErrorRemoteThreadResumeFailed = 27,

    /// `thread_get_state` on the remote thread failed while waiting for it.
    MIMachInjectorErrorThreadStateReadFailed = 28,

    /// The target died while loading the dylib.
    ///
    /// Distinct from a refusal: `dlopen` never returned, so there is no
    /// `dlerror` to report. The usual cause is a payload whose page hashes do
    /// not match its signature — the kernel kills the process as the page is
    /// faulted in. Re-sign the payload and check it with
    /// `codesign --verify --deep --strict`.
    MIMachInjectorErrorTargetTerminatedWhileLoading = 29,

    /// The addresses the shellcode needs could not be resolved inside the
    /// target.
    ///
    /// Only reported for a target that does not share this process's dyld
    /// shared cache — an iOS Simulator process is the case this exists for.
    /// Where injector and target do share a cache, an unresolvable symbol falls
    /// back to the injector's own `dlsym`, which is what every release before
    /// this used unconditionally.
    MIMachInjectorErrorTargetSymbolsUnresolvable = 30,
} NS_SWIFT_NAME(MachInjector.Error);

NS_SWIFT_NAME(MachInjector)
@interface MIMachInjector : NSObject

/// Inject `dylibPath` into `pid` by running shellcode that spawns a pthread and
/// calls `dlopen` inside the target.
///
/// Returns `NO` when the injection itself fails (no task port, no sandbox
/// extension, thread setup rejected), when the target's `dlopen` refuses the
/// dylib — the latter carries `dlerror`'s message in the returned error — and
/// when the target dies while loading it.
///
/// A refusal is the normal outcome for a target whose seatbelt profile denies
/// `file-map-executable`, and for one that is actually having AMFI library
/// validation enforced against it. The seatbelt case is not fixable from any
/// side; use `MIMachInjectorRemap` for it. Library validation is fixable, but
/// only by the machine's owner and only machine-wide — see the paragraph below
/// for the global switch that governs it.
///
/// Do not predict a refusal from `csops(CS_OPS_STATUS)` reporting
/// `CS_REQUIRE_LV`. The flag says the target requests library validation, not
/// that the system is enforcing it, and enforcement is a property of the whole
/// machine rather than of the target: `amfid` consults
/// `/Library/Preferences/com.apple.security.libraryvalidation.plist` and lets
/// every load through when its `DisableLibraryValidation` key is true. It only
/// reads that file at all when SIP is disabled (or on an Apple-internal
/// machine); with SIP on, the key is ignored and validation is enforced
/// regardless. So disabling SIP is necessary but not sufficient — it unlocks
/// the switch, it is not the switch — and a `CS_REQUIRE_LV` target on a machine
/// where the key is set loads unsigned, ad-hoc, and foreign-Team-ID dylibs
/// without complaint (measured on macOS 26.5). Attempt the injection and branch
/// on the result instead: a refusal arrives as
/// `MIMachInjectorErrorTargetRefusedToLoadDylib` with `dlerror`'s own words
/// under `MIMachInjectorRemoteErrorMessageKey`. The README's "Library
/// validation" requirement documents the switch and how to confirm it took.
///
/// The dylib's own initialization is not waited for: `YES` means the image was
/// mapped, not that its constructors finished.
+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)error NS_SWIFT_NAME(inject(pid:dylibPath:));

@end

NS_ASSUME_NONNULL_END
