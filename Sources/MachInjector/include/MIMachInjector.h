#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MIMachInjectorErrorDomain;

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
/// on the result instead.
///
/// The dylib's own initialization is not waited for: `YES` means the image was
/// mapped, not that its constructors finished.
+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)error NS_SWIFT_NAME(inject(pid:dylibPath:));

@end

NS_ASSUME_NONNULL_END
