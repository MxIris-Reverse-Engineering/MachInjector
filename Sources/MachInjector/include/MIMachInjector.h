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
/// validation enforced against it. Neither is fixable from this side; use
/// `MIMachInjectorRemap` for those targets.
///
/// Do not predict a refusal from `csops(CS_OPS_STATUS)` reporting
/// `CS_REQUIRE_LV`. The flag says the target requests library validation, not
/// that the system is enforcing it: with SIP disabled, a process signed
/// `library,runtime` and reporting `CS_REQUIRE_LV` loads unsigned, ad-hoc, and
/// foreign-Team-ID dylibs without complaint (measured on macOS 26.5). And SIP
/// is disabled on essentially every machine where this class can be used at
/// all, since `task_for_pid` against a hardened target requires it — so the
/// prediction tends to be wrong exactly where it would be consulted. Attempt
/// the injection and branch on the result instead.
///
/// The dylib's own initialization is not waited for: `YES` means the image was
/// mapped, not that its constructors finished.
+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)error NS_SWIFT_NAME(inject(pid:dylibPath:));

@end

NS_ASSUME_NONNULL_END
