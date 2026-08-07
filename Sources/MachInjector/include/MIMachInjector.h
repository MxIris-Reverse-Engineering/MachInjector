#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MIMachInjectorErrorDomain;

NS_SWIFT_NAME(MachInjector)
@interface MIMachInjector : NSObject

/// Inject `dylibPath` into `pid` by running shellcode that spawns a pthread and
/// calls `dlopen` inside the target.
///
/// Returns `NO` when the injection itself fails (no task port, no sandbox
/// extension, thread setup rejected) *and* when the target's `dlopen` refuses
/// the dylib — the latter carries `dlerror`'s message in the returned error.
/// A refusal is the normal outcome for a target that enforces AMFI library
/// validation (every Apple app: `csops(CS_OPS_STATUS)` reports `CS_REQUIRE_LV`)
/// or whose seatbelt profile denies `file-map-executable`. Neither is fixable
/// from this side; use `MIMachInjectorRemap` for those targets.
///
/// The dylib's own initialization is not waited for: `YES` means the image was
/// mapped, not that its constructors finished.
+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)error NS_SWIFT_NAME(inject(pid:dylibPath:));

@end

NS_ASSUME_NONNULL_END
