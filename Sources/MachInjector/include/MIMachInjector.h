#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MIMachInjectorErrorDomain;

NS_SWIFT_NAME(MachInjector)
@interface MIMachInjector : NSObject

+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)error NS_SWIFT_NAME(inject(pid:dylibPath:));

@end

NS_ASSUME_NONNULL_END
