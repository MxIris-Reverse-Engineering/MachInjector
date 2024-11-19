//
//  MIMachInjector.h
//  MachInjector
//
//  Created by JH on 2024/11/19.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MIMachInjectorErrorDomain;

@interface MIMachInjector : NSObject
+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable *)error;
@end

NS_ASSUME_NONNULL_END
