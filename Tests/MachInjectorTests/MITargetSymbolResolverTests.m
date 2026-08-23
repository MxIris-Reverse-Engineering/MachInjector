// Exercises MITargetSymbolResolver against the *test process itself*.
//
// Using our own task is what makes these tests cheap enough to keep: a resolver
// built on `mach_task_self()` runs the exact production path — task_info,
// dyld_all_image_infos, the image walk, the Mach-O and symbol-table parsing —
// without root and without a second process to babysit. And because the answers
// are about this process, `dlsym` is available as an independent oracle for
// every address the parser produces.
//
// What this cannot cover is the cross-architecture case the resolver exists for
// (an arm64e injector reading an arm64 simulator target). That needs a live
// simulator and root, and belongs to the proposal's end-to-end step.

#import <XCTest/XCTest.h>
#import "MITargetSymbolResolver.h"

#include <dlfcn.h>
#include <mach/mach.h>
#include <ptrauth.h>

@interface MITargetSymbolResolverTests : XCTestCase
@end

@implementation MITargetSymbolResolverTests

- (MITargetSymbolResolver *)resolverForSelf {
    NSError *error = nil;
    MITargetSymbolResolver *resolver = [MITargetSymbolResolver resolverForTask:mach_task_self() error:&error];
    XCTAssertNotNil(resolver, @"could not build a resolver for our own task: %@", error);
    return resolver;
}

- (uint64_t)strippedAddressOfLocalSymbol:(const char *)name {
    void *symbol = dlsym(RTLD_DEFAULT, name);
    return (uint64_t)(uintptr_t)ptrauth_strip(symbol, ptrauth_key_function_pointer);
}

#pragma mark - Image list

- (void)testResolverReadsThisProcessImageList {
    MITargetSymbolResolver *resolver = [self resolverForSelf];
    XCTAssertGreaterThan(resolver.imagePaths.count, 1u);

    BOOL sawLibsystem = NO;
    for (NSString *path in resolver.imagePaths) {
        if ([path hasSuffix:@"libsystem_pthread.dylib"]) {
            sawLibsystem = YES;
            break;
        }
    }
    XCTAssertTrue(sawLibsystem, @"libsystem_pthread is loaded in every process; the image walk missed it");
}

- (void)testArchitectureComesFromTheTargetsOwnHeader {
    MITargetSymbolResolver *resolver = [self resolverForSelf];
#if defined(__arm64__)
    XCTAssertEqual(resolver.targetCPUType, CPU_TYPE_ARM64);
#elif defined(__x86_64__)
    XCTAssertEqual(resolver.targetCPUType, CPU_TYPE_X86_64);
#endif
}

- (void)testThisProcessIsNotASimulatorTarget {
    // The detection keys on RuntimeRoot/.simruntime in the image paths, so a
    // normal macOS process must come back NO. Guards against a predicate loose
    // enough to match everything.
    XCTAssertFalse([self resolverForSelf].isSimulatorTarget);
}

#pragma mark - Symbol resolution

- (void)testResolvedAddressMatchesDlsym {
    // The whole point of the class: an address derived purely from the target's
    // own symbol table, with nothing borrowed from the caller's address space.
    // Here the two happen to be the same process, which is exactly why dlsym
    // can be trusted as the answer key.
    MITargetSymbolResolver *resolver = [self resolverForSelf];
    NSError *error = nil;
    uint64_t resolved = [resolver addressOfSymbol:@"pthread_create_from_mach_thread"
                                  inImageWithPath:@"libsystem_pthread.dylib"
                                            error:&error];
    XCTAssertNotEqual(resolved, 0ull, @"resolution failed: %@", error);
    XCTAssertEqual(resolved, [self strippedAddressOfLocalSymbol:"pthread_create_from_mach_thread"]);
}

- (void)testResolvesSymbolsFromSeveralImages {
    MITargetSymbolResolver *resolver = [self resolverForSelf];
    NSDictionary<NSString *, NSString *> *cases = @{
        @"pthread_create_from_mach_thread": @"libsystem_pthread.dylib",
        @"mach_vm_read_overwrite": @"libsystem_kernel.dylib",
    };

    [cases enumerateKeysAndObjectsUsingBlock:^(NSString *symbol, NSString *image, BOOL *stop) {
        NSError *error = nil;
        uint64_t resolved = [resolver addressOfSymbol:symbol inImageWithPath:image error:&error];
        XCTAssertNotEqual(resolved, 0ull, @"%@ in %@ failed: %@", symbol, image, error);
        XCTAssertEqual(resolved, [self strippedAddressOfLocalSymbol:symbol.UTF8String], @"%@", symbol);
    }];
}

- (void)testLoadAddressMatchesTheResolvedSymbolsImage {
    MITargetSymbolResolver *resolver = [self resolverForSelf];
    uint64_t base = [resolver loadAddressOfImageWithPath:@"libsystem_pthread.dylib"];
    XCTAssertNotEqual(base, 0ull);

    uint64_t symbol = [resolver addressOfSymbol:@"pthread_create_from_mach_thread"
                                inImageWithPath:@"libsystem_pthread.dylib"
                                          error:NULL];
    XCTAssertGreaterThan(symbol, base, @"a symbol must sit above the load address of its own image");
}

#pragma mark - Failure modes

- (void)testMissingImageIsReported {
    NSError *error = nil;
    uint64_t resolved = [[self resolverForSelf] addressOfSymbol:@"malloc"
                                                inImageWithPath:@"libnothing_here.dylib"
                                                          error:&error];
    XCTAssertEqual(resolved, 0ull);
    XCTAssertEqualObjects(error.domain, MITargetSymbolResolverErrorDomain);
    XCTAssertEqual(error.code, MITargetSymbolResolverErrorImageNotFound);
}

- (void)testMissingSymbolIsReportedSeparatelyFromMissingImage {
    // These two must not collapse into one error: "the image is not loaded" and
    // "the image is loaded but lacks the symbol" call for different fixes.
    NSError *error = nil;
    uint64_t resolved = [[self resolverForSelf] addressOfSymbol:@"mi_no_such_symbol_exists"
                                                inImageWithPath:@"libsystem_pthread.dylib"
                                                          error:&error];
    XCTAssertEqual(resolved, 0ull);
    XCTAssertEqual(error.code, MITargetSymbolResolverErrorSymbolNotFound);
}

- (void)testUnreadableTargetIsReportedRatherThanCrashing {
    // A reader that refuses everything stands in for a task port that died
    // between the snapshot and the read.
    NSError *error = nil;
    MITargetSymbolResolver *resolver =
        [MITargetSymbolResolver resolverWithMemoryReader:^BOOL(uint64_t address, void *buffer, size_t size) {
            return NO;
        }
                                    allImageInfosAddress:0x1000
                                                   error:&error];
    XCTAssertNil(resolver);
    XCTAssertEqual(error.code, MITargetSymbolResolverErrorAllImageInfosUnreadable);
}

- (void)testZeroAllImageInfosAddressIsRejected {
    NSError *error = nil;
    MITargetSymbolResolver *resolver =
        [MITargetSymbolResolver resolverWithMemoryReader:^BOOL(uint64_t address, void *buffer, size_t size) {
            return YES;
        }
                                    allImageInfosAddress:0
                                                   error:&error];
    XCTAssertNil(resolver);
    XCTAssertEqual(error.code, MITargetSymbolResolverErrorAllImageInfosUnreadable);
}

@end
