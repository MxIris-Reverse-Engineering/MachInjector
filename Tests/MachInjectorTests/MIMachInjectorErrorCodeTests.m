// -----------------------------------------------------------------------------
// Regression tests for proposal 0002 — classifying injection failures into error
// codes a caller can branch on.
// -----------------------------------------------------------------------------
//
// The defect these pin down: every one of the synchronous path's failure points
// returned code:1, so the only thing separating "no task port" from "the target
// refused the dylib" was the English sentence in userInfo — which this library's
// typical deployment (inject from a privileged daemon, report back over XPC)
// drops on the floor. A caller was left with
// "MIMachInjectorErrorDomain error 1".
//
// Two halves are testable without root, and they are the two that matter:
//
//   - Reaching two different failure points really does produce two different
//     codes. Both of these failures happen before any task port is needed.
//   - The dlopen verdict — the failure this whole proposal came from — is a
//     pure function of the report block, the target's liveness, and whether the
//     report could be read at all. MIMachInjectorErrorForDlopenReport() is that
//     function, split out of the polling loop precisely so it can be tested
//     here; the mach_vm_read_overwrite that feeds it stays in the injector and
//     still needs root.

#import <XCTest/XCTest.h>

#import <errno.h>
#import <signal.h>
#import <string.h>

#import "MIMachInjector.h"
#import "MIMachInjectorAsync.h"
#import "MIMachInjectorRemap.h"

#import "MIMachInjectorInternal.h"

@interface MIMachInjectorErrorCodeTests : XCTestCase
@end

@implementation MIMachInjectorErrorCodeTests

#pragma mark - Helpers

/// A pid that is guaranteed not to name a live process, so `task_for_pid` fails
/// for a reason the test controls rather than for lack of privilege.
///
/// Searched downwards from the system maximum because low pids are the ones in
/// use. `kill(pid, 0)` failing with ESRCH is the only answer that proves
/// absence — EPERM means the process is alive and merely not ours.
static pid_t FindProcessIdentifierThatDoesNotExist(void) {
    for (pid_t candidate = 99999; candidate > 1000; --candidate) {
        if (kill(candidate, 0) == -1 && errno == ESRCH) {
            return candidate;
        }
    }
    return 0;
}

#pragma mark - Distinct codes for distinct failures

- (void)testInvalidProcessIdentifierAndMissingTaskPortReportDifferentCodes {
    NSError *invalidProcessIdentifierError = nil;
    XCTAssertFalse([MIMachInjector injectToPID:0
                                     dylibPath:@"/nonexistent/payload.dylib"
                                         error:&invalidProcessIdentifierError]);
    XCTAssertNotNil(invalidProcessIdentifierError);

    pid_t absentProcessIdentifier = FindProcessIdentifierThatDoesNotExist();
    XCTAssertGreaterThan(absentProcessIdentifier, 0,
                         @"could not find a pid that is free; the test cannot proceed");

    NSError *missingTaskPortError = nil;
    XCTAssertFalse([MIMachInjector injectToPID:absentProcessIdentifier
                                     dylibPath:@"/nonexistent/payload.dylib"
                                         error:&missingTaskPortError]);
    XCTAssertNotNil(missingTaskPortError);

    XCTAssertEqualObjects(invalidProcessIdentifierError.domain, MIMachInjectorErrorDomain);
    XCTAssertEqualObjects(missingTaskPortError.domain, MIMachInjectorErrorDomain);

    // The point of the whole proposal: these are different failures and a caller
    // must be able to tell them apart from `code` alone, because that is the
    // only field guaranteed to survive an XPC hop. Before 0002 both were 1.
    XCTAssertNotEqual(invalidProcessIdentifierError.code, missingTaskPortError.code,
                      @"distinct failure points must not share an error code");

    XCTAssertEqual(invalidProcessIdentifierError.code, MIMachInjectorErrorInvalidProcessIdentifier);
    XCTAssertEqual(missingTaskPortError.code, MIMachInjectorErrorTaskPortUnavailable);
}

/// The numbering deliberately mirrors the async path rather than running 1..N,
/// so that a caller who confuses the two domains is not silently misled. Pin the
/// three codes both paths must agree on.
- (void)testCodesShareTheAsyncPathsNumbering {
    XCTAssertEqual(MIMachInjectorErrorInvalidProcessIdentifier, 2);
    XCTAssertEqual(MIMachInjectorErrorTaskPortUnavailable, 3);
    XCTAssertEqual(MIMachInjectorErrorTargetRefusedToLoadDylib, 18);
    XCTAssertEqual(MIMachInjectorErrorTimedOut, 19);
}

#pragma mark - The dlopen verdict

- (void)testReportOfLoadedIsSuccess {
    MIMachInjectorDlopenReport report = {0};
    report.resultCode = MIMachInjectorDlopenResultCodeLoaded;
    report.handle = 0x1234;

    NSError *error = MIMachInjectorErrorForDlopenReport(&report, YES, YES, 4242, @"/payload.dylib");
    XCTAssertNil(error);
}

- (void)testReportOfFailureCarriesTheDlerrorTextInItsOwnUserInfoKey {
    MIMachInjectorDlopenReport report = {0};
    report.resultCode = MIMachInjectorDlopenResultCodeFailed;
    const char *dlopenMessage =
        "dlopen(/payload.dylib, 0x0001): tried: '/payload.dylib' (code signature invalid)";
    strlcpy(report.errorMessage, dlopenMessage, sizeof(report.errorMessage));

    NSError *error = MIMachInjectorErrorForDlopenReport(&report, YES, YES, 4242, @"/payload.dylib");

    XCTAssertNotNil(error);
    XCTAssertEqualObjects(error.domain, MIMachInjectorErrorDomain);
    XCTAssertEqual(error.code, MIMachInjectorErrorTargetRefusedToLoadDylib);

    // The reason this key exists: a caller that wants to distinguish "bad
    // signature" from "seatbelt denied the mapping" should not have to fish a
    // substring out of a human-readable sentence.
    XCTAssertEqualObjects(error.userInfo[MIMachInjectorRemoteErrorMessageKey],
                          @(dlopenMessage));

    // …and it is still readable on its own.
    XCTAssertTrue([error.localizedDescription containsString:@"/payload.dylib"]);
    XCTAssertTrue([error.localizedDescription containsString:@"code signature invalid"]);
}

/// dlopen can return NULL with nothing to say. The code must still classify.
- (void)testReportOfFailureWithNoMessageStillClassifies {
    MIMachInjectorDlopenReport report = {0};
    report.resultCode = MIMachInjectorDlopenResultCodeFailed;

    NSError *error = MIMachInjectorErrorForDlopenReport(&report, YES, YES, 4242, @"/payload.dylib");

    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, MIMachInjectorErrorTargetRefusedToLoadDylib);
    XCTAssertNil(error.userInfo[MIMachInjectorRemoteErrorMessageKey],
                 @"an absent dlerror must not become an empty string a caller has to special-case");
}

/// An unreadable report from a target that is gone is a failed injection wearing
/// a success's clothes — the code-signing monitor kills the process as the page
/// faults in, so dlopen never returns and nothing is ever written.
- (void)testUnreadableReportFromDeadTargetIsTerminatedWhileLoading {
    NSError *error = MIMachInjectorErrorForDlopenReport(NULL, NO, NO, 4242, @"/payload.dylib");

    XCTAssertNotNil(error);
    XCTAssertEqual(error.code, MIMachInjectorErrorTargetTerminatedWhileLoading);
}

/// …whereas an unreadable report from a live target keeps the pre-0002
/// behaviour: a payload slower than the poll budget must not regress into a
/// spurious error.
- (void)testUnreadableReportFromLiveTargetIsSuccess {
    NSError *error = MIMachInjectorErrorForDlopenReport(NULL, NO, YES, 4242, @"/payload.dylib");

    XCTAssertNil(error);
}

/// A report that reads back as still-pending is also success, for the same
/// reason: only an explicit failure downgrades the verdict.
- (void)testPendingReportIsSuccess {
    MIMachInjectorDlopenReport report = {0};
    report.resultCode = MIMachInjectorDlopenResultCodePending;

    NSError *error = MIMachInjectorErrorForDlopenReport(&report, YES, YES, 4242, @"/payload.dylib");
    XCTAssertNil(error);
}

#pragma mark - The published numbering must not drift

/// The async path's codes were published as a table in its header long before
/// they were an enumeration. Turning them into one was required to change
/// nothing, so pin every value: a caller out there has these integers hardcoded,
/// because until now that was the only way to use them.
- (void)testAsyncCodesMatchTheNumbersItsHeaderHasAlwaysPublished {
    XCTAssertEqual(MIMachInjectorAsyncErrorInjectionContextAllocationFailed, 1);
    XCTAssertEqual(MIMachInjectorAsyncErrorInvalidProcessIdentifier, 2);
    XCTAssertEqual(MIMachInjectorAsyncErrorTaskPortUnavailable, 3);
    XCTAssertEqual(MIMachInjectorAsyncErrorNotepadAllocationFailed, 4);
    XCTAssertEqual(MIMachInjectorAsyncErrorNotepadInitializationFailed, 5);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemoteStackAllocationFailed, 6);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemoteStackProtectionFailed, 7);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemoteCodeAllocationFailed, 8);
    XCTAssertEqual(MIMachInjectorAsyncErrorLocalShellcodeBufferAllocationFailed, 9);
    XCTAssertEqual(MIMachInjectorAsyncErrorDylibPathTooLong, 10);
    XCTAssertEqual(MIMachInjectorAsyncErrorShellcodeWriteFailed, 11);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemoteCodeProtectionFailed, 12);
    XCTAssertEqual(MIMachInjectorAsyncErrorThreadStateConverterUnavailable, 13);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemoteThreadCreationFailed, 14);
    XCTAssertEqual(MIMachInjectorAsyncErrorThreadStateConversionFailed, 15);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemoteThreadStartFailed, 16);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemotePthreadCreationFailed, 17);
    XCTAssertEqual(MIMachInjectorAsyncErrorTargetRefusedToLoadDylib, 18);
    XCTAssertEqual(MIMachInjectorAsyncErrorTimedOut, 19);
    XCTAssertEqual(MIMachInjectorAsyncErrorRemoteMachPortAllocationFailed, 21);
    XCTAssertEqual(MIMachInjectorAsyncErrorDispatchSourceCreationFailed, 22);
}

/// Likewise for the remap path, whose codes have been in its header since it
/// shipped. Moving the enumeration out of the .m changed visibility, not values.
- (void)testRemapCodesMatchTheNumbersItsHeaderHasAlwaysPublished {
    XCTAssertEqual(MIMachInjectorRemapErrorLoaderWriteFailed, 1);
    XCTAssertEqual(MIMachInjectorRemapErrorLoaderDlopenFailed, 2);
    XCTAssertEqual(MIMachInjectorRemapErrorLoaderSymbolsMissing, 3);
    XCTAssertEqual(MIMachInjectorRemapErrorPayloadDlopenFailed, 4);
    XCTAssertEqual(MIMachInjectorRemapErrorPayloadEntryMissing, 5);
    XCTAssertEqual(MIMachInjectorRemapErrorPayloadSegmentsInvalid, 6);
    XCTAssertEqual(MIMachInjectorRemapErrorSwiftCoreDlopenFailed, 7);
    XCTAssertEqual(MIMachInjectorRemapErrorSwiftRegistersMissing, 8);
    XCTAssertEqual(MIMachInjectorRemapErrorMapImagesNotFound, 9);
    XCTAssertEqual(MIMachInjectorRemapErrorTaskForPIDFailed, 10);
    XCTAssertEqual(MIMachInjectorRemapErrorMachVMAllocateFailed, 11);
    XCTAssertEqual(MIMachInjectorRemapErrorMachVMWriteFailed, 12);
    XCTAssertEqual(MIMachInjectorRemapErrorMachVMRemapPayloadFailed, 13);
    XCTAssertEqual(MIMachInjectorRemapErrorMachVMRemapLoaderFailed, 14);
    XCTAssertEqual(MIMachInjectorRemapErrorThreadStateConvertFailed, 15);
    XCTAssertEqual(MIMachInjectorRemapErrorRemoteThreadStartFailed, 16);

    // Appended, not squeezed into the published range: the non-arm64 stub used
    // to report 1, which this enumeration defines as a failed loader write —
    // a failure that had not happened. The async path's stub had the same bug.
    XCTAssertEqual(MIMachInjectorRemapErrorArchitectureUnsupported, 17);
}

/// The one thing the three domains must never do is give one integer two
/// meanings *within the numbering the two dlopen paths share*. Remap is exempt
/// by design — hence the "check the domain first" warning on all three.
- (void)testTheTwoDlopenPathsAgreeWhereverBothCanFail {
    XCTAssertEqual((NSInteger)MIMachInjectorErrorInvalidProcessIdentifier,
                   (NSInteger)MIMachInjectorAsyncErrorInvalidProcessIdentifier);
    XCTAssertEqual((NSInteger)MIMachInjectorErrorTaskPortUnavailable,
                   (NSInteger)MIMachInjectorAsyncErrorTaskPortUnavailable);
    XCTAssertEqual((NSInteger)MIMachInjectorErrorRemoteStackAllocationFailed,
                   (NSInteger)MIMachInjectorAsyncErrorRemoteStackAllocationFailed);
    XCTAssertEqual((NSInteger)MIMachInjectorErrorDylibPathTooLong,
                   (NSInteger)MIMachInjectorAsyncErrorDylibPathTooLong);
    XCTAssertEqual((NSInteger)MIMachInjectorErrorTargetRefusedToLoadDylib,
                   (NSInteger)MIMachInjectorAsyncErrorTargetRefusedToLoadDylib);
    XCTAssertEqual((NSInteger)MIMachInjectorErrorTimedOut,
                   (NSInteger)MIMachInjectorAsyncErrorTimedOut);

    // The synchronous path's own failures start above everything the async path
    // uses, so neither can collide with the other as both grow.
    XCTAssertGreaterThan((NSInteger)MIMachInjectorErrorRemoteStackWriteFailed,
                         (NSInteger)MIMachInjectorAsyncErrorDispatchSourceCreationFailed);
    XCTAssertGreaterThan((NSInteger)MIMachInjectorAsyncErrorArchitectureUnsupported,
                         (NSInteger)MIMachInjectorErrorTargetTerminatedWhileLoading);
}

@end
