// -----------------------------------------------------------------------------
// MIMachInjectorInternal.h — internals of MIMachInjector, exposed only so the
// test target can reach them.
// -----------------------------------------------------------------------------
//
// NOT a public header: it lives beside the implementation rather than in
// `include/`, so it is absent from the MachInjector module and no caller can
// import it. MachInjectorTests reaches these symbols through a header search
// path. Nothing here is API; it may change without notice.
//
// What is here and why: the synchronous path decides whether an injection
// succeeded by reading a report block out of the target, which needs a task port
// and therefore root. The decision itself does not — given the bytes, the
// liveness answer, and whether the read worked at all, the verdict is a pure
// function. MIMachInjectorErrorForDlopenReport() is that function, split out of
// the polling loop so the two failures proposal 0002 came from (a refusal
// carrying dlerror's text, and a target killed mid-load) can be covered by a
// unit test. The polling, the mach_vm_read_overwrite, and the liveness probe
// stay in the injector.

#ifndef MI_MACH_INJECTOR_INTERNAL_H
#define MI_MACH_INJECTOR_INTERNAL_H

#import <Foundation/Foundation.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

// What the shellcode writes back after its dlopen returns.
//
// Layout is a binary contract with loader_arm64.s / loader_x86_64.s — the
// static assertions below are the enforcement. A target that loads the dylib
// and one that never reports are indistinguishable without this block, which is
// how a refused injection used to be reported as a success: the mach thread had
// signalled DONE while nothing whatsoever was loaded.
typedef struct {
    int32_t resultCode;
    int32_t reserved;
    uint64_t handle;
    char errorMessage[256];
} MIMachInjectorDlopenReport;

// WARNING — this and MINotepadResultCode in MIMachInjectorAsync.m are DIFFERENT
// ENCODINGS OF THE SAME IDEA, and `1` means the opposite thing in each:
//
//              value 0            value 1              value 2
//   this file  not reported yet   dlopen succeeded     dlopen failed
//   async path success            dlopen failed        pthread_create failed
//
// See the matching note in MIMachInjectorAsync.m for why they are not unified.
//
// Neither of them is MIMachInjectorErrorCode. These two are the injector's
// private protocol with its own shellcode; the error codes are API. Do not
// carry a value from one into the other.
typedef NS_ENUM(int32_t, MIMachInjectorDlopenResultCode) {
    MIMachInjectorDlopenResultCodePending = 0,
    MIMachInjectorDlopenResultCodeLoaded = 1,
    MIMachInjectorDlopenResultCodeFailed = 2,
};

_Static_assert(offsetof(MIMachInjectorDlopenReport, resultCode) == 0x00, "report layout drifted from the loader shellcode");
_Static_assert(offsetof(MIMachInjectorDlopenReport, handle) == 0x08, "report layout drifted from the loader shellcode");
_Static_assert(offsetof(MIMachInjectorDlopenReport, errorMessage) == 0x10, "report layout drifted from the loader shellcode");
_Static_assert(sizeof(((MIMachInjectorDlopenReport *)0)->errorMessage) == 0x100, "report layout drifted from the loader shellcode");

#ifdef __cplusplus
extern "C" {
#endif

/// The verdict on one poll of the target's dlopen report block: `nil` to keep
/// waiting or to accept success, an error to fail the injection with.
///
/// `report` is the bytes read out of the target, or NULL when the read failed;
/// `reportWasReadable` says which. `targetIsAlive` is only consulted when the
/// report could not be read, and separates "the payload has not answered yet"
/// from "there is nobody left to answer".
///
/// Success is the default in every ambiguous case, because a payload whose
/// constructor outlasts the poll budget must not regress into a spurious error.
/// Only two answers are failures: an explicit refusal, and an unreadable report
/// from a target that no longer exists.
NSError *_Nullable MIMachInjectorErrorForDlopenReport(const MIMachInjectorDlopenReport *_Nullable report,
                                                      BOOL reportWasReadable,
                                                      BOOL targetIsAlive,
                                                      pid_t processIdentifier,
                                                      NSString *dylibPath);

#ifdef __cplusplus
}
#endif

NS_ASSUME_NONNULL_END

#endif // MI_MACH_INJECTOR_INTERNAL_H
