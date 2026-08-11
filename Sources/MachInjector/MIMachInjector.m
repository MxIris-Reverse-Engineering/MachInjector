#import "MIMachInjector.h"

#import "MIMachInjectorInternal.h"
#include <Cocoa/Cocoa.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bsm/libbsm.h>

extern char *sandbox_extension_issue_file_to_process(const char *extension_class, const char *path, uint32_t flags, audit_token_t);

#ifndef TASK_AUDIT_TOKEN
#define TASK_AUDIT_TOKEN 15
#endif

// Completion magic number: "DONE" in little-endian (0x444f4e45)
#define MI_INJECTION_DONE 0x444f4e45

// The report block the shellcode's pthread fills in after calling dlopen, its
// result codes, and the layout assertions that keep it in sync with the
// REPORT_* offsets in loader_arm64.s / loader_x86_64.s all live in
// MIMachInjectorInternal.h — the tests build one to exercise the verdict below
// without a task port.

// How long to wait for the pthread's dlopen to land after the mach thread
// signalled "DONE". A payload whose constructor is slow can outlast this; a
// still-pending report is therefore treated as success, exactly as before this
// block existed. Only an explicit failure code turns into an error.
//
// The budget is generous by two orders of magnitude: measured on macOS 26.5,
// every refusal that returns to dlopen does so well inside 20 ms — a missing
// path in 0.3 ms, a seatbelt `deny file-map-executable` in 0.7 ms, and an
// invalid code signature on a 10 MB dylib (cold vnode, amfid consulted) in
// 15-19 ms.
#define MI_DLOPEN_REPORT_POLL_ATTEMPTS 100
#define MI_DLOPEN_REPORT_POLL_INTERVAL_MICROSECONDS 20000

// Whether the target still exists.
//
// Checked when the report block cannot be read, to tell "the payload has not
// answered yet" apart from "there is nobody left to answer". Consults the task
// port first: the kernel turns our send right into a dead name the moment the
// task dies, which is both immediate and immune to the PID being recycled onto
// some unrelated process. kill(pid, 0) is the fallback — EPERM means the
// process is alive but not ours to signal, so only ESRCH proves absence.
static BOOL MIMachInjectorTargetIsAlive(mach_port_t task, pid_t pid) {
    if (task != MACH_PORT_NULL) {
        mach_port_type_t portType = 0;
        if (mach_port_type(mach_task_self(), task, &portType) == KERN_SUCCESS &&
            (portType & MACH_PORT_TYPE_DEAD_NAME) != 0) {
            return NO;
        }
    }
    return !(kill(pid, 0) != 0 && errno == ESRCH);
}

#ifdef __arm64__

#include <ptrauth.h>
#include <sys/sysctl.h>

extern const char *const APP_SANDBOX_READ;
extern char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);

extern char __shellcode_start[];
extern char __shellcode_end[];
extern char __patch_pthread_create[];
extern char __patch_sandbox_consume[];
extern char __patch_dlopen[];
extern char __patch_dlerror[];
extern char __data_payload_path[];
extern char __data_sandbox_token[];
extern char __data_report_address[];

static kern_return_t (*_thread_convert_thread_state)(thread_act_t thread, int direction, thread_state_flavor_t flavor, thread_state_t in_state, mach_msg_type_number_t in_stateCnt, thread_state_t out_state, mach_msg_type_number_t *out_stateCnt);

#else // __x86_64__

// External symbols from loader_x86_64.s
// These define the shellcode boundaries and patch locations
extern char __x86_shellcode_start[];
extern char __x86_shellcode_end[];
extern char __x86_patch_pthread_create[];
extern char __x86_patch_dlopen[];
extern char __x86_patch_dlerror[];
extern char __x86_data_payload_path[];
extern char __x86_data_report_address[];

// Maximum dylib path length (must match .zero size in loader_x86_64.s)
#define X86_MAX_PATH_LENGTH 512

#endif

NSErrorDomain const MIMachInjectorErrorDomain = @"MIMachInjectorErrorDomain";

//
// Attribution:
// The arm64e injection path is based on work by Jeremy Legendre (https://github.com/jslegendre)
//

NSErrorUserInfoKey const MIMachInjectorRemoteErrorMessageKey = @"MIMachInjectorRemoteErrorMessage";

// Every failure in this file goes through here, so that classifying one is a
// matter of naming a code rather than remembering to. The code parameter is
// typed rather than NSInteger: a new failure point cannot compile until it has
// decided which code it is.
static NSError *MIMachInjectorErrorMake(MIMachInjectorErrorCode code, NSString *description, ...) {
    va_list args;
    va_start(args, description);
    description = [[NSString alloc] initWithFormat:description arguments:args];
    va_end(args);
    return [NSError errorWithDomain:MIMachInjectorErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey: description}];
}

// Turn one poll of the target's report block into a verdict.
//
// Kept free of the task port, the polling and the VM read on purpose: those need
// root and cannot be unit-tested, while this — which report means which error —
// is where the interesting decisions are and is exactly what proposal 0002 came
// from. MIMachInjectorErrorCodeTests exercises every branch below.
//
// Success is the answer in every ambiguous case. A payload whose constructor
// outlasts the poll budget, a page that cannot be read, a report still pending:
// all of them keep the behaviour this class had before it reported dlopen
// verdicts at all. Only two answers fail an injection.
NSError *MIMachInjectorErrorForDlopenReport(const MIMachInjectorDlopenReport *report,
                                            BOOL reportWasReadable,
                                            BOOL targetIsAlive,
                                            pid_t processIdentifier,
                                            NSString *dylibPath) {
    if (!reportWasReadable || report == NULL) {
        // A target that is gone did not merely fail to report — it was killed
        // while loading. That is what the code-signing monitor does when a
        // page's hash does not match: the process dies as the page faults in,
        // dlopen never returns, and nothing is ever written here. Reporting
        // success for a process that no longer exists is the worst outcome
        // available, since callers use this verdict to decide whether to fall
        // back to another injection strategy.
        if (targetIsAlive) {
            return nil;
        }
        return MIMachInjectorErrorMake(MIMachInjectorErrorTargetTerminatedWhileLoading,
                                       @"target process %d terminated while loading %@ "
                                       @"(it was killed before dlopen could report; a code signature "
                                       @"whose page hashes do not match does this)",
                                       processIdentifier, dylibPath);
    }

    if (report->resultCode != MIMachInjectorDlopenResultCodeFailed) {
        return nil;
    }

    // The shellcode writes into a fixed-size buffer and is not obliged to
    // terminate it; copy before reading so the caller's report stays const.
    char remoteMessage[sizeof(report->errorMessage)];
    memcpy(remoteMessage, report->errorMessage, sizeof(remoteMessage));
    remoteMessage[sizeof(remoteMessage) - 1] = '\0';

    NSString *description = [NSString stringWithFormat:@"target process refused to load %@: %s",
                             dylibPath, remoteMessage[0] ? remoteMessage : "dlopen returned NULL"];

    NSMutableDictionary<NSErrorUserInfoKey, id> *userInfo =
        [NSMutableDictionary dictionaryWithObject:description forKey:NSLocalizedDescriptionKey];

    // dlopen can return NULL with nothing to say. Leave the key absent rather
    // than present-and-empty, so `userInfo[key] != nil` means "there is a reason
    // to read".
    if (remoteMessage[0]) {
        userInfo[MIMachInjectorRemoteErrorMessageKey] = @(remoteMessage);
    }

    return [NSError errorWithDomain:MIMachInjectorErrorDomain
                               code:MIMachInjectorErrorTargetRefusedToLoadDylib
                           userInfo:userInfo];
}

@implementation MIMachInjector

+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)outError {
    BOOL result = NO;
    NSError *error = nil;

    // Mach resources that need cleanup
    mach_port_t task = MACH_PORT_NULL;
    thread_act_t thread = MACH_PORT_NULL;
    mach_vm_address_t stack = 0;
    mach_vm_address_t code = 0;
    mach_vm_address_t report = 0;
    vm_size_t stack_size = 16 * 1024;
    vm_size_t code_size = 0;
    vm_size_t report_size = sizeof(MIMachInjectorDlopenReport);

    // Local allocations
    char *sandbox_token = NULL;
    unsigned char *local_shellcode = NULL;

    // Thread state variables
#ifdef __x86_64__
    x86_thread_state64_t thread_state = {};
    thread_state_flavor_t thread_flavor = x86_THREAD_STATE64;
    mach_msg_type_number_t thread_flavor_count = x86_THREAD_STATE64_COUNT;
#elif __arm64__
    arm_thread_state64_t thread_state = {}, machine_thread_state = {};
    thread_state_flavor_t thread_flavor = ARM_THREAD_STATE64;
    mach_msg_type_number_t thread_flavor_count = ARM_THREAD_STATE64_COUNT;
    mach_msg_type_number_t machine_thread_flavor_count = ARM_THREAD_STATE64_COUNT;
#endif

    // Validate input
    if (!pid) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorInvalidProcessIdentifier, @"invalid pid");
        goto cleanup;
    }

    // Get task port for target process
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorTaskPortUnavailable, @"could not retrieve task port for pid: %d", pid);
        goto cleanup;
    }

#ifdef __arm64__
    // Issue a sandbox extension token bound to the target process's audit token.
    //
    // Xcode's DVTInstrumentsFoundation.RemoteBundleLoader uses this variant
    // (see -[RemoteBundleLoader scheduleLibraryLoad:...]) so the token is
    // bound to the specific target. A generic token from
    // sandbox_extension_issue_file suffices for App Sandbox targets, but
    // seatbelt-profiled daemons whose profile predicates check the emitting
    // audit token reject it. Fall back to the generic variant if the audit
    // lookup fails (dead target, stripped task port, etc.).
    audit_token_t targetAuditToken = {{0}};
    mach_msg_type_number_t auditTokenCount = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t auditKr = task_info(task, TASK_AUDIT_TOKEN,
                                     (task_info_t)&targetAuditToken, &auditTokenCount);
    if (auditKr == KERN_SUCCESS) {
        sandbox_token = sandbox_extension_issue_file_to_process(
            APP_SANDBOX_READ, dylibPath.UTF8String, 0, targetAuditToken);
    }
    if (!sandbox_token) {
        sandbox_token = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath.UTF8String, 0);
    }
    if (!sandbox_token) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorSandboxExtensionTokenUnavailable, @"could not issue sandbox extension token");
        goto cleanup;
    }
#endif

    // Allocate stack in target process
    if (mach_vm_allocate(task, &stack, stack_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteStackAllocationFailed, @"could not allocate stack segment");
        goto cleanup;
    }

    // Write dummy return address to stack
    uint64_t stack_contents = 0x00000000CAFEBABE;
    if (mach_vm_write(task, stack, (vm_address_t)&stack_contents, sizeof(uint64_t)) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteStackWriteFailed, @"could not write to stack segment");
        goto cleanup;
    }

    // Set stack protection
    if (vm_protect(task, stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteStackProtectionFailed, @"could not set stack protection");
        goto cleanup;
    }

    // Allocate the dlopen report block. Freshly allocated Mach memory is
    // zero-filled and read/write, which is all the pthread needs — the
    // shellcode page itself is mapped read+execute and cannot be written to.
    //
    // A failure here is not fatal: the shellcode treats a zero report address
    // as "nowhere to report", so the injection still proceeds, just blind.
    if (mach_vm_allocate(task, &report, report_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        report = 0;
    }

#ifdef __x86_64__
    // x86_64: Prepare and inject shellcode from external assembly
    const uintptr_t X86_SHELLCODE_SIZE = __x86_shellcode_end - __x86_shellcode_start;
    const uintptr_t X86_PTHREAD_CREATE_OFFSET = __x86_patch_pthread_create - __x86_shellcode_start;
    const uintptr_t X86_DLOPEN_OFFSET = __x86_patch_dlopen - __x86_shellcode_start;
    const uintptr_t X86_DLERROR_OFFSET = __x86_patch_dlerror - __x86_shellcode_start;
    const uintptr_t X86_PAYLOAD_PATH_OFFSET = __x86_data_payload_path - __x86_shellcode_start;
    const uintptr_t X86_REPORT_ADDRESS_OFFSET = __x86_data_report_address - __x86_shellcode_start;

    code_size = X86_SHELLCODE_SIZE;

    if (mach_vm_allocate(task, &code, code_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteCodeAllocationFailed, @"could not allocate code segment");
        goto cleanup;
    }

    // Create local copy for patching
    local_shellcode = malloc(code_size);
    if (!local_shellcode) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorLocalShellcodeBufferAllocationFailed, @"malloc failed");
        goto cleanup;
    }
    memcpy(local_shellcode, __x86_shellcode_start, code_size);

    // Patch function addresses
    // The patch locations are .quad data entries that are loaded via RIP-relative addressing
    uint64_t pcfmt_address = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    uint64_t dlopen_address = (uint64_t)dlsym(RTLD_DEFAULT, "dlopen");
    uint64_t dlerror_address = (uint64_t)dlsym(RTLD_DEFAULT, "dlerror");
    uint64_t report_address = (uint64_t)report;

    memcpy(local_shellcode + X86_PTHREAD_CREATE_OFFSET, &pcfmt_address, sizeof(uint64_t));
    memcpy(local_shellcode + X86_DLOPEN_OFFSET, &dlopen_address, sizeof(uint64_t));
    memcpy(local_shellcode + X86_DLERROR_OFFSET, &dlerror_address, sizeof(uint64_t));
    memcpy(local_shellcode + X86_REPORT_ADDRESS_OFFSET, &report_address, sizeof(uint64_t));

    // Copy dylib path with bounds check
    size_t pathLen = strlen(dylibPath.UTF8String);
    if (pathLen >= X86_MAX_PATH_LENGTH) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorDylibPathTooLong, @"dylib path too long (max %d)", X86_MAX_PATH_LENGTH - 1);
        goto cleanup;
    }
    memcpy(local_shellcode + X86_PAYLOAD_PATH_OFFSET, dylibPath.UTF8String, pathLen + 1);

    // Write shellcode to target process
    if (mach_vm_write(task, code, (vm_address_t)local_shellcode, (mach_msg_type_number_t)code_size) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorShellcodeWriteFailed, @"could not write shellcode to target");
        goto cleanup;
    }

    // Set code segment as executable
    if (vm_protect(task, code, code_size, 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteCodeProtectionFailed, @"could not set code protection");
        goto cleanup;
    }

    // Create and start remote thread
    thread_state.__rip = (uint64_t)code;
    thread_state.__rsp = (uint64_t)stack + (stack_size / 2);

    kern_return_t kr = thread_create_running(task, thread_flavor, (thread_state_t)&thread_state, thread_flavor_count, &thread);
    if (kr != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteThreadCreationFailed, @"could not create remote thread: %s", mach_error_string(kr));
        goto cleanup;
    }

#elif __arm64__
    // ARM64: Prepare and inject shellcode from external assembly
    const uintptr_t SHELLCODE_SIZE = __shellcode_end - __shellcode_start;
    const uintptr_t PTHREAD_CREATE_OFFSET = __patch_pthread_create - __shellcode_start;
    const uintptr_t SANDBOX_CONSUME_OFFSET = __patch_sandbox_consume - __shellcode_start;
    const uintptr_t DLOPEN_OFFSET = __patch_dlopen - __shellcode_start;
    const uintptr_t DLERROR_OFFSET = __patch_dlerror - __shellcode_start;
    const uintptr_t PAYLOAD_PATH_OFFSET = __data_payload_path - __shellcode_start;
    const uintptr_t SANDBOX_TOKEN_OFFSET = __data_sandbox_token - __shellcode_start;
    const uintptr_t REPORT_ADDRESS_OFFSET = __data_report_address - __shellcode_start;

    code_size = SHELLCODE_SIZE;

    if (mach_vm_allocate(task, &code, code_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteCodeAllocationFailed, @"could not allocate code segment");
        goto cleanup;
    }

    // Create local copy for patching
    local_shellcode = malloc(SHELLCODE_SIZE);
    if (!local_shellcode) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorLocalShellcodeBufferAllocationFailed, @"malloc failed");
        goto cleanup;
    }
    memcpy(local_shellcode, __shellcode_start, SHELLCODE_SIZE);

    // Get function addresses (strip PAC signatures)
    uint64_t pcfmt_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread"), ptrauth_key_function_pointer);
    uint64_t dlopen_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "dlopen"), ptrauth_key_function_pointer);
    uint64_t sandbox_consume_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "sandbox_extension_consume"), ptrauth_key_function_pointer);
    uint64_t dlerror_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "dlerror"), ptrauth_key_function_pointer);
    uint64_t report_address = (uint64_t)report;

    // Patch function addresses
    memcpy(local_shellcode + PTHREAD_CREATE_OFFSET, &pcfmt_address, sizeof(uint64_t));
    memcpy(local_shellcode + SANDBOX_CONSUME_OFFSET, &sandbox_consume_address, sizeof(uint64_t));
    memcpy(local_shellcode + DLOPEN_OFFSET, &dlopen_address, sizeof(uint64_t));
    memcpy(local_shellcode + DLERROR_OFFSET, &dlerror_address, sizeof(uint64_t));
    memcpy(local_shellcode + REPORT_ADDRESS_OFFSET, &report_address, sizeof(uint64_t));

    // Copy dylib path with bounds check
    size_t pathLen = strlen(dylibPath.UTF8String);
    if (pathLen >= 0x500) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorDylibPathTooLong, @"dylib path too long");
        goto cleanup;
    }
    memcpy(local_shellcode + PAYLOAD_PATH_OFFSET, dylibPath.UTF8String, pathLen + 1);

    // Copy sandbox token with bounds check
    if (sandbox_token) {
        size_t tokenLen = strlen(sandbox_token);
        if (tokenLen >= 0x500) {
            error = MIMachInjectorErrorMake(MIMachInjectorErrorSandboxExtensionTokenTooLong, @"sandbox token too long");
            goto cleanup;
        }
        memcpy(local_shellcode + SANDBOX_TOKEN_OFFSET, sandbox_token, tokenLen + 1);
    }

    // Write shellcode to target process
    if (mach_vm_write(task, code, (vm_address_t)local_shellcode, (mach_msg_type_number_t)SHELLCODE_SIZE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorShellcodeWriteFailed, @"could not write shellcode to target");
        goto cleanup;
    }

    // Set code segment as executable
    if (vm_protect(task, code, SHELLCODE_SIZE, 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteCodeProtectionFailed, @"could not set code protection");
        goto cleanup;
    }

    // Load thread_convert_thread_state from libsystem_kernel
    void *handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
    if (handle) {
        _thread_convert_thread_state = dlsym(handle, "thread_convert_thread_state");
        dlclose(handle);
    }

    if (!_thread_convert_thread_state) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorThreadStateConverterUnavailable, @"could not load thread_convert_thread_state");
        goto cleanup;
    }

    // Set up thread state with PAC-signed PC
    __darwin_arm_thread_state64_set_pc_fptr(thread_state, ptrauth_sign_unauthenticated((void *)code, ptrauth_key_asia, 0));
    __darwin_arm_thread_state64_set_sp(thread_state, stack + (stack_size / 2));

    kern_return_t kr = thread_create(task, &thread);
    if (kr != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteThreadCreationFailed, @"could not create remote thread: %s", mach_error_string(kr));
        goto cleanup;
    }

    kr = _thread_convert_thread_state(thread, 2, thread_flavor, (thread_state_t)&thread_state, thread_flavor_count, (thread_state_t)&machine_thread_state, &machine_thread_flavor_count);
    if (kr != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(MIMachInjectorErrorThreadStateConversionFailed, @"could not convert thread state: %s", mach_error_string(kr));
        goto cleanup;
    }

    // Handle different macOS versions
    NSOperatingSystemVersion os_version = [[NSProcessInfo processInfo] operatingSystemVersion];
    if ((os_version.majorVersion == 14 && os_version.minorVersion >= 4) ||
        (os_version.majorVersion >= 15)) {
        // macOS 14.4+ and 15+: terminate and recreate thread
        thread_terminate(thread);
        thread = MACH_PORT_NULL;

        kr = thread_create_running(task, thread_flavor, (thread_state_t)&machine_thread_state, machine_thread_flavor_count, &thread);
        if (kr != KERN_SUCCESS) {
            error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteThreadStartFailed, @"could not start remote thread: %s", mach_error_string(kr));
            goto cleanup;
        }
    } else {
        // Earlier versions: set state and resume
        kr = thread_set_state(thread, thread_flavor, (thread_state_t)&machine_thread_state, machine_thread_flavor_count);
        if (kr != KERN_SUCCESS) {
            error = MIMachInjectorErrorMake(MIMachInjectorErrorThreadStateAssignmentFailed, @"could not set thread state: %s", mach_error_string(kr));
            goto cleanup;
        }

        kr = thread_resume(thread);
        if (kr != KERN_SUCCESS) {
            error = MIMachInjectorErrorMake(MIMachInjectorErrorRemoteThreadResumeFailed, @"could not resume remote thread: %s", mach_error_string(kr));
            goto cleanup;
        }
    }
#endif

    // Wait for the mach thread to report that it spawned the pthread
    usleep(10000);

    BOOL didCreatePthread = NO;

    for (int i = 0; i < 10; ++i) {
        // Reset count before each call (in/out parameter)
        mach_msg_type_number_t state_count = thread_flavor_count;
        kern_return_t kr = thread_get_state(thread, thread_flavor, (thread_state_t)&thread_state, &state_count);

        if (kr != KERN_SUCCESS) {
            error = MIMachInjectorErrorMake(MIMachInjectorErrorThreadStateReadFailed, @"could not get thread state: %s", mach_error_string(kr));
            goto cleanup;
        }

#ifdef __x86_64__
        if (thread_state.__rax == MI_INJECTION_DONE) {
#elif __arm64__
        if (thread_state.__x[0] == MI_INJECTION_DONE) {
#endif
            didCreatePthread = YES;
            break;
        }

        usleep(20000);
    }

    if (!didCreatePthread) {
        // Timeout
        error = MIMachInjectorErrorMake(MIMachInjectorErrorTimedOut, @"injection timed out");
        goto cleanup;
    }

    // The pthread exists, but the dylib may still have been refused. Poll the
    // report block for dlopen's verdict; only an explicit failure downgrades
    // the result, so a payload slower than the poll budget keeps reporting
    // success the way it always did.
    result = YES;

    if (report != 0) {
        for (int i = 0; i < MI_DLOPEN_REPORT_POLL_ATTEMPTS; ++i) {
            MIMachInjectorDlopenReport dlopenReport = {0};
            mach_vm_size_t bytesRead = 0;
            kern_return_t kr = mach_vm_read_overwrite(task, report, sizeof(dlopenReport),
                                                     (mach_vm_address_t)&dlopenReport, &bytesRead);
            BOOL reportWasReadable = (kr == KERN_SUCCESS && bytesRead == sizeof(dlopenReport));

            // Keep polling only while the target has genuinely not answered yet.
            // Every other state is terminal, and which of them it is belongs to
            // the verdict function, not to this loop.
            if (reportWasReadable && dlopenReport.resultCode == MIMachInjectorDlopenResultCodePending) {
                usleep(MI_DLOPEN_REPORT_POLL_INTERVAL_MICROSECONDS);
                continue;
            }

            // Liveness costs a round trip to the kernel, so only ask when the
            // answer can change the verdict — an unreadable report.
            BOOL targetIsAlive = reportWasReadable ? YES : MIMachInjectorTargetIsAlive(task, pid);

            error = MIMachInjectorErrorForDlopenReport(reportWasReadable ? &dlopenReport : NULL,
                                                      reportWasReadable, targetIsAlive, pid, dylibPath);
            if (error != nil) {
                result = NO;
            }
            break;
        }
    }

cleanup:
    // Terminate remote thread
    if (thread != MACH_PORT_NULL) {
        thread_terminate(thread);
    }

    // Note: We intentionally do NOT deallocate the stack, code, or report
    // segments in the target process, as they may still be in use by the
    // injected thread or the loaded dylib — the pthread can still be inside
    // dlopen, and writes its verdict into the report block when it returns.
    // This is expected behavior for injection.

    // Release task port
    if (task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), task);
    }

    // Free local allocations
    if (local_shellcode) {
        free(local_shellcode);
    }
    if (sandbox_token) {
        free(sandbox_token);
    }

    // Set output error if provided
    if (outError && error) {
        *outError = error;
    }

    return result;
}

@end
