/*
 * MIT License
 *
 * Copyright (c) 2024
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * =============================================================================
 * MIMachInjectorAsync Implementation V2
 * =============================================================================
 *
 * This is the V2 implementation where pthread terminates the mach thread.
 *
 * =============================================================================
 * DESIGN CHALLENGES AND SOLUTIONS
 * =============================================================================
 *
 * PROBLEM 1: Raw mach threads cannot call `ret` to exit
 * -----------------------------------------------------
 * When a thread is created via thread_create_running(), the link register (x30)
 * is initialized to 0. If the mach thread tries to return normally with `ret`,
 * it jumps to address 0x0, causing an immediate crash:
 *   - Exception: EXC_BAD_ACCESS (code=1, address=0x0)
 *   - pc: 0x0000000000000000
 *
 * PROBLEM 2: Raw mach threads cannot use mach_msg()
 * -------------------------------------------------
 * We initially tried to have the mach thread wait for a completion message
 * using mach_msg(). However, mach_msg() uses MIG (Mach Interface Generator)
 * internally, which calls mig_get_reply_port() to obtain a reply port.
 *
 * mig_get_reply_port() accesses Thread-Local Storage (TLS) via the TPIDRRO_EL0
 * register on ARM64. In raw mach threads created by thread_create_running(),
 * TPIDRRO_EL0 is 0 (no TLS is set up). This causes a crash when trying to
 * access [0 + 0x10]:
 *   - Exception: EXC_BAD_ACCESS (code=1, address=0x10)
 *   - Crash in: mig_get_reply_port -> _pthread_getspecific_direct
 *
 * PROBLEM 3: Raw mach threads cannot call thread_terminate()
 * ----------------------------------------------------------
 * We then tried to have the mach thread terminate itself by calling
 * thread_terminate(mach_thread_self()). However, thread_terminate() ALSO uses
 * MIG internally, causing the same TLS-related crash at address 0x10.
 *
 * This was discovered after implementing and testing - the crash occurred at:
 *   thread_terminate + 36 -> mig_get_reply_port
 *
 * SOLUTION: pthread terminates the mach thread
 * --------------------------------------------
 * Since pthread has full runtime support including TLS, it can safely call
 * thread_terminate(). The solution is:
 *
 *   1. Mach thread saves its own port to notepad (mach_thread_self() is a
 *      direct Mach trap that doesn't require TLS)
 *   2. Mach thread creates a pthread
 *   3. Mach thread enters an infinite loop (using yield instruction)
 *   4. pthread performs dlopen() and writes results to notepad
 *   5. pthread reads mach_thread_port from notepad
 *   6. pthread calls thread_terminate(mach_thread_port)
 *   7. This triggers MACH_SEND_DEAD in the injector
 *
 * PROBLEM 4: Cannot monitor pthread exit from injector
 * ----------------------------------------------------
 * We initially designed a two-phase cleanup:
 *   Phase 1: When mach thread dies, cleanup stack/notepad, monitor pthread
 *   Phase 2: When pthread dies, cleanup code, call completion handler
 *
 * However, pthread_port saved in notepad is a port NAME in the TARGET
 * process's Mach port namespace. This port name is meaningless in the
 * injector process - it either doesn't exist or refers to a completely
 * different port. We cannot create a dispatch_source to monitor it.
 *
 * FINAL SOLUTION: Single-phase completion
 * ---------------------------------------
 * When MACH_SEND_DEAD triggers (mach thread terminated by pthread):
 *   1. Read notepad to get dlopen() results
 *   2. Cleanup: stack, notepad (safe because pthread has finished writing)
 *   3. Call completion handler immediately
 *   4. Code segment is NOT deallocated (pthread may still be in its return
 *      sequence). This is an acceptable ~2.6KB memory overhead per injection.
 *
 * =============================================================================
 * ARCHITECTURE SUMMARY
 * =============================================================================
 *
 * Mach Thread (no TLS):
 *   1. mach_thread_self() -> save to notepad  [safe: direct Mach trap]
 *   2. pthread_create_from_mach_thread()      [safe: doesn't require TLS]
 *   3. yield loop forever                     [wait to be terminated]
 *
 * pthread (full TLS support):
 *   1. dlopen() -> save result to notepad
 *   2. mach_thread_self() -> save pthread_port to notepad (for debugging)
 *   3. Read mach_thread_port from notepad
 *   4. thread_terminate(mach_thread_port)     [safe: pthread has TLS]
 *   5. retab (return)
 *
 * Injector:
 *   1. Create dispatch_source monitoring mach thread port
 *   2. When MACH_SEND_DEAD triggers:
 *      - Read notepad for results
 *      - Cleanup stack, notepad
 *      - Call completion handler
 *
 * =============================================================================
 * KEY LEARNINGS
 * =============================================================================
 *
 * 1. Raw mach threads have NO TLS - TPIDRRO_EL0 = 0
 * 2. Many Mach functions use MIG internally, which requires TLS
 * 3. Safe functions in raw mach threads:
 *    - mach_thread_self() - direct Mach trap
 *    - pthread_create_from_mach_thread() - designed for this use case
 *    - Basic memory operations (load/store)
 * 4. Unsafe functions in raw mach threads:
 *    - mach_msg() - uses MIG
 *    - thread_terminate() - uses MIG
 *    - Most other Mach IPC functions
 * 5. Port names are process-local - a port name from one process cannot
 *    be used directly in another process without explicit port transfer
 *
 */

#import "include/MIMachInjectorAsync.h"

#ifdef __arm64__

// =============================================================================
// MARK: - System Headers
// =============================================================================

#import <Cocoa/Cocoa.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <dlfcn.h>
#import <ptrauth.h>
#import <dispatch/dispatch.h>
#import <sys/sysctl.h>

// =============================================================================
// MARK: - Rosetta Detection
// =============================================================================

// P_TRANSLATED flag indicates process is running under Rosetta
#ifndef P_TRANSLATED
#define P_TRANSLATED 0x00020000
#endif

/// Check if a process is running under Rosetta translation
/// @param pid The process ID to check
/// @return YES if the process is translated (x86_64 running on ARM64)
static BOOL isProcessTranslated(pid_t pid) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info = {0};
    size_t size = sizeof(info);

    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0 && size > 0) {
        return (info.kp_proc.p_flag & P_TRANSLATED) != 0;
    }
    return NO;
}

/// Function pointer type for oah_thread_create_running
typedef kern_return_t (*oah_thread_create_running_t)(
    task_t task,
    thread_state_flavor_t flavor,
    thread_state_t new_state,
    mach_msg_type_number_t new_stateCnt,
    thread_act_t *new_thread
);

/// Get the oah_thread_create_running function pointer
/// @return Function pointer or NULL if not available
static oah_thread_create_running_t get_oah_thread_create_running(void) {
    static oah_thread_create_running_t fn = NULL;
    static dispatch_once_t once;

    dispatch_once(&once, ^{
        void *handle = dlopen("/usr/lib/liboah.dylib", RTLD_LAZY);
        if (handle) {
            fn = dlsym(handle, "oah_thread_create_running");
            // Don't dlclose - keep handle valid
        }
    });

    return fn;
}

// =============================================================================
// MARK: - Sandbox Extension Functions
// =============================================================================

extern const char *const APP_SANDBOX_READ;
extern char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);

// =============================================================================
// MARK: - External Shellcode Symbols (V2)
// =============================================================================

extern char __async_shellcode_start[];
extern char __async_shellcode_end[];
extern char __async_patch_pthread_create[];
extern char __async_patch_sandbox_consume[];
extern char __async_patch_dlopen[];
extern char __async_patch_dlerror[];
extern char __async_patch_mach_thread_self[];
extern char __async_patch_thread_terminate[];
extern char __async_data_notepad[];
extern char __async_data_payload_path[];
extern char __async_data_sandbox_token[];

// =============================================================================
// MARK: - Thread State Conversion Function
// =============================================================================

static kern_return_t (*_thread_convert_thread_state)(
    thread_act_t thread,
    int direction,
    thread_state_flavor_t flavor,
    thread_state_t in_state,
    mach_msg_type_number_t in_stateCnt,
    thread_state_t out_state,
    mach_msg_type_number_t *out_stateCnt
);

// =============================================================================
// MARK: - Notepad Structure (V2)
// =============================================================================

/*
 * MINotepad V2 Memory Layout:
 * +--------+------+------------------+----------------------------------------+
 * | Offset | Size | Field            | Description                            |
 * +--------+------+------------------+----------------------------------------+
 * | 0x00   | 4    | pthread_port     | pthread's mach port for phase 2        |
 * | 0x04   | 4    | mach_thread_port | mach thread's port (pthread terminates)|
 * | 0x08   | 4    | result_code      | 0=success, 1=dlopen, 2=pthread         |
 * | 0x0C   | 4    | (reserved)       | padding for alignment                  |
 * | 0x10   | 8    | handle           | dlopen() return value                  |
 * | 0x18   | 256  | error_message    | dlerror() string                       |
 * +--------+------+------------------+----------------------------------------+
 * | Total  | 280  |                  |                                        |
 * +--------+------+------------------+----------------------------------------+
 */
typedef struct {
    uint32_t pthread_port;         // +0x00: pthread's mach port (for phase 2)
    uint32_t mach_thread_port;     // +0x04: mach thread's port (pthread terminates it)
    int32_t result_code;           // +0x08: Result code
    int32_t reserved;              // +0x0C: Reserved/padding
    uint64_t handle;               // +0x10: dlopen() return value
    char error_message[256];       // +0x18: Error message from dlerror()
} MINotepad;

// =============================================================================
// MARK: - Injection Context Structure (V2)
// =============================================================================

typedef struct {
    // Mach task and thread ports
    mach_port_t task;
    thread_act_t thread;

    // Memory regions in target process
    mach_vm_address_t code;
    mach_vm_address_t stack;
    mach_vm_address_t notepad;

    // Memory sizes
    mach_vm_size_t code_size;
    mach_vm_size_t stack_size;

    // Dispatch sources
    dispatch_source_t mach_thread_source;   // Monitors mach thread for MACH_SEND_DEAD
    dispatch_source_t timer_source;         // Timeout timer

    // Completion handling
    MIInjectionCompletionHandler completionHandler;
    BOOL completed;

    // Result data (captured during phase 1)
    uint64_t resultHandle;
    int32_t resultCode;
    char resultErrorMessage[256];
} MIInjectionContext;

// =============================================================================
// MARK: - Error Domain
// =============================================================================

NSErrorDomain const MIMachInjectorAsyncErrorDomain = @"MIMachInjectorAsyncErrorDomain";

// =============================================================================
// MARK: - MIInjectionResult Implementation
// =============================================================================

@implementation MIInjectionResult {
    BOOL _success;
    uint64_t _handle;
    NSError *_error;
    NSString *_remoteErrorMessage;
}

- (instancetype)initWithSuccess:(BOOL)success
                         handle:(uint64_t)handle
                          error:(NSError *)error
             remoteErrorMessage:(NSString *)remoteErrorMessage {
    self = [super init];
    if (self) {
        _success = success;
        _handle = handle;
        _error = error;
        _remoteErrorMessage = remoteErrorMessage;
    }
    return self;
}

- (BOOL)success { return _success; }
- (uint64_t)handle { return _handle; }
- (NSError *)error { return _error; }
- (NSString *)remoteErrorMessage { return _remoteErrorMessage; }

@end

// =============================================================================
// MARK: - Helper Functions
// =============================================================================

#pragma mark - Error Creation

static NSError *MakeError(NSInteger code, NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *description = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    return [NSError errorWithDomain:MIMachInjectorAsyncErrorDomain
                               code:code
                           userInfo:@{NSLocalizedDescriptionKey: description}];
}

#pragma mark - Completion Invocation

/// Phase 2 completion - final cleanup and callback
static void InvokeCompletion(MIInjectionContext *ctx) {
    // Guard against double invocation (can happen if timeout fires after MACH_SEND_DEAD)
    if (ctx->completed) return;
    ctx->completed = YES;

    // Capture data before cleanup
    MIInjectionCompletionHandler handler = ctx->completionHandler;
    uint64_t handle = ctx->resultHandle;
    int32_t resultCode = ctx->resultCode;

    NSString *remoteError = nil;
    if (ctx->resultErrorMessage[0] != '\0') {
        remoteError = [NSString stringWithUTF8String:ctx->resultErrorMessage];
    }

    // Phase 2 cleanup: deallocate code segment
    if (ctx->task != MACH_PORT_NULL && ctx->code != 0) {
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        ctx->code = 0;
    }

    // Release task port
    if (ctx->task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), ctx->task);
        ctx->task = MACH_PORT_NULL;
    }

    // Cancel dispatch sources
    if (ctx->mach_thread_source) {
        dispatch_source_cancel(ctx->mach_thread_source);
        ctx->mach_thread_source = nil;
    }
    if (ctx->timer_source) {
        dispatch_source_cancel(ctx->timer_source);
        ctx->timer_source = nil;
    }

    // Determine success
    BOOL success = (resultCode == 0 && handle != 0);

    NSError *error = nil;
    if (!success) {
        switch (resultCode) {
            case 2:
                error = MakeError(17, @"Failed to create pthread in target process");
                break;
            case 3:
                error = MakeError(21, @"Failed to allocate mach port in target process");
                break;
            default:
                error = MakeError(18, @"dlopen failed: %@", remoteError ?: @"unknown error");
                break;
        }
    }

    // Create result
    MIInjectionResult *result = [[MIInjectionResult alloc]
        initWithSuccess:success
                 handle:handle
                  error:error
     remoteErrorMessage:remoteError];

    // Free context
    free(ctx);

    // Invoke handler on main thread (required for Swift async/await compatibility)
    dispatch_async(dispatch_get_main_queue(), ^{
        if (handler) {
            handler(result, result.error);
        }
    });
}

/// Phase 1 completion - called when mach thread is terminated (MACH_SEND_DEAD triggers)
/// At this point, pthread has completed dlopen() and terminated the mach thread.
/// We read the results from notepad and invoke the completion handler.
static void Phase1Completion(MIInjectionContext *ctx) {
    // Guard against double invocation
    if (ctx->completed) return;

    // Read notepad to get results and pthread_port
    vm_offset_t data = 0;
    mach_msg_type_number_t dataCnt = 0;
    MINotepad notepadResult = {0};

    kern_return_t kr = mach_vm_read(
        ctx->task,
        ctx->notepad,
        sizeof(MINotepad),
        &data,
        &dataCnt
    );

    if (kr == KERN_SUCCESS && dataCnt >= sizeof(MINotepad)) {
        memcpy(&notepadResult, (void *)data, sizeof(MINotepad));
        vm_deallocate(mach_task_self(), data, dataCnt);
    }
    // Note: If notepad read fails, we proceed with zeroed notepadResult
    // This will result in a failed injection (handle=0)

    // Save results to context
    ctx->resultHandle = notepadResult.handle;
    ctx->resultCode = notepadResult.result_code;
    if (notepadResult.error_message[0] != '\0') {
        notepadResult.error_message[255] = '\0';
        strlcpy(ctx->resultErrorMessage, notepadResult.error_message, sizeof(ctx->resultErrorMessage));
    }

    // Phase 1 cleanup: deallocate stack and notepad
    if (ctx->stack != 0) {
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        ctx->stack = 0;
    }
    if (ctx->notepad != 0) {
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        ctx->notepad = 0;
    }

    // Cancel mach thread source
    if (ctx->mach_thread_source) {
        dispatch_source_cancel(ctx->mach_thread_source);
        ctx->mach_thread_source = nil;
    }

    /*
     * IMPORTANT: Why we don't monitor pthread exit
     * --------------------------------------------
     * pthread_port saved in notepad is a port NAME in the TARGET process's Mach
     * port namespace. Port names are process-local identifiers - they have no
     * meaning in other processes. We CANNOT create a dispatch_source in the
     * injector to monitor this port.
     *
     * To properly monitor pthread exit, we would need to:
     * 1. Allocate a port in the injector
     * 2. Transfer a send right to the target process via mach_msg
     * 3. Have pthread send a message before exiting
     *
     * But step 2 requires MIG, which requires TLS, which the mach thread doesn't
     * have. So we complete immediately after mach thread exits.
     *
     * The code segment (~2.6 KB) is intentionally NOT deallocated because pthread
     * may still be executing its return sequence (ldp, add sp, retab). This is
     * an acceptable memory overhead per injection.
     */

    // Complete injection immediately
    InvokeCompletion(ctx);
}

// =============================================================================
// MARK: - MIMachInjectorAsync Implementation
// =============================================================================

@implementation MIMachInjectorAsync

+ (void)injectWithPID:(pid_t)pid
            dylibPath:(NSString *)dylibPath
              timeout:(NSTimeInterval)timeout
    completionHandler:(MIInjectionCompletionHandler)completionHandler {

    // =========================================================================
    // Step 1: Allocate and initialize injection context
    // =========================================================================

    MIInjectionContext *ctx = calloc(1, sizeof(MIInjectionContext));
    if (!ctx) {
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(1, @"Failed to allocate injection context")
         remoteErrorMessage:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    ctx->completionHandler = completionHandler;
    ctx->stack_size = 16 * 1024;

    // =========================================================================
    // Step 2: Validate input parameters
    // =========================================================================

    if (pid <= 0) {
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(2, @"Invalid PID: %d", pid)
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 3: Check for Rosetta translation
    // =========================================================================

    BOOL isTranslated = isProcessTranslated(pid);

    // =========================================================================
    // Step 4: Issue sandbox extension token
    // =========================================================================

    char *sandbox_token = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath.UTF8String, 0);

    // =========================================================================
    // Step 5: Get task port for target process
    // =========================================================================

    kern_return_t kr = task_for_pid(mach_task_self(), pid, &ctx->task);
    if (kr != KERN_SUCCESS) {
        if (sandbox_token) free(sandbox_token);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(3, @"Failed to get task port for pid %d: %s", pid, mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 6: Calculate shellcode layout (V2)
    // =========================================================================

    const size_t SHELLCODE_SIZE = __async_shellcode_end - __async_shellcode_start;
    const size_t PTHREAD_CREATE_OFFSET = __async_patch_pthread_create - __async_shellcode_start;
    const size_t SANDBOX_CONSUME_OFFSET = __async_patch_sandbox_consume - __async_shellcode_start;
    const size_t DLOPEN_OFFSET = __async_patch_dlopen - __async_shellcode_start;
    const size_t DLERROR_OFFSET = __async_patch_dlerror - __async_shellcode_start;
    const size_t MACH_THREAD_SELF_OFFSET = __async_patch_mach_thread_self - __async_shellcode_start;
    const size_t THREAD_TERMINATE_OFFSET = __async_patch_thread_terminate - __async_shellcode_start;
    const size_t NOTEPAD_ADDR_OFFSET = __async_data_notepad - __async_shellcode_start;
    const size_t PAYLOAD_PATH_OFFSET = __async_data_payload_path - __async_shellcode_start;
    const size_t SANDBOX_TOKEN_OFFSET = __async_data_sandbox_token - __async_shellcode_start;

    ctx->code_size = SHELLCODE_SIZE;

    // =========================================================================
    // Step 7: Allocate notepad in target process
    // =========================================================================

    kr = mach_vm_allocate(ctx->task, &ctx->notepad, sizeof(MINotepad), VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        if (sandbox_token) free(sandbox_token);
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(4, @"Failed to allocate notepad: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // Initialize notepad to zeros
    MINotepad initialNotepad = {0};
    kr = mach_vm_write(ctx->task, ctx->notepad, (vm_offset_t)&initialNotepad, sizeof(MINotepad));
    if (kr != KERN_SUCCESS) {
        if (sandbox_token) free(sandbox_token);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(5, @"Failed to initialize notepad: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 8: Allocate stack in target process
    // =========================================================================

    kr = mach_vm_allocate(ctx->task, &ctx->stack, ctx->stack_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        if (sandbox_token) free(sandbox_token);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(6, @"Failed to allocate stack: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    kr = vm_protect(ctx->task, (vm_address_t)ctx->stack, ctx->stack_size, TRUE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        if (sandbox_token) free(sandbox_token);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(7, @"Failed to set stack protection: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 9: Allocate code segment in target process
    // =========================================================================

    kr = mach_vm_allocate(ctx->task, &ctx->code, ctx->code_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        if (sandbox_token) free(sandbox_token);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(8, @"Failed to allocate code segment: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 10: Prepare shellcode with patched addresses (V2)
    // =========================================================================

    unsigned char *local_shellcode = malloc(SHELLCODE_SIZE);
    if (!local_shellcode) {
        if (sandbox_token) free(sandbox_token);
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(9, @"Failed to allocate local shellcode buffer")
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // Copy shellcode template
    memcpy(local_shellcode, __async_shellcode_start, SHELLCODE_SIZE);

    // Get function addresses and strip PAC signatures
    uint64_t pthread_create_addr = (uint64_t)ptrauth_strip(
        dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread"),
        ptrauth_key_function_pointer
    );
    uint64_t sandbox_consume_addr = (uint64_t)ptrauth_strip(
        dlsym(RTLD_DEFAULT, "sandbox_extension_consume"),
        ptrauth_key_function_pointer
    );
    uint64_t dlopen_addr = (uint64_t)ptrauth_strip(
        dlsym(RTLD_DEFAULT, "dlopen"),
        ptrauth_key_function_pointer
    );
    uint64_t dlerror_addr = (uint64_t)ptrauth_strip(
        dlsym(RTLD_DEFAULT, "dlerror"),
        ptrauth_key_function_pointer
    );
    uint64_t mach_thread_self_addr = (uint64_t)ptrauth_strip(
        dlsym(RTLD_DEFAULT, "mach_thread_self"),
        ptrauth_key_function_pointer
    );
    uint64_t thread_terminate_addr = (uint64_t)ptrauth_strip(
        dlsym(RTLD_DEFAULT, "thread_terminate"),
        ptrauth_key_function_pointer
    );

    // Patch all function addresses
    memcpy(local_shellcode + PTHREAD_CREATE_OFFSET, &pthread_create_addr, sizeof(uint64_t));
    memcpy(local_shellcode + SANDBOX_CONSUME_OFFSET, &sandbox_consume_addr, sizeof(uint64_t));
    memcpy(local_shellcode + DLOPEN_OFFSET, &dlopen_addr, sizeof(uint64_t));
    memcpy(local_shellcode + DLERROR_OFFSET, &dlerror_addr, sizeof(uint64_t));
    memcpy(local_shellcode + MACH_THREAD_SELF_OFFSET, &mach_thread_self_addr, sizeof(uint64_t));
    memcpy(local_shellcode + THREAD_TERMINATE_OFFSET, &thread_terminate_addr, sizeof(uint64_t));

    // Patch notepad address
    uint64_t notepad_addr = ctx->notepad;
    memcpy(local_shellcode + NOTEPAD_ADDR_OFFSET, &notepad_addr, sizeof(uint64_t));

    // Copy dylib path
    size_t pathLen = strlen(dylibPath.UTF8String);
    if (pathLen >= 0x500) {
        free(local_shellcode);
        if (sandbox_token) free(sandbox_token);
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(10, @"Dylib path too long (%zu bytes, max 1279)", pathLen)
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }
    memcpy(local_shellcode + PAYLOAD_PATH_OFFSET, dylibPath.UTF8String, pathLen + 1);

    // Copy sandbox token if available
    if (sandbox_token) {
        size_t tokenLen = strlen(sandbox_token);
        if (tokenLen < 0x500) {
            memcpy(local_shellcode + SANDBOX_TOKEN_OFFSET, sandbox_token, tokenLen + 1);
        }
        free(sandbox_token);
        sandbox_token = NULL;
    }

    // =========================================================================
    // Step 11: Write shellcode to target process
    // =========================================================================

    kr = mach_vm_write(ctx->task, ctx->code, (vm_offset_t)local_shellcode, (mach_msg_type_number_t)SHELLCODE_SIZE);
    free(local_shellcode);

    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(11, @"Failed to write shellcode: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 12: Set code segment as executable
    // =========================================================================

    kr = vm_protect(ctx->task, (vm_address_t)ctx->code, ctx->code_size, FALSE, VM_PROT_EXECUTE | VM_PROT_READ);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(12, @"Failed to set code protection: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 13: Load thread_convert_thread_state function
    // =========================================================================

    void *kernel_handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
    if (kernel_handle) {
        _thread_convert_thread_state = dlsym(kernel_handle, "thread_convert_thread_state");
        dlclose(kernel_handle);
    }

    if (!_thread_convert_thread_state) {
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(13, @"Failed to load thread_convert_thread_state")
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 14: Set up thread state
    // =========================================================================

    arm_thread_state64_t thread_state = {};
    arm_thread_state64_t machine_thread_state = {};
    thread_state_flavor_t thread_flavor = ARM_THREAD_STATE64;
    mach_msg_type_number_t thread_flavor_count = ARM_THREAD_STATE64_COUNT;
    mach_msg_type_number_t machine_thread_flavor_count = ARM_THREAD_STATE64_COUNT;

    __darwin_arm_thread_state64_set_pc_fptr(
        thread_state,
        ptrauth_sign_unauthenticated((void *)ctx->code, ptrauth_key_asia, 0)
    );
    __darwin_arm_thread_state64_set_sp(thread_state, ctx->stack + (ctx->stack_size / 2));

    // =========================================================================
    // Step 15: Create remote thread
    // =========================================================================

    kr = thread_create(ctx->task, &ctx->thread);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(14, @"Failed to create thread: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 16: Convert thread state
    // =========================================================================

    kr = _thread_convert_thread_state(
        ctx->thread,
        2,
        thread_flavor,
        (thread_state_t)&thread_state,
        thread_flavor_count,
        (thread_state_t)&machine_thread_state,
        &machine_thread_flavor_count
    );

    if (kr != KERN_SUCCESS) {
        thread_terminate(ctx->thread);
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(15, @"Failed to convert thread state: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 17: Start remote thread (with Rosetta support)
    // =========================================================================

    NSOperatingSystemVersion os_version = [[NSProcessInfo processInfo] operatingSystemVersion];

    if (isTranslated) {
        // Target is running under Rosetta - use oah_thread_create_running
        oah_thread_create_running_t oah_fn = get_oah_thread_create_running();
        if (oah_fn) {
            thread_terminate(ctx->thread);
            ctx->thread = MACH_PORT_NULL;

            kr = oah_fn(
                ctx->task,
                thread_flavor,
                (thread_state_t)&machine_thread_state,
                machine_thread_flavor_count,
                &ctx->thread
            );
        } else {
            // Fallback to normal approach
            thread_terminate(ctx->thread);
            ctx->thread = MACH_PORT_NULL;
            kr = thread_create_running(
                ctx->task,
                thread_flavor,
                (thread_state_t)&machine_thread_state,
                machine_thread_flavor_count,
                &ctx->thread
            );
        }
    } else if ((os_version.majorVersion == 14 && os_version.minorVersion >= 4) ||
               (os_version.majorVersion >= 15)) {
        // macOS 14.4+ and 15+: use thread_create_running
        thread_terminate(ctx->thread);
        ctx->thread = MACH_PORT_NULL;

        kr = thread_create_running(
            ctx->task,
            thread_flavor,
            (thread_state_t)&machine_thread_state,
            machine_thread_flavor_count,
            &ctx->thread
        );
    } else {
        // Earlier versions: set state and resume
        kr = thread_set_state(
            ctx->thread,
            thread_flavor,
            (thread_state_t)&machine_thread_state,
            machine_thread_flavor_count
        );

        if (kr == KERN_SUCCESS) {
            kr = thread_resume(ctx->thread);
        }
    }

    if (kr != KERN_SUCCESS) {
        if (ctx->thread != MACH_PORT_NULL) {
            thread_terminate(ctx->thread);
        }
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(16, @"Failed to start thread: %s", mach_error_string(kr))
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    // =========================================================================
    // Step 18: Set up MACH_SEND_DEAD monitoring for mach thread
    // =========================================================================

    dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);

    ctx->mach_thread_source = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_MACH_SEND,
        ctx->thread,
        DISPATCH_MACH_SEND_DEAD,
        queue
    );

    if (!ctx->mach_thread_source) {
        thread_terminate(ctx->thread);
        mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
        mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
        mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
        mach_port_deallocate(mach_task_self(), ctx->task);
        MIInjectionResult *result = [[MIInjectionResult alloc]
            initWithSuccess:NO
                     handle:0
                      error:MakeError(22, @"Failed to create dispatch source")
         remoteErrorMessage:nil];
        free(ctx);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completionHandler) completionHandler(result, result.error);
        });
        return;
    }

    /*
     * MACH_SEND_DEAD Event Handler
     * ----------------------------
     * This is triggered when the mach thread's port becomes a dead name.
     * This happens when pthread calls thread_terminate(mach_thread_port).
     *
     * At this point:
     * - pthread has completed dlopen() and written results to notepad
     * - pthread has terminated the mach thread
     * - We can safely read notepad and complete the injection
     */
    dispatch_source_set_event_handler(ctx->mach_thread_source, ^{
        Phase1Completion(ctx);
    });

    dispatch_source_set_cancel_handler(ctx->mach_thread_source, ^{
        // Nothing to do - cleanup handled elsewhere
    });

    dispatch_resume(ctx->mach_thread_source);

    // =========================================================================
    // Step 19: Set up timeout timer (if specified)
    // =========================================================================

    if (timeout > 0) {
        ctx->timer_source = dispatch_source_create(
            DISPATCH_SOURCE_TYPE_TIMER,
            0,
            0,
            queue
        );

        if (ctx->timer_source) {
            dispatch_source_set_timer(
                ctx->timer_source,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout * NSEC_PER_SEC)),
                DISPATCH_TIME_FOREVER,  // One-shot
                1 * NSEC_PER_SEC        // 1 second leeway
            );

            /*
             * Timeout Handler
             * ---------------
             * This is a fallback in case MACH_SEND_DEAD doesn't trigger.
             * Possible reasons:
             * - pthread failed to create
             * - pthread crashed before terminating mach thread
             * - Target process was killed
             *
             * We attempt to read notepad to salvage any results.
             */
            dispatch_source_set_event_handler(ctx->timer_source, ^{
                if (ctx->completed) return;

                // Try to read notepad for any partial results
                vm_offset_t data = 0;
                mach_msg_type_number_t dataCnt = 0;
                MINotepad notepadResult = {0};
                NSString *debugInfo = nil;

                kern_return_t readKr = mach_vm_read(
                    ctx->task,
                    ctx->notepad,
                    sizeof(MINotepad),
                    &data,
                    &dataCnt
                );

                if (readKr == KERN_SUCCESS && dataCnt >= sizeof(MINotepad)) {
                    memcpy(&notepadResult, (void *)data, sizeof(MINotepad));
                    vm_deallocate(mach_task_self(), data, dataCnt);

                    // Build debug info for error message
                    debugInfo = [NSString stringWithFormat:
                        @"Notepad: pthread_port=0x%x, mach_thread_port=0x%x, result=%d, handle=0x%llx",
                        notepadResult.pthread_port,
                        notepadResult.mach_thread_port,
                        notepadResult.result_code,
                        notepadResult.handle];

                    // Check if pthread actually completed successfully
                    if (notepadResult.handle != 0 || notepadResult.pthread_port != 0) {
                        ctx->resultCode = notepadResult.result_code;
                        ctx->resultHandle = notepadResult.handle;
                        if (notepadResult.error_message[0] != '\0') {
                            notepadResult.error_message[255] = '\0';
                            strlcpy(ctx->resultErrorMessage, notepadResult.error_message, sizeof(ctx->resultErrorMessage));
                        }
                    } else {
                        ctx->resultCode = -1;
                        ctx->resultHandle = 0;
                        strlcpy(ctx->resultErrorMessage, "Injection timed out", sizeof(ctx->resultErrorMessage));
                    }
                } else {
                    ctx->resultCode = -1;
                    ctx->resultHandle = 0;
                    strlcpy(ctx->resultErrorMessage, "Injection timed out (notepad read failed)", sizeof(ctx->resultErrorMessage));
                }

                // Terminate thread and cleanup
                if (ctx->thread != MACH_PORT_NULL) {
                    thread_terminate(ctx->thread);
                    ctx->thread = MACH_PORT_NULL;
                }

                // Determine success based on notepad data
                BOOL success = (notepadResult.result_code == 0 && notepadResult.handle != 0);
                NSError *error = nil;

                if (!success) {
                    NSString *errorDesc = debugInfo ?
                        [NSString stringWithFormat:@"MACH_SEND_DEAD not triggered. %@", debugInfo] :
                        @"Injection timed out";
                    error = MakeError(19, @"%@", errorDesc);
                }

                MIInjectionResult *result = [[MIInjectionResult alloc]
                    initWithSuccess:success
                             handle:notepadResult.handle
                              error:error
                 remoteErrorMessage:ctx->resultErrorMessage[0] ? [NSString stringWithUTF8String:ctx->resultErrorMessage] : nil];

                ctx->completed = YES;

                // Cleanup
                if (ctx->mach_thread_source) {
                    dispatch_source_cancel(ctx->mach_thread_source);
                    ctx->mach_thread_source = nil;
                }
                if (ctx->timer_source) {
                    dispatch_source_cancel(ctx->timer_source);
                    ctx->timer_source = nil;
                }
                if (ctx->stack != 0) {
                    mach_vm_deallocate(ctx->task, ctx->stack, ctx->stack_size);
                }
                if (ctx->notepad != 0) {
                    mach_vm_deallocate(ctx->task, ctx->notepad, sizeof(MINotepad));
                }
                if (ctx->code != 0) {
                    mach_vm_deallocate(ctx->task, ctx->code, ctx->code_size);
                }
                if (ctx->task != MACH_PORT_NULL) {
                    mach_port_deallocate(mach_task_self(), ctx->task);
                }

                free(ctx);

                dispatch_async(dispatch_get_main_queue(), ^{
                    if (completionHandler) completionHandler(result, result.error);
                });
            });

            dispatch_resume(ctx->timer_source);
        }
    }

    // Injection initiated successfully - wait for MACH_SEND_DEAD
}

@end

#else // !__arm64__

// =============================================================================
// MARK: - Stub Implementation for non-ARM64 Platforms
// =============================================================================

NSErrorDomain const MIMachInjectorAsyncErrorDomain = @"MIMachInjectorAsyncErrorDomain";

@implementation MIInjectionResult

- (BOOL)success { return NO; }
- (uint64_t)handle { return 0; }
- (NSError *)error {
    return [NSError errorWithDomain:MIMachInjectorAsyncErrorDomain
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: @"MIMachInjectorAsync is only available on ARM64"}];
}
- (NSString *)remoteErrorMessage { return nil; }

@end

@implementation MIMachInjectorAsync

+ (void)injectWithPID:(pid_t)pid
            dylibPath:(NSString *)dylibPath
              timeout:(NSTimeInterval)timeout
    completionHandler:(MIInjectionCompletionHandler)completionHandler {

    NSError *error = [NSError errorWithDomain:MIMachInjectorAsyncErrorDomain
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"MIMachInjectorAsync is only available on ARM64. Use MIMachInjector for x86_64."}];

    MIInjectionResult *result = [[MIInjectionResult alloc] init];

    dispatch_async(dispatch_get_main_queue(), ^{
        if (completionHandler) completionHandler(result, error);
    });
}

@end

#endif // __arm64__
