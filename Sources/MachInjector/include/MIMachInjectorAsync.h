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
 * MIMachInjectorAsync - Asynchronous Dylib Injection for macOS (ARM64) V2
 * =============================================================================
 *
 * This module provides an asynchronous implementation of dylib injection into
 * running macOS processes. V2 uses event-driven completion detection via
 * MACH_SEND_DEAD instead of polling.
 *
 * Key Features:
 * - MACH_SEND_DEAD event-driven completion (no polling)
 * - pthread terminates mach thread (triggers MACH_SEND_DEAD)
 * - Rosetta 2 support for translated processes
 *
 * =============================================================================
 * DESIGN CHALLENGES AND SOLUTIONS
 * =============================================================================
 *
 * PROBLEM 1: Raw mach threads cannot call `ret` to exit
 * -----------------------------------------------------
 * When thread_create_running() creates a thread, x30 (link register) = 0.
 * Using `ret` would jump to address 0x0, causing EXC_BAD_ACCESS.
 *
 * PROBLEM 2: Raw mach threads cannot use mach_msg() or thread_terminate()
 * -----------------------------------------------------------------------
 * These functions use MIG (Mach Interface Generator) internally, which calls
 * mig_get_reply_port(). This function accesses TLS via TPIDRRO_EL0 register.
 * In raw mach threads, TPIDRRO_EL0 = 0, causing a crash at address 0x10:
 *   - EXC_BAD_ACCESS (code=1, address=0x10)
 *   - Crash in: mig_get_reply_port -> _pthread_getspecific_direct
 *
 * SOLUTION: pthread terminates the mach thread
 * --------------------------------------------
 * pthread has full TLS support and can safely call thread_terminate().
 * The mach thread saves its port to notepad, enters infinite yield loop.
 * pthread terminates it after completing dlopen(), triggering MACH_SEND_DEAD.
 *
 * PROBLEM 3: Cannot monitor pthread exit from injector
 * ----------------------------------------------------
 * pthread_port in notepad is a port NAME in the target process's namespace.
 * Port names are process-local - we cannot use it to monitor pthread exit.
 * SOLUTION: Complete immediately after mach thread dies. Code segment is
 * intentionally not freed (~2.6KB overhead) as pthread may still be returning.
 *
 * =============================================================================
 * ARCHITECTURE OVERVIEW
 * =============================================================================
 *
 * Thread Communication Flow:
 *
 *   Mach Thread (no TLS)                    pthread (full TLS)
 *   --------------------                    ------------------
 *   mach_thread_self()  [safe: direct trap]
 *   Save port to notepad
 *   pthread_create_from_mach_thread()  ---> Start
 *                                              |
 *   Infinite loop (yield)                      |
 *       |                                      dlopen()
 *       |                                      Write results to notepad
 *       |                                      Read mach_thread_port from notepad
 *       X <------------------------------ thread_terminate(mach_thread_port)
 *       |                                      retab (pthread exits)
 *       v
 *   MACH_SEND_DEAD triggers
 *       |
 *       v
 *   Injector reads notepad
 *   Cleanup: stack, notepad
 *   Call completion handler
 *
 * =============================================================================
 * SAFE vs UNSAFE FUNCTIONS IN RAW MACH THREADS
 * =============================================================================
 *
 * SAFE (no TLS required):
 *   - mach_thread_self()                  Direct Mach trap
 *   - pthread_create_from_mach_thread()   Designed for this use case
 *   - Memory load/store                   Basic CPU operations
 *
 * UNSAFE (requires TLS, will crash):
 *   - mach_msg()                          Uses MIG -> mig_get_reply_port
 *   - thread_terminate()                  Uses MIG -> mig_get_reply_port
 *   - mach_port_allocate()                Uses MIG
 *   - Most Mach IPC functions             Use MIG internally
 *
 * =============================================================================
 * NOTEPAD COMMUNICATION STRUCTURE
 * =============================================================================
 *
 * The notepad is a shared memory region for communication:
 *
 *   Offset  Size    Field             Description
 *   ------  ----    -----             -----------
 *   0x00    4       pthread_port      pthread's mach port (for debugging)
 *   0x04    4       mach_thread_port  mach thread's port (pthread terminates it)
 *   0x08    4       result_code       0=success, 1=dlopen fail, 2=pthread fail
 *   0x0C    4       (reserved)        padding for alignment
 *   0x10    8       handle            dlopen() return value (void*)
 *   0x18    256     error_message     dlerror() string if dlopen failed
 *
 *   Total size: 280 bytes
 *
 * =============================================================================
 * RESOURCE CLEANUP
 * =============================================================================
 *
 * When MACH_SEND_DEAD triggers (mach thread terminated by pthread):
 *   - Read notepad for results
 *   - Deallocate: stack, notepad
 *   - Call completion handler
 *
 * NOTE: The code segment (~2.6KB) is intentionally NOT deallocated because
 * pthread may still be executing its return sequence (ldp, add sp, retab).
 * This is an acceptable memory overhead per injection.
 *
 * Originally we planned two-phase cleanup (monitor pthread exit to free code),
 * but pthread_port in notepad is a port NAME in the target process's namespace.
 * Port names are process-local and cannot be used from another process.
 *
 * =============================================================================
 * ERROR CODES
 * =============================================================================
 *
 *   Code    Description
 *   ----    -----------
 *   1       Failed to allocate injection context
 *   2       Invalid PID provided
 *   3       task_for_pid() failed (permission denied or process not found)
 *   4       Failed to allocate notepad in target process
 *   5       Failed to initialize notepad
 *   6       Failed to allocate stack in target process
 *   7       Failed to set stack memory protection
 *   8       Failed to allocate code segment in target process
 *   9       Failed to allocate local shellcode buffer
 *   10      Dylib path too long (max 1279 bytes)
 *   11      Failed to write shellcode to target process
 *   12      Failed to set code segment as executable
 *   13      Failed to load thread_convert_thread_state function
 *   14      Failed to create remote thread
 *   15      Failed to convert thread state (ARM64 specific)
 *   16      Failed to start remote thread
 *   17      Failed to create pthread in target process
 *   18      dlopen() failed in target process
 *   19      Injection timed out
 *   21      Failed to allocate mach port in target process
 *   22      Failed to create dispatch source
 *
 * =============================================================================
 * PLATFORM SUPPORT
 * =============================================================================
 *
 * - ARM64 (Apple Silicon): Full support
 * - Rosetta 2 (translated x86_64 processes): Supported via liboah.dylib
 * - x86_64 native: Use synchronous MIMachInjector instead
 *
 */

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Error domain for MIMachInjectorAsync errors.
/// See the header documentation for a complete list of error codes.
FOUNDATION_EXPORT NSErrorDomain const MIMachInjectorAsyncErrorDomain NS_SWIFT_NAME(MachInjectorAsyncErrorDomain);

/// Represents the result of an asynchronous dylib injection operation.
///
/// This class encapsulates all information about the injection result:
/// - Whether the injection succeeded
/// - The dlopen handle (for potential future dlclose/detach operations)
/// - Any error that occurred
/// - The remote error message from dlerror() if dlopen failed
///
/// @note This class is immutable; all properties are readonly.
NS_SWIFT_NAME(InjectionResult)
@interface MIInjectionResult : NSObject

/// Indicates whether the injection was successful.
///
/// When YES:
/// - The dylib was successfully loaded into the target process
/// - The `handle` property contains the valid dlopen() return value
/// - The `error` property is nil
///
/// When NO:
/// - The injection failed at some stage
/// - Check `error` for the specific failure reason
/// - Check `remoteErrorMessage` for dlerror() output if available
@property (nonatomic, readonly) BOOL success;

/// The dlopen() handle returned from the target process.
///
/// This value is only meaningful when `success` is YES. The handle
/// represents the loaded dylib in the target process's address space
/// and can be used for:
/// - Tracking which dylibs have been injected
/// - Future dlclose() operations (detach functionality)
/// - Calling dlsym() to find symbols in the injected dylib
///
/// @note The handle is a 64-bit value representing a pointer in the
///       target process's address space, not the injector's.
@property (nonatomic, readonly) uint64_t handle;

/// Error information if injection failed.
///
/// This property is nil when `success` is YES. When injection fails,
/// this contains an NSError with:
/// - Domain: MIMachInjectorAsyncErrorDomain
/// - Code: One of the error codes documented in the header
/// - LocalizedDescription: Human-readable error message
@property (nonatomic, readonly, nullable) NSError *error;

/// Remote error message from dlerror() in the target process.
///
/// When dlopen() fails in the target process, this property contains
/// the error string returned by dlerror(). This provides more specific
/// information about why the dylib failed to load, such as:
/// - "image not found" - dylib path doesn't exist
/// - "code signature invalid" - dylib not properly signed
/// - "Symbol not found" - missing dependency
///
/// This property may be nil even when injection fails, if the failure
/// occurred before dlopen() was called.
@property (nonatomic, readonly, nullable) NSString *remoteErrorMessage;

@end

/// Completion handler type for asynchronous injection operations.
///
/// @param result The injection result containing success status, handle, and error info.
///               This is always non-nil; check result.success for success/failure.
/// @param error The error if injection failed, nil on success. This is redundant with
///              result.error but provided for Swift async/await compatibility.
///
/// @note This block is always called on the main thread.
/// @note The block is called exactly once, regardless of success or failure.
typedef void (^MIInjectionCompletionHandler)(MIInjectionResult *result, NSError * _Nullable error) NS_SWIFT_NAME(InjectionCompletionHandler);

/// Asynchronous dylib injector using Xcode RemoteInjectionAgent-style implementation.
///
/// This class provides an asynchronous API for injecting dylibs into running macOS
/// processes. Unlike the synchronous MIMachInjector, this implementation:
///
/// 1. **Uses dispatch_source for completion detection**: Instead of polling thread
///    registers, it monitors the mach thread port for MACH_SEND_DEAD events.
///
/// 2. **Properly cleans up all resources**: All memory allocated in the target
///    process (notepad, stack, code) is deallocated after injection completes.
///
/// 3. **Returns the dlopen handle**: The completion result includes the handle
///    returned by dlopen(), enabling future detach (dlclose) operations.
///
/// 4. **Supports configurable timeout**: A timeout can be specified to prevent
///    indefinite waiting if the target process hangs or crashes.
///
/// 5. **Provides detailed error information**: Including remote error messages
///    from dlerror() when dlopen() fails.
///
/// ## Usage Example (Objective-C)
///
/// ```objc
/// [MIMachInjectorAsync injectWithPID:targetPID
///                          dylibPath:@"/path/to/payload.dylib"
///                            timeout:5.0
///                  completionHandler:^(MIInjectionResult *result, NSError *error) {
///     if (result.success) {
///         NSLog(@"Injection succeeded! Handle: 0x%llx", result.handle);
///     } else {
///         NSLog(@"Injection failed: %@", error.localizedDescription);
///         if (result.remoteErrorMessage) {
///             NSLog(@"Remote error: %@", result.remoteErrorMessage);
///         }
///     }
/// }];
/// ```
///
/// ## Usage Example (Swift with async/await)
///
/// ```swift
/// do {
///     let result = try await AsyncMachInjector.inject(
///         pid: targetPID,
///         dylibPath: "/path/to/payload.dylib",
///         timeout: 5.0
///     )
///     print("Injection succeeded! Handle: 0x\(String(result.handle, radix: 16))")
/// } catch {
///     print("Injection failed: \(error.localizedDescription)")
/// }
/// ```
///
/// ## Thread Safety
///
/// This class is thread-safe. Multiple injection operations can be performed
/// concurrently from different threads. Each operation maintains its own
/// independent state and resources.
///
/// ## Platform Requirements
///
/// - macOS 11.0 or later
/// - ARM64 (Apple Silicon) only
/// - Requires appropriate entitlements for task_for_pid()
///
/// @note For x86_64 targets, use the synchronous MIMachInjector class instead.
///
/// ## Swift Usage
///
/// This class is imported into Swift as `MachInjectorAsync` with an async method:
///
/// ```swift
/// let result = try await MachInjectorAsync.inject(
///     pid: targetPID,
///     dylibPath: "/path/to/payload.dylib",
///     timeout: 5.0
/// )
/// print("Handle: \(result.handle)")
/// ```
NS_SWIFT_NAME(MachInjectorAsync)
@interface MIMachInjectorAsync : NSObject

/// Asynchronously inject a dylib into the target process.
///
/// This method performs dylib injection asynchronously, returning immediately
/// and calling the completion handler when the operation finishes (successfully
/// or with an error).
///
/// ## Injection Process
///
/// 1. Obtains the task port for the target process via task_for_pid()
/// 2. Allocates memory in the target process for notepad, stack, and code
/// 3. Writes the shellcode (loader) to the target process
/// 4. Creates and starts a remote mach thread
/// 5. Sets up dispatch_source to monitor thread termination
/// 6. The remote thread creates a pthread which calls dlopen()
/// 7. When the thread terminates, reads results from notepad
/// 8. Cleans up all allocated resources in the target process
/// 9. Calls the completion handler on the main thread
///
/// ## Timeout Behavior
///
/// If a timeout is specified (> 0), a timer is started when the remote thread
/// begins execution. If the thread doesn't complete within the timeout period:
/// - The remote thread is terminated
/// - All resources are cleaned up
/// - The completion handler is called with a timeout error
///
/// ## Resource Management
///
/// Resources are partially cleaned up after injection:
/// - Notepad memory region: Deallocated (safe after done_flag is set)
/// - Stack memory region: NOT deallocated (pthread may still be using it)
/// - Code (shellcode) memory region: NOT deallocated (pthread needs it to return)
/// - Remote mach thread: Terminated
///
/// The stack and code regions are intentionally leaked because the pthread
/// created by the shellcode may still be executing when the mach thread exits.
/// This is the same behavior as the synchronous MIMachInjector.
///
/// Memory overhead per injection: ~18.6 KB (16 KB stack + ~2.6 KB code)
///
/// @param pid The process ID of the target process. Must be a valid, running
///            process that the caller has permission to access.
///
/// @param dylibPath The full filesystem path to the dylib to inject. The path
///                  must be accessible from the target process (consider sandbox
///                  restrictions). Maximum length is 1279 bytes.
///
/// @param timeout The maximum time to wait for injection to complete, in seconds.
///                Pass 0 for no timeout (wait indefinitely). Recommended values
///                are 3-10 seconds for typical dylib loading.
///
/// @param completion A block that will be called when injection completes.
///                   This block is always called on the main thread, exactly
///                   once, regardless of success or failure.
///
/// ## Error Handling
///
/// The completion handler's result object contains detailed error information:
/// - `result.success`: Quick check for success/failure
/// - `result.error`: NSError with domain, code, and description
/// - `result.remoteErrorMessage`: dlerror() output from target process
///
/// Common failure scenarios:
/// - Invalid PID or process not found
/// - Permission denied (missing entitlements)
/// - Dylib not found or invalid
/// - Code signing issues
/// - Target process crashed during injection
/// - Timeout exceeded
///
/// ## Swift Async Import
///
/// This method is automatically imported into Swift as an async throwing function:
/// ```swift
/// class func inject(pid: pid_t, dylibPath: String, timeout: TimeInterval) async throws -> InjectionResult
/// ```
///
+ (void)injectWithPID:(pid_t)pid
            dylibPath:(NSString *)dylibPath
              timeout:(NSTimeInterval)timeout
    completionHandler:(MIInjectionCompletionHandler)completionHandler
    NS_SWIFT_ASYNC_NAME(inject(pid:dylibPath:timeout:))
    NS_SWIFT_NAME(inject(pid:dylibPath:timeout:completionHandler:));

@end

NS_ASSUME_NONNULL_END
