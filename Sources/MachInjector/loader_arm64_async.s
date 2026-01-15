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

#ifdef __arm64__

/*
 * =============================================================================
 * Asynchronous Loader Shellcode for ARM64 (Apple Silicon) - V2
 * =============================================================================
 *
 * This shellcode is injected into the target process and executed to load
 * a dylib via dlopen(). The V2 implementation uses pthread to terminate
 * the mach thread, enabling event-driven completion detection.
 *
 * =============================================================================
 * DESIGN CHALLENGES AND WHY THIS APPROACH
 * =============================================================================
 *
 * PROBLEM: How to cleanly exit from the mach thread?
 *
 * Failed Approach 1: Use `ret` instruction
 * ----------------------------------------
 * When thread_create_running() creates a thread, the link register (x30)
 * is set to 0. Using `ret` would jump to address 0x0, causing:
 *   - EXC_BAD_ACCESS (code=1, address=0x0)
 *
 * Failed Approach 2: Use mach_msg() to wait
 * -----------------------------------------
 * We tried having the mach thread wait for a message via mach_msg().
 * However, mach_msg() uses MIG (Mach Interface Generator) internally,
 * which calls mig_get_reply_port(). This function accesses TLS via
 * the TPIDRRO_EL0 register. In raw mach threads, TPIDRRO_EL0 = 0,
 * causing a crash when accessing [0 + 0x10]:
 *   - EXC_BAD_ACCESS (code=1, address=0x10)
 *   - Crash location: mig_get_reply_port -> _pthread_getspecific_direct
 *
 * Failed Approach 3: Mach thread calls thread_terminate(self)
 * -----------------------------------------------------------
 * We tried having the mach thread terminate itself via:
 *   thread_terminate(mach_thread_self())
 *
 * While mach_thread_self() is safe (it's a direct Mach trap that doesn't
 * require TLS), thread_terminate() uses MIG internally and also requires
 * TLS. This causes the same crash at address 0x10:
 *   - EXC_BAD_ACCESS (code=1, address=0x10)
 *   - Crash location: thread_terminate + 36 -> mig_get_reply_port
 *
 * WORKING SOLUTION: pthread terminates the mach thread
 * ----------------------------------------------------
 * pthread has full runtime support including TLS, so it can safely call
 * thread_terminate(). The protocol is:
 *
 *   1. Mach thread saves its port to notepad (mach_thread_self is safe)
 *   2. Mach thread creates pthread
 *   3. Mach thread enters infinite yield loop
 *   4. pthread does dlopen, writes results to notepad
 *   5. pthread reads mach_thread_port from notepad
 *   6. pthread calls thread_terminate(mach_thread_port) <- safe, has TLS
 *   7. Mach thread dies, triggering MACH_SEND_DEAD in injector
 *
 * =============================================================================
 * SAFE vs UNSAFE FUNCTIONS IN RAW MACH THREADS
 * =============================================================================
 *
 * SAFE (no TLS required):
 *   - mach_thread_self()             Direct Mach trap
 *   - pthread_create_from_mach_thread()  Designed for this use case
 *   - Memory load/store operations   Basic CPU operations
 *   - yield instruction              CPU hint, no system call
 *
 * UNSAFE (requires TLS, will crash):
 *   - mach_msg()                     Uses MIG -> mig_get_reply_port
 *   - thread_terminate()             Uses MIG -> mig_get_reply_port
 *   - mach_port_allocate()           Uses MIG
 *   - Most Mach IPC functions        Use MIG internally
 *
 * =============================================================================
 * THREAD COMMUNICATION FLOW
 * =============================================================================
 *
 *   Mach Thread                              pthread
 *   -----------                              -------
 *   mach_thread_self()
 *   Save mach_thread_port to notepad
 *   pthread_create_from_mach_thread()  ----> Start
 *                                              |
 *   Infinite loop (yield)                      |
 *       |                                      dlopen()
 *       |                                      Write results to notepad
 *       |                                      mach_thread_self()
 *       |                                      Save pthread_port to notepad
 *       |                                      Read mach_thread_port from notepad
 *       X <------------------------------ thread_terminate(mach_thread_port)
 *       |                                      retab (pthread exits)
 *       v
 *   MACH_SEND_DEAD triggers in injector
 *       |
 *       v
 *   Injector reads notepad, calls completion handler
 *
 * =============================================================================
 * NOTEPAD MEMORY LAYOUT (MINotepad structure)
 * =============================================================================
 *
 *   Offset  Size    Field             Description
 *   ------  ----    -----             -----------
 *   0x00    4       pthread_port      pthread's mach port (for debugging/future use)
 *   0x04    4       mach_thread_port  mach thread's port (pthread reads this to terminate)
 *   0x08    4       result_code       0=success, 1=dlopen fail, 2=pthread fail
 *   0x0C    4       (reserved)        Padding for alignment
 *   0x10    8       handle            dlopen() return value
 *   0x18    256     error_message     dlerror() string
 *
 *   Total notepad size: 280 bytes (0x118)
 *
 * =============================================================================
 * WHY PTHREAD_PORT IS SAVED BUT NOT USED
 * =============================================================================
 *
 * We originally planned two-phase cleanup:
 *   Phase 1: mach thread dies -> cleanup stack/notepad, monitor pthread
 *   Phase 2: pthread dies -> cleanup code, call completion
 *
 * However, pthread_port in notepad is a port NAME in the TARGET process's
 * Mach namespace. Port names are process-local identifiers. This name is
 * MEANINGLESS in the injector process - we cannot create a dispatch_source
 * to monitor it without explicit port transfer (which would require MIG).
 *
 * So pthread_port is saved for debugging purposes but not used for cleanup.
 * The injector completes immediately after mach thread terminates.
 *
 * =============================================================================
 */

.section __DATA, __data

/*
 * -----------------------------------------------------------------------------
 * EXPORTED SYMBOLS
 * -----------------------------------------------------------------------------
 */
.global ___async_shellcode_start
.global ___async_shellcode_end
.global ___async_patch_pthread_create
.global ___async_patch_sandbox_consume
.global ___async_patch_dlopen
.global ___async_patch_dlerror
.global ___async_patch_mach_thread_self
.global ___async_patch_thread_terminate
.global ___async_data_notepad
.global ___async_data_payload_path
.global ___async_data_sandbox_token

/*
 * -----------------------------------------------------------------------------
 * NOTEPAD STRUCTURE OFFSETS (V2)
 * -----------------------------------------------------------------------------
 * Note: mach thread cannot use mach_msg or thread_terminate because they
 * require TLS (via mig_get_reply_port). Instead, pthread terminates mach thread.
 */
.set NOTEPAD_PTHREAD_PORT,      0x00    // mach_port_t: pthread's mach port (for phase 2)
.set NOTEPAD_MACH_THREAD_PORT,  0x04    // mach_port_t: mach thread's port (pthread terminates it)
.set NOTEPAD_RESULT_CODE,       0x08    // int32_t: 0=success, 1=dlopen fail, 2=pthread fail
.set NOTEPAD_RESERVED,          0x0C    // int32_t: reserved/padding
.set NOTEPAD_HANDLE,            0x10    // uint64_t: dlopen return value
.set NOTEPAD_ERROR_MSG,         0x18    // char[256]: dlerror() string
.set NOTEPAD_ERROR_SIZE,        0x100   // Maximum error message length (256 bytes)

/*
 * =============================================================================
 * MACH THREAD ENTRY POINT
 * =============================================================================
 *
 * Responsibilities:
 *   1. Get own mach port and save to notepad (so pthread can terminate us)
 *   2. Create pthread to do the actual work
 *   3. Enter infinite loop waiting to be terminated by pthread
 *
 * NOTE: We cannot call thread_terminate(self) from mach thread because
 * thread_terminate uses MIG internally, which calls mig_get_reply_port,
 * which requires TLS. Raw mach threads don't have TLS.
 *
 * Instead, pthread will terminate the mach thread after completing its work.
 */
___async_shellcode_start:
    /*
     * Stack Frame Setup
     * -----------------
     * Allocate 48 bytes (0x30) on the stack:
     *   [sp+0x00]: pthread_t output (8 bytes)
     *   [sp+0x08]: padding
     *   [sp+0x10]: saved x19, x20 (16 bytes)
     *   [sp+0x20]: saved x29, x30 (16 bytes) <- frame pointer here
     */
    sub sp, sp, #0x30               // Allocate 48 bytes on stack
    stp x29, x30, [sp, #0x20]       // Save frame pointer and link register
    add x29, sp, #0x20              // Set up frame pointer
    stp x19, x20, [sp, #0x10]       // Save callee-saved registers

    /*
     * Load Notepad Address
     * --------------------
     * x19 = notepad address (preserved across all calls)
     */
    adr x19, ___async_data_notepad
    ldr x19, [x19]

    /*
     * Initialize Notepad Fields
     * -------------------------
     */
    str wzr, [x19, #NOTEPAD_PTHREAD_PORT]
    str wzr, [x19, #NOTEPAD_MACH_THREAD_PORT]
    str wzr, [x19, #NOTEPAD_RESULT_CODE]

    /*
     * Step 1: Get Mach Thread Port
     * ----------------------------
     * mach_thread_self() is a direct Mach trap that doesn't require TLS.
     * We save this port so pthread can terminate us later.
     */
    adr x9, ___async_patch_mach_thread_self
    ldr x9, [x9]
    blr x9
    str w0, [x19, #NOTEPAD_MACH_THREAD_PORT]

    /*
     * Step 2: Create pthread
     * ----------------------
     * int pthread_create_from_mach_thread(
     *     pthread_t *thread,
     *     const pthread_attr_t *attr,
     *     void *(*start_routine)(void *),
     *     void *arg
     * );
     */
    add    x0, sp, #0x00            // x0 = &thread (output)
    mov    x1, xzr                  // x1 = NULL (default attributes)
    adr    x2, ___async_thread_entry
    paciza x2                       // Sign the function pointer
    mov    x3, xzr                  // x3 = NULL (no argument)

    adr x9, ___async_patch_pthread_create
    ldr x9, [x9]
    blr x9

    // Check result
    cbnz w0, ___async_pthread_failed

    /*
     * Step 3: Infinite Loop
     * ---------------------
     * Wait to be terminated by pthread.
     * Use 'yield' instruction to reduce power consumption.
     */
___async_wait_loop:
    yield
    b ___async_wait_loop

/*
 * -----------------------------------------------------------------------------
 * PTHREAD CREATION FAILURE
 * -----------------------------------------------------------------------------
 * If pthread creation fails, we have no way to terminate cleanly (no TLS).
 * Set error code and enter infinite loop. The injector's timeout will catch this.
 */
___async_pthread_failed:
    mov w8, #2                      // result_code = 2 (pthread failed)
    str w8, [x19, #NOTEPAD_RESULT_CODE]

    // Infinite loop - injector timeout will terminate us
    b ___async_wait_loop

    .align 4

/*
 * =============================================================================
 * PTHREAD ENTRY POINT
 * =============================================================================
 *
 * Execution Flow:
 *   1. Set up stack frame with PAC
 *   2. Consume sandbox extension (if provided)
 *   3. Call dlopen() to load the target dylib
 *   4. Write results to notepad
 *   5. Get pthread's mach port and save to notepad
 *   6. Terminate the mach thread (triggers MACH_SEND_DEAD in injector)
 *   7. Return (thread exits)
 *
 * NOTE: pthread has full runtime support including TLS, so it can safely
 * call thread_terminate() which uses MIG internally.
 */
___async_thread_entry:
    pacibsp
    sub sp, sp, #0x40
    stp x29, x30, [sp, #0x30]
    add x29, sp, #0x30
    stp x19, x20, [sp, #0x20]
    stp x21, x22, [sp, #0x10]

    /*
     * Load Notepad Address
     */
    adr x19, ___async_data_notepad
    ldr x19, [x19]

    /*
     * Initialize Result Fields
     */
    str xzr, [x19, #NOTEPAD_HANDLE]
    str wzr, [x19, #NOTEPAD_RESULT_CODE]

    /*
     * Sandbox Extension Handling
     */
    adr x0, ___async_data_sandbox_token
    ldrb w8, [x0]
    cbz w8, ___async_skip_sandbox

    adr x9, ___async_patch_sandbox_consume
    ldr x9, [x9]
    blr x9

___async_skip_sandbox:
    /*
     * Call dlopen
     */
    adr x0, ___async_data_payload_path
    mov x1, #1                      // RTLD_LAZY
    adr x9, ___async_patch_dlopen
    ldr x9, [x9]
    blr x9

    // Save handle
    str x0, [x19, #NOTEPAD_HANDLE]

    // Check result
    cbnz x0, ___async_dlopen_success

    /*
     * dlopen Failed - Get Error
     */
    adr x9, ___async_patch_dlerror
    ldr x9, [x9]
    blr x9

    // Copy error string
    mov x20, x0
    add x21, x19, #NOTEPAD_ERROR_MSG
    mov x22, #(NOTEPAD_ERROR_SIZE - 1)

___async_copy_error:
    cbz x22, ___async_copy_done
    ldrb w8, [x20], #1
    strb w8, [x21], #1
    cbz w8, ___async_copy_done
    sub x22, x22, #1
    b ___async_copy_error

___async_copy_done:
    strb wzr, [x21]

    // Set failure result
    mov w8, #1
    str w8, [x19, #NOTEPAD_RESULT_CODE]
    b ___async_finish

___async_dlopen_success:
    str wzr, [x19, #NOTEPAD_RESULT_CODE]

___async_finish:
    /*
     * Get pthread's mach port and save to notepad
     * mach_port_t mach_thread_self(void);
     */
    adr x9, ___async_patch_mach_thread_self
    ldr x9, [x9]
    blr x9
    str w0, [x19, #NOTEPAD_PTHREAD_PORT]

    /*
     * Memory Barrier
     * --------------
     * Ensure all notepad writes are visible before terminating mach thread
     */
    dmb sy

    /*
     * Terminate Mach Thread
     * ---------------------
     * Read the mach thread port from notepad and terminate it.
     * This triggers MACH_SEND_DEAD in the injector, starting phase 1 cleanup.
     *
     * pthread has TLS support, so it can safely call thread_terminate().
     */
    ldr w0, [x19, #NOTEPAD_MACH_THREAD_PORT]
    cbz w0, ___async_skip_terminate     // Skip if port is 0 (shouldn't happen)

    adr x9, ___async_patch_thread_terminate
    ldr x9, [x9]
    blr x9

___async_skip_terminate:
    /*
     * Return from pthread
     */
    ldp x21, x22, [sp, #0x10]
    ldp x19, x20, [sp, #0x20]
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    retab

/*
 * =============================================================================
 * RUNTIME PATCH LOCATIONS
 * =============================================================================
 */
    .align 3
___async_patch_pthread_create:
    .quad 0x0

    .align 3
___async_patch_sandbox_consume:
    .quad 0x0

    .align 3
___async_patch_dlopen:
    .quad 0x0

    .align 3
___async_patch_dlerror:
    .quad 0x0

    .align 3
___async_patch_mach_thread_self:
    .quad 0x0

    .align 3
___async_patch_thread_terminate:
    .quad 0x0

/*
 * =============================================================================
 * DATA SECTION
 * =============================================================================
 */
    .align 3
___async_data_notepad:
    .quad 0x0

    .align 3
___async_data_payload_path:
    .zero 0x500

    .align 3
___async_data_sandbox_token:
    .zero 0x500

___async_shellcode_end:

#endif /* __arm64__ */
