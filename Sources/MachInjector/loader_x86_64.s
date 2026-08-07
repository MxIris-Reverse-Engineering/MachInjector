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

#ifdef __x86_64__

/*
 * =============================================================================
 * Synchronous Loader Shellcode for x86_64 (Intel)
 * =============================================================================
 *
 * This shellcode is injected into a target process to load a dylib on x86_64
 * (Intel) macOS systems. It follows the same two-thread pattern as the ARM64
 * version but without pointer authentication requirements.
 *
 * =============================================================================
 * ARCHITECTURE OVERVIEW
 * =============================================================================
 *
 * The injection uses a two-thread model:
 *
 *   1. Mach Thread (shellcode entry point)
 *      - Created by the injector using thread_create_running()
 *      - Sets up pthread_create_from_mach_thread() call
 *      - After creating pthread, signals completion via RAX register
 *      - Enters infinite loop waiting for injector to read status
 *
 *   2. pthread (thread entry point)
 *      - Created by mach thread via pthread_create_from_mach_thread()
 *      - Has full pthread capabilities (TLS, etc.)
 *      - Calls dlopen() to load the target dylib
 *      - Returns normally
 *
 * Execution Flow:
 *
 *   Injector Process              Target Process
 *   ================              ==============
 *
 *   thread_create_running() ----> Mach Thread starts
 *                                      |
 *                                      v
 *                                 pthread_create_from_mach_thread()
 *                                      |
 *                                      +-------> pthread starts
 *                                      |              |
 *                                      v              v
 *                                 RAX = "DONE"   dlopen(path)
 *                                      |              |
 *                                      v              v
 *                                 infinite loop   return
 *                                      |
 *   Poll thread_get_state() <---------+
 *   (check RAX == "DONE")
 *
 * =============================================================================
 * COMPLETION DETECTION
 * =============================================================================
 *
 * Unlike the async ARM64 version which uses dispatch_source, this synchronous
 * version uses register polling:
 *
 * 1. Mach thread sets RAX to "DONE" (0x444F4E45) after creating pthread
 * 2. Mach thread enters infinite loop (jmp $)
 * 3. Injector polls thread_get_state() to read RAX
 * 4. When RAX == "DONE", injector knows pthread was created
 * 5. Injector terminates the mach thread
 *
 * dlopen's own outcome arrives separately: the pthread writes its handle, and
 * dlerror()'s message on failure, into the report block the injector allocated
 * in the target (see REPORT BLOCK LAYOUT below), which the injector polls after
 * seeing "DONE".
 *
 * This polling approach still has limitations:
 * - Thread and memory resources are not cleaned up
 *
 * For better resource management, use MIMachInjectorAsync (ARM64 only).
 *
 * =============================================================================
 * MEMORY LAYOUT
 * =============================================================================
 *
 * The shellcode is position-independent and uses RIP-relative addressing.
 * Function addresses are stored in a data section at the end, not inline.
 *
 *   Section                        Description
 *   -------                        -----------
 *   Code Section:
 *     __x86_shellcode_start        Mach thread entry point
 *     __x86_thread_entry           pthread entry point
 *
 *   Data Section (at end):
 *     __x86_patch_pthread_create   8 bytes - pthread_create_from_mach_thread address
 *     __x86_patch_dlopen           8 bytes - dlopen address
 *     __x86_data_payload_path      512 bytes - Null-terminated dylib path
 *     __x86_shellcode_end          End marker for size calculation
 *
 * =============================================================================
 * CALLING CONVENTIONS (System V AMD64 ABI)
 * =============================================================================
 *
 * Arguments: RDI, RSI, RDX, RCX, R8, R9, then stack
 * Return value: RAX
 * Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11
 * Callee-saved: RBX, RBP, R12-R15
 *
 * pthread_create_from_mach_thread(pthread_t *thread,
 *                                  const pthread_attr_t *attr,
 *                                  void *(*start_routine)(void *),
 *                                  void *arg)
 *   RDI = &thread (output)
 *   RSI = attr (NULL)
 *   RDX = start_routine
 *   RCX = arg (NULL)
 *
 * dlopen(const char *path, int mode)
 *   RDI = path
 *   RSI = mode (RTLD_LAZY = 1)
 *
 * =============================================================================
 * LIMITATIONS COMPARED TO ARM64 VERSION
 * =============================================================================
 *
 * 1. No sandbox extension support
 *    - Cannot inject into sandboxed processes that can't access the dylib
 *
 * 2. No resource cleanup
 *    - Allocated memory (code, stack) is intentionally leaked
 *    - Mach thread is terminated but not deallocated
 *
 * For production use, consider using the async ARM64 implementation or
 * extending this implementation with notepad-based communication.
 *
 * =============================================================================
 */

.section __DATA, __data

/*
 * -----------------------------------------------------------------------------
 * EXPORTED SYMBOLS
 * -----------------------------------------------------------------------------
 * These symbols are referenced by the C code in MIMachInjector.m to:
 * - Calculate shellcode size (end - start)
 * - Locate patch points for runtime address fixup
 * - Locate data buffer for writing dylib path
 */
.global ___x86_shellcode_start
.global ___x86_shellcode_end
.global ___x86_patch_pthread_create
.global ___x86_patch_dlopen
.global ___x86_patch_dlerror
.global ___x86_data_payload_path
.global ___x86_data_report_address

/*
 * Completion magic number: "DONE" in little-endian ASCII
 * D=0x44, O=0x4F, N=0x4E, E=0x45 -> 0x454E4F44 as dword
 * But we store as 0x444F4E45 to match existing code expectations
 */
.set MI_INJECTION_DONE, 0x444F4E45

/*
 * -----------------------------------------------------------------------------
 * REPORT BLOCK LAYOUT
 * -----------------------------------------------------------------------------
 * The RAX "DONE" signal only says pthread_create returned — dlopen runs on the
 * pthread afterwards, so a target that refuses the payload used to look exactly
 * like a successful load. The pthread records dlopen's outcome in a page the
 * injector allocated read/write in the target, which the injector then polls.
 *
 * The block lives on its own page rather than inside the shellcode blob because
 * the shellcode is mapped read+execute in the target; the pthread cannot write
 * to it. Layout matches loader_arm64.s.
 */
.set REPORT_RESULT_CODE,        0x00    // int32_t: 0=pending, 1=loaded, 2=dlopen failed
.set REPORT_HANDLE,             0x08    // uint64_t: dlopen return value
.set REPORT_ERROR_MESSAGE,      0x10    // char[256]: dlerror() string
.set REPORT_ERROR_MESSAGE_SIZE, 0x100   // Maximum error message length (256 bytes)

/*
 * =============================================================================
 * MACH THREAD ENTRY POINT
 * =============================================================================
 *
 * This is where execution begins when the injector creates the remote thread.
 * The mach thread's purpose is to bootstrap a pthread that will do the actual
 * dylib loading.
 *
 * Register state on entry (set by thread_create_running):
 *   RIP = __x86_shellcode_start (this address)
 *   RSP = allocated stack top
 *   All other registers = 0
 */
___x86_shellcode_start:
    /*
     * Stack Frame Setup
     * -----------------
     * Standard x86_64 function prologue.
     * We need 16 bytes on stack for:
     *   [rbp-8]: pthread_t output from pthread_create
     */
    pushq   %rbp                        // Save frame pointer
    movq    %rsp, %rbp                  // Set up new frame pointer
    subq    $0x10, %rsp                 // Allocate 16 bytes (maintains 16-byte alignment)

    /*
     * Prepare pthread_create_from_mach_thread Arguments
     * -------------------------------------------------
     * int pthread_create_from_mach_thread(
     *     pthread_t *thread,               // RDI: output - where to store thread handle
     *     const pthread_attr_t *attr,      // RSI: thread attributes (NULL = default)
     *     void *(*start_routine)(void *),  // RDX: thread entry point
     *     void *arg                        // RCX: argument to pass (NULL)
     * );
     */
    leaq    -0x8(%rbp), %rdi            // RDI = &thread (stack location for output)
    xorl    %eax, %eax                  // Zero out EAX (efficient way to get 0)
    movl    %eax, %ecx                  // RCX = 0 (arg = NULL)
    leaq    ___x86_thread_entry(%rip), %rdx  // RDX = address of thread entry (RIP-relative)
    movq    %rcx, %rsi                  // RSI = 0 (attr = NULL)

    /*
     * Load pthread_create_from_mach_thread Address
     * --------------------------------------------
     * Load the function address from our data section. The address is
     * patched at runtime by the injector before the shellcode is executed.
     */
    movq    ___x86_patch_pthread_create(%rip), %rax  // Load function address
    callq   *%rax                       // Call pthread_create_from_mach_thread

    /*
     * Clean Up Stack Frame
     * --------------------
     * Restore stack pointer (not strictly necessary since we loop forever,
     * but good practice for code clarity).
     */
    addq    $0x10, %rsp                 // Deallocate stack space
    popq    %rbp                        // Restore frame pointer

    /*
     * Signal Completion
     * -----------------
     * Set RAX to "DONE" magic number to indicate pthread was created.
     * The injector polls this register via thread_get_state().
     */
    movq    $MI_INJECTION_DONE, %rax    // RAX = 0x444F4E45 ("DONE")

    /*
     * Infinite Loop
     * -------------
     * Loop forever, waiting for the injector to read our status and
     * terminate this thread. We don't exit cleanly because:
     * 1. The pthread needs to keep running
     * 2. We have no way to signal completion to the injector otherwise
     *
     * The injector will call thread_terminate() on this thread after
     * detecting the "DONE" signal.
     */
___x86_wait_loop:
    jmp     ___x86_wait_loop            // Infinite loop (2-byte encoding: EB FE)

    /*
     * Unreachable return instruction
     * ------------------------------
     * This is never executed but included for disassembler clarity.
     */
    retq

/*
 * =============================================================================
 * PTHREAD ENTRY POINT
 * =============================================================================
 *
 * This function is called as the start routine for the new pthread.
 * It runs in a proper pthread context with TLS and signal handling available.
 *
 * The pthread's job is simple: call dlopen() to load the target dylib.
 *
 * Parameters:
 *   RDI = arg (always NULL in our case)
 *
 * Return:
 *   RAX = thread exit value (ignored)
 */
    .align 4  // Align to 16-byte boundary for performance
___x86_thread_entry:
    /*
     * Stack Frame Setup
     * -----------------
     * Standard function prologue. RBX is callee-saved and holds the report
     * block address across the dlopen / dlerror calls; the extra 8 bytes keep
     * RSP 16-byte aligned at the call sites.
     */
    pushq   %rbp                        // Save frame pointer
    movq    %rsp, %rbp                  // Set up new frame pointer
    pushq   %rbx                        // Save callee-saved register
    subq    $0x8, %rsp                  // Re-align stack to 16 bytes

    /*
     * Load Report Block Address
     * -------------------------
     * Zero when the injector could not allocate one; the load still proceeds,
     * it just goes unreported.
     */
    movq    ___x86_data_report_address(%rip), %rbx

    /*
     * Prepare dlopen Arguments
     * ------------------------
     * void *dlopen(const char *path, int mode);
     *
     * RDI = path to dylib (RIP-relative address of embedded path)
     * RSI = RTLD_LAZY (1) - resolve symbols lazily
     */
    movl    $0x1, %esi                  // RSI = RTLD_LAZY (1)
    leaq    ___x86_data_payload_path(%rip), %rdi  // RDI = dylib path address

    /*
     * Load dlopen Address
     * -------------------
     * Load the function address from our data section.
     */
    movq    ___x86_patch_dlopen(%rip), %rax  // Load dlopen address
    callq   *%rax                       // Call dlopen(path, RTLD_LAZY)

    /*
     * Record the Outcome
     * ------------------
     * dlopen returns a non-NULL handle on success, NULL on failure (with the
     * reason available from dlerror()).
     */
    testq   %rbx, %rbx
    je      ___x86_thread_entry_return
    movq    %rax, REPORT_HANDLE(%rbx)
    testq   %rax, %rax
    jne     ___x86_dlopen_succeeded

    movq    ___x86_patch_dlerror(%rip), %rax  // Load dlerror address
    callq   *%rax                       // Call dlerror()
    testq   %rax, %rax
    je      ___x86_dlopen_failed

    movq    %rax, %rsi                          // RSI = source cursor
    leaq    REPORT_ERROR_MESSAGE(%rbx), %rdi    // RDI = destination cursor
    movl    $(REPORT_ERROR_MESSAGE_SIZE - 1), %ecx

___x86_copy_error_message:
    testl   %ecx, %ecx
    je      ___x86_copy_error_message_done
    movb    (%rsi), %al
    movb    %al, (%rdi)
    incq    %rsi
    incq    %rdi
    testb   %al, %al
    je      ___x86_copy_error_message_done
    decl    %ecx
    jmp     ___x86_copy_error_message

___x86_copy_error_message_done:
    movb    $0x0, (%rdi)

___x86_dlopen_failed:
    mfence                              // Publish handle and message first
    movl    $0x2, REPORT_RESULT_CODE(%rbx)
    jmp     ___x86_thread_entry_return

___x86_dlopen_succeeded:
    mfence
    movl    $0x1, REPORT_RESULT_CODE(%rbx)

___x86_thread_entry_return:
    /*
     * Return from Thread
     * ------------------
     * The return value doesn't matter - the injector doesn't check it.
     */
    xorl    %eax, %eax                  // RAX = 0 (return value)
    addq    $0x8, %rsp                  // Undo the alignment padding
    popq    %rbx                        // Restore callee-saved register
    popq    %rbp                        // Restore frame pointer
    retq                                // Return from thread

/*
 * =============================================================================
 * RUNTIME PATCH LOCATIONS
 * =============================================================================
 *
 * These locations are filled at runtime by the injector with the actual
 * addresses of functions in the target process. Since ASLR randomizes
 * library load addresses, we can't know these addresses at compile time.
 *
 * The injector:
 * 1. Finds these functions in the target process using dlsym()
 * 2. Writes the addresses to these locations before starting the thread
 *
 * Each location is 8-byte aligned for atomic access on x86_64.
 */
    .align 3  // Align to 8-byte boundary
___x86_patch_pthread_create:
    .quad 0x0                           // Address of pthread_create_from_mach_thread

    .align 3
___x86_patch_dlopen:
    .quad 0x0                           // Address of dlopen

    .align 3
___x86_patch_dlerror:
    .quad 0x0                           // Address of dlerror

/*
 * =============================================================================
 * DATA SECTION
 * =============================================================================
 *
 * This buffer is filled at runtime by the injector with the path to the
 * dylib to inject. The maximum path length is 512 bytes including the
 * null terminator.
 */
    .align 3  // Align to 8-byte boundary
___x86_data_payload_path:
    .zero 0x200                         // 512 bytes for dylib path

    .align 3
___x86_data_report_address:
    .quad 0x0                           // Report block address in the target process

/*
 * End marker - used to calculate shellcode size: end - start
 */
___x86_shellcode_end:

#endif /* __x86_64__ */
