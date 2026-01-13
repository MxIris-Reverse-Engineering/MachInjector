/*
 * MIT License
 *
 * Copyright (c) 2024 kekeimiku
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

.section __DATA, __data

// Export symbols for C code to reference
.global ___shellcode_start
.global ___shellcode_end
.global ___patch_pthread_create
.global ___patch_sandbox_consume
.global ___patch_dlopen
.global ___data_payload_path
.global ___data_sandbox_token

// Shellcode entry point
// Called from remote thread created by thread_create_running
___shellcode_start:
    sub sp, sp, #0x30
    stp x29, x30, [sp, #0x20]
    add x29, sp, #0x20

    stur w0, [x29, #-0x4]
    str  x1, [sp, #0x10]

    // Prepare arguments for pthread_create_from_mach_thread
    add    x0, sp, #0x8           // &thread (output)
    mov    x8, #0
    str    x8, [sp, #0x8]
    mov    x1, x8                 // attr = NULL
    adr    x2, __thread_entry     // start_routine
    paciza x2                     // Sign the function pointer
    mov    x3, x8                 // arg = NULL

    // Call pthread_create_from_mach_thread
    adr x9, ___patch_pthread_create
    ldr x9, [x9]
    blr x9

    // Set completion signal: "DONE" (0x444f4e45) in little-endian
    movz x0, #0x4e45              // "NE"
    movk x0, #0x444f, lsl #16     // "DO"

    // Infinite loop - wait for host to read completion status
    b .

    .align 4
// Thread entry point - runs in the newly created pthread
__thread_entry:
    pacibsp
    sub sp, sp, #0x30
    stp x29, x30, [sp, #0x20]
    add x29, sp, #0x20

    stur w0, [x29, #-0x4]
    str  x1, [sp, #0x10]

    // Consume sandbox extension token to gain file access
    adr x0, ___data_sandbox_token
    adr x9, ___patch_sandbox_consume
    ldr x9, [x9]
    blr x9

    // Call dlopen to load the target dylib
    mov x1, #1                    // RTLD_LAZY
    adr x0, ___data_payload_path  // dylib path
    adr x9, ___patch_dlopen
    ldr x9, [x9]
    blr x9

    // Return from thread
    ldp x29, x30, [sp, #0x20]
    add sp, sp, #0x30
    retab

// Patch locations for function addresses (filled at runtime)
    .align 3
___patch_pthread_create:
    .quad 0x0

    .align 3
___patch_sandbox_consume:
    .quad 0x0

    .align 3
___patch_dlopen:
    .quad 0x0

// Data buffers (filled at runtime)
    .align 3
___data_payload_path:
    .zero 0x500                   // 1280 bytes for dylib path

    .align 3
___data_sandbox_token:
    .zero 0x500                   // 1280 bytes for sandbox token

___shellcode_end:

#endif
