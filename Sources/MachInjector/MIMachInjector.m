#import "MIMachInjector.h"
#include <Cocoa/Cocoa.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

// Completion magic number: "DONE" in little-endian (0x444f4e45)
#define MI_INJECTION_DONE 0x444f4e45

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
extern char __data_payload_path[];
extern char __data_sandbox_token[];

static kern_return_t (*_thread_convert_thread_state)(thread_act_t thread, int direction, thread_state_flavor_t flavor, thread_state_t in_state, mach_msg_type_number_t in_stateCnt, thread_state_t out_state, mach_msg_type_number_t *out_stateCnt);

#else // __x86_64__

// x86_64 shellcode for dylib injection.
// Creates a new thread via pthread_create_from_mach_thread,
// then the new thread calls dlopen to load the target dylib.
static char x86_shellcode[] =
    "\x55"                             // push       rbp
    "\x48\x89\xE5"                     // mov        rbp, rsp
    "\x48\x83\xEC\x10"                 // sub        rsp, 0x10
    "\x48\x8D\x7D\xF8"                 // lea        rdi, qword [rbp+var_8]
    "\x31\xC0"                         // xor        eax, eax
    "\x89\xC1"                         // mov        ecx, eax
    "\x48\x8D\x15\x1E\x00\x00\x00"     // lea        rdx, qword ptr [rip+0x1E]
    "\x48\x89\xCE"                     // mov        rsi, rcx
    "\x48\xB8"                         // movabs     rax, pthread_create_from_mach_thread
    "\x00\x00\x00\x00\x00\x00\x00\x00" // [PATCH: pthread_create address at offset 28]
    "\xFF\xD0"                         // call       rax
    "\x48\x83\xC4\x10"                 // add        rsp, 0x10
    "\x5D"                             // pop        rbp
    "\x48\xC7\xC0\x45\x4e\x4f\x44"     // mov        rax, MI_INJECTION_DONE (0x444f4e45)
    "\xEB\xFE"                         // jmp        0x0 (infinite loop)
    "\xC3"                             // ret
    "\x55"                             // push       rbp (thread entry point)
    "\x48\x89\xE5"                     // mov        rbp, rsp
    "\xBE\x01\x00\x00\x00"             // mov        esi, 0x1 (RTLD_LAZY)
    "\x48\x8D\x3D\x16\x00\x00\x00"     // lea        rdi, qword ptr [rip+0x16] (payload_path)
    "\x48\xB8"                         // movabs     rax, dlopen
    "\x00\x00\x00\x00\x00\x00\x00\x00" // [PATCH: dlopen address at offset 71]
    "\xFF\xD0"                         // call       rax
    "\x31\xF6"                         // xor        esi, esi
    "\x89\xF7"                         // mov        edi, esi
    "\x48\x89\xF8"                     // mov        rax, rdi
    "\x5D"                             // pop        rbp
    "\xC3"                             // ret
    // Payload path buffer (512 bytes starting at offset 90)
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

// Shellcode patch offsets for x86_64
#define X86_PATCH_PTHREAD_CREATE  28
#define X86_PATCH_DLOPEN          71
#define X86_PAYLOAD_PATH_OFFSET   90
#define X86_MAX_PATH_LENGTH       512

#endif

NSErrorDomain const MIMachInjectorErrorDomain = @"MIMachInjectorErrorDomain";

//
// Attribution:
// The arm64e injection path is based on work by Jeremy Legendre (https://github.com/jslegendre)
//

static NSError *MIMachInjectorErrorMake(NSString *description, ...) {
    va_list args;
    va_start(args, description);
    description = [[NSString alloc] initWithFormat:description arguments:args];
    va_end(args);
    return [NSError errorWithDomain:MIMachInjectorErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
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
    vm_size_t stack_size = 16 * 1024;
    vm_size_t code_size = 0;

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
        error = MIMachInjectorErrorMake(@"invalid pid");
        goto cleanup;
    }

#ifdef __arm64__
    // Issue sandbox extension token for the dylib path
    sandbox_token = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath.UTF8String, 0);
    if (!sandbox_token) {
        error = MIMachInjectorErrorMake(@"could not issue sandbox extension token");
        goto cleanup;
    }
#endif

    // Get task port for target process
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not retrieve task port for pid: %d", pid);
        goto cleanup;
    }

    // Allocate stack in target process
    if (mach_vm_allocate(task, &stack, stack_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not allocate stack segment");
        goto cleanup;
    }

    // Write dummy return address to stack
    uint64_t stack_contents = 0x00000000CAFEBABE;
    if (mach_vm_write(task, stack, (vm_address_t)&stack_contents, sizeof(uint64_t)) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not write to stack segment");
        goto cleanup;
    }

    // Set stack protection
    if (vm_protect(task, stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not set stack protection");
        goto cleanup;
    }

#ifdef __x86_64__
    // x86_64: Prepare and inject shellcode
    code_size = sizeof(x86_shellcode);

    if (mach_vm_allocate(task, &code, code_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not allocate code segment");
        goto cleanup;
    }

    // Create local copy for patching
    local_shellcode = malloc(code_size);
    if (!local_shellcode) {
        error = MIMachInjectorErrorMake(@"malloc failed");
        goto cleanup;
    }
    memcpy(local_shellcode, x86_shellcode, code_size);

    // Patch function addresses
    uint64_t pcfmt_address = (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    uint64_t dlopen_address = (uint64_t)dlsym(RTLD_DEFAULT, "dlopen");

    memcpy(local_shellcode + X86_PATCH_PTHREAD_CREATE, &pcfmt_address, sizeof(uint64_t));
    memcpy(local_shellcode + X86_PATCH_DLOPEN, &dlopen_address, sizeof(uint64_t));

    // Copy dylib path with bounds check
    size_t pathLen = strlen(dylibPath.UTF8String);
    if (pathLen >= X86_MAX_PATH_LENGTH) {
        error = MIMachInjectorErrorMake(@"dylib path too long (max %d)", X86_MAX_PATH_LENGTH - 1);
        goto cleanup;
    }
    memcpy(local_shellcode + X86_PAYLOAD_PATH_OFFSET, dylibPath.UTF8String, pathLen + 1);

    // Write shellcode to target process
    if (mach_vm_write(task, code, (vm_address_t)local_shellcode, (mach_msg_type_number_t)code_size) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not write shellcode to target");
        goto cleanup;
    }

    // Set code segment as executable
    if (vm_protect(task, code, code_size, 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not set code protection");
        goto cleanup;
    }

    // Create and start remote thread
    thread_state.__rip = (uint64_t)code;
    thread_state.__rsp = (uint64_t)stack + (stack_size / 2);

    kern_return_t kr = thread_create_running(task, thread_flavor, (thread_state_t)&thread_state, thread_flavor_count, &thread);
    if (kr != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not create remote thread: %s", mach_error_string(kr));
        goto cleanup;
    }

#elif __arm64__
    // ARM64: Prepare and inject shellcode from external assembly
    const uintptr_t SHELLCODE_SIZE = __shellcode_end - __shellcode_start;
    const uintptr_t PTHREAD_CREATE_OFFSET = __patch_pthread_create - __shellcode_start;
    const uintptr_t SANDBOX_CONSUME_OFFSET = __patch_sandbox_consume - __shellcode_start;
    const uintptr_t DLOPEN_OFFSET = __patch_dlopen - __shellcode_start;
    const uintptr_t PAYLOAD_PATH_OFFSET = __data_payload_path - __shellcode_start;
    const uintptr_t SANDBOX_TOKEN_OFFSET = __data_sandbox_token - __shellcode_start;

    code_size = SHELLCODE_SIZE;

    if (mach_vm_allocate(task, &code, code_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not allocate code segment");
        goto cleanup;
    }

    // Create local copy for patching
    local_shellcode = malloc(SHELLCODE_SIZE);
    if (!local_shellcode) {
        error = MIMachInjectorErrorMake(@"malloc failed");
        goto cleanup;
    }
    memcpy(local_shellcode, __shellcode_start, SHELLCODE_SIZE);

    // Get function addresses (strip PAC signatures)
    uint64_t pcfmt_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread"), ptrauth_key_function_pointer);
    uint64_t dlopen_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "dlopen"), ptrauth_key_function_pointer);
    uint64_t sandbox_consume_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "sandbox_extension_consume"), ptrauth_key_function_pointer);

    // Patch function addresses
    memcpy(local_shellcode + PTHREAD_CREATE_OFFSET, &pcfmt_address, sizeof(uint64_t));
    memcpy(local_shellcode + SANDBOX_CONSUME_OFFSET, &sandbox_consume_address, sizeof(uint64_t));
    memcpy(local_shellcode + DLOPEN_OFFSET, &dlopen_address, sizeof(uint64_t));

    // Copy dylib path with bounds check
    size_t pathLen = strlen(dylibPath.UTF8String);
    if (pathLen >= 0x500) {
        error = MIMachInjectorErrorMake(@"dylib path too long");
        goto cleanup;
    }
    memcpy(local_shellcode + PAYLOAD_PATH_OFFSET, dylibPath.UTF8String, pathLen + 1);

    // Copy sandbox token with bounds check
    if (sandbox_token) {
        size_t tokenLen = strlen(sandbox_token);
        if (tokenLen >= 0x500) {
            error = MIMachInjectorErrorMake(@"sandbox token too long");
            goto cleanup;
        }
        memcpy(local_shellcode + SANDBOX_TOKEN_OFFSET, sandbox_token, tokenLen + 1);
    }

    // Write shellcode to target process
    if (mach_vm_write(task, code, (vm_address_t)local_shellcode, (mach_msg_type_number_t)SHELLCODE_SIZE) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not write shellcode to target");
        goto cleanup;
    }

    // Set code segment as executable
    if (vm_protect(task, code, SHELLCODE_SIZE, 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not set code protection");
        goto cleanup;
    }

    // Load thread_convert_thread_state from libsystem_kernel
    void *handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
    if (handle) {
        _thread_convert_thread_state = dlsym(handle, "thread_convert_thread_state");
        dlclose(handle);
    }

    if (!_thread_convert_thread_state) {
        error = MIMachInjectorErrorMake(@"could not load thread_convert_thread_state");
        goto cleanup;
    }

    // Set up thread state with PAC-signed PC
    __darwin_arm_thread_state64_set_pc_fptr(thread_state, ptrauth_sign_unauthenticated((void *)code, ptrauth_key_asia, 0));
    __darwin_arm_thread_state64_set_sp(thread_state, stack + (stack_size / 2));

    kern_return_t kr = thread_create(task, &thread);
    if (kr != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not create remote thread: %s", mach_error_string(kr));
        goto cleanup;
    }

    kr = _thread_convert_thread_state(thread, 2, thread_flavor, (thread_state_t)&thread_state, thread_flavor_count, (thread_state_t)&machine_thread_state, &machine_thread_flavor_count);
    if (kr != KERN_SUCCESS) {
        error = MIMachInjectorErrorMake(@"could not convert thread state: %s", mach_error_string(kr));
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
            error = MIMachInjectorErrorMake(@"could not start remote thread: %s", mach_error_string(kr));
            goto cleanup;
        }
    } else {
        // Earlier versions: set state and resume
        kr = thread_set_state(thread, thread_flavor, (thread_state_t)&machine_thread_state, machine_thread_flavor_count);
        if (kr != KERN_SUCCESS) {
            error = MIMachInjectorErrorMake(@"could not set thread state: %s", mach_error_string(kr));
            goto cleanup;
        }

        kr = thread_resume(thread);
        if (kr != KERN_SUCCESS) {
            error = MIMachInjectorErrorMake(@"could not resume remote thread: %s", mach_error_string(kr));
            goto cleanup;
        }
    }
#endif

    // Wait for injection to complete
    usleep(10000);

    for (int i = 0; i < 10; ++i) {
        // Reset count before each call (in/out parameter)
        mach_msg_type_number_t state_count = thread_flavor_count;
        kern_return_t kr = thread_get_state(thread, thread_flavor, (thread_state_t)&thread_state, &state_count);

        if (kr != KERN_SUCCESS) {
            error = MIMachInjectorErrorMake(@"could not get thread state: %s", mach_error_string(kr));
            goto cleanup;
        }

#ifdef __x86_64__
        if (thread_state.__rax == MI_INJECTION_DONE) {
#elif __arm64__
        if (thread_state.__x[0] == MI_INJECTION_DONE) {
#endif
            result = YES;
            goto cleanup;
        }

        usleep(20000);
    }

    // Timeout
    error = MIMachInjectorErrorMake(@"injection timed out");

cleanup:
    // Terminate remote thread
    if (thread != MACH_PORT_NULL) {
        thread_terminate(thread);
    }

    // Note: We intentionally do NOT deallocate stack and code segments
    // in the target process, as they may still be in use by the injected
    // thread or the loaded dylib. This is expected behavior for injection.

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
