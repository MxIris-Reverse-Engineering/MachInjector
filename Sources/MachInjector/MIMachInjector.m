#import "MIMachInjector.h"
#include <Cocoa/Cocoa.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

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

kern_return_t (*_thread_convert_thread_state)(thread_act_t thread, int direction, thread_state_flavor_t flavor, thread_state_t in_state, mach_msg_type_number_t in_stateCnt, thread_state_t out_state, mach_msg_type_number_t *out_stateCnt);
#endif

NSErrorDomain const MIMachInjectorErrorDomain = @"MIMachInjectorErrorDomain";

//
// :Attribution
//
// The arm64e injection path is based on work by Jeremy Legendre (https://github.com/jslegendre)
//

static char shell_code[] =
#ifdef __x86_64__
"\x55"                             // push       rbp
"\x48\x89\xE5"                     // mov        rbp, rsp
"\x48\x83\xEC\x10"                 // sub        rsp, 0x10
"\x48\x8D\x7D\xF8"                 // lea        rdi, qword [rbp+var_8]
"\x31\xC0"                         // xor        eax, eax
"\x89\xC1"                         // mov        ecx, eax
"\x48\x8D\x15\x1E\x00\x00\x00"     // lea        rdx, qword ptr [rip+0x1E]
"\x48\x89\xCE"                     // mov        rsi, rcx
"\x48\xB8"                         // movabs     rax, pthread_create_from_mach_thread
"\x00\x00\x00\x00\x00\x00\x00\x00" //
"\xFF\xD0"                         // call       rax
"\x48\x83\xC4\x10"                 // add        rsp, 0x10
"\x5D"                             // pop        rbp
"\x48\xC7\xC0\x65\x62\x61\x79"     // mov        rax, 0x79616265
"\xEB\xFE"                         // jmp        0x0
"\xC3"                             // ret
"\x55"                             // push       rbp
"\x48\x89\xE5"                     // mov        rbp, rsp
"\xBE\x01\x00\x00\x00"             // mov        esi, 0x1
"\x48\x8D\x3D\x16\x00\x00\x00"     // lea        rdi, qword ptr [rip+0x16]
"\x48\xB8"                         // movabs     rax, dlopen
"\x00\x00\x00\x00\x00\x00\x00\x00" //
"\xFF\xD0"                         // call       rax
"\x31\xF6"                         // xor        esi, esi
"\x89\xF7"                         // mov        edi, esi
"\x48\x89\xF8"                     // mov        rax, rdi
"\x5D"                             // pop        rbp
"\xC3"                             // ret
#elif __arm64__
"\xFF\xC3\x00\xD1"                 // sub        sp, sp, #0x30
"\xFD\x7B\x02\xA9"                 // stp        x29, x30, [sp, #0x20]
"\xFD\x83\x00\x91"                 // add        x29, sp, #0x20
"\xA0\xC3\x1F\xB8"                 // stur       w0, [x29, #-0x4]
"\xE1\x0B\x00\xF9"                 // str        x1, [sp, #0x10]
"\xE0\x23\x00\x91"                 // add        x0, sp, #0x8
"\x08\x00\x80\xD2"                 // mov        x8, #0
"\xE8\x07\x00\xF9"                 // str        x8, [sp, #0x8]
"\xE1\x03\x08\xAA"                 // mov        x1, x8
"\xE2\x01\x00\x10"                 // adr        x2, #0x3C
"\xE2\x23\xC1\xDA"                 // paciza     x2
"\xE3\x03\x08\xAA"                 // mov        x3, x8
"\x49\x01\x00\x10"                 // adr        x9, #0x28 ; pthread_create_from_mach_thread
"\x29\x01\x40\xF9"                 // ldr        x9, [x9]
"\x20\x01\x3F\xD6"                 // blr        x9
"\xA0\x4C\x8C\xD2"                 // movz       x0, #0x6265
"\x20\x2C\xAF\xF2"                 // movk       x0, #0x7961, lsl #16
"\x09\x00\x00\x10"                 // adr        x9, #0
"\x20\x01\x1F\xD6"                 // br         x9
"\xFD\x7B\x42\xA9"                 // ldp        x29, x30, [sp, #0x20]
"\xFF\xC3\x00\x91"                 // add        sp, sp, #0x30
"\xC0\x03\x5F\xD6"                 // ret
"\x00\x00\x00\x00\x00\x00\x00\x00" //
"\x7F\x23\x03\xD5"                 // pacibsp
"\xFF\xC3\x00\xD1"                 // sub        sp, sp, #0x30
"\xFD\x7B\x02\xA9"                 // stp        x29, x30, [sp, #0x20]
"\xFD\x83\x00\x91"                 // add        x29, sp, #0x20
"\xA0\xC3\x1F\xB8"                 // stur       w0, [x29, #-0x4]
"\xE1\x0B\x00\xF9"                 // str        x1, [sp, #0x10]
"\x21\x00\x80\xD2"                 // mov        x1, #1
"\x60\x01\x00\x10"                 // adr        x0, #0x2c ; payload_path
"\x09\x01\x00\x10"                 // adr        x9, #0x20 ; dlopen
"\x29\x01\x40\xF9"                 // ldr        x9, [x9]
"\x20\x01\x3F\xD6"                 // blr        x9
"\x09\x00\x80\x52"                 // mov        w9, #0
"\xE0\x03\x09\xAA"                 // mov        x0, x9
"\xFD\x7B\x42\xA9"                 // ldp        x29, x30, [sp, #0x20]
"\xFF\xC3\x00\x91"                 // add        sp, sp, #0x30
"\xFF\x0F\x5F\xD6"                 // retab
"\x00\x00\x00\x00\x00\x00\x00\x00" //
#endif
"\x00\x00\x00\x00\x00\x00\x00\x00" // empty space for payload_path
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";


NSError *MIMachInjectorErrorMake(NSString *description, ...) {
    va_list args;
    va_start(args, description);
    description = [[NSString alloc] initWithFormat:description arguments:args];
    va_end(args);
    return [NSError errorWithDomain:MIMachInjectorErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
}

@implementation MIMachInjector

+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)outError {
    BOOL result = YES;
    mach_port_t task = 0;
    thread_act_t thread = 0;
    mach_vm_address_t code = 0;
    mach_vm_address_t stack = 0;
    vm_size_t stack_size = 16 * 1024;
    uint64_t stack_contents = 0x00000000CAFEBABE;
    
    // 定义变量作用域，防止编译错误
    char *sandbox_token = NULL;

    // 辅助宏：统一处理错误返回和内存释放
    #define RETURN_ERROR(fmt, ...) do { \
        if (outError) *outError = MIMachInjectorErrorMake(fmt, ##__VA_ARGS__); \
        if (sandbox_token) free(sandbox_token); \
        return NO; \
    } while(0)
#ifdef __arm64__
    // 1. 获取沙盒 Token
    sandbox_token = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath.UTF8String, 0);
    if (!sandbox_token) {
        RETURN_ERROR(@"Warning: could not issue sandbox extension token\n");
    }
#endif
    if (!pid) RETURN_ERROR(@"could not locate pid");

    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not retrieve task port for pid: %d", pid);
    }

    if (mach_vm_allocate(task, &stack, stack_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not allocate stack segment");
    }

    if (mach_vm_write(task, stack, (vm_address_t) &stack_contents, sizeof(uint64_t)) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not copy dummy return address into stack segment");
    }

    if (vm_protect(task, stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not change protection for stack segment");
    }

#ifdef __x86_64__
    // --- x86_64 逻辑 (保持不变，增加 malloc 保护) ---
    vm_size_t code_size = sizeof(shell_code);
    if (mach_vm_allocate(task, &code, code_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not allocate code segment");
    }
    
    // 创建本地副本
    char *local_shellcode = malloc(code_size);
    if (!local_shellcode) RETURN_ERROR(@"malloc failed");
    memcpy(local_shellcode, shell_code, code_size);

    uint64_t pcfmt_address = (uint64_t) dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    uint64_t dlopen_address = (uint64_t) dlsym(RTLD_DEFAULT, "dlopen");

    memcpy(local_shellcode + 28, &pcfmt_address, sizeof(uint64_t));
    memcpy(local_shellcode + 71, &dlopen_address, sizeof(uint64_t));
    
    // 简单的长度保护
    if (strlen(dylibPath.UTF8String) > 200) {
        free(local_shellcode);
        RETURN_ERROR(@"dylib path too long for x86 shellcode");
    }
    memcpy(local_shellcode + 90, dylibPath.UTF8String, strlen(dylibPath.UTF8String));
    
    if (mach_vm_write(task, code, (vm_address_t) local_shellcode, (mach_msg_type_number_t)code_size) != KERN_SUCCESS) {
        free(local_shellcode);
        RETURN_ERROR(@"could not copy shellcode into code segment");
    }
    free(local_shellcode);

    if (vm_protect(task, code, code_size, 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not change protection for code segment");
    }

#elif __arm64__
    // --- ARM64 逻辑 (集成沙盒功能) ---
    
    // 1. 计算大小和偏移量 (保持原变量名)
    const uintptr_t SHELLCODE_SIZE = __shellcode_end - __shellcode_start;
    const uintptr_t PTHREAD_CREATE = __patch_pthread_create - __shellcode_start;
    const uintptr_t SANDBOX_CONSUME = __patch_sandbox_consume - __shellcode_start;
    const uintptr_t DLOPEN = __patch_dlopen - __shellcode_start;
    const uintptr_t PAYLOAD_PATH = __data_payload_path - __shellcode_start;
    const uintptr_t SANDBOX_TOKEN = __data_sandbox_token - __shellcode_start;

    if (mach_vm_allocate(task, &code, SHELLCODE_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not allocate code segment");
    }
    
    // [关键修正] 创建本地缓冲区 local_shellcode
    // 不能直接修改 __shellcode_start，因为那是只读内存
    unsigned char *local_shellcode = malloc(SHELLCODE_SIZE);
    if (!local_shellcode) RETURN_ERROR(@"malloc failed");
    
    // 将原始汇编模板复制到本地缓冲区
    memcpy(local_shellcode, __shellcode_start, SHELLCODE_SIZE);
    
    // 获取函数地址
    uint64_t pcfmt_address = (uint64_t) ptrauth_strip(dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread"), ptrauth_key_function_pointer);
    uint64_t dlopen_address = (uint64_t) ptrauth_strip(dlsym(RTLD_DEFAULT, "dlopen"), ptrauth_key_function_pointer);
    uint64_t sandbox_consume_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "sandbox_extension_consume"), ptrauth_key_function_pointer);
    
    // 填充函数地址 (修改的是 local_shellcode)
    memcpy(local_shellcode + PTHREAD_CREATE, &pcfmt_address, sizeof(uint64_t));
    memcpy(local_shellcode + SANDBOX_CONSUME, &sandbox_consume_address, sizeof(uint64_t));
    memcpy(local_shellcode + DLOPEN, &dlopen_address, sizeof(uint64_t));
    
    // 填充路径 (带长度检查)
    size_t pathLen = strlen(dylibPath.UTF8String);
    if (pathLen < 0x500) {
        memcpy(local_shellcode + PAYLOAD_PATH, dylibPath.UTF8String, pathLen + 1);
    } else {
        free(local_shellcode);
        RETURN_ERROR(@"dylib path too long");
    }
    
    // 填充 Token (带长度检查)
    if (sandbox_token) {
        size_t tokenLen = strlen(sandbox_token);
        if (tokenLen < 0x500) {
            memcpy(local_shellcode + SANDBOX_TOKEN, sandbox_token, tokenLen + 1);
        } else {
            RETURN_ERROR(@"Warning: Sandbox token too long, skipping.\n");
        }
    }
    
    // 写入目标进程
    if (mach_vm_write(task, code, (vm_address_t)local_shellcode, (mach_msg_type_number_t)SHELLCODE_SIZE) != KERN_SUCCESS) {
        free(local_shellcode);
        RETURN_ERROR(@"could not copy shellcode into code segment");
    }
    free(local_shellcode); // 释放本地缓冲区

    if (vm_protect(task, code, SHELLCODE_SIZE, 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
        RETURN_ERROR(@"could not change protection for code segment");
    }
#endif

    // 释放 Host 端的 Token
    if (sandbox_token) {
        free(sandbox_token);
        sandbox_token = NULL;
    }

    // --- 线程创建逻辑 (保持不变) ---

#ifdef __x86_64__
    x86_thread_state64_t thread_state = {};
    thread_state_flavor_t thread_flavor = x86_THREAD_STATE64;
    mach_msg_type_number_t thread_flavor_count = x86_THREAD_STATE64_COUNT;

    thread_state.__rip = (uint64_t) code;
    thread_state.__rsp = (uint64_t) stack + (stack_size / 2);

    kern_return_t error = thread_create_running(task, thread_flavor, (thread_state_t)&thread_state, thread_flavor_count, &thread);
    if (error != KERN_SUCCESS) {
        if (outError) *outError = MIMachInjectorErrorMake(@"could not spawn remote thread: %s", mach_error_string(error));
        return NO;
    }
#elif __arm64__
    void *handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
    if (handle) {
        _thread_convert_thread_state = dlsym(handle, "thread_convert_thread_state");
        dlclose(handle);
    }

    if (!_thread_convert_thread_state) {
        RETURN_ERROR(@"could not load symbol: thread_convert_thread_state");
    }

    arm_thread_state64_t thread_state = {}, machine_thread_state = {};
    thread_state_flavor_t thread_flavor = ARM_THREAD_STATE64;
    mach_msg_type_number_t thread_flavor_count = ARM_THREAD_STATE64_COUNT, machine_thread_flavor_count = ARM_THREAD_STATE64_COUNT;

    __darwin_arm_thread_state64_set_pc_fptr(thread_state, ptrauth_sign_unauthenticated((void *) code, ptrauth_key_asia, 0));
    __darwin_arm_thread_state64_set_sp(thread_state, stack + (stack_size / 2));

    kern_return_t error = thread_create(task, &thread);
    if (error != KERN_SUCCESS) {
        RETURN_ERROR(@"could not create remote thread: %s", mach_error_string(error));
    }

    error = _thread_convert_thread_state(thread, 2, thread_flavor, (thread_state_t) &thread_state, thread_flavor_count, (thread_state_t) &machine_thread_state, &machine_thread_flavor_count);
    if (error != KERN_SUCCESS) {
        RETURN_ERROR(@"could not convert thread state: %s", mach_error_string(error));
    }

    NSOperatingSystemVersion os_version = [[NSProcessInfo processInfo] operatingSystemVersion];
    if ((os_version.majorVersion == 14 && os_version.minorVersion >= 4) ||
        (os_version.majorVersion >= 15)) {
        thread_terminate(thread);
        error = thread_create_running(task, thread_flavor, (thread_state_t)&machine_thread_state, machine_thread_flavor_count, &thread);
        if (error != KERN_SUCCESS) {
            RETURN_ERROR(@"could not spawn remote thread: %s", mach_error_string(error));
        }
    } else {
        error = thread_set_state(thread, thread_flavor, (thread_state_t)&machine_thread_state, machine_thread_flavor_count);
        if (error != KERN_SUCCESS) {
            RETURN_ERROR(@"could not set thread state: %s", mach_error_string(error));
        }

        error = thread_resume(thread);
        if (error != KERN_SUCCESS) {
            RETURN_ERROR(@"could not resume remote thread: %s", mach_error_string(error));
        }
    }
#endif

    usleep(10000);

    for (int i = 0; i < 10; ++i) {
        kern_return_t error = thread_get_state(thread, thread_flavor, (thread_state_t)&thread_state, &thread_flavor_count);

        if (error != KERN_SUCCESS) {
            result = NO;
            goto terminate;
        }

#ifdef __x86_64__
        if (thread_state.__rax == 0x79616265) {
#elif __arm64__
        if (thread_state.__x[0] == 0x444f4e45) {
#endif
            result = YES;
            goto terminate;
        }

        usleep(20000);
    }
    
    // 超时
    result = NO;
    if (outError) *outError = MIMachInjectorErrorMake(@"injection timed out");

terminate:
    error = thread_terminate(thread);
    if (error != KERN_SUCCESS) {
        RETURN_ERROR(@"failed to terminate remote thread: %s\n", mach_error_string(error));
    }
    
    return result;
}

@end

//#import "MIMachInjector.h"
//#include <Cocoa/Cocoa.h>
//#include <mach/mach.h>
//#include <mach/mach_vm.h>
//#include <dlfcn.h>
//#include <stdio.h>
//#include <unistd.h>
//
//#ifdef __arm64__
//
//#include <ptrauth.h>
//#include <sys/sysctl.h>
//
//extern const char *const APP_SANDBOX_READ;
//extern char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);
//
//extern char __shellcode_start[];
//extern char __shellcode_end[];
//extern char __patch_pthread_create[];
//extern char __patch_sandbox_consume[];
//extern char __patch_dlopen[];
//extern char __data_payload_path[];
//extern char __data_sandbox_token[];
//
//kern_return_t (*_thread_convert_thread_state)(thread_act_t thread, int direction, thread_state_flavor_t flavor, thread_state_t in_state, mach_msg_type_number_t in_stateCnt, thread_state_t out_state, mach_msg_type_number_t *out_stateCnt);
//#endif
//
//NSErrorDomain const MIMachInjectorErrorDomain = @"MIMachInjectorErrorDomain";
//
////
//// :Attribution
////
//// The arm64e injection path is based on work by Jeremy Legendre (https://github.com/jslegendre)
////
//
//static char shell_code[] =
//#ifdef __x86_64__
//"\x55"                             // push       rbp
//"\x48\x89\xE5"                     // mov        rbp, rsp
//"\x48\x83\xEC\x10"                 // sub        rsp, 0x10
//"\x48\x8D\x7D\xF8"                 // lea        rdi, qword [rbp+var_8]
//"\x31\xC0"                         // xor        eax, eax
//"\x89\xC1"                         // mov        ecx, eax
//"\x48\x8D\x15\x1E\x00\x00\x00"     // lea        rdx, qword ptr [rip+0x1E]
//"\x48\x89\xCE"                     // mov        rsi, rcx
//"\x48\xB8"                         // movabs     rax, pthread_create_from_mach_thread
//"\x00\x00\x00\x00\x00\x00\x00\x00" //
//"\xFF\xD0"                         // call       rax
//"\x48\x83\xC4\x10"                 // add        rsp, 0x10
//"\x5D"                             // pop        rbp
//"\x48\xC7\xC0\x65\x62\x61\x79"     // mov        rax, 0x79616265
//"\xEB\xFE"                         // jmp        0x0
//"\xC3"                             // ret
//"\x55"                             // push       rbp
//"\x48\x89\xE5"                     // mov        rbp, rsp
//"\xBE\x01\x00\x00\x00"             // mov        esi, 0x1
//"\x48\x8D\x3D\x16\x00\x00\x00"     // lea        rdi, qword ptr [rip+0x16]
//"\x48\xB8"                         // movabs     rax, dlopen
//"\x00\x00\x00\x00\x00\x00\x00\x00" //
//"\xFF\xD0"                         // call       rax
//"\x31\xF6"                         // xor        esi, esi
//"\x89\xF7"                         // mov        edi, esi
//"\x48\x89\xF8"                     // mov        rax, rdi
//"\x5D"                             // pop        rbp
//"\xC3"                             // ret
//#elif __arm64__
//"\xFF\xC3\x00\xD1"                 // sub        sp, sp, #0x30
//"\xFD\x7B\x02\xA9"                 // stp        x29, x30, [sp, #0x20]
//"\xFD\x83\x00\x91"                 // add        x29, sp, #0x20
//"\xA0\xC3\x1F\xB8"                 // stur       w0, [x29, #-0x4]
//"\xE1\x0B\x00\xF9"                 // str        x1, [sp, #0x10]
//"\xE0\x23\x00\x91"                 // add        x0, sp, #0x8
//"\x08\x00\x80\xD2"                 // mov        x8, #0
//"\xE8\x07\x00\xF9"                 // str        x8, [sp, #0x8]
//"\xE1\x03\x08\xAA"                 // mov        x1, x8
//"\xE2\x01\x00\x10"                 // adr        x2, #0x3C
//"\xE2\x23\xC1\xDA"                 // paciza     x2
//"\xE3\x03\x08\xAA"                 // mov        x3, x8
//"\x49\x01\x00\x10"                 // adr        x9, #0x28 ; pthread_create_from_mach_thread
//"\x29\x01\x40\xF9"                 // ldr        x9, [x9]
//"\x20\x01\x3F\xD6"                 // blr        x9
//"\xA0\x4C\x8C\xD2"                 // movz       x0, #0x6265
//"\x20\x2C\xAF\xF2"                 // movk       x0, #0x7961, lsl #16
//"\x09\x00\x00\x10"                 // adr        x9, #0
//"\x20\x01\x1F\xD6"                 // br         x9
//"\xFD\x7B\x42\xA9"                 // ldp        x29, x30, [sp, #0x20]
//"\xFF\xC3\x00\x91"                 // add        sp, sp, #0x30
//"\xC0\x03\x5F\xD6"                 // ret
//"\x00\x00\x00\x00\x00\x00\x00\x00" //
//"\x7F\x23\x03\xD5"                 // pacibsp
//"\xFF\xC3\x00\xD1"                 // sub        sp, sp, #0x30
//"\xFD\x7B\x02\xA9"                 // stp        x29, x30, [sp, #0x20]
//"\xFD\x83\x00\x91"                 // add        x29, sp, #0x20
//"\xA0\xC3\x1F\xB8"                 // stur       w0, [x29, #-0x4]
//"\xE1\x0B\x00\xF9"                 // str        x1, [sp, #0x10]
//"\x21\x00\x80\xD2"                 // mov        x1, #1
//"\x60\x01\x00\x10"                 // adr        x0, #0x2c ; payload_path
//"\x09\x01\x00\x10"                 // adr        x9, #0x20 ; dlopen
//"\x29\x01\x40\xF9"                 // ldr        x9, [x9]
//"\x20\x01\x3F\xD6"                 // blr        x9
//"\x09\x00\x80\x52"                 // mov        w9, #0
//"\xE0\x03\x09\xAA"                 // mov        x0, x9
//"\xFD\x7B\x42\xA9"                 // ldp        x29, x30, [sp, #0x20]
//"\xFF\xC3\x00\x91"                 // add        sp, sp, #0x30
//"\xFF\x0F\x5F\xD6"                 // retab
//"\x00\x00\x00\x00\x00\x00\x00\x00" //
//#endif
//"\x00\x00\x00\x00\x00\x00\x00\x00" // empty space for payload_path
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00"
//"\x00\x00\x00\x00\x00\x00\x00\x00";
//
//
//NSError *MIMachInjectorErrorMake(NSString *description, ...) {
//    va_list args;
//    va_start(args, description);
//    description = [[NSString alloc] initWithFormat:description arguments:args];
//    va_end(args);
//    return [NSError errorWithDomain:MIMachInjectorErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: description}];
//}
//
//@implementation MIMachInjector
//
//+ (BOOL)injectToPID:(pid_t)pid dylibPath:(NSString *)dylibPath error:(NSError * _Nullable __autoreleasing * _Nullable)outError {
//    BOOL result = YES;
//    mach_port_t task = 0;
//    thread_act_t thread = 0;
//    mach_vm_address_t code = 0;
//    mach_vm_address_t stack = 0;
//    vm_size_t stack_size = 16 * 1024;
//    uint64_t stack_contents = 0x00000000CAFEBABE;
//    
//#ifdef __arm64__
//    char *sandbox_token = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath.UTF8String, 0);
//    if (!sandbox_token) {
////        NSLog(@"could not issue sandbox extension token");
//        *outError = MIMachInjectorErrorMake(@"could not issue sandbox extension token");
//        return NO;
//    }
//#endif
//    
//    if (!pid) {
//        *outError = MIMachInjectorErrorMake(@"could not locate pid");
//        return NO;
//    }
//
//    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not retrieve task port for pid: %d", pid);
//        return NO;
//    }
//
//    if (mach_vm_allocate(task, &stack, stack_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not allocate stack segment");
//        return NO;
//    }
//
//    if (mach_vm_write(task, stack, (vm_address_t) &stack_contents, sizeof(uint64_t)) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not copy dummy return address into stack segment");
//        return NO;
//    }
//
//    if (vm_protect(task, stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not change protection for stack segment");
//        return NO;
//    }
//
//#ifdef __x86_64__
//    if (mach_vm_allocate(task, &code, sizeof(shell_code), VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not allocate code segment");
//        return NO;
//    }
//    uint64_t pcfmt_address = (uint64_t) dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
//    uint64_t dlopen_address = (uint64_t) dlsym(RTLD_DEFAULT, "dlopen");
//
//    memcpy(shell_code + 28, &pcfmt_address, sizeof(uint64_t));
//    memcpy(shell_code + 71, &dlopen_address, sizeof(uint64_t));
//    memcpy(shell_code + 90, dylibPath.UTF8String, strlen(dylibPath.UTF8String));
//    if (mach_vm_write(task, code, (vm_address_t) shell_code, sizeof(shell_code)) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not copy shellcode into code segment");
//        return NO;
//    }
//
//    if (vm_protect(task, code, sizeof(shell_code), 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not change protection for code segment");
//        return NO;
//    }
//#elif __arm64__
//    
//    unsigned char *SHELLCODE = (unsigned char *)__shellcode_start;
//    const uintptr_t SHELLCODE_SIZE = __shellcode_end - __shellcode_start;
//    const uintptr_t PTHREAD_CREATE = __patch_pthread_create - __shellcode_start;
//    const uintptr_t SANDBOX_CONSUME = __patch_sandbox_consume - __shellcode_start;
//    const uintptr_t DLOPEN = __patch_dlopen - __shellcode_start;
//    const uintptr_t PAYLOAD_PATH = __data_payload_path - __shellcode_start;
//    const uintptr_t SANDBOX_TOKEN = __data_sandbox_token - __shellcode_start;
//    if (mach_vm_allocate(task, &code, SHELLCODE_SIZE, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not allocate code segment");
//        return NO;
//    }
//    uint64_t pcfmt_address = (uint64_t) ptrauth_strip(dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread"), ptrauth_key_function_pointer);
//    uint64_t dlopen_address = (uint64_t) ptrauth_strip(dlsym(RTLD_DEFAULT, "dlopen"), ptrauth_key_function_pointer);
//    uint64_t sandbox_consume_address = (uint64_t)ptrauth_strip(dlsym(RTLD_DEFAULT, "sandbox_extension_consume"), ptrauth_key_function_pointer);
//    
//    memcpy(SHELLCODE + PTHREAD_CREATE, &pcfmt_address, sizeof(uint64_t));
//    memcpy(SHELLCODE + SANDBOX_CONSUME, &sandbox_consume_address, sizeof(uint64_t));
//    memcpy(SHELLCODE + DLOPEN, &dlopen_address, sizeof(uint64_t));
//    memcpy(SHELLCODE + PAYLOAD_PATH, dylibPath.UTF8String, strlen(dylibPath.UTF8String));
//    memcpy(SHELLCODE + SANDBOX_TOKEN, sandbox_token, strlen(sandbox_token));
//    if (mach_vm_write(task, code, (vm_address_t)SHELLCODE, (mach_msg_type_number_t)SHELLCODE_SIZE) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not copy shellcode into code segment");
//        return NO;
//    }
//
//    if (vm_protect(task, code, SHELLCODE_SIZE, 0, VM_PROT_EXECUTE | VM_PROT_READ) != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not change protection for code segment");
//        return NO;
//    }
//#endif
//
//
//
//#ifdef __x86_64__
//    x86_thread_state64_t thread_state = {};
//    thread_state_flavor_t thread_flavor = x86_THREAD_STATE64;
//    mach_msg_type_number_t thread_flavor_count = x86_THREAD_STATE64_COUNT;
//
//    thread_state.__rip = (uint64_t) code;
//    thread_state.__rsp = (uint64_t) stack + (stack_size / 2);
//
//    kern_return_t error = thread_create_running(task, thread_flavor, (thread_state_t)&thread_state, thread_flavor_count, &thread);
//    if (error != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not spawn remote thread: %s", mach_error_string(error));
//        return NO;
//    }
//#elif __arm64__
//    void *handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_GLOBAL | RTLD_LAZY);
//    if (handle) {
//        _thread_convert_thread_state = dlsym(handle, "thread_convert_thread_state");
//        dlclose(handle);
//    }
//
//    if (!_thread_convert_thread_state) {
//        *outError = MIMachInjectorErrorMake(@"could not load symbol: thread_convert_thread_state");
//        return NO;
//    }
//
//    arm_thread_state64_t thread_state = {}, machine_thread_state = {};
//    thread_state_flavor_t thread_flavor = ARM_THREAD_STATE64;
//    mach_msg_type_number_t thread_flavor_count = ARM_THREAD_STATE64_COUNT, machine_thread_flavor_count = ARM_THREAD_STATE64_COUNT;
//
//    __darwin_arm_thread_state64_set_pc_fptr(thread_state, ptrauth_sign_unauthenticated((void *) code, ptrauth_key_asia, 0));
//    __darwin_arm_thread_state64_set_sp(thread_state, stack + (stack_size / 2));
//
//    kern_return_t error = thread_create(task, &thread);
//    if (error != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not create remote thread: %s", mach_error_string(error));
//        return NO;
//    }
//
//    error = _thread_convert_thread_state(thread, 2, thread_flavor, (thread_state_t) &thread_state, thread_flavor_count, (thread_state_t) &machine_thread_state, &machine_thread_flavor_count);
//    if (error != KERN_SUCCESS) {
//        *outError = MIMachInjectorErrorMake(@"could not convert thread state: %s", mach_error_string(error));
//        return NO;
//    }
//
//    NSOperatingSystemVersion os_version = [[NSProcessInfo processInfo] operatingSystemVersion];
//    if ((os_version.majorVersion == 14 && os_version.minorVersion >= 4) ||
//        (os_version.majorVersion >= 15)) {
//        thread_terminate(thread);
//        error = thread_create_running(task, thread_flavor, (thread_state_t)&machine_thread_state, machine_thread_flavor_count, &thread);
//        if (error != KERN_SUCCESS) {
//            *outError = MIMachInjectorErrorMake(@"could not spawn remote thread: %s", mach_error_string(error));
//            return NO;
//        }
//    } else {
//        error = thread_set_state(thread, thread_flavor, (thread_state_t)&machine_thread_state, machine_thread_flavor_count);
//        if (error != KERN_SUCCESS) {
//            *outError = MIMachInjectorErrorMake(@"could not set thread state: %s", mach_error_string(error));
//            return NO;
//        }
//
//        error = thread_resume(thread);
//        if (error != KERN_SUCCESS) {
//            *outError = MIMachInjectorErrorMake(@"could not resume remote thread: %s", mach_error_string(error));
//            return NO;
//        }
//    }
//#endif
//
//    usleep(10000);
//
//    for (int i = 0; i < 10; ++i) {
//        kern_return_t error = thread_get_state(thread, thread_flavor, (thread_state_t)&thread_state, &thread_flavor_count);
//
//        if (error != KERN_SUCCESS) {
//            result = NO;
//            goto terminate;
//        }
//
//#ifdef __x86_64__
//        if (thread_state.__rax == 0x79616265) {
//#elif __arm64__
//        if (thread_state.__x[0] == 0x444f4e45) {
//#endif
//            result = YES;
//            goto terminate;
//        }
//
//        usleep(20000);
//    }
//
//terminate:
//        error = thread_terminate(thread);
//        if (error != KERN_SUCCESS) {
//            *outError = MIMachInjectorErrorMake(@"failed to terminate remote thread: %s", mach_error_string(error));
//        }
//#ifdef __arm64__
//        if (sandbox_token) {
//            free(sandbox_token);
//        }
//#endif
//    return result;
//}
//
//@end
