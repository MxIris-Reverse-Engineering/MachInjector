// -----------------------------------------------------------------------------
// MITargetSymbolResolver.h — resolves symbols to addresses *inside a target
// process*, which may not share the injector's address space layout.
// -----------------------------------------------------------------------------
//
// NOT a public header: it sits beside the implementation rather than in
// `include/`, so it is absent from the MachInjector module. MachInjectorTests
// reaches it through a header search path, the same way MIMachInjectorInternal.h
// is reached.
//
// Why this exists at all. The injector patches three function addresses into its
// shellcode and lets the target execute them. It used to obtain them with
// `dlsym(RTLD_DEFAULT, …)` — that is, from *its own* address space. That works
// only while injector and target share a dyld shared cache. An iOS Simulator
// process does not: it runs on its own cache, so the injector's address for
// `dlopen` lands on unrelated code over there. Three SpringBoard crashes
// (2026-08-18, EXC_BAD_ACCESS with the loader's `__thread_entry` in x2) were
// exactly this.
//
// The obvious repair — "same file, same offset, just swap the base address" —
// is also wrong, and wrong in a way that survives review. `libsystem_pthread`
// is one of the few images a simulator process takes from the *host* (threads
// must go through the host kernel), so it is tempting to rebase the injector's
// own offset onto the target's load address. But the file is universal and its
// slices disagree: `_pthread_create_from_mach_thread` sits at 0x7d84 in the
// arm64 slice and 0x847c in arm64e. The injector runs against the host cache's
// arm64e copy; the simulator process maps the arm64 one. Rebasing the injector's
// offset therefore lands 0x6f8 bytes into the function — still a crash, and one
// whose symptoms are indistinguishable from resolving the address wholesale
// wrong.
//
// So nothing here reads the injector's own process. Every answer is derived from
// the target: its image list, its Mach-O headers, its symbol tables.
//
// Testability. All target memory access goes through `MIMemoryReader` rather
// than `mach_vm_read_overwrite` directly. The production reader wraps a task
// port and needs root; a test can hand over a reader backed by ordinary memory
// and point the resolver at the *test process itself*, where every answer can be
// checked against `dlsym`. That keeps the parsing — which is where the bugs are
// — covered without a live target or elevated privileges.

#ifndef MI_TARGET_SYMBOL_RESOLVER_H
#define MI_TARGET_SYMBOL_RESOLVER_H

#import <Foundation/Foundation.h>

#include <mach/mach.h>
#include <mach/machine.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const MITargetSymbolResolverErrorDomain;

typedef NS_ERROR_ENUM(MITargetSymbolResolverErrorDomain, MITargetSymbolResolverErrorCode) {
    /// `task_info(TASK_DYLD_INFO)` failed — usually a dead task port.
    MITargetSymbolResolverErrorDyldInfoUnavailable = 1,
    /// The target's `dyld_all_image_infos` could not be read.
    MITargetSymbolResolverErrorAllImageInfosUnreadable = 2,
    /// The target's image list could not be read, or came back empty.
    MITargetSymbolResolverErrorImageListUnreadable = 3,
    /// No loaded image matched the requested path suffix.
    MITargetSymbolResolverErrorImageNotFound = 4,
    /// An image was found but its Mach-O header did not parse.
    MITargetSymbolResolverErrorMachHeaderUnreadable = 5,
    /// The image carries no symbol table this resolver can read. Shared-cache
    /// images are the expected case: their LINKEDIT is shared and trimmed.
    MITargetSymbolResolverErrorSymbolTableUnavailable = 6,
    /// The image parsed and its symbol table was read, but the symbol is absent.
    MITargetSymbolResolverErrorSymbolNotFound = 7,
};

/// Reads `size` bytes from `address` in the target into `buffer`.
/// Returns NO if the range could not be read in full.
typedef BOOL (^MIMemoryReader)(uint64_t address, void *buffer, size_t size);

@interface MITargetSymbolResolver : NSObject

/// Snapshots a target's image list through its task port.
///
/// Fails if the port is dead or the target has not yet published a usable
/// `dyld_all_image_infos`. Note that for a simulator process this returns the
/// list `dyld_sim` maintains — 576 of 580 entries belonged to the simulator's
/// RuntimeRoot when measured on iOS 18.5 — so the simulator's own images are
/// reachable here, not just the handful the host provides.
+ (nullable instancetype)resolverForTask:(mach_port_t)task
                                   error:(NSError **)error;

/// Designated entry point, and the one tests use: same logic against an
/// arbitrary reader instead of a task port.
+ (nullable instancetype)resolverWithMemoryReader:(MIMemoryReader)memoryReader
                              allImageInfosAddress:(uint64_t)allImageInfosAddress
                                             error:(NSError **)error;

/// Absolute address of `symbolName` inside the target, or 0 on failure.
///
/// `imagePathSuffix` is matched against the tail of each loaded image's path,
/// so `"libsystem_pthread.dylib"` selects the target's copy without the caller
/// having to know whether it came from the host, a simulator runtime, or a
/// cache. Symbol names are given as they appear in source — the leading
/// underscore of the Mach-O symbol table is added here.
- (uint64_t)addressOfSymbol:(NSString *)symbolName
            inImageWithPath:(NSString *)imagePathSuffix
                      error:(NSError **)error;

/// Load address of the first image whose path ends in `imagePathSuffix`, or 0.
- (uint64_t)loadAddressOfImageWithPath:(NSString *)imagePathSuffix;

/// Paths of every image the target has loaded, in the target's own order.
@property (nonatomic, readonly) NSArray<NSString *> *imagePaths;

/// The target's architecture, read from a loaded image's Mach-O header rather
/// than assumed from the injector's. This is what decides whether the shellcode
/// entry point needs a PAC signature: an arm64e target wants one, an arm64
/// target must not get one.
@property (nonatomic, readonly) cpu_type_t targetCPUType;
@property (nonatomic, readonly) cpu_subtype_t targetCPUSubtype;

/// The target's shared-cache placement, straight from `dyld_all_image_infos`.
/// Never assume the slide is zero: it happens to be for a simulator runtime,
/// and is not for the host.
@property (nonatomic, readonly) uint64_t sharedCacheSlide;
@property (nonatomic, readonly) uint64_t sharedCacheBaseAddress;

/// YES when the target's images come from a simulator runtime root.
///
/// Decided from the image paths. Deliberately *not* from `dyldPath`, which
/// reads as the host's `/usr/lib/dyld` even for a simulator process whose
/// entire image list is simulator-side — using it would misjudge every target.
@property (nonatomic, readonly, getter=isSimulatorTarget) BOOL simulatorTarget;

@end

NS_ASSUME_NONNULL_END

#endif // MI_TARGET_SYMBOL_RESOLVER_H
