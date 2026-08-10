// -----------------------------------------------------------------------------
// Regression tests for proposal 0001 — restoring the payload's writable segments
// to their on-disk contents before apply_fixups() runs.
// -----------------------------------------------------------------------------
//
// The defect these pin down: MIMachInjectorRemap mach_vm_remaps the payload as
// it exists in the INJECTOR after dlopen, and dlopen leaves process-private
// runtime state in __DATA that no chained fixup covers, so apply_fixups()
// cannot correct it. In the real crash this surfaced as a Swift generic metadata
// cache carrying the injector's pointer into Finder.
//
// Doing that end to end would need task_for_pid on a second process, i.e. root.
// The part worth pinning is byte-level and process-local: given the injector's
// dlopen'd image, does the target end up with the file's bytes? So these tests
// build a real dylib, dlopen it (dirtying it exactly as the injector's dlopen
// would), model the remap with a buffer copy, and check what the target would
// have received.
//
// The fixture is compiled at test time rather than committed as a binary: a
// checked-in dylib is unreadable in review, goes stale against the toolchain,
// and cannot be re-signed per-machine. clang is present wherever `swift test`
// runs.

#import <XCTest/XCTest.h>

#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>

#import "MIMachInjectorRemapInternal.h"

// A payload that dirties its own __DATA from a constructor. `gRuntimeCache` has
// no initialiser, so it is zero in the file and carries no chained fixup —
// the same shape as the Swift metadata cache that caused the original crash.
// `gFixupBackedPointer` does have one, so a fixup covers it; it is the control.
static NSString *const kFixtureSource =
@"#include <stdint.h>\n"
@"static void *gRuntimeCache;\n"
@"static void *gFixupBackedPointer = (void *)&gRuntimeCache;\n"
@"__attribute__((constructor)) static void FixtureInitialize(void) {\n"
@"    gRuntimeCache = (void *)&FixtureInitialize;\n"
@"}\n"
@"__attribute__((visibility(\"default\"))) void *FixtureRuntimeCacheAddress(void) { return &gRuntimeCache; }\n"
@"__attribute__((visibility(\"default\"))) void *FixtureFixupBackedAddress(void) { return &gFixupBackedPointer; }\n";

@interface MIMachInjectorRemapRestoreTests : XCTestCase
@end

@implementation MIMachInjectorRemapRestoreTests {
    NSString *_fixtureDirectory;
    NSString *_fixtureDylibPath;
    void *_fixtureHandle;
    const struct mach_header_64 *_fixtureHeader;
    NSData *_fixtureFileBytes;
}

#pragma mark - Fixture

- (void)setUp {
    [super setUp];

    _fixtureDirectory = [NSTemporaryDirectory() stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"MIRemapRestore-%@", [[NSUUID UUID] UUIDString]]];
    NSError *directoryError = nil;
    XCTAssertTrue([[NSFileManager defaultManager] createDirectoryAtPath:_fixtureDirectory
                                           withIntermediateDirectories:YES
                                                            attributes:nil
                                                                 error:&directoryError],
                  @"failed to create fixture directory: %@", directoryError);

    NSString *sourcePath = [_fixtureDirectory stringByAppendingPathComponent:@"fixture.c"];
    NSError *writeError = nil;
    XCTAssertTrue([kFixtureSource writeToFile:sourcePath atomically:YES
                                     encoding:NSUTF8StringEncoding error:&writeError],
                  @"failed to write fixture source: %@", writeError);

    _fixtureDylibPath = [_fixtureDirectory stringByAppendingPathComponent:@"libfixture.dylib"];

    NSTask *compile = [[NSTask alloc] init];
    compile.launchPath = @"/usr/bin/xcrun";
    compile.arguments = @[@"clang", @"-dynamiclib", @"-O0",
                          @"-o", _fixtureDylibPath, sourcePath];
    compile.standardOutput = [NSPipe pipe];
    compile.standardError = [NSPipe pipe];
    [compile launch];
    [compile waitUntilExit];
    XCTAssertEqual(compile.terminationStatus, 0, @"clang failed to build the fixture dylib");

    _fixtureFileBytes = [NSData dataWithContentsOfFile:_fixtureDylibPath];
    XCTAssertNotNil(_fixtureFileBytes, @"fixture dylib is unreadable");

    // This dlopen stands in for the injector's dlopen of the payload — the very
    // step that dirties __DATA.
    _fixtureHandle = dlopen([_fixtureDylibPath fileSystemRepresentation], RTLD_NOW | RTLD_LOCAL);
    XCTAssertTrue(_fixtureHandle != NULL, @"dlopen of the fixture failed: %s", dlerror());

    void *cacheAccessor = dlsym(_fixtureHandle, "FixtureRuntimeCacheAddress");
    XCTAssertTrue(cacheAccessor != NULL, @"fixture is missing its accessor: %s", dlerror());
    Dl_info info = {0};
    XCTAssertTrue(dladdr(cacheAccessor, &info) != 0, @"dladdr on the fixture failed");
    _fixtureHeader = (const struct mach_header_64 *)info.dli_fbase;
}

- (void)tearDown {
    // Deliberately not dlclose'ing: the injector leaks its handles for the same
    // reason (unloading mprotects pages that the target shares), and the fixture
    // is tiny.
    [[NSFileManager defaultManager] removeItemAtPath:_fixtureDirectory error:NULL];
    [super tearDown];
}

#pragma mark - Helpers

/// Walk the loaded fixture's load commands the way EnumerateSegments does.
- (int)collectSegments:(MIRemapSegment *)segments
              capacity:(int)capacity
            minVmaddr:(uint64_t *)outMinVmaddr
             maxVmend:(uint64_t *)outMaxVmend {
    int count = 0;
    uint64_t minVmaddr = UINT64_MAX;
    uint64_t maxVmend = 0;
    const struct load_command *command = (const struct load_command *)(_fixtureHeader + 1);
    for (uint32_t commandIndex = 0; commandIndex < _fixtureHeader->ncmds; ++commandIndex) {
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)command;
            if (strcmp(segment->segname, SEG_LINKEDIT) != 0 &&
                strcmp(segment->segname, SEG_PAGEZERO) != 0 &&
                segment->vmsize > 0) {
                XCTAssertLessThan(count, capacity, @"fixture has more segments than expected");
                strlcpy(segments[count].name, segment->segname, sizeof segments[count].name);
                segments[count].vmaddr = segment->vmaddr;
                segments[count].vmsize = segment->vmsize;
                segments[count].initprot = segment->initprot;
                segments[count].localStart = (uint64_t)_fixtureHeader + segment->vmaddr;
                segments[count].fileOffsetInSlice = segment->fileoff;
                segments[count].fileBackedSize = segment->filesize;
                if (segment->vmaddr < minVmaddr) minVmaddr = segment->vmaddr;
                uint64_t end = segment->vmaddr + segment->vmsize;
                if (end > maxVmend) maxVmend = end;
                count++;
            }
        }
        command = (const struct load_command *)((const char *)command + command->cmdsize);
    }
    *outMinVmaddr = minVmaddr;
    *outMaxVmend = maxVmend;
    return count;
}

/// Byte-for-byte copy of the loaded image at its intra-image offsets — what
/// RemapSegments() leaves in the target before any restore.
- (NSMutableData *)modelRemappedImageWithSegments:(const MIRemapSegment *)segments
                                            count:(int)count
                                        minVmaddr:(uint64_t)minVmaddr
                                             span:(uint64_t)span {
    NSMutableData *image = [NSMutableData dataWithLength:(NSUInteger)span];
    for (int segmentIndex = 0; segmentIndex < count; ++segmentIndex) {
        memcpy((uint8_t *)image.mutableBytes + (segments[segmentIndex].vmaddr - minVmaddr),
               (const void *)segments[segmentIndex].localStart,
               (size_t)segments[segmentIndex].vmsize);
    }
    return image;
}

- (uint64_t)runtimeCacheImageOffsetForMinVmaddr:(uint64_t)minVmaddr {
    void *(*cacheAddress)(void) = (void *(*)(void))dlsym(_fixtureHandle, "FixtureRuntimeCacheAddress");
    XCTAssertTrue(cacheAddress != NULL, @"fixture accessor vanished");
    uint64_t address = (uint64_t)cacheAddress();
    return address - (uint64_t)_fixtureHeader - minVmaddr;
}

#pragma mark - Tests

/// Establishes the defect exists: dlopen writes a word that no chained fixup
/// covers, so remapping the loaded image hands the target the injector's value.
/// If this ever fails, the fixture stopped reproducing the situation and the
/// restore test below is no longer proving anything.
- (void)testDlopenDirtiesAWordThatIsZeroInTheFile {
    MIRemapSegment segments[16];
    uint64_t minVmaddr = 0, maxVmend = 0;
    int count = [self collectSegments:segments capacity:16 minVmaddr:&minVmaddr maxVmend:&maxVmend];
    XCTAssertGreaterThan(count, 0);

    uint64_t cacheOffset = [self runtimeCacheImageOffsetForMinVmaddr:minVmaddr];
    NSMutableData *remapped = [self modelRemappedImageWithSegments:segments count:count
                                                        minVmaddr:minVmaddr
                                                             span:maxVmend - minVmaddr];

    uint64_t loadedValue = 0;
    memcpy(&loadedValue, (const uint8_t *)remapped.bytes + cacheOffset, sizeof loadedValue);
    XCTAssertNotEqual(loadedValue, 0ULL,
                      @"fixture no longer dirties its cache word during dlopen");

    // Same word, straight from the file: zero.
    const MIRemapSegment *owningSegment = NULL;
    for (int segmentIndex = 0; segmentIndex < count; ++segmentIndex) {
        uint64_t start = segments[segmentIndex].vmaddr - minVmaddr;
        if (cacheOffset >= start && cacheOffset < start + segments[segmentIndex].vmsize) {
            owningSegment = &segments[segmentIndex];
            break;
        }
    }
    XCTAssertTrue(owningSegment != NULL, @"cache word is outside every segment");
    XCTAssertTrue(MIRemapSegmentNeedsWritableRestore(owningSegment->name),
                  @"cache word landed in %s, which the restore does not cover", owningSegment->name);

    uint64_t offsetWithinSegment = cacheOffset - (owningSegment->vmaddr - minVmaddr);
    uint64_t fileValue = 0;
    memcpy(&fileValue,
           (const uint8_t *)_fixtureFileBytes.bytes + owningSegment->fileOffsetInSlice + offsetWithinSegment,
           sizeof fileValue);
    XCTAssertEqual(fileValue, 0ULL, @"the file's copy of the cache word should be zero");
}

/// The fix: after restoring, every writable byte the target holds equals the
/// file's. Fails before the restore exists, because the remapped image still
/// carries dlopen's writes.
- (void)testRestoreMakesWritableSegmentsMatchTheFile {
    MIRemapSegment segments[16];
    uint64_t minVmaddr = 0, maxVmend = 0;
    int count = [self collectSegments:segments capacity:16 minVmaddr:&minVmaddr maxVmend:&maxVmend];
    uint64_t span = maxVmend - minVmaddr;

    NSMutableData *remapped = [self modelRemappedImageWithSegments:segments count:count
                                                        minVmaddr:minVmaddr span:span];

    int restored = MIRemapRestoreWritableSegmentsIntoBuffer(
        (const uint8_t *)_fixtureFileBytes.bytes, _fixtureFileBytes.length,
        segments, count, minVmaddr,
        (uint8_t *)remapped.mutableBytes, (size_t)span);
    XCTAssertGreaterThan(restored, 0, @"no writable segment was restored");

    for (int segmentIndex = 0; segmentIndex < count; ++segmentIndex) {
        const MIRemapSegment *segment = &segments[segmentIndex];
        if (!MIRemapSegmentNeedsWritableRestore(segment->name)) continue;

        const uint8_t *restoredBytes = (const uint8_t *)remapped.bytes + (segment->vmaddr - minVmaddr);
        const uint8_t *fileBytes = (const uint8_t *)_fixtureFileBytes.bytes + segment->fileOffsetInSlice;
        XCTAssertEqual(memcmp(restoredBytes, fileBytes, (size_t)segment->fileBackedSize), 0,
                       @"%s does not match the file after restore", segment->name);

        for (uint64_t tail = segment->fileBackedSize; tail < segment->vmsize; ++tail) {
            XCTAssertEqual(restoredBytes[tail], 0,
                           @"%s zerofill tail is not zeroed at +%llu", segment->name, tail);
        }
    }
}

/// The specific word from the crash: the injector's runtime value must not
/// survive into the target.
- (void)testRestoreClearsTheRuntimeDirtiedWord {
    MIRemapSegment segments[16];
    uint64_t minVmaddr = 0, maxVmend = 0;
    int count = [self collectSegments:segments capacity:16 minVmaddr:&minVmaddr maxVmend:&maxVmend];
    uint64_t span = maxVmend - minVmaddr;
    uint64_t cacheOffset = [self runtimeCacheImageOffsetForMinVmaddr:minVmaddr];

    NSMutableData *remapped = [self modelRemappedImageWithSegments:segments count:count
                                                        minVmaddr:minVmaddr span:span];

    XCTAssertGreaterThan(MIRemapRestoreWritableSegmentsIntoBuffer(
        (const uint8_t *)_fixtureFileBytes.bytes, _fixtureFileBytes.length,
        segments, count, minVmaddr,
        (uint8_t *)remapped.mutableBytes, (size_t)span), 0);

    uint64_t restoredValue = 0;
    memcpy(&restoredValue, (const uint8_t *)remapped.bytes + cacheOffset, sizeof restoredValue);
    XCTAssertEqual(restoredValue, 0ULL,
                   @"the injector's runtime value survived into the target's copy");
}

#pragma mark - Segment name policy

- (void)testWritableSegmentPolicyCoversAuthSegments {
    XCTAssertTrue(MIRemapSegmentNeedsWritableRestore("__DATA_CONST"));
    XCTAssertTrue(MIRemapSegmentNeedsWritableRestore("__DATA"));
    // No __AUTH* segment appears in the injection fixture, so these two are the
    // only coverage they get. See proposal 0001.
    XCTAssertTrue(MIRemapSegmentNeedsWritableRestore("__AUTH_CONST"));
    XCTAssertTrue(MIRemapSegmentNeedsWritableRestore("__AUTH"));

    XCTAssertFalse(MIRemapSegmentNeedsWritableRestore("__TEXT"));
    XCTAssertFalse(MIRemapSegmentNeedsWritableRestore("__LINKEDIT"));
    XCTAssertFalse(MIRemapSegmentNeedsWritableRestore(NULL));
}

#pragma mark - Malformed input

- (void)testRestoreRejectsSegmentReachingPastTheSlice {
    MIRemapSegment segment = {0};
    strlcpy(segment.name, "__DATA", sizeof segment.name);
    segment.vmaddr = 0x4000;
    segment.vmsize = 0x1000;
    segment.fileOffsetInSlice = 0x4000;
    segment.fileBackedSize = 0x1000;

    uint8_t sliceBytes[0x100] = {0};
    uint8_t destination[0x1000];
    memset(destination, 0xAB, sizeof destination);

    XCTAssertFalse(MIRemapRestoreSegmentIntoBuffer(sliceBytes, sizeof sliceBytes, &segment,
                                                   destination, sizeof destination),
                   @"a segment whose file range exceeds the slice must be refused");
    XCTAssertEqual(destination[0], 0xAB, @"destination must be untouched on refusal");
}

- (void)testRestoreRejectsFileSizeLargerThanVMSize {
    MIRemapSegment segment = {0};
    strlcpy(segment.name, "__DATA", sizeof segment.name);
    segment.vmsize = 0x10;
    segment.fileOffsetInSlice = 0;
    segment.fileBackedSize = 0x20;

    uint8_t sliceBytes[0x100] = {0};
    uint8_t destination[0x10];
    XCTAssertFalse(MIRemapRestoreSegmentIntoBuffer(sliceBytes, sizeof sliceBytes, &segment,
                                                   destination, sizeof destination));
}

@end
