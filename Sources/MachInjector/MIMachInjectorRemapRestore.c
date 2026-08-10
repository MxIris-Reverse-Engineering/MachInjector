// -----------------------------------------------------------------------------
// MIMachInjectorRemapRestore.c — put the payload's writable segments back the
// way the file has them, before apply_fixups() runs.
// -----------------------------------------------------------------------------
//
// SEE ALSO (before touching this file)
//   Documentations/Evolutions/0001-restore-payload-writable-segments-before-fixups.md
//     — the crash that motivated this, the measurements behind it, and the
//     alternatives that were rejected.
//   Documentations/Design/RemapArchitecture.md — where step 7c sits in the
//     injection pipeline.
//
// PROBLEM
//   MIMachInjectorRemap dlopens the payload in the INJECTOR, only to learn its
//   mach-header layout and entry offset, and then mach_vm_remaps that image
//   into the target. But dlopen does not merely map the file: dyld applies its
//   fixups, and the Swift and Objective-C runtimes write process-private state
//   into __DATA — generic metadata caches, swift_once flags, realized-class
//   records. None of that is a chained-fixup target, so apply_fixups() cannot
//   correct it, and the injector's private pointers land in the target intact.
//
//   The first thing to trip over it is usually a Swift generic metadata cache:
//   the payload reads the injector's cached metadata pointer, which in the
//   target addresses an unrelated object, and dies authenticating a value
//   witness table that was never there. The value looks legitimate — only the
//   pointer-authentication bits are wrong — which is why this reads as a PAC
//   bug and is not one.
//
// SOLUTION
//   Overwrite those segments with the payload FILE's bytes once they are in the
//   target, before apply_fixups() rewrites the chained-fixup slots on top. The
//   target then holds an image equivalent to one freshly mapped and never
//   executed.
//
// WHY ONLY THE WRITABLE SEGMENTS
//   __TEXT has to keep coming from the dlopen'd image. The target enforces code
//   signing, so its executable pages must be backed by a mapping dyld already
//   validated; remapping executable bytes the injector assembled itself is
//   refused. The writable segments carry no execute permission and are under no
//   such constraint.

#include "MIMachInjectorRemapInternal.h"

#include <string.h>

bool MIRemapSegmentNeedsWritableRestore(const char *segmentName) {
    if (segmentName == NULL) return false;
    // __AUTH_CONST / __AUTH do not appear in every arm64e payload — on macOS the
    // linker keeps authenticated pointers in __DATA_CONST unless a section
    // attribute forces the split — but they are handled here on exactly the same
    // terms as the other two. That uniformity is load-bearing: the injection
    // fixture used to verify this code has no __AUTH* segments, so any branch
    // taken only for them would ship unverified. Filter by name, treat alike.
    return strcmp(segmentName, "__DATA_CONST") == 0 ||
           strcmp(segmentName, "__DATA") == 0 ||
           strcmp(segmentName, "__AUTH_CONST") == 0 ||
           strcmp(segmentName, "__AUTH") == 0;
}

bool MIRemapRestoreSegmentIntoBuffer(const uint8_t *sliceBase,
                                     size_t sliceAvailable,
                                     const MIRemapSegment *segment,
                                     uint8_t *destination,
                                     size_t destinationLength) {
    if (sliceBase == NULL || segment == NULL || destination == NULL) return false;
    if (destinationLength != segment->vmsize) return false;
    if (segment->fileBackedSize > segment->vmsize) return false;

    // Guard the file read against a malformed payload rather than walking off
    // the end of the injector's own mapping.
    if (segment->fileOffsetInSlice > sliceAvailable) return false;
    if (segment->fileBackedSize > sliceAvailable - segment->fileOffsetInSlice) return false;

    memcpy(destination, sliceBase + segment->fileOffsetInSlice, (size_t)segment->fileBackedSize);

    // Everything past filesize is zerofill (__bss / __common). dyld hands the
    // target zeroed pages there; the injector's copy may hold whatever its own
    // runtime put in them.
    uint64_t zeroFillLength = segment->vmsize - segment->fileBackedSize;
    if (zeroFillLength > 0) {
        memset(destination + segment->fileBackedSize, 0, (size_t)zeroFillLength);
    }
    return true;
}

int MIRemapRestoreWritableSegmentsIntoBuffer(const uint8_t *sliceBase,
                                             size_t sliceAvailable,
                                             const MIRemapSegment *segments,
                                             int segmentCount,
                                             uint64_t minVmaddr,
                                             uint8_t *imageBuffer,
                                             size_t imageBufferLength) {
    if (segments == NULL || imageBuffer == NULL || segmentCount < 0) return -1;

    int restored = 0;
    for (int segmentIndex = 0; segmentIndex < segmentCount; ++segmentIndex) {
        const MIRemapSegment *segment = &segments[segmentIndex];
        if (!MIRemapSegmentNeedsWritableRestore(segment->name)) continue;
        if (segment->vmaddr < minVmaddr) return -1;

        uint64_t offsetInImage = segment->vmaddr - minVmaddr;
        if (offsetInImage > imageBufferLength) return -1;
        if (segment->vmsize > imageBufferLength - offsetInImage) return -1;

        if (!MIRemapRestoreSegmentIntoBuffer(sliceBase, sliceAvailable, segment,
                                             imageBuffer + offsetInImage,
                                             (size_t)segment->vmsize)) {
            return -1;
        }
        restored++;
    }
    return restored;
}
