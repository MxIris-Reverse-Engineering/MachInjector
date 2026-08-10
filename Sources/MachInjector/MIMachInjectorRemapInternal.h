// -----------------------------------------------------------------------------
// MIMachInjectorRemapInternal.h — internals of MIMachInjectorRemap, exposed only
// so the test target can reach them.
// -----------------------------------------------------------------------------
//
// NOT a public header: it lives beside the implementation rather than in
// `include/`, so it is absent from the MachInjector module and no caller can
// import it. MachInjectorTests reaches these symbols through a header search
// path. Nothing here is API; it may change without notice.
//
// What is here and why: the writable-segment restore described in
// Documentations/Evolutions/0001-restore-payload-writable-segments-before-fixups.md
// ultimately mach_vm_writes into another process, which a unit test cannot do
// without root. So the byte-level decision — which segments, which file bytes,
// how long a zerofill tail — is separated from the act of writing it across the
// task boundary. MIRemapRestoreWritableSegmentsIntoBuffer() does the former
// against a plain buffer and is fully testable; the injector's VM path applies
// the same decisions through mach_vm_write.

#ifndef MI_MACH_INJECTOR_REMAP_INTERNAL_H
#define MI_MACH_INJECTOR_REMAP_INTERNAL_H

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// One LC_SEGMENT_64 worth of what the remap path needs.
//
// `fileOffsetInSlice` / `fileBackedSize` are what let the restore read a
// segment's pristine bytes out of the payload file. They are the segment's own
// `fileoff` / `filesize`, never `vmaddr` — see the "一个已在真实 payload 上失效、
// 但尚未致害的假设" section of proposal 0001 for why conflating the two is a
// live hazard rather than a theoretical one.
typedef struct {
    char name[16];
    uint64_t localStart;
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileOffsetInSlice;
    uint64_t fileBackedSize;
    vm_prot_t initprot;
} MIRemapSegment;

#ifdef __cplusplus
extern "C" {
#endif

/// Whether a segment holds payload state that the target must receive in its
/// on-disk form: the writable segments, whose contents the injector's dlopen
/// has already mutated.
///
/// Single source of truth for two call sites that must never disagree — the
/// mach_vm_protect that opens these segments for writing, and the restore that
/// overwrites them. A segment opened but not restored keeps the injector's
/// runtime state; one restored but not opened fails the write. Both are silent.
bool MIRemapSegmentNeedsWritableRestore(const char *segmentName);

/// Restore one segment's pristine bytes into `destination`, which models the
/// target's copy of that segment: `fileBackedSize` bytes copied from the slice,
/// then the zerofill tail (`vmsize - fileBackedSize`) zeroed.
///
/// `destinationLength` must be the segment's `vmsize`. Returns false without
/// touching `destination` if the segment's file range does not fit inside
/// `sliceAvailable` (a malformed payload) or the length disagrees.
bool MIRemapRestoreSegmentIntoBuffer(const uint8_t *sliceBase,
                                     size_t sliceAvailable,
                                     const MIRemapSegment *segment,
                                     uint8_t *destination,
                                     size_t destinationLength);

/// Apply MIRemapRestoreSegmentIntoBuffer to every writable segment of an image
/// laid out contiguously in `imageBuffer` at its natural intra-image offsets
/// (`vmaddr - minVmaddr`), the layout RemapSegments() produces in the target.
///
/// Returns the number of segments restored, or -1 on a malformed payload.
int MIRemapRestoreWritableSegmentsIntoBuffer(const uint8_t *sliceBase,
                                             size_t sliceAvailable,
                                             const MIRemapSegment *segments,
                                             int segmentCount,
                                             uint64_t minVmaddr,
                                             uint8_t *imageBuffer,
                                             size_t imageBufferLength);

#ifdef __cplusplus
}
#endif

#endif // MI_MACH_INJECTOR_REMAP_INTERNAL_H
