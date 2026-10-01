//
//  MIMachVMCompat.h
//  MachInjector
//
//  One interface, two header stories.
//
//  On macOS, `<mach/mach_vm.h>` is the MIG-generated declaration of the
//  `mach_vm_*` family and is included as-is. On iOS the SDK ships that same
//  path as a file whose entire contents are
//
//      #error mach_vm.h unsupported.
//
//  even though every routine declared below is exported from the public
//  `usr/lib/libSystem.B.tbd` and links against the stock SDK — measured on
//  iPhoneOS27.0.sdk. The trap is that the header *exists*, so a `__has_include`
//  probe reports success and then the build fails inside it; the platform test
//  is the only thing that distinguishes the two.
//
//  The prototypes are copied verbatim from the macOS header, parameter types
//  included. They are the wire format of a MIG call: `mach_vm_read` and
//  `mach_vm_read_overwrite` take `vm_map_read_t` rather than `vm_map_t`, and
//  transcribing either as the other would compile and then misbehave.
//

#ifndef MIMachVMCompat_h
#define MIMachVMCompat_h

#include <TargetConditionals.h>

#if TARGET_OS_OSX || TARGET_OS_MACCATALYST

#include <mach/mach_vm.h>

#else

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_inherit.h>
#include <mach/vm_region.h>

__BEGIN_DECLS

extern kern_return_t mach_vm_allocate
(
	vm_map_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
);

extern kern_return_t mach_vm_deallocate
(
	vm_map_t target,
	mach_vm_address_t address,
	mach_vm_size_t size
);

extern kern_return_t mach_vm_protect
(
	vm_map_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection
);

extern kern_return_t mach_vm_read
(
	vm_map_read_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	vm_offset_t *data,
	mach_msg_type_number_t *dataCnt
);

extern kern_return_t mach_vm_read_overwrite
(
	vm_map_read_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	mach_vm_address_t data,
	mach_vm_size_t *outsize
);

extern kern_return_t mach_vm_write
(
	vm_map_t target_task,
	mach_vm_address_t address,
	vm_offset_t data,
	mach_msg_type_number_t dataCnt
);

extern kern_return_t mach_vm_remap
(
	vm_map_t target_task,
	mach_vm_address_t *target_address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	vm_map_t src_task,
	mach_vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance
);

__END_DECLS

#endif /* TARGET_OS_OSX || TARGET_OS_MACCATALYST */

#endif /* MIMachVMCompat_h */
