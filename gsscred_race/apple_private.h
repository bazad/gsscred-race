#ifndef GSSCRED_RACE__APPLE_PRIVATE_H_
#define GSSCRED_RACE__APPLE_PRIVATE_H_

#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <xpc/xpc.h>

#if __x86_64__

// ---- Header files not available on iOS ---------------------------------------------------------

#include <mach/mach_vm.h>

#else /* __x86_64__ */

// If we're not on x86_64, then we probably don't have access to the above headers. The following
// definitions are copied directly from the macOS header files.

// ---- Definitions from mach/mach_vm.h -----------------------------------------------------------

extern
kern_return_t mach_vm_allocate
(
	vm_map_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags
);

extern
kern_return_t mach_vm_deallocate
(
	vm_map_t target,
	mach_vm_address_t address,
	mach_vm_size_t size
);

extern
kern_return_t mach_vm_remap
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

extern
kern_return_t mach_vm_region_recurse
(
	vm_map_t target_task,
	mach_vm_address_t *address,
	mach_vm_size_t *size,
	natural_t *nesting_depth,
	vm_region_recurse_info_t info,
	mach_msg_type_number_t *infoCnt
);

#endif /* __x86_64__ */

// The following definitions are not available in the header files for any platform. They are
// copied from the corresponding header files available at opensource.apple.com (if available).

// ---- Definitions from libdispatch private/data_private.h ---------------------------------------

/*!
 * @const DISPATCH_DATA_DESTRUCTOR_VM_DEALLOCATE
 * @discussion The destructor for dispatch data objects that have been created
 * from buffers that require deallocation using vm_deallocate.
 */
#define DISPATCH_DATA_DESTRUCTOR_VM_DEALLOCATE \
		(_dispatch_data_destructor_vm_deallocate)
API_AVAILABLE(macos(10.8), ios(6.0)) DISPATCH_LINUX_UNAVAILABLE()
DISPATCH_DATA_DESTRUCTOR_TYPE_DECL(vm_deallocate);

// ---- Definitions from private libxpc headers ---------------------------------------------------

void xpc_dictionary_set_mach_send(xpc_object_t xdict, const char *key, mach_port_t mach_send);

#endif
