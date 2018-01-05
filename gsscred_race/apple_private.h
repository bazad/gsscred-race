#ifndef GSSCRED_RACE__APPLE_PRIVATE_H_
#define GSSCRED_RACE__APPLE_PRIVATE_H_

#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <os/object.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"

#if __x86_64__

// ---- Header files not available on iOS ---------------------------------------------------------

#include <mach/mach_vm.h>
#include <xpc/xpc.h>

#else /* __x86_64__ */

// If we're not on x86_64, then we probably don't have access to the above headers. The following
// definitions are copied directly from the macOS header files.

// ---- Definitions from xpc/base.h ---------------------------------------------------------------

#define XPC_EXPORT extern __attribute__((visibility("default")))
#define XPC_INLINE static __inline__ __attribute__((__always_inline__))
#define XPC_MALLOC __attribute__((__malloc__))
#define XPC_NONNULL1 __attribute__((__nonnull__(1)))
#define XPC_NONNULL2 __attribute__((__nonnull__(2)))
#define XPC_NONNULL3 __attribute__((__nonnull__(3)))
#define XPC_NONNULL4 __attribute__((__nonnull__(4)))
#define XPC_NONNULL_ALL __attribute__((__nonnull__))
#define XPC_WARN_RESULT __attribute__((__warn_unused_result__))

#if __has_feature(nullability_on_arrays)
#define XPC_NONNULL_ARRAY _Nonnull
#else
#define XPC_NONNULL_ARRAY
#endif

// ---- Definitions from xpc/xpc.h ----------------------------------------------------------------

typedef const struct _xpc_type_s * xpc_type_t;
#define XPC_TYPE(type) const struct _xpc_type_s type

#if OS_OBJECT_USE_OBJC
OS_OBJECT_DECL(xpc_object);
#define XPC_DECL(name) typedef xpc_object_t name##_t
#define XPC_GLOBAL_OBJECT(object) ((OS_OBJECT_BRIDGE xpc_object_t)&(object))
#define XPC_RETURNS_RETAINED OS_OBJECT_RETURNS_RETAINED
XPC_INLINE XPC_NONNULL_ALL
void
_xpc_object_validate(xpc_object_t object) {
	void *isa = *(void * volatile *)(OS_OBJECT_BRIDGE void *)object;
	(void)isa;
}
#else // OS_OBJECT_USE_OBJC
typedef void * xpc_object_t;
#define XPC_DECL(name) typedef struct _##name##_s * name##_t
#define XPC_GLOBAL_OBJECT(object) (&(object))
#define XPC_RETURNS_RETAINED
#endif // OS_OBJECT_USE_OBJC

#if __BLOCKS__
typedef void (^xpc_handler_t)(xpc_object_t object);
#endif // __BLOCKS__

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT
XPC_TYPE(_xpc_type_connection);
XPC_DECL(xpc_connection);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL1
void
xpc_release(xpc_object_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#undef xpc_release
#define xpc_release(object) ({ xpc_object_t _o = (object); \
		_xpc_object_validate(_o); [_o release]; })
#endif // OS_OBJECT_USE_OBJC_RETAIN_RELEASE

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_MALLOC XPC_WARN_RESULT XPC_NONNULL1
char *
xpc_copy_description(xpc_object_t object);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_MALLOC XPC_RETURNS_RETAINED XPC_WARN_RESULT XPC_NONNULL1
xpc_object_t
xpc_data_create_with_dispatch_data(dispatch_data_t ddata);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_MALLOC XPC_RETURNS_RETAINED XPC_WARN_RESULT
xpc_object_t
xpc_array_create(const xpc_object_t _Nonnull * _Nullable objects, size_t count);

#define XPC_ARRAY_APPEND ((size_t)(-1))

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL1 XPC_NONNULL3
void
xpc_array_set_string(xpc_object_t xarray, size_t index, const char *string);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_MALLOC XPC_RETURNS_RETAINED XPC_WARN_RESULT
xpc_object_t
xpc_dictionary_create(const char * _Nonnull const * _Nullable keys,
	const xpc_object_t _Nullable * _Nullable values, size_t count);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL1 XPC_NONNULL2
void
xpc_dictionary_set_value(xpc_object_t xdict, const char *key,
	xpc_object_t _Nullable value);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_WARN_RESULT XPC_NONNULL1 XPC_NONNULL2
xpc_object_t _Nullable
xpc_dictionary_get_value(xpc_object_t xdict, const char *key);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL1 XPC_NONNULL2 XPC_NONNULL3
void
xpc_dictionary_set_string(xpc_object_t xdict, const char *key,
	const char *string);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL1 XPC_NONNULL2 XPC_NONNULL3
void
xpc_dictionary_set_uuid(xpc_object_t xdict, const char *key,
	const uuid_t XPC_NONNULL_ARRAY uuid);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_WARN_RESULT XPC_NONNULL1 XPC_NONNULL2
const uint8_t * _Nullable
xpc_dictionary_get_uuid(xpc_object_t xdict, const char *key);

// ---- Definitions from xpc/connection.h ---------------------------------------------------------

#if __BLOCKS__

#define XPC_ERROR_CONNECTION_INTERRUPTED \
	XPC_GLOBAL_OBJECT(_xpc_error_connection_interrupted)
__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT
const struct _xpc_dictionary_s _xpc_error_connection_interrupted;

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_MALLOC XPC_RETURNS_RETAINED XPC_WARN_RESULT XPC_NONNULL1
xpc_connection_t
xpc_connection_create_mach_service(const char *name,
	dispatch_queue_t _Nullable targetq, uint64_t flags);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL_ALL
void
xpc_connection_set_event_handler(xpc_connection_t connection,
	xpc_handler_t handler);

__OSX_AVAILABLE(10.12) __IOS_AVAILABLE(10.0)
__TVOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0)
XPC_EXPORT XPC_NONNULL_ALL
void
xpc_connection_activate(xpc_connection_t connection);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL1 XPC_NONNULL2 XPC_NONNULL4
void
xpc_connection_send_message_with_reply(xpc_connection_t connection,
	xpc_object_t message, dispatch_queue_t _Nullable replyq,
	xpc_handler_t handler);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL_ALL XPC_WARN_RESULT XPC_RETURNS_RETAINED
xpc_object_t
xpc_connection_send_message_with_reply_sync(xpc_connection_t connection,
	xpc_object_t message);

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL_ALL
void
xpc_connection_cancel(xpc_connection_t connection);

#endif // __BLOCKS__

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

__OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_5_0)
XPC_EXPORT XPC_NONNULL1 XPC_NONNULL2
void
xpc_dictionary_set_mach_send(xpc_object_t xdict, const char *key,
	mach_port_t mach_send);

#pragma clang diagnostic pop

#endif
