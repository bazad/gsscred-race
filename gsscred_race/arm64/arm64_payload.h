#ifndef GSSCRED_RACE__ARM64__ARM64_PAYLOAD_H_
#define GSSCRED_RACE__ARM64__ARM64_PAYLOAD_H_

#include "payload.h"

// A strategy for the exploit payload. Because we're relying on ROP/JOP programs to implement the
// payload, we may not find the specific gadgets we'd like to use in all builds and on all
// platforms. You can add a new strategy to support a new build and platform.
struct payload_strategy {
	// Check if this payload is suitable for the current platform.
	bool (*check_platform)(void);
	// Build the payload in the specified payload buffer.
	platform_payload_generator_fn build_payload;
	// Process the Mach message sent by the exploit payload. Returns a task port and a thread
	// port for a thread in the task. Any post-processing needed to stabilize the process after
	// the exploit happens here.
	payload_message_processor_fn process_message;
};

// The currently defined strategies.
extern const struct payload_strategy payload_strategy_1;

// Choose the payload generation strategy most suitable for the current arm64 platform.
const struct payload_strategy *arm64_choose_payload(void);

#endif
