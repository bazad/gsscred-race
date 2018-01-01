#ifndef GSSCRED_RACE__ARM64__ARM64_PAYLOAD_H_
#define GSSCRED_RACE__ARM64__ARM64_PAYLOAD_H_

#include "payload.h"

// A strategy for the exploit payload. Because we're relying on ROP/JOP programs to implement the
// payload, we may not find the specific gadgets we'd like to use in all builds and on all
// platforms. You can add a new strategy to support a new build and platform.
struct payload_strategy {
	bool (*check_platform)(void);
	void (*build_payload)(uint8_t *payload);
};

// The currently defined strategies.
extern const struct payload_strategy payload_strategy_1;

// Choose the payload generation strategy most suitable for the current arm64 platform.
gsscred_race_platform_payload_generator_fn arm64_choose_payload(void);

#endif
