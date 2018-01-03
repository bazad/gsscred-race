#include "arm64/gadgets.h"

#include <assert.h>
#include <string.h>

// NOTE: Keep this list synchronized with the enumeration in the header.
#define G(str, ...)							\
	{ 0, sizeof((uint32_t[]) { __VA_ARGS__ }) / sizeof(uint32_t),	\
	  (const uint32_t *) &(const uint32_t[]) { __VA_ARGS__ }, str }
struct gadget gadgets[GADGET_COUNT] = {
	G("ldp x1, x0, [x0, #0x20] ; br x1",            0xa9420001, 0xd61f0020),
	G("ldp x8, x2, [x19] ; blr x8",                 0xa9400a68, 0xd63f0100),
	G("ldp x3, x2, [x2] ; br x3",                   0xa9400843, 0xd61f0060),
	G("add x1, x21, x20 ; blr x8",                  0x8b1402a1, 0xd63f0100),

	G("mov x20, x1 ; blr x8",                       0xaa0103f4, 0xd63f0100),
	G("str x1, [x19, #0x80] ; blr x8",              0xf9004261, 0xd63f0100),
	G("mov x0, x26 ; blr x8",                       0xaa1a03e0, 0xd63f0100),
	G("sub x1, x1, x0 ; blr x8",                    0xcb000021, 0xd63f0100),

	G("mov x13, x1 ; br x8",                        0xaa0103ed, 0xd61f0100),
	G("mov x9, x13 ; br x8",                        0xaa0d03e9, 0xd61f0100),
	G("mov x11, x24 ; br x8",                       0xaa1803eb, 0xd61f0100),
	G("cmp x9, #0 ; csel x1, x10, x9, eq ; blr x8", 0xf100013f, 0x9a890141, 0xd63f0100),

	G("mov x9, x22 ; br x8",                        0xaa1603e9, 0xd61f0100),
	G("csel x2, x11, x9, lt ; blr x8",              0x9a89b162, 0xd63f0100),
	G("mov x0, x27 ; blr x8",                       0xaa1b03e0, 0xd63f0100),
	G("blr x23 ; mov x0, x21 ; blr x25",            0xd63f02e0, 0xaa1503e0, 0xd63f0320),

	G("ldr x8, [x19, #0x10] ; blr x8",              0xf9400a68, 0xd63f0100),
	G("blr x8",                                     0xd63f0100),
};
#undef G

void
find_gadgets(uint64_t address, const void *code, size_t size) {
	assert((address & 0x3) == 0);
	for (size_t i = 0; i < GADGET_COUNT; i++) {
		if (gadgets[i].address != 0) {
			continue;
		}
		const uint8_t *start = code;
		for (;;) {
			const uint8_t *found = memmem(start, size, gadgets[i].ins,
					gadgets[i].count * sizeof(*gadgets[i].ins));
			if (found == NULL) {
				break;
			}
			if (((uintptr_t) found) % sizeof(*gadgets[i].ins) == 0) {
				gadgets[i].address = address + (found - (const uint8_t *)code);
				break;
			}
			size -= (found + 1 - start);
			start = found + 1;
		}
	}
}
