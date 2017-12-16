/*
 * gsscred-race
 * Brandon Azad
 *
 * Exploit a race condition in the com.apple.GSSCred XPC service.
 */

#include <stdio.h>

#include "gsscred_race.h"

int main(int argc, const char *argv[]) {
	bool success = gsscred_race();
	return (success ? 0 : 1);
}
