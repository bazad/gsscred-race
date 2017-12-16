/*
 * gsscred-race
 * Brandon Azad
 *
 * Exploit a race condition in the com.apple.GSSCred XPC service.
 */

#ifndef GSSCRED_RACE__GSSCRED_RACE_H_
#define GSSCRED_RACE__GSSCRED_RACE_H_

#include <stdbool.h>

bool gsscred_race(void);

#endif
