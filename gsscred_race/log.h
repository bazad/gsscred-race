#ifndef GSSCRED_RACE__LOG_H_
#define GSSCRED_RACE__LOG_H_

#include "gsscred_race.h"

#define DEBUG_LEVEL(level)	(DEBUG && level <= DEBUG)

#if DEBUG
#define DEBUG_TRACE(level, fmt, ...)						\
	do {									\
		if (DEBUG_LEVEL(level)) {					\
			gsscred_race_log_internal('D', fmt, ##__VA_ARGS__);	\
		}								\
	} while (0)
#else
#define DEBUG_TRACE(level, fmt, ...)	do {} while (0)
#endif
#define INFO(fmt, ...)			gsscred_race_log_internal('I', fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...)		gsscred_race_log_internal('W', fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)			gsscred_race_log_internal('E', fmt, ##__VA_ARGS__)

// A function to call the logging implementation.
void gsscred_race_log_internal(char type, const char *format, ...);

#endif
