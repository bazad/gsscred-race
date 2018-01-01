#include "gsscred_race.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

// Log all messages to stderr.
static void
gsscred_race_log_stderr(char type, const char *format, va_list ap) {
	char *message = NULL;
	vasprintf(&message, format, ap);
	assert(message != NULL);
	const char *logtype   = "";
	const char *separator = ": ";
	switch (type) {
		case 'D': logtype = "Debug";   break;
		case 'I': logtype = "Info";    break;
		case 'W': logtype = "Warning"; break;
		case 'E': logtype = "Error";   break;
		default:  separator = "";
	}
	fprintf(stderr, "%s%s%s\n", logtype, separator, message);
	free(message);
}

void (*gsscred_race_log)(char type, const char *format, va_list ap) = &gsscred_race_log_stderr;

void
gsscred_race_log_internal(char type, const char *format, ...) {
	if (gsscred_race_log != NULL) {
		va_list ap;
		va_start(ap, format);
		gsscred_race_log(type, format, ap);
		va_end(ap);
	}
}
