/*
 * gsscred-race
 * Brandon Azad
 *
 * Exploit a race condition in the com.apple.GSSCred XPC service.
 */

#ifndef GSSCRED_RACE__GSSCRED_RACE_H_
#define GSSCRED_RACE__GSSCRED_RACE_H_

#include <mach/mach.h>
#include <stdarg.h>
#include <stdbool.h>

/*
 * gsscred_race_log
 *
 * Description:
 * 	This is the log handler that will be executed when gsscred_race wants to log a message. The
 * 	default implementation logs the message to stderr. Setting this value to NULL will disable
 * 	all logging. Specify a custom log handler to process log messages in another way.
 *
 * Parameters:
 * 	type				A character representing the type of message that is being
 * 					logged.
 * 	format				A printf-style format string describing the error message.
 * 	ap				The variadic argument list for the format string.
 *
 * Log Type:
 * 	The type parameters is one of:
 * 	- D: Debug:     Used for debugging messages. Set the DEBUG build variable to control debug
 * 	                verbosity.
 * 	- I: Info:      Used to convey general information about the exploit or its progress.
 * 	- W: Warning:   Used to indicate that an unusual but recoverable condition was encountered.
 * 	- E: Error:     Used to indicate that an unrecoverable error was encountered. gsscred_race
 * 	                might continue running after an error was encountered, but it almost
 * 	                certainly will not succeed.
 */
extern void (*gsscred_race_log)(char type, const char *format, va_list ap);

/*
 * gsscred_race
 *
 * Description:
 * 	Exploit a race condition in the com.apple.GSSCred XPC service in order to access GSSCred's
 * 	task port. GSSCred runs as root on macOS and iOS.
 *
 * Parameters:
 * 	gsscred_task_port		On return, contains the task port for GSSCred. Note that
 * 					this port's usage may be restricted on some platforms,
 * 					including iOS 11.
 * 	gsscred_thread_port		On return, contains the thread port for a thread in
 * 					GSSCred. This thread port can be used to execute code
 * 					within the GSSCred process. The thread is returned
 * 					suspended.
 *
 * Returns:
 * 	Returns true if GSSCred's task port and thread port were both successfully retrieved.
 * 	Otherwise, returns false and both ports are set to MACH_PORT_NULL.
 *
 * Logging:
 * 	Many error conditions may be encountered by gsscred_race during its execution. Error
 * 	messages are logged using the gsscred_race_log function pointer described above.
 *
 * Notes:
 * 	The race condition can only safely be exploited once during the lifetime of the GSSCred
 * 	process. Subsequent attempts to exploit the vulnerability will probably fail and may cause
 * 	instability.
 */
bool gsscred_race(mach_port_t *gsscred_task_port, mach_port_t *gsscred_thread_port);

#endif
