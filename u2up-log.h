/*
 * The u2up-log Logging support module
 *
 * This file is part of the "u2up-log" software project.
 *
 *  Copyright 2019 Samo Pogacnik <samo_pogacnik@t-2.net>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
*/

/*
 * This "u2up-log" module provides various output definitions in a single header file.
 */

#ifndef U2UP_LOG_FILE_u2up_log_h
#define U2UP_LOG_FILE_u2up_log_h

/*
 * Here starts the PUBLIC stuff.
 */

#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

extern unsigned int u2up_log_use_syslog;
extern unsigned int u2up_log_normal;
extern unsigned int u2up_log_verbose;
extern unsigned int u2up_log_trace;
extern unsigned int u2up_log_debug;
extern unsigned int u2up_log_add_header;

#define U2UP_LOG_MODULE_INIT(name, value)\
static const char *u2up_log_module_name = #name;\
/*Not yet needed:static const unsigned int u2up_log_module_value = value;*/\

#define U2UP_LOG_5DIGIT_SECS(timespec_x) (timespec_x.tv_sec % 100000)
#define U2UP_LOG_6DIGIT_USECS(timespec_x) (timespec_x.tv_nsec / 1000)

#define U2UP_LOG_WITH_HEADER_DEBUG_FORMAT "[%05ld.%06ld|%d|%s] %s:%d %s(): "
#define U2UP_LOG_WITH_HEADER_DEBUG_ARGS U2UP_LOG_5DIGIT_SECS(ts), U2UP_LOG_6DIGIT_USECS(ts), (int)syscall(SYS_gettid), u2up_log_module_name, __FILE__, __LINE__, __FUNCTION__
#define U2UP_LOG_WITH_HEADER_TRACE_FORMAT "[%05ld.%06ld|%d|%s] %s(): "
#define U2UP_LOG_WITH_HEADER_TRACE_ARGS U2UP_LOG_5DIGIT_SECS(ts), U2UP_LOG_6DIGIT_USECS(ts), (int)syscall(SYS_gettid), u2up_log_module_name, __FUNCTION__
#define U2UP_LOG_WITH_HEADER_NORMAL_FORMAT "[%05ld.%06ld|%d|%s] "
#define U2UP_LOG_WITH_HEADER_NORMAL_ARGS U2UP_LOG_5DIGIT_SECS(ts), U2UP_LOG_6DIGIT_USECS(ts), (int)syscall(SYS_gettid), u2up_log_module_name

#define U2UP_LOG_NO_HEADER_DEBUG_FORMAT "%s:%d %s(): "
#define U2UP_LOG_NO_HEADER_DEBUG_ARGS __FILE__, __LINE__, __FUNCTION__
#define U2UP_LOG_NO_HEADER_TRACE_FORMAT "%s(): "
#define U2UP_LOG_NO_HEADER_TRACE_ARGS __FUNCTION__
#define U2UP_LOG_NO_HEADER_NORMAL_FORMAT "%s"
#define U2UP_LOG_NO_HEADER_NORMAL_ARGS ""

#define u2up_log_system_error(format, args...) {\
	char buf[1024];\
	strerror_r(errno, buf, 1024);\
	if (u2up_log_add_header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, buf, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, buf, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, buf, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, buf, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, buf, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, buf, ##args);\
				fflush(stderr);\
			}\
		}\
	} else {\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, buf, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_TRACE_ARGS, buf, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, buf, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, buf, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_TRACE_ARGS, buf, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, buf, ##args);\
				fflush(stderr);\
			}\
		}\
	}\
}

#define u2up_log_error(format, args...) {\
	if (u2up_log_add_header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stderr);\
			}\
		}\
	} else {\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stderr);\
			}\
		}\
	}\
}

#define u2up_log_warning(format, args...) {\
	if (u2up_log_add_header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_WARNING, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_WARNING, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				syslog(LOG_WARNING, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_WARNING, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_WARNING, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				syslog(LOG_WARNING, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_notice(format, args...) {\
	if (u2up_log_add_header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_NOTICE, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_NOTICE, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				syslog(LOG_NOTICE, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_NOTICE, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_NOTICE, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				syslog(LOG_NOTICE, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (u2up_log_normal || u2up_log_verbose) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_info(format, args...) {\
	if (u2up_log_add_header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_INFO, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_INFO, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else if (u2up_log_verbose) {\
				syslog(LOG_INFO, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (u2up_log_verbose) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_INFO, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				syslog(LOG_INFO, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else if (u2up_log_verbose) {\
				syslog(LOG_INFO, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && u2up_log_trace) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (u2up_log_verbose) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_debug(format, args...) {\
	if (u2up_log_add_header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_DEBUG, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (u2up_log_use_syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				syslog(LOG_DEBUG, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && u2up_log_debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_return_system_err(msg, args...) {\
	int errsv = errno;\
	u2up_log_system_error(msg, ##args);\
	return -errsv;\
}

#define u2up_log_return_err(msg, args...) {\
	int errsv = errno;\
	u2up_log_error(msg, ##args);\
	return -errsv;\
}

#endif /*U2UP_LOG_FILE_u2up_log_h*/

