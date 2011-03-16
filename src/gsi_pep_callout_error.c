/*
 * Copyright (c) Members of the EGEE Collaboration. 2008.
 * See http://www.eu-egee.org/partners for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 *
 * $Id$
 */
#include <syslog.h>
#include <stdarg.h>

#include "gsi_pep_callout.h"
#include "gsi_pep_callout_error.h"
#include "version.h"

/*
 * Error strings for gsi_pep_callout_error_t
 *
 * GSI_PEP_CALLOUT_ERROR_OK 				= 0,
 * GSI_PEP_CALLOUT_ERROR_CONFIG 			= 1,
 * GSI_PEP_CALLOUT_ERROR_HASHTABLE 			= 2,
 * GSI_PEP_CALLOUT_ERROR_MEMORY 			= 3,
 * GSI_PEP_CALLOUT_ERROR_PEP_CLIENT 		= 4,
 * GSI_PEP_CALLOUT_ERROR_OPENSSL 			= 5,
 * GSI_PEP_CALLOUT_ERROR_GSSAPI 			= 6,
 * GSI_PEP_CALLOUT_ERROR_GSI_CREDENTIAL 	= 7,
 * GSI_PEP_CALLOUT_ERROR_IDENTITY_BUFFER 	= 8,
 * GSI_PEP_CALLOUT_ERROR_AUTHZ 				= 9,
 * GSI_PEP_CALLOUT_ERROR_XACML 				= 10,
 * GSI_PEP_CALLOUT_ERROR_MODULE_ACTIVATION  = 11,
 * GSI_PEP_CALLOUT_ERROR_LAST_NOT_USED 		= 12
 */

char * gsi_pep_callout_error_strings[GSI_PEP_CALLOUT_ERROR_LAST_NOT_USED] =
{
	"OK",
	"Configuration error",
	"Hashtable error",
	"Memory error",
	"PEP client error",
	"OpenSSL error",
	"GSSAPI error",
	"GSI credential error",
	"Identity buffer error",
	"Authorization error",
	"XACML error",
	"Module activation error",
};

/**
 * Module activation/deactivation prototypes
 */
static int gsi_pep_callout_error_activate(void);
static int gsi_pep_callout_error_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t gsi_pep_callout_error_module =
{
    "gsi_pep_callout_error",
    gsi_pep_callout_error_activate,
    gsi_pep_callout_error_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

static int syslog_enabled= 0;

/**
 * Module activation
 *
 * Open syslog LOG_LOCAL5 facility
 */
static int gsi_pep_callout_error_activate(void) {
	int rc= 0;
    // function name for error
	static char * _function_name_ = "gsi_pep_callout_error_activate";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    rc= globus_module_activate(GLOBUS_COMMON_MODULE);
    if (rc!=GLOBUS_SUCCESS) {
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
    	return rc;
    }
    rc= globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
    if (rc!=GLOBUS_SUCCESS) {
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
    	return rc;
    }

    // syslog
    openlog("gsi_pep_callout", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_LOCAL5);
    syslog_enabled= 1;

    GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("syslog (local5) enabled: %d\n",syslog_enabled));

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
    return rc;
}

/**
 * Module deactivation
 */
static int gsi_pep_callout_error_deactivate(void) {
    // function name for error
	static char * _function_name_ = "gsi_pep_callout_error_deactivate";
	int rc= 0;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

	// syslog
	closelog();

    globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
    globus_module_deactivate(GLOBUS_COMMON_MODULE);

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
    return rc;
}

static void log_syslog(int prio, const char * format, va_list args) {
	if (!syslog_enabled) return;
    vsyslog(prio, format, args);
}

void log_error(const char * format, ...) {
	if (!syslog_enabled) return;
	va_list args;
    va_start(args, format);
    log_syslog(LOG_ERR,format,args);
    va_end(args);
}

void log_info(const char * format, ...) {
	if (!syslog_enabled) return;
	va_list args;
    va_start(args, format);
    log_syslog(LOG_INFO,format,args);
    va_end(args);
}

void log_debug(const char * format, ...) {
	if (!syslog_enabled) return;
	va_list args;
    va_start(args, format);
    log_syslog(LOG_DEBUG,format,args);
    va_end(args);
}

void log_set_enabled(int enabled) {
	syslog_enabled= enabled;
}

int log_is_enabled(void) {
	return syslog_enabled;
}
