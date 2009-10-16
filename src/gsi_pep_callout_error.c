/*
 * Copyright 2009 Members of the EGEE Collaboration.
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
 * GSI_PEP_CALLOUT_ERROR_XACML 				= 9,
 * GSI_PEP_CALLOUT_ERROR_AUTHZ 				= 10,
 * GSI_PEP_CALLOUT_ERROR_LAST 				= 11
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

/**
 * Module activation
 */
static int gsi_pep_callout_error_activate(void) {
	int rc= 0;
    // function name for error
	static char * _function_name_ = "gsi_pep_callout_error_activate";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    rc= globus_module_activate(GLOBUS_COMMON_MODULE);
    rc= globus_module_activate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);

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

    rc= globus_module_deactivate(GLOBUS_GSI_OPENSSL_ERROR_MODULE);
    rc= globus_module_deactivate(GLOBUS_COMMON_MODULE);

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
    return rc;
}

