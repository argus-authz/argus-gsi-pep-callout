/*
 * Copyright 2009 Members of the EGEE Collaboration.
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
 * $Id$
 */

#ifndef _GSI_PEP_CALLOUT_H_
#define _GSI_PEP_CALLOUT_H_

#ifdef  __cplusplus
extern "C" {
#endif

/***********************************************/
/******* INTERNAL HEADER, DON'T USE ************/
/***********************************************/

#include <globus_common.h>

/**
 * DEBUG macros
 *
 * Set environment variables GSI_PEP_CALLOUT_DEBUG_LEVEL
 * and GSI_PEP_CALLOUT_DEBUG_FILE for debugging.
 */
extern int gsi_pep_callout_debug_level;
extern FILE * gsi_pep_callout_debug_fstream;

#define GSI_PEP_CALLOUT_DEBUG(_LEVEL_) \
    (gsi_pep_callout_debug_level >= (_LEVEL_))

#define GSI_PEP_CALLOUT_DEBUG_FPRINTF(_LEVEL_, _FPRINTF_ARGS_) {  \
    if (GSI_PEP_CALLOUT_DEBUG(_LEVEL_)) {                    \
        globus_libc_fprintf _FPRINTF_ARGS_;                       \
    }                                                        \
}

#define GSI_PEP_CALLOUT_DEBUG_PRINTF(_LEVEL_, _MESSAGE_) {      \
	if (GSI_PEP_CALLOUT_DEBUG(_LEVEL_)) {                       \
	   char * _msg_str_= globus_common_create_string _MESSAGE_; \
	   GSI_PEP_CALLOUT_DEBUG_FPRINTF( _LEVEL_, \
			(gsi_pep_callout_debug_fstream, \
					"DEBUG%d:%s: %s",_LEVEL_,_function_name_,_msg_str_)) \
	   globus_libc_free(_msg_str_);                             \
	}                                                           \
}

#define GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN \
	GSI_PEP_CALLOUT_DEBUG_FPRINTF( \
			1, (gsi_pep_callout_debug_fstream, \
					"DEBUG1:%s: begin\n", _function_name_))

#define GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(_RC_) \
	GSI_PEP_CALLOUT_DEBUG_FPRINTF( \
			1, (gsi_pep_callout_debug_fstream, \
					"DEBUG1:%s: return %d\n",_function_name_,(int)_RC_))


/**
 * Module descriptor
 */
extern globus_module_descriptor_t gsi_pep_callout_module;
#define GSI_PEP_CALLOUT_MODULE (&gsi_pep_callout_module)

/**
 * ARGUS Authorization Service PEP callout function
 *
 * This function provides a authorization/mapping callout to the ARGUS AuthZ Service PEP.
 *
 * @param ap
 *        This function, like all functions using the Globus Callout API, is
 *        passed parameter though the variable argument list facility. The
 *        actual arguments that are passed are:
 *
 *        - The GSS Security context established during service
 *          invocation. This parameter is of type gss_ctx_id_t.
 *        - The name of the service being invoced. This parameter should be
 *          passed as a NUL terminated string. If no service string is
 *          available a value of NULL should be passed in its stead. This
 *          parameter is of type char *
 *        - A NUL terminated string indicating the desired local identity. If
 *          no identity is desired NULL may be passed. In this case the first
 *          local identity that is found will be returned. This parameter is of
 *          type char *.
 *        - A pointer to a buffer. This buffer will contain the mapped (local)
 *          identity (NUL terminated string) upon successful return. This
 *          parameter is of type char *.
 *        - The length of the above mentioned buffer. This parameter is of type
 *          unsigned int.
 *
 * @return
 *        GLOBUS_SUCCESS upon success
 *        A globus result structure upon failure (needs to be defined better)
 */
globus_result_t authz_pep_callout(va_list ap);


#ifdef  __cplusplus
}
#endif


#endif /* _GSI_PEP_CALLOUT_H_ */
