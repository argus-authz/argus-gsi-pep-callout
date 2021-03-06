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

#ifndef _GSI_PEP_CALLOUT_ERROR_H_
#define _GSI_PEP_CALLOUT_ERROR_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <globus_common.h>
#include <globus_error_gssapi.h> /* globus_error_wrap_gssapi_error */
#include <globus_error_openssl.h> /* globus_error_wrap_openssl_error */

/**
 * Module descriptor
 */
extern globus_module_descriptor_t gsi_pep_callout_error_module;
#define GSI_PEP_CALLOUT_ERROR_MODULE (&gsi_pep_callout_error_module)

/**
 * GSI PEP Callout Error codes
 *
 * number the error types -> fill the message table
 */
typedef enum
{
    GSI_PEP_CALLOUT_ERROR_OK = 0,
    GSI_PEP_CALLOUT_ERROR_CONFIG,
    GSI_PEP_CALLOUT_ERROR_HASHTABLE,
    GSI_PEP_CALLOUT_ERROR_MEMORY,
    GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
    GSI_PEP_CALLOUT_ERROR_OPENSSL,
    GSI_PEP_CALLOUT_ERROR_GSSAPI,
    GSI_PEP_CALLOUT_ERROR_GSI_CREDENTIAL,
    GSI_PEP_CALLOUT_ERROR_IDENTITY_BUFFER,
    GSI_PEP_CALLOUT_ERROR_AUTHZ,
    GSI_PEP_CALLOUT_ERROR_XACML,
    GSI_PEP_CALLOUT_ERROR_MODULE_ACTIVATION,
    GSI_PEP_CALLOUT_ERROR_LAST_NOT_USED,
}
gsi_pep_callout_error_t;
extern char * gsi_pep_callout_error_strings[];

/**
 * Logging facility
 */
void syslog_error(const char * format, ...);
void syslog_info(const char * format, ...);
void syslog_debug(const char * format, ...);
void log_set_enabled(int enabled);
int log_is_enabled(void);

/**
 * ERROR MACROS
 */
#define GSI_PEP_CALLOUT_ERROR_LOG(_ERRORTYPE_, _ERRORSTR_) \
{      \
	char * _tmp_str_= globus_common_create_string _ERRORSTR_;    \
	syslog_error( \
		"%s: %s%s%s%s",  \
		_function_name_,                                             \
		gsi_pep_callout_error_strings[_ERRORTYPE_], \
        _tmp_str_ ? ": " : "",                                       \
        _tmp_str_ ? _tmp_str_ : "", "\n");                                \
	globus_libc_free(_tmp_str_);                             \
}


#define GSI_PEP_CALLOUT_ERROR(_RESULT_, _ERRORTYPE_, _ERRORSTR_)                \
{                                                                        \
    char * _tmp_str_ = globus_common_create_string _ERRORSTR_;             \
    _RESULT_= globus_error_put(                                                    \
        globus_error_construct_error(                                    \
            GSI_PEP_CALLOUT_ERROR_MODULE,                                \
            (_RESULT_) ? globus_error_get(_RESULT_) : NULL,              \
            _ERRORTYPE_,                                                      \
            __FILE__,                                                    \
			_function_name_,                                             \
            __LINE__,                                                    \
            "%s%s%s",                                                    \
            gsi_pep_callout_error_strings[_ERRORTYPE_],                       \
            _tmp_str_ ? ": " : "",                                       \
            _tmp_str_ ? _tmp_str_ : ""));                                \
    globus_libc_free(_tmp_str_);                                         \
    if (_RESULT_ == GLOBUS_SUCCESS) { \
    	GSI_PEP_CALLOUT_ERROR_LOG(_ERRORTYPE_,_ERRORSTR_); \
    	_RESULT_ = GLOBUS_FAILURE; \
    } \
}

#define GSI_PEP_CALLOUT_ERRNO_ERROR(_RESULT_, _ERRORTYPE_, _ERRORSTR_)   \
{                                                                        \
	char *  _tmp_str_ = globus_common_create_string _ERRORSTR_;          \
	_RESULT_= globus_error_put(                                                    \
		globus_error_wrap_errno_error(                                   \
			GSI_PEP_CALLOUT_ERROR_MODULE,                                \
			errno,                                                       \
			_ERRORTYPE_,                                                 \
			__FILE__,                                                    \
			_function_name_,                                             \
			__LINE__,                                                    \
			"%s",                                                        \
			_tmp_str_));                                                 \
	globus_libc_free(_tmp_str_);                                         \
    if (_RESULT_ == GLOBUS_SUCCESS) { \
    	GSI_PEP_CALLOUT_ERROR_LOG(_ERRORTYPE_,_ERRORSTR_); \
    	_RESULT_ = GLOBUS_FAILURE; \
    } \
}

#define GSI_PEP_CALLOUT_OPENSSL_ERROR(_RESULT_, _ERRORTYPE_, _ERRORSTR_)   \
{                                                                        \
	char *  _tmp_str_ = globus_common_create_string _ERRORSTR_;          \
	_RESULT_= globus_error_put(                                                    \
		globus_error_wrap_openssl_error(                                 \
			GSI_PEP_CALLOUT_ERROR_MODULE,                                \
			_ERRORTYPE_,                                                 \
			__FILE__,                                                    \
			_function_name_,                                             \
			__LINE__,                                                    \
			"%s",                                                        \
			_tmp_str_));                                                 \
	globus_libc_free(_tmp_str_);                                         \
    if (_RESULT_ == GLOBUS_SUCCESS) { \
    	GSI_PEP_CALLOUT_ERROR_LOG(_ERRORTYPE_,_ERRORSTR_); \
    	_RESULT_ = GLOBUS_FAILURE; \
    } \
}

#define GSI_PEP_CALLOUT_GSS_ERROR(_RESULT_, __MAJOR_STATUS, __MINOR_STATUS) \
{ \
	_RESULT_ = globus_error_put(                                                       \
        globus_error_wrap_gssapi_error(                                            \
            GSI_PEP_CALLOUT_ERROR_MODULE,                                   \
            __MAJOR_STATUS,                                                        \
            __MINOR_STATUS,                                                        \
            GSI_PEP_CALLOUT_ERROR_GSSAPI,                                   \
            __FILE__,                                                              \
			_function_name_,                                             \
            __LINE__,                                                              \
            "%s",                                                                  \
            gsi_pep_callout_error_strings[GSI_PEP_CALLOUT_ERROR_GSSAPI])); \
    if (_RESULT_ == GLOBUS_SUCCESS) { \
    	GSI_PEP_CALLOUT_ERROR_LOG(GSI_PEP_CALLOUT_ERROR_GSSAPI,("GSS error")); \
        _RESULT_ = GLOBUS_FAILURE; \
    } \
}

#ifdef  __cplusplus
}
#endif

#endif /* _GSI_PEP_CALLOUT_ERROR_H_ */
