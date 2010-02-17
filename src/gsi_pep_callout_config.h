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
 * $Id$
 */
#ifndef _GSI_PEP_CALLOUT_CONFIG_H_
#define _GSI_PEP_CALLOUT_CONFIG_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <globus_common.h>

//
// Config file constants
//
#define GSI_PEP_CALLOUT_CONFIG_GETENV 				"GSI_PEP_CALLOUT_CONF"
#define GSI_PEP_CALLOUT_CONFIG_DEFAULT_FILE 		"/etc/grid-security/gsi-pep-callout.conf"

/**
 *  PEP client config key constants
 */
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL 					"pep_url"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_TIMEOUT 				"pep_timeout"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_VALIDATION 		"pep_ssl_validation"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_CERT 		"pep_ssl_client_cert"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_KEY 		"pep_ssl_client_key"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_KEYPASS 	"pep_ssl_client_keypasswd"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_SERVER_CERT 		"pep_ssl_server_cert"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_SERVER_CAPATH 	"pep_ssl_server_capath"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_LOG_LEVEL 			"pep_log_level"
#define GSI_PEP_CALLOUT_CONFIG_KEY_PEP_LOG_FILE 			"pep_log_file"

/**
 * XACML message config key constants
 */
#define GSI_PEP_CALLOUT_CONFIG_KEY_XACML_RESOURCEID 		"xacml_resourceid"
#define GSI_PEP_CALLOUT_CONFIG_KEY_XACML_ACTIONID 			"xacml_actionid"

/**
 * Globus module descriptor
 */
#define GSI_PEP_CALLOUT_CONFIG_MODULE (&gsi_pep_callout_config_module)
extern globus_module_descriptor_t gsi_pep_callout_config_module;

/**
 * <key,value> pair type
 */
typedef struct keyvalue_s {
	char * key;
	char * value;
	struct keyvalue_s * next;
} keyvalue_t;

//
// Function prototypes
//

/**
 * Returns the configuration filename
 */
const char * gsi_pep_callout_config_getfilename(void);

/**
 * Reads the configuration from given filename
 */
globus_result_t gsi_pep_callout_config_read(const char *filename);

/**
 * Returns the first configuration value for the given key.
 * Returns default_value if the key is not found.
 */
const char * gsi_pep_callout_config_getvalue(const char *key, const char *default_value);

/**
 * Returns the configuration <key,value,next> pair for the given key.
 * Used for multi-valued key. e.g. kv->next ...
 * NULL if not found.
 */
const keyvalue_t * gsi_pep_callout_config_getkeyvalue(const char *key);

#ifdef  __cplusplus
}
#endif

#endif /* _GSI_PEP_CALLOUT_CONFIG_H_ */
