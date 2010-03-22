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
 * $Id$
 */

#include <stdlib.h>
#include <unistd.h>

#include "gsi_pep_callout.h"
#include "gsi_pep_callout_error.h"
#include "gsi_pep_callout_config.h"
#include "version.h"

/**
 * Module activation/deactivation prototypes
 */
static int gsi_pep_callout_config_activate(void);
static int gsi_pep_callout_config_deactivate(void);

/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t gsi_pep_callout_config_module =
{
    "gsi_pep_callout_config",
    gsi_pep_callout_config_activate,
    gsi_pep_callout_config_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Hashtable for PEP-C config params
 */
#define CONFIG_HASHTABLE_SIZE 32
static globus_hashtable_t config_hashtable;
#define CONFIG_FILENAME_LENGTH 1024
static char config_filename[CONFIG_FILENAME_LENGTH + 1];

/**
 * Creates a key value pair.
 */
static keyvalue_t * keyvalue_alloc(const char *key, const char * value) {
    keyvalue_t * kv= calloc(1,sizeof(keyvalue_t));
    if (kv==NULL) {
    	return NULL;
    }
    char * kv_key= strdup(key);
    if (kv_key==NULL) {
    	free(kv);
    	return NULL;
    }
    char * kv_value= strdup(value);
    if (kv_value==NULL) {
    	free(kv_key);
    	free(kv);
    	return NULL;
    }
    kv->key= kv_key;
    kv->value= kv_value;
    kv->next= NULL;
    return kv;
}

/**
 * Releases a keyvalue pair
 * @see globus_hashtable_free_all
 */
static void keyvalue_free(keyvalue_t * kv) {
	if (kv) {
		if (kv->key) free(kv->key);
		if (kv->value) free(kv->value);
		if (kv->next) {
			keyvalue_free(kv->next);
		}
		free(kv);
	}
}

/**
 * Reads and parses the given config file. Populate the configuration hashtable
 * with the key,value pairs.
 */
globus_result_t gsi_pep_callout_config_load(void)
{
	globus_result_t result= GLOBUS_SUCCESS;
	FILE * config_file;
	char buffer[1024];
	char key[256];
	char value[256];
    char * pound;
    int index;

    // function name for error and debug
	static char * _function_name_ = "gsi_pep_callout_config_load";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(3);

	// open config file
	GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("filename: %s\n", config_filename));

	config_file= fopen(config_filename,"r");
	if (config_file == NULL) {
		GSI_PEP_CALLOUT_ERRNO_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_CONFIG,
            ("Configuration file %s", config_filename));
        goto error_exit;
	}

	// read config
	int line_num= 0;
    while(fgets(buffer,1024,config_file))
    {
    	line_num++;
    	GSI_PEP_CALLOUT_DEBUG_PRINTF(9,("file[%d]: %s\n", line_num,buffer));
        /* strip any comments */
        pound = strchr(buffer, '#');
        if(pound != NULL) {
            *pound = '\0';
        }

        /* strip white space from start */
        index = 0;
        while (buffer[index] == '\t' || buffer[index] == ' ') {
            index++;
            // boundary check
            if (index > 1024) {
                GSI_PEP_CALLOUT_ERROR(
                    result,
                    GSI_PEP_CALLOUT_ERROR_CONFIG,
                    ("file %s: line %d too long",config_filename,line_num));
                goto error_exit;
            }
        }
    	//GSI_PEP_CALLOUT_DEBUG_PRINTF(9,("index: %d\n", index));

        /* if blank line continue */
        if (buffer[index] == '\0' || buffer[index] == '\n') {
            continue;
        }

        if (sscanf(&buffer[index],"%255s %255s",key,value) < 2) {
            GSI_PEP_CALLOUT_ERROR(
                result,
                GSI_PEP_CALLOUT_ERROR_CONFIG,
                ("file %s: line %d malformed: %s", config_filename,line_num, &buffer[index]));
            goto error_exit;
        }

        // push key,value in hash table
        keyvalue_t * kv= keyvalue_alloc(key,value);
        if (kv==NULL) {
        	GSI_PEP_CALLOUT_ERRNO_ERROR(
                result,
                GSI_PEP_CALLOUT_ERROR_MEMORY,
                ("keyvalue_alloc(%s,%s): can't allocate keyvalue pair",key,value));
            goto error_exit;
        }
        int rc= 0;
        GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("key_value(%s,%s)\n",kv->key,kv->value));
        if ((rc= globus_hashtable_insert(&config_hashtable, kv->key, kv)) == -1) {
        	// already exists, try to link new with existing
        	keyvalue_t * existing_kv= globus_hashtable_lookup(&config_hashtable,kv->key);
        	if (existing_kv) {
        		while (existing_kv->next) {
        			existing_kv= existing_kv->next;
        		}
                GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("key: %s have multiple value: %s\n",kv->key,kv->value));
        		existing_kv->next= kv;
        	}
        	else {
            	GSI_PEP_CALLOUT_ERROR(
                    result,
                    GSI_PEP_CALLOUT_ERROR_HASHTABLE,
                    ("globus_hashtable_insert(%s,%s) failed: %d",kv->key,kv->value,rc));
                goto error_exit;
        	}
        }
        else if (rc != 0) {
        	GSI_PEP_CALLOUT_ERROR(
                result,
                GSI_PEP_CALLOUT_ERROR_HASHTABLE,
                ("globus_hashtable_insert(%s,%s) failed: %d",kv->key,kv->value,rc));
            goto error_exit;
        }
    }

error_exit:
	// close file
    if (config_file) fclose(config_file);

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,result);

	return result;
}

/**
 * Returns the value associated with the given key.
 * If the key is not found, the default value is returned.
 */
const char * gsi_pep_callout_config_getvalue(const char * key, const char * default_value) {
    // function name for error and debug
	static char * _function_name_ = "gsi_pep_callout_config_getvalue";

	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("key: %s\n", key));

	const keyvalue_t * kv= gsi_pep_callout_config_getkeyvalue(key);
	if (kv) {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("key: %s value: %s\n", kv->key, kv->value));
		return kv->value;
	}
	else {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("key: %s NOT FOUND, return default: %s\n",key,default_value));
		return default_value;
	}
}

/**
 * Returns the keyvalue_t pair for the given key.
 * @param key The parameter key to look up.
 * @return NULL if the keyvalue_t pair is not found.
 */
const keyvalue_t * gsi_pep_callout_config_getkeyvalue(const char *key) {
    // function name for error and debug
	static char * _function_name_ = "gsi_pep_callout_config_getkeyvalue";

	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("key: %s\n", key));

	keyvalue_t * kv= globus_hashtable_lookup(&config_hashtable,(void *)key);
	return kv;
}

/**
 * Returns the configuration filename to use:
 *
 * 1. Environment variable GSI_PEP_CALLOUT_CONF value if env set and file exists
 * 2. Default file /etc/grid-security/gsi-pep-callout.conf
 */
const char * gsi_pep_callout_config_getfilename(void) {
	return config_filename;
}

/**
 * Module activation:
 * - The internal hashtable is allocated.
 * - The default configuration file is determined.
 */
static int gsi_pep_callout_config_activate(void)
{
    // function name for error
	static char * _function_name_ = "gsi_pep_callout_config_activate";
	globus_result_t result= GLOBUS_SUCCESS;
	struct stat stat_buffer;
	int rc= 0;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    // allocate the config hashtable
    if ((rc= globus_hashtable_init(&config_hashtable,
    		CONFIG_HASHTABLE_SIZE,
    		globus_hashtable_string_hash,
    		globus_hashtable_string_keyeq)) != 0) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_HASHTABLE,
				("can not create configuration hashtable: %d", rc));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
    }

    // determine config filename
    // file buffer with 0
	memset(&config_filename,0,CONFIG_FILENAME_LENGTH + 1);

	// 1. try environment variable GSI_PEP_CALLOUT_CONF
	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("getenv %s\n",GSI_PEP_CALLOUT_CONFIG_GETENV));
	char * env_filename= globus_module_getenv(GSI_PEP_CALLOUT_CONFIG_GETENV);
	if (env_filename!=NULL && strlen(env_filename)>0) {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("%s=%s\n",GSI_PEP_CALLOUT_CONFIG_GETENV,env_filename));
		// file exists ??
		if ((rc= stat(env_filename,&stat_buffer)) != 0) {
			GSI_PEP_CALLOUT_ERRNO_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_CONFIG,
					("Configuration GSI_PEP_CALLOUT_CONF=%s does not exist", env_filename));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
		// readable ??
		if ((rc= access(env_filename,R_OK)) != 0) {
			GSI_PEP_CALLOUT_ERRNO_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_CONFIG,
					("Configuration GSI_PEP_CALLOUT_CONF=%s is not readable", env_filename));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
		// everythink ok
		strncpy(config_filename,env_filename,CONFIG_FILENAME_LENGTH);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("using GSI_PEP_CALLOUT_CONF=%s\n",config_filename));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}

	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("env var %s not set\n",GSI_PEP_CALLOUT_CONFIG_GETENV));

	// 2. try to use default /etc/grid-security/gsi-pep-callout.conf
	// exists?
	if ((rc= stat(GSI_PEP_CALLOUT_CONFIG_DEFAULT_FILE,&stat_buffer)) != 0) {
		GSI_PEP_CALLOUT_ERRNO_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Default configuration %s does not exist", GSI_PEP_CALLOUT_CONFIG_DEFAULT_FILE));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}
	// readable ??
	if ((rc= access(GSI_PEP_CALLOUT_CONFIG_DEFAULT_FILE,R_OK)) != 0) {
		GSI_PEP_CALLOUT_ERRNO_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Default configuration %s is not readable", GSI_PEP_CALLOUT_CONFIG_DEFAULT_FILE));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}
	// everythink ok

	strncpy(config_filename,GSI_PEP_CALLOUT_CONFIG_DEFAULT_FILE,CONFIG_FILENAME_LENGTH);
	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("using default: %s\n",config_filename));
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
    return GLOBUS_SUCCESS;
}

/**
 * Module deactivation
 */
static int gsi_pep_callout_config_deactivate(void) {
    // function name for error
	static char * _function_name_ = "gsi_pep_callout_config_deactivate";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

	int rc= GLOBUS_SUCCESS;
	// release the config hashtable
    globus_hashtable_destroy_all(&config_hashtable,(globus_hashtable_destructor_func_t)keyvalue_free);

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
	return rc;
}

