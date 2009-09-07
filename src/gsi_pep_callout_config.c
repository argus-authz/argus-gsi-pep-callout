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

#include <stdlib.h>

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
globus_hashtable_t config_hashtable;
#define CONFIG_FILENAME_LENGTH 1024
char config_filename[CONFIG_FILENAME_LENGTH + 1];

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
    	free(kv->key);
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
globus_result_t gsi_pep_callout_config_read(const char *filename)
{
	globus_result_t result= GLOBUS_SUCCESS;
	FILE * config_file;
	char buffer[1024];
	char key[256];
	char value[256];
    char * pound;
    int index;

    // function name for error and debug
	static char * _function_name_ = "gsi_pep_callout_config_read";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(3);

	// open config file
	GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("filename: %s\n", filename));

	config_file= fopen(filename,"r");
	if (config_file == NULL) {
		GSI_PEP_CALLOUT_ERRNO_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_CONFIG,
            ("Configuration file %s", filename));
        goto error_exit;
	}

	// read config
	int line_num= 0;
    while(fgets(buffer,1024,config_file))
    {
    	line_num++;
        /* strip any comments */
        pound = strchr(buffer, '#');
        if(pound != NULL) {
            *pound = '\0';
        }

        /* strip white space from start */
        index = 0;
        while (buffer[index] == '\t' || buffer[index] == ' ') {
            index++;
        }

        /* if blank line continue */
        if (buffer[index] == '\0' || buffer[index] == '\n') {
            continue;
        }

        if (sscanf(&buffer[index],"%255s %255s",key,value) < 2) {
            GSI_PEP_CALLOUT_ERROR(
                result,
                GSI_PEP_CALLOUT_ERROR_CONFIG,
                ("file %s: line %d malformed: %s", filename,line_num, &buffer[index]));
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
 * 2. User file $HOME/.gsi-pep-callout.conf if file exists
 * 3. Default file /etc/grid-security/gsi-pep-callout.conf
 */
const char * gsi_pep_callout_config_getfilename(void) {
	return config_filename;
}

/**
 * 1. environment variable GSI_PEP_CALLOUT_CONF
 * 2. user file $HOME/.gsi-pep-callout.conf
 * 3. /etc/grid-security/gsi-pep-callout.conf
 */
static int determine_config_filename(void) {
    // function name for error and debug
	static char * _function_name_ = "determine_config_filename";

	int rc= 0;
	FILE * fd;
	char * home_filename= NULL;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    // file buffer with 0
	memset(&config_filename,0,CONFIG_FILENAME_LENGTH + 1);
	// 1. try environment variable
	char * env_filename= globus_module_getenv(GSI_PEP_CALLOUT_CONFIG_GETENV);
	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("getenv: %s=%s\n",GSI_PEP_CALLOUT_CONFIG_GETENV,env_filename));
	if (env_filename!=NULL && strlen(env_filename)>0) {
		if ((fd= fopen(env_filename,"r")) != NULL) {
			fclose(fd);
			strncpy(config_filename,env_filename,CONFIG_FILENAME_LENGTH);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("from env: %s\n",config_filename));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
			return rc;
		}
		else {
			GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("env=%s doesn't exist\n",env_filename));
		}
	}
	else {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("env var %s not set\n",GSI_PEP_CALLOUT_CONFIG_GETENV));
	}

	// 2. try user home
	char * home = globus_module_getenv("HOME");
	if (home!=NULL && strlen(home)>0) {
		home_filename= calloc(CONFIG_FILENAME_LENGTH + 1,sizeof(char));
		if (home_filename==NULL) {
			rc = -1;
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
			return rc;
		}
		strncpy(home_filename,home,CONFIG_FILENAME_LENGTH);
		size_t count= CONFIG_FILENAME_LENGTH - strlen(home_filename);
		if (home_filename[strlen(home_filename)-1] != '/') {
			strncat(home_filename,"/",count);
			count= count - strlen(home_filename);
		}
		strncat(home_filename,GSI_PEP_CALLOUT_CONFIG_DEFAULT_USER_FILE,count);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("user file: %s\n",home_filename));

		if ((fd= fopen(home_filename,"r")) != NULL) {
			fclose(fd);
			strncpy(config_filename,home_filename,CONFIG_FILENAME_LENGTH);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("from user file: %s\n",config_filename));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
			return rc;
		}
		else {
			GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("user file %s doesn't exist\n",home_filename));
		}
	}

	// 3. use default
	strncpy(config_filename,GSI_PEP_CALLOUT_CONFIG_DEFAULT_FILE,CONFIG_FILENAME_LENGTH);
	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("default: %s\n",config_filename));

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
	return rc;

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

	int rc= 0;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    rc= globus_module_activate(GLOBUS_COMMON_MODULE);
    rc= globus_module_activate(GSI_PEP_CALLOUT_ERROR_MODULE);

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
    if ((rc= determine_config_filename()) != 0) {
		GSI_PEP_CALLOUT_ERRNO_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("can not determine configuration filename: %d", rc));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
    }

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
    return rc;
}

/**
 * Module deactivation
 */
static int gsi_pep_callout_config_deactivate(void) {
    // function name for error
	static char * _function_name_ = "gsi_pep_callout_config_deactivate";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

	int rc= 0;
	// release the config hashtable
    globus_hashtable_destroy_all(&config_hashtable,(globus_hashtable_destructor_func_t)keyvalue_free);

    rc= globus_module_deactivate(GSI_PEP_CALLOUT_ERROR_MODULE);
    rc= globus_module_deactivate(GLOBUS_COMMON_MODULE);
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,rc);
	return rc;
}

