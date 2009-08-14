#include <globus_common.h>
#include "gsi_pep_callout_config.h"
#include <stdio.h>

int main(int argc, char **argv) {
	int rc= 0;
	globus_result_t result= GLOBUS_SUCCESS;

	char key[256];
	char value[256];

	if ((rc= sscanf("key = value","%s=%s",key,value)) < 2) {
		printf("ERROR: scanf: %d\n",rc);
	}
	if ((rc= sscanf("key value","%s %s",key,value)) < 2) {
		printf("ERROR: scanf: %d\n",rc);
	}


	rc = globus_module_activate(GSI_PEP_CALLOUT_CONFIG_MODULE);
	printf("activate GSI_PEP_CALLOUT_CONFIG_MODULE: %d\n",rc);

	const char * filename= gsi_pep_callout_config_getfilename();
	printf("config: %s\n",filename);

	result= gsi_pep_callout_config_read(filename);
	if (result!=GLOBUS_SUCCESS) {
		globus_object_t *error= globus_error_get(result);
		char * error_string= globus_error_print_chain(error);
		printf("GLOBUS ERROR: %s",error_string);
		goto error;
	}

	#define MYKEY "key1"
	const char * param= gsi_pep_callout_config_getvalue(MYKEY);
	if (param) {
		printf("config[%s]: %s\n", MYKEY, param);
	}
	else {
		printf("ERROR: no value found for key: %s\n",MYKEY);
	}

	#define PEPD_URL "pepd_url"
	const keyvalue_t * kv= gsi_pep_callout_config_getkeyvalue(PEPD_URL);
	if (kv) {
		printf("config[%s]: %s\n", kv->key, kv->value);
		while (kv->next) {
			kv= kv->next;
			printf("config[%s]: %s\n", kv->key, kv->value);
		}
	}
	else {
		printf("ERROR: no keyvalue found for key: %s\n",PEPD_URL);
	}


error:

	rc = globus_module_deactivate(GSI_PEP_CALLOUT_CONFIG_MODULE);
	printf("deactivate GSI_PEP_CALLOUT_CONFIG_MODULE: %d\n",rc);

	return 0;
}
