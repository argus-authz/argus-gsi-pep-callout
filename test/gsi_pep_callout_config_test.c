#include <globus_common.h>
#include "gsi_pep_callout.h"
#include "gsi_pep_callout_config.h"
#include <stdio.h>

int main(int argc, char **argv) {
	int rc= 0;
	globus_result_t result= GLOBUS_SUCCESS;

	char key[256];
	char value[256];

	result= globus_module_activate(GSI_PEP_CALLOUT_MODULE);
	if (result!=GLOBUS_SUCCESS) {
		globus_object_t *error= globus_error_get(result);
		char * error_string= globus_error_print_chain(error);
		printf("GLOBUS ERROR: %s",error_string);
		goto error;
	}
	printf("activated GSI_PEP_CALLOUT_MODULE: %d\n",result);

	const char * filename= gsi_pep_callout_config_getfilename();
	printf("config: %s\n",filename);

	result= gsi_pep_callout_config_load();
	if (result!=GLOBUS_SUCCESS) {
		globus_object_t *error= globus_error_get(result);
		char * error_string= globus_error_print_chain(error);
		printf("GLOBUS ERROR: %s",error_string);
		goto error;
	}

	#define MYKEY "key1"
	const char * param= gsi_pep_callout_config_getvalue(MYKEY,NULL);
	if (param) {
		printf("config[%s]: %s=%s\n", filename,MYKEY, param);
	}
	else {
		printf("OK: no value found for key: %s\n",MYKEY);
	}

	const keyvalue_t * kv;
	kv= gsi_pep_callout_config_getkeyvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL);
	if (kv) {
		printf("config[%s]: %s=%s\n", filename, kv->key, kv->value);
		while (kv->next) {
			kv= kv->next;
			printf("config[%s]: %s=%s\n", filename, kv->key, kv->value);
		}
	}
	else {
		printf("ERROR: no keyvalue found for key: %s\n",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL);
	}

	kv= gsi_pep_callout_config_getkeyvalue(GSI_PEP_CALLOUT_CONFIG_KEY_XACML_RESOURCEID);
	if (kv) {
		printf("config[%s]: %s=%s\n", filename, kv->key, kv->value);
		while (kv->next) {
			kv= kv->next;
			printf("config[%s]: %s=%s\n", filename, kv->key, kv->value);
		}
	}
	else {
		printf("ERROR: no keyvalue found for key: %s\n",GSI_PEP_CALLOUT_CONFIG_KEY_XACML_RESOURCEID);
	}

error:

	rc = globus_module_deactivate(GSI_PEP_CALLOUT_MODULE);
	printf("deactivated GSI_PEP_CALLOUT_MODULE: %d\n",rc);

	return 0;
}
