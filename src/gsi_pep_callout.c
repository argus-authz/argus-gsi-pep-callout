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

#include <globus_common.h>
#include <gssapi.h>
#include <globus_gsi_credential.h>

#include <pep/pep.h>
#include <pep/profiles.h>
#include <pep/xacml.h>

#include <stdlib.h>

#include "gssapi_openssl.h" /* internal, define gss_ctx_id_t and gss_cred_id_t structure */

#include "gsi_pep_callout.h"
#include "gsi_pep_callout_error.h"
#include "gsi_pep_callout_config.h"
#include "version.h"

/**
 * Debugging level
 *
 * Currently this isn't terribly well defined. The idea is that 0 is no
 * debugging output, and 9 is a whole lot.
 */
int gsi_pep_callout_debug_level;

/**
 * Debugging Log File
 *
 * Debugging output gets written to this file
 */
FILE * gsi_pep_callout_debug_fstream;


/**
 * Module activation/deactivation prototypes
 */
static int gsi_pep_callout_activate(void);
static int gsi_pep_callout_deactivate(void);

/*
 * internal prototypes
 */
static globus_result_t gss_ctx_extract_peer_name(const gss_ctx_id_t gss_context, char ** peer_name);
static gss_cred_id_t get_gss_cred_id(const gss_ctx_id_t gss_context);
static globus_result_t gss_cred_extract_cert(const gss_cred_id_t gss_cred, X509 ** out_cert);
static globus_result_t gss_cred_extract_cert_chain(const gss_cred_id_t gss_cred,STACK_OF(X509) ** out_chain);
static globus_result_t x509_convert_to_PEM(const X509 * x509, const STACK_OF(X509) * chain, char ** out_pem);
static globus_result_t pep_client_configure(void);
static globus_result_t pep_client_create_request(const char *certchain,const char *resourceid, const char *actionid, xacml_request_t ** out_request);
static globus_result_t pep_client_authorize(const char *peer, const char * cert_chain, const char * actionid, char ** out_identity);

static int debug_xacml_request(int debug_level, const xacml_request_t * request);
static int debug_xacml_response(int debug_level, const xacml_response_t * response);

/**
 * ARGUS AuthZ Service PEP Callout Function
 *
 * This function provides a authorization/mapping callout to the ARGUS AuthZ Service PEP daemon.
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
 * It would be like to call: 
 *          authz_pep_callout(gss_ctx_id_t context,
 *                            char *       service,
 *                            char *       desired_identity,
 *                            char *       identity_buffer,
 *                            unsigned int identity_buffer_length);
 *
 * @return
 *        GLOBUS_SUCCESS upon success
 *        A globus result structure upon failure (needs to be defined better)
 */
globus_result_t authz_pep_callout(va_list ap)
{
	// va_list params
    gss_ctx_id_t                        gss_context;
    char *                              service;
    char *                              desired_identity;
    char *                              identity_buffer;
    unsigned int                        identity_buffer_l;

    // internal variables
    char * local_identity;
    globus_result_t result = GLOBUS_SUCCESS;
    X509 * x509= NULL;
    STACK_OF(X509) * chain= NULL;
    char * cert_chain= NULL;

    // function name for error macros
	static char * _function_name_ = "authz_pep_callout";

    // active module
    globus_module_activate(GSI_PEP_CALLOUT_MODULE);

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(1);

    // process va_list arguments
    gss_context= va_arg(ap, gss_ctx_id_t);
    service= va_arg(ap, char *);
    desired_identity= va_arg(ap, char *);
    identity_buffer= va_arg(ap, char *);
    identity_buffer_l= va_arg(ap, unsigned int);

    GSI_PEP_CALLOUT_DEBUG_PRINTF(
    		2 /* level */,
    		("service: %s\n", service == NULL ? "NULL" : service));
    GSI_PEP_CALLOUT_DEBUG_PRINTF(
            2,
            ("requested identity: %s\n",desired_identity == NULL ? "NULL" : desired_identity));

    // extract peer_name from context
    char *peer_name= NULL;
    if ((result= gss_ctx_extract_peer_name(gss_context,&peer_name))!=GLOBUS_SUCCESS) {
    	GSI_PEP_CALLOUT_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_GSSAPI,
            ("Can not extract peer name from GSS context"));
        goto error;
    }

    GSI_PEP_CALLOUT_DEBUG_PRINTF(
    		2 /* level */,
            ("peer name: %s\n", peer_name == NULL ? "NULL" : peer_name));

    // extract credentials  (X509 or proxy) from context
    gss_cred_id_t cred = get_gss_cred_id(gss_context);
    if (cred == NULL) {
    	GSI_PEP_CALLOUT_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_GSSAPI,
            ("GSS context does not contain GSS credentials"));
        goto error;
    }
    if ((result= gss_cred_extract_cert(cred, &x509)) != GLOBUS_SUCCESS) {
    	GSI_PEP_CALLOUT_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_GSSAPI,
            ("Can not extract cert from GSS credentials"));
        goto error;

    }
    if ((result= gss_cred_extract_cert_chain(cred, &chain)) != GLOBUS_SUCCESS) {
    	GSI_PEP_CALLOUT_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_GSSAPI,
            ("Can not extract cert chain from GSS credentials"));
        goto error;
    }

    if ((result= x509_convert_to_PEM(x509,chain,&cert_chain)) != GLOBUS_SUCCESS) {
    	GSI_PEP_CALLOUT_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("Can not convert X509 cert and chain to PEM"));
        goto error;
    }

    GSI_PEP_CALLOUT_DEBUG_PRINTF(
    		9 /* level */,
            ("X509 with chain:\n%s",
            cert_chain == NULL ? "NULL" : cert_chain));

    // configure PEP client
	if ((result= pep_client_configure()) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
				("Failed to configure PEP client"));
		goto error;
	}

	if ((result= pep_client_authorize(peer_name,cert_chain,service,&local_identity)) !=  GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
			result,
			GSI_PEP_CALLOUT_ERROR_AUTHZ,
			("Can not map %s to local identity", peer_name));
		goto error;
	}

	if (desired_identity != NULL) {
		if (strncmp(desired_identity,local_identity,strlen(local_identity)) != 0) {
			GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_AUTHZ,
				("Can not map desired identity %s to local identity %s", desired_identity,local_identity));
			goto error;
		}
    }

	if(strlen(local_identity) + 1 > identity_buffer_l)
	{
		GSI_PEP_CALLOUT_ERROR(
			result,
			GSI_PEP_CALLOUT_ERROR_IDENTITY_BUFFER,
			("Local identity length: %d Buffer length: %d\n",
			 strlen(local_identity), identity_buffer_l));
	}
	else
	{
		strncpy(identity_buffer,local_identity,identity_buffer_l);
	    GSI_PEP_CALLOUT_DEBUG_PRINTF(
	    		2 /* level */,
				("%s mapped to %s\n",
				peer_name, identity_buffer));
	}
	free(local_identity);



error:
	if (peer_name) free(peer_name);
	if (cert_chain) free(cert_chain);

	globus_module_deactivate(GSI_PEP_CALLOUT_MODULE);

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(1,result);

    return result;
}

/**
 * Caller must free the resulting peer_name
 */
static globus_result_t gss_ctx_extract_peer_name(const gss_ctx_id_t gss_context, char ** peer_name) {
    // function name for error macros
	static char * _function_name_ = "gss_ctx_extract_peer_name";
	globus_result_t result= GLOBUS_SUCCESS;
    OM_uint32 major_status;
    OM_uint32 minor_status;
    int locally_initiated;
    gss_name_t peer;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    // get source and target peer and initiator
    major_status= gss_inquire_context(&minor_status,
                                       gss_context,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       &locally_initiated,
                                       GLOBUS_NULL);
    if (GSS_ERROR(major_status)) {
    	GSI_PEP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
        return result;
    }

    // get source and target peer and initiator
    major_status= gss_inquire_context(&minor_status,
                                       gss_context,
                                       locally_initiated ? GLOBUS_NULL : &peer,
                                       locally_initiated ? &peer : GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL,
                                       GLOBUS_NULL);
    if (GSS_ERROR(major_status)) {
    	GSI_PEP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
        return result;
    }

	gss_buffer_desc peer_name_buffer;
	major_status= gss_display_name(&minor_status,
									peer,
									&peer_name_buffer,
									GLOBUS_NULL);
	if (GSS_ERROR(major_status)) {
		GSI_PEP_CALLOUT_GSS_ERROR(result, major_status, minor_status);
		gss_release_name(&minor_status,&peer);

		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}

	*peer_name= (char *)peer_name_buffer.value;

	gss_release_name(&minor_status,&peer);

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);

	return result;
}

/**
 * Returns the gss_cred_id handle from the GSS context.
 */
static gss_cred_id_t get_gss_cred_id(const gss_ctx_id_t gss_context)
{
	if (gss_context==NULL) {
		return NULL;
	}
	else {
		return (gss_cred_id_t)gss_context->peer_cred_handle;
	}
}

/**
 * Gets the X509 certificate from the GSS credential.
 */
static globus_result_t gss_cred_extract_cert(const gss_cred_id_t gss_cred, X509 ** out_cert)
{
    // function name for error macros
	static char * _function_name_ = "gss_cred_extract_cert";
	globus_result_t result= GLOBUS_SUCCESS;

	/* Internally a gss_cred_id_t type is a pointer to a gss_cred_id_desc */
    gss_cred_id_desc * cred_desc= NULL;
    globus_gsi_cred_handle_t gsi_cred;

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    /* cast to gss_cred_id_desc */
    if (gss_cred != GSS_C_NO_CREDENTIAL) {
        cred_desc = (gss_cred_id_desc *) gss_cred;
        gsi_cred = cred_desc->cred_handle;
        if ((result= globus_gsi_cred_get_cert(gsi_cred, out_cert)) != GLOBUS_SUCCESS) {
        	GSI_PEP_CALLOUT_ERROR(
                result,
                GSI_PEP_CALLOUT_ERROR_GSI_CREDENTIAL,
                ("Can not extract cert from GSI credential"));
        }
    }
    else {
    	GSI_PEP_CALLOUT_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_GSSAPI,
            ("No GSS credential available"));
    }

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
    return result;
}

/**
 * Gets the X509 certificate chain from the GSS credential.
 */
static globus_result_t gss_cred_extract_cert_chain(const gss_cred_id_t gss_cred,STACK_OF(X509) **out_chain)
{
    // function name for error macros
	static char * _function_name_ = "gss_cred_extract_cert_chain";
	globus_result_t result= GLOBUS_SUCCESS;

    // internally a gss_cred_id_t type is a pointer to a gss_cred_id_desc
    gss_cred_id_desc * cred_desc= NULL;
    globus_gsi_cred_handle_t gsi_cred;

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    /* cast to gss_cred_id_desc */
    if (gss_cred != GSS_C_NO_CREDENTIAL) {
        cred_desc = (gss_cred_id_desc *) gss_cred;
        gsi_cred = cred_desc->cred_handle;
        if ((result= globus_gsi_cred_get_cert_chain(gsi_cred,out_chain)) != GLOBUS_SUCCESS) {
        	GSI_PEP_CALLOUT_ERROR(
                result,
                GSI_PEP_CALLOUT_ERROR_GSI_CREDENTIAL,
                ("Can not extract cert chain from GSI credential"));
        }
    }
    else {
    	GSI_PEP_CALLOUT_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_GSSAPI,
            ("No GSS credential available"));
    }

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
    return result;
}

/**
 * Gets the X509 subject name as string.
 * out_subject must be release by the caller
 */
static globus_result_t x509_get_subject(const X509 * x509, char ** out_subject) {
    // function name for error macros
	static char * _function_name_ = "x509_get_subject";
	globus_result_t result= GLOBUS_SUCCESS;
	int rc= 0;

	BIO * bio = BIO_new(BIO_s_mem());
    if (bio==NULL) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't allocate subject bio buffer"));
    	return result;
    }

    // flags: XN_FLAG_RFC2253 & XN_FLAG_ONELINE ??
	if ((rc= X509_NAME_print_ex(bio,X509_get_subject_name((X509 *)x509),0,XN_FLAG_ONELINE)) != 0) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't write X509_NAME to subject bio buffer: %d",rc));
    	BIO_free(bio);
    	return result;
	}
    char *buffer= NULL;
    if ((rc= BIO_get_mem_data(bio,&buffer)) <= 0) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't read subject bio buffer: %d",rc));
    	BIO_free(bio);
    	return result;
    }
    *out_subject= strdup(buffer);
    if (*out_subject==NULL) {
    	GSI_PEP_CALLOUT_ERRNO_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_MEMORY,
            ("can't duplicate subject bio buffer: %s",buffer)); // WARN buffer can be big!!!
    }
    BIO_free(bio);
    return result;
}

/**
 * Converts the X509 certificate and chain to a PEM string
 * output_buffer should be release by the caller.
 */
static globus_result_t x509_convert_to_PEM(const X509 * x509, const STACK_OF(X509) * chain, char ** out_pem)
{
    // function name for error macros
	static char * _function_name_ = "x509_convert_to_PEM";
	globus_result_t result= GLOBUS_SUCCESS;
    int i, rc= 0;

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

    BIO * bio = BIO_new(BIO_s_mem());
    if (bio==NULL) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't allocate PEM bio buffer"));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
    	return result;
    }
    if ((rc= PEM_write_bio_X509(bio, (X509 *)x509)) != 1) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't write PEM cert into bio buffer: %d",rc));
        BIO_free(bio);
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
    	return result;
    }

    int chain_l= sk_X509_num(chain);
    for(i= 0; i<chain_l; i++) {
        X509 * x509elt= sk_X509_value(chain,i);
        if (x509elt == NULL) break;
        if ((rc= PEM_write_bio_X509(bio, x509elt)) != 1) {
        	GSI_PEP_CALLOUT_OPENSSL_ERROR(
                result,
                GSI_PEP_CALLOUT_ERROR_OPENSSL,
                ("can't write PEM cert chain %d into bio buffer: %d",i,rc));
            BIO_free(bio);
        	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
        	return result;
        }
    }
    char *buffer= NULL;
    if ((rc= BIO_get_mem_data(bio,&buffer)) <= 0) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't read PEM bio buffer: %d",rc));
    	BIO_free(bio);
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
    	return result;
    }

    *out_pem= strdup(buffer);
    if (*out_pem==NULL) {
    	GSI_PEP_CALLOUT_ERRNO_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_MEMORY,
            ("can't duplicate PEM bio buffer: %s",buffer)); // WARN buffer can be big!!!
    }
    BIO_free(bio);

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);

    return result;
}

/**
 * Configures the PEP client.
 */
static globus_result_t pep_client_configure(void) {
	static char * _function_name_ = "pep_client_configure";
	globus_result_t result= GLOBUS_SUCCESS;
	pep_error_t pep_rc= PEP_OK;
	const char * option= NULL;
	const keyvalue_t * option_kv= NULL;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);

	const char * config= gsi_pep_callout_config_getfilename();
	if ((result= gsi_pep_callout_config_read(config))!=GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Failed to read configuration file: %s",config));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}
	// MANDATORY: pep_url(s)
	option_kv= gsi_pep_callout_config_getkeyvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL);
	if (option_kv==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Mandatory option %s missing from file: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL,config));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}
	do {
		// loop for all possible value(s)
		option= option_kv->value;
		option_kv= option_kv->next;
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_URL=%s\n",option));
		if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_URL,option)) != PEP_OK) {
			GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
					("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL,option,pep_strerror(pep_rc)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
	} while (option_kv);
	// OPTIONAL: pep_timeout if any (default is 30s in PEP-C lib)
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_TIMEOUT,NULL);
	if (option != NULL) {
		int timeout= (int)strtol(option,NULL,10);
		if (timeout>0) {
			GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_TIMEOUT=%d\n",timeout));
			if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_TIMEOUT,timeout))!=PEP_OK) {
				GSI_PEP_CALLOUT_ERROR(
						result,
						GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
						("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_TIMEOUT,option,pep_strerror(pep_rc)));
				GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
				return result;
			}
		}
	}
	// OPTIONAL: pep_ssl_validation true|false|1|0 (default is true)
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_VALIDATION,GSI_PEP_CALLOUT_CONFIG_DEFAULT_PEP_SSL_VALIDATION);
	int ssl_validate= 0;
	if (strncasecmp(option,"true",strlen("true")) == 0 || strncasecmp(option,"1",strlen("1")) == 0) {
		ssl_validate= 1;
	}
	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_SSL_VALIDATION=%d\n",ssl_validate));
	if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_SSL_VALIDATION,ssl_validate))!=PEP_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
				("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_VALIDATION,option,pep_strerror(pep_rc)));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}
	// OPTIONAL: pep_ssl_client_cert <filename>
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_CERT,GSI_PEP_CALLOUT_CONFIG_DEFAULT_PEP_SSL_CLIENT_CERT);
	if (option!=NULL) {
		// TODO: check file exists
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_CLIENT_CERT=%s\n",option));
		if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_CLIENT_CERT,option))!=PEP_OK) {
			GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
					("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_CERT,option,pep_strerror(pep_rc)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
	}

	// OPTIONAL: pep_ssl_client_key <filename>
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_KEY,GSI_PEP_CALLOUT_CONFIG_DEFAULT_PEP_SSL_CLIENT_KEY);
	if (option!=NULL) {
		// TODO: check file exists
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_CLIENT_KEY=%s\n",option));
		if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_CLIENT_KEY,option))!=PEP_OK) {
			GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
					("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_KEY,option,pep_strerror(pep_rc)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
	}
	// OPTIONAL: pep_ssl_client_keypasswd <key password>
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_KEYPASS,NULL);
	if (option!=NULL) {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_CLIENT_KEYPASSWORD=%s\n",option));
		if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_CLIENT_KEYPASSWORD,option))!=PEP_OK) {
			GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
					("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_CLIENT_KEYPASS,option,pep_strerror(pep_rc)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
	}
	// OPTIONAL: pep_ssl_server_capath <directory>
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_SERVER_CAPATH,GSI_PEP_CALLOUT_CONFIG_DEFAULT_PEP_SSL_SERVER_CAPATH);
	if (option!=NULL) {
		// TODO: check directory exists
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_SERVER_CAPATH=%s\n",option));
		if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_SERVER_CAPATH,option))!=PEP_OK) {
			GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
					("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_SERVER_CAPATH,option,pep_strerror(pep_rc)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
	}
	// OPTIONAL: pep_ssl_server_cert <filename>
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_SERVER_CERT,NULL);
	if (option!=NULL) {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_ENDPOINT_SERVER_CERT=%s\n",option));
		if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_SERVER_CERT,option))!=PEP_OK) {
			GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
					("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_SSL_SERVER_CERT,option,pep_strerror(pep_rc)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
			return result;
		}
	}
	// log level and debug output
	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_LOG_STDERR=gsi_pep_callout_debug_fstream\n"));
	pep_setoption(PEP_OPTION_LOG_STDERR,gsi_pep_callout_debug_fstream);
	switch(gsi_pep_callout_debug_level) {
	case 1:
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_LOG_LEVEL=PEP_LOGLEVEL_ERROR\n"));
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_ERROR);
		break;
	case 2:
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_LOG_LEVEL=PEP_LOGLEVEL_WARN\n"));
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_WARN);
		break;
	case 3:
	case 4:
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_LOG_LEVEL=PEP_LOGLEVEL_INFO\n"));
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_INFO);
		break;
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_LOG_LEVEL=PEP_LOGLEVEL_DEBUG\n"));
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_DEBUG);
		break;
	default:
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("set PEP_OPTION_LOG_LEVEL=PEP_LOGLEVEL_NONE\n"));
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_NONE);
		break;
	}
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
	return result;
}

/**
 * Returns the string representation of the decision.
 */
static const char * decision_str(const xacml_decision_t decision) {
    switch(decision) {
    case XACML_DECISION_DENY:
        return "Deny";
        break;
    case XACML_DECISION_PERMIT:
        return "Permit";
        break;
    case XACML_DECISION_INDETERMINATE:
        return "Indeterminate";
        break;
    case XACML_DECISION_NOT_APPLICABLE:
        return "Not Applicable";
        break;
    default:
        return "ERROR: Invalid decision";
        break;
    }
}

/**
 * Parses the XACML response and extract the identity to map.
 * Implements XACML Grid WN AuthZ Profile 1.0
 * @param repsonse the XACML response to parse
 * @param out_identity pointer to the username received or NULL
 * @return GLOBUS_SUCCESS if obligation and username is found, or an error.
 */
static globus_result_t pep_client_parse_response(const xacml_response_t * response, char ** out_identity) {
	static char * _function_name_ = "pep_client_parse_response";
	globus_result_t g_result= GLOBUS_SUCCESS;
	globus_bool_t username_found= GLOBUS_FALSE;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(3);

	int i= 0;
	size_t results_l= xacml_response_results_length(response);
	if (results_l <= 0) {
		GSI_PEP_CALLOUT_ERROR(
				g_result,
				GSI_PEP_CALLOUT_ERROR_AUTHZ,
				("No XACML Results found"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,g_result);
		return g_result;
	}
	for (i= 0; i<results_l; i++) {
		xacml_result_t * result= xacml_response_getresult(response,i);
		const char * resource_id= xacml_result_getresourceid(result);
		if (resource_id!=NULL) {
			GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("XACML Resource: %s\n",resource_id));
		}
		xacml_decision_t decision= xacml_result_getdecision(result);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("XACML Decision: %s\n", decision_str(decision)));
		if (decision!=XACML_DECISION_PERMIT) {
			xacml_status_t * status= xacml_result_getstatus(result);
			xacml_statuscode_t * statuscode= xacml_status_getcode(status);
			const char * status_value= xacml_statuscode_getvalue(statuscode);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("XACML Status: %s\n", status_value));
			const char * status_message= NULL;
			// show status value and message only on not OK
			if (strcmp(XACML_STATUSCODE_OK,status_value)!=0) {
				status_message= xacml_status_getmessage(status);
				if (status_message) {
					GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("XACML Status message: %s\n", status_message));
				}
			}
			GSI_PEP_CALLOUT_ERROR(
					g_result,
					GSI_PEP_CALLOUT_ERROR_AUTHZ,
					("XACML Decision: %s, XACML Status: %s",decision_str(decision),status_message ? status_message : status_value));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,g_result);
			return g_result;
		}
		size_t obligations_l= xacml_result_obligations_length(result);
		if (obligations_l==0 && decision==XACML_DECISION_PERMIT) {
			GSI_PEP_CALLOUT_ERROR(
					g_result,
					GSI_PEP_CALLOUT_ERROR_AUTHZ,
					("XACML Decision: %s, but no Obligation received",decision_str(decision)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,g_result);
			return g_result;
		}
		// process obligations
		int j, k, l;
		for (j= 0; j<obligations_l; j++) {
			xacml_obligation_t * obligation= xacml_result_getobligation(result,j);
			xacml_fulfillon_t fulfillon= xacml_obligation_getfulfillon(obligation);
			if (fulfillon == decision) {
				const char * obligation_id= xacml_obligation_getid(obligation);
				GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("XACML Obligation[%s]\n", obligation_id));
				if (strcmp(XACML_GRIDWN_OBLIGATION_LOCAL_ENVIRONMENT_MAP_POSIX,obligation_id)==0) {
					size_t attrs_l= xacml_obligation_attributeassignments_length(obligation);
					for (k= 0; k<attrs_l; k++) {
						xacml_attributeassignment_t * attr= xacml_obligation_getattributeassignment(obligation,k);
						const char * attr_id= xacml_attributeassignment_getid(attr);
						size_t values_l= xacml_attributeassignment_values_length(attr);
						for (l= 0; l<values_l; l++) {
							const char * value= xacml_attributeassignment_getvalue(attr,l);
							GSI_PEP_CALLOUT_DEBUG_PRINTF(4,("XACML Obligation[%s]: %s=%s\n", obligation_id,attr_id,value));
							if (strcmp(XACML_GRIDWN_ATTRIBUTE_USER_ID,attr_id)==0) {
								GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("Username: %s\n",value));
								*out_identity= strdup(value);
								if (*out_identity==NULL) {
									GSI_PEP_CALLOUT_ERRNO_ERROR(
											g_result,
											GSI_PEP_CALLOUT_ERROR_MEMORY,
											("Failed to duplicate identity: %s",value));
									GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,g_result);
									return g_result;
								}
								username_found= GLOBUS_TRUE;
							}
						}
					}
				}
			}
		}
	}
	if (username_found != GLOBUS_TRUE) {
		GSI_PEP_CALLOUT_ERROR(
				g_result,
				GSI_PEP_CALLOUT_ERROR_AUTHZ,
				("XACML Decision %s, but no Obligation[%s]/AttributeAssigment[%s] found",decision_str(XACML_DECISION_PERMIT),XACML_GRIDWN_OBLIGATION_LOCAL_ENVIRONMENT_MAP_POSIX,XACML_GRIDWN_ATTRIBUTE_USER_ID));
	}

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,g_result);
	return g_result;
}

/**
 *
 */
static globus_result_t pep_client_authorize(const char *peer_name, const char * cert_chain, const char * service, char ** local_identity) {
	static char * _function_name_ = "pep_client_authorize";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(2);


	// create XACML request
	const char * resourceid= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_XACML_RESOURCEID,NULL);
	if (resourceid==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Mandatory parameter %s missing from file: %s",GSI_PEP_CALLOUT_CONFIG_KEY_XACML_RESOURCEID,gsi_pep_callout_config_getfilename()));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}
	// check for xacml_actionid in config file, if not defined, use the service arg
	const char * actionid= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_XACML_ACTIONID,service);
	if (actionid==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Argument service is NULL, and parameter %s not defined in file: %s",GSI_PEP_CALLOUT_CONFIG_KEY_XACML_ACTIONID,gsi_pep_callout_config_getfilename()));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}
	xacml_request_t * request= NULL;
	if ((result= pep_client_create_request(cert_chain,resourceid,actionid,&request))!=GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("Failed to create XACML request"));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}

	debug_xacml_request(9,request);

	// 3. authorize
	xacml_response_t * response= NULL;
	pep_error_t pep_rc= PEP_OK;
	if ((pep_rc= pep_authorize(&request,&response))!=PEP_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
				("Failed to authorize XACML request: %s", pep_strerror(pep_rc)));
		xacml_request_delete(request);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("ERROR pep_authorize(req,resp): %d\n",pep_rc));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
		return result;
	}

	GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("pep_authorize(req,resp): %d\n",pep_rc));
	debug_xacml_request(9,request);
	debug_xacml_response(9,response);

	// 4. analyse XACML response
	if ((result= pep_client_parse_response(response,local_identity))!=GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
						result,
						GSI_PEP_CALLOUT_ERROR_AUTHZ,
						("XACML Response did not authorize: %s", peer_name));
	}
	// mapping done
	xacml_request_delete(request);
	xacml_response_delete(response);

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(2,result);
	return result;
}

/**
 * Creates a XACML Request with a Subject, a Resource, a Action and a Environment.
 */
static globus_result_t xacml_create_request(xacml_subject_t * subject, xacml_resource_t * resource, xacml_action_t * action, xacml_environment_t * environment, xacml_request_t ** out_request) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_request";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(4);

	*out_request= xacml_request_create();
	if (*out_request==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Request"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (subject!=NULL && xacml_request_addsubject(*out_request,subject) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Subject to Request"));
		xacml_request_delete(*out_request);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (resource!=NULL && xacml_request_addresource(*out_request,resource)!=PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Resource to Request"));
		xacml_request_delete(*out_request);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (action!=NULL && xacml_request_setaction(*out_request,action)!=PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Action to Request"));
		xacml_request_delete(*out_request);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (environment!=NULL && xacml_request_setenvironment(*out_request,environment) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Environment to Request"));
		xacml_request_delete(*out_request);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
	return result;
}

/**
 * Creates a XACML Subject key-info (XACML Grid WN AuthZ Profile 1.0)
 * @param certchain the PEM blocks of the certificate chain
 * @return pointer to the XACML Subject created or @c NULL on error.
 */
static globus_result_t xacml_create_subject_keyinfo(const char * certchain, xacml_subject_t ** out_subject ) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_subject_keyinfo";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(4);

	if (certchain==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("cert chain is NULL"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	// XACML Subject
	*out_subject= xacml_subject_create();
	if (*out_subject==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Subject"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	// Subject key-info
	xacml_attribute_t * subject_attr_id= xacml_attribute_create(XACML_SUBJECT_KEY_INFO);
	if (subject_attr_id==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Subject/Attribute: %s",XACML_SUBJECT_KEY_INFO));
		xacml_subject_delete(*out_subject);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	xacml_attribute_setdatatype(subject_attr_id,XACML_DATATYPE_STRING);
	if (xacml_attribute_addvalue(subject_attr_id,certchain) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Subject/Attribute[%s] value: %s",XACML_SUBJECT_KEY_INFO,certchain));
		xacml_attribute_delete(subject_attr_id);
		xacml_subject_delete(*out_subject);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (xacml_subject_addattribute(*out_subject,subject_attr_id) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Attribute[%s] to Subject",XACML_SUBJECT_KEY_INFO));
		xacml_attribute_delete(subject_attr_id);
		xacml_subject_delete(*out_subject);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
	return result;
}

/**
 * Create a XACML Resource with an resource-id Attribute.
 * @param resourceid The Resource identifier
 * @return pointer to the XACML Resource created or @c NULL on error.
 */
static globus_result_t xacml_create_resource_id(const char * resourceid, xacml_resource_t  ** out_resource) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_resource_id";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(4);

	if (resourceid==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("resourceid is NULL"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	*out_resource= xacml_resource_create();
	if (*out_resource==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Resource"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	xacml_attribute_t * resource_attr_id= xacml_attribute_create(XACML_RESOURCE_ID);
	if (resource_attr_id==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Resource/Attribute: %s",XACML_RESOURCE_ID));
		xacml_resource_delete(*out_resource);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (xacml_attribute_addvalue(resource_attr_id,resourceid) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Resource/Attribute[%s] value: %s",XACML_RESOURCE_ID,resourceid));
		xacml_attribute_delete(resource_attr_id);
		xacml_resource_delete(*out_resource);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (xacml_resource_addattribute(*out_resource,resource_attr_id) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Attribute[%s] to Resource",XACML_RESOURCE_ID));
		xacml_attribute_delete(resource_attr_id);
		xacml_resource_delete(*out_resource);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
	return result;
}

/**
 * Create a XACML Action with action-id Attribute.
 * @param actionid The action-id value
 * @param out_action pointer to the XACML Action created or @c NULL on error
 * @return GLOBUS_SUCCESS or an error
 */
static globus_result_t xacml_create_action_id(const char * actionid, xacml_action_t ** out_action ) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_action_id";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(4);

	if (actionid==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("actionid is NULL"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	*out_action= xacml_action_create();
	if (*out_action==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Action"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	xacml_attribute_t * action_attr_id= xacml_attribute_create(XACML_ACTION_ID);
	if (action_attr_id==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Action/Attribute: %s",XACML_ACTION_ID));
		xacml_action_delete(*out_action);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (xacml_attribute_addvalue(action_attr_id,actionid) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Action/Attribute[%s] value: %s",XACML_ACTION_ID,actionid));
		xacml_attribute_delete(action_attr_id);
		xacml_action_delete(*out_action);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (xacml_action_addattribute(*out_action,action_attr_id) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_XACML,
					("can not add XACML Attribute[%s] to Action",XACML_ACTION_ID));
			xacml_attribute_delete(action_attr_id);
			xacml_action_delete(*out_action);
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
			return result;
	}
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
	return result;
}

/**
 * Create a XACML Environment with the XACML Grid WN AuthZ Profile ID attribute.
 * @param out_environment pointer to the XACML Environment created or @c NULL on error
 * @return GLOBUS_SUCCESS or an error
 */
static globus_result_t xacml_create_environment_profile_id(xacml_environment_t ** out_environment) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_environment_profile_id";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(4);

	*out_environment= xacml_environment_create();
	if (*out_environment==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Environment"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	xacml_attribute_t * profile_attr_id= xacml_attribute_create(XACML_GRIDWN_ATTRIBUTE_PROFILE_ID);
	if (profile_attr_id==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Environment/Attribute: %s",XACML_GRIDWN_ATTRIBUTE_PROFILE_ID));
		xacml_environment_delete(*out_environment);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (xacml_attribute_addvalue(profile_attr_id,XACML_GRIDWN_PROFILE_VERSION) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not add XACML Environment/Attribute[%s] value: %s",XACML_GRIDWN_ATTRIBUTE_PROFILE_ID,XACML_GRIDWN_PROFILE_VERSION));
		xacml_attribute_delete(profile_attr_id);
		xacml_environment_delete(*out_environment);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
		return result;
	}
	if (xacml_environment_addattribute(*out_environment,profile_attr_id) != PEP_XACML_OK) {
		GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_XACML,
					("can not add XACML Attribute[%s] to Environment",XACML_GRIDWN_ATTRIBUTE_PROFILE_ID));
			xacml_attribute_delete(profile_attr_id);
			xacml_environment_delete(*out_environment);
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
			return result;
	}
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(4,result);
	return result;

}

static globus_result_t pep_client_create_request(const char * cert_chain, const char * resourceid, const char * actionid, xacml_request_t ** out_request)
{
	// function name for error macros
	static char * _function_name_ = "pep_client_create_request";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(3);

	globus_result_t result= GLOBUS_SUCCESS;
	xacml_subject_t * subject= NULL;
	xacml_resource_t * resource= NULL;
	xacml_action_t * action= NULL;
	xacml_environment_t * environment= NULL;

	if ((result= xacml_create_subject_keyinfo(cert_chain,&subject)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Subject for certificate chain"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,result);
		return result;
	}
	if ((result= xacml_create_resource_id(resourceid,&resource)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Resource for resourceid: %s", resourceid));
		xacml_subject_delete(subject);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,result);
		return result;
	}
	if ((result= xacml_create_action_id(actionid,&action)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Action for actionid: %s", actionid));
		xacml_subject_delete(subject);
		xacml_resource_delete(resource);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,result);
		return result;
	}
	if ((result= xacml_create_environment_profile_id(&environment)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Environment for profile ID"));
		xacml_subject_delete(subject);
		xacml_resource_delete(resource);
		xacml_action_delete(action);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,result);
		return result;

	}
	if ((result= xacml_create_request(subject,resource,action,environment,out_request)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Request"));
		xacml_subject_delete(subject);
		xacml_resource_delete(resource);
		xacml_action_delete(action);
		xacml_environment_delete(environment);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,result);
		return result;
	}

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(3,result);

	return result;
}

/**
 * Debug a XACML request. NULL values are not displayed.
 */
static int debug_xacml_request(int debug_level, const xacml_request_t * request) {
	// function name for error macros
	static char * _function_name_ = "debug_xacml_request";

	if (request == NULL) {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("ERROR: request is NULL\n"));
		return 1;
	}
	if (GSI_PEP_CALLOUT_DEBUG(debug_level)) {
		size_t subjects_l= xacml_request_subjects_length(request);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request: %d subjects\n", (int)subjects_l));
		int i= 0;
		for (i= 0; i<subjects_l; i++) {
			xacml_subject_t * subject= xacml_request_getsubject(request,i);
			const char * category= xacml_subject_getcategory(subject);
			if (category)
				GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.subject[%d].category= %s\n", i, category));
			size_t attrs_l= xacml_subject_attributes_length(subject);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.subject[%d]: %d attributes\n", i, (int)attrs_l));
			int j= 0;
			for(j= 0; j<attrs_l; j++) {
				xacml_attribute_t * attr= xacml_subject_getattribute(subject,j);
				const char * attr_id= xacml_attribute_getid(attr);
				if (attr_id)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.subject[%d].attribute[%d].id= %s\n", i,j,attr_id));
				const char * attr_datatype= xacml_attribute_getdatatype(attr);
				if (attr_datatype)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.subject[%d].attribute[%d].datatype= %s\n", i,j,attr_datatype));
				const char * attr_issuer= xacml_attribute_getissuer(attr);
				if (attr_issuer)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.subject[%d].attribute[%d].issuer= %s\n", i,j,attr_issuer));
				size_t values_l= xacml_attribute_values_length(attr);
				//show_info("request.subject[%d].attribute[%d]: %d values", i,j,(int)values_l);
				int k= 0;
				for (k= 0; k<values_l; k++) {
					const char * attr_value= xacml_attribute_getvalue(attr,k);
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.subject[%d].attribute[%d].value[%d]= %s\n", i,j,k,attr_value));
				}
			}
		}
		size_t resources_l= xacml_request_resources_length(request);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request: %d resources\n", (int)resources_l));
		for (i= 0; i<resources_l; i++) {
			xacml_resource_t * resource= xacml_request_getresource(request,i);
			const char * res_content= xacml_resource_getcontent(resource);
			if (res_content)
				GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.resource[%d].content= %s\n", i, res_content));
			size_t attrs_l= xacml_resource_attributes_length(resource);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.resource[%d]: %d attributes\n", i, (int)attrs_l));
			int j= 0;
			for(j= 0; j<attrs_l; j++) {
				xacml_attribute_t * attr= xacml_resource_getattribute(resource,j);
				const char * attr_id= xacml_attribute_getid(attr);
				if (attr_id)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.resource[%d].attribute[%d].id= %s\n", i,j,attr_id));
				const char * attr_datatype= xacml_attribute_getdatatype(attr);
				if (attr_datatype)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.resource[%d].attribute[%d].datatype= %s\n", i,j,attr_datatype));
				const char * attr_issuer= xacml_attribute_getissuer(attr);
				if (attr_issuer)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.resource[%d].attribute[%d].issuer= %s\n", i,j,attr_issuer));
				size_t values_l= xacml_attribute_values_length(attr);
				//show_info("request.resource[%d].attribute[%d]: %d values", i,j,(int)values_l);
				int k= 0;
				for (k= 0; k<values_l; k++) {
					const char * attr_value= xacml_attribute_getvalue(attr,k);
					if (attr_value)
						GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.resource[%d].attribute[%d].value[%d]= %s\n", i,j,k,attr_value));
				}
			}
		}
		int j= 0;
		xacml_action_t * action= xacml_request_getaction(request);
		if (action) {
			size_t act_attrs_l= xacml_action_attributes_length(action);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.action: %d attributes\n",(int)act_attrs_l));
			for (j= 0; j<act_attrs_l; j++) {
				xacml_attribute_t * attr= xacml_action_getattribute(action,j);
				const char * attr_id= xacml_attribute_getid(attr);
				if (attr_id)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.action.attribute[%d].id= %s\n", j,attr_id));
				const char * attr_datatype= xacml_attribute_getdatatype(attr);
				if (attr_datatype)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.action.attribute[%d].datatype= %s\n", j,attr_datatype));
				const char * attr_issuer= xacml_attribute_getissuer(attr);
				if (attr_issuer)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.action.attribute[%d].issuer= %s\n", j,attr_issuer));
				size_t values_l= xacml_attribute_values_length(attr);
				//show_info("request.action.attribute[%d]: %d values", j,(int)values_l);
				int k= 0;
				for (k= 0; k<values_l; k++) {
					const char * attr_value= xacml_attribute_getvalue(attr,k);
					if (attr_value)
						GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.action.attribute[%d].value[%d]= %s\n",j,k,attr_value));
				}
			}
		}
		xacml_environment_t * env= xacml_request_getenvironment(request);
		if (env) {
			size_t env_attrs_l= xacml_environment_attributes_length(env);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.environment: %d attributes\n",(int)env_attrs_l));
			for (j= 0; j<env_attrs_l; j++) {
				xacml_attribute_t * attr= xacml_environment_getattribute(env,j);
				const char * attr_id= xacml_attribute_getid(attr);
				if (attr_id)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.environment.attribute[%d].id= %s\n", j,attr_id));
				const char * attr_datatype= xacml_attribute_getdatatype(attr);
				if (attr_datatype)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.environment.attribute[%d].datatype= %s\n", j,attr_datatype));
				const char * attr_issuer= xacml_attribute_getissuer(attr);
				if (attr_issuer)
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.environment.attribute[%d].issuer= %s\n", j,attr_issuer));
				size_t values_l= xacml_attribute_values_length(attr);
				//show_info("request.environment.attribute[%d]: %d values", j,(int)values_l);
				int k= 0;
				for (k= 0; k<values_l; k++) {
					const char * attr_value= xacml_attribute_getvalue(attr,k);
					if (attr_value)
						GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("request.environment.attribute[%d].value[%d]= %s\n",j,k,attr_value));
				}
			}
		}
	}
	return 0;
}

/**
 * Dumps a XACML response.
 */
static int debug_xacml_response(int debug_level,const xacml_response_t * response) {
	// function name for error macros
	static char * _function_name_ = "debug_xacml_response";

	if (response == NULL) {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("ERROR: response is NULL\n"));
		return 1;
	}
	if (GSI_PEP_CALLOUT_DEBUG(debug_level)) {
		size_t results_l= xacml_response_results_length(response);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response: %d results\n", (int)results_l));
		int i= 0;
		for(i= 0; i<results_l; i++) {
			xacml_result_t * result= xacml_response_getresult(response,i);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].decision= %s\n", i, decision_str(xacml_result_getdecision(result))));

			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].resourceid= %s\n", i, xacml_result_getresourceid(result)));
			xacml_status_t * status= xacml_result_getstatus(result);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].status.message= %s\n", i, xacml_status_getmessage(status)));
			xacml_statuscode_t * statuscode= xacml_status_getcode(status);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].status.code.value= %s\n", i, xacml_statuscode_getvalue(statuscode)));
			xacml_statuscode_t * subcode= xacml_statuscode_getsubcode(statuscode);
			if (subcode != NULL) {
				GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].status.code.subcode.value= %s\n", i, xacml_statuscode_getvalue(subcode)));
			}
			size_t obligations_l= xacml_result_obligations_length(result);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d]: %d obligations\n", i, (int)obligations_l));
			int j=0;
			for(j= 0; j<obligations_l; j++) {
				xacml_obligation_t * obligation= xacml_result_getobligation(result,j);
				GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].obligation[%d].id= %s\n",i,j, xacml_obligation_getid(obligation)));
				GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].obligation[%d].fulfillOn= %s\n",i,j, decision_str(xacml_obligation_getfulfillon(obligation))));
				size_t attrs_l= xacml_obligation_attributeassignments_length(obligation);
				GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].obligation[%d]: %d attribute assignments\n",i,j,(int)attrs_l));
				int k= 0;
				for (k= 0; k<attrs_l; k++) {
					xacml_attributeassignment_t * attr= xacml_obligation_getattributeassignment(obligation,k);
					GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].obligation[%d].attributeassignment[%d].id= %s\n",i,j,k,xacml_attributeassignment_getid(attr)));
					size_t values_l= xacml_attributeassignment_values_length(attr);
					int l= 0;
					for (l= 0; l<values_l; l++) {
						GSI_PEP_CALLOUT_DEBUG_PRINTF(debug_level,("response.result[%d].obligation[%d].attributeassignment[%d].value[%d]= %s\n",i,j,k,l,xacml_attributeassignment_getvalue(attr,l)));
					}
				}
			}
		}
	}
	return 0;
}



/**
 * Module descriptor static initializer.
 */
globus_module_descriptor_t gsi_pep_callout_module =
{
    "gsi_pep_callout",
    gsi_pep_callout_activate,
    gsi_pep_callout_deactivate,
    GLOBUS_NULL,
    GLOBUS_NULL,
    &local_version
};

/**
 * Module activation
 */
static int gsi_pep_callout_activate(void)
{
    // function name for error macros
	static char * _function_name_ = "gsi_pep_callout_activate";
	globus_result_t result= GLOBUS_SUCCESS;

    char * tmp_string = globus_module_getenv("GSI_PEP_CALLOUT_DEBUG_LEVEL");
    if(tmp_string != GLOBUS_NULL)
    {
    	gsi_pep_callout_debug_level= (int)strtol(tmp_string,NULL,10);
        if(gsi_pep_callout_debug_level < 0) {
        	gsi_pep_callout_debug_level = 0;
        }
    }
    tmp_string = globus_module_getenv("GSI_PEP_CALLOUT_DEBUG_FILE");
    if(tmp_string != GLOBUS_NULL) {
    	gsi_pep_callout_debug_fstream = fopen(tmp_string, "a");
        if(gsi_pep_callout_debug_fstream==NULL) {
            return (int) GLOBUS_FAILURE;
        }
    }
    else {
    	// default use stderr
    	gsi_pep_callout_debug_fstream= stderr;
    }

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(1);

    result= globus_module_activate(GLOBUS_COMMON_MODULE);
    result= globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
    result= globus_module_activate(GLOBUS_GSI_CREDENTIAL_MODULE);
    result= globus_module_activate(GSI_PEP_CALLOUT_ERROR_MODULE);
    result= globus_module_activate(GSI_PEP_CALLOUT_CONFIG_MODULE);

    // initialize the PEP client
    pep_error_t pep_rc= pep_initialize();
	if (pep_rc!=PEP_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
				("failed to initialize PEP client: %s", pep_strerror(pep_rc)));
	}

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(1,result);

    return result;
}

/**
 * Module deactivation
 */
static int gsi_pep_callout_deactivate(void)
{
    // function name for error macros
	static char * _function_name_ = "gsi_pep_callout_deactivate";
	globus_result_t result= GLOBUS_SUCCESS;

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN(1);

	// release the PEP client
	pep_error_t pep_rc= pep_destroy();
	if (pep_rc!=PEP_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
				("failed to release PEP client: %s", pep_strerror(pep_rc)));
	}

    result= globus_module_deactivate(GSI_PEP_CALLOUT_CONFIG_MODULE);
    result= globus_module_deactivate(GSI_PEP_CALLOUT_ERROR_MODULE);
    result= globus_module_deactivate(GLOBUS_GSI_CREDENTIAL_MODULE);
    result= globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
    result= globus_module_deactivate(GLOBUS_COMMON_MODULE);

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(1,result);

    return result;
}

