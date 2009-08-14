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

#include <globus_common.h>
#include <gssapi.h>
#include <globus_gsi_credential.h>

#include <pep/pep.h>

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

/*
 * internal variable
 */


/**
 * ARGUS AuthZ Service PEP Callout Function
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

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

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
    		5 /* level */,
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
	    		1 /* level */,
				("Mapped: %s to: %s\n",
				peer_name, identity_buffer));
	}
	free(local_identity);



error:
	if (peer_name) free(peer_name);
	if (cert_chain) free(cert_chain);

	globus_module_deactivate(GSI_PEP_CALLOUT_MODULE);

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);

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

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

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
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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

		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}

	// TODO: error handling
	*peer_name= (char *)peer_name_buffer.value;

	gss_release_name(&minor_status,&peer);

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);

	return result;
}

/**
 * Returns the gss_cred_id handle from the GSS context.
 */
static gss_cred_id_t get_gss_cred_id(const gss_ctx_id_t gss_context)
{
    return (gss_cred_id_t)gss_context->peer_cred_handle;
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

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

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

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

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

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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
	char * subject= *out_subject;
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
    subject= strdup(buffer);
    if (subject==NULL) {
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

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

    BIO * bio = BIO_new(BIO_s_mem());
    if (bio==NULL) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't allocate PEM bio buffer"));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
    	return result;
    }
    if ((rc= PEM_write_bio_X509(bio, (X509 *)x509)) != 1) {
    	GSI_PEP_CALLOUT_OPENSSL_ERROR(
            result,
            GSI_PEP_CALLOUT_ERROR_OPENSSL,
            ("can't write PEM cert into bio buffer: %d",rc));
        BIO_free(bio);
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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
        	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);

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

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

	const char * config= gsi_pep_callout_config_getfilename();
	if ((result= gsi_pep_callout_config_read(config))!=GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Failed to read configuration file: %s",config));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	// set mandatory PEPd url(s)
	option_kv= gsi_pep_callout_config_getkeyvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL);
	if (option_kv==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Mandatory option %s missing from file: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL,config));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	do {
		option= option_kv->value;
		option_kv= option_kv->next;
		if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_URL,option)) != PEP_OK) {
			GSI_PEP_CALLOUT_ERROR(
					result,
					GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
					("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_URL,option,pep_strerror(pep_rc)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
			return result;
		}
	} while (option_kv);
	// set optional PEPd timeout if any
	option= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_PEP_TIMEOUT);
	if (option != NULL) {
		int timeout= (int)strtol(option,NULL,10);
		if (timeout>0) {
			if ((pep_rc= pep_setoption(PEP_OPTION_ENDPOINT_TIMEOUT,timeout))!=PEP_OK) {
				GSI_PEP_CALLOUT_ERROR(
						result,
						GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
						("Failed to set PEP client option %s %s: %s",GSI_PEP_CALLOUT_CONFIG_KEY_PEP_TIMEOUT,option,pep_strerror(pep_rc)));
				GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
				return result;
			}
		}
	}
	// TODO: other options???
	// pep_ssl_validation on|off|1|0
	GSI_PEP_CALLOUT_DEBUG_PRINTF(1,("XXX: pep_setoption(PEP_OPTION_ENDPOINT_SSL_VALIDATION,0)\n"));
	pep_setoption(PEP_OPTION_ENDPOINT_SSL_VALIDATION,0);
	// pep_ssl_client_cert <filename>
	// pep_ssl_client_key <filename>
	// pep_ssl_client_keypass <key password>
	// pep_ssl_server_cert <filename>
	// pep_ssl_server_capath <directory>
	// pep_log_level [0..5]

	GSI_PEP_CALLOUT_DEBUG_PRINTF(1,("XXX: pep_setoption(PEP_OPTION_LOG_STDERR,stderr)\n"));
	pep_setoption(PEP_OPTION_LOG_STDERR,stderr);
	if (gsi_pep_callout_debug_level >= 5) {
		GSI_PEP_CALLOUT_DEBUG_PRINTF(1,("XXX: pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_DEBUG)\n"));
		pep_setoption(PEP_OPTION_LOG_LEVEL,PEP_LOGLEVEL_DEBUG);
	}
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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
        return "ERRRO: Invalid decision";
        break;
    }
}

/**
 * Parses the XACML response and extract the identity to map.
 */
static globus_result_t pep_client_parse_response(const xacml_response_t * response, char ** out_identity) {
	static char * _function_name_ = "pep_client_parse_response";
	globus_result_t g_result= GLOBUS_SUCCESS;
	globus_bool_t username_found= GLOBUS_FALSE;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

	int i= 0;
	size_t results_l= xacml_response_results_length(response);
	if (results_l <= 0) {
		GSI_PEP_CALLOUT_ERROR(
				g_result,
				GSI_PEP_CALLOUT_ERROR_AUTHZ,
				("No XACML Results found"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(g_result);
		return g_result;
	}
	for (i= 0; i<results_l; i++) {
		xacml_result_t * result= xacml_response_getresult(response,i);
		const char * resource_id= xacml_result_getresourceid(result);
		if (resource_id!=NULL) {
			GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("XACML Resource: %s\n",resource_id));
		}
		xacml_decision_t decision= xacml_result_getdecision(result);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("XACML Decision: %s\n", decision_str(decision)));
		if (decision!=XACML_DECISION_PERMIT) {
			xacml_status_t * status= xacml_result_getstatus(result);
			xacml_statuscode_t * statuscode= xacml_status_getcode(status);
			const char * status_value= xacml_statuscode_getvalue(statuscode);
			GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("XACML Status: %s\n", status_value));
			const char * status_message= NULL;
			// show status value and message only on not OK
			if (strcmp(XACML_STATUSCODE_OK,status_value)!=0) {
				status_message= xacml_status_getmessage(status);
				if (status_message) {
					GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("XACML Status message: %s\n", status_message));
				}
			}
			GSI_PEP_CALLOUT_ERROR(
					g_result,
					GSI_PEP_CALLOUT_ERROR_AUTHZ,
					("XACML Decision: %s, XACML Status: %s",decision_str(decision),status_message ? status_message : status_value));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(g_result);
			return g_result;
		}
		size_t obligations_l= xacml_result_obligations_length(result);
		if (obligations_l==0 && decision==XACML_DECISION_PERMIT) {
			GSI_PEP_CALLOUT_ERROR(
					g_result,
					GSI_PEP_CALLOUT_ERROR_AUTHZ,
					("XACML Decision: %s, but no Obligation received",decision_str(decision)));
			GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(g_result);
			return g_result;
		}
		// process obligations
		int j, k, l;
		for (j= 0; j<obligations_l; j++) {
			xacml_obligation_t * obligation= xacml_result_getobligation(result,j);
			xacml_fulfillon_t fulfillon= xacml_obligation_getfulfillon(obligation);
			if (fulfillon == decision) {
				const char * obligation_id= xacml_obligation_getid(obligation);
				size_t attrs_l= xacml_obligation_attributeassignments_length(obligation);
				for (k= 0; k<attrs_l; k++) {
					xacml_attributeassignment_t * attr= xacml_obligation_getattributeassignment(obligation,k);
					const char * attr_id= xacml_attributeassignment_getid(attr);
					size_t values_l= xacml_attributeassignment_values_length(attr);
					for (l= 0; l<values_l; l++) {
						const char * value= xacml_attributeassignment_getvalue(attr,l);
						GSI_PEP_CALLOUT_DEBUG_PRINTF(3,("XACML Obligation[%s]: %s=%s\n", obligation_id,attr_id,value));
						if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_USERNAME,obligation_id)==0) {
							if (strcmp(XACML_AUTHZINTEROP_OBLIGATION_ATTR_USERNAME,attr_id)==0) {
								GSI_PEP_CALLOUT_DEBUG_PRINTF(1,("Username: %s",value));
								*out_identity= strdup(value);
								if (*out_identity==NULL) {
									GSI_PEP_CALLOUT_ERRNO_ERROR(
											g_result,
											GSI_PEP_CALLOUT_ERROR_MEMORY,
											("Failed to duplicate identity: %s",value));
									GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(g_result);
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
				("XACML Decision %s, but no Obligation[%s]:AttributeAssigment[%s] found",decision_str(XACML_DECISION_PERMIT),XACML_AUTHZINTEROP_OBLIGATION_USERNAME,XACML_AUTHZINTEROP_OBLIGATION_ATTR_USERNAME));
	}

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(g_result);
	return g_result;
}

/**
 *
 */
static globus_result_t pep_client_authorize(const char *peer_name, const char * cert_chain, const char * actionid, char ** local_identity) {
	static char * _function_name_ = "pep_client_authorize";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;


	// 2. create XACML request
	const char * resourceid= gsi_pep_callout_config_getvalue(GSI_PEP_CALLOUT_CONFIG_KEY_XACML_RESOURCEID);
	if (resourceid==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_CONFIG,
				("Mandatory parameter %s missing from file: %s",GSI_PEP_CALLOUT_CONFIG_KEY_XACML_RESOURCEID,gsi_pep_callout_config_getfilename()));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_request_t * request= NULL;
	if ((result= pep_client_create_request(cert_chain,resourceid,actionid,&request))!=GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("Failed to create XACML request"));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	// 3. authorize
	xacml_response_t * response= NULL;
	pep_error_t pep_rc= PEP_OK;
	if ((pep_rc= pep_authorize(&request,&response))!=PEP_OK) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_PEP_CLIENT,
				("Failed to authorize XACML request: %s", pep_strerror(pep_rc)));
		xacml_request_delete(request);
		GSI_PEP_CALLOUT_DEBUG_PRINTF(1,("ERROR pep_authorize(req,resp): %d\n",pep_rc));
    	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}

	GSI_PEP_CALLOUT_DEBUG_PRINTF(5,("call pep_authorize(req,resp): %d\n",pep_rc));

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

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
	return result;
}

/**
 * Creates a XACML Request with a Subject, a Resource and a Action.
 */
static globus_result_t xacml_create_request(xacml_subject_t * subject, xacml_resource_t * resource, xacml_action_t * action, xacml_request_t ** out_request) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_request";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

	*out_request= xacml_request_create();
	if (*out_request==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Request"));
		//xacml_subject_delete(subject);
		//xacml_resource_delete(resource);
		//xacml_action_delete(action);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	if (subject!=NULL) {
		// TODO: error handling
		xacml_request_addsubject(*out_request,subject);
	}
	if (resource!=NULL) {
		// TODO: error handling
		xacml_request_addresource(*out_request,resource);
	}
	if (action!=NULL) {
		// TODO: error handling
		xacml_request_setaction(*out_request,action);
	}

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
	return result;
}

/**
 * Creates a XACML Subject cert-chain
 * @param certchain the PEM blocks of the certificate chain
 * @return pointer to the XACML Subject created or @c NULL on error.
 */
static globus_result_t xacml_create_subject_certchain(const char * certchain, xacml_subject_t ** out_subject ) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_subject_certchain";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

	if (certchain==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("cert chain is NULL"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	// Subject cert-chain
	xacml_subject_t * subject= *out_subject;
	subject= xacml_subject_create();
	if (subject==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Subject"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_attribute_t * subject_attr_id= xacml_attribute_create(XACML_AUTHZINTEROP_SUBJECT_CERTCHAIN);
	if (subject_attr_id==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Subject/Attribute: %s",XACML_AUTHZINTEROP_SUBJECT_CERTCHAIN));
		xacml_subject_delete(subject);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	// TODO: error handling
	xacml_attribute_setdatatype(subject_attr_id,XACML_DATATYPE_BASE64BINARY);
	xacml_attribute_addvalue(subject_attr_id,certchain);
	xacml_subject_addattribute(subject,subject_attr_id);
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
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

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

	if (resourceid==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("resourceid is NULL"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_resource_t * resource= *out_resource;
	resource= xacml_resource_create();
	if (resource==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Resource"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_attribute_t * resource_attr_id= xacml_attribute_create(XACML_RESOURCE_ID);
	if (resource_attr_id==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Resource/Attribute: %s",XACML_RESOURCE_ID));
		xacml_resource_delete(resource);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_attribute_addvalue(resource_attr_id,resourceid);
	xacml_resource_addattribute(resource,resource_attr_id);
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
	return result;
}

/**
 * Create a XACML Action with action-id Attribute.
 * @param actionid The Action identifier
 * @return pointer to the XACML Action created or @c NULL on error.
 */
static globus_result_t xacml_create_action_id(const char * actionid, xacml_action_t ** out_action ) {
    // function name for error macros
	static char * _function_name_ = "xacml_create_action_id";
	globus_result_t result= GLOBUS_SUCCESS;

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

	if (actionid==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("actionid is NULL"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_action_t * action= *out_action;
	action= xacml_action_create();
	if (action==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Action"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_attribute_t * action_attr_id= xacml_attribute_create(XACML_ACTION_ID);
	if (action_attr_id==NULL) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not allocate XACML Action/Attribute: %s",XACML_ACTION_ID));
		xacml_action_delete(action);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	xacml_attribute_addvalue(action_attr_id,actionid);
	xacml_action_addattribute(action,action_attr_id);
	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
	return result;
}

static globus_result_t pep_client_create_request(const char * cert_chain, const char * resourceid, const char * actionid, xacml_request_t ** out_request)
{
	// function name for error macros
	static char * _function_name_ = "pep_client_create_request";

	GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

	globus_result_t result= GLOBUS_SUCCESS;
	xacml_subject_t * subject= NULL;
	xacml_resource_t * resource= NULL;
	xacml_action_t * action= NULL;

	if ((result= xacml_create_subject_certchain(cert_chain,&subject)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Subject: cert-chain"));
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	if ((result= xacml_create_resource_id(resourceid,&resource)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Resource: resourceid %s", resourceid));
		xacml_subject_delete(subject);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	if ((result= xacml_create_action_id(actionid,&action)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Action: actionid %s", actionid));
		xacml_subject_delete(subject);
		xacml_resource_delete(resource);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}
	if ((result= xacml_create_request(subject,resource,action,out_request)) != GLOBUS_SUCCESS) {
		GSI_PEP_CALLOUT_ERROR(
				result,
				GSI_PEP_CALLOUT_ERROR_XACML,
				("can not create XACML Request"));
		xacml_subject_delete(subject);
		xacml_resource_delete(resource);
		xacml_action_delete(action);
		GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);
		return result;
	}

	GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);

	return result;
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

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

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

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);

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

    GSI_PEP_CALLOUT_DEBUG_FCT_BEGIN;

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

    GSI_PEP_CALLOUT_DEBUG_FCT_RETURN(result);

    return result;
}

