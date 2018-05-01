/**
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010. 
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.  
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
 *
 *  Authors:
 *  2009-
 *     Oscar Koeroo <okoeroo@nikhef.nl>
 *     Mischa Sall\'e <msalle@nikhef.nl>
 *     David Groep <davidg@nikhef.nl>
 *     NIKHEF Amsterdam, the Netherlands
 *     <grid-mw-security@nikhef.nl> 
 *
 *  2007-2009
 *     Oscar Koeroo <okoeroo@nikhef.nl>
 *     David Groep <davidg@nikhef.nl>
 *     NIKHEF Amsterdam, the Netherlands
 *
 *  2003-2007
 *     Martijn Steenbakkers <martijn@nikhef.nl>
 *     Oscar Koeroo <okoeroo@nikhef.nl>
 *     David Groep <davidg@nikhef.nl>
 *     NIKHEF Amsterdam, the Netherlands
 *
 */

/*!
 * This header file contains all the types needed to extract the gss_cred_id_t
 * from the supplied gss_ctx_id_t. The essential one is gss_ctx_id_desc. Note
 * that this is not in line with the GSSAPI as advertised in the RFC.
 * As far as we can see this should have been done by the gss_acquire_cred().
 * However, the globus version of this function only acquires the local
 * credential. Another option would have been to provide the gss_cred_id_t
 * instead of/in addition to the gss_ctx_id_t in the call to the globus_callout.
 *
 * Note that this is bound to break as soon as globus changes the internal
 * format of the here defined structs.
 */
#ifndef _PEP_GLOBUS_INTERNAL_H
#define _PEP_GLOBUS_INTERNAL_H

#include <gssapi.h>
#include <globus_gsi_credential.h>
#include <globus_gsi_proxy.h>

/* Defined in globus_gsi_gss_constants.h as
 * gss_delegation_state_t */
typedef enum
{
    GSS_DELEGATION_START,
    GSS_DELEGATION_DONE,
    GSS_DELEGATION_COMPLETE_CRED,
    GSS_DELEGATION_SIGN_CERT
} pep_gss_delegation_state_t;

/* Defined in globus_gsi_gss_constants.h as
 * gss_con_st_t */
typedef enum {
    GSS_CON_ST_HANDSHAKE = 0,
    GSS_CON_ST_FLAGS,
    GSS_CON_ST_REQ,
    GSS_CON_ST_CERT,
    GSS_CON_ST_DONE
} pep_gss_con_st_t;

/* Defined in gssapi_openssl.h as
 * struct gss_ctx_id_desc_struct and gss_ctx_id_desc */
typedef struct pep_gss_ctx_id_desc_struct{
    globus_mutex_t                      mutex;
    globus_gsi_callback_data_t          callback_data;
    gss_cred_id_t                       peer_cred_handle;
    gss_cred_id_t                       cred_handle;
    gss_cred_id_t                       deleg_cred_handle;
    globus_gsi_proxy_handle_t           proxy_handle;
    OM_uint32                           ret_flags;
    OM_uint32                           req_flags;
    OM_uint32                           ctx_flags;
    int                                 cred_obtained;
#if OPENSSL_VERSION_NUMBER >= 0x10000100L
    /** For GCM ciphers, sequence number of next read MAC token */
    uint64_t                            mac_read_sequence;
    /** For GCM ciphers, sequence number of next write MAC token */
    uint64_t                            mac_write_sequence;
    /** For GCM ciphers, key for MAC token generation/validation */
    unsigned char *                     mac_key;
    /**
     * For GCM ciphers, fixed part of the IV for MAC token
     * generation/validation
     */
    unsigned char *                     mac_iv_fixed;
#endif
    SSL *                               gss_ssl; 
    BIO *                               gss_rbio;
    BIO *                               gss_wbio;
    BIO *                               gss_sslbio;
    pep_gss_con_st_t                   gss_state;
    int                                 locally_initiated;
    pep_gss_delegation_state_t         delegation_state;
    gss_OID_set                         extension_oids;
} pep_gss_ctx_id_desc;

/* Defined in gssapi_openssl.h as
 * struct gss_cred_id_desc_struct and gss_cred_id_desc */
typedef struct pep_gss_cred_id_desc_struct {
    globus_gsi_cred_handle_t            cred_handle;
    gss_name_t                          globusid;
    gss_cred_usage_t                    cred_usage;
    SSL_CTX *                           ssl_context;
} pep_gss_cred_id_desc;

#endif /* _PEP_GLOBUS_INTERNAL_H */
