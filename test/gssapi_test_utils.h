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
 */


#include "gssapi.h"
#include "globus_gss_assist.h"
#include "globus_common.h"

gss_cred_id_t 
globus_gsi_gssapi_test_acquire_credential();

void 
globus_gsi_gssapi_test_release_credential(
    gss_cred_id_t *                     credential);

globus_bool_t
globus_gsi_gssapi_test_authenticate(
    int                                 fd,
    globus_bool_t                       server, 
    gss_cred_id_t                       credential, 
    gss_ctx_id_t *                      context_handle, 
    char **                             user_id, 
    gss_cred_id_t *                     delegated_cred);

void 
globus_gsi_gssapi_test_cleanup(
    gss_ctx_id_t *                      context_handle,
    char *                              userid,
    gss_cred_id_t *                     delegated_cred);

globus_bool_t
globus_gsi_gssapi_test_export_context(
    char *                              filename,
    gss_ctx_id_t *                      context);


globus_bool_t
globus_gsi_gssapi_test_import_context(
    char *                              filename,
    gss_ctx_id_t *                      context);

globus_bool_t
globus_gsi_gssapi_test_send_hello(
    int                                 fd,
    gss_ctx_id_t                        context);

globus_bool_t
globus_gsi_gssapi_test_receive_hello(
    int                                 fd,
    gss_ctx_id_t                        context);

globus_bool_t
globus_gsi_gssapi_test_dump_cert_chain(
    char *                              filename,
    gss_ctx_id_t                        context);

