/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */
#include <stdio.h>
#include <globus_common.h>
#include <gssapi.h>

#include "gsi_pep_callout.h"

#include "gssapi_test_utils.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Note: The above allow this file to build, but it won't run under windows
 unless the unix fork() is replaced by a CreateProcess or something
 */

struct context_arg {
	gss_cred_id_t credential;
	int fd;
	struct sockaddr_un * address;
};

void *
server_func(void * arg);

void *
client_func(void * arg);

int main() {
	gss_cred_id_t credential;
	int listen_fd;
	int accept_fd;
	struct sockaddr_un * address;
	struct context_arg * arg = NULL;
	pid_t pid;

	/* module activation */
	globus_module_activate(GLOBUS_GSI_GSS_ASSIST_MODULE);
	globus_module_activate(GLOBUS_GSI_GSSAPI_MODULE);
	globus_module_activate(GLOBUS_COMMON_MODULE);
	globus_module_activate(GSI_PEP_CALLOUT_MODULE);

	/* setup listener */

	address = malloc(sizeof(struct sockaddr_un));

	memset(address, 0, sizeof(struct sockaddr_un));

	address->sun_family = PF_UNIX;

	tmpnam(address->sun_path);

	listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);

	bind(listen_fd, (struct sockaddr *) address, sizeof(struct sockaddr_un));

	listen(listen_fd, 1);

	/* acquire credentials */

	credential = globus_gsi_gssapi_test_acquire_credential();

	if (credential == GSS_C_NO_CREDENTIAL) {
		fprintf(stderr,"Unable to aquire credential\n");
		exit(-1);
	}

	pid = fork();

	if (pid == 0) {
		/* child */
		arg = malloc(sizeof(struct context_arg));

		arg->address = address;

		arg->credential = credential;

		client_func(arg);
	} else {
		accept_fd = accept(listen_fd, NULL,0);

		if (accept_fd < 0) {
			abort();
		}

		arg = malloc(sizeof(struct context_arg));

		arg->fd = accept_fd;

		arg->credential = credential;

		server_func(arg);
	}

	/* close the listener */

	close(listen_fd);

	/* release credentials */

	globus_gsi_gssapi_test_release_credential(&credential);

	/* free address */

	free(address);

	globus_module_deactivate(GLOBUS_COMMON_MODULE);
	globus_module_deactivate(GLOBUS_GSI_GSSAPI_MODULE);
	globus_module_deactivate(GLOBUS_GSI_GSS_ASSIST_MODULE);

	exit(0);
}

globus_bool_t gsi_pep_callout_test_authz(int argc, ...) {
	globus_result_t result= GLOBUS_SUCCESS;
	globus_bool_t rc= GLOBUS_TRUE;
	va_list authz_pep_callout_args;

	va_start(authz_pep_callout_args,argc);
	result= authz_pep_callout( authz_pep_callout_args);
	if (result!=GLOBUS_SUCCESS) {
		globus_object_t *error= globus_error_get(result);
		char * error_string= globus_error_print_chain(error);
		printf("GLOBUS ERROR: %s",error_string);
		rc= GLOBUS_FALSE;
	}
	va_end(authz_pep_callout_args);

	return rc;
}

void *
server_func(void * arg) {
	struct context_arg * server_args;
	globus_bool_t bool_rc;
	gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
	char * user_id = NULL;
	gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;

	server_args = (struct context_arg *) arg;

	bool_rc
			= globus_gsi_gssapi_test_authenticate(server_args->fd, GLOBUS_TRUE,
					server_args->credential, &gss_context, &user_id,
					&delegated_cred);

	fprintf(stderr,"Authentication: user_id: %s\n",user_id);

	if (bool_rc != GLOBUS_TRUE) {
		fprintf(stderr, "SERVER: Authentication failed\n");
		exit(1);
	}

	const char * service= "file";
	size_t identity_l= 1024;
	char identity[1024];
	bool_rc= gsi_pep_callout_test_authz(5,gss_context,service,GLOBUS_NULL,&identity,identity_l);
	if (bool_rc != GLOBUS_TRUE) {
		fprintf(stderr, "SERVER: Authorization failed\n");
		exit(1);
	}

	fprintf(stderr,"Authorization: identity: %s\n",identity);

	bool_rc = globus_gsi_gssapi_test_receive_hello(server_args->fd,
			gss_context);

	if (bool_rc != GLOBUS_TRUE) {
		fprintf(stderr, "SERVER: failed to receive hello\n");
		exit(1);
	}

	close(server_args->fd);

	free(server_args);

	globus_gsi_gssapi_test_cleanup(&gss_context, user_id, &delegated_cred);

	return NULL;
}

void *
client_func(void * arg) {
	struct context_arg * client_args;
	globus_bool_t result;
	gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
	char * user_id = NULL;
	gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
	int connect_fd;
	int rc;

	client_args = (struct context_arg *) arg;

	connect_fd = socket(PF_UNIX, SOCK_STREAM, 0);

	rc = connect(connect_fd, (struct sockaddr *) client_args->address,
			sizeof(struct sockaddr_un));

	if (rc != 0) {
		abort();
	}

	result
			= globus_gsi_gssapi_test_authenticate(connect_fd, GLOBUS_FALSE,
					client_args->credential, &context_handle, &user_id,
					&delegated_cred);

	if (result == GLOBUS_FALSE) {
		fprintf(stderr, "CLIENT: Authentication failed\n");
		exit(1);
	}

	result = globus_gsi_gssapi_test_send_hello(connect_fd, context_handle);

	if (result == GLOBUS_FALSE) {
		fprintf(stderr, "CLIENT: failed to send hello\n");
		exit(1);
	}

	globus_gsi_gssapi_test_cleanup(&context_handle, user_id, &delegated_cred);
	user_id = NULL;

	close(connect_fd);

	free(client_args);

	return NULL;
}
