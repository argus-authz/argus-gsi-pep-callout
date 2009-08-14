#
# $Id$
#

#
# library to build
#
lib_LTLIBRARIES = libgsi_pep_callout_$(GLOBUS_NOTHR_FLAVOR).la

# sources not distributed
libgsi_pep_callout___GLOBUS_NOTHR_FLAVOR__la_SOURCES = \
    gssapi_openssl.h \
    globus_gsi_gss_constants.h \
    gsi_pep_callout.h \
    gsi_pep_callout.c \
    gsi_pep_callout_error.h \
    gsi_pep_callout_error.c \
    gsi_pep_callout_config.h \
    gsi_pep_callout_config.c

# compiler flags
libgsi_pep_callout___GLOBUS_NOTHR_FLAVOR__la_CFLAGS = \
    $(GLITE_CFLAGS) \
    $(GLOBUS_NOTHR_CFLAGS)


# linker flags
libgsi_pep_callout___GLOBUS_NOTHR_FLAVOR__la_LDFLAGS = \
    -version-info 0:0:0 \
    $(GLITE_LDFLAGS) \
    $(GLOBUS_NOTHR_LDFLAGS)


# libraries to link with
libgsi_pep_callout___GLOBUS_NOTHR_FLAVOR__la_LIBADD = \
	$(GLOBUS_COMMON_NOTHR_LIBS) \
    $(GLOBUS_GSI_NOTHR_LIBS) 
    
    ## 
    ## -lglobus_gridmap_callout_error_$(GLOBUS_NOTHR_FLAVOR)
    ## $(GLOBUS_GSS_NOTHR_LIBS) 
	##
