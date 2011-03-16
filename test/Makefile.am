#
# tests
#
bin_PROGRAMS = gsi_pep_callout_config_test gsi_pep_callout_test

EXTRA_CFLAGS= \
    -DDEBUG \
    -DALLOW_EMPTY_CREDENTIALS 


gsi_pep_callout_config_test_SOURCES = \
	gsi_pep_callout_config_test.c

gsi_pep_callout_config_test_CFLAGS = \
    $(EXTRA_CFLAGS) \
    $(GLOBUS_GSI_CFLAGS) \
    $(LIBARGUS_PEP_CFLAGS) 

gsi_pep_callout_config_test_LDADD = \
	../src/libgsi_pep_callout.la \
    $(GLOBUS_GSI_LIBS) \
    $(LIBARGUS_PEP_LIBS)

gsi_pep_callout_test_SOURCES = \
	gsi_pep_callout_test.c \
	gssapi_test_utils.c \
	gssapi_test_utils.h

gsi_pep_callout_test_CFLAGS = \
    $(EXTRA_CFLAGS) \
    $(GLOBUS_GSI_CFLAGS) \
    $(LIBARGUS_PEP_CFLAGS) 

gsi_pep_callout_test_LDADD = \
	../src/libgsi_pep_callout.la \
    $(GLOBUS_GSI_LIBS) \
    $(LIBARGUS_PEP_LIBS)
