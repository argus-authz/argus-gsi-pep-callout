#
# tests
#
bin_PROGRAMS = gsi_pep_callout_config_test gsi_pep_callout_test

gsi_pep_callout_config_test_SOURCES = \
	gsi_pep_callout_config_test.c

gsi_pep_callout_config_test_CFLAGS = \
    -DDEBUG \
    -DALLOW_EMPTY_CREDENTIALS \
    $(LIBARGUS_PEP_CFLAGS) \
    $(GLOBUS_GSI_CFLAGS)

gsi_pep_callout_config_test_LDADD = \
	../src/libgsi_pep_callout.la \
    $(LIBARGUS_PEP_LIBS) \
    $(GLOBUS_GSI_LIBS)

gsi_pep_callout_test_SOURCES = \
	gsi_pep_callout_test.c \
	gssapi_test_utils.c \
	gssapi_test_utils.h

gsi_pep_callout_test_CFLAGS = \
    -DDEBUG \
    -DALLOW_EMPTY_CREDENTIALS \
    $(LIBARGUS_PEP_CFLAGS) \
    $(GLOBUS_GSI_CFLAGS)

gsi_pep_callout_test_LDADD = \
	../src/libgsi_pep_callout.la \
    $(LIBARGUS_PEP_LIBS) \
    $(GLOBUS_GSI_LIBS)
