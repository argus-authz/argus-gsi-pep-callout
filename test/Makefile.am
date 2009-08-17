#
# tests
#
bin_PROGRAMS = gsi_pep_callout_config_test gsi_pep_callout_test

gsi_pep_callout_config_test_SOURCES = \
	gsi_pep_callout_config_test.c
gsi_pep_callout_config_test_CFLAGS = \
    -DDEBUG \
    $(GLITE_CFLAGS) \
    $(GLOBUS_NOTHR_CFLAGS)
gsi_pep_callout_config_test_LDADD = \
	../src/libgsi_pep_callout_$(GLOBUS_NOTHR_FLAVOR).la \
    -lpep-c \
	$(GLOBUS_GSS_NOTHR_LIBS) 
	
gsi_pep_callout_test_SOURCES = \
	gsi_pep_callout_test.c \
	gssapi_test_utils.c \
	gssapi_test_utils.h
gsi_pep_callout_test_CFLAGS = \
    -DDEBUG \
    $(GLITE_CFLAGS) \
    $(GLOBUS_NOTHR_CFLAGS)
gsi_pep_callout_test_LDADD = \
	../src/libgsi_pep_callout_$(GLOBUS_NOTHR_FLAVOR).la \
    -lpep-c \
	$(GLOBUS_GSS_NOTHR_LIBS) 

