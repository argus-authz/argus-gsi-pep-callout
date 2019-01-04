#
# Copyright Members of the EGEE Collaboration. 2008.
# See http://www.eu-egee.org/partners for details on the copyright holders. 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# $Id$
#

#
# library to build
#
lib_LTLIBRARIES = libgsi_pep_callout.la

# sources not distributed
libgsi_pep_callout_la_SOURCES = \
    gsi_pep_callout_globus_internal.h \
    gsi_pep_callout.h \
    gsi_pep_callout.c \
    gsi_pep_callout_error.h \
    gsi_pep_callout_error.c \
    gsi_pep_callout_config.h \
    gsi_pep_callout_config.c

# compiler flags
libgsi_pep_callout_la_CFLAGS = \
    -DDEBUG \
    -DALLOW_EMPTY_CREDENTIALS \
    $(GLOBUS_GSI_CFLAGS) \
    $(LIBARGUS_PEP_CFLAGS) 

# linker flags
libgsi_pep_callout_la_LDFLAGS = \
    -version-info 1:1:0


# libraries to link with
libgsi_pep_callout_la_LIBADD = \
    $(GLOBUS_GSI_LIBS) \
    $(LIBARGUS_PEP_LIBS) 

#    -lglobus_common \
#    -lglobus_gssapi_gsi -lglobus_gssapi_error \
#    -lglobus_gss_assist \
#    -lglobus_gsi_credential
