#                                              -*- Autoconf -*-
#
# Copyright 2008 Members of the EGEE Collaboration.
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
# $Id: configure.ac 1194 2009-06-19 12:54:48Z vtschopp $
#
##
# IMPORTANT! When updating version also update VERSION_* variables (here below)
AC_INIT([argus-gsi-pep-callout], [1.1.1], [grid@switch.ch])

AC_CONFIG_AUX_DIR(project)
AC_CONFIG_MACRO_DIR(project)

##
# version numbers
# used for version.h.in -> version.h
##
VERSION_MAJOR=1
VERSION_MINOR=1
VERSION_REVISION=1
# timestamp epoch
VERSION_TIMESTAMP=esyscmd(perl -e 'print time')
AC_SUBST(VERSION_MAJOR)
AC_SUBST(VERSION_MINOR)
AC_SUBST(VERSION_REVISION)
AC_SUBST(VERSION_TIMESTAMP)

# OSX requires ./configure --disable-dependency-tracking to compile, others don't care
AM_INIT_AUTOMAKE([no-dependencies])
# disable default static library
AM_DISABLE_STATIC

# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC
#AC_PROG_MKDIR_P # not defined on SL4 !!!
AC_PROG_INSTALL
AC_PROG_LN_S

# Check for doxygen
#AC_CHECK_PROG(DOXYGEN,doxygen,doxygen,$ac_aux_dir/missing --run doxygen)
#AC_SUBST(DOXYGEN)

# GCC CFLAGS
if test "$GCC" = "yes"; then
    CFLAGS="$CFLAGS -Wall "
fi

# Check glite location
AC_GLITE

# Checks for glite PEP-C headers and library
# will automatically add -lpep-c in LDFLAGS
ac_cflags_backup=$CFLAGS
ac_ldflags_backup=$LDFLAGS
CFLAGS=$GLITE_CFLAGS
LDFLAGS=$GLITE_LDFLAGS
AC_CHECK_HEADER([pep/pep.h],,[AC_MSG_ERROR(can not find libpep-c header pep/pep.h)])
AC_CHECK_LIB(pep-c,pep_initialize)
CFLAGS=$ac_cflags_backup
LDFLAGS=$ac_ldflags_backup

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T


# Check globus location
#AC_GLOBUS

#
# EMI globus EPEL HACK
# set CFLAGS and LDFLAGS:
#
# CFLAGS=-I/usr/lib64/include/globus -I/usr/include/globus
# LDFLAGS=-lglobus_common -lglobus_gssapi_gsi -lglobus_gssapi_error -lglobus_gss_assist -lglobus_gsi_credential
#
AC_CHECK_HEADER([globus_config.h],,[AC_MSG_ERROR(Globus header globus_config.h not found)])
AC_CHECK_HEADER([globus/globus_common.h],,[AC_MSG_ERROR(Globus header globus_common.h not found)])

#GLOBUS_EMI_CFLAGS=-I/usr/include/globus
#AC_SUBST(GLOBUS_EMI_CFLAGS)
#AC_MSG_NOTICE([GLOBUS_EMI_CFLAGS= $GLOBUS_EMI_CFLAGS])

#GLOBUS_EMI_LDFLAGS=-L/usr/lib64
#GLOBUS_EMI_LDFLAGS=
#AC_SUBST(GLOBUS_EMI_LDFLAGS)
#AC_MSG_NOTICE([GLOBUS_EMI_LDFLAGS= $GLOBUS_EMI_LDFLAGS])


# Checks for library and functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strerror strrchr calloc])

# Sets default prefix
AC_PREFIX_DEFAULT(/opt/glite)

AC_CONFIG_SRCDIR(src)
AM_CONFIG_HEADER(src/config.h)

AC_CONFIG_FILES([
Makefile
src/Makefile
src/version.h
test/Makefile
])

AC_OUTPUT


