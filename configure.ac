#                                              -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# $Id: configure.ac 1194 2009-06-19 12:54:48Z vtschopp $
#
##
# when updating version also update VERSION_* variables (here below)
##
AC_INIT([glite-authz-gsi-pep-callout], [1.0.0], [grid@switch.ch])

AC_CONFIG_AUX_DIR(project)

##
# version numbers
# used for version.h.in -> version.h
##
VERSION_MAJOR=1
VERSION_MINOR=0
VERSION_REVISION=0
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
# OSX CFLAGS
#case $host in
#*-*-darwin*)
#    AC_MSG_NOTICE([Mac OSX ($host_os): building for i386 and x86_64 architectures])
#    CFLAGS="$CFLAGS -arch i386 -arch x86_64 "
#    ;;
#esac

# Check glite location
AC_GLITE

# Checks for glite PEP-C headers and library
# will automatically add -lpep-c in LDFLAGS
ac_cppflags_backup=$CPPFLAGS
ac_ldflags_backup=$LDFLAGS
CPPFLAGS="-I$GLITE_LOCATION/include"
LDFLAGS="-L$GLITE_LOCATION/lib"
AC_CHECK_HEADER([pep/pep.h],,[AC_MSG_ERROR(can not find libpep-c header pep/pep.h)])
AC_CHECK_LIB(pep-c,pep_initialize)
CPPFLAGS=$ac_cppflags_backup
LDFLAGS=$ac_ldflags_backup

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T


# Check globus location
AC_GLOBUS


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
])

AC_OUTPUT


