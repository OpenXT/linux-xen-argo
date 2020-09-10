#
# Copyright (c) 2010 Citrix Systems, Inc.
# 
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

#
# Autoconf initialisation.
#
AC_INIT(libargo, 1.0)
AC_PREREQ(2.13)
AC_CONFIG_HEADERS(src/config.h)
AC_CONFIG_SRCDIR(src/libargo.h)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])

#
# Version management.
# +1    : 0     Interface changes breaking retro-compatibility.
# 0     : +1    Internal changes without lost of retro-compatibility.
#
VERSION_MAJOR=1
VERSION_MINOR=0
AC_DEFINE_UNQUOTED([VERSION_MAJOR], [$VERSION_MAJOR], [libargo major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [$VERSION_MINOR], [libargo minor version number])

#
# Standard checks.
#
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AR

#
# Libtool version system.
#
# TODO: A lot of scripts assume libargo-1.0.so.0 or even libargo-1.0.so.0.0.0 to
# exist and have hardcoded that value.
# It makes little difference to maintain the soname for now since the version
# is unlikely to change soon, but will most certainly break the various scripts
# trying to use the interposer.
#LT_CURRENT=$VERSION_MAJOR
LT_CURRENT=0
#LT_REVISION=$VERSION_MINOR
LT_REVISION=0
LT_AGE=0
LT_RELEASE=$VERSION_MAJOR.$VERSION_MINOR
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)
AC_SUBST(LT_RELEASE)

LT_INIT

# Compiler capabilities.
AC_C_INLINE
AC_C_CONST

# Required headers.
AC_CHECK_HEADERS([linux/argo.h linux/argo_dev.h], [] , AC_MSG_ERROR([ARGO headers are missing.]),
                 [#include <stdint.h>
                  #include <unistd.h>
                  #define ARGO_EXCLUDE_INTERNAL
                  ])

# Required libraries.
AC_CHECK_LIB([dl], [dlopen])

# Output files.
AC_OUTPUT([Makefile
           src/Makefile
	   test/Makefile
	   app/Makefile
           libargo.pc
           ])
