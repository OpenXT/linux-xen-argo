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

AC_PREREQ(2.13)
AC_INIT(src/libv4v.c)

AC_PROG_CC
AC_SYS_LARGEFILE
#AM_PROG_CC_C_O
AC_CONFIG_MACRO_DIR([m4])


LIBV4V_MAJOR_VERSION=`cat $srcdir/version-major`
LIBV4V_MINOR_VERSION=`cat $srcdir/version-minor`
LIBV4V_MICRO_VERSION=`cat $srcdir/version-micro`



LIBV4V_INTERFACE_VERSION_MIN=$LIBV4V_MINOR_VERSION
LIBV4V_INTERFACE_VERSION_MAX=$LIBV4V_MINOR_VERSION
LIBV4V_INTERFACE_REVISION=1

LIBV4V_VERSION=$LIBV4V_MAJOR_VERSION.$LIBV4V_MINOR_VERSION.$LIBV4V_MICRO_VERSION

AC_SUBST(LIBV4V_MAJOR_VERSION)
AC_SUBST(LIBV4V_MINOR_VERSION)
AC_SUBST(LIBV4V_MICRO_VERSION)
AC_SUBST(LIBV4V_VERSION)

AC_SUBST(LIBV4V_INTERFACE_VERSION_MIN)
AC_SUBST(LIBV4V_INTERFACE_VERSION_MAX)
AC_SUBST(LIBV4V_INTERFACE_REVISION)


LT_RELEASE=$LIBV4V_MAJOR_VERSION.$LIBV4V_MINOR_VERSION
LT_CURRENT=$LIBV4V_INTERFACE_VERSION_MAX
LT_REVISION=$LIBV4V_MICRO_VERSION
LT_AGE=`expr $LIBV4V_INTERFACE_VERSION_MAX - $LIBV4V_INTERFACE_VERSION_MIN`

AC_SUBST(LT_RELEASE)
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

VERSION=$LIBV4V_VERSION
PACKAGE=libv4v

AM_INIT_AUTOMAKE($PACKAGE,$VERSION)

AM_PROG_LIBTOOL

AM_CONFIG_HEADER(src/config.h)

AC_CHECK_PROG(MD5SUM,md5sum,md5sum)
AC_CHECK_PROG(GREP,grep,grep)
AC_CHECK_PROG(SED,sed,sed)
AC_PROG_AWK

dnl AC_DEFINE_UNQUOTED(LIBV4V_MAJOR_VERSION, $LIBV4V_MAJOR_VERSION)
dnl AC_DEFINE_UNQUOTED(LIBV4V_MINOR_VERSION, $LIBV4V_MINOR_VERSION)
dnl AC_DEFINE_UNQUOTED(LIBV4V_MICRO_VERSION, $LIBV4V_MICRO_VERSION)

AC_CHECK_HEADERS(fcntl.h malloc.h sys/ioctl.h unistd.h)
AC_CHECK_HEADERS(sys/scsi/impl/uscsi.h scsi/sg.h stdint.h)
AC_CHECK_HEADERS(sys/int_types.h string.h strings.h)
AC_CHECK_HEADERS(dirent.h sys/stat.h)

AC_C_INLINE
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM
AC_CHECK_FUNCS(select strdup strstr)

I2_TM_H=$ac_cv_struct_tm

I2_HAVE_STDINT_H=0
I2_HAVE_SYS_INT_TYPES_H=0
if test "$ac_cv_header_sys_int_types_h" = "yes"; then
	I2_HAVE_SYS_INT_TYPES_H=1
fi
if test "$ac_cv_header_stdint_h" = "yes"; then
	I2_HAVE_STDINT_H=1
fi
I2_HAVE_UNISTD_H=0
if test "$ac_cv_header_unistd_h" = "yes"; then
	I2_HAVE_UNISTD_H=1
fi

AC_SUBST(I2_TM_H)
AC_SUBST(I2_HAVE_STDINT_H)
AC_SUBST(I2_HAVE_SYS_INT_TYPES_H)
AC_SUBST(I2_HAVE_UNISTD_H)



AC_OUTPUT([Makefile 
	src/Makefile 
	src/v4v-head.h
	test/Makefile 
	app/Makefile
	libv4v.pc.src
	libv4v-config.src],[chmod +x libv4v-config.src])

