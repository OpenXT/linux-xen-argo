#
#
# Makefile.am:
#
# Copyright (c) 2010 James McKenzie <20@madingley.org>,
# All rights reserved.
#
# $Id:$
#
# $Log:$
#
#
#

#
# Copyright (c) 2012 Citrix Systems, Inc.
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


INCLUDES = 

NOINTERPOSER_SRCS= libv4v.c version.c v4v.c map.c
SRCS=${NOINTERPOSER_SRCS} interposer.c

CPROTO=cproto

V4VSRCS=${SRCS}

noinst_HEADERS= project.h prototypes.h v4v-tail.h ext_prototypes.h

libv4v_la_SOURCES = ${V4VSRCS}

libv4v_nointerposer_la_SOURCES = ${NOINTERPOSER_SRCS}
libv4v_nointerposer_la_CFLAGS = ${AM_CFLAGS} -fPIC
libv4v_la_CFLAGS = ${AM_CFLAGS} -fPIC

BUILT_SOURCES = version.h libv4v.h

lib_LTLIBRARIES=libv4v.la libv4v_nointerposer.la

include_HEADERS=libv4v.h

AM_CFLAGS=-g

libv4v_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -release $(LT_RELEASE) \
        -export-dynamic  -ldl

libv4v_nointerposer_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -release $(LT_RELEASE) \
        -export-dynamic  -ldl

VFD=${srcdir}/..
VF=${shell cat ${VFD}/version-files}
VFS=${VF:%=${VFD}/%}
VCHK=${shell cat ${VFS} | @MD5SUM@ | @AWK@ '{print $$1 }' }
VNUM=${shell @GREP@ ${VCHK} ${VFD}/version-md5sums | @AWK@ '{ print $$2 }'  }
VDEF=${shell echo `cat ${VFD}/version-major`.`cat ${VFD}/version-minor`.`cat ${VFD}/version-micro` }


libv4v.h:v4v-head.h ext_prototypes.h v4v-tail.h
	cat v4v-head.h ext_prototypes.h v4v-tail.h > libv4v.h

protos: 
	echo > prototypes.h
	echo > ext_prototypes.h
	cat v4v-head.h ext_prototypes.h v4v-tail.h > libv4v.h
	${CPROTO} -v -DINT_PROTOS ${INCLUDES} ${SRCS} > prototypes.tmp
	mv -f prototypes.tmp prototypes.h
	${CPROTO} -v -DEXT_PROTOS ${INCLUDES} ${SRCS} > ext_prototypes.h
	cat v4v-head.h ext_prototypes.h v4v-tail.h > libv4v.h

version.h: $(VFD)/version-files $(VFD)/version-major \
	$(VFD)/version-minor $(VFD)/version-micro \
	$(VFD)/version-md5sums ${VFS} Makefile
	if [ .${VNUM} = . ]; then \
		echo "#define FULL_VERSION \"libv4v Version ${VDEF} + Edits\"" > version.h; \
		echo ${VDEF}-E > version-num; \
	else \
		echo "#define FULL_VERSION \"libv4v Version ${VNUM}\"" > version.h; \
		echo ${VNUM} > version-num; \
	fi

