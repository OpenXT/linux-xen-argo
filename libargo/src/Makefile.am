#
# Copyright (c) 2012 Citrix Systems, Inc.
# Modifications by Christopher Clark, Copyright (c) 2018 BAE Systems
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

noinst_HEADERS = project.h

include_HEADERS = libargo.h

lib_LTLIBRARIES = libargo_nointerposer.la libargo.la

libargo_nointerposer_la_SOURCES = \
	argo.c \
	map.c
libargo_nointerposer_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-release $(LT_RELEASE) \
	-export-dynamic
libargo_nointerposer_la_LIBTOOLFLAGS = --silent

libargo_la_SOURCES = \
	argo.c \
	map.c \
	interposer.c
libargo_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-release $(LT_RELEASE) \
	-export-dynamic
libargo_la_LIBTOOLFLAGS = --silent
