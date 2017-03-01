/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __LIBV4V_H__
#define __LIBV4V_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/*the integer constants here are set by configure*/

/*get uint32_t and friends defined */
#if @I2_HAVE_STDINT_H@
#include <stdint.h>
#elif @I2_HAVE_SYS_INT_TYPES_H@
#include <sys/int_types.h>
#endif
#if @I2_HAVE_UNISTD_H@
#include <unistd.h>
#endif

/* If the following is <> then configure failed to find where */
/* struct tm was defined - report it as a bug */

/*get struct tm defined*/
#include <@I2_TM_H@>

#define V4V_EXCLUDE_INTERNAL
#include <xen/v4v.h>
#include <sys/socket.h>

#define PF_XENV4V	13398		/*An unimaginative constant*/
#define AF_XENV4V      PF_XENV4V
#define PF_INETV4V	13399		/* v4v socket but otherwise treated as inet everywhere */
#define AF_INETV4V	PF_INETV4V 

struct sockaddr_xenv4v {
	__SOCKADDR_COMMON (sxenv4v_);    /* Common data: address family and length.  */
	uint32_t sxenv4v_port;
	domid_t sxenv4v_domain;

        unsigned char sxenv4v_zero[sizeof (struct sockaddr) -
                           __SOCKADDR_COMMON_SIZE -
                           sizeof (domid_t) -
                           sizeof (uint32_t)];
};

