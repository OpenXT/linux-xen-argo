/*
 * project.h:
 *
 * Copyright (c) 2010 James McKenzie <20@madingley.org>,
 * All rights reserved.
 *
 */

/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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


/*
 * $Id:$
 */

/*
 * $Log:$
 *
 */

#ifndef __PROJECT_H__
#define __PROJECT_H__

#include "config.h"

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif
#include <time.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(HAVE_SYS_INT_TYPES_H)
#include <sys/int_types.h>
#endif

#ifdef INT_PROTOS
#define INTERNAL
#define EXTERNAL
#else 
#ifdef EXT_PROTOS
#define INTERNAL static
#define EXTERNAL
#else
#define INTERNAL
#define EXTERNAL
#endif
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/v4v_dev.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <malloc.h>
#include <sys/stat.h>

#include "libv4v.h"

#include "prototypes.h"

#ifdef DEBUG
#define v4v_ioctl(a,b,c) ({ int ret=ioctl(a,b,c); fprintf(stderr,"ioctl(%d,%s,%s)=%d\n",a,#b,#c,ret);perror("ioctl"); ret; })
#define DEBUG_PRINTF(a...) fprintf(stderr,a);
#else 
#define v4v_ioctl(a,b,c) ioctl(a,b,c)
#define DEBUG_PRINTF(a...) 0
#endif

#define V4V_STREAM_DEV "/dev/v4v_stream"
#define V4V_DGRAM_DEV "/dev/v4v_dgram"

#endif /* __PROJECT_H__ */
