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

#ifndef __PROJECT_H__
# define __PROJECT_H__

# include "config.h"

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stdarg.h>
# include <ctype.h>

# include <inttypes.h>
# include <limits.h>

# include <errno.h>
# include <assert.h>

# include <unistd.h>
# include <fcntl.h>

# include <dlfcn.h>

# include <memory.h>

# include <strings.h>
# include <string.h>

# include <syslog.h>

# include <signal.h>

# include <malloc.h>

# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <sys/ioctl.h>
# include <sys/socket.h>

# include <netinet/in.h>
# include <netinet/tcp.h>

# include <linux/v4v_dev.h>

# include "libv4v.h"

void v4v_map_v4va_to_sin (struct sockaddr *addr, socklen_t *addrlen,
		v4v_addr_t *peer);
int v4v_map_sin_to_v4va (v4v_addr_t *peer, const struct sockaddr *addr,
		int addrlen);
void v4v_map_v4va_to_sxenv4v (struct sockaddr *addr, socklen_t *addrlen,
		v4v_addr_t *peer);
int v4v_map_sxenv4v_to_v4va (v4v_addr_t *peer, const struct sockaddr *addr,
		int addrlen);
int v4v_map_sa_to_v4va (v4v_addr_t *peer, const struct sockaddr *addr,
		int addrlen);


# ifdef DEBUG
#  define v4v_ioctl(a,b,c) ({ int ret=ioctl(a,b,c); fprintf(stderr,"ioctl(%d,%s,%s)=%d\n",a,#b,#c,ret);perror("ioctl"); ret; })
#  define DEBUG_PRINTF(a...) fprintf(stderr,a);
# else
#  define v4v_ioctl(a,b,c) ioctl(a,b,c)
#  define DEBUG_PRINTF(a...) 0
# endif

# define V4V_STREAM_DEV	"/dev/v4v_stream"
# define V4V_DGRAM_DEV	"/dev/v4v_dgram"

#endif /* __PROJECT_H__ */
