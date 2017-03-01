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
# define __LIBV4V_H__

# ifdef __cplusplus
extern "C" {
# endif

# include <stdint.h>
# define V4V_EXCLUDE_INTERNAL
# include <xen/v4v.h>
# include <sys/socket.h>

# define PF_XENV4V      13398		/*An unimaginative constant*/
# define AF_XENV4V      PF_XENV4V
# define PF_INETV4V     13399		/* v4v socket but otherwise treated as inet everywhere */
# define AF_INETV4V     PF_INETV4V

struct sockaddr_xenv4v {
	__SOCKADDR_COMMON (sxenv4v_);    /* Common data: address family and length.  */
	uint32_t sxenv4v_port;
	domid_t sxenv4v_domain;

        unsigned char sxenv4v_zero[sizeof (struct sockaddr) -
                           __SOCKADDR_COMMON_SIZE -
                           sizeof (domid_t) -
                           sizeof (uint32_t)];
};

int v4v_socket(int type);
int v4v_close(int fd);
int v4v_bind(int fd, v4v_addr_t *addr, domid_t partner);
int v4v_connect(int fd, v4v_addr_t *peer);
int v4v_listen(int fd, int backlog);
int v4v_accept(int fd, v4v_addr_t *peer);
ssize_t v4v_send(int fd, const void *buf, size_t len, int flags);
ssize_t v4v_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t v4v_sendto(int fd, const void *buf, size_t len, int flags, v4v_addr_t *dest_addr);
ssize_t v4v_recv(int fd, void *buf, size_t len, int flags);
ssize_t v4v_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t v4v_recvfrom(int fd, void *buf, size_t len, int flags, v4v_addr_t *src_addr);
int v4v_getsockname(int fd, v4v_addr_t *addr, domid_t *partner);
int v4v_getpeername(int fd, v4v_addr_t *addr);
int v4v_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);

int v4v_convert_inet_to_xen(int arg);

# ifdef __cplusplus
}
# endif /* __cplusplus */
#endif /* __LIBV4V_H__ */
