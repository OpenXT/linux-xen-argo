/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * Modifications by Christopher Clark, Copyright (c) 2018 BAE Systems
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

#ifndef __LIBARGO_H__
# define __LIBARGO_H__

# ifdef __cplusplus
extern "C" {
# endif

# include <stdint.h>
# define ARGO_EXCLUDE_INTERNAL
# include <linux/argo.h>
# include <sys/socket.h>

# define PF_XENARGO      13398		/*An unimaginative constant*/
# define AF_XENARGO      PF_XENARGO
# define PF_INETARGO     13399		/* argo socket but otherwise treated as inet everywhere */
# define AF_INETARGO     PF_INETARGO

struct sockaddr_xenargo {
	__SOCKADDR_COMMON (sxenargo_);    /* Common data: address family and length.  */
	uint32_t sxenargo_port;
	domid_t sxenargo_domain;

        unsigned char sxenargo_zero[sizeof (struct sockaddr) -
                           __SOCKADDR_COMMON_SIZE -
                           sizeof (domid_t) -
                           sizeof (uint32_t)];
};

int argo_socket(int type);
int argo_close(int fd);
int argo_bind(int fd, xen_argo_addr_t *addr, domid_t partner_id);
int argo_connect(int fd, xen_argo_addr_t *peer);
int argo_listen(int fd, int backlog);
int argo_accept(int fd, xen_argo_addr_t *peer);
ssize_t argo_send(int fd, const void *buf, size_t len, int flags);
ssize_t argo_sendmsg(int fd, const struct msghdr *msg, int flags);
ssize_t argo_sendto(int fd, const void *buf, size_t len, int flags, xen_argo_addr_t *dest_addr);
ssize_t argo_recv(int fd, void *buf, size_t len, int flags);
ssize_t argo_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t argo_recvfrom(int fd, void *buf, size_t len, int flags, xen_argo_addr_t *src_addr);
int argo_getsockname(int fd, xen_argo_addr_t *out_addr, domid_t *out_partner_id);
int argo_getpeername(int fd, xen_argo_addr_t *out_addr);
int argo_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
int viptables_add (int fd, xen_argo_viptables_rule_t *rule, int position);
int viptables_del (int fd, xen_argo_viptables_rule_t *rule, int position);
int viptables_flush (int fd);
int viptables_list (int fd);

# ifdef __cplusplus
}
# endif /* __cplusplus */
#endif /* __LIBARGO_H__ */
