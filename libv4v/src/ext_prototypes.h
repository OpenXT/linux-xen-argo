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

/* libv4v.c */
/* version.c */
/* v4v.c */
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
/* interposer.c */
int v4v_convert_inet_to_xen(int arg);
/* map.c */
