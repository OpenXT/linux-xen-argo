/*
 * Copyright (c) 2011 Citrix Systems, Inc.
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
char *libv4v_get_version(void);
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
int v4v_viptables_add (int fd, v4v_viptables_rule_t* rule, int position);
int v4v_viptables_del (int fd, v4v_viptables_rule_t* rule, int position);
int v4v_viptables_flush (int fd);
int v4v_viptables_list (int fd);
/* interposer.c */
int v4v_convert_inet_to_xen(int arg);
int socket(int domain, int type, int protocol);
int close(int fd);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int dup(int oldfd);
int dup2(int oldfd, int newfd);
int dup3(int oldfd, int newfd, int flags);
int shutdown(int sockfd, int how);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
/* map.c */
void v4v_map_v4va_to_sin(struct sockaddr *addr, socklen_t *addrlen, v4v_addr_t *peer);
int v4v_map_sin_to_v4va(v4v_addr_t *peer, const struct sockaddr *addr, int addrlen);
void v4v_map_v4va_to_sxenv4v(struct sockaddr *addr, socklen_t *addrlen, v4v_addr_t *peer);
int v4v_map_sxenv4v_to_v4va(v4v_addr_t *peer, const struct sockaddr *addr, int addrlen);
int v4v_map_sa_to_v4va(v4v_addr_t *peer, const struct sockaddr *addr, int addrlen);
