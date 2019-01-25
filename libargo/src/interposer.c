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

#include "project.h"

#define INTERPOSE(n,rt,p...)  \
		static rt (*orig_ ## n) (p); \
		rt n (p)

#define CHECK_INTERPOSE(n) \
		do { \
			init(); \
			if (!orig_ ## n) { \
				errno=ENOSYS; \
				return -1; \
			} \
		} while (1==0)

#define FIND(n) \
    do { \
        orig_ ## n = dlsym(RTLD_NEXT, #n ); \
    } while (1==0)

static void init (void);

/*
 * argo_fds:     lists interposed fd's
 * argo_checked: lists fd's we have already checked are not ARGO
 * argo_afs:     lists fd's with AF_XENARGO
 */
static fd_set argo_fds;
static fd_set argo_checked;
static fd_set argo_afs;

static int force_xen;

static void inline
do_register (fd_set * p, int fd)
{
  if ((fd<0) || (fd>=FD_SETSIZE)) return;
  FD_SET (fd, p);
}


static void inline
do_unregister (fd_set * p, int fd)
{
  if ((fd<0) || (fd>=FD_SETSIZE)) return;
  FD_CLR (fd, p);
}

static int inline
is_registered (fd_set * p, int fd)
{
  if ((fd<0) || (fd>=FD_SETSIZE)) return 0;
  return FD_ISSET (fd, p);
}


static void inline
register_fd (int fd)
{
  do_register (&argo_fds, fd);
}

static void inline
unregister_fd (int fd)
{
  do_unregister (&argo_fds, fd);
}


static void
check_fd (int fd)
{
#if 0
  /* This would be a better way if the accept()'ed socket
   * had the /dev/argo_* inode but for now it doesn't */
  struct stat st;
  if (argo_dgram_inode.st_ino == (ino_t) (-1L) ||
      argo_stream_inode.st_ino == (ino_t) (-1L))
    {
      if (stat (ARGO_DGRAM_DEV, &st))
        return;
      argo_dgram_inode.st_dev = st.st_dev;
      argo_dgram_inode.st_ino = st.st_ino;
      if (stat (ARGO_STREAM_DEV, &st))
        return;
      argo_stream_inode.st_dev = st.st_dev;
      argo_stream_inode.st_ino = st.st_ino;
    }
  if (fstat (fd, &st))
    return;
  do_register (&argo_checked, fd);
  if (((st.st_dev == argo_stream_inode.st_dev) &&
       (st.st_ino == argo_stream_inode.st_ino)) ||
      ((st.st_dev == argo_dgram_inode.st_dev) &&
       (st.st_ino == argo_dgram_inode.st_ino)))
    do_register (&argo_fds, fd);
#else
  struct argo_ring_id id;
  int ret;

  do_register (&argo_checked, fd);
  if (!ioctl (fd, ARGOIOCGETSOCKNAME, &id))
    {
      do_register (&argo_fds, fd);
    }
#endif
}


static int inline
is_our_fd (int fd)
{
  if ((!is_registered (&argo_fds, fd)) && (!is_registered (&argo_checked, fd)))
    {
      check_fd (fd);
    }
  return is_registered (&argo_fds, fd);
}


static void inline
register_af (int fd)
{
  do_register (&argo_afs, fd);
}

static void inline
unregister_af (int fd)
{
  do_unregister (&argo_afs, fd);
}

static int inline
is_our_af (int fd)
{
  return is_registered (&argo_afs, fd);
}

static void
do_copy (fd_set * p, int src, int dst)
{
  if ((src<0) || (src>=FD_SETSIZE)) return;
  if ((dst<0) || (dst>=FD_SETSIZE)) return;
  if (FD_ISSET (src, p))
    FD_SET (dst, p);
  else
    FD_CLR (dst, p);
}

static void
copy_our_fd (int src, int dst)
{
  do_copy (&argo_fds, src, dst);
}

static void
copy_our_af (int src, int dst)
{
  do_copy (&argo_afs, src, dst);
}

static void init (void);


INTERPOSE (socket, int, int domain, int type, int protocol)
{
  int ret;

  CHECK_INTERPOSE (socket);

  if ((domain != PF_XENARGO) && (domain != PF_INETARGO) &&
      ((domain != PF_INET) || (!getenv ("INET_IS_ARGO"))) && !force_xen)
    return orig_socket (domain, type, protocol);

  ret = argo_socket (type);
  if (ret < 0)
    return ret;

  register_fd (ret);

  if (domain == PF_XENARGO)
    register_af (ret);
  else
    unregister_af (ret);

  return ret;
}

INTERPOSE (close, int, int fd)
{
  CHECK_INTERPOSE (close);

  unregister_fd (fd);

  return orig_close (fd);
}


INTERPOSE (bind, int, int sockfd, const struct sockaddr * addr,
           socklen_t addrlen)
{
  xen_argo_addr_t argoa;

  CHECK_INTERPOSE (bind);

  if (!is_our_fd (sockfd))
    return orig_bind (sockfd, addr, addrlen);

  if (addr->sa_family == AF_XENARGO)
    register_af (sockfd);
  else
    unregister_af (sockfd);

  if (argo_map_sa_to_argoa (&argoa, addr, addrlen))
    return -EINVAL;

  return argo_bind (sockfd, &argoa,
                   getenv ("ARGO_ACCEPT_DOM0_ONLY") ? 0 : XEN_ARGO_DOMID_ANY);
}



INTERPOSE (connect, int, int sockfd, const struct sockaddr * addr,
           socklen_t addrlen)
{
  xen_argo_addr_t peer, me;
  char *val, *end;
  int addend, ret;

  CHECK_INTERPOSE (connect);

  if (!is_our_fd (sockfd))
    return orig_connect (sockfd, addr, addrlen);

  if (argo_map_sa_to_argoa (&peer, addr, addrlen))
    return -EINVAL;

  /* Bind the socket to a specific port if requested */
  val = getenv ("ARGO_CLIENT_PORT_ADDEND");
  if (val != NULL) {
    addend = strtol(val, &end, 10);
    /* Sanitize the addend */
    if (end == NULL || *end != '\0' || addend < 0)
      return -EINVAL;
    me.domain_id = XEN_ARGO_DOMID_ANY;
    me.aport = peer.aport + addend;
    DEBUG_PRINTF ("BINDING CLIENT TO aport %d\n", (int) me.aport);
    DEBUG_PRINTF ("  AND SET %d AS THE PARTNER\n", (int) peer.domain_id);
    ret = argo_bind(sockfd, &me, peer.domain_id);
    if (ret)
      return ret;
  }

  DEBUG_PRINTF ("CONNECTING TO %d:%d\n", (int) peer.domain_id,
                (int) peer.aport);

  return argo_connect (sockfd, &peer);
}

INTERPOSE (listen, int, int sockfd, int backlog)
{
  int ret;

  CHECK_INTERPOSE (listen);

  if (!is_our_fd (sockfd))
    return orig_listen (sockfd, backlog);

  return argo_listen (sockfd, backlog);
}

INTERPOSE (accept, int, int sockfd, struct sockaddr * addr,
           socklen_t * addrlen)
{
  xen_argo_addr_t peer;
  int ret;

  CHECK_INTERPOSE (accept);

  if (!is_our_fd (sockfd))
    return orig_accept (sockfd, addr, addrlen);

  ret = argo_accept (sockfd, &peer);

  register_fd (ret);

  if (is_our_af (sockfd))
    {
      argo_map_argoa_to_sxenargo (addr, addrlen, &peer);
    }
  else
    {
      argo_map_argoa_to_sin (addr, addrlen, &peer);
    }

  return ret;
}



INTERPOSE (send, ssize_t, int sockfd, const void *buf, size_t len, int flags)
{
  CHECK_INTERPOSE (send);

  if (!is_our_fd (sockfd))
    return orig_send (sockfd, buf, len, flags);


  return argo_send (sockfd, buf, len, flags);
}

INTERPOSE (sendmsg, ssize_t, int sockfd, const struct msghdr * msg, int flags)
{
  struct msghdr argomsg;
  xen_argo_addr_t argoa;
  CHECK_INTERPOSE (sendmsg);

  if (!is_our_fd (sockfd))
    return orig_sendmsg (sockfd, msg, flags);

  if (!msg)
	  return -EINVAL;

  argomsg = *msg;
  if (argomsg.msg_name) {
	if (argo_map_sa_to_argoa(&argoa, argomsg.msg_name, argomsg.msg_namelen))
		return -EINVAL;
	argomsg.msg_name = &argoa;
	argomsg.msg_namelen = sizeof(argoa);
  }

  return argo_sendmsg (sockfd, &argomsg, flags);
}

INTERPOSE (sendto, ssize_t, int sockfd, const void *buf, size_t len,
           int flags, const struct sockaddr * dest_addr, socklen_t addrlen)
{
  xen_argo_addr_t peer;

  CHECK_INTERPOSE (sendto);

  if (!is_our_fd (sockfd))
    return orig_sendto (sockfd, buf, len, flags, dest_addr, addrlen);

  if (dest_addr && argo_map_sa_to_argoa (&peer, dest_addr, addrlen))
    return -EINVAL;

  return argo_sendto (sockfd, buf, len, flags, dest_addr ? &peer : NULL);

}


INTERPOSE (recv, ssize_t, int sockfd, void *buf, size_t len, int flags)
{
  CHECK_INTERPOSE (recv);

  if (!is_our_fd (sockfd))
    return orig_recv (sockfd, buf, len, flags);

  return argo_recv (sockfd, buf, len, flags);
}

INTERPOSE (recvmsg, ssize_t, int sockfd, struct msghdr * msg, int flags)
{
  struct xen_argo_addr peer;
  struct msghdr my_msg = *msg;
  ssize_t ret;

  CHECK_INTERPOSE (recvmsg);

  if (!is_our_fd (sockfd))
    return orig_recvmsg (sockfd, msg, flags);

  if (msg->msg_name)
    {
      my_msg.msg_name = &peer;
    }


  ret = argo_recvmsg (sockfd, &my_msg, flags);


  if (msg->msg_name)
    {
      if (is_our_af (sockfd))
        {
          argo_map_argoa_to_sxenargo (msg->msg_name, &msg->msg_namelen, &peer);
        }
      else
        {
          argo_map_argoa_to_sin (msg->msg_name, &msg->msg_namelen, &peer);
        }
    }

  msg->msg_controllen = my_msg.msg_controllen;

  return ret;
}


INTERPOSE (recvfrom, ssize_t, int sockfd, void *buf, size_t len,
           int flags, struct sockaddr * src_addr, socklen_t * addrlen)
{
  ssize_t ret;
  xen_argo_addr_t peer = { 0 };

  CHECK_INTERPOSE (recvfrom);

  if (!is_our_fd (sockfd))
    return orig_recvfrom (sockfd, buf, len, flags, src_addr, addrlen);

  ret = argo_recvfrom (sockfd, buf, len, flags, &peer);

  if (is_our_af (sockfd))
    {
      argo_map_argoa_to_sxenargo (src_addr, addrlen, &peer);
    }
  else
    {
      argo_map_argoa_to_sin (src_addr, addrlen, &peer);
    }

  return ret;
}


INTERPOSE (getsockname, int, int sockfd, struct sockaddr * addr,
           socklen_t * addrlen)
{
  ssize_t ret;
  xen_argo_addr_t name;

  CHECK_INTERPOSE (getsockname);

  if (!is_our_fd (sockfd))
    return orig_getsockname (sockfd, addr, addrlen);

  ret = argo_getsockname (sockfd, &name, NULL);

  if (is_our_af (sockfd))
    {
      argo_map_argoa_to_sxenargo (addr, addrlen, &name);
    }
  else
    {
      argo_map_argoa_to_sin (addr, addrlen, &name);
    }

  return ret;
}


INTERPOSE (getpeername, int, int sockfd, struct sockaddr * addr,
           socklen_t * addrlen)
{
  ssize_t ret;
  xen_argo_addr_t ring_addr = { 0 };

  CHECK_INTERPOSE (getpeername);

  if (!is_our_fd (sockfd))
    return orig_getpeername (sockfd, addr, addrlen);

  ret = argo_getpeername (sockfd, &ring_addr);

  if (is_our_af (sockfd))
    {
      argo_map_argoa_to_sxenargo (addr, addrlen, &ring_addr);
    }
  else
    {
      argo_map_argoa_to_sin (addr, addrlen, &ring_addr);
    }

  return ret;
}

INTERPOSE (dup, int, int oldfd)
{
  int ret;
  CHECK_INTERPOSE (dup);

  ret = orig_dup (oldfd);

  copy_our_fd (oldfd, ret);
  copy_our_af (oldfd, ret);

  return ret;
}


INTERPOSE (dup2, int, int oldfd, int newfd)
{
  int ret;

  CHECK_INTERPOSE (dup2);

  ret = orig_dup2 (oldfd, newfd);

  copy_our_fd (oldfd, ret);
  copy_our_af (oldfd, ret);


  return ret;
}

INTERPOSE (dup3, int, int oldfd, int newfd, int flags)
{
  int ret;

  CHECK_INTERPOSE (dup3);

  ret = dup3 (oldfd, newfd, flags);

  copy_our_fd (oldfd, ret);
  copy_our_af (oldfd, ret);


  return ret;
}


INTERPOSE (shutdown, int, int sockfd, int how)
{
  CHECK_INTERPOSE (shutdown);

  if (!is_our_fd (sockfd))
    return orig_shutdown (sockfd, how);

  return 0;
}

INTERPOSE (setsockopt, int, int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  CHECK_INTERPOSE (setsockopt);

  if (!is_our_fd (sockfd))
    return orig_setsockopt (sockfd, level, optname, optval, optlen);

  if ((level == SOL_SOCKET) && (optname == SO_KEEPALIVE))
    {
      /* Can be safely ignored */
      return 0;
    }
  if ((level == SOL_SOCKET) && (optname == SO_REUSEADDR))
    {
      //FIXME
      return 0;
    }
  if ((level == SOL_SOCKET) && (optname == SO_LINGER))
    {
      //FIXME
      return 0;
    }

  if ((level == IPPROTO_IP) && (optname == IP_PKTINFO))
    {
      //FIXME
      return 0;
    }
  if ((level == IPPROTO_IP) && (optname == IP_TOS))
    {
      /* Can be safely ignored */
      return 0;
    }
  if ((level == IPPROTO_IP) && (optname == IP_TTL))
    {
      /* Can be safely ignored */
      return 0;
    }

  if ((level == IPPROTO_TCP) && (optname == TCP_NODELAY))
    {
      //FIXME
      return 0;
    }


  DEBUG_PRINTF ("unknown setsockopt %d %d %d %p %d\n",
                sockfd, level, optname, optval, optlen);

  errno = ENOPROTOOPT;
  return -1;
}


INTERPOSE (getsockopt, int, int sockfd, int level, int optname,
           void *optval, socklen_t * optlen)
{
  int ret;
  CHECK_INTERPOSE (getsockopt);

  if (!is_our_fd (sockfd))
    return orig_getsockopt (sockfd, level, optname, optval, optlen);

  return argo_getsockopt (sockfd, level, optname, optval, optlen);
}



static void
init (void)
{
  static int ready;

  if (ready)
    return;

  FD_ZERO (&argo_fds);
  FD_ZERO (&argo_afs);

#if 0
  argo_dgram_inode.st_dev = (dev_t) (-1L);
  argo_dgram_inode.st_ino = (ino_t) (-1L);
#endif

  FIND (socket);
  FIND (close);
  FIND (bind);
  FIND (connect);
  FIND (accept);
  FIND (listen);
  FIND (send);
  FIND (sendmsg);
  FIND (sendto);
  FIND (recv);
  FIND (recvmsg);
  FIND (recvfrom);
  FIND (dup);
  FIND (dup2);
  FIND (dup3);
  FIND (setsockopt);
  FIND (getsockopt);
  FIND (getsockname);
  FIND (getpeername);
  FIND (shutdown);

  ready++;
}
